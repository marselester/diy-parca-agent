//go:build linux

/*
Program profiler3 is a CPU profiler based on Parca Agent.
It takes PID as an input and samples the process 100 times per second.

By default it collects CPU samples for 10 seconds and then prints the stack traces.
Additionally, the program saves a pprof profile.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/google/pprof/profile"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-13 ParcaAgent ../profiler/bpf/parca-agent.bpf.c -- -I../../headers

// stackDepth is the max depth of each stack trace to track.
// as defined in BPF C program, i.e., MAX_STACK_DEPTH constant.
const stackDepth = 127

func main() {
	// By default an exit code is set to indicate a failure since
	// there are more failure scenarios to begin with.
	exitCode := 1
	defer func() { os.Exit(exitCode) }()

	pid := flag.Int("pid", 0, "PID whose stack traces should be collected")
	profilingDuration := flag.Duration("wait", 10*time.Second, "profiling duration")
	filename := flag.String("profile", "cpu.pprof", "CPU profile filename where samples will be stored")
	flag.Parse()

	// Open and parse a memory map file of a given process.
	path := fmt.Sprintf("/proc/%d/maps", *pid)
	fm, err := os.Open(path)
	if err != nil {
		log.Printf("failed to open memory map file: %v", err)
		return
	}
	defer fm.Close()

	mm, err := profile.ParseProcMaps(fm)
	if err != nil {
		log.Printf("failed to parse memory map file: %v", err)
		return
	}
	fmt.Println(path)
	for _, m := range mm {
		fmt.Printf("start=0x%x limit=0x%x offset=0x%x %s\n", m.Start, m.Limit, m.Offset, m.File)
	}

	// Increase the resource limit of the current process to provide sufficient space
	// for locking memory for the BPF maps.
	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	objs := ParcaAgentObjects{}
	if err := LoadParcaAgentObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF program and maps: %v", err)
		return
	}
	defer objs.Close()

	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		fd, err := unix.PerfEventOpen(
			&unix.PerfEventAttr{
				// PERF_TYPE_SOFTWARE event type indicates that
				// we are measuring software events provided by the kernel.
				Type: unix.PERF_TYPE_SOFTWARE,
				// Config is a Type-specific configuration.
				// PERF_COUNT_SW_CPU_CLOCK reports the CPU clock, a high-resolution per-CPU timer.
				Config: unix.PERF_COUNT_SW_CPU_CLOCK,
				// Size of attribute structure for forward/backward compatibility.
				Size: uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
				// Sample could mean sampling period (expressed as the number of occurrences of an event)
				// or frequency (the average rate of samples per second).
				// See https://perf.wiki.kernel.org/index.php/Tutorial#Period_and_rate.
				// In order to use frequency PerfBitFreq flag is set below.
				// The kernel will adjust the sampling period to try and achieve the desired rate.
				Sample: 100,
				Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
			},
			*pid,
			cpu,
			// groupFd argument allows event groups to be created.
			// A single event on its own is created with groupFd = -1
			// and is considered to be a group with only 1 member.
			-1,
			// PERF_FLAG_FD_CLOEXEC flag enables the close-on-exec flag for the created
			// event file descriptor, so that the file descriptor is
			// automatically closed on execve(2).
			unix.PERF_FLAG_FD_CLOEXEC,
		)
		if err != nil {
			log.Printf("failed to open the perf event: %v", err)
			return
		}
		defer func(fd int) {
			if err = unix.Close(fd); err != nil {
				log.Printf("failed to close the perf event: %v", err)
			}
		}(fd)

		// Attach the BPF program to the perf event.
		err = unix.IoctlSetInt(
			fd,
			unix.PERF_EVENT_IOC_SET_BPF,
			// This BPF program file descriptor was created by a previous bpf(2) system call.
			objs.ParcaAgentPrograms.DoSample.FD(),
		)
		if err != nil {
			log.Printf("failed to attach BPF program to perf event: %v", err)
			return
		}

		// PERF_EVENT_IOC_ENABLE enables the individual event or
		// event group specified by the file descriptor argument.
		err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0)
		if err != nil {
			log.Printf("failed to enable the perf event: %v", err)
			return
		}
		// PERF_EVENT_IOC_DISABLE disables the individual counter or
		// event group specified by the file descriptor argument.
		defer func(fd int) {
			err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
			if err != nil {
				log.Printf("failed to disable the perf event: %v", err)
			}
		}(fd)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	prof := newProfile(*profilingDuration)
	fmt.Printf("\nWaiting for stack traces for %v...\n", *profilingDuration)

	// Wait until samples are accumulated in the BPF maps,
	// and then store them in a file in pprof format.
	select {
	case <-sig:
	case <-time.After(*profilingDuration):
	}

	fillProfile(
		objs.ParcaAgentMaps.Counts,
		objs.ParcaAgentMaps.StackTraces,
		prof,
		*pid,
		mm,
	)

	fp, err := os.Create(*filename)
	if err != nil {
		log.Printf("failed to open profile: %v", err)
		return
	}
	defer fp.Close()
	if err = prof.Write(fp); err != nil {
		log.Printf("failed to save profile: %v", err)
		return
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}

// newProfile creates a pprof profile so it can be filled with CPU samples.
func newProfile(profilingDuration time.Duration) *profile.Profile {
	prof := profile.Profile{
		// SampleType is a description of the samples associated with each Sample.Value.
		// By convention the number of events should use unit "count" and
		// it should be at index 0.
		SampleType: []*profile.ValueType{{
			Type: "samples",
			Unit: "count",
		}},
		// TimeNanos is a time of collection (UTC) represented as nanoseconds past the epoch.
		TimeNanos: time.Now().UnixNano(),
		// DurationNanos is a profiling duration in nanoseconds, 10s by default.
		DurationNanos: int64(profilingDuration),
		// PeriodType is the kind of events between sampled ocurrences,
		// i.e., ["cpu", "nanoseconds"].
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		// Period is the number of events between sampled occurrences.
		// We sample at 100Hz (100 times per second),
		// which is every 0.01s or 10 million nanoseconds.
		Period: 10000000,
	}

	return &prof
}

// stackCountKey represents "Counts" map key sent to user space from the BPF program running in the kernel.
// Note, that it must match the C stack_count_key_t struct,
// and both C and Go structs must be aligned the same way.
type stackCountKey struct {
	PID           uint32
	UserStackID   int32
	KernelStackID int32
}

// locationIndex helps to look up a respective profile.Location
// by PID and memory address.
type locationIndex struct {
	PID  int
	Addr uint64
}

// fillProfile fills the pprof profile with samples read from the BPF maps.
func fillProfile(counts, stackTraces *ebpf.Map, prof *profile.Profile, pid int, mm []*profile.Mapping) {
	// locationIndices maps {pid; addr} found in the sample
	// to an index in the Profile.Location slice
	// to look up a respective Location.
	locationIndices := make(map[locationIndex]int)

	var (
		it = counts.Iterate()

		key  stackCountKey
		seen uint64
	)
	for it.Next(&key, &seen) {
		fmt.Printf("%+v seen %d times\n", key, seen)

		stackBytes, err := stackTraces.LookupBytes(key.UserStackID)
		if err != nil {
			log.Printf("failed to look up user-space stack traces: %v", err)
			continue
		}
		userStack := [stackDepth]uint64{}
		err = binary.Read(bytes.NewBuffer(stackBytes), binary.LittleEndian, userStack[:])
		if err != nil {
			log.Printf("failed to read user-space stack traces: %v", err)
			continue
		}
		fmt.Printf("\t%d %x\n", key.UserStackID, tracedAddresses(userStack))

		stackBytes, err = stackTraces.LookupBytes(key.KernelStackID)
		if err != nil {
			log.Printf("failed to look up kernel-space stack traces: %v", err)
			continue
		}
		kernelStack := [stackDepth]uint64{}
		err = binary.Read(bytes.NewBuffer(stackBytes), binary.LittleEndian, kernelStack[:])
		if err != nil {
			log.Printf("failed to read kernel-space stack traces: %v", err)
			// Even if we couldn't get a kernel stack trace,
			// continue to create a profile because
			// in this version only a user stack is included into a pprof.
		} else {
			fmt.Printf("\t%d %x\n", key.KernelStackID, tracedAddresses(kernelStack))
		}

		// Collect user-space stack trace samples.
		sampleLocations := []*profile.Location{}
		for _, addr := range userStack {
			if addr == 0 {
				continue
			}

			// Look up a location for the given PID and address
			// and append it to the current sample's locations.
			//
			// In case a location wasn't found, create one.
			locKey := locationIndex{pid, addr}
			locIndex, found := locationIndices[locKey]
			if !found {
				m := mappingForAddr(mm, addr)
				if m == nil {
					log.Printf("failed to get process mapping for addr: %x", addr)
				}

				locIndex = len(prof.Location)
				// Each Location describes function and line table debug information.
				prof.Location = append(prof.Location, &profile.Location{
					// ID is a unique nonzero id for the location.
					ID: uint64(locIndex + 1),
					// Address is the instruction address for this location.
					// It should be within [Mapping.memory_start...Mapping.memory_limit]
					// for the corresponding mapping.
					Address: addr,
					// Mapping is the corresponding profile.Mapping for this location.
					// It can be nil if the mapping is unknown.
					Mapping: m,
				})
				locationIndices[locKey] = locIndex
			}

			sampleLocations = append(sampleLocations, prof.Location[locIndex])
		}

		// Each Sample records how many times a particular stack trace was seen
		// along with the corresponding locations.
		prof.Sample = append(prof.Sample, &profile.Sample{
			Value:    []int64{int64(seen)},
			Location: sampleLocations,
		})
	}
	if err := it.Err(); err != nil {
		log.Printf("failed to read from Counts map: %v", err)
	}

	// Mappings in pprof must have IDs and need to start with 1.
	for i, m := range mm {
		m.ID = uint64(i + 1)
	}
	prof.Mapping = mm
}

// Look up a mapping for the given memory address
// based on start/limit params.
func mappingForAddr(mapping []*profile.Mapping, addr uint64) *profile.Mapping {
	for _, m := range mapping {
		if m.Start <= addr && m.Limit >= addr {
			return m
		}
	}

	return nil
}

func tracedAddresses(stack [stackDepth]uint64) []uint64 {
	for i, addr := range stack {
		if addr == 0 {
			return stack[:i]
		}
	}
	return nil
}
