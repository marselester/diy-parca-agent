# DIY Parca Agent

I was curious how Parca Agent was implemented.
According to its [design doc](https://github.com/parca-dev/parca-agent/blob/main/docs/design.md)
it attaches the BPF program to a Linux cgroup using
[perf_event_open()](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) system call.
The call creates a file descriptor that allows measuring performance information.
It instructs the kernel to call the BPF program 100 times per second.

Parca Agent relies on [cgo bindings for libbpf](https://github.com/aquasecurity/libbpfgo) from Aqua Security.
I wanted to make something similar using
[github.com/cilium/ebpf](https://github.com/cilium/ebpf) which doesn't need cgo.
See the related blog posts:

- [Continuous profiling in Go](https://marselester.com/continuous-profiling-in-go.html)
- [DIY CPU profiler: from BPF maps to pprof](https://marselester.com/diy-cpu-profiler-from-bpf-maps-to-pprof.html)
- [DIY CPU profiler: the simplest case of symbolization](https://marselester.com/diy-cpu-profiler-the-simplest-case-of-symbolization.html)

## Setup

Start a virtual machine, install Clang and Go.

```sh
% vagrant up
% vagrant ssh
$ sudo apt-get update
$ sudo apt-get install clang
$ sudo snap install go --classic
```

The easiest way to quickly get some stack traces is to run `top`
and collect its CPU profile by PID.

```sh
$ top # Its PID is 15958.
$ cd /vagrant/
$ sudo go run ./cmd/profiler/ -pid 15958
Waiting for stack traces...
{PID:15958 UserStackID:132 KernelStackID:114} seen 1 times
{PID:15958 UserStackID:709 KernelStackID:-14} seen 1 times # -14 indicates bpf_get_stackid() error.
{PID:15958 UserStackID:366 KernelStackID:30} seen 2 times
{PID:15958 UserStackID:674 KernelStackID:943} seen 1 times
```
