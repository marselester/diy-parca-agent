// Program addr2func converts addresses into function names
// as long as they don't belong to shared libraries.
package main

import (
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"sort"
)

func main() {
	path := flag.String("path", "", "path to the ELF file")
	sampledAddr := flag.Uint64("addr", 0, "sampled address to resolve")
	memoryStart := flag.Uint64("memory-start", 0x401000, "virtual address where segment was mapped")
	fileOffset := flag.Uint64("file-offset", 0x1000, "file offset of mapped segment")
	flag.Parse()

	f, err := elf.Open(*path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	s, err := newSymbolizer(f, *fileOffset, *memoryStart)
	if err != nil {
		log.Fatal(err)
	}

	funcName := s.Addr2FuncName(*sampledAddr)
	fmt.Println(funcName)
}

// newSymbolizer creates a symbolizer for ELF file f.
// The caller must provide the file offset of mapped segment (e.g., 0x1000),
// and the virtual address where segment was mapped, e.g., 0x401000.
func newSymbolizer(f *elf.File, fileOffset, memoryStart uint64) (*symbolizer, error) {
	symbols, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to get symbols: %w", err)
	}
	sort.SliceStable(symbols, func(i, j int) bool {
		return symbols[i].Value < symbols[j].Value
	})

	var segment elf.ProgHeader
	for i := range f.Progs {
		if f.Progs[i].Off == fileOffset {
			segment = f.Progs[i].ProgHeader
			break
		}
	}
	if segment.Type != elf.PT_LOAD {
		return nil, fmt.Errorf("loadable segment not found at offset %x", fileOffset)
	}

	// In case of PIE, virtual address and file offset are equal
	// when looking at the ELF file,
	// but vm_start shown in /proc/$PID/maps will be a random high address,
	// e.g., 94862440955904.
	//
	// Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
	// LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x0001ed 0x0001ed R E 0x1000
	isPIE := segment.Vaddr == segment.Off

	s := symbolizer{
		symbols:       symbols,
		segmentOffset: segment.Off,
		memoryStart:   memoryStart,
		isPIE:         isPIE,
	}
	return &s, nil
}

type symbolizer struct {
	// symbols represents sorted symbols found in .symtab section.
	symbols []elf.Symbol
	// segmentOffset is a segment offset within ELF file, e.g., 0x1000.
	segmentOffset uint64
	// memoryStart is a virtual address where segment was mapped, e.g., 0x401000.
	memoryStart uint64
	// isPIE indicates whether the program is PIE.
	// Position independent executable (PIE)
	// is used by default in gcc for security measures,
	// i.e., address space layout randomization.
	isPIE bool
}

// Addr2FuncName binary searches a function name in the symbol table
// by the memory address of a machine instruction found in a sample.
//
// The address can't be zero or less than memoryStart by definition.
// The function returns "?" if the symbol wasn't found.
func (s *symbolizer) Addr2FuncName(addr uint64) string {
	notfound := "?"
	if addr == 0 {
		return notfound
	}

	if s.isPIE {
		if addr < s.memoryStart {
			return notfound
		}
		// Distance between the sampled memory address and
		// beginning of the loaded segment (vm_start memory address).
		segmentDistance := addr - s.memoryStart
		// Sampled address adjusted to .symtab address range.
		addr = s.segmentOffset + segmentDistance
	}

	i := sort.Search(len(s.symbols), func(i int) bool {
		return s.symbols[i].Value >= addr
	})
	if i >= len(s.symbols) {
		return notfound
	}
	if s.symbols[i].Value == addr {
		return s.symbols[i].Name
	}

	// Since addr wasn't found in the symbols array,
	// now i points to a symbol whose address > addr, i.e., 0x40115a.
	//
	// 0x401120 frame_dummy
	// 0x401126 fibNaive
	// 0x40112c ?
	// 0x40115a main
	//
	// Therefore the desired symbol's address is 0x401126.
	if i >= 1 && s.symbols[i-1].Value > 0 {
		return s.symbols[i-1].Name
	}

	return notfound
}
