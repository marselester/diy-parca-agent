package main

import (
	"debug/elf"
	"testing"
)

func TestPC2FuncNameNoPIE(t *testing.T) {
	f, err := elf.Open("../../testdata/fib-nopie")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	const (
		fileOffset  = 4096
		memoryStart = 4198400
	)
	s, err := newSymbolizer(f, fileOffset, memoryStart)
	if err != nil {
		t.Fatal(err)
	}

	tt := map[string][]uint64{
		"fibNaive": {4198694, 4198700, 4198705, 4198706, 4198707, 4198708, 4198712, 4198715, 4198719, 4198724, 4198727, 4198736, 4198739, 4198743, 4198744, 4198745},
		"main":     {0x40115a},
		"?":        {0, 123, 94862440956340},
	}

	for name, sampledAddrs := range tt {
		for _, addr := range sampledAddrs {
			funcName := s.Addr2FuncName(addr)
			if funcName != name {
				t.Errorf("expected %q got %q: %d", name, funcName, addr)
			}
		}
	}
}

func TestPC2FuncNamePIE(t *testing.T) {
	f, err := elf.Open("../../testdata/fib-pie")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	const (
		fileOffset  = 4096
		memoryStart = 94862440955904
	)
	s, err := newSymbolizer(f, fileOffset, memoryStart)
	if err != nil {
		t.Fatal(err)
	}

	tt := map[string][]uint64{
		"fibNaive": {94862440956233, 94862440956237, 94862440956238, 94862440956241, 94862440956242, 94862440956246, 94862440956250, 94862440956255, 94862440956257, 94862440956262, 94862440956264, 94862440956268, 94862440956272, 94862440956275, 94862440956280, 94862440956283, 94862440956287, 94862440956291, 94862440956294, 94862440956299, 94862440956302, 94862440956306, 94862440956307},
		"main":     {94862440956340},
		"?":        {0, 123},
	}

	for name, sampledAddrs := range tt {
		for _, addr := range sampledAddrs {
			funcName := s.Addr2FuncName(addr)
			if funcName != name {
				t.Errorf("expected %q got %q: %d", name, funcName, addr)
			}
		}
	}
}
