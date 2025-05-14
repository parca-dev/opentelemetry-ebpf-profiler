package main

import (
	// "fmt"
	// "os"

	"fmt"
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	xh "go.opentelemetry.io/ebpf-profiler/x86helpers"
	"golang.org/x/arch/x86/x86asm"
)

// x86

type reg struct {
	loc     uint64
	nameLoc uint64
}

type streamingDisasm struct {
	r      io.Reader
	cursor int
	len    int
	done   bool
	ip     uint64
	buf    [4096]byte
}

func streamingDisasmFor(r io.Reader, base uint64) streamingDisasm {
	return streamingDisasm{
		r:  r,
		ip: base,
	}
}

func (s *streamingDisasm) refillIfNecessary() error {
	if !s.done && s.len - s.cursor < 15 {
		rem := s.len - s.cursor
		copy(s.buf[0:rem], s.buf[s.cursor:s.len])
		n, err := s.r.Read(s.buf[rem:])
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF {
			s.done = true
		}
		s.len += n
		s.cursor = 0
	}
	return nil
}

func (s *streamingDisasm) next() (x86asm.Inst, error) {
	for {
		err := s.refillIfNecessary()
		if err != nil {
			return x86asm.Inst{}, err
		}
		if s.len == 0 {
			return x86asm.Inst{}, io.EOF
		}
		_, i := xh.SkipEndBranch(s.buf[s.cursor:s.len])
		s.cursor += int(i)
		s.ip += uint64(i)
		if i == 0 {
			break
		}
	}
	inst, err := x86asm.Decode(s.buf[s.cursor:s.len], 64)
	s.ip += uint64(inst.Len)
	s.cursor += inst.Len
	return inst, err
}

func findRegistrations(crfLoc uint64, s *streamingDisasm, base uint64) ([]reg, error) {
	states := make(map[x86asm.Reg]uint64)
	var result []reg
	
	for {
		inst, err := s.next()
		if err == io.EOF {
			break
		}
		switch inst.Op {
		case x86asm.MOV:
			r0, ok := inst.Args[0].(x86asm.Reg)
			if ok {
				switch a1 := inst.Args[1].(type) {
				case x86asm.Reg:
					val, valKnown := states[a1]
					if valKnown {
						states[r0] = val
					} else {
						delete(states, r0)
					}
				case x86asm.Imm:
					val := uint64(a1)
					states[r0] = val
				default:
					delete(states, r0)
				}
			}
		case x86asm.LEA:
			r0, ok0 := inst.Args[0].(x86asm.Reg)
			m1, ok1 := inst.Args[1].(x86asm.Mem)
			if ok0 && ok1 && m1.Segment == 0 && m1.Base == x86asm.RIP && m1.Index == 0 {
				states[r0] = s.ip + uint64(m1.Disp)
			}
		case x86asm.CALL:
			rel, ok := inst.Args[0].(x86asm.Rel)
			rcx, okRCX := states[x86asm.RCX]
			rsi, okRSI := states[x86asm.RSI]
			if ok && int64(s.ip)+int64(rel) == int64(crfLoc) && okRCX && okRSI {
				r := reg{
					loc:     rsi,
					nameLoc: rcx,
				}
				result = append(result, r)
				for r2 := range states {
					delete(states, r2)
				}

			}
			states = make(map[x86asm.Reg]uint64)
		}
	}
	return result, nil
}

// func test(b []byte) {
// 	b, _ = xh.SkipEndBranch(b)
// 	for len(b) > 0 {
// 		inst, err := x86asm.Decode(b, 64)
// 		if err != nil {
// 			panic(err)
// 		}
// 		fmt.Println(inst)
// 		for _, arg := range(inst.Args) {
// 			var s string
// 			switch arg.(type) {
// 			case x86asm.Reg:
// 				s = "reg"
// 			case x86asm.Imm:
// 				s = "imm"
// 			case x86asm.Mem:
// 				s = "mem"
// 			case x86asm.Rel:
// 				s = "rel"
// 			}
// 			fmt.Printf("  %v (%s)\n", arg, s)
// 		}
// 		b = b[inst.Len:]
// 	}
// }

func main() {
	elf, err := pfelf.Open("/home/brennan/libtorch_cuda.so")
	// elf, err := pfelf.Open("/gnu/store/6wrg0va5fr78ym1f2r3wmhyxni7x1ydn-coreutils-9.1-debug/lib/debug/gnu/store/lc3ziy4bvyyb9l6qnynzb7vjjq0dn9q8-coreutils-9.1/bin/ls.debug")
	if err != nil {
		panic(err)
	}
	// syms, err := elf.ReadSymbols()
	// if err != nil {
	// 	panic(err)
	// }
	// syms.VisitAll(func(s libpf.Symbol) {
	// 	fmt.Println(s.Name)
	// })
	err = elf.StreamSymbolTable(".symtab", func(s libpf.Symbol) {
		fmt.Printf("%s 0x%08x 0x%x\n", s.Name, s.Address, s.Size)
	})
	if err != nil {
		panic(err)
	}

	// rs, err := findRegistrations(0xcc9290, data, 0xdaf880)
	// if err != nil {
	// 	panic(err)
	// }
	// // fmt.Println(rs)
	// for _, r := range rs {
	// 	fmt.Printf("0x%08x 0x%08x\n", r.loc, r.nameLoc)
	// }
}
