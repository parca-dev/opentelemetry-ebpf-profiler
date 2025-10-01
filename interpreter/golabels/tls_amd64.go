//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"golang.org/x/arch/x86/x86asm"
)

// Most normal amd64 Go binaries use -8 as offset into TLS space for
// storing the current g but "static" binaries it ends up as -80. There
// may be dynamic relocating going on so just read it from a known
// symbol if possible.
func extractTLSGOffset(f *pfelf.File) (int32, error) {
	pclntab, err := elfunwindinfo.NewGopclntab(f)
	if err != nil {
		log.Debugf("Failed to find symbols (%v) using default TLSG offset", err)
		return -8, nil
	}
	defer pclntab.Close()

	// Dump of assembler code for function runtime.stackcheck:
	// 0x0000000000470080 <+0>:     mov    %fs:0xfffffffffffffff8,%rax
	sym, err := pclntab.LookupSymbol("runtime.stackcheck")
	if err != nil {
		return 0, err
	}
	b, err := f.VirtualMemory(int64(sym.Address), 16, 16)
	if err != nil {
		return 0, err
	}

	i, err := x86asm.Decode(b, 64)
	if err != nil {
		return 0, err
	}
	if i.Op == x86asm.MOV {
		mem, ok := i.Args[1].(x86asm.Mem)
		if ok {
			return int32(mem.Disp), nil
		}
		// allow mov const to register as well to silence warnings on this:
		// 00000000002ed100 <runtime.stackcheck.abi0>:
		// 2ed100: 48 c7 c1 f8 ff ff ff          movq    $-0x8, %rcx
		// 2ed107: 64 48 8b 01                   movq    %fs:(%rcx), %rax
		if imm, ok := i.Args[1].(x86asm.Imm); ok {
			if reg, ok := i.Args[0].(x86asm.Reg); ok {
				i, err = x86asm.Decode(b[i.Len:], 64)
				if err != nil {
					goto exit
				}
				if i.Op == x86asm.MOV {
					if m, ok := i.Args[1].(x86asm.Mem); ok && m.Base == reg {
						return int32(imm), nil
					}
				}
			}
		}
	}
exit:
	log.Warnf("Failed to decode stackcheck symbol, Go label collection might not work")
	return -8, nil
}
