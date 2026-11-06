// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func nodeMajorVersion(ef *pfelf.File, sym *libpf.Symbol) (uint32, error) {
	var addr uint64
	if sym != nil {
		if sym.Size < 12 {
			return 0, fmt.Errorf("version symbol in Node binary too small: %d", sym.Size)
		}
		addr = uint64(sym.Address)
	} else {
		// The function is part of Node's public ABI; its function-local version
		// structure has no dynamic symbol and disappears from .symtab when stripped.
		code, start, err := readCustomLabelsFunction(ef, "napi_get_node_version")
		if err != nil {
			return 0, err
		}
		addr, err = decodeNodeVersionAddress(ef.Machine, code, start)
		if err != nil {
			return 0, fmt.Errorf("failed to analyze napi_get_node_version: %w", err)
		}
	}
	var version [12]byte
	if _, err := ef.ReadAt(version[:], int64(addr)); err != nil {
		return 0, fmt.Errorf("failed to read Node version data: %w", err)
	}
	return binary.LittleEndian.Uint32(version[:4]), nil
}

func currentIsolateOffset(ef *pfelf.File, sym *libpf.Symbol) (int64, error) {
	if sym != nil {
		return ef.AdjustTLSSymbol(sym)
	}
	// The decoder only supports TLS in the main executable, just like
	// AdjustTLSSymbol. A shared library's GOT may require runtime relocations.
	if !ef.IsExecutable() {
		return 0, errors.New("cannot analyze current isolate TLS in a shared library")
	}
	code, addr, err := readCustomLabelsFunction(ef, "_ZN2v87Isolate13TryGetCurrentEv")
	if err != nil {
		return 0, err
	}
	offset, err := decodeCurrentIsolateOffset(ef, code, addr)
	if err != nil {
		return 0, fmt.Errorf("failed to analyze v8::Isolate::TryGetCurrent: %w", err)
	}
	// The decoder returns a TP-relative offset. Convert it to the same
	// representation as AdjustTLSSymbol (module-relative on aarch64).
	base, err := ef.StaticTLSOffset(&libpf.Symbol{})
	if err != nil {
		return 0, err
	}
	tls, err := ef.TLS()
	if err != nil {
		return 0, err
	}
	moduleOffset := uint64(offset) - base
	if tls.Memsz < 8 || moduleOffset > tls.Memsz-8 {
		return 0, errors.New("current isolate offset lies outside the executable TLS block")
	}
	return ef.AdjustTLSSymbol(&libpf.Symbol{Address: libpf.SymbolValue(moduleOffset)})
}

func readCustomLabelsFunction(ef *pfelf.File, name libpf.SymbolName) ([]byte, uint64, error) {
	sym, err := ef.LookupSymbol(name)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to look up %s: %w", name, err)
	}
	// Bound decoding even if the ELF claims an implausibly large function.
	code := make([]byte, min(sym.Size, 256))
	if _, err := ef.ReadAt(code, int64(sym.Address)); err != nil {
		return nil, 0, fmt.Errorf("failed to read %s: %w", name, err)
	}
	return code, uint64(sym.Address), nil
}

// decodeNodeVersionAddress finds the constant pointer stored through the second
// argument of napi_get_node_version. Other stores (including last-error updates
// through the first argument) must not be mistaken for the version pointer.
func decodeNodeVersionAddress(machine elf.Machine, code []byte, addr uint64) (uint64, error) {
	switch machine {
	case elf.EM_X86_64:
		it := amd.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		result := it.Regs.Get(amd.RSI)
		for {
			op, err := it.Step()
			if err != nil {
				return 0, err
			}
			if op.Op == x86asm.RET || op.Op == x86asm.CALL || op.Op == x86asm.JMP {
				break
			}
			if op.Op != x86asm.MOV || op.MemBytes != 8 {
				continue
			}
			dst, ok := op.Args[0].(x86asm.Mem)
			if !ok || dst.Segment != 0 || !it.MemArg(dst).Match(result) {
				continue
			}
			switch src := op.Args[1].(type) {
			case x86asm.Imm:
				return uint64(src), nil
			case x86asm.Reg:
				if value, ok := expression.AsConstant(it.Regs.GetX86(src)); ok {
					return value, nil
				}
			}
		}
	case elf.EM_AARCH64:
		it := arm.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		result := it.Regs.Get(arm.X1)
		for {
			op, err := it.Step()
			if err != nil {
				return 0, err
			}
			if op.Op == arm64asm.RET || op.Op == arm64asm.BL || op.Op == arm64asm.BLR || op.Op == arm64asm.B {
				break
			}
			if op.Op != arm64asm.STR {
				continue
			}
			dst, ok := op.Args[1].(arm64asm.MemImmediate)
			if !ok || dst.Mode != arm64asm.AddrOffset {
				continue
			}
			disp, ok := arm.DecodeImmediate(dst)
			if !ok || disp != 0 || !it.Regs.GetArmSP(dst.Base).Match(result) {
				continue
			}
			src, ok := op.Args[0].(arm64asm.Reg)
			if ok && src >= arm64asm.X0 && src <= arm64asm.X30 {
				if value, ok := expression.AsConstant(it.Regs.GetArm(src)); ok {
					return value, nil
				}
			}
		}
	default:
		return 0, fmt.Errorf("unsupported machine: %s", machine)
	}
	return 0, errors.New("no constant version pointer stored through result argument")
}

func decodeCurrentIsolateOffset(ef *pfelf.File, code []byte, addr uint64) (int64, error) {
	offset := expression.NewImmediateCapture("offset")
	switch ef.Machine {
	case elf.EM_X86_64:
		it := amd.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		for {
			op, err := it.Step()
			if err != nil {
				return 0, err
			}
			if op.Op == x86asm.CALL {
				// Forget caller-clobbered state. The TLS load must be independently
				// recognizable after any optional V8 assertion helper call.
				pc := it.PC()
				code, addr = code[pc:], addr+pc
				it = amd.NewInterpreterWithCodeAt(code, expression.Imm(addr))
			}
			if op.Op == x86asm.JMP {
				break
			}
			if op.Op != x86asm.RET {
				continue
			}
			value := it.Regs.Get(amd.RAX)
			if value.Match(expression.MemWithSegment8(x86asm.FS, offset)) {
				return int64(offset.CapturedValue()), nil
			}
			if value.Match(expression.MemWithSegment8(x86asm.FS, expression.Mem8(offset))) {
				var got [8]byte
				if _, err := ef.ReadAt(got[:], int64(offset.CapturedValue())); err != nil {
					return 0, err
				}
				return int64(binary.LittleEndian.Uint64(got[:])), nil
			}
			break
		}
	case elf.EM_AARCH64:
		it := arm.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		var tp expression.Expression
		for {
			op, err := it.Step()
			if err != nil {
				return 0, err
			}
			if op.Op == arm64asm.MRS && op.Args[1].String() == "S3_3_C13_C0_2" {
				if reg, ok := op.Args[0].(arm64asm.Reg); ok {
					v := it.Regs.GetArm(reg)
					if _, ok := expression.AsNamed(v); ok {
						tp = v
					}
				}
			}
			if op.Op == arm64asm.BL || op.Op == arm64asm.BLR || op.Op == arm64asm.B {
				break
			}
			if op.Op == arm64asm.RET {
				if tp != nil && it.Regs.Get(arm.X0).Match(expression.Mem8(expression.Add(tp, offset))) {
					return int64(offset.CapturedValue()), nil
				}
				break
			}
		}
	default:
		return 0, fmt.Errorf("unsupported machine: %s", ef.Machine)
	}
	return 0, errors.New("return value is not a recognized thread-local isolate pointer")
}
