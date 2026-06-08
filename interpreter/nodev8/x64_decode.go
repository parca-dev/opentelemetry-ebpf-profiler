package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

// GetJsDispatchTableOffsetX64 finds the offset of `js_dispatch_table_` within `IsolateGroup`
// by analyzing v8::internal::ExternalReference::js_dispatch_table_address().
//
// We are interested in the offset of the field that ends up being returned,
// so we run until `ret` and then see what offset rax (the return value) was loaded from.
// We don't care how the base pointer was computed, and in fact, this can vary in debug vs. release builds
//
// 0xc736d0: mov rax, qword ptr [rip + 0x5a2d231]
// 0xc736d7: mov rax, qword ptr [rax + 0x3268]
// 0xc736de: lea rdx, [rax - 1]
// 0xc736e2: cmp rdx, 0x20
// 0xc736e6: jbe 0xc736f0
// 0xc736e8: ret
// 0xc736e9: nop dword ptr [rax]
// 0xc736f0: push rbp
// 0xc736f1: mov esi, 0x39e76c3
// 0xc736f6: mov edi, 0x39a9ae3
// 0xc736fb: xor eax, eax
// 0xc736fd: mov rbp, rsp
// 0xc73700: call 0x26887a0 ; _Z8V8_FatalPKcz+0
func GetJsDispatchTableOffsetX64(code []byte) (uint64, error) {
	it := amd.NewInterpreterWithCode(code)
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET
	})
	if err != nil {
		return 0, err
	}
	rax := it.Regs.Get(amd.RAX)
	offset, ok := e.MemOffset(rax)
	if !ok {
		return 0, errors.New("Failed to find js_dispatch_table_ field offset")
	}
	return offset, nil
}
