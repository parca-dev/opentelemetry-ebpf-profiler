package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// GetJsDispatchTableOffsetAarch64 finds the offset of `js_dispatch_table_` within `IsolateGroup`
// by analyzing v8::internal::ExternalReference::js_dispatch_table_address().
//
// We are interested in the offset of the field that ends up being returned,
// so we run until `ret` and then see what offset x0 (the return value) was loaded from.
// We don't care how the base pointer was computed, and in fact, this can vary in debug vs. release builds
//
// 0x7c8668: adrp x8, #0x32ee000
// 0x7c866c: ldr x8, [x8, #0xa70]
// 0x7c8670: ldr x8, [x8]
// 0x7c8674: ldr x0, [x8, #0x3268]
// 0x7c8678: sub x8, x0, #1
// 0x7c867c: cmp x8, #0x20
// 0x7c8680: b.ls #0x7c8688 ; _ZN2v88internal17ExternalReference25js_dispatch_table_addressEv+0x20
// 0x7c8684: ret
// 0x7c8688: stp x29, x30, [sp, #-0x10]!
// 0x7c868c: mov x29, sp
// 0x7c8690: adrp x0, #0x282b000
// 0x7c8694: add x0, x0, #0xae0
// 0x7c8698: adrp x1, #0x284b000
// 0x7c869c: add x1, x1, #0xadf
// 0x7c86a0: bl #0x17c3d34 ; _Z8V8_FatalPKcz+0
func GetJsDispatchTableOffsetAarch64(code []byte) (uint64, bool) {
	// code := []byte{
	// 	0x28, 0x59, 0x01, 0xd0, 0x08, 0x39, 0x45, 0xf9,
	// 	0x08, 0x01, 0x40, 0xf9, 0x00, 0x35, 0x59, 0xf9,
	// 	0x08, 0x04, 0x00, 0xd1, 0x1f, 0x81, 0x00, 0xf1,
	// 	0x49, 0x00, 0x00, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
	// 	0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91,
	// 	0x00, 0x03, 0x01, 0xf0, 0x00, 0x80, 0x2b, 0x91,
	// 	0x01, 0x04, 0x01, 0xf0, 0x21, 0x7c, 0x2b, 0x91,
	// 	0xa5, 0xed, 0x3f, 0x94,
	// }

	regLastOffsets := make(map[int]uint64)
	for offs := 0; offs < len(code); offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			break
		}
		switch inst.Op {
		case aa.RET:
			retvalOffset, ok := regLastOffsets[0]
			return retvalOffset, ok
		case aa.MOV:
			// Track register moves
			destReg, ok := arm.Xreg2num(inst.Args[0])
			if !ok {
				continue
			}
			if srcReg, ok := arm.Xreg2num(inst.Args[1]); ok {
				regLastOffsets[destReg] = regLastOffsets[srcReg]
			}
		case aa.LDR:
			destReg, ok := arm.Xreg2num(inst.Args[0])
			if !ok {
				continue
			}
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				continue
			}
			imm, ok := arm.DecodeImmediate(m)
			if !ok {
				continue
			}
			regLastOffsets[destReg] = uint64(imm)
		}
	}
	return 0, false
}
