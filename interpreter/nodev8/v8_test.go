// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestRegexs(t *testing.T) {
	shouldMatch := []string{
		"node",
		"node8",
		"./node",
		"/foo/bar/node",
		"./foo/bar/node",
		"nsolid",
		"nsolid8",
		"./nsolid",
		"/foo/bar/nsolid",
		"./foo/bar/nsolid",
		"./libnode.so",
		"/lib/libnode.so.12",
	}
	for _, s := range shouldMatch {
		assert.True(t, v8Regex.MatchString(s), "regex %s should match %s",
			v8Regex.String(), s)
	}

	shouldNotMatch := []string{
		"node-foo",
		"./nsolid-bar",
		"/lib/libnodetest.so",
		"/lib/libnode.so.1.2.3.4.5",
		"node-nsolid",
	}
	for _, s := range shouldNotMatch {
		assert.False(t, v8Regex.MatchString(s), "regex %s should not match %s",
			v8Regex.String(), s)
	}
}

func TestGetJsDispatchTableOffsetAarch64(t *testing.T) {
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
	code := []byte{
		0x28, 0x59, 0x01, 0xd0, 0x08, 0x39, 0x45, 0xf9,
		0x08, 0x01, 0x40, 0xf9, 0x00, 0x35, 0x59, 0xf9,
		0x08, 0x04, 0x00, 0xd1, 0x1f, 0x81, 0x00, 0xf1,
		0x49, 0x00, 0x00, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
		0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91,
		0x00, 0x03, 0x01, 0xf0, 0x00, 0x80, 0x2b, 0x91,
		0x01, 0x04, 0x01, 0xf0, 0x21, 0x7c, 0x2b, 0x91,
		0xa5, 0xed, 0x3f, 0x94,
	}
	off, ok := GetJsDispatchTableOffsetAarch64(code)
	assert.True(t, ok)
	assert.Equal(t, uint64(0x3268), off)

	// This is from a debug build.
	// 0x11780ac: stp x29, x30, [sp, #-0x20]!
	// 0x11780b0: str x19, [sp, #0x10]
	// 0x11780b4: mov x29, sp
	// 0x11780b8: adrp x8, #0x557e000
	// 0x11780bc: ldr x8, [x8, #0x480]
	// 0x11780c0: ldr x19, [x8]
	// 0x11780c4: ldr x8, [x19, #0x3270]
	// 0x11780c8: cbz x8, #0x11780dc ; _ZN2v88internal17ExternalReference25js_dispatch_table_addressEv+0x30
	// 0x11780cc: ldr x9, [x19, #0x3278]
	// 0x11780d0: ldr x9, [x9, #0x18]
	// 0x11780d4: cmp x9, x8
	// 0x11780d8: b.ne #0x1178100 ; _ZN2v88internal17ExternalReference25js_dispatch_table_addressEv+0x54
	// 0x11780dc: ldr x8, [x19, #0x3278]
	// 0x11780e0: cbz x8, #0x1178120 ; _ZN2v88internal17ExternalReference25js_dispatch_table_addressEv+0x74
	// 0x11780e4: ldr x0, [x19, #0x3270]
	// 0x11780e8: sub x8, x0, #1
	// 0x11780ec: cmp x8, #0x20
	// 0x11780f0: b.ls #0x1178148 ; _ZN2v88internal17ExternalReference25js_dispatch_table_addressEv+0x9c
	// 0x11780f4: ldr x19, [sp, #0x10]
	// 0x11780f8: ldp x29, x30, [sp], #0x20
	// 0x11780fc: ret
	// ... snip ...

	code = []byte{
		0xfd, 0x7b, 0xbe, 0xa9, 0xf3, 0x0b, 0x00, 0xf9,
		0xfd, 0x03, 0x00, 0x91, 0x28, 0x20, 0x02, 0xd0,
		0x08, 0x41, 0x42, 0xf9, 0x13, 0x01, 0x40, 0xf9,
		0x68, 0x3a, 0x59, 0xf9, 0xa8, 0x00, 0x00, 0xb4,
		0x69, 0x3e, 0x59, 0xf9, 0x29, 0x0d, 0x40, 0xf9,
		0x3f, 0x01, 0x08, 0xeb, 0x41, 0x01, 0x00, 0x54,
		0x68, 0x3e, 0x59, 0xf9, 0x08, 0x02, 0x00, 0xb4,
		0x60, 0x3a, 0x59, 0xf9, 0x08, 0x04, 0x00, 0xd1,
		0x1f, 0x81, 0x00, 0xf1, 0xc9, 0x02, 0x00, 0x54,
		0xf3, 0x0b, 0x40, 0xf9, 0xfd, 0x7b, 0xc2, 0xa8,
		0xc0, 0x03, 0x5f, 0xd6, 0x00, 0xa2, 0x01, 0xd0,
		0x00, 0x04, 0x32, 0x91, 0x02, 0xa2, 0x01, 0xd0,
		0x42, 0xb4, 0x32, 0x91, 0x61, 0x06, 0x80, 0x52,
		0x23, 0xe5, 0x73, 0x94, 0x68, 0x3e, 0x59, 0xf9,
		0x48, 0xfe, 0xff, 0xb5, 0x00, 0xa2, 0x01, 0xd0,
		0x00, 0x04, 0x32, 0x91, 0xa2, 0xa0, 0x01, 0xd0,
		0x42, 0x80, 0x0b, 0x91, 0x21, 0x07, 0x80, 0x52,
		0x1b, 0xe5, 0x73, 0x94, 0x60, 0x3a, 0x59, 0xf9,
		0x08, 0x04, 0x00, 0xd1, 0x1f, 0x81, 0x00, 0xf1,
		0x88, 0xfd, 0xff, 0x54, 0x00, 0xa2, 0x01, 0xd0,
		0x00, 0xb4, 0x30, 0x91, 0x22, 0xa0, 0x01, 0xd0,
		0x42, 0xb8, 0x08, 0x91, 0x03, 0xa2, 0x01, 0xd0,
		0x63, 0xc8, 0x2e, 0x91, 0x61, 0x54, 0x80, 0x52,
		0x95, 0xe4, 0x73, 0x94,
	}
	off, ok = GetJsDispatchTableOffsetAarch64(code)
	assert.True(t, ok)
	assert.Equal(t, uint64(0x3270), off)
}

func newTestV8Instance() *v8Instance {
	d := &v8Data{}
	vms := &d.vmStructs
	vms.Fixed.StringRepresentationMask = 0x0f
	vms.Fixed.StringEncodingMask = 0xf0
	vms.Fixed.SeqStringTag = 0x00
	vms.Fixed.ConsStringTag = 0x01
	vms.Fixed.ThinStringTag = 0x02
	vms.Fixed.OneByteStringTag = 0x20
	vms.Fixed.FirstNonstringType = 0xf0
	vms.String.Length = 4
	vms.SeqOneByteString.Chars = 8
	vms.ConsString.First = 8
	vms.ConsString.Second = 16
	vms.ThinString.Actual = 24
	vms.HeapObject.Map = 0
	vms.Map.InstanceType = 4
	vms.FixedArrayBase.Length = 8

	addrToType, err := freelru.New[libpf.Address, uint16](64, libpf.Address.Hash32)
	if err != nil {
		panic(err)
	}
	return &v8Instance{d: d, addrToType: addrToType}
}

func putUint64(buf []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(buf[off:off+8], v)
}

func putUint16(buf []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(buf[off:off+2], v)
}

func TestExtractStringLengthLimit(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 4096)
	// Advertise a ~4 GiB sequence string; extraction must fail without reading
	// or invoking the callback even once.
	binary.LittleEndian.PutUint32(buf[4:], 0xFFFFFFFF)
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	tag := uint16(i.d.vmStructs.Fixed.SeqStringTag | i.d.vmStructs.Fixed.OneByteStringTag)
	calls := 0
	_, err := i.extractString(0, tag, func(string) error { calls++; return nil },
		maxMemoizedStringBytes, maxStringDepth)
	require.Error(t, err)
	require.Zero(t, calls)
}

func TestExtractStringValid(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 4096)
	binary.LittleEndian.PutUint32(buf[4:], 6)
	copy(buf[8:], "abcdef")
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	tag := uint16(i.d.vmStructs.Fixed.SeqStringTag | i.d.vmStructs.Fixed.OneByteStringTag)
	got := ""
	_, err := i.extractString(0, tag, func(s string) error { got += s; return nil },
		maxMemoizedStringBytes, maxStringDepth)
	require.NoError(t, err)
	assert.Equal(t, "abcdef", got)
}

func TestExtractStringConsCycle(t *testing.T) {
	i := newTestV8Instance()
	const (
		A libpf.Address = 0x1000
		M libpf.Address = 0x2000
	)
	buf := make([]byte, 0x3000)
	putUint64(buf, int(A)+int(i.d.vmStructs.HeapObject.Map), uint64(M|HeapObjectTag))
	putUint16(buf, int(M)+int(i.d.vmStructs.Map.InstanceType),
		uint16(i.d.vmStructs.Fixed.ConsStringTag))
	putUint64(buf, int(A)+int(i.d.vmStructs.ConsString.First), uint64(A|HeapObjectTag))
	putUint64(buf, int(A)+int(i.d.vmStructs.ConsString.Second), uint64(A|HeapObjectTag))
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	// A self-referencing ConsString must be stopped by the depth bound instead
	// of exhausting the stack.
	_, err := i.extractString(A|HeapObjectTag, 0, func(string) error { return nil },
		maxSourceStringBytes, maxStringDepth)
	require.Error(t, err)
}

func TestReadFixedTableSizeLimit(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 256)
	// A huge SMI length whose product with itemSize would wrap a uint32.
	numItems := uint64(1) << 30
	binary.LittleEndian.PutUint64(buf[8:], numItems<<32)
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	_, err := i.readFixedTable(0, 8, 0)
	require.Error(t, err)
}
