// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"debug/elf"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestDecodeNodeVersionAddress(t *testing.T) {
	tests := map[string]struct {
		machine elf.Machine
		addr    uint64
		code    []byte
		want    uint64
	}{
		"node 22.23.4 linux x64": {
			machine: elf.EM_X86_64, addr: 0xf6ac10, want: 0x3437480,
			code: []byte{
				0x48, 0x85, 0xff, 0x74, 0x4b, // test rdi,rdi; je error
				0x48, 0x85, 0xf6, 0x74, 0x26, // test rsi,rsi; je error
				0x66, 0x0f, 0xef, 0xc0, // pxor xmm0,xmm0
				0x48, 0xc7, 0x06, 0x80, 0x74, 0x43, 0x03, // mov qword [rsi],0x3437480
			},
		},
		"x64 PIE": {
			machine: elf.EM_X86_64, addr: 0x1155, want: 0x3db8,
			code: []byte{
				0x48, 0x8d, 0x05, 0x5c, 0x2c, 0x00, 0x00, // lea rax,[rip+0x2c5c]
				0x48, 0x89, 0x06, // mov [rsi],rax
			},
		},
		"arm64 ADR": {
			machine: elf.EM_AARCH64, addr: 0x21029c, want: 0x2001e8,
			code: []byte{
				0x68, 0xfa, 0xf7, 0x10, // adr x8,0x2001e8
				0x28, 0x00, 0x00, 0xf9, // str x8,[x1]
			},
		},
		"arm64 ADRP ADD": {
			machine: elf.EM_AARCH64, addr: 0x1000, want: 0x1234,
			code: []byte{
				0x08, 0x00, 0x00, 0x90, // adrp x8,0x1000
				0x08, 0xd1, 0x08, 0x91, // add x8,x8,#0x234
				0x28, 0x00, 0x00, 0xf9, // str x8,[x1]
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			addr, err := decodeNodeVersionAddress(tc.machine, tc.code, tc.addr)
			require.NoError(t, err)
			assert.Equal(t, tc.want, addr)
		})
	}
}

func TestDecodeNodeVersionAddressRejectsUnrecognizedCode(t *testing.T) {
	for name, code := range map[string][]byte{
		"empty":          nil,
		"truncated":      {0x48, 0x8d},
		"wrong argument": {0x48, 0xc7, 0x07, 0x80, 0x74, 0x43, 0x03, 0xc3},
		"narrow store":   {0xc7, 0x06, 0x80, 0x74, 0x43, 0x03, 0xc3},
		"after return":   {0xc3, 0x48, 0xc7, 0x06, 0x80, 0x74, 0x43, 0x03},
		"after call":     {0xe8, 0, 0, 0, 0, 0x48, 0xc7, 0x06, 0x80, 0x74, 0x43, 0x03},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeNodeVersionAddress(elf.EM_X86_64, code, 0x1000)
			require.Error(t, err)
		})
	}
	_, err := decodeNodeVersionAddress(elf.EM_RISCV, nil, 0)
	require.Error(t, err)
}

func TestDecodeCurrentIsolateOffset(t *testing.T) {
	tests := map[string]struct {
		machine elf.Machine
		code    []byte
		want    int64
	}{
		"x64 direct": {
			machine: elf.EM_X86_64, want: -8,
			code: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, 0xc3},
		},
		"x64 register": {
			machine: elf.EM_X86_64, want: -8,
			code: []byte{
				0x48, 0xc7, 0xc0, 0xf8, 0xff, 0xff, 0xff, // mov rax,-8
				0x64, 0x48, 0x8b, 0x00, 0xc3, // mov rax,fs:[rax]; ret
			},
		},
		"arm64 local exec": {
			machine: elf.EM_AARCH64, want: 16,
			code: []byte{
				0x48, 0xd0, 0x3b, 0xd5, // mrs x8,TPIDR_EL0
				0x08, 0x01, 0x40, 0x91, // add x8,x8,#0,lsl #12
				0x08, 0x41, 0x00, 0x91, // add x8,x8,#16
				0x00, 0x01, 0x40, 0xf9, // ldr x0,[x8]
				0xc0, 0x03, 0x5f, 0xd6, // ret
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			offset, err := decodeCurrentIsolateOffset(&pfelf.File{Machine: tc.machine}, tc.code, 0x1000)
			require.NoError(t, err)
			assert.Equal(t, tc.want, offset)
		})
	}
	// A normal memory load is not TLS. Nor may a value survive an unknown call.
	for _, code := range [][]byte{
		{0x48, 0x8b, 0x00, 0xc3},
		{0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, 0xe8, 0, 0, 0, 0, 0xc3},
	} {
		_, err := decodeCurrentIsolateOffset(&pfelf.File{Machine: elf.EM_X86_64}, code, 0x1000)
		require.Error(t, err)
	}
}

// Compile the same public accessors with both compilers and executable models.
// Compare the decoder result against the symbols before stripping, then verify
// custom-label initialization with neither private symbol available.
func TestCustomLabelsStrippedExecutable(t *testing.T) {
	for _, compiler := range []string{"g++", "clang++"} {
		t.Run(compiler, func(t *testing.T) {
			cc, err := exec.LookPath(compiler)
			if err != nil {
				t.Skipf("%s unavailable: %v", compiler, err)
			}
			strip, err := exec.LookPath("strip")
			require.NoError(t, err)
			for _, model := range []string{"-pie", "-no-pie"} {
				t.Run(model, func(t *testing.T) {
					testCustomLabelsExecutable(t, cc, strip, []string{"-fPIE", model})
				})
			}
		})
	}
}

func TestCustomLabelsStrippedArm64Executable(t *testing.T) {
	for _, tool := range []string{"clang++", "ld.lld", "llvm-objcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable: %v", tool, err)
		}
	}
	testCustomLabelsExecutable(t, "clang++", "llvm-objcopy", []string{
		"--target=aarch64-linux-gnu", "-fuse-ld=lld", "-nostdlib",
		"-fPIE", "-pie", "-ftls-model=local-exec", "-Wl,-e,main",
	})
}

func testCustomLabelsExecutable(t *testing.T, compiler, strip string, flags []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node")
	args := append([]string{"-O2", "-fvisibility=hidden", "-Wl,--export-dynamic",
		"testdata/customlabels.cc", "-o", path}, flags...)
	out, err := exec.Command(compiler, args...).CombinedOutput()
	require.NoError(t, err, "%s", out)
	ef, err := pfelf.Open(path)
	require.NoError(t, err)
	var syms relevantSymbols
	require.NoError(t, syms.scan(ef))
	require.NotNil(t, syms.NodeVersion)
	require.NotNil(t, syms.CurrentIsolate)
	var expected, decoded v8Data
	require.NoError(t, expected.loadNodeClData(ef, syms))
	require.NoError(t, decoded.loadNodeClData(ef, relevantSymbols{}))
	assert.Equal(t, expected.isolateSym, decoded.isolateSym)
	require.NoError(t, ef.Close())
	out, err = exec.Command(strip, "--strip-all", path).CombinedOutput()
	require.NoError(t, err, "%s", out)
	ef, err = pfelf.Open(path)
	require.NoError(t, err)
	defer ef.Close()
	err = ef.VisitSymbols(func(libpf.Symbol) bool { return true })
	require.ErrorIs(t, err, pfelf.ErrSectionNotPresent)
	_, err = ef.LookupSymbol("_ZN2v88internal18g_current_isolate_E")
	require.Error(t, err)
	require.NoError(t, decoded.loadNodeClData(ef, relevantSymbols{}))
	assert.Equal(t, expected.isolateSym, decoded.isolateSym)
	assert.Equal(t, expected.cpedOffset, decoded.cpedOffset)
	assert.Equal(t, expected.wrappedObjectOffset, decoded.wrappedObjectOffset)

	tls, err := ef.TLS()
	require.NoError(t, err)
	tls.Memsz = 0
	_, err = currentIsolateOffset(ef, nil)
	require.Error(t, err, "a decoded offset must belong to the executable TLS block")
}
