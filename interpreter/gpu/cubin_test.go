// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emCUDA      = 190
	ehdrSize    = 64
	shdrSize    = 64
	textAddr    = 0x1000
	testSMVer   = 90
	cudaVersion = 129 // what CUDA 12.9 writes into e_version
)

// buildCubin assembles a minimal ELF64 shaped like an NVIDIA cubin: e_version
// carries eVersion, and e_flags encodes the SM version in bits [8:15].
func buildCubin(t *testing.T, eVersion uint32, textData []byte) []byte {
	t.Helper()

	shstrtab := []byte("\x00.text\x00.shstrtab\x00")
	const (
		textNameOff     = 1
		shstrtabNameOff = 7
	)

	textOff := uint64(ehdrSize)
	shstrtabOff := textOff + uint64(len(textData))
	shoff := shstrtabOff + uint64(len(shstrtab))

	buf := make([]byte, shoff+3*shdrSize)
	le := binary.LittleEndian

	// ELF identification.
	copy(buf, []byte{0x7f, 'E', 'L', 'F'})
	buf[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	buf[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	buf[elf.EI_VERSION] = byte(elf.EV_CURRENT) // valid; the 32-bit field is not
	buf[elf.EI_OSABI] = 0x33                   // ELFOSABI_CUDA

	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], emCUDA)
	le.PutUint32(buf[elfVersionOff:], eVersion)
	le.PutUint32(buf[48:], uint32(testSMVer)<<8) // e_flags
	le.PutUint16(buf[52:], ehdrSize)             // e_ehsize
	le.PutUint64(buf[40:], shoff)
	le.PutUint16(buf[58:], shdrSize) // e_shentsize
	le.PutUint16(buf[60:], 3)        // e_shnum
	le.PutUint16(buf[62:], 2)        // e_shstrndx

	copy(buf[textOff:], textData)
	copy(buf[shstrtabOff:], shstrtab)

	putShdr := func(idx int, name uint32, typ elf.SectionType, flags elf.SectionFlag,
		addr, off, size uint64) {
		s := buf[shoff+uint64(idx*shdrSize):]
		le.PutUint32(s[0:], name)
		le.PutUint32(s[4:], uint32(typ))
		le.PutUint64(s[8:], uint64(flags))
		le.PutUint64(s[16:], addr)
		le.PutUint64(s[24:], off)
		le.PutUint64(s[32:], size)
	}
	putShdr(0, 0, elf.SHT_NULL, 0, 0, 0, 0)
	putShdr(1, textNameOff, elf.SHT_PROGBITS, elf.SHF_ALLOC|elf.SHF_EXECINSTR,
		textAddr, textOff, uint64(len(textData)))
	putShdr(2, shstrtabNameOff, elf.SHT_STRTAB, 0, 0, shstrtabOff, uint64(len(shstrtab)))

	return buf
}

// TestParseCubinELFNonStandardVersion is the regression test for cubins from
// recent CUDA toolkits, which debug/elf rejected with "mismatched ELF version".
func TestParseCubinELFNonStandardVersion(t *testing.T) {
	text := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")

	for _, tc := range []struct {
		name     string
		eVersion uint32
	}{
		{"cuda_12_9", cudaVersion},
		{"standard", 1},
		{"future_toolkit", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildCubin(t, tc.eVersion, text)
			original := bytes.Clone(data)

			smVersion, texts, err := ParseCubinELF(data)
			require.NoError(t, err)
			assert.Equal(t, testSMVer, smVersion)
			require.Len(t, texts, 1)
			assert.Equal(t, ".text", texts[0].Name)
			assert.Equal(t, uint64(textAddr), texts[0].Addr)
			assert.Equal(t, text, texts[0].Data)

			// The caller hashes these bytes for the FileID and uploads them as
			// the debug file, so parsing must not have rewritten the header.
			assert.Equal(t, original, data, "ParseCubinELF modified the input buffer")
		})
	}
}

// TestParseCubinELFRejectsGarbage confirms normalizing e_version does not make
// the parser accept input that is not an ELF at all.
func TestParseCubinELFRejectsGarbage(t *testing.T) {
	_, _, err := ParseCubinELF(bytes.Repeat([]byte{0xab}, 512))
	require.Error(t, err)
}

// TestCubinVersionReaderPartialReads exercises the offsets debug/elf actually
// reads at, plus reads that straddle or miss the patched window entirely.
func TestCubinVersionReaderPartialReads(t *testing.T) {
	data := buildCubin(t, cudaVersion, []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
	r := cubinVersionReader{bytes.NewReader(data)}

	for _, tc := range []struct {
		name     string
		off      int64
		size     int
		wantAt14 []byte // expected bytes of the e_version window, if covered
	}{
		{"full_header", 0, ehdrSize, []byte{1, 0, 0, 0}},
		{"exact_window", elfVersionOff, 4, []byte{1, 0, 0, 0}},
		{"straddle_start", elfVersionOff - 2, 4, []byte{1, 0}},
		{"straddle_end", elfVersionOff + 2, 4, []byte{0, 0}},
		{"before_window", 0, 4, nil},
		{"after_window", elfVersionOff + 4, 8, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.size)
			n, err := r.ReadAt(p, tc.off)
			require.NoError(t, err)
			require.Equal(t, tc.size, n)

			// Compare against the raw bytes, with the window substituted.
			want := bytes.Clone(data[tc.off : tc.off+int64(tc.size)])
			switch tc.name {
			case "full_header", "exact_window":
				copy(want[elfVersionOff-tc.off:], []byte{1, 0, 0, 0})
			case "straddle_start":
				copy(want[2:], []byte{1, 0})
			case "straddle_end":
				copy(want[0:], []byte{0, 0})
			}
			assert.Equal(t, want, p)
		})
	}
}

// TestCubinProcessOpenMappingFileParses covers the bytes handed to downstream
// consumers rather than to ParseCubinELF. parca-agent's symbol uploader opens
// the cubin through this path and runs it through elfwriter, which parses it
// with debug/elf and failed the same way ParseCubinELF used to:
//
//	Failed to upload with fileName 'cubin-000000000ee1858b' and buildID '':
//	extract debuginfo: initialize nullifying writer: error reading ELF file:
//	mismatched ELF version 'EV_CURRENT+128' in record at byte 0x0
func TestCubinProcessOpenMappingFileParses(t *testing.T) {
	text := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")
	data := buildCubin(t, cudaVersion, text)
	original := bytes.Clone(data)

	p := NewCubinProcess(1234, data)
	rac, err := p.OpenMappingFile(nil)
	require.NoError(t, err)
	defer rac.Close()

	// debug/elf is what every downstream consumer reaches for.
	ef, err := elf.NewFile(rac)
	require.NoError(t, err)
	defer ef.Close()

	sec := ef.Section(".text")
	require.NotNil(t, sec)
	sdata, err := sec.Data()
	require.NoError(t, err)
	assert.Equal(t, text, sdata)

	assert.Equal(t, original, data, "OpenMappingFile modified the backing buffer")
}
