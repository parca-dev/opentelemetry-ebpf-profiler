// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	sasstable "github.com/gnurizen/sass-table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	emCUDA      = 190
	ehdrSize    = 64
	shdrSize    = 64
	textAddr    = 0x1000
	testSMVer   = 90
	cudaVersion = 129 // what CUDA 12.9 writes into e_version
)

func TestOriginalCubinFileReads(t *testing.T) {
	data := make([]byte, 8203)
	for i := range data {
		data[i] = byte((i*31 + i/4096) % 251)
	}
	path := filepath.Join(t.TempDir(), "original.cubin")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	source, err := MatchCubinFile(uint32(os.Getpid()), path, data)
	require.NoError(t, err)
	for _, tc := range []struct {
		offset int64
		size   int
	}{
		{0, 16}, {4087, 27}, {8190, 13}, {8190, 20}, {8203, 1}, {-1, 16},
	} {
		t.Run(fmt.Sprintf("%d/%d", tc.offset, tc.size), func(t *testing.T) {
			got, want := make([]byte, tc.size), make([]byte, tc.size)
			n, err := source.ReadAt(got, tc.offset)
			if tc.offset < 0 {
				require.Error(t, err)
				require.Zero(t, n)
				return
			}
			wn, we := bytes.NewReader(data).ReadAt(want, tc.offset)
			require.Equal(t, we, err)
			require.Equal(t, wn, n)
			require.Equal(t, want, got)
		})
	}
}

func TestOriginalCubinFileChanges(t *testing.T) {
	data := buildCubin(t, cudaVersion, make([]byte, 16384))
	for _, change := range []string{"replace", "rewrite", "truncate", "delete"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original.cubin")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			source, err := MatchCubinFile(uint32(os.Getpid()), path, data)
			require.NoError(t, err)
			p := source.UploadProcess()
			f, err := p.OpenMappingFile(nil)
			require.NoError(t, err)
			defer f.Close()
			before, err := os.Stat(path)
			require.NoError(t, err)
			switch change {
			case "replace":
				require.NoError(t, os.Rename(path, path+".old"))
				require.NoError(t, os.WriteFile(path, data, 0o600))
			case "rewrite":
				wrong := bytes.Clone(data)
				wrong[8192] = 1 // Outside the FileID's header/trailer windows.
				id1, err := libpf.FileIDFromExecutableReader(bytes.NewReader(data))
				require.NoError(t, err)
				id2, err := libpf.FileIDFromExecutableReader(bytes.NewReader(wrong))
				require.NoError(t, err)
				require.Equal(t, id1, id2, "FileID alone cannot validate an original image")
				require.NoError(t, os.WriteFile(path, wrong, 0o600))
				require.NoError(t, os.Chtimes(path, before.ModTime(), before.ModTime()))
				_, err = MatchCubinFile(uint32(os.Getpid()), path, data)
				require.Error(t, err)
			case "truncate":
				require.NoError(t, os.Truncate(path, 64))
			case "delete":
				require.NoError(t, os.Remove(path))
			}
			// The source holds the original inode: replacing or unlinking the
			// path cannot change what it reads, but writing to the inode can.
			var instruction [16]byte
			_, readErr := source.ReadAt(instruction[:], 8192)
			upload, err := p.OpenMappingFile(nil)
			if change == "replace" || change == "delete" {
				require.NoError(t, readErr)
				require.Equal(t, data[8192:8208], instruction[:])
				require.NoError(t, err)
				got, err := io.ReadAll(upload.(io.Reader))
				require.NoError(t, err)
				want := bytes.Clone(data)
				binary.LittleEndian.PutUint32(want[20:], 1)
				require.Equal(t, want, got)
			} else {
				require.Error(t, readErr)
				require.Error(t, err)
			}
			// An already-open upload must also reject in-place changes.
			if change == "rewrite" || change == "truncate" {
				_, err = f.(io.ReaderAt).ReadAt(instruction[:], 8192)
				require.Error(t, err)
			}
		})
	}
}

// TestOriginalCubinProcessExit checks that instruction lookups and uploads
// keep reading the matched file after the process that loaded it exits, when
// its /proc/<pid>/root is gone.
func TestOriginalCubinProcessExit(t *testing.T) {
	data := buildCubin(t, cudaVersion, make([]byte, 8192))
	path := filepath.Join(t.TempDir(), "original.cubin")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	cmd := exec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	source, err := MatchCubinFile(uint32(cmd.Process.Pid), path, data)
	require.NoError(t, err)
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()
	_, err = os.Stat(fmt.Sprintf("/proc/%d/root", cmd.Process.Pid))
	require.Error(t, err, "process root must be gone")

	var instruction [16]byte
	_, err = source.ReadAt(instruction[:], 4096)
	require.NoError(t, err)
	require.Equal(t, data[4096:4112], instruction[:])
	upload, err := source.UploadProcess().OpenMappingFile(nil)
	require.NoError(t, err)
	got, err := io.ReadAll(upload.(io.Reader))
	require.NoError(t, err)
	want := bytes.Clone(data)
	binary.LittleEndian.PutUint32(want[20:], 1)
	require.Equal(t, want, got)
}

func TestOriginalCubinNamespace(t *testing.T) {
	if root := os.Getenv("CUBIN_TEST_CHROOT"); root != "" {
		require.NoError(t, syscall.Chroot(root))
		require.NoError(t, os.Chdir("/"))
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		t.Skip("chroot namespace test requires root")
	}
	root := t.TempDir()
	data := buildCubin(t, cudaVersion, []byte("application instruction bytes"))
	require.NoError(t, os.WriteFile(filepath.Join(root, "application.cubin"), data, 0o600))
	require.NoError(t, os.Symlink("/application.cubin", filepath.Join(root, "selected.cubin")))
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestOriginalCubinNamespace$")
	cmd.Env = append(os.Environ(), "CUBIN_TEST_CHROOT="+root)
	in, err := cmd.StdinPipe()
	require.NoError(t, err)
	out, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", line)
	source, err := MatchCubinFile(uint32(cmd.Process.Pid), "/selected.cubin", data)
	require.NoError(t, err, "absolute symlinks must resolve inside the target root")
	got := make([]byte, len(data))
	_, err = source.ReadAt(got, 0)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

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
	ra, ok := rac.(io.ReaderAt)
	require.True(t, ok, "OpenMappingFile result must implement io.ReaderAt")
	ef, err := elf.NewFile(ra)
	require.NoError(t, err)
	defer ef.Close()

	sec := ef.Section(".text")
	require.NotNil(t, sec)
	sdata, err := sec.Data()
	require.NoError(t, err)
	assert.Equal(t, text, sdata)

	assert.Equal(t, original, data, "OpenMappingFile modified the backing buffer")
}

// TestSMVersionFromFlags covers both e_flags layouts NVIDIA uses. Reading bits
// [8:15] unconditionally decoded a typical sm_90 cubin as 5, which is not a
// real SM version -- the opcode table lookup then missed silently and PC
// samples carried a stall reason but never an instruction mnemonic.
func TestSMVersionFromFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint32
		want  int
	}{
		// Legacy layout: SM in the low byte, feature flags above it.
		// 0x550 = TEXMODE_UNIFIED | 64BIT_ADDRESS | ACCELERATORS_V1.
		{"sm_90_with_feature_flags", 0x0055055a, 90},
		{"sm_90_bare", 0x0000005a, 90},
		{"sm_90a_accelerated", 0x0000085a, 90},
		{"sm_75", 0x0000054b, 75},
		{"sm_80", 0x00000550, 80},
		{"sm_89", 0x00000559, 89},
		{"sm_20_lower_bound", 0x00000014, 20},

		// Blackwell layout: SM at bits [8:15], low byte only ACCELERATORS.
		{"sm_100", 0x00006400, 100},
		{"sm_100a_accelerated", 0x00006408, 100},
		{"sm_120", 0x00007800, 120},
		{"sm_121", 0x00007900, 121},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, smVersionFromFlags(tc.flags))
		})
	}
}

// TestParseCubinELFSMVersion checks the version survives a full parse, and that
// what comes out is a version the SASS decoder actually has a table for --
// the property that actually matters for instruction mnemonics.
func TestParseCubinELFSMVersion(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint32
		want  int
	}{
		{"sm_90_h100", 0x0055055a, 90},
		{"sm_100_blackwell", 0x00006400, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildCubin(t, cudaVersion, []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
			binary.LittleEndian.PutUint32(data[elfFlagsOff:], tc.flags)

			smVersion, _, err := ParseCubinELF(data)
			require.NoError(t, err)
			assert.Equal(t, tc.want, smVersion)
			assert.Contains(t, sasstable.ArchTables, smVersion,
				"no SASS opcode table for decoded SM version")
		})
	}
}
