package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// TextSection holds a single executable .text section from a cubin ELF.
type TextSection struct {
	Name string
	Addr uint64
	Data []byte
}

// CubinInfo holds parsed cubin metadata cached for PC sample processing.
type CubinInfo struct {
	CRC       uint64
	FileID    libpf.FileID
	SMVersion int
	Texts     []TextSection
}

var cubinCache sync.Map // map[uint64]*CubinInfo (keyed by CRC)

// StoreCubin caches a CubinInfo by its CRC.
func StoreCubin(info *CubinInfo) {
	cubinCache.Store(info.CRC, info)
}

// LoadCubin looks up a cached CubinInfo by CRC.
func LoadCubin(crc uint64) (*CubinInfo, bool) {
	v, ok := cubinCache.Load(crc)
	if !ok {
		return nil, false
	}
	return v.(*CubinInfo), true
}

// HandleCubinEvent processes a single EVENT_TYPE_CUBIN_LOADED event from the
// cupti_events ringbuf.  It reads the cubin bytes from the producer process,
// parses the GPU ELF for SM version and .text sections, caches the metadata
// keyed by CRC, and (if a reporter is supplied) reports the cubin to the
// ExecutableReporter so the backend can resolve source lines from the cubin's
// DWARF info.  Repeat events for an already-cached CRC are dropped.
func HandleCubinEvent(ev *CuptiCubinEvent, rep reporter.ExecutableReporter) {
	if _, ok := LoadCubin(ev.CubinCRC); ok {
		return
	}
	data, err := ReadCubinFromProcess(ev.Pid, ev.CubinPtr, ev.CubinSize)
	if err != nil {
		log.Warnf("[cuda] cubin read failed pid=%d crc=0x%x: %v", ev.Pid, ev.CubinCRC, err)
		return
	}
	smVersion, texts, err := ParseCubinELF(data)
	if err != nil {
		log.Warnf("[cuda] cubin parse failed pid=%d crc=0x%x: %v", ev.Pid, ev.CubinCRC, err)
		return
	}
	// FileID is derived from the cubin CRC alone — cubins lack a build-id and
	// the CRC is already a content hash from the producer side.
	fileID := libpf.NewFileID(ev.CubinCRC, 0)
	StoreCubin(&CubinInfo{
		CRC:       ev.CubinCRC,
		FileID:    fileID,
		SMVersion: smVersion,
		Texts:     texts,
	})
	if rep == nil {
		return
	}
	cubinName := fmt.Sprintf("cubin-%016x", ev.CubinCRC)
	rep.ReportExecutable(&reporter.ExecutableMetadata{
		MappingFile: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   fileID,
			FileName: libpf.Intern(cubinName),
		}),
		Process: NewCubinProcess(ev.Pid, data),
		IsElf:   true,
	})
}

// ReadCubinFromProcess reads cubin bytes from a process's memory via /proc/pid/mem.
func ReadCubinFromProcess(pid uint32, ptr, size uint64) ([]byte, error) {
	if size == 0 || size > 256*1024*1024 {
		return nil, fmt.Errorf("cubin size %d out of range", size)
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, fmt.Errorf("open /proc/%d/mem: %w", pid, err)
	}
	defer f.Close()

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(ptr))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read cubin at 0x%x: %w", ptr, err)
	}
	return buf[:n], nil
}

// elfVersionOff is the offset of the 32-bit e_version field in an ELF64
// header, and evCurrent the only value debug/elf accepts there.
const (
	elfVersionOff = 0x14
	evCurrent     = 1
)

// cubinVersionReader presents a cubin with its e_version field normalized to
// EV_CURRENT. NVIDIA stores a toolkit-specific value there (CUDA 12.9, as
// shipped in nvcr.io/nvidia/pytorch:25.06-py3, emits 129) rather than
// EV_CURRENT, and debug/elf rejects the header outright over it. nvdisasm and
// the CUDA loader ignore the field, so normalizing it unconditionally is
// safe and keeps us working across toolkit releases that bump the value.
//
// The substitution happens on the way out of ReadAt so the caller's buffer is
// never modified: those bytes are hashed for the FileID and uploaded verbatim
// as the debug file, and rewriting them in place would corrupt both.
type cubinVersionReader struct{ base io.ReaderAt }

func (r cubinVersionReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.base.ReadAt(p, off)
	// Patch whatever part of [elfVersionOff, elfVersionOff+4) this read covers.
	for i := range int64(4) {
		if idx := elfVersionOff + i - off; idx >= 0 && idx < int64(n) {
			// Little-endian EV_CURRENT: 0x01 0x00 0x00 0x00.
			if i == 0 {
				p[idx] = evCurrent
			} else {
				p[idx] = 0
			}
		}
	}
	return n, err
}

// elfFlagsOff is the offset of the e_flags field in an ELF64 header, and the
// bounds below are the SM values NVIDIA has assigned under each e_flags ABI
// (see EF_CUDA_SM* in LLVM's BinaryFormat/ELF.h).
const (
	elfFlagsOff = 0x30

	// Lowest and highest SM values encoded in the low byte: sm_20 to sm_90.
	minLegacySM = 0x14
	maxLegacySM = 0x5a
)

// smVersionFromFlags extracts the SM version from a cubin's e_flags.
//
// NVIDIA uses two layouts. Up to sm_90 the version sits in the low byte
// (EF_CUDA_SM = 0xff); from Blackwell on it moved to bits [8:15]
// (EF_CUDA_SM_MASK = 0xff00, EF_CUDA_SM_OFFSET = 8).
//
// Reading bits [8:15] unconditionally is wrong for every pre-Blackwell cubin,
// because that is where the older ABI keeps feature flags:
// EF_CUDA_TEXMODE_UNIFIED (0x100), EF_CUDA_TEXMODE_INDEPENDENT (0x200),
// EF_CUDA_64BIT_ADDRESS (0x400), EF_CUDA_ACCELERATORS_V1 (0x800). A typical
// sm_90 cubin decodes to 5 that way, which is not a real SM version, so the
// opcode table lookup silently misses and no instruction mnemonic is reported.
//
// The two encodings are distinguishable: assigned pre-Blackwell values run
// 0x14..0x5a, while in the new ABI the low byte carries only
// EF_CUDA_ACCELERATORS (0x8). So a low byte in the legacy range identifies the
// old layout, and anything else means the version is in the high byte.
func smVersionFromFlags(flags uint32) int {
	if lo := int(flags & 0xFF); lo >= minLegacySM && lo <= maxLegacySM {
		return lo
	}
	return int((flags >> 8) & 0xFF)
}

// ParseCubinELF parses a cubin ELF binary, extracting the SM version and
// executable .text sections. Cubins are GPU ELF files — we use debug/elf
// (not pfelf) since pfelf is host-architecture-specific.
func ParseCubinELF(data []byte) (int, []TextSection, error) {
	ef, err := elf.NewFile(cubinVersionReader{bytes.NewReader(data)})
	if err != nil {
		return 0, nil, fmt.Errorf("parse cubin ELF: %w", err)
	}
	defer ef.Close()

	if len(data) >= elfVersionOff+4 {
		if v := binary.LittleEndian.Uint32(data[elfVersionOff : elfVersionOff+4]); v != evCurrent {
			log.Debugf("[cuda] cubin has non-standard ELF e_version %d (toolkit-specific)", v)
		}
	}

	// The SM version lives in e_flags. Go's debug/elf doesn't expose e_flags,
	// so we read it directly from the raw header (offset 48 for ELF64).
	var smVersion int
	if len(data) >= elfFlagsOff+4 {
		smVersion = smVersionFromFlags(binary.LittleEndian.Uint32(
			data[elfFlagsOff : elfFlagsOff+4]))
	}

	var texts []TextSection
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_PROGBITS &&
			s.Flags&elf.SHF_EXECINSTR != 0 &&
			strings.HasPrefix(s.Name, ".text") {
			sdata, err := s.Data()
			if err != nil {
				log.Warnf("[cuda] error reading cubin elf section data: %v", err)
				continue
			}
			texts = append(texts, TextSection{
				Name: s.Name,
				Addr: s.Addr,
				Data: sdata,
			})
		}
	}

	return smVersion, texts, nil
}

// cubinProcess is a minimal process.Process adapter for reporting cubins
// to the ExecutableReporter. Only OpenMappingFile is meaningful — the rest
// are stubs since parca-agent's ReportExecutable only calls OpenMappingFile.
type cubinProcess struct {
	pid  uint32
	data []byte
}

// cubinReadAtCloser hands out the cubin with e_version normalized, exactly as
// ParseCubinELF sees it. Everything downstream of OpenMappingFile parses these
// bytes with debug/elf too -- parca-agent's symbol uploader runs them through
// elfwriter to extract debuginfo -- and would otherwise hit the same
// "mismatched ELF version" rejection that ParseCubinELF works around.
type cubinReadAtCloser struct {
	cubinVersionReader
}

func (cubinReadAtCloser) Close() error { return nil }

// NewCubinProcess returns a minimal process.Process adapter wrapping in-memory
// cubin bytes. Used to report cubins to the ExecutableReporter.
func NewCubinProcess(pid uint32, data []byte) process.Process {
	return &cubinProcess{pid: pid, data: data}
}

func (p *cubinProcess) OpenMappingFile(_ *process.RawMapping) (process.ReadAtCloser, error) {
	return cubinReadAtCloser{cubinVersionReader{bytes.NewReader(p.data)}}, nil
}

func (p *cubinProcess) PID() libpf.PID                      { return libpf.PID(p.pid) }
func (p *cubinProcess) GetMachineData() process.MachineData { return process.MachineData{} }
func (p *cubinProcess) GetProcessMeta([]process.MetaEnricher) process.Meta {
	return process.Meta{}
}
func (p *cubinProcess) GetExe() (libpf.String, error) { return libpf.NullString, nil }
func (p *cubinProcess) IterateMappings(_ func(m process.RawMapping) bool) (uint32, error) {
	return 0, nil
}
func (p *cubinProcess) GetThreads() ([]process.ThreadInfo, error) { return nil, nil }
func (p *cubinProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}
func (p *cubinProcess) GetMappingFileLastModified(_ *process.RawMapping) int64 { return 0 }
func (p *cubinProcess) CalculateMappingFileID(_ *process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, nil
}
func (p *cubinProcess) Close() error { return nil }
func (p *cubinProcess) OpenELF(_ string) (*pfelf.File, error) {
	return nil, errors.New("not supported")
}
