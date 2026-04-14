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

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
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

// ParseCubinELF parses a cubin ELF binary, extracting the SM version and
// executable .text sections. Cubins are GPU ELF files — we use debug/elf
// (not pfelf) since pfelf is host-architecture-specific.
func ParseCubinELF(data []byte) (int, []TextSection, error) {
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("parse cubin ELF: %w", err)
	}
	defer ef.Close()

	// SM version is in e_flags bits [8:15]. Go's debug/elf doesn't expose
	// e_flags, so we read it directly from the raw header (offset 48 for ELF64).
	var smVersion int
	if len(data) >= 52 {
		flags := binary.LittleEndian.Uint32(data[48:52])
		smVersion = int((flags >> 8) & 0xFF)
	}

	var texts []TextSection
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_PROGBITS &&
			s.Flags&elf.SHF_EXECINSTR != 0 &&
			strings.HasPrefix(s.Name, ".text") {
			sdata, err := s.Data()
			if err != nil {
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

type cubinReadAtCloser struct {
	*bytes.Reader
}

func (cubinReadAtCloser) Close() error { return nil }

// NewCubinProcess returns a minimal process.Process adapter wrapping in-memory
// cubin bytes. Used to report cubins to the ExecutableReporter.
func NewCubinProcess(pid uint32, data []byte) process.Process {
	return &cubinProcess{pid: pid, data: data}
}

func (p *cubinProcess) OpenMappingFile(_ *process.Mapping) (process.ReadAtCloser, error) {
	return cubinReadAtCloser{bytes.NewReader(p.data)}, nil
}

func (p *cubinProcess) PID() libpf.PID                             { return libpf.PID(p.pid) }
func (p *cubinProcess) GetMachineData() process.MachineData         { return process.MachineData{} }
func (p *cubinProcess) GetProcessMeta(process.MetaConfig) process.ProcessMeta {
	return process.ProcessMeta{}
}
func (p *cubinProcess) GetExe() (libpf.String, error) { return libpf.NullString, nil }
func (p *cubinProcess) GetMappings() ([]process.Mapping, uint32, error) {
	return nil, 0, nil
}
func (p *cubinProcess) GetThreads() ([]process.ThreadInfo, error) { return nil, nil }
func (p *cubinProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}
func (p *cubinProcess) GetMappingFileLastModified(_ *process.Mapping) int64 { return 0 }
func (p *cubinProcess) CalculateMappingFileID(_ *process.Mapping) (libpf.FileID, error) {
	return libpf.FileID{}, nil
}
func (p *cubinProcess) Close() error                             { return nil }
func (p *cubinProcess) OpenELF(_ string) (*pfelf.File, error) {
	return nil, errors.New("not supported")
}
