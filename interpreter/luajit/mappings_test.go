package luajit

import (
	"debug/elf"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type prefixKey struct {
	pid libpf.PID
	pfx lpm.Prefix
}

// ebpfMapsMockup implements the ebpf interface as test mockup
type ebpfMapsMockup struct {
	// interpreter.EbpfHandlerStubs
	prefixes map[prefixKey]lpm.Prefix
}

var _ interpreter.EbpfHandler = &ebpfMapsMockup{}

func (h *ebpfMapsMockup) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (m *ebpfMapsMockup) CoredumpTest() bool {
	return false
}

func (h *ebpfMapsMockup) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (h *ebpfMapsMockup) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (m *ebpfMapsMockup) UpdatePidInterpreterMapping(pid libpf.PID,
	pfx lpm.Prefix, _ uint8, _ host.FileID, _ uint64) error {
	m.prefixes[prefixKey{pid: pid, pfx: pfx}] = pfx
	return nil
}

func (m *ebpfMapsMockup) DeletePidInterpreterMapping(pid libpf.PID, pfx lpm.Prefix) error {
	delete(m.prefixes, prefixKey{pid: pid, pfx: pfx})
	return nil
}

func (h *ebpfMapsMockup) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

func (h *ebpfMapsMockup) UpdateExeIDToStackDeltas(
	host.FileID, []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	return 0, nil
}

func (h *ebpfMapsMockup) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (h *ebpfMapsMockup) UpdateStackDeltaPages(host.FileID, []uint16, uint16, uint64) error {
	return nil
}

func (h *ebpfMapsMockup) DeleteStackDeltaPage(host.FileID, uint64) error {
	return nil
}

func (h *ebpfMapsMockup) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix,
	fileID, bias uint64,
) error {
	return nil
}

func (h *ebpfMapsMockup) DeletePidPageMappingInfo(libpf.PID, []lpm.Prefix) (uint64, error) {
	return 0, nil
}

func (h *ebpfMapsMockup) CollectMetrics() []metrics.Metric {
	return nil
}

func (h *ebpfMapsMockup) SupportsLPMTrieBatchOperations() bool {
	return false
}

// TestSynchronizeMappings tests that if a mapping is realloc'd we do the right thing.
func TestSynchronizeMappings(t *testing.T) {
	for _, tc := range []struct {
		calls []process.RawMapping
	}{
		{[]process.RawMapping{
			{Vaddr: 0x2000, Length: 0x1000, Flags: elf.PF_X},
			{Vaddr: 0x1000, Length: 0x2000, Flags: elf.PF_X},
		}},
		{[]process.RawMapping{
			{Vaddr: 0x2000, Length: 0x1000, Flags: elf.PF_X},
			{Vaddr: 0x2000, Length: 0x2000, Flags: elf.PF_X},
		}},
	} {
		ebpf := &ebpfMapsMockup{prefixes: make(map[prefixKey]lpm.Prefix)}
		lj := &luajitInstance{
			jitRegions:  make(regionMap),
			prefixes:    make(map[regionKey][]lpm.Prefix),
			prefixesByG: make(map[libpf.Address][]lpm.Prefix),
		}
		for _, call := range tc.calls {
			err := lj.synchronizeMappings(ebpf, 0, []process.RawMapping{call})
			require.NoError(t, err)
		}
		initial := tc.calls[0]
		require.Empty(t, lj.jitRegions[initial])
		require.Empty(t, lj.prefixes[regionKey{initial.Vaddr, initial.Vaddr + initial.Length}])
		final := tc.calls[len(tc.calls)-1]
		require.NotEmpty(t, lj.jitRegions[final])
		require.NotEmpty(t, lj.prefixes[regionKey{final.Vaddr, final.Vaddr + final.Length}])
		err := lj.Detach(ebpf, 0)
		require.NoError(t, err)
		require.Empty(t, ebpf.prefixes)
	}
}
