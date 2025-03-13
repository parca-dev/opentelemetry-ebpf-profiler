package probes

import (
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type probeSpec struct {
	label    string
	exe      string
	function string
	variable string
}

// TODO: load this from a file or config.yaml
var probes = []probeSpec{
	{"message", "hello", "burn", "message"},
	{"message", "hello2", "main", "message"},
}

type probe struct {
	addr     util.Range
	desc     int32 // 0 postive offset, 1 neg offset, 2 rdi, 3 rsi...
	spOffset int32
	id       int
}

var hello_data = []probe{
	{util.Range{Start: 0x1153, End: 0x1180}, 0, 0x8, 0}, // before strcpy...
}

var hello2_data = []probe{
	{util.Range{Start: 0x1200, End: 0x123f}, 0, 0x18, 1}, // before sub1...
}

type probeData struct {
	probes []probe
}

type probeInstance struct {
	probes []probe
	bias   libpf.Address
	interpreter.InstanceStubs
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	for _, p := range probes {
		if strings.HasSuffix(info.FileName(), p.exe) {
			fmt.Println("engaging prober on ", p.exe)
			pd := probeData{}
			if p.exe == "hello" {
				pd.probes = hello_data
			} else {
				pd.probes = hello2_data
			}
			return &pd, nil
		}
	}
	return nil, nil
}

func (pd probeData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	pcSave := pd.probes[0].addr.Start + uint64(bias) - 1
	for _, pd := range pd.probes {
		fmt.Printf("attaching probe 0x%x-0x%x\n", pd.addr.Start+uint64(bias), pd.addr.End+uint64(bias))
		prefixes, err := lpm.CalculatePrefixList(pd.addr.Start+uint64(bias), pd.addr.End+uint64(bias))
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindProbe, host.FileID(pcSave), uint64(pd.spOffset)<<32|uint64(pd.desc))
		}
	}
	return &probeInstance{probes: pd.probes, bias: bias}, nil
}

func (pi *probeInstance) Detach(ejsonbpf interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

// Symbolize requests symbolization of the given frame, and dispatches this symbolization
// to the collection agent. The frame's contents (frame type, file ID and line number)
// are appended to newTrace.
func (pi *probeInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame,
	trace *libpf.Trace) error {
	offset := uint64(frame.File) - uint64(pi.bias)
	id := int(frame.Lineno)
	var name string
	for _, pb := range pi.probes {
		if offset >= pb.addr.Start && offset < pb.addr.End {
			name = probes[pb.id].label
		}
	}
	//	fmt.Printf("symbolize %d:%x:%s\n", id, offset, name)
	// error?
	if name == "" {
		return nil
	}
	for k, v := range trace.CustomLabels {
		if strings.HasPrefix(k, "probe") {
			numStr := strings.TrimPrefix(k, "probe")
			// convert numStr to int
			num, err := strconv.Atoi(numStr)
			if err == nil && num == id {
				fmt.Printf("got probe: %d:%s=%s\n", num, name, v)
				delete(trace.CustomLabels, k)
				trace.CustomLabels[name] = v
			}
		}
	}
	return nil
}
