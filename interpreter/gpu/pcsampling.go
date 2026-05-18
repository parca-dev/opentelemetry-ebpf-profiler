package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"time"
	"unique"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"

	sasstable "github.com/gnurizen/sass-table"
)

// HandlePCSample processes a single PC sample event. It correlates the sample
// with a CPU trace (if correlation ID is available), decodes the instruction
// mnemonic from the cubin's SASS code, and reports one gpupc trace per
// non-zero stall reason.
func HandlePCSample(ev *CuptiPCSampleEvent, rep reporter.TraceReporter) {
	cubinInfo, ok := LoadCubin(ev.Data.CubinCRC)
	if !ok {
		log.Debugf("[cuda] pc sample: cubin 0x%x not in cache, dropping", ev.Data.CubinCRC)
		return
	}

	kernelName := nullTermBytes(ev.FunctionName[:])

	// Decode instruction mnemonic from cubin .text section.
	mnemonic := decodeInstruction(cubinInfo, ev.Data.PCOffset)

	// Look up CPU trace for correlation. If found, emit immediately.
	// If not, store for deferred resolution when the trace arrives.
	var cpuTrace *SymbolizedCudaTrace
	if ev.CorrelationID != 0 {
		cpuTrace = LookupTraceForPCSample(libpf.PID(ev.Pid), ev.CorrelationID)
		if cpuTrace == nil {
			StorePendingPCSample(libpf.PID(ev.Pid), *ev, rep)
			return
		}
		if waitLogEnabled && cpuTrace.StoredAtNs != 0 {
			logWait("pc_sample", "matched_immediate",
				time.Now().UnixNano()-cpuTrace.StoredAtNs,
				ev.CorrelationID, ev.Pid)
		}
	}

	log.Debugf("[cuda] pc sample: pid=%d kernel=%q offset=0x%x mnemonic=%q corrID=%d stallReasons=%d cpuTrace=%v",
		ev.Pid, kernelName, ev.Data.PCOffset, mnemonic, ev.CorrelationID, ev.Data.StallReasonCount, cpuTrace != nil)

	// Build cubin file mapping for the offset frame.
	cubinName := fmt.Sprintf("cubin-%016x", cubinInfo.CRC)
	cubinMapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   cubinInfo.FileID,
			FileName: libpf.Intern(cubinName),
		}),
	})

	count := ev.Data.StallReasonCount
	if count > 64 {
		count = 64
	}

	for i := uint64(0); i < count; i++ {
		sr := ev.StallReasons[i]
		if sr.Samples == 0 {
			continue
		}

		stallName := LookupStallReason(ev.Pid, sr.Index)
		trace := buildGpuPCTrace(cpuTrace, cubinMapping, kernelName,
			ev.Data.PCOffset, mnemonic, stallName, sr.Index)

		meta := buildGpuPCMeta(cpuTrace, ev.Pid, int64(sr.Samples))

		trace.Hash = traceutil.HashTrace(trace)
		if err := rep.ReportTraceEvent(trace, meta); err != nil {
			log.Errorf("[cuda] failed to report GPU PC sample: %v", err)
		} else {
			log.Debugf("[cuda] reported gpupc: kernel=%q offset=0x%x mnemonic=%q stall=%q stallIdx=%d samples=%d",
				kernelName, ev.Data.PCOffset, mnemonic, stallName, sr.Index, sr.Samples)
		}
	}
}

// buildGpuPCTrace constructs a trace with GPU PC sampling frames, optionally
// prepended with CPU frames from the correlated trace.
//
// Frame order (leaf to root):
//
//	[0] stall_reason  — CUDAKernelFrame
//	[1] instruction   — CUDAKernelFrame (omitted if mnemonic is empty)
//	[2] offset        — NativeFrame with cubin Mapping
//	[3] kernel_name   — CUDAKernelFrame
//	[4..N] CPU frames — from correlated trace (if available)
func buildGpuPCTrace(cpuTrace *SymbolizedCudaTrace, cubinMapping libpf.FrameMapping,
	kernelName string, pcOffset uint64, mnemonic, stallName string, stallIndex uint32) *libpf.Trace {

	// Count GPU frames: kernel + offset + stall_reason, plus instruction if available.
	gpuFrameCount := 3
	if mnemonic != "" {
		gpuFrameCount = 4
	}

	// Count CPU frames (exclude the original CUDAKernelFrame).
	cpuFrameCount := 0
	if cpuTrace != nil {
		cpuFrameCount = len(cpuTrace.Trace.Frames) - 1 // exclude CUDAKernelFrame
		if cpuFrameCount < 0 {
			cpuFrameCount = 0
		}
	}

	trace := &libpf.Trace{
		Frames: make(libpf.Frames, 0, gpuFrameCount+cpuFrameCount),
	}

	// GPU frames (leaf to root order).
	// AddressOrLineno on the stall reason frame ensures HashTrace produces
	// distinct hashes per stall reason (the hash only covers FileID + AddressOrLineno).
	trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
		Type:            libpf.CUDAKernelFrame,
		FunctionName:    libpf.Intern(stallName),
		AddressOrLineno: libpf.AddressOrLineno(stallIndex),
	}))

	if mnemonic != "" {
		trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
			Type:         libpf.CUDAKernelFrame,
			FunctionName: libpf.Intern(mnemonic),
		}))
	}

	trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: libpf.AddressOrLineno(pcOffset),
		Mapping:         cubinMapping,
	}))

	trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
		Type:         libpf.CUDAKernelFrame,
		FunctionName: libpf.Intern(kernelName),
	}))

	// CPU frames from correlated trace (skip the CUDAKernelFrame).
	if cpuTrace != nil {
		for i, f := range cpuTrace.Trace.Frames {
			if i == cpuTrace.CUDAFrameIdx {
				continue
			}
			trace.Frames = append(trace.Frames, f)
		}
	}

	return trace
}

// buildGpuPCMeta constructs TraceEventMeta for a gpupc sample.
// If a CPU trace is available, metadata is copied from it.
//
// OffTime carries the GPU time attributable to this PC in nanoseconds when a
// GpuConfig has been received for the pid (period_ns × sample_count); otherwise
// the raw count, with a one-shot warn — the reporter's merged sample_type is
// nanoseconds, so unconfigured pids render as tiny slivers and the warning
// surfaces the cause.
func buildGpuPCMeta(cpuTrace *SymbolizedCudaTrace, pid uint32,
	sampleCount int64) *samples.TraceEventMeta {
	offTime := sampleCount
	if cfg, ok := LoadGpuConfig(pid); ok {
		if ns := cfg.NsPerSample(); ns > 0 {
			offTime = sampleCount * ns
		}
	} else {
		warnMissingGpuConfig(pid)
	}
	meta := &samples.TraceEventMeta{
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       libpf.PID(pid),
		Origin:    support.TraceOriginGpuPC,
		OffTime:   offTime,
	}
	if cpuTrace != nil && cpuTrace.Meta != nil {
		meta.Timestamp = cpuTrace.Meta.Timestamp
		meta.Comm = cpuTrace.Meta.Comm
		meta.ProcessName = cpuTrace.Meta.ProcessName
		meta.ExecutablePath = cpuTrace.Meta.ExecutablePath
		meta.ContainerID = cpuTrace.Meta.ContainerID
		meta.TID = cpuTrace.Meta.TID
		meta.CPU = cpuTrace.Meta.CPU
		meta.APMServiceName = cpuTrace.Meta.APMServiceName
		meta.EnvVars = cpuTrace.Meta.EnvVars
	}
	return meta
}

// decodeInstruction finds the .text section containing pcOffset and decodes
// the SASS instruction mnemonic using sasstable.
func decodeInstruction(info *CubinInfo, pcOffset uint64) string {
	if info.SMVersion == 0 || len(info.Texts) == 0 {
		return ""
	}

	// Try each .text section — find the one whose address range contains pcOffset.
	for _, ts := range info.Texts {
		if pcOffset >= ts.Addr && pcOffset < ts.Addr+uint64(len(ts.Data)) {
			off := pcOffset - ts.Addr
			if off+16 <= uint64(len(ts.Data)) {
				m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[off:])
				if m != "" {
					return m
				}
			}
		}
	}

	// Fallback: pcOffset might be function-relative. Try each section from offset 0.
	for _, ts := range info.Texts {
		if pcOffset+16 <= uint64(len(ts.Data)) {
			m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[pcOffset:])
			if m != "" {
				return m
			}
		}
	}

	return ""
}

func nullTermBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
