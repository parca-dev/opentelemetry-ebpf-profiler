package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"hash/fnv"
	"time"
	"unique"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"

	sasstable "github.com/gnurizen/sass-table"
)

// Comes from cupti_bpf.h from parcagpu
const maxStallReasons = 64

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

	// Transient: kernelName is interned (copied) before ev goes out of scope.
	kernelName := pfunsafe.ToString(nullTerm(ev.FunctionName[:]))

	// Decode instruction mnemonic from cubin .text section.
	mnemonic := decodeInstruction(cubinInfo, kernelName, ev.Data.PCOffset)

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

	log.Debugf("[cuda] pc sample: pid=%d kernel=%q funcIdx=%d offset=0x%x mnemonic=%q corrID=%d stallReasons=%d cpuTrace=%v",
		ev.Pid, kernelName, ev.Data.FunctionIndex, ev.Data.PCOffset, mnemonic, ev.CorrelationID,
		ev.Data.StallReasonCount, cpuTrace != nil)

	// Build cubin file mapping for the offset frame.
	//
	// The frame is keyed by a PER-FUNCTION FileID, not the per-cubin FileID:
	// CUPTI reports pcOffset relative to the start of the kernel, and ptxas
	// lays every kernel 0-based, so within one cubin offset 0x10 exists in
	// every kernel. Keying on (cubinFileID, offset) alone would alias them.
	// funcFileID folds the kernel name into the key so each kernel resolves to
	// its own debuginfo (the backend partitions the cubin the same way via
	// PerFunctionCubinPCs). The offset itself stays 0-based — unchanged.
	cubinName := fmt.Sprintf("cubin-%016x:%s", cubinInfo.CRC, kernelName)
	cubinMapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   funcFileID(cubinInfo.CRC, cubinInfo.FileID, kernelName),
			FileName: libpf.Intern(cubinName),
		}),
	})

	count := min(ev.Data.StallReasonCount, maxStallReasons)

	for i := range count {
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

// funcFileID derives the per-function FileID for a GPU PC sample frame.
//
// The high word carries the cubin CRC (so the backend can recover which cubin
// this is) and the low word is a stable FNV-1a hash of the mangled kernel name,
// which the backend reproduces from the cubin's symbol table when it partitions
// the cubin in PerFunctionCubinPCs. Keep this hashing in sync with the backend.
//
// When the kernel name is unavailable we fall back to the per-cubin FileID
// (low word 0) so symbolization degrades to the old behavior rather than
// keying on a hash of the empty string.
func funcFileID(cubinCRC uint64, cubinFileID libpf.FileID, functionName string) libpf.FileID {
	if functionName == "" {
		return cubinFileID
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(functionName))
	return libpf.NewFileID(cubinCRC, h.Sum64())
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
	kernelName string, pcOffset uint64, mnemonic string, stallName libpf.String,
	stallIndex uint32) *libpf.Trace {

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
		FunctionName:    stallName,
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
// OffTime carries the raw PC sample count for this (pid, trace). The reporter
// pairs it with the per-pid GpuConfig (via LoadGpuConfig) to set the profile
// period to ns_per_sample, so a "count" sample_type stays mathematically
// convertible to GPU nanoseconds via value × period.
func buildGpuPCMeta(cpuTrace *SymbolizedCudaTrace, pid uint32,
	sampleCount int64) *samples.TraceEventMeta {
	meta := &samples.TraceEventMeta{
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       libpf.PID(pid),
		Origin:    support.TraceOriginGpuPC,
		OffTime:   sampleCount,
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

// decodeInstruction decodes the SASS mnemonic of the instruction at pcOffset in
// the cubin. CUPTI reports pcOffset relative to the start of functionName, and
// ptxas emits one ".text.<mangled-name>" section per function starting at the
// function base, so when functionName names such a section we can index it
// directly — an exact, layout-independent lookup.
//
// If the name doesn't resolve (empty name, or an unconventional cubin layout
// where functions share a .text section), we fall back to guessing: first
// treating pcOffset as a section-absolute address, then as a function-relative
// offset into each section.
func decodeInstruction(info *CubinInfo, functionName string, pcOffset uint64) string {
	if info.SMVersion == 0 || len(info.Texts) == 0 {
		return ""
	}

	// Deterministic path: decode at pcOffset within the function's own section.
	if functionName != "" {
		want := ".text." + functionName
		for _, ts := range info.Texts {
			if ts.Name != want {
				continue
			}
			if pcOffset+16 > uint64(len(ts.Data)) {
				break // right section, but offset is out of range; fall back
			}
			// Authoritative: this is the function's section, so return whatever
			// it decodes to rather than guessing against other sections.
			return sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[pcOffset:])
		}
	}

	// Fallback: pcOffset as a section-absolute address.
	for _, ts := range info.Texts {
		if pcOffset >= ts.Addr && pcOffset < ts.Addr+uint64(len(ts.Data)) {
			off := pcOffset - ts.Addr
			if off+16 <= uint64(len(ts.Data)) {
				if m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[off:]); m != "" {
					return m
				}
			}
		}
	}

	// Fallback: pcOffset as a function-relative offset into each section.
	for _, ts := range info.Texts {
		if pcOffset+16 <= uint64(len(ts.Data)) {
			if m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[pcOffset:]); m != "" {
				return m
			}
		}
	}

	return ""
}
