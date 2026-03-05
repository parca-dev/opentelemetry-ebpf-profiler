// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu_test

import (
	"testing"
	"unique"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

// TestProgramNamesExist verifies that the eBPF program names used in cuda.go
// actually exist in the compiled eBPF collection. This catches bugs where
// the program names don't match the SEC() names in the .ebpf.c files.
func TestProgramNamesExist(t *testing.T) {
	// Load the eBPF collection
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err, "Failed to load eBPF collection spec")

	// Verify single-shot program names exist
	t.Run("SingleShotPrograms", func(t *testing.T) {
		progNames := []string{
			gpu.USDTProgCudaCorrelation,
			gpu.USDTProgCudaKernel,
			gpu.USDTProgCudaActivityBatch,
			gpu.USDTProgCudaActivityBatchTail,
		}

		for _, progName := range progNames {
			t.Run(progName, func(t *testing.T) {
				prog := coll.Programs[progName]
				require.NotNil(t, prog, "eBPF program %q not found in collection", progName)
				t.Logf("Found program %q", progName)
			})
		}
	})

	// Verify multi-attach program name exists
	t.Run("MultiAttachProgram", func(t *testing.T) {
		prog := coll.Programs[gpu.USDTProgCudaProbe]
		require.NotNil(t, prog, "eBPF program %q not found in collection", gpu.USDTProgCudaProbe)
		t.Logf("Found program %q", gpu.USDTProgCudaProbe)
	})
}

// packCudaID encodes a correlation ID and CBID into the AddressOrLineno value
// that ConvertTrace produces for CUDA kernel frames.
// Layout: correlationID in low 32 bits, cbid in high 32 bits.
func packCudaID(correlationID uint32, cbid int32) libpf.AddressOrLineno {
	return libpf.AddressOrLineno(uint64(correlationID) | (uint64(uint32(cbid)) << 32))
}

// makeMapping creates a FrameMapping with the given FileID high bits.
func makeMapping(fileIDHi uint64) libpf.FrameMapping {
	return libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID: libpf.NewFileID(fileIDHi, 0),
		}),
	})
}

// TestCUDATraceHashStability verifies that traceutil.HashTrace produces the same
// hash for CUDA traces from the same call site after the CUDA frame's
// AddressOrLineno is zeroed (as prepTrace does). Different correlation IDs
// encoded in AddressOrLineno must not affect the output hash.
func TestCUDATraceHashStability(t *testing.T) {
	mapping1 := makeMapping(0xaaaa)
	mapping2 := makeMapping(0xbbbb)

	makeTrace := func(correlationID uint32, cbid int32) *libpf.Trace {
		trace := &libpf.Trace{}
		trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
			Type:            libpf.CUDAKernelFrame,
			AddressOrLineno: packCudaID(correlationID, cbid),
		}))
		trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: 0x1000,
			Mapping:         mapping1,
		}))
		trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: 0x2000,
			Mapping:         mapping2,
		}))
		return trace
	}

	// Same call site, different correlation IDs, same CBID.
	tr1 := makeTrace(42, 1)
	tr2 := makeTrace(999, 1)

	hash1 := traceutil.HashTrace(tr1)
	hash2 := traceutil.HashTrace(tr2)
	assert.NotEqual(t, hash1, hash2,
		"before prepTrace: different cuda_ids should produce different hashes")

	// Same call site, same correlation ID, different CBID.
	tr3 := makeTrace(42, 7)
	hash3 := traceutil.HashTrace(tr3)
	assert.NotEqual(t, hash1, hash3,
		"before prepTrace: different CBIDs should produce different hashes")

	// After zeroing (simulating what prepTrace does): same call site → same hash.
	tr1.Frames[0] = unique.Make(libpf.Frame{Type: libpf.CUDAKernelFrame})
	tr2.Frames[0] = unique.Make(libpf.Frame{Type: libpf.CUDAKernelFrame})
	tr3.Frames[0] = unique.Make(libpf.Frame{Type: libpf.CUDAKernelFrame})

	hash1z := traceutil.HashTrace(tr1)
	hash2z := traceutil.HashTrace(tr2)
	hash3z := traceutil.HashTrace(tr3)
	assert.Equal(t, hash1z, hash2z,
		"after prepTrace: same call site with different correlation IDs must hash equal")
	assert.Equal(t, hash1z, hash3z,
		"after prepTrace: same call site with different CBIDs must hash equal")
}

// TestCUDATraceHashDiffers verifies that traces with different native stacks
// produce different hashes.
func TestCUDATraceHashDiffers(t *testing.T) {
	mapping := makeMapping(0xaaaa)

	trA := &libpf.Trace{}
	trA.Frames = append(trA.Frames, unique.Make(libpf.Frame{
		Type: libpf.CUDAKernelFrame,
	}))
	trA.Frames = append(trA.Frames, unique.Make(libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x1000,
		Mapping:         mapping,
	}))

	trB := &libpf.Trace{}
	trB.Frames = append(trB.Frames, unique.Make(libpf.Frame{
		Type: libpf.CUDAKernelFrame,
	}))
	trB.Frames = append(trB.Frames, unique.Make(libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x2000, // different addr
		Mapping:         mapping,
	}))

	hashA := traceutil.HashTrace(trA)
	hashB := traceutil.HashTrace(trB)
	assert.NotEqual(t, hashA, hashB,
		"different native stacks should produce different hashes")
}

// TestNonCUDATraceHashIncludesAddrOrLine verifies that for non-CUDA frames,
// AddressOrLineno is included in the hash.
func TestNonCUDATraceHashIncludesAddrOrLine(t *testing.T) {
	mapping := makeMapping(0xaaaa)

	makeNative := func(addr uint64) *libpf.Trace {
		trace := &libpf.Trace{}
		trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: libpf.AddressOrLineno(addr),
			Mapping:         mapping,
		}))
		return trace
	}

	tr1 := makeNative(0x1000)
	tr2 := makeNative(0x2000)

	hash1 := traceutil.HashTrace(tr1)
	hash2 := traceutil.HashTrace(tr2)
	assert.NotEqual(t, hash1, hash2,
		"non-CUDA traces with different addresses must have different hashes")
}

// makeSymbolizedTrace builds a libpf.Trace that looks like what ConvertTrace
// produces for a CUDA trace: frames before cudaFrameIdx are native, then the
// CUDAKernelFrame (with packed cuda_id in AddressOrLineno), then more native frames.
func makeSymbolizedTrace(cudaFrameIdx int, nativeFrameCount int,
	correlationID uint32, cbid int32) *libpf.Trace {
	trace := &libpf.Trace{}
	for i := range cudaFrameIdx + 1 + nativeFrameCount {
		if i == cudaFrameIdx {
			trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
				Type:            libpf.CUDAKernelFrame,
				AddressOrLineno: packCudaID(correlationID, cbid),
			}))
		} else {
			trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: libpf.AddressOrLineno(0x1000 * (i + 1)),
				Mapping:         makeMapping(uint64(i + 1)),
			}))
		}
	}
	return trace
}

func TestAddTraceAndTimes(t *testing.T) {
	const pid = libpf.PID(500)
	gpu.RegisterTestFixer(pid)
	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

	// Simulate: trace arrives first, timing arrives second.
	trace := makeSymbolizedTrace(0, 2, 100, 1) // CUDA frame at index 0
	meta := &samples.TraceEventMeta{PID: pid}

	var finished []gpu.CudaTraceOutput
	finishTrace := func(t *libpf.Trace, m *samples.TraceEventMeta) {
		finished = append(finished, gpu.CudaTraceOutput{Trace: t, Meta: m})
	}

	// InterceptTrace with no pending timing -> stored, finishTrace not called.
	gpu.InterceptTrace(trace, meta, finishTrace)
	assert.Empty(t, finished, "no timing yet, should produce no outputs")

	// Now timing arrives.
	kernelName := [256]byte{}
	copy(kernelName[:], "_Z9myKernelPfS_i")

	events := []gpu.CuptiTimingEvent{{
		Pid:        uint32(pid),
		Id:         100,
		Start:      1000,
		End:        2000,
		Dev:        0,
		Stream:     7,
		KernelName: kernelName,
	}}

	outputs := gpu.AddTimes(events)
	require.Len(t, outputs, 1, "timing matched, should produce one output")

	out := outputs[0]
	assert.Equal(t, int64(1000), out.Meta.OffTime, "OffTime should be End-Start")
	assert.Equal(t, "0", out.Trace.CustomLabels[libpf.Intern("cuda_device")].String())
	assert.Equal(t, "7", out.Trace.CustomLabels[libpf.Intern("cuda_stream")].String())

	// Verify the CUDA frame got the kernel name and zeroed AddressOrLineno.
	cudaFrame := out.Trace.Frames[0].Value()
	assert.Equal(t, libpf.CUDAKernelFrame, cudaFrame.Type)
	assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno,
		"correlation ID should be zeroed in output")
	assert.Equal(t, "_Z9myKernelPfS_i", cudaFrame.FunctionName.String())
}

func TestAddTimeThenTrace(t *testing.T) {
	const pid = libpf.PID(501)
	gpu.RegisterTestFixer(pid)
	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

	// Simulate: timing arrives first, trace arrives second.
	kernelName := [256]byte{}
	copy(kernelName[:], "_Z6squarePfS_")

	events := []gpu.CuptiTimingEvent{{
		Pid:        uint32(pid),
		Id:         200,
		Start:      5000,
		End:        8000,
		Dev:        1,
		KernelName: kernelName,
	}}

	// Timing arrives first -> stored, no outputs.
	outputs := gpu.AddTimes(events)
	assert.Empty(t, outputs)

	// Now trace arrives and matches — finishTrace called immediately.
	trace := makeSymbolizedTrace(0, 1, 200, 1)
	meta := &samples.TraceEventMeta{PID: pid}

	var finished []gpu.CudaTraceOutput
	finishTrace := func(t *libpf.Trace, m *samples.TraceEventMeta) {
		finished = append(finished, gpu.CudaTraceOutput{Trace: t, Meta: m})
	}

	gpu.InterceptTrace(trace, meta, finishTrace)
	require.Len(t, finished, 1)

	out := finished[0]
	assert.Equal(t, int64(3000), out.Meta.OffTime)
	assert.Equal(t, "1", out.Trace.CustomLabels[libpf.Intern("cuda_device")].String())

	cudaFrame := out.Trace.Frames[0].Value()
	assert.Equal(t, "_Z6squarePfS_", cudaFrame.FunctionName.String())
	assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno)
}

func TestCachedTemplateWithDifferentCorrelationIDs(t *testing.T) {
	const pid = libpf.PID(502)
	gpu.RegisterTestFixer(pid)
	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

	// Simulate two launches from the same call site with different correlation
	// IDs and different kernel names from timing. Trace arrives first each time.
	var finished []gpu.CudaTraceOutput
	finishTrace := func(t *libpf.Trace, m *samples.TraceEventMeta) {
		finished = append(finished, gpu.CudaTraceOutput{Trace: t, Meta: m})
	}

	for _, tc := range []struct {
		corrID     uint32
		kernelName string
		offTime    int64
	}{
		{corrID: 300, kernelName: "_Z7kernelAv", offTime: 100},
		{corrID: 301, kernelName: "_Z7kernelBv", offTime: 200},
	} {
		trace := makeSymbolizedTrace(0, 2, tc.corrID, 1)
		meta := &samples.TraceEventMeta{PID: pid}

		gpu.InterceptTrace(trace, meta, finishTrace)

		kn := [256]byte{}
		copy(kn[:], tc.kernelName)
		outputs := gpu.AddTimes([]gpu.CuptiTimingEvent{{
			Pid:        uint32(pid),
			Id:         tc.corrID,
			Start:      0,
			End:        uint64(tc.offTime),
			KernelName: kn,
		}})
		require.Len(t, outputs, 1, "corrID %d should produce one output", tc.corrID)

		out := outputs[0]
		assert.Equal(t, tc.offTime, out.Meta.OffTime)

		cudaFrame := out.Trace.Frames[0].Value()
		assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno,
			"correlation ID must not leak into output")
		// Verify each launch got its own kernel name.
		assert.Equal(t, tc.kernelName, cudaFrame.FunctionName.String(),
			"each launch should get its own kernel name")
	}
}

func TestCUDAFrameIdxNonZero(t *testing.T) {
	const pid = libpf.PID(503)
	gpu.RegisterTestFixer(pid)
	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

	// CUDA frame at index 2 (after two native frames).
	trace := makeSymbolizedTrace(2, 2, 400, 1) // [native, native, CUDA, native, native]
	meta := &samples.TraceEventMeta{PID: pid}

	var finished []gpu.CudaTraceOutput
	finishTrace := func(t *libpf.Trace, m *samples.TraceEventMeta) {
		finished = append(finished, gpu.CudaTraceOutput{Trace: t, Meta: m})
	}

	// Trace first, timing second.
	gpu.InterceptTrace(trace, meta, finishTrace)
	assert.Empty(t, finished)

	kernelName := [256]byte{}
	copy(kernelName[:], "_Z4testv")

	outputs := gpu.AddTimes([]gpu.CuptiTimingEvent{{
		Pid:        uint32(pid),
		Id:         400,
		Start:      0,
		End:        500,
		KernelName: kernelName,
	}})
	require.Len(t, outputs, 1)

	// The CUDA frame at index 2 should have the kernel name.
	cudaFrame := outputs[0].Trace.Frames[2].Value()
	assert.Equal(t, libpf.CUDAKernelFrame, cudaFrame.Type)
	assert.Equal(t, "_Z4testv", cudaFrame.FunctionName.String())

	// The non-CUDA frames should be untouched.
	for _, idx := range []int{0, 1, 3, 4} {
		f := outputs[0].Trace.Frames[idx].Value()
		assert.Equal(t, libpf.NativeFrame, f.Type,
			"frame %d should remain native", idx)
	}
}
