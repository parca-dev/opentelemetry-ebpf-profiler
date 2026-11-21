// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

//go:generate go run ./gencbids /usr/local/cuda/include cbid_names.go

import (
	"maps"
	"strconv"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Context values of a cuda_blocking_call trace. Must match
// CUDA_BLOCKING_CTX_* in support/ebpf/cuda.ebpf.c.
const (
	// BlockingCtxWeight is the blocked time the sample stands for, in ns:
	// the call's duration, or parcagpu's threshold for a sampled short call.
	BlockingCtxWeight = 0
	// BlockingCtxDuration is the call's own duration, in ns.
	BlockingCtxDuration = 1
	// BlockingCtxCall packs the signed cbid (low 32 bits) and the CUDA
	// device (high 32 bits).
	BlockingCtxCall = 2

	blockingCtxCount = 3
)

// blockingNoDevice is parcagpu's deviceId when the device is unknown.
const blockingNoDevice = ^uint32(0)

var cudaAPI libpf.String

func init() {
	cudaAPI = libpf.Intern("cuda_api")
}

// CbidName returns the CUDA API function a signed CUPTI callback ID stands
// for, as parcagpu's probes pass it: positive for the runtime API, negative
// for the driver API. Runtime names drop CUPTI's version suffix
// (cudaMalloc_v3020 is cudaMalloc). IDs newer than the generated table get
// a placeholder that still identifies them.
func CbidName(cbid int32) string {
	if cbid >= 0 {
		if int(cbid) < len(runtimeCbidNames) && runtimeCbidNames[cbid] != "" {
			return runtimeCbidNames[cbid]
		}
		return "cuda_runtime_cbid_" + strconv.Itoa(int(cbid))
	}
	id := -int64(cbid)
	if id < int64(len(driverCbidNames)) && driverCbidNames[id] != "" {
		return driverCbidNames[id]
	}
	return "cuda_driver_cbid_" + strconv.FormatInt(id, 10)
}

// BlockingCall is the call a cuda_blocking_call trace reports.
type BlockingCall struct {
	CBID       int32
	DeviceID   uint32 // 0xFFFFFFFF if parcagpu didn't know it
	WeightNs   uint64
	DurationNs uint64
}

// ParseBlockingCall decodes a cuda_blocking_call trace's context values.
func ParseBlockingCall(meta *samples.TraceEventMeta) (BlockingCall, bool) {
	cv := meta.ContextValues
	if len(cv) < blockingCtxCount {
		return BlockingCall{}, false
	}
	return BlockingCall{
		CBID:       int32(uint32(cv[BlockingCtxCall])),
		DeviceID:   uint32(cv[BlockingCtxCall] >> 32),
		WeightNs:   cv[BlockingCtxWeight],
		DurationNs: cv[BlockingCtxDuration],
	}, true
}

// DecorateBlockingTrace labels a cuda_blocking_call trace with the CUDA API
// call (cuda_api) and, when known, its device (cuda_device). The trace's
// value, the blocked time, is its first context value and needs no change.
// Call it before the trace is reported, while meta.ContextValues is valid.
func DecorateBlockingTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	call, ok := ParseBlockingCall(meta)
	if !ok {
		return
	}
	// The map may be the eBPF trace's own; don't write into it.
	labels := make(map[libpf.String]libpf.String, len(trace.CustomLabels)+2)
	maps.Copy(labels, trace.CustomLabels)
	labels[cudaAPI] = libpf.Intern(CbidName(call.CBID))
	if call.DeviceID != blockingNoDevice {
		labels[cudaDevice] = libpf.Intern(strconv.FormatUint(uint64(call.DeviceID), 10))
	}
	trace.CustomLabels = labels
}
