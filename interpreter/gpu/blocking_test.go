// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestCbidName(t *testing.T) {
	for _, tc := range []struct {
		cbid int32
		want string
	}{
		// Runtime cbids are positive and lose the _vNNNN suffix.
		{131, "cudaStreamSynchronize"},       // _v3020
		{239, "cudaStreamSynchronize_ptsz"},  // _ptsz_v7000
		{20, "cudaMalloc"},                   // _v3020
		{165, "cudaDeviceSynchronize"},       // _v3020
		{-126, "cuStreamSynchronize"},        // driver cbids are negative
		{-243, "cuMemAlloc_v2"},              // driver names are the symbols
		{-17, "cuCtxSynchronize"},            // low driver cbid
		{0, "cuda_runtime_cbid_0"},           // INVALID
		{100000, "cuda_runtime_cbid_100000"}, // newer than the table
		{-100000, "cuda_driver_cbid_100000"},
	} {
		assert.Equal(t, tc.want, CbidName(tc.cbid), "cbid %d", tc.cbid)
	}
}

func blockingMeta(cbid int32, dev uint32, weight, duration uint64) *samples.TraceEventMeta {
	return &samples.TraceEventMeta{
		ProfileType: ProfileTypeCudaBlocking,
		ContextValues: []uint64{weight, duration,
			uint64(uint32(cbid)) | uint64(dev)<<32},
	}
}

func TestParseBlockingCall(t *testing.T) {
	call, ok := ParseBlockingCall(blockingMeta(-126, 3, 10_000, 4_000))
	require.True(t, ok)
	assert.Equal(t, BlockingCall{CBID: -126, DeviceID: 3, WeightNs: 10_000,
		DurationNs: 4_000}, call)

	_, ok = ParseBlockingCall(&samples.TraceEventMeta{ContextValues: []uint64{1, 2}})
	assert.False(t, ok)
}

func TestDecorateBlockingTrace(t *testing.T) {
	ebpfLabels := map[libpf.String]libpf.String{libpf.Intern("k"): libpf.Intern("v")}
	trace := &libpf.Trace{CustomLabels: ebpfLabels}
	meta := blockingMeta(131, 1, 25_000, 25_000)
	DecorateBlockingTrace(trace, meta)
	assert.Equal(t, map[libpf.String]libpf.String{
		libpf.Intern("k"):           libpf.Intern("v"),
		libpf.Intern("cuda_api"):    libpf.Intern("cudaStreamSynchronize"),
		libpf.Intern("cuda_device"): libpf.Intern("1"),
	}, trace.CustomLabels)
	assert.Len(t, ebpfLabels, 1, "the eBPF trace's labels were modified")
	// The profile value is the weight.
	assert.Equal(t, []int64{25_000}, ProfileTypeCudaBlocking.AppendValues(nil, meta))

	// An unknown device gets no cuda_device label.
	trace = &libpf.Trace{}
	DecorateBlockingTrace(trace, blockingMeta(-126, ^uint32(0), 10_000, 300))
	assert.Equal(t, map[libpf.String]libpf.String{
		libpf.Intern("cuda_api"): libpf.Intern("cuStreamSynchronize"),
	}, trace.CustomLabels)

	// A trace without the context values is left alone.
	trace = &libpf.Trace{}
	DecorateBlockingTrace(trace, &samples.TraceEventMeta{})
	assert.Nil(t, trace.CustomLabels)
}
