// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func usdt(names ...string) []pfelf.USDTProbe {
	probes := []pfelf.USDTProbe{{Provider: "other", Name: "cuda_correlation"}}
	for _, n := range names {
		probes = append(probes, pfelf.USDTProbe{Provider: "parcagpu", Name: n})
	}
	return probes
}

func probeNames(probes []pfelf.USDTProbe) []string {
	var names []string
	for _, p := range probes {
		names = append(names, p.Name)
	}
	return names
}

func TestSelectProbes(t *testing.T) {
	for _, tc := range []struct {
		name string
		have []string
		want []string
	}{
		{"current library",
			[]string{"cuda_blocking_call", "kernel_stats", "nvtx_resource_name",
				"nvtx_event_batch", "gpu_config", "error", "stall_reason_map",
				"pc_sample_batch", "cubin_loaded", "cubin_loaded_file", "activity_batch",
				"kernel_executed", "cuda_correlation", "device_info", "cubin_unloaded"},
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded_file",
				"pc_sample_batch", "stall_reason_map", "error", "gpu_config",
				"nvtx_event_batch", "nvtx_resource_name", "kernel_stats", "device_info",
				"cubin_unloaded", "cuda_blocking_call"}},
		{"library from before cuda_blocking_call",
			[]string{"kernel_stats", "nvtx_resource_name", "nvtx_event_batch", "gpu_config",
				"error", "stall_reason_map", "pc_sample_batch", "cubin_loaded",
				"cubin_loaded_file", "activity_batch", "kernel_executed", "cuda_correlation",
				"device_info", "cubin_unloaded"},
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded_file",
				"pc_sample_batch", "stall_reason_map", "error", "gpu_config",
				"nvtx_event_batch", "nvtx_resource_name", "kernel_stats", "device_info",
				"cubin_unloaded"}},
		{"library from before device_info",
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded_file",
				"cubin_unloaded", "pc_sample_batch", "kernel_stats"},
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded_file",
				"pc_sample_batch", "kernel_stats", "cubin_unloaded"}},
		{"library from before kernel_stats",
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded", "pc_sample_batch",
				"stall_reason_map", "error", "gpu_config", "nvtx_event_batch",
				"nvtx_resource_name"},
			[]string{"cuda_correlation", "activity_batch", "cubin_loaded", "pc_sample_batch",
				"stall_reason_map", "error", "gpu_config", "nvtx_event_batch",
				"nvtx_resource_name"}},
		{"oldest library",
			[]string{"kernel_executed", "cuda_correlation"},
			[]string{"cuda_correlation", "kernel_executed"}},
		{"no cuda_correlation", []string{"activity_batch", "kernel_stats"}, nil},
		{"no kernel probe", []string{"cuda_correlation", "kernel_stats"}, nil},
		{"not parcagpu", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, probeNames(selectProbes("lib.so", usdt(tc.have...))))
		})
	}
}

type progArrayStub struct {
	interpreter.EbpfHandlerStubs
	fail  map[string]bool
	slots map[uint32]string
}

func (s *progArrayStub) UpdateProgArray(_ string, slot uint32, prog string) error {
	if s.fail[prog] {
		return errors.New("verifier says no")
	}
	s.slots[slot] = prog
	return nil
}

func TestSetupTailCalls(t *testing.T) {
	all := selectProbes("lib.so", usdt("cuda_correlation", "activity_batch",
		"pc_sample_batch", "nvtx_event_batch", "kernel_stats"))

	s := &progArrayStub{slots: map[uint32]string{}}
	kept, err := setupTailCalls(s, all)
	require.NoError(t, err)
	assert.Equal(t, probeNames(all), probeNames(kept))
	assert.Equal(t, map[uint32]string{
		0: USDTProgCudaActivityBatchTail, 1: USDTProgCudaPCSampleBatchTail,
		2: USDTProgCudaNvtxBatchTail, 3: USDTProgCudaKernelStatsTail,
	}, s.slots)

	// An optional batch probe whose tail program won't load is dropped.
	s = &progArrayStub{slots: map[uint32]string{},
		fail: map[string]bool{USDTProgCudaKernelStatsTail: true}}
	kept, err = setupTailCalls(s, all)
	require.NoError(t, err)
	assert.Equal(t, []string{"cuda_correlation", "activity_batch", "pc_sample_batch",
		"nvtx_event_batch"}, probeNames(kept))

	// A required one fails the library.
	s = &progArrayStub{slots: map[uint32]string{},
		fail: map[string]bool{USDTProgCudaActivityBatchTail: true}}
	_, err = setupTailCalls(s, all)
	require.Error(t, err)
}

// Every probe that can be selected is in probeTable, and its programs are in
// the eBPF collection.
func TestProbeTable(t *testing.T) {
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, choice := range probeChoices {
		for _, name := range choice {
			p, ok := probeTable[name]
			require.True(t, ok, "%s not in probeTable", name)
			seen[name] = true
			assert.NotNil(t, coll.Programs[p.prog], "%s: program %s", name, p.prog)
			if p.tail != "" {
				assert.NotNil(t, coll.Programs[p.tail], "%s: tail %s", name, p.tail)
			}
		}
	}
	assert.Len(t, seen, len(probeTable), "probeTable has probes no choice selects")
}
