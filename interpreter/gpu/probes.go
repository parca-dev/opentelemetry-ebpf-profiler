// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// probeSpec is how one parcagpu USDT probe is handled.
type probeSpec struct {
	cookie uint64 // CudaProg*: the branch of cuda_probe that handles it
	prog   string // its single-shot program

	// tail, if set, is the program cuda_progs[tailSlot] must hold for
	// cuda_probe to hand the probe's batches to.
	tail     string
	tailSlot uint32
	// optionalTail: if tail can't be loaded, attach without this probe
	// rather than not at all.
	optionalTail bool
}

// probeTable lists every parcagpu probe the profiler handles.
var probeTable = map[string]probeSpec{
	"cuda_correlation": {cookie: CudaProgCorrelation, prog: USDTProgCudaCorrelation},
	"kernel_executed":  {cookie: CudaProgKernelExec, prog: USDTProgCudaKernel},
	"activity_batch": {cookie: CudaProgActivityBatch, prog: USDTProgCudaActivityBatch,
		tail: USDTProgCudaActivityBatchTail, tailSlot: 0},
	"cubin_loaded":      {cookie: CudaProgCubinLoaded, prog: USDTProgCudaCubinLoaded},
	"cubin_loaded_file": {cookie: CudaProgCubinLoadedFile, prog: USDTProgCudaCubinLoadedFile},
	"pc_sample_batch": {cookie: CudaProgPCSampleBatch, prog: USDTProgCudaPCSampleBatch,
		tail: USDTProgCudaPCSampleBatchTail, tailSlot: 1},
	"stall_reason_map": {cookie: CudaProgStallReasonMap, prog: USDTProgCudaStallReasonMap},
	"error":            {cookie: CudaProgError, prog: USDTProgCudaError},
	"gpu_config":       {cookie: CudaProgGpuConfig, prog: USDTProgCudaGpuConfig},
	"nvtx_event_batch": {cookie: CudaProgNvtxEventBatch, prog: USDTProgCudaNvtxEventBatch,
		tail: USDTProgCudaNvtxBatchTail, tailSlot: 2, optionalTail: true},
	"nvtx_resource_name": {cookie: CudaProgNvtxResource, prog: USDTProgCudaNvtxResourceName},
	"kernel_stats": {cookie: CudaProgKernelStats, prog: USDTProgCudaKernelStats,
		tail: USDTProgCudaKernelStatsTail, tailSlot: 3, optionalTail: true},
}

// probeChoices is which probes are attached, in order: from each entry, the
// first the library has. A library must have the first requiredChoices;
// the rest are attached when present, so a library built before a probe
// existed still works without it.
var probeChoices = [][]string{
	{"cuda_correlation"},
	{"activity_batch", "kernel_executed"},
	// The extended probe, even with an empty path: attaching just one avoids
	// racing legacy and file-bearing notifications.
	{"cubin_loaded_file", "cubin_loaded"},
	{"pc_sample_batch"},
	{"stall_reason_map"},
	{"error"},
	{"gpu_config"},
	{"nvtx_event_batch"},
	{"nvtx_resource_name"},
	{"kernel_stats"},
}

const requiredChoices = 2

// selectProbes picks the parcagpu probes to attach from a library's USDT
// probes. It returns nil if the library isn't parcagpu or lacks a required
// probe.
func selectProbes(file string, probes []pfelf.USDTProbe) []pfelf.USDTProbe {
	byName := make(map[string]pfelf.USDTProbe)
	for _, p := range probes {
		if p.Provider == "parcagpu" {
			byName[p.Name] = p
		}
	}
	if len(byName) == 0 {
		return nil
	}
	var selected []pfelf.USDTProbe
	for i, choice := range probeChoices {
		found := false
		for _, name := range choice {
			if p, ok := byName[name]; ok {
				selected = append(selected, p)
				found = true
				break
			}
		}
		if !found && i < requiredChoices {
			names := make([]string, 0, len(byName))
			for name := range byName {
				names = append(names, name)
			}
			log.Warnf("parcagpu USDT probes in %s missing %s: %v",
				file, strings.Join(choice, " or "), names)
			return nil
		}
	}
	return selected
}

// setupTailCalls loads the tail programs the probes need into cuda_progs. A
// probe whose optional tail program fails to load is dropped. Map updates
// are idempotent, so a library loaded again redoes them harmlessly.
func setupTailCalls(ebpf interpreter.EbpfHandler,
	probes []pfelf.USDTProbe) ([]pfelf.USDTProbe, error) {
	kept := make([]pfelf.USDTProbe, 0, len(probes))
	for _, probe := range probes {
		p := probeTable[probe.Name]
		if p.tail != "" {
			if err := ebpf.UpdateProgArray(cudaProgsMap, p.tailSlot, p.tail); err != nil {
				if !p.optionalTail {
					return nil, fmt.Errorf("[cuda] %s tail call setup failed: %w",
						probe.Name, err)
				}
				log.Errorf("[cuda] %s tail call failed: %v — dropping %s",
					probe.Name, err, probe.Name)
				continue
			}
		}
		kept = append(kept, probe)
	}
	return kept, nil
}

// pcSampleHasDevice reports whether the library's pc_sample_batch passes the
// CUDA device, its third argument.
func pcSampleHasDevice(file string, probes []pfelf.USDTProbe) bool {
	for _, probe := range probes {
		if probe.Name != "pc_sample_batch" {
			continue
		}
		spec, err := pfelf.ParseUSDTArguments(probe.Arguments)
		if err != nil {
			return false
		}
		if spec.Arg_cnt < 3 {
			log.Warnf("[cuda] %s: pc_sample_batch has %d args (need 3 for cuda_device) — "+
				"built from an older parcagpu; PC samples won't carry a cuda_device label",
				file, spec.Arg_cnt)
			return false
		}
		return true
	}
	return false
}
