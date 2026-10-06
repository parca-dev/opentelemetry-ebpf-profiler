// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// TestClearAtEvictsByAge checks that entries older than maxEntryAge leave
// every fixer map even though the maps are far below clearTriggerThreshold,
// and that recent entries stay even when they're outside retentionWindow
// (that limit only applies past the threshold).
func TestClearAtEvictsByAge(t *testing.T) {
	f := newGpuTraceFixer(false)
	now := time.Now().UnixNano()
	old := now - (maxEntryAge + time.Second).Nanoseconds()
	const oldID, newID = 1, 2
	meta := &samples.TraceEventMeta{PID: 1}
	for id, at := range map[uint32]int64{oldID: old, newID: now} {
		st := &SymbolizedCudaTrace{Meta: meta, CorrelationID: id, StoredAtNs: at}
		f.tracesAwaitingTimes[id] = st // e.g. a graph trace, kept after matching
		f.pcTraces[id] = st
		f.timesAwaitingTraces[id] = []CuptiKernelEvent{{Id: id}}
		f.timesStoredAtNs[id] = at
		f.pendingPCSamples[id] = []pendingPCSample{{arrivalNs: at}}
	}
	f.maxCorrelationId = newID + retentionWindow + 10

	stats := f.clearAt(now)

	for name, m := range map[string]map[uint32]bool{
		"tracesAwaitingTimes": keysOf(f.tracesAwaitingTimes),
		"pcTraces":            keysOf(f.pcTraces),
		"timesAwaitingTraces": keysOf(f.timesAwaitingTraces),
		"timesStoredAtNs":     keysOf(f.timesStoredAtNs),
		"pendingPCSamples":    keysOf(f.pendingPCSamples),
	} {
		assert.Equal(t, map[uint32]bool{newID: true}, m, name)
	}
	assert.Equal(t, 1, stats.tracesCleared)
	assert.Equal(t, 1, stats.timesCleared)
	assert.Equal(t, 1, stats.pendingSamplesEvicted)
}

func keysOf[V any](m map[uint32]V) map[uint32]bool {
	out := make(map[uint32]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
