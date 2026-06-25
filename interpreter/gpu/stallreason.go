package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// stallReasonMaps stores per-PID stall reason name tables.
// Key: uint32 PID, Value: []libpf.String (indexed by stall reason index).
var stallReasonMaps sync.Map

// StoreStallReasonMap caches a stall reason name table for a given PID.
func StoreStallReasonMap(pid uint32, names []libpf.String) {
	stallReasonMaps.Store(pid, names)
}

// HandleStallReasonMap processes a single EVENT_TYPE_STALL_REASON_MAP event
// from the cupti_events ringbuf, extracting up to MAX_STALL_REASONS null-
// terminated names and caching them keyed by PID for later use by PC sample
// processing.
func HandleStallReasonMap(ev *CuptiStallReasonMapEvent) {
	count := ev.Count
	if count > uint32(len(ev.Names)) {
		count = uint32(len(ev.Names))
	}
	names := make([]libpf.String, count)
	for i := uint32(0); i < count; i++ {
		// Intern dedups the small fixed set of CUPTI names repeated across every
		// PID and event, and copies internally, so we can hand it the no-copy
		// ToString view of ev's buffer.
		names[i] = libpf.Intern(pfunsafe.ToString(nullTerm(ev.Names[i][:])))
	}
	StoreStallReasonMap(ev.Pid, names)
}

// LookupStallReason returns the human-readable stall reason name for a given
// PID and stall reason index. Returns a numeric fallback if the index is out
// of range or the PID has no stall reason map.
func LookupStallReason(pid uint32, index uint32) libpf.String {
	v, ok := stallReasonMaps.Load(pid)
	if !ok {
		log.Warnf("[cuda] stall reason map not found for pid %d (index %d)", pid, index)
		return libpf.Intern(fmt.Sprintf("stall_reason_%d", index))
	}
	names := v.([]libpf.String)
	if int(index) >= len(names) || names[index] == libpf.NullString {
		log.Warnf("[cuda] stall reason index %d out of range for pid %d (len=%d)", index, pid, len(names))
		return libpf.Intern(fmt.Sprintf("stall_reason_%d", index))
	}
	return names[index]
}

// DeleteStallReasonMap removes the stall reason map for a given PID.
func DeleteStallReasonMap(pid uint32) {
	stallReasonMaps.Delete(pid)
}
