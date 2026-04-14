package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"sync"
)

// stallReasonMaps stores per-PID stall reason name tables.
// Key: uint32 PID, Value: []string (indexed by stall reason index).
var stallReasonMaps sync.Map

// StoreStallReasonMap caches a stall reason name table for a given PID.
func StoreStallReasonMap(pid uint32, names []string) {
	stallReasonMaps.Store(pid, names)
}

// LookupStallReason returns the human-readable stall reason name for a given
// PID and stall reason index. Returns a numeric fallback if the index is out
// of range or the PID has no stall reason map.
func LookupStallReason(pid uint32, index uint32) string {
	v, ok := stallReasonMaps.Load(pid)
	if !ok {
		return fmt.Sprintf("stall_reason_%d", index)
	}
	names := v.([]string)
	if int(index) >= len(names) || names[index] == "" {
		return fmt.Sprintf("stall_reason_%d", index)
	}
	return names[index]
}

// DeleteStallReasonMap removes the stall reason map for a given PID.
func DeleteStallReasonMap(pid uint32) {
	stallReasonMaps.Delete(pid)
}
