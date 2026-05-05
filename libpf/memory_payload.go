// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

// A synthetic MemoryPayloadFrame carries the four memory-origin counters
// (alloc count, free count, alloc bytes, free bytes) inline on a single
// libpf.Frame, so reporters can decode them straight off trace.Frames
// without an out-of-band side channel on TraceEventMeta. The encoding
// uses the per-frame uint64-sized fields:
//
//	AddressOrLineno = Allocs       (count)
//	SourceLine      = Frees        (count)
//	FileID.Hi       = AllocBytes
//	FileID.Lo       = FreeBytes
//
// FileID is repurposed here purely as 128 bits of scratch storage; this
// frame is never resolved against the executable cache.

// NewMemoryPayloadFrame returns a synthetic frame carrying a memory-origin
// counter set.
func NewMemoryPayloadFrame(allocs, frees, allocBytes, freeBytes uint64) Frame {
	return Frame{
		Type:            MemoryPayloadFrame,
		AddressOrLineno: AddressOrLineno(allocs),
		SourceLine:      SourceLineno(frees),
		FileID:          NewFileID(allocBytes, freeBytes),
	}
}

// DecodeMemoryPayload returns the (allocs, frees, allocBytes, freeBytes)
// tuple stored on a synthetic memory-payload frame. The caller is
// responsible for ensuring f.Type == MemoryPayloadFrame before calling.
func DecodeMemoryPayload(f Frame) (allocs, frees, allocBytes, freeBytes uint64) {
	allocBytes, freeBytes = f.FileID.Words()
	return uint64(f.AddressOrLineno), uint64(f.SourceLine), allocBytes, freeBytes
}
