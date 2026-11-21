// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// storeTestCubin caches identity metadata for crc and forgets everything the
// package keeps for it when the test ends.
func storeTestCubin(t *testing.T, crc uint64) {
	t.Helper()
	StoreCubin(&CubinInfo{CRC: crc, FileID: libpf.NewFileID(crc, 0)})
	t.Cleanup(func() {
		cubinCache.Delete(crc)
		cubinLifetimes.Lock()
		delete(cubinLifetimes.crcs, crc)
		cubinLifetimes.Unlock()
		cubinCodeCache.Lock()
		if e, ok := cubinCodeCache.entries[crc]; ok {
			removeCubinCode(e)
		}
		delete(cubinCodeCache.origins, crc)
		cubinCodeCache.Unlock()
	})
}

func trackLoad(pid uint32, crc, ptr, size uint64) {
	TrackCubinLoad(&CuptiCubinEvent{EventType: EventTypeCubinLoaded, Pid: pid,
		CubinCRC: crc, CubinPtr: ptr, CubinSize: size})
}

func cubinCached(crc uint64) bool {
	_, ok := LoadCubin(crc)
	return ok
}

// Samples still in flight after the unload must resolve: those waiting for
// their correlation trace live up to maxEntryAge, plus one ~2 s sweep.
func TestCubinUnloadGraceOutlivesPendingSamples(t *testing.T) {
	assert.Greater(t, cubinUnloadGrace, maxEntryAge+5*time.Second)
}

func TestCubinUnloadDropsAfterGrace(t *testing.T) {
	const crc, pid = uint64(0xc0b1), uint32(7001)
	storeTestCubin(t, crc)
	trackLoad(pid, crc, 0x1000, 64)

	t0 := time.Now()
	releaseCubin(pid, crc, t0)
	assert.Zero(t, sweepUnloadedCubins(t0.Add(cubinUnloadGrace-time.Second)))
	assert.True(t, cubinCached(crc), "in-flight samples still need the cubin")

	assert.Equal(t, 1, sweepUnloadedCubins(t0.Add(cubinUnloadGrace)))
	assert.False(t, cubinCached(crc))

	// A late duplicate unload, or one for a cubin never tracked, is harmless.
	releaseCubin(pid, crc, t0)
	assert.Zero(t, sweepUnloadedCubins(t0.Add(2*cubinUnloadGrace)))
}

// The same CRC loaded by several processes shares one CubinInfo, so it stays
// until the last of them unloads it or exits.
func TestCubinUnloadSharedAcrossProcesses(t *testing.T) {
	const crc, pidA, pidB = uint64(0xc0b2), uint32(7002), uint32(7003)
	storeTestCubin(t, crc)
	trackLoad(pidA, crc, 0x1000, 64)
	trackLoad(pidB, crc, 0x2000, 64)

	t0 := time.Now()
	releaseCubin(pidA, crc, t0)
	assert.Zero(t, sweepUnloadedCubins(t0.Add(10*cubinUnloadGrace)))
	assert.True(t, cubinCached(crc))

	// B exits without unloading, as most processes do.
	t1 := t0.Add(10 * cubinUnloadGrace)
	releaseProcessCubins(pidB, t1)
	assert.Zero(t, sweepUnloadedCubins(t1.Add(cubinUnloadGrace-time.Second)))
	assert.Equal(t, 1, sweepUnloadedCubins(t1.Add(cubinUnloadGrace)))
	assert.False(t, cubinCached(crc))
}

// A reload during the grace period keeps the cubin, and a later unload
// starts a fresh grace period rather than inheriting the first deadline.
func TestCubinReloadDuringGrace(t *testing.T) {
	const crc, pidA, pidB = uint64(0xc0b3), uint32(7004), uint32(7005)
	storeTestCubin(t, crc)
	trackLoad(pidA, crc, 0x1000, 64)

	t0 := time.Now()
	releaseCubin(pidA, crc, t0)
	trackLoad(pidB, crc, 0x3000, 64) // another process loads it
	assert.Zero(t, sweepUnloadedCubins(t0.Add(cubinUnloadGrace)))

	t1 := t0.Add(cubinUnloadGrace / 2)
	releaseCubin(pidB, crc, t1)
	assert.Zero(t, sweepUnloadedCubins(t0.Add(cubinUnloadGrace)))
	assert.True(t, cubinCached(crc))
	assert.Equal(t, 1, sweepUnloadedCubins(t1.Add(cubinUnloadGrace)))
}

// Cubins never passed to TrackCubinLoad (a consumer predating it) are kept
// forever, as before.
func TestCubinUnloadUntracked(t *testing.T) {
	const crc, pid = uint64(0xc0b4), uint32(7006)
	storeTestCubin(t, crc)
	t0 := time.Now()
	HandleCubinUnloadedEvent(&CuptiCubinUnloadedEvent{EventType: EventTypeCubinUnloaded,
		Pid: pid, CubinCRC: crc})
	assert.Zero(t, sweepUnloadedCubins(t0.Add(10*cubinUnloadGrace)))
	assert.True(t, cubinCached(crc))
}

// An evicted memory-only image is reread from the process that loaded it.
// Once that process unloads it, rereads move to another holder, and stop
// when none is left; the resident image itself goes with the metadata.
func TestCubinUnloadMovesImageOrigin(t *testing.T) {
	const crc, pidA, pidB = uint64(0xc0b5), uint32(7007), uint32(7008)
	SetCubinCodeCacheSize(1 << 20)
	t.Cleanup(func() { SetCubinCodeCacheSize(DefaultCubinCodeCacheSize) })
	storeTestCubin(t, crc)
	image := make([]byte, 64)
	info, _ := LoadCubin(crc)

	trackLoad(pidA, crc, 0x1000, 64)
	CacheCubinCode(info, pidA, 0x1000, image)
	trackLoad(pidB, crc, 0x2000, 64)
	require.True(t, hasCubinCode(crc))

	origin := func() *cubinOrigin {
		cubinCodeCache.Lock()
		defer cubinCodeCache.Unlock()
		return cubinCodeCache.origins[crc]
	}
	require.NotNil(t, origin())
	hash := origin().hash

	t0 := time.Now()
	releaseCubin(pidA, crc, t0)
	o := origin()
	require.NotNil(t, o)
	assert.Equal(t, pidB, o.pid)
	assert.Equal(t, uint64(0x2000), o.ptr)
	assert.Equal(t, hash, o.hash)

	releaseCubin(pidB, crc, t0)
	assert.Nil(t, origin())
	assert.True(t, hasCubinCode(crc), "resident code serves in-flight samples")

	assert.Equal(t, 1, sweepUnloadedCubins(t0.Add(cubinUnloadGrace)))
	assert.False(t, hasCubinCode(crc))
	cubinCodeCache.Lock()
	assert.Zero(t, cubinCodeCache.used)
	cubinCodeCache.Unlock()
}

type recordingReporter struct {
	mu     sync.Mutex
	traces []*libpf.Trace
}

func (r *recordingReporter) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traces = append(r.traces, trace)
	return nil
}

func (r *recordingReporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.traces)
}

// A PC sample taken before the unload, but still waiting for its correlation
// trace when the unload event is handled, is reported once the trace arrives.
func TestPendingPCSampleSurvivesUnload(t *testing.T) {
	const pid = libpf.PID(7009)
	const crc = uint64(0xc0b6)
	RegisterTestFixer(pid)
	t.Cleanup(func() { UnregisterTestFixer(pid) })
	storeTestCubin(t, crc)
	trackLoad(uint32(pid), crc, 0x1000, 64)

	rep := &recordingReporter{}
	ev := &CuptiPCSampleEvent{Pid: uint32(pid), CorrelationID: 77}
	ev.Data.CubinCRC = crc
	ev.Data.StallReasonCount = 1
	ev.StallReasons[0].Samples = 5
	HandlePCSample(ev, rep)
	require.Zero(t, rep.count(), "buffered until the correlation trace arrives")

	HandleCubinUnloadedEvent(&CuptiCubinUnloadedEvent{EventType: EventTypeCubinUnloaded,
		Pid: uint32(pid), CubinCRC: crc})
	sweepUnloadedCubins(time.Now())

	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{Type: libpf.CUDAKernelFrame, AddressOrLineno: 77})
	InterceptTrace(trace, &samples.TraceEventMeta{PID: pid, ProfileType: ProfileTypeCuda,
		Timestamp: libpf.UnixTime64(time.Now().UnixNano())})
	require.Eventually(t, func() bool { return rep.count() == 1 }, 5*time.Second,
		10*time.Millisecond)
}
