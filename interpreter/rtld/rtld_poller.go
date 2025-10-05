// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rtld // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld"

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

var (
	pollerInstance *mapsPoller
	pollerOnce     sync.Once
)

type pidInfo struct {
	hash string
}

type mapsPoller struct {
	mu          sync.RWMutex
	pids        map[libpf.PID]*pidInfo
	quit        chan struct{}
	stopped     bool
	triggerFunc func(pid libpf.PID)
	buffer      []byte         // Reusable buffer to avoid allocations
	testNotify  chan libpf.PID // Channel for test notifications
}

func getPoller(triggerFunc func(pid libpf.PID)) *mapsPoller {
	pollerOnce.Do(func() {
		pollerInstance = &mapsPoller{
			pids:        make(map[libpf.PID]*pidInfo),
			quit:        make(chan struct{}),
			buffer:      make([]byte, 64*1024), // 64KB buffer, reused across calls
			triggerFunc: triggerFunc,
		}
		go pollerInstance.run()
	})
	return pollerInstance
}

func (p *mapsPoller) registerPID(pid libpf.PID) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.pids[pid] = &pidInfo{}
	log.Debugf("[rtld] Registered PID %d for maps polling", pid)
}

func (p *mapsPoller) deregisterPID(pid libpf.PID) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.pids, pid)
	log.Debugf("[rtld] Deregistered PID %d from maps polling", pid)

	// If no more PIDs, we could optionally stop the poller
	// but keeping it running is fine for simplicity
}

func (p *mapsPoller) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Debug("[rtld] Maps poller started")

	for {
		select {
		case <-ticker.C:
			p.checkMaps()
		case <-p.quit:
			log.Debug("[rtld] Maps poller stopped")
			return
		}
	}
}

func (p *mapsPoller) checkMaps() {
	p.mu.RLock()
	// Make a copy of the PIDs to avoid holding the lock during file I/O
	pids := make([]libpf.PID, 0, len(p.pids))
	pids = slices.AppendSeq(pids, maps.Keys(p.pids))
	p.mu.RUnlock()

	for _, pid := range pids {
		p.checkPIDMaps(pid)
	}
}

func (p *mapsPoller) checkPIDMaps(pid libpf.PID) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)

	file, err := os.Open(mapsPath)
	if err != nil {
		// Process might have exited, remove it from our tracking
		p.deregisterPID(pid)
		return
	}
	defer file.Close()

	// Calculate hash of entire maps file content using raw I/O
	hasher := sha256.New()

	// Use the shared buffer, no allocations in the hot path
	for {
		n, err := file.Read(p.buffer)
		if n > 0 {
			hasher.Write(p.buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Debugf("[rtld] Error reading maps for PID %d: %v", pid, err)
			return
		}
	}

	newHash := hex.EncodeToString(hasher.Sum(nil))

	p.mu.RLock()
	info, exists := p.pids[pid]
	p.mu.RUnlock()

	if !exists {
		// PID was deregistered while we were processing
		return
	}

	if info.hash != newHash {
		log.Debugf("[rtld] Maps changed for PID %d, triggering process sync", pid)
		p.mu.Lock()
		info.hash = newHash
		p.mu.Unlock()

		// Notify test if channel is available (non-blocking)
		if p.testNotify != nil {
			select {
			case p.testNotify <- pid:
			default:
			}
		}

		if p.triggerFunc != nil {
			p.triggerFunc(pid)
		}
	}
}

// Test helpers - exported functions for testing
func GetPollerForTesting(triggerFunc func(pid libpf.PID)) interface{} {
	return getPoller(triggerFunc)
}

func RegisterPIDForTesting(pid libpf.PID, triggerFunc func(pid libpf.PID)) {
	getPoller(triggerFunc).registerPID(pid)
}

func DeregisterPIDForTesting(pid libpf.PID, triggerFunc func(pid libpf.PID)) {
	getPoller(triggerFunc).deregisterPID(pid)
}

func SetTestNotifyChannelForTesting(ch chan libpf.PID, triggerFunc func(pid libpf.PID)) {
	p := getPoller(triggerFunc)
	p.mu.Lock()
	p.testNotify = ch
	p.mu.Unlock()
}
