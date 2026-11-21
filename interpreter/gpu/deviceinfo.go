// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// CuptiDeviceInfoEvent matches struct device_info_event in cuda.ebpf.c.
type CuptiDeviceInfoEvent struct {
	EventType uint32
	Pid       uint32
	DeviceID  uint32 // CUDA ordinal in the process
	_pad      uint32
	UUID      [16]byte
	PCIBusID  [32]byte // NUL-terminated
}

// DeviceInfo identifies the GPU behind one of a process's CUDA ordinals.
// Kernel timings, PC samples and NVTX events carry the ordinal, which depends
// on the process's CUDA_VISIBLE_DEVICES and CUDA_DEVICE_ORDER; the UUID is
// the same in every process and in NVML.
type DeviceInfo struct {
	DeviceID uint32 // CUDA ordinal in the process
	UUID     [16]byte
	PCIBusID string // e.g. "0000:01:00.0"; empty if parcagpu couldn't get it
}

// UUIDString formats the UUID as nvidia-smi and NVML do, which is also the
// hw.id of host GPU metrics: "GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
func (d DeviceInfo) UUIDString() string {
	u := d.UUID
	return fmt.Sprintf("GPU-%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// deviceInfos caches DeviceInfo per pid and CUDA ordinal, like gpuConfigs.
var deviceInfos sync.Map // map[uint32]*pidDeviceInfos keyed by pid

type pidDeviceInfos struct {
	mu      sync.Mutex
	devices map[uint32]DeviceInfo
}

// HandleDeviceInfoEvent caches the device mapping the event reports. parcagpu
// replays it periodically, so a replay of a known mapping is cheap.
func HandleDeviceInfoEvent(ev *CuptiDeviceInfoEvent) {
	info := DeviceInfo{
		DeviceID: ev.DeviceID,
		UUID:     ev.UUID,
		PCIBusID: string(nullTerm(ev.PCIBusID[:])),
	}
	v, _ := deviceInfos.LoadOrStore(ev.Pid, &pidDeviceInfos{devices: map[uint32]DeviceInfo{}})
	p := v.(*pidDeviceInfos)
	p.mu.Lock()
	prev, known := p.devices[ev.DeviceID]
	p.devices[ev.DeviceID] = info
	p.mu.Unlock()
	if !known || prev != info {
		// A change means the pid was recycled before Detach dropped its state.
		log.Infof("[cuda] device pid=%d dev=%d uuid=%s pci=%q",
			ev.Pid, ev.DeviceID, info.UUIDString(), info.PCIBusID)
	}
}

// LoadDeviceInfo returns the device behind CUDA ordinal dev in process pid.
// It is false until the process's device_info event arrives (at its first
// context creation on that device, or at a replay within ~30 s of the
// profiler attaching), and always for parcagpu builds without the probe.
func LoadDeviceInfo(pid, dev uint32) (DeviceInfo, bool) {
	v, ok := deviceInfos.Load(pid)
	if !ok {
		return DeviceInfo{}, false
	}
	p := v.(*pidDeviceInfos)
	p.mu.Lock()
	defer p.mu.Unlock()
	info, ok := p.devices[dev]
	return info, ok
}

// PCSampleDeviceInfo returns the device a PC sample in meta was taken on, if
// the sample carries its ordinal and the process's mapping has arrived.
func PCSampleDeviceInfo(meta *samples.TraceEventMeta) (DeviceInfo, bool) {
	o, isPC := meta.OriginData.(*PCSampleOrigin)
	if !isPC || o == nil || !o.HasDevice {
		return DeviceInfo{}, false
	}
	return LoadDeviceInfo(uint32(meta.PID), o.DeviceID)
}

// DeleteDeviceInfos drops every cached mapping for pid.
func DeleteDeviceInfos(pid uint32) {
	deviceInfos.Delete(pid)
}
