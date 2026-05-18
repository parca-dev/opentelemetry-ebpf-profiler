package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// GpuConfig holds the per-process parcagpu sampling parameters used to convert
// PC sample counts to nanoseconds.
type GpuConfig struct {
	DeviceID       uint32
	SamplingFactor uint32 // CUPTI samplingPeriod: period = 2^SamplingFactor cycles
	ClockKHz       uint32
	SMCount        uint32
}

// NsPerSample returns the nanoseconds of GPU time attributable to one PC sample
// observation. period_ns = cycles_per_sample / clock_hz × 1e9, with cycles_per_
// sample = 2^SamplingFactor and clock_hz = ClockKHz × 1e3.
func (c GpuConfig) NsPerSample() int64 {
	if c.ClockKHz == 0 {
		return 0
	}
	return int64((uint64(1) << c.SamplingFactor) * 1_000_000 / uint64(c.ClockKHz))
}

var gpuConfigCache sync.Map // map[uint32]*GpuConfig keyed by pid

// gpuConfigMissingWarned tracks pids we've already warned about (one warn per
// pid for missing GpuConfig at PC-sample arrival).
var gpuConfigMissingWarned sync.Map // map[uint32]struct{} keyed by pid

// warnMissingGpuConfig emits a single warning per pid that received PC samples
// before its GpuConfig probe was received. Caller falls back to raw sample
// count in the merged-profile path; samples render as tiny slivers until the
// config event arrives.
func warnMissingGpuConfig(pid uint32) {
	if _, loaded := gpuConfigMissingWarned.LoadOrStore(pid, struct{}{}); loaded {
		return
	}
	log.Warnf("[cuda] PC sample for pid=%d arrived before gpu_config probe; falling back to raw sample count (subsequent samples will convert correctly once the probe lands)", pid)
}

// StoreGpuConfig caches a GpuConfig for the given pid.
func StoreGpuConfig(pid uint32, cfg *GpuConfig) {
	gpuConfigCache.Store(pid, cfg)
}

// LoadGpuConfig looks up a cached GpuConfig by pid.
func LoadGpuConfig(pid uint32) (*GpuConfig, bool) {
	v, ok := gpuConfigCache.Load(pid)
	if !ok {
		return nil, false
	}
	return v.(*GpuConfig), true
}

// HandleGpuConfigEvent caches the config and logs at info on first observation;
// warns if a subsequent config for the same pid disagrees on ClockKHz (suggests
// a multi-GPU process — current code keyed by pid alone, last write wins).
func HandleGpuConfigEvent(ev *CuptiGpuConfigEvent) {
	cfg := &GpuConfig{
		DeviceID:       ev.DeviceID,
		SamplingFactor: ev.SamplingFactor,
		ClockKHz:       ev.ClockKHz,
		SMCount:        ev.SMCount,
	}
	if prev, ok := LoadGpuConfig(ev.Pid); ok {
		if prev.ClockKHz != cfg.ClockKHz || prev.SamplingFactor != cfg.SamplingFactor {
			log.Warnf("[cuda] gpu config diverged for pid=%d: was dev=%d factor=%d clock=%d sm=%d; now dev=%d factor=%d clock=%d sm=%d (last-write-wins; multi-GPU processes are not yet supported by the per-pid cache)",
				ev.Pid,
				prev.DeviceID, prev.SamplingFactor, prev.ClockKHz, prev.SMCount,
				cfg.DeviceID, cfg.SamplingFactor, cfg.ClockKHz, cfg.SMCount)
		}
	} else {
		log.Infof("[cuda] loaded gpu config pid=%d dev=%d factor=%d clockKHz=%d sm=%d ns_per_sample=%d",
			ev.Pid, cfg.DeviceID, cfg.SamplingFactor, cfg.ClockKHz, cfg.SMCount, cfg.NsPerSample())
	}
	StoreGpuConfig(ev.Pid, cfg)
}
