package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// ProfileTypeCuda and ProfileTypeGpuPC are the profile types carried by
// TraceEventMeta.ProfileType for GPU traces. Upstream #1576 replaced
// TraceEventMeta.Origin with ProfileType, so consumers that used to compare
// against support.TraceOriginCuda/TraceOriginGpuPC now compare against these
// pointers instead.
//
// ProfileTypeCuda is registered with the tracer's origin registry at load time
// (upstream #1607), which assigns it the origin ID the cuda_correlation eBPF
// probe stamps into Trace.origin. ProfileTypeGpuPC never reaches eBPF: PC
// samples are synthesized in user space and carry this pointer directly.
//
// They live here rather than in tracer because the import edge runs
// tracer -> interpreterconfig -> gpu; gpu cannot import tracer.
//
// SampleTypes[0].Type is the identifying field: it is unique across every profile type
// the profiler produces, and nothing assigns to a TypeMetadata after it is
// constructed. parca-agent keys off it rather than off pointer identity,
// because the three types the tracer registers for itself are anonymous
// literals it cannot reach. (--merge-gpu-profiles does relabel GPU samples,
// but it rewrites the profile parca-agent emits, not the metadata here.)
var (
	ProfileTypeCuda = &samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: "gpu_kernel_time", Unit: "nanoseconds"}},
		ReportValues: true,
		AppendValues: samples.AppendFirstContextValue,
	}
	ProfileTypeGpuPC = &samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: "gpu_pcsample", Unit: "count"}},
		ReportValues: true,
		AppendValues: samples.AppendFirstContextValue,
	}
)

// Config is the enable/disable knob wired into interpreterconfig.Config.
// (Distinct from GpuConfig below, which is a process's CUPTI sampling
// parameters for one device, delivered at runtime by the gpu_config probe.)
type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}

// GpuConfig holds a process's parcagpu sampling parameters for one device,
// used to convert PC sample counts to nanoseconds.
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

// gpuConfigs caches GpuConfig per pid and device. A process can use several
// GPUs, with different clocks, and parca-agent can change a device's
// sampling factor while the process runs, so one entry per pid isn't enough.
var gpuConfigs sync.Map // map[uint32]*pidGpuConfigs keyed by pid

type pidGpuConfigs struct {
	mu      sync.Mutex
	devices map[uint32]*GpuConfig
}

// gpuConfigMissingWarned tracks pids we've already warned about (one warn per
// pid for missing GpuConfig at PC-sample arrival).
var gpuConfigMissingWarned sync.Map // map[uint32]struct{} keyed by pid

// WarnMissingGpuConfig emits a single warning per pid that received PC samples
// before its GpuConfig probe was received. The caller (reporter) decides what
// to do with raw sample counts that lack a NsPerSample period — typically
// surface them with a degraded period of 1 until the config event arrives.
func WarnMissingGpuConfig(pid uint32) {
	if _, loaded := gpuConfigMissingWarned.LoadOrStore(pid, struct{}{}); loaded {
		return
	}
	log.Warnf("[cuda] PC sample for pid=%d arrived before gpu_config probe; falling back to raw sample count (subsequent samples will convert correctly once the probe lands)", pid)
}

// StoreGpuConfig caches cfg for pid and cfg.DeviceID, replacing that
// device's previous config.
func StoreGpuConfig(pid uint32, cfg *GpuConfig) {
	v, _ := gpuConfigs.LoadOrStore(pid, &pidGpuConfigs{devices: map[uint32]*GpuConfig{}})
	p := v.(*pidGpuConfigs)
	p.mu.Lock()
	p.devices[cfg.DeviceID] = cfg
	p.mu.Unlock()
}

// LoadGpuConfig looks up the cached GpuConfig for pid's device dev.
func LoadGpuConfig(pid, dev uint32) (*GpuConfig, bool) {
	v, ok := gpuConfigs.Load(pid)
	if !ok {
		return nil, false
	}
	p := v.(*pidGpuConfigs)
	p.mu.Lock()
	defer p.mu.Unlock()
	cfg, ok := p.devices[dev]
	return cfg, ok
}

// loadOnlyGpuConfig returns pid's config if pid has one for exactly one device.
func loadOnlyGpuConfig(pid uint32) (*GpuConfig, bool) {
	v, ok := gpuConfigs.Load(pid)
	if !ok {
		return nil, false
	}
	p := v.(*pidGpuConfigs)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.devices) != 1 {
		return nil, false
	}
	for _, cfg := range p.devices {
		return cfg, true
	}
	return nil, false
}

// DeleteGpuConfigs drops every cached config for pid.
func DeleteGpuConfigs(pid uint32) {
	gpuConfigs.Delete(pid)
	gpuConfigMissingWarned.Delete(pid)
}

// PCSampleOrigin is the OriginData of a GPU PC sample's TraceEventMeta: the
// device the sample was taken on.
type PCSampleOrigin struct {
	DeviceID uint32
	// HasDevice is false when the producing parcagpu predates the device
	// argument of pc_sample_batch; DeviceID is meaningless then.
	HasDevice bool
}

// PCSampleNsPerSample returns the nanoseconds of GPU time one PC sample in
// meta stands for, from the config of the device it was taken on, or 0 if
// that config hasn't arrived yet. A sample without a device (an older
// parcagpu) uses the pid's config if the pid has one for a single device.
func PCSampleNsPerSample(meta *samples.TraceEventMeta) int64 {
	pid := uint32(meta.PID)
	var cfg *GpuConfig
	var ok bool
	if o, isPC := meta.OriginData.(*PCSampleOrigin); isPC && o != nil && o.HasDevice {
		cfg, ok = LoadGpuConfig(pid, o.DeviceID)
	} else {
		cfg, ok = loadOnlyGpuConfig(pid)
	}
	if !ok {
		WarnMissingGpuConfig(pid)
		return 0
	}
	return cfg.NsPerSample()
}

// HandleGpuConfigEvent caches the config for the event's pid and device. A
// device's config changes when parca-agent sets a new sampling factor.
func HandleGpuConfigEvent(ev *CuptiGpuConfigEvent) {
	cfg := &GpuConfig{
		DeviceID:       ev.DeviceID,
		SamplingFactor: ev.SamplingFactor,
		ClockKHz:       ev.ClockKHz,
		SMCount:        ev.SMCount,
	}
	if prev, ok := LoadGpuConfig(ev.Pid, ev.DeviceID); ok {
		if *prev != *cfg {
			log.Infof("[cuda] gpu config changed pid=%d dev=%d: factor=%d clockKHz=%d sm=%d -> factor=%d clockKHz=%d sm=%d ns_per_sample=%d",
				ev.Pid, ev.DeviceID,
				prev.SamplingFactor, prev.ClockKHz, prev.SMCount,
				cfg.SamplingFactor, cfg.ClockKHz, cfg.SMCount, cfg.NsPerSample())
		}
	} else {
		log.Infof("[cuda] loaded gpu config pid=%d dev=%d factor=%d clockKHz=%d sm=%d ns_per_sample=%d",
			ev.Pid, cfg.DeviceID, cfg.SamplingFactor, cfg.ClockKHz, cfg.SMCount, cfg.NsPerSample())
	}
	StoreGpuConfig(ev.Pid, cfg)
}
