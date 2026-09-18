// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package types // import "go.opentelemetry.io/ebpf-profiler/tracer/types"

import (
	"fmt"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/beam"
	"go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"
	golang "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/interpreter/luajit"
	"go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"
	"go.opentelemetry.io/ebpf-profiler/interpreter/perl"
	"go.opentelemetry.io/ebpf-profiler/interpreter/php"
	"go.opentelemetry.io/ebpf-profiler/interpreter/python"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
)

// tracerType values identify tracers, such as the native code tracer, or PHP tracer
type tracerType int

const (
	PerlTracer tracerType = iota
	PHPTracer
	PythonTracer
	HotspotTracer
	RubyTracer
	V8Tracer
	DotnetTracer
	LuaJITTracer
	GoTracer
	Labels
	BEAMTracer
	CUDATracer

	// maxTracers indicates the max. number of different tracers
	maxTracers
)

var tracerTypeToName = map[tracerType]string{
	PerlTracer:    "perl",
	PHPTracer:     "php",
	PythonTracer:  "python",
	HotspotTracer: "hotspot",
	RubyTracer:    "ruby",
	V8Tracer:      "v8",
	DotnetTracer:  "dotnet",
	LuaJITTracer:  "luajit",
	GoTracer:      "go",
	Labels:        "labels",
	BEAMTracer:    "beam",
	CUDATracer:    "cuda",
}

var tracerNameToType = make(map[string]tracerType, maxTracers)

func init() {
	for k, v := range tracerTypeToName {
		tracerNameToType[v] = k
	}
}

// IsMapEnabled checks if the given map is enabled and should be loaded.
func IsMapEnabled(mapName string, includeTracers IncludedTracers) bool {
	switch mapName {
	case "perl_procs":
		return includeTracers.Has(PerlTracer)
	case "php_procs":
		return includeTracers.Has(PHPTracer)
	case "py_procs":
		return includeTracers.Has(PythonTracer)
	case "hotspot_procs":
		return includeTracers.Has(HotspotTracer)
	case "ruby_procs":
		return includeTracers.Has(RubyTracer)
	case "dotnet_procs":
		return includeTracers.Has(DotnetTracer)
	case "beam_procs":
		return includeTracers.Has(BEAMTracer)
	case "go_procs", "apm_int_procs", "v8_procs":
		// these are called from
		// unwind_stop and therefore need to be available all the time.
		return true
	default:
		return true // Not an interpreter map, so it should be loaded
	}
}

// tracerTypeFromName returns the tracer type for the given name.
func tracerTypeFromName(s string) (tracerType, bool) {
	tt, ok := tracerNameToType[s]
	return tt, ok
}

// String returns the tracer's name.
// It returns '<unknown>' in case the tracer is unknown.
func (t tracerType) String() string {
	if result, ok := tracerTypeToName[t]; ok {
		return result
	}

	return "<unknown>"
}

// IncludedTracers holds information about which tracers are enabled.
type IncludedTracers uint16

// String returns a comma-separated list of enabled tracers.
func (t *IncludedTracers) String() string {
	var names []string
	for tracer := range maxTracers {
		if t.Has(tracer) {
			names = append(names, tracer.String())
		}
	}
	return strings.Join(names, ",")
}

// Has returns true if the given tracer is enabled.
func (t *IncludedTracers) Has(tracer tracerType) bool {
	return *t&(1<<tracer) != 0
}

// Enable enables the given tracer.
func (t *IncludedTracers) Enable(tracer tracerType) {
	*t |= 1 << tracer
}

// Disable disables the given tracer.
func (t *IncludedTracers) Disable(tracer tracerType) {
	*t &= ^(1 << tracer)
}

// enableAll enables all known tracers.
func (t *IncludedTracers) enableAll() {
	for tracer := range maxTracers {
		t.Enable(tracer)
	}
}

// enableByName enables the given tracer by its name.
func (t *IncludedTracers) enableByName(name string) bool {
	tracer, ok := tracerTypeFromName(name)
	if ok {
		t.Enable(tracer)
	}
	return ok
}

// Parse parses a string that specifies one or more eBPF tracers to enable.
// Valid inputs are 'all', or any comma-delimited combination of names listed in tracerTypeToName.
// The return value holds the information whether a tracer has been set or not.
// E.g. to check if the Python tracer was requested: `if result.Has(tracertypes.PythonTracer)...`.
func Parse(tracers string) (IncludedTracers, error) {
	var result IncludedTracers

	// Parse and validate tracers string.
	for name := range strings.SplitSeq(tracers, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}

		if result.enableByName(name) {
			continue
		}

		switch name {
		case "all":
			result.enableAll()
		case "native":
			log.Warn("Enabling the `native` tracer explicitly is deprecated (it's always-on)")
		default:
			return result, fmt.Errorf("unknown tracer: %s", name)
		}
	}

	if tracersEnabled := result.String(); tracersEnabled != "" {
		log.Debugf("Tracer string: %v", tracers)
	}

	return result, nil
}

// AllTracers is a shortcut that returns an element with all
// tracers enabled.
func AllTracers() IncludedTracers {
	var result IncludedTracers
	result.enableAll()
	return result
}

// ToInterpretersConfig converts the legacy IncludedTracers bitset into the
// upstream interpreterconfig.Config shape (each tracer absent from the bitset
// gets Disabled=true). Tests still driven off tracertypes.Parse(...) use this
// to populate tracer.Config.InterpretersConfig.
func (t IncludedTracers) ToInterpretersConfig() interpreterconfig.Config {
	dis := func(enabled bool) interpreter.BaseConfig {
		return interpreter.BaseConfig{Disabled: !enabled}
	}
	return interpreterconfig.Config{
		Python:  python.Config{BaseConfig: dis(t.Has(PythonTracer))},
		Perl:    perl.Config{BaseConfig: dis(t.Has(PerlTracer))},
		PHP:     php.Config{BaseConfig: dis(t.Has(PHPTracer))},
		Hotspot: hotspot.Config{BaseConfig: dis(t.Has(HotspotTracer))},
		Ruby:    ruby.Config{BaseConfig: dis(t.Has(RubyTracer))},
		V8:      nodev8.Config{BaseConfig: dis(t.Has(V8Tracer))},
		Dotnet:  dotnet.Config{BaseConfig: dis(t.Has(DotnetTracer))},
		// Upstream #1564 folded the standalone `labels` interpreter into Go, so
		// the Labels tracer type now drives Go.Labels rather than its own config.
		Go: golang.Config{
			BaseConfig: dis(t.Has(GoTracer)),
			Labels:     dis(t.Has(Labels)),
		},
		BEAM:   beam.Config{BaseConfig: dis(t.Has(BEAMTracer))},
		LuaJIT: luajit.Config{BaseConfig: dis(t.Has(LuaJITTracer))},
		CUDA:   gpu.Config{BaseConfig: dis(t.Has(CUDATracer))},
	}
}
