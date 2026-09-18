// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

// NB: upstream also defines GetEbpfMaps here. parca keeps it in tracer.go because
// out-of-package tests (interpreter/rtld, test/cudaverify, support/usdt/test) need
// it, and methods declared in a _test.go file are not visible to other packages.

import (
	"testing"
	"unique"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestSymbolizeKernelFramesIgnoresInvalidCacheEntries(t *testing.T) {
	kernelFrameCache, err := lru.New[libpf.Address, kernelFrameCacheValue](
		kernelFrameCacheSize, libpf.Address.Hash32)
	if err != nil {
		t.Fatalf("failed to create kernel frame cache: %v", err)
	}

	cachedFrame := unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0,
		FunctionName:    libpf.Intern("cached"),
	})
	kernelFrameCache.Add(0x1234, kernelFrameCacheValue{
		generation: kallsyms.Generation(2),
		frame:      cachedFrame,
	})

	tracer := &Tracer{
		kernelSymbolizer: &kallsyms.Symbolizer{},
		kernelFrameCache: kernelFrameCache,
	}

	frames := tracer.symbolizeKernelFrames([]uint64{0x1234}, nil)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0] == cachedFrame {
		t.Fatalf("expected stale cache entry to be ignored")
	}
}
