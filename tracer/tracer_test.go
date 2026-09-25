// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

// NB: upstream also defines GetEbpfMaps here. parca keeps it in tracer.go because
// out-of-package tests (interpreter/rtld, test/cudaverify, support/usdt/test) need
// it, and methods declared in a _test.go file are not visible to other packages.
// Taking upstream's copy of this file would duplicate the method and break the build.
//
// Upstream #1629 moved kernel symbolization from Tracer to ProcessManager, deleting
// the subject of the test that used to live here
// (TestSymbolizeKernelFramesIgnoresInvalidCacheEntries). It needs no replacement:
// that test guarded against a stale kernel-frame cache entry being returned, and
// ProcessManager folds the symbol generation into the cache key instead of
// validating it on read, so a stale entry can no longer be found at all.
