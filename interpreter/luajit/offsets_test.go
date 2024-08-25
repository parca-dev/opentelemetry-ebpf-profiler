// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind/elfunwindinfo"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind/stackdeltatypes"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
)

const (
	openrestyBase = "openresty/openresty"
)

func TestOffsets(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		suf  string
		fail bool
	}{
		{"1.13.6.2-alpine", "0", true},
		{"1.15.8.3-alpine", "0", false},
		{"1.17.8.2-alpine", "0", false},
		{"1.19.9.1-focal", "0", false},
		{"1.21.4.3-buster-fat", "0", false},
		{"1.25.3.2-bullseye-fat", "ROLLING", false},
		{"jammy", "ROLLING", false},
	} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			tag, suffix := tc.tag, tc.suf
			libFile := "libluajit-5.1.so.2.1." + suffix
			t.Run(tag+"-"+platform, func(t *testing.T) {
				baseDir := "/tmp/offsets_artifacts/" + tag + "/" + platform
				target := baseDir + "/libluajit-5.1.so"

				if strings.HasPrefix(tag, "1.13") || strings.HasPrefix(tag, "1.15") {
					if platform == "linux/arm64" {
						t.Skip("old openresty doesn't have arm")
						return
					}
				}

				if _, err := os.Stat(target); os.IsNotExist(err) {
					err = os.MkdirAll(baseDir, 0o755)
					require.NoError(t, err)
					getLibFromImage(t, openrestyBase+":"+tag, platform, libFile, target)
				}

				ef, err := pfelf.Open(target)
				require.NoError(t, err)

				ljd := luajitData{}
				err = extractOffsets(ef, &ljd)

				if tc.fail {
					//nolint:lll
					require.Error(t, err, "unexpected glref offset 8, only luajit with LJ_GC64 is supported")
					return
				}

				require.NoError(t, err)
				require.NotZero(t, ljd.currentLOffset)
				require.NotZero(t, ljd.g2Traces)
				require.NotZero(t, ljd.g2Dispatch)

				od := offsetData{}
				err = od.init(ef)
				require.NoError(t, err)

				// Test that our chicanery for finding traceinfo checks out on symbolized builds.
				if ti, err1 := od.lookupSymbol("lj_cf_jit_util_traceinfo"); err1 == nil {
					ti2, err2 := od.findTraceInfoFromLuaOpen()
					require.NoError(t, err2)
					require.Equal(t, ti.Address, ti2.Address)
				}

				// Ditto for lj_dispatch_update
				if du, err1 := od.lookupSymbol("lj_dispatch_update"); err1 == nil {
					du2, err2 := od.e.findLjDispatchUpdateAddr(od.luajitOpen, od.luajitOpenAddr)
					require.NoError(t, err2)
					require.Equal(t, uint64(du.Address), du2)
				}

				// create stacktrace deltas to make sure we can find interp bounds
				var intervals stackdeltatypes.IntervalData
				err = elfunwindinfo.Extract(target, &intervals)
				require.NoError(t, err)
				// some ugliness so we can run arm and x86 unit tests on both platforms.
				var param int32
				switch ef.Machine {
				case elf.EM_AARCH64:
					param = 208
				case elf.EM_X86_64:
					param = 80
				}
				interp, err := extractInterpreterBounds(intervals.Deltas, param)
				require.NoError(t, err)

				fmt.Printf("%s: %+v, interp: %+v", target, ljd, interp)
				// TODO: strip binary and do it again.
			})
		}
	}
}

func getLibFromImage(t *testing.T, name, platform, fullPath, target string) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	image, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:         name,
			ImagePlatform: platform,
		},
		Started: false,
	})
	require.NoError(t, err)

	rc, err := image.CopyFileFromContainer(ctx, "/usr/local/openresty/luajit/lib/"+fullPath)
	require.NoError(t, err)
	defer rc.Close()
	f, err := os.Create(target)
	require.NoError(t, err)

	_, err = io.Copy(f, rc)
	require.NoError(t, err)
}

// // spot testing
func TestFile(t *testing.T) {
	target := "./testdata/libluajit-5.1.so"
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Skip("no test file")
	}
	ef, err := pfelf.Open(target)
	require.NoError(t, err)
	ljd := luajitData{}
	err = extractOffsets(ef, &ljd)
	require.NoError(t, err)
	require.NotZero(t, ljd.currentLOffset)
	require.NotZero(t, ljd.g2Traces)
	require.NotZero(t, ljd.g2Dispatch)
	// create stacktrace deltas to make sure we can find interp bounds
	var intervals stackdeltatypes.IntervalData
	err = elfunwindinfo.Extract(target, &intervals)
	require.NoError(t, err)
	// some ugliness so we can run arm and x86 unit tests on both platforms.
	var param int32
	switch ef.Machine {
	case elf.EM_AARCH64:
		param = 208
	case elf.EM_X86_64:
		param = 80
	}
	interp, err := extractInterpreterBounds(intervals.Deltas, param)
	require.NoError(t, err)

	t.Logf("%+v, interp: %+v", ljd, interp)
}
