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
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// moduleCacheDir is tools/coredump's module cache, shared so this test and the
// coredump test don't download the same fixtures twice. It is gitignored there.
const moduleCacheDir = "../../tools/coredump/modulecache"

// The interpreter-bounds cases deliberately use the same /usr/bin/luajit binaries
// as tools/coredump/testdata/{amd64,arm64}/fib-lua.json, addressed by the same
// module-store refs. Two properties make this the right corpus:
//
//   - Statically linked luajit executables are the only binaries that exercise the
//     bug. In a libluajit-5.1.so the VM blob is first in .text, so nothing can
//     shadow it and the heuristic lands on it either way; in these executables the
//     VM is linked in last and two ordinary frame-pointer prologue regions precede
//     it. (Checked against 18 openresty builds plus openresty's own bin/luajit: none
//     of them reproduce it.)
//   - Module-store refs are content hashes, so these binaries are immutable and the
//     expected ranges below cannot drift. Fetching the equivalent binary from a
//     distro image would not be stable: today's Ubuntu 24.04 luajit package is a
//     different binary at the same size, and its interpreter starts at 0x76930.
//
// Both binaries are stripped, so there is no lj_vm_asm_begin to self-check against
// and the ranges are pinned, in the same style as the g2Dispatch pins in
// tools/luajitoffsets.
var interpreterBoundsCases = []struct {
	name       string
	ref        string
	machine    elf.Machine
	cframeSize int32
	want       util.Range
	// mustContain, when non-zero, is a text offset that the interpreter range has
	// to cover for the unwinder to behave correctly.
	mustContain uint64
}{
	{
		name:       "amd64",
		ref:        "6211ad8cd0d8603bed26e7e38a98aa95a1a343744cee06729215c1f37469c3f2",
		machine:    elf.EM_X86_64,
		cframeSize: support.LJCframeSpaceX86,
		want:       util.Range{Start: 0x76920, End: 0x7a9b5},
		// lj_vm_cpcall, as recorded in amd64/fib-lua.json. This is the regression:
		// ungated, the first frame-pointer region (0x5446b-0x57860) wins instead and
		// does not contain it, so the unwinder never hands off to unwind_luajit there
		// and the Lua/C boundary frames come out wrong.
		mustContain: 0x785d5,
	},
	{
		name:       "arm64",
		ref:        "b783336ff24a35b10022a737f18500e39e68eb5ff2a208579ee88ceddaf4ea29",
		machine:    elf.EM_AARCH64,
		cframeSize: support.LJCframeSpaceArm,
		want:       util.Range{Start: 0x75ac0, End: 0x79940},
		// The control: on aarch64 the frame-pointer clause is the one that legitimately
		// fires, neither preceding region matches, and gating changes nothing.
		//
		// This end moved from 0x79924 when the basic-block stack delta refactor
		// (upstream #1678) landed. Both starts, and the whole amd64 range, were
		// unchanged across it: the difference is in delta extraction, not in the
		// bounds heuristic.
	},
}

func TestExtractInterpreterBounds(t *testing.T) {
	// Reads resolve over plain HTTP against the public read URLs; the S3 client is
	// only used for uploads and listings.
	store, err := modulestore.New(nil, cloudstore.PublicReadURL(),
		cloudstore.ModulestoreS3Bucket(), moduleCacheDir)
	require.NoError(t, err)

	for _, tc := range interpreterBoundsCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := modulestore.IDFromString(tc.ref)
			require.NoError(t, err)

			target := filepath.Join(t.TempDir(), "luajit")
			if err := store.UnpackModuleToPath(id, target); err != nil {
				// Deliberately not a t.Skip: this module lives only in parca's GCS
				// bucket, and the missing-fixture failure is what will remind us to
				// upload it to the upstream module store when the fix is upstreamed.
				t.Fatalf("fetching the %s luajit module %s: %v\n\n"+
					"This fixture is not in the upstream module store, only in parca's GCS "+
					"bucket, which needs %s=parca-coredump-artifacts (currently %q). "+
					"Upload it upstream and delete this note rather than skipping the test.",
					tc.name, tc.ref, err, cloudstore.GCSBucketEnvVar,
					os.Getenv(cloudstore.GCSBucketEnvVar))
			}

			ef, err := pfelf.Open(target)
			require.NoError(t, err)
			defer ef.Close()
			require.Equal(t, tc.machine, ef.Machine)

			intervals, err := elfunwindinfo.Extract(target)
			require.NoError(t, err)

			got, err := extractInterpreterBounds(ef.Machine, *intervals, tc.cframeSize)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)

			if tc.mustContain != 0 {
				require.True(t, tc.mustContain >= got.Start && tc.mustContain < got.End,
					"interpreter range %v does not contain %#x", got, tc.mustContain)
			}
		})
	}
}
