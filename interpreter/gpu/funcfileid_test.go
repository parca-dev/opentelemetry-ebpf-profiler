package gpu

import (
	"hash/fnv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// TestFuncFileIDDisambiguatesKernels verifies the agent-side half of the
// per-function-FileID fix: two kernels in the SAME cubin must get distinct
// FileIDs so their (FileID, 0-based-offset) sample frames don't alias.
func TestFuncFileIDDisambiguatesKernels(t *testing.T) {
	const crc = uint64(0xdeadbeefcafef00d)
	cubinID := libpf.NewFileID(crc, 0)

	a := funcFileID(crc, cubinID, "_Z12shmem_bouncePfiy")
	b := funcFileID(crc, cubinID, "_Z10hash_churnPjiy")

	// Different kernels in the same cubin -> different FileIDs.
	assert.False(t, a.Equal(b), "two kernels collided onto one FileID")

	// Same kernel -> same FileID (stable, so agent and backend agree).
	assert.True(t, a.Equal(funcFileID(crc, cubinID, "_Z12shmem_bouncePfiy")))

	// High word stays the cubin CRC so the backend can recover it and
	// recompute the same per-function FileIDs from the cubin symbol table.
	assert.Equal(t, crc, a.Hi())
	assert.Equal(t, crc, b.Hi())

	// Low word is exactly FNV-1a(name) — the contract the backend mirrors.
	h := fnv.New64a()
	_, _ = h.Write([]byte("_Z12shmem_bouncePfiy"))
	assert.Equal(t, h.Sum64(), a.Lo())
}

// TestFuncFileIDMatchesBackendBuildID locks the cross-repo contract: the build
// ID string the agent stamps on a cubin PC sample frame (fid.StringNoQuotes())
// must byte-for-byte equal the per-function key the polarsignals optimizer
// writes artifacts under (encodeFileID(cubinCRC, fnv1a64(name)) in
// pkg/debuginfo/optimizer/cubin_index.go). These literals are the exact
// outputs asserted by that package's TestCubinPerFunctionOptimize for
// cubinCRC=0xabcddcba12344321 — if either side's hashing/encoding drifts, one
// of the two tests breaks.
func TestFuncFileIDMatchesBackendBuildID(t *testing.T) {
	const cubinCRC = uint64(0xabcddcba12344321)
	cubinID := libpf.NewFileID(cubinCRC, 0)

	want := map[string]string{
		"_Z12shmem_bouncePfiy": "abcddcba123443212868dcb2f58897ba",
		"_Z10hash_churnPjiy":   "abcddcba12344321d886a737b53b5e78",
		"_Z10trig_stormPfiy":   "abcddcba12344321f071fa7c1a632ded",
	}
	for name, expected := range want {
		assert.Equal(t, expected, funcFileID(cubinCRC, cubinID, name).StringNoQuotes(),
			"build ID for kernel %s drifted from the backend optimizer", name)
	}
}

// TestFuncFileIDEmptyNameFallsBack covers the missing-name case: with no kernel
// name we must not key on a hash of "" — we fall back to the per-cubin FileID.
func TestFuncFileIDEmptyNameFallsBack(t *testing.T) {
	const crc = uint64(0x1234)
	cubinID := libpf.NewFileID(crc, 0)
	require.True(t, funcFileID(crc, cubinID, "").Equal(cubinID))
}
