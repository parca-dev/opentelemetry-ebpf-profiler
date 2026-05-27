// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"os"
	"testing"

	sasstable "github.com/gnurizen/sass-table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toyFuncName is the single kernel in testdata/toy.cubin: add(int*, int*, int*, int).
// The cubin carries a matching ".text._Z3addPiS_S_i" section at address 0.
const toyFuncName = "_Z3addPiS_S_i"

func loadToyCubin(t *testing.T) *CubinInfo {
	t.Helper()
	data, err := os.ReadFile("testdata/toy.cubin")
	require.NoError(t, err)
	sm, texts, err := ParseCubinELF(data)
	require.NoError(t, err)
	return &CubinInfo{SMVersion: sm, Texts: texts}
}

func TestParseCubinELF_Toy(t *testing.T) {
	info := loadToyCubin(t)

	// SM version lives in e_flags bits [8:15]; toy.cubin is sm_75 (Turing).
	assert.Equal(t, 75, info.SMVersion)

	require.Len(t, info.Texts, 1)
	ts := info.Texts[0]
	assert.Equal(t, ".text."+toyFuncName, ts.Name)
	assert.Equal(t, uint64(0), ts.Addr)
	assert.Len(t, ts.Data, 256)
}

// TestDecodeInstruction_NamePath checks the deterministic path: with the CUPTI
// function name in hand, every 16-byte instruction slot decodes to exactly what
// a direct decode of the function's section yields.
func TestDecodeInstruction_NamePath(t *testing.T) {
	info := loadToyCubin(t)
	data := info.Texts[0].Data

	var sawMnemonic bool
	for off := uint64(0); off+16 <= uint64(len(data)); off += 16 {
		want := sasstable.DecodeMnemonicFromSlice(info.SMVersion, data[off:])
		assert.Equalf(t, want, decodeInstruction(info, toyFuncName, off), "offset %d", off)
		sawMnemonic = sawMnemonic || want != ""
	}
	require.True(t, sawMnemonic, "expected at least one decodable SASS instruction in toy.cubin")

	// Offset past the end of the function's section yields no mnemonic.
	assert.Empty(t, decodeInstruction(info, toyFuncName, uint64(len(data))))
}

// TestDecodeInstruction_SelectsFunctionSection is the regression guard for the
// whole change: when two functions occupy separate .text sections, a
// function-relative pcOffset must be decoded against the *named* function's
// section — not whichever section's address range happens to contain the raw
// offset (which is what the old address-first heuristic did).
func TestDecodeInstruction_SelectsFunctionSection(t *testing.T) {
	base := loadToyCubin(t)
	data := base.Texts[0].Data
	sm := base.SMVersion

	// Find a second slot whose mnemonic differs from offset 0's, so we can tell
	// which section got indexed.
	m0 := sasstable.DecodeMnemonicFromSlice(sm, data[0:])
	require.NotEmpty(t, m0)
	var altOff uint64
	var mAlt string
	for off := uint64(16); off+16 <= uint64(len(data)); off += 16 {
		if m := sasstable.DecodeMnemonicFromSlice(sm, data[off:]); m != "" && m != m0 {
			altOff, mAlt = off, m
			break
		}
	}
	require.NotZerof(t, altOff, "toy.cubin needs two differing mnemonics for this test")

	// funcA occupies [0, len); funcB is packed right after it at a non-zero
	// address. funcB's bytes start at altOff, so funcB[0] decodes to mAlt.
	info := &CubinInfo{
		SMVersion: sm,
		Texts: []TextSection{
			{Name: ".text.funcA", Addr: 0, Data: data},
			{Name: ".text.funcB", Addr: uint64(len(data)), Data: data[altOff:]},
		},
	}

	// pcOffset 0 is function-relative. funcB resolves to mAlt; the old heuristic
	// would have matched funcA (its [0,len) range contains offset 0) and returned m0.
	assert.Equal(t, mAlt, decodeInstruction(info, "funcB", 0))
	assert.Equal(t, m0, decodeInstruction(info, "funcA", 0))
}

// TestDecodeInstruction_FallbackUnknownName checks that an unresolved name
// (empty, or no matching section) still decodes via the heuristic fallback.
func TestDecodeInstruction_FallbackUnknownName(t *testing.T) {
	info := loadToyCubin(t)
	data := info.Texts[0].Data

	want := sasstable.DecodeMnemonicFromSlice(info.SMVersion, data[16:])
	assert.Equal(t, want, decodeInstruction(info, "nonexistent", 16))
	assert.Equal(t, want, decodeInstruction(info, "", 16))
}
