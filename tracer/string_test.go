// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoString(t *testing.T) {
	tests := map[string]struct {
		input     []byte
		wantValue string
	}{
		"plain ascii": {
			input:     []byte("tenant\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			wantValue: "tenant",
		},
		"valid multi-byte utf8": {
			input:     append([]byte("héllo"), 0),
			wantValue: "héllo",
		},
		"empty buffer": {
			input:     make([]byte, 16),
			wantValue: "",
		},
		"no nul terminator uses whole buffer": {
			input:     []byte("exactlysixteenb!"),
			wantValue: "exactlysixteenb!",
		},
		"stale bytes after nul are discarded": {
			// Models a short string written into a per-CPU slot that previously
			// held a longer one. Everything past the first NUL must be dropped.
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
		},
		"invalid utf8 is passed through unvalidated": {
			// goString is used for comm, which is kernel-supplied and trusted
			// as-is; validation happens only for label strings.
			input:     []byte{'b', 'a', 'd', 0x80, 0x00},
			wantValue: "bad\x80",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := goString(tc.input)
			require.Equal(t, tc.wantValue, got.String())
		})
	}
}

func TestGoLabelKey(t *testing.T) {
	tests := map[string]struct {
		input     []byte
		wantValue string
		wantOK    bool
	}{
		"plain ascii": {
			input:     []byte("tenant\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			wantValue: "tenant",
			wantOK:    true,
		},
		"valid multi-byte utf8": {
			input:     append([]byte("héllo"), 0),
			wantValue: "héllo",
			wantOK:    true,
		},
		"empty buffer drops": {
			// An empty key cannot be grouped against, so reject.
			input:  make([]byte, 16),
			wantOK: false,
		},
		"stale bytes after nul are discarded": {
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
			wantOK:    true,
		},
		"mid-rune truncation drops the whole key": {
			// Keys are strict: a salvageable value-style prefix is not enough,
			// since dropping the trailing byte would silently change which key
			// samples are grouped under.
			input:  []byte{'o', 'k', 0xE2, 0x00},
			wantOK: false,
		},
		"trailing lone continuation byte drops": {
			input:  []byte{'a', 'b', 'c', 0x80, 0x00},
			wantOK: false,
		},
		"all-invalid bytes drop": {
			input:  []byte{0x80, 0x80, 0x00},
			wantOK: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := goLabelKey(tc.input)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got.String())
		})
	}
}

func TestGoLabelValue(t *testing.T) {
	tests := map[string]struct {
		input     []byte
		wantValue string
		wantOK    bool
	}{
		"plain ascii": {
			input:     []byte("tenant\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			wantValue: "tenant",
			wantOK:    true,
		},
		"valid multi-byte utf8": {
			input:     append([]byte("héllo"), 0),
			wantValue: "héllo",
			wantOK:    true,
		},
		"empty buffer is valid": {
			input:     make([]byte, 16),
			wantValue: "",
			wantOK:    true,
		},
		"stale bytes after nul are discarded": {
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
			wantOK:    true,
		},
		"mid-rune truncation salvages valid prefix": {
			// 3-byte rune (0xE2 0x98 0x83 = U+2603) cut after the first byte.
			// The valid "ok" prefix must be preserved.
			input:     []byte{'o', 'k', 0xE2, 0x00},
			wantValue: "ok",
			wantOK:    true,
		},
		"trailing lone continuation byte salvages valid prefix": {
			input:     []byte{'a', 'b', 'c', 0x80, 0x00},
			wantValue: "abc",
			wantOK:    true,
		},
		"all-invalid bytes drop": {
			input:  []byte{0x80, 0x80, 0x00},
			wantOK: false,
		},
		"single invalid byte drops": {
			input:  []byte{0xC0, 0x00},
			wantOK: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := goLabelValue(tc.input)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got.String())
		})
	}
}
