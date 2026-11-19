// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrameTypeFromString(t *testing.T) {
	// Simple check whether all FrameType values can be converted to string and back.
	for _, ft := range []FrameType{
		UnknownFrame, PHPFrame, PythonFrame, NativeFrame, KernelFrame, HotSpotFrame, RubyFrame,
		PerlFrame, V8Frame, DotnetFrame, LuaJITFrame, CUDAKernelFrame} {
		t.Run(ft.String(), func(t *testing.T) {
			name := ft.String()
			result := FrameTypeFromString(name)
			require.Equal(t, ft, result)
		})
	}
}

func TestCUDAFrameTypesShareSemConvString(t *testing.T) {
	// Both CUDA frame types export as the single SemConv "cuda" value, which
	// parses back to the kernel frame type.
	require.Equal(t, "cuda", CUDAKernelFrame.String())
	require.Equal(t, "cuda", CUDAPCFrame.String())
	require.Equal(t, CUDAKernelFrame, FrameTypeFromString("cuda"))
	require.Equal(t, UnknownFrame, FrameTypeFromString("cuda-pc"))
}
