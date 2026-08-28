//go:build arm64

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
// See the License for the specific language governing permissions and
// limitations under the License.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/support"

const (
	cframeSize    int32 = support.LJCframeSpaceArm
	cframeSizeJIT int32 = cframeSize + cframeJITTransitionSize

	// Standard LuaJIT, OpenResty, and Tarantool all store the arm64 previous
	// C-frame link at the beginning of the VM C frame. Both values being zero
	// makes the eBPF ABI's zero-means-architecture-default fallback unambiguous;
	// a future differing arm64 layout would require revisiting that sentinel.
	defaultCframePrevOffset   uint16 = 0
	tarantoolCframePrevOffset uint16 = 0
)
