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

// #include "lua.h"
import "C"

func bcOp(ins uint32) uint32 {
	return ins & 0xff
}

func bcModeMM(op uint32) uint32 {
	//nolint:gocritic
	return uint32(C.lj_bc_mode[op] >> 11)
}

func bcModeA(op uint32) uint32 {
	//nolint:gocritic
	return uint32(C.lj_bc_mode[op] & 7)
}

func bcA(ins uint32) uint32 {
	return (ins >> 8) & 0xff
}

func bcB(ins uint32) uint32 {
	return ins >> 24
}

func bcC(ins uint32) uint32 {
	return (ins >> 16) & 0xff
}

func bcD(ins uint32) uint32 {
	return ins >> 16
}

// Return the register used to store the function called at pc or metaname if it's a metamethod
func getSlotOrMetaname(ins uint32) (slot uint32, metaname string) {
	mm := bcModeMM(bcOp(ins))
	if mm == C.MM_call {
		slot := bcA(ins)
		if bcOp(ins) == C.BC_ITERC {
			slot -= 3
		}
		return slot, ""
	} else if mm != C.MM__MAX {
		//nolint:gocritic
		return 0, C.GoString(C.lj_metanames[mm])
	}
	return 0, ""
}
func bcModeAIsBase(op uint32) bool {
	return bcModeA(op) == C.BCMbase
}
func bcModeAIsDst(op uint32) bool {
	return bcModeA(op) == C.BCMdst
}

//nolint:revive,stylecheck
const (
	BC_MOV   = C.BC_MOV
	BC_GGET  = C.BC_GGET
	BC_TGETS = C.BC_TGETS
	BC_UGET  = C.BC_UGET
	BC_KNIL  = C.BC_KNIL
)
