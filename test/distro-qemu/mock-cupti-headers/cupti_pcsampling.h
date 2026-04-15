// Minimal CUPTI PC-sampling type definitions for building mock libraries.
#ifndef MOCK_CUPTI_PCSAMPLING_H
#define MOCK_CUPTI_PCSAMPLING_H

#include <stdint.h>
#include <stddef.h>
#include "cupti.h"

#define CUPTI_STALL_REASON_STRING_SIZE 128
#define CUPTI_PC_SAMPLING_MAX_STALL_REASONS 32

typedef struct {
    uint32_t pcSamplingStallReasonIndex;
    uint32_t samples;
} CUpti_PCSamplingStallReason;

// Layout must match cupti_pc_data in cupti_bpf.h — BPF reads this struct
// directly from user-space memory via bpf_probe_read_user.
//
// Pre-CUDA 12.4 (size == 56):
//   offset  0: size_t   size
//   offset  8: uint64_t cubinCrc
//   offset 16: uint64_t pcOffset
//   offset 24: uint32_t functionIndex
//   offset 28: (4 bytes padding)
//   offset 32: char    *functionName       (pointer)
//   offset 40: uint64_t stallReasonCount   (note: u64 not u32)
//   offset 48: CUpti_PCSamplingStallReason *stallReason (pointer)
//   = 56 bytes
//
// CUDA 12.4+ (size > 56):
//   offset 56: uint32_t correlationId
typedef struct {
    size_t    size;
    uint64_t  cubinCrc;
    uint64_t  pcOffset;
    uint32_t  functionIndex;
    uint32_t  _pad0;
    char     *functionName;
    uint64_t  stallReasonCount;
    CUpti_PCSamplingStallReason *stallReason;
    // CUDA 12.4+ extension
    uint32_t  correlationId;
} CUpti_PCSamplingPCData;

typedef struct {
    uint32_t  collectNumPcs;
    uint32_t  totalNumPcs;
    uint32_t  remainingNumPcs;
    uint64_t  totalSamples;
    CUpti_PCSamplingPCData *pPcData;
} CUpti_PCSamplingData;

typedef struct { CUpti_PCSamplingData *pcSamplingData; } CUpti_PCSamplingGetDataParams;
typedef struct { void *dummy; } CUpti_PCSamplingEnableParams;
typedef struct { void *dummy; } CUpti_PCSamplingDisableParams;
typedef struct { void *dummy; } CUpti_PCSamplingStartParams;
typedef struct { void *dummy; } CUpti_PCSamplingStopParams;
typedef struct { void *dummy; } CUpti_PCSamplingConfigurationInfoParams;
typedef struct {
    uint32_t *numStallReasons;
} CUpti_PCSamplingGetNumStallReasonsParams;
typedef struct {
    size_t    numStallReasons;
    char    (*stallReasons)[CUPTI_STALL_REASON_STRING_SIZE];
    uint32_t *stallReasonIndex;
} CUpti_PCSamplingGetStallReasonsParams;

#endif // MOCK_CUPTI_PCSAMPLING_H
