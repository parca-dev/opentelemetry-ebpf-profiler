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

typedef struct {
    size_t    size;
    uint64_t  cubinCrc;
    uint64_t  pcOffset;
    uint32_t  functionIndex;
    char     *functionName;
    uint32_t  stallReasonCount;
    CUpti_PCSamplingStallReason stallReason[CUPTI_PC_SAMPLING_MAX_STALL_REASONS];
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
