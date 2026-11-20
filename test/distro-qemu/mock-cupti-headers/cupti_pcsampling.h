// Minimal CUPTI PC-sampling type definitions for building mock libraries.
// Layouts must match the real cupti_pcsampling.h (checked against CUPTI 13).
#ifndef MOCK_CUPTI_PCSAMPLING_H
#define MOCK_CUPTI_PCSAMPLING_H

#include "cupti.h"
#include <stddef.h>
#include <stdint.h>

#define CUPTI_STALL_REASON_STRING_SIZE 128

#define MOCK_PACKED __attribute__((__packed__)) __attribute__((aligned(8)))

typedef struct MOCK_PACKED {
  uint32_t pcSamplingStallReasonIndex;
  uint32_t samples;
} CUpti_PCSamplingStallReason;

// BPF reads this struct directly from user memory; see cupti_pc_data in
// parcagpu's cupti_bpf.h. correlationId is the CUDA 12.4+ extension.
typedef struct MOCK_PACKED {
  size_t size;
  uint64_t cubinCrc;
  uint64_t pcOffset;
  uint32_t functionIndex;
  uint32_t pad;
  char *functionName;
  size_t stallReasonCount;
  CUpti_PCSamplingStallReason *stallReason;
  uint32_t correlationId;
} CUpti_PCSamplingPCData;

_Static_assert(sizeof(CUpti_PCSamplingPCData) == 64, "CUpti_PCSamplingPCData size");

typedef struct MOCK_PACKED {
  size_t size;
  size_t collectNumPcs;
  uint64_t totalSamples;
  uint64_t droppedSamples;
  size_t totalNumPcs;
  size_t remainingNumPcs;
  uint64_t rangeId;
  CUpti_PCSamplingPCData *pPcData;
  uint64_t nonUsrKernelsTotalSamples;
  uint8_t hardwareBufferFull;
} CUpti_PCSamplingData;

_Static_assert(sizeof(CUpti_PCSamplingData) == 80, "CUpti_PCSamplingData size");

#define CUPTI_PC_SAMPLING_PARAMS_HEADER \
  size_t size;                          \
  void *pPriv;                          \
  CUcontext ctx;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
  void *pcSamplingData;
} CUpti_PCSamplingGetDataParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
} CUpti_PCSamplingEnableParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
} CUpti_PCSamplingDisableParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
} CUpti_PCSamplingStartParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
} CUpti_PCSamplingStopParams;

typedef enum {
  CUPTI_PC_SAMPLING_CONFIGURATION_ATTR_TYPE_INVALID         = 0,
  CUPTI_PC_SAMPLING_CONFIGURATION_ATTR_TYPE_SAMPLING_PERIOD = 1,
} CUpti_PCSamplingConfigurationAttributeType;

typedef struct {
  CUpti_PCSamplingConfigurationAttributeType attributeType;
  CUptiResult attributeStatus;
  union {
    struct {
      uint64_t data[3];
    } invalidData;
    struct {
      uint32_t samplingPeriod;
    } samplingPeriodData;
  } attributeData;
} CUpti_PCSamplingConfigurationInfo;

_Static_assert(sizeof(CUpti_PCSamplingConfigurationInfo) == 32,
               "CUpti_PCSamplingConfigurationInfo size");

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
  size_t numAttributes;
  CUpti_PCSamplingConfigurationInfo *pPCSamplingConfigurationInfo;
} CUpti_PCSamplingConfigurationInfoParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
  size_t *numStallReasons;
} CUpti_PCSamplingGetNumStallReasonsParams;

typedef struct {
  CUPTI_PC_SAMPLING_PARAMS_HEADER
  size_t numStallReasons;
  uint32_t *stallReasonIndex;
  char **stallReasons;
} CUpti_PCSamplingGetStallReasonsParams;

typedef struct {
  size_t size;
  size_t cubinSize;
  const void *cubin;
  uint64_t cubinCrc;
} CUpti_GetCubinCrcParams;

typedef struct {
  size_t size;
  const void *cubin;
  const char *functionName;
  size_t cubinSize;
  uint32_t lineNumber;
  uint64_t pcOffset;
  char *fileName;
  char *dirName;
} CUpti_GetSassToSourceCorrelationParams;

#endif // MOCK_CUPTI_PCSAMPLING_H
