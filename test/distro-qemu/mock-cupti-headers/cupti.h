// Minimal CUPTI type definitions for building mock libraries.
// Only the types referenced by parcagpu's test/mock_cupti.c are needed.
// libparcagpucupti.so is built against the real CUPTI headers, so values and
// struct layouts here must match them (checked against CUPTI 13).
#ifndef MOCK_CUPTI_H
#define MOCK_CUPTI_H

#include <stdint.h>
#include <stddef.h>
#include "cuda.h"

typedef int CUptiResult;
#define CUPTI_SUCCESS                 0
#define CUPTI_ERROR_INVALID_PARAMETER 1
#define CUPTI_ERROR_INVALID_OPERATION 7
#define CUPTI_ERROR_MAX_LIMIT_REACHED 12
#define CUPTI_ERROR_INVALID_KIND      21
#define CUPTI_ERROR_NOT_SUPPORTED     27
#define CUPTI_ERROR_UNKNOWN           999

typedef void *CUpti_SubscriberHandle;

typedef enum {
  CUPTI_CB_DOMAIN_INVALID     = 0,
  CUPTI_CB_DOMAIN_DRIVER_API  = 1,
  CUPTI_CB_DOMAIN_RUNTIME_API = 2,
  CUPTI_CB_DOMAIN_RESOURCE    = 3,
  CUPTI_CB_DOMAIN_SYNCHRONIZE = 4,
  CUPTI_CB_DOMAIN_NVTX        = 5,
  CUPTI_CB_DOMAIN_SIZE        = 6,
} CUpti_CallbackDomain;

typedef uint32_t CUpti_CallbackId;

#define CUPTI_CBID_RESOURCE_CONTEXT_CREATED 1
#define CUPTI_CBID_RESOURCE_MODULE_LOADED   6

typedef enum {
  CUPTI_API_ENTER = 0,
  CUPTI_API_EXIT  = 1,
} CUpti_ApiCallbackSite;

typedef struct {
  CUpti_ApiCallbackSite callbackSite; // offset 0
  const char *functionName;           // offset 8
  const void *functionParams;         // offset 16
  void *functionReturnValue;          // offset 24
  const char *symbolName;             // offset 32
  CUcontext context;                  // offset 40
  uint32_t contextUid;                // offset 48
  uint64_t *correlationData;          // offset 56
  uint32_t correlationId;             // offset 64
} CUpti_CallbackData;

_Static_assert(sizeof(CUpti_CallbackData) == 72, "CUpti_CallbackData size");

typedef void (*CUpti_CallbackFunc)(void *userdata,
                                   CUpti_CallbackDomain domain,
                                   CUpti_CallbackId cbid,
                                   const void *cbdata);

typedef void (*CUpti_BufferRequestFunc)(uint8_t **buffer, size_t *size,
                                        size_t *maxNumRecords);
typedef void (*CUpti_BufferCompletedFunc)(CUcontext ctx, uint32_t streamId,
                                          uint8_t *buffer, size_t size,
                                          size_t validSize);

typedef uint32_t CUpti_ActivityKind;
#define CUPTI_ACTIVITY_KIND_KERNEL            3
#define CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL 10
#define CUPTI_ACTIVITY_KIND_GRAPH_TRACE       51

typedef struct {
  uint32_t kind;
} CUpti_Activity;

// CUpti_ActivityKernel5: only the fields parcagpu reads are named.
typedef struct {
  uint32_t kind;            // offset 0
  uint8_t  _pad1[12];       // offset 4
  uint64_t start;           // offset 16
  uint64_t end;             // offset 24
  uint64_t completed;       // offset 32
  uint32_t deviceId;        // offset 40
  uint32_t contextId;       // offset 44
  uint32_t streamId;        // offset 48
  uint8_t  _pad2[40];       // offset 52
  uint32_t correlationId;   // offset 92
  int64_t  gridId;          // offset 96
  const char *name;         // offset 104
  uint64_t _reserved0;      // offset 112
  uint64_t queued;          // offset 120
  uint64_t submitted;       // offset 128
  uint8_t  _pad3[8];        // offset 136
  uint64_t graphNodeId;     // offset 144
  uint32_t shmemLimitCfg;   // offset 152
  uint32_t graphId;         // offset 156
} __attribute__((aligned(8))) CUpti_ActivityKernel5;

_Static_assert(sizeof(CUpti_ActivityKernel5) == 160, "CUpti_ActivityKernel5 size");

typedef struct {
  CUpti_ActivityKind kind;
  uint32_t correlationId;
  uint64_t start;
  uint64_t end;
  uint32_t deviceId;
  uint32_t graphId;
  uint32_t contextId;
  uint32_t streamId;
  void *reserved;
} __attribute__((aligned(8))) CUpti_ActivityGraphTrace;

_Static_assert(sizeof(CUpti_ActivityGraphTrace) == 48, "CUpti_ActivityGraphTrace size");

// Resource callback data.
typedef struct {
  CUcontext context;
  union {
    CUstream stream;
  } resourceHandle;
  void *resourceDescriptor;
} CUpti_ResourceData;

typedef struct {
  uint32_t moduleId;
  size_t cubinSize;
  const char *pCubin;
} CUpti_ModuleResourceData;

typedef uint32_t CUpti_ActivityAttribute;

#endif // MOCK_CUPTI_H
