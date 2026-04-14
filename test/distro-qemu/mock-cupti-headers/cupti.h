// Minimal CUPTI type definitions for building mock libraries.
// Only the types referenced by parcagpu's test/mock_cupti.c are needed.
// Struct layouts must be ABI-compatible with the real CUPTI headers.
#ifndef MOCK_CUPTI_H
#define MOCK_CUPTI_H

#include <stdint.h>
#include <stddef.h>
#include "cuda.h"

typedef int CUptiResult;
#define CUPTI_SUCCESS                  0
#define CUPTI_ERROR_MAX_LIMIT_REACHED  21
#define CUPTI_ERROR_INVALID_KIND       46

typedef void *CUpti_SubscriberHandle;

typedef enum {
  CUPTI_CB_DOMAIN_RUNTIME_API = 2,
  CUPTI_CB_DOMAIN_DRIVER_API  = 3,
  CUPTI_CB_DOMAIN_RESOURCE    = 4,
} CUpti_CallbackDomain;

typedef uint32_t CUpti_CallbackId;

#define CUPTI_CBID_RESOURCE_CONTEXT_CREATED 1
#define CUPTI_CBID_RESOURCE_MODULE_LOADED   4

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
#define CUPTI_ACTIVITY_KIND_GRAPH_TRACE       34

typedef struct {
  uint32_t kind;
} CUpti_Activity;

// CUpti_ActivityKernel5 — 160 bytes, matching cupti_activity.h.
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

// CUpti_ActivityGraphTrace — 64 bytes.
typedef struct {
  uint32_t kind;
  uint8_t  _pad[60];
} __attribute__((aligned(8))) CUpti_ActivityGraphTrace;

// Resource callback data.
typedef struct {
  CUcontext context;
  void     *resourceDescriptor;
} CUpti_ResourceData;

typedef struct {
  const char *pCubin;
  size_t      cubinSize;
} CUpti_ModuleResourceData;

// cuptiGetCubinCrc params.
typedef struct {
  const char *cubin;
  size_t      cubinSize;
  uint64_t    cubinCrc;
} CUpti_GetCubinCrcParams;

// cuptiGetSassToSourceCorrelation params.
typedef struct {
  uint64_t    pcOffset;
  const char *functionName;
  uint32_t    lineNumber;
  char       *fileName;
  char       *dirName;
} CUpti_GetSassToSourceCorrelationParams;

// cuptiActivitySetAttribute placeholder.
typedef uint32_t CUpti_ActivityAttribute;

#endif // MOCK_CUPTI_H
