// Minimal CUDA Driver API type definitions for building mock libraries.
// Only the types referenced by parcagpu's test/mock_cuda.c are needed.
// Values match the real cuda.h.
#ifndef MOCK_CUDA_H
#define MOCK_CUDA_H

typedef int CUresult;
#define CUDA_SUCCESS               0
#define CUDA_ERROR_INVALID_VALUE   1
#define CUDA_ERROR_INVALID_CONTEXT 201

typedef void *CUcontext;
typedef void *CUstream;
typedef int CUdevice;

typedef struct CUuuid_st {
  char bytes[16];
} CUuuid;

typedef enum CUdevice_attribute_enum {
  CU_DEVICE_ATTRIBUTE_CLOCK_RATE           = 13,
  CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT = 16,
} CUdevice_attribute;

#endif // MOCK_CUDA_H
