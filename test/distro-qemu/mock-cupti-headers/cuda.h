// Minimal CUDA Driver API type definitions for building mock libraries.
// Only the types referenced by parcagpu's test/mock_cuda.c are needed.
#ifndef MOCK_CUDA_H
#define MOCK_CUDA_H

typedef int CUresult;
#define CUDA_SUCCESS 0
#define CUDA_ERROR_INVALID_VALUE 1

typedef void *CUcontext;
typedef int CUdevice;

typedef enum CUdevice_attribute_enum {
  CU_DEVICE_ATTRIBUTE_CLOCK_RATE,
  CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
  CU_DEVICE_ATTRIBUTE_MAX
} CUdevice_attribute;

#endif // MOCK_CUDA_H
