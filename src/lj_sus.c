#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct dynamic_array_struct
{
  MEMORY_BASIC_INFORMATION* data;
  size_t capacity; /* total capacity */
  size_t size; /* number of elements in vector */
} MEMORY_BASIC_INFORMATION_VECTOR;
MEMORY_BASIC_INFORMATION_VECTOR* mbi_vector;

void push(MEMORY_BASIC_INFORMATION_VECTOR* vector, MEMORY_BASIC_INFORMATION element)
{
  if (vector->capacity == 0)
  {
    vector->capacity = 1;
    vector->data = (MEMORY_BASIC_INFORMATION*)malloc(sizeof(MEMORY_BASIC_INFORMATION));
  }
  else if (vector->capacity == vector->size)
  {
    vector->capacity *= 2;
    vector->data = (MEMORY_BASIC_INFORMATION*)realloc(vector->data, vector->capacity * sizeof(MEMORY_BASIC_INFORMATION));
  }
  vector->data[vector->size++] = element;
}

void pop(MEMORY_BASIC_INFORMATION_VECTOR* vector)
{
  if (vector->size == 0)
    return;
  --vector->size;
}

void erase(MEMORY_BASIC_INFORMATION_VECTOR* vector, size_t index)
{
  if (index >= vector->size)
    return;
  for (size_t i = index; i < vector->size - 1; ++i)
    vector->data[i] = vector->data[i + 1];
  --vector->size;
}

void* SusAlloc(void* you_wish, size_t dwSize, unsigned int flAllocationType, unsigned int flags)
{
  void* v = VirtualAlloc(you_wish, dwSize, flAllocationType, flags); //  + 0x100
  if (v == NULL)
    return NULL;

  //unsigned int SuperJunk = 0xDEADC0DE;
  //for (unsigned int i = 0; i < 0x50 / sizeof(unsigned int); ++i)
  //{
  //    SuperJunk ^= (i << (i % 32));
  //    SuperJunk -= 0x11111111;
  //    ((unsigned int*)((uintptr_t)v + dwSize))[i] = SuperJunk;
  //}
  
  if (mbi_vector == NULL)
  {
    mbi_vector = (MEMORY_BASIC_INFORMATION_VECTOR*)malloc(sizeof(MEMORY_BASIC_INFORMATION_VECTOR));
    mbi_vector->capacity = 0;
    mbi_vector->size = 0;
    mbi_vector->data = NULL;
  }
  MEMORY_BASIC_INFORMATION mbi;
  mbi.BaseAddress = v;
  mbi.AllocationBase = v;
  mbi.AllocationProtect = flAllocationType;
  mbi.RegionSize = dwSize;
  mbi.State = MEM_COMMIT;
  mbi.Protect = flAllocationType;
  mbi.Type = MEM_PRIVATE;
  push(mbi_vector, mbi);

  return (void*)((uintptr_t)v);
}

int SusFree(void* lpAddress, size_t dwSize, unsigned int dwFreeType)
{
  if (lpAddress == NULL)
    return NULL;

  //unsigned int SuperJunk = 0xDEADC0DE;
  //for (unsigned int i = 0; i < 0x50 / sizeof(unsigned int); ++i)
  //{
  //    SuperJunk ^= (i << (i % 32));
  //    SuperJunk -= 0x11111111;
  //    if (((unsigned int*)((uintptr_t)lpAddress + dwSize))[i] != SuperJunk)
  //    {
  //        __debugbreak();
  //    }
  //}

  BOOL result = VirtualFree(lpAddress, 0, dwFreeType);

  if (mbi_vector == NULL || result == 0)
    return result;

  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (mbi_vector->data[i].BaseAddress == lpAddress)
    {
      erase(mbi_vector, i);
      return result;
    }
  }

  return result;
}

size_t SusQuery(void* lpAddress, void* lpBuffer, size_t dwLength)
{
  if (lpAddress == NULL)
    return NULL;

  if (mbi_vector == NULL)
    return NULL;

  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (mbi_vector->data[i].BaseAddress == lpAddress)
    {
      *(PMEMORY_BASIC_INFORMATION)lpBuffer = mbi_vector->data[i];
      return lpBuffer;
    }
  }

  return NULL;
}