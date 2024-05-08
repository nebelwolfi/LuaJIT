#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN

#include "../phnt/phnt_windows.h"
#include "../phnt/phnt.h"

#include <minwindef.h>

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

#ifdef _WIN64
typedef struct POINTER_LIST {
    struct POINTER_LIST *next;
    void *address;
} POINTER_LIST;
#endif

//int printf(const char *fmt, ...);
//int sprintf(char* const _Buffer, char const* const _Format, ...);
//int wprintf(const wchar_t *fmt, ...);
#include <stdio.h>

typedef struct dynamic_array_struct
{
  MEMORY_BASIC_INFORMATION* data;
  size_t capacity; /* total capacity */
  size_t size; /* number of elements in vector */
} MBI_VECTOR;
MBI_VECTOR* mbi_vector = NULL;
CRITICAL_SECTION CriticalSection;

void init_vector()
{
  InitializeCriticalSection(&CriticalSection);
  EnterCriticalSection(&CriticalSection);
  mbi_vector = (MBI_VECTOR*)malloc(sizeof(MBI_VECTOR));
  mbi_vector->capacity = 0;
  mbi_vector->size = 0;
  mbi_vector->data = NULL;
  ////printf("Allocated vector\n");
  LeaveCriticalSection(&CriticalSection);
}

void push(MBI_VECTOR* vector, MEMORY_BASIC_INFORMATION* value)
{
  if (vector->capacity == 0)
  {
    vector->capacity = 1000;
    vector->data = (MEMORY_BASIC_INFORMATION*)malloc(vector->capacity * sizeof(MEMORY_BASIC_INFORMATION));
  }
  else if (vector->capacity == vector->size)
  {
    vector->capacity *= 2;
    MEMORY_BASIC_INFORMATION* new_data = (MEMORY_BASIC_INFORMATION*)realloc(vector->data, vector->capacity * sizeof(MEMORY_BASIC_INFORMATION));
    if (new_data == NULL)
    {
      free(vector->data);
      vector->data = (MEMORY_BASIC_INFORMATION*)malloc(vector->capacity * sizeof(MEMORY_BASIC_INFORMATION));
    } else {
      vector->data = new_data;
    }
  }
  memcpy(vector->data + vector->size++, value, sizeof(MEMORY_BASIC_INFORMATION));
}

void erase(MBI_VECTOR* vector, size_t index)
{
  if (index >= vector->size)
    return;
  for (size_t i = index; i < vector->size - 1; ++i)
    vector->data[i] = vector->data[i + 1];
  --vector->size;
}

void* SusAlloc(void* you_wish, size_t dwSize, unsigned long flAllocationType, unsigned long flags)
{
  ////printf("SusAlloc\n");
  void* v = VirtualAlloc(you_wish, dwSize, flAllocationType, flags); //  + 0x100
  if (v == NULL) {
    v = VirtualAlloc(NULL, dwSize, flAllocationType, flags);
    if (v == NULL) {
      //printf("Failed to allocate %d bytes\n", dwSize);
      return NULL;
    }
  }

  //unsigned int SuperJunk = 0xDEADC0DE;
  //for (unsigned int i = 0; i < 0x50 / sizeof(unsigned int); ++i)
  //{
  //    SuperJunk ^= (i << (i % 32));
  //    SuperJunk -= 0x11111111;
  //    ((unsigned int*)((uintptr_t)v + dwSize))[i] = SuperJunk;
  //}
  
  ////printf("Allocating 1\n");

  if (mbi_vector == NULL)
    init_vector();
  ////printf("Allocating 2\n");

  MEMORY_BASIC_INFORMATION mbi = { 0 };
  mbi.BaseAddress = v;
  mbi.AllocationBase = v;
  mbi.AllocationProtect = flags;
  mbi.RegionSize = dwSize;
  mbi.State = flAllocationType;
  mbi.Protect = flags;
  mbi.Type = MEM_PRIVATE;
  mbi.PartitionId = 0;
  EnterCriticalSection(&CriticalSection);
  push(mbi_vector, &mbi);
  LeaveCriticalSection(&CriticalSection);

  //{
  //  size_t total = 0;
  //  EnterCriticalSection(&CriticalSection);
  //  for (size_t i = 0; i < mbi_vector->size; ++i)
  //    total += mbi_vector->data[i].RegionSize;
  //  LeaveCriticalSection(&CriticalSection);
  //  printf("Allocated %p (%llx), now %lld elements using %lld bytes\n", v, dwSize, mbi_vector->size, total);
  //}

  return (void*)((uintptr_t)v);
}

size_t SusCount()
{
  ////printf("SusCount\n");
  if (mbi_vector == NULL)
    return 0;
  size_t total = 0;
  EnterCriticalSection(&CriticalSection);
  for (size_t i = 0; i < mbi_vector->size; ++i)
    total += mbi_vector->data[i].RegionSize;
  LeaveCriticalSection(&CriticalSection);
  return total;
}

int SusFree(void* lpAddress, size_t dwSize, unsigned long dwFreeType)
{
  ////printf("SusFree\n");
  if (lpAddress == NULL)
    return 0;

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

  EnterCriticalSection(&CriticalSection);
  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (mbi_vector->data[i].BaseAddress == lpAddress)
    {
      //printf("Erased %p (%llX) (%lld elements) => ", lpAddress, mbi_vector->data[i].RegionSize, mbi_vector->size);
      erase(mbi_vector, i);
      //printf("%lld elements\n", mbi_vector->size);
      LeaveCriticalSection(&CriticalSection);
      return result;
    }
  }
  LeaveCriticalSection(&CriticalSection);

  //printf("Trying to free %p (%llX) but it's not in the vector\n", lpAddress, dwSize);

  return result;
}

size_t SusQuery(void* lpAddress, void* lpBuffer, size_t dwLength)
{
  ////printf("SusQuery\n");
  if (lpAddress == NULL)
    return 0;

  if (mbi_vector == NULL)
    return 0;

  EnterCriticalSection(&CriticalSection);
  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (mbi_vector->data[i].BaseAddress == lpAddress)
    {
      //printf("Queried %p | %p | %llx\n", lpAddress, mbi_vector->data[i].BaseAddress, mbi_vector->data[i].RegionSize);
      memcpy(lpBuffer, mbi_vector->data + i, dwLength);
      LeaveCriticalSection(&CriticalSection);
      return sizeof(MEMORY_BASIC_INFORMATION);
    }
  }
  LeaveCriticalSection(&CriticalSection);

  //printf("Trying to query %p but it's not in the vector\n", lpAddress);

  return 0;
}

uint32_t HashStringCaseInsensitiveFNV1a(const char* str)
{
  uint32_t hash = 0x811C9DC5;

  for (; *str; str++)
  {
    char c = *str;
    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';

    hash ^= c;
    hash *= 0x1000193;
  }

  return hash;
}
uint32_t HashStringCaseInsensitiveFNV1aW(const wchar_t* str)
{
  uint32_t hash = 0x811C9DC5;

  for (; *str; str++)
  {
    wchar_t c = *str;
    if (c >= L'A' && c <= L'Z')
    {
      c += L'a' - L'A';
    }

    hash ^= c;
    hash *= 0x1000193;
  }

  return hash;
}

void* SusGetModuleHandleH(uint32_t hash)
{
  if (!hash)
    return (void*)NtCurrentPeb()->ImageBaseAddress;

  LIST_ENTRY* ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
  LIST_ENTRY* ListEntry = ListHead->Flink;

  while (ListEntry != ListHead)
  {
    LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (HashStringCaseInsensitiveFNV1aW(LdrEntry->BaseDllName.Buffer) == hash)
    {
      return (void*)LdrEntry->DllBase;
    }
    ListEntry = ListEntry->Flink;
  }

  return NULL;
}

void* SusGetModuleHandleA(void *L, const char* lpModuleName)
{
  if (!lpModuleName)
    return (void*)NtCurrentPeb()->ImageBaseAddress;

  uint32_t hash = HashStringCaseInsensitiveFNV1a(lpModuleName);

  LIST_ENTRY* ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
  LIST_ENTRY* ListEntry = ListHead->Flink;

  while (ListEntry != ListHead)
  {
    LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (HashStringCaseInsensitiveFNV1aW(LdrEntry->BaseDllName.Buffer) == hash)
    {
      return (void*)LdrEntry->DllBase;
    }
    ListEntry = ListEntry->Flink;
  }

  return NULL;
}

void* SusGetProcAddress(void *L, void* hModule, const char* lpProcName)
{
  if (hModule == NULL)
    return NULL;

  IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
  IMAGE_NT_HEADERS64* NtHeaders = (IMAGE_NT_HEADERS64*)((uintptr_t)DosHeader + DosHeader->e_lfanew);
  IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)DosHeader + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  uint16_t* AddressOfNameOrdinals = (uint16_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfNameOrdinals);
  uint32_t* AddressOfFunctions = (uint32_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfFunctions);

	FARPROC funcAddress = NULL;

  if ((uintptr_t)lpProcName > 0xFFFF)
  {
    uint32_t* AddressOfNames = (uint32_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfNames);
    uint32_t hash = HashStringCaseInsensitiveFNV1a(lpProcName);
    for (uint32_t i = 0; i < ExportDirectory->NumberOfNames; ++i)
    {
      char* Name = (char*)((uintptr_t)DosHeader + AddressOfNames[i]);
      if (HashStringCaseInsensitiveFNV1a(Name) == hash)
      {
        uint16_t Ordinal = AddressOfNameOrdinals[i];
        uint32_t RVA = AddressOfFunctions[Ordinal];
        funcAddress = (void*)((uintptr_t)hModule + RVA);
        break;
      }
    }
  } else {
      uint16_t Ordinal = (uint16_t)lpProcName - ExportDirectory->Base;
      if (Ordinal >= ExportDirectory->NumberOfFunctions)
        return NULL;
      funcAddress = (void*)((uintptr_t)DosHeader + AddressOfFunctions[Ordinal]);
  }

  if (funcAddress >= NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (uintptr_t)hModule &&
    funcAddress < NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size + (uintptr_t)hModule)
  {
    HMODULE hDll;
    char* forwardedFunctionName = (char*)funcAddress;
    uint32_t hash = 0x811C9DC5;
    for (uint32_t i = 0; i < strlen(forwardedFunctionName); ++i)
    {
      if (forwardedFunctionName[i] >= 'A' && forwardedFunctionName[i] <= 'Z')
        hash = (hash ^ (forwardedFunctionName[i] + 'a' - 'A')) * 0x1000193;
      else
        hash = (hash ^ forwardedFunctionName[i]) * 0x1000193;
      if (forwardedFunctionName[i] == '.')
      {
        hash = (hash ^ 'd') * 0x1000193;
        hash = (hash ^ 'l') * 0x1000193;
        hash = (hash ^ 'l') * 0x1000193;
        hDll = SusGetModuleHandleH(hash);
        if (hDll == NULL) {
          char* dllName = (char*)malloc(i + 5);
          memcpy(dllName, forwardedFunctionName, i);
          dllName[i] = '.';
          dllName[i + 1] = 'd';
          dllName[i + 2] = 'l';
          dllName[i + 3] = 'l';
          dllName[i + 4] = '\0';
          hDll = LoadLibraryExA(dllName, NULL, 0);
          free(dllName);
        }
        if (hDll == NULL)
          return NULL;
        forwardedFunctionName = forwardedFunctionName + i + 1;
        break;
      }
    }
    if ((forwardedFunctionName[0] == '#') && forwardedFunctionName[1] != '\0') {
      uint16_t ord = 0;
      for (forwardedFunctionName++; *forwardedFunctionName; ++forwardedFunctionName)
        ord = ord * 10 + forwardedFunctionName[0] - '0';
      funcAddress = SusGetProcAddress(L, hDll, (LPCSTR)ord);
    }
    else {
      funcAddress = SusGetProcAddress(L, hDll, forwardedFunctionName);
    }
  }

  if (!funcAddress) {
    return NULL;
  }
  
  return funcAddress;
}
