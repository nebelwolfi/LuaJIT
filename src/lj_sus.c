#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN

#include "C:/LuaJIT-2.1.M.64/phnt/phnt_windows.h"
#include "C:/LuaJIT-2.1.M.64/phnt/phnt.h"

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
  void** data;
  size_t capacity; /* total capacity */
  size_t size; /* number of elements in vector */
} PVOID_VECTOR;
PVOID_VECTOR* mbi_vector = NULL;

PVOID_VECTOR* init_vector()
{
  PVOID_VECTOR* vector = (PVOID_VECTOR*)malloc(sizeof(PVOID_VECTOR));
  vector->capacity = 0;
  vector->size = 0;
  vector->data = NULL;
  ////printf("Allocated vector\n");
  return vector;
}

void push(PVOID_VECTOR* vector, void* element)
{
  if (vector->capacity == 0)
  {
    vector->capacity = 1;
    vector->data = (void**)malloc(sizeof(void*));
  }
  else if (vector->capacity == vector->size)
  {
    vector->capacity *= 2;
    vector->data = (void**)realloc(vector->data, vector->capacity * sizeof(void*));
  }
  vector->data[vector->size++] = element;
}

void pop(PVOID_VECTOR* vector)
{
  if (vector->size == 0)
    return;
  --vector->size;
}

void erase(PVOID_VECTOR* vector, size_t index)
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
  if (v == NULL)
    return NULL;

  //unsigned int SuperJunk = 0xDEADC0DE;
  //for (unsigned int i = 0; i < 0x50 / sizeof(unsigned int); ++i)
  //{
  //    SuperJunk ^= (i << (i % 32));
  //    SuperJunk -= 0x11111111;
  //    ((unsigned int*)((uintptr_t)v + dwSize))[i] = SuperJunk;
  //}
  
  ////printf("Allocating 1\n");

  if (mbi_vector == NULL)
    mbi_vector = init_vector();
  ////printf("Allocating 2\n");

  PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
  mbi->BaseAddress = v;
  mbi->AllocationBase = v;
  mbi->AllocationProtect = flAllocationType;
  mbi->RegionSize = dwSize;
  mbi->State = MEM_COMMIT;
  mbi->Protect = flAllocationType;
  mbi->Type = MEM_PRIVATE;
  push(mbi_vector, mbi);

  ////printf("Allocated %p (%d), now %d elements\n", v, dwSize, mbi_vector->size);

  return (void*)((uintptr_t)v);
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

  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (((PMEMORY_BASIC_INFORMATION)mbi_vector->data[i])->BaseAddress == lpAddress)
    {
      erase(mbi_vector, i);
      ////printf("Erased %p (%d), now %d elements\n", lpAddress, ((PMEMORY_BASIC_INFORMATION)mbi_vector->data[i])->RegionSize, mbi_vector->size);
      return result;
    }
  }

  return result;
}

size_t SusQuery(void* lpAddress, void* lpBuffer, size_t dwLength)
{
  ////printf("SusQuery\n");
  if (lpAddress == NULL)
    return 0;

  if (mbi_vector == NULL)
    return 0;

  for (size_t i = 0; i < mbi_vector->size; ++i)
  {
    if (((PMEMORY_BASIC_INFORMATION)mbi_vector->data[i])->State == lpAddress)
    {
      *(PMEMORY_BASIC_INFORMATION)lpBuffer = *((PMEMORY_BASIC_INFORMATION)mbi_vector->data[i]);
      return sizeof(MEMORY_BASIC_INFORMATION);
    }
  }

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