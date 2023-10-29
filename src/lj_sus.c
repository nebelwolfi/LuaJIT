#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN

#include "C:/LuaJIT-2.1.M.64/phnt/phnt_windows.h"
#include "C:/LuaJIT-2.1.M.64/phnt/phnt.h"

#include <minwindef.h>
#include <stdio.h>

#include "lj_sus_mm.h"

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

#ifdef _WIN64
typedef struct POINTER_LIST {
    struct POINTER_LIST *next;
    void *address;
} POINTER_LIST;
#endif

typedef struct {
    PIMAGE_NT_HEADERS headers;
    unsigned char *codeBase;
    HCUSTOMMODULE *modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    CustomAllocFunc alloc;
    CustomFreeFunc free;
    CustomLoadLibraryFunc loadLibrary;
    CustomGetProcAddressFunc getProcAddress;
    CustomFreeLibraryFunc freeLibrary;
    struct ExportNameEntry *nameExportsTable;
    void *userdata;
    ExeEntryProc exeEntry;
    DWORD pageSize;
#ifdef _WIN64
    POINTER_LIST *blockedMemory;
#endif
} MEMORYMODULE, *PMEMORYMODULE;

int printf(const char *fmt, ...);

typedef struct dynamic_array_struct
{
  void** data;
  size_t capacity; /* total capacity */
  size_t size; /* number of elements in vector */
} PVOID_VECTOR;
PVOID_VECTOR* mbi_vector = NULL;

typedef struct {
  MEMORYMODULE *m;
  char *name;
  uint32_t hash;
} LOADEDMEMORYMODULE;
PVOID_VECTOR* mm_vector = NULL;

PVOID_VECTOR* init_vector()
{
  PVOID_VECTOR* vector = (PVOID_VECTOR*)malloc(sizeof(PVOID_VECTOR));
  vector->capacity = 0;
  vector->size = 0;
  vector->data = NULL;
  //printf("Allocated vector\n");
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
  //printf("SusAlloc\n");
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
  
  //printf("Allocating 1\n");

  if (mbi_vector == NULL)
    mbi_vector = init_vector();
  //printf("Allocating 2\n");

  PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
  mbi->BaseAddress = v;
  mbi->AllocationBase = v;
  mbi->AllocationProtect = flAllocationType;
  mbi->RegionSize = dwSize;
  mbi->State = MEM_COMMIT;
  mbi->Protect = flAllocationType;
  mbi->Type = MEM_PRIVATE;
  push(mbi_vector, mbi);

  //printf("Allocated %p (%d), now %d elements\n", v, dwSize, mbi_vector->size);

  return (void*)((uintptr_t)v);
}

int SusFree(void* lpAddress, size_t dwSize, unsigned long dwFreeType)
{
  //printf("SusFree\n");
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
      //printf("Erased %p (%d), now %d elements\n", lpAddress, ((PMEMORY_BASIC_INFORMATION)mbi_vector->data[i])->RegionSize, mbi_vector->size);
      return result;
    }
  }

  return result;
}

size_t SusQuery(void* lpAddress, void* lpBuffer, size_t dwLength)
{
  //printf("SusQuery\n");
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

uint32_t HashDataFNV1a(const char* data, uint32_t len)
{
  uint32_t hash = 0x811C9DC5;

  for (uint32_t i = 0; i < len; i++)
  {
    char c = data[i];
    hash ^= c;
    hash *= 0x1000193;
  }

  return hash;
}
uint32_t HashStringCaseInsensitiveFNV1a(const char* str)
{
  uint32_t hash = 0x811C9DC5;

  for (; *str; str++)
  {
    char c = *str;
    if (c >= 'A' && c <= 'Z')
    {
      c += 'a' - 'A';
    }

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
  //printf("SusGetModuleHandleH\n");
  if (mm_vector != NULL)
  {
    for (size_t i = 0; i < mm_vector->size; ++i)
    {
      LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)mm_vector->data[i];
      if (mm->hash == hash)
      {
        return mm->m;
      }
    }
  }

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
  printf("SusGetModuleHandleA %s\n", lpModuleName);
  if (!lpModuleName)
    return (void*)NtCurrentPeb()->ImageBaseAddress;

  uint32_t hash = HashStringCaseInsensitiveFNV1a(lpModuleName);

  if (mm_vector != NULL)
  {
    //printf("why %p\n", mm_vector);
    for (size_t i = 0; i < mm_vector->size; ++i)
    {
      LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)mm_vector->data[i];
      //printf("mm->name %s vs %s\n", mm->name, lpModuleName);
      if (mm->hash == hash)
      {
        return mm->m;
      }
    }
  }

  LIST_ENTRY* ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
  LIST_ENTRY* ListEntry = ListHead->Flink;

  while (ListEntry != ListHead)
  {
    LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (HashStringCaseInsensitiveFNV1aW(LdrEntry->BaseDllName.Buffer) == hash)
    {
      //wprintf(L"Found in LOML %s | %p\n", LdrEntry->BaseDllName.Buffer, LdrEntry->DllBase);
      return (void*)LdrEntry->DllBase;
    }
    ListEntry = ListEntry->Flink;
  }

  printf("GetModuleHandleA Unresolved (%s)\n", lpModuleName);

  return NULL;
}

BOOL MemoryIsModuleFromLibrary(void* mod)
{
  if (mm_vector != NULL)
    for (size_t i = 0; i < mm_vector->size; ++i)
    {
      LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)mm_vector->data[i];
      if (mm->m == mod)
        return 1;
    }
  return 0;
}

void* SusGetProcAddress(void *L, void* hModule, const char* lpProcName)
{
  printf("MemoryIsModuleFromLibrary? %p %s %d\n", hModule, lpProcName, MemoryIsModuleFromLibrary(hModule));
  if (MemoryIsModuleFromLibrary(hModule))
    return MemoryGetProcAddress(hModule, lpProcName);
  printf("SusGetProcAddress %p %s\n", hModule, lpProcName);
  //return GetProcAddress(hModule, lpProcName);
  if (hModule == NULL)
    return NULL;

  IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
  IMAGE_NT_HEADERS64* NtHeaders = (IMAGE_NT_HEADERS64*)((uintptr_t)DosHeader + DosHeader->e_lfanew);
  IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)DosHeader + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  uint32_t* AddressOfNames = (uint32_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfNames);
  uint16_t* AddressOfNameOrdinals = (uint16_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfNameOrdinals);
  uint32_t* AddressOfFunctions = (uint32_t*)((uintptr_t)DosHeader + ExportDirectory->AddressOfFunctions);

  //printf("SusGetProcAddress(%p, %s) | NumberOfNames %d | NumberOfFunctions %d\n", hModule, lpProcName, ExportDirectory->NumberOfNames, ExportDirectory->NumberOfFunctions);

  if ((uintptr_t)lpProcName > 0xFFFF)
  {
    uint32_t hash = HashStringCaseInsensitiveFNV1a(lpProcName);
    for (uint32_t i = 0; i < ExportDirectory->NumberOfNames; ++i)
    {
      char* Name = (char*)((uintptr_t)DosHeader + AddressOfNames[i]);
      if (HashStringCaseInsensitiveFNV1a(Name) == hash)
      {
        uint16_t Ordinal = AddressOfNameOrdinals[i];
        //printf("Ordinal: %d\n", Ordinal);
        uint32_t RVA = AddressOfFunctions[Ordinal];
        if (RVA >= NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && RVA < NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
        {
          printf("Forwarded export: %s\n", (char*)((uintptr_t)DosHeader + RVA));
          char* fwd = (char*)((uintptr_t)DosHeader + RVA);
          char* dot = strchr(fwd, '.');
          if (dot == NULL)
            return NULL;
          char dll[0x100];
          memcpy(dll, fwd, dot - fwd);
          dll[dot - fwd] = 0;
          uint32_t dllHash = HashDataFNV1a(fwd, dot - fwd);
          void* hDll = SusGetModuleHandleH(dllHash);
          if (hDll == NULL) {
            hDll = SusLoadLibraryExA(L, dll, NULL, 0);
            //printf("LoadLibraryA: %s => %p\n", dll, hDll);
            if (hDll == NULL)
              return NULL;
          }
          printf("lpProcName: %s | hDll: %p\n", dot + 1, hDll);
          return SusGetProcAddress(L, hDll, dot + 1);
        }
        printf("Res: %p | GetProcAddress: %p\n", (void*)((uintptr_t)hModule + RVA), GetProcAddress(hModule, lpProcName));
        return (void*)((uintptr_t)hModule + RVA);
      }
    }
  } else {
    for (uint32_t i = 0; i < ExportDirectory->NumberOfNames; ++i)
    {
      uint16_t Ordinal = AddressOfNameOrdinals[i];
      if ((uint16_t)lpProcName == Ordinal)
      {
        uint32_t RVA = AddressOfFunctions[Ordinal];
        return (void*)((uintptr_t)DosHeader + RVA);
      }
    }
  }

  printf("GetProcAddress Unresolved (%p, %s)\n", hModule, lpProcName);

  return NULL;
}

static int readable(const char *filename)
{
  //printf("readable(%s)\n", filename); // readable(.\?.dll)
  return GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
}

static const char *pushnexttemplate(lua_State *L, const char *path)
{
  const char *l;
  while (*path == *LUA_PATHSEP) path++;  /* skip separators */
  if (*path == '\0') return NULL;  /* no more templates */
  l = strchr(path, *LUA_PATHSEP);  /* find next separator */
  if (l == NULL) l = path + strlen(path);
  lua_pushlstring(L, path, (size_t)(l - path));  /* template */
  return l;
}

static const char *searchpath (lua_State *L, const char *name,
			       const char *path, const char *sep,
			       const char *dirsep)
{
  char mname[0x100];
  // ends in .dll?
  size_t strl = strlen(name);
  if (strl > 4 && strcmp(name + strl - 4, ".dll") == 0)
  {
    strcpy(mname, name);
    mname[strl - 4] = 0;
    name = mname;
    strl -= 4;
  } else {
    strcpy(mname, name);
  }
  if (*sep != '\0')  /* non-empty separator? */
  {
    for (char* l = mname; *l; ++l)  /* replace it by 'dirsep' */
      if (*l == *sep) *l = *dirsep;
  }
  //printf("mname: %s\n", mname); // mname: .\?.dll
  while ((path = pushnexttemplate(L, path)) != NULL) {
    char* pat = lua_tostring(L, -1);
    //printf("pat: %s\n", pat); // pat: .\?.dll
    int count = 0;
    for (char* l = pat; *l; ++l)
      if (*l == *LUA_PATH_MARK) ++count;
    char* filename = (char*)malloc(strlen(pat) + strl * count + 1);
    char* p = filename;
    for (char* l = pat; *l; ++l)
    {
      if (*l == *LUA_PATH_MARK)
      {
        strcpy(p, mname);
        p += strl;
      } else {
        *p++ = *l;
      }
    }
    *p = 0;
    lua_pop(L, 1);
    //printf("filename: %s\n", filename); // filename: .\?.dll
    if (readable(filename))  /* does file exist and is readable? */
      return filename;  /* return that file name */
    lua_pop(L, 1);
  }
  return NULL;  /* not found */
}

HCUSTOMMODULE SusLoadLibraryA(void *L, LPCSTR lpLibFileName)
{
  return SusLoadLibraryExA(L, lpLibFileName, NULL, 0); 
}

void SusFreeLibrary(void *L, HCUSTOMMODULE hLibModule)
{
  MemoryFreeLibrary(hLibModule);
}

void* TryFile(lua_State *L, const char* lpLibFileName, const char* orig_lpLibFileName)
{
  HANDLE f = CreateFileA(lpLibFileName, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
  {
    //printf("f: %p, INVALID_HANDLE_VALUE\n", f);
    return NULL;
  }

  size_t size;
  GetFileSizeEx(f, &size);

	HANDLE hMapping = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hMapping == INVALID_HANDLE_VALUE)
	{
		CloseHandle(f);
		return NULL;
	}

	char* fileBuffer = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMapping);
	CloseHandle(f);

  //printf("fileName: %s, fileBuffer: %p, size: %d\n", lpLibFileName, fileBuffer, size);

  void* res = MemoryLoadLibraryEx(fileBuffer, size, SusAlloc, SusFree, SusLoadLibraryA, SusGetModuleHandleA, SusGetProcAddress, SusFreeLibrary, L, orig_lpLibFileName);
  if (res) {
    if (mm_vector == NULL)
      mm_vector = init_vector();
    LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)malloc(sizeof(LOADEDMEMORYMODULE));
    mm->m = res;
    mm->name = (char*)malloc(strlen(orig_lpLibFileName) + 1);
    strcpy(mm->name, orig_lpLibFileName);
    mm->hash = HashStringCaseInsensitiveFNV1a(orig_lpLibFileName);
    push(mm_vector, mm);
  }
  return res;
}

void* SusLoadLibraryExA(lua_State *L, const char* lpLibFileName, void* hFile, unsigned long dwFlags)
{
  //printf("SusLoadLibraryExA\n");
  printf("SusLoadLibraryExA(%s, %p, %d)\n", lpLibFileName, hFile, dwFlags);
  if (lpLibFileName == NULL)
    return NULL;
  {
    printf("> LoadLibraryExA(%s, %p, %d) | orig %s\n", lpLibFileName, hFile, dwFlags, lpLibFileName);
    PMEMORYMODULE result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    result->codeBase = LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    printf("< LoadLibraryExA(%s, %p, %d) | orig %s\n", lpLibFileName, hFile, dwFlags, lpLibFileName);
    return result;
  }

  const char* orig_lpLibFileName = lpLibFileName;
  
  if (!readable(lpLibFileName))
  {
    if (L)
    {
      //printf("L: %p, !readable(%s)\n", L, lpLibFileName);
      lua_getglobal(L, "package");
      lua_getfield(L, -1, "cpath");
      const char* cpath = lua_tostring(L, -1);
      lua_pop(L, 2);
      //printf("cpath: %s\n", cpath);
      const char *filename = searchpath(L, lpLibFileName, cpath, ".", LUA_DIRSEP);
      if (filename != NULL) {
        //printf("filename: %s\n", filename);
        lpLibFileName = filename;
      }
    }
    if (!readable(lpLibFileName)) {
      // try .dll
      char tmpfilename[0x100];
      strcpy(tmpfilename, lpLibFileName);
      strcat(tmpfilename, ".dll");
      if (readable(tmpfilename)) {
        lpLibFileName = tmpfilename;
        void* LMM = TryFile(L, lpLibFileName, orig_lpLibFileName);
        if (LMM != NULL)
          return LMM;
      }
      // try system32
      strcpy(tmpfilename, "C:\\Windows\\system32\\");
      strcat(tmpfilename, lpLibFileName);
      if (readable(tmpfilename)) {
        lpLibFileName = tmpfilename;
        void* LMM = TryFile(L, lpLibFileName, orig_lpLibFileName);
        if (LMM != NULL)
          return LMM;
      }
      // try system32.dll
      strcat(tmpfilename, ".dll");
      if (readable(tmpfilename)) {
        lpLibFileName = tmpfilename;
        void* LMM = TryFile(L, lpLibFileName, orig_lpLibFileName);
        if (LMM != NULL)
          return LMM;
      }
    }
  }

  void* LMM = TryFile(L, lpLibFileName, orig_lpLibFileName);
  if (LMM != NULL)
    return LMM;
  LMM = TryFile(L, orig_lpLibFileName, orig_lpLibFileName);
  if (LMM != NULL)
    return LMM;
  printf("> LoadLibraryExA(%s, %p, %d) | orig %s\n", orig_lpLibFileName, hFile, dwFlags, lpLibFileName);
  PMEMORYMODULE result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
  result->codeBase = LoadLibraryExA(lpLibFileName, hFile, dwFlags);
  printf("< LoadLibraryExA(%s, %p, %d) | orig %s | %p\n", orig_lpLibFileName, hFile, dwFlags, lpLibFileName, LMM);
  return result;
}