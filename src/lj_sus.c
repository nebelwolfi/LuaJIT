#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN

#include "C:/LuaJIT-2.1.M.64/phnt/phnt_windows.h"
#include "C:/LuaJIT-2.1.M.64/phnt/phnt.h"

#include <minwindef.h>

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

typedef struct {
  PMEMORYMODULE m;
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

  //printf(" ====== SusGetModuleHandleA %s ====== \n", lpModuleName);

  uint32_t hash = HashStringCaseInsensitiveFNV1a(lpModuleName);

  //if (mm_vector != NULL)
  //{
  //  ////printf("why %p\n", mm_vector);
  //  for (size_t i = 0; i < mm_vector->size; ++i)
  //  {
  //    LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)mm_vector->data[i];
  //    //printf("mm->name %s vs %s\n", mm->name, lpModuleName);
  //    if (mm->hash == hash)
  //    {
  //      return mm->m->codeBase;
  //    }
  //  }
  //}

  LIST_ENTRY* ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
  LIST_ENTRY* ListEntry = ListHead->Flink;

  while (ListEntry != ListHead)
  {
    LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    //wprintf(L"LdrEntry %p => %s\n", LdrEntry->DllBase, LdrEntry->BaseDllName.Buffer);
    if (HashStringCaseInsensitiveFNV1aW(LdrEntry->BaseDllName.Buffer) == hash)
    {
      //wprintf(L"Found in LOML %s | %p\n", LdrEntry->BaseDllName.Buffer, LdrEntry->DllBase);
      return (void*)LdrEntry->DllBase;
    }
    ListEntry = ListEntry->Flink;
  }

  //printf("GetModuleHandleA Unresolved (%p, %s)\n", L, lpModuleName);

  return NULL; // SusLoadLibraryExA(L, lpModuleName, NULL, 0);
}

/*BOOL MemoryIsModuleFromLibrary(void* mod)
{
  if (mm_vector != NULL)
    for (size_t i = 0; i < mm_vector->size; ++i)
    {
      LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)mm_vector->data[i];
      if (mm->m == mod)
        return 1;
    }
  return 0;
}*/

void* SusGetProcAddress(void *L, void* hModule, const char* lpProcName)
{
  if (hModule == NULL)
    return NULL;

  //printf(" >>>>>> GetProcAddress %p\n      ? %s\n", hModule, lpProcName);

  IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
  IMAGE_NT_HEADERS64* NtHeaders = (IMAGE_NT_HEADERS64*)((uintptr_t)DosHeader + DosHeader->e_lfanew);
  IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)DosHeader + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  ////printf("SusGetProcAddress(%p, %s) | NumberOfNames %d | NumberOfFunctions %d\n", hModule, lpProcName, ExportDirectory->NumberOfNames, ExportDirectory->NumberOfFunctions);

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
      ////printf("Name %s | %p | %X == %X\n", Name, (void*)((uintptr_t)hModule + AddressOfFunctions[AddressOfNameOrdinals[i]]), hash, HashStringCaseInsensitiveFNV1a(Name));
      if (HashStringCaseInsensitiveFNV1a(Name) == hash)
      {
        uint16_t Ordinal = AddressOfNameOrdinals[i];
        uint32_t RVA = AddressOfFunctions[Ordinal];
        funcAddress = (void*)((uintptr_t)hModule + RVA);
        ////printf("Found %s | %p\n", Name, funcAddress);
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
    //printf("Forwarded export: %s | Would be %p vs base %p\n",
    //  (char*)(funcAddress),
    //  GetProcAddress(hModule, lpProcName),
    //  (void*)((uintptr_t)hModule)
    //);
    //return GetProcAddress(hModule, lpProcName); // TODO: Forwarded export
		/*char *dllName = malloc(MAX_PATH);
		char *funcName = malloc(256);
		char *thedot = strchr((char *)funcAddress, '.');
		lstrcpynA(funcName, ++thedot, 256);
		lstrcpynA(dllName, (char *)funcAddress, (thedot - (char *)funcAddress));
		lstrcatA(dllName, ".dll");
    HMODULE hDll = SusGetModuleHandleA(L, dllName);
    if (hDll == NULL)
      hDll = SusLoadLibraryExA(NULL, dllName, NULL, 0);
    if (hDll == NULL)
      return NULL;
		if((lstrlenA(funcName) > 1) && (funcName[0] == '#'))
    {
      funcAddress = SusGetProcAddress(L, hDll, (LPCSTR)atoi(&funcName[1]));
      ////printf("forwarded by ordinal: %s | %p\n", funcName, funcAddress);
    }
    else
    {
      funcAddress = SusGetProcAddress(L, hDll, funcName);
      ////printf("forwarded by name: %s | %p\n", funcName, funcAddress);
    }
    free(dllName);
    free(funcName);*/
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
          //printf("Forwarded export: %s | %p\n", dllName, hash);
          hDll = SusLoadLibraryExA(L, dllName, NULL, 0);
          free(dllName);
        }
        if (hDll == NULL)
          return NULL;
        forwardedFunctionName = forwardedFunctionName + i + 1;
        break;
      }
    }
    //printf("Forwarded export: %s | %p\n", forwardedFunctionName, hash);
    if ((forwardedFunctionName[0] == '#') && forwardedFunctionName[1] != '\0') {
      uint16_t ord = 0;
      for (forwardedFunctionName++; *forwardedFunctionName; ++forwardedFunctionName)
        ord = ord * 10 + forwardedFunctionName[0] - '0';
      //printf("Forwarded export by ordinal: %d\n", ord);
      funcAddress = SusGetProcAddress(L, hDll, (LPCSTR)ord);
    }
    else {
      //printf("Forwarded export by name: %s\n", forwardedFunctionName);
      funcAddress = SusGetProcAddress(L, hDll, forwardedFunctionName);
    }
    //printf("Forwarded export: %p | %p   (%X VS %X)    (%p VS %p)\n", SusGetModuleHandleH(hash), funcAddress, hash, HashStringCaseInsensitiveFNV1a("CRYPTBASE.dll"), SusGetModuleHandleH(HashStringCaseInsensitiveFNV1a("CRYPTBASE")), SusGetModuleHandleA(L, "CRYPTBASE"));
  }

  if (!funcAddress) {
    //printf("Unresolved (%p, %s) | %p\n", hModule, lpProcName, GetProcAddress(hModule, lpProcName));
    //return GetProcAddress(hModule, lpProcName);
    return NULL;
  }
  
  //printf("     <> %s  |  %p\n", lpProcName, funcAddress);
  
  /*if (funcAddress != GetProcAddress(hModule, lpProcName))
  {
    //printf("SusGetProcAddress %p %s\n", hModule, lpProcName);
    //printf("NameRes: %p | GetProcAddress: %p\n", funcAddress, GetProcAddress(hModule, lpProcName));

    LIST_ENTRY* ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* ListEntry = ListHead->Flink;
    while (ListEntry != ListHead)
    {
      LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      //wprintf(L"LdrEntry %p => %s\n", LdrEntry->DllBase, LdrEntry->BaseDllName.Buffer);
      ListEntry = ListEntry->Flink;
    }
  }*/

  return funcAddress;
}

static int readable(const char *filename)
{
  ////printf("readable(%s)\n", filename); // readable(.\?.dll)
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
  ////printf("mname: %s\n", mname); // mname: .\?.dll
  while ((path = pushnexttemplate(L, path)) != NULL) {
    char* pat = lua_tostring(L, -1);
    ////printf("pat: %s\n", pat); // pat: .\?.dll
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
    ////printf("filename: %s\n", filename); // filename: .\?.dll
    if (readable(filename))  /* does file exist and is readable? */
      return filename;  /* return that file name */
    lua_pop(L, 1);
  }
  return NULL;  /* not found */
}

typedef int (WINAPI *MessageBoxAT)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
MessageBoxAT msgbox = NULL;

HCUSTOMMODULE SusLoadLibraryA(void *L, LPCSTR lpLibFileName)
{
  //char buff[0x100];
  //sprintf(buff, "SusLoadLibraryA(%p, %s)\n", L, lpLibFileName);
  if (!msgbox) msgbox = (MessageBoxAT)SusGetProcAddress(L, SusGetModuleHandleA(L, "user32.dll"), "MessageBoxA");
  if (msgbox) msgbox(NULL, ".", "LoadLibraryA", MB_OK);
  return SusLoadLibraryExA(NULL, lpLibFileName, NULL, 0); 
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
    ////printf("f: %p, INVALID_HANDLE_VALUE\n", f);
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

  ////printf("fileName: %s, fileBuffer: %p, size: %d\n", lpLibFileName, fileBuffer, size);
  //printf("MemoryLoadLibraryEx %s\n", orig_lpLibFileName);

  PMEMORYMODULE res = MemoryLoadLibraryEx(fileBuffer, size, SusAlloc, SusFree, SusLoadLibraryA, SusGetModuleHandleA, SusGetProcAddress, SusFreeLibrary, L, orig_lpLibFileName);
  if (res) {
    if (mm_vector == NULL)
      mm_vector = init_vector();
    LOADEDMEMORYMODULE* mm = (LOADEDMEMORYMODULE*)malloc(sizeof(LOADEDMEMORYMODULE));
    mm->m = res;
    mm->name = (char*)malloc(strlen(orig_lpLibFileName) + 1);
    strcpy(mm->name, orig_lpLibFileName);
    mm->hash = HashStringCaseInsensitiveFNV1a(orig_lpLibFileName);
    push(mm_vector, mm);
    //printf("Loaded %s | %p\n", orig_lpLibFileName, res->codeBase);
    return res->codeBase;
  }
  //printf("Failed to load %s\n", orig_lpLibFileName);
  return NULL;
}

void* SusLoadLibraryExA(lua_State *L, const char* lpLibFileName, void* hFile, unsigned long dwFlags)
{
  ////printf("SusLoadLibraryExA\n");
  ////printf("SusLoadLibraryExA(%s, %p, %d)\n", lpLibFileName, hFile, dwFlags);
  if (lpLibFileName == NULL)
    return NULL;

  /*if (L)
  {
    if (!readable(lpLibFileName))
    {
      ////printf("L: %p, !readable(%s)\n", L, lpLibFileName);
      lua_getglobal(L, "package");
      lua_getfield(L, -1, "cpath");
      const char* cpath = lua_tostring(L, -1);
      lua_pop(L, 2);
      ////printf("cpath: %s\n", cpath);
      const char *filename = searchpath(L, lpLibFileName, cpath, ".", LUA_DIRSEP);
      if (filename != NULL) {
        ////printf("filename: %s\n", filename);
        return TryFile(NULL, filename, lpLibFileName);
      }
    } else {
      //void* LMM = TryFile(NULL, lpLibFileName, lpLibFileName);
      //if (LMM != NULL)
      //  return LMM;
    }
    /*if (!readable(lpLibFileName)) {
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
    }*/
  //}

  //void* LMM = TryFile(L, lpLibFileName, orig_lpLibFileName);
  //if (LMM != NULL)
  //  return LMM;
  //LMM = TryFile(L, orig_lpLibFileName, orig_lpLibFileName);
  //if (LMM != NULL)
  //  return LMM;

  //if (!L)
  {
    //printf("LoadLibraryExA(%p, %s, %p, %d)\n", L, lpLibFileName, hFile, dwFlags);
    //char buff[0x100];
    //sprintf(buff, "(%p, %s, %p, %d)\n", L, lpLibFileName, hFile, dwFlags);
    //if (!msgbox) msgbox = (MessageBoxAT)SusGetProcAddress(L, SusGetModuleHandleA(L, "user32.dll"), "MessageBoxA");
    //if (msgbox) msgbox(NULL, ".", "LoadLibraryExA", MB_OK);
    //PMEMORYMODULE result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    //result->codeBase = LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    return LoadLibraryExA(lpLibFileName, hFile, dwFlags);
  }

  //printf("Unresolved (%s)\n", lpLibFileName);
  return NULL;

  /*{
    const char* orig_lpLibFileName = lpLibFileName;
    
    if (!readable(lpLibFileName))
    {
      if (L)
      {
        ////printf("L: %p, !readable(%s)\n", L, lpLibFileName);
        lua_getglobal(L, "package");
        lua_getfield(L, -1, "cpath");
        const char* cpath = lua_tostring(L, -1);
        lua_pop(L, 2);
        ////printf("cpath: %s\n", cpath);
        const char *filename = searchpath(L, lpLibFileName, cpath, ".", LUA_DIRSEP);
        if (filename != NULL) {
          ////printf("filename: %s\n", filename);
          lpLibFileName = filename;
          FILE* f = fopen(lpLibFileName, "rb");
          if (f != NULL) {
            return LoadLibraryExA(lpLibFileName, f, dwFlags);
          }
        }
      }
    }
    ////printf("LoadLibraryExA(%s, %p, %d) | orig %s\n", lpLibFileName, hFile, dwFlags, lpLibFileName);
    char buff[0x100];
    s//printf(buff, "LoadLibraryExA(%s, %p, %d) | orig %s\n", lpLibFileName, hFile, dwFlags, lpLibFileName);
    //MessageBoxAT msgbox = *(MessageBoxAT*)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    MessageBoxA(NULL, buff, "SusLoadLibraryExA", MB_OK);
    //PMEMORYMODULE result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    //result->codeBase = LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    return LoadLibraryExA(lpLibFileName, hFile, dwFlags);
  }*/
}