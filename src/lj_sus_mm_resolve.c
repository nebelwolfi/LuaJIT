#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sal.h>

#ifdef _X86_
#error "This snippet only build in 64-bit due to heavy use of uintptr arithmetics."
#endif

// don't include <winternl.h> since their
// _PEB struct definition clash with ours.
// Instead use Processhacker's phnt internals.
#include "C:/LuaJIT-2.1.M.64/phnt/phnt_ntdef.h"

// The api set resolution rely on ntdll.lib internals to
// query the PEB.ApiSet member for the API_NAMESPACE struct
// and RtlCompareUnicodeStrings for strings comparisons
#pragma region ntdll internals

const NTSTATUS STATUS_SUCCESS = 0;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	/*PPEB_LDR_DATA*/ void* Ldr;
	/*PRTL_USER_PROCESS_PARAMETERS*/ void* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ReservedBits0 : 25;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

LONG CompareUnicodeStrings(
	_In_reads_(String1Length) PWCH s1,
	_In_ SIZE_T len1,
	_In_reads_(String2Length) PWCH s2,
	_In_ SIZE_T len2,
	_In_ BOOLEAN case_insensitive
) {
	LONG ret = 0;
	unsigned int len = len1 < len2 ? len1 : len2;
	
	if (case_insensitive)
	{
		while (!ret && len--) ret = towlower(*s1++) - towlower(*s2++);
	}
	else
	{
		while (!ret && len--) ret = *s1++ - *s2++;
	}
	if (!ret) ret = len1 - len2;
	return ret;
}
#pragma endregion ntdll internals


// Unlike ntdll internals, the following
// structures and functions are not even exported
// by ntdll.lib. Only public symbols exists for some.
//
// API_SET_XXX structs are copied from https://github.com/zodiacon/WindowsInternals/blob/master/APISetMap/ApiSet.h
// while functions were manually reversed (with the help of HexRays).
#pragma region api set internals

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _API_SET_HASH_ENTRY {
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY, *PAPI_SET_HASH_ENTRY;

typedef struct _API_SET_NAMESPACE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;


const uint64_t API_ = (uint64_t)0x2D004900500041; // L"api-"
const uint64_t EXT_ = (uint64_t)0x2D005400580045; // L"ext-";
#define API_SET_PREFIX_API_     (ULONGLONG)0x002D004900500041 /* L"api-" */
#define API_SET_PREFIX_EXT_     (ULONGLONG)0x002D005400580045 /* L"ext-" */
#define API_SET_DLL_EXTENSTION  (ULONGLONG)0x004C004C0044002E /* L".DLL" */

// wordcount = bytecount / sizeof(wchar)
#define GET_WCHAR_COUNT(ByteLen) ((ByteLen) >> 1) 

#define GET_API_SET_NAMESPACE_ENTRY(ApiNamespace, HashIndex) ((API_SET_NAMESPACE_ENTRY *)((uintptr_t)ApiNamespace + HashIndex*sizeof(API_SET_NAMESPACE_ENTRY) + ApiNamespace->EntryOffset))
#define GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, Index) ((API_SET_VALUE_ENTRY *)((uintptr_t)ApiNamespace + Index*sizeof(API_SET_VALUE_ENTRY) + Entry->ValueOffset))
#define GET_API_SET_VALUE_NAME(ApiNamespace, _Entry) ((PWCHAR)((uintptr_t)ApiNamespace + _Entry->NameOffset))
#define GET_API_SET_VALUE_VALUE(ApiNamespace, _Entry) ((PWCHAR)((uintptr_t)ApiNamespace + _Entry->ValueOffset))
#define GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex) ((API_SET_HASH_ENTRY*)((uintptr_t)ApiNamespace + ApiNamespace->HashOffset  + sizeof(uint64_t) * HashIndex))

PAPI_SET_NAMESPACE_ENTRY 
__fastcall ApiSetpSearchForApiSet(
	_In_ PAPI_SET_NAMESPACE ApiNamespace,
	_In_ PWCHAR ApiNameToResolve, 
	_In_ uint16_t ApiNameToResolveSize
)
{
	
	if (!ApiNameToResolveSize)
		return NULL;

	// HashKey = Hash(ApiNameToResolve.ToLower())	
	ULONG HashKey = 0;
	for (int i = 0; i < ApiNameToResolveSize; i++)
	{
		WCHAR CurrentChar = ApiNameToResolve[i];
		if (CurrentChar >= 'A' && CurrentChar <= 'Z')
			CurrentChar += 0x20;
		HashKey = HashKey * ApiNamespace->HashFactor + CurrentChar;
	}

	int ApiSetEntryCount = ApiNamespace->Count - 1;
	if (ApiSetEntryCount < 0)
		return NULL;


	// HashTable.get("apiset-name") -> HashIndex
	int HashCounter = 0;
	int HashIndex;
	while (1)
	{
		HashIndex = (ApiSetEntryCount + HashCounter) >> 1;
		
		if (HashKey < GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Hash)
		{
			ApiSetEntryCount = HashIndex - 1;
			goto CHECK_HASH_COUNTER;
		}

		
		if (HashKey == GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Hash)
			break;

		HashCounter = HashIndex + 1;

	CHECK_HASH_COUNTER:
		if (HashCounter > ApiSetEntryCount)
			return NULL;
	}

	API_SET_NAMESPACE_ENTRY *FoundEntry = GET_API_SET_NAMESPACE_ENTRY(
		ApiNamespace, 
		GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Index
	);


	if (!FoundEntry)
		return NULL;

	// Final check on apiset library name in order to make sure we didn't collide with another hash bucket.
	if (0 == CompareUnicodeStrings(
		/* _In_ PWCHAR */ ApiNameToResolve,
		/* _In_ SHORT  */ ApiNameToResolveSize,
		/* _In_ PWCHAR */ GET_API_SET_VALUE_NAME(ApiNamespace, FoundEntry),
		/* _In_ SHORT  */ GET_WCHAR_COUNT(FoundEntry->HashedLength),
		TRUE              // Ignore case
	)) {
		return FoundEntry;
	}


	return NULL;
}

PAPI_SET_VALUE_ENTRY 
__stdcall ApiSetpSearchForApiSetHost(
	_In_ PAPI_SET_NAMESPACE_ENTRY Entry, 
	_In_ PWCHAR *ApiToResolve,
	_In_ SHORT ApiToResolveLen,
	_In_ PAPI_SET_NAMESPACE ApiNamespace
)
{
	//__int64 _EntryValueOffset; // r12@1
	int EntryHasAlias; // ebx@1
	API_SET_VALUE_ENTRY *FoundEntry; // rdi@1
	int EntryAliasIndex; // esi@3
	API_SET_VALUE_ENTRY *AliasEntry; // r14@3
	int _result; // eax@3

	// If there is no alias, don't bother checking each one.
	FoundEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, 0);
	EntryHasAlias = Entry->ValueCount - 1;
	if (!EntryHasAlias)
		return FoundEntry;

	int Counter = 1;
	do
	{
		EntryAliasIndex = (EntryHasAlias + Counter) >> 1; // Why ?
		AliasEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, EntryAliasIndex);

		_result = CompareUnicodeStrings(
			/* _In_ PWCHAR */ ApiToResolve,
			/* _In_ SHORT  */ ApiToResolveLen,
			/* _In_ PWCHAR */ GET_API_SET_VALUE_NAME(ApiNamespace, AliasEntry),
			/* _In_ SHORT  */ GET_WCHAR_COUNT(AliasEntry->NameLength),
			TRUE	// Ignore case
		);

		if (_result < 0)
		{
			EntryHasAlias = EntryAliasIndex - 1;
		}
		else
		{
			if (_result == 0)
			{
				return GET_API_SET_VALUE_ENTRY(
					ApiNamespace, 
					Entry, 
					((EntryHasAlias + Counter) >> 1) // Why ?
				);
			}

			Counter = EntryAliasIndex + 1;
		}

	} while (Counter <= EntryHasAlias);
	
	return FoundEntry;
}

NTSTATUS 
__fastcall ApiSetResolveToHost(
	_In_ PAPI_SET_NAMESPACE ApiNamespace,
	_In_ PUNICODE_STRING ApiToResolve, 
	_In_ PUNICODE_STRING ParentName, 
	_Out_ PBOOLEAN Resolved, 
	_Out_ PUNICODE_STRING Output
)
{
	NTSTATUS Status; // rax@4
	char IsResolved; // bl@1
	wchar_t *ApiSetNameBuffer; // rdx@2
	__int16 ApiSetNameWithoutExtensionWordCount; // ax@8
	API_SET_NAMESPACE_ENTRY *ResolvedEntry; // rax@9
	API_SET_VALUE_ENTRY *HostLibraryEntry; // rcx@12

	IsResolved = FALSE;	
	Output->Buffer = NULL;
	Output->Length = 0;
	Output->MaximumLength = 0;

	if (ApiToResolve->Length < wcslen(L"api-") * sizeof(WCHAR))
	{
		goto EPILOGUE;
	}

	// --------------------------
	// Check library name starts with "api-" or "ext-"
	ApiSetNameBuffer = ApiToResolve->Buffer;
	uint64_t ApiSetNameBufferPrefix = ((uint64_t*) ApiSetNameBuffer)[0] & 0xFFFFFFDFFFDFFFDF;
	if (!(ApiSetNameBufferPrefix == API_ || ApiSetNameBufferPrefix == EXT_))
	{
		goto EPILOGUE;
	}

	// ------------------------------
	// Compute word count of apiset library name without the dll suffix and anything beyond the last hyphen
	// Ex: 
	//     api-ms-win-core-apiquery-l1-1-0.dll -> wordlen(api-ms-win-core-apiquery-l1-1)
	// ------------------------------
	uintptr_t LastHyphen = (uintptr_t) wcsrchr(ApiSetNameBuffer, '-');
	ApiSetNameWithoutExtensionWordCount = (SHORT) GET_WCHAR_COUNT(LastHyphen - (uintptr_t) ApiSetNameBuffer);
	if (!ApiSetNameWithoutExtensionWordCount)
	{
		goto EPILOGUE;
	}

	// Hash table lookup
	ResolvedEntry = ApiSetpSearchForApiSet(
		ApiNamespace,
		ApiSetNameBuffer,
		ApiSetNameWithoutExtensionWordCount);
	if (!ResolvedEntry)
	{
		goto EPILOGUE;
	}

	// Look for aliases in hosts librairies if necessary
	if (ParentName && ResolvedEntry->ValueCount > 1)
	{
		HostLibraryEntry = ApiSetpSearchForApiSetHost(
			ResolvedEntry,
			(PWCHAR *) ParentName->Buffer,
			GET_WCHAR_COUNT(ParentName->Length),
			ApiNamespace
		);

		goto WRITING_RESOLVED_API;
	}

	// Output resolved host library into _Out_ UNICODE_STRING structure
	if (ResolvedEntry->ValueCount > 0)
	{
		HostLibraryEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, ResolvedEntry, 0);
	
	WRITING_RESOLVED_API:
		IsResolved = TRUE;
		Output->Buffer = GET_API_SET_VALUE_VALUE(ApiNamespace, HostLibraryEntry);
		Output->MaximumLength = HostLibraryEntry->ValueLength;
		Output->Length = HostLibraryEntry->ValueLength;
		//wprintf(L"Resolved %s to %s with parent %s out of %d aliases\n", ApiToResolve->Buffer, Output->Buffer, ParentName->Buffer, ResolvedEntry->ValueCount);
		goto EPILOGUE;
	}
	

EPILOGUE:
	Status = STATUS_SUCCESS;
	*Resolved = IsResolved;
	return Status;
}
#pragma endregion api set internals


typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
} TEB, *PTEB;

PAPI_SET_NAMESPACE 
GetApiSetNamespace()
{
	ULONG	ReturnLength;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	PAPI_SET_NAMESPACE apiSetMap = NULL;

	//	Parsing PEB structure and locating api set map
	PPEB peb = (PPEB) NtCurrentTeb()->ProcessEnvironmentBlock;
	apiSetMap = (PAPI_SET_NAMESPACE) peb->ApiSetMap;

	return apiSetMap;
}

bool 
ResolveApiSetLibraryW(
	_In_ wchar_t *ApiSetLibraryName,
	PUNICODE_STRING ResolvedHostLibrary,
	PUNICODE_STRING ParentName
)
{
	PAPI_SET_NAMESPACE ApiSetNamespace = GetApiSetNamespace();
	BOOLEAN Resolved = FALSE;
	UNICODE_STRING ApiToResolve = {
		.Buffer = ApiSetLibraryName,
		.Length = (short) wcslen(ApiSetLibraryName)*sizeof(wchar_t),
		.MaximumLength = (short) wcslen(ApiSetLibraryName) * sizeof(wchar_t)
	};

	NTSTATUS Status = ApiSetResolveToHost(
		ApiSetNamespace,
		&ApiToResolve,
		ParentName,
		&Resolved,
		ResolvedHostLibrary
	);

	return (NT_SUCCESS(Status) && Resolved);
}

bool
ResolveApiSetLibraryA(
	_In_ char *ApiSetLibraryName,
	PSTRING ResolvedHostLibraryA,
	PSTRING ParentName
)
{
	wchar_t ApiSetLibraryNameW[256];
	mbstowcs(ApiSetLibraryNameW, ApiSetLibraryName, 256);
	UNICODE_STRING ResolvedHostLibraryW = {0};
	UNICODE_STRING ParentNameW = {0};
	if (ParentName)
	{
		ParentNameW.MaximumLength = mbstowcs(NULL, ParentName->Buffer, 0) + 1;
		ParentNameW.Buffer = malloc(ParentNameW.MaximumLength);
		ParentNameW.Length = mbstowcs(ParentNameW.Buffer, ParentName->Buffer, ParentName->Length);
	}
	bool res = ResolveApiSetLibraryW(ApiSetLibraryNameW, &ResolvedHostLibraryW, &ParentNameW);
	if (res)
	{
		ResolvedHostLibraryA->MaximumLength = wcstombs(NULL, ResolvedHostLibraryW.Buffer, ResolvedHostLibraryW.Length) + 1;
		ResolvedHostLibraryA->Buffer = malloc(ResolvedHostLibraryA->MaximumLength);
		ResolvedHostLibraryA->Length = wcstombs(ResolvedHostLibraryA->Buffer, ResolvedHostLibraryW.Buffer, ResolvedHostLibraryW.Length);
		char* s = strstr(ResolvedHostLibraryA->Buffer, ".dll");
		if (s)
			ResolvedHostLibraryA->Length = s - ResolvedHostLibraryA->Buffer + 4;
		ResolvedHostLibraryA->Buffer[ResolvedHostLibraryA->Length] = 0; // wcstombs doesn't add the null terminator
		//printf("Resolved %s to %s\n", ApiSetLibraryName, ResolvedHostLibraryA->Buffer);
	}
	return res;
}