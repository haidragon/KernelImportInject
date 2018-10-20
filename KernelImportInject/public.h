#ifndef _PUBLIC_H
#define _PUBLIC_H


#include "headers.h"


#define LODWORD(l)           ((ULONG)((ULONG_PTR)(l) & 0xffffffff))
#define HIDWORD(l)           ((ULONG)((ULONG_PTR)(l) >> 32))

#define KERNEL_HANDLE_MASK ((ULONG_PTR)((LONG)0x80000000))

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
#if DEVL
	,MemoryWorkingSetInformation
#endif
	,MemoryMappedFilenameInformation
	,MemoryRegionInformation
	,MemoryWorkingSetExInformation

} MEMORY_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY32
{
	ULONG 	Reserved[2];
	PVOID  	Base;
	ULONG  	Size;
	ULONG  	Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  ModuleNameOffset;
	CHAR  	ImageName[256];

} SYSTEM_MODULE_INFORMATION_ENTRY32, *PSYSTEM_MODULE_INFORMATION_ENTRY32;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY64
{
	ULONG 	Reserved[4];
	PVOID  	Base;
	ULONG  	Size;
	ULONG  	Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  ModuleNameOffset;
	CHAR  	ImageName[256];

} SYSTEM_MODULE_INFORMATION_ENTRY64, *PSYSTEM_MODULE_INFORMATION_ENTRY64;

typedef struct _SYSTEM_MODULE_INFORMATION32 // Information Class 11
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY32 Module[1];

} SYSTEM_MODULE_INFORMATION32, *PSYSTEM_MODULE_INFORMATION32;

typedef struct _SYSTEM_MODULE_INFORMATION64 // Information Class 11
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY64 Module[1];

} SYSTEM_MODULE_INFORMATION64, *PSYSTEM_MODULE_INFORMATION64;

#ifdef _WIN64
typedef SYSTEM_MODULE_INFORMATION_ENTRY64      	SYSTEM_MODULE_INFORMATION_ENTRY;
typedef PSYSTEM_MODULE_INFORMATION_ENTRY64    	PSYSTEM_MODULE_INFORMATION_ENTRY;
typedef SYSTEM_MODULE_INFORMATION64             SYSTEM_MODULE_INFORMATION;
typedef PSYSTEM_MODULE_INFORMATION64            PSYSTEM_MODULE_INFORMATION;
#else
typedef SYSTEM_MODULE_INFORMATION_ENTRY32      	SYSTEM_MODULE_INFORMATION_ENTRY;
typedef PSYSTEM_MODULE_INFORMATION_ENTRY32     	PSYSTEM_MODULE_INFORMATION_ENTRY;
typedef SYSTEM_MODULE_INFORMATION32            	SYSTEM_MODULE_INFORMATION;
typedef PSYSTEM_MODULE_INFORMATION32           	PSYSTEM_MODULE_INFORMATION;
#endif

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32 {
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	ULONG Mutant;                      // INITIAL_PEB structure is also updated.

	ULONG ImageBaseAddress;
	ULONG Ldr;
}PEB32,*PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY32 HashLinks;
		struct {
			ULONG SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			ULONG LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
}RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
}PEB,*PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



NTSYSAPI
	NTSTATUS
	NTAPI
	ZwQuerySystemInformation (
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

NTSYSAPI
	NTSTATUS 
	NTAPI
	ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

NTSYSAPI
	PIMAGE_NT_HEADERS
	NTAPI
	RtlImageNtHeader(
	PVOID Base
	);

NTSYSAPI
	PVOID
	NTAPI
	RtlImageDirectoryEntryToData(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size); 

NTSYSAPI
	NTSTATUS
	NTAPI
	ObCloseHandle(
	IN HANDLE Handle,
	IN KPROCESSOR_MODE AccessMode);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS (NTAPI* ZwProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PSIZE_T ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	);

typedef NTSTATUS (NTAPI* ZwQueryVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID pBaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN ULONG MemoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS (NTAPI* ZwReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL
	);

typedef NTSTATUS (NTAPI* ZwWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesWritten OPTIONAL
	);

//////////////////////////////////////////////////////////////////////////////////////////////////

extern ULONG InitSafeBootMode;

//////////////////////////////////////////////////////////////////////////////////////////////////

PDRIVER_OBJECT g_DriverObject;
LOGICAL g_bDriverVerify;

PVOID g_pNtdllbase;
ULONG g_dwNtdllSize;

PVOID g_pNtoskrnlbase;
ULONG g_dwNtoskrnlSize;

BOOLEAN g_bInitLoadImageNotify;

WCHAR   g_szDllPath32[MAX_PATH];
WCHAR   g_szDllPath64[MAX_PATH];

ZwQueryVirtualMemory   g_ZwQueryVirtualMemory;
ZwReadVirtualMemory    g_ZwReadVirtualMemory;
ZwWriteVirtualMemory   g_ZwWriteVirtualMemory;
ZwProtectVirtualMemory g_ZwProtectVirtualMemory;

/////////////////////////////////////////////////////////////////////////////////////////////////

VOID LoadImageNotifyRoutinue(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo
	);

NTSTATUS Init(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath);
NTSTATUS UnInit();

NTSTATUS GetKernelModuleBase(LPCSTR ImageName, PVOID* pImageBaseAddr, PULONG pImageSize);
NTSTATUS LdrMapDataFile(LPWSTR lpNtImageName, PVOID* lpImageBase, ULONG* lpdwImageSize);

PVOID GetModuleExportApiAddress(PVOID lpNtdllbase, LPSTR lpNativeApiName, BOOLEAN bImageAlignment);
PVOID GetNativeApiAddress(PVOID lpNtdllbase, BOOLEAN bImageAlignment, LPSTR lpNativeApiName);
ULONG Rva2Raw(PIMAGE_NT_HEADERS pNtHeader, ULONG Rva);

BOOLEAN __declspec(noinline) CheckIs64Process(HANDLE hProcessHandle);
BOOLEAN CheckFileExist(LPCWCH lpFilePath);

#endif