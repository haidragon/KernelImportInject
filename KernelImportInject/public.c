#include "public.h"
#include "IMTInject.h"

NTSTATUS Init(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	UNICODE_STRING uniFuncName;
	BOOLEAN        bImageAlignment = TRUE;

	g_DriverObject = DriverObject;
	g_pNtdllbase = NULL;
	g_dwNtdllSize = 0;
	g_pNtoskrnlbase = NULL;
	g_dwNtoskrnlSize = 0;
	g_bInitLoadImageNotify = FALSE;

	memset(g_szDllPath32, 0, sizeof(WCHAR) * MAX_PATH);
	memset(g_szDllPath64, 0, sizeof(WCHAR) * MAX_PATH);

 	wcscpy_s(g_szDllPath32, MAX_PATH, L"C:\\UserMapDllX86.dll");
 	wcscpy_s(g_szDllPath64, MAX_PATH, L"C:\\UserMapDllX64.dll");

// 	if ( InitSafeBootMode )
// 		return Status;

	DbgPrint("[KernelImportInject] Init Get Called");

//	g_bDriverVerify = MmIsDriverVerifying(DriverObject);
	RtlInitUnicodeString(&uniFuncName, L"ZwQueryVirtualMemory");
	g_ZwQueryVirtualMemory = (ZwQueryVirtualMemory)MmGetSystemRoutineAddress(&uniFuncName);
	DbgPrint("[KernelImportInject] Init g_ZwQueryVirtualMemory:%x", g_ZwQueryVirtualMemory);

	Status = GetKernelModuleBase("ntdll.dll", &g_pNtdllbase, &g_dwNtdllSize);
	if (!NT_SUCCESS(Status)){

		Status = LdrMapDataFile(L"\\SystemRoot\\System32\\ntdll.dll", &g_pNtdllbase, &g_dwNtdllSize);
		if (!NT_SUCCESS(Status))
			return Status;

		DbgPrint("[KernelImportInject] LdrMapDataFile g_pNtdllbase:%x, g_dwNtdllSize:%x", g_pNtdllbase, g_dwNtdllSize);
		bImageAlignment = FALSE;
	}

	g_ZwReadVirtualMemory = (ZwReadVirtualMemory)GetNativeApiAddress(g_pNtdllbase, bImageAlignment, "ZwReadVirtualMemory");
	DbgPrint("[KernelImportInject] Init g_ZwReadVirtualMemory:%p", g_ZwReadVirtualMemory);
	if (g_ZwReadVirtualMemory)
	{
		g_ZwWriteVirtualMemory = (ZwWriteVirtualMemory)GetNativeApiAddress(g_pNtdllbase, bImageAlignment, "ZwWriteVirtualMemory");
		DbgPrint("[KernelImportInject] Init g_ZwWriteVirtualMemory:%p", g_ZwWriteVirtualMemory);
		if ( g_ZwWriteVirtualMemory )
		{
			g_ZwQueryVirtualMemory = (ZwQueryVirtualMemory)GetNativeApiAddress(g_pNtdllbase, bImageAlignment, "ZwQueryVirtualMemory");
			DbgPrint("[KernelImportInject] Init g_ZwQueryVirtualMemory:%p", g_ZwQueryVirtualMemory);
			if ( g_ZwQueryVirtualMemory )
			{
				g_ZwProtectVirtualMemory = (ZwProtectVirtualMemory)GetNativeApiAddress(g_pNtdllbase, bImageAlignment, "ZwProtectVirtualMemory");
				DbgPrint("[KernelImportInject] Init g_ZwProtectVirtualMemory:%p", g_ZwProtectVirtualMemory);
			}
		}
	}

	if (!bImageAlignment) {
		ZwUnmapViewOfSection(NtCurrentProcess(), g_pNtdllbase);
	}

	if (!g_ZwReadVirtualMemory || !g_ZwWriteVirtualMemory || !g_ZwQueryVirtualMemory || !g_ZwProtectVirtualMemory) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutinue);
	if (NT_SUCCESS(Status)) {
		g_bInitLoadImageNotify = TRUE;
	}
	return Status;
}

NTSTATUS UnInit()
{
	NTSTATUS Status = STATUS_SUCCESS;

	if (g_bInitLoadImageNotify)
		Status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutinue);

	return Status;
}

VOID LoadImageNotifyRoutinue(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo
	)
{
	ULONG                     ulReturnLength      = 0;
	PROCESS_BASIC_INFORMATION pbi                 = {0};
	UNICODE_STRING            uniTargetModuleName = {0};
	PPEB                      Peb                 = NULL;
	ULONG                     v7                  = 0;
	WCHAR*                    lpszInjectDllPath   = NULL;
	ULONG                     uldirectorySize     = 0;
	BOOLEAN                   bIs64Process        = FALSE;

//	DbgPrint("[KernelImportInject] LoadImageNotifyRoutinue ProcessId:%x, %wZ", ProcessId, FullImageName);

	if (MmIsAddressValid(ImageInfo) )
	{
		if (!ImageInfo->SystemModeImage)
		{
			 RtlInitUnicodeString(&uniTargetModuleName, L"*\\MSCOREE.DLL");
			 
			 if (!FsRtlIsNameInExpression(&uniTargetModuleName, FullImageName, TRUE, NULL) &&
				 NT_SUCCESS(ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, 
				 &pbi, sizeof(pbi), &ulReturnLength)) )
			 {
				 if (pbi.PebBaseAddress)
				 {
					 Peb = pbi.PebBaseAddress;
					 ProbeForRead(&Peb->ImageBaseAddress, 8, 8);
					 if (Peb->ImageBaseAddress == ImageInfo->ImageBase)
					 {
						 DbgPrint("[KernelImportInject] LoadImageNotifyRoutinue FullImageName: %wZ", FullImageName);
						 if (pbi.UniqueProcessId)
						 {
							 lpszInjectDllPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR) * MAX_PATH, 'iath');
							 if (lpszInjectDllPath)
							 {

								 memset(lpszInjectDllPath, 0, sizeof(WCHAR) * MAX_PATH);
								 bIs64Process = CheckIs64Process(NtCurrentProcess());
								 if (bIs64Process)
									 wcscpy_s(lpszInjectDllPath, MAX_PATH, g_szDllPath64);
								 else
									 wcscpy_s(lpszInjectDllPath, MAX_PATH, g_szDllPath32);

								 if (!RtlImageDirectoryEntryToData(ImageInfo->ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &uldirectorySize))
								 {
									 DbgPrint("[KernelImportInject] LoadImageNotifyRoutinue RtlImageDirectoryEntryToData None COM_DESCRIPTOR");
									 if (CheckFileExist(lpszInjectDllPath))
									 {
										 DbgPrint("[KernelImportInject] LoadImageNotifyRoutinue Now IMTInject lpszInjectDllPath:%S", lpszInjectDllPath);
										 MakeIMTInject(ImageInfo->ImageBase, lpszInjectDllPath, bIs64Process);
									 }
								 }
							 }
						 }
					 }
				 }
			 }
		}
	}

	if ( lpszInjectDllPath ) {
		ExFreePoolWithTag(lpszInjectDllPath, 'iath');
	}
}

/*
 * inline之后很可能判断不准确，最好反汇编看下
 */
BOOLEAN __declspec(noinline) CheckIs64Process(HANDLE hProcessHandle)
{
	PPEB     Peb;
	ULONG    ulReturnLength;
	NTSTATUS Status;
	BOOLEAN  bIs64Process    = FALSE;

	Status = ZwQueryInformationProcess(hProcessHandle, ProcessWow64Information, &Peb, sizeof(PPEB), &ulReturnLength);
	if (!NT_SUCCESS(Status) || !Peb ) {
		bIs64Process = TRUE;
	}

	return bIs64Process;
}

/*
 * 注: ImageName传入NULL获取当前nt模块信息
 */
NTSTATUS GetKernelModuleBase(LPCSTR ImageName, PVOID* pImageBaseAddr, PULONG pImageSize)
{
	NTSTATUS         					ntStatus = STATUS_UNSUCCESSFUL;
	PVOID            					pBuffer	= NULL;
	ULONG            					ulNeed = sizeof(SYSTEM_MODULE_INFORMATION) + 30 * sizeof(SYSTEM_MODULE_INFORMATION_ENTRY);
	ULONG			 					ulIndex = 0;
	PSYSTEM_MODULE_INFORMATION   		pSysModInfo = NULL;
	PSYSTEM_MODULE_INFORMATION_ENTRY	pModEntry = NULL;

	pBuffer = ExAllocatePoolWithTag(PagedPool, ulNeed, 'gkmb');	
	if (pBuffer == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeed, &ulNeed);
	if( ntStatus == STATUS_INFO_LENGTH_MISMATCH )
	{
		ExFreePool(pBuffer);

		pBuffer = ExAllocatePoolWithTag(PagedPool, ulNeed, 'kgmb');	
		if( pBuffer == NULL ) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeed, &ulNeed);
		if (ntStatus != STATUS_SUCCESS ) {
			ExFreePool(pBuffer);
			return ntStatus;
		}
	}
	else if( ntStatus != STATUS_SUCCESS )
	{
		ExFreePool(pBuffer);	
		return ntStatus;
	}

	pSysModInfo 	= (PSYSTEM_MODULE_INFORMATION)pBuffer;
	pModEntry 	    = pSysModInfo->Module;

	if (ImageName == NULL) 
	{
		if (pImageBaseAddr) {
			*pImageBaseAddr = pModEntry[0].Base;
		}	
		if (pImageSize) {
			*pImageSize = pModEntry[0].Size;
		}

		ntStatus = STATUS_SUCCESS;
	}
	else
	{
		for( ulIndex = 0; ulIndex < pSysModInfo->Count; ulIndex ++ ) 
		{
			if( _stricmp(pModEntry[ulIndex].ImageName + pModEntry[ulIndex].ModuleNameOffset, ImageName) == 0 )
			{
				if (pImageBaseAddr)
					*pImageBaseAddr = pModEntry[ulIndex].Base;	

				if (pImageSize)
					*pImageSize = pModEntry[ulIndex].Size;

				ntStatus = STATUS_SUCCESS;
				break;
			}
		}
	}

	ExFreePool(pBuffer);
	return ntStatus;
}

NTSTATUS LdrMapDataFile(LPWSTR lpNtImageName, PVOID* lpImageBase, ULONG* lpdwImageSize)
{
	NTSTATUS          Status      = STATUS_SUCCESS;
	HANDLE            hFileHandle = NULL;
	HANDLE            hSection    = NULL;
	PVOID             lpBaseAddr  = NULL;
	SIZE_T            dwImageSize = 0;
	UNICODE_STRING    uniImageName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK   IoStatusblock;

	PIMAGE_DOS_HEADER pDosHeader  = NULL;
	PIMAGE_NT_HEADERS pNtHeader   = NULL;


	RtlInitUnicodeString(&uniImageName, lpNtImageName);
	InitializeObjectAttributes(&oa, &uniImageName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&hFileHandle, FILE_READ_ACCESS, &oa, &IoStatusblock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("[KernelImportInject] LdrMapDataFile ZwCreateFile success");
		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = ZwCreateSection(&hSection, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ, &oa, NULL, PAGE_READONLY, SEC_COMMIT, hFileHandle);
		if (NT_SUCCESS(Status))
		{
			DbgPrint("[KernelImportInject] LdrMapDataFile ZwCreateSection success");
			Status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &lpBaseAddr, 0, 0, NULL, &dwImageSize, ViewShare, 0, PAGE_READONLY);
			if (NT_SUCCESS(Status) && lpBaseAddr)
			{
				DbgPrint("[KernelImportInject] LdrMapDataFile ZwMapViewOfSection success");
				pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddr;
				pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpBaseAddr + pDosHeader->e_lfanew);

				if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && pNtHeader->Signature == IMAGE_NT_SIGNATURE)
				{
					DbgPrint("[KernelImportInject] LdrMapDataFile CheckPE Header success");
					if (lpImageBase) {
						*lpImageBase = lpBaseAddr;
					}

					if (lpdwImageSize) {
						*lpdwImageSize = LODWORD(dwImageSize);
					}
				}
			}
			ZwClose(hSection);
		}
		ZwClose(hFileHandle);
	}

	return Status;
}

ULONG Rva2Raw(PIMAGE_NT_HEADERS pNtHeader, ULONG Rva)
{
	ULONG                 ulRaw              = 0;
	ULONG                 ulIndex            = 0;
	ULONG                 ulNumberOfSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeader     = NULL;

	if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS64));
	else
		pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS32));

	ulNumberOfSections = pNtHeader->FileHeader.NumberOfSections;
	if (ulNumberOfSections <= 0) {
		//ulRaw = Rva;
		ulRaw = 0;
	}
	else
	{
		for ( ; ulIndex < ulNumberOfSections ; ulIndex++ )
		{
			if (pSectionHeader[ulIndex].VirtualAddress <= Rva &&
				pSectionHeader[ulIndex].VirtualAddress +  pSectionHeader[ulIndex].SizeOfRawData >= Rva)
			{
				ulRaw = Rva - pSectionHeader[ulIndex].VirtualAddress + pSectionHeader[ulIndex].PointerToRawData;
				break;
			}
		}
	}

	return ulRaw;
}

PVOID GetModuleExportApiAddress(PVOID lpModulebase, LPSTR lpNativeApiName, BOOLEAN bImageAlignment)
{
	PIMAGE_NT_HEADERS       pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportTable;
	ULONG*                  pAddressesArray;
	ULONG*                  pNamesArray;
	USHORT*                 pOrdinalsArray;
	ULONG                   dwFuncIndex;
	ULONG                   i;
	CHAR*                   szFunName;
	ULONG_PTR               FunAddress = 0;

	__try
	{
		pNtHeaders = RtlImageNtHeader(lpModulebase);
		if (pNtHeaders && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) 
		{
			if (bImageAlignment)
			{
				pExportTable    = (IMAGE_EXPORT_DIRECTORY *)((ULONG_PTR)lpModulebase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				pAddressesArray = (ULONG* )((ULONG_PTR)lpModulebase + pExportTable->AddressOfFunctions);
				pNamesArray     = (ULONG* )((ULONG_PTR)lpModulebase + pExportTable->AddressOfNames);
				pOrdinalsArray  = (USHORT* )((ULONG_PTR)lpModulebase + pExportTable->AddressOfNameOrdinals);
			}
			else
			{
				pExportTable    = (IMAGE_EXPORT_DIRECTORY *)((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
				pAddressesArray = (ULONG* )((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pExportTable->AddressOfFunctions));
				pNamesArray     = (ULONG* )((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pExportTable->AddressOfNames));
				pOrdinalsArray  = (USHORT* )((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pExportTable->AddressOfNameOrdinals));
			}
			

			for(i = 0; i < pExportTable->NumberOfNames; i++){
				if (bImageAlignment)
					szFunName = (LPSTR)((ULONG_PTR)lpModulebase + pNamesArray[i]);
				else
					szFunName = (LPSTR)((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pNamesArray[i]));

				dwFuncIndex = pOrdinalsArray[i]; 
				if (_stricmp(szFunName, lpNativeApiName) == 0) {

					if (bImageAlignment)
						FunAddress = (ULONG_PTR)((ULONG_PTR)lpModulebase + pAddressesArray[dwFuncIndex]);
					else
						FunAddress = (ULONG_PTR)((ULONG_PTR)lpModulebase + Rva2Raw(pNtHeaders, pAddressesArray[dwFuncIndex]));
					break;
				}
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		FunAddress = 0;
	}

	return (PVOID)FunAddress;
}

/*
 * 由ntoskrnl!Zw*导出函数查找ntoskrnl!Zw*未导出函数地址
 */
PVOID GetNativeApiAddress(PVOID lpNtdllbase, BOOLEAN bImageAlignment, LPSTR lpNativeApiName)
{
	NTSTATUS  Status                   = STATUS_SUCCESS;
	PVOID     lpNtdllFuncAddr          = NULL;
	PVOID     lpNtoskrnlStartFuncAddr  = NULL;
	PVOID     lpNtoskrnlNextFuncAddr   = NULL;
	PVOID     lpNtdllStartFuncAddr     = NULL;
	PVOID     lpNativeApiAddr          = NULL;

	ULONG     ulNativeApiIndex         = 0;
	ULONG     ulStartApiIndex          = 0;

	ULONG     uloffset                 = 0;
	ULONG     ulNextoffset             = 0;

	lpNtdllFuncAddr = GetModuleExportApiAddress(lpNtdllbase, lpNativeApiName, bImageAlignment);
	if (lpNtdllFuncAddr && *(ULONG*)lpNtdllFuncAddr == 0xB8D18B4C) {
		ulNativeApiIndex = *(ULONG*)((ULONG_PTR)lpNtdllFuncAddr + 4);
	}
	else {
		ulNativeApiIndex = -1;
	}
	DbgPrint("[KernelImportInject] GetNativeApiAddress ulNativeApiIndex : %x\r\n", ulNativeApiIndex);

	if (ulNativeApiIndex != -1)
	{
		 lpNtdllStartFuncAddr = GetModuleExportApiAddress(lpNtdllbase, "ZwAllocateVirtualMemory", bImageAlignment);
		 if (lpNtdllStartFuncAddr && *(ULONG*)lpNtdllStartFuncAddr == 0xB8D18B4C) {
			 ulStartApiIndex = *(ULONG*)((ULONG_PTR)lpNtdllStartFuncAddr + 4);
		 }
		 else {
			 ulStartApiIndex = -1;
		 }
		 DbgPrint("[KernelImportInject] GetNativeApiAddress ulStartApiIndex : %x\r\n", ulStartApiIndex);

		 if (ulStartApiIndex != -1)
		 {
			 if (!g_pNtoskrnlbase)
			 {
				Status = GetKernelModuleBase(NULL, &g_pNtoskrnlbase, &g_dwNtoskrnlSize);
				if (!NT_SUCCESS(Status) || !g_pNtoskrnlbase) {
					return NULL;
				}
			 }

			 lpNtoskrnlStartFuncAddr = GetModuleExportApiAddress(g_pNtoskrnlbase, "ZwAllocateVirtualMemory", TRUE);
			 DbgPrint("[KernelImportInject] GetNativeApiAddress ZwAllocateVirtualMemory : %p\r\n", lpNtoskrnlStartFuncAddr);
			 if (lpNtoskrnlStartFuncAddr)
			 {
				 while (*(BYTE*)((ULONG_PTR)lpNtoskrnlStartFuncAddr + uloffset) != 0xB8 || *(ULONG *)((ULONG_PTR)lpNtoskrnlStartFuncAddr + uloffset + 1) != ulStartApiIndex )
				 {
					 ++uloffset;
					 if ( uloffset >= 100 ) {
						 return lpNativeApiAddr;
					 }
				 }
				 DbgPrint("[KernelImportInject] GetNativeApiAddress uloffset : %d\r\n", uloffset);

				 // ZwAllocateVirtualMemory Next Zw*
				 ulNextoffset = uloffset;
				 lpNtoskrnlNextFuncAddr = (PVOID)((ULONG_PTR)lpNtoskrnlStartFuncAddr + uloffset + 1);
				 while (*((BYTE*)((ULONG_PTR)lpNtoskrnlNextFuncAddr - 1)) != 0xB8 || 
					    *(ULONG*)lpNtoskrnlNextFuncAddr != ulStartApiIndex + 1)
				 {
					 ++ulNextoffset;
					 lpNtoskrnlNextFuncAddr = (PVOID)((ULONG_PTR)lpNtoskrnlNextFuncAddr + 1);
					 if (ulNextoffset >= uloffset + 100) {
						 return lpNativeApiAddr;
					 }
				 }
				 DbgPrint("[KernelImportInject] GetNativeApiAddress ulNextoffset : %d\r\n", ulNextoffset);

				 // Delta Index * SizeOf Zw* Stub == Delta to ZwAllocateVirtualMemory
				 lpNativeApiAddr = (PVOID)((ULONG_PTR)lpNtoskrnlStartFuncAddr + (ulNativeApiIndex - ulStartApiIndex) * (ulNextoffset - uloffset));
				 
				 // Final Check
				 if (*(BYTE*)((ULONG_PTR)lpNativeApiAddr + uloffset) != 0xB8 || 
					 *(ULONG *)((ULONG_PTR)lpNativeApiAddr + uloffset + 1) != ulNativeApiIndex)
					 lpNativeApiAddr = NULL;
			 }
		 }
	}

	return lpNativeApiAddr;
}

BOOLEAN CheckFileExist(LPCWCH lpFilePath)
{
	NTSTATUS          Status          = STATUS_SUCCESS;
	IO_STATUS_BLOCK   IoStatusBlock   = {0};
	OBJECT_ATTRIBUTES oa              = {0};
	UNICODE_STRING    uniFileFullPath = {0};
	UNICODE_STRING    uniNtFixPath    = {0};
	USHORT            ulLength        = 0;
	WCHAR*            wzFileFullPath  = NULL;
	HANDLE            hFileHandle;
	KPROCESSOR_MODE   ExecuteMode;
	BOOLEAN           bFileExist      = FALSE;

	if (lpFilePath)
	{
		RtlInitUnicodeString(&uniNtFixPath, L"\\??\\");
		// 这个函数一编译就内联，烦躁
		ulLength = wcslen(lpFilePath);

		if ( uniNtFixPath.Length + ulLength <= 0x800 )
		{
			wzFileFullPath = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, 0x800, 'iath');
			if (wzFileFullPath)
			{
				uniFileFullPath.Buffer = wzFileFullPath;
				uniFileFullPath.Length = 0;
				uniFileFullPath.MaximumLength = 0x800;

				RtlCopyUnicodeString(&uniFileFullPath, &uniNtFixPath);
				RtlUnicodeStringCatString(&uniFileFullPath, lpFilePath);

				DbgPrint("[KernelImportInject] CheckFileExist uniFileFullPath: %wZ", uniFileFullPath);

				InitializeObjectAttributes(&oa, &uniFileFullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				Status = IoCreateFile(
					&hFileHandle, 
					GENERIC_READ | SYNCHRONIZE,
					&oa,
					&IoStatusBlock,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,
					0,
					CreateFileTypeNone,
					NULL,
					IO_NO_PARAMETER_CHECKING);

				if (NT_SUCCESS(Status))
				{
					bFileExist = TRUE;
					if ((ULONG)hFileHandle & KERNEL_HANDLE_MASK)
						ExecuteMode = KernelMode;
					else
						ExecuteMode = UserMode;

					ObCloseHandle(hFileHandle, ExecuteMode);
				}

				ExFreePoolWithTag(wzFileFullPath, 'iath');
			}
		}
	}

	return bFileExist;
}