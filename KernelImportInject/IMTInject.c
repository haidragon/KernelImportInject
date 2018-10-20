#include "IMTInject.h"
#include "public.h"

NTSTATUS MakeIMTInject(PVOID lpImagebase, LPWCH lpszDllPath, BOOLEAN bIs64Process)
{
	NTSTATUS                    Status       = STATUS_UNSUCCESSFUL;
	UNICODE_STRING              uniDllPath   = { 0 };
	ANSI_STRING                 ansiDllPath  = { 0 };
	PIMAGE_NT_HEADERS           pNtHeader    = NULL;
	PVOID                       pImportTable = NULL;
	PVOID                       pImportVa    = NULL;
	PIMAGE_THUNK_DATA           lpThunkData  = NULL;
	PVOID                       pProtectBase;
	SIZE_T                      ulProtectSize;
	ULONG                       ulOldProtect;
	ULONG                       ulImtSize;
	ULONG                       ulcount;
	ULONG                       uSize;
	PVOID                       lpAllocAddr;
	PCHAR                       lpNewIIDModulePath;
	PIMAGE_IMPORT_DESCRIPTOR    lpNewIIDItem;
	
	
	if (lpImagebase && lpszDllPath)
	{
		DbgPrint("[KernelImportInject] MakeIMTInject lpImagebase:%p\r\n", lpImagebase);
		RtlInitUnicodeString(&uniDllPath, lpszDllPath);
		Status = RtlUnicodeStringToAnsiString(&ansiDllPath, &uniDllPath, TRUE);
		if (NT_SUCCESS(Status) && ansiDllPath.Buffer)
		{
			// Ring3不识别NT模块路径
			if (!strstr(ansiDllPath.Buffer, "?"))
			{
				pImportTable = RtlImageDirectoryEntryToData(lpImagebase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulImtSize);
				if (pImportTable)
				{
					pNtHeader = RtlImageNtHeader(lpImagebase);
					if (pNtHeader)
					{
						ulcount = ulImtSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) + 1;
						uSize = ulcount * sizeof(IMAGE_IMPORT_DESCRIPTOR) + (MAX_PATH + 5) * 8;
						DbgPrint("[KernelImportInject] MakeIMTInject uSize:%x", uSize);

						// 在一定范围内申请内存空间用于存放新导入表信息，因为PE导入表RVA只有4字节
						// 32位进程基地址如果申请到了64位地址就GG
						lpAllocAddr = AllocateWow64MemoryRegion64(NtCurrentProcess(), uSize, lpImagebase);
						DbgPrint("[KernelImportInject] MakeIMTInject lpAllocAddr:%p", lpAllocAddr);

						// Now Create New Import Table
						if (lpAllocAddr)
						{
							// [NewIID] + [OriginalIID...] + [lpszDllPath(ANSI)] + ...... + [NewModule IAT Table]
							memset(lpAllocAddr, 0, uSize);
							lpNewIIDItem = (PIMAGE_IMPORT_DESCRIPTOR)lpAllocAddr;
							lpNewIIDModulePath = (PCHAR)((ULONG_PTR)lpAllocAddr + ulcount * sizeof(IMAGE_IMPORT_DESCRIPTOR));

							lpNewIIDItem->OriginalFirstThunk = (ULONG)((ULONG_PTR)lpAllocAddr - (ULONG_PTR)lpImagebase + 2084);
							lpNewIIDItem->TimeDateStamp = 0;
							lpNewIIDItem->ForwarderChain = 0;
							lpNewIIDItem->Name = (ULONG)((ULONG_PTR)lpNewIIDModulePath - (ULONG_PTR)lpImagebase);
							lpNewIIDItem->FirstThunk = lpNewIIDItem->OriginalFirstThunk;

							lpThunkData = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpAllocAddr + 2084);
							if (bIs64Process)
								((PIMAGE_THUNK_DATA64)lpThunkData)->u1.Ordinal = 0x8000000000000001;
							else
								((PIMAGE_THUNK_DATA32)lpThunkData)->u1.Ordinal = 0x80000001;
							
							memcpy(lpNewIIDItem + 1, pImportTable, ulImtSize);
							memcpy(lpNewIIDModulePath, ansiDllPath.Buffer, ansiDllPath.Length);
							
							// Patch DataDirectory[IMPORT].Rva/Size
							if (bIs64Process) {
								pImportVa = &((PIMAGE_NT_HEADERS64)pNtHeader)->OptionalHeader.DataDirectory
									[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

								DbgPrint("[KernelImportInject] MakeIMTInject pImportVa:%x", *(ULONG*)pImportVa);
								DbgPrint("[KernelImportInject] MakeIMTInject Size:%x", *(ULONG*)((ULONG_PTR)pImportVa + 4));
							}
							else {
								pImportVa = &((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory
									[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

								DbgPrint("[KernelImportInject] MakeIMTInject pImportVa:%x", *(ULONG*)pImportVa);
								DbgPrint("[KernelImportInject] MakeIMTInject Size:%x", *(ULONG*)((ULONG_PTR)pImportVa + 4));
							}

							if (g_ZwProtectVirtualMemory)
							{
								ulProtectSize = 8;
								pProtectBase = pImportVa;
								Status = g_ZwProtectVirtualMemory(NtCurrentProcess(), &pProtectBase, &ulProtectSize, PAGE_READWRITE, &ulOldProtect);

								if (NT_SUCCESS(Status))
								{
									DbgPrint("[KernelImportInject] MakeIMTInject ulProtectSize:%x", ulProtectSize);
									*(ULONG*)((ULONG_PTR)pImportVa + 4) += sizeof(IMAGE_IMPORT_DESCRIPTOR);
									*(ULONG*)pImportVa = (ULONG)((ULONG_PTR)lpAllocAddr - (ULONG_PTR)lpImagebase);

									// Clear Bound Import Table ... 
									// 虽然改页属性只改了8字节，但是由于ZwProtectVirtualMemory的内存对齐，
									// 其实整个页面都被改了
									if (bIs64Process) {
										((PIMAGE_NT_HEADERS64)pNtHeader)->OptionalHeader.DataDirectory
											[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
										((PIMAGE_NT_HEADERS64)pNtHeader)->OptionalHeader.DataDirectory
											[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
									}
									else {
										((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory
											[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
										((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory
											[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
									}

									Status = g_ZwProtectVirtualMemory(NtCurrentProcess(), &pProtectBase, 
										&ulProtectSize, ulOldProtect, &ulOldProtect);
								}
								else
								{
									DbgPrint("[KernelImportInject] MakeIMTInject g_ZwProtectVirtualMemory failed:%x", Status);
								}
							}
						}
					}
				}
			}
		}
	}

	if (ansiDllPath.Buffer)
		RtlFreeAnsiString(&ansiDllPath);

	return Status;
}


PVOID AllocateWow64MemoryRegion64(HANDLE hProcessHandle, ULONG ulAllocateSize, PVOID lpBaseAddress)
{
	NTSTATUS                  Status;
	PVOID                     lpFarAddress;
	ULONG                     ulReturnLength;
	ULONG_PTR                 v8;
	MEMORY_BASIC_INFORMATION  mbi;
	SIZE_T                    ulRegionSize    = ulAllocateSize;
	volatile PVOID            lpAllocatedAddr = NULL;

	if ((ULONG_PTR)lpBaseAddress - 0x70000000 <= 0x0FFFFFFF)
	{
		// 确保在32位地址空间内
		lpFarAddress = (PVOID)0x71B00000;

		// 没有给定进程基地址
		if (!lpBaseAddress && CheckIs64Process(hProcessHandle))
			lpFarAddress = (PVOID)0x7FF00000000;

		if (NT_SUCCESS(g_ZwQueryVirtualMemory(hProcessHandle, lpFarAddress, 
			MemoryBasicInformation, &mbi, sizeof(mbi), &ulReturnLength)) )
		{
			while (mbi.State != MEM_FREE || 
				!NT_SUCCESS(ZwAllocateVirtualMemory(hProcessHandle, &mbi.BaseAddress, 0, 
				&ulRegionSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)) )
			{

				if (lpFarAddress == mbi.AllocationBase)
					lpFarAddress = (PVOID)((ULONG_PTR)lpFarAddress - 0x10000);
				else
					lpFarAddress = mbi.AllocationBase;

				if (!NT_SUCCESS(g_ZwQueryVirtualMemory(hProcessHandle, lpFarAddress, 
					MemoryBasicInformation, &mbi, sizeof(mbi), &ulReturnLength)))
					goto Lable_2;

			}

			goto Lable_1;
		}
	}

	// 向上搜索
	lpFarAddress = lpBaseAddress;
	while (NT_SUCCESS(g_ZwQueryVirtualMemory(hProcessHandle, lpFarAddress, 
		MemoryBasicInformation, &mbi, sizeof(mbi), &ulReturnLength)))
	{
		if (mbi.State == MEM_FREE)
		{
			// 直到溢出32位地址空间
			if ((ULONG_PTR)mbi.BaseAddress - (ULONG_PTR)lpBaseAddress >= 0x80000000 )
				break;

			Status = ZwAllocateVirtualMemory(hProcessHandle, &mbi.BaseAddress, 0, 
				&ulRegionSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (NT_SUCCESS(Status))
			{
				lpAllocatedAddr = mbi.BaseAddress;
				break;
			}
		}
		if ( mbi.RegionSize >= 0x10000 )
			v8 = mbi.RegionSize & 0xFFFFFFFFFFFF0000;
		else
			v8 = 0x10000;

		lpFarAddress = (PVOID)((ULONG_PTR)lpFarAddress + v8);
		mbi.RegionSize = v8;

	}
	
	// 向下搜索
	if (!lpAllocatedAddr)
	{
		lpFarAddress = lpBaseAddress;
		while (NT_SUCCESS(g_ZwQueryVirtualMemory(hProcessHandle, lpFarAddress, 
			MemoryBasicInformation, &mbi, sizeof(mbi), &ulReturnLength)))
		{
			if ( mbi.State == MEM_FREE )
			{
				if ((ULONG_PTR)lpBaseAddress - (ULONG_PTR)mbi.BaseAddress >= 0x80000000)
					goto Lable_2;

				Status = ZwAllocateVirtualMemory(hProcessHandle, &mbi.BaseAddress, 0, 
					&ulRegionSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				if (NT_SUCCESS(Status))
					goto Lable_1;
			}

			if ( lpFarAddress == mbi.AllocationBase )
				lpFarAddress = (PVOID)((ULONG_PTR)lpFarAddress - 0x10000);
			else
				lpFarAddress = mbi.AllocationBase;

		}
		goto Lable_2;

Lable_1:
		lpAllocatedAddr = mbi.BaseAddress;
Lable_2:
		if (lpAllocatedAddr == NULL)
			goto Lable_3;
	}

	// Change MEM_RESERVE --> MEM_COMMIT
	if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcessHandle, (PVOID*)&lpAllocatedAddr, 0, 
		&ulRegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		DbgPrint("[KernelImportInject] MakeIMTInject ZwAllocateVirtualMemory MEM_COMMIT:%p\r\n", lpAllocatedAddr);
		return lpAllocatedAddr;
	}

Lable_3:
	return NULL;
}