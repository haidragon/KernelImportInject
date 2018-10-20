#ifndef _IMTINJECT_H
#define _IMTINJECT_H

#include "headers.h"

NTSTATUS MakeIMTInject(PVOID lpImagebase, LPWCH lpszDllPath, BOOLEAN bIs64Process);
PVOID AllocateWow64MemoryRegion64(HANDLE hProcessHandle, ULONG ulAllocateSize, PVOID lpBaseAddress);

#endif