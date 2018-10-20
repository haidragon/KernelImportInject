/***************************************************************************************
* AUTHOR : FaEry
* DATE   : 2017-3-24
* MODULE : KernlImportInject.C
*
*  Description: Just For X64/WOW64 Process Injection
****************************************************************************************
* Copyright (C) 2010 FaEry.
****************************************************************************************/

#include "KernelImportInject.h"
#include "public.h"

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS		status = STATUS_SUCCESS;

	DbgPrint("[KernelImportInject] DriverEntry Get Called");

	Init(pDriverObj, pRegistryString);
	pDriverObj->DriverUnload = DriverUnload;

	return status;
}

VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	UnInit();
	return;
}