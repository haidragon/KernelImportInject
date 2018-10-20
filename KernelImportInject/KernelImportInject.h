/***************************************************************************************
* AUTHOR : FaEry
* DATE   : 2017-3-24
* MODULE : KernlImportInject.H
*
* IOCTRL Sample Driver
*
* Description:
*		Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 FaEry.
****************************************************************************************/

#ifndef CXX_KERNLIMPORTINJECT_H
#define CXX_KERNLIMPORTINJECT_H


#include "headers.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);


#endif	//CXX_KERNLIMPORTINJECT_H
/* EOF */
