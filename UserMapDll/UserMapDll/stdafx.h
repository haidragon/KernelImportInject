// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             //  从 Windows 头文件中排除极少使用的信息
// Windows 头文件:
#include <windows.h>



// TODO: 在此处引用程序需要的其他头文件


#define OUTPUT_DEBUG_INFO

#if (defined _DEBUG) || (defined OUTPUT_DEBUG_INFO)

void _DbgPrintW(const WCHAR* pszFormat, ...);
void _DbgPrintA(const char* pszFormat, ...);

#define DbgPrintW  _DbgPrintW
#define DbgPrintA _DbgPrintA
#else
void DbgPrintW(const WCHAR* pszFormat, ...) { do{}while(FALSE); }
void DbgPrintA(const char* pszFormat, ...) { do{}while(FALSE); }
#endif