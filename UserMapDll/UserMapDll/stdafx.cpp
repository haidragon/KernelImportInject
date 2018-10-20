// stdafx.cpp : 只包括标准包含文件的源文件
// UserMapDll.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"

// TODO: 在 STDAFX.H 中
// 引用任何所需的附加头文件，而不是在此文件中引用

#include <tchar.h>
#include <strsafe.h>


void _DbgPrintW(const WCHAR* pszFormat, ...) 
{ 
	va_list args;
	ULONG ulIndex = 0;
	WCHAR szDebugInfo[MAX_PATH] = {0};
	va_start(args, pszFormat);

#ifdef _WIN64
	HRESULT hr = StringCchCopyW(szDebugInfo, MAX_PATH, L"[UserMapDllX64]");
	ulIndex = wcslen(L"[UserMapDllX64]");
#else
	HRESULT hr = StringCchCopyW(szDebugInfo, MAX_PATH, L"[UserMapDllX86]");
	ulIndex = wcslen(L"[UserMapDllX86]");
#endif
	if (FAILED(hr)){
		return;
	}

	hr = StringCchVPrintfW(szDebugInfo + ulIndex, MAX_PATH - ulIndex, pszFormat, args);
	if (FAILED(hr)){
		return;
	}

	OutputDebugStringW(szDebugInfo);
	va_end(args);
}

void _DbgPrintA(const char* pszFormat, ...) 
{ 
	va_list args;
	ULONG ulIndex = 0;
	char szDebugInfo[MAX_PATH] = {0};
	va_start(args, pszFormat);

#ifdef _WIN64
	HRESULT hr = StringCchCopyA(szDebugInfo, MAX_PATH, "[UserMapDllX64]");
	ulIndex = wcslen(L"[UserMapDllX64]");
#else
	HRESULT hr = StringCchCopyA(szDebugInfo, MAX_PATH, "[UserMapDllX86]");
	ulIndex = wcslen(L"[UserMapDllX86]");
#endif
	
	if (FAILED(hr)){
		return;
	}

	hr = StringCchVPrintfA(szDebugInfo + ulIndex, MAX_PATH - ulIndex, pszFormat, args);
	if (FAILED(hr)){
		return;
	}

	OutputDebugStringA(szDebugInfo);
	va_end(args);
}