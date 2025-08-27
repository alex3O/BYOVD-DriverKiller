#pragma once
#include <windows.h>

#define RES_DRIVER 1

BOOL ExtractDriver(wchar_t* path);
BOOL InstallAndStartDriver(wchar_t* Path, LPCWSTR serviceName);
BOOL StopAndRemoveDriver(LPCWSTR serviceName, wchar_t* path);
BOOL CheckDriver(LPCWSTR serviceName);