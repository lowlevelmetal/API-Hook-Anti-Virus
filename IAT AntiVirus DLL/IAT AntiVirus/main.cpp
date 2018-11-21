/*
* Project: Api Hooking Anti Virus
* File: main.cpp
*
* Author: Matthew Todd Geiger
*
* Time: 20:32
*
* Brief: This file contains the entire program
*/

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>
#include <TlHelp32.h>

typedef int(WINAPI *fpMessageBoxA)(
	HWND    hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT    uType
	);


fpMessageBoxA OriginalMessageBoxA =
(fpMessageBoxA)GetProcAddress(GetModuleHandle("user32.dll"),
	"MessageBoxA");

DWORD StartProcess() {
	MessageBox(NULL, "Anti Virus Loaded", "Taskmgr.exe", MB_OK);

	//
	// Find the base address
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

	if (!modInfo.lpBaseOfDll)
		return EXIT_FAILURE;

	//
	// Find Import Directory
	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddress;

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//
	// Create Check Sum of IAT
	unsigned long dwCount = 0;

	for (; pIID->Characteristics; pIID++) {
		PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)(pAddress + pIID->FirstThunk);
		PIMAGE_IMPORT_BY_NAME pIIBM;

		for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
			pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);

			if (pFirstThunkTest->u1.Function) {
				dwCount = dwCount + (DWORD)pFirstThunkTest->u1.Function;
			}

			pFirstThunkTest++;
		}
	}

	//
	// Constantly Compare Check Sum
	while (true) {
		unsigned long dwTarget = 0;

		pAddress = (LPBYTE)modInfo.lpBaseOfDll;
		pIDH = (PIMAGE_DOS_HEADER)pAddress;

		pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew);
		pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
		pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (; pIID->Characteristics; pIID++) {
			PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)(pAddress + pIID->FirstThunk);
			PIMAGE_IMPORT_BY_NAME pIIBM;

			for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
				pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);

				if (pFirstThunkTest->u1.Function) {
					dwTarget = dwTarget + (DWORD)pFirstThunkTest->u1.Function;
				}

				pFirstThunkTest++;
			}
		}

		//
		// Exit if check sums dont match
		if (dwTarget != dwCount) {
			OriginalMessageBoxA(NULL, "VIRUS FOUND", "ATTENTION", MB_ICONERROR);
			return EXIT_FAILURE;
		}
	}

	return 1337;
}

//
// Thread Start
DWORD __stdcall StartThread(LPVOID pData) {
	DWORD dwResult = StartProcess();
	if (dwResult == EXIT_FAILURE || dwResult == 1337)
		ExitProcess(EXIT_FAILURE);

	return dwResult;
}

bool __stdcall DllMain(HINSTANCE hInstance,
	DWORD dwReason,
	LPVOID lpReserved)
{
	//
	// CreateThread and exit for DLL Loader to Finish.
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hInstance);
		CreateThread(NULL, NULL, StartThread, NULL, NULL, NULL);
		Sleep(5000);
		break;
	}

	return true;
}