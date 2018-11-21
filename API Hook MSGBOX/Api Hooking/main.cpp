/*
* Project: Api Hooking
* File: main.cpp
*
* Author: Matthew Todd Geiger
*
* Time: 3:00
*
* Brief: This file contains the entire program
*/

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

//
// Defines and typedefs
typedef int (WINAPI *fpMessageBoxA)(
	HWND    hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT    uType
	);


fpMessageBoxA OriginalMessageBoxA = 
    (fpMessageBoxA)GetProcAddress(GetModuleHandle("user32.dll"), 
    "MessageBoxA");

// Hooked function
int WINAPI HookedMessageBoxA(
	HWND    hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT    uType
)
{
	int iStatus = OriginalMessageBoxA(hWnd,
		"Get Hacked!",
		lpCaption,
		uType);
	//ExitProcess(EXIT_SUCCESS);

	//
	// Doesnt really matter
	return iStatus;
}

void StartHook() {
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);

	// Find the base address
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

	char szAddress[64];

	// Find Import Directory
	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddress;

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Find ntdll.dll
	for(; pIID->Characteristics; pIID++) {
		if(!strcmp("USER32.dll", (char *)(pAddress + pIID->Name)))
			break;
	}

	// Search for NtQuerySystemInformation
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)((pAddress + pIID->FirstThunk));
	PIMAGE_IMPORT_BY_NAME pIIBM;

	for(; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
		pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);
		if(!strcmp("MessageBoxA", (char *)(pIIBM->Name)))
			break;
		pFirstThunkTest++;
	}

	// Write over function pointer
	DWORD dwOld = NULL;
	VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	pFirstThunkTest->u1.Function = (DWORD)HookedMessageBoxA;
	VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);

	sprintf(szAddress, "%s 0x%X 0x%X", (char *)(pIIBM->Name), pAddress, pFirstThunkTest->u1.Function); 

	if(pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		MessageBox(NULL, szAddress, "TEST", MB_OK);
	else
		MessageBox(NULL, "FAIL", "FAIL", MB_OK);

	CloseHandle(hModule);
}

DWORD __stdcall StartThread(LPVOID pData) {
	StartHook();
	return EXIT_SUCCESS;
}

bool __stdcall DllMain(HINSTANCE hInstance,
					   DWORD dwReason,
					   LPVOID lpReserved)
{
	switch(dwReason) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hInstance);
		CreateThread(NULL, NULL, StartThread, NULL, NULL, NULL);
		Sleep(5000);
		break;
	}

	return TRUE;
}