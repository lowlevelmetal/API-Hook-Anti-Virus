#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <Psapi.h>

typedef int(WINAPI *fpMessageBoxA)(
	HWND    hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT    uType
	);


fpMessageBoxA OriginalMessageBoxA =
(fpMessageBoxA)GetProcAddress(GetModuleHandle("user32.dll"),
	"MessageBoxA");

DWORD AntiVirus() {
	MessageBox(NULL, "Anti Virus Loaded", "TEST", MB_OK);

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
		Sleep(150);
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
// MAKING SURE THAT IT USES DYNAMIC LINKING
//

DWORD __stdcall CallMessageBox(LPVOID pData) {
	while (true) {
		MessageBox(NULL, "Click Me", "Click Me", MB_OK);

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
			Sleep(150);
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

			if(dwTarget)
				int iStatus = MessageBox(NULL, "Click Me NOW", "Click Me NOW", NULL);
		}
	}

	return EXIT_SUCCESS;
}

HANDLE hThreads[2];

DWORD __stdcall RunAntiVirus(LPVOID pData) {
	DWORD dwStatus = AntiVirus();

	if (dwStatus == EXIT_FAILURE || dwStatus == 1337) {
		TerminateThread(hThreads[1], EXIT_FAILURE);
		TerminateThread(hThreads[0], EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {

	hThreads[0] = CreateThread(0, 0, RunAntiVirus, 0, 0, 0);
	hThreads[1] = CreateThread(0, 0, CallMessageBox, 0, 0, 0);

	WaitForMultipleObjects(2, hThreads, TRUE, INFINITE);

	CloseHandle(hThreads[0]);
	CloseHandle(hThreads[1]);

	return EXIT_SUCCESS;
}