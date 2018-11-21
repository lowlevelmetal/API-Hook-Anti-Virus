#include <Windows.h>
#include <Psapi.h>

//
// BIG USELESS FUNCTION TO MAKE SURE DYNAMIC LINKING OCCURS
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

			if (dwTarget)
				int iStatus = MessageBox(NULL, "Click Me NOW", "Click Me NOW", NULL);
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	HANDLE hThread = CreateThread(0, 0, CallMessageBox, 0, 0, 0);

	WaitForSingleObject(hThread, INFINITE);

	return EXIT_SUCCESS;
}