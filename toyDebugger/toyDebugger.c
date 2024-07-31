#include "toyDebugger.h"

#define SOFTWAREbp
// #define HARDWAREbp

///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------

const char* pGlobalTargetFunction = "NtWriteFile";

// chosen section
const char* PEsection = ".rdata";

// Original byte before the software breakpoint
BYTE bGlobalOriginalByte = NULL;

// address of nt function we want to set the breakpoint (hardware or software)
PVOID pGlobalFuncAddress = NULL;

// target.exe entry address
PVOID pGlobalEntryImageAddress = NULL;


///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL PrintStackFrame(HANDLE hProcess, HANDLE hThread, CONTEXT ctx) {

	// stackframe structure:
	STACKFRAME sf = { .AddrPC = ctx.Eip,
					  .AddrFrame = ctx.Ebp,
					  .AddrStack = ctx.Esp
	};

	printf("\n\t\t{STACK FRAME}\n");

	int MAX_FRAMES = 16;
	int frame = 0;

	// Creamos un counter para que nos suelte todos los frames disponibles
	while (StackWalk64(IMAGE_FILE_MACHINE_I386, hProcess, hThread, &sf, &ctx, NULL, NULL, NULL, NULL)) {

		printf("\t\t\tFrame: %d", frame); // nos dice en el frame en el que estamos
		printf("\n\t\t\tPC address: 0x%p", sf.AddrPC.Offset); // program counter address
		printf("\n\t\t\tStack address: 0x%p", sf.AddrStack.Offset); // stack address
		printf("\n\t\t\tPFrame address: 0x%p\n\n", sf.AddrFrame.Offset); // base pointer address

		if (frame <= MAX_FRAMES) {
			break;
		}
		else {
			frame++;
		}
	}

	return TRUE;
}


DWORD handleEventException(DEBUG_EVENT pEvent) {

	if (pEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

		// if software breakpoint...
		if (pEvent.u.Exception.ExceptionRecord.ExceptionAddress == pGlobalFuncAddress) {
			printf("\n\n[EXCEPTION_BREAKPOINT] %s at 0x%p\n\n", pGlobalTargetFunction, pGlobalFuncAddress);

			///
			/// Writing a the orignial byte back into nt target function address
			///
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEvent.dwProcessId);
			BYTE bpFunctionByte = NULL;

			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pEvent.dwThreadId);

			CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };
			if (GetThreadContext(hThread, &ctx) != TRUE) {
				printf("\n[ERROR GETTING THE CONTEXT] %d\n", GetLastError());
				return DBG_CONTINUE;
			}

			printf("\n\t\tEIP before CONTEXT fix: 0x%p", ctx.Eip);

			ctx.Eip = ctx.Eip - 1;

			printf("\n\t\tEIP after CONTEXT fix: 0x%p", ctx.Eip);

			if (SetThreadContext(hThread, &ctx) != TRUE) {
				printf("\n[ERROR SETTING THE CONTEXT] %d\n", GetLastError());
				return DBG_CONTINUE;
			}

			DWORD lpflOldProtect = NULL;
			DWORD lpflNewOldProtect = NULL;

			if (VirtualProtectEx(hProcess, pEvent.u.Exception.ExceptionRecord.ExceptionAddress, sizeof(BYTE), PAGE_READWRITE, &lpflOldProtect) != TRUE) {
				printf("\n[TRYING TO SET A BREAKPOINT] error changing the memory permission - %d\n", GetLastError());
				CloseHandle(hThread);
				CloseHandle(hProcess);
				return DBG_CONTINUE;
			}

			SIZE_T lpNumberOfBytesRead = NULL;
			if (ReadProcessMemory(hProcess, pEvent.u.Exception.ExceptionRecord.ExceptionAddress, &bpFunctionByte, sizeof(BYTE), &lpNumberOfBytesRead) != TRUE) {
				printf("\n[TRYING TO SET A BREAKPOINT] error reading the '0xcc' opcode into the address - %d\n", GetLastError());
				CloseHandle(hThread);
				CloseHandle(hProcess);
				return DBG_CONTINUE;
			}
			printf("\n\t\tThis is the byte after the breakpoint 0x%0.2X\n", bpFunctionByte);
			printf("\t\tThis is the original byte 0x%0.2X\n", bGlobalOriginalByte);

			SIZE_T lpNumberOfBytesWritten = NULL;
			if (WriteProcessMemory(hProcess, pEvent.u.Exception.ExceptionRecord.ExceptionAddress, &bGlobalOriginalByte, sizeof(BYTE), &lpNumberOfBytesWritten) != TRUE) {
				printf("[TRYING TO SET A BREAKPOINT] error writing de '0xcc' opcode into the address - %d\n", GetLastError());
				CloseHandle(hThread);
				CloseHandle(hProcess);
				return DBG_CONTINUE;
			}

			if (VirtualProtectEx(hProcess, pEvent.u.Exception.ExceptionRecord.ExceptionAddress, sizeof(BYTE), lpflOldProtect, &lpflNewOldProtect) != TRUE) {
				printf("[TRYING TO SET A BREAKPOINT] error changing back the memory permission - %d\n", GetLastError());
				CloseHandle(hThread);
				CloseHandle(hProcess);
				return DBG_CONTINUE;
			}

			///
			/// Getting the stack frame for the target Nt function
			///

			STACKFRAME sf = { .AddrPC = ctx.Eip,
							  .AddrFrame = ctx.Ebp,
							  .AddrStack = ctx.Esp
			};

			printf("\n\t\t{%s STACK FRAME}\n", pGlobalTargetFunction);

			int MAX_FRAMES = 16;
			int frame = 0;

			CloseHandle(hThread);
			CloseHandle(hProcess);
		}
		else {
			printf("\n\n[EXCEPTION_BREAKPOINT] 0x%p\n\n", pEvent.u.Exception.ExceptionRecord.ExceptionAddress);
		}
	}

	if (pEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if (pEvent.u.Exception.ExceptionRecord.ExceptionAddress == pGlobalFuncAddress) {
			printf("\n[HARDWARE BREAKPOINT] 0x%p\n", pEvent.u.Exception.ExceptionRecord.ExceptionAddress);

			///
			/// Cleaning the hardware breakpoint
			///
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEvent.dwProcessId);
			CONTEXT ctxHard = { .ContextFlags = CONTEXT_ALL };
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pEvent.dwThreadId);
			if (GetThreadContext(hThread, &ctxHard) != TRUE) {
				printf("\n[ERROR GETTING THE CONTEXT FOR THE HARDWARE BREAKPOINT] - %d\n", GetLastError());
				CloseHandle(hThread);
			}

			// Ways to clean Dr7
			// ctxHard.Dr7 &= 0b000000000000000000000000;
			// ctxHard.Dr7 = ~0b000000000000000000000001 & 0xffffffff;
			// ctxHard.Dr7 = 0b000000000000000000000000;
			// ctxHard.Dr7 = 0b111111111111111111111111;
			ctxHard.Dr7 = 0x0;

			if (SetThreadContext(hThread, &ctxHard) != TRUE) {
				printf("\n[ERROR SETTING THE CONTEXT FOR THE HARDWARE BREAKPOINT] - %d\n", GetLastError());
				CloseHandle(hThread);
			}

			///
			/// Getting the stack frame for nt target function (Hardware breakpoint)
			///

			STACKFRAME sf = { .AddrPC = ctxHard.Eip,
							  .AddrFrame = ctxHard.Ebp,
							  .AddrStack = ctxHard.Esp
			};

			printf("\n\t\t{%s STACK FRAME}\n", pGlobalTargetFunction);

			int MAX_FRAMES = 16;
			int frame = 0;

			// Get all the available frames
			while (StackWalk64(IMAGE_FILE_MACHINE_I386, hProcess, hThread, &sf, &ctxHard, NULL, NULL, NULL, NULL)) {


				printf("\n\t\t\tstack address: 0x%p", sf.AddrStack.Offset);
				SIZE_T lpNumberOfBytesRead = NULL;
				PVOID NtTargethFile = NULL;
				if (ReadProcessMemory(hProcess, (PVOID)((PBYTE)sf.AddrStack.Offset + 0x4), &NtTargethFile, sizeof(HANDLE), &lpNumberOfBytesRead) != TRUE) {
					printf("\n[TRYING TO READ THE STACK] - %d\n", GetLastError());
					CloseHandle(hThread);
					CloseHandle(hProcess);
					return DBG_CONTINUE;
				}
				printf("\n\t\t\t%s handle: 0x%p", pGlobalTargetFunction, NtTargethFile);


				// buffer address from nt target function stack
				lpNumberOfBytesRead = NULL;
				PVOID NtTargetBufferAddress = NULL;
				if (ReadProcessMemory(hProcess, (PVOID)((PBYTE)sf.AddrStack.Offset + 0x18), &NtTargetBufferAddress, sizeof(HANDLE), &lpNumberOfBytesRead) != TRUE) {
					printf("\n[TRYING TO READ THE STACK] - %d\n", GetLastError());
					CloseHandle(hThread);
					CloseHandle(hProcess);
					return DBG_CONTINUE;
				}
				printf("\n\t\t\t%s buffer address from the stack: 0x%p\n\n", pGlobalTargetFunction, NtTargetBufferAddress);

				if (frame <= MAX_FRAMES) {
					break;
				}
				else {
					frame++;
				}
			}

			CloseHandle(hProcess);
			CloseHandle(hThread);
		}
	}

	return DBG_CONTINUE;
}


///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------


DWORD handleEventLoadDll(DEBUG_EVENT pEvent) {

	// get the loaded dll's base address
	PBYTE pDllPeBase = (PBYTE)(pEvent.u.LoadDll.lpBaseOfDll);

	LPCWSTR pPath[(MAX_PATH * sizeof(wchar_t))];
	DWORD dwPath = GetFinalPathNameByHandleW(pEvent.u.LoadDll.hFile, pPath, (sizeof(WCHAR) * MAX_PATH), FILE_NAME_NORMALIZED);
	LPCWSTR pDisplay = &pPath[2];

	wprintf(L"\n\n[LOADED DLL] %s", pDisplay);

	HANDLE hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR] reading the file from disk - %d\n", GetLastError());
		return DBG_CONTINUE;
	}
	printf("\n\t\\__hfile = 0x%p\n", hFile);
	SIZE_T sFile = GetFileSize(hFile, NULL);
	if (sFile == NULL) {
		printf("\n[ERROR] getting the size of the file - %d\n", GetLastError());
		return DBG_CONTINUE;
	}
	printf("\t\t\\____size -> %d\n", sFile);
	PVOID pFile = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sFile);
	if (ReadFile(hFile, pFile, sFile, NULL, NULL) != TRUE) {
		printf("\n[ERROR] reading the file - %d\n", GetLastError());
		CloseHandle(hFile);
		return DBG_CONTINUE;
	}
	CloseHandle(hFile);

	PBYTE pDiskDllBase = (PBYTE)pFile;

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pDiskDllBase;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
		HeapFree(GetProcessHeap(), 0, pFile);
		return DBG_CONTINUE;
	}

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDiskDllBase + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) {
		HeapFree(GetProcessHeap(), 0, pFile);
		return DBG_CONTINUE;
	}

	IMAGE_OPTIONAL_HEADER pOpt = (pNt->OptionalHeader);

	PVOID pPeEntryPoint = (pDllPeBase + pOpt.AddressOfEntryPoint);
	PVOID pLoadedDllBase = (PVOID)(pDllPeBase);

	printf("\n\t\t[LOADED DLL INFO]\n");
	printf("\t\t\t\\__PE Dll base -> 0x%p\n", pLoadedDllBase);
	printf("\t\t\t\\__PE Dll Entry point -> 0x%p\n", pPeEntryPoint);

	// get the ntdll.dll
	for (unsigned int i = 0; i < (MAX_PATH * sizeof(WCHAR)); i++) {
		if (pDisplay[i] == L'n' &&
			pDisplay[i + 1] == L't' &&
			pDisplay[i + 2] == L'd' &&
			pDisplay[i + 3] == L'l' &&
			pDisplay[i + 4] == L'l') {

			PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)(pDllPeBase + pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			printf("\n\t\t\t\t[ntdll.dll] 0x%p\n", pExpDir);
			PDWORD pdwAddress = (PDWORD)(pDllPeBase + pExpDir->AddressOfFunctions);
			PDWORD pdwNames = (PDWORD)(pDllPeBase + pExpDir->AddressOfNames);
			PWORD pdwOrdinals = (PWORD)(pDllPeBase + pExpDir->AddressOfNameOrdinals);

			for (unsigned int o = 0; o < pExpDir->NumberOfFunctions; o++) {

				CHAR* FuncName = (CHAR*)(pDllPeBase + pdwNames[o]);

				PVOID pFuncAddresses = (PVOID)(pDllPeBase + pdwAddress[pdwOrdinals[o]]);

				//printf("\nFunctions - %s\n", FunctionNames);

				if (strcmp(FuncName, pGlobalTargetFunction) == 0) {

					printf("\t\t\t\t\t\\__[%s] Found at 0x%p\n", FuncName, pFuncAddresses);
					pGlobalFuncAddress = pFuncAddresses;

#ifdef SOFTWAREbp
					///
					/// Software breakpoint
					///
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEvent.dwProcessId);
					BYTE bpINT = 0xcc;

					DWORD lpflOldProtect = NULL;
					DWORD lpflNewOldProtect = NULL;

					printf("\n\t\t\t\t\t[SOFTWARE BREAKPOINT] at 0x%p\n", pFuncAddresses);

					if (VirtualProtectEx(hProcess, pFuncAddresses, sizeof(BYTE), PAGE_READWRITE, &lpflOldProtect) != TRUE) {
						printf("\n[TRYING TO SET A SOFTWARE BREAKPOINT] error changing the memory permission - %d\n", GetLastError());
						CloseHandle(hProcess);
						return DBG_CONTINUE;
					}

					SIZE_T lpNumberOfBytesRead = NULL;
					if (ReadProcessMemory(hProcess, pFuncAddresses, &bGlobalOriginalByte, sizeof(BYTE), &lpNumberOfBytesRead) != TRUE) {
						printf("\n[TRYING TO SET A SOFTWARE BREAKPOINT] error writing de '0xcc' opcode into the address - %d\n", GetLastError());
						CloseHandle(hProcess);
						return DBG_CONTINUE;
					}
					printf("\t\t\t\t\t\t\\__Original byte replaced by 0xcc -> [0x%0.2X]\n", bGlobalOriginalByte);

					SIZE_T lpNumberOfBytesWritten = NULL;
					if (WriteProcessMemory(hProcess, pFuncAddresses, &bpINT, sizeof(BYTE), &lpNumberOfBytesWritten) != TRUE) {
						printf("\n[TRYING TO SET A BREAKPOINT] error writing de '0xcc' opcode into the address - %d\n", GetLastError());
						CloseHandle(hProcess);
						return DBG_CONTINUE;
					}

					if (VirtualProtectEx(hProcess, pFuncAddresses, sizeof(BYTE), lpflOldProtect, &lpflNewOldProtect) != TRUE) {
						printf("\n[TRYING TO SET A BREAKPOINT] error changing back the memory permission - %d\n", GetLastError());
						CloseHandle(hProcess);
						return DBG_CONTINUE;
					}

					CloseHandle(hProcess);
#endif

#ifdef HARDWAREbp
					///
					/// Hardware Breakpoint
					///
					CONTEXT ctxHard = { .ContextFlags = CONTEXT_ALL };
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pEvent.dwThreadId);
					if (GetThreadContext(hThread, &ctxHard) != TRUE) {
						printf("\n[ERROR GETTING THE CONTEXT FOR THE HARDWARE BREAKPOINT] - %d\n", GetLastError());
						CloseHandle(hThread);
					}

					ctxHard.Dr0 = pFuncAddresses;
					ctxHard.Dr7 |= 0b000000000000000000000001;

					if (SetThreadContext(hThread, &ctxHard) != TRUE) {
						printf("\n[ERROR SETTING THE CONTEXT FOR THE HARDWARE BREAKPOINT] - %d\n", GetLastError());
						CloseHandle(hThread);
					}

					printf("\n\t\t\t\t\t[HARDWARE BREAKPOINT] at 0x%p\n", pFuncAddresses);

					CloseHandle(hThread);
					HeapFree(GetProcessHeap(), 0, pFile);
					return DBG_CONTINUE;
#endif
				}
			}

			break;
		}
	}

	HeapFree(GetProcessHeap(), 0, pFile);
	return DBG_CONTINUE;
}

DWORD handleEventUnloadDll(DEBUG_EVENT pEvent) {

	printf("\n\n[UNLOAD_DLL_DEBUG_EVENT]\n");

	return DBG_CONTINUE;
}

DWORD handleEventCreateProcess(DEBUG_EVENT pEvent) {

	pGlobalEntryImageAddress = pEvent.u.CreateProcessInfo.lpBaseOfImage;

	printf("\n\n[CREATE_PROCESS_DEBUG_EVENT]\n");
	printf("\nTarget loaded at 0x%p\n", pEvent.u.CreateProcessInfo.lpBaseOfImage);
	printf("\nTarget entry point at 0x%p\n", pEvent.u.CreateProcessInfo.lpStartAddress);

	LPCWSTR pImagePath[MAX_PATH * sizeof(WCHAR)];

	DWORD dwPath = GetFinalPathNameByHandleW(pEvent.u.CreateProcessInfo.hFile, pImagePath, (sizeof(WCHAR) * MAX_PATH), FILE_NAME_NORMALIZED);
	LPCWSTR pDisplay = &pImagePath[2];

	wprintf(L"\n\t[!] Getting image file of %s\n", pDisplay);

	// Copying target image to a buffer
	HANDLE hFile = CreateFileW(pImagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR] reading the file from disk - %d\n", GetLastError());
		return DBG_CONTINUE;
	}
	printf("\t\t\\__hfile = 0x%p\n", hFile);
	SIZE_T sImage = GetFileSize(hFile, NULL);
	if (sImage == NULL) {
		printf("\n[ERROR] getting the size of the file - %d\n", GetLastError());
		return DBG_CONTINUE;
	}
	printf("\t\t\t\\____size -> %d\n", sImage);
	PVOID pImage = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sImage);
	if (ReadFile(hFile, pImage, sImage, NULL, NULL) != TRUE) {
		printf("\n[ERROR] reading the file - %d\n", GetLastError());
		CloseHandle(hFile);
		return DBG_CONTINUE;
	}
	CloseHandle(hFile);

	PBYTE pImageBase = (PBYTE)(pImage);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
		return DBG_CONTINUE;
	}

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImageBase + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) {
		return DBG_CONTINUE;
	}

	IMAGE_OPTIONAL_HEADER pOpt = (pNt->OptionalHeader);

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));

	for (unsigned int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		printf("\n\t%s\n", pSection->Name);
		if (strcmp(PEsection, pSection->Name) == 0) {
			PVOID pRemoteRdata = (PVOID)((PBYTE)pEvent.u.CreateProcessInfo.lpBaseOfImage + pSection->VirtualAddress);
			printf("\n\n\t   [%s] at 0x%p\n", PEsection, pRemoteRdata);
			printf("\t   Image loaded at: 0x%p\n", pEvent.u.CreateProcessInfo.lpBaseOfImage);
			printf("\t   size = %d\n", pSection->Misc.VirtualSize);
			printf("\t   Virtual Address = 0x%p\n", pSection->VirtualAddress);


			// asignamos el buffer para el .rdata del proceso remoto
			PVOID pSectionBuffer = HeapAlloc(GetProcessHeap(), 0, pSection->Misc.VirtualSize);
			SIZE_T sNumberOfBytesRead = NULL;
			// con el RVA de .rdata coseguimos la .rdata section del remote process y lo copiamos al buffer
			if (ReadProcessMemory(pEvent.u.CreateProcessInfo.hProcess, pRemoteRdata, pSectionBuffer, pSection->Misc.VirtualSize, sNumberOfBytesRead) != TRUE) {
				printf("\n[ERROR] reading the .rdata section - %d\n", GetLastError());
				return DBG_CONTINUE;
			}
			PBYTE pbSectionBuffer = (PBYTE)pSectionBuffer;

			printf("\n\t\t[%s] Dumping all data...\n", PEsection);
			for (DWORD sSize = 0; sSize < pSection->Misc.VirtualSize; sSize++) {

				// dump all data into the section
				if (sSize % 16 == 0) {
					printf("\n\t\t\t");
				}
				if (sSize + 2 > pSection->Misc.VirtualSize) {
					printf("0x%0.2X", *(pbSectionBuffer + sSize));
				}
				else {
					printf("0x%0.2X, ", *(pbSectionBuffer + sSize));
				}

			}
			HeapFree(GetProcessHeap(), 0, pSectionBuffer);
		}
		pSection = (PIMAGE_SECTION_HEADER)((PBYTE)pSection + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	HeapFree(GetProcessHeap(), 0, pImageBase);
	return DBG_CONTINUE;
}


DWORD handleEventExitProcess(DEBUG_EVENT pEvent) {

	printf("\n\n[EXIT_PROCESS_DEBUG_EVENT]\n");
	printf("\t\\__Exit code [%d]\n", pEvent.u.ExitProcess.dwExitCode);
	return DBG_CONTINUE;
}

DWORD handleEventCreateThread(DEBUG_EVENT pEvent) {

	printf("\n\n[CREATE_THREAD_DEBUG_EVENT]\n");
	printf("\n\tThread [%d] CONTEXT:", pEvent.dwThreadId);
	CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };
	if (GetThreadContext(pEvent.u.CreateThread.hThread, &ctx) != TRUE) {
		printf("\n[ERROR] Getting the thread context - %d\n", GetLastError());
		return DBG_CONTINUE;
	}
	printf("\n\t\t Dr0 \t0x%p\n", ctx.Dr0);
	printf("\t\t Dr1 \t0x%p\n", ctx.Dr1);
	printf("\t\t Dr2 \t0x%p\n", ctx.Dr2);
	printf("\t\t Dr3 \t0x%p\n", ctx.Dr3);
	printf("\t\t Dr6 \t0x%p\n", ctx.Dr6);
	printf("\t\t Dr7 \t0x%p\n\n", ctx.Dr7);

	printf("\n\t\t Edi \t0x%p\n", ctx.Edi);
	printf("\t\t Esi \t0x%p\n", ctx.Esi);
	printf("\t\t Ebx \t0x%p\n", ctx.Ebx);
	printf("\t\t Edx \t0x%p\n", ctx.Edx);
	printf("\t\t Ecx \t0x%p\n", ctx.Ecx);
	printf("\t\t Eax \t0x%p\n", ctx.Eax);
	printf("\t\t Ebp \t0x%p\n", ctx.Ebp);
	printf("\t\t Eip \t0x%p\n", ctx.Eip);


	printf("\n\t\t SegCs \t0x%p\n", ctx.SegCs);
	printf("\t\t EFlags 0x%p\n", ctx.EFlags);
	printf("\t\t Esp \t0x%p\n\n", ctx.Esp);
	printf("\t\t SegSs \t0x%p\n\n", ctx.SegSs);

	if (PrintStackFrame(GetCurrentProcess(), pEvent.u.CreateThread.hThread, ctx) != TRUE) {
		printf("\n[ERROR] Getting the Stack Frame - %d\n", GetLastError());
		return DBG_CONTINUE;
	}

	return DBG_CONTINUE;
}

DWORD handleEventExitThread(DEBUG_EVENT pEvent) {

	printf("\n\n[EXIT_THREAD_DEBUG_EVENT]\n");
	printf("\t\\__Thread Exit Code [%d]\n", pEvent.u.ExitThread.dwExitCode);

	return DBG_CONTINUE;
}