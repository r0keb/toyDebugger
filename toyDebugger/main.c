#include "toyDebugger.h"

int wmain(int argc, wchar_t* argv[]) {

	if (argc < 2) {
		printf("\nUsage: \"<debugger.exe> program2debug.exe\"\n");
		return -1;
	}

	wchar_t* pTargetPath = argv[1];
	wprintf(L"\n[+] TARGET PATH: '%s'\n", pTargetPath);

	STARTUPINFOW si = { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION pi = { 0 };


	if (CreateProcessW(pTargetPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi) != TRUE) {
		printf("\n[!] Error getting the path to the PE %d\n", GetLastError());
		return -1;
	}

	HANDLE hTargetProcess = pi.hProcess;
	HANDLE hTargetThread = pi.hThread;

	printf("\n[+] Target Process ID [%d]\n\t\\__Thread ID [%d]\n", pi.dwProcessId, pi.dwThreadId);

	// debug event loop
	// We keep processing debug events until the target has exited
	// The debug loop can also be terminated by pressing ENTER
	printf("\nPress ENTER to quit debug loop\n");
	while (TRUE) {
		// Create a DEBUG_EVENT struct to be populated with event information
		DEBUG_EVENT pEvent = { 0 };

		// Set the default debug status to DBG_EXCEPTION_NOT_HANDLED
		// This will be passed to ContinueDebugEvent() if the event is not handled
		DWORD dwStatus = DBG_EXCEPTION_NOT_HANDLED;

		// Wait for a debug event from the target
		// We timeout every 100 ms to allow the loop a chance to check if
		if (WaitForDebugEvent(&pEvent, 100)) {

			// If WaitForDebugEvent() returns TRUE we have a debug event to process
			// Check if the event is CREATE_PROCESS_DEBUG_EVENT
			switch (pEvent.dwDebugEventCode) {
			case CREATE_PROCESS_DEBUG_EVENT:
				// Pass event to handler and return status
				dwStatus = handleEventCreateProcess(pEvent);
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				dwStatus = handleEventExitProcess(pEvent);
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				dwStatus = handleEventCreateThread(pEvent);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				dwStatus = handleEventExitThread(pEvent);
				break;
			case LOAD_DLL_DEBUG_EVENT:
				dwStatus = handleEventLoadDll(pEvent);
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				dwStatus = handleEventUnloadDll(pEvent);
				break;
			case EXCEPTION_DEBUG_EVENT:
				dwStatus = handleEventException(pEvent);
				break;
			default:
				dwStatus = DBG_CONTINUE;
				break;
			}
			// Continue to target process
			ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus);
		}

		if (_kbhit()) {
			int c = _getch();

			if (c == '\r') {
				break;
			}
		}
	}

	CloseHandle(hTargetProcess);
	CloseHandle(hTargetThread);

	printf("bien :u\n");
	return 0;
}