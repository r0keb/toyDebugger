#pragma once
#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp")

BOOL PrintStackFrame(HANDLE hProcess, HANDLE hThread, CONTEXT ctx);
DWORD handleEventException(DEBUG_EVENT pEvent);

DWORD handleEventLoadDll(DEBUG_EVENT pEvent);
DWORD handleEventUnloadDll(DEBUG_EVENT pEvent);
DWORD handleEventCreateThread(DEBUG_EVENT pEvent);
DWORD handleEventExitThread(DEBUG_EVENT pEvent);
DWORD handleEventCreateProcess(DEBUG_EVENT pEvent);
DWORD handleEventExitProcess(DEBUG_EVENT pEvent);