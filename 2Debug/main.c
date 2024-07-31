#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile;
    DWORD bytesWritten;
    BOOL bErrorFlag;
    const char data[] = "Hello, world!";
    DWORD dataSize = strlen(data);

    hFile = CreateFileA("output.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    bErrorFlag = WriteFile(hFile, data, dataSize, &bytesWritten, NULL);

    if (bErrorFlag == FALSE) {
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    return 0;
}
