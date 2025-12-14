#include <Windows.h>
#include <iostream>
#include "Coff.h"

int main()
{
    wchar_t objectFilePath[MAX_PATH] = L"C:\\Users\\Administrator\\Documents\\BOF-Samples\\SA\\whoami\\whoami.x64.o";

    // read file bytes
    HANDLE coffHandle = CreateFile(objectFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (coffHandle == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Could not open COFF file" << std::endl;
        return 0;
    }

    DWORD coffFileSize = 0, coffReadSize = 0;
    coffFileSize = GetFileSize(coffHandle, NULL);

    BYTE* coffData = (BYTE*)malloc(coffFileSize);
    if(!ReadFile(coffHandle, coffData, coffFileSize, &coffReadSize, NULL)) {
        std::cout << "[!] Could not read COFF file" << std::endl;
        return 0;
    }

    if (coffFileSize != coffReadSize) {
        std::cout << "[!] Something went wrong reading COFF file" << std::endl;
        return 0;
    }
    
    CloseHandle(coffHandle);

    // parse COFF file
    FullCoff* fullCoff = Coff::parseCoffFile(coffData, coffFileSize);

    if (!Coff::parseRelocations(fullCoff)) {
        std::cout << "[!] Something went wrong parsing relocations" << std::endl;
        goto cleanup;
    }

    // cleanup
cleanup:
    free(fullCoff->coffSectionHeaders);
    free(fullCoff);

    return 0;
}
