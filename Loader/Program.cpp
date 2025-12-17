#include <Windows.h>
#include <iostream>
#include "Coff.h"

// used for Cobalt Strike compatibility
#include "BeaconCompatibility.h"

int main()
{
    int bofOutdataSize = 0;
    char* bofOutdata = NULL;

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

    // modify memory protections to allow read, write, execute on the sections
    DWORD oldProtect = 0;
    if (VirtualProtect(coffData, coffReadSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        std::cout << "[!] `VirtualProtect` failed to allow eecute on memory." << std::endl;
        return 0;
    }

    // parse COFF file
    FullCoff* fullCoff = Coff::parseCoffFile(coffData, coffFileSize);

    if (!Coff::parseRelocations(fullCoff)) {
        std::cout << "[!] Something went wrong parsing relocations" << std::endl;
        goto cleanup;
    }

    if (!Coff::executeCoffFunction(fullCoff, (char*)"go", NULL, 0)) {
        goto cleanup;
    }

    // get outpput from BOF (Cobalt Strike style)
    bofOutdata = BeaconGetOutputData(&bofOutdataSize);
    if (bofOutdata != NULL) {
        std::cout << "[+] Retrieved BOF output:" << std::endl;
        std::cout << bofOutdata << std::endl;
    }
    else {
        std::cout << "[!] Error retrieving BOF output." << std::endl;
    }

    // cleanup
cleanup:
    free(fullCoff->coffSectionHeaders);
    free(fullCoff);

    return 0;
}
