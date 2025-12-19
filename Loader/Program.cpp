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

    // map coff in memory
    LPVOID fullCoffMapped = VirtualAlloc(NULL, coffReadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (fullCoffMapped == NULL) {
        std::cout << "[!] VirtualAlloc failed" << std::endl;
        return 0;
    }

    // copy COFF data in our buffer
    RtlCopyMemory(fullCoffMapped, coffData, coffReadSize);

    // parse COFF file
    FullCoff* fullCoff = Coff::parseCoffFile((BYTE*)fullCoffMapped, coffFileSize);

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

    free(fullCoff->functionsArray);

    for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {
        VirtualFree(fullCoff->coffSections[i], fullCoff->coffSectionHeaders[i]->sizeOfRawData, MEM_RELEASE);
        VirtualFree(fullCoff->coffSectionHeaders[i], sizeof(CoffSectionHeader), MEM_RELEASE);
    }

    free(fullCoff->coffSectionHeaders);
    free(fullCoff->coffSections);
    VirtualFree(fullCoff, coffReadSize, MEM_RELEASE);

    return 0;
}
