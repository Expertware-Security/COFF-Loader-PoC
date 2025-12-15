#include "Coff.h"

#pragma region PrivateRegions
BOOL executeRelocation(FullCoff* fullCoff, CoffReloc* relocation, CoffSectionHeader* relocatedCoffSection, char* symbolName, BOOL isSection)
{
	std::cout << "[+] Relocating " << symbolName << std::endl;

	// resolve relocation
	uint32_t targetAddress = NULL;

	if (isSection) {
		// we will calculate the relative offset to the target section
		for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {
			if (strcmp(fullCoff->coffSectionHeaders[i]->name, symbolName) == 0) { // check if the section name is the one we are looking for
				targetAddress = fullCoff->coffSectionHeaders[i]->pointerToRawData;
				break;
			}
		}
	}
	else {
		char* buffer = NULL; // this should store library name and function name
		
		char* ctx = NULL;

		buffer = strtok_s(symbolName, "$", &ctx); // now buffer will have library name

		// retrieve library
		HMODULE library = NULL;

		// if the library name starts with `__imp_` (some have this name, dunno why :))
		if(strncmp("__imp_", buffer, 6) == 0)
			library = LoadLibraryA((char*)(buffer+6));
		else
			library = LoadLibraryA(buffer);

		buffer = strtok_s(NULL, "$", &ctx); // now buffer will have function name

		// retrieve function address
		FARPROC functionAddress = GetProcAddress(library, buffer);

		// no cleanup needed for shitty STL functions
	}

	if (targetAddress == NULL) {
		std::cout << "[!] Could not perform relocation for " << symbolName << std::endl;
		return FALSE;
	}

	if (relocation->type == IMAGE_REL_AMD64_REL32) {
		
	}

	return TRUE;
}
#pragma endregion

#pragma region PublicFunctions
FullCoff* Coff::parseCoffFile(BYTE* coffFileBytes, DWORD coffSize) {
	FullCoff* fullCoff = (FullCoff*)malloc(sizeof(FullCoff));

	fullCoff->coffHeader = ((CoffHeader*)coffFileBytes);

	// allocate memory for sections
	// we will allocate memory to store the pointers, no need to map this in memory
	fullCoff->coffSectionHeaders = ((CoffSectionHeader**)malloc(sizeof(CoffSectionHeader*) * fullCoff->coffHeader->numberOfSections));

	int realSectionNumbers = 0;

	// iterate through all sections and map them in memory
	for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {
		// POINTER_TO_COFF + HEADER + SECTION_SIZE * ITERATION_NUMBER
		CoffSectionHeader* tempSectionHeader = (CoffSectionHeader*)(coffFileBytes + sizeof(CoffHeader) + i * sizeof(CoffSectionHeader));

		// avoid false sections
		if (tempSectionHeader->name[0] != '.')
			continue;

		std::cout << "[+] Found section: " << tempSectionHeader->name << std::endl;

		fullCoff->coffSectionHeaders[i] = tempSectionHeader;
		realSectionNumbers++;
	}

	// write real number of sections
	fullCoff->coffHeader->numberOfSections = realSectionNumbers;

	fullCoff->coffRawBytes = coffFileBytes;

	return fullCoff;
}

BOOL Coff::parseRelocations(FullCoff* fullCoff) {
	// check all sections for relocations
	for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {

		// if we have relocations
		if (fullCoff->coffSectionHeaders[i]->numberOfRelocations > 0) {
			std::cout << "[+] Found " << fullCoff->coffSectionHeaders[i]->numberOfRelocations << " relocations in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;

			CoffReloc** relocations = (CoffReloc**)malloc(sizeof(CoffReloc*) * fullCoff->coffSectionHeaders[i]->numberOfRelocations);

			for (int j = 0; j < fullCoff->coffSectionHeaders[i]->numberOfRelocations; j++) {
				relocations[j] = (CoffReloc*) (fullCoff->coffRawBytes + fullCoff->coffSectionHeaders[i]->pointerToRelocations + j * sizeof(CoffReloc));

				// retrieve temporary symbol struct
				CoffSymbol* tempCoffSymbol = (CoffSymbol*)(fullCoff->coffRawBytes + fullCoff->coffHeader->pointerToSymbolTable + relocations[j]->symbolTableIndex * sizeof(CoffSymbol));

				if (tempCoffSymbol->first.name[0] == 0) {
					// the symbol offset is found in value[1] (because value[0] contains '\0' which is the end str of the name - we have union, not struct)
					char* symbolNameTemp = (char*)(fullCoff->coffRawBytes + fullCoff->coffHeader->pointerToSymbolTable 
						+ fullCoff->coffHeader->numberOfSymbols * sizeof(CoffSymbol)) // table of symbols is in the end of the Symbols sections
																					  // so we will skip them all
						+ tempCoffSymbol->first.value[1]; // value[1] contains the offset in Table of Symbol Strings
					std::cout << "    [+] Symbol " << symbolNameTemp << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;

					// execute function reloc
					executeRelocation(fullCoff, relocations[j], fullCoff->coffSectionHeaders[i], symbolNameTemp, FALSE);
				}
				else {
					std::cout << "    [+] Symbol " << tempCoffSymbol->first.name << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;
				
					// execute section reloc
					executeRelocation(fullCoff, relocations[j], fullCoff->coffSectionHeaders[i], tempCoffSymbol->first.name, TRUE);
				}
			}

		}
	}

	return TRUE;
}
#pragma endregion