#include "Coff.h"

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
					// the symbol name is in Symbol String Table
				}
				else {
					std::cout << "    [+] Symbol " << tempCoffSymbol->first.name << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;
				}
			}

		}
	}

	return TRUE;
}