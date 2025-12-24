#include "Coff.h"

// this header contains Beacon functions from CobaltStrike
#include "BeaconCompatibility.h"

#pragma region PrivateRegions
BOOL Coff::executeRelocation(
	FullCoff* fullCoff,
	CoffReloc* relocation,
	int sectionNumber,
	CoffSymbol* coffSymbol,
	void* functionPtr
)
{

	// 8 bytes long (64 bits)
	// absolute address relocation
	if (relocation->type == IMAGE_REL_AMD64_ADDR64) {
		if (coffSymbol->sectionNumber > 0) {
			// this case is pretty straight forward, we need to calculate the absolute 64 bit address of the symbol and replace it
			uint64_t absoluteOffset = 0;

			// we will get the offset address of the symbol. stored at the target memory address
			memcpy(&absoluteOffset, (void*)((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), sizeof(uint32_t));

			// we will add the symbol source section offset to the absoluteOffset
			absoluteOffset = (uint64_t)((char*)fullCoff->coffSections[coffSymbol->sectionNumber - 1] + absoluteOffset) + (uint64_t)absoluteOffset;

			// finally, we will add the symbol offset
			absoluteOffset += coffSymbol->value;

			// and we will copy 64 bit address to it
			memcpy(((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&absoluteOffset,   // absolute address
				sizeof(uint64_t)); // copy 8 bytes
		}
		else {
			return FALSE;
		}
	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_ADDR32NB) { // IMAGE_REL_AMD64_ADDR32NB is used by variable assembly commands
		// FORMULA: relative_relocated_address = absolute_address - (relocation_point_address+4); relocation_point_address+4 is actually where RIP would be located


		if (coffSymbol->sectionNumber > 0) {

			// calculate initial offset
			uint32_t offsetAddr = 0;
			memcpy(&offsetAddr, (void*)((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), sizeof(uint32_t));

			offsetAddr = (uint32_t) (((char*)fullCoff->coffSections[coffSymbol->sectionNumber - 1] + offsetAddr)
				- ((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress + 4));

			// add the Symbol offset
			offsetAddr += coffSymbol->value;

			memcpy(((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&offsetAddr,              // RVA address to replace
				sizeof(uint32_t)); // copy 4 bytes
		}
		else {
			return FALSE;
		}
	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_REL32) { // IMAGE_REL_AMD64_REL32 is used by `call` and `jump`
		// FORMULA: relative_relocated_address = absolute_address - (relocation_point_address+4); symbol_address+4 is actually where RIP would be located


		if (functionPtr != NULL) {
			// this case covers external and internal function references
			// we have to simulate GOT in `fullCoff->functionsArray`
			
			// we will use size of uint64_t to establish compatibility with x64 systems
			memcpy(((char*)fullCoff->functionsArray + fullCoff->functionNumbered * sizeof(uint64_t)), &functionPtr, sizeof(uint64_t));

			uint32_t offsetAddr = 0;

			offsetAddr = (uint32_t)(((char*)fullCoff->functionsArray + fullCoff->functionNumbered * sizeof(uint64_t))
				- ((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress + 4));

			// add the Symbol offset, which in this case will always be 0
			offsetAddr += coffSymbol->value;

			memcpy(((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&offsetAddr,              // RVA address to replace
				sizeof(uint32_t)); // copy 4 bytes

			fullCoff->functionNumbered++;

		}
		else {
			// this case covers a symbol relocated from another section

			uint32_t offsetAddr = 0;
			memcpy(&offsetAddr, (void*)((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), sizeof(uint32_t));

			offsetAddr = (((char*)fullCoff->coffSections[coffSymbol->sectionNumber - 1] + offsetAddr)
				- ((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress + 4));

			// add the Symbol offset
			offsetAddr += coffSymbol->value;

			memcpy(((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&offsetAddr,              // RVA address to replace
				sizeof(uint32_t)); // copy 4 bytes
		}

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
	// allocate data to store sections mapped in memory (only pointers here)
	fullCoff->coffSections = (void**)malloc(sizeof(void*) * fullCoff->coffHeader->numberOfSections);

	int realSectionNumbers = 0;

	// write source buffer to object
	fullCoff->coffRawBytes = coffFileBytes;

	// init relocation count to 0
	fullCoff->relocationCount = 0;


	// iterate through all sections and map them in memory
	for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {
		// POINTER_TO_COFF + HEADER + SECTION_SIZE * ITERATION_NUMBER

		CoffSectionHeader* tempSectionHeader = (CoffSectionHeader*)(coffFileBytes + sizeof(CoffHeader) + i * sizeof(CoffSectionHeader));

		void* tempSection = VirtualAlloc(NULL, tempSectionHeader->sizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

		// if the pointer to section has been set, map it in memory
		if (tempSectionHeader->pointerToRawData != 0) {
			memcpy(tempSection, fullCoff->coffRawBytes + tempSectionHeader->pointerToRawData, tempSectionHeader->sizeOfRawData);
		}
		else {
			// otherwise set all bytes to 0 (we will probably ignore it
			memset(tempSection, 0, tempSectionHeader->sizeOfRawData);
		}

		std::cout << "[+] Found section: " << tempSectionHeader->name << std::endl;

		fullCoff->coffSectionHeaders[i] = tempSectionHeader;
		fullCoff->coffSections[i] = tempSection;

		// count section relocations:
		fullCoff->relocationCount += fullCoff->coffSectionHeaders[i]->numberOfRelocations;
	}

	// we will support relocations of functions for all relocations defined
	fullCoff->functionsArray = (uint64_t*)VirtualAlloc(NULL, fullCoff->relocationCount * sizeof(uint64_t), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

	// number of functions will be initialized with 0
	fullCoff->functionNumbered = 0;

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
					char* symbolNameOriginal = (char*)(fullCoff->coffRawBytes + fullCoff->coffHeader->pointerToSymbolTable 
						+ fullCoff->coffHeader->numberOfSymbols * sizeof(CoffSymbol)) // table of symbols is in the end of the Symbols sections
																					  // so we will skip them all
						+ tempCoffSymbol->first.value[1]; // value[1] contains the offset in Table of Symbol Strings

					// we have to copy it to not modify the memory itself, otherwise, when solving a function, we will also change memory with strtok_s
					char* symbolNameTemp = _strdup(symbolNameOriginal);

					std::cout << "[+] Symbol " << symbolNameTemp << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;


					void* funcPtr = NULL;

					if (strncmp(symbolNameTemp, "__imp_", 6) == 0) {
						symbolNameTemp = symbolNameTemp + 6;
					}

					// process function internal or external
					if (strncmp(symbolNameTemp, "Beacon", min(strlen(symbolNameTemp), strlen("Beacon"))) == 0 ||
						strncmp(symbolNameTemp, "GetProcAddress", min(strlen(symbolNameTemp), strlen("GetProcAddress"))) == 0 ||
						strncmp(symbolNameTemp, "GetModuleHandleA", min(strlen(symbolNameTemp), strlen("GetModuleHandleA"))) == 0 ||
						strncmp(symbolNameTemp, "toWideChar", min(strlen(symbolNameTemp), strlen("toWideChar"))) == 0 ||
						strncmp(symbolNameTemp, "LoadLibraryA", min(strlen(symbolNameTemp), strlen("LoadLibraryA"))) == 0 ||
						strncmp(symbolNameTemp, "FreeLibrary", min(strlen(symbolNameTemp), strlen("FreeLibrary"))) == 0) {

						for (int k = 0; k < 30; k++) {
							// function found in internal functions array
							if (strcmp((const char*)InternalFunctions[k][0], symbolNameTemp) == 0) {
								funcPtr = (void*)InternalFunctions[k][1];
								break;
							}
						}
					}
					else {
						// we will assume a format of LIB$Function
						char* ctx = NULL;
						// get module string
						char* localLib = strtok_s(symbolNameTemp, "$", &ctx);

						// load a library and map it to memory
						HMODULE libHandle = LoadLibraryA(localLib);

						// get function string 
						char* localFunc = strtok_s(NULL, "$", &ctx);
						localFunc = strtok_s(localFunc, "@", &ctx);

						funcPtr = GetProcAddress(libHandle, localFunc);
					}

					// execute function reloc
					executeRelocation(fullCoff, relocations[j], i, tempCoffSymbol, funcPtr);
				}
				else {
					std::cout << "[+] Symbol " << tempCoffSymbol->first.name << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;
				
					// execute section reloc
					executeRelocation(fullCoff, relocations[j], i, tempCoffSymbol, NULL);
				}
			}

		}
	}

	return TRUE;
}

BOOL Coff::executeCoffFunction(FullCoff* fullCoff, char* functionName, char* args, unsigned long argSize) {
	int textSectionIdx = -1;

	// first we will get the .text section to search for target function symbol
	for (int i = 0; i < fullCoff->coffHeader->numberOfSections; i++) {

		// get the section header
		CoffSectionHeader* tempSectionHeader = (CoffSectionHeader*)(fullCoff->coffRawBytes + sizeof(CoffHeader) + i * sizeof(CoffSectionHeader));

		if (strcmp(tempSectionHeader->name, ".text") == 0) {
			textSectionIdx = i;
			break;
		}
	}

	// fallback case if test section is not found
	if (textSectionIdx == -1) {
		std::cout << "[!] Unable to find `.text` section." << std::endl;
		return FALSE;
	}

	// define function variable
	VOID(*func)(char* in, uint32_t datalen) = NULL;

	// iterate all symbols
	for (int i = 0; i < fullCoff->coffHeader->numberOfSymbols; i++) {
		CoffSymbol* tempSymbol = (CoffSymbol*)(fullCoff->coffRawBytes + fullCoff->coffHeader->pointerToSymbolTable // get to the symbol table absolute address
			+ i * sizeof(CoffSymbol));

		// if the symbol name is equal with the function we are looking for
		if(strcmp(tempSymbol->first.name, functionName) == 0 && (tempSymbol->sectionNumber-1)==textSectionIdx){

			func = (void(*)(char* in, uint32_t datalen))((char*)fullCoff->coffSections[textSectionIdx] // go to the text section absolute address
				+ tempSymbol->value); // add symbol relative offset

			break;
		}
	}

	if (func) {
		std::cout << "[+] Found function at address " << func << "." << std::endl;

		func((char*)args, argSize);
		std::cout << "[+] Executed BOF function " << functionName << std::endl;
	}
	else {
		std::cout << "[!] Unable to execute function " << functionName << std::endl;
		return FALSE;
	}

	return TRUE;

}
#pragma endregion