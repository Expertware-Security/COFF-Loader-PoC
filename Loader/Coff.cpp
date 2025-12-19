#include "Coff.h"

// this header contains Beacon functions from CobaltStrike
#include "BeaconCompatibility.h"

#pragma region PrivateRegions
BOOL executeRelocation(
	FullCoff* fullCoff,
	CoffReloc* relocation,
	int sectionNumber,
	CoffSymbol* coffSymbol,
	void* functionPtr,
	BOOL isInternal
)
{

	/*
	if (!isInternal){
		char* symbolNameCopy = _strdup(symbolName);

		char* buffer = NULL; // this should store library name and function name
		
		char* ctx = NULL;

		buffer = strtok_s(symbolNameCopy, "$", &ctx); // now buffer will have library name

		// retrieve library
		HMODULE library = NULL;

		// if the library name starts with `__imp_` it means it is external
		if(strncmp("__imp_", buffer, 6) == 0)
			library = LoadLibraryA((char*)(buffer+6));
		else
			library = LoadLibraryA(buffer);

		buffer = strtok_s(NULL, "$", &ctx); // now buffer will have function name

		// retrieve function address
		FARPROC functionAddress = GetProcAddress(library, buffer);

		targetFunctionAddress = (uint64_t)functionAddress;

		// cleanup
		free(symbolNameCopy);
	}*/

	// 8 bytes long (64 bits)
	// absolute address relocation
	if (relocation->type == IMAGE_REL_AMD64_ADDR64) {

		// to be implemented

	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_ADDR32NB) { // IMAGE_REL_AMD64_ADDR32NB is used by variable assembly commands
		// FORMULA: relative_relocated_address = RVA of the actual symbol


		if (coffSymbol->sectionNumber > 0) {

			// calculate initial offset
			uint32_t offsetAddr = 0;
			memcpy(&offsetAddr, (void*)((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), sizeof(uint32_t));

			offsetAddr = (uint32_t) (((char*)fullCoff->coffRawBytes + fullCoff->coffSectionHeaders[coffSymbol->sectionNumber - 1]->pointerToRawData + offsetAddr)
				- ((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress + 4));

			// add the Symbol offset
			offsetAddr += coffSymbol->value;

			memcpy(((char*)fullCoff->coffSections[sectionNumber] + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&offsetAddr,              // RVA address to replace
				sizeof(uint32_t)); // copy 4 bytes
		}
		else {
		}
	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_REL32) { // IMAGE_REL_AMD64_REL32 is used by `call` and `jump`
		// FORMULA: relative_relocated_address = absolute_address - (relocation_point_address+4); symbol_address+4 is actually where RIP would be located




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
	}

	fullCoff->coffRawBytes = coffFileBytes;

	// we will support only 1024 functions to relocate; it's a BOF so I think it should be enough
	fullCoff->functionsArray = (uint64_t*)malloc(1024 * sizeof(uint64_t));

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
					char* symbolNameTemp = (char*)(fullCoff->coffRawBytes + fullCoff->coffHeader->pointerToSymbolTable 
						+ fullCoff->coffHeader->numberOfSymbols * sizeof(CoffSymbol)) // table of symbols is in the end of the Symbols sections
																					  // so we will skip them all
						+ tempCoffSymbol->first.value[1]; // value[1] contains the offset in Table of Symbol Strings
					std::cout << "[+] Symbol " << symbolNameTemp << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;

					bool internalFunction = FALSE;

					void* funcPtr = NULL;

					if (strcmp(symbolNameTemp, "__imp_")) {
						symbolNameTemp = symbolNameTemp + 6;
					}

					// process function internal or external
					if (strcmp(symbolNameTemp, "Beacon") == 0 ||
						strcmp(symbolNameTemp, "GetProcAddress") == 0 ||
						strcmp(symbolNameTemp, "GetModuleHandleA") == 0 ||
						strcmp(symbolNameTemp, "toWideChar") == 0 ||
						strcmp(symbolNameTemp, "LoadLibraryA") == 0 ||
						strcmp(symbolNameTemp, "FreeLibrary") == 0) {

						internalFunction = TRUE;

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
						HMODULE libHandle = GetModuleHandleA(localLib);

						// get function string 
						char* localFunc = strtok_s(NULL, "$", &ctx);
						localFunc = strtok_s(localFunc, "@", &ctx);

						funcPtr = GetProcAddress(libHandle, localFunc);
					}

					// execute function reloc
					executeRelocation(fullCoff, relocations[j], i, tempCoffSymbol, funcPtr, internalFunction);
				}
				else {
					std::cout << "[+] Symbol " << tempCoffSymbol->first.name << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;
				
					// execute section reloc
					executeRelocation(fullCoff, relocations[j], i, tempCoffSymbol, NULL, FALSE);
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

		if (strncmp(tempSectionHeader->name, ".text", 5) == 0) {
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
		if(strncmp(tempSymbol->first.name, functionName, min(strlen(tempSymbol->first.name), strlen(functionName))) == 0 && tempSymbol->sectionNumber==textSectionIdx){

			func = (void(*)(char* in, uint32_t datalen))(fullCoff->coffRawBytes + fullCoff->coffSectionHeaders[textSectionIdx]->pointerToRawData // go to the text section absolute address
				+ tempSymbol->value); // add symbol relative offset
		}
	}

	if (func) {
		std::cout << "[+] Found function at address " << func << ". Press enter `go` and enter to execute." << std::endl;
		int temp = 0;
		std::cin >> temp;

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