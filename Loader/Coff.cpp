#include "Coff.h"

// this header contains Beacon functions from CobaltStrike
#include "BeaconCompatibility.h"

#pragma region PrivateRegions
BOOL Coff::executeRelocation(
	FullCoff* fullCoff,
	CoffReloc* relocation,
	CoffSectionHeader* relocatedCoffSection,
	char* symbolName,
	CoffSymbol* coffSymbol,
	BOOL isInternal
)
{
	std::cout << "    [+] Relocating " << symbolName << std::endl;

	// resolve relocation of external functions
	uint64_t targetFunctionAddress = 0;

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
	}

	// 8 bytes long (64 bits)
	// absolute address relocation
	if (relocation->type == IMAGE_REL_AMD64_ADDR64) {
		std::cout << "    [+] IMAGE_REL_AMD64_ADDR64 reloc: " << symbolName << std::endl;

		// to be implemented

	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_ADDR32NB) { // IMAGE_REL_AMD64_ADDR32NB is used by variable assembly commands
		// FORMULA: relative_relocated_address = RVA of the actual symbol

		std::cout << "    [+] IMAGE_REL_AMD64_ADDR32NB reloc: " << symbolName << std::endl;

		if (coffSymbol->sectionNumber > 0) {
			// calculate absolute address in COFF object
			uint32_t absoluteAddress = (uint32_t)(fullCoff->coffRawBytes
				+ fullCoff->coffSectionHeaders[coffSymbol->sectionNumber - 1]->pointerToRawData
				+ coffSymbol->value);

			// compute relative address
			uint32_t rva = (uint32_t)(absoluteAddress - (uint32_t)fullCoff->coffRawBytes);

			memcpy((fullCoff->coffRawBytes + relocatedCoffSection->pointerToRawData + relocation->virtualAddress), // calculate the absolute address to the first byte that needs relocation
				&rva,              // RVA address to replace
				sizeof(uint32_t)); // copy 4 bytes
		}
		else {
			std::cout << "    [!] Could not resolve IMAGE_REL_AMD64_ADDR32NB symbol: " << symbolName << " - section number 0" << std::endl;
		}
	}
	// 4 bytes long (32 bits)
	// relative address relocation (relative to the RIP registry which will be at 4 bytes further from our symbol address)
	else if (relocation->type == IMAGE_REL_AMD64_REL32) { // IMAGE_REL_AMD64_REL32 is used by `call` and `jump`
		// FORMULA: relative_relocated_address = absolute_address - (relocation_point_address+4); symbol_address+4 is actually where RIP would be located

		std::cout << "    [+] IMAGE_REL_AMD64_REL32 reloc: " << symbolName << std::endl;

		// if the symbol is contained in another section, in the same object
		if (isInternal) {
			if (coffSymbol->sectionNumber > 0) {
				// calculate absolute address in COFF object
				uint64_t absoluteAddress = (uint64_t)(fullCoff->coffRawBytes // we use uint64_t because we are on 64 bits and addresses are uint64_t
					+ fullCoff->coffSectionHeaders[coffSymbol->sectionNumber - 1]->pointerToRawData
					+ coffSymbol->value);

				// calculate absolute address to to the relocation position
				uint64_t absoluteRelocationPosition = (uint64_t) (fullCoff->coffRawBytes + relocatedCoffSection->pointerToRawData + relocation->virtualAddress);
				// we use uint64_t because we are on 64 bits and addresses are uint64_t

				// calculate the relative address from relocation point address + 4 to the actual absolute position
				uint32_t relativePosition = absoluteAddress - (absoluteRelocationPosition + 4); // + 4 because the symbol address is 4 bytes long

				memcpy((void*)absoluteRelocationPosition,
					&relativePosition,
					sizeof(uint32_t));

			}
			else {
				std::cout << "    [!] Could not resolve IMAGE_REL_AMD64_REL32 symbol: " << symbolName << " - section number 0" << std::endl;
			}
		}
		else { // otherwise, the symbol is external, solved at runtime
			// simulate GOT (global offset table) for functions
			// this is done to keep the relative address under 32 bit data

			// this works because the compiler will eventually generate assembly code similat with `call PTR[RIP + displacement]`
			// so there is no direct call

			if (targetFunctionAddress == 0) {
				// suppose this is an internal function offered by Cobalt Strike exposed API
				std::cout << "    [!] Could not resolve IMAGE_REL_AMD64_REL32 symbol: " << symbolName << " - unable to resolve function, trying to resolve it internally with exposed API" << std::endl;

				char* symbolNameCopy = _strdup(symbolName);

				char* symbolNameCopyPtrCp = symbolNameCopy;

				// get symbol without `__imp_` if needed
				if (strncmp("__imp_", symbolNameCopy, 6) == 0)
					symbolNameCopyPtrCp = (char*)(symbolNameCopyPtrCp + 6);


				// iterate through internal functions to find our target function
				for (int i = 0; i < INTERNAL_FUNCTIONS_COUNT; i++) {
					// check if our stored symbol is equal to the exposed function
					if (strncmp(symbolNameCopyPtrCp,
						(const char*)InternalFunctions[i][0],
						min(strlen(symbolNameCopyPtrCp), strlen((const char*)InternalFunctions[i][0])))
						== 0) // this is a safe mechanism to not read out of bounds
						targetFunctionAddress = (uint64_t)InternalFunctions[i][1];
					break;
				}

				// cleanup
				free(symbolNameCopy);
			}

			if (targetFunctionAddress != 0) {

				// initially we will search for the address of target function, if it is present in the simulated GOT
				uint32_t foundIdx = 0;

				for (int i = 0; i < fullCoff->functionNumbered; i++) {
					if (fullCoff->functionsArray[i] == targetFunctionAddress) {
						foundIdx = i;
						break;
					}
				}

				// if we did not find it in simulated GOT
				if (foundIdx == 0) {
					// we will add it to the GOT
					fullCoff->functionsArray[fullCoff->functionNumbered] = targetFunctionAddress;
					foundIdx = fullCoff->functionNumbered;

					// increment function number in simulated GOT
					fullCoff->functionNumbered++;
				}

				// now `foundIdx` has the index of function to relocate

				// absolute address of target found function
				uint64_t absoluteAddress = (uint64_t)(fullCoff->functionsArray + foundIdx * sizeof(uint64_t));

				// calculate absolute address to to the relocation position
				uint64_t absoluteRelocationPosition = (uint64_t)(fullCoff->coffRawBytes + relocatedCoffSection->pointerToRawData + relocation->virtualAddress);

				// calculate the relative address from relocation point address + 4 to the actual absolute position
				uint32_t relativePosition = absoluteAddress - (absoluteRelocationPosition + 4); // + 4 because the symbol address is 4 bytes long

				// execute relocation using function stub from simulated GOT
				memcpy((void*)absoluteRelocationPosition,
					&relativePosition,
					sizeof(uint32_t));


			}
			else {
				std::cout << "    [!] Could not resolve IMAGE_REL_AMD64_REL32 symbol: " << symbolName << " - unable to resolve function" << std::endl;
			}
		}
	}

	std::cout << "    [+] Relocated symbol: " << symbolName << std::endl;


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

		std::cout << "[+] Found section: " << tempSectionHeader->name << std::endl;

		fullCoff->coffSectionHeaders[i] = tempSectionHeader;
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

					// execute function reloc
					executeRelocation(fullCoff, relocations[j], fullCoff->coffSectionHeaders[i], symbolNameTemp, tempCoffSymbol, FALSE);
				}
				else {
					std::cout << "[+] Symbol " << tempCoffSymbol->first.name << " in section " << fullCoff->coffSectionHeaders[i]->name << std::endl;
				
					// execute section reloc
					executeRelocation(fullCoff, relocations[j], fullCoff->coffSectionHeaders[i], tempCoffSymbol->first.name, tempCoffSymbol, TRUE);
				}
			}

		}
	}

	return TRUE;
}

BOOL Coff::executeCoffFunction(FullCoff* fullCoff, char* functionName, char* args, unsigned long argSize) {
	uint32_t textSectionIdx = -1;

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
		if(strncmp(tempSymbol->first.name, functionName, min(strlen(tempSymbol->first.name), strlen(functionName))) == 0){

			func = (void(*)(char* in, uint32_t datalen))(fullCoff->coffRawBytes + fullCoff->coffSectionHeaders[textSectionIdx]->pointerToRawData // go to the text section absolute address
				+ tempSymbol->value); // add symbol relative offset
		}
	}

	if (func) {
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