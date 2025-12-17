#include <iostream>
#include <Windows.h>
#include <cstdint>

#pragma once

//// COFF Format:
// Header
// ---------- (Section Headers)
// Section Header 1
// Section Header 2
// .
// .
// .
// Section Header N
// ---------- (Relocation Table)
// Relocation 1
// Relocation 2
// .
// .
// .
// Relocation N
// ---------- (Symbols Table)
// Symbol 1
// Symbol 2
// .
// .
// .
// Symbol N
// ---------- (Symbols Table String)
// String 1
// String 2
// .
// .
// .
// String N
//
////

// this will start from offset 0
struct CoffHeader {
	uint16_t machine;
	uint16_t numberOfSections;
	uint32_t timeDateStamp;
	uint32_t pointerToSymbolTable; // absolute address to Symbol Table
	uint32_t numberOfSymbols;
	uint16_t sizeOfOptionalHeader; // always 0 in case of COFF object
	uint16_t characteristics;
};

// this header stores info about each section
struct CoffSectionHeader {
    char        name[8];
    uint32_t    virtualSize;    // always 0 in COFF
    uint32_t    virtualAddress; // always 0 in COFF
    uint32_t    sizeOfRawData;
    uint32_t    pointerToRawData; // absolute address to the section bytes
    uint32_t    pointerToRelocations; // absolute address to the relocation bytes
    uint32_t    pointerToLinenumber;
    uint16_t    numberOfRelocations;
    uint16_t    numberOfLinenumber;
    uint32_t    characteristics;
};

__pragma(pack(push, 2)) // we need this pragma to align the structure; otherwise, the size of structure will be 12 bytes, which is incorrect
struct CoffSymbol {
    union { // union means either name or value
        char     name[8];  // if name length is greater than 8 characters,
        uint32_t value[2]; // value will contain the offset in Symbol String Table
    } first;
    // `value` will contain the relative value of the symbol, according to the section where the symbol is defined
    // it may be 0 if the `sectionNumber` is 0
    uint32_t    value;
    uint16_t    sectionNumber; // defines in which section is the symbol defined (if the symbol is external, then the section refers to the other COFF object)
    // `sectionNumber` starts indexing at 1 (strange)
    
    uint16_t    type;
    uint8_t     storageClass;
    uint8_t     numberOfAuxSymbols;
};
__pragma(pack(pop))

__pragma(pack(push, 2)) // we need this pragma to align the structure; otherwise, the size of structure will be 12 bytes, which is incorrect
struct CoffReloc {
    uint32_t    virtualAddress;   // relative address from the start section to the first byte that needs relocation
    uint32_t    symbolTableIndex; // idx where symbol can be found in Symbols Table 
    uint16_t    type;
};
__pragma(pack(pop))

// entire Coff object
struct FullCoff {
    BYTE* coffRawBytes;
    CoffHeader* coffHeader;
    CoffSectionHeader** coffSectionHeaders;

    // this will simulate a GOT implementation ;
    // it will store the pointers to the functions that are needed to operate,
    // so that the relative address written in `IMAGE_REL_AMD64_REL32` will have only 32 bits
    uint64_t* functionsArray;
    uint32_t functionNumbered = 0;
};

class Coff
{
public:
    static FullCoff* parseCoffFile(BYTE* coffFileBytes, DWORD coffSize);
    static BOOL parseRelocations(FullCoff* fullCoff);
    static BOOL executeCoffFunction(FullCoff* fullCoff, char* functionName, char* args, unsigned long argSize);

private:
    static BOOL executeRelocation(
    FullCoff* fullCoff,
        CoffReloc* relocation,
        CoffSectionHeader* relocatedCoffSection,
        char* symbolName,
        CoffSymbol* coffSymbol,
        BOOL isInternal
    );
};

