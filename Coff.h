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
    uint32_t    value;
    uint16_t    sectionNumber;
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
};

class Coff
{
public:
    static FullCoff* parseCoffFile(BYTE* coffFileBytes, DWORD coffSize);
    static BOOL parseRelocations(FullCoff* fullCoff);

private:
    //static BOOL executeRelocation(FullCoff* fullCoff, CoffReloc* relocation, char* symbolName, BOOL isSection);
};

