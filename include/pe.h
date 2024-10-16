#ifndef PE_H
#define PE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "winntdef.h"

#define IMAGE_DOS_SIGNATURE 0x5A4D    // MZ
#define IMAGE_NT_SIGNATURE 0x00004550 // PE00

#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

#define IMAGE_SCN_CNT_CODE 0x00000020

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif

#ifndef IMAGE_SCN_MEM_READ
#define IMAGE_SCN_MEM_READ 0x40000000
#endif

#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000
#endif

#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#endif

#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#endif

typedef struct _IMAGE_DOS_HEADER
{
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    int32_t e_lfanew;    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER
{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct s_pe
{
    FILE *file;
    IMAGE_DOS_HEADER *dos_header;
    IMAGE_NT_HEADERS *nt_headers;
    IMAGE_SECTION_HEADER *sect_headers;
} t_pe;

#endif // PE_H