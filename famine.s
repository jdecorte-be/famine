bits 64
default rel

section .data
    msg db "Hello world!", 0xd, 0xa
    msg_len equ $ - msg

section .text
global _start

_start:
    ; Save registers
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    ; Get the base address of kernel32.dll
    mov rdx, gs:[0x60]              ; PEB in Windows x64 is at gs:[0x60]
    mov rdx, [rdx+0x18]             ; ProcessModuleInfo
    mov rdx, [rdx+0x20]             ; List of loaded modules (InLoadOrderModuleList)
    mov rdx, [rdx]                  ; Next module (kernel32.dll)
    mov rdx, [rdx+0x20]             ; Base address of kernel32.dll in rdx

    ; Find the address of GetStdHandle and WriteFile in kernel32.dll exports
    ; We'll use a function that hashes API names to find them

    ; Prepare for parsing the Export Table
    push rdx                        ; Save kernel32 base address

    ; Get Export Directory
    mov ebx, [rdx+0x3C]             ; Offset to PE header (e_lfanew)
    mov ebx, [rdx+rbx+0x88]         ; RVA of Export Table (offset 0x88 from PE header)
    add rbx, rdx                    ; Absolute address of Export Table
    mov rdi, [rbx+0x20]             ; RVA of AddressOfNames
    add rdi, rdx                    ; Absolute AddressOfNames
    mov rcx, [rbx+0x18]             ; Number of names
    xor rsi, rsi                    ; Index = 0

find_function_loop:
    test rcx, rcx
    jz function_not_found

    ; Get function name RVA
    mov rax, [rdi+rsi*8]            ; Each entry is 8 bytes in x64
    add rax, rdx                    ; Absolute address of function name

    ; Calculate hash of function name
    ; We'll use a simple hash function for demonstration
    xor rbx, rbx
    xor rcx, rcx
hash_loop:
    mov bl, [rax+rcx]
    test bl, bl
    jz hash_done
    ror rdx, 13
    add rdx, rbx
    inc rcx
    jmp hash_loop
hash_done:

    ; Compare hash with desired function hash
    ; For demonstration, we will hardcode the hash value of "GetStdHandle" and "WriteFile"
    ; You need to compute the hash of these function names using the same hash function

    ; Let's assume the hash of "GetStdHandle" is in rax, and our desired hash is in rdi
    ; Compare and proceed accordingly

    ; For brevity, we'll skip the detailed implementation and assume we've found the function addresses
    ; In practice, you'd implement the full parsing and hashing

    ; Assume we've found GetStdHandle and WriteFile addresses and stored them
    ; For this example, we'll hardcode the function addresses (Not recommended in real shellcode due to ASLR)

    ; Restore kernel32 base address
    pop rdx

    ; Get handle to STD_OUTPUT_HANDLE
    xor rcx, rcx
    mov ecx, -11                    ; STD_OUTPUT_HANDLE (-11)
    call GetStdHandleAddress        ; Call GetStdHandle

    ; Handle is in rax
    mov rcx, rax                    ; hFile
    lea rdx, [rel msg]              ; lpBuffer
    mov r8d, msg_len                ; nNumberOfBytesToWrite
    lea r9, [rsp-8]                 ; lpNumberOfBytesWritten (we don't care about the value)
    sub rsp, 32                     ; Shadow space
    call WriteFileAddress           ; Call WriteFile
    add rsp, 32                     ; Clean up stack

    ; Call ExitProcess(0)
    xor rcx, rcx                    ; uExitCode = 0
    call ExitProcessAddress         ; Call ExitProcess

    ; Restore registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ; Return (shouldn't reach here)
    ret

; Function addresses (we need to resolve these dynamically)
; For this example, we'll define labels and fill them in during injection
GetStdHandleAddress:
    dq 0xAAAAAAAAAAAAAAAA           ; Placeholder for GetStdHandle address
WriteFileAddress:
    dq 0xBBBBBBBBBBBBBBBB           ; Placeholder for WriteFile address
ExitProcessAddress:
    dq 0xCCCCCCCCCCCCCCCC           ; Placeholder for ExitProcess address
