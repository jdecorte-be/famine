[BITS 64]

; [ Famine entrypoint ]
; This is the entrypoint of famine.
; - We save the entrypoint of famine
; - We get kernel32.dll base address
; - We resolve the addresses of the functions we need from kernel32.dll


section .data
    hello db 'Hello, World!', 0  
    helloLen equ $ - hello        


section .text
	global start

	extern _get_proc_address
	extern GetStdHandle
	extern WriteConsoleA
	extern ExitProcess

start:
    mov rcx, 0xFD8452C6
    call _get_proc_address
    mov r10, rax

    xor rax, rax
    sub rsp, 28h               
    mov rcx, -11
    call r10

    ; Escribir el mensaje en la consola
    mov r9, 0                
    mov r8, helloLen          
    mov rdx, hello            
    mov rcx, rax               
    call WriteConsoleA        

    ; Terminar el programa
    mov rcx, 0                 
    call ExitProcess   

	; mov rcx, 0xB207C0C3
	; call _get_proc_address
	; ret


