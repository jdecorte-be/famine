[BITS 64]

section .text

global _return_zero
_return_zero:
	xor 	rax, rax 
	ret