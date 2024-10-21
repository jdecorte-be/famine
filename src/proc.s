[BITS 64]

; [ PEB ]
; The Process Environment Block (PEB) is a data structure that Windows uses
; internally to manage the environment and resources of a process.
; https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb
; typedef struct _PEB {
;   BYTE                          Reserved1[2];
;   BYTE                          BeingDebugged;
;   BYTE                          Reserved2[1];
;   PVOID                         Reserved3[2];
;   PPEB_LDR_DATA                 Ldr;
;   PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
;   PVOID                         Reserved4[3];
;   PVOID                         AtlThunkSListPtr;
;   PVOID                         Reserved5;
;   ULONG                         Reserved6;
;   PVOID                         Reserved7;
;   ULONG                         Reserved8;
;   ULONG                         AtlThunkSListPtr32;
;   PVOID                         Reserved9[45];
;   BYTE                          Reserved10[96];
;   PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
;   BYTE                          Reserved11[128];
;   PVOID                         Reserved12[1];
;   ULONG                         SessionId;
; } PEB, *PPEB;



section .text
	global _get_kernel32_handle
	global _get_proc_address
	global _init_kernel32_address_table

_get_kernel32_handle:
; https://bowtiedcrawfish.substack.com/p/understanding-the-peb-and-teb
; https://dennisbabkin.com/blog/?t=how-to-implement-getprocaddress-in-shellcode
	xor rdi, rdi            ; RDI = 0x0
	mul rdi                 ; RAX&RDX =0x0
	mov rbx, gs:[rax+0x60]  ; RBX = Address_of_PEB
	mov rbx, [rbx+0x18]     ; RBX = Address_of_LDR
	mov rbx, [rbx+0x20]     ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
	mov rbx, [rbx]          ; RBX = 2nd entry in InitOrderModuleList / kernelbase.dll
	mov rbx, [rbx]          ; RBX = 3rd entry in InitOrderModuleList / kernel32.dll
	mov rbx, [rbx+0x20]     ; RBX = &kernel32.dll ( Base Address of kernel32.dll)
	mov r8, rbx             ; RBX & R8 = &kernel32.dll
	ret

_load_dll:
	;be868d9e8d9d96b3
	; 9b9e90b3
	

_init_kernel32_address_table:

	call _get_kernel32_handle ; r8 = 

	; Get kernel32.dll ExportTable Address
	mov ebx, [rbx+0x3C]     ; RBX = Offset NewEXEHeader
	add rbx, r8             ; RBX = &kernel32.dll + Offset NewEXEHeader = &NewEXEHeader
	xor rcx, rcx            ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
	add cx, 0x88ff
	shr rcx, 0x8            ; RCX = 0x88ff --> 0x88
	mov edx, [rbx+rcx]      ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
	add rdx, r8             ; RDX = &kernel32.dll + RVA ExportTable = &ExportTable

	; Get &AddressTable from Kernel32.dll ExportTable
	xor r10, r10
	mov r10d, [rdx+0x1C]    ; RDI = RVA AddressTable
	add r10, r8             ; R10 = &AddressTable

	; Get &NamePointerTable from Kernel32.dll ExportTable
	xor r11, r11
	mov r11d, [rdx+0x20]    ; R11 = [&ExportTable + Offset RVA Name PointerTable] = RVA NamePointerTable
	add r11, r8             ; R11 = &NamePointerTable (Memory Address of Kernel32.dll Export NamePointerTable)

	; Get &OrdinalTable from Kernel32.dll ExportTable
	xor r12, r12
	mov r12d, [rdx+0x24]    ; R12 = RVA  OrdinalTable
	add r12, r8             ; R12 = &OrdinalTable

	ret

_get_proc_address:
	pop rbx                 ; save the return address for ret 2 caller after API address is found
	pop rcx                 ; Get the string length counter from stack
	xor rax, rax            ; Setup Counter for resolving the API Address after finding the name string
	mov rdx, rsp            ; RDX = Address of API Name String to match on the Stack 
	push rcx                ; push the string length counter to stack
	loop:
		mov rcx, [rsp]          ; reset the string length counter from the stack
		xor rdi,rdi             ; Clear RDI for setting up string name retrieval
		mov edi, [r11+rax*4]    ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		add rdi, r8             ; RDI = &NameString    = RVA NameString + &kernel32.dll
		mov rsi, rdx            ; RSI = Address of API Name String to match on the Stack  (reset to start of string)
		repe cmpsb              ; Compare strings at RDI & RSI
		je resolveaddr          ; If match then we found the API string. Now we need to find the Address of the API 
		incloop:
			inc rax
			jmp short loop

	; Find the address of GetProcAddress by using the last value of the Counter
	resolveaddr:
		pop rcx                 ; remove string length counter from top of stack
		mov ax, [r12+rax*2]     ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of kernel32.<API>
		mov eax, [r10+rax*4]    ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
		add rax, r8             ; RAX = Kernel32.<API> = RVA kernel32.<API> + kernel32.dll BaseAddress
		push rbx                ; place the return address from the api string call back on the top of the stack
		ret                     ; return to API caller
































; ;Hashing section to resolve a function address	
; GetProcessAddress:		
; 	mov r13, rcx                     ;base address of dll loaded 
; 	mov eax, [r13d + 0x3c]           ;skip DOS header and go to PE header
; 	mov r14d, [r13d + eax + 0x88]    ;0x88 offset from the PE header is the export table. 

; 	add r14d, r13d                  ;make the export table an absolute base address and put it in r14d.
; 	mov r10d, [r14d + 0x18]         ;go into the export table and get the numberOfNames 
; 	mov ebx, [r14d + 0x20]          ;get the AddressOfNames offset. 
; 	add ebx, r13d                   ;AddressofNames base. 
	
; find_function_loop:	
; 	jecxz find_function_finished   ;if ecx is zero, quit :( nothing found. 
; 	dec r10d                       ;dec ECX by one for the loop until a match/none are found
; 	mov esi, [ebx + r10d * 4]      ;get a name to play with from the export table. 
; 	add esi, r13d                  ;esi is now the current name to search on. 
	
; find_hashes:
; 	xor edi, edi
; 	xor eax, eax
; 	cld			
	
; continue_hashing:	
; 	lodsb                         ;get into al from esi
; 	test al, al                   ;is the end of string resarched?
; 	jz compute_hash_finished
; 	ror dword edi, 0xd            ;ROR13 for hash calculation!
; 	add edi, eax		
; 	jmp continue_hashing
	
; compute_hash_finished:
; 	cmp edi, edx                  ;edx has the function hash
; 	jnz find_function_loop        ;didn't match, keep trying!
; 	mov ebx, [r14d + 0x24]        ;put the address of the ordinal table and put it in ebx. 
; 	add ebx, r13d                 ;absolute address
; 	xor ecx, ecx                  ;ensure ecx is 0'd. 
; 	mov cx, [ebx + 2 * r10d]      ;ordinal = 2 bytes. Get the current ordinal and put it in cx. ECX was our counter for which # we were in. 
; 	mov ebx, [r14d + 0x1c]        ;extract the address table offset
; 	add ebx, r13d                 ;put absolute address in EBX.
; 	mov eax, [ebx + 4 * ecx]      ;relative address
; 	add eax, r13d	
	
; find_function_finished:
; 	ret 
