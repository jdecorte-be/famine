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
	global .find_function_loop
	global .done
	global .next_module
	global _find_hash
	global .ror13_hash_dll
	global .function_found
	global .loop_function


; PARAMETERS
; rcx = function + dll hash
; =======
; return address of the function
_get_proc_address:
	mov rdi, rcx
    ; Access PEB
    xor rax, rax
    mov rax, gs:[0x60]              ; RAX = Address_of_PEB
    mov rax, [rax + 0x18]           ; RAX = Address_of_LDR
	mov r10, [rax + 0x10]			; RBX = First entry in InLoadOrderModuleList (PEB_LDR_DATA->InLoadOrderModuleList)

    .find_function_loop:
		; get pModuleBase -> r14
		mov r14, [r10 + 0x30]

		; typedef struct _IMAGE_NT_HEADERS {
		; 	DWORD                   Signature;  // 0x4
		; 	IMAGE_FILE_HEADER       FileHeader;
		; 	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
		; } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32; // 0x18
		; get dwExportDirRVA -> r15d
		mov r15d, [r14 + 0x3c] ; edx = e_lfanew
		add r15, r14 ; r15 = ntheader
		add r15, 0x18 ; r15
		add r15, 0x70
		mov r15d, [r15]
		and r15d, 0x0FFFFFFF
		
		test r15d, r15d
		jz .next_module

		; get pExportDir -> r15
		add r15, r14

		; typedef struct _UNICODE_STRING {
		; USHORT Length;				; 2 bytes
		; USHORT MaximumLength; 		; 2 bytes
		; PWSTR  Buffer;				; 8 bytes
		; } UNICODE_STRING, *PUNICODE_STRING;
		; dllBase + 0x58 = LDR_DATA_TABLE_ENTRY->BaseDllName
		mov rcx, [r10 + 0x58 + 0x8] ; rcx = BaseDllName.MaximumLength
		movzx rdx, word [r10 + 0x58 + 0x2] ; rdx = address of BaseDllName.Buffer
		call .ror13_hash_dll ; rax = hash of dll
		mov r11, rax

		; public struct IMAGE_EXPORT_DIRECTORY
		; {
		;     public UInt32 Characteristics;
		;     public UInt32 TimeDateStamp;
		;     public UInt16 MajorVersion;
		;     public UInt16 MinorVersion;
		;     public UInt32 Name;
		;     public UInt32 Base;
		;     public UInt32 NumberOfFunctions;
		;     public UInt32 NumberOfNames;
		;     public UInt32 AddressOfFunctions;     // RVA from base of image
		;     public UInt32 AddressOfNames;     // RVA from base of image
		;     public UInt32 AddressOfNameOrdinals;  // RVA from base of image
		; }
		mov ecx, [r15 + 0x18] ; rcx = pExportTable->NumberOfNames

		xor rdx, rdx
		mov edx, [r15 + 0x20] ; rax = pExportTable->AddressOfNames
		add rdx, r14 ; rdx = pdwFunctionNameBase

		; NEED
		; dwNumFunctions -> rcx 
		; pdwFunctionNameBase -> rdx
		; i -> rsi
		; rdi -> arg1
		; r8 -> pFunctionName
		; r9
		xor r13, r13
		xor r8, r8
		.loop_function:
			mov r8d, [rdx]
			add r8, r14
			add rdx, 4

			push r9
			push r8
			push rcx
			mov rcx, r8
			call .ror13_hash_fun
			; add rdx, r8 ; add len of fun name 
			pop rcx
			pop r8
			pop r9
			
			add rax, r11
			cmp edi, eax
			jnz .next_function

			; Function found
			jmp .function_found

			.next_function:
			inc r13
			cmp rcx, r13
			jnz .loop_function

		.next_module:
        mov r10, [r10]             ; Get next flink

		test r14, r14                ; If DllBase is NULL, we're done
        jnz .find_function_loop

		xor rax, rax ; Return NULL
		ret

	.function_found:
		xor rax, rax
		xor rcx, rcx
		xor rdx, rdx

		mov eax, [r15 + 0x24] ; pExportTable->AddressOfNameOrdinals
		add rax, r14

		mov dx, [rax + 2 * r13]


; (HMODULE) ((ULONG_PTR) pModuleBase + *(PDWORD)(pModuleBase + pExportDir->AddressOfFunctions + 4 * usOrdinalTableIndex));
		mov ecx, [r15 + 0x1C]
		add rcx, r14
		mov ecx, [rcx + 4 * rdx]
		and rcx, 0x0FFFFFFF

		xor rax, rax
		add rax, r14
		add rax, rcx





		; mov r12d, [r15 + 0x1C] ; pExportTable->AddressOfFunctions
		; mov eax, [r15 + 0x24] ; pExportTable->AddressOfNameOrdinals

		; add rax, rdx ; rax = DllBase + pExportTable->AddressOfNameOrdinals | RVA
		; movzx rax, word [rax + 2 * r8] 
		
		; ; rax * 4
		; mov rcx, 4
		; imul rax, rcx

		; add rax, r12
		; add rax, rdx

		; mov ecx, [rax]
		; mov rax, rcx
		; add rax, rdx

		ret


	; PARAMETERS
	; rcx = string
	; rdx = string length
	; =======
	; r8 = counter
	; r9 = dwModuleHash
	; =======
	; return hash of dll∂
	.ror13_hash_dll:
		xor r8, r8
		xor r9, r9
		.loop_hash_dll:
			mov al, byte [rcx + r8]	; al = BaseDllName.Buffer[rcx]

			; to upper character
			cmp al, 0x61 ; compare with 'a'
			jl .skip_upper
			sub al, 0x20 ; al = al - 32 / to upper
			.skip_upper:

			ror r9d, 13 ; rdx = rdx >> 13
			movzx rax, al ; rax = al
			add r9, rax ; rdx = rdx + rax


			inc r8
			cmp r8, rdx
			jnz .loop_hash_dll
		mov rax, r9
		ret

	; PARAMETERS
	; rcx = string
	; =======
	; r8 = counter
	; r9 = dwModuleHash
	; =======
	; return hash of dll∂
	.ror13_hash_fun:
		xor r8, r8
		xor r9, r9
		.loop_hash_fun:
			mov al, byte [rcx + r8]	; al = BaseDllName.Buffer[rcx]

			ror r9d, 13 ; rdx = rdx >> 13
			movzx rax, al ; rax = al
			add r9, rax ; rdx = rdx + rax

			inc r8
			cmp al, 0
			jnz .loop_hash_fun
		mov rax, r9
		ret


