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
	mov rcx, [rax + 0x10]			; RBX = First entry in InLoadOrderModuleList (PEB_LDR_DATA->InLoadOrderModuleList)

    .find_function_loop:
        ; Get _LDR_DATA_TABLE_ENTRY
        mov r9, rbx                 ; r9 = _LDR_DATA_TABLE_ENTRY

		; typedef struct _UNICODE_STRING {
		; USHORT Length;				; 2 bytes
		; USHORT MaximumLength; 		; 2 bytes
		; PWSTR  Buffer;				; 8 bytes
		; } UNICODE_STRING, *PUNICODE_STRING;
		add r9, 0x58               ; r9 = LDR_DATA_TABLE_ENTRY->BaseDllName
		movzx r10, word [r9 + 0x2] ; r10 = BaseDllName.MaximumLength
		mov r11, [r9 + 0x8]			; r11 = address of BaseDllName.Buffer

		mov rcx, r11
		mov rdx, r10
		call .ror13_hash_dll ; rax = hash of dll
		mov r11, rax

		mov r9, [rbx + 0x30] ; r9 = DllBase
		mov edx, [r9 + 0x3c] ; edx = e_lfanew

		; typedef struct _IMAGE_NT_HEADERS {
		; 	DWORD                   Signature;  // 0x4
		; 	IMAGE_FILE_HEADER       FileHeader;
		; 	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
		; } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32; // 0x18
		add r9, rdx; r9 = NT Header
		add r9, 0x18 ; r9 + 0x18 = OptionalHeader

		; typedef struct _IMAGE_DATA_DIRECTORY {
		; DWORD VirtualAddress;
		; DWORD Size;
		; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
		add r9, 0x70 ; r9 = IMAGE_DATA_DIRECTORY
		xor rdx, rdx
		mov edx, [r9] ; edx = IMAGE_DATA_DIRECTORY.VirtualAddress / dwExportDirRVA
		test edx, edx
		jz .next_module		; if dwExportDirRVA == 0, no export directory

		mov r9, [rbx + 0x30] ; r9 = DllBase
		add r9, rdx ; r9 = DllBase + IMAGE_DATA_DIRECTORY.VirtualAddress / pExportTable

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
		mov ecx, [r9 + 0x18] ; rcx = pExportTable->NumberOfNames
		mov eax, [r9 + 0x20] ; rax = pExportTable->AddressOfNames
		mov r13, r9
		sub r9, rdx ; r9 = DLLBase
		mov eax, [r9 + rax] ; rax = pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);
		mov r10, rax ; r10 = pdwFunctionNameBase


		; PARAMETERS
		; DllBase : r9
		; pExportTable : r13
		; pExportTable->NumberOfNames : rcx 
		xor rsi, rsi
		.loop_function:
			mov r8, r9
			add r8, r10 ; r8 = pFunctionName

			push r9
			mov rcx, r8
			call .ror13_hash_fun
			pop r9
			mov r12, rax
			add r10, r8 ; add len of fun name 
			
			add r12, r11
			cmp edi, r12d
			jnz .next_function

			; Function found
			mov rcx, r13
			mov rdx, r9
			mov r8, rsi
			jmp .function_found

			.next_function:
			inc rsi
			cmp rcx, rsi
			jnz .loop_function

		.next_module:
        mov rbx, [rbx]             ; Get next flink
		mov r9, [rbx + 0x30]       ; Get DllBase from LDR_DATA_TABLE_ENTRY (offset 0x30)
		test r9, r9                ; If DllBase is NULL, we're done
        jnz .find_function_loop
		xor rax, rax ; Return NULL
		ret

	; PARAMETERS
	; rcx = pExportTable
	; rdx = DllBase
	; r8 = loop counter | i
	; =======
	; return address of the function
	.function_found:
		mov r12d, [rcx + 0x1C] ; pExportTable->AddressOfFunctions
		mov eax, [rcx + 0x24] ; pExportTable->AddressOfNameOrdinals

		add rax, rdx ; rax = DllBase + pExportTable->AddressOfNameOrdinals | RVA
		movzx rax, word [rax + 2 * r8] 
		
		; rax * 4
		mov rcx, 4
		imul rax, rcx

		add rax, r12
		add rax, rdx

		mov ecx, [rax]
		mov rax, rcx
		add rax, rdx

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


