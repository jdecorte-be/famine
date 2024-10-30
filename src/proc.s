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



_get_proc_address:
	mov rdi, rcx
    ; Access PEB
    xor rax, rax
    mov rax, gs:[0x60]              ; RAX = Address_of_PEB
    mov rax, [rax + 0x18]           ; RAX = Address_of_LDR
	mov rbx, [rax + 0x10] ; RBX = First entry in InLoadOrderModuleList (PEB_LDR_DATA->InLoadOrderModuleList)

    .find_function_loop:
        ; Get _LDR_DATA_TABLE_ENTRY
        mov r9, rbx                 ; r9 = _LDR_DATA_TABLE_ENTRY

		; typedef struct _UNICODE_STRING {
		; USHORT Length;				; 2 bytes
		; USHORT MaximumLength; 		; 2 bytes
		; PWSTR  Buffer;				; 8 bytes
		; } UNICODE_STRING, *PUNICODE_STRING;
		add r9, 0x58               ; r9 = LDR_DATA_TABLE_ENTRY->BaseDllName
		movzx r10, word [r9 + 0x2] ; r10 = BaseDllName.Length
		mov r11, [r9 + 0x8]			; r11 = address of BaseDllName.Buffer

		xor rcx, rcx				; rcx = 0 / counter
		xor rax, rax
		xor r9, r9
		xor rdx, rdx
		.loop_hash_dll:
			mov al, byte [r11 + rcx]	; al = BaseDllName.Buffer[rcx]

			; to upper character
			cmp al, 0x61 ; compare with 'a'
			jl .next_char
			sub al, 0x20 ; al = al - 32 / to upper
			.next_char:

			ror edx, 13 ; rdx = rdx >> 13
			movzx rax, al ; rax = al
			add rdx, rax ; rdx = rdx + rax


			inc rcx
			cmp rcx, r10
			jnz .loop_hash_dll
		; rdx = hash of the dll name
		mov r11, rdx

		xor rcx, rcx
		xor rax, rax
		xor r9, r9
		xor rdx, rdx

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
		push r9
		sub r9, rdx ; r9 = DLLBase
		mov eax, [r9 + rax] ; rax = pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);
		mov r10, rax ; r10 = pdwFunctionNameBase

		; need : r9, r10
		xor r8, r8
		xor rsi, rsi
		.loop_function:
			mov r8, r9
			add r8, r10 ; r8 = pFunctionName

			xor rax, rax
			xor rdx, rdx ; hash of the function name
			xor r12, r12
			.loop_hash_function:
				mov al, byte [r8 + r12]
				cmp al, 0x61

				ror edx, 13 ; rdx = rdx >> 13
				movzx rax, al ; rax = al
				add rdx, rax ; rdx = rdx + rax

				inc r12
				cmp al, 0
				jnz .loop_hash_function

			add r10, r12
			mov r12, rdx
			add r12, r11
			cmp edi, r12d
			jnz .next_function
			; found function
			xor rcx, rcx
			xor r12, r12
			xor rax, rax

			; usOrdinalTableIndex
			pop rax
			mov r12d, [rax + 0x1C]       ; r12 = pExportTable->AddressOfFunctions
			mov eax, [rax + 0x24]       ; eax = pExportTable->AddressOfNameOrdinals

			add rax, r9               ;	 rax = Absolute address of AddressOfNameOrdinals
			movzx rax, word [rax + 2 * rsi] ; edx = Ordinal (from AddressOfNameOrdinals)


			mov rcx, 4
			mul rcx

			add rax, r12
			add rax, r9

			mov ecx, [rax] ; rax = address of function
			xor rax, rax
			mov rax, rcx
			add rax, r9

			xor rbx, rbx
			xor rcx, rcx
			xor rdi, rdi
			xor r8, r8
			xor r9, r9
			xor r10, r10
			xor r11, r11
			xor r12, r12

			ret

			.next_function:
			inc rsi
			cmp rcx, rsi
			jnz .loop_function

		.next_module:
        ; Move to next module in list
        mov rbx, [rbx]             ; Get next flink
		mov r9, [rbx + 0x30]       ; Get DllBase from LDR_DATA_TABLE_ENTRY (offset 0x30)
		test r9, r9                ; If DllBase is NULL, we're done
        jnz .find_function_loop
		xor rax, rax ; Return NULL
		ret

		; PARAMETERS
		; rcx = string
		; rdx = string length
		; =======
		; rcx = counter
		.ror13_hash_dll:
			xor rcx, rcx
			.loop_hash:
				mov al, byte [rdi + rcx]	; al = BaseDllName.Buffer[rcx]

				; to upper character
				cmp al, 0x61 ; compare with 'a'
				jl .next_char
				sub al, 0x20 ; al = al - 32 / to upper
				.next_char:

				ror edx, 13 ; rdx = rdx >> 13
				movzx rax, al ; rax = al
				add rdx, rax ; rdx = rdx + rax


				inc rcx
				cmp rcx, r10
				jnz .loop_hash
			ret






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