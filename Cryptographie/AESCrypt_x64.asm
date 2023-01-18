;/****************************************************************************
;  AESCrypt_x64.asm
;  For more information see https://github.com/RePag/AES-CBC-256bit
;****************************************************************************/
;
;/****************************************************************************
;  The MIT License(MIT)
;
;  Copyright(c) 2021 René Pagel
;
;  Permission is hereby granted, free of charge, to any person obtaining a copy
;  of this softwareand associated documentation files(the "Software"), to deal
;  in the Software without restriction, including without limitation the rights
;  to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
;  copies of the Software, and to permit persons to whom the Software is
;  furnished to do so, subject to the following conditions :
;
;  The above copyright noticeand this permission notice shall be included in all
;  copies or substantial portions of the Software.
;
;  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
;  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;  SOFTWARE.
;******************************************************************************/

INCLUDE listing.inc
INCLUDELIB OLDNAMES

INCLUDE ..\..\Include\CompSys_x64.inc
INCLUDE ..\..\Include\ADT_x64.inc

CS_AES_Crypt SEGMENT EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT
s_push = 16
s_Bytes = 32

aqp_Key = 72 + s_Bytes + s_push

sqp_Vector = 56 + s_Bytes + s_push
sqp_Bytes = 48 + s_Bytes + s_push
sqp_PlainText = 40 + s_Bytes + s_push

sxp_Kleiner_16 = 12 + s_ShadowRegister + s_push
sqp_Speicher = 4 + s_ShadowRegister + s_push
sdi_Bytes = 0 + s_ShadowRegister + s_push
?AES_CBC_Encrypt@@YQPEADPEBX0AEAKQEAE2@Z PROC PUBLIC
		push rsi
		push rdi
		sub rsp, s_ShadowRegister + s_Bytes

		mov qword ptr sqp_Speicher[rsp], rcx

		test rdx, rdx
		je Ende
		mov qword ptr sqp_PlainText[rsp], rdx
		
		test r9, r9
		je Ende
		mov qword ptr sqp_Vector[rsp], r9
		
		mov r10, qword ptr aqp_Key[rsp]
		test r10, r10
		je Ende

		test r8, r8
		je Ende
		mov qword ptr sqp_Bytes[rsp], r8
		mov eax, dword ptr [r8]
		mov dword ptr sdi_Bytes[rsp], eax

		xor rdx, rdx
		mov rcx, 10h
		div rcx
		test rdx, rdx
		je NoRound
		add rax, 1
	
	NoRound:
		add rax, 1
		mov rdx, 10h
		imul rdx, rax
		mov dword ptr [r8], edx
		mov rcx, qword ptr sqp_Speicher[rsp]
		call ?VMBlockS@System@RePag@@YQPEADPEBXK@Z ; VMBlockS(vmSpeicher, ulBytes)
		mov r8, rax
		
		mov rdx, qword ptr sqp_Bytes[rsp]
		mov edx, dword ptr [rdx]
		sub rdx, 10h
		mov r9d, dword ptr sdi_Bytes[rsp]
		mov dword ptr [r8 + rdx], r9d
		mov rcx, qword ptr sqp_PlainText[rsp]
		add rdx, rcx
		sub rdx, 10h
		xor rdi, rdi

		mov r10, qword ptr sqp_Vector[rsp]
		movups xmm0, xmmword ptr [r10]

		mov r10, qword ptr aqp_Key[rsp]

		cmp r9, 10h
		jae short Bytes_Crypt
		
		mov rsi, rcx
		mov rcx, r9

		vpxor xmm1, xmm1, xmm1
		vmovdqu xmmword ptr sxp_Kleiner_16[rsp], xmm1
		lea rdi, sxp_Kleiner_16[rsp]
		rep movsb
		vmovdqu xmm1, xmmword ptr sxp_Kleiner_16[rsp]

		mov rcx, rdx
		jmp Bytes_Crypt_Kleiner_16

	Bytes_Crypt:
		movups xmm1, xmmword ptr [rcx]

	Bytes_Crypt_Kleiner_16:
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [r10]

		aesenc xmm0, xmmword ptr [r10 + 10h]
		aesenc xmm0, xmmword ptr [r10 + 20h]
		aesenc xmm0, xmmword ptr [r10 + 30h]
		aesenc xmm0, xmmword ptr [r10 + 40h]
		aesenc xmm0, xmmword ptr [r10 + 50h]
		aesenc xmm0, xmmword ptr [r10 + 60h]
		aesenc xmm0, xmmword ptr [r10 + 70h]
		aesenc xmm0, xmmword ptr [r10 + 80h]
		aesenc xmm0, xmmword ptr [r10 + 90h]
		aesenc xmm0, xmmword ptr [r10 + 0a0h]
		aesenc xmm0, xmmword ptr [r10 + 0b0h]
		aesenc xmm0, xmmword ptr [r10 + 0c0h]
		aesenc xmm0, xmmword ptr [r10 + 0d0h]
		aesenclast xmm0, xmmword ptr [r10 + 0e0h]

		movups xmmword ptr [r8], xmm0

		add rcx, 10h
		add r8, 10h
		cmp	rcx, rdx
		jb Bytes_Crypt
		test rdi, rdi
		jne short Ende

		mov rsi, rcx
		mov ecx, dword ptr sdi_Bytes[rsp]
		cmp ecx, 10h
		jbe short Ende
		add rcx, qword ptr sqp_PlainText[rsp]
		sub rcx, rdx

		vpxor xmm1, xmm1, xmm1
		vmovdqu xmmword ptr sxp_Kleiner_16[rsp], xmm1
		lea rdi, sxp_Kleiner_16[rsp]
		rep movsb
		vmovdqu xmm1, xmmword ptr sxp_Kleiner_16[rsp]
		mov rcx, rdx 
		jmp Bytes_Crypt_Kleiner_16

	Ende:
		add rsp, s_ShadowRegister + s_Bytes
		pop rdi
		pop rsi
		ret
?AES_CBC_Encrypt@@YQPEADPEBX0AEAKQEAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
_Text SEGMENT		
aqp_Key = 72

sqp_Vector = 56
sqp_Bytes = 48
sqp_ChipperText = 40
?AES_CBC_Decrypt@@YQPEADPEBX0AEAKQEAE2@Z PROC PUBLIC
		sub rsp, s_ShadowRegister

		test rdx, rdx
		je Ende
		mov qword ptr sqp_ChipperText[rsp], rdx

		test r9, r9
		je Ende
		mov qword ptr sqp_Vector[rsp], r9
		
		mov r10, qword ptr aqp_Key[rsp]
		test r10, r10
		je Ende

		test r8, r8
		je Ende
		mov qword ptr sqp_Bytes[rsp], r8
		mov edx, dword ptr [r8]
		cmp edx, 10h
		ja short CipperText
		xor rax, rax
		mov dword ptr [r8], eax
		je Ende

	CipperText:
		call ?VMBlockS@System@RePag@@YQPEADPEBXK@Z ; VMBlockS(vmSpeicher, ulBytes)
		mov r8, rax

		mov rdx, qword ptr sqp_Bytes[rsp]
		mov r10, rdx
		mov edx, dword ptr [rdx]
		sub rdx, 10h
		mov rcx, qword ptr sqp_ChipperText[rsp]
		add rdx, rcx
		mov r9d, dword ptr [rdx]
		mov dword ptr [r10], r9d

		mov r9, qword ptr sqp_Vector[rsp]
		movups xmm2, xmmword ptr [r9]

		mov r9, qword ptr aqp_Key[rsp]

	Bytes_Crypt:
		movups xmm0, xmmword ptr [rcx]
		movups xmm1, xmm0
		pxor xmm0, xmmword ptr [r9]

		aesdec xmm0, xmmword ptr [r9 + 10h]
		aesdec xmm0, xmmword ptr [r9 + 20h]
		aesdec xmm0, xmmword ptr [r9 + 30h]
		aesdec xmm0, xmmword ptr [r9 + 40h]
		aesdec xmm0, xmmword ptr [r9 + 50h]
		aesdec xmm0, xmmword ptr [r9 + 60h]
		aesdec xmm0, xmmword ptr [r9 + 70h]
		aesdec xmm0, xmmword ptr [r9 + 80h]
		aesdec xmm0, xmmword ptr [r9 + 90h]
		aesdec xmm0, xmmword ptr [r9 + 0a0h]
		aesdec xmm0, xmmword ptr [r9 + 0b0h]
		aesdec xmm0, xmmword ptr [r9 + 0c0h]
		aesdec xmm0, xmmword ptr [r9 + 0d0h]
		aesdeclast xmm0, xmmword ptr [r9 + 0e0h]

		pxor xmm0, xmm2
		movups xmmword ptr [r8], xmm0
		movups xmm2, xmm1

		add rcx, 10h
		add r8, 10h
		cmp	rcx, rdx
		jb Bytes_Crypt

	Ende:
		add rsp, s_ShadowRegister
		ret
?AES_CBC_Decrypt@@YQPEADPEBX0AEAKQEAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_AES_Crypt ENDS
;----------------------------------------------------------------------------
CS_Crypt SEGMENT EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT
; ax usBytes
; cx usPositions_Daten
; dh ucPosition_Schlussel
; dl ucRest
?KeyDecrypt@@YAXQEAEPEAEG@Z PROC
		push rbx
		push rdi
		push rsi

		mov rsi, rdx
		mov rdi, rcx
		mov r9, rcx
		mov rdx, 8
		mov rax, r8
		div dl
		mov dl, ah
		mov rax, r8
		mov dh, 0
		xor rcx, rcx
		jmp CoreDecrypt_Schleife_Vergleich

	CoreDecrypt_Schleife_Anfang:
		mov rdi, r9 
		add rdi, 8

	CoreDecrypt_Schleife_Vergleich:
		cmp rcx, rax
		jge CoreDecrypt_Schleife_Ende

		cmp dh, 16
		jne CoreDecrypt_Schlussel
		xor dh, dh
		sub rdi, 8

	CoreDecrypt_Schlussel:
		mov bh, byte ptr [rsi]
		add bh, byte ptr [rdi]
		mov byte ptr [rsi], bh

		mov bh, byte ptr [rsi + 1]
		add bh, byte ptr [rdi + 1]
		mov byte ptr [rsi + 1], bh

		mov bh, byte ptr [rsi + 2]
		add bh, byte ptr [rdi + 2]
		mov byte ptr [rsi + 2], bh

		mov bh, byte ptr [rsi + 3]
		add bh, byte ptr [rdi + 3]
		mov byte ptr [rsi + 3], bh

		mov bh, byte ptr [rsi + 4]
		add bh, byte ptr [rdi + 4]
		mov byte ptr [rsi + 4], bh

		mov bh, byte ptr [rsi + 5]
		add bh, byte ptr [rdi + 5]
		mov byte ptr [rsi + 5], bh

		mov bh, byte ptr [rsi + 6]
		add bh, byte ptr [rdi + 6]
		mov byte ptr [rsi + 6], bh

		mov bh, byte ptr [rsi + 7]
		add bh, byte ptr [rdi + 7]
		mov byte ptr [rsi + 7], bh
		jmp CoreDecrypt_Schlussel_Add

	CoreDecrypt_Schlussel_Add:
		add dh, 8
		add rcx, 8

		mov bx, cx
		add bx, 8
		cmp ax, bx
		jl CoreDecrypt_Rest

		mov rdi, rsi
		add rsi, 8
		add rdi, 7

		mov bh, byte ptr [rsi]
		xor bh, byte ptr [rdi]
		mov byte ptr [rsi], bh

		mov bh, byte ptr [rsi + 1]
		xor bh, byte ptr [rdi - 1]
		mov byte ptr [rsi + 1], bh

		mov bh, byte ptr [rsi + 2]
		xor bh, byte ptr [rdi - 2]
		mov byte ptr [rsi + 2], bh

		mov bh, byte ptr [rsi + 3]
		xor bh, byte ptr [rdi - 3]
		mov byte ptr [rsi + 3], bh

		mov bh, byte ptr [rsi + 4]
		xor bh, byte ptr [rdi - 4]
		mov byte ptr [rsi + 4], bh

		mov bh, byte ptr [rsi + 5]
		xor bh, byte ptr [rdi - 5]
		mov byte ptr [rsi + 5], bh

		mov bh, byte ptr [rsi + 6]
		xor bh, byte ptr [rdi - 6]
		mov byte ptr [rsi + 6], bh

		mov bh, byte ptr [rsi + 7]
		xor bh, byte ptr [rdi - 7]
		mov byte ptr [rsi + 7], bh
		jmp CoreDecrypt_Schleife_Anfang

	CoreDecrypt_Rest:
		cmp dl, 0
		je CoreDecrypt_Schleife_Ende

		mov rax, 1
		add rsi, 7
		mov rdi, rsi
		jmp CoreDecrypt_Schleife_Rest_Vergleich

	CoreDecrypt_Schleife_Rest_Anfang:
		add al, 1
		sub rdi, 1

	CoreDecrypt_Schleife_Rest_Vergleich:
		cmp al, dl
		jg CoreDecrypt_Rest_Schlussel

		mov bh, byte ptr [rsi + rax]
		xor bh, byte ptr [rdi]
		mov byte ptr [rsi + rax], bh
		jmp CoreDecrypt_Schleife_Rest_Anfang

	CoreDecrypt_Rest_Schlussel:
		cmp dh, 16
		jne CoreDecrypt_B
		xor dh, dh

	CoreDecrypt_B:
		mov rdi, r9
		bt dx, 11
		jnc CoreDecrypt_RestAdd_Vergleich
		add rdi, 8 
		jmp CoreDecrypt_RestAdd_Vergleich

	CoreDecrypt_RestAdd_Anfang:
		add rdi, 1
		sub dl, 1

	CoreDecrypt_RestAdd_Vergleich:
		cmp dl, 0
		je CoreDecrypt_Schleife_Ende

		add rsi, 1
		mov bh, byte ptr [rsi] 
		add bh, byte ptr [rdi]
		mov byte ptr [rsi], bh
		jmp CoreDecrypt_RestAdd_Anfang

	CoreDecrypt_Schleife_Ende:
		pop rsi
		pop rdi
		pop rbx
		ret
?KeyDecrypt@@YAXQEAEPEAEG@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
_Text SEGMENT
; ax usBytes
; cx usPositions_Daten
; dh ucPosition_Schlussel
; dl ucRest
?KeyEncrypt@@YAXQEAEPEAEG@Z PROC
		push rbx
		push rdi
		push rsi

		mov rsi, rdx
		mov rdi, rcx
		mov r9, rcx

		mov rdx, 8
		mov rax, r8
		div dl
		mov dl, ah

		mov rax, r8
		mov rcx, rax
		shr ax, 4
		shl ax, 4
		sub cx, ax
		mov dh, cl

		mov rax, r8
		mov rcx, rax
		sub rcx, 1
		xor rbx, rbx
		mov bl, dh
		add rdi, rbx
		mov rbx, rax
		sub bl, dl
		shl rax, 16
		jmp CoreEncrypt_Schleife_RestSub_Vergleich

	CoreEncrypt_Schleife_RestSub_Anfang:
		sub rcx, 1
		sub dh, 1

	CoreEncrypt_Schleife_RestSub_Vergleich:
		cmp cx, bx
		jl CoreEncrypt_Schleife_RestSub_Ende

		sub rdi, 1
		mov al, byte ptr [rsi + rcx]
		sub al, byte ptr [rdi]
		mov byte ptr [rsi + rcx], al
		jmp CoreEncrypt_Schleife_RestSub_Anfang

	CoreEncrypt_Schleife_RestSub_Ende:
		shr rax, 16
		add cx, 1
		mov rbx, rcx
		mov rdi, rsi
		add rdi, rbx
		sub rdi, 1
		shl rdx, 16
		jmp CoreEncrypt_Schleife_Rest_Vergleich

	CoreEncrypt_Schleife_Rest_Anfang:
		add rbx, 1
		sub rdi, 1

	CoreEncrypt_Schleife_Rest_Vergleich:
		cmp bx, ax
		jge CoreEncrypt_Schleife_Rest_Ende

		mov dl, byte ptr [rsi + rbx]
		xor dl, byte ptr [rdi]
		mov byte ptr [rsi + rbx], dl
		jmp CoreEncrypt_Schleife_Rest_Anfang

	CoreEncrypt_Schleife_Rest_Ende:
		shr rdx, 24
		mov rdi, r9
		add rdi, rdx
		test dl, dl
		jne CoreEncrypt_B
		mov dl, 16
		add rdi, 16

	CoreEncrypt_B:
		sub rcx, 1
		add rsi, rcx
		add rcx, 1
		jmp CoreEncrypt_A

	CoreEncrypt_Schleife_Anfang:
		sub rsi, 1
		sub dl, 8
		mov rdi, r9
		add rdi, rdx
		test dl, dl
		jne CoreEncrypt_A
		mov dl, 16
		add rdi, 16

	CoreEncrypt_A:
		sub rdi, 1
		mov bh, byte ptr [rsi]
		sub bh, byte ptr [rdi]
		mov byte ptr [rsi], bh

		mov bh, byte ptr [rsi - 1]
		sub bh, byte ptr [rdi - 1]
		mov byte ptr [rsi - 1], bh

		mov bh, byte ptr [rsi - 2]
		sub bh, byte ptr [rdi - 2]
		mov byte ptr [rsi - 2], bh

		mov bh, byte ptr [rsi - 3]
		sub bh, byte ptr [rdi - 3]
		mov byte ptr [rsi - 3], bh

		mov bh, byte ptr [rsi - 4]
		sub bh, byte ptr [rdi - 4]
		mov byte ptr [rsi - 4], bh

		mov bh, byte ptr [rsi - 5]
		sub bh, byte ptr [rdi - 5]
		mov byte ptr [rsi - 5], bh

		mov bh, byte ptr [rsi - 6]
		sub bh, byte ptr [rdi - 6]
		mov byte ptr [rsi - 6], bh

		mov bh, byte ptr [rsi - 7]
		sub bh, byte ptr [rdi - 7]
		mov byte ptr [rsi - 7], bh

		sub cx, 8
		test cx, cx
		je CoreEncrypt_Schleife_Ende

		sub rsi, 7
		mov rdi, rsi
		sub rdi, 1

		mov bh, byte ptr [rsi]
		xor bh, byte ptr [rdi]
		mov byte ptr [rsi], bh

		mov bh, byte ptr [rsi + 1]
		xor bh, byte ptr [rdi - 1]
		mov byte ptr [rsi + 1], bh

		mov bh, byte ptr [rsi + 2]
		xor bh, byte ptr [rdi - 2]
		mov byte ptr [rsi + 2], bh

		mov bh, byte ptr [rsi + 3]
		xor bh, byte ptr [rdi - 3]
		mov byte ptr [rsi + 3], bh

		mov bh, byte ptr [rsi + 4]
		xor bh, byte ptr [rdi - 4]
		mov byte ptr [rsi + 4], bh

		mov bh, byte ptr [rsi + 5]
		xor bh, byte ptr [rdi - 5]
		mov byte ptr [rsi + 5], bh

		mov bh, byte ptr [rsi + 6]
		xor bh, byte ptr [rdi - 6]
		mov byte ptr [rsi + 6], bh

		mov bh, byte ptr [rsi + 7]
		xor bh, byte ptr [rdi - 7]
		mov byte ptr [rsi + 7], bh
		jmp CoreEncrypt_Schleife_Anfang

	CoreEncrypt_Schleife_Ende:
		pop rsi
		pop rdi
		pop rbx
		ret
?KeyEncrypt@@YAXQEAEPEAEG@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_Crypt ENDS
END
