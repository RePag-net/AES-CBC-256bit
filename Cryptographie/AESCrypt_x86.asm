;/****************************************************************************
;  AESCrypt_x86.asm
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

.686P
.XMM
include listing.inc
.MODEL FLAT
INCLUDE ..\..\Include\CompSys.inc
INCLUDE ..\..\Include\ADT.inc
INCLUDELIB LIBCMTD
INCLUDELIB OLDNAMES

CS_AES_Crypt SEGMENT PRIVATE EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT
s_Bytes = 28

sxp_Kleiner_16 = 12
sdp_PlainText = 8
sdi_Bytes = 4
sdp_Speicher = 0

adauc_256Key = 24 + s_Bytes
adauc_16IVec = 20 + s_Bytes
add_Bytes = 16 + s_Bytes
?AES_CBC_Encrypt@@YQPADPBX0AAKQAE2@Z PROC PUBLIC
		push esi
		push edi
		push ebx
		sub esp, s_Bytes

		mov dword ptr sdp_Speicher[esp], ecx

		mov	esi, edx
		test esi, esi
		je Ende
		mov dword ptr sdp_PlainText[esp], edx

		mov ebx, dword ptr add_Bytes[esp]
		test ebx, ebx
		je Ende
		mov eax, dword ptr [ebx]
		mov dword ptr sdi_Bytes[esp], eax

		xor edx, edx
		mov ecx, 10h
		div ecx
		test edx, edx
		je NoRound
		add eax, 1

	NoRound:
		add eax, 1
		mov edx, 10h
		imul edx, eax
		mov dword ptr [ebx], edx
		mov ecx, dword ptr sdp_Speicher[esp]
		call ?VMBlockS@System@RePag@@YQPADPBXK@Z ; VMBlockS(vmSpeicher, ulBytes)
		mov edi, eax

		mov edx, dword ptr add_Bytes[esp]
		mov edx, dword ptr [edx]
		sub edx, 10h
		mov ecx, dword ptr sdi_Bytes[esp]
		mov dword ptr [edi + edx], ecx
		add edx, esi
		sub edx, 10h
		xor ebx, ebx

		mov	ecx, dword ptr adauc_16IVec[esp]
		test ecx, ecx
		je Ende_Frei
		movups xmm0, xmmword ptr [ecx]

		mov eax, dword ptr adauc_256Key[esp]
		test eax, eax
		je Ende_Frei

		mov ecx, dword ptr sdi_Bytes[esp]
		cmp ecx, 10h
		jae short Bytes_Crypt

		push esi
		push edi
		
		mov esi, sdp_PlainText[esp]

		pxor xmm1, xmm1
		movdqu xmmword ptr sxp_Kleiner_16[esp], xmm1
		lea edi, sxp_Kleiner_16[esp]
		rep movsb
		vmovdqu xmm1, xmmword ptr sxp_Kleiner_16[esp]

		pop edi
		pop esi

		jmp Bytes_Crypt_Kleiner_16

	Bytes_Crypt:
		movups xmm1, xmmword ptr [esi]

	Bytes_Crypt_Kleiner_16:
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [eax]

		aesenc xmm0, xmmword ptr [eax + 10h]
		aesenc xmm0, xmmword ptr [eax + 20h]
		aesenc xmm0, xmmword ptr [eax + 30h]
		aesenc xmm0, xmmword ptr [eax + 40h]
		aesenc xmm0, xmmword ptr [eax + 50h]
		aesenc xmm0, xmmword ptr [eax + 60h]
		aesenc xmm0, xmmword ptr [eax + 70h]
		aesenc xmm0, xmmword ptr [eax + 80h]
		aesenc xmm0, xmmword ptr [eax + 90h]
		aesenc xmm0, xmmword ptr [eax + 0a0h]
		aesenc xmm0, xmmword ptr [eax + 0b0h]
		aesenc xmm0, xmmword ptr [eax + 0c0h]
		aesenc xmm0, xmmword ptr [eax + 0d0h]
		aesenclast xmm0, xmmword ptr [eax + 0e0h]

		movups xmmword ptr [edi], xmm0

		add esi, 10h
		add edi, 10h
		cmp	esi, edx
		jb Bytes_Crypt
		test ebx, ebx
		jne short Ende

		push edi
		push ecx
		
		mov ecx, dword ptr sdi_Bytes[esp]
		cmp ecx, 10h
		jbe short Ende
		add ecx, dword ptr sdp_PlainText[esp]
		sub ecx, edx

		pxor xmm1, xmm1
		movdqu xmmword ptr sxp_Kleiner_16[esp], xmm1
		lea edi, sxp_Kleiner_16[esp]
		rep movsb
		movdqu xmm1, xmmword ptr sxp_Kleiner_16[esp]

		pop ecx
		pop edi
		
		mov esi, edx
		add ebx, 1
		jmp	Bytes_Crypt_Kleiner_16

	Ende_Frei:
		mov edx, edi
		mov ecx, dword ptr sdp_Speicher[esp]
		call ?VMFrei@System@RePag@@YQXPBXPAX@Z ; VMFrei(vmSpeicher, vbAdresse)
		xor eax, eax

	Ende:
		add esp, s_Bytes
		pop ebx
		pop	edi
		pop	esi
		ret	12
?AES_CBC_Encrypt@@YQPADPBX0AAKQAE2@Z ENDP
_Text ENDS
;-----------------------------------------------------------------------------
_Text SEGMENT
s_Bytes = 4

sdp_Speicher = 0

adauc256Key = 24 + s_Bytes
adauc_16IVec = 20 + s_Bytes
add_Bytes = 16 + s_Bytes
?AES_CBC_Decrypt@@YQPADPBX0AAKQAE2@Z PROC PUBLIC
		push ebx
		push esi
		push edi
		sub esp, s_Bytes

		mov esi, edx
		test esi, esi
		je Ende

		mov edx, dword ptr add_Bytes[esp]
		test edx, edx
		je Ende
		mov edx, dword ptr [edx]
		cmp edx, 10h
		ja ChipperText
		xor eax, eax
		mov dword ptr [edx], eax
		je Ende

	ChipperText:
		call ?VMBlockS@System@RePag@@YQPADPBXK@Z ; VMBlockS(vmSpeicher, ulBytes)
		mov edi, eax

		mov edx, dword ptr add_Bytes[esp]
		mov ebx, edx
		mov edx, dword ptr [edx]
		sub edx, 10h
		add edx, esi
		mov ecx, dword ptr [edx]
		mov dword ptr [ebx], ecx

		mov	ecx, dword ptr adauc_16IVec[esp]
		test ecx, ecx
		je Ende
		movups xmm2, xmmword ptr [ecx]

		mov ecx, dword ptr adauc256Key[esp]
		test ecx, ecx
		je Ende

	Bytes_Crypt:
		movups xmm0, xmmword ptr [esi]
		movups xmm1, xmm0
		pxor xmm0, xmmword ptr [ecx]

		aesdec xmm0, xmmword ptr [ecx + 10h]
		aesdec xmm0, xmmword ptr [ecx + 20h]
		aesdec xmm0, xmmword ptr [ecx + 30h]
		aesdec xmm0, xmmword ptr [ecx + 40h]
		aesdec xmm0, xmmword ptr [ecx + 50h]
		aesdec xmm0, xmmword ptr [ecx + 60h]
		aesdec xmm0, xmmword ptr [ecx + 70h]
		aesdec xmm0, xmmword ptr [ecx + 80h]
		aesdec xmm0, xmmword ptr [ecx + 90h]
		aesdec xmm0, xmmword ptr [ecx + 0a0h]
		aesdec xmm0, xmmword ptr [ecx + 0b0h]
		aesdec xmm0, xmmword ptr [ecx + 0c0h]
		aesdec xmm0, xmmword ptr [ecx + 0d0h]
		aesdeclast xmm0, xmmword ptr [ecx + 0e0h]

		pxor xmm0, xmm2
		movups xmmword ptr [edi], xmm0
		movups xmm2, xmm1

		add esi, 10h
		add edi, 10h
		cmp	esi, edx
		jb Bytes_Crypt
		jmp short Ende

	Ende_Frei:
		mov edx, edi
		mov ecx, dword ptr sdp_Speicher[esp]
		call ?VMFreiS@System@RePag@@YQXPBXPAX@Z ; VMFreiS(vmSpeicher, vbAdresse)
		xor eax, eax

	Ende:
		add esp, s_Bytes
		pop	edi
		pop	esi
		pop	ebx
		ret	12
?AES_CBC_Decrypt@@YQPADPBX0AAKQAE2@Z ENDP
_Text ENDS
CS_AES_Crypt ENDS
;----------------------------------------------------------------------------
CS_Crypt SEGMENT PARA PRIVATE FLAT EXECUTE
;----------------------------------------------------------------------------
; ax usBytes
; cx usPositions_Daten
; dh ucPosition_Schlussel
; dl ucRest
bit128Key = 8
pucCrypthText = 12
usBytes = 16
?KeyDecrypt@@YGXQAEPAEG@Z PROC
		push ebp
		mov	ebp, esp
		push ebx
		push edi
		push esi

		mov edx, 8
		movzx eax, word ptr usBytes[ebp]
		div dl
		mov dl, ah
		movzx eax, word ptr usBytes[ebp]
		mov dh, 0
		xor ecx, ecx
		mov edi, dword ptr bit128Key[ebp]
		mov esi, dword ptr pucCrypthText[ebp]
		jmp CoreDecrypt_Schleife_Vergleich

	CoreDecrypt_Schleife_Anfang:
		mov edi, dword ptr bit128Key[ebp] 
		add edi, 8

	CoreDecrypt_Schleife_Vergleich:
		cmp ecx, eax
		jge CoreDecrypt_Schleife_Ende

		cmp dh, 16
		jne CoreDecrypt_Schlussel
		xor dh, dh
		sub edi, 8

	CoreDecrypt_Schlussel:
		mov bh, byte ptr [esi]
		add bh, byte ptr [edi]
		mov byte ptr [esi], bh

		mov bh, byte ptr [esi + 1]
		add bh, byte ptr [edi + 1]
		mov byte ptr [esi + 1], bh

		mov bh, byte ptr [esi + 2]
		add bh, byte ptr [edi + 2]
		mov byte ptr [esi + 2], bh

		mov bh, byte ptr [esi + 3]
		add bh, byte ptr [edi + 3]
		mov byte ptr [esi + 3], bh

		mov bh, byte ptr [esi + 4]
		add bh, byte ptr [edi + 4]
		mov byte ptr [esi + 4], bh

		mov bh, byte ptr [esi + 5]
		add bh, byte ptr [edi + 5]
		mov byte ptr [esi + 5], bh

		mov bh, byte ptr [esi + 6]
		add bh, byte ptr [edi + 6]
		mov byte ptr [esi + 6], bh

		mov bh, byte ptr [esi + 7]
		add bh, byte ptr [edi + 7]
		mov byte ptr [esi + 7], bh
		jmp CoreDecrypt_Schlussel_Add

	CoreDecrypt_Schlussel_Add:
		add dh, 8
		add ecx, 8

		mov bx, cx
		add bx, 8
		cmp ax, bx
		jl CoreDecrypt_Rest

		mov edi, esi
		add esi, 8
		add edi, 7

		mov bh, byte ptr [esi]
		xor bh, byte ptr [edi]
		mov byte ptr [esi], bh

		mov bh, byte ptr [esi + 1]
		xor bh, byte ptr [edi - 1]
		mov byte ptr [esi + 1], bh

		mov bh, byte ptr [esi + 2]
		xor bh, byte ptr [edi - 2]
		mov byte ptr [esi + 2], bh

		mov bh, byte ptr [esi + 3]
		xor bh, byte ptr [edi - 3]
		mov byte ptr [esi + 3], bh

		mov bh, byte ptr [esi + 4]
		xor bh, byte ptr [edi - 4]
		mov byte ptr [esi + 4], bh

		mov bh, byte ptr [esi + 5]
		xor bh, byte ptr [edi - 5]
		mov byte ptr [esi + 5], bh

		mov bh, byte ptr [esi + 6]
		xor bh, byte ptr [edi - 6]
		mov byte ptr [esi + 6], bh

		mov bh, byte ptr [esi + 7]
		xor bh, byte ptr [edi - 7]
		mov byte ptr [esi + 7], bh
		jmp CoreDecrypt_Schleife_Anfang

	CoreDecrypt_Rest:
		cmp dl, 0
		je CoreDecrypt_Schleife_Ende

		mov eax, 1
		add esi, 7
		mov edi, esi
		jmp CoreDecrypt_Schleife_Rest_Vergleich

	CoreDecrypt_Schleife_Rest_Anfang:
		add al, 1
		sub edi, 1

	CoreDecrypt_Schleife_Rest_Vergleich:
		cmp al, dl
		jg CoreDecrypt_Rest_Schlussel

		mov bh, byte ptr [esi + eax]
		xor bh, byte ptr [edi]
		mov byte ptr [esi + eax], bh
		jmp CoreDecrypt_Schleife_Rest_Anfang

	CoreDecrypt_Rest_Schlussel:
		cmp dh, 16
		jne CoreDecrypt_B
		xor dh, dh

	CoreDecrypt_B:
		mov edi, dword ptr bit128Key[ebp]
		bt dx, 11
		jnc CoreDecrypt_RestAdd_Vergleich
		add edi, 8 
		jmp CoreDecrypt_RestAdd_Vergleich

	CoreDecrypt_RestAdd_Anfang:
		add edi, 1
		sub dl, 1

	CoreDecrypt_RestAdd_Vergleich:
		cmp dl, 0
		je CoreDecrypt_Schleife_Ende

		add esi, 1
		mov bh, byte ptr [esi] 
		add bh, byte ptr [edi]
		mov byte ptr [esi], bh
		jmp CoreDecrypt_RestAdd_Anfang

	CoreDecrypt_Schleife_Ende:
		pop esi
		pop edi
		pop ebx
		mov esp, ebp
		pop ebp
		ret 12
?KeyDecrypt@@YGXQAEPAEG@Z ENDP
;----------------------------------------------------------------------------
; ax usBytes
; cx usPositions_Daten
; dh ucPosition_Schlussel
; dl ucRest
?KeyEncrypt@@YGXQAEPAEG@Z PROC
		push ebp
		mov	ebp, esp
		push ebx
		push edi
		push esi

		mov esi, dword ptr pucCrypthText[ebp]
		mov edi, dword ptr bit128Key[ebp]

		mov edx, 8
		movzx eax, word ptr usBytes[ebp]
		div dl
		mov dl, ah

		movzx eax, word ptr usBytes[ebp]
		mov ecx, eax
		shr ax, 4
		shl ax, 4
		sub cx, ax
		mov dh, cl

		movzx eax, word ptr usBytes[ebp]
		mov ecx, eax
		sub ecx, 1
		movzx ebx, dh
		add edi, ebx
		mov ebx, eax
		sub bl, dl
		shl eax, 16
		jmp CoreEncrypt_Schleife_RestSub_Vergleich

	CoreEncrypt_Schleife_RestSub_Anfang:
		sub ecx, 1
		sub dh, 1

	CoreEncrypt_Schleife_RestSub_Vergleich:
		cmp cx, bx
		jl CoreEncrypt_Schleife_RestSub_Ende

		sub edi, 1
		mov al, byte ptr [esi + ecx]
		sub al, byte ptr [edi]
		mov byte ptr [esi + ecx], al
		jmp CoreEncrypt_Schleife_RestSub_Anfang

	CoreEncrypt_Schleife_RestSub_Ende:
		shr eax, 16
		add cx, 1
		mov ebx, ecx
		mov edi, esi
		add edi, ebx
		sub edi, 1
		shl edx, 16
		jmp CoreEncrypt_Schleife_Rest_Vergleich

	CoreEncrypt_Schleife_Rest_Anfang:
		add ebx, 1
		sub edi, 1

	CoreEncrypt_Schleife_Rest_Vergleich:
		cmp bx, ax
		jge CoreEncrypt_Schleife_Rest_Ende

		mov dl, byte ptr [esi + ebx]
		xor dl, byte ptr [edi]
		mov byte ptr [esi + ebx], dl
		jmp CoreEncrypt_Schleife_Rest_Anfang

	CoreEncrypt_Schleife_Rest_Ende:
		shr edx, 24
		mov edi, dword ptr bit128Key[ebp]
		add edi, edx
		test dl, dl
		jne CoreEncrypt_B
		mov dl, 16
		add edi, 16

	CoreEncrypt_B:
		sub ecx, 1
		add esi, ecx
		add ecx, 1
		jmp CoreEncrypt_A

	CoreEncrypt_Schleife_Anfang:
		sub esi, 1
		sub dl, 8
		mov edi, dword ptr bit128Key[ebp]
		add edi, edx
		test dl, dl
		jne CoreEncrypt_A
		mov dl, 16
		add edi, 16

	CoreEncrypt_A:
		sub edi, 1
		mov bh, byte ptr [esi]
		sub bh, byte ptr [edi]
		mov byte ptr [esi], bh

		mov bh, byte ptr [esi - 1]
		sub bh, byte ptr [edi - 1]
		mov byte ptr [esi - 1], bh

		mov bh, byte ptr [esi - 2]
		sub bh, byte ptr [edi - 2]
		mov byte ptr [esi - 2], bh

		mov bh, byte ptr [esi - 3]
		sub bh, byte ptr [edi - 3]
		mov byte ptr [esi - 3], bh

		mov bh, byte ptr [esi - 4]
		sub bh, byte ptr [edi - 4]
		mov byte ptr [esi - 4], bh

		mov bh, byte ptr [esi - 5]
		sub bh, byte ptr [edi - 5]
		mov byte ptr [esi - 5], bh

		mov bh, byte ptr [esi - 6]
		sub bh, byte ptr [edi - 6]
		mov byte ptr [esi - 6], bh

		mov bh, byte ptr [esi - 7]
		sub bh, byte ptr [edi - 7]
		mov byte ptr [esi - 7], bh

		sub cx, 8
		test cx, cx
		je CoreEncrypt_Schleife_Ende

		sub esi, 7
		mov edi, esi
		sub edi, 1

		mov bh, byte ptr [esi]
		xor bh, byte ptr [edi]
		mov byte ptr [esi], bh

		mov bh, byte ptr [esi + 1]
		xor bh, byte ptr [edi - 1]
		mov byte ptr [esi + 1], bh

		mov bh, byte ptr [esi + 2]
		xor bh, byte ptr [edi - 2]
		mov byte ptr [esi + 2], bh

		mov bh, byte ptr [esi + 3]
		xor bh, byte ptr [edi - 3]
		mov byte ptr [esi + 3], bh

		mov bh, byte ptr [esi + 4]
		xor bh, byte ptr [edi - 4]
		mov byte ptr [esi + 4], bh

		mov bh, byte ptr [esi + 5]
		xor bh, byte ptr [edi - 5]
		mov byte ptr [esi + 5], bh

		mov bh, byte ptr [esi + 6]
		xor bh, byte ptr [edi - 6]
		mov byte ptr [esi + 6], bh

		mov bh, byte ptr [esi + 7]
		xor bh, byte ptr [edi - 7]
		mov byte ptr [esi + 7], bh
		jmp CoreEncrypt_Schleife_Anfang

	CoreEncrypt_Schleife_Ende:
		pop esi
		pop edi
		pop ebx
		mov esp, ebp
		pop ebp
		ret 12
?KeyEncrypt@@YGXQAEPAEG@Z ENDP
;----------------------------------------------------------------------------
CS_Crypt ENDS
END