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
s_Bytes = 8

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

		mov	ecx, dword ptr adauc_16IVec[esp]
		test ecx, ecx
		je Ende_Frei
		movups xmm0, xmmword ptr [ecx]

		mov ecx, dword ptr adauc_256Key[esp]
		test ecx, ecx
		je Ende_Frei

	Bytes_Crypt:
		movups xmm1, xmmword ptr [esi]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [ecx]

		aesenc xmm0, xmmword ptr [ecx + 10h]
		aesenc xmm0, xmmword ptr [ecx + 20h]
		aesenc xmm0, xmmword ptr [ecx + 30h]
		aesenc xmm0, xmmword ptr [ecx + 40h]
		aesenc xmm0, xmmword ptr [ecx + 50h]
		aesenc xmm0, xmmword ptr [ecx + 60h]
		aesenc xmm0, xmmword ptr [ecx + 70h]
		aesenc xmm0, xmmword ptr [ecx + 80h]
		aesenc xmm0, xmmword ptr [ecx + 90h]
		aesenc xmm0, xmmword ptr [ecx + 0a0h]
		aesenc xmm0, xmmword ptr [ecx + 0b0h]
		aesenc xmm0, xmmword ptr [ecx + 0c0h]
		aesenc xmm0, xmmword ptr [ecx + 0d0h]
		aesenclast xmm0, xmmword ptr [ecx + 0e0h]

		movups xmmword ptr [edi], xmm0

		add esi, 10h
		add edi, 10h
		cmp	esi, edx
		jb Bytes_Crypt
    jmp short Ende

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

    mov dword ptr sdp_Speicher[esp], ecx

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
END