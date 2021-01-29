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
INCLUDELIB LIBCMTD
INCLUDELIB OLDNAMES

CS_AES_Crypt SEGMENT PRIVATE EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT
a_ulBytes = 16		
a_auc16IVec = 20												
a_auc256Key = 24
?AES_CBC_Encrypt@@YQXPBXPAXKQAE2@Z PROC PUBLIC
		push ebx
		push esi
		push edi

		mov ebx, dword ptr [esp + a_auc256Key]
		test ebx, ebx
		je Ende
		mov	esi, ecx
		test esi, esi
		je Ende
		mov	edi, edx
		test edi, edi
		je Ende
		mov	ecx, dword ptr [esp + a_auc16IVec]
		test ecx, ecx
		je Ende
		movups xmm0, xmmword ptr [ecx]
		mov	eax, dword ptr [esp + a_ulBytes]
		test eax, eax
		je Ende
		cmp eax, 10h
		jb Bytes_Crypt_Short
		sub eax, 10h
		add eax, esi

	Bytes_Crypt_Long:
		movups xmm1, xmmword ptr [esi]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [ebx]

		aesenc xmm0, xmmword ptr [ebx + 10h]
		aesenc xmm0, xmmword ptr [ebx + 20h]
		aesenc xmm0, xmmword ptr [ebx + 30h]
		aesenc xmm0, xmmword ptr [ebx + 40h]
		aesenc xmm0, xmmword ptr [ebx + 50h]
		aesenc xmm0, xmmword ptr [ebx + 60h]
		aesenc xmm0, xmmword ptr [ebx + 70h]
		aesenc xmm0, xmmword ptr [ebx + 80h]
		aesenc xmm0, xmmword ptr [ebx + 90h]
		aesenc xmm0, xmmword ptr [ebx + 0a0h]
		aesenc xmm0, xmmword ptr [ebx + 0b0h]
		aesenc xmm0, xmmword ptr [ebx + 0c0h]
		aesenc xmm0, xmmword ptr [ebx + 0d0h]
		aesenclast xmm0, xmmword ptr [ebx + 0e0h]

		movups xmmword ptr [edi], xmm0

		add esi, 10h
		add edi, 10h
		cmp	esi, eax
		jbe Bytes_Crypt_Long

		add eax, 10h
		sub eax, esi
		test eax, eax
		jz Ende

	Bytes_Crypt_Short:
		xor ecx, ecx
		xor edx, edx
	LastByte_PlanText:
		mov dl, byte ptr [esi + ecx]
		mov byte ptr [ebx + 0f0h + ecx], dl
		add ecx, 01h
		cmp ecx, eax
		jb short LastByte_PlanText

		movaps xmm1, xmmword ptr [ebx + 0f0h]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [ebx]

		aesenc xmm0, xmmword ptr [ebx + 10h]
		aesenc xmm0, xmmword ptr [ebx + 20h]
		aesenc xmm0, xmmword ptr [ebx + 30h]
		aesenc xmm0, xmmword ptr [ebx + 40h]
		aesenc xmm0, xmmword ptr [ebx + 50h]
		aesenc xmm0, xmmword ptr [ebx + 60h]
		aesenc xmm0, xmmword ptr [ebx + 70h]
		aesenc xmm0, xmmword ptr [ebx + 80h]
		aesenc xmm0, xmmword ptr [ebx + 90h]
		aesenc xmm0, xmmword ptr [ebx + 0a0h]
		aesenc xmm0, xmmword ptr [ebx + 0b0h]
		aesenc xmm0, xmmword ptr [ebx + 0c0h]
		aesenc xmm0, xmmword ptr [ebx + 0d0h]
		aesenclast xmm0, xmmword ptr [ebx + 0e0h]

		xor ecx, ecx
	LastByte_ChipperText:
		mov dl, byte ptr [ebx + 0f0h + ecx]
		mov byte ptr [edi + ecx], dl
		add ecx, 1
		cmp ecx, eax
		jb short LastByte_ChipperText

	Ende:
		pop	edi
		pop	esi
		pop	ebx
		ret	12
?AES_CBC_Encrypt@@YQXPBXPAXKQAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
_Text SEGMENT
a_ulBytes = 16
a_auc16IVec = 20												
a_auc256Key = 24
?AES_CBC_Decrypt@@YQXPBXPAXKQAE2@Z PROC PUBLIC
		push ebx
		push esi
		push edi

		mov ebx, dword ptr [esp + a_auc256Key]
		test ebx, ebx
		jz Ende
		mov esi, ecx
		test esi, esi
		jz Ende
		mov edi, edx
		test edi, edi
		jz Ende
		mov	ecx, dword ptr [esp + a_auc16IVec]
		test ecx, ecx
		jz Ende
		movups xmm2, xmmword ptr [ecx]
		mov	eax, dword ptr [esp + a_ulBytes]
		test eax, eax
		jz Ende
		cmp eax, 10h
		jb Bytes_Crypt_Short
		sub eax, 10h
		add eax, esi

	Bytes_Crypt_Long:
		movups xmm0, xmmword ptr [esi]
		movups xmm1, xmm0
		pxor xmm0, xmmword ptr [ebx]

		aesdec xmm0, xmmword ptr [ebx + 10h]
		aesdec xmm0, xmmword ptr [ebx + 20h]
		aesdec xmm0, xmmword ptr [ebx + 30h]
		aesdec xmm0, xmmword ptr [ebx + 40h]
		aesdec xmm0, xmmword ptr [ebx + 50h]
		aesdec xmm0, xmmword ptr [ebx + 60h]
		aesdec xmm0, xmmword ptr [ebx + 70h]
		aesdec xmm0, xmmword ptr [ebx + 80h]
		aesdec xmm0, xmmword ptr [ebx + 90h]
		aesdec xmm0, xmmword ptr [ebx + 0a0h]
		aesdec xmm0, xmmword ptr [ebx + 0b0h]
		aesdec xmm0, xmmword ptr [ebx + 0c0h]
		aesdec xmm0, xmmword ptr [ebx + 0d0h]
		aesdeclast xmm0, xmmword ptr [ebx + 0e0h]

		pxor xmm0, xmm2
		movups xmmword ptr [edi], xmm0
		movups xmm2, xmm1

		add esi, 10h
		add edi, 10h
		cmp	esi, eax
		jbe Bytes_Crypt_Long

		add eax, 10h
		sub eax, esi
		test eax, eax
		jz Ende

	Bytes_Crypt_Short:
		xor ecx, ecx
		xor edx, edx
	LastByte_ChipperText:
		mov dl, byte ptr [esi + ecx]
		mov byte ptr [ebx + 0f0h + ecx], dl
		add ecx, 1
		cmp ecx, eax
		jb LastByte_ChipperText

		movaps xmm0, xmmword ptr [ebx + 0f0h]
		pxor xmm0, xmmword ptr [ebx]

		aesdec xmm0, xmmword ptr [ebx + 10h]
		aesdec xmm0, xmmword ptr [ebx + 20h]
		aesdec xmm0, xmmword ptr [ebx + 30h]
		aesdec xmm0, xmmword ptr [ebx + 40h]
		aesdec xmm0, xmmword ptr [ebx + 50h]
		aesdec xmm0, xmmword ptr [ebx + 60h]
		aesdec xmm0, xmmword ptr [ebx + 70h]
		aesdec xmm0, xmmword ptr [ebx + 80h]
		aesdec xmm0, xmmword ptr [ebx + 90h]
		aesdec xmm0, xmmword ptr [ebx + 0a0h]
		aesdec xmm0, xmmword ptr [ebx + 0b0h]
		aesdec xmm0, xmmword ptr [ebx + 0c0h]
		aesdec xmm0, xmmword ptr [ebx + 0d0h]
		aesdeclast xmm0, xmmword ptr [ebx + 0e0h]

		xor ecx, ecx
	LastByte_DecryptText:
		mov dl, byte ptr [ebx + 0f0h + ecx]
		mov byte ptr [edi + ecx], dl
		add ecx, 1
		cmp ecx, eax
		jb LastByte_DecryptText

	Ende:
		pop	edi
		pop	esi
		pop	ebx
		ret	12
?AES_CBC_Decrypt@@YQXPBXPAXKQAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_AES_Crypt ENDS
;----------------------------------------------------------------------------
END