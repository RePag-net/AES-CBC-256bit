;/****************************************************************************
;  AESKey_x86.asm
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
INCLUDE listing.inc
.MODEL FLAT
INCLUDELIB LIBCMTD
INCLUDELIB OLDNAMES

CS_AES_Key SEGMENT PARA PRIVATE FLAT EXECUTE
;----------------------------------------------------------------------------
AES_256_ASSIST_1 PROC PRIVATE
		pshufd xmm0, xmm2, 255
		movaps xmm2, xmm0
		pslldq xmm1, 4
		movaps xmm4, xmm1
		pxor xmm1, xmm4
		pslldq xmm4, 4
		pxor xmm1, xmm4
		pslldq xmm4, 4
		pxor xmm1, xmm4
		pxor xmm1, xmm2

		ret
AES_256_ASSIST_1 ENDP
;----------------------------------------------------------------------------
AES_256_ASSIST_2 PROC PRIVATE
		aeskeygenassist xmm0, xmm1, 0
		movaps xmm4, xmm0
		pshufd xmm0, xmm4, 170
		movaps xmm2, xmm0
		pslldq xmm3, 4
		movaps xmm4, xmm3
		pxor xmm3, xmm4
		pslldq xmm4, 4
		pxor xmm3, xmm4
		pslldq xmm4, 4
		pxor xmm3, xmm4
		pxor xmm3, xmm2

		ret
AES_256_ASSIST_2 ENDP
;----------------------------------------------------------------------------
?AES_SetEncryptKey@@YQXPAEQAE@Z PROC PUBLIC
		test ecx, ecx
		jz Ende
		test edx, edx
		jz Ende

		movups xmm1, xmmword ptr [ecx]
		movaps xmmword ptr [edx], xmm1
		movups xmm3, xmmword ptr [ecx + 10h]

		movaps xmmword ptr [edx + 10h], xmm3
		aeskeygenassist xmm2, xmm3, 1
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 20h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 30h], xmm3
		aeskeygenassist xmm2, xmm3, 2
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 40h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 50h], xmm3	
		aeskeygenassist xmm2, xmm3, 4
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 60h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 70h], xmm3
		aeskeygenassist xmm2, xmm3, 8
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 80h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 90h], xmm3
		aeskeygenassist xmm2, xmm3, 16
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 0a0h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 0b0h], xmm3
		aeskeygenassist xmm2, xmm3, 32
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 0c0h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [edx + 0d0h], xmm3
		aeskeygenassist xmm2, xmm3, 64
		call AES_256_ASSIST_1

		movaps xmmword ptr [edx + 0e0h], xmm1

	Ende:
		ret	0
?AES_SetEncryptKey@@YQXPAEQAE@Z ENDP
;----------------------------------------------------------------------------
_Text SEGMENT
a_auc240TempKey = 12
?AES_SetDecryptKey@@YQXPAEQAE1@Z PROC PUBLIC
		push esi
		push edi

		test ecx, ecx
		jz Ende
		mov esi, edx
		test esi, esi
		jz Ende
		mov edi, dword ptr [esp + a_auc240TempKey]
		test edi, edi
		jz Ende

		mov edx, edi
		call ?AES_SetEncryptKey@@YQXPAEQAE@Z

		movaps xmm0, xmmword ptr [edi]
		movaps xmmword ptr [esi + 0e0h], xmm0

		aesimc xmm0, xmmword ptr [edi + 10h]
		movaps xmmword ptr [esi + 0d0h], xmm0

		aesimc xmm0, xmmword ptr [edi + 20h]
		movaps xmmword ptr [esi + 0c0h], xmm0

		aesimc xmm0, xmmword ptr [edi + 30h]
		movaps xmmword ptr [esi + 0b0h], xmm0

		aesimc xmm0, xmmword ptr [edi + 40h]
		movaps xmmword ptr [esi + 0a0h], xmm0

		aesimc xmm0, xmmword ptr [edi + 50h]
		movaps xmmword ptr [esi + 90h], xmm0

		aesimc xmm0, xmmword ptr [edi + 60h]
		movaps xmmword ptr [esi + 80h], xmm0

		aesimc xmm0, xmmword ptr [edi + 70h]
		movaps xmmword ptr [esi + 70h], xmm0

		aesimc xmm0, xmmword ptr [edi + 80h]
		movaps xmmword ptr [esi + 60h], xmm0

		aesimc xmm0, xmmword ptr [edi + 90h]
		movaps xmmword ptr [esi + 50h], xmm0

		aesimc xmm0, xmmword ptr [edi + 0a0h]
		movaps xmmword ptr [esi + 40h], xmm0

		aesimc xmm0, xmmword ptr [edi + 0b0h]
		movaps xmmword ptr [esi + 30h], xmm0

		aesimc xmm0, xmmword ptr [edi + 0c0h]
		movaps xmmword ptr [esi + 20h], xmm0

		aesimc xmm0, xmmword ptr [edi + 0d0h]
		movaps xmmword ptr [esi + 10h], xmm0

		movaps xmm0, xmmword ptr [edi + 0e0h]
		movaps xmmword ptr [esi], xmm0

	Ende:
		pop	edi
		pop	esi
		ret	4
?AES_SetDecryptKey@@YQXPAEQAE1@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_AES_Key ENDS
END