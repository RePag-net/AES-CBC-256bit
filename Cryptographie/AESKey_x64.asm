;/****************************************************************************
;  AESKey_x64.asm
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

CS_AES_Key SEGMENT EXECUTE
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

		ret 0
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

		ret 0
AES_256_ASSIST_2 ENDP
;----------------------------------------------------------------------------
?AES_SetEncryptKey@@YQXPEAEQEAE@Z PROC PUBLIC
		test rcx, rcx
		jz Ende
		test rdx, rdx
		jz Ende

		movups xmm1, xmmword ptr [rcx]
		movaps xmmword ptr [rdx], xmm1
		movups xmm3, xmmword ptr [rcx + 10h]

		movaps xmmword ptr [rdx + 10h], xmm3
		aeskeygenassist xmm2, xmm3, 1
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 20h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 30h], xmm3
		aeskeygenassist xmm2, xmm3, 2
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 40h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 50h], xmm3	
		aeskeygenassist xmm2, xmm3, 4
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 60h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 70h], xmm3
		aeskeygenassist xmm2, xmm3, 8
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 80h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 90h], xmm3
		aeskeygenassist xmm2, xmm3, 16
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 0a0h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 0b0h], xmm3
		aeskeygenassist xmm2, xmm3, 32
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 0c0h], xmm1
		call AES_256_ASSIST_2

		movaps xmmword ptr [rdx + 0d0h], xmm3
		aeskeygenassist xmm2, xmm3, 64
		call AES_256_ASSIST_1

		movaps xmmword ptr [rdx + 0e0h], xmm1

	Ende:
		ret
?AES_SetEncryptKey@@YQXPEAEQEAE@Z ENDP
;----------------------------------------------------------------------------
_Text SEGMENT
aqp_auc240TempKey = 40
?AES_SetDecryptKey@@YQXPEAEQEAE1@Z PROC PUBLIC
		push rsi
		push rdi

		test rcx, rcx
		jz Ende
		mov rsi, rdx
		test rsi, rsi
		jz Ende
		mov rdi, qword ptr aqp_auc240TempKey[rsp]
		test rdi, rdi
		jz Ende

		mov rdx, rdi
		call ?AES_SetEncryptKey@@YQXPEAEQEAE@Z

		movaps xmm0, xmmword ptr [rdi]
		movaps xmmword ptr [rsi + 0e0h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 10h]
		movaps xmmword ptr [rsi + 0d0h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 20h]
		movaps xmmword ptr [rsi + 0c0h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 30h]
		movaps xmmword ptr [rsi + 0b0h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 40h]
		movaps xmmword ptr [rsi + 0a0h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 50h]
		movaps xmmword ptr [rsi + 90h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 60h]
		movaps xmmword ptr [rsi + 80h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 70h]
		movaps xmmword ptr [rsi + 70h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 80h]
		movaps xmmword ptr [rsi + 60h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 90h]
		movaps xmmword ptr [rsi + 50h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 0a0h]
		movaps xmmword ptr [rsi + 40h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 0b0h]
		movaps xmmword ptr [rsi + 30h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 0c0h]
		movaps xmmword ptr [rsi + 20h], xmm0

		aesimc xmm0, xmmword ptr [rdi + 0d0h]
		movaps xmmword ptr [rsi + 10h], xmm0

		movaps xmm0, xmmword ptr [rdi + 0e0h]
		movaps xmmword ptr [rsi], xmm0

	Ende:
		pop	rdi
		pop	rsi
		ret
?AES_SetDecryptKey@@YQXPEAEQEAE1@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_AES_Key ENDS
END
