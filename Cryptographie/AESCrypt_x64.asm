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

CS_AES_Crypt SEGMENT EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT										
aqp_auc256Key = 40
?AES_CBC_Encrypt@@YQXPEBXPEAXKQEAE2@Z PROC PUBLIC
		mov rax, qword ptr aqp_auc256Key[rsp]
		test rax, rax
		je Ende
		test rcx, rcx
		je Ende
		test rdx, rdx
		je Ende
		test r9, r9
		je Ende
		movups xmm0, xmmword ptr [r9]
		test r8, r8
		je Ende
		cmp r8, 16
		jb Bytes_Crypt_Short
		sub r8, 16
		add r8, rcx

	Bytes_Crypt_Long:
		movups xmm1, xmmword ptr [rcx]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [rax]

		aesenc xmm0, xmmword ptr [rax + 10h]
		aesenc xmm0, xmmword ptr [rax + 20h]
		aesenc xmm0, xmmword ptr [rax + 30h]
		aesenc xmm0, xmmword ptr [rax + 40h]
		aesenc xmm0, xmmword ptr [rax + 50h]
		aesenc xmm0, xmmword ptr [rax + 60h]
		aesenc xmm0, xmmword ptr [rax + 70h]
		aesenc xmm0, xmmword ptr [rax + 80h]
		aesenc xmm0, xmmword ptr [rax + 90h]
		aesenc xmm0, xmmword ptr [rax + 0a0h]
		aesenc xmm0, xmmword ptr [rax + 0b0h]
		aesenc xmm0, xmmword ptr [rax + 0c0h]
		aesenc xmm0, xmmword ptr [rax + 0d0h]
		aesenclast xmm0, xmmword ptr [rax + 0e0h]

		movups xmmword ptr [rdx], xmm0

		add rcx, 16
		add rdx, 16
		cmp	rcx, r8
		jbe Bytes_Crypt_Long

		add r8, 16
		sub r8, rcx
		test r8, r8
		jz Ende

	Bytes_Crypt_Short:
		xor r10, r10
		xor r11, r11
	LastByte_PlanText:
		mov r11b, byte ptr [rcx + r10]
		mov byte ptr [rax + 0f0h + r10], r11b
		add r10, 1
		cmp r10, r8
		jb short LastByte_PlanText

		movaps xmm1, xmmword ptr [rax + 0f0h]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [rax]

		aesenc xmm0, xmmword ptr [rax + 10h]
		aesenc xmm0, xmmword ptr [rax + 20h]
		aesenc xmm0, xmmword ptr [rax + 30h]
		aesenc xmm0, xmmword ptr [rax + 40h]
		aesenc xmm0, xmmword ptr [rax + 50h]
		aesenc xmm0, xmmword ptr [rax + 60h]
		aesenc xmm0, xmmword ptr [rax + 70h]
		aesenc xmm0, xmmword ptr [rax + 80h]
		aesenc xmm0, xmmword ptr [rax + 90h]
		aesenc xmm0, xmmword ptr [rax + 0a0h]
		aesenc xmm0, xmmword ptr [rax + 0b0h]
		aesenc xmm0, xmmword ptr [rax + 0c0h]
		aesenc xmm0, xmmword ptr [rax + 0d0h]
		aesenclast xmm0, xmmword ptr [rax + 0e0h]

		xor r10, r10
	LastByte_ChipperText:
		mov r11b, byte ptr [rax + 0f0h + r10]
		mov byte ptr [rdx + r10], r11b
		add r10, 1
		cmp r10, r8
		jb short LastByte_ChipperText

	Ende:
		ret
?AES_CBC_Encrypt@@YQXPEBXPEAXKQEAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
_Text SEGMENT											
aqp_auc256Key = 40
?AES_CBC_Decrypt@@YQXPEBXPEAXKQEAE2@Z PROC PUBLIC
		mov rax, qword ptr aqp_auc256Key[rsp]
		test rax, rax
		jz Ende
		test rcx, rcx
		jz Ende
		test rdx, rdx
		jz Ende
		test r9, r9
		jz Ende
		movups xmm2, xmmword ptr [r9]
		test r8, r8
		jz Ende
		cmp r8, 16
		jb Bytes_Crypt_Short
		sub r8, 16
		add r8, rcx

	Bytes_Crypt_Long:
		movups xmm0, xmmword ptr [rcx]
		movups xmm1, xmm0
		pxor xmm0, xmmword ptr [rax]

		aesdec xmm0, xmmword ptr [rax + 10h]
		aesdec xmm0, xmmword ptr [rax + 20h]
		aesdec xmm0, xmmword ptr [rax + 30h]
		aesdec xmm0, xmmword ptr [rax + 40h]
		aesdec xmm0, xmmword ptr [rax + 50h]
		aesdec xmm0, xmmword ptr [rax + 60h]
		aesdec xmm0, xmmword ptr [rax + 70h]
		aesdec xmm0, xmmword ptr [rax + 80h]
		aesdec xmm0, xmmword ptr [rax + 90h]
		aesdec xmm0, xmmword ptr [rax + 0a0h]
		aesdec xmm0, xmmword ptr [rax + 0b0h]
		aesdec xmm0, xmmword ptr [rax + 0c0h]
		aesdec xmm0, xmmword ptr [rax + 0d0h]
		aesdeclast xmm0, xmmword ptr [rax + 224]

		pxor xmm0, xmm2
		movups xmmword ptr [rdx], xmm0
		movups xmm2, xmm1

		add rcx, 16
		add rdx, 16
		cmp	rcx, r8
		jbe Bytes_Crypt_Long

		add r8, 16
		sub r8, rcx
		test r8, r8
		jz Ende

	Bytes_Crypt_Short:
		xor r10, r10
		xor r11, r11
	LastByte_ChipperText:
		mov r11b, byte ptr [rcx + r10]
		mov byte ptr [rax + 240 + r10], r11b
		add r10, 1
		cmp r10, r8
		jb LastByte_ChipperText

		movaps xmm0, xmmword ptr [rax + 240]
		pxor xmm0, xmmword ptr [rax]

		aesdec xmm0, xmmword ptr [rax + 10h]
		aesdec xmm0, xmmword ptr [rax + 20h]
		aesdec xmm0, xmmword ptr [rax + 30h]
		aesdec xmm0, xmmword ptr [rax + 40h]
		aesdec xmm0, xmmword ptr [rax + 50h]
		aesdec xmm0, xmmword ptr [rax + 60h]
		aesdec xmm0, xmmword ptr [rax + 70h]
		aesdec xmm0, xmmword ptr [rax + 80h]
		aesdec xmm0, xmmword ptr [rax + 90h]
		aesdec xmm0, xmmword ptr [rax + 0a0h]
		aesdec xmm0, xmmword ptr [rax + 0b0h]
		aesdec xmm0, xmmword ptr [rax + 0c0h]
		aesdec xmm0, xmmword ptr [rax + 0d0h]
		aesdeclast xmm0, xmmword ptr [rax + 0e0h]

		xor r10, r10
	LastByte_DecryptText:
		mov r11b, byte ptr [rax + 240 + r10]
		mov byte ptr [rdx + r10], r11b
		add r10, 1
		cmp r10, r8
		jb LastByte_DecryptText

	Ende:
		ret
?AES_CBC_Decrypt@@YQXPEBXPEAXKQEAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
CS_AES_Crypt ENDS
;----------------------------------------------------------------------------
END
