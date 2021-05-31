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

INCLUDE ..\..\Include\CompSys_x64.inc
INCLUDE ..\..\Include\ADT_x64.inc

CS_AES_Crypt SEGMENT EXECUTE
;----------------------------------------------------------------------------
_Text SEGMENT
s_Bytes = 16

aqp_Key = 72 + s_Bytes

sqp_Vector = 56 + s_Bytes
sqp_Bytes = 48 + s_Bytes
sqp_PlainText = 40 + s_Bytes

sqp_Speicher = 4 + s_ShadowRegister
sdi_Bytes = 0 + s_ShadowRegister
?AES_CBC_Encrypt@@YQPEADPEBX0AEAKQEAE2@Z PROC PUBLIC
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

    mov r9, qword ptr sqp_Vector[rsp]
    movups xmm0, xmmword ptr [r9]

    mov r9, qword ptr aqp_Key[rsp]

	Bytes_Crypt:
    movups xmm1, xmmword ptr [rcx]
		pxor xmm0, xmm1
		pxor xmm0, xmmword ptr [r9]

		aesenc xmm0, xmmword ptr [r9 + 10h]
		aesenc xmm0, xmmword ptr [r9 + 20h]
		aesenc xmm0, xmmword ptr [r9 + 30h]
		aesenc xmm0, xmmword ptr [r9 + 40h]
		aesenc xmm0, xmmword ptr [r9 + 50h]
		aesenc xmm0, xmmword ptr [r9 + 60h]
		aesenc xmm0, xmmword ptr [r9 + 70h]
		aesenc xmm0, xmmword ptr [r9 + 80h]
		aesenc xmm0, xmmword ptr [r9 + 90h]
		aesenc xmm0, xmmword ptr [r9 + 0a0h]
		aesenc xmm0, xmmword ptr [r9 + 0b0h]
		aesenc xmm0, xmmword ptr [r9 + 0c0h]
		aesenc xmm0, xmmword ptr [r9 + 0d0h]
		aesenclast xmm0, xmmword ptr [r9 + 0e0h]

		movups xmmword ptr [r8], xmm0

		add rcx, 10h
		add r8, 10h
		cmp	rcx, rdx
		jb Bytes_Crypt

	Ende:
    add rsp, s_ShadowRegister + s_Bytes
		ret
?AES_CBC_Encrypt@@YQPEADPEBX0AEAKQEAE2@Z ENDP
_Text ENDS
;----------------------------------------------------------------------------
_Text SEGMENT		
aqp_Key = 72

sqp_Speicher = 64
sqp_Vector = 56
sqp_Bytes = 48
sqp_ChipperText = 40
?AES_CBC_Decrypt@@YQPEADPEBX0AEAKQEAE2@Z PROC PUBLIC
    sub rsp, s_ShadowRegister

    mov qword ptr sqp_Speicher[rsp], rcx

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
END
