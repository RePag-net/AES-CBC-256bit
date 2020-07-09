/****************************************************************************
  AESCrypt_x86.h
  For more information see https://github.com/RePag/AES-CBC-256bit
****************************************************************************/

/****************************************************************************
  The MIT License(MIT)

  Copyright(c) 2020 René Pagel

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this softwareand associated documentation files(the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions :

  The above copyright noticeand this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
******************************************************************************/

#include <sal.h>
void __vectorcall AES_CBC_Encrypt(_In_ const void* pvPlainText, _In_ void* pvChipperText, _In_ unsigned long ulBytes,
																	_In_ unsigned char uc16IVec[16], _In_ unsigned char auc256Key[256]);
void __vectorcall AES_CBC_Decrypt(_In_ const void* pvChipperText, _In_ void* pvDecryptText, _In_ unsigned long ulBytes,
																	_In_ unsigned char uc16IVec[16], _In_ unsigned char auc256Key[256]);
void __vectorcall AES_SetEncryptKey(_In_ unsigned char* pucUserKey, _In_ unsigned char auc240Key[240]);
void __vectorcall AES_SetDecryptKey(_In_ unsigned char* pucUserKey, _In_ unsigned char auc256DecryptKey[256], _In_ unsigned char auc240EncryptKey[240]);