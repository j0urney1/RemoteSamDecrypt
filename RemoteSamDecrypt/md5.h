#include <Windows.h>
#ifndef _MD5_H
#define _MD5_H

typedef struct
{
	ULONG i[2];
	ULONG buf[4];
	UCHAR in[64];
	UCHAR digest[16];
}MD5_CTX;

VOID MD5Init(
	_Out_ MD5_CTX *Context
);

VOID MD5Update(
	_Inout_ MD5_CTX *Context,
	 BYTE *Input,
	_In_ ULONG Length
);

VOID MD5Final(
	_Inout_ MD5_CTX *Context
);

#endif
typedef struct _CRYPTO_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PBYTE Buffer;
} CRYPTO_BUFFER, *PCRYPTO_BUFFER;