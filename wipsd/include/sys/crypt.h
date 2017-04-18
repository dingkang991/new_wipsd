#ifndef __CRYPT_H__
#define __CRYPT_H__

#define MAX_KEY_LEN 16

char * input_toupper(char * input);
int do_crypt(char *filename, unsigned char *key);
int AesEncryptFile ( char * szSrc, char * szTarget ,	 char * key, int iType);
int AesDecryptFile ( char * szSrc, char * szTarget ,	 char * key, int iType);

#endif
