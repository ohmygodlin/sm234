/* a simple test program of IDEA encryption and decryption. 
 * Author shenyang
 * */
#include <stdio.h>
#include <string.h>
#include "sm4.h"
#define MAX_SIZE 16 * 1024

void usage()
{
	printf("Usage: sm4 [-e(encrypt)|-d(decrypt)|-c(cbc_encrypt)|-b(cdc_decrypt]\n");
}

unsigned char iv[16];
void read_iv()
{
  char str[20];
  int i;
  printf("\ninput 128-bit initial value:");
	scanf("%s", str);
  for(i = 0; i < 16; i++)
    sscanf(str+i*2, "%02x", &iv[i]);
}

#define PLAIN_STR "plain"
#define CIPHER_STR "cipher"

void crypt(int mode)
{
	unsigned char key[16];
  unsigned char input[MAX_SIZE];
  unsigned char output[MAX_SIZE];
  char str[MAX_SIZE * 2];
  sm4_context ctx;
  int len = 0, i;
  
  memset(input, 0, MAX_SIZE);
  memset(output, 0, MAX_SIZE);
  
  printf("\ninput %stext(in hex):", (mode == SM4_ENCRYPT) ? PLAIN_STR : CIPHER_STR);
  scanf("%s", str);
	while(sscanf(str+len*2, "%02x", &(input[len]))!=EOF)
		len++;
  
  printf("\ninput 128-bit secret key(in hex):");
	scanf("%s", str);
  for(i = 0; i < 16; i++)
		sscanf(str+i*2, "%02x", &key[i]);
    
  //encrypt standard testing vector
  if (mode == SM4_ENCRYPT)
    sm4_setkey_enc(&ctx,key);
  else
    sm4_setkey_dec(&ctx,key);
  
  if (strlen(iv))
    sm4_crypt_cbc(&ctx,mode,len,iv,input,output);
  else
    sm4_crypt_ecb(&ctx,mode,len,input,output);
  
  printf("\n%stext = ", (mode == SM4_ENCRYPT) ? CIPHER_STR : PLAIN_STR);
	for(i=0;i<len;i++)
		printf("%02x", output[i]);
	printf("\n");
  if (mode == SM4_DECRYPT)
    printf("\nplaintext = %s\n", output);
}

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		usage();
		return 1;
	}
	if(argv[1][0] != '-')
	{
		usage();
		return 1;
	}
  memset(iv, 0, sizeof(iv));
	switch(argv[1][1])
	{
    case 'c':
    case 'C':
      read_iv();
		case 'e':
		case 'E': 
			crypt(SM4_ENCRYPT);
			break;
		case 'b':
		case 'B':
      read_iv();
    case 'd':
		case 'D':
			crypt(SM4_DECRYPT);
			break;
		default:
			usage();
			return 1;
	}
	return 0;
}
