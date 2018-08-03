/* a simple test program of IDEA encryption and decryption. 
 * Author shenyang
 * */
#include <stdio.h>
#include <string.h>
#include "sm4.h"
#define MAX_SIZE 16 * 1024

void usage()
{
	printf("Usage: sm4 [-e(encrypt)|-d(decrypt)]\n");
}

void encrypt()
{
	unsigned char key[16];
  unsigned char input[MAX_SIZE];
  unsigned char output[MAX_SIZE];
  char str[MAX_SIZE * 2];
  sm4_context ctx;
  int len = 0, i;
  
  memset(input, 0, MAX_SIZE);
  memset(output, 0, MAX_SIZE);
  
  printf("\ninput plaintext(in hex):");
  scanf("%s", str);
	while(sscanf(str+len*2, "%02x", &(input[len]))!=EOF)
		len++;
  
  printf("\ninput 128-bit secret key(in hex):");
	scanf("%s", str);
  for(i = 0; i < 16; i++)
		sscanf(str+i*2, "%02x", &key[i]);
    
  //encrypt standard testing vector
	sm4_setkey_enc(&ctx,key);
	sm4_crypt_ecb(&ctx,SM4_ENCRYPT,len,input,output);
  printf("\nciphertext = ");
	for(i=0;i<len;i++)
		printf("%02x", output[i]);
	printf("\n");

}

void decrypt()
{
	unsigned char key[16];
  unsigned char input[MAX_SIZE];
  unsigned char output[MAX_SIZE];
  char str[MAX_SIZE * 2];
  sm4_context ctx;
  int len = 0, i;
  
  memset(input, 0, MAX_SIZE);
  memset(output, 0, MAX_SIZE);
  
  printf("\ninput ciphertext(in hex):");
  scanf("%s", str);
	while(sscanf(str+len*2, "%02x", &(input[len]))!=EOF)
		len++;
  
  printf("\ninput 128-bit secret key(in hex):");
	scanf("%s", str);
  for(i = 0; i < 16; i++)
		sscanf(str+i*2, "%02x", &key[i]);
    
  //encrypt standard testing vector
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_ecb(&ctx,SM4_DECRYPT,len,input,output);
  printf("\nplainnum = ");
	for(i=0;i<len;i++)
		printf("%02x", output[i]);
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
	switch(argv[1][1])
	{
		case 'e':
		case 'E': 
			encrypt();
			break;
		case 'd':
		case 'D':
			decrypt();
			break;
		default:
			usage();
			return 1;
	}
	return 0;
}
