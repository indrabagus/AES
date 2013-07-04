#include "aes.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>

static AES128 aes;
static const char* szplaintext = "Serang saat fajar!";
static const char* szkey       = "Janur Kuning";
static unsigned char plaintext[32];
static unsigned char decipher[32];
static unsigned char plaintext_recover[32];

static unsigned char ecb128_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 
    0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 
    0x09, 0xcf, 0x4f, 0x3c
};

enum verify_t { pass,fail };

static unsigned char ecb128_plaintext[4][16] = {
    { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
    { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51},
    { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
    { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }
};

static unsigned char ecb128_ciphertext[4][16] = {
    { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 },
    { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf },
    { 0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88 },
    { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 }
};

static verify_t verify_vector(unsigned char* arr_a,unsigned char* arr_b,int len)
{
    for(int idx=0;idx<len;++idx)
    {
        if((arr_a[idx] ^ arr_b[idx]) != 0 )
            return fail;
    }
    return pass;
}

static verify_t test_ecb_vectors(void)
{
    memcpy(aes.aeskey,ecb128_key,sizeof(ecb128_key));
    static unsigned char resultdata[16];
    aes.aes_mode = AES_MODE_ECB;
    // test encrypt
    for(int idx=0;idx < 4 ;++idx)
    {
        aes.p_input  = ecb128_plaintext[idx];
        aes.inlength = 16;
        aes.p_output = resultdata;
        aes.outlength = sizeof(resultdata);
        aes128_encipher(&aes);
        if(verify_vector(resultdata,ecb128_ciphertext[idx],16) == fail)
            return fail;
    }

    // test decrypt
    for(int idx=0;idx<4;++idx)
    {
        aes.p_input  = ecb128_ciphertext[idx];
        aes.inlength = 16;
        aes.p_output = resultdata;
        aes.outlength = sizeof(resultdata);
        aes128_decipher(&aes);
        if(verify_vector(resultdata,ecb128_plaintext[idx],16) == fail)
            return fail;
    }

    return pass;
}

static void example_usage(void)
{
    memcpy(aes.aeskey,szkey,16);
    memset(aes.initvector,0xDF,16);
    strcpy((char*)plaintext,szplaintext);
    aes.p_input = plaintext;
    aes.inlength= strlen(szplaintext);
    aes.p_output = decipher;
    aes.outlength = sizeof(decipher);
    aes.aes_mode = AES_MODE_CBC;

    aes128_encipher(&aes);

    aes.p_input = decipher;
    aes.inlength = sizeof(decipher);
    aes.p_output = plaintext_recover;
    aes.outlength=sizeof(plaintext_recover);
    aes128_decipher(&aes);

}

int main(){
#ifdef EXAMPLE_USAGE
    example_usage();
#endif
    verify_t result =  test_ecb_vectors();
    printf("RESULT : %s\n",(result==pass)?"PASS" : "FAIL");
    return result;
}