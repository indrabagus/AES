/*
 * AES
 * @author Indra Bagus <indra@xirkachipset.com>
 * 
 * Implementasi algoritma Advanced Encryption Standard 128 bit
 * dan algoritma untuk men-generate AES-CMAC 
 * ( AES Ciphered Based Message Authentication Code )
 */


#ifndef AES_H
#define AES_H
typedef void* AES_T;

#ifndef AESBYTE_T
typedef unsigned char aesbyte_t;
#endif

#define AES_MODE_CBC    0
#define AES_MODE_ECB    1

typedef struct aes_t{
    aesbyte_t*  p_input;
    int         inlength;
    aesbyte_t*  p_output;
    int         outlength;
    aesbyte_t   initvector[16];
    aesbyte_t   aeskey[16];
    int         aes_mode;
}AES128;

#ifdef __cplusplus
extern "C" {
#endif

int aes128_encipher(AES128* aes);
int aes128_decipher(AES128* aes);
int aescmac_generate(AES128* paes);

#ifdef __cplusplus
}
#endif


#endif