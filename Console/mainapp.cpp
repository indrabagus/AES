#include "aes.h"
#include <cstdlib>
#include <cstring>

static AES128 aes;
static const char* szplaintext = "Serang saat fajar!";
static const char* szkey       = "Janur Kuning";
static unsigned char plaintext[32];
static unsigned char decipher[32];
int main(){
    memcpy(aes.aeskey,szkey,16);
    memset(aes.initvector,0xDF,16);
    strcpy((char*)plaintext,szplaintext);
    aes.p_input = plaintext;
    aes.inlength= strlen(szplaintext);
    aes.p_output = decipher;
    aes.outlength = sizeof(decipher);
    aes.aes_mode = AES_MODE_CBC;
    aes128_encipher(&aes);

    return 0;
}