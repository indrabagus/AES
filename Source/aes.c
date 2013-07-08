#include <memory.h>
#include "aes.h"

/* Number of round for 128 bit */
#define Nr_128      10
#define AESTRUE     1
#define AESFALSE    0


static const aesbyte_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, 
};

static aesbyte_t r_sbox[256] ={ 
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

static aesbyte_t r_const[15][4] = {
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00}, 
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00},
    {0x6C, 0x00, 0x00, 0x00},
    {0xD8, 0x00, 0x00, 0x00},
    {0xAB, 0x00, 0x00, 0x00},
    {0x4D, 0x00, 0x00, 0x00},
    {0x9A, 0x00, 0x00, 0x00}
};


static aesbyte_t mul_matrix_encr[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};


static aesbyte_t mul_matrix_decr[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09}, 
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E} 
};

static aesbyte_t e_table[256]={
    0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35,
    0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA,
    0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31,
    0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD,
    0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A,
    0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3,
    0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0,
    0xFB, 0x16, 0x3A, 0x4E, 0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41,
    0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75,
    0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80,
    0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43, 0xC5, 0x54,
    0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA,
    0x45, 0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E,
    0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17,
    0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01
};

static aesbyte_t l_table[256] = {
    0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03,
    0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1,
    0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78,
    0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E,
    0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA,
    0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57,
    0xAF, 0x58, 0xA8, 0x50, 0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8,
    0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0,
    0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7,
    0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55, 0x29, 0x9D,
    0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1,
    0x53, 0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB,
    0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5,
    0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07 
};

/* const RB dan const Zero digunakan saat proses penghitungan AES CMAC */
static aesbyte_t const_rb[16] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 
};


static aesbyte_t const_zero[16] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
};

static void 
xor_array(const aesbyte_t* arr_a,const aesbyte_t* arr_b,aesbyte_t* output,int len){
    int idx;
    for(idx=0;idx<len;++idx){
        output[idx]=arr_a[idx] ^ arr_b[idx];
    }
}


static void 
key_rotate(aesbyte_t inout[]){
    aesbyte_t a, idx;
    a=inout[0];
    for (idx=0;idx<3;++idx){
        inout[idx] = inout[idx+1];
    }
    inout[3]=a;
}

/*
 asumsi jumlah array yang diproses adalah 16
 */
static void 
addround_key(aesbyte_t* inout,const aesbyte_t* key){
    int idx;
    for(idx=0; idx < 16; ++idx){
        inout[idx] = inout[idx] ^ key[idx];
    }
}

static void 
rconst4byte(aesbyte_t* inout,int numround){
    int idx;
    for(idx=0;idx<4;++idx){
        inout[idx] = inout[idx] ^ r_const[numround][idx];
    }
}


/* Byte subtitution
   each value of the state is replaced with corresponding s_box*/
static void
byte_subtitution(aesbyte_t inout[],int numbyte){
    int idx = 0;
    for(idx;idx < numbyte; ++idx){
        inout[idx] = s_box[inout[idx]];
    }

}


static void
inverse_byte_subtitution(aesbyte_t* inout,int numbyte){
    int idx=0;
    for(idx;idx < numbyte;++idx){
        inout[idx] = r_sbox[inout[idx]];
    }
}


/*
 * Asumsi: 1. keyinput sebanyak 16 byte,jumlah roundnya adalah 10
 */
static int
key_expand(const aesbyte_t* keyinput,aesbyte_t* expandkey){
    aesbyte_t temp[4];
    aesbyte_t input[16];
    aesbyte_t* outputtrack;
    int idx;
    int jdx;
    int round = 1;
    memcpy(input,keyinput,16);
    memcpy(expandkey,keyinput,16);
    /* key yang digunakan adalah 128 bit = 10 putaran*/
    while(round < 11){
        outputtrack = &expandkey[16*round];
        // copy 4 byte terakhir
        memcpy(temp,&input[12],4);
        // rotasi 4 byte terakhir
        key_rotate(temp);
        // subtitusi dengan s-box
        byte_subtitution(temp,4);
        // xor dengan rconstant
        rconst4byte(temp,round-1);
        // xor tiap member dari key dengan temp hasil fungsi diatas
        for(idx=0;idx<4;++idx){
            for(jdx=0;jdx < 4; ++jdx){
                input[(idx*4)+jdx] = input[(idx*4)+jdx] ^ temp[jdx];
                temp[jdx] = input[(idx*4)+jdx];
            }
        }
        // Kopi hasil loop diatas ke satu baris output, ini menandakan hasil akhir dari 1 putaran
        memcpy(outputtrack,input,16);

        ++round;
    }
    return 0;
}

/*
 Fungsi untuk menggeser baris kearah kanan atau kearah kiri tergantung
 flag "is_inverse". Jika is_inverse=0 maka tiap baris 
 pada matrix akan digeser ke kiri sebanyak 1 (kecuali baris ke-0).
 Jika "is_inverse=1" maka tiap baris pada matrix akan digeser 
 ke kanan sebanyak 1 (kecuali baris ke-0)

 */
static void
shift_row(aesbyte_t inout[],int is_inverse){
    /* konversi dari row menjadi matrix 4x4
       e.g:
       00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       menjadi
       matrix [4][4] = {
       00,04,08,0c
       01,05,09,0d
       02,06,0a,0e
       03,07,0b,0f
       }
     */
    int row,col;
    aesbyte_t matrix_in[4][4];
    aesbyte_t matrix_out[4][4];
    for(row=0;row<4;++row){
        for(col=0;col<4;++col){
            matrix_in[col][row]=inout[(row*4)+col];
        }
    }


    for(row=0;row<4;++row){
        for(col=0;col<4;++col){
            matrix_out[row][col] = is_inverse ? matrix_in[row][((col-row) + 4) % 4] 
                                              : matrix_in[row][(col+row)%4];
        }
    }

    /* konversi ulang (terlihat tidak efisien) */
    for(row=0;row<4;++row){
        for(col=0;col<4;++col){
            inout[(row*4)+col] = matrix_out[col][row];
        }
    }
}

static aesbyte_t
galois_mul(aesbyte_t a, aesbyte_t b){
    unsigned int result;
    if((a==0) || (b==0))
        return 0;

    if(a==1)
        return b;

    if(b==1)
        return a;

    result = l_table[a] + l_table[b];
    if(result > 0xFF){
        result -= 0xFF;
    }
    result = e_table[result];

    return ((aesbyte_t) (result&0xFF));
}

static void 
mix_column(aesbyte_t* in, aesbyte_t* out,int is_inverse){
    int col,idx,ijx;
    aesbyte_t temp;
    for(col=0;col<4;++col){
        for(idx=0;idx<4;++idx){
            temp = 0x00;
            for(ijx=0;ijx<4;++ijx){
                if(is_inverse){
                    temp = temp ^ galois_mul(in[(col*4)+ijx],mul_matrix_decr[idx][ijx]);
                }else{
                    temp = temp ^ galois_mul(in[(col*4)+ijx],mul_matrix_encr[idx][ijx]);
                }
            }
            out[(col*4)+idx] = temp;
        }
    }
}

static void
round(aesbyte_t* inout, const aesbyte_t* expandedkey){
    aesbyte_t mixcol[16];
    byte_subtitution(inout,16);
    shift_row(inout,0);
    mix_column(inout,mixcol,0);
    addround_key(mixcol,expandedkey);
    memcpy(inout,mixcol,16);
}

static void
inverse_round(aesbyte_t* inout,const aesbyte_t* expandedkey){
    aesbyte_t mixcol[16];
    shift_row(inout,1);
    inverse_byte_subtitution(inout,16);
    addround_key(inout,expandedkey);
    mix_column(inout,mixcol,1);
    memcpy(inout,mixcol,16);

}

static void
inverse_finalround(aesbyte_t* inout, const aesbyte_t* expkey){
    shift_row(inout,1);
    inverse_byte_subtitution(inout,16);
    addround_key(inout,expkey);
}

static void 
final_round(aesbyte_t* inout, const aesbyte_t* expandedkey){
    byte_subtitution(inout,16);
    shift_row(inout,0);
    addround_key(inout,expandedkey);
}


int
aes_encrypt(const aesbyte_t* rawdata, const aesbyte_t* key, aesbyte_t* ciphered)
{
    int idx;
    static aesbyte_t expandedkey[11][16];
    key_expand(key,(aesbyte_t*)expandedkey);
    memcpy(ciphered,rawdata,16);
    addround_key(ciphered,expandedkey[0]);
    for(idx=1;idx<Nr_128;++idx){
        round(ciphered,expandedkey[idx]);
    }
    final_round(ciphered,expandedkey[10]);
    
    return 0;

}

int 
aes_decrypt(const aesbyte_t* ciphered, const aesbyte_t* key,aesbyte_t* raw){
    int idx;
    static aesbyte_t expandedkeydecr[11][16];
    memcpy(raw,ciphered,16);
    key_expand(key,(aesbyte_t*)expandedkeydecr);
    addround_key(raw,expandedkeydecr[10]);
    for(idx=9;idx>0;--idx){
        inverse_round(raw,expandedkeydecr[idx]);
    }
    inverse_finalround(raw,expandedkeydecr[0]);

    return 0;
    
}


int 
aes128_encipher(AES128* aes){
    int loop;
    aesbyte_t* piterinput;
    aesbyte_t* piteroutput;
    /* pointer yang digunakan saat mode CBC */
    aesbyte_t* pxorvector; 
    static aesbyte_t padblock[16];

    /* output buffer harus kelipatan 16 byte */
    if( (aes->outlength==0)   || 
        (aes->outlength % 16) || 
        (aes->outlength < aes->inlength)){
        return -1;
    }

    piterinput=aes->p_input;
    piteroutput=aes->p_output;
    pxorvector=aes->initvector;
    loop = (aes->inlength/16);
    while(loop>0){
        if(aes->aes_mode==AES_MODE_CBC){
            xor_array(piterinput,pxorvector,padblock,16);
            aes_encrypt(padblock,aes->aeskey,piteroutput);
            pxorvector = piteroutput;
        }else{
            aes_encrypt(piterinput,aes->aeskey,piteroutput);
        }

        piterinput+=16;
        piteroutput+=16;
        --loop;
    }
    /* enkripsi blok yg "terfragment"*/
    if(piterinput < (aes->p_input+aes->inlength)){
        memset(padblock,0x00,16);
        memcpy(padblock,piterinput,(aes->inlength % 16));
        if(aes->aes_mode==AES_MODE_CBC){
            xor_array(padblock,pxorvector,padblock,16);
        }
        aes_encrypt(padblock,aes->aeskey,piteroutput);
    }



    return 0;
}


int 
aes128_decipher(AES128* aes){
    int loop;
    aesbyte_t* piterinput;
    aesbyte_t* piteroutput;
    /* pointer yang digunakan saat mode CBC */
    aesbyte_t* pxorvector; 
    static aesbyte_t padblock[16];

    /* output buffer harus kelipatan 16 byte */
    if( (aes->outlength==0)   || 
        (aes->outlength % 16) || 
        (aes->outlength < aes->inlength)){
        return -1;
    }

    piterinput=aes->p_input;
    piteroutput=aes->p_output;
    pxorvector=aes->initvector;
    loop = (aes->inlength/16);
    while(loop){
        if(aes->aes_mode==AES_MODE_CBC){
            aes_decrypt(piterinput,aes->aeskey,padblock);
            xor_array(padblock,pxorvector,piteroutput,16);
            pxorvector = piterinput;
        }else{
            aes_decrypt(piterinput,aes->aeskey,piteroutput);
        }
        piterinput+=16;
        piteroutput+=16;
        --loop;
    }

    return 0;
}


/*
    10000...n padded output of input x
    example:
    input : C0 FF EE
    output: C0 FF EE 80 00 00 00 00 .... 00
*/
static void
aesmac_padding(const aesbyte_t* input,aesbyte_t* padding,int inputlen){
    memcpy(padding,input,inputlen);
    padding[inputlen] = 0x80;
    memset(&padding[inputlen+1],0x00,15-inputlen);
}

static void 
aesmac_leftshift1bit(const aesbyte_t* input, aesbyte_t* output){
    int idx;
    aesbyte_t overflow = 0;
    for(idx=15;idx>=0;--idx){
        output[idx] = input[idx] << 1;
        output[idx] |= overflow;
        overflow = (input[idx] & 0x80) ? 1:0;
    }
}


static void 
aesmac_gen_subkey(const aesbyte_t* key,aesbyte_t* k1,aesbyte_t* k2){
    aesbyte_t input[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    aesbyte_t ciphered[16];
    aesbyte_t temp[16];
    aes_encrypt(input,key,ciphered);
    if(( ciphered[0] & 0x80 ) == 0) { /* MSB(L) = 0 then K1 = L << 1 */
        aesmac_leftshift1bit(ciphered,k1);
    }else{ /* K1 = (L<<1) ^ Rb */
        aesmac_leftshift1bit(ciphered,temp);
        xor_array(temp,ciphered,k1,16);
    }

    if((k1[0] & 0x80) == 0){
        aesmac_leftshift1bit(k1,k2);
    }else{
        aesmac_leftshift1bit(k1,temp);
        xor_array(temp,k1,k2,16);
    }


}


int 
aescmac_generate(AES128* paes){
    aesbyte_t subkey_k1[16],subkey_k2[16],m_last[16];
    aesbyte_t X[16],Y[16],padded[16];
    int numround;
    int flagfragment = 0;
    /* generate 2 subkey */
    aesmac_gen_subkey(paes->aeskey,subkey_k1,subkey_k2);
    /* Tentukan jumlah putaran proses per blok data ( 16 byte ) */
    numround = (paes->inlength + 15 ) / 16;
    if(numround == 0)
        numround = 1;

    /* tentukan apakah butuh padding (16 byte) atau tidak */
    flagfragment = ((paes->inlength % 16) != 0 ) ? 1 : 0;

    /* jika panjang data input genap kelipatan 16 byte maka blok terakhir
       pada data input di-XOR dengan subkey k1, hasil dari xor ini akan digunakan
       pada akhir putaran AES CMAC
     */
    if(flagfragment == 0){
        xor_array(paes->p_input[16*(numround-1)],subkey_k1,m_last,16);
    }else{
        aesmac_padding(paes->p_input[16*(numround-1)],padded,paes->inlength%16);
        xor_array(padded,subkey_k2,m_last,16);
    }


    return 0;
}

