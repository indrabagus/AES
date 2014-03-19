#include <algorithm>
#include <cassert>
#include "xkaes.h"

#define ROTATE_WORD(aesword) ((aesword << 8)|((aesword >> 24) & 0xFF))
#define MAKE_WORD(a,b,c,d) ((a << 24) | (b << 16)| (c << 8)| d )


    
xkaes::ubyte_t xkaes::s_subs_box[256] = {
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



xkaes::ubyte_t xkaes::s_rsubs_box[256] = {
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





__int32 xkaes::r_const[15] = {
    0x01000000,
    0x02000000, 
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
    0x6C000000,
    0xD8000000,
    0xAB000000,
    0x4D000000,
    0x9A000000
};

xkaes::ubyte_t xkaes::mul_matrix_encr[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};


xkaes::ubyte_t xkaes::mul_matrix_decr[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09}, 
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E} 
};

xkaes::ubyte_t xkaes::e_table[256]={
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

xkaes::ubyte_t xkaes::l_table[256] = {
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
xkaes::ubyte_t xkaes::const_rb[16] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 
};


xkaes::ubyte_t xkaes::const_zero[16] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
};


void xkaes::Word::subtitute()
{
    this->u.m_data[0] = xkaes::s_subs_box[this->u.m_data[0]];
    this->u.m_data[1] = xkaes::s_subs_box[this->u.m_data[1]];
    this->u.m_data[2] = xkaes::s_subs_box[this->u.m_data[2]];
    this->u.m_data[3] = xkaes::s_subs_box[this->u.m_data[3]];
}

void xkaes::Word::invsubtitute()
{
    this->u.m_data[0] = xkaes::s_rsubs_box[this->u.m_data[0]];
    this->u.m_data[1] = xkaes::s_rsubs_box[this->u.m_data[1]];
    this->u.m_data[2] = xkaes::s_rsubs_box[this->u.m_data[2]];
    this->u.m_data[3] = xkaes::s_rsubs_box[this->u.m_data[3]];
}


void xkaes::Word::rotate()
{
    /* WARNING assume we worked in LITTLE ENDIAN environment*/
    ubyte_t tmp = this->u.m_data[3];
    this->u.m_data[3]=this->u.m_data[2];
    this->u.m_data[2]=this->u.m_data[1];
    this->u.m_data[1]=this->u.m_data[0];
    this->u.m_data[0]=tmp;
}

xkaes::ubyte_t xkaes::Word::galoismult(ubyte_t a, ubyte_t b)
{
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

    return ((ubyte_t) (result & 0xFF));
}

/*

 As a result of this multiplication, the four bytes in a column are replaced by the following:

    | X0 |   | 0x02  0x03  0x01  0x01 |   | S0 |
    | X1 |   | 0x01  0x02  0x03  0x01 |   | S1 |
    | X2 | = | 0x01  0x01  0x02  0x03 | . | S2 |
    | X3 |   | 0x03  0x01  0x01  0x02 |   | S3 |
    
*/
void xkaes::Word::mixcolumntransform(void)
{
    static ubyte_t tmp[4];
    tmp[0] = galoismult(this->u.m_data[3],0x02) ^ 
             galoismult(this->u.m_data[2],0x03) ^ 
             this->u.m_data[1] ^ this->u.m_data[0];
    
    tmp[1] = this->u.m_data[3] ^ 
             galoismult(this->u.m_data[2],2) ^
             galoismult(this->u.m_data[1],3) ^
             this->u.m_data[0];

    tmp[2] = this->u.m_data[3] ^ 
             this->u.m_data[2] ^
             galoismult(this->u.m_data[1],2) ^
             galoismult(this->u.m_data[0],3);

    tmp[3] = galoismult(this->u.m_data[3],3) ^ 
             this->u.m_data[2] ^
             this->u.m_data[1] ^
             galoismult(this->u.m_data[0],2);

    this->u.m_data[3] = tmp[0];
    this->u.m_data[2] = tmp[1];
    this->u.m_data[1] = tmp[2];
    this->u.m_data[0] = tmp[3];

}
/*
    | S0 |   | 0x0e  0x0b  0x0d  0x09 |   | X0 |
    | S1 |   | 0x09  0x0e  0x0b  0x0d |   | X1 |
    | S2 | = | 0x0d  0x09  0x0e  0x0b | . | X2 |
    | S3 |   | 0x0b  0x0d  0x09  0x0e |   | X3 |

    catatan: Kita berada pada 'wilayah' Little endian 

*/
void xkaes::Word::invertmixcoltrans()
{
    static ubyte_t tmp[4];
    tmp[0] = galoismult(this->u.m_data[3],0x0e) ^ 
             galoismult(this->u.m_data[2],0x0b) ^ 
             galoismult(this->u.m_data[1],0x0d) ^ 
             galoismult(this->u.m_data[0],0x09);

    tmp[1] = galoismult(this->u.m_data[3],0x09) ^ 
             galoismult(this->u.m_data[2],0x0e) ^ 
             galoismult(this->u.m_data[1],0x0b) ^ 
             galoismult(this->u.m_data[0],0x0d);


    tmp[2] = galoismult(this->u.m_data[3],0x0d) ^ 
             galoismult(this->u.m_data[2],0x09) ^ 
             galoismult(this->u.m_data[1],0x0e) ^ 
             galoismult(this->u.m_data[0],0x0b);

    tmp[3] = galoismult(this->u.m_data[3],0x0b) ^ 
             galoismult(this->u.m_data[2],0x0d) ^ 
             galoismult(this->u.m_data[1],0x09) ^ 
             galoismult(this->u.m_data[0],0x0e);

    this->u.m_data[3] = tmp[0];
    this->u.m_data[2] = tmp[1];
    this->u.m_data[1] = tmp[2];
    this->u.m_data[0] = tmp[3];

}

xkaes::xkaes(aeslen bitlen,aesmode mod)
    :m_bitlen(bitlen)
    ,m_mode(mod)
    ,m_iv(4)
    ,m_key(bitlen/8)
    ,m_nb(4)
{
    switch(bitlen)
    {
    case bitlen128:
        m_nr= 10;
        m_nk = 4;
    break;

    case bitlen192:
        m_nr = 12;
        m_nk = 6;
        break;
    case bitlen256:
        m_nr = 14;
        m_nk = 8;
        break;
    }
    
    m_expandkey.resize(m_nb*(m_nr+1));

}


void xkaes::key_expand(void)
{
    xkaes::Word tmp;
    int i = 0;
    int totalexpkey=m_nb*(m_nr+1);
    while(i<m_nk){
        m_expandkey[i] = Word(&m_key[4*i]);
        ++i;
    }
    i = m_nk;
    while(i<totalexpkey)
    {
        tmp = m_expandkey[i-1];
        if((i % m_nk) == 0){
            // do rotation
            tmp.rotate();
            tmp.subtitute();
            tmp ^= r_const[i/m_nk-1];
        }
        else if((m_nk > 6) && ((i % m_nk) == 4))
        {
            tmp.subtitute();
        }
        m_expandkey[i]  = m_expandkey[i-m_nk] ^ tmp;
        ++i;
    }
}

void xkaes::set_iv(const void* piv, size_t len)
{
    assert(m_iv.size() == 4);
    if(len != 16)
        throw std::length_error("IV length should be 16");

    ubyte_t* pbyte = (ubyte_t*)piv;
    std::vector<Word>::iterator iter = m_iv.begin();
    while(iter != m_iv.end())
    {
        iter->assign(pbyte);
        ++iter;
        pbyte += 4;
    }
}


void xkaes::set_iv(const std::vector<unsigned char>& vect)
{
    this->set_iv(vect.data(),vect.size());
}


void xkaes::set_key(const void* pkey, size_t len)
{
    if((len*8) != m_bitlen)
        throw std::length_error("Key len doesn't match with current AES bit len");
    ubyte_t* pbyte = (ubyte_t*)pkey;
    std::copy(pbyte,pbyte+len,m_key.begin());
    key_expand();
}


void xkaes::set_key(const std::vector<unsigned char>& vect)
{
    set_key(vect.data(),vect.size());
}


size_t xkaes::encrypt(void* poutput,const void* indata, size_t datalen)
{
    if(datalen % 16)
        throw std::length_error("Data len should multiple 16 bytes");

    ubyte_t* pdata = (ubyte_t*)indata;
    ubyte_t* piterout = (ubyte_t*)poutput;
    static std::vector<Word> winputs(4);
    static std::vector<Word>::iterator witer;
    for(int i = 0; i < datalen;i+=16)
    {
        witer = winputs.begin();
        while(witer != winputs.end()){
            witer->assign(pdata);
            pdata+=4;
            ++witer;
        }

        if(m_mode == cbc){
            winputs[0] = winputs[0] ^ m_iv[0];
            winputs[1] = winputs[1] ^ m_iv[1];
            winputs[2] = winputs[2] ^ m_iv[2];
            winputs[3] = winputs[3] ^ m_iv[3];
        }
        
        /* block encrypt */
        encrypt_block(winputs);

        /* jika cbc update iv-nya*/
        if(m_mode == cbc){
            m_iv[0] = winputs[0];
            m_iv[1] = winputs[1];
            m_iv[2] = winputs[2];
            m_iv[3] = winputs[3];
        }
        /* kembalikan dalam bentuk poutput*/
        witer = winputs.begin();
        while(witer != winputs.end()){
            std::copy(witer->data(),witer->data()+4,piterout);
            piterout+=4;
            ++witer;
        }

    } // end of big block aes data looping
    return datalen;
}


size_t xkaes::encrypt(std::vector<unsigned char>& out,const void* pinput, size_t len)
{
    return this->encrypt(out.data(),pinput,len);
}


/* TODO optimasi dumb algorithm CBC */
int xkaes::decrypt(void* poutput,const void* indata,size_t datalen)
{
    if(datalen % 16)
        throw std::length_error("Data len should multiple 16 bytes");

    ubyte_t* pdata = (ubyte_t*)indata;
    ubyte_t* piterout = (ubyte_t*)poutput;
    static std::vector<Word> winputs(4);
    static std::vector<Word> wivtemp(4);
    static std::vector<Word>::iterator witer;
    static std::vector<Word>::iterator witerivtemp;
    for(int i = 0; i < datalen;i+=16)
    {
        witer = winputs.begin();
        witerivtemp = wivtemp.begin();
        while(witer != winputs.end()){
            witer->assign(pdata);
            witerivtemp->assign(pdata);
            pdata+=4;
            ++witer;
            ++witerivtemp;
        }

        
        /* block encrypt */
        decrypt_block(winputs);

        if(m_mode == cbc){
            winputs[0] = winputs[0] ^ m_iv[0];
            winputs[1] = winputs[1] ^ m_iv[1];
            winputs[2] = winputs[2] ^ m_iv[2];
            winputs[3] = winputs[3] ^ m_iv[3];

            /* update IV */
            m_iv[0] = witerivtemp[0];
            m_iv[1] = witerivtemp[1];
            m_iv[2] = witerivtemp[2];
            m_iv[3] = witerivtemp[3];
        }


        /* jika cbc update iv-nya*/
        if(m_mode == cbc){

        }
        /* kembalikan dalam bentuk poutput*/
        witer = winputs.begin();
        while(witer != winputs.end()){
            std::copy(witer->data(),witer->data()+4,piterout);
            piterout+=4;
            ++witer;
        }

    } // end of big block aes data looping
    return datalen;
}


int xkaes::decrypt(std::vector<unsigned char>& out,const void* pinput,size_t len)
{
    return 0;
}

void xkaes::encrypt_block(std::vector<Word>& inoutstate)
{
    this->addroundkey(inoutstate,0);
    for(int rnd=1;rnd<m_nr;++rnd)
    {
        this->subsbytes(inoutstate);
        this->shiftrow(inoutstate);
        this->mixcolumns(inoutstate);
        this->addroundkey(inoutstate,(rnd*m_nb));
    }
    this->subsbytes(inoutstate);
    this->shiftrow(inoutstate);
    this->addroundkey(inoutstate,(m_nr*m_nb));

}


void xkaes::decrypt_block(std::vector<Word>& inoutstate)
{
    this->addroundkey(inoutstate,(m_nr*m_nb));
    for(int rnd = (m_nr-1);rnd>0;--rnd)
    {
        this->invertshiftrow(inoutstate);
        this->invertsubsbytes(inoutstate);
        this->addroundkey(inoutstate,(rnd*m_nb));
        this->invertmixcolumns(inoutstate);
    }
    this->invertshiftrow(inoutstate);
    this->invertsubsbytes(inoutstate);
    this->addroundkey(inoutstate,0);
}

 void xkaes::addroundkey(std::vector<Word>& rstate,int beginkey)
 {
     assert((beginkey) < (m_expandkey.size()-3));
     assert(rstate.size() == 4);
     std::vector<Word>::iterator iter = rstate.begin();
     int idx = beginkey;
     while(iter != rstate.end())
     {
         *iter ^= m_expandkey[idx];
         ++iter;
         ++idx;
     }
 }


 void xkaes::subsbytes(std::vector<Word>& rstate)
 {
     assert(rstate.size() == 4);
     std::vector<Word>::iterator iter = rstate.begin();
     while(iter != rstate.end())
     {
         iter->subtitute();
         ++iter;
     }
 }

void xkaes::invertsubsbytes(std::vector<Word>& rstate)
{
    assert(rstate.size() == 4);
    std::vector<Word>::iterator iter = rstate.begin();
    while(iter != rstate.end()){
        iter->invsubtitute();
        ++iter;
    }
}

/*
 Menggeser matrik data ke arah 'kiri' sesuai dengan skema berikut ini

 input data = { {00,10,20,30} {01,11,21,31}, { 02,12,22,32}, {03,13,23,33} }

 | 00  01  02  03 |         | 00  01  02  03 |
 | 10  11  12  13 |   -->   | 11  12  13  10 |
 | 20  21  22  23 |   -->   | 22  23  20  21 |
 | 30  31  32  33 |   -->   | 33  30  31  32 |


 */
 void xkaes::shiftrow(std::vector<Word>& rstate)
 {
     /* dumb and lazy implementation */
     static ubyte_t temp[2];
     temp[0] = rstate[0][1];
     rstate[0][1] = rstate[1][1];
     rstate[1][1] = rstate[2][1];
     rstate[2][1] = rstate[3][1];
     rstate[3][1] = temp[0];

     temp[0] = rstate[0][2];temp[1]=rstate[1][2];
     rstate[0][2] = rstate[2][2];
     rstate[1][2] = rstate[3][2];
     rstate[2][2] = temp[0];
     rstate[3][2] = temp[1];
     
     temp[0] = rstate[3][3];
     rstate[3][3] = rstate[2][3];
     rstate[2][3] = rstate[1][3];
     rstate[1][3] = rstate[0][3];
     rstate[0][3] = temp[0];
 }


 /* serupa dengan proses shiftrow diatas, tapi dibalik */
 void xkaes::invertshiftrow(std::vector<Word>& rstate)
 {
     /* Another dumb and lazy implementation */
     static ubyte_t temp[2];
     temp[0] = rstate[3][1];
     rstate[3][1] = rstate[2][1];
     rstate[2][1] = rstate[1][1];
     rstate[1][1] = rstate[0][1];
     rstate[0][1] = temp[0];

     temp[0] = rstate[2][2];temp[1]=rstate[3][2];
     rstate[2][2] = rstate[0][2];
     rstate[3][2] = rstate[1][2];
     rstate[0][2] = temp[0];
     rstate[1][2] = temp[1];

     temp[0] = rstate[0][3];
     rstate[0][3] = rstate[1][3];
     rstate[1][3] = rstate[2][3];
     rstate[2][3] = rstate[3][3];
     rstate[3][3] = temp[0];
 }

void xkaes::mixcolumns(std::vector<Word>& rstate)
{
    std::vector<Word>::iterator iter = rstate.begin();
    while(iter != rstate.end()){
        iter->mixcolumntransform();
        ++iter;
    }
}

void xkaes::invertmixcolumns(std::vector<Word>& rstate)
{
    std::vector<Word>::iterator iter = rstate.begin();
    while(iter != rstate.end())
    {
        iter->invertmixcoltrans();
        ++iter;
    }
}

