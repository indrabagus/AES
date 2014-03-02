#ifndef XK_AES_H
#define XK_AES_H

#pragma once

#include <vector>
#include <stdexcept>

class xkaes
{
    enum aeslen{
        bitlen128=128,
        bitlen192=192,
        bitlen256=256
    };

    enum aesmode{ ecb, cbc };

    typedef std::vector<unsigned char> payload_t;
    typedef unsigned char ubyte_t;

public:
    explicit xkaes(aeslen bitlen=bitlen128,aesmode mod=cbc);
    void set_iv(const void* piv,size_t len)throw(...);
    void set_iv(const std::vector<unsigned char>& vect);

    void set_key(const void* pkey, size_t len)throw(...);

    void set_key(const std::vector<unsigned char>& vect);

    /* dangerous function, since i assume the length of output buffer shouldbe the same size of datalen */
    int encrypt(void* poutput,const void* indata, size_t datalen);
    int encrypt(std::vector<unsigned char>& out,const void* pinput, size_t len);

    int decrypt(void* poutput,const void* indata,size_t datalen);
    int decrypt(std::vector<unsigned char>& out,const void* pinput,size_t len);

private:
    void key_rotate(ubyte_t inout[]);

private:
    payload_t m_iv;
    payload_t m_key;
    aeslen m_bitlen;
    aesmode m_mode;
    std::vector<payload_t> m_expandedkey;
    static ubyte_t s_subs_box[256];
    static ubyte_t s_rsubs_box[256];
    static ubyte_t const_zero[16];
    static ubyte_t const_rb[16];
    static ubyte_t l_table[256];
    static ubyte_t e_table[256];
    static ubyte_t mul_matrix_decr[4][4];
    static ubyte_t mul_matrix_encr[4][4];
    static ubyte_t r_const[15][4];



};


/*
    USAGE:
    ======
    xkaes xkaes(xkaes::bit192,xkaes::cbc);
    try{
        xkaes.set_iv(piv,ivlen);
        xkaes.set_key(pkey,keylen);
        xkaes.encrypt(output,static_cast<void*)(szdata.c_str())
    }catch(std::exception& ex){
        std::cout<<"exception occured, what="<<ex.what()<<std::endl;
    }
*/
#endif // XK_AES_H