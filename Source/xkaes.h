#ifndef XK_AES_H
#define XK_AES_H

#pragma once

#include <vector>
#include <stdexcept>

class xkaes
{

public:
    enum aeslen{
        bitlen128=128,
        bitlen192=192,
        bitlen256=256
    };

    enum aesmode{ ecb, cbc };


private:
    typedef std::vector<unsigned char> payload_t;
    typedef unsigned char ubyte_t;
    typedef ubyte_t aesword[4];
    typedef __int32 intword;
    typedef union {
        ubyte_t data[4];
        __int32 idata;
    }AESWORD;
    typedef std::vector<AESWORD> wordarray_t;
    typedef wordarray_t::iterator iterword_t;

private:
    class Word
    {
    public:
        explicit Word(const ubyte_t* pinput,size_t len)
        {
            std::copy(pinput,pinput+4,m_data);
            m_idata = (m_data[0] << 24) | (m_data[1] << 16) | (m_data[2] << 8) | m_data[3];
        }

        explicit Word(void) { /* do nothing */ }
        
        void subtitute();
        void rotate();

        Word& operator ^= (__int32 rhs)
        {
            m_idata = m_idata^rhs;
            return *this;
        }

        Word& operator ^ (Word& rhs)
        {
            m_idata = m_idata ^ rhs.m_idata;
            return *this;
        }
        

        Word& operator = (Word& rhs);

    private:
        ubyte_t m_data[4];
        unsigned __int32 m_idata;
    };

public:
    explicit xkaes(aeslen bitlen=bitlen128,aesmode mod=cbc);
    void set_iv(const void* piv,size_t len)throw(...);
    void set_iv(const std::vector<unsigned char>& vect);

    void set_key(const void* pkey, size_t len)throw(...);

    void set_key(const std::vector<unsigned char>& vect);

    /* dangerous function, since i assume the length of output buffer should be the same size of datalen */
    int encrypt(void* poutput,const void* indata, size_t datalen);
    int encrypt(std::vector<unsigned char>& out,const void* pinput, size_t len);

    int decrypt(void* poutput,const void* indata,size_t datalen);
    int decrypt(std::vector<unsigned char>& out,const void* pinput,size_t len);

private:
    void rotate_word(aesword inout);
    void subs_word(aesword inout);
    void key_expand(void);
    void add_roundkey(wordarray_t& inout,iterword_t begin, iterword_t end);
    void encrypt_block(payload_t::iterator out,payload_t::iterator in);

private:
    payload_t m_iv;
    payload_t m_key;
    aeslen m_bitlen;
    aesmode m_mode;
    std::vector<Word> m_expandkey;
    int m_rotation_num;
    int m_nr; // Number of rounds
    int m_nk; // Key length in words
    int m_nb; // Block size;

    static ubyte_t s_subs_box[256];
    static ubyte_t s_rsubs_box[256];
    static ubyte_t const_zero[16];
    static ubyte_t const_rb[16];
    static ubyte_t l_table[256];
    static ubyte_t e_table[256];
    static ubyte_t mul_matrix_decr[4][4];
    static ubyte_t mul_matrix_encr[4][4];
    static __int32 r_const[15];



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