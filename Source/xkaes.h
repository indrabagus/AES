#ifndef XK_AES_H
#define XK_AES_H

#pragma once

#include <vector>
#include <stdexcept>
#include <algorithm>

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
        explicit Word(const ubyte_t pinput[4])
        {
            this->u.m_idata = (pinput[0] << 24) | (pinput[1] << 16) | (pinput[2] << 8) | pinput[3];
        }

        explicit Word(void) { /* do nothing */ }
        inline ubyte_t* data(void )
        {
            return this->u.m_data; 
        }

        inline void assign(const ubyte_t in[4]) 
        {
            this->u.m_idata = ((in[0] << 24 )| (in[1] << 16 ) | (in[2] << 8 ) | in[3]);
        }
        
        void subtitute();
        void rotate();

        Word& operator ^= (__int32 rhs)
        {
            this->u.m_idata = this->u.m_idata ^ rhs;
            return *this;
        }

        Word& operator ^= (const Word& rhs)
        {
            this->u.m_idata = this->u.m_idata ^ rhs.u.m_idata;
            return *this;
        }

        Word operator ^ (Word& rhs)
        {
            Word retval;
            retval.u.m_idata = this->u.m_idata ^ rhs.u.m_idata;
            return retval;
        }
        

        Word& operator = (const Word& rhs)
        {
            this->u.m_idata = rhs.u.m_idata;
            return *this;
        }

        ubyte_t& operator[](std::size_t index)
        {
            assert(index<4);
            /* dikarenakan endiannes = LITTLE ENDIAN */
            return u.m_data[3-index];
        }

    private:
        union{
            ubyte_t m_data[4];
            unsigned __int32 m_idata;
        } u;
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
    void addroundkey(std::vector<Word>& rstate,int beginkey);
    void subsbytes(std::vector<Word>& rstate);
    void shiftrow(std::vector<Word>& rstate);
    void mixcolumns(std::vector<Word>& rstate);
    void encrypt_block(ubyte_t* pout, ubyte_t* const pin);

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