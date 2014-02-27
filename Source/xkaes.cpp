#include "xkaes.h"
#include <algorithm>

xkaes::xkaes(aeslen bitlen,aesmode mod)
    :m_bitlen(bitlen)
    ,m_mode(mod)
    ,m_iv(16)
    ,m_key(bitlen/8)
{
}

void xkaes::set_iv(const void* piv,size_t len)
{
    if(len != 16)
        throw std::length_error("Length IV should be 16 bytes");
    ubyte_t* pbyte = (ubyte_t*)piv;
    std::copy(pbyte,pbyte+16,m_iv.begin());

}

void xkaes::set_iv(const std::vector<unsigned char>& vect)
{
    if(vect.size() < 16)
        throw std::length_error("Length IV should be 16 byte");
    std::copy(vect.begin(),vect.end(),m_iv.begin());
}

void xkaes::set_key(const void* pkey, size_t len)
{
    if((len*8) != m_bitlen)
        throw std::length_error("Key len doesn't match with current AES bit len");
    ubyte_t* pbyte = (ubyte_t*)pkey;
    std::copy(pbyte,pbyte+len,m_key.begin());
}


void xkaes::set_key(const std::vector<unsigned char>& vect)
{
    if(vect.size() != m_key.size())
        throw std::length_error("Key len doesn't match with current AES bit len");
    std::copy(vect.begin(),vect.end(),m_key.begin());
}

int xkaes::encrypt(void* poutput,const void* indata, size_t datalen)
{
    return 0;
}

int xkaes::encrypt(std::vector<unsigned char>& out,const void* pinput, size_t len)
{
    return 0;
}

int xkaes::decrypt(void* poutput,const void* indata,size_t datalen)
{
    return 0;
}


int xkaes::decrypt(std::vector<unsigned char>& out,const void* pinput,size_t len)
{
    return 0;
}

