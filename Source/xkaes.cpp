#include "xkaes.h"


xkaes::xkaes(aeslen bitlen,aesmode mod)
    :m_bitlen(bitlen)
    ,m_mode(mod)
{

}

void xkaes::set_iv(const void* piv,size_t len)
{
}

void xkaes::set_iv(const std::vector<unsigned char>& vect)
{}

void xkaes::set_key(const void* pkey, size_t len)
{}


void xkaes::set_key(const std::vector<unsigned char>& vect)
{}

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

