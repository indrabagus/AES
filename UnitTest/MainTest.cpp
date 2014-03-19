#define BOOST_TEST_MODULE   securednfc

#include <boost\test\unit_test.hpp>
#include <boost\array.hpp>
#include <stdexcept>

#include "xkaes.h"


namespace cbcmmt0{

    boost::array<unsigned char,24> key = {{
        0xba,0x75,0xf4,0xd1,0xd9,0xd7,0xcf,0x7f,
        0x55,0x14,0x45,0xd5,0x6c,0xc1,0xa8,0xab,
        0x2a,0x07,0x8e,0x15,0xe0,0x49,0xdc,0x2c
    }};

    boost::array<unsigned char,16> iv = {{
        0x53,0x1c,0xe7,0x81,0x76,0x40,0x16,0x66,
        0xaa,0x30,0xdb,0x94,0xec,0x4a,0x30,0xeb
    }};

    boost::array<unsigned char,16> plaintext = {{
        0xc5,0x1f,0xc2,0x76,0x77,0x4d,0xad,0x94,
        0xbc,0xdc,0x1d,0x28,0x91,0xec,0x86,0x68
    }};

    boost::array<unsigned char,16> ciphertext = {{
        0x70,0xdd,0x95,0xa1,0x4e,0xe9,0x75,0xe2,
        0x39,0xdf,0x36,0xff,0x4a,0xee,0x1d,0x5d
    }};
};


namespace cbcmmt1{
    boost::array<unsigned char,24> key = {{
        0xea,0xb3,0xb1,0x9c,0x58,0x1a,0xa8,0x73,
        0xe1,0x98,0x1c,0x83,0xab,0x8d,0x83,0xbb,
        0xf8,0x02,0x51,0x11,0xfb,0x2e,0x6b,0x21
    }};

    boost::array<unsigned char,16> iv = {{
        0xf3,0xd6,0x66,0x7e,0x8d,0x4d,0x79,0x1e,
        0x60,0xf7,0x50,0x5b,0xa3,0x83,0xeb,0x05
    }};

    boost::array<unsigned char,32> plaintext = {{
        0x9d,0x4e,0x4c,0xcc,0xd1,0x68,0x23,0x21,
        0x85,0x6d,0xf0,0x69,0xe3,0xf1,0xc6,0xfa,
        0x39,0x1a,0x08,0x3a,0x9f,0xb0,0x2d,0x59,
        0xdb,0x74,0xc1,0x40,0x81,0xb3,0xac,0xc4
    }};

    boost::array<unsigned char,32> ciphertext = {{
        0x51,0xd4,0x47,0x79,0xf9,0x0d,0x40,0xa8,
        0x00,0x48,0x27,0x6c,0x03,0x5c,0xb4,0x9c,
        0xa2,0xa4,0x7b,0xcb,0x9b,0x9c,0xf7,0x27,
        0x0b,0x91,0x44,0x79,0x37,0x87,0xd5,0x3f        
    }};
};



BOOST_AUTO_TEST_SUITE(aes192testsuite)

    
BOOST_AUTO_TEST_CASE(setkeyerror)
{
    boost::array<unsigned char,16> key = {{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                          0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}};
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_THROW(aes.set_key(key.data(),key.size()),std::exception); 
}

BOOST_AUTO_TEST_CASE(setkeyerrornull)
{
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_THROW(aes.set_key(NULL,0),std::exception); 
}

BOOST_AUTO_TEST_CASE(setkeynothrow)
{
    boost::array<unsigned char,24> key = {{0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,
                                           0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
                                         }};
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW( aes.set_key(key.data(),key.size()));
}

BOOST_AUTO_TEST_CASE(setivnull)
{
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_THROW(aes.set_iv(NULL,0),std::exception);
}

BOOST_AUTO_TEST_CASE(setiverrorlen)
{
    boost::array<unsigned char,8> iv = {{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}};
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_THROW(aes.set_iv(iv.data(),iv.size()),std::exception);
}

BOOST_AUTO_TEST_CASE(setiv)
{
    boost::array<unsigned char,16> iv = {{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                          0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}};
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv(iv.data(),iv.size()));
}

BOOST_AUTO_TEST_CASE(setiv2)
{
    std::vector<unsigned char> iv(16);
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv(iv));
}

BOOST_AUTO_TEST_CASE(cbcmmt0encrypt)
{
    using namespace cbcmmt0;

    boost::array<unsigned char,16> result;

    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv(iv.data(),iv.size()));
    BOOST_CHECK_NO_THROW(aes.set_key(key.data(),key.size()));
    size_t size = aes.encrypt(result.data(),plaintext.data(),plaintext.size());
    BOOST_REQUIRE_EQUAL(size,ciphertext.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(ciphertext.begin(),ciphertext.end(),result.begin(),result.end());

}


BOOST_AUTO_TEST_CASE(cbcmmt1encrypt)
{
    boost::array<unsigned char,32> result;

    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv(cbcmmt1::iv.data(),cbcmmt1::iv.size()));
    BOOST_CHECK_NO_THROW(aes.set_key(cbcmmt1::key.data(),cbcmmt1::key.size()));
    size_t size = aes.encrypt(result.data(),
                             cbcmmt1::plaintext.data(),
                             cbcmmt1::plaintext.size());

    BOOST_REQUIRE_EQUAL(size,cbcmmt1::ciphertext.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(cbcmmt1::ciphertext.begin(),
                                  cbcmmt1::ciphertext.end(),
                                  result.begin(),
                                  result.end());

}

BOOST_AUTO_TEST_CASE(cbcmmt0_decrypt)
{

    boost::array<unsigned char,16> result;
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv( cbcmmt0::iv.data(),cbcmmt0::iv.size()));
    BOOST_CHECK_NO_THROW(aes.set_key(cbcmmt0::key.data(),cbcmmt0::key.size()));
    size_t size = aes.decrypt(result.data(),cbcmmt0::ciphertext.data(),cbcmmt0::ciphertext.size());
    BOOST_REQUIRE_EQUAL(size,cbcmmt0::plaintext.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(cbcmmt0::plaintext.begin(),cbcmmt0::plaintext.end(),result.begin(),result.end());

}

BOOST_AUTO_TEST_CASE(cbcmmt1decrypt)
{
    using namespace cbcmmt1;
    boost::array<unsigned char,32> result;

    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW(aes.set_iv(iv.data(),iv.size()));
    BOOST_CHECK_NO_THROW(aes.set_key(key.data(),key.size()));
    size_t size = aes.decrypt(result.data(),ciphertext.data(),ciphertext.size());
    BOOST_REQUIRE_EQUAL(size,plaintext.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(plaintext.begin(),plaintext.end(),
                                  result.begin(),result.end());

}

BOOST_AUTO_TEST_SUITE_END();



BOOST_AUTO_TEST_SUITE(aes256testsuite)

BOOST_AUTO_TEST_SUITE_END();
