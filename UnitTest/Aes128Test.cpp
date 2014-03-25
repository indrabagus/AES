

#include "AesTest.h"

namespace aes128{

    namespace cbcmmt7{
        boost::array<unsigned char,16> key = {{
            0xc4,0x91,0xca,0x31,0xf9,0x17,0x08,0x45,
            0x8e,0x29,0xa9,0x25,0xec,0x55,0x8d,0x78
        }};

        boost::array<unsigned char,16> iv = {{
            0x9e,0xf9,0x34,0x94,0x6e,0x5c,0xd0,0xae,
            0x97,0xbd,0x58,0x53,0x2c,0xb4,0x93,0x81,
        }};
        
        
        boost::array<unsigned char,128> plaintext = {{         
            0xcb,0x6a,0x78,0x7e,0x0d,0xec,0x56,0xf9,
            0xa1,0x65,0x95,0x7f,0x81,0xaf,0x33,0x6c,
            0xa6,0xb4,0x07,0x85,0xd9,0xe9,0x40,0x93,
            0xc6,0x19,0x0e,0x51,0x52,0x64,0x9f,0x88,
            0x2e,0x87,0x4d,0x79,0xac,0x5e,0x16,0x7b,
            0xd2,0xa7,0x4c,0xe5,0xae,0x08,0x8d,0x2e,
            0xe8,0x54,0xf6,0x53,0x9e,0x0a,0x94,0x79,
            0x6b,0x1e,0x1b,0xd4,0xc9,0xfc,0xdb,0xc7,
            0x9a,0xcb,0xef,0x4d,0x01,0xee,0xb8,0x97,
            0x76,0xd1,0x8a,0xf7,0x1a,0xe2,0xa4,0xfc,
            0x47,0xdd,0x66,0xdf,0x6c,0x4d,0xbe,0x1d,
            0x18,0x50,0xe4,0x66,0x54,0x9a,0x47,0xb6,
            0x36,0xbc,0xc7,0xc2,0xb3,0xa6,0x24,0x95,
            0xb5,0x6b,0xb6,0x7b,0x6d,0x45,0x5f,0x1e,
            0xeb,0xd9,0xbf,0xef,0xec,0xbc,0xa6,0xc7,
            0xf3,0x35,0xcf,0xce,0x9b,0x45,0xcb,0x9d
        }};

        boost::array<unsigned char,128> ciphertext = {{ 
            0x7b,0x29,0x31,0xf5,0x85,0x5f,0x71,0x71,
            0x45,0xe0,0x0f,0x15,0x2a,0x9f,0x47,0x94,
            0x35,0x9b,0x1f,0xfc,0xb3,0xe5,0x5f,0x59,
            0x4e,0x33,0x09,0x8b,0x51,0xc2,0x3a,0x6c,
            0x74,0xa0,0x6c,0x1d,0x94,0xfd,0xed,0x7f,
            0xd2,0xae,0x42,0xc7,0xdb,0x7a,0xca,0xef,
            0x58,0x44,0xcb,0x33,0xae,0xdd,0xc6,0x85,
            0x25,0x85,0xed,0x00,0x20,0xa6,0x69,0x9d,
            0x2c,0xb5,0x38,0x09,0xce,0xfd,0x16,0x91,
            0x48,0xce,0x42,0x29,0x2a,0xfa,0xb0,0x63,
            0x44,0x39,0x78,0x30,0x6c,0x58,0x2c,0x18,
            0xb9,0xce,0x0d,0xa3,0xd0,0x84,0xce,0x4d,
            0x3c,0x48,0x2c,0xfd,0x8f,0xcf,0x1a,0x85,
            0x08,0x4e,0x89,0xfb,0x88,0xb4,0x0a,0x08,
            0x4d,0x5e,0x97,0x24,0x66,0xd0,0x76,0x66,
            0x12,0x6f,0xb7,0x61,0xf8,0x40,0x78,0xf2
        }};
        

    }; // End of namespace cbcmmt7


}; // End of namespace 128


BOOST_AUTO_TEST_SUITE(aes128testsuite)

    BOOST_AUTO_TEST_CASE(cbcmmt7decrypt)
    {
        using namespace aes128::cbcmmt7;
        boost::array<unsigned char,128> result;
        XK_AES aes(XK_AES::bitlen128);
        BOOST_CHECK_NO_THROW(aes.set_iv(iv.data(),iv.size()));
        BOOST_CHECK_NO_THROW(aes.set_key(key.data(),key.size()));
        size_t size = aes.decrypt(result.data(),ciphertext.data(),ciphertext.size());
        BOOST_REQUIRE_EQUAL(size,plaintext.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(plaintext.begin(),plaintext.end(),result.begin(),result.end());
    }


    BOOST_AUTO_TEST_CASE(cbcmmt7encrypt)
    {
        using namespace aes128::cbcmmt7;
        boost::array<unsigned char,128> result;
        XK_AES aes(XK_AES::bitlen128);
        BOOST_CHECK_NO_THROW(aes.set_iv(iv.data(),iv.size()));
        BOOST_CHECK_NO_THROW(aes.set_key(key.data(),key.size()));
        size_t size = aes.encrypt(result.data(),plaintext.data(),plaintext.size());
        BOOST_REQUIRE_EQUAL(size,ciphertext.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(ciphertext.begin(),ciphertext.end(),result.begin(),result.end());
    }

BOOST_AUTO_TEST_SUITE_END();
