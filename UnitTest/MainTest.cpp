#define BOOST_TEST_MODULE   securednfc

#include <boost\test\unit_test.hpp>
#include <boost\array.hpp>
#include <stdexcept>

#include "xkaes.h"

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
    boost::array<unsigned char,24> key = {{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                           0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                           0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
                                         }};
    xkaes aes(xkaes::bitlen192);
    BOOST_CHECK_NO_THROW( aes.set_key(key.data(),key.size()));
}

BOOST_AUTO_TEST_SUITE_END();