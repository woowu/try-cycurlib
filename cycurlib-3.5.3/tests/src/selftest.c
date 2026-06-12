/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
    \file

   \brief Selftest of the CycurLIB for embedded use.

   The selftest is stored in a separate library,
   to allow optional combining and separation.

   This selftest follows the coding guidelines
   of the CycurLIB, i.e., MISRA-C:2012.

   $Rev: 4122 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "selftest.h"

/*************************************************************************************************
To remove a test case, remove the corresponding line of the include files.
*************************************************************************************************/
/* include headers from CycurLIB modules */
#include "selftest.h"
#include "arch_printf.h"
#include "test_types.h"
#include "test_aes_cbc.h"
#include "test_aes_cbc_mac.h"
#include "test_aes_ccm.h"
#include "test_aes_ctr.h"
#include "test_aes_eax.h"
#include "test_aes_ecb.h"
#include "test_aes_gcm.h"
#include "test_aes_key_wrap.h"
#include "test_aes_xts.h"
#include "test_blowfish_ecb.h"
#include "test_chacha20.h"
#include "test_chacha20_poly1305.h"
#include "test_cmac_aes.h"
#include "test_crc_32.h"
#include "test_der.h"
#include "test_des3_cbc.h"
#include "test_des3_ecb.h"
#include "test_cmac_des3.h"
#include "test_dh.h"
#include "test_ecc.h"
#include "test_ecc_kdf.h"
#include "test_ecies.h"
#include "test_eddsa.h"
#include "test_hash_drbg.h"
#include "test_hmac_ripemd_160.h"
#include "test_hmac_sha_1.h"
#include "test_hmac_sha_256.h"
#include "test_hmac_sha_512.h"
#include "test_poly1305.h"
#include "test_pkcs1_rsaes_oaep.h"
#include "test_pkcs1_rsaes_v15.h"
#include "test_pkcs1_rsassa_pss.h"
#include "test_pkcs1_rsassa_v15.h"
#include "test_random.h"
#include "test_ripemd_160.h"
#include "test_rsa.h"
#include "test_sha_1.h"
#include "test_sha_256.h"
#include "test_sha_512.h"
#include "test_sha_3.h"
#include "test_she_mp.h"
#include "test_whirlpool.h"
#include "test_x509.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
#if EscTst_ENABLE_LOGGING == 1
/* For debugging, we allow the use of printf */
#   include "arch_printf.h"
#   define ESCLIB_PRINTF printf
#endif

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
typedef struct
{
    /*lint -save -esym(754,test_case::name) if ESCLIB_PRINT is defined empty, this element is unused */
    Esc_CHAR name[32];
    Esc_ERROR (* TestFunction)(
        void );
} test_case;

static Esc_ERROR
EscTst_executeOneTest(
    const test_case* test );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
static Esc_ERROR
EscTst_executeOneTest(
    const test_case* test )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "\n\n************************************************************\n" );
    EscTst_PrintString( "* Testing " );
    EscTst_PrintString( test->name );
    EscTst_PrintString( "\n" );
    EscTst_PrintString( "************************************************************\n" );

    returnCode = test->TestFunction();

    EscTst_PrintString( "\n************************************************************\n" );
    EscTst_PrintString( "* Test " );
    EscTst_PrintString( test->name );
    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintString( " FAILED!!!\n" );
    }
    else
    {
        EscTst_PrintString( " returned successful\n" );
    }
    EscTst_PrintString( "************************************************************\n" );

    return returnCode;
}

Esc_ERROR
EscTst_Perform(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;

/*
   The test cases are sorted on the dependency. So if HMAC-SHA-1 fails, it has
   already been tested that SHA-1 works.
 */
    static const test_case test_cases[] =
    {
        /* This test case depends on nothing */
#ifdef ESC_TEST_TYPES_H_
        { "Types", EscTstTypes_Perform },
#endif

#ifdef ESC_TEST_AES_CBC_H_
        { "AES-CBC", EscTstAesCbc_Perform },
#endif

#ifdef ESC_TEST_AES_CBC_MAC_H_
        { "AES-CBC-MAC", EscTstAesCbcMac_Perform },
#endif

#ifdef ESC_TEST_AES_CTR_H_
        { "AES-CTR", EscTstAesCtr_Perform },
#endif

#ifdef ESC_TEST_AES_EAX_H_
        { "AES-EAX", EscTstAesEax_Perform },
#endif

#ifdef ESC_TEST_AES_ECB_H_
        { "AES-ECB", EscTstAesEcb_Perform },
#endif

#ifdef ESC_TEST_AES_CCM_H_
        { "AES-CCM", EscTstAesCcm_Perform },
#endif

#ifdef ESC_TEST_AES_GCM_H_
        { "AES-GCM", EscTstAesGcm_Perform },
#endif

#ifdef ESC_TEST_AES_KEY_WRAP_H_
        { "AES-KEY-WRAP", EscTstAesKeyWrap_Perform },
#endif

#ifdef ESC_TEST_CMAC_AES_H_
        { "CMAC-AES", EscTstCmacAes_Perform },
#endif

#ifdef ESC_TEST_AES_XTS_H_
        { "AES-XTS", EscTstAesXts_Perform },
#endif

#ifdef ESC_TEST_BLOWFISH_ECB_H_
        { "Blowfish-ECB", EscTstBfishEcb_Perform },
#endif

#ifdef ESC_TEST_CHACHA20_H_
        { "ChaCha20", EscTstChaCha20_Perform },
#endif

#ifdef  ESC_TEST_CRC_32_H_
        { "CRC-32", EscTstCrc32_Perform },
#endif

#ifdef ESC_TEST_DES3_ECB_H_
        { "3DES-ECB", EscTstDes3Ecb_Perform },
#endif

#ifdef ESC_TEST_DES3_CBC_H_
        { "3DES-CBC", EscTstDes3Cbc_Perform },
#endif

#ifdef ESC_TEST_DH_H_
        { "DH", EscTstDh_Perform },
#endif

#ifdef ESC_TEST_CMAC_DES3_H_
        { "CMAC-DES3", EscTstCmacDes3_Perform },
#endif

#ifdef ESC_TEST_ECC_H_
        { "ECC", EscTstEcc_Perform },
#endif

#ifdef ESC_TEST_ECC_KDF_H_
        { "ECC-KDF", EscTstEccKdf_Perform },
#endif

#ifdef ESC_TEST_EDDSA_H_
        { "EdDsa", EscTstEdDsa_Perform },
#endif

#ifdef ESC_TEST_SHA_1_H_
        { "SHA-1", EscTstSha1_Perform },
#endif

#ifdef ESC_TEST_SHA_256_H_
        { "SHA-224/SHA-256", EscTstSha256_Perform },
#endif

#ifdef ESC_TEST_SHA_512_H_
        { "SHA-384/SHA-512", EscTstSha512_Perform },
#endif

#ifdef ESC_TEST_SHA_3_H_
        { "SHA-3", EscTstSha3_Perform },
#endif

#ifdef ESC_TEST_SHE_MP_H_
        { "SHE-MP", EscTstSheMp_Perform },
#endif

#ifdef ESC_TEST_HASH_DRBG_H_
        { "HASH-DRBG", EscTstHashDrbg_Perform },
#endif

#ifdef ESC_TEST_RIPEMD_160_H_
        { "RIPEMD-160", EscTstRipemd160_Perform },
#endif

#ifdef ESC_TEST_RSA_H_
        { "RSA", EscTstRsa_Perform },
#endif

#ifdef ESC_TEST_DER_H_
        { "DER encoding", EscTstDer_Perform },
#endif

#ifdef ESC_TEST_PKCS1_RSAES_OAEP_H_
        { "RSAES OAEP", EscTstPkcs1RsaEsOaep_Perform },
#endif

#ifdef ESC_TEST_PKCS1_RSASSA_PSS_H_
        { "RSASSA PSS", EscTstPkcs1RsaSsaPss_Perform },
#endif

#ifdef ESC_TEST_PKCS1_RSASSA_V15_H_
        { "PKCS#1-V1.5", EscTstPkcs1RsaSsaV15_Perform },
#endif

#ifdef ESC_TEST_PKCS1_RSAES_V15_H_
        { "PKCS#1 RSAES V1.5", EscTstPkcs1RsaEsV15_Perform },
#endif

#ifdef ESC_TEST_WHIRLPOOL_H_
        { "Whirlpool", EscTstWhirlpool_Perform },
#endif

#ifdef ESC_TEST_X509_H_
        { "x.509", EscTstX509_Perform },
#endif

#ifdef  ESC_TEST_HMAC_RIPEMD_160_H_
        { "HMAC-RIPEMD-160", EscTstHmacRipemd160_Perform },
#endif

#ifdef ESC_TEST_HMAC_SHA_1_H_
        { "HMAC-SHA-1", EscTstHmacSha1_Perform },
#endif

#ifdef ESC_TEST_HMAC_SHA_256_H_
        { "HMAC-SHA-2-256", EscTstHmacSha256_Perform },
#endif

#ifdef ESC_TEST_HMAC_SHA_512_H_
        { "HMAC-SHA-2-512", EscTstHmacSha512_Perform },
#endif

#ifdef ESC_TEST_ECIES_H_
        { "ECIES", EscTstEcies_Perform },
#endif

#ifdef ESC_TEST_POLY1305_H_
        { "Poly1305", EscTstPoly1305_Perform },
#endif

#ifdef ESC_TEST_CHACHA20_POLY1305_H_
        { "ChaCha20_Poly1305", EscTstChaCha20Poly1305_Perform },
#endif
    };

    EscTst_PrintString( "*** CycurLIB: Performing internal selftest ***\n\n" );
#if Esc_HAS_INT64 == 1
    EscTst_PrintString( "Esc_HAS_INT64 is 1\n" );
#else
    EscTst_PrintString( "Esc_HAS_INT64 is 0\n" );
#endif

    EscTst_PrintString( "\n" );

    for (i = 0U; (returnCode == Esc_NO_ERROR) && ( i < ( sizeof(test_cases) / sizeof(test_cases[0]) ) ); i++)
    {
        returnCode = EscTst_executeOneTest( &test_cases[i] );
    }
    EscTst_PrintString( "\n" );

    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintString( "Selftest failed\n\n" );
    }
    else
    {
        EscTst_PrintString( "All tests successful\n\n" );
    }
    return returnCode;
}

Esc_BOOL
EscTst_Memcmp(
    const Esc_UINT8 mem1[],
    const Esc_UINT8 mem2[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;
    Esc_BOOL isEqual = TRUE;

    for (i = 0U; i < len; i++)
    {
        if (mem1[i] != mem2[i])
        {
            isEqual = FALSE;
            break;
        }
    }

    return isEqual;
}

Esc_BOOL
EscTst_Memcmp8_16(
    const Esc_UINT8 mem1[],
    const Esc_UINT16 mem2[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;
    Esc_UINT16 temp;
    Esc_BOOL isEqual = TRUE;

    for (i = 0U; i < len; i++)
    {
        temp = ( (Esc_UINT16)( (Esc_UINT16)mem1[(i * 2U) + 1U] << 8U ) | (Esc_UINT16)(mem1[i * 2U]) );
        if (temp != mem2[i])
        {
            isEqual = FALSE;
            break;
        }
    }

    return isEqual;
}

Esc_BOOL
EscTst_Memcmp8_32(
    const Esc_UINT8 mem1[],
    const Esc_UINT32 mem2[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;
    Esc_UINT32 temp;
    Esc_BOOL isEqual = TRUE;

    for (i = 0U; i < len; i++)
    {
        temp = ( (Esc_UINT32)( (Esc_UINT32)mem1[(i * 4U) + 3U] << 24U ) | (Esc_UINT32)( (Esc_UINT32)mem1[(i * 4U) + 2U] << 16U ) | (Esc_UINT32)( (Esc_UINT32)mem1[(i * 4U) + 1U] << 8U ) | (Esc_UINT32)(mem1[i * 4U]) );
        if (temp != mem2[i])
        {
            isEqual = FALSE;
            break;
        }
    }

    return isEqual;
}

Esc_BOOL
EscTst_MemcmpWord(
    const Esc_UINT32 mem1[],
    const Esc_UINT32 mem2[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;
    Esc_BOOL isEqual = TRUE;

    for (i = 0U; i < len; i++)
    {
        if (mem1[i] != mem2[i])
        {
            isEqual = FALSE;
            break;
        }
    }

    return isEqual;
}

Esc_BOOL
EscTst_MemIsZero(
    const Esc_UINT8 mem[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;
    Esc_BOOL isZero = TRUE;

    for (i = 0U; i < len; i++)
    {
        if (mem[i] != 0U)
        {
            isZero = FALSE;
            break;
        }
    }

    return isZero;
}

void
EscTst_Memset(
    Esc_UINT8 mem[],
    Esc_UINT32 len,
    Esc_UINT8 value )
{
    Esc_UINT32 i;

    for (i = 0U; i < len; i++)
    {
        mem[i] = value;
    }
}

void
EscTst_Memcpy(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[],
    Esc_UINT32 len )
{
    Esc_UINT32 i;

    for (i = 0U; i < len; i++)
    {
        dest[i] = source[i];
    }
}

Esc_UINT32
EscTst_Strlen(
    const Esc_CHAR s[] )
{
    Esc_UINT32 len = 0U;

    while (s[len] != '\0')
    {
        len++;
    }

    return len;
}

Esc_ERROR
EscTst_CheckResultSuccess(
    Esc_ERROR receivedResult )
{
    if (receivedResult == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Correct\n\n" );
    }
    else
    {
        EscTst_PrintString( "Expected return value: 0 ( no error )\n" );
        EscTst_PrintWord( "Received return value", (Esc_UINT32)receivedResult );

        EscTst_PrintString( "FAILED!!!\n\n" );
    }

    return receivedResult;
}

Esc_ERROR
EscTst_CheckResultFailed(
    Esc_ERROR* result,
    Esc_ERROR expectedResult )
{
    if ( (*result) == expectedResult )
    {
        EscTst_PrintString( "Correct\n\n" );
        *result = Esc_NO_ERROR;
    }
    else
    {
        EscTst_PrintWord( "Expected return value", (Esc_UINT32)expectedResult );
        EscTst_PrintWord( "Received return value", (Esc_UINT32)(*result) );

        EscTst_PrintString( "FAILED!!!\n\n" );
        if ( (*result) == Esc_NO_ERROR )
        {
            *result = Esc_KAT_FAILED;
        }
    }

    return *result;
}

Esc_ERROR
EscTst_CheckWords(
    Esc_UINT32 expected,
    Esc_UINT32 received )
{
    Esc_ERROR returnCode;

    EscTst_PrintWordHex( "Expected value", expected );
    EscTst_PrintWordHex( "Received value", received );

    if (expected == received)
    {
        EscTst_PrintString( "Correct\n\n" );
        returnCode = Esc_NO_ERROR;
    }
    else
    {
        EscTst_PrintString( "FAILED!!!\n\n" );
        returnCode = Esc_KAT_FAILED;
    }

    return returnCode;
}

Esc_ERROR
EscTst_CheckStrings(
    const Esc_UINT8 expected[],
    Esc_UINT32 expectedLen,
    const Esc_UINT8 received[],
    Esc_UINT32 receivedLen )
{
    Esc_ERROR returnCode;
    EscTst_PrintArray( "Expected value", expected, expectedLen );
    EscTst_PrintArray( "Received value", received, receivedLen );

    if (expectedLen == receivedLen)
    {
        if ( EscTst_Memcmp( expected, received, expectedLen ) )
        {
            EscTst_PrintString( "Correct\n\n" );
            returnCode = Esc_NO_ERROR;
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }
    else
    {
        EscTst_PrintString( "FAILED!!!\n\n" );
        returnCode = Esc_KAT_FAILED;
    }

    return returnCode;
}

/* Function to initialize an array */
void
EscTst_InitArray(
    Esc_UINT8 array[],
    Esc_UINT32 arrayLen )
{
    Esc_UINT32 i;

    for ( i = 0U; i < arrayLen; i++ )
    {
        array[i] = 0U;
    }
}

#if EscTst_ENABLE_LOGGING == 1
/* Functions to output debug messages */
void
EscTst_PrintString(
    const Esc_CHAR* msg )
{
    ESCLIB_PRINTF( "%s", msg );
}

void
EscTst_PrintWordOnly(
    Esc_UINT32 val )
{
    ESCLIB_PRINTF( "%lu", (unsigned long int)val );
}

void
EscTst_PrintWord(
    const Esc_CHAR* msg,
    Esc_UINT32 val )
{
    ESCLIB_PRINTF( "%s: %lu\n", msg, (unsigned long int)val );
}

void
EscTst_PrintWordHex(
    const Esc_CHAR* msg,
    Esc_UINT32 val )
{
    ESCLIB_PRINTF( "%s: 0x%08lx\n", msg, (unsigned long int)val );
}

void
EscTst_PrintArray(
    const Esc_CHAR* msg,
    const Esc_UINT8 arr[],
    Esc_UINT32 numBytes )
{
    Esc_UINT32 i;

    ESCLIB_PRINTF( "%s:\n\t", msg );
    for (i = 0U; i < numBytes; i++)
    {
        ESCLIB_PRINTF( "%02x ", arr[i] );
        if ( ((i % 16U) == 15U) && (i != (numBytes - 1)) )
        {
            ESCLIB_PRINTF( "\n\t" );
        }
    }

    ESCLIB_PRINTF( "\n" );
}

#endif /* EscTst_ENABLE_LOGGING */

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
