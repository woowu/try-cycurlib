/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-CBC Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_aes_cbc.h"
#include "selftest.h"
#include "aes_cbc.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Maximum size of test ciphertext and plaintext */
#define AES_MAX_TEST_LENGTH 80U

#define NUMBER_OF_AES_CBC_TESTCASES 2U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

typedef struct
{
    const Esc_UINT8     iv[16];
    const Esc_UINT8     key[EscAes_MAX_KEY_BYTES];
    const Esc_UINT8     cipher[AES_MAX_TEST_LENGTH];
    const Esc_UINT8     plain[AES_MAX_TEST_LENGTH];
    Esc_UINT32          length;
} EscTstAesCbc_Testcase;

static const Esc_UINT16 keySizes[] =
{
    128,
    192,
    256
};

/*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
static const EscTstAesCbc_Testcase aes_128_tests[] =
{
    {
        /* iv */
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* cipher */
        {
            0x69U, 0xc4U, 0xe0U, 0xd8U, 0x6aU, 0x7bU, 0x04U, 0x30U,
            0xd8U, 0xcdU, 0xb7U, 0x80U, 0x70U, 0xb4U, 0xc5U, 0x5AU
        },
        /* plain */
        {
            0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
            0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU
        },
        /* length */
        16U
    },

    {
        /* iv */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* cipher */
        {
            0xc6U, 0xa1U, 0x3bU, 0x37U, 0x87U, 0x8fU, 0x5bU, 0x82U,
            0x6fU, 0x4fU, 0x81U, 0x62U, 0xa1U, 0xc8U, 0xd8U, 0x79U,
            0xb5U, 0x8aU, 0x10U, 0x64U, 0xd8U, 0xacU, 0xa9U, 0x9bU,
            0xd9U, 0xb0U, 0x40U, 0x5bU, 0x85U, 0x45U, 0xf5U, 0xbbU,
            0xe3U, 0xe6U, 0x82U, 0x58U, 0x92U, 0x5aU, 0x82U, 0x0dU,
            0xb7U, 0x9dU, 0xd8U, 0xb6U, 0x53U, 0x22U, 0x77U, 0xa3U,
            0x39U, 0xd3U, 0xd4U, 0xc6U, 0x77U, 0x1dU, 0x16U, 0xc3U,
            0xf6U, 0x0eU, 0x8dU, 0xa0U, 0xd9U, 0x6aU, 0x6cU, 0xb7U,
            0x17U, 0x1fU, 0x68U, 0x88U, 0x81U, 0x2dU, 0x7aU, 0x9eU,
            0xd4U, 0xd1U, 0xeeU, 0x39U, 0x1dU, 0x1bU, 0xf0U, 0x8fU
        },
        /* plain */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* length */
        80U
    }
};

#if EscAes_MAX_KEY_BITS >= 192U
static const EscTstAesCbc_Testcase aes_192_tests[] =
{
    {
        /* iv */
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U
        },
        /* cipher */
        {
            0x00U, 0x60U, 0xbfU, 0xfeU, 0x46U, 0x83U, 0x4bU, 0xb8U,
            0xdaU, 0x5cU, 0xf9U, 0xa6U, 0x1fU, 0xf2U, 0x20U, 0xaeU
        },
        /* plain */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* length */
        16U
    },

    {
        /* iv */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U
        },
        /* cipher */
        {
            0x91U, 0x62U, 0x51U, 0x82U, 0x1cU, 0x73U, 0xa5U, 0x22U,
            0xc3U, 0x96U, 0xd6U, 0x27U, 0x38U, 0x01U, 0x96U, 0x07U,
            0x59U, 0xd3U, 0x16U, 0xdeU, 0x86U, 0x4fU, 0x79U, 0x5eU,
            0x8eU, 0xeaU, 0xcbU, 0x15U, 0x05U, 0x8eU, 0xd7U, 0x7eU,
            0xb2U, 0x34U, 0x63U, 0x57U, 0x5aU, 0x2bU, 0x73U, 0x3fU,
            0xf0U, 0x11U, 0x37U, 0xe7U, 0x1fU, 0x95U, 0x3dU, 0x94U,
            0x8bU, 0x42U, 0xd1U, 0xafU, 0xc9U, 0x23U, 0x2cU, 0xeeU,
            0xbaU, 0xaeU, 0x36U, 0xd0U, 0x4bU, 0x72U, 0x2aU, 0x39U,
            0xa4U, 0x1cU, 0x91U, 0xfbU, 0x6fU, 0x04U, 0x4bU, 0x37U,
            0x99U, 0x4dU, 0xfbU, 0x07U, 0xe6U, 0x40U, 0x97U, 0xa7U
        },
        /* plain */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* length */
        80U
    }
};
#endif

#if EscAes_MAX_KEY_BITS == 256U
static const EscTstAesCbc_Testcase aes_256_tests[] =
{
    {
        /* iv */
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
            0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
        },
        /* cipher */
        {
            0x5AU, 0x6EU, 0x04U, 0x57U, 0x08U, 0xFBU, 0x71U, 0x96U,
            0xF0U, 0x2EU, 0x55U, 0x3DU, 0x02U, 0xC3U, 0xA6U, 0x92U
        },
        /* plain */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* length */
        16U
    },

    {
        /* iv */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* key */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
            0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
        },
        /* cipher */
        {
            0xf2U, 0x90U, 0x00U, 0xb6U, 0x2aU, 0x49U, 0x9fU, 0xd0U,
            0xa9U, 0xf3U, 0x9aU, 0x6aU, 0xddU, 0x2eU, 0x77U, 0x80U,
            0x9aU, 0xe5U, 0x93U, 0x8fU, 0xd5U, 0x5aU, 0xc6U, 0x26U,
            0xf8U, 0x50U, 0x86U, 0x3eU, 0xa3U, 0x70U, 0x99U, 0xd4U,
            0xf5U, 0xb8U, 0x27U, 0xc9U, 0x2fU, 0x4eU, 0x43U, 0xe4U,
            0x36U, 0xffU, 0x4fU, 0x64U, 0x0fU, 0x3cU, 0xc0U, 0x5dU,
            0xbbU, 0x13U, 0x75U, 0x48U, 0xf5U, 0x03U, 0x86U, 0xf4U,
            0xcbU, 0xe7U, 0xe5U, 0x87U, 0x9cU, 0x0dU, 0x67U, 0xa9U,
            0x0fU, 0x2eU, 0x30U, 0x5dU, 0x80U, 0x86U, 0x91U, 0x92U,
            0xc7U, 0x78U, 0x31U, 0xf3U, 0x8aU, 0x35U, 0x59U, 0x4fU
        },
        /* plain */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
        },
        /* length */
        80U
    }
};
#endif

/*lint -restore */

static const EscTstAesCbc_Testcase* testcases[] =
{
    aes_128_tests,
#if EscAes_MAX_KEY_BITS >= 192U
    aes_192_tests,
#endif
#if EscAes_MAX_KEY_BITS == 256U
    aes_256_tests
#endif
};

static Esc_ERROR
EscTstAesCbc_DecrCompSplit(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_EncrCompSplit(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_DecrComp(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_EncrComp(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_InitParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_DecryptionParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_EncryptionParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_SetIVParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_EncryptIVChange(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbc_DecryptIVChange(
    Esc_UINT8 keyIndex );

typedef Esc_ERROR (
* EscTstAesCbc_TestFunctionsT )(
    Esc_UINT8 keyIndex );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbc_DecrComp(
    Esc_UINT8 keyIndex )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;

    EscTst_PrintString( "AES-CBC Decryption Compliance test (EscAes_DecryptCbc)\n" );

    for (i = 0U; (i < NUMBER_OF_AES_CBC_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstAesCbc_Testcase* testcase = &testcases[keyIndex][i];
        /* convert hex string to byte array */
        EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex]/8U );
        EscTst_PrintArray( "IV", testcase->iv, EscAes_BLOCK_BYTES );
        EscTst_PrintArray( "Ciphertext", testcase->cipher, testcase->length );
        EscTst_PrintArray( "Expected plaintext", testcase->plain, testcase->length );

        returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase->key, testcase->iv );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscAesCbc_Decrypt( &ctx, testcase->cipher, aes_buf, testcase->length );

            /* compare returnCodes */
            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", aes_buf, testcase->length );

                if ( EscTst_Memcmp( aes_buf, testcase->plain, testcase->length ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbc_DecrCompSplit(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase = &testcases[keyIndex][1];

    EscTst_PrintString( "AES-CBC Decryption Compliance test (EscAesCbc_Decrypt)\n" );

    EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex]/8U );
    EscTst_PrintArray( "IV", testcase->iv, EscAes_IV_BYTES );
    EscTst_PrintArray( "Ciphertext", testcase->cipher, testcase->length );
    EscTst_PrintArray( "Expected plaintext", testcase->plain, testcase->length );

    /* Initialize */
    EscTst_PrintString( "Calling EscAesCbc_Init()\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase->key, testcase->iv );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Decrypt first block */
        EscTst_PrintString( "Decrypting first 2 blocks with EscAesCbc_Decrypt()\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase->cipher, aes_buf, 2U * EscAes_BLOCK_BYTES );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            Esc_ASSERT( testcase->length == (5U * EscAes_BLOCK_BYTES) );          /* We have 5 blocks */

            /* Decrypt remaining blocks */
            EscTst_PrintString( "Decrypting remaining 3 blocks with EscAesCbc_Decrypt()\n" );
            returnCode = EscAesCbc_Decrypt( &ctx,
                    &testcase->cipher[2U * EscAes_BLOCK_BYTES],
                    &aes_buf[2U * EscAes_BLOCK_BYTES], 3U * EscAes_BLOCK_BYTES );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", aes_buf, testcase->length );
                if ( EscTst_Memcmp( aes_buf, testcase->plain, testcase->length ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbc_EncrCompSplit(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase = &testcases[keyIndex][1];

    EscTst_PrintString( "AES-CBC Encryption Compliance test (EscAesCbc_Encrypt)\n" );

    EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex]/8U );
    EscTst_PrintArray( "IV", testcase->iv, EscAes_IV_BYTES );
    EscTst_PrintArray( "Plaintext", testcase->plain, testcase->length );
    EscTst_PrintArray( "Expected ciphertext", testcase->cipher, testcase->length );

    /* Initialize */
    EscTst_PrintString( "Calling EscAesCbc_Init()\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase->key, testcase->iv );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Encrypt first block */
        EscTst_PrintString( "Encrypting first 2 blocks with EscAesCbc_Encrypt()\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase->plain, aes_buf, 2U * EscAes_BLOCK_BYTES );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            Esc_ASSERT( testcase->length == (5U * EscAes_BLOCK_BYTES) );          /* We have 5 blocks */

            /* Decrypt remaining blocks */
            EscTst_PrintString( "Encrypting remaining 3 blocks with EscAesCbc_Encrypt()\n" );
            returnCode = EscAesCbc_Encrypt( &ctx,
                    &testcase->plain[2U * EscAes_BLOCK_BYTES],
                    &aes_buf[2U * EscAes_BLOCK_BYTES],
                    3U * EscAes_BLOCK_BYTES );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", aes_buf, testcase->length );
                if ( EscTst_Memcmp( aes_buf, testcase->cipher, testcase->length ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_InitParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbc_Init parameter test on test case 0\n" );
    EscTst_PrintString( "With correct parameters\n" );

    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx == 0\n" );
        returnCode = EscAesCbc_Init( Esc_NULL_PTR, keySizes[keyIndex], testcase0->key, testcase0->iv );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "key == 0\n" );
        returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], Esc_NULL_PTR, testcase0->iv );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "iv == 0\n" );
        returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesCbc_Init( &ctx, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), testcase0->key, testcase0->iv );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_DecryptionParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbc_Decrypt parameter test on test case 0\n" );

    EscTst_PrintString( "Calling EscAesCbc_Init with correct parameters\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_Decrypt with correct parameters\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase0->cipher, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx == 0\n" );
        returnCode = EscAesCbc_Decrypt( Esc_NULL_PTR, testcase0->cipher, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "plain == 0\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase0->cipher, Esc_NULL_PTR, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "cipher == 0\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, Esc_NULL_PTR, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "length % 8 != 0\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase0->cipher, aes_buf, testcase0->length + 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_EncrComp(
    Esc_UINT8 keyIndex )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;

    EscTst_PrintString( "AES-CBC Encryption Compliance test\n" );

    for (i = 0U; (i < NUMBER_OF_AES_CBC_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstAesCbc_Testcase* testcase = &testcases[keyIndex][i];
        EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex]/8U );
        EscTst_PrintArray( "IV", testcase->iv, EscAes_BLOCK_BYTES );
        EscTst_PrintArray( "Plaintext", testcase->plain, testcase->length );
        EscTst_PrintArray( "Expected ciphertext", testcase->cipher, testcase->length );

        returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase->key, testcase->iv );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            /* decrypt aes_buf and store result in aes_buf */
            returnCode = EscAesCbc_Encrypt( &ctx, testcase->plain, aes_buf, testcase->length );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", aes_buf, testcase->length );

                if ( EscTst_Memcmp( aes_buf, testcase->cipher, testcase->length ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_EncryptionParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbc_Encrypt parameter test on test case 0\n" );
    EscTst_PrintString( "Calling EscAesCbc_Init with correct parameters\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_Encrypt with correct parameters\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase0->plain, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx == 0\n" );
        returnCode = EscAesCbc_Encrypt( Esc_NULL_PTR, testcase0->plain, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "plain == 0\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, Esc_NULL_PTR, aes_buf, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "cipher == 0\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase0->plain, Esc_NULL_PTR, testcase0->length );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "length % 8 != 0\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase0->plain, aes_buf, testcase0->length - 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_SetIVParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbc_SetIVParams parameter test on test case 0\n" );
    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx == 0\n" );
        returnCode = EscAesCbc_SetIV( Esc_NULL_PTR, testcase0->iv );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "iv == 0\n" );
            returnCode = EscAesCbc_SetIV( &ctx, Esc_NULL_PTR );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_DecryptIVChange(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];
    const EscTstAesCbc_Testcase* testcase1 = &testcases[keyIndex][1];

    EscTst_PrintString( "EscTstAesCbc_DecryptIVChange test\n" );

    EscTst_PrintString( "Calling EscAesCbc_Init()\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_Decrypt() using IV_0\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase0->cipher, aes_buf, testcase0->length );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received plaintext", aes_buf, testcase0->length );
        if ( EscTst_Memcmp( aes_buf, testcase0->plain, testcase0->length ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_SetIV() with IV_1\n" );
        returnCode = EscAesCbc_SetIV( &ctx, testcase1->iv );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Remark: Since aes_key_cbc[0] == aes_key_cbc[1] we do not update the key! */
        EscTst_PrintString( "Calling EscAesCbc_Decrypt() using IV_1\n" );
        returnCode = EscAesCbc_Decrypt( &ctx, testcase1->cipher, aes_buf, testcase1->length );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received plaintext", aes_buf, testcase1->length );

        if ( EscTst_Memcmp( aes_buf, testcase1->plain, testcase1->length ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbc_EncryptIVChange(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 aes_buf[AES_MAX_TEST_LENGTH];   /* buffer for data to decrypt      */
    EscAesCbc_ContextT ctx;
    const EscTstAesCbc_Testcase* testcase0 = &testcases[keyIndex][0];
    const EscTstAesCbc_Testcase* testcase1 = &testcases[keyIndex][1];

    EscTst_PrintString( "EscTstAesCbc_EncryptIVChange test\n" );

    EscTst_PrintString( "Calling EscAesCbc_Init()\n" );
    returnCode = EscAesCbc_Init( &ctx, keySizes[keyIndex], testcase0->key, testcase0->iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_Encrypt() using IV_0\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase0->plain, aes_buf, testcase0->length );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received ciphertext", aes_buf, testcase0->length );

        if ( EscTst_Memcmp( aes_buf, testcase0->cipher, testcase0->length ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscAesCbc_SetIV() with IV_1\n" );
        returnCode = EscAesCbc_SetIV( &ctx, testcase1->iv );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Remark: Since aes_key_cbc[0] == aes_key_cbc[1] we do not update the key! */
        EscTst_PrintString( "Calling EscAesCbc_Encrypt() using IV_1\n" );
        returnCode = EscAesCbc_Encrypt( &ctx, testcase1->plain, aes_buf, testcase1->length );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received ciphertext", aes_buf, testcase1->length );

        if ( EscTst_Memcmp( aes_buf, testcase1->cipher, testcase1->length ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

Esc_ERROR
EscTstAesCbc_Perform(
    void )
{
    /* The test cases */
    static const EscTstAesCbc_TestFunctionsT AES_TESTS[] =
    {
        EscTstAesCbc_InitParams,
        EscTstAesCbc_DecryptionParams,
        EscTstAesCbc_EncryptionParams,
        EscTstAesCbc_DecrCompSplit,
        EscTstAesCbc_EncrCompSplit,
        EscTstAesCbc_DecrComp,
        EscTstAesCbc_EncrComp,
        EscTstAesCbc_SetIVParams,
        EscTstAesCbc_DecryptIVChange,
        EscTstAesCbc_EncryptIVChange
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;

    for (j = 0U; j < 3U; ++j)
    {
        if (keySizes[j] <= EscAes_MAX_KEY_BITS)
        {
            EscTst_PrintWord( "Aes KEY BITS", keySizes[j] );
            EscTst_PrintString( "*******************************************************\n" );

            for (i = 0U; (i < (sizeof(AES_TESTS) / sizeof(AES_TESTS[0]))) && (returnCode == Esc_NO_ERROR); i++)
            {
                EscTstAesCbc_TestFunctionsT TestFunction;
                /* Perform test #i */
                TestFunction = AES_TESTS[i];
                returnCode = TestFunction(j);
                if (returnCode != Esc_NO_ERROR)
                {
                    break;
                }
                EscTst_PrintString( "*******************************************************\n" );
            }
        }
        if (returnCode != Esc_NO_ERROR)
        {
            break;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
