/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-GCM Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "test_aes_gcm.h"
#include "selftest.h"
#include "aes_gcm.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscTstAesGcm_NUM_TESTCASES 2U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

typedef Esc_ERROR (* EscTstAesGcm_TestFunctionsT )(
    Esc_UINT8 keyIndex );

/**
 * Test the encryption and decryption functions of compliance with the
 * given testvectors from
 * "The Galois/Counter Mode of Operation (GCM)", David A. McGrew and John Viega
 */
static Esc_ERROR
EscTstAesGcm_ComplianceTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesGcm_InitParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesGcm_StartParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesGcm_UpdateParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesGcm_FinishParams(
    Esc_UINT8 keyIndex );

#define EscTstAesGcm_NUM_TESTS ( sizeof(AES_TESTS) / sizeof(AES_TESTS[0]) )

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

static const Esc_UINT16 keySizes[] =
{
    128,
    192,
    256
};

static const Esc_UINT8 key[][EscTstAesGcm_NUM_TESTCASES][32] =
{
    /* key size 128 bit */
    {
        {
            0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
            0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },

#if EscAes_MAX_KEY_BITS >= 192U
    /* key size 192 bit */
    {
        {
            0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
            0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U,
            0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    /* key size 256 bit */
    {
        {
            0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
            0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U,
            0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
            0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
#endif
};

static const Esc_UINT8 test_data[EscTstAesGcm_NUM_TESTCASES][60] =
{
    {
        0xd9U, 0x31U, 0x32U, 0x25U, 0xf8U, 0x84U, 0x06U, 0xe5U,
        0xa5U, 0x59U, 0x09U, 0xc5U, 0xafU, 0xf5U, 0x26U, 0x9aU,
        0x86U, 0xa7U, 0xa9U, 0x53U, 0x15U, 0x34U, 0xf7U, 0xdaU,
        0x2eU, 0x4cU, 0x30U, 0x3dU, 0x8aU, 0x31U, 0x8aU, 0x72U,
        0x1cU, 0x3cU, 0x0cU, 0x95U, 0x95U, 0x68U, 0x09U, 0x53U,
        0x2fU, 0xcfU, 0x0eU, 0x24U, 0x49U, 0xa6U, 0xb5U, 0x25U,
        0xb1U, 0x6aU, 0xedU, 0xf5U, 0xaaU, 0x0dU, 0xe6U, 0x57U,
        0xbaU, 0x63U, 0x7bU, 0x39U
    },
    {
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U
    }
};

static const Esc_UINT32 len_data[EscTstAesGcm_NUM_TESTCASES] = { 60U, 16U };

static const Esc_UINT8 iv[EscTstAesGcm_NUM_TESTCASES][60] =
{
    {
        0x93U, 0x13U, 0x22U, 0x5dU, 0xf8U, 0x84U, 0x06U, 0xe5U,
        0x55U, 0x90U, 0x9cU, 0x5aU, 0xffU, 0x52U, 0x69U, 0xaaU,
        0x6aU, 0x7aU, 0x95U, 0x38U, 0x53U, 0x4fU, 0x7dU, 0xa1U,
        0xe4U, 0xc3U, 0x03U, 0xd2U, 0xa3U, 0x18U, 0xa7U, 0x28U,
        0xc3U, 0xc0U, 0xc9U, 0x51U, 0x56U, 0x80U, 0x95U, 0x39U,
        0xfcU, 0xf0U, 0xe2U, 0x42U, 0x9aU, 0x6bU, 0x52U, 0x54U,
        0x16U, 0xaeU, 0xdbU, 0xf5U, 0xa0U, 0xdeU, 0x6aU, 0x57U,
        0xa6U, 0x37U, 0xb3U, 0x9bU
    },
    {
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U
    }
};

static const Esc_UINT32 len_iv[EscTstAesGcm_NUM_TESTCASES] = { 60U, 12U };

static const Esc_UINT8 exp_tag[][EscTstAesGcm_NUM_TESTCASES][16] =
{
    /* key length 128 bit*/
    {
        {
            0x61U, 0x9cU, 0xc5U, 0xaeU, 0xffU, 0xfeU, 0x0bU, 0xfaU,
            0x46U, 0x2aU, 0xf4U, 0x3cU, 0x16U, 0x99U, 0xd0U, 0x50U
        },
        {
            0xabU, 0x6eU, 0x47U, 0xd4U, 0x2cU, 0xecU, 0x13U, 0xbdU,
            0xf5U, 0x3aU, 0x67U, 0xb2U, 0x12U, 0x57U, 0xbdU, 0xdfU
        }
    },
    /* key length 192 bit*/
    {
        {
            0xdcU, 0xf5U, 0x66U, 0xffU, 0x29U, 0x1cU, 0x25U, 0xbbU,
            0xb8U, 0x56U, 0x8fU, 0xc3U, 0xd3U, 0x76U, 0xa6U, 0xd9U
        },
        {
            0x2fU, 0xf5U, 0x8dU, 0x80U, 0x03U, 0x39U, 0x27U, 0xabU,
            0x8eU, 0xf4U, 0xd4U, 0x58U, 0x75U, 0x14U, 0xf0U, 0xfbU,
        }
    },
    /* key length 256 bit*/
    {
        {
            0xa4U, 0x4aU, 0x82U, 0x66U, 0xeeU, 0x1cU, 0x8eU, 0xb0U,
            0xc8U, 0xb5U, 0xd4U, 0xcfU, 0x5aU, 0xe9U, 0xf1U, 0x9aU
        },
        {
            0xd0U, 0xd1U, 0xc8U, 0xa7U, 0x99U, 0x99U, 0x6bU, 0xf0U,
            0x26U, 0x5bU, 0x98U, 0xb5U, 0xd4U, 0x8aU, 0xb9U, 0x19U
        }
    }
};


/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscTstAesGcm_ComplianceTest(
    Esc_UINT8 keyIndex )
{
    static const Esc_UINT8 A[EscTstAesGcm_NUM_TESTCASES][20] =
    {
        {
            0xfeU, 0xedU, 0xfaU, 0xceU, 0xdeU, 0xadU, 0xbeU, 0xefU,
            0xfeU, 0xedU, 0xfaU, 0xceU, 0xdeU, 0xadU, 0xbeU, 0xefU,
            0xabU, 0xadU, 0xdaU, 0xd2U
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U
        }
    };

    static const Esc_UINT32 len_aad[EscTstAesGcm_NUM_TESTCASES] = { 20U, 0U };

    const Esc_UINT8 result[][EscTstAesGcm_NUM_TESTCASES][60] =
    {
        /* key length 128 bit*/
        {
            {
                0x8cU, 0xe2U, 0x49U, 0x98U, 0x62U, 0x56U, 0x15U, 0xb6U,
                0x03U, 0xa0U, 0x33U, 0xacU, 0xa1U, 0x3fU, 0xb8U, 0x94U,
                0xbeU, 0x91U, 0x12U, 0xa5U, 0xc3U, 0xa2U, 0x11U, 0xa8U,
                0xbaU, 0x26U, 0x2aU, 0x3cU, 0xcaU, 0x7eU, 0x2cU, 0xa7U,
                0x01U, 0xe4U, 0xa9U, 0xa4U, 0xfbU, 0xa4U, 0x3cU, 0x90U,
                0xccU, 0xdcU, 0xb2U, 0x81U, 0xd4U, 0x8cU, 0x7cU, 0x6fU,
                0xd6U, 0x28U, 0x75U, 0xd2U, 0xacU, 0xa4U, 0x17U, 0x03U,
                0x4cU, 0x34U, 0xaeU, 0xe5U
            },
            {
                0x03U, 0x88U, 0xdaU, 0xceU, 0x60U, 0xb6U, 0xa3U, 0x92U,
                0xf3U, 0x28U, 0xc2U, 0xb9U, 0x71U, 0xb2U, 0xfeU, 0x78U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U
            }
        },
        /* key length 192 bit*/
        {
            {
                0xd2U, 0x7eU, 0x88U, 0x68U, 0x1cU, 0xe3U, 0x24U, 0x3cU,
                0x48U, 0x30U, 0x16U, 0x5aU, 0x8fU, 0xdcU, 0xf9U, 0xffU,
                0x1dU, 0xe9U, 0xa1U, 0xd8U, 0xe6U, 0xb4U, 0x47U, 0xefU,
                0x6eU, 0xf7U, 0xb7U, 0x98U, 0x28U, 0x66U, 0x6eU, 0x45U,
                0x81U, 0xe7U, 0x90U, 0x12U, 0xafU, 0x34U, 0xddU, 0xd9U,
                0xe2U, 0xf0U, 0x37U, 0x58U, 0x9bU, 0x29U, 0x2dU, 0xb3U,
                0xe6U, 0x7cU, 0x03U, 0x67U, 0x45U, 0xfaU, 0x22U, 0xe7U,
                0xe9U, 0xb7U, 0x37U, 0x3bU
            },
            {
                0x98U, 0xe7U, 0x24U, 0x7cU, 0x07U, 0xf0U, 0xfeU, 0x41U,
                0x1cU, 0x26U, 0x7eU, 0x43U, 0x84U, 0xb0U, 0xf6U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U
            }
        },
        /* key length 256 bit*/
        {
            {
                0x5aU, 0x8dU, 0xefU, 0x2fU, 0x0cU, 0x9eU, 0x53U, 0xf1U,
                0xf7U, 0x5dU, 0x78U, 0x53U, 0x65U, 0x9eU, 0x2aU, 0x20U,
                0xeeU, 0xb2U, 0xb2U, 0x2aU, 0xafU, 0xdeU, 0x64U, 0x19U,
                0xa0U, 0x58U, 0xabU, 0x4fU, 0x6fU, 0x74U, 0x6bU, 0xf4U,
                0x0fU, 0xc0U, 0xc3U, 0xb7U, 0x80U, 0xf2U, 0x44U, 0x45U,
                0x2dU, 0xa3U, 0xebU, 0xf1U, 0xc5U, 0xd8U, 0x2cU, 0xdeU,
                0xa2U, 0x41U, 0x89U, 0x97U, 0x20U, 0x0eU, 0xf8U, 0x2eU,
                0x44U, 0xaeU, 0x7eU, 0x3fU
            },
            {
                0xceU, 0xa7U, 0x40U, 0x3dU, 0x4dU, 0x60U, 0x6bU, 0x6eU,
                0x07U, 0x4eU, 0xc5U, 0xd3U, 0xbaU, 0xf3U, 0x9dU, 0x18U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U
            }
        }
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i, j;
    Esc_UINT8 cipher[60];
    Esc_UINT8 plain[60];
    Esc_UINT8 T[16];

    /* Initialize plain */
    for (i = 0U; i < 60U; i++)
    {
        plain[i] = 0U;
    }

    EscTst_PrintWord( "AES Key-Size", keySizes[keyIndex]/8 );

    for (i = 0U; (i < EscTstAesGcm_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintString( "Start encrypting ...\n\n\n" );
        EscTst_PrintArray( "Original Message", test_data[i], len_data[i] );
        EscTst_PrintArray( "Additional Data to authenticate", A[i], len_aad[i] );

        returnCode = EscAesGcm_Encrypt(
                keySizes[keyIndex],
                key[keyIndex][i],
                iv[i],
                len_iv[i],
                A[i],
                len_aad[i],
                test_data[i],
                len_data[i],
                cipher,
                T,
                16U );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Encrypted Message", cipher, len_data[i] );

            if ( EscTst_Memcmp( cipher, result[keyIndex][i], len_data[i] ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Authentication-Tag", T, 16U );
                EscTst_PrintArray( "Expected Authentication-Tag", exp_tag[keyIndex][i], 16U );

                if ( EscTst_Memcmp( T, exp_tag[keyIndex][i], 16U ) )
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

        for (j = 1U; (j <= 20U) && (returnCode == Esc_NO_ERROR); j++)
        {
            EscAesGcm_ContextT ctx;
            Esc_UINT32 offs = 0U;

            EscTst_PrintWord(  "Chunk size: ", j );
            returnCode = EscAesGcm_Init( &ctx, keySizes[keyIndex], key[keyIndex][i] );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_startEncryptDecrypt( &ctx, iv[i], len_iv[i] );
            }

            while ( (returnCode == Esc_NO_ERROR) && (offs < len_aad[i]) )
            {
                Esc_UINT32 len;

                if ( (len_aad[i] - offs) < j )
                {
                    len = len_aad[i] - offs;
                }
                else
                {
                    len = j;
                }

                returnCode = EscAesGcm_AssociatedData_Update( &ctx, &A[i][offs], len );
                offs += len;
            }

            offs = 0U;

            while ( (returnCode == Esc_NO_ERROR) && (offs < len_data[i]) )
            {
                Esc_UINT32 len;

                if ( (len_data[i] - offs) < j )
                {
                    len = len_data[i] - offs;
                }
                else
                {
                    len = j;
                }

                returnCode = EscAesGcm_Encrypt_Update( &ctx, &test_data[i][offs], &cipher[offs], len );
                offs += len;
            }

            /* one final update with zero data */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Encrypt_Update( &ctx, Esc_NULL_PTR, Esc_NULL_PTR, 0U );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Encrypt_Finish( &ctx, T, 16U );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                if ( ( EscTst_Memcmp( cipher, result[keyIndex][i], len_data[i] ) != FALSE) &&
                     ( EscTst_Memcmp( T, exp_tag[keyIndex][i], 16U ) != FALSE ) )
                {
                    EscTst_PrintString( "Correct\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Start decrypting ...\n\n\n" );

            returnCode = EscAesGcm_Decrypt(
                    keySizes[keyIndex],
                    key[keyIndex][i],
                    iv[i],
                    len_iv[i],
                    A[i],
                    len_aad[i],
                    cipher,
                    len_data[i],
                    plain,
                    T,
                    16U );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString( "Authentication-Tag Verification successful.\n\n\n" );
                EscTst_PrintArray( "Decrypted Message", plain, len_data[i] );

                if ( EscTst_Memcmp( plain, test_data[i], len_data[i] ) )
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

        for (j = 1U; (j <= 20U) && (returnCode == Esc_NO_ERROR); j++)
        {
            EscAesGcm_ContextT ctx;
            Esc_UINT32 offs = 0U;

            EscTst_PrintWord(  "Chunk size: ", j );
            returnCode = EscAesGcm_Init( &ctx, keySizes[keyIndex], key[keyIndex][i] );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_startEncryptDecrypt( &ctx, iv[i], len_iv[i] );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_AssociatedData_Update( &ctx, A[i], len_aad[i] );
            }

            while ( (returnCode == Esc_NO_ERROR) && (offs < len_data[i]) )
            {
                Esc_UINT32 len;

                if ( (len_data[i] - offs) < j )
                {
                    len = len_data[i] - offs;
                }
                else
                {
                    len = j;
                }

                returnCode = EscAesGcm_Decrypt_Update( &ctx, &plain[offs], &cipher[offs], len );
                offs += len;
            }

            /* one final update with zero data */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Decrypt_Update( &ctx, Esc_NULL_PTR, Esc_NULL_PTR, 0U );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Decrypt_Finish( &ctx, T, 16U );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                if ( EscTst_Memcmp( plain, test_data[i], len_data[i] ) )
                {
                    EscTst_PrintString( "Correct\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesGcm_InitParams(
    Esc_UINT8 keyIndex )
{
    EscAesGcm_ContextT context;
    Esc_ERROR returnCode;

    EscTst_PrintString( "EscAesGcm_Init parameter test\n\n" );

    EscTst_PrintString( "With ctx == 0\n" );
    returnCode = EscAesGcm_Init( Esc_NULL_PTR, keySizes[keyIndex], key[keyIndex][0U] );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key == 0\n" );
        returnCode = EscAesGcm_Init( &context, keySizes[keyIndex], Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesGcm_Init( &context, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), key[keyIndex][0U] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesGcm_StartParams(
    Esc_UINT8 keyIndex )
{
    EscAesGcm_ContextT context;
    Esc_ERROR returnCode;

    Esc_UNUSED_PARAM( keyIndex );

    EscTst_PrintString( "EscAesGcm_startEncryptDecrypt parameter test\n\n" );
    EscTst_PrintString( "With ctx == 0\n" );
    returnCode = EscAesGcm_startEncryptDecrypt( Esc_NULL_PTR, iv[0], len_iv[0] );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With iv == 0\n" );
        returnCode = EscAesGcm_startEncryptDecrypt( &context,  Esc_NULL_PTR, len_iv[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }


    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With len_iv == 0\n" );
        returnCode = EscAesGcm_startEncryptDecrypt( &context, iv[0], 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesGcm_UpdateParams(
    Esc_UINT8 keyIndex )
{
    EscAesGcm_ContextT context;
    Esc_ERROR returnCode;
    Esc_UINT8 buffer[60];

    Esc_UNUSED_PARAM( keyIndex );

    /* Encrypt */

    EscTst_PrintString( "EscAesGcm_EncryptUpdate parameter test\n\n" );

    EscTst_PrintString( "With ctx == 0\n" );
    returnCode = EscAesGcm_Encrypt_Update( Esc_NULL_PTR, test_data[0], buffer, len_data[0] );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With plain == 0\n" );
        returnCode = EscAesGcm_Encrypt_Update( &context, Esc_NULL_PTR, buffer, len_data[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cipher == 0\n" );
        returnCode = EscAesGcm_Encrypt_Update( &context, test_data[0], Esc_NULL_PTR, len_data[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    /* Decrypt */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscAesGcm_DecryptUpdate parameter test\n\n" );

        EscTst_PrintString( "With ctx == 0\n" );
        returnCode = EscAesGcm_Decrypt_Update( Esc_NULL_PTR, buffer, test_data[0], len_data[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With plain == 0\n" );
        returnCode = EscAesGcm_Decrypt_Update( &context, Esc_NULL_PTR, test_data[0], len_data[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cipher == 0\n" );
        returnCode = EscAesGcm_Decrypt_Update( &context, buffer, Esc_NULL_PTR, len_data[0] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    /* AAD update */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscAesGcm_AssociatedData_Update parameter test\n\n" );

        EscTst_PrintString( "With aad == 0 and aadLen > 0\n" );
        returnCode = EscAesGcm_AssociatedData_Update( &context, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx == 0\n" );
        returnCode = EscAesGcm_AssociatedData_Update( Esc_NULL_PTR, buffer, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesGcm_FinishParams(
    Esc_UINT8 keyIndex )
{
    EscAesGcm_ContextT context;
    Esc_ERROR returnCode;
    Esc_UINT8 T[16];

    /* Encrypt */
    EscTst_PrintString( "EscAesGcm_EncryptFinish parameter test\n\n" );

    EscTst_PrintString( "With ctx == 0\n" );
    returnCode = EscAesGcm_Encrypt_Finish( Esc_NULL_PTR, T, 16U );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tag == 0\n" );
        returnCode = EscAesGcm_Encrypt_Finish( &context, Esc_NULL_PTR, 16U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen == 0\n" );
        returnCode = EscAesGcm_Encrypt_Finish( &context, T, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen < 12 && != 8 && != 4\n" );
        returnCode = EscAesGcm_Encrypt_Finish( &context, T, 11U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen > 16\n" );
        returnCode = EscAesGcm_Encrypt_Finish( &context, T, 17U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    /* Decrypt */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscAesGcm_DecryptFinish parameter test\n\n" );

        EscTst_PrintString( "With ctx == 0\n" );
        returnCode = EscAesGcm_Decrypt_Finish( Esc_NULL_PTR, exp_tag[keyIndex][0], 16U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tag == 0\n" );
        returnCode = EscAesGcm_Decrypt_Finish( &context, Esc_NULL_PTR, 16U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen == 0\n" );
        returnCode = EscAesGcm_Decrypt_Finish( &context, exp_tag[keyIndex][0], 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen < 12 && != 8 && != 4\n" );
        returnCode = EscAesGcm_Decrypt_Finish( &context, exp_tag[keyIndex][0], 11U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With tagLen > 16\n" );
        returnCode = EscAesGcm_Decrypt_Finish( &context, exp_tag[keyIndex][0], 17U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

Esc_ERROR
EscTstAesGcm_Perform(
    void )
{
    /* The test cases */
    static const EscTstAesGcm_TestFunctionsT AES_TESTS[] =
    {
        EscTstAesGcm_ComplianceTest,
        EscTstAesGcm_InitParams,
        EscTstAesGcm_StartParams,
        EscTstAesGcm_UpdateParams,
        EscTstAesGcm_FinishParams
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;


    for (j = 0; j < 3U; ++j)
    {
        if (keySizes[j] <= EscAes_MAX_KEY_BITS)
        {
            EscTst_PrintWord( "Aes KEY BITS", keySizes[j] );
            EscTst_PrintString( "*******************************************************\n" );

            for (i = 0U; i < EscTstAesGcm_NUM_TESTS; i++)
            {
                EscTstAesGcm_TestFunctionsT TestFunction;
                /* Perform test #i */
                TestFunction = AES_TESTS[i];
                returnCode = TestFunction(j);
                if (returnCode != Esc_NO_ERROR)
                {
                    break;
                }
                EscTst_PrintString( "*******************************************************\n" );
            }
            if (returnCode != Esc_NO_ERROR)
            {
                break;
            }
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
