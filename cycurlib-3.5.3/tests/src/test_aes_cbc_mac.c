/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief AES Selftest.

   Decrypts a given ciphertext and checks if the result matches
   a precalculated plaintext pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_aes_cbc_mac.h"
#include "selftest.h"
#include "aes_cbc_mac.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscTstAesCbcMac_MAX_DATALEN 0x10U
#define EscTstAesCbcMac_NUM_VECTORS_PER_KEYSIZE 2U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** CBC-MAC test vector */
typedef struct
{
    Esc_UINT8 key[EscAes_MAX_KEY_BYTES];
    Esc_UINT8 msg[EscTstAesCbcMac_MAX_DATALEN];
    Esc_UINT32 msgLen;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];
    Esc_UINT8 iv[EscAes_IV_BYTES];
} EscTstAesCbcMac_testcaseT;

static const Esc_UINT16 keySizes[] =
{
    128,
    192,
    256
};

/*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
static const EscTstAesCbcMac_testcaseT testcases[3][EscTstAesCbcMac_NUM_VECTORS_PER_KEYSIZE] =
{
    {
        {
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* key */
            {
                0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
                0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0x69U, 0xc4U, 0xe0U, 0xd8U, 0x6aU, 0x7bU, 0x04U, 0x30U,
                0xd8U, 0xcdU, 0xb7U, 0x80U, 0x70U, 0xb4U, 0xc5U, 0x5AU
            }, /* MAC */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            } /* IV */
        },
        {
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* key */
            {
                0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
                0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0x10U, 0x58U, 0xc8U, 0x2cU, 0x54U, 0x69U, 0x82U, 0x2aU,
                0x2bU, 0xc7U, 0xd5U, 0x95U, 0xafU, 0xc9U, 0x65U, 0xd4U
            }, /* MAC */
            {
                0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U,
                0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U, 0x51U
            } /* IV */
        }
    },

#if EscAes_MAX_KEY_BITS >= 192U
    {
        {
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
                0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U
            }, /* key */
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0x00U, 0x60U, 0xbfU, 0xfeU, 0x46U, 0x83U, 0x4bU, 0xb8U,
                0xdaU, 0x5cU, 0xf9U, 0xa6U, 0x1fU, 0xf2U, 0x20U, 0xaeU
            }, /* MAC */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            } /* IV */
        },
        {
            {
                0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU, 0xcdU, 0xefU,
                0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU, 0xcdU, 0xefU,
                0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU, 0xcdU, 0xefU
            }, /* key */
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0x46U, 0xc3U, 0x02U, 0xbaU, 0xf9U, 0x3cU, 0xd6U, 0x84U,
                0x78U, 0x2aU, 0x01U, 0xf0U, 0x3eU, 0x69U, 0x0eU, 0xd6U
            }, /* MAC */
            {
                0x34U, 0x2aU, 0xf4U, 0x23U, 0x55U, 0x0aU, 0xc3U, 0x2aU,
                0x34U, 0x87U, 0x34U, 0x98U, 0x44U, 0x22U, 0x43U, 0x2bU
            } /* IV */
        }
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    {
        {
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
                0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
                0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
            }, /* key */
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0x5AU, 0x6EU, 0x04U, 0x57U, 0x08U, 0xFBU, 0x71U, 0x96U,
                0xF0U, 0x2EU, 0x55U, 0x3DU, 0x02U, 0xC3U, 0xA6U, 0x92U
            }, /* MAC */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            } /* IV */
        },
        {
            {
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
                0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
            }, /* key */
            {
                0x0FU, 0x0EU, 0x0DU, 0x0CU, 0x0BU, 0x0AU, 0x09U, 0x08U,
                0x07U, 0x06U, 0x05U, 0x04U, 0x03U, 0x02U, 0x01U, 0x00U
            }, /* msg */
            0x10U,                 /* msgLen */
            {
                0xc8U, 0xe2U, 0xd6U, 0x0aU, 0x08U, 0xb8U, 0x1cU, 0xedU,
                0xd6U, 0x13U, 0x23U, 0xb4U, 0x43U, 0x3bU, 0xe6U, 0xa4U
            }, /* MAC */
            {
                0x37U, 0x2fU, 0xa6U, 0x74U, 0x51U, 0x25U, 0xe0U, 0x0aU,
                0x75U, 0x78U, 0x86U, 0xb5U, 0x3eU, 0x2cU, 0x23U, 0xc7U
            } /* IV */
        }
    }
#endif
};
/*lint -restore */

static Esc_ERROR
EscTstAesCbcMac_InitParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbcMac_SetIvParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbcMac_UpdateParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbcMac_FinishParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbcMac_ComplianceSteps(
    Esc_UINT8 keyIndex,
    const EscTstAesCbcMac_testcaseT* testcase );

static Esc_ERROR
EscTstAesCbcMac_ComplianceCalc(
    Esc_UINT8 keyIndex,
    const Esc_UINT8 iv[],
    const EscTstAesCbcMac_testcaseT* testcase );

static Esc_ERROR
EscTstAesCbcMac_ComplianceTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesCbcMac_CalcParams(
    Esc_UINT8 keyIndex );

typedef Esc_ERROR (
* EscTstAesCbcMac_TestFunctionsT )(
    Esc_UINT8 keyIndex );

#define EscTstAesCbcMac_NUM_TESTS ( sizeof(AES_TESTS) / sizeof(AES_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbcMac_InitParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    const EscTstAesCbcMac_testcaseT* test = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbcMac_Init parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscAesCbcMac_Init( &ctx, keySizes[keyIndex], test->key );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesCbcMac_Init( Esc_NULL_PTR, keySizes[keyIndex], test->key );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscAesCbcMac_Init( &ctx, keySizes[keyIndex], Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesCbcMac_Init( &ctx, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), test->key );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbcMac_SetIvParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    const EscTstAesCbcMac_testcaseT* test = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbcMac_SetIV parameter test on testcase 1\n" );

    EscTst_PrintString( "With ctx==0\n" );
    returnCode = EscAesCbcMac_SetIV( Esc_NULL_PTR, test->iv );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With iv==0\n" );
        returnCode = EscAesCbcMac_SetIV( &ctx, Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbcMac_UpdateParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    const EscTstAesCbcMac_testcaseT* test = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbcMac_Update parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscAesCbcMac_Init( &ctx, keySizes[keyIndex], test->key );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesCbcMac_Update( &ctx, test->msg, test->msgLen );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesCbcMac_Update( Esc_NULL_PTR, test->msg, test->msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With message==0\n" );
        returnCode = EscAesCbcMac_Update( &ctx, Esc_NULL_PTR, test->msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With length % EscAes_BLOCK_BYTES != 0\n" );
        returnCode = EscAesCbcMac_Update( &ctx, test->msg, EscAes_BLOCK_BYTES - 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCbcMac_FinishParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesCbc_ContextT ctx;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];
    const EscTstAesCbcMac_testcaseT* test = &testcases[keyIndex][0];

    EscTst_PrintString( "EscAesCbcMac_Finish parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscAesCbcMac_Init( &ctx, keySizes[keyIndex], test->key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesCbcMac_Update( &ctx, test->msg, test->msgLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesCbcMac_Finish( &ctx, mac );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == FALSE)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesCbcMac_Finish( Esc_NULL_PTR, mac );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With mac==0\n" );
            returnCode = EscAesCbcMac_Finish( &ctx, Esc_NULL_PTR );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbcMac_ComplianceSteps(
    Esc_UINT8 keyIndex,
    const EscTstAesCbcMac_testcaseT* testcase )
{
    Esc_ERROR returnCode;
    Esc_UINT8 calcMac[EscAes_BLOCK_BYTES];    /* buffer for returnCode */
    EscAesCbc_ContextT ctx;

    EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex]/8U );
    EscTst_PrintArray( "IV", testcase->iv, EscAes_BLOCK_BYTES );
    EscTst_PrintArray( "Message", testcase->msg, testcase->msgLen );
    EscTst_PrintArray( "Expected MAC", testcase->mac, EscAes_BLOCK_BYTES );

    EscTst_PrintString( "EscAesCbcMac_Init()\n" );
    returnCode = EscAesCbcMac_Init( &ctx, keySizes[keyIndex], testcase->key );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscAesCbcMac_SetIV()\n" );
        returnCode = EscAesCbcMac_SetIV( &ctx, testcase->iv );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesCbcMac_Update()\n" );
            returnCode = EscAesCbcMac_Update( &ctx, testcase->msg, testcase->msgLen );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscAesCbcMac_Finish()\n" );
                returnCode = EscAesCbcMac_Finish( &ctx, calcMac );

                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );

                    if ( EscTst_Memcmp( calcMac, testcase->mac, EscAes_BLOCK_BYTES ) )
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
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbcMac_ComplianceCalc(
    Esc_UINT8 keyIndex,
    const Esc_UINT8 iv[],
    const EscTstAesCbcMac_testcaseT* testcase )
{
    Esc_ERROR returnCode;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];

    EscTst_PrintArray( "Message", testcase->msg, EscAes_BLOCK_BYTES );
    EscTst_PrintArray( "Key", testcase->key, keySizes[keyIndex] / 8U );
    EscTst_PrintArray( "IV", testcase->iv, EscAes_BLOCK_BYTES );

    returnCode = EscAesCbcMac_Calc( keySizes[keyIndex], testcase->key, iv, testcase->msg, testcase->msgLen, mac );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Expected Result", testcase->mac, EscAes_BLOCK_BYTES );
        EscTst_PrintArray( "Received Result", mac, EscAes_BLOCK_BYTES );
        if ( EscTst_Memcmp( mac, testcase->mac, EscAes_BLOCK_BYTES ) )
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
    else
    {
        EscTst_PrintString( "FAILED!!!\n\n\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbcMac_ComplianceTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    for (i = 0U; ( (returnCode == Esc_NO_ERROR) && (i < EscTstAesCbcMac_NUM_VECTORS_PER_KEYSIZE) ); i++)
    {
        EscTst_PrintWord( "AES-CBC-MAC Compliance test #", i );
        returnCode = EscTstAesCbcMac_ComplianceSteps( keyIndex, &testcases[keyIndex][i] );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        for (i = 0U; ( (returnCode == Esc_NO_ERROR) && (i < EscTstAesCbcMac_NUM_VECTORS_PER_KEYSIZE) ); i++)
        {
            EscTst_PrintWord( "AES-CBC-MAC_Calc() test on test (explicit IV) vector #", i );
            returnCode = EscTstAesCbcMac_ComplianceCalc( keyIndex, testcases[keyIndex][i].iv, &testcases[keyIndex][i] );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "AES-CBC-MAC_Calc() test on test vector 1 (implicit IV)\n" );
        returnCode = EscTstAesCbcMac_ComplianceCalc( keyIndex, Esc_NULL_PTR, &testcases[keyIndex][0] );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCbcMac_CalcParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];
    const EscTstAesCbcMac_testcaseT* test = &testcases[keyIndex][0];

    EscTst_PrintString( "AES-CBC-MAC Calc Params test");

    EscTst_PrintString( "With message==0\n" );
    returnCode = EscAesCbcMac_Calc( keySizes[keyIndex], test->key, test->iv, Esc_NULL_PTR, test->msgLen, mac );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscAesCbcMac_Calc( keySizes[keyIndex], Esc_NULL_PTR, test->iv, test->msg, test->msgLen, mac );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

Esc_ERROR
EscTstAesCbcMac_Perform(
    void )
{
    /* The test cases */
    static const EscTstAesCbcMac_TestFunctionsT AES_TESTS[] =
    {
        EscTstAesCbcMac_InitParams,
        EscTstAesCbcMac_SetIvParams,
        EscTstAesCbcMac_UpdateParams,
        EscTstAesCbcMac_FinishParams,
        EscTstAesCbcMac_ComplianceTest,
        EscTstAesCbcMac_CalcParams
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;


    for (j = 0; j < 3U; ++j)
    {
        if (keySizes[j] <= EscAes_MAX_KEY_BITS)
        {
            EscTst_PrintWord( "Aes KEY BITS", keySizes[j] );
            EscTst_PrintString( "*******************************************************\n" );

            for (i = 0U; i < EscTstAesCbcMac_NUM_TESTS; i++)
            {
                EscTstAesCbcMac_TestFunctionsT TestFunction;
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
