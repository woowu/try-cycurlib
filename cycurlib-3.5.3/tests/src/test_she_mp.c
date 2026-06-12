/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief SHE AES-MP Compression & KDF Selftest

   $Rev$
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "selftest.h"
#include "test_she_mp.h"
#include "she_mp.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Test case data for compression function*/
typedef struct
{
    /** Message as input */
    const Esc_UINT8 *message;
    /** Length of message in bits */
    const Esc_UINT32 lengthMessage;
    /** The caclulated digest */
    const Esc_UINT8 *digest;
} EscTstSheMp_TestcaseT;

/** Test case data for key derivation function*/
typedef struct
{
    /** Key as input */
    const Esc_UINT8 *key;
    /** Type of key */
    const Esc_UINT8 type;
    /** The derived key */
    const Esc_UINT8 *derived;
} EscTstSheKdf_TestcaseT;
/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
static const Esc_UINT8  message_1[] = {0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, 0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                                       0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, 0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U};
static const Esc_UINT8  message_1_digest[16] = {0xc7U, 0x27U, 0x7aU, 0x0dU, 0xc1U, 0xfbU, 0x85U, 0x3bU, 0x5fU, 0x4dU, 0x9cU, 0xbdU, 0x26U, 0xbeU, 0x40U, 0xc6U};

static const Esc_UINT8  message_2[] = {0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU};
static const Esc_UINT8  message_2_digest_128[16] = {0xd2U, 0x97U, 0x35U, 0xcfU, 0x7aU, 0xdaU, 0xfdU, 0x67U, 0x12U, 0xd5U, 0x00U, 0x52U, 0xd8U, 0xf1U, 0x59U, 0xd6U};
static const Esc_UINT8  message_2_digest_88[16] = {0xb6U, 0xd2U, 0x05U, 0x31U, 0x89U, 0xf9U, 0x0dU, 0x79U, 0x34U, 0xf8U, 0x6eU, 0x6bU, 0x08U, 0x6eU, 0xe7U, 0x47U};
static const Esc_UINT8  message_2_digest_89[16] = {0x39U, 0x55U, 0x45U, 0x0eU, 0xefU, 0x37U, 0x8eU, 0xf2U, 0xa4U, 0x2cU, 0xe9U, 0x2fU, 0xf1U, 0xbeU, 0xa2U, 0xdeU};

static const Esc_UINT8  message_3[] = {0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
static const Esc_UINT8  message_3_digest_128[16] = {0xcbU, 0xb2U, 0x5fU, 0x2cU, 0x61U, 0xf8U, 0x52U, 0x37U, 0xd5U, 0xd0U, 0x4dU, 0x21U, 0xf6U, 0xc0U, 0x8cU, 0xcfU};
static const Esc_UINT8  message_3_digest_127[16] = {0x56U, 0x43U, 0xb0U, 0x2fU, 0x0bU, 0xb5U, 0x33U, 0x2dU, 0xeaU, 0xc4U, 0x47U, 0xfeU, 0xdeU, 0x46U, 0xc6U, 0x77U};
static const Esc_UINT8  message_3_digest_88[16] = {0xcdU, 0x2cU, 0x92U, 0x37U, 0xa4U, 0x49U, 0xd2U, 0x8eU, 0xc9U, 0x9cU, 0x02U, 0xaaU, 0xa7U, 0x88U, 0x1eU, 0x8dU};
static const Esc_UINT8  message_3_digest_89[16] = {0x62U, 0xf5U, 0x05U, 0xd7U, 0xedU, 0x42U, 0x71U, 0x22U, 0xbbU, 0x06U, 0x92U, 0x6eU, 0x82U, 0xccU, 0x75U, 0x70U};

/*lint -esym(9003, EscTstSheMp_testcases) keep definition of testcases out of block level. */
static const EscTstSheMp_TestcaseT EscTstSheMp_testcases[] =
{
    {
        /* Message */
        message_1,
        /* Message size in bits */
        256U,
        /* Known digest */
        message_1_digest
    },
    {
        message_2,
        128U,
        message_2_digest_128
    },
    {
        message_2,
        88U,
        message_2_digest_88
    },
    {
        message_2,
        89U,
        message_2_digest_89
    },
    {
        message_3,
        128U,
        message_3_digest_128
    },
    {
        message_3,
        127U,
        message_3_digest_127
    },
    {
        message_3,
        88U,
        message_3_digest_88
    },
    {
        message_3,
        89U,
        message_3_digest_89
    },

};

#define EscTstSheMp_numTestcases (sizeof(EscTstSheMp_testcases) / sizeof(EscTstSheMp_testcases[0]))

static const Esc_UINT8  kdf_1_k[16] = {0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU};
static const Esc_UINT8  kdf_1_d[16] = {0x11U, 0x8aU, 0x46U, 0x44U, 0x7aU, 0x77U, 0x0dU, 0x87U, 0x82U, 0x8aU, 0x69U, 0xc2U, 0x22U, 0xe2U, 0xd1U, 0x7eU};

/*lint -esym(9003, EscTstSheKdf_testcases) keep definition of testcases out of block level. */
static const EscTstSheKdf_TestcaseT EscTstSheKdf_testcases[] =
{
    {
        /* Input key */
        kdf_1_k,
        /* Type of key */
        0x01U,
        /* derived key */
        kdf_1_d
    },
};

#define EscTstSheKdf_numTestcases (sizeof(EscTstSheKdf_testcases) / sizeof(EscTstSheKdf_testcases[0]))

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static
Esc_ERROR
EscTstSheMpComp_KAT()
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 digest[16];
    Esc_UINT32 i;

    EscTst_PrintString( "SHE compression function known answer test (EscSheMpComp)\n" );

    for (i=0U; i<EscTstSheMp_numTestcases; i++)
    {
        const EscTstSheMp_TestcaseT* testcase = &EscTstSheMp_testcases[i];
        /* convert hex string to byte array */
        EscTst_PrintArray( "Message", testcase->message, ((testcase->lengthMessage / 8U) + (testcase->lengthMessage % 8U > 0 ? 1 : 0)) );
        EscTst_PrintWord( "Message Length", testcase->lengthMessage );
        EscTst_PrintArray( "Expected digest", testcase->digest, 16 );

        returnCode = EscSheMpComp(testcase->message, testcase->lengthMessage, digest);

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Calculated digest", digest, 16 );

            if ( EscTst_Memcmp( digest, testcase->digest, 16 ) )
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
    return returnCode;
}

static
Esc_ERROR
EscTstSheMpKdf_KAT()
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 derived[16];
    Esc_UINT32 i;

    EscTst_PrintString( "SHE key derivation function known answer test (EscSheMpKdf)\n" );

    for (i=0U; i<EscTstSheKdf_numTestcases; i++)
    {
        const EscTstSheKdf_TestcaseT* testcase = &EscTstSheKdf_testcases[i];
        /* convert hex string to byte array */
        EscTst_PrintArray( "Key", testcase->key, 16 );
        EscTst_PrintWord("Key Type", testcase->type);
        EscTst_PrintArray( "Expected derived", testcase->derived, 16 );

        returnCode = EscSheMpKdf(testcase->key, testcase->type, derived);

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Calculated derived", derived, 16 );

            if ( EscTst_Memcmp( derived, testcase->derived, 16 ) )
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
    return returnCode;
}

static Esc_ERROR
EscTstSheMpComp_InvalidParams()
{
    Esc_UINT8 buffer[16];
    Esc_ERROR returnCode;
    EscTst_PrintString( "EscSheMpComp parameter test\n\n" );

    EscTst_PrintString( "With message == 0\n" );
    returnCode = EscSheMpComp(Esc_NULL_PTR, 0, buffer);
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With digest == 0\n" );
        returnCode = EscSheMpComp(buffer, 0, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstSheMpKdf_InvalidParams()
{
    Esc_UINT8 buffer[16];
    Esc_ERROR returnCode;
    EscTst_PrintString( "EscSheMpKdf parameter test\n\n" );

    EscTst_PrintString( "With key == 0\n" );
    returnCode = EscSheMpKdf(Esc_NULL_PTR, EscShe_KEY_UPDATE_ENC_C, buffer);
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With derived == 0\n" );
        returnCode = EscSheMpKdf(buffer, EscShe_KEY_UPDATE_ENC_C, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key type == 0\n" );
        returnCode = EscSheMpKdf(buffer, 0, buffer);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key type > max\n" );
        returnCode = EscSheMpKdf(buffer, 255, buffer);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

Esc_ERROR
EscTstSheMp_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstSheMpComp_InvalidParams();
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSheMpKdf_InvalidParams();
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSheMpComp_KAT();
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSheMpKdf_KAT();
    }
    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
