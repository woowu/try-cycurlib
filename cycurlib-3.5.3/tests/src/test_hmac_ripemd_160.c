/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief HMAC-RIPEMD-160 Selftest

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_hmac_ripemd_160.h"
#include "selftest.h"
#include "hmac_ripemd_160.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define NUMBER_HMAC_160_RIP_TSTCASE     7U
#define HMAC_160_TESTKEY_LEN            20U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

static const Esc_UINT8 hmac_ripemd_test_keys[HMAC_160_TESTKEY_LEN] =
{
    0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU, 0xcdU, 0xefU, 0xfeU, 0xdcU,
    0xbaU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U, 0x00U, 0x11U, 0x22U, 0x33U
};

static const Esc_CHAR* const hmac_rmd_msg[NUMBER_HMAC_160_RIP_TSTCASE] =
{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
};

static const Esc_UINT8 hmac_rmd_res[NUMBER_HMAC_160_RIP_TSTCASE][EscHmacRipemd160_MAX_MAC_LENGTH] =
{
    {
        0xfeU, 0x69U, 0xa6U, 0x6cU, 0x74U, 0x23U, 0xeeU, 0xa9U, 0xc8U, 0xfaU,
        0x2eU, 0xffU, 0x8dU, 0x9dU, 0xafU, 0xb4U, 0xf1U, 0x7aU, 0x62U, 0xf5U
    },
    {
        0x85U, 0x74U, 0x3eU, 0x89U, 0x9bU, 0xc8U, 0x2dU, 0xbfU, 0xa3U, 0x6fU,
        0xaaU, 0xa7U, 0xa2U, 0x5bU, 0x7cU, 0xfdU, 0x37U, 0x24U, 0x32U, 0xcdU
    },
    {
        0x6eU, 0x4aU, 0xfdU, 0x50U, 0x1fU, 0xa6U, 0xb4U, 0xa1U, 0x82U, 0x3cU,
        0xa3U, 0xb1U, 0x0bU, 0xd9U, 0xaaU, 0x0bU, 0xa9U, 0x7bU, 0xa1U, 0x82U
    },
    {
        0x2eU, 0x06U, 0x6eU, 0x62U, 0x4bU, 0xadU, 0xb7U, 0x6aU, 0x18U, 0x4cU,
        0x8fU, 0x90U, 0xfbU, 0xa0U, 0x53U, 0x33U, 0x0eU, 0x65U, 0x0eU, 0x92U
    },
    {
        0x07U, 0xe9U, 0x42U, 0xaaU, 0x4eU, 0x3cU, 0xd7U, 0xc0U, 0x4dU, 0xedU,
        0xc1U, 0xd4U, 0x6eU, 0x2eU, 0x8cU, 0xc4U, 0xc7U, 0x41U, 0xb3U, 0xd9U
    },
    {
        0xb6U, 0x58U, 0x23U, 0x18U, 0xddU, 0xcfU, 0xb6U, 0x7aU, 0x53U, 0xa6U,
        0x7dU, 0x67U, 0x6bU, 0x8aU, 0xd8U, 0x69U, 0xadU, 0xedU, 0x62U, 0x9aU
    },
    {
        0x85U, 0xf1U, 0x64U, 0x70U, 0x3eU, 0x61U, 0xa6U, 0x31U, 0x31U, 0xbeU,
        0x7eU, 0x45U, 0x95U, 0x8eU, 0x07U, 0x94U, 0x12U, 0x39U, 0x04U, 0xf9U
    }
};

static Esc_ERROR
EscTstHmacRipemd160_Compliance(
    void );

static Esc_ERROR
EscTstHmacRipemd160_ComplianceChunkwise(
    void );

static Esc_ERROR
EscTstHmacRipemd160_ComplianceLongKey(
    void );

static Esc_ERROR
EscTstHmacRipemd160_StepsParams(
    void );

static Esc_ERROR
EscTstHmacRipemd160_FullParams(
    void );

static Esc_ERROR
EscTstHmacRipemd160_Truncation(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstHmacRipemd160_Compliance(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "HMAC-RIPEMD-160 Compliance test\n" );
    for (i = 0U; (i < NUMBER_HMAC_160_RIP_TSTCASE) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 hmac_rmd_hash[EscHmacRipemd160_MAX_MAC_LENGTH];    /* hash value        */

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_rmd_msg[i] );
        EscTst_PrintString( "\"\n" );

        returnCode = EscHmacRipemd160_Calc(
                hmac_ripemd_test_keys,
                HMAC_160_TESTKEY_LEN,
                (const Esc_UINT8*)hmac_rmd_msg[i],
                EscTst_Strlen( hmac_rmd_msg[i] ),
                hmac_rmd_hash,
                EscHmacRipemd160_MAX_MAC_LENGTH);

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
            EscTst_PrintArray( "Expected Result", hmac_rmd_res[i], EscHmacRipemd160_MAX_MAC_LENGTH );
            EscTst_PrintArray( "Received Result", hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
            if ( EscTst_Memcmp( hmac_rmd_hash, hmac_rmd_res[i], EscHmacRipemd160_MAX_MAC_LENGTH ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
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
EscTstHmacRipemd160_ComplianceChunkwise(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "HMAC-RIPEMD-160 Compliance test (in chunks)\n" );
    for (i = 0U; (i < NUMBER_HMAC_160_RIP_TSTCASE) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT32 msgLen;
        const Esc_UINT8 *message;
        Esc_UINT8 hmac_rmd_hash[EscHmacRipemd160_MAX_MAC_LENGTH];    /* hash value        */
        EscHmacRipemd160_ContextT ctx;

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_rmd_msg[i] );
        EscTst_PrintString( "\"\n" );

        msgLen = EscTst_Strlen(hmac_rmd_msg[i]);
        message = (const Esc_UINT8 *) hmac_rmd_msg[i];

        /* Init context */
        returnCode = EscHmacRipemd160_Init(&ctx, hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN);

        /* Update in small chunk of increasing size */
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 remainingLen = msgLen;
            Esc_UINT32 chunkLen = 1U;
            Esc_UINT32 offset = 0U;

            while ( (returnCode == Esc_NO_ERROR) && (remainingLen > 0U) )
            {
                if (chunkLen > remainingLen)
                {
                    chunkLen = remainingLen;
                }

                /* Also call with zero-length updates in between */

                returnCode = EscHmacRipemd160_Update( &ctx, Esc_NULL_PTR, 0U );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscHmacRipemd160_Update( &ctx, &message[offset], chunkLen );
                }

                remainingLen -= chunkLen;
                offset += chunkLen;
                chunkLen += 3U;
            }

            /* Final zero-length update before finish */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacRipemd160_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        /* Finish MAC calculation */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacRipemd160_Finish(&ctx, hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH);
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac_rmd_res[i], EscHmacRipemd160_MAX_MAC_LENGTH );
            EscTst_PrintArray( "Received Result", hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
            if ( EscTst_Memcmp( hmac_rmd_hash, hmac_rmd_res[i], EscHmacRipemd160_MAX_MAC_LENGTH ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
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
EscTstHmacRipemd160_ComplianceLongKey(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 result[EscHmacRipemd160_MAX_MAC_LENGTH];

    static const Esc_UINT8 inputData[] =
    {
        0x51U, 0x24U, 0x74U, 0x7aU, 0x51U, 0x84U, 0xdbU, 0x00U, 0xd7U, 0x85U, 0x6eU, 0x08U,
        0xe8U, 0x80U, 0x68U, 0x83U, 0xeaU, 0x31U, 0x47U, 0x85U, 0x7fU, 0x50U, 0xe2U, 0xb8U,
        0xe1U, 0x14U, 0x21U, 0xc8U, 0xf2U, 0x60U, 0x5cU, 0x4aU
    };

    /* Long key with 65 bytes */
    static const Esc_UINT8 key[] =
    {
        0x99U, 0x1cU, 0x0eU, 0x48U, 0x3eU, 0x00U, 0x21U, 0xedU, 0x24U, 0x58U, 0xcfU, 0x6eU,
        0xe8U, 0xfdU, 0x12U, 0x3dU, 0x94U, 0xdeU, 0xebU, 0x84U, 0x87U, 0x9cU, 0x74U, 0x37U,
        0x67U, 0x25U, 0xf6U, 0x1eU, 0x4dU, 0xacU, 0x5dU, 0xdeU, 0x73U, 0xf1U, 0x82U, 0x17U,
        0xf4U, 0x4bU, 0xaaU, 0x45U, 0xf4U, 0x8fU, 0x85U, 0x4dU, 0xbdU, 0xf2U, 0x0bU, 0x57U,
        0xf8U, 0xe6U, 0xa5U, 0x3cU, 0x83U, 0x32U, 0xaaU, 0x1cU, 0xffU, 0x69U, 0xa4U, 0x39U,
        0x30U, 0x02U, 0x6eU, 0xfdU, 0x41U
    };

    /* HMAC result computed with OpenSSL */
    static const Esc_UINT8 expectedResult[EscHmacRipemd160_MAX_MAC_LENGTH] =
    {
        0x26U, 0x87U, 0x94U, 0x7aU, 0xc5U, 0xc6U, 0xb4U, 0x4bU, 0x79U, 0x6fU, 0xa4U, 0x3bU,
        0xe8U, 0x1dU, 0xe9U, 0x3bU, 0xeeU, 0x4cU, 0xa6U, 0x5aU
    };

    EscTst_PrintString( "HMAC-RIPEMD-160 Compliance test (using a long key > 64 bytes)\n" );

    returnCode = EscHmacRipemd160_Calc(key, sizeof(key), inputData, sizeof(inputData), result, EscHmacRipemd160_MAX_MAC_LENGTH);
    returnCode = EscTst_CheckResultSuccess(returnCode);

    if (returnCode == Esc_NO_ERROR)
    {
        if ( EscTst_Memcmp( result, expectedResult, EscHmacRipemd160_MAX_MAC_LENGTH ) )
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
EscTstHmacRipemd160_StepsParams(
    void )
{
    Esc_ERROR returnCode;
    EscHmacRipemd160_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac_rmd_hash[EscHmacRipemd160_MAX_MAC_LENGTH];

    msg = (const Esc_UINT8*)hmac_rmd_msg[1];
    msgLen = EscTst_Strlen( hmac_rmd_msg[1] );

    /* Init */

    EscTst_PrintString( "EscHmacRipemd160_Init() with ctx==0\n" );
    returnCode = EscHmacRipemd160_Init( Esc_NULL_PTR, hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Init() with hmac_key==0\n" );
        returnCode = EscHmacRipemd160_Init( &ctx, Esc_NULL_PTR, HMAC_160_TESTKEY_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Init() with key_length==0\n" );
        returnCode = EscHmacRipemd160_Init( &ctx, hmac_ripemd_test_keys, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    /* Update */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Update() with ctx==0\n" );
        returnCode = EscHmacRipemd160_Update( Esc_NULL_PTR, msg, msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Update() with chunk_data==0\n" );
        returnCode = EscHmacRipemd160_Update( &ctx, Esc_NULL_PTR, msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Finish() with ctx==0\n" );
        returnCode = EscHmacRipemd160_Finish( Esc_NULL_PTR, hmac_rmd_hash, EscRipemd160_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    /* Finish */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Finish() with hmac_hash==0\n" );
        returnCode = EscHmacRipemd160_Finish( &ctx, Esc_NULL_PTR, EscRipemd160_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Finish() with hmac_hashLength==0\n" );
        returnCode = EscHmacRipemd160_Finish( &ctx, hmac_rmd_hash, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Finish() with hmac_hashLength > EscRipemd160_DIGEST_LEN\n" );
        returnCode = EscHmacRipemd160_Finish( &ctx, hmac_rmd_hash, (Esc_UINT8)(EscRipemd160_DIGEST_LEN+1U) );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacRipemd160_FullParams(
    void )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac_rmd_hash[EscHmacRipemd160_MAX_MAC_LENGTH];

    msg = (const Esc_UINT8*)hmac_rmd_msg[1];
    msgLen = EscTst_Strlen( hmac_rmd_msg[1] );

    EscTst_PrintString( "EscHmacRipemd160_Calc() with all parameters\n" );
    returnCode = EscHmacRipemd160_Calc( hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN, msg, msgLen, hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Calc() with key==0\n" );
        returnCode = EscHmacRipemd160_Calc( Esc_NULL_PTR, HMAC_160_TESTKEY_LEN, msg, msgLen, hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Calc() with data==0\n" );
        returnCode = EscHmacRipemd160_Calc( hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN, Esc_NULL_PTR, msgLen, hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Calc() with hmac_hash==0\n" );
        returnCode = EscHmacRipemd160_Calc( hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN, msg, msgLen, Esc_NULL_PTR, EscHmacRipemd160_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacRipemd160_Calc() with key_length==0\n" );
        returnCode = EscHmacRipemd160_Calc( hmac_ripemd_test_keys, 0U, msg, msgLen, hmac_rmd_hash, EscHmacRipemd160_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacRipemd160_Truncation(
    void )
{
    static const Esc_CHAR* hmac_rmd_message = "abcdefghijklmnopqrstuvwxyz";
    static const Esc_UINT8 hmacLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacRipemd160_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacRipemd160_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacRipemd160_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacRipemd160_MAX_MAC_LENGTH - 1U)
    };

    Esc_UINT32 numHmacLengths = sizeof(hmacLengths) / sizeof(hmacLengths[0]);

    Esc_UINT8 result[EscHmacRipemd160_MAX_MAC_LENGTH];
    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscHmacRipemd160_ContextT ctx;
    Esc_UINT8 hmac_rmd_hash[EscHmacRipemd160_MAX_MAC_LENGTH];    /* hash value        */
    Esc_UINT8 zeroArray[EscHmacRipemd160_MAX_MAC_LENGTH];
    Esc_UINT8 i, j;

    EscTst_PrintString( "HMAC-RIPEMD-160 Truncation test\n" );
    for (i = 0U; (i < numHmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 hmacLength = hmacLengths[i];

        EscTst_PrintWord( "HMAC length = ", hmacLength);

        for (j = 0U; j < EscHmacRipemd160_MAX_MAC_LENGTH; j++)
        {
            zeroArray[j] = 0U;
            hmac_rmd_hash[j] = 0U;
        }

        returnCode = EscHmacRipemd160_Calc(
                hmac_ripemd_test_keys,
                HMAC_160_TESTKEY_LEN,
                (const Esc_UINT8*)hmac_rmd_message,
                EscTst_Strlen( hmac_rmd_message ),
                result,
                EscHmacRipemd160_MAX_MAC_LENGTH);

        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscHmacRipemd160_Init( &ctx, hmac_ripemd_test_keys, HMAC_160_TESTKEY_LEN );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacRipemd160_Update( &ctx, (const Esc_UINT8*)hmac_rmd_message, EscTst_Strlen( hmac_rmd_message ) );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacRipemd160_Finish( &ctx, hmac_rmd_hash, hmacLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
            EscTst_PrintArray( "Expected Result", result, hmacLength );
            EscTst_PrintArray( "Received Result", hmac_rmd_hash, hmacLength );
            if ( EscTst_Memcmp( hmac_rmd_hash, result, hmacLength ) )
            {
                if ( EscTst_Memcmp( &hmac_rmd_hash[hmacLength], &zeroArray[hmacLength], EscHmacRipemd160_MAX_MAC_LENGTH - (Esc_UINT32)hmacLength ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                }
                else
                {
                    EscTst_PrintString( "FAILED truncation!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
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


Esc_ERROR
EscTstHmacRipemd160_Perform(
    void )
{
    Esc_ERROR returnCode;

    returnCode = EscTstHmacRipemd160_Compliance();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacRipemd160_ComplianceChunkwise();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacRipemd160_ComplianceLongKey();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacRipemd160_StepsParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacRipemd160_FullParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacRipemd160_Truncation();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
