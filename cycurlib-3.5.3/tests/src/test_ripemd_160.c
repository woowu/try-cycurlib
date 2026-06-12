/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief RIPEMD-160 Selftest

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_ripemd_160.h"
#include "selftest.h"
#include "ripemd_160.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define NUMBER_OF_RIPEMD_160_TESTCASES 8U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
static const Esc_CHAR* const rmd_msg[NUMBER_OF_RIPEMD_160_TESTCASES] =
{
    "",                         /* empty string */
    "a",                        /* one byte     */
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
};

static const Esc_UINT8 rmd_res[NUMBER_OF_RIPEMD_160_TESTCASES][EscRipemd160_DIGEST_LEN] =
{
    {
        0x9cU, 0x11U, 0x85U, 0xa5U, 0xc5U, 0xe9U, 0xfcU, 0x54U, 0x61U, 0x28U,
        0x08U, 0x97U, 0x7eU, 0xe8U, 0xf5U, 0x48U, 0xb2U, 0x25U, 0x8dU, 0x31U
    },
    {
        0x0bU, 0xdcU, 0x9dU, 0x2dU, 0x25U, 0x6bU, 0x3eU, 0xe9U, 0xdaU, 0xaeU,
        0x34U, 0x7bU, 0xe6U, 0xf4U, 0xdcU, 0x83U, 0x5aU, 0x46U, 0x7fU, 0xfeU
    },
    {
        0x8eU, 0xb2U, 0x08U, 0xf7U, 0xe0U, 0x5dU, 0x98U, 0x7aU, 0x9bU, 0x04U,
        0x4aU, 0x8eU, 0x98U, 0xc6U, 0xb0U, 0x87U, 0xf1U, 0x5aU, 0x0bU, 0xfcU
    },
    {
        0x5dU, 0x06U, 0x89U, 0xefU, 0x49U, 0xd2U, 0xfaU, 0xe5U, 0x72U, 0xb8U,
        0x81U, 0xb1U, 0x23U, 0xa8U, 0x5fU, 0xfaU, 0x21U, 0x59U, 0x5fU, 0x36U
    },
    {
        0xf7U, 0x1cU, 0x27U, 0x10U, 0x9cU, 0x69U, 0x2cU, 0x1bU, 0x56U, 0xbbU,
        0xdcU, 0xebU, 0x5bU, 0x9dU, 0x28U, 0x65U, 0xb3U, 0x70U, 0x8dU, 0xbcU
    },
    {
        0x12U, 0xa0U, 0x53U, 0x38U, 0x4aU, 0x9cU, 0x0cU, 0x88U, 0xe4U, 0x05U,
        0xa0U, 0x6cU, 0x27U, 0xdcU, 0xf4U, 0x9aU, 0xdaU, 0x62U, 0xebU, 0x2bU
    },
    {
        0xb0U, 0xe2U, 0x0bU, 0x6eU, 0x31U, 0x16U, 0x64U, 0x02U, 0x86U, 0xedU,
        0x3aU, 0x87U, 0xa5U, 0x71U, 0x30U, 0x79U, 0xb2U, 0x1fU, 0x51U, 0x89U
    },
    {
        0x9bU, 0x75U, 0x2eU, 0x45U, 0x57U, 0x3dU, 0x4bU, 0x39U, 0xf4U, 0xdbU,
        0xd3U, 0x32U, 0x3cU, 0xabU, 0x82U, 0xbfU, 0x63U, 0x32U, 0x6bU, 0xfbU
    }
};

static Esc_ERROR
EscTstRipemd160_Compliance(
    void );

static Esc_ERROR
EscTstRipemd160_ComplianceChunkwise(
    void );

static Esc_ERROR
EscTstRipemd160_FullParams(
    void );

static Esc_ERROR
EscTstRipemd160_StepsParams(
    void );

static Esc_ERROR
EscTstRipemd160_Truncation(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstRipemd160_Compliance(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "RIPEMD-160 Compliance test\n" );

    for (i = 0U; (i < NUMBER_OF_RIPEMD_160_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscRipemd160_ContextT rmd_ctx;              /* hash context */
        Esc_UINT8 rmd_hash[EscRipemd160_DIGEST_LEN];    /* hash value   */
        Esc_UINT32 msgLen;
        const Esc_UINT8* message;

        msgLen = EscTst_Strlen( rmd_msg[i] );
        if (msgLen == 0U)
        {
            message = Esc_NULL_PTR;
        }
        else
        {
            message = (const Esc_UINT8*)rmd_msg[i];
        }

        returnCode = EscRipemd160_Init( &rmd_ctx );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Message: \"" );
            EscTst_PrintString( rmd_msg[i] );
            EscTst_PrintString( "\"\n" );
            returnCode = EscRipemd160_Update( &rmd_ctx, message, msgLen );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Finish( &rmd_ctx, rmd_hash, EscRipemd160_DIGEST_LEN );
        }

        /* compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", rmd_res[i], EscRipemd160_DIGEST_LEN );
            EscTst_PrintArray( "Received Result", rmd_hash, EscRipemd160_DIGEST_LEN );
            if ( EscTst_Memcmp( rmd_hash, rmd_res[i], EscRipemd160_DIGEST_LEN ) )
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
EscTstRipemd160_ComplianceChunkwise(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "RIPEMD-160 Compliance test (in chunks)\n" );

    for (i = 0U; (i < NUMBER_OF_RIPEMD_160_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscRipemd160_ContextT rmd_ctx;              /* hash context */
        Esc_UINT8 rmd_hash[EscRipemd160_DIGEST_LEN];    /* hash value   */
        Esc_UINT32 msgLen;
        Esc_UINT32 chunkLen;
        Esc_UINT32 offset;
        Esc_UINT32 remainingLen;
        const Esc_UINT8* message;

        msgLen = EscTst_Strlen( rmd_msg[i] );
        if (msgLen == 0U)
        {
            message = Esc_NULL_PTR;
        }
        else
        {
            message = (const Esc_UINT8*)rmd_msg[i];
        }

        returnCode = EscRipemd160_Init( &rmd_ctx );

        remainingLen = msgLen;
        chunkLen = 1U;
        offset = 0U;

        while ( (returnCode == Esc_NO_ERROR) && (remainingLen > 0U) )
        {
            if (chunkLen > remainingLen)
            {
                chunkLen = remainingLen;
            }

            returnCode = EscRipemd160_Update( &rmd_ctx, &message[offset], chunkLen );

            remainingLen -= chunkLen;
            offset += chunkLen;
            chunkLen += 3U;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Finish( &rmd_ctx, rmd_hash, EscRipemd160_DIGEST_LEN );
        }

        /* compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", rmd_res[i], EscRipemd160_DIGEST_LEN );
            EscTst_PrintArray( "Received Result", rmd_hash, EscRipemd160_DIGEST_LEN );
            if ( EscTst_Memcmp( rmd_hash, rmd_res[i], EscRipemd160_DIGEST_LEN ) )
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
EscTstRipemd160_StepsParams(
    void )
{
    Esc_ERROR returnCode;
    EscRipemd160_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 rmd_hash[EscRipemd160_DIGEST_LEN];

    msg = (const Esc_UINT8*)rmd_msg[1];
    msgLen = EscTst_Strlen( rmd_msg[1] );

    EscTst_PrintString( "EscRipemd160_Init() with ctx==0\n" );
    returnCode = EscRipemd160_Init( Esc_NULL_PTR );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscRipemd160_Update() with ctx==0\n" );
        returnCode = EscRipemd160_Update( Esc_NULL_PTR, msg, msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscRipemd160_Update() with chunk_data==0 and chunk_length>0\n" );
            returnCode = EscRipemd160_Update( &ctx, Esc_NULL_PTR, 1U );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscRipemd160_Finish() with ctx==0\n" );
        returnCode = EscRipemd160_Finish( Esc_NULL_PTR, rmd_hash, EscRipemd160_DIGEST_LEN );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscRipemd160_Finish() with rmd_hash==0\n" );
            returnCode = EscRipemd160_Finish( &ctx, Esc_NULL_PTR, EscRipemd160_DIGEST_LEN );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscRipemd160_Finish() with rmd_hashLength==0\n" );
                returnCode = EscRipemd160_Finish( &ctx, rmd_hash, 0U );
                if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscRipemd160_Finish() with rmd_hashLength > EscRipemd160_DIGEST_LEN\n" );
                    returnCode = EscRipemd160_Finish( &ctx, rmd_hash, (Esc_UINT8)(EscRipemd160_DIGEST_LEN+1U) );
                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstRipemd160_FullParams(
    void )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 rmd_hash[EscRipemd160_DIGEST_LEN];

    msg = (const Esc_UINT8*)rmd_msg[1];
    msgLen = EscTst_Strlen( rmd_msg[1] );

    EscTst_PrintString( "EscRipemd160_Calc() with all parameters\n" );
    returnCode = EscRipemd160_Calc( msg, msgLen, rmd_hash, EscRipemd160_DIGEST_LEN );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscRipemd160_Calc() with message==0 and data_length>0\n" );
        returnCode = EscRipemd160_Calc( Esc_NULL_PTR, 1U, rmd_hash, EscRipemd160_DIGEST_LEN );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscRipemd160_Calc() with rmd_hash==0\n" );
            returnCode = EscRipemd160_Calc( msg, msgLen, Esc_NULL_PTR, EscRipemd160_DIGEST_LEN );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstRipemd160_Truncation(
    void )
{
    static const Esc_CHAR* msg = "message digest";
    static const Esc_UINT8 digestLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscRipemd160_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscRipemd160_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscRipemd160_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscRipemd160_DIGEST_LEN - 1U)
    };

    Esc_UINT32 numDigestLengths = sizeof(digestLengths) / sizeof(digestLengths[0]);

    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscRipemd160_ContextT ctx;
    Esc_UINT8 rmd_result[EscRipemd160_DIGEST_LEN];
    Esc_UINT8 zeroArray[EscRipemd160_DIGEST_LEN];
    Esc_UINT8 digest[EscRipemd160_DIGEST_LEN];
    Esc_UINT8 i, j;

    for (i = 0U; (i < numDigestLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 digestLength = digestLengths[i];

        for (j = 0U; j < EscRipemd160_DIGEST_LEN; j++)
        {
            digest[j] = 0U;
            zeroArray[j] = 0;
        }

        returnCode = EscRipemd160_Calc( (const Esc_UINT8*)msg, EscTst_Strlen( msg ), rmd_result, EscRipemd160_DIGEST_LEN );

        EscTst_PrintWord( "RIPEMD-160 Truncation test with digestLength = ", digestLength );

        if (returnCode == Esc_NO_ERROR )
        {
            returnCode = EscRipemd160_Init( &ctx );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Message: \"" );
            EscTst_PrintString( msg );
            EscTst_PrintString( "\"\n" );
            returnCode = EscRipemd160_Update( &ctx, (const Esc_UINT8*)msg, EscTst_Strlen( msg ) );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscRipemd160_Finish( &ctx, digest, digestLength );
            }
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", rmd_result, (Esc_UINT32)digestLength );
            EscTst_PrintArray( "Received Result", digest, (Esc_UINT32)digestLength );
            if ( EscTst_Memcmp( digest, rmd_result, (Esc_UINT32)digestLength ) )
            {
                if ( EscTst_Memcmp( &digest[digestLength], &zeroArray[digestLength], (EscRipemd160_DIGEST_LEN - (Esc_UINT32)digestLength )) )
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
EscTstRipemd160_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstRipemd160_Compliance();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstRipemd160_ComplianceChunkwise();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstRipemd160_StepsParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstRipemd160_FullParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstRipemd160_Truncation();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
