/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief SHA-1 Selftest

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_sha_1.h"
#include "selftest.h"
#include "sha_1.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
/* Number of testcases for SHA compliance test */
#define NUMBER_OF_SHA_1_TESTCASES 10U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
/* SHA-1 test vectors */
static const Esc_CHAR* const sha1_msg[NUMBER_OF_SHA_1_TESTCASES] =
{
    "",                         /* empty string */
    "a",                        /* one byte     */
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  /* Block boundary test */
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   /* boundary test */
};

static Esc_ERROR
EscTstSha1_Compliance(
    void );

static Esc_ERROR
EscTstSha1_ComplianceSteps(
    void );

static Esc_ERROR
EscTstSha1_StepsParams(
    void );

static Esc_ERROR
EscTstSha1_FullParams(
    void );

static Esc_ERROR
EscTstSha1_Truncation(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstSha1_Compliance(
    void )
{
    /* expected results after hashing */
    static const Esc_UINT8 sha1_res[NUMBER_OF_SHA_1_TESTCASES][EscSha1_DIGEST_LEN] =
    {
        {
            0xdaU, 0x39U, 0xa3U, 0xeeU, 0x5eU, 0x6bU, 0x4bU, 0x0dU, 0x32U, 0x55U,
            0xbfU, 0xefU, 0x95U, 0x60U, 0x18U, 0x90U, 0xafU, 0xd8U, 0x07U, 0x09U
        },
        {
            0x86U, 0xf7U, 0xe4U, 0x37U, 0xfaU, 0xa5U, 0xa7U, 0xfcU, 0xe1U, 0x5dU,
            0x1dU, 0xdcU, 0xb9U, 0xeaU, 0xeaU, 0xeaU, 0x37U, 0x76U, 0x67U, 0xb8U
        },
        {
            0xa9U, 0x99U, 0x3eU, 0x36U, 0x47U, 0x06U, 0x81U, 0x6aU, 0xbaU, 0x3eU,
            0x25U, 0x71U, 0x78U, 0x50U, 0xc2U, 0x6cU, 0x9cU, 0xd0U, 0xd8U, 0x9dU
        },
        {
            0xc1U, 0x22U, 0x52U, 0xceU, 0xdaU, 0x8bU, 0xe8U, 0x99U, 0x4dU, 0x5fU,
            0xa0U, 0x29U, 0x0aU, 0x47U, 0x23U, 0x1cU, 0x1dU, 0x16U, 0xaaU, 0xe3U
        },
        {
            0x32U, 0xd1U, 0x0cU, 0x7bU, 0x8cU, 0xf9U, 0x65U, 0x70U, 0xcaU, 0x04U,
            0xceU, 0x37U, 0xf2U, 0xa1U, 0x9dU, 0x84U, 0x24U, 0x0dU, 0x3aU, 0x89U
        },
        {
            0x84U, 0x98U, 0x3eU, 0x44U, 0x1cU, 0x3bU, 0xd2U, 0x6eU, 0xbaU, 0xaeU,
            0x4aU, 0xa1U, 0xf9U, 0x51U, 0x29U, 0xe5U, 0xe5U, 0x46U, 0x70U, 0xf1U
        },
        {
            0x76U, 0x1cU, 0x45U, 0x7bU, 0xf7U, 0x3bU, 0x14U, 0xd2U, 0x7eU, 0x9eU,
            0x92U, 0x65U, 0xc4U, 0x6fU, 0x4bU, 0x4dU, 0xdaU, 0x11U, 0xf9U, 0x40U
        },
        {
            0x50U, 0xabU, 0xf5U, 0x70U, 0x6aU, 0x15U, 0x09U, 0x90U, 0xa0U, 0x8bU,
            0x2cU, 0x5eU, 0xa4U, 0x0fU, 0xa0U, 0xe5U, 0x85U, 0x55U, 0x47U, 0x32U
        },
        {
            0xc1U, 0xc8U, 0xbbU, 0xdcU, 0x22U, 0x79U, 0x6eU, 0x28U, 0xc0U, 0xe1U,
            0x51U, 0x63U, 0xd2U, 0x8U, 0x99U, 0xb6U, 0x56U, 0x21U, 0xd6U, 0x5aU
        },
        {
            0x03U, 0xf0U, 0x9fU, 0x5bU, 0x15U, 0x8aU, 0x7aU, 0x8cU, 0xdaU, 0xd9U,
            0x20U, 0xbdU, 0xdcU, 0x29U, 0xb8U, 0x1cU, 0x18U, 0xa5U, 0x51U, 0xf5U
        }
    };

    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscSha1_ContextT sha_ctx;   /* hashing context   */
    Esc_UINT8 sha_hash[EscSha1_DIGEST_LEN];   /* hash value        */

    EscTst_PrintString( "SHA-1 Compliance test\n" );

    for (i = 0U; (i < NUMBER_OF_SHA_1_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscSha1_Init( &sha_ctx );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Message: \"" );
            EscTst_PrintString( sha1_msg[i] );
            EscTst_PrintString( "\"\n" );
            returnCode = EscSha1_Update( &sha_ctx, (const Esc_UINT8*)sha1_msg[i], EscTst_Strlen( sha1_msg[i] ) );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha1_Finish( &sha_ctx, sha_hash, EscSha1_DIGEST_LEN );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
            EscTst_PrintArray( "Expected result", sha1_res[i], EscSha1_DIGEST_LEN );
            EscTst_PrintArray( "Received result", sha_hash, EscSha1_DIGEST_LEN );
            if ( EscTst_Memcmp( sha_hash, sha1_res[i], EscSha1_DIGEST_LEN ) )
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

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstSha1_ComplianceSteps(
    void )
{
    /* A long test vector */
    static const Esc_CHAR sha1_msg_long[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    static const Esc_UINT8 sha1_res_long[EscSha1_DIGEST_LEN] =
    {
        0x50U, 0xabU, 0xf5U, 0x70U, 0x6aU, 0x15U, 0x09U, 0x90U, 0xa0U, 0x8bU,
        0x2cU, 0x5eU, 0xa4U, 0x0fU, 0xa0U, 0xe5U, 0x85U, 0x55U, 0x47U, 0x32U
    };

    Esc_ERROR returnCode;
    EscSha1_ContextT sha_ctx;   /* hashing context   */
    Esc_UINT8 sha_hash[EscSha1_DIGEST_LEN];   /* hash value        */

    EscTst_PrintString( "SHA-1 ComplianceSteps test\n" );

    returnCode = EscSha1_Init( &sha_ctx );

    /* Zero length update() */
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update with zero length\n" );
        returnCode = EscSha1_Update( &sha_ctx, Esc_NULL_PTR, 0U);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( sha1_msg_long );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintString( "EscSha1_Update (First 3 bytes)\n" );
        returnCode = EscSha1_Update( &sha_ctx, (const Esc_UINT8*)sha1_msg_long, 3U );
    }

    /* Zero length update() */
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update with zero length\n" );
        returnCode = EscSha1_Update( &sha_ctx, Esc_NULL_PTR, 0U);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update (Remaining bytes)\n" );
        returnCode = EscSha1_Update( &sha_ctx, (const Esc_UINT8*)&sha1_msg_long[3], EscTst_Strlen( sha1_msg_long ) - 3U );
    }

    /* Zero length update() */
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update with zero length\n" );
        returnCode = EscSha1_Update( &sha_ctx, Esc_NULL_PTR, 0U);
    }


    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscSha1_Finish( &sha_ctx, sha_hash, EscSha1_DIGEST_LEN );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* compare results */
        EscTst_PrintArray( "Expected result", sha1_res_long, EscSha1_DIGEST_LEN );
        EscTst_PrintArray( "Received result", sha_hash, EscSha1_DIGEST_LEN );
        if ( EscTst_Memcmp( sha_hash, sha1_res_long, EscSha1_DIGEST_LEN ) )
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
EscTstSha1_StepsParams(
    void )
{
    Esc_ERROR returnCode;
    EscSha1_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 sha_hash[EscSha1_DIGEST_LEN];

    msg = (const Esc_UINT8*)sha1_msg[1];
    msgLen = EscTst_Strlen( sha1_msg[1] );

    /* Tests for init() */

    EscTst_PrintString( "EscSha1_Init() with ctx==0\n" );
    returnCode = EscSha1_Init( Esc_NULL_PTR );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    /* Tests for update() */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update() with ctx==0\n" );
        returnCode = EscSha1_Update( Esc_NULL_PTR, msg, msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update() with message==0 and dataLen>0\n" );
        returnCode = EscSha1_Update( &ctx, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Update() with message==0 and dataLen>0\n" );
        returnCode = EscSha1_Update( &ctx, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    /* Tests for finish() */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Finish() with ctx==0\n" );
        returnCode = EscSha1_Finish( Esc_NULL_PTR, sha_hash, EscSha1_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Finish() with sha_hash==0\n" );
        returnCode = EscSha1_Finish( &ctx, Esc_NULL_PTR, EscSha1_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Finish() with digestLength==0\n" );
        returnCode = EscSha1_Finish( &ctx, sha_hash, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Finish() with digestLength > EscSha1_DIGEST_LEN\n" );
        returnCode = EscSha1_Finish( &ctx, sha_hash, (Esc_UINT8)(EscSha1_DIGEST_LEN+1U) );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }


    return returnCode;
}

static Esc_ERROR
EscTstSha1_FullParams(
    void )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 sha_hash[EscSha1_DIGEST_LEN];
    EscTst_PrintString( "\"\n" );

    msg = (const Esc_UINT8*)sha1_msg[1];
    msgLen = EscTst_Strlen( sha1_msg[1] );

    EscTst_PrintString( "EscSha1_Calc() with all parameters\n" );
    returnCode = EscSha1_Calc( msg, msgLen, sha_hash, EscSha1_DIGEST_LEN );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscSha1_Calc() with message==0 and dataLen>0\n" );
        returnCode = EscSha1_Calc( Esc_NULL_PTR, 1U, sha_hash, EscSha1_DIGEST_LEN );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscSha1_Calc() with sha1_hash==0\n" );
            returnCode = EscSha1_Calc( msg, msgLen, Esc_NULL_PTR, EscSha1_DIGEST_LEN );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha1_Truncation(
    void )
{
    static const Esc_CHAR* sha1_msgTruncation = "abcdefghijklmnopqrstuvwxyz";
    static const Esc_UINT8 digestLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscSha1_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscSha1_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscSha1_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscSha1_DIGEST_LEN - 1U)
    };

    Esc_UINT32 numDigestLengths = sizeof(digestLengths) / sizeof(digestLengths[0]);

    Esc_UINT8 sha1_res[EscSha1_DIGEST_LEN];
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;
    EscSha1_ContextT sha_ctx;   /* hashing context   */
    Esc_UINT8 digest[EscSha1_DIGEST_LEN];   /* hash value  */
    Esc_UINT8 zeroArray[EscSha1_DIGEST_LEN];

    for (i = 0U; (i < numDigestLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 digestLength = digestLengths[i];

        for (j = 0U; j < EscSha1_DIGEST_LEN; j++)
        {
            digest[j] = 0U;
            zeroArray[j] = 0;
        }

        returnCode = EscSha1_Calc((const Esc_UINT8*)sha1_msgTruncation, EscTst_Strlen( sha1_msgTruncation ), sha1_res, digestLength);

        EscTst_PrintWord( "SHA-1 Truncation test with digestLength = ", digestLength );

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha1_Init( &sha_ctx );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Message: \"" );
            EscTst_PrintString( sha1_msgTruncation );
            returnCode = EscSha1_Update( &sha_ctx, (const Esc_UINT8*)sha1_msgTruncation, EscTst_Strlen( sha1_msgTruncation ) );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha1_Finish( &sha_ctx, digest, digestLength );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
            EscTst_PrintArray( "Expected result", sha1_res, (Esc_UINT32)digestLength );
            EscTst_PrintArray( "Received result", digest, (Esc_UINT32)digestLength );
            if ( EscTst_Memcmp( digest, sha1_res, (Esc_UINT32)digestLength ) )
            {
                if ( EscTst_Memcmp( &digest[digestLength], zeroArray, (EscSha1_DIGEST_LEN - (Esc_UINT32)digestLength )) )
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
EscTstSha1_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstSha1_Compliance();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha1_ComplianceSteps();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha1_StepsParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha1_FullParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha1_Truncation();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
