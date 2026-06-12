/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief HMAC-SHA-1 Selftest


   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_hmac_sha_1.h"
#include "selftest.h"
#include "hmac_sha_1.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define NUMBER_OF_HMAC_SHA_1_TESTCASES 8U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

typedef struct
{
    Esc_UINT8 len;
    Esc_UINT8 message[80];
} hmac_sha1_test_key;

static const hmac_sha1_test_key hmac_sha1_test_keys[NUMBER_OF_HMAC_SHA_1_TESTCASES] =
{
    {
        20U,
        {
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        4U,
        {
            0x4aU, 0x65U, 0x66U, 0x65U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        20U,
        {
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        25U,
        {
            0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
            0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U,
            0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U,
            0x19U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        20U,
        {
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        80U,
        {
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU
        }
    },
    {
        80U,
        {
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU
        }
    },
    {
        25U,
        {
            0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
            0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U,
            0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U,
            0x19U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
};

/* HMAC SHA-1 message */
static const Esc_CHAR* const hmac_msg[NUMBER_OF_HMAC_SHA_1_TESTCASES] =
{
    "Hi There",
    "what do ya want for nothing?",
    "ÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝÝ",
    "ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ",
    "Test With Truncation",
    "Test Using Larger Than Block-Size Key - Hash Key First",
    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
    "Hi There"
};

/* HMAC SHA-1 expected values */
static const Esc_UINT8 hmac_res[NUMBER_OF_HMAC_SHA_1_TESTCASES][EscHmacSha1_MAX_MAC_LENGTH] =
{
    {
        0xb6U, 0x17U, 0x31U, 0x86U, 0x55U, 0x05U, 0x72U, 0x64U, 0xe2U, 0x8bU,
        0xc0U, 0xb6U, 0xfbU, 0x37U, 0x8cU, 0x8eU, 0xf1U, 0x46U, 0xbeU, 0x00U
    },
    {
        0xefU, 0xfcU, 0xdfU, 0x6aU, 0xe5U, 0xebU, 0x2fU, 0xa2U, 0xd2U, 0x74U,
        0x16U, 0xd5U, 0xf1U, 0x84U, 0xdfU, 0x9cU, 0x25U, 0x9aU, 0x7cU, 0x79U
    },
    {
        0x12U, 0x5dU, 0x73U, 0x42U, 0xb9U, 0xacU, 0x11U, 0xcdU, 0x91U, 0xa3U,
        0x9aU, 0xf4U, 0x8aU, 0xa1U, 0x7bU, 0x4fU, 0x63U, 0xf1U, 0x75U, 0xd3U
    },
    {
        0x4cU, 0x90U, 0x07U, 0xf4U, 0x02U, 0x62U, 0x50U, 0xc6U, 0xbcU, 0x84U,
        0x14U, 0xf9U, 0xbfU, 0x50U, 0xc8U, 0x6cU, 0x2dU, 0x72U, 0x35U, 0xdaU
    },
    {
        0x4cU, 0x1aU, 0x03U, 0x42U, 0x4bU, 0x55U, 0xe0U, 0x7fU, 0xe7U, 0xf2U,
        0x7bU, 0xe1U, 0xd5U, 0x8bU, 0xb9U, 0x32U, 0x4aU, 0x9aU, 0x5aU, 0x04U
    },
    {
        0xaaU, 0x4aU, 0xe5U, 0xe1U, 0x52U, 0x72U, 0xd0U, 0x0eU, 0x95U, 0x70U,
        0x56U, 0x37U, 0xceU, 0x8aU, 0x3bU, 0x55U, 0xedU, 0x40U, 0x21U, 0x12U
    },
    {
        0xe8U, 0xe9U, 0x9dU, 0x0fU, 0x45U, 0x23U, 0x7dU, 0x78U, 0x6dU, 0x6bU,
        0xbaU, 0xa7U, 0x96U, 0x5cU, 0x78U, 0x08U, 0xbbU, 0xffU, 0x1aU, 0x91U
    },
    {
        0x00U, 0xa9U, 0xcfU, 0x7aU, 0xe7U, 0x10U, 0xe7U, 0x9bU, 0xd4U, 0xddU,
        0x65U, 0xcdU, 0x7bU, 0x46U, 0x4bU, 0xc4U, 0x61U, 0x28U, 0xa5U, 0x57U
    }
};


static Esc_ERROR
EscTstHmacSha1_Compliance(
    void );

static Esc_ERROR
EscTstHmacSha1_ComplianceChunkwise(
    void );

static Esc_ERROR
EscTstHmacSha1_StepsParams(
    void );

static Esc_ERROR
EscTstHmacSha1_FullParams(
    void );

static Esc_ERROR
EscTstHmacSha1_Truncation(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstHmacSha1_Compliance(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "HMAC-SHA-1 Compliance test\n" );
    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_1_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 sha_hash[EscHmacSha1_MAX_MAC_LENGTH];      /* hash value */

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha1_test_keys[i].message, (Esc_UINT32)hmac_sha1_test_keys[i].len );

        returnCode = EscHmacSha1_Calc(
                hmac_sha1_test_keys[i].message,
                (Esc_UINT32)hmac_sha1_test_keys[i].len,
                (const Esc_UINT8*)hmac_msg[i],
                EscTst_Strlen( hmac_msg[i] ),
                sha_hash,
                EscHmacSha1_MAX_MAC_LENGTH );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac_res[i], EscHmacSha1_MAX_MAC_LENGTH );
            EscTst_PrintArray( "Received Result", sha_hash, EscHmacSha1_MAX_MAC_LENGTH );
            if ( EscTst_Memcmp( sha_hash, hmac_res[i], EscHmacSha1_MAX_MAC_LENGTH ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
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
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha1_ComplianceChunkwise(
    void )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "HMAC-SHA-1 Compliance test (chunk-wise)\n" );
    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_1_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT32 msgLen;
        const Esc_UINT8 *message;
        Esc_UINT8 sha_hash[EscHmacSha1_MAX_MAC_LENGTH];      /* hash value */
        EscHmacSha1_ContextT ctx;

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha1_test_keys[i].message, (Esc_UINT32)hmac_sha1_test_keys[i].len );

        msgLen = EscTst_Strlen(hmac_msg[i]);
        message = (const Esc_UINT8 *) hmac_msg[i];

        /* Init context */
        returnCode = EscHmacSha1_Init(&ctx, hmac_sha1_test_keys[i].message, (Esc_UINT32)hmac_sha1_test_keys[i].len);

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
                returnCode = EscHmacSha1_Update( &ctx, Esc_NULL_PTR, 0U );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscHmacSha1_Update( &ctx, &message[offset], chunkLen );
                }

                remainingLen -= chunkLen;
                offset += chunkLen;
                chunkLen += 3U;
            }

            /* Final zero-length update before finish */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha1_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        /* Finish MAC calculation */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha1_Finish(&ctx, sha_hash, EscHmacSha1_MAX_MAC_LENGTH);
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac_res[i], EscHmacSha1_MAX_MAC_LENGTH );
            EscTst_PrintArray( "Received Result", sha_hash, EscHmacSha1_MAX_MAC_LENGTH );
            if ( EscTst_Memcmp( sha_hash, hmac_res[i], EscHmacSha1_MAX_MAC_LENGTH ) )
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
EscTstHmacSha1_StepsParams(
    void )
{
    Esc_ERROR returnCode;
    EscHmacSha1_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac_rmd_hash[EscHmacSha1_MAX_MAC_LENGTH];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;

    key = (const Esc_UINT8*)hmac_sha1_test_keys[1].message;
    keyLen = hmac_sha1_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    EscTst_PrintString( "EscHmacSha1_Init() with ctx==0\n" );
    returnCode = EscHmacSha1_Init( Esc_NULL_PTR, key, keyLen );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Init() with hmac_key==0\n" );
        returnCode = EscHmacSha1_Init( &ctx, Esc_NULL_PTR, keyLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha1_Init() with key_length==0\n" );
            returnCode = EscHmacSha1_Init( &ctx, key, 0U );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
        }
    }


    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Update() with ctx==0\n" );
        returnCode = EscHmacSha1_Update( Esc_NULL_PTR, msg, msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha1_Update() with chunk_data==0\n" );
            returnCode = EscHmacSha1_Update( &ctx, Esc_NULL_PTR, msgLen );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Finish() with ctx==0\n" );
        returnCode = EscHmacSha1_Finish( Esc_NULL_PTR, hmac_rmd_hash, EscSha1_DIGEST_LEN );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha1_Finish() with hmac_hash==0\n" );
            returnCode = EscHmacSha1_Finish( &ctx, Esc_NULL_PTR, EscSha1_DIGEST_LEN );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscHmacSha1_Finish() with hmac_hashLength==0\n" );
                returnCode = EscHmacSha1_Finish( &ctx, hmac_rmd_hash, 0U );
                if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscHmacSha1_Finish() with hmac_hashLength > EscSha1_DIGEST_LEN\n" );
                    returnCode = EscHmacSha1_Finish( &ctx, hmac_rmd_hash, (Esc_UINT8)(EscSha1_DIGEST_LEN+1U) );
                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha1_FullParams(
    void )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac_rmd_hash[EscHmacSha1_MAX_MAC_LENGTH];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;

    key = (const Esc_UINT8*)hmac_sha1_test_keys[1].message;
    keyLen = hmac_sha1_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    EscTst_PrintString( "EscHmacSha1_Calc() with all parameters\n" );
    returnCode = EscHmacSha1_Calc( key, keyLen, msg, msgLen, hmac_rmd_hash, EscHmacSha1_MAX_MAC_LENGTH );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Calc() with key==0\n" );
        returnCode = EscHmacSha1_Calc( Esc_NULL_PTR, keyLen, msg, msgLen, hmac_rmd_hash, EscHmacSha1_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Calc() with message==0\n" );
        returnCode = EscHmacSha1_Calc( key, keyLen, Esc_NULL_PTR, msgLen, hmac_rmd_hash, EscHmacSha1_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Calc() with hmac_hash==0\n" );
        returnCode = EscHmacSha1_Calc( key, keyLen, msg, msgLen, Esc_NULL_PTR, EscHmacSha1_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha1_Calc() with key_length==0\n" );
        returnCode = EscHmacSha1_Calc( key, 0U, msg, msgLen, hmac_rmd_hash, EscHmacSha1_MAX_MAC_LENGTH );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha1_Truncation(
    void )
{
    static const Esc_UINT8 key[20] =
    {
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU
    };
    static const Esc_CHAR* hmac_sha1_truncationMsg = "Test With Truncation";

    static const Esc_UINT8 hmacLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacSha1_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacSha1_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacSha1_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacSha1_MAX_MAC_LENGTH - 1U)
    };

    Esc_UINT32 numHmacLengths = sizeof(hmacLengths) / sizeof(hmacLengths[0]);

    Esc_UINT8 hmac_resultTruncation[EscHmacSha1_MAX_MAC_LENGTH];
    Esc_UINT8 hmac_hash_digest[EscHmacSha1_MAX_MAC_LENGTH];      /* hash value */
    Esc_UINT8 zeroArray[EscHmacSha1_MAX_MAC_LENGTH];
    Esc_UINT32 keyLen = 20U;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;

    EscHmacSha1_ContextT ctx;

    EscTst_PrintString( "HMAC-SHA-1 Truncation test \n" );

    for (i = 0U; (i < numHmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 hmacLength = hmacLengths[i];

        EscTst_PrintWord( "HMAC length = ", hmacLength);

        for (j = 0U; j < EscHmacSha1_MAX_MAC_LENGTH; j++)
        {
            hmac_hash_digest[j] = 0U;
            zeroArray[j] = 0U;
        }

        returnCode = EscHmacSha1_Calc(
                key,
                keyLen,
                (const Esc_UINT8*)hmac_sha1_truncationMsg,
                EscTst_Strlen( hmac_sha1_truncationMsg ),
                hmac_resultTruncation,
                EscHmacSha1_MAX_MAC_LENGTH);

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha1_Init( &ctx, key, keyLen );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha1_Update( &ctx, (const Esc_UINT8*)hmac_sha1_truncationMsg, EscTst_Strlen( hmac_sha1_truncationMsg ) );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha1_Finish( &ctx, hmac_hash_digest, hmacLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac_resultTruncation, (Esc_UINT32)hmacLength );
            EscTst_PrintArray( "Received Result", hmac_hash_digest, (Esc_UINT32)hmacLength );
            if ( EscTst_Memcmp( hmac_hash_digest, hmac_resultTruncation, (Esc_UINT32)hmacLength ) )
            {
                if ( EscTst_Memcmp( &hmac_hash_digest[hmacLength], &zeroArray[hmacLength], EscHmacSha1_MAX_MAC_LENGTH - (Esc_UINT32)hmacLength ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
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
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
        }
    }

    return returnCode;
}


Esc_ERROR
EscTstHmacSha1_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstHmacSha1_Compliance();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha1_StepsParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha1_ComplianceChunkwise();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha1_FullParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha1_Truncation();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
