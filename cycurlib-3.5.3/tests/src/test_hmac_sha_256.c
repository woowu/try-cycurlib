/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief HMAC-SHA-256 Selftest (224 and 256 bit), testcases from RFC 4231


   $Rev: 2711 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_hmac_sha_256.h"
#include "selftest.h"
#include "hmac_sha_256.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define NUMBER_OF_HMAC_SHA_2_TESTCASES 5U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

typedef struct
{
    Esc_UINT8 len;
    Esc_UINT8 message[136];
} hmac_sha2_test_key;

static const hmac_sha2_test_key hmac_sha2_test_keys[NUMBER_OF_HMAC_SHA_2_TESTCASES] =
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
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
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
        131U,
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
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        131U,
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
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
};

/* HMAC SHA-256 message */
static const Esc_CHAR* const hmac_msg[NUMBER_OF_HMAC_SHA_2_TESTCASES] =
{
    "Hi There",
    "what do ya want for nothing?",
    "Test With Truncation",
    "Test Using Larger Than Block-Size Key - Hash Key First",
    "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
};

/* HMAC SHA-2-224 expected values */
static const Esc_UINT8 hmac224_res[NUMBER_OF_HMAC_SHA_2_TESTCASES][EscSha224_DIGEST_LEN] =
{
    {
        0x89U, 0x6fU, 0xb1U, 0x12U, 0x8aU, 0xbbU, 0xdfU, 0x19U, 0x68U,
        0x32U, 0x10U, 0x7cU, 0xd4U, 0x9dU, 0xf3U, 0x3fU, 0x47U, 0xb4U,
        0xb1U, 0x16U, 0x99U, 0x12U, 0xbaU, 0x4fU, 0x53U, 0x68U, 0x4bU, 0x22U
    },
    {
        0xa3U, 0x0eU, 0x01U, 0x09U, 0x8bU, 0xc6U, 0xdbU, 0xbfU, 0x45U,
        0x69U, 0x0fU, 0x3aU, 0x7eU, 0x9eU, 0x6dU, 0x0fU, 0x8bU, 0xbeU,
        0xa2U, 0xa3U, 0x9eU, 0x61U, 0x48U, 0x00U, 0x8fU, 0xd0U, 0x5eU, 0x44U
    },
    {
        0x0eU, 0x2aU, 0xeaU, 0x68U, 0xa9U, 0x0cU, 0x8dU, 0x37U, 0xc9U,
        0x88U, 0xbcU, 0xdbU, 0x9fU, 0xcaU, 0x6fU, 0xa8U, 0x09U, 0x9cU,
        0xd8U, 0x57U, 0xc7U, 0xecU, 0x4aU, 0x18U, 0x15U, 0xcaU, 0xc5U, 0x4cU
    },
    {
        0x95U, 0xe9U, 0xa0U, 0xdbU, 0x96U, 0x20U, 0x95U, 0xadU, 0xaeU,
        0xbeU, 0x9bU, 0x2dU, 0x6fU, 0x0dU, 0xbcU, 0xe2U, 0xd4U, 0x99U,
        0xf1U, 0x12U, 0xf2U, 0xd2U, 0xb7U, 0x27U, 0x3fU, 0xa6U, 0x87U, 0x0eU
    },
    {
        0x3aU, 0x85U, 0x41U, 0x66U, 0xacU, 0x5dU, 0x9fU, 0x02U, 0x3fU,
        0x54U, 0xd5U, 0x17U, 0xd0U, 0xb3U, 0x9dU, 0xbdU, 0x94U, 0x67U,
        0x70U, 0xdbU, 0x9cU, 0x2bU, 0x95U, 0xc9U, 0xf6U, 0xf5U, 0x65U, 0xd1U
    }
};

/* HMAC SHA-2-256 expected values */
static const Esc_UINT8 hmac256_res[NUMBER_OF_HMAC_SHA_2_TESTCASES][EscSha256_DIGEST_LEN] =
{
    {
        0xb0U, 0x34U, 0x4cU, 0x61U, 0xd8U, 0xdbU, 0x38U, 0x53U, 0x5cU, 0xa8U, 0xafU,
        0xceU, 0xafU, 0x0bU, 0xf1U, 0x2bU, 0x88U, 0x1dU, 0xc2U, 0x00U, 0xc9U, 0x83U,
        0x3dU, 0xa7U, 0x26U, 0xe9U, 0x37U, 0x6cU, 0x2eU, 0x32U, 0xcfU, 0xf7U
    },
    {
        0x5bU, 0xdcU, 0xc1U, 0x46U, 0xbfU, 0x60U, 0x75U, 0x4eU, 0x6aU, 0x04U, 0x24U,
        0x26U, 0x08U, 0x95U, 0x75U, 0xc7U, 0x5aU, 0x00U, 0x3fU, 0x08U, 0x9dU, 0x27U,
        0x39U, 0x83U, 0x9dU, 0xecU, 0x58U, 0xb9U, 0x64U, 0xecU, 0x38U, 0x43U
    },
    {
        0xa3U, 0xb6U, 0x16U, 0x74U, 0x73U, 0x10U, 0x0eU, 0xe0U, 0x6eU, 0x0cU, 0x79U,
        0x6cU, 0x29U, 0x55U, 0x55U, 0x2bU, 0xfaU, 0x6fU, 0x7cU, 0x0aU, 0x6aU, 0x8aU,
        0xefU, 0x8bU, 0x93U, 0xf8U, 0x60U, 0xaaU, 0xb0U, 0xcdU, 0x20U, 0xc5U
    },
    {
        0x60U, 0xe4U, 0x31U, 0x59U, 0x1eU, 0xe0U, 0xb6U, 0x7fU, 0x0dU, 0x8aU, 0x26U,
        0xaaU, 0xcbU, 0xf5U, 0xb7U, 0x7fU, 0x8eU, 0x0bU, 0xc6U, 0x21U, 0x37U, 0x28U,
        0xc5U, 0x14U, 0x05U, 0x46U, 0x04U, 0x0fU, 0x0eU, 0xe3U, 0x7fU, 0x54U
    },
    {
        0x9bU, 0x09U, 0xffU, 0xa7U, 0x1bU, 0x94U, 0x2fU, 0xcbU, 0x27U, 0x63U, 0x5fU,
        0xbcU, 0xd5U, 0xb0U, 0xe9U, 0x44U, 0xbfU, 0xdcU, 0x63U, 0x64U, 0x4fU, 0x07U,
        0x13U, 0x93U, 0x8aU, 0x7fU, 0x51U, 0x53U, 0x5cU, 0x3aU, 0x35U, 0xe2U
    }
};


/* SHA-256 */
static Esc_ERROR
EscTstHmacSha256_Compliance(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstHmacSha256_ComplianceChunkwise(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstHmacSha256_StepsParams(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstHmacSha256_FullParams(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstHmacSha256_Truncation(
    Esc_BOOL isSha224 );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/* SHA-256 */
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstHmacSha256_Compliance(
    Esc_BOOL isSha224 )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_BOOL cmpResult;
    Esc_UINT8 digestLength;

    EscTst_PrintString( "\nHMAC-SHA-2 Compliance test\n" );
    if (isSha224)
    {
        EscTst_PrintString( "SHA-2 Bitlength = 224\n" );
        digestLength = EscSha224_DIGEST_LEN;
    }
    else
    {
        EscTst_PrintString( "SHA-2 Bitlength = 256\n" );
        digestLength = EscSha256_DIGEST_LEN;
    }

    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_2_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 sha_hash[EscSha256_DIGEST_LEN];      /* hash value */

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len );

        returnCode = EscHmacSha256_Calc(
                isSha224,
                hmac_sha2_test_keys[i].message,
                (Esc_UINT32)hmac_sha2_test_keys[i].len,
                (const Esc_UINT8*)hmac_msg[i],
                EscTst_Strlen( hmac_msg[i] ),
                sha_hash,
                digestLength );

        if (returnCode == Esc_NO_ERROR)
        {
            if (isSha224)
            {
                EscTst_PrintArray( "Expected Result", hmac224_res[i], EscSha224_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha224_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac224_res[i], EscSha224_DIGEST_LEN );
            }
            else
            {
                EscTst_PrintArray( "Expected Result", hmac256_res[i], EscSha256_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha256_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac256_res[i], EscSha256_DIGEST_LEN );
            }

            if (cmpResult)
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
EscTstHmacSha256_ComplianceChunkwise(
    Esc_BOOL isSha224 )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 digestLength;
    Esc_BOOL cmpResult;

    EscTst_PrintString( "\nHMAC-SHA-2 Compliance test (chunk-wise)\n" );
    if (isSha224)
    {
        EscTst_PrintString( "SHA-2 Bitlength = 224\n" );
        digestLength = EscSha224_DIGEST_LEN;
    }
    else
    {
        EscTst_PrintString( "SHA-2 Bitlength = 256\n" );
        digestLength = EscSha256_DIGEST_LEN;
    }

    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_2_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT32 msgLen;
        const Esc_UINT8 *message;
        Esc_UINT8 sha_hash[EscHmacSha256_MAX_MAC_LENGTH];      /* hash value */
        EscHmacSha256_ContextT ctx;

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len );

        msgLen = EscTst_Strlen(hmac_msg[i]);
        message = (const Esc_UINT8 *) hmac_msg[i];

        /* Init context */
        returnCode = EscHmacSha256_Init(isSha224, &ctx, hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len);

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
                returnCode = EscHmacSha256_Update( &ctx, Esc_NULL_PTR, 0U );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscHmacSha256_Update( &ctx, &message[offset], chunkLen );
                }

                remainingLen -= chunkLen;
                offset += chunkLen;
                chunkLen += 3U;
            }

            /* Final zero-length update before finish */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha256_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        /* Finish MAC calculation */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha256_Finish(&ctx, sha_hash, digestLength);
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            if (isSha224)
            {
                EscTst_PrintArray( "Expected Result", hmac224_res[i], EscSha224_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha224_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac224_res[i], EscSha224_DIGEST_LEN );
            }
            else
            {
                EscTst_PrintArray( "Expected Result", hmac256_res[i], EscSha256_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha256_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac256_res[i], EscSha256_DIGEST_LEN );
            }

            if (cmpResult)
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
EscTstHmacSha256_StepsParams(
    Esc_BOOL isSha224 )
{
    Esc_ERROR returnCode;
    EscHmacSha256_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac[EscSha256_DIGEST_LEN];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;
    Esc_UINT8 digestLength;

    key = (const Esc_UINT8*)hmac_sha2_test_keys[1].message;
    keyLen = hmac_sha2_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    if (isSha224)
    {
        digestLength = EscSha224_DIGEST_LEN;
    }
    else
    {
        digestLength = EscSha256_DIGEST_LEN;
    }

    EscTst_PrintString( "EscHmacSha256_Init() with ctx==0\n" );
    returnCode = EscHmacSha256_Init( isSha224, Esc_NULL_PTR, key, keyLen );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Init() with hmac_key==0\n" );
        returnCode = EscHmacSha256_Init( isSha224, &ctx, Esc_NULL_PTR, keyLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha256_Init() with key_length==0\n" );
            returnCode = EscHmacSha256_Init( isSha224, &ctx, key, 0U );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Update() with ctx==0\n" );
        returnCode = EscHmacSha256_Update( Esc_NULL_PTR, msg, msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha256_Update() with chunk_data==0\n" );
            returnCode = EscHmacSha256_Update( &ctx, Esc_NULL_PTR, msgLen );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscHmacSha256_Init( isSha224, &ctx, key, keyLen);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Finish() with ctx==0\n" );
        returnCode = EscHmacSha256_Finish( Esc_NULL_PTR, hmac, digestLength );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha256_Finish() with hmac_hash==0\n" );
            returnCode = EscHmacSha256_Finish( &ctx, Esc_NULL_PTR, digestLength );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscHmacSha256_Finish() with hmac_hashLength==0\n" );
                returnCode = EscHmacSha256_Finish( &ctx, hmac, 0U );
                if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscHmacSha256_Finish() with hmac_hashLength too long\n" );
                    returnCode = EscHmacSha256_Finish( &ctx, hmac, digestLength+1U );
                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha256_FullParams(
    Esc_BOOL isSha224 )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac[EscSha256_DIGEST_LEN];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;

    key = (const Esc_UINT8*)hmac_sha2_test_keys[1].message;
    keyLen = hmac_sha2_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    EscTst_PrintString( "EscHmacSha256_Calc() with all parameters\n" );
    returnCode = EscHmacSha256_Calc( isSha224, key, keyLen, msg, msgLen, hmac, EscSha224_DIGEST_LEN );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Calc() with key==0\n" );
        returnCode = EscHmacSha256_Calc( isSha224, Esc_NULL_PTR, keyLen, msg, msgLen, hmac, EscSha224_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Calc() with message==0\n" );
        returnCode = EscHmacSha256_Calc( isSha224, key, keyLen, Esc_NULL_PTR, msgLen, hmac, EscSha224_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Calc() with hmac_hash==0\n" );
        returnCode = EscHmacSha256_Calc( isSha224, key, keyLen, msg, msgLen, Esc_NULL_PTR, EscSha224_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha256_Calc() with key_length==0\n" );
        returnCode = EscHmacSha256_Calc( isSha224, key, 0U, msg, msgLen, hmac, EscSha224_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha256_Truncation(
    Esc_BOOL isSha224 )
{
    static const Esc_UINT8 key[20] =
    {
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU
    };
    static const Esc_CHAR* msg = "Test With Truncation";

    static const Esc_UINT8 hmacLengthsSha224[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacSha224_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacSha224_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacSha224_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacSha224_MAX_MAC_LENGTH - 1U)
    };

    static const Esc_UINT8 hmacLengthsSha256[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacSha256_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacSha256_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacSha256_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacSha256_MAX_MAC_LENGTH - 1U)
    };

    Esc_UINT32 numHmacLengths;
    const Esc_UINT8 *hmacLengths;
    Esc_UINT8 maxHmacLength;

    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscHmacSha256_ContextT ctx;
    Esc_UINT32 msgLen = EscTst_Strlen( msg );
    Esc_UINT8 hmac[EscHmacSha256_MAX_MAC_LENGTH];
    Esc_UINT8 hmac256_resultTruncation[EscHmacSha256_MAX_MAC_LENGTH];
    Esc_UINT32 keyLen = 20U;
    Esc_UINT8 i, j;
    Esc_UINT8 zeroArray[EscHmacSha256_MAX_MAC_LENGTH];

    if (isSha224)
    {
        hmacLengths = hmacLengthsSha224;
        numHmacLengths = sizeof(hmacLengthsSha224) / sizeof(hmacLengthsSha224[0]);
        maxHmacLength = EscHmacSha224_MAX_MAC_LENGTH;
        EscTst_PrintString( "HMAC-SHA224 Truncation test\n" );
    }
    else
    {
        hmacLengths = hmacLengthsSha256;
        numHmacLengths = sizeof(hmacLengthsSha256) / sizeof(hmacLengthsSha256[0]);
        maxHmacLength = EscHmacSha256_MAX_MAC_LENGTH;
        EscTst_PrintString( "HMAC-SHA256 Truncation test\n" );
    }

    for (i = 0U; (i < numHmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 hmacLength = hmacLengths[i];

        EscTst_PrintWord( "HMAC length = ", hmacLength);

        for (j = 0U; j < EscHmacSha256_MAX_MAC_LENGTH; j++)
        {
            zeroArray[j] = 0U;
            hmac[j] = 0U;
        }

        returnCode = EscHmacSha256_Calc(isSha224, key, keyLen, (const Esc_UINT8*)msg, msgLen, hmac256_resultTruncation, maxHmacLength);

        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscHmacSha256_Init( isSha224, &ctx, key, keyLen );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha256_Update( &ctx, (const Esc_UINT8*)msg, msgLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha256_Finish( &ctx, hmac, hmacLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac256_resultTruncation, (Esc_UINT32)hmacLength );
            EscTst_PrintArray( "Received Result", hmac, (Esc_UINT32)hmacLength );
            if ( EscTst_Memcmp( hmac, hmac256_resultTruncation, (Esc_UINT32)hmacLength ) )
            {
                if ( EscTst_Memcmp( &hmac[hmacLength], &zeroArray[hmacLength], (Esc_UINT32)maxHmacLength - (Esc_UINT32)hmacLength ) )
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
EscTstHmacSha256_Perform(
    void )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "Testing HMAC-SHA-224" );

    returnCode = EscTstHmacSha256_Compliance(TRUE);

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_ComplianceChunkwise(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_StepsParams(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_FullParams(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_Truncation(TRUE);
    }



    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Testing HMAC-SHA-256" );
        returnCode = EscTstHmacSha256_Compliance(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_ComplianceChunkwise(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_StepsParams(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_FullParams(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha256_Truncation(FALSE);
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
