/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-CTR Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_aes_ctr.h"
#include "selftest.h"
#include "aes_ctr.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscTstAesCtr_MAX_DATALEN (2U * EscAes_BLOCK_BYTES)

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** CTR test vector */
typedef struct
{
    const Esc_UINT8 *iv;
    Esc_UINT8 nonceLength;

    const Esc_UINT8 *key;
    Esc_UINT32 keyLength;

    const Esc_UINT8 *plain;
    const Esc_UINT8 *cipher;
    Esc_UINT32 dataLength;
} EscTstAesCtr_testcaseT;

/* Test vector data - key size 128 bit */

static const Esc_UINT8 ctr128iv0[] =
{
    0x00U, 0x00U, 0x00U, 0x30U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr128key0[] =
{
    0xAEU, 0x68U, 0x52U, 0xF8U, 0x12U, 0x10U, 0x67U, 0xCCU,
    0x4BU, 0xF7U, 0xA5U, 0x76U, 0x55U, 0x77U, 0xF3U, 0x9EU
};

static const Esc_UINT8 ctr128plain0[] =
{
    0x53U, 0x69U, 0x6EU, 0x67U, 0x6CU, 0x65U, 0x20U, 0x62U,
    0x6CU, 0x6FU, 0x63U, 0x6BU, 0x20U, 0x6DU, 0x73U, 0x67U,
};

static const Esc_UINT8 ctr128cipher0[] =
{
    0xE4U, 0x09U, 0x5DU, 0x4FU, 0xB7U, 0xA7U, 0xB3U, 0x79U,
    0x2DU, 0x61U, 0x75U, 0xA3U, 0x26U, 0x13U, 0x11U, 0xB8U,
};


static const Esc_UINT8 ctr128iv1[] =
{
    0x00U, 0x6CU, 0xB6U, 0xDBU, 0xC0U, 0x54U, 0x3BU, 0x59U,
    0xDAU, 0x48U, 0xD9U, 0x0BU, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr128key1[] =
{
    0x7EU, 0x24U, 0x06U, 0x78U, 0x17U, 0xFAU, 0xE0U, 0xD7U,
    0x43U, 0xD6U, 0xCEU, 0x1FU, 0x32U, 0x53U, 0x91U, 0x63U
};

static const Esc_UINT8 ctr128plain1[] =
{
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

static const Esc_UINT8 ctr128cipher1[] =
{
    0x51U, 0x04U, 0xA1U, 0x06U, 0x16U, 0x8AU, 0x72U, 0xD9U,
    0x79U, 0x0DU, 0x41U, 0xEEU, 0x8EU, 0xDAU, 0xD3U, 0x88U,
    0xEBU, 0x2EU, 0x1EU, 0xFCU, 0x46U, 0xDAU, 0x57U, 0xC8U,
    0xFCU, 0xE6U, 0x30U, 0xDFU, 0x91U, 0x41U, 0xBEU, 0x28U
};

/* Test vector data - key size 192 bit */

#if EscAes_MAX_KEY_BITS >= 192U
static const Esc_UINT8 ctr192iv0[] =
{
    0x00U, 0x00U, 0x00U, 0x48U, 0x36U, 0x73U, 0x3CU, 0x14U,
    0x7DU, 0x6DU, 0x93U, 0xCBU, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr192key0[] =
{
    0x16U, 0xAFU, 0x5BU, 0x14U, 0x5FU, 0xC9U, 0xF5U, 0x79U,
    0xC1U, 0x75U, 0xF9U, 0x3EU, 0x3BU, 0xFBU, 0x0EU, 0xEDU,
    0x86U, 0x3DU, 0x06U, 0xCCU, 0xFDU, 0xB7U, 0x85U, 0x15U
};

static const Esc_UINT8 ctr192plain0[] =
{
    0x53U, 0x69U, 0x6EU, 0x67U, 0x6CU, 0x65U, 0x20U, 0x62U,
    0x6CU, 0x6FU, 0x63U, 0x6BU, 0x20U, 0x6DU, 0x73U, 0x67U,
};

static const Esc_UINT8 ctr192cipher0[] =
{
    0x4BU, 0x55U, 0x38U, 0x4FU, 0xE2U, 0x59U, 0xC9U, 0xC8U,
    0x4EU, 0x79U, 0x35U, 0xA0U, 0x03U, 0xCBU, 0xE9U, 0x28U,
};


static const Esc_UINT8 ctr192iv1[] =
{
    0x00U, 0x96U, 0xB0U, 0x3BU, 0x02U, 0x0CU, 0x6EU, 0xADU,
    0xC2U, 0xCBU, 0x50U, 0x0DU, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr192key1[] =
{
    0x7CU, 0x5CU, 0xB2U, 0x40U, 0x1BU, 0x3DU, 0xC3U, 0x3CU,
    0x19U, 0xE7U, 0x34U, 0x08U, 0x19U, 0xE0U, 0xF6U, 0x9CU,
    0x67U, 0x8CU, 0x3DU, 0xB8U, 0xE6U, 0xF6U, 0xA9U, 0x1AU
};

static const Esc_UINT8 ctr192plain1[] =
{
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

static const Esc_UINT8 ctr192cipher1[] =
{
    0x45U, 0x32U, 0x43U, 0xFCU, 0x60U, 0x9BU, 0x23U, 0x32U,
    0x7EU, 0xDFU, 0xAAU, 0xFAU, 0x71U, 0x31U, 0xCDU, 0x9FU,
    0x84U, 0x90U, 0x70U, 0x1CU, 0x5AU, 0xD4U, 0xA7U, 0x9CU,
    0xFCU, 0x1FU, 0xE0U, 0xFFU, 0x42U, 0xF4U, 0xFBU, 0x00U
};
#endif

/* Test vector data - key size 256 bit */

#if EscAes_MAX_KEY_BITS == 256U
static const Esc_UINT8 ctr256iv0[] =
{
    0x00U, 0x00U, 0x00U, 0x60U, 0xDBU, 0x56U, 0x72U, 0xC9U,
    0x7AU, 0xA8U, 0xF0U, 0xB2U, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr256key0[] =
{
    0x77U, 0x6BU, 0xEFU, 0xF2U, 0x85U, 0x1DU, 0xB0U, 0x6FU,
    0x4CU, 0x8AU, 0x05U, 0x42U, 0xC8U, 0x69U, 0x6FU, 0x6CU,
    0x6AU, 0x81U, 0xAFU, 0x1EU, 0xECU, 0x96U, 0xB4U, 0xD3U,
    0x7FU, 0xC1U, 0xD6U, 0x89U, 0xE6U, 0xC1U, 0xC1U, 0x04U
};

static const Esc_UINT8 ctr256plain0[] =
{
    0x53U, 0x69U, 0x6EU, 0x67U, 0x6CU, 0x65U, 0x20U, 0x62U,
    0x6CU, 0x6FU, 0x63U, 0x6BU, 0x20U, 0x6DU, 0x73U, 0x67U,
};

static const Esc_UINT8 ctr256cipher0[] =
{
    0x14U, 0x5AU, 0xD0U, 0x1DU, 0xBFU, 0x82U, 0x4EU, 0xC7U,
    0x56U, 0x08U, 0x63U, 0xDCU, 0x71U, 0xE3U, 0xE0U, 0xC0U,
};


static const Esc_UINT8 ctr256iv1[] =
{
    0x00U, 0xFAU, 0xACU, 0x24U, 0xC1U, 0x58U, 0x5EU, 0xF1U,
    0x5AU, 0x43U, 0xD8U, 0x75U, 0x00U, 0x00U, 0x00U, 0x01U
};

static const Esc_UINT8 ctr256key1[] =
{
    0xF6U, 0xD6U, 0x6DU, 0x6BU, 0xD5U, 0x2DU, 0x59U, 0xBBU,
    0x07U, 0x96U, 0x36U, 0x58U, 0x79U, 0xEFU, 0xF8U, 0x86U,
    0xC6U, 0x6DU, 0xD5U, 0x1AU, 0x5BU, 0x6AU, 0x99U, 0x74U,
    0x4BU, 0x50U, 0x59U, 0x0CU, 0x87U, 0xA2U, 0x38U, 0x84U
};

static const Esc_UINT8 ctr256plain1[] =
{
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

static const Esc_UINT8 ctr256cipher1[] =
{
    0xF0U, 0x5EU, 0x23U, 0x1BU, 0x38U, 0x94U, 0x61U, 0x2CU,
    0x49U, 0xEEU, 0x00U, 0x0BU, 0x80U, 0x4EU, 0xB2U, 0xA9U,
    0xB8U, 0x30U, 0x6BU, 0x50U, 0x8FU, 0x83U, 0x9DU, 0x6AU,
    0x55U, 0x30U, 0x83U, 0x1DU, 0x93U, 0x44U, 0xAFU, 0x1CU
};
#endif

static const EscTstAesCtr_testcaseT testcases[] =
{
    /* key size 128 bit */
    {
        ctr128iv0,
        12U,

        ctr128key0,
        sizeof(ctr128key0),

        ctr128plain0,
        ctr128cipher0,
        sizeof(ctr128plain0)
    },

    {
        ctr128iv1,
        12U,

        ctr128key1,
        sizeof(ctr128key1),

        ctr128plain1,
        ctr128cipher1,
        sizeof(ctr128plain1),
    },

#if EscAes_MAX_KEY_BITS >= 192U
    /* key size 192 bit */
    {
        ctr192iv0,
        12U,

        ctr192key0,
        sizeof(ctr192key0),

        ctr192plain0,
        ctr192cipher0,
        sizeof(ctr192plain0)
    },

    {
        ctr192iv1,
        12U,

        ctr192key1,
        sizeof(ctr192key1),

        ctr192plain1,
        ctr192cipher1,
        sizeof(ctr192plain1),
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    /* key size 256 bit */
    {
        ctr256iv0,
        12U,

        ctr256key0,
        sizeof(ctr256key0),

        ctr256plain0,
        ctr256cipher0,
        sizeof(ctr256plain0)
    },

    {
        ctr256iv1,
        12U,

        ctr256key1,
        sizeof(ctr256key1),

        ctr256plain1,
        ctr256cipher1,
        sizeof(ctr256plain1),
    }
#endif
};

#define EscTstAesCtr_NUM_TESTCASES ( sizeof(testcases) / sizeof(testcases[0]) )

static Esc_ERROR
EscTstAesCtr_InitParams(void);

static Esc_ERROR
EscTstAesCtr_ApplyParams(void);

static Esc_ERROR
EscTstAesCtr_DecryptionComp(void);

static Esc_ERROR
EscTstAesCtr_EncryptionComp(void);

static Esc_ERROR
EscTstAesCtr_Split(void);

typedef Esc_ERROR (
* EscTstAesCtr_TestFunctionsT )(void);

#define EscTstAesCtr_NUM_TEST_FUNCTIONS ( sizeof(AES_TESTS) / sizeof(AES_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCtr_InitParams(void)
{
    Esc_ERROR returnCode;
    EscAesCtr_ContextT ctx;

    const EscTstAesCtr_testcaseT *test = &testcases[0];
    Esc_UINT16 keyBits = (Esc_UINT16)(test->keyLength * 8U);

    EscTst_PrintString( "EscAesCtr_Init parameter test on testcase 0\n" );

    EscTst_PrintString( "With ctx==0\n" );
    returnCode = EscAesCtr_Init( Esc_NULL_PTR, keyBits, test->key, test->iv, test->nonceLength );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, Esc_NULL_PTR, test->iv, test->nonceLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With iv==0\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, Esc_NULL_PTR, test->nonceLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With nonceLength == (EscAes_IV_BYTES+1)\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, (Esc_UINT8)(EscAes_IV_BYTES + 1U) );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesCtr_Init( &ctx, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), test->key, test->iv, test->nonceLength);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesCtr_ApplyParams(void)
{
    Esc_ERROR returnCode;
    EscAesCtr_ContextT ctx;
    Esc_UINT8 cipher[EscTstAesCtr_MAX_DATALEN];
    const EscTstAesCtr_testcaseT *test = &testcases[0];
    Esc_UINT16 keyBits = (Esc_UINT16)(test->keyLength * 8U);

    EscTst_PrintString( "EscAesCtr_apply parameter test on testcase 0\n" );

    /* We ignore the return values if Init() */

    returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, test->nonceLength );
    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintString( "Init failed!" );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesCtr_Apply( Esc_NULL_PTR, test->plain, cipher, test->dataLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With source==0\n" );
        returnCode = EscAesCtr_Apply( &ctx, Esc_NULL_PTR, cipher, test->dataLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With dest==0\n" );
        returnCode = EscAesCtr_Apply( &ctx, test->plain, Esc_NULL_PTR, test->dataLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesCtr_DecryptionComp(void)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 aesBuf[EscTstAesCtr_MAX_DATALEN];   /* buffer for data to decrypt      */
    EscAesCtr_ContextT ctx;

    EscTst_PrintString( "AES-CTR Decryption Compliance test\n" );

    for (i = 0U; (i < EscTstAesCtr_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstAesCtr_testcaseT* test = &testcases[i];
        Esc_UINT16 keyBits = (Esc_UINT16)(test->keyLength * 8U);

        EscTst_PrintWord( "Test #", (Esc_UINT32)i );
        EscTst_PrintArray( "IV", test->iv, EscAes_IV_BYTES );
        EscTst_PrintWord( "Nonce-length", (Esc_UINT32)test->nonceLength );
        EscTst_PrintArray( "Key", test->key, test->keyLength );
        EscTst_PrintArray( "Ciphertext", test->cipher, test->dataLength );
        EscTst_PrintArray( "Expected plaintext", test->plain, test->dataLength );

        EscTst_PrintString( "EscAesCtr_Init()\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, test->nonceLength );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesCtr_Apply()\n" );
            returnCode = EscAesCtr_Apply( &ctx, test->cipher, aesBuf, test->dataLength );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", aesBuf, test->dataLength );

                if ( EscTst_Memcmp( aesBuf, test->plain, test->dataLength ) )
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
EscTstAesCtr_EncryptionComp(void)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 aesBuf[EscTstAesCtr_MAX_DATALEN];   /* buffer for data to decrypt      */
    EscAesCtr_ContextT ctx;

    EscTst_PrintString( "AES-CTR Encryption Compliance test\n" );

    for (i = 0U; (i < EscTstAesCtr_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstAesCtr_testcaseT* test = &testcases[i];
        Esc_UINT16 keyBits = (Esc_UINT16)(test->keyLength * 8U);

        EscTst_PrintWord( "Test #", (Esc_UINT32)i );
        EscTst_PrintArray( "IV", test->iv, EscAes_IV_BYTES );
        EscTst_PrintWord( "Nonce-length", (Esc_UINT32)test->nonceLength );
        EscTst_PrintArray( "Key", test->key, keyBits );
        EscTst_PrintArray( "Plaintext", test->plain, test->dataLength );
        EscTst_PrintArray( "Expected ciphertext", test->cipher, test->dataLength );

        EscTst_PrintString( "EscAesCtr_Init()\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, test->nonceLength );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesCtr_Apply()\n" );
            returnCode = EscAesCtr_Apply( &ctx, test->plain, aesBuf, test->dataLength );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", aesBuf, test->dataLength );

                if ( EscTst_Memcmp( aesBuf, test->cipher, test->dataLength ) )
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
EscTstAesCtr_Split(void)
{
    Esc_ERROR returnCode;
    Esc_UINT8 aesBuf[EscTstAesCtr_MAX_DATALEN];   /* buffer for data to decrypt      */
    EscAesCtr_ContextT ctx;
    const EscTstAesCtr_testcaseT* test = &testcases[1];
    Esc_UINT16 keyBits = (Esc_UINT16)(test->keyLength * 8U);

    Esc_ASSERT( test->dataLength == (2U * EscAes_BLOCK_BYTES) );        /* We have two blocks */

    EscTst_PrintString( "AES-CTR Encryption Compliance test\n");

    EscTst_PrintArray( "IV", test->iv, EscAes_IV_BYTES );
    EscTst_PrintWord( "Nonce-length", (Esc_UINT32)test->nonceLength );
    EscTst_PrintArray( "Key", test->key, keyBits );
    EscTst_PrintArray( "Plaintext", test->plain, test->dataLength );
    EscTst_PrintArray( "Expected ciphertext", test->cipher, test->dataLength );

    EscTst_PrintString( "Encryption split up in two blocks\n\n" );
    EscTst_PrintString( "EscAesCtr_Init()\n" );
    returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, test->nonceLength );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscAesCtr_Apply() on first block\n" );
        returnCode = EscAesCtr_Apply( &ctx, test->plain, aesBuf, EscAes_BLOCK_BYTES );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesCtr_Apply() on second block\n" );
            returnCode = EscAesCtr_Apply( &ctx, &test->plain[EscAes_BLOCK_BYTES], &aesBuf[EscAes_BLOCK_BYTES], EscAes_BLOCK_BYTES);

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", aesBuf, test->dataLength );

                if ( EscTst_Memcmp( aesBuf, test->cipher, test->dataLength ) )
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

    if ( returnCode == Esc_NO_ERROR )
    {
        EscTst_PrintString( "Encryption split up in different parts\n\n" );
        EscTst_PrintString( "EscAesCtr_Init()\n" );
        returnCode = EscAesCtr_Init( &ctx, keyBits, test->key, test->iv, test->nonceLength );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesCtr_Apply() on first part of 4 Byte\n" );
            returnCode = EscAesCtr_Apply( &ctx, test->plain, aesBuf, 4U );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                returnCode = EscAesCtr_Apply( &ctx, &test->plain[4U], &aesBuf[4U], 2U );
                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscAesCtr_Apply() on second part\n" );
                    returnCode = EscAesCtr_Apply( &ctx, &test->plain[6U], &aesBuf[6U], (2U * EscAes_BLOCK_BYTES) - 6U);

                    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                    {
                        EscTst_PrintArray( "Received ciphertext", aesBuf, test->dataLength );

                        if ( EscTst_Memcmp( aesBuf, test->cipher, test->dataLength ) )
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
    }

    return returnCode;
}

Esc_ERROR
EscTstAesCtr_Perform(
    void )
{
    /* The test cases */
    static const EscTstAesCtr_TestFunctionsT AES_TESTS[] =
    {
        EscTstAesCtr_InitParams,
        EscTstAesCtr_ApplyParams,
        EscTstAesCtr_DecryptionComp,
        EscTstAesCtr_EncryptionComp,
        EscTstAesCtr_Split,
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    for (i = 0U; (i < EscTstAesCtr_NUM_TEST_FUNCTIONS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstAesCtr_TestFunctionsT TestFunction = AES_TESTS[i];

        returnCode = TestFunction();
        if (returnCode != Esc_NO_ERROR)
        {
            break;
        }
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
