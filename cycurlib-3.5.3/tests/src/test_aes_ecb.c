/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-ECB Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_aes_ecb.h"
#include "selftest.h"
#include "aes_ecb.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of the largest test vector in bytes */
#define EscTstAesEcb_MAX_DATA_LENGTH    (2U * EscAes_BLOCK_BYTES)

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** ECB test vector */
typedef struct
{
    const Esc_UINT8 *key;
    const Esc_UINT8 *plain;
    const Esc_UINT8 *cipher;

    Esc_UINT32 keyLength;
    Esc_UINT32 dataLength;
} Testcase;

/*
    Testvectors taken from csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
*/

/* Key size 128 bit */

static const Esc_UINT8 ecb128Key0[] =
{
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

static const Esc_UINT8 ecb128Plain0[] =
{
    0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,

    0xFFU, 0xFFU, 0xFEU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
};

static const Esc_UINT8 ecb128Cipher0[] =
{
    0x3aU, 0xd7U, 0x8eU, 0x72U, 0x6cU, 0x1eU, 0xc0U, 0x2bU,
    0x7eU, 0xbfU, 0xe9U, 0x2bU, 0x23U, 0xd9U, 0xecU, 0x34U,

    0xc0U, 0xb5U, 0xfdU, 0x98U, 0x19U, 0x0eU, 0xf4U, 0x5fU,
    0xbbU, 0x43U, 0x01U, 0x43U, 0x8dU, 0x09U, 0x59U, 0x50U
};

/* Key size 192 bit */

#if EscAes_MAX_KEY_BITS >= 192U
static const Esc_UINT8 ecb192Key0[] =
{
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

static const Esc_UINT8 ecb192Plain0[] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,

    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

static const Esc_UINT8 ecb192Cipher0[] =
{
    0x3CU, 0xC9U, 0xE9U, 0xA9U, 0xBEU, 0x8CU, 0xC3U, 0xF6U,
    0xFBU, 0x2EU, 0xA2U, 0x40U, 0x88U, 0xE9U, 0xBBU, 0x19U,

    0x09U, 0x1DU, 0x1FU, 0xDCU, 0x2BU, 0xD2U, 0xC3U, 0x46U,
    0xCDU, 0x50U, 0x46U, 0xA8U, 0xC6U, 0x20U, 0x91U, 0x46U
};
#endif

/* Key size 256 bit */

#if EscAes_MAX_KEY_BITS == 256U
static const Esc_UINT8 ecb256Key0[] =
{
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

static const Esc_UINT8 ecb256Plain0[] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0x00U, 0x00U
};

static const Esc_UINT8 ecb256Cipher0[] =
{
    0x14U, 0x5BU, 0x60U, 0xD6U, 0xD0U, 0x19U, 0x3CU, 0x23U,
    0xF4U, 0x22U, 0x18U, 0x48U, 0xA8U, 0x92U, 0xD6U, 0x1AU,
    0x4BU, 0x00U, 0xC2U, 0x7EU, 0x8BU, 0x26U, 0xDAU, 0x7EU,
    0xABU, 0x9DU, 0x3AU, 0x88U, 0xDEU, 0xC8U, 0xB0U, 0x31U
};
#endif

static const Testcase testcases[] =
{
    {
        ecb128Key0,
        ecb128Plain0,
        ecb128Cipher0,

        16U,
        sizeof(ecb128Plain0)
    },

#if EscAes_MAX_KEY_BITS >= 192U
    {
        ecb192Key0,
        ecb192Plain0,
        ecb192Cipher0,

        24U,
        sizeof(ecb192Plain0)
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    {
        ecb256Key0,
        ecb256Plain0,
        ecb256Cipher0,

        32U,
        sizeof(ecb256Plain0)
    },
#endif
};

static Esc_ERROR
EscTstAesEcb_InitParams(void);

static Esc_ERROR
EscTstAesEcb_DecryptionParams(void);

static Esc_ERROR
EscTstAesEcb_EncryptionParams(void);

static Esc_ERROR
EscTstAesEcb_DecryptionComp(void);

static Esc_ERROR
EscTstAesEcb_EncryptionComp(void);

typedef Esc_ERROR (* EscTstAesEcb_TestFunction )(void);

#define EscTstAesEcb_NUM_TESTVECTORS ( sizeof(testcases) / sizeof(testcases[0]) )

#define EscTstAesEcb_NUM_TESTFUNCTIONS ( sizeof(AES_TESTS) / sizeof(AES_TESTS[0]) )


/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesEcb_InitParams(void)
{
    Esc_ERROR returnCode;
    EscAesEcb_ContextT ctx;

    EscTst_PrintString( "EscAesEcb_Init parameter test\n" );

    EscTst_PrintString( "With ctx==0\n" );
    returnCode = EscAesEcb_Init( Esc_NULL_PTR, 128, ecb128Key0 );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscAesEcb_Init( &ctx, 128, Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesEcb_Init( &ctx, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), ecb128Key0 );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstAesEcb_DecryptionParams(void)
{
    Esc_ERROR returnCode;
    EscAesEcb_ContextT ctx;
    Esc_UINT8 plain[EscTstAesEcb_MAX_DATA_LENGTH];

    EscTst_PrintString( "EscAesEcb_Decrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscAesEcb_Init()\n" );
    returnCode = EscAesEcb_Init( &ctx, 128U, ecb128Key0 );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesEcb_Decrypt( Esc_NULL_PTR, ecb128Cipher0, plain, EscAes_BLOCK_BYTES );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With cipher==0\n" );
            returnCode = EscAesEcb_Decrypt( &ctx, Esc_NULL_PTR, plain, EscAes_BLOCK_BYTES );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With plain==0\n" );
                returnCode = EscAesEcb_Decrypt( &ctx, ecb128Cipher0, Esc_NULL_PTR, EscAes_BLOCK_BYTES );
                if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "With length not multiple of block size\n" );
                    returnCode = EscAesEcb_Decrypt( &ctx, ecb128Cipher0, plain, EscAes_BLOCK_BYTES - 1U );

                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
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
EscTstAesEcb_EncryptionParams(void)
{
    Esc_ERROR returnCode;
    EscAesEcb_ContextT ctx;
    Esc_UINT8 cipher[EscTstAesEcb_MAX_DATA_LENGTH];

    EscTst_PrintString( "EscAesEcb_Encrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscAesEcb_Init()\n" );
    returnCode = EscAesEcb_Init( &ctx, 128U, ecb128Key0 );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscAesEcb_Encrypt( Esc_NULL_PTR, ecb128Plain0, cipher, EscAes_BLOCK_BYTES );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With plain==0\n" );
            returnCode = EscAesEcb_Encrypt( &ctx, Esc_NULL_PTR, cipher, EscAes_BLOCK_BYTES );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With cipher==0\n" );
                returnCode = EscAesEcb_Encrypt( &ctx, ecb128Plain0, Esc_NULL_PTR, EscAes_BLOCK_BYTES );
                if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "With length not multiple of block size\n" );
                    returnCode = EscAesEcb_Encrypt( &ctx, ecb128Plain0, cipher, EscAes_BLOCK_BYTES - 1U );

                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEcb_DecryptionComp(void)
{
    Esc_ERROR returnCode;
    Esc_UINT8 aesBuf[EscTstAesEcb_MAX_DATA_LENGTH];     /* buffer for data to decrypt      */
    EscAesEcb_ContextT ctx;

    Esc_UINT32 i;

    EscTst_PrintString( "AES-ECB Decryption Compliance test\n" );

    for (i = 0U; i < EscTstAesEcb_NUM_TESTVECTORS; i++)
    {
        const Testcase *test = &testcases[i];

        Esc_ASSERT(test->dataLength <= EscTstAesEcb_MAX_DATA_LENGTH);

        EscTst_PrintArray( "Key", test->key, test->keyLength );
        EscTst_PrintArray( "Ciphertext", test->cipher, test->dataLength );
        EscTst_PrintArray( "Expected plaintext", test->plain, test->dataLength );

        EscTst_PrintString( "EscAesEcb_Init()\n" );
        returnCode = EscAesEcb_Init( &ctx, (Esc_UINT16)(test->keyLength * 8U), test->key );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesEcb_Decrypt()\n" );
            returnCode = EscAesEcb_Decrypt( &ctx, test->cipher, aesBuf, test->dataLength );

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
EscTstAesEcb_EncryptionComp(void)
{
    Esc_ERROR returnCode;
    Esc_UINT8 aesBuf[EscTstAesEcb_MAX_DATA_LENGTH];     /* buffer for data to encrypt      */
    EscAesEcb_ContextT ctx;

    Esc_UINT32 i;

    EscTst_PrintString( "AES-ECB Encryption Compliance test\n" );

    for (i = 0U; i < EscTstAesEcb_NUM_TESTVECTORS; i++)
    {
        const Testcase *test = &testcases[i];

        Esc_ASSERT(test->dataLength <= EscTstAesEcb_MAX_DATA_LENGTH);

        EscTst_PrintArray( "Key", test->key, test->keyLength );
        EscTst_PrintArray( "Plaintext", test->plain, test->dataLength);
        EscTst_PrintArray( "Expected ciphertext", test->cipher, test->dataLength );

        EscTst_PrintString( "EscAesEcb_Init()\n" );
        returnCode = EscAesEcb_Init( &ctx, (Esc_UINT16)(test->keyLength * 8U), test->key );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscAesEcb_Encrypt()\n" );
            returnCode = EscAesEcb_Encrypt( &ctx, test->plain, aesBuf, test->dataLength );

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

Esc_ERROR
EscTstAesEcb_Perform(
    void )
{
    /* The test cases */
    EscTstAesEcb_TestFunction AES_TESTS[] =
    {
        EscTstAesEcb_InitParams,
        EscTstAesEcb_DecryptionParams,
        EscTstAesEcb_EncryptionParams,
        EscTstAesEcb_DecryptionComp,
        EscTstAesEcb_EncryptionComp,
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    for (i = 0U; (i < EscTstAesEcb_NUM_TESTFUNCTIONS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstAesEcb_TestFunction func;
        /* Perform test #i */
        func = AES_TESTS[i];
        returnCode = func();
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
