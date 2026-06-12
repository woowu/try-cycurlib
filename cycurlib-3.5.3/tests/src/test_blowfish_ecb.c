/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief Blowfish Selftest.


   $Rev: 1458 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "blowfish_ecb.h"
#include "test_blowfish_ecb.h"
#include "selftest.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscTstBfish_MAX_KEY_BYTES 24U

#define EscTstBfishEcb_NUM_TESTCASES 10U

#define EscTstBfishEcb_NUM_TESTS ( sizeof(EscTstBfishEcb_TESTS) / sizeof(EscTstBfishEcb_TESTS[0]) )

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
/** ECB test vector */
typedef struct
{
    Esc_UINT8 key[EscTstBfish_MAX_KEY_BYTES];
    Esc_UINT8 plain[EscBfish_BLOCK_BYTES];
    Esc_UINT8 cipher[EscBfish_BLOCK_BYTES];
    Esc_UINT8 keyLen;
} EscTstBfishEcb_TestcaseT;

static const EscTstBfishEcb_TestcaseT EscTstBfishEcb_TESTCASES[EscTstBfishEcb_NUM_TESTCASES] =
{
    /* From www.schneier.com/code/vectors.txt */

    /* 8-byte keys*/
    /* FEDCBA9876543210        0123456789ABCDEF        0ACEAB0FC6A0A28D */
    {
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U,    /* key */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU },  /* plain */
        { 0x0AU, 0xCEU, 0xABU, 0x0FU, 0xC6U, 0xA0U, 0xA2U, 0x8DU },  /* cipher */
        0x08U                                                        /* key length */
    },
    /* 7CA110454A1A6E57        01A1D6D039776742        59C68245EB05282B */
    {
        { 0x7CU, 0xA1U, 0x10U, 0x45U, 0x4AU, 0x1AU, 0x6EU, 0x57U,    /* key */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0x01U, 0xA1U, 0xD6U, 0xD0U, 0x39U, 0x77U, 0x67U, 0x42U },  /* plain */
        { 0x59U, 0xC6U, 0x82U, 0x45U, 0xEBU, 0x05U, 0x28U, 0x2BU },  /* cipher */
        0x08U                                                        /* key length */
    },
    /* 0131D9619DC1376E        5CD54CA83DEF57DA        B1B8CC0B250F09A0 */
    {
        { 0x01U, 0x31U, 0xD9U, 0x61U, 0x9DU, 0xC1U, 0x37U, 0x6EU,    /* key */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0x5CU, 0xD5U, 0x4CU, 0xA8U, 0x3DU, 0xEFU, 0x57U, 0xDAU },  /* plain */
        { 0xB1U, 0xB8U, 0xCCU, 0x0BU, 0x25U, 0x0FU, 0x09U, 0xA0U },  /* cipher */
        0x08U                                                        /* key length */
    },
    /* 07A1133E4A0B2686        0248D43806F67172        1730E5778BEA1DA4 */
    {
        { 0x07U, 0xA1U, 0x13U, 0x3EU, 0x4AU, 0x0BU, 0x26U, 0x86U,    /* key */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0x02U, 0x48U, 0xD4U, 0x38U, 0x06U, 0xF6U, 0x71U, 0x72U },  /* plain */
        { 0x17U, 0x30U, 0xE5U, 0x77U, 0x8BU, 0xEAU, 0x1DU, 0xA4U },  /* cipher */
        0x08U                                                        /* key length */
    },
    /* 3849674C2602319E        51454B582DDF440A        A25E7856CF2651EB */
    {
        { 0x38U, 0x49U, 0x67U, 0x4CU, 0x26U, 0x02U, 0x31U, 0x9EU,    /* key */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0x51U, 0x45U, 0x4BU, 0x58U, 0x2DU, 0xDFU, 0x44U, 0x0AU },  /* plain */
        { 0xA2U, 0x5EU, 0x78U, 0x56U, 0xCFU, 0x26U, 0x51U, 0xEBU },  /* cipher */
        0x08U                                                        /* key length */
    },
    /* 20-byte key */
    /* F0E1D2C3B4A5968778695A4B3C2D1E0F00112233   FEDCBA9876543210   10851C0E3858DA9F      */
    {
        { 0xF0U, 0xE1U, 0xD2U, 0xC3U, 0xB4U, 0xA5U, 0x96U, 0x87U,    /* key */
          0x78U, 0x69U, 0x5AU, 0x4BU, 0x3CU, 0x2DU, 0x1EU, 0x0FU,
          0x00U, 0x11U, 0x22U, 0x33U, 0x00U, 0x00U, 0x00U, 0x00U },
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* plain */
        { 0x10U, 0x85U, 0x1CU, 0x0EU, 0x38U, 0x58U, 0xDAU, 0x9FU },  /* cipher */
        0x14U                                                        /* key length */
    },
    /* 21-byte key */
    /* F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344   FEDCBA9876543210   E6F51ED79B9DB21F     */
    {
        { 0xF0U, 0xE1U, 0xD2U, 0xC3U, 0xB4U, 0xA5U, 0x96U, 0x87U,    /* key */
          0x78U, 0x69U, 0x5AU, 0x4BU, 0x3CU, 0x2DU, 0x1EU, 0x0FU,
          0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x00U, 0x00U, 0x00U },
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* plain */
        { 0xE6U, 0xF5U, 0x1EU, 0xD7U, 0x9BU, 0x9DU, 0xB2U, 0x1FU },  /* cipher */
        0x15U                                                        /* key length */
    },
    /* 22-byte key */
    /* F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455   FEDCBA9876543210   64A6E14AFD36B46F    */
    {
        { 0xF0U, 0xE1U, 0xD2U, 0xC3U, 0xB4U, 0xA5U, 0x96U, 0x87U,    /* key */
          0x78U, 0x69U, 0x5AU, 0x4BU, 0x3CU, 0x2DU, 0x1EU, 0x0FU,
          0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x00U, 0x00U },
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* plain */
        { 0x64U, 0xA6U, 0xE1U, 0x4AU, 0xFDU, 0x36U, 0xB4U, 0x6FU },  /* cipher */
        0x16U                                                        /* key length */
    },
    /* 23-byte key */
    /* F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566   FEDCBA9876543210   80C7D7D45A5479AD   */
    {
        { 0xF0U, 0xE1U, 0xD2U, 0xC3U, 0xB4U, 0xA5U, 0x96U, 0x87U,    /* key */
          0x78U, 0x69U, 0x5AU, 0x4BU, 0x3CU, 0x2DU, 0x1EU, 0x0FU,
          0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x00U },
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* plain */
        { 0x80U, 0xC7U, 0xD7U, 0xD4U, 0x5AU, 0x54U, 0x79U, 0xADU },  /* cipher */
        0x17U                                                        /* key length */
    },
    /* 24-byte key */
    /* F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677   FEDCBA9876543210   05044B62FA52D080  */
    {
        { 0xF0U, 0xE1U, 0xD2U, 0xC3U, 0xB4U, 0xA5U, 0x96U, 0x87U,    /* key */
          0x78U, 0x69U, 0x5AU, 0x4BU, 0x3CU, 0x2DU, 0x1EU, 0x0FU,
          0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U },
        { 0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* plain */
        { 0x05U, 0x04U, 0x4BU, 0x62U, 0xFAU, 0x52U, 0xD0U, 0x80U },  /* cipher */
        0x18U                                                        /* key length */
    },
};

static Esc_ERROR
EscTstBfishEcb_InitParams(
    void );

static Esc_ERROR
EscTstBfishEcb_DecryptionParams(
    void );

static Esc_ERROR
EscTstBfishEcb_EncryptionParams(
    void );

static Esc_ERROR
EscTstBfishEcb_DecryptionComp(
    void );

static Esc_ERROR
EscTstBfishEcb_EncryptionComp(
    void );

typedef Esc_ERROR (
* EscTstBfishEcb_TestFunctionsT )(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstBfishEcb_InitParams(
    void )
{
    Esc_ERROR returnCode;
    EscBfishEcb_ContextT ctx;

    EscTst_PrintString( "EscBfishEcb_Init parameter test\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscBfishEcb_Init( &ctx, EscTstBfishEcb_TESTCASES[0].key, EscTstBfishEcb_TESTCASES[0].keyLen );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscBfishEcb_Init( Esc_NULL_PTR, EscTstBfishEcb_TESTCASES[0].key, EscTstBfishEcb_TESTCASES[0].keyLen );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With key==0\n" );
            returnCode = EscBfishEcb_Init( &ctx, Esc_NULL_PTR, EscTstBfishEcb_TESTCASES[0].keyLen );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With keyLen<4\n" );
                returnCode = EscBfishEcb_Init( &ctx, EscTstBfishEcb_TESTCASES[0].key, 3U );
                if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "With keyLen>56\n" );
                    returnCode = EscBfishEcb_Init( &ctx, EscTstBfishEcb_TESTCASES[0].key, 57U );
                    if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                    {
                        returnCode = Esc_NO_ERROR;
                    }
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
EscTstBfishEcb_DecryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscBfishEcb_ContextT ctx;
    Esc_UINT8 plain[EscBfish_BLOCK_BYTES];

    EscTst_PrintString( "EscBfishEcb_Decrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscBfishEcb_Init()\n" );
    returnCode = EscBfishEcb_Init( &ctx, EscTstBfishEcb_TESTCASES[0].key, EscTstBfishEcb_TESTCASES[0].keyLen );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscBfishEcb_Decrypt( Esc_NULL_PTR, EscTstBfishEcb_TESTCASES[0].cipher, plain );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With cipher==0\n" );
            returnCode = EscBfishEcb_Decrypt( &ctx, Esc_NULL_PTR, plain );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With plain==0\n" );
                returnCode = EscBfishEcb_Decrypt( &ctx, EscTstBfishEcb_TESTCASES[0].cipher, Esc_NULL_PTR );

                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
            }
        }
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstBfishEcb_EncryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscBfishEcb_ContextT ctx;
    Esc_UINT8 cipher[EscBfish_BLOCK_BYTES];

    EscTst_PrintString( "EscBfishEcb_Encrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscBfishEcb_Init()\n" );
    returnCode = EscBfishEcb_Init( &ctx, EscTstBfishEcb_TESTCASES[0].key, EscTstBfishEcb_TESTCASES[0].keyLen );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscBfishEcb_Encrypt( Esc_NULL_PTR, EscTstBfishEcb_TESTCASES[0].plain, cipher );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With plain==0\n" );
            returnCode = EscBfishEcb_Encrypt( &ctx, Esc_NULL_PTR, cipher );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With cipher==0\n" );
                returnCode = EscBfishEcb_Encrypt( &ctx, EscTstBfishEcb_TESTCASES[0].plain, Esc_NULL_PTR );

                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstBfishEcb_DecryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 bfishBuf[EscBfish_BLOCK_BYTES];     /* buffer for data to decrypt */
    EscBfishEcb_ContextT ecbCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "Blowfish-ECB Decryption Compliance test\n" );

    for (i = 0U; (i < EscTstBfishEcb_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstBfishEcb_TestcaseT* test = &EscTstBfishEcb_TESTCASES[i];

        EscTst_PrintWord( "Test #", (Esc_UINT32)i );

        EscTst_PrintArray( "Key", test->key, (Esc_UINT32)test->keyLen );
        EscTst_PrintArray( "Ciphertext", test->cipher, EscBfish_BLOCK_BYTES );
        EscTst_PrintArray( "Expected plaintext", test->plain, EscBfish_BLOCK_BYTES );

        EscTst_PrintString( "EscBfishEcb_Init()\n" );
        returnCode = EscBfishEcb_Init( &ecbCtx, test->key, test->keyLen );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscBfishEcb_Decrypt()\n" );
            returnCode = EscBfishEcb_Decrypt( &ecbCtx, test->cipher, bfishBuf );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", bfishBuf, sizeof(bfishBuf) );

                if ( EscTst_Memcmp( bfishBuf, test->plain, EscBfish_BLOCK_BYTES ) )
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
EscTstBfishEcb_EncryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 bfishBuf[EscBfish_BLOCK_BYTES];     /* buffer for data to encrypt */
    EscBfishEcb_ContextT ecbCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "Blowfish-ECB Encryption Compliance test\n" );

    for (i = 0U; (i < EscTstBfishEcb_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstBfishEcb_TestcaseT* test = &EscTstBfishEcb_TESTCASES[i];

        EscTst_PrintArray( "Key", test->key, (Esc_UINT32)test->keyLen );
        EscTst_PrintArray( "Plaintext", test->plain, EscBfish_BLOCK_BYTES );
        EscTst_PrintArray( "Expected ciphertext", test->cipher, EscBfish_BLOCK_BYTES );

        EscTst_PrintString( "EscBfishEcb_Init()\n" );
        returnCode = EscBfishEcb_Init( &ecbCtx, test->key, test->keyLen );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscBfishEcb_Encrypt()\n" );
            returnCode = EscBfishEcb_Encrypt( &ecbCtx, test->plain, bfishBuf );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", bfishBuf, sizeof(bfishBuf) );

                if ( EscTst_Memcmp( bfishBuf, test->cipher, EscBfish_BLOCK_BYTES ) )
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
EscTstBfishEcb_Perform(
    void )
{
    /* The test cases */
    static const EscTstBfishEcb_TestFunctionsT EscTstBfishEcb_TESTS[] =
    {
        EscTstBfishEcb_InitParams,
        EscTstBfishEcb_EncryptionParams,
        EscTstBfishEcb_DecryptionParams,
        EscTstBfishEcb_EncryptionComp,
        EscTstBfishEcb_DecryptionComp,
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    EscTst_PrintString( "*******************************************************\n" );

    for (i = 0U; (i < EscTstBfishEcb_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstBfishEcb_TestFunctionsT TestFunction;
        /* Perform test #i */
        TestFunction = EscTstBfishEcb_TESTS[i];
        returnCode = TestFunction();
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
