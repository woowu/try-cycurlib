/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief DES Selftest.


   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_des3_ecb.h"
#include "selftest.h"
#include "des3_ecb.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
/** ECB test vector */
typedef struct
{
    Esc_UINT8 k1[EscDes_KEY_BYTES];
    Esc_UINT8 k2[EscDes_KEY_BYTES];
    Esc_UINT8 k3[EscDes_KEY_BYTES];
    Esc_UINT8 plain[EscDes_BLOCK_BYTES];
    Esc_UINT8 cipher[EscDes_BLOCK_BYTES];
} EscTstDes3Ecb_TestcaseT;

#define EscTstDes3Ecb_NUM_TESTCASES 4U
static const EscTstDes3Ecb_TestcaseT EscTstDes3Ecb_TESTCASES[EscTstDes3Ecb_NUM_TESTCASES] =
{
    /* from openssl 1.0.0-beta2 */
    {
        { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU, 0xcdU, 0xefU },  /* k1 */
        { 0xf1U, 0xe0U, 0xd3U, 0xc2U, 0xb5U, 0xa4U, 0x97U, 0x86U },  /* k2 */
        { 0xfeU, 0xdcU, 0xbaU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U },  /* k3 */
        { 0xC9U, 0xEAU, 0x8FU, 0xACU, 0x45U, 0x66U, 0x03U, 0x30U }, /* plain */
        { 0x3FU, 0xE3U, 0x01U, 0xC9U, 0x62U, 0xACU, 0x01U, 0xD0U },  /* cipher */
    },
    /* from NIST SP 800-67-Rev1; Appendix B.1.
       Be careful, the conversion of the string "The quic" into hex-values is wrong in the example! */
    {
        { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU }, /* k1 */
        { 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U }, /* k2 */
        { 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U, 0x23U }, /* k3 */
        { 0x54U, 0x68U, 0x65U, 0x20U, 0x71U, 0x75U, 0x66U, 0x63U }, /* plain - "The qufc" */
        { 0xA8U, 0x26U, 0xFDU, 0x8CU, 0xE5U, 0x3BU, 0x85U, 0x5FU },  /* cipher */
    },
    {
        { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU }, /* k1 */
        { 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U }, /* k2 */
        { 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U, 0x23U }, /* k3 */
        { 0x6BU, 0x20U, 0x62U, 0x72U, 0x6FU, 0x77U, 0x6EU, 0x20U }, /* plain - "k brown " */
        { 0xCCU, 0xE2U, 0x1CU, 0x81U, 0x12U, 0x25U, 0x6FU, 0xE6U },  /* cipher */
    },
    {
        { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU }, /* k1 */
        { 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U }, /* k2 */
        { 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x01U, 0x23U }, /* k3 */
        { 0x66U, 0x6FU, 0x78U, 0x20U, 0x6AU, 0x75U, 0x6DU, 0x70U }, /* plain - "fox jump" */
        { 0x68U, 0xD5U, 0xC0U, 0x5DU, 0xD9U, 0xB6U, 0xB9U, 0x00U },  /* cipher */
    },
};
static Esc_ERROR
EscTstDes3Ecb_InitParams(
    void );

static Esc_ERROR
EscTstDes3Ecb_DecryptionParams(
    void );

static Esc_ERROR
EscTstDes3Ecb_EncryptionParams(
    void );

static Esc_ERROR
EscTstDes3Ecb_DecryptionComp(
    void );

static Esc_ERROR
EscTstDes3Ecb_EncryptionComp(
    void );

typedef Esc_ERROR (
* EscTstDes3Ecb_TestFunctionsT )(
    void );

#define EscTstDes3Ecb_NUM_TESTS ( sizeof(EscTstDes3Ecb_TESTS) / sizeof(EscTstDes3Ecb_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstDes3Ecb_InitParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Ecb_ContextT ctx;

    EscTst_PrintString( "EscDes3Ecb_Init parameter test\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscDes3Ecb_Init( &ctx,
            EscTstDes3Ecb_TESTCASES[0].k1,
            EscTstDes3Ecb_TESTCASES[0].k2, EscTstDes3Ecb_TESTCASES[0].k3 );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscDes3Ecb_Init( Esc_NULL_PTR,
                EscTstDes3Ecb_TESTCASES[0].k1,
                EscTstDes3Ecb_TESTCASES[0].k2, EscTstDes3Ecb_TESTCASES[0].k3 );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With k3==0\n" );
            returnCode = EscDes3Ecb_Init( &ctx, EscTstDes3Ecb_TESTCASES[0].k1, EscTstDes3Ecb_TESTCASES[0].k2, Esc_NULL_PTR );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                returnCode = Esc_NO_ERROR;
            }
        }
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstDes3Ecb_DecryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Ecb_ContextT ctx;
    Esc_UINT8 plain[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscDes3Ecb_Decrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscDes3Ecb_Init()\n" );
    returnCode = EscDes3Ecb_Init( &ctx,
            EscTstDes3Ecb_TESTCASES[0].k1,
            EscTstDes3Ecb_TESTCASES[0].k2, EscTstDes3Ecb_TESTCASES[0].k3 );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscDes3Ecb_Decrypt( Esc_NULL_PTR, EscTstDes3Ecb_TESTCASES[0].cipher, plain );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With cipher==0\n" );
            returnCode = EscDes3Ecb_Decrypt( &ctx, Esc_NULL_PTR, plain );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With plain==0\n" );
                returnCode = EscDes3Ecb_Decrypt( &ctx, EscTstDes3Ecb_TESTCASES[0].cipher, Esc_NULL_PTR );

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
EscTstDes3Ecb_EncryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Ecb_ContextT ctx;
    Esc_UINT8 cipher[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscDes3Ecb_Encrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscDes3Ecb_Init()\n" );
    returnCode = EscDes3Ecb_Init( &ctx,
            EscTstDes3Ecb_TESTCASES[0].k1,
            EscTstDes3Ecb_TESTCASES[0].k2, EscTstDes3Ecb_TESTCASES[0].k3 );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ecbCtx==0\n" );
        returnCode = EscDes3Ecb_Encrypt( Esc_NULL_PTR, EscTstDes3Ecb_TESTCASES[0].plain, cipher );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With plain==0\n" );
            returnCode = EscDes3Ecb_Encrypt( &ctx, Esc_NULL_PTR, cipher );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With cipher==0\n" );
                returnCode = EscDes3Ecb_Encrypt( &ctx, EscTstDes3Ecb_TESTCASES[0].plain, Esc_NULL_PTR );

                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDes3Ecb_DecryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 desBuf[EscDes_BLOCK_BYTES];     /* buffer for data to decrypt      */
    EscDes3Ecb_ContextT ecbCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "DES-ECB Decryption Compliance test\n" );

    for (i = 0U; (i < EscTstDes3Ecb_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstDes3Ecb_TestcaseT* test = &EscTstDes3Ecb_TESTCASES[i];

        EscTst_PrintWord( "Test #", (Esc_UINT32)i );

        EscTst_PrintArray( "Key k1", test->k1, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key k2", test->k2, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key k3", test->k3, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Ciphertext", test->cipher, EscDes_BLOCK_BYTES );
        EscTst_PrintArray( "Expected plaintext", test->plain, EscDes_BLOCK_BYTES );

        EscTst_PrintString( "EscDes3Ecb_Init()\n" );
        returnCode = EscDes3Ecb_Init( &ecbCtx, test->k1, test->k2, test->k3 );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscDes3Ecb_Decrypt()\n" );
            returnCode = EscDes3Ecb_Decrypt( &ecbCtx, test->cipher, desBuf );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", desBuf, sizeof(desBuf) );

                if ( EscTst_Memcmp( desBuf, test->plain, EscDes_BLOCK_BYTES ) )
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
EscTstDes3Ecb_EncryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 desBuf[EscDes_BLOCK_BYTES];     /* buffer for data to decrypt      */
    EscDes3Ecb_ContextT ecbCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "DES-ECB Encryption Compliance test\n" );

    for (i = 0U; (i < EscTstDes3Ecb_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstDes3Ecb_TestcaseT* test = &EscTstDes3Ecb_TESTCASES[i];

        EscTst_PrintArray( "Key k1", test->k1, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key k2", test->k2, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key k3", test->k3, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Plaintext", test->plain, EscDes_BLOCK_BYTES );
        EscTst_PrintArray( "Expected ciphertext", test->cipher, EscDes_BLOCK_BYTES );

        EscTst_PrintString( "EscDes3Ecb_Init()\n" );
        returnCode = EscDes3Ecb_Init( &ecbCtx, test->k1, test->k2, test->k3 );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscDes3Ecb_Encrypt()\n" );
            returnCode = EscDes3Ecb_Encrypt( &ecbCtx, test->plain, desBuf );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", desBuf, sizeof(desBuf) );

                if ( EscTst_Memcmp( desBuf, test->cipher, EscDes_BLOCK_BYTES ) )
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
EscTstDes3Ecb_Perform(
    void )
{
    /* The test cases */
    static const EscTstDes3Ecb_TestFunctionsT EscTstDes3Ecb_TESTS[] =
    {
        EscTstDes3Ecb_InitParams,
        EscTstDes3Ecb_EncryptionParams,
        EscTstDes3Ecb_DecryptionParams,
        EscTstDes3Ecb_EncryptionComp,
        EscTstDes3Ecb_DecryptionComp,
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    EscTst_PrintString( "*******************************************************\n" );

    for (i = 0U; (i < EscTstDes3Ecb_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstDes3Ecb_TestFunctionsT TestFunction;
        /* Perform test #i */
        TestFunction = EscTstDes3Ecb_TESTS[i];
        returnCode = TestFunction();
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
