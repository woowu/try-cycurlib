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
#include "test_des3_cbc.h"
#include "selftest.h"
#include "des3_cbc.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
/** The maximum length of a test vector. */
#define EscTstDes3Cbc_MAX_MSG_LEN 32U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
/** CBC test vector */
typedef struct
{
    Esc_UINT8 k1[EscDes_KEY_BYTES];
    Esc_UINT8 k2[EscDes_KEY_BYTES];
    Esc_UINT8 k3[EscDes_KEY_BYTES];
    Esc_UINT8 iv[EscDes_BLOCK_BYTES];
    Esc_UINT8 plain[EscTstDes3Cbc_MAX_MSG_LEN];
    Esc_UINT8 cipher[EscTstDes3Cbc_MAX_MSG_LEN];
    Esc_UINT32 len;
} EscTstDes3Cbc_TestcaseT;

#define EscTstDes3Cbc_NUM_TESTCASES 3U
static const EscTstDes3Cbc_TestcaseT EscTstDes3Cbc_TESTCASES[EscTstDes3Cbc_NUM_TESTCASES] =
{
    /* Official test vectors from NIST: csrc.nist.gov/groups/STM/cavp/#01
     * Uses test vectors no 10 of TCBCIvartext.rsp */
    {
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k1 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k2 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k3 */
        { 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U },  /* iv */
        {
            0x00U, 0x20U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* plain */
        {
            0xb8U, 0x06U, 0x1bU, 0x7eU, 0xcdU, 0x9aU, 0x21U, 0xe5U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* cipher */
        8U                        /* len */
    },
    {
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k1 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k2 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k3 */
        { 0x55U, 0x55U, 0x55U, 0x55U, 0x55U, 0x55U, 0x55U, 0x55U },  /* iv */
        {
            0x00U, 0x20U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* plain */
        {
            0xc8U, 0xebU, 0x2eU, 0x34U, 0x08U, 0x55U, 0x32U, 0x5bU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* cipher */
        8U                        /* len */
    },
    {
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k1 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k2 */
        { 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U },  /* k3 */
        { 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU },  /* iv */
        {
            0x00U, 0x20U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* plain */
        {
            0xd5U, 0x11U, 0x75U, 0x25U, 0x9cU, 0x60U, 0x7fU, 0xb4U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },  /* cipher */
        8U                        /* len */
    }
};
static Esc_ERROR
EscTstDes3Cbc_InitParams(
    void );

static Esc_ERROR
EscTstDes3Cbc_DecryptionParams(
    void );

static Esc_ERROR
EscTstDes3Cbc_EncryptionParams(
    void );

static Esc_ERROR
EscTstDes3Cbc_DecryptionComp(
    void );

static Esc_ERROR
EscTstDes3Cbc_EncryptionComp(
    void );

static Esc_ERROR
EscTstDes3Cbc_SetIVParams(
    void );

static Esc_ERROR
EscTstDes3Cbc_DecryptIVChange(
    void );

static Esc_ERROR
EscTstDes3Cbc_EncryptIVChange(
    void );

typedef Esc_ERROR (
* EscTstDes3Cbc_TestFunctionsT )(
    void );

#define EscTstDes3Cbc_NUM_TESTS ( sizeof(EscTstDes3Cbc_TESTS) / sizeof(EscTstDes3Cbc_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstDes3Cbc_InitParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Cbc_ContextT ctx;

    EscTst_PrintString( "EscDes3Cbc_Init parameter test\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3, EscTstDes3Cbc_TESTCASES[0].iv );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cbcCtx==0\n" );
        returnCode = EscDes3Cbc_Init( Esc_NULL_PTR,
                EscTstDes3Cbc_TESTCASES[0].k1,
                EscTstDes3Cbc_TESTCASES[0].k2,
                EscTstDes3Cbc_TESTCASES[0].k3, EscTstDes3Cbc_TESTCASES[0].iv );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With k2==0\n" );
            returnCode = EscDes3Cbc_Init( &ctx,
                    EscTstDes3Cbc_TESTCASES[0].k1,
                    Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].k3, EscTstDes3Cbc_TESTCASES[0].iv );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With iv==0\n" );
                returnCode = EscDes3Cbc_Init( &ctx,
                        EscTstDes3Cbc_TESTCASES[0].k1,
                        EscTstDes3Cbc_TESTCASES[0].k2, EscTstDes3Cbc_TESTCASES[0].k3, Esc_NULL_PTR );
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
EscTstDes3Cbc_DecryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Cbc_ContextT ctx;
    Esc_UINT8 plain[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscDes3Cbc_Decrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscDes3Cbc_Init()\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3, EscTstDes3Cbc_TESTCASES[0].iv );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cbcCtx==0\n" );
        returnCode = EscDes3Cbc_Decrypt( Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].cipher, plain, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With plain==0\n" );
        returnCode = EscDes3Cbc_Decrypt( &ctx, EscTstDes3Cbc_TESTCASES[0].cipher, Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cipher==0\n" );
        returnCode = EscDes3Cbc_Decrypt( &ctx, Esc_NULL_PTR, plain, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With len % 8 != 0\n" );
        returnCode = EscDes3Cbc_Decrypt( &ctx,
                EscTstDes3Cbc_TESTCASES[0].cipher,
                plain,
                EscTstDes3Cbc_TESTCASES[0].len - 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstDes3Cbc_EncryptionParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Cbc_ContextT ctx;
    Esc_UINT8 cipher[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscDes3Cbc_Encrypt parameter test\n" );

    EscTst_PrintString( "Initializing context with EscDes3Cbc_Init()\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3, EscTstDes3Cbc_TESTCASES[0].iv );

    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cbcCtx==0\n" );
        returnCode = EscDes3Cbc_Encrypt( Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].plain, cipher, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With cipher==0\n" );
        returnCode = EscDes3Cbc_Encrypt( &ctx, EscTstDes3Cbc_TESTCASES[0].plain, Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With plain==0\n" );
        returnCode = EscDes3Cbc_Encrypt( &ctx, Esc_NULL_PTR, cipher, EscTstDes3Cbc_TESTCASES[0].len );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With len % 8 != 0\n" );
        returnCode = EscDes3Cbc_Encrypt( &ctx,
                EscTstDes3Cbc_TESTCASES[0].plain,
                cipher,
                EscTstDes3Cbc_TESTCASES[0].len - 1U );

        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstDes3Cbc_DecryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 desBuf[EscTstDes3Cbc_MAX_MSG_LEN];      /* buffer for data to decrypt      */
    EscDes3Cbc_ContextT cbcCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "DES-CBC Decryption Compliance test\n" );

    for (i = 0U; (i < EscTstDes3Cbc_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstDes3Cbc_TestcaseT* test = &EscTstDes3Cbc_TESTCASES[i];

        EscTst_PrintWord( "Test #", (Esc_UINT32)i );

        EscTst_PrintArray( "Key K1", test->k1, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key K2", test->k2, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key K3", test->k3, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Ciphertext", test->cipher, test->len );
        EscTst_PrintArray( "Expected plaintext", test->plain, test->len );

        EscTst_PrintString( "EscDes3Cbc_Init()\n" );
        returnCode = EscDes3Cbc_Init( &cbcCtx, test->k1, test->k2, test->k3, test->iv );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscDes3Cbc_Decrypt()\n" );
            returnCode = EscDes3Cbc_Decrypt( &cbcCtx, test->cipher, desBuf, test->len );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received plaintext", desBuf, test->len );

                if ( EscTst_Memcmp( desBuf, test->plain, test->len ) )
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
EscTstDes3Cbc_EncryptionComp(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 desBuf[EscTstDes3Cbc_MAX_MSG_LEN];      /* buffer for data to decrypt      */
    EscDes3Cbc_ContextT cbcCtx;
    Esc_UINT8 i;

    EscTst_PrintString( "DES-CBC Encryption Compliance test\n" );

    for (i = 0U; (i < EscTstDes3Cbc_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        const EscTstDes3Cbc_TestcaseT* test = &EscTstDes3Cbc_TESTCASES[i];

        EscTst_PrintArray( "Key K1", test->k1, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key K2", test->k2, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Key K3", test->k3, EscDes_KEY_BYTES );
        EscTst_PrintArray( "Plaintext", test->plain, test->len );
        EscTst_PrintArray( "Expected ciphertext", test->cipher, test->len );

        EscTst_PrintString( "EscDes3Cbc_Init()\n" );
        returnCode = EscDes3Cbc_Init( &cbcCtx, test->k1, test->k2, test->k3, test->iv );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscDes3Cbc_Encrypt()\n" );
            returnCode = EscDes3Cbc_Encrypt( &cbcCtx, test->plain, desBuf, test->len );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received ciphertext", desBuf, test->len );

                if ( EscTst_Memcmp( desBuf, test->cipher, test->len ) )
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
EscTstDes3Cbc_SetIVParams(
    void )
{
    Esc_ERROR returnCode;
    EscDes3Cbc_ContextT ctx;

    EscTst_PrintString( "EscDes3Cbc_SetIVParams parameter test on test case 0\n" );
    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3,
            EscTstDes3Cbc_TESTCASES[0].iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx == 0\n" );
        returnCode = EscDes3Cbc_SetIV( Esc_NULL_PTR, EscTstDes3Cbc_TESTCASES[0].iv );
    }

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "iv == 0\n" );
        returnCode = EscDes3Cbc_SetIV( &ctx, Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstDes3Cbc_DecryptIVChange(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 desBuf[EscTstDes3Cbc_MAX_MSG_LEN];   /* buffer for data to decrypt      */
    EscDes3Cbc_ContextT ctx;

#if (EscTstDes3Cbc_NUM_TESTCASES <= 1U)
#   error "Insufficient number of test cases for IV change!"
#endif

    EscTst_PrintString( "EscTstDes3Cbc_DecryptIVChange test\n" );

    EscTst_PrintString( "Calling EscDesCbc_Init()\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3,
            EscTstDes3Cbc_TESTCASES[0].iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscDes3Cbc_Decrypt() using IV_0\n" );
        returnCode = EscDes3Cbc_Decrypt( &ctx, EscTstDes3Cbc_TESTCASES[0].cipher, desBuf, EscTstDes3Cbc_TESTCASES[0].len );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received plaintext", desBuf, EscTstDes3Cbc_TESTCASES[0].len );
        if ( EscTst_Memcmp( desBuf, EscTstDes3Cbc_TESTCASES[0].plain, EscTstDes3Cbc_TESTCASES[0].len ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscDes3Cbc_SetIV() with IV_1\n" );
        returnCode = EscDes3Cbc_SetIV( &ctx, EscTstDes3Cbc_TESTCASES[1].iv );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Remark: Since EscTstDes3Cbc_TESTCASES[0].k1/k2/k3 == EscTstDes3Cbc_TESTCASES[1].k1/k2/k3 we do not update the key! */
        EscTst_PrintString( "Calling EscDes3Cbc_Decrypt() using IV_1\n" );
        returnCode = EscDes3Cbc_Decrypt( &ctx, EscTstDes3Cbc_TESTCASES[1].cipher, desBuf, EscTstDes3Cbc_TESTCASES[1].len );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received plaintext", desBuf, EscTstDes3Cbc_TESTCASES[1].len );

        if ( EscTst_Memcmp( desBuf, EscTstDes3Cbc_TESTCASES[1].plain, EscTstDes3Cbc_TESTCASES[1].len ) )
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
EscTstDes3Cbc_EncryptIVChange(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 desBuf[EscTstDes3Cbc_MAX_MSG_LEN];   /* buffer for data to decrypt      */
    EscDes3Cbc_ContextT ctx;

#if (EscTstDes3Cbc_NUM_TESTCASES <= 1U)
#   error "Insufficient number of test cases for IV change!"
#endif

    EscTst_PrintString( "EscTstDes3Cbc_EncryptIVChange test\n" );

    EscTst_PrintString( "Calling EscDes3Cbc_Init()\n" );
    returnCode = EscDes3Cbc_Init( &ctx,
            EscTstDes3Cbc_TESTCASES[0].k1,
            EscTstDes3Cbc_TESTCASES[0].k2,
            EscTstDes3Cbc_TESTCASES[0].k3,
            EscTstDes3Cbc_TESTCASES[0].iv );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscDes3Cbc_Encrypt() using IV_0\n" );
        returnCode = EscDes3Cbc_Encrypt( &ctx, EscTstDes3Cbc_TESTCASES[0].plain, desBuf, EscTstDes3Cbc_TESTCASES[0].len );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received ciphertext", desBuf, EscTstDes3Cbc_TESTCASES[0].len );

        if ( EscTst_Memcmp( desBuf, EscTstDes3Cbc_TESTCASES[0].cipher, EscTstDes3Cbc_TESTCASES[0].len ) )
        {
            EscTst_PrintString( "Correct\n\n\n" );
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscDes3Cbc_SetIV() with IV_1\n" );
        returnCode = EscDes3Cbc_SetIV( &ctx, EscTstDes3Cbc_TESTCASES[1].iv );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        /* Remark: Since EscTstDesCbc_TESTCASES[0].key == EscTstDesCbc_TESTCASES[1].key we do not update the key! */
        EscTst_PrintString( "Calling EscDes3Cbc_Encrypt() using IV_1\n" );
        returnCode = EscDes3Cbc_Encrypt( &ctx, EscTstDes3Cbc_TESTCASES[1].plain, desBuf, EscTstDes3Cbc_TESTCASES[1].len );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintArray( "Received ciphertext", desBuf, EscTstDes3Cbc_TESTCASES[1].len );

        if ( EscTst_Memcmp( desBuf, EscTstDes3Cbc_TESTCASES[1].cipher, EscTstDes3Cbc_TESTCASES[1].len ) )
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

Esc_ERROR
EscTstDes3Cbc_Perform(
    void )
{
    /* The test cases */
    static const EscTstDes3Cbc_TestFunctionsT EscTstDes3Cbc_TESTS[] =
    {
        EscTstDes3Cbc_InitParams,
        EscTstDes3Cbc_EncryptionParams,
        EscTstDes3Cbc_DecryptionParams,
        EscTstDes3Cbc_EncryptionComp,
        EscTstDes3Cbc_DecryptionComp,
        EscTstDes3Cbc_SetIVParams,
        EscTstDes3Cbc_DecryptIVChange,
        EscTstDes3Cbc_EncryptIVChange
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    EscTst_PrintString( "*******************************************************\n" );

    for (i = 0U; (i < EscTstDes3Cbc_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstDes3Cbc_TestFunctionsT TestFunction;
        /* Perform test #i */
        TestFunction = EscTstDes3Cbc_TESTS[i];
        returnCode = TestFunction();
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
