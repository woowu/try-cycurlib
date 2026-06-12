/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief SHA-224 and SHA-256 Selftest

   Checks pre-computed test patterns.

   \see Compliance test vectors from FIPS-180-2
   csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_sha_256.h"
#include "selftest.h"
#include "sha_256.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    const Esc_CHAR* title;
#endif
    const Esc_CHAR* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 digest[EscSha256_DIGEST_LEN];
} EscTstSha256_TestT;

/*
   Tests from FIPS-180-2. Appendix B. and others.
 */
static const EscTstSha256_TestT EscTstSha224_FIPS_TESTS[] =
{
    {
        /* SHA-224 */
#    if EscTst_ENABLE_LOGGING == 1
        "Empty string",
#    endif
        "", 0U,
        {
            0xd1U, 0x4aU, 0x02U, 0x8cU, 0x2aU, 0x3aU, 0x2bU, 0xc9U,
            0x47U, 0x61U, 0x02U, 0xbbU, 0x28U, 0x82U, 0x34U, 0xc4U,
            0x15U, 0xa2U, 0xb0U, 0x1fU, 0x82U, 0x8eU, 0xa6U, 0x2aU,
            0xc5U, 0xb3U, 0xe4U, 0x2fU, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Change 1",
#    endif
        "abc", 3U,
        {
            0x23U, 0x09U, 0x7dU, 0x22U, 0x34U, 0x05U, 0xd8U, 0x22U,
            0x86U, 0x42U, 0xa4U, 0x77U, 0xbdU, 0xa2U, 0x55U, 0xb3U,
            0x2aU, 0xadU, 0xbcU, 0xe4U, 0xbdU, 0xa0U, 0xb3U, 0xf7U,
            0xe3U, 0x6cU, 0x9dU, 0xa7U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },

    {
#    if EscTst_ENABLE_LOGGING == 1
        "Change 2",
#    endif
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56U,
        {
            0x75U, 0x38U, 0x8bU, 0x16U, 0x51U, 0x27U, 0x76U, 0xccU,
            0x5dU, 0xbaU, 0x5dU, 0xa1U, 0xfdU, 0x89U, 0x01U, 0x50U,
            0xb0U, 0xc6U, 0x45U, 0x5cU, 0xb4U, 0xf5U, 0x8bU, 0x19U,
            0x52U, 0x52U, 0x25U, 0x25U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 63 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 63U,
        {
            0x1dU, 0x4eU, 0x05U, 0x1fU, 0x4dU, 0x6fU, 0xedU, 0x2aU,
            0x63U, 0xfdU, 0x24U, 0x21U, 0xe6U, 0x58U, 0x34U, 0xceU,
            0xc0U, 0x0dU, 0x64U, 0x45U, 0x65U, 0x53U, 0xdeU, 0x34U,
            0x96U, 0xaeU, 0x8bU, 0x1dU, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 64 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64U,
        {
            0xa8U, 0x8cU, 0xd5U, 0xcdU, 0xe6U, 0xd6U, 0xfeU, 0x91U,
            0x36U, 0xa4U, 0xe5U, 0x8bU, 0x49U, 0x16U, 0x74U, 0x61U,
            0xeaU, 0x95U, 0xd3U, 0x88U, 0xcaU, 0x2bU, 0xdbU, 0x7aU,
            0xfdU, 0xc3U, 0xcbU, 0xf4U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
};

static const EscTstSha256_TestT EscTstSha256_FIPS_TESTS[] =
{
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Empty string",
#    endif
        "", 0U,
        {
            0xe3U, 0xb0U, 0xc4U, 0x42U, 0x98U, 0xfcU, 0x1cU, 0x14U,
            0x9aU, 0xfbU, 0xf4U, 0xc8U, 0x99U, 0x6fU, 0xb9U, 0x24U,
            0x27U, 0xaeU, 0x41U, 0xe4U, 0x64U, 0x9bU, 0x93U, 0x4cU,
            0xa4U, 0x95U, 0x99U, 0x1bU, 0x78U, 0x52U, 0xb8U, 0x55U
        }
    }, {
#    if EscTst_ENABLE_LOGGING == 1
        "B.1",
#    endif
        "abc", 3U,
        {
            0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
            0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
            0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
            0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU
        }
    },

    {
#    if EscTst_ENABLE_LOGGING == 1
        "B.2",
#    endif
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56U,
        {
            0x24U, 0x8dU, 0x6aU, 0x61U, 0xd2U, 0x06U, 0x38U, 0xb8U,
            0xe5U, 0xc0U, 0x26U, 0x93U, 0x0cU, 0x3eU, 0x60U, 0x39U,
            0xa3U, 0x3cU, 0xe4U, 0x59U, 0x64U, 0xffU, 0x21U, 0x67U,
            0xf6U, 0xecU, 0xedU, 0xd4U, 0x19U, 0xdbU, 0x06U, 0xc1U
        }
    }, {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 63U,
        {
            0x7dU, 0x3eU, 0x74U, 0xa0U, 0x5dU, 0x7dU, 0xb1U, 0x5bU,
            0xceU, 0x4aU, 0xd9U, 0xecU, 0x06U, 0x58U, 0xeaU, 0x98U,
            0xe3U, 0xf0U, 0x6eU, 0xeeU, 0xcfU, 0x16U, 0xb4U, 0xc6U,
            0xffU, 0xf2U, 0xdaU, 0x45U, 0x7dU, 0xdcU, 0x2fU, 0x34U
        }
    }, {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 64 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64U,
        {
            0xffU, 0xe0U, 0x54U, 0xfeU, 0x7aU, 0xe0U, 0xcbU, 0x6dU,
            0xc6U, 0x5cU, 0x3aU, 0xf9U, 0xb6U, 0x1dU, 0x52U, 0x09U,
            0xf4U, 0x39U, 0x85U, 0x1dU, 0xb4U, 0x3dU, 0x0bU, 0xa5U,
            0x99U, 0x73U, 0x37U, 0xdfU, 0x15U, 0x46U, 0x68U, 0xebU
        }
    }
};

/* Number of FIPS-180-2 compliance tests for SHA-224 */
#define EscTstSha224_FIPS_TESTS_NUM ( sizeof(EscTstSha224_FIPS_TESTS) / sizeof(EscTstSha224_FIPS_TESTS[0]) )

/* Number of FIPS-180-2 compliance tests for SHA-256*/
#define EscTstSha256_FIPS_TESTS_NUM ( sizeof(EscTstSha256_FIPS_TESTS) / sizeof(EscTstSha256_FIPS_TESTS[0]) )

typedef Esc_ERROR (
* EscTstSha256_TestFunctionsT )(
    Esc_BOOL isSha224 );

typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    Esc_CHAR name[64];
#endif
    EscTstSha256_TestFunctionsT TestFunction;
} EscTstSha256_TestModuleT;

static Esc_ERROR
EscTstSha256_ComplianceTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_FipsComplB3Tst(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_CalcParamTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_InitParamTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_UpdateParamTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_FinishParamTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_BlockTest(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_RunTests(
    Esc_BOOL isSha224 );

static Esc_ERROR
EscTstSha256_TruncationTest(
    Esc_BOOL isSha224 );

/* Number of test cases */
#define EscTstSha256_NUM_TESTS ( sizeof(EscTstSha256_TESTS) / sizeof(EscTstSha256_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscTstSha256_InitParamTest(
    Esc_BOOL isSha224 )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "ctx = 0\n" );

    returnCode = EscSha256_Init( isSha224, Esc_NULL_PTR );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    return returnCode;
}

static Esc_ERROR
EscTstSha256_UpdateParamTest(
    Esc_BOOL isSha224 )
{
    EscSha256_ContextT ctx;
    Esc_ERROR returnCode;

    EscTst_PrintString( "Initializing ctx\n" );
    returnCode = EscSha256_Init( isSha224, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx=0\n" );
        returnCode = EscSha256_Update( Esc_NULL_PTR, (const Esc_UINT8*)EscTstSha256_FIPS_TESTS[0].msg, EscTstSha256_FIPS_TESTS[0].msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "data=0 and dataLen>0\n" );
            returnCode = EscSha256_Update( &ctx, Esc_NULL_PTR, 1U );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_FinishParamTest(
    Esc_BOOL isSha224 )
{
    EscSha256_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha256_DIGEST_LEN];
    Esc_ERROR returnCode;
    Esc_UINT8 digestLength;

    if (isSha224)
    {
        digestLength = EscSha224_DIGEST_LEN;
    }
    else
    {
        digestLength = EscSha256_DIGEST_LEN;
    }

    EscTst_PrintString( "Initializing ctx\n" );
    returnCode = EscSha256_Init( isSha224, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Updating with message\n" );

        returnCode = EscSha256_Update( &ctx, (const Esc_UINT8*)EscTstSha256_FIPS_TESTS[0].msg, EscTstSha256_FIPS_TESTS[0].msgLen );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "ctx=0\n" );
            returnCode = EscSha256_Finish( Esc_NULL_PTR, receivedDigest, digestLength );

            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "digest=0\n" );
                returnCode = EscSha256_Finish( &ctx, Esc_NULL_PTR, digestLength );

                if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "digestLength=0\n" );
                    returnCode = EscSha256_Finish( &ctx, receivedDigest, 0U );

                    if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                    {
                        EscTst_PrintString( "digestLength too long\n" );
                        returnCode = EscSha256_Finish( &ctx, receivedDigest, (digestLength+1U) );

                        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                    }
                }
            }

        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_CalcParamTest(
    Esc_BOOL isSha224 )
{
    Esc_UINT8 receivedDigest[EscSha256_DIGEST_LEN];
    Esc_ERROR returnCode;

    EscTst_PrintString( "data = 0 and dataLen > 0\n" );
    returnCode = EscSha256_Calc( isSha224, Esc_NULL_PTR, 1U, receivedDigest, EscSha224_DIGEST_LEN );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "digest = 0\n" );
        returnCode = EscSha256_Calc( isSha224, (const Esc_UINT8*)EscTstSha256_FIPS_TESTS[0].msg, EscTstSha256_FIPS_TESTS[0].msgLen, Esc_NULL_PTR, EscSha224_DIGEST_LEN );

        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_BlockTest(
    Esc_BOOL isSha224 )
{
    Esc_ERROR returnCode;
    EscSha256_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha256_DIGEST_LEN];
    const EscTstSha256_TestT* testCase;
    Esc_UINT8 digestLen;

    if (isSha224)
    {
        testCase = &EscTstSha224_FIPS_TESTS[1];
        digestLen = EscSha224_DIGEST_LEN;
    }
    else
    {
        testCase = &EscTstSha256_FIPS_TESTS[1];
        digestLen = EscSha256_DIGEST_LEN;
    }

    EscTst_PrintString( "Testscase: " );
    EscTst_PrintString( testCase->title );
    EscTst_PrintString( "\n" );

    EscTst_PrintString( "Message: \"" );
    EscTst_PrintString( testCase->msg );
    EscTst_PrintString( "\"\n" );

    EscTst_PrintString( "Calling EscSha256_Init()\n" );
    returnCode = EscSha256_Init( isSha224, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscSha256_Update() with 1st byte of message\n" );

        returnCode = EscSha256_Update( &ctx, (const Esc_UINT8*)testCase->msg, 1U );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Calling EscSha256_Update() with remaining bytes of message\n" );

            returnCode = EscSha256_Update( &ctx,
                    (const Esc_UINT8*)&testCase->msg[1],
                    (testCase->msgLen - 1U) );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "Calling EscSha256_Finish()\n" );

                returnCode = EscSha256_Finish( &ctx, receivedDigest, digestLen );

                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    returnCode = EscTst_CheckStrings(
                            testCase->digest,
                            (Esc_UINT32)digestLen,
                            receivedDigest,
                            (Esc_UINT32)digestLen );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_FipsComplB3Tst(
    Esc_BOOL isSha224 )
{
    /* Fips test B.3 and Change 3 */
    static const Esc_UINT8 EscTstSha224_FIPS_DIGEST[EscSha256_DIGEST_LEN] =
    {
        0x20U, 0x79U, 0x46U, 0x55U, 0x98U, 0x0cU, 0x91U, 0xd8U,
        0xbbU, 0xb4U, 0xc1U, 0xeaU, 0x97U, 0x61U, 0x8aU, 0x4bU,
        0xf0U, 0x3fU, 0x42U, 0x58U, 0x19U, 0x48U, 0xb2U, 0xeeU,
        0x4eU, 0xe7U, 0xadU, 0x67U, 0x00U, 0x00U, 0x00U, 0x00U
    };

    static const Esc_UINT8 EscTstSha256_FIPS_DIGEST[EscSha256_DIGEST_LEN] =
    {
        0xcdU, 0xc7U, 0x6eU, 0x5cU, 0x99U, 0x14U, 0xfbU, 0x92U,
        0x81U, 0xa1U, 0xc7U, 0xe2U, 0x84U, 0xd7U, 0x3eU, 0x67U,
        0xf1U, 0x80U, 0x9aU, 0x48U, 0xa4U, 0x97U, 0x20U, 0x0eU,
        0x04U, 0x6dU, 0x39U, 0xccU, 0xc7U, 0x11U, 0x2cU, 0xd0U
    };

    Esc_ERROR returnCode;
    EscSha256_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha256_DIGEST_LEN];
    Esc_UINT32 numCharactersLeft = 1000000U;    /* 1 Million repetitions */
    static const Esc_CHAR A_BLOCK[18] = "aaaaaaaaaaaaaaaaa";
    static const Esc_UINT32 BLOCK_SIZE = 17U;

    const Esc_UINT8* digest;
    Esc_UINT8 digestLen;

    if (isSha224)
    {
        digest = &EscTstSha224_FIPS_DIGEST[0];
        digestLen = EscSha224_DIGEST_LEN;
    }
    else
    {
        digest = &EscTstSha256_FIPS_DIGEST[0];
        digestLen = EscSha256_DIGEST_LEN;
    }

    EscTst_PrintString( "1 Million repetitions of the character 'a' in 17 Byte blocks" );
    EscTst_PrintString( "Calling EscSha256_Init()\n" );
    returnCode = EscSha256_Init( isSha224, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscSha256_Update() multiple times\n" );

        while (numCharactersLeft > BLOCK_SIZE)
        {
            returnCode = EscSha256_Update( &ctx, (const Esc_UINT8*)A_BLOCK, BLOCK_SIZE );
            if (returnCode != Esc_NO_ERROR)
            {
                break;
            }
            numCharactersLeft -= BLOCK_SIZE;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintString( "Update failed! (1)\n" );
        }
        else
        {
            returnCode = EscSha256_Update( &ctx, (const Esc_UINT8*)A_BLOCK, numCharactersLeft );

            if (returnCode != Esc_NO_ERROR)
            {
                EscTst_PrintString( "Update failed! (2)\n" );
            }
            else
            {
                EscTst_PrintString( "Update success\n" );

                EscTst_PrintString( "Calling EscSha256_Finish()\n" );

                returnCode = EscSha256_Finish( &ctx, receivedDigest, digestLen );

                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    returnCode = EscTst_CheckStrings( digest,
                            (Esc_UINT32)digestLen,
                            receivedDigest,
                            (Esc_UINT32)digestLen );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_ComplianceTest(
    Esc_BOOL isSha224 )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 receivedDigest[EscSha256_DIGEST_LEN];
    const EscTstSha256_TestT* testCases;
    Esc_UINT32 digestLen;
    Esc_UINT8 numTests;
    const Esc_UINT8* msg;

    if (isSha224)
    {
        testCases = &EscTstSha224_FIPS_TESTS[0];
        digestLen = EscSha224_DIGEST_LEN;
        numTests = (Esc_UINT8)EscTstSha224_FIPS_TESTS_NUM;
    }
    else
    {
        testCases = &EscTstSha256_FIPS_TESTS[0];
        digestLen = EscSha256_DIGEST_LEN;
        numTests = (Esc_UINT8)EscTstSha256_FIPS_TESTS_NUM;
    }

    for (i = 0U; (i < numTests) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_ERROR result;

        EscTst_PrintString( "Testcase: " );
        EscTst_PrintString( testCases[i].title );
        EscTst_PrintString( "\n" );

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( testCases[i].msg );
        EscTst_PrintString( "\"\n" );

        EscTst_PrintString( "Calling EscSha256_Calc()\n" );
        if (testCases[i].msgLen == 0U)
        {
            /* Enforce NULL pointer with zero length */
            msg = Esc_NULL_PTR;
        }
        else
        {
            msg = (const Esc_UINT8*)testCases[i].msg;
        }

        result = EscSha256_Calc( isSha224, msg, testCases[i].msgLen, receivedDigest, (Esc_UINT8)digestLen );
        returnCode = EscTst_CheckResultSuccess( result );

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings(
                    testCases[i].digest,
                    digestLen,
                    receivedDigest,
                    digestLen );
        }
        else
        {
            returnCode = result;
        }

        EscTst_PrintString( "\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha256_TruncationTest(
    Esc_BOOL isSha224 )
{
    static const Esc_CHAR* msg = "abc";
    static const Esc_UINT8 digestLengthsSha224[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscSha224_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscSha224_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscSha224_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscSha224_DIGEST_LEN - 1U)
    };

    static const Esc_UINT8 digestLengthsSha256[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscSha256_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscSha256_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscSha256_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscSha256_DIGEST_LEN - 1U)
    };

    Esc_UINT32 numDigestLengths;
    const Esc_UINT8 *digestLengths;
    Esc_UINT8 maxDigestLength;

    Esc_UINT8 result[EscSha256_DIGEST_LEN];
    EscSha256_ContextT ctx;
    Esc_UINT8 digest[EscSha256_DIGEST_LEN];
    Esc_UINT8 zeroArray[EscSha256_DIGEST_LEN];
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;

    if (isSha224)
    {
        digestLengths = digestLengthsSha224;
        numDigestLengths = sizeof(digestLengthsSha224) / sizeof(digestLengthsSha224[0]);
        maxDigestLength = EscSha224_DIGEST_LEN;
        EscTst_PrintString( "SHA-224 Truncation test\n" );
    }
    else
    {
        digestLengths = digestLengthsSha256;
        numDigestLengths = sizeof(digestLengthsSha256) / sizeof(digestLengthsSha256[0]);
        maxDigestLength = EscSha256_DIGEST_LEN;
        EscTst_PrintString( "SHA-256 Truncation test\n" );
    }

    for (i = 0U; (i < numDigestLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 digestLength = digestLengths[i];

        for (j = 0U; j < EscSha256_DIGEST_LEN; j++)
        {
            digest[j] = 0U;
            zeroArray[j] = 0;
        }

        EscTst_PrintWord( "digestLength = ", digestLength );

        returnCode = EscSha256_Calc(isSha224, (const Esc_UINT8*)msg, EscTst_Strlen( msg ), result, maxDigestLength);

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( msg );
        EscTst_PrintString( "\"\n" );
        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscSha256_Init( isSha224, &ctx );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha256_Update( &ctx, (const Esc_UINT8*)msg,  EscTst_Strlen( msg ) );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscSha256_Finish( &ctx, digest, digestLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Compare results */
            EscTst_PrintArray( "Expected result", result, (Esc_UINT32)digestLength );
            EscTst_PrintArray( "Received result", digest, (Esc_UINT32)digestLength );
            if ( EscTst_Memcmp( digest, result, (Esc_UINT32)digestLength ) )
            {
                if ( EscTst_Memcmp( &digest[digestLength], &zeroArray[digestLength], (Esc_UINT32)maxDigestLength - (Esc_UINT32)digestLength ) )
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

static Esc_ERROR
EscTstSha256_RunTests(
    Esc_BOOL isSha224 )
{
    /* The test cases */
    static const EscTstSha256_TestModuleT EscTstSha256_TESTS[] =
    {
        {
    #if EscTst_ENABLE_LOGGING == 1
            "Empty message and FIPS-180-2 Appendix B and Change Compliance",
    #endif
            EscTstSha256_ComplianceTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "FIPS-180-2 Appendix B and Change Compliance",
    #endif
            EscTstSha256_FipsComplB3Tst
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "EscSha256_Init() parameters",
    #endif
            EscTstSha256_InitParamTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "EscSha256_Update() parameters",
    #endif
            EscTstSha256_UpdateParamTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "EscSha256_Finish() parameters",
    #endif
            EscTstSha256_FinishParamTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "EscSha256_Calc() parameters",
    #endif
            EscTstSha256_CalcParamTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "Calculation in two blocks",
    #endif
            EscTstSha256_BlockTest
        },
        {
    #if EscTst_ENABLE_LOGGING == 1
            "TruncationTest",
    #endif
            EscTstSha256_TruncationTest
        },
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    if (isSha224)
    {
        EscTst_PrintString( "Testing SHA-224\n\n" );
    }
    else
    {
        EscTst_PrintString( "Testing SHA-256\n\n" );
    }

    for (i = 0U; (i < EscTstSha256_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstSha256_TestFunctionsT TestFunction;

        EscTst_PrintString( "*** " );
        EscTst_PrintString( EscTstSha256_TESTS[i].name );
        EscTst_PrintString( " ***\n" );

        TestFunction = EscTstSha256_TESTS[i].TestFunction;
        returnCode = TestFunction( isSha224 );

        EscTst_PrintString( "\n" );
    }

    return returnCode;
}

Esc_ERROR
EscTstSha256_Perform(
    void )
{
    Esc_ERROR returnCode;

    returnCode = EscTstSha256_RunTests( TRUE );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha256_RunTests( FALSE );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
