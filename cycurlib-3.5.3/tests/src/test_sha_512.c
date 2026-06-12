/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief SHA-384 and SHA-512 Selftest

   Checks pre-computed test patterns.

   \see Compliance test vectors from FIPS-180-2
   csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_sha_512.h"
#include "selftest.h"
#include "sha_512.h"

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
    Esc_UINT8 digest[EscSha512_DIGEST_LEN];
} EscTstSha512_FipsTestT;

/*
   Tests from FIPS-180-2. Appendix D.
   and self generated
 */
static const EscTstSha512_FipsTestT EscTstSha384_COMP_TESTS[] =
{
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Empty string",
#    endif
        "", 0U,
        {
            0x38U, 0xb0U, 0x60U, 0xa7U, 0x51U, 0xacU, 0x96U, 0x38U,
            0x4cU, 0xd9U, 0x32U, 0x7eU, 0xb1U, 0xb1U, 0xe3U, 0x6aU,
            0x21U, 0xfdU, 0xb7U, 0x11U, 0x14U, 0xbeU, 0x07U, 0x43U,
            0x4cU, 0x0cU, 0xc7U, 0xbfU, 0x63U, 0xf6U, 0xe1U, 0xdaU,
            0x27U, 0x4eU, 0xdeU, 0xbfU, 0xe7U, 0x6fU, 0x65U, 0xfbU,
            0xd5U, 0x1aU, 0xd2U, 0xf1U, 0x48U, 0x98U, 0xb9U, 0x5bU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "D.1",
#    endif
        "abc", 3U,
        {
            0xcbU, 0x00U, 0x75U, 0x3fU, 0x45U, 0xa3U, 0x5eU, 0x8bU,
            0xb5U, 0xa0U, 0x3dU, 0x69U, 0x9aU, 0xc6U, 0x50U, 0x07U,
            0x27U, 0x2cU, 0x32U, 0xabU, 0x0eU, 0xdeU, 0xd1U, 0x63U,
            0x1aU, 0x8bU, 0x60U, 0x5aU, 0x43U, 0xffU, 0x5bU, 0xedU,
            0x80U, 0x86U, 0x07U, 0x2bU, 0xa1U, 0xe7U, 0xccU, 0x23U,
            0x58U, 0xbaU, 0xecU, 0xa1U, 0x34U, 0xc8U, 0x25U, 0xa7U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "D.2",
#    endif
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        112U,
        {
            0x09U, 0x33U, 0x0cU, 0x33U, 0xf7U, 0x11U, 0x47U, 0xe8U,
            0x3dU, 0x19U, 0x2fU, 0xc7U, 0x82U, 0xcdU, 0x1bU, 0x47U,
            0x53U, 0x11U, 0x1bU, 0x17U, 0x3bU, 0x3bU, 0x05U, 0xd2U,
            0x2fU, 0xa0U, 0x80U, 0x86U, 0xe3U, 0xb0U, 0xf7U, 0x12U,
            0xfcU, 0xc7U, 0xc7U, 0x1aU, 0x55U, 0x7eU, 0x2dU, 0xb9U,
            0x66U, 0xc3U, 0xe9U, 0xfaU, 0x91U, 0x74U, 0x60U, 0x39U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 127 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        127U,
        {
            0x9bU, 0xd0U, 0x6bU, 0x17U, 0x63U, 0xc2U, 0xcfU, 0x7aU,
            0xefU, 0x40U, 0xe7U, 0x95U, 0xdcU, 0x65U, 0xbcU, 0x96U,
            0xd5U, 0x9cU, 0x41U, 0xb5U, 0x37U, 0xf3U, 0xadU, 0x72U,
            0xebU, 0xdeU, 0xfdU, 0x48U, 0x54U, 0x76U, 0xb5U, 0x71U,
            0x7cU, 0x1aU, 0xebU, 0x37U, 0xc3U, 0x27U, 0xfeU, 0x9cU,
            0x18U, 0x31U, 0xb1U, 0x2bU, 0x9eU, 0xfdU, 0x08U, 0xaeU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 128 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        128U,
        {
            0xedU, 0xb1U, 0x27U, 0x30U, 0xa3U, 0x66U, 0x09U, 0x8bU,
            0x3bU, 0x2bU, 0xeaU, 0xc7U, 0x5aU, 0x3bU, 0xefU, 0x1bU,
            0x09U, 0x69U, 0xb1U, 0x5cU, 0x48U, 0xe2U, 0x16U, 0x3cU,
            0x23U, 0xd9U, 0x69U, 0x94U, 0xf8U, 0xd1U, 0xbeU, 0xf7U,
            0x60U, 0xc7U, 0xe2U, 0x7fU, 0x3cU, 0x46U, 0x4dU, 0x38U,
            0x29U, 0xf5U, 0x6cU, 0x0dU, 0x53U, 0x80U, 0x8bU, 0x0bU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
};

/*
   Tests from FIPS-180-2. Appendix D.
   and self generated.
 */
static const EscTstSha512_FipsTestT EscTstSha512_COMP_TESTS[] =
{
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Empty string",
#    endif
        "", 0U,
        {
            0xcfU, 0x83U, 0xe1U, 0x35U, 0x7eU, 0xefU, 0xb8U, 0xbdU,
            0xf1U, 0x54U, 0x28U, 0x50U, 0xd6U, 0x6dU, 0x80U, 0x07U,
            0xd6U, 0x20U, 0xe4U, 0x05U, 0x0bU, 0x57U, 0x15U, 0xdcU,
            0x83U, 0xf4U, 0xa9U, 0x21U, 0xd3U, 0x6cU, 0xe9U, 0xceU,
            0x47U, 0xd0U, 0xd1U, 0x3cU, 0x5dU, 0x85U, 0xf2U, 0xb0U,
            0xffU, 0x83U, 0x18U, 0xd2U, 0x87U, 0x7eU, 0xecU, 0x2fU,
            0x63U, 0xb9U, 0x31U, 0xbdU, 0x47U, 0x41U, 0x7aU, 0x81U,
            0xa5U, 0x38U, 0x32U, 0x7aU, 0xf9U, 0x27U, 0xdaU, 0x3eU
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "C.1",
#    endif
        "abc", 3U,
        {
            0xddU, 0xafU, 0x35U, 0xa1U, 0x93U, 0x61U, 0x7aU, 0xbaU,
            0xccU, 0x41U, 0x73U, 0x49U, 0xaeU, 0x20U, 0x41U, 0x31U,
            0x12U, 0xe6U, 0xfaU, 0x4eU, 0x89U, 0xa9U, 0x7eU, 0xa2U,
            0x0aU, 0x9eU, 0xeeU, 0xe6U, 0x4bU, 0x55U, 0xd3U, 0x9aU,
            0x21U, 0x92U, 0x99U, 0x2aU, 0x27U, 0x4fU, 0xc1U, 0xa8U,
            0x36U, 0xbaU, 0x3cU, 0x23U, 0xa3U, 0xfeU, 0xebU, 0xbdU,
            0x45U, 0x4dU, 0x44U, 0x23U, 0x64U, 0x3cU, 0xe8U, 0x0eU,
            0x2aU, 0x9aU, 0xc9U, 0x4fU, 0xa5U, 0x4cU, 0xa4U, 0x9fU
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "C.2",
#    endif
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        112U,
        {
            0x8eU, 0x95U, 0x9bU, 0x75U, 0xdaU, 0xe3U, 0x13U, 0xdaU,
            0x8cU, 0xf4U, 0xf7U, 0x28U, 0x14U, 0xfcU, 0x14U, 0x3fU,
            0x8fU, 0x77U, 0x79U, 0xc6U, 0xebU, 0x9fU, 0x7fU, 0xa1U,
            0x72U, 0x99U, 0xaeU, 0xadU, 0xb6U, 0x88U, 0x90U, 0x18U,
            0x50U, 0x1dU, 0x28U, 0x9eU, 0x49U, 0x00U, 0xf7U, 0xe4U,
            0x33U, 0x1bU, 0x99U, 0xdeU, 0xc4U, 0xb5U, 0x43U, 0x3aU,
            0xc7U, 0xd3U, 0x29U, 0xeeU, 0xb6U, 0xddU, 0x26U, 0x54U,
            0x5eU, 0x96U, 0xe5U, 0x5bU, 0x87U, 0x4bU, 0xe9U, 0x09U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 127 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        127U,
        {
            0x82U, 0x86U, 0x13U, 0x96U, 0x8bU, 0x50U, 0x1dU, 0xc0U,
            0x0aU, 0x97U, 0xe0U, 0x8cU, 0x73U, 0xb1U, 0x18U, 0xaaU,
            0x88U, 0x76U, 0xc2U, 0x6bU, 0x8aU, 0xacU, 0x93U, 0xdfU,
            0x12U, 0x85U, 0x02U, 0xabU, 0x36U, 0x0fU, 0x91U, 0xbaU,
            0xb5U, 0x0aU, 0x51U, 0xe0U, 0x88U, 0x76U, 0x9aU, 0x5cU,
            0x1eU, 0xffU, 0x47U, 0x82U, 0xacU, 0xe1U, 0x47U, 0xdcU,
            0xe3U, 0x64U, 0x25U, 0x54U, 0x19U, 0x98U, 0x76U, 0x37U,
            0x42U, 0x91U, 0xf5U, 0xd9U, 0x21U, 0x62U, 0x95U, 0x02U
        }
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "Boundary Test: 128 times 'a'",
#    endif
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        128U,
        {
            0xb7U, 0x3dU, 0x19U, 0x29U, 0xaaU, 0x61U, 0x59U, 0x34U,
            0xe6U, 0x1aU, 0x87U, 0x15U, 0x96U, 0xb3U, 0xf3U, 0xb3U,
            0x33U, 0x59U, 0xf4U, 0x2bU, 0x81U, 0x75U, 0x60U, 0x2eU,
            0x89U, 0xf7U, 0xe0U, 0x6eU, 0x5fU, 0x65U, 0x8aU, 0x24U,
            0x36U, 0x67U, 0x80U, 0x7eU, 0xd3U, 0x00U, 0x31U, 0x4bU,
            0x95U, 0xcaU, 0xcdU, 0xd5U, 0x79U, 0xf3U, 0xe3U, 0x3aU,
            0xbdU, 0xfbU, 0xe3U, 0x51U, 0x90U, 0x95U, 0x19U, 0xa8U,
            0x46U, 0xd4U, 0x65U, 0xc5U, 0x95U, 0x82U, 0xf3U, 0x21U
        }
    }
};

/* Number of FIPS-180-2 compliance tests for SHA-384 */
#define EscTstSha384_NUM_FIPS_TESTS ( sizeof(EscTstSha384_COMP_TESTS) / sizeof(EscTstSha384_COMP_TESTS[0]) )

/* Number of FIPS-180-2 compliance tests for SHA-512 */
#define EscTstSha512_NUM_FIPS_TESTS ( sizeof(EscTstSha512_COMP_TESTS) / sizeof(EscTstSha512_COMP_TESTS[0]) )

typedef Esc_ERROR (
* EscTstSha512_TestFunctionsT )(
    Esc_BOOL isSha384 );

typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    const Esc_CHAR* name;
#endif
    EscTstSha512_TestFunctionsT TestFunction;
} EscTstSha512_TestModuleT;

static Esc_ERROR
EscTstSha512_ComplianceTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_FipsComplianceB3Test(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_CalcParamTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_InitParamTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_UpdateParamTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_FinishParamTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_BlockTest(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_RunTests(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstSha512_TruncationTest(
    Esc_BOOL isSha384 );

/* Number of test cases */
#define EscTstSha512_NUM_TESTS ( sizeof(EscTstSha512_TESTS) / sizeof(EscTstSha512_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscTstSha512_InitParamTest(
    Esc_BOOL isSha384 )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "ctx = 0\n" );
    returnCode = EscSha512_Init( isSha384, Esc_NULL_PTR );

    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    return returnCode;
}

static Esc_ERROR
EscTstSha512_UpdateParamTest(
    Esc_BOOL isSha384 )
{
    EscSha512_ContextT ctx;
    Esc_ERROR returnCode;
    const EscTstSha512_FipsTestT* testCase;

    if (isSha384)
    {
        testCase = &EscTstSha384_COMP_TESTS[0];
    }
    else
    {
        testCase = &EscTstSha512_COMP_TESTS[0];
    }

    EscTst_PrintString( "Initializing ctx\n" );
    returnCode = EscSha512_Init( isSha384, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "ctx=0\n" );

        returnCode = EscSha512_Update( Esc_NULL_PTR, (const Esc_UINT8*)testCase->msg, testCase->msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "data=0 and dataLen>0\n" );
            returnCode = EscSha512_Update( &ctx, Esc_NULL_PTR, 1U );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha512_FinishParamTest(
    Esc_BOOL isSha384 )
{
    EscSha512_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha512_DIGEST_LEN];
    Esc_ERROR returnCode;
    const EscTstSha512_FipsTestT* testCase;
    Esc_UINT8 digestLen;

    if (isSha384)
    {
        testCase = &EscTstSha384_COMP_TESTS[0];
        digestLen = (Esc_UINT8)(EscSha384_DIGEST_LEN);
    }
    else
    {
        testCase = &EscTstSha512_COMP_TESTS[0];
        digestLen = (Esc_UINT8)(EscSha512_DIGEST_LEN);
    }

    EscTst_PrintString( "Initializing ctx\n" );
    returnCode = EscSha512_Init( isSha384, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Updating with message\n" );

        returnCode = EscSha512_Update( &ctx, (const Esc_UINT8*)testCase->msg, testCase->msgLen );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "ctx=0\n" );
            returnCode = EscSha512_Finish( Esc_NULL_PTR, receivedDigest, digestLen );

            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "digest=0\n" );
                returnCode = EscSha512_Finish( &ctx, Esc_NULL_PTR, digestLen );

                if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "digestLength=0\n" );
                    returnCode = EscSha512_Finish( &ctx, receivedDigest, 0U );

                    if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                    {
                        EscTst_PrintString( "digestLength too large\n" );
                        returnCode = EscSha512_Finish( &ctx, receivedDigest, digestLen+1U );

                        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                    }
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha512_CalcParamTest(
    Esc_BOOL isSha384 )
{
    Esc_UINT8 receivedDigest[EscSha512_DIGEST_LEN];
    Esc_ERROR returnCode;
    const EscTstSha512_FipsTestT* testCase;

    if (isSha384)
    {
        testCase = &EscTstSha384_COMP_TESTS[0];
    }
    else
    {
        testCase = &EscTstSha512_COMP_TESTS[0];
    }

    EscTst_PrintString( "data=0 and dataLen>0\n" );
    returnCode = EscSha512_Calc( isSha384, Esc_NULL_PTR, 1U, receivedDigest, EscSha384_DIGEST_LEN );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "digest=0\n" );
        returnCode = EscSha512_Calc( isSha384, (const Esc_UINT8*)testCase->msg, testCase->msgLen, Esc_NULL_PTR, EscSha384_DIGEST_LEN );

        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha512_BlockTest(
    Esc_BOOL isSha384 )
{
    Esc_ERROR returnCode;
    EscSha512_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha512_DIGEST_LEN];
    const EscTstSha512_FipsTestT* testCase;
    Esc_UINT8 digestLen;

    if (isSha384)
    {
        testCase = &EscTstSha384_COMP_TESTS[1];
        digestLen = EscSha384_DIGEST_LEN;
    }
    else
    {
        testCase = &EscTstSha512_COMP_TESTS[1];
        digestLen = EscSha512_DIGEST_LEN;
    }

    EscTst_PrintString( "Testcase: " );
    EscTst_PrintString( testCase->title );
    EscTst_PrintString( "\n" );

    EscTst_PrintString( "Message: \"" );
    EscTst_PrintString( testCase->msg );
    EscTst_PrintString( "\"\n" );

    EscTst_PrintString( "Calling EscSha512_Init()\n" );
    returnCode = EscSha512_Init( isSha384, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscSha512_Update() with 1st byte of message\n" );

        returnCode = EscSha512_Update( &ctx, (const Esc_UINT8*)testCase->msg, 1U );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Calling EscSha512_Update() with remaining bytes of message\n" );

            returnCode = EscSha512_Update( &ctx,
                    (const Esc_UINT8*)&testCase->msg[1],
                    (testCase->msgLen - 1U) );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "Calling EscSha512_Finish()\n" );

                returnCode = EscSha512_Finish( &ctx, receivedDigest, digestLen );

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
EscTstSha512_FipsComplianceB3Test(
    Esc_BOOL isSha384 )
{
    /* Fips test D.3 */
    static const Esc_UINT8 EscTstSha384_COMP_TESTSD3_DIGEST[EscSha384_DIGEST_LEN] =
    {
        0x9dU, 0x0eU, 0x18U, 0x09U, 0x71U, 0x64U, 0x74U, 0xcbU,
        0x08U, 0x6eU, 0x83U, 0x4eU, 0x31U, 0x0aU, 0x4aU, 0x1cU,
        0xedU, 0x14U, 0x9eU, 0x9cU, 0x00U, 0xf2U, 0x48U, 0x52U,
        0x79U, 0x72U, 0xceU, 0xc5U, 0x70U, 0x4cU, 0x2aU, 0x5bU,
        0x07U, 0xb8U, 0xb3U, 0xdcU, 0x38U, 0xecU, 0xc4U, 0xebU,
        0xaeU, 0x97U, 0xddU, 0xd8U, 0x7fU, 0x3dU, 0x89U, 0x85U
    };

    /* Fips test C.3 */
    static const Esc_UINT8 EscTstSha512_COMP_TESTSD3_DIGEST[EscSha512_DIGEST_LEN] =
    {
        0xe7U, 0x18U, 0x48U, 0x3dU, 0x0cU, 0xe7U, 0x69U, 0x64U,
        0x4eU, 0x2eU, 0x42U, 0xc7U, 0xbcU, 0x15U, 0xb4U, 0x63U,
        0x8eU, 0x1fU, 0x98U, 0xb1U, 0x3bU, 0x20U, 0x44U, 0x28U,
        0x56U, 0x32U, 0xa8U, 0x03U, 0xafU, 0xa9U, 0x73U, 0xebU,
        0xdeU, 0x0fU, 0xf2U, 0x44U, 0x87U, 0x7eU, 0xa6U, 0x0aU,
        0x4cU, 0xb0U, 0x43U, 0x2cU, 0xe5U, 0x77U, 0xc3U, 0x1bU,
        0xebU, 0x00U, 0x9cU, 0x5cU, 0x2cU, 0x49U, 0xaaU, 0x2eU,
        0x4eU, 0xadU, 0xb2U, 0x17U, 0xadU, 0x8cU, 0xc0U, 0x9bU
    };

    Esc_ERROR returnCode;
    EscSha512_ContextT ctx;
    Esc_UINT8 receivedDigest[EscSha512_DIGEST_LEN];
    Esc_UINT32 numCharactersLeft = 1000000U;    /* 1 Million repetitions */
    static const Esc_CHAR A_BLOCK[18] = "aaaaaaaaaaaaaaaaa";
    static const Esc_UINT32 BLOCK_SIZE = 17U;

    const Esc_UINT8* digest;
    Esc_UINT8 digestLen;

    if (isSha384)
    {
        digest = &EscTstSha384_COMP_TESTSD3_DIGEST[0];
        digestLen = EscSha384_DIGEST_LEN;
    }
    else
    {
        digest = &EscTstSha512_COMP_TESTSD3_DIGEST[0];
        digestLen = EscSha512_DIGEST_LEN;
    }

    EscTst_PrintString( "1 Million repetitions of the character 'a' in 17 Byte blocks" );
    EscTst_PrintString( "Calling EscSha512_Init()\n" );
    returnCode = EscSha512_Init( isSha384, &ctx );

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Calling EscSha512_Update() multiple times\n" );

        while (numCharactersLeft > BLOCK_SIZE)
        {
            returnCode = EscSha512_Update( &ctx, (const Esc_UINT8*)A_BLOCK, BLOCK_SIZE );
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
            returnCode = EscSha512_Update( &ctx, (const Esc_UINT8*)A_BLOCK, numCharactersLeft );

            if (returnCode != Esc_NO_ERROR)
            {
                EscTst_PrintString( "Update failed! (2)\n" );
            }
            else
            {
                EscTst_PrintString( "Update success\n" );

                EscTst_PrintString( "Calling EscSha512_Finish()\n" );

                returnCode = EscSha512_Finish( &ctx, receivedDigest, digestLen );

                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    returnCode = EscTst_CheckStrings(
                            digest,
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
EscTstSha512_ComplianceTest(
    Esc_BOOL isSha384 )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 receivedDigest[EscSha512_DIGEST_LEN];

    const EscTstSha512_FipsTestT* testCases;
    Esc_UINT32 digestLen;
    Esc_UINT8 numTests;

    if (isSha384)
    {
        testCases = &EscTstSha384_COMP_TESTS[0];
        digestLen = EscSha384_DIGEST_LEN;
        numTests = (Esc_UINT8)EscTstSha384_NUM_FIPS_TESTS;
    }
    else
    {
        testCases = &EscTstSha512_COMP_TESTS[0];
        digestLen = EscSha512_DIGEST_LEN;
        numTests = (Esc_UINT8)EscTstSha512_NUM_FIPS_TESTS;
    }


    for (i = 0U; (i < numTests) && (returnCode == Esc_NO_ERROR); i++)
    {
        const Esc_UINT8* message;
        Esc_UINT32 msgLen;

        message = (const Esc_UINT8*)testCases[i].msg;
        msgLen = testCases[i].msgLen;
        if (msgLen == 0U)
        {
            message = Esc_NULL_PTR;
        }

        EscTst_PrintString( "Testcase: " );
        EscTst_PrintString( testCases[i].title );
        EscTst_PrintString( "\n" );

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( testCases[i].msg );
        EscTst_PrintString( "\"\n" );

        EscTst_PrintString( "Calling EscSha512_Calc()\n" );
        returnCode = EscSha512_Calc( isSha384, message, msgLen, receivedDigest, (Esc_UINT8)digestLen );

        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( testCases[i].digest,
                    digestLen, receivedDigest, digestLen );
        }

        EscTst_PrintString( "\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstSha512_TruncationTest(
    Esc_BOOL isSha384 )
{
    static const Esc_CHAR* msg = "abc";
    static const Esc_UINT8 digestLengthsSha384[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscSha384_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscSha384_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscSha384_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscSha384_DIGEST_LEN - 1U)
    };

    static const Esc_UINT8 digestLengthsSha512[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscSha512_DIGEST_LEN - 4U),
        (Esc_UINT8)(EscSha512_DIGEST_LEN - 3U),
        (Esc_UINT8)(EscSha512_DIGEST_LEN - 2U),
        (Esc_UINT8)(EscSha512_DIGEST_LEN - 1U)
    };

    Esc_UINT32 numDigestLengths;
    const Esc_UINT8 *digestLengths;
    Esc_UINT8 maxDigestLength;

    Esc_UINT8 result[EscSha512_DIGEST_LEN];
    EscSha512_ContextT ctx;
    Esc_UINT8 digest[EscSha512_DIGEST_LEN];
    Esc_UINT8 zeroArray[EscSha512_DIGEST_LEN];
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i, j;

    if (isSha384)
    {
        digestLengths = digestLengthsSha384;
        numDigestLengths = sizeof(digestLengthsSha384) / sizeof(digestLengthsSha384[0]);
        maxDigestLength = EscSha384_DIGEST_LEN;
        EscTst_PrintString( "SHA-384 Truncation test\n" );
    }
    else
    {
        digestLengths = digestLengthsSha512;
        numDigestLengths = sizeof(digestLengthsSha512) / sizeof(digestLengthsSha512[0]);
        maxDigestLength = EscSha512_DIGEST_LEN;
        EscTst_PrintString( "SHA-512 Truncation test\n" );
    }

    for (i = 0U; (i < numDigestLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 digestLength = digestLengths[i];

        EscTst_PrintWord( "digestLength = ", digestLength );

        for (j = 0U; j < EscSha512_DIGEST_LEN; j++)
        {
            digest[j] = 0U;
            zeroArray[j] = 0;
        }

        returnCode = EscSha512_Calc(isSha384, (const Esc_UINT8*)msg, EscTst_Strlen( msg ), result, maxDigestLength );

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( msg );
        EscTst_PrintString( "\"\n" );
        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscSha512_Init( isSha384, &ctx );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha512_Update( &ctx, (const Esc_UINT8*)msg,  EscTst_Strlen( msg ) );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscSha512_Finish( &ctx, digest, digestLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
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
EscTstSha512_RunTests(
    Esc_BOOL isSha384 )
{
    /* The test functions */
    static const EscTstSha512_TestModuleT EscTstSha512_TESTS[] =
    {
        {
#if EscTst_ENABLE_LOGGING == 1
            "Empty message and FIPS-180-2 Appendix C.1/D.1 and C.2/D.2 Compliance",
#endif
            EscTstSha512_ComplianceTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "FIPS-180-2 Appendix D, D.3 Compliance",
#endif
            EscTstSha512_FipsComplianceB3Test
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "EscSha512_Init() parameters",
#endif
            EscTstSha512_InitParamTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "EscSha512_Update() parameters",
#endif
            EscTstSha512_UpdateParamTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "EscSha512_Finish() parameters",
#endif
            EscTstSha512_FinishParamTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "EscSha512_Calc() parameters",
#endif
            EscTstSha512_CalcParamTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "Calculation in two blocks",
#endif
            EscTstSha512_BlockTest
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "TruncationTest",
#endif
            EscTstSha512_TruncationTest
        },
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    if (isSha384)
    {
        EscTst_PrintString( "Testing SHA-384\n\n" );
    }
    else
    {
        EscTst_PrintString( "Testing SHA-512\n\n" );
    }

    for (i = 0U; (i < EscTstSha512_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstSha512_TestFunctionsT TestFunction;

        EscTst_PrintString( "*** " );
        EscTst_PrintString( EscTstSha512_TESTS[i].name );
        EscTst_PrintString( " ***\n" );

        TestFunction = EscTstSha512_TESTS[i].TestFunction;
        returnCode = TestFunction( isSha384 );

        EscTst_PrintString( "\n" );
    }

    return returnCode;
}

Esc_ERROR
EscTstSha512_Perform(
    void )
{
    Esc_ERROR returnCode;

    returnCode = EscTstSha512_RunTests( TRUE );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstSha512_RunTests( FALSE );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
