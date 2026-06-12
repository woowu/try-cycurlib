/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DES3_CMAC Selftest.

   $Rev: 896 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_cmac_des3.h"
#include "selftest.h"
#include "cmac_des3.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscCmacDes3_NUMBER_OF_TESTS    7U
#define EscTstCmacDes3_MAX_DATALEN     32U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** CMAC test vector */
typedef struct
{
    Esc_UINT8 k1[EscDes_KEY_BYTES];
    Esc_UINT8 k2[EscDes_KEY_BYTES];
    Esc_UINT8 k3[EscDes_KEY_BYTES];
    Esc_UINT8 msg[EscTstCmacDes3_MAX_DATALEN];
    Esc_UINT32 msgLen;
    Esc_UINT8 mac[EscDes_BLOCK_BYTES];
} EscTstCmacDes3_testcaseT;

/* Test cases taken from NIST SP 800-38B */
static const EscTstCmacDes3_testcaseT cmac_test[] =
{
    {
        { /* k1 */
            0x8aU, 0xa8U, 0x3bU, 0xf8U, 0xcbU, 0xdaU, 0x10U, 0x62U
        },
        { /* k2 */
            0x0bU, 0xc1U, 0xbfU, 0x19U, 0xfbU, 0xb6U, 0xcdU, 0x58U
        },
        { /* k3 */
            0xbcU, 0x31U, 0x3dU, 0x4aU, 0x37U, 0x1cU, 0xa8U, 0xb5U
        },
        { /* msg */
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        0U, /* msgLen */
        { /* MAC */
            0xb7U, 0xa6U, 0x88U, 0xe1U, 0x22U, 0xffU, 0xafU, 0x95U
        }
    },
    {
        { /* k1 */
            0x8aU, 0xa8U, 0x3bU, 0xf8U, 0xcbU, 0xdaU, 0x10U, 0x62U
        },
        { /* k2 */
            0x0bU, 0xc1U, 0xbfU, 0x19U, 0xfbU, 0xb6U, 0xcdU, 0x58U
        },
        { /* k3 */
            0xbcU, 0x31U, 0x3dU, 0x4aU, 0x37U, 0x1cU, 0xa8U, 0xb5U
        },
        { /* msg */
            0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        8U, /* msgLen */
        { /* MAC */
            0x8eU, 0x8fU, 0x29U, 0x31U, 0x36U, 0x28U, 0x37U, 0x97U
        }
    },
    {
        { /* k1 */
            0x8aU, 0xa8U, 0x3bU, 0xf8U, 0xcbU, 0xdaU, 0x10U, 0x62U
        },
        { /* k2 */
            0x0bU, 0xc1U, 0xbfU, 0x19U, 0xfbU, 0xb6U, 0xcdU, 0x58U
        },
        { /* k3 */
            0xbcU, 0x31U, 0x3dU, 0x4aU, 0x37U, 0x1cU, 0xa8U, 0xb5U
        },
        { /* msg */
            0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
            0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
            0xaeU, 0x2dU, 0x8aU, 0x57U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        },
        20U, /* msgLen */
        { /* MAC */
            0x74U, 0x3dU, 0xdbU, 0xe0U, 0xceU, 0x2dU, 0xc2U, 0xedU
        }
    },
    {
        { /* k1 */
            0x8aU, 0xa8U, 0x3bU, 0xf8U, 0xcbU, 0xdaU, 0x10U, 0x62U
        },
        { /* k2 */
            0x0bU, 0xc1U, 0xbfU, 0x19U, 0xfbU, 0xb6U, 0xcdU, 0x58U
        },
        { /* k3 */
            0xbcU, 0x31U, 0x3dU, 0x4aU, 0x37U, 0x1cU, 0xa8U, 0xb5U
        },
        { /* msg */
            0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
            0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
            0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
            0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U
        },
        32U, /* msgLen */
        { /* MAC */
            0x33U, 0xe6U, 0xb1U, 0x09U, 0x24U, 0x00U, 0xeaU, 0xe5U
        }
    },
    {
        { /* k1 */
            0x07U, 0x8cU, 0x57U, 0xd6U, 0xdfU, 0x9bU, 0xa1U, 0xd5U
        },
        { /* k2 */
            0x08U, 0xd9U, 0x4aU, 0xc1U, 0xb3U, 0xd3U, 0xc1U, 0x83U
        },
        { /* k3 */
            0xe9U, 0x0bU, 0xf4U, 0xfeU, 0x79U, 0x73U, 0xc2U, 0xc7U
        },
        { /* msg */
            0x00U
        },
        0U, /* msgLen */
        { /* MAC,  */
            0x9aU, 0xf3U, 0xf0U, 0x1eU, 0x20U, 0xdcU, 0x7cU, 0x1eU
        }
    },
    {
        { /* k1 */
            0xf8U, 0x7cU, 0x4cU, 0x3dU, 0xf7U, 0x1fU, 0xd9U, 0x8cU
        },
        { /* k2 */
            0xe5U, 0x32U, 0xf4U, 0x1fU, 0xfeU, 0x31U, 0x58U, 0x20U
        },
        { /* k3 */
            0x51U, 0x4fU, 0xadU, 0x7cU, 0x7aU, 0xaeU, 0x2fU, 0x46U
        },
        { /* msg */
            0x00U
        },
        0U, /* msgLen */
        { /* MAC */
            0x19U, 0xfbU, 0xd3U, 0xdcU, 0x15U, 0x4bU, 0xc1U, 0x39U
        }
    },
    {
        { /* k1 */
            0x5dU, 0x26U, 0xd3U, 0x29U, 0xc1U, 0x13U, 0x07U, 0xdaU
        },
        { /* k2 */
            0xdcU, 0xecU, 0x70U, 0x32U, 0xbcU, 0x9eU, 0xa4U, 0xf2U
        },
        { /* k3 */
            0x5dU, 0x26U, 0xd3U, 0x29U, 0xc1U, 0x13U, 0x07U, 0xdaU
        },
        { /* msg */
            0x00U
        },
        0U, /* msgLen */
        { /* MAC */
            0xe8U, 0xa2U, 0x03U, 0xeeU, 0x66U, 0x41U, 0x04U, 0x19U
        }
    }
};

static Esc_ERROR
EscTstCmacDes3_InitParams(
    void );

static Esc_ERROR
EscTstCmacDes3_StartParams(void);

static Esc_ERROR
EscTstCmacDes3_UpdateParams(
    void );

static Esc_ERROR
EscTstCmacDes3_FinishParams(
    void );

static Esc_ERROR
EscTstCmacDes3_Compliance(
    void );

static Esc_ERROR
EscTstCmacDes3_CompBlockWise(
    void );

static Esc_ERROR
EscTstCmacDes3_CompRBlocks(
    void );

static Esc_ERROR
EscTestCmacDes3_CalcParams(
    void );

static Esc_ERROR
EscTestCmacDes3_TruncationTest(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacDes3_InitParams(
    void )
{
    Esc_ERROR returnCode;
    EscCmacDes3_ContextT ctx;

    const Esc_UINT8 *key1 = cmac_test[0].k1;
    const Esc_UINT8 *key2 = cmac_test[0].k2;
    const Esc_UINT8 *key3 = cmac_test[0].k3;

    EscTst_PrintString( "EscCmacDes3_Init parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacDes3_Init( &ctx, key1, key2, key3 );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacDes3_Init( Esc_NULL_PTR, key1, key2, key3 );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key1==0\n" );
        returnCode = EscCmacDes3_Init( &ctx, Esc_NULL_PTR, key2, key3);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key2==0\n" );
        returnCode = EscCmacDes3_Init( &ctx, key1, Esc_NULL_PTR, key3);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key3==0\n" );
        returnCode = EscCmacDes3_Init( &ctx, key1, key2, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacDes3_StartParams(void)
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "EscCmacDes3_Start parameter test\n" );

    EscTst_PrintString( "With ctx==0\n" );
    returnCode = EscCmacDes3_Start( Esc_NULL_PTR );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacDes3_UpdateParams(
    void )
{
    Esc_ERROR returnCode;
    EscCmacDes3_ContextT ctx;

    EscTst_PrintString( "EscCmacDes3_Update parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacDes3_Init( &ctx, cmac_test[0].k1, cmac_test[0].k2, cmac_test[0].k3 );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacDes3_Update( &ctx, cmac_test[0].msg, cmac_test[0].msgLen );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacDes3_Update( Esc_NULL_PTR, cmac_test[0].msg, cmac_test[0].msgLen );
        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With message==0 and messageLength>0\n" );
            returnCode = EscCmacDes3_Update( &ctx, Esc_NULL_PTR, 1U );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacDes3_FinishParams(
    void )
{
    Esc_ERROR returnCode;
    EscCmacDes3_ContextT ctx;
    Esc_UINT8 mac[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscCmacDes3_Finish parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacDes3_Init( &ctx, cmac_test[0].k1, cmac_test[0].k2, cmac_test[0].k3 );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacDes3_Update( &ctx, cmac_test[0].msg, cmac_test[0].msgLen );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacDes3_Finish( &ctx, mac, EscDes_BLOCK_BYTES );
    }

    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacDes3_Finish( Esc_NULL_PTR, mac, EscDes_BLOCK_BYTES );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With mac==0\n" );
        returnCode = EscCmacDes3_Finish( &ctx, Esc_NULL_PTR, EscDes_BLOCK_BYTES );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With macLength = 0\n" );
        returnCode = EscCmacDes3_Finish( &ctx, mac, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With macLength too large\n" );
        returnCode = EscCmacDes3_Finish( &ctx, mac, (Esc_UINT8)(EscCmacDes3_MAX_MAC_LENGTH + 1U) );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstCmacDes3_Compliance(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT8 calcMac[EscDes_BLOCK_BYTES];
    EscCmacDes3_ContextT ctx;

    for (i = 0U; (i < EscCmacDes3_NUMBER_OF_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "DES3-CMAC Compliance testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacDes3_Init()\n" );
        returnCode = EscCmacDes3_Init( &ctx, cmac_test[i].k1, cmac_test[i].k2, cmac_test[i].k3 );
        returnCode = EscTst_CheckResultSuccess( returnCode );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Update()\n" );
            returnCode = EscCmacDes3_Update( &ctx, cmac_test[i].msg, cmac_test[i].msgLen );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Finish()\n" );
            returnCode = EscCmacDes3_Finish( &ctx, calcMac, EscDes_BLOCK_BYTES );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscDes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[i].mac, EscDes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[i].mac, EscDes_BLOCK_BYTES ) )
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

        /* Repeat with Start() */

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Start()\n" );
            returnCode = EscCmacDes3_Start( &ctx );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Update()\n" );
            returnCode = EscCmacDes3_Update( &ctx, cmac_test[i].msg, cmac_test[i].msgLen );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Finish()\n" );
            returnCode = EscCmacDes3_Finish( &ctx, calcMac, EscDes_BLOCK_BYTES );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscDes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[i].mac, EscDes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[i].mac, EscDes_BLOCK_BYTES ) )
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

        /* One-shot function Calc() */

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Calc()\n" );

            returnCode = EscCmacDes3_Calc( cmac_test[i].k1, cmac_test[i].k2, cmac_test[i].k3, cmac_test[i].msg, cmac_test[i].msgLen, calcMac, EscDes_BLOCK_BYTES );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscDes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[i].mac, EscDes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[i].mac, EscDes_BLOCK_BYTES ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
    } /* end of loop */

    return returnCode;
}

static Esc_ERROR
EscTstCmacDes3_CompBlockWise(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i, j;
    Esc_UINT32 blocksize;
    Esc_UINT8 calcMac[EscDes_BLOCK_BYTES];
    EscCmacDes3_ContextT ctx;

    for (i = 0U; (i < EscCmacDes3_NUMBER_OF_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "DES3-CMAC Compliance - Blockwise - testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacDes3_Init()\n" );
        returnCode = EscCmacDes3_Init( &ctx, cmac_test[i].k1, cmac_test[i].k2, cmac_test[i].k3 );

        for (j = 0U; ( j < (cmac_test[i].msgLen) ) && (returnCode == Esc_NO_ERROR); j += EscDes_BLOCK_BYTES)
        {
            if ( (cmac_test[i].msgLen - j) < EscDes_BLOCK_BYTES )
            {
                blocksize = cmac_test[i].msgLen - j;
            }
            else
            {
                blocksize = EscDes_BLOCK_BYTES;
            }

            EscTst_PrintString( "EscCmacDes3_Update()\n" );

            /* Also call update with zero length before and after the actual update */

            returnCode = EscCmacDes3_Update( &ctx, Esc_NULL_PTR, 0U );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacDes3_Update( &ctx, &cmac_test[i].msg[j], blocksize );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacDes3_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Finish()\n" );
            returnCode = EscCmacDes3_Finish( &ctx, calcMac, EscDes_BLOCK_BYTES );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received MAC", calcMac, EscDes_BLOCK_BYTES );
                EscTst_PrintArray( "Expected MAC", cmac_test[i].mac, EscDes_BLOCK_BYTES );

                if ( EscTst_Memcmp( calcMac, cmac_test[i].mac, EscDes_BLOCK_BYTES ) )
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
    }

    return returnCode;
}

static Esc_ERROR
EscTstCmacDes3_CompRBlocks(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i, j;
    Esc_UINT32 blocksize;
    Esc_UINT32 bytesleft;
    Esc_UINT8 blocksizes[]  = { 0U, 3U, 5U, 7U, 10U };
    Esc_UINT8 calcMac[EscDes_BLOCK_BYTES];
    EscCmacDes3_ContextT ctx;

    for (i = 0U; (i < EscCmacDes3_NUMBER_OF_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "DES3-CMAC Compliance - Random Blocksize - testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacDes3_Init()\n" );
        returnCode = EscCmacDes3_Init( &ctx, cmac_test[i].k1, cmac_test[i].k2, cmac_test[i].k3 );

        bytesleft = cmac_test[i].msgLen;
        j = 0U;

        while ( (bytesleft > 0U) && (returnCode == Esc_NO_ERROR) )
        {
            if (j < (sizeof(blocksizes) / sizeof(blocksizes[0])))
            {
                /*lint -e{644} blocksizes is initialized at declaration */
                if (bytesleft < blocksizes[j])
                {
                    blocksize = bytesleft;
                }
                else
                {
                    blocksize = blocksizes[j];
                }
            }
            else
            {
                blocksize = bytesleft;
            }

            EscTst_PrintString( "EscCmacDes3_Update()\n" );
            returnCode = EscCmacDes3_Update( &ctx, &cmac_test[i].msg[cmac_test[i].msgLen - bytesleft], blocksize );

            bytesleft -= blocksize;
            j++;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacDes3_Finish()\n" );
            returnCode = EscCmacDes3_Finish( &ctx, calcMac, EscDes_BLOCK_BYTES );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received MAC", calcMac, EscDes_BLOCK_BYTES );
                EscTst_PrintArray( "Expected MAC", cmac_test[i].mac, EscDes_BLOCK_BYTES );

                if ( EscTst_Memcmp( calcMac, cmac_test[i].mac, EscDes_BLOCK_BYTES ) )
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
    }

    return returnCode;
}

static Esc_ERROR
EscTestCmacDes3_CalcParams(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 mac[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "EscCmacDes3_Calc() parameter test\n" );

    EscTst_PrintString( "With message==0 and messageLength>0\n" );
    returnCode = EscCmacDes3_Calc(
            cmac_test[0].k1, cmac_test[0].k2, cmac_test[0].k3, Esc_NULL_PTR, 1U, mac, EscDes_BLOCK_BYTES );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With k1==0\n" );
        returnCode = EscCmacDes3_Calc( Esc_NULL_PTR, cmac_test[0].k2, cmac_test[0].k3, cmac_test[0].msg, cmac_test[0].msgLen, mac, EscDes_BLOCK_BYTES );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "With k2==0\n" );
            returnCode = EscCmacDes3_Calc( cmac_test[0].k1, Esc_NULL_PTR, cmac_test[0].k3, cmac_test[0].msg, cmac_test[0].msgLen, mac, EscDes_BLOCK_BYTES );

            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "With k3==0\n" );
                returnCode = EscCmacDes3_Calc( cmac_test[0].k1, cmac_test[0].k2, Esc_NULL_PTR, cmac_test[0].msg, cmac_test[0].msgLen, mac, EscDes_BLOCK_BYTES );

                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTestCmacDes3_TruncationTest(
    void )
{
    const Esc_CHAR* msg = "Test With Truncation";
    static const Esc_UINT8 cmacLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscDes_BLOCK_BYTES - 4U),
        (Esc_UINT8)(EscDes_BLOCK_BYTES - 3U),
        (Esc_UINT8)(EscDes_BLOCK_BYTES - 2U),
        (Esc_UINT8)(EscDes_BLOCK_BYTES - 1U)
    };

    Esc_UINT32 numCmacLengths = sizeof(cmacLengths) / sizeof(cmacLengths[0]);

    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscCmacDes3_ContextT ctx;
    Esc_UINT8 mac_result[EscDes_BLOCK_BYTES];
    Esc_UINT8 mac[EscDes_BLOCK_BYTES];
    Esc_UINT8 i, j;
    Esc_UINT32 msgLen = EscTst_Strlen( msg );
    Esc_UINT8 zeroArray[EscDes_BLOCK_BYTES];

    EscTst_PrintString( "CMAC-3DES Truncation test\n" );

    for (i = 0U; (i < numCmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 cmacLength = cmacLengths[i];
        EscTst_PrintWord( "CMAC length = ", cmacLength);

        for ( j = 0U; j < EscDes_BLOCK_BYTES; j++)
        {
            zeroArray[j] = 0U;
            mac[j] = 0U;
        }

        returnCode = EscCmacDes3_Calc(
                cmac_test[0].k1,
                cmac_test[1].k2,
                cmac_test[2].k3,
                (const Esc_UINT8*)msg,
                msgLen,
                mac_result,
                (Esc_UINT8)EscDes_BLOCK_BYTES );

        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscCmacDes3_Init( &ctx, cmac_test[0].k1, cmac_test[1].k2, cmac_test[2].k3 );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscCmacDes3_Update( &ctx, (const Esc_UINT8*)msg, msgLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacDes3_Finish( &ctx, mac, cmacLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", mac, (Esc_UINT32)cmacLength );
            EscTst_PrintArray( "Received Result", mac_result, (Esc_UINT32)cmacLength );
            if ( EscTst_Memcmp( mac, mac_result, (Esc_UINT32)cmacLength ) )
            {
                if ( EscTst_Memcmp( &mac[cmacLength], &zeroArray[cmacLength], EscDes_BLOCK_BYTES - (Esc_UINT32)cmacLength ) )
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
EscTstCmacDes3_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstCmacDes3_InitParams();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_StartParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_UpdateParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_FinishParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_Compliance();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_CompBlockWise();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCmacDes3_CompRBlocks();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTestCmacDes3_CalcParams();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTestCmacDes3_TruncationTest();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
