/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief CRC-32 Selftest

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_crc_32.h"

#include "selftest.h"
#include "crc_32.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
#define NUMBER_OF_CRC_32_TESTCASES 17U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/* test-messages */
static const Esc_CHAR* const crc_msg[NUMBER_OF_CRC_32_TESTCASES] =
{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    /* Test Values acc. HIS specification */
    "1",
    "12",
    "123",
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789"
};

static Esc_ERROR
EscTstCrc32_Compliance(
    void );

static Esc_ERROR
EscTstCrc32_Parameters(
    void );

static Esc_ERROR
EscTstCrc32_InitCrc(
    Esc_UINT32* crc );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCrc32_Compliance(
    void )
{
    /* Expected results */
    static const Esc_UINT32 crc_res[NUMBER_OF_CRC_32_TESTCASES] =
    {
        0x0U,
        0xe8b7be43U,
        0x352441c2U,
        0x20159d7fU,
        0x4c2750bdU,
        0x171a3f5fU,
        0x1fc2e6d2U,
        0x7ca94a72U,
        /* Test Values acc. HIS specification */
        0x83dcefb7U,
        0x4f5344cdU,
        0x884863d2U,
        0x9be3e0a3U,
        0xcbf53a1cU,
        0x0972d361U,
        0x5003699fU,
        0x9ae0daafU,
        0xcbf43926U
    };

    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    EscTst_PrintString( "CRC Compliance test\n" );
    for (i = 0U; (i < NUMBER_OF_CRC_32_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT32 crc_result;

        returnCode = EscCrc32_Init( &crc_result );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Message: \"" );
            EscTst_PrintString( crc_msg[i] );
            EscTst_PrintString( "\"\n" );
            returnCode = EscCrc32_Compute( (const Esc_UINT8*)crc_msg[i], &crc_result, EscTst_Strlen( crc_msg[i] ) );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscCrc32_Finalize( &crc_result );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare results */
            EscTst_PrintWordHex( "Expected Result", crc_res[i] );
            EscTst_PrintWordHex( "Received Result", crc_result );
            if (crc_result == crc_res[i])
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
EscTstCrc32_InitCrc(
    Esc_UINT32* crc )
{
    Esc_ERROR returnCode;

    returnCode = EscCrc32_Init( crc );
    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintString( "Error: Init failed\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstCrc32_Parameters(
    void )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT32 crc;

    EscTst_PrintString( "Parameter test\n" );

    msg = (const Esc_UINT8*)crc_msg[3];
    msgLen = EscTst_Strlen( crc_msg[3] );

    EscTst_PrintString( "EscCrc32_Init(0)\n" );
    returnCode = EscCrc32_Init( Esc_NULL_PTR );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscCrc32_Compute with message==0\n" );
        returnCode = EscTstCrc32_InitCrc( &crc );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscCrc32_Compute( Esc_NULL_PTR, &crc, msgLen );

            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscCrc32_Compute with crc==0\n" );

                returnCode = EscCrc32_Compute( msg, Esc_NULL_PTR, msgLen );
                if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscCrc32_Compute with length==0\n" );
                    returnCode = EscCrc32_Compute( msg, &crc, 0U );
                    returnCode = EscTst_CheckResultSuccess( returnCode );
                }
            }
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscCrc32_Finalize with crc==0\n" );
        returnCode = EscCrc32_Finalize( Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }


    return returnCode;
}


Esc_ERROR
EscTstCrc32_Perform(
    void )
{
    Esc_ERROR returnCode = EscTstCrc32_Compliance();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstCrc32_Parameters();
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
