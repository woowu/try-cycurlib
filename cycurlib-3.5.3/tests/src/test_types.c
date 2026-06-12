/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief Type definitions Selftest

   Checks the correct behaviour of the types defined in cycurlib_config.h.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_types.h"
#include "selftest.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

static Esc_ERROR
EscTstTypes_Uint8(
    void );

static Esc_ERROR
EscTstTypes_Sint8(
    void );

static Esc_ERROR
EscTstTypes_Uint16(
    void );

static Esc_ERROR
EscTstTypes_Sint16(
    void );

static Esc_ERROR
EscTstTypes_Uint32(
    void );

static Esc_ERROR
EscTstTypes_Sint32(
    void );

#if Esc_HAS_INT64 == 1
static Esc_ERROR
EscTstTypes_Uint64(
    void );

static Esc_ERROR
EscTstTypes_Sint64(
    void );

#endif

/** A test function */
typedef Esc_ERROR (
* EscTstTypes_TestFunctionsT )(
    void );

#define EscTstTypes_NUM_TESTS ( sizeof(EscTstTypes_TESTS) / sizeof(EscTstTypes_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if Esc_HAS_INT64 == 1
/* Esc_SINT64 */
static Esc_ERROR
EscTstTypes_Sint64(
    void )
{
    volatile Esc_SINT64 v64[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_SINT64\n" );
    EscTst_PrintString( "Calculating (0x3fffffffffffffff + 2) = -0x3fffffffffffffff to confirm it is a 64 bit value\n" );

    v64[0] = (Esc_SINT64)0x3fffffffffffffffLL;
    v64[0] += (Esc_SINT64)2LL;
    if (v64[0] == (Esc_SINT64)0x4000000000000001LL)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating 0x8000000000000002 / 2 = 0xC000000000000001 to confirm signed value\n" );

        v64[1] = (Esc_SINT64)0x8000000000000002ULL;
        v64[1] /= (Esc_SINT64)2LL;

        if (v64[1] == (Esc_SINT64)0xC000000000000001ULL)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_UINT64 */
static Esc_ERROR
EscTstTypes_Uint64(
    void )
{
    volatile Esc_UINT64 v64[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_UINT64\n" );
    EscTst_PrintString( "Calculating (0 - 1) = 0xffffffffffffffff to confirm it is a 16 bit value\n" );

    v64[0] = (Esc_UINT64)0ULL;
    v64[0]--;
    if (v64[0] == (Esc_UINT64)0xffffffffffffffffULL)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating 0x800000000001U / 2U = 0x400000000000U to confirm unsigned value\n" );

        v64[1] = (Esc_UINT64)0x800000000001ULL;
        v64[1] /= (Esc_UINT64)2ULL;

        if (v64[1] == (Esc_UINT64)0x400000000000ULL)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

#endif

/* Esc_SINT32 */
static Esc_ERROR
EscTstTypes_Sint32(
    void )
{
    volatile Esc_SINT32 v32[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_SINT32\n" );
    EscTst_PrintString( "Calculating (2147483647 + 2) = -2147483647 to confirm it is a 16 bit value\n" );

    v32[0] = (Esc_SINT32)2147483647L;
    v32[0] += (Esc_SINT32)2L;
    if (v32[0] == (Esc_SINT32) - 2147483647L)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating -2147483646 / 2 = -1073741824 to confirm signed value\n" );

        v32[1] = (Esc_SINT32) - 2147483646L;
        v32[1] /= (Esc_SINT32)2;

        if (v32[1] == (Esc_SINT32) - 1073741823L)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_UINT32 */
static Esc_ERROR
EscTstTypes_Uint32(
    void )
{
    volatile Esc_UINT32 v32[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_UINT32\n" );
    EscTst_PrintString( "Calculating (0 - 1) = 4294967295 to confirm it is a 32 bit value\n" );

    v32[0] = (Esc_UINT32)0UL;
    v32[0]--;
    if (v32[0] == (Esc_UINT32)4294967295UL)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating 0x80000001U / 2U = 0x40000000U to confirm unsigned value\n" );

        v32[1] = (Esc_UINT32)0x80000001UL;
        v32[1] /= (Esc_UINT32)2U;

        if (v32[1] == (Esc_UINT32)0x40000000UL)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_SINT16 */
static Esc_ERROR
EscTstTypes_Sint16(
    void )
{
    volatile Esc_SINT16 v16[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_SINT16\n" );
    EscTst_PrintString( "Calculating (32767 + 2) = -32767 to confirm it is a 16 bit value\n" );

    v16[0] = (Esc_SINT16)32767;
    v16[0] += (Esc_SINT16)2;
    if (v16[0] == (Esc_SINT16) - 32767)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating -32766 / 2 = -16383 to confirm signed value\n" );

        v16[1] = (Esc_SINT16) - 32766;
        v16[1] /= (Esc_SINT16)2;

        if (v16[1] == (Esc_SINT16) - 16383)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_UINT16 */
static Esc_ERROR
EscTstTypes_Uint16(
    void )
{
    volatile Esc_UINT16 v16[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_UINT16\n" );
    EscTst_PrintString( "Calculating (0 - 1) = 65535 to confirm it is a 16 bit value\n" );

    v16[0] = (Esc_UINT16)0U;
    v16[0]--;
    if (v16[0] == (Esc_UINT16)65535U)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating 0x8001U / 2U = 0x4000U to confirm unsigned value\n" );

        v16[1] = (Esc_UINT16)0x8001U;
        v16[1] /= (Esc_UINT16)2U;

        if (v16[1] == (Esc_UINT16)0x4000U)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_SINT8 */
static Esc_ERROR
EscTstTypes_Sint8(
    void )
{
    volatile Esc_SINT8 v8[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_SINT8\n" );
    EscTst_PrintString( "Calculating (127 + 2) = -127 to confirm it is a 8 bit value\n" );

    v8[0] = (Esc_SINT8)127;
    v8[0] += (Esc_SINT8)2;
    if (v8[0] == (Esc_SINT8) - 127)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating -126 / 2 = -63 to confirm signed value\n" );

        v8[1] = (Esc_SINT8) - 126;
        v8[1] /= (Esc_SINT8)2;

        if (v8[1] == (Esc_SINT8) - 63)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

/* Esc_UINT8 */
static Esc_ERROR
EscTstTypes_Uint8(
    void )
{
    volatile Esc_UINT8 v8[2];

    Esc_ERROR returnCode = Esc_TYPE_TEST_FAILED;
    EscTst_PrintString( "Testing Esc_UINT8\n" );
    EscTst_PrintString( "Calculating (0 - 1) = 255 to confirm it is a 8 bit value\n" );

    v8[0] = (Esc_UINT8)0U;
    v8[0]--;
    if (v8[0] == (Esc_UINT8)255U)
    {
        EscTst_PrintString( "Success\n\n" );
        EscTst_PrintString( "Calculating 0x81U / 2U = 0x40U to confirm unsigned value\n" );

        v8[1] = (Esc_UINT8)0x81U;
        v8[1] /= (Esc_UINT8)2U;

        if (v8[1] == (Esc_UINT8)0x40U)
        {
            EscTst_PrintString( "Success\n\n" );
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscTstTypes_Perform(
    void )
{
    /* The test cases */
    static const EscTstTypes_TestFunctionsT EscTstTypes_TESTS[] =
    {
        EscTstTypes_Uint8,
        EscTstTypes_Sint8,
        EscTstTypes_Uint16,
        EscTstTypes_Sint16,
        EscTstTypes_Uint32,
        EscTstTypes_Sint32,
#if Esc_HAS_INT64 == 1
        EscTstTypes_Uint64,
        EscTstTypes_Sint64,
#endif
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    EscTst_PrintString( "*******************************************************\n" );
#if Esc_HAS_INT64 == 1
    EscTst_PrintString( "Esc_HAS_INT64 is 1\n" );
#else
    EscTst_PrintString( "Esc_HAS_INT64 is 0\n" );
#endif

    for (i = 0U; (i < EscTstTypes_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstTypes_TestFunctionsT TestFunction;
        /* Perform test #i */
        TestFunction = EscTstTypes_TESTS[i];
        returnCode = TestFunction();
        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
        }
        EscTst_PrintString( "*******************************************************\n" );
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
