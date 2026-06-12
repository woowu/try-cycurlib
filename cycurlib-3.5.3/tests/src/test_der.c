/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DER encoding selftest

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_der.h"
#include "selftest.h"
#include "der.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Size of 0x05U, 0x00U */
#define NULL_CODE_LEN 2U /*except for this one*/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
static const Esc_UINT8 INTEGER_TEST_CODE[] = { 0x02U, 0x04U, 0x12U, 0x34U, 0x56U, 0x78U, 0x05U, 0x00U };

static Esc_ERROR
EscTstDer_Compliance(
    void );

static Esc_ERROR
EscTstDer_Init(
    EscDer_ContextT* ctx,
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLen );

static Esc_ERROR
EscTstDer_CheckNull(
    EscDer_ContextT* ctx );

static Esc_ERROR
EscTstDer_NextBoolean(
    void );

static Esc_ERROR
EscTstDer_NextInteger(
    void );

static Esc_ERROR
EscTstDer_NextIntegerBe(
    void );

static Esc_ERROR
EscTstDer_NextBitString(
    void );

static Esc_ERROR
EscTstDer_NextOctetString(
    void );

static Esc_ERROR
EscTstDer_NextIa5String(
    void );

static Esc_ERROR
EscTstDer_NextVisibleString(
    void );

static Esc_ERROR
EscTstDer_NextUTCTime(
    void );

static Esc_ERROR
EscTstDer_NextGeneralizedTime(
    void );

static Esc_ERROR
EscTstDer_NextAnyString1(
    void );

static Esc_ERROR
EscTstDer_NextAnyString2(
    void );

static Esc_ERROR
EscTstDer_NextSequenceElements(
    EscDer_ContextT* ctx );

static Esc_ERROR
EscTstDer_NextSequence(
    void );

static Esc_ERROR
EscTstDer_NextSet(
    void );

static Esc_ERROR
EscTstDer_Length(
    void );

static Esc_ERROR
EscTstDer_NextOid(
    void );

static Esc_ERROR
EscTstDer_NextOidCheck(
    void );

static Esc_ERROR
EscTstDer_NextOidRel(
    void );

static Esc_ERROR
EscTstDer_NextOidRelCheck(
    void );

static Esc_ERROR
EscTstDer_NexttaggedValue(
    void );

static Esc_ERROR
EscTstDer_NextPrintableString(
    void );

static Esc_ERROR
EscTstDer_LengthCheck(
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLength,
    Esc_UINT32 expectedLength );

typedef Esc_ERROR (
* EscTstDer_TestFunctionsT )(
    void );

#define EscTstDer_NUM_TESTS ( sizeof(EscTstDer_TESTS) / sizeof(EscTstDer_TESTS[0]) )

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscTstDer_Init(
    EscDer_ContextT* ctx,
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLen )
{
    Esc_ERROR returnCode;

    EscTst_PrintArray( "DER code", derCode, codeLen );

    returnCode = EscDer_Init( ctx, derCode, codeLen );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    return returnCode;
}

static Esc_ERROR
EscTstDer_CheckNull(
    EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "Checking for final null\n" );

    returnCode = EscDer_NextNull( ctx );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextBoolean(
    void )
{
    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    Esc_UINT8 boolVal;
    static const Esc_UINT8 derCode[] = { 0x01U, 0x01U, 0xFFU, 0x05U, 0x00U };

    EscTst_PrintString( "BOOLEAN test\n" );

    returnCode = EscTstDer_Init( &ctx, derCode, sizeof(derCode) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextBoolean( &ctx, &boolVal );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            if (EscTst_CheckWords( 0xffU, (Esc_UINT32)boolVal ) == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextIntegerBe(
    void )
{
    static const Esc_UINT8 VAL[] = { 0x12U, 0x34U, 0x56U, 0x78U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedBeVal;
    Esc_UINT32 valLen;

    EscTst_PrintString( "INTEGER test (big endian)\n" );

    returnCode = EscTstDer_Init( &ctx, INTEGER_TEST_CODE, sizeof(INTEGER_TEST_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextIntegerLongBe( &ctx, &receivedBeVal, &valLen );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( VAL, sizeof(VAL), receivedBeVal, valLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextInteger(
    void )
{
    const Esc_UINT32 INTVAL = 0x12345678U;

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    Esc_UINT32 val;

    EscTst_PrintString( "INTEGER test (Esc_UINT32)\n" );

    returnCode = EscTstDer_Init( &ctx, INTEGER_TEST_CODE, sizeof(INTEGER_TEST_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextInteger( &ctx, &val );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckWords( INTVAL, val );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextBitString(
    void )
{
    static const Esc_UINT8 BITSTRING_CODE[] = { 0x03U, 0x07U, 0x04U, 0x0aU, 0x3bU, 0x5fU, 0x29U, 0x1cU, 0xd0U, 0x05U, 0x00U };
    static const Esc_UINT8 BITSTRING_RESULT[] = { 0x0aU, 0x3bU, 0x5fU, 0x29U, 0x1cU, 0xd0U };
    const Esc_UINT32 NUM_BITS = 44U;

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 numBits;

    EscTst_PrintString( "BIT STRING test\n" );

    returnCode = EscTstDer_Init( &ctx, BITSTRING_CODE, sizeof(BITSTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextBitString( &ctx, &receivedVal, &numBits );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "Checking numBits\n" );
            returnCode = EscTst_CheckWords( NUM_BITS, numBits );
            if (returnCode == Esc_NO_ERROR)
            {
                Esc_UINT32 numBytes = (numBits + 7U) / 8U;

                EscTst_PrintString( "Checking content\n" );
                returnCode = EscTst_CheckStrings( BITSTRING_RESULT, sizeof(BITSTRING_RESULT), receivedVal, numBytes );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscTstDer_CheckNull( &ctx );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextOctetString(
    void )
{
    static const Esc_UINT8 OCTETSTRING_CODE[] = { 0x04U, 0x06U, 0x0aU, 0x3bU, 0x5fU, 0x29U, 0x1cU, 0xd0U, 0x05U, 0x00U };
    static const Esc_UINT8 OCTETSTRING_RESULT[] = { 0x0aU, 0x3bU, 0x5fU, 0x29U, 0x1cU, 0xd0U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "OCTET STRING test\n" );

    returnCode = EscTstDer_Init( &ctx, OCTETSTRING_CODE, sizeof(OCTETSTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOctetString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( OCTETSTRING_RESULT, sizeof(OCTETSTRING_RESULT), receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextIa5String(
    void )
{
    static const Esc_UINT8 IA5STRING_CODE[] = { 0x16U, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U, 0x05U, 0x00U };
    static const Esc_CHAR IA5STRING_RESULT[] = { 'J', 'o', 'n', 'e', 's' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "IA5String test\n" );

    returnCode = EscTstDer_Init( &ctx, IA5STRING_CODE, sizeof(IA5STRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextIa5String( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings(
                    (const Esc_UINT8*)IA5STRING_RESULT,
                    sizeof(IA5STRING_RESULT),
                    receivedVal,
                    lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextVisibleString(
    void )
{
    static const Esc_UINT8 VISIBLESTRING_CODE[] = { 0x1aU, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U, 0x05U, 0x00U };
    static const Esc_CHAR VISIBLESTRING_RESULT[] = { 'J', 'o', 'n', 'e', 's' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "VisibleString test\n" );

    returnCode = EscTstDer_Init( &ctx, VISIBLESTRING_CODE, sizeof(VISIBLESTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextVisibleString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings(
                    (const Esc_UINT8*)VISIBLESTRING_RESULT,
                    sizeof(VISIBLESTRING_RESULT),
                    receivedVal,
                    lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextPrintableString(
    void )
{
    static const Esc_UINT8 PRINTABLESTRING_CODE[] = { 0x13U, 0x02U, 0x44U, 0x45U, 0x05U, 0x00U };
    static const Esc_CHAR PRINTABLESTRING_RESULT[] = { 'D', 'E' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "PrintableString test\n" );

    returnCode = EscTstDer_Init( &ctx, PRINTABLESTRING_CODE, sizeof(PRINTABLESTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextPrintableString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings(
                    (const Esc_UINT8*)PRINTABLESTRING_RESULT,
                    sizeof(PRINTABLESTRING_RESULT),
                    receivedVal,
                    lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextAnyString2(
    void )
{
    static const Esc_UINT8 PRINTABLESTRING_CODE[] = { 0x13U, 0x02U, 0x44U, 0x45U, 0x05U, 0x00U };
    static const Esc_CHAR RESULT[] = { 'D', 'E' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "AnyString test on PrintableString\n" );

    returnCode = EscTstDer_Init( &ctx, PRINTABLESTRING_CODE, sizeof(PRINTABLESTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextAnyString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( (const Esc_UINT8*)RESULT, sizeof(RESULT), receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextAnyString1(
    void )
{
    static const Esc_UINT8 VISIBLESTRING_CODE[] = { 0x1aU, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U, 0x05U, 0x00U };
    static const Esc_UINT8 IA5STRING_CODE[] = { 0x16U, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U, 0x05U, 0x00U };
    static const Esc_CHAR RESULT[] = { 'J', 'o', 'n', 'e', 's' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "AnyString test on VisibleString\n" );

    returnCode = EscTstDer_Init( &ctx, VISIBLESTRING_CODE, sizeof(VISIBLESTRING_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextAnyString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( (const Esc_UINT8*)RESULT, sizeof(RESULT), receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString( "AnyString test on IA5String\n" );
                returnCode = EscTstDer_Init( &ctx, IA5STRING_CODE, sizeof(IA5STRING_CODE) );
                if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                {
                    returnCode = EscDer_NextAnyString( &ctx, &receivedVal, &lengthOfString );
                    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
                    {
                        returnCode = EscTst_CheckStrings( (const Esc_UINT8*)RESULT, sizeof(RESULT), receivedVal, lengthOfString );
                        if (returnCode == Esc_NO_ERROR)
                        {
                            returnCode = EscTstDer_CheckNull( &ctx );
                        }
                    }
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextUTCTime(
    void )
{
    static const Esc_UINT8 derCode[] =
    {
        0x17U, 0x0dU,
        0x30U, 0x36U, 0x31U, 0x32U, 0x31U, 0x35U, 0x32U, 0x30U, 0x35U, 0x32U, 0x32U, 0x32U, 0x5AU,
        0x05U, 0x00U
    };
    static const Esc_CHAR RESULT[] = { '0', '6', '1', '2', '1', '5', '2', '0', '5', '2', '2', '2', 'Z' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "UTCTime test\n" );

    returnCode = EscTstDer_Init( &ctx, derCode, sizeof(derCode) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextUtcTime( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( (const Esc_UINT8*)RESULT, sizeof(RESULT), receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextGeneralizedTime(
    void )
{
    /* No external test vector. So it might be incorrect. */
    static const Esc_UINT8 derCode[] =
    {
        0x18U, 0x0fU,
        0x32U, 0x30U, 0x30U, 0x36U, 0x31U, 0x32U, 0x31U, 0x35U, 0x32U, 0x30U, 0x35U, 0x32U, 0x32U, 0x32U, 0x5AU,
        0x05U, 0x00U
    };
    static const Esc_CHAR RESULT[] = { '2', '0', '0', '6', '1', '2', '1', '5', '2', '0', '5', '2', '2', '2', 'Z' };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "GeneralizedTime test\n" );

    returnCode = EscTstDer_Init( &ctx, derCode, sizeof(derCode) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextGeneralizedTime( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( (const Esc_UINT8*)RESULT, sizeof(RESULT), receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextSequenceElements(
    EscDer_ContextT* ctx )
{
    static const Esc_CHAR IA5STRING_RESULT[] = { 'J', 'o', 'n', 'e', 's' };

    Esc_ERROR returnCode;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintString( "Testing IA5String in sequence\n" );

    returnCode = EscDer_NextIa5String( ctx, &receivedVal, &lengthOfString );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscTst_CheckStrings(
                (const Esc_UINT8*)IA5STRING_RESULT,
                sizeof(IA5STRING_RESULT),
                receivedVal,
                lengthOfString );

        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT8 boolVal;

            EscTst_PrintString( "Testing Esc_BOOLEAN in sequence\n" );
            returnCode = EscDer_NextBoolean( ctx, &boolVal );
            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                returnCode = EscTst_CheckWords( 0xffU, (Esc_UINT32)boolVal );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextSequence(
    void )
{
    static const Esc_UINT8 SEQUENCE_CODE[] =
    {
        0x30U, 0x0aU,
        0x16U, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U,                                           /* IA5String "Jones" */
        0x01U, 0x01U, 0xffU,                                           /* boolean FF */
        0x05U, 0x00U
    };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    EscDer_ContextT sequence;

    EscTst_PrintString( "Sequence test\n" );

    returnCode = EscTstDer_Init( &ctx, SEQUENCE_CODE, sizeof(SEQUENCE_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSequence( &ctx, &sequence );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTstDer_NextSequenceElements( &sequence );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextSet(
    void )
{
    static const Esc_UINT8 SET_CODE[] =
    {
        0x31U, 0x04U,
        0x13U, 0x02U, 0x44U, 0x45U,                                   /* PrintableString "DE" */
        0x05U, 0x00U
    };
    static const Esc_UINT8 SET_RESULT[] = { 0x44U, 0x45U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    EscDer_ContextT set;

    EscTst_PrintString( "Set test\n" );

    returnCode = EscTstDer_Init( &ctx, SET_CODE, sizeof(SET_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSet( &ctx, &set );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            const Esc_UINT8* receivedVal;
            Esc_UINT32 lengthOfString;

            EscTst_PrintString( "Testing PrintableString in set\n" );

            returnCode = EscDer_NextPrintableString( &set, &receivedVal, &lengthOfString );

            if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
            {
                returnCode = EscTst_CheckStrings( SET_RESULT, sizeof(SET_RESULT), receivedVal, lengthOfString );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscTstDer_CheckNull( &ctx );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_LengthCheck(
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLength,
    Esc_UINT32 expectedLength )
{
    static const Esc_UINT8 RESULT_258[258] =
    {
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U
    };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    const Esc_UINT8* receivedVal;
    Esc_UINT32 lengthOfString;

    EscTst_PrintWord( "Test size", expectedLength );

    returnCode = EscTstDer_Init( &ctx, derCode, codeLength );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOctetString( &ctx, &receivedVal, &lengthOfString );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( RESULT_258, expectedLength, receivedVal, lengthOfString );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

/** Tests lengths > 126 */
static Esc_ERROR
EscTstDer_Length(
    void )
{
    static const Esc_UINT8 CODE_127[2U + 127U + NULL_CODE_LEN] =
    {
        0x04U, 0x7FU,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x05U, 0x00U
    };

    static const Esc_UINT8 CODE_130[3U + 130U + NULL_CODE_LEN] =
    {
        0x04U, 0x81U, 0x82U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U,
        0x05U, 0x00U
    };

    static const Esc_UINT8 CODE_258[4U + 258U + NULL_CODE_LEN] =
    {
        0x04U, 0x82U, 0x01U, 0x02U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U,
        0x05U, 0x00U
    };

    Esc_ERROR returnCode;

    EscTst_PrintString( "Length tests\n" );

    returnCode = EscTstDer_LengthCheck( CODE_127, sizeof(CODE_127), 127U );
    if (returnCode != Esc_NO_ERROR)
    {
        returnCode = EscTstDer_LengthCheck( CODE_130, sizeof(CODE_130), 130U );
        if (returnCode != Esc_NO_ERROR)
        {
            returnCode = EscTstDer_LengthCheck( CODE_258, sizeof(CODE_258), 258U );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextOid(
    void )
{
    static const Esc_UINT8 OID_CODE[] = { 0x06U, 0x03U, 0x81U, 0x34U, 0x03U, 0x05U, 0x00U };
    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    static const Esc_UINT32 IDENT_RESULT[2] = { (2U * 40U) + 100U, 3U };
    Esc_UINT32 identifiers[2];
    Esc_UINT32 numIdents;

    EscTst_PrintString( "OID test\n" );

    returnCode = EscTstDer_Init( &ctx, OID_CODE, sizeof(OID_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOid( &ctx, identifiers, 2U, &numIdents );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            Esc_UINT8 i;

            for (i = 0U; (i < 2U) && (returnCode == Esc_NO_ERROR); i++)
            {
                EscTst_PrintWord( "Subidentifier #", (Esc_UINT32)i );
                returnCode = EscTst_CheckWords( IDENT_RESULT[i], identifiers[i] );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextOidCheck(
    void )
{
    static const Esc_UINT8 OID_CODE[] =
    {
        0x06U, 0x03U, 0x81U, 0x34U, 0x03U,
        0x05U, 0x00U,
        0x06U, 0x03U, 0x81U, 0x34U, 0x04U
    };
    static const Esc_UINT32 IDENT_RESULT[3] = { 2U, 100U, 3U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;

    EscTst_PrintString( "OID check test\n" );

    returnCode = EscTstDer_Init( &ctx, OID_CODE, sizeof(OID_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOidCheck( &ctx, IDENT_RESULT, 3U );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            returnCode = EscTstDer_CheckNull( &ctx );
            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString( "OID check test (invalid OID)\n" );

                returnCode = EscDer_NextOidCheck( &ctx, IDENT_RESULT, 3U );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_OBJECT_IDENTIFIER );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextOidRel(
    void )
{
    static const Esc_UINT8 OID_CODE[] = { 0x0dU, 0x04U, 0xc2U, 0x7bU, 0x03U, 0x02U, 0x05U, 0x00U };
    static const Esc_UINT32 IDENT_RESULT[3] = { 8571U, 3U, 2U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    Esc_UINT32 identifiers[3];
    Esc_UINT32 numIdents;

    EscTst_PrintString( "RELATIVE OID test\n" );

    returnCode = EscTstDer_Init( &ctx, OID_CODE, sizeof(OID_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOidRel( &ctx, identifiers, 3U, &numIdents );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            Esc_UINT8 i;

            for (i = 0U; (i < 3U) && (returnCode == Esc_NO_ERROR); i++)
            {
                EscTst_PrintWord( "Subidentifier #", (Esc_UINT32)i );
                returnCode = EscTst_CheckWords( IDENT_RESULT[i], identifiers[i] );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NextOidRelCheck(
    void )
{
    static const Esc_UINT8 OID_CODE[] =
    {
        0x0dU, 0x04U, 0xc2U, 0x7bU, 0x03U, 0x02U,
        0x05U, 0x00U,
        0x0cU, 0x04U, 0xc2U, 0x7bU, 0x03U, 0x02U
    };
    static const Esc_UINT32 IDENT_RESULT[3] = { 8571U, 3U, 2U };

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;

    EscTst_PrintString( "RELATIVE OID check test\n" );

    returnCode = EscTstDer_Init( &ctx, OID_CODE, sizeof(OID_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextOidRelCheck( &ctx, IDENT_RESULT, 3U );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            if (EscTstDer_CheckNull( &ctx ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "OID check test (invalid OID)\n" );

                returnCode = EscDer_NextOidRelCheck( &ctx, IDENT_RESULT, 3U );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_PARSE_ERROR );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_NexttaggedValue(
    void )
{
    static const Esc_UINT8 TAGGED_CODE[] =
    {
        0xA1U, 0x0aU,
        0x16U, 0x05U, 0x4aU, 0x6fU, 0x6eU, 0x65U, 0x73U,                                     /* IA5String "Jones" */
        0x01U, 0x01U, 0xffU,                                     /* boolean FF */
        0x05U, 0x00U
    };
    const Esc_UINT32 TAG = 0x01U;

    Esc_ERROR returnCode;
    EscDer_ContextT ctx;
    EscDer_ContextT sequence;

    EscTst_PrintString( "Tagged value test\n" );

    returnCode = EscTstDer_Init( &ctx, TAGGED_CODE, sizeof(TAGGED_CODE) );
    if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextTaggedValue( &ctx, TAG, &sequence );
        if (EscTst_CheckResultSuccess( returnCode ) == Esc_NO_ERROR)
        {
            if (EscTstDer_NextSequenceElements( &sequence ) == Esc_NO_ERROR)
            {
                returnCode = EscTstDer_CheckNull( &ctx );
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDer_Compliance(
    void )
{
    /* The test cases */
    static const EscTstDer_TestFunctionsT EscTstDer_TESTS[] =
    {
        EscTstDer_NextBoolean,
        EscTstDer_NextIntegerBe,
        EscTstDer_NextInteger,
        EscTstDer_NextBitString,
        EscTstDer_NextOctetString,
        EscTstDer_NextIa5String,
        EscTstDer_NextVisibleString,
        EscTstDer_NextPrintableString,
        EscTstDer_NextAnyString1,
        EscTstDer_NextAnyString2,
        EscTstDer_NextUTCTime,
        EscTstDer_NextGeneralizedTime,
        EscTstDer_NextSequence,
        EscTstDer_NextSet,
        EscTstDer_Length,
        EscTstDer_NextOid,
        EscTstDer_NextOidCheck,
        EscTstDer_NextOidRel,
        EscTstDer_NextOidRelCheck,
        EscTstDer_NexttaggedValue
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    for (i = 0U; (i < EscTstDer_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstDer_TestFunctionsT TestFunction;
        /* Perform test #i */
        TestFunction = EscTstDer_TESTS[i];
        returnCode = TestFunction();
        EscTst_PrintString( "\n\n\n" );
    }

    return returnCode;
}

Esc_ERROR
EscTstDer_Perform(
    void )
{
    return EscTstDer_Compliance();
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
