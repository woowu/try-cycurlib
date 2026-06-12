/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DER encoding rules according to ISO8825-1:2003
   Only primitives can be decoded, no constructed values yet.

   $Rev: 3832 $
 */
/***************************************************************************/

/*
   We define a EscDer_ContextT, which is just an Esc_UINT8 string, with access functions
   to detect an overflow.

   Additionally, we have a DER_Element which consist of the contents and
   header information. In this way, it is possible to read and skip an element
   without knowing what is inside. As the contents is another context, it is
   possible to "enter" an element, as necessary for SEQUENCE encodings.
 */

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "der.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/* Identifier classes according to ISO8825-1:2003 8.1.2.2 */
/** Masks out the identifier bits */
#define DER_CLASS_MASK 0xc0U

/** Indicates that identifier is constructed */
#define DER_IDENT_CONSTRUCTED 0x20U

/** Masks out the primitive tag bytes */
#define DER_TAG_MASK 0x1fU

/* Tags */
#define DER_TAG_BIT_STRING 0x03U    /* String of zero or more bits */
#define DER_TAG_OCTET_STRING 0x04U  /* String of zero or more bytes */
#define DER_TAG_NULL 0x05U      /* Has one value: NULL  */
#define DER_TAG_OBJECT_IDENTIFIER 0x06U /* Unique string of numbers associated with an object   */
#define DER_TAG_OBJECT_IDENTIFIER_REL 0x0DU /* relative object identifier */
#define DER_TAG_SEQUENCE 0x10U  /* SEQUENCE OF, either an ordered list of values, one for each type in the SEQUENCE, or an ordered list of zero or more values of a particular type, for SEQUENCE OF    */
#define DER_TAG_SET 0x11U       /* SET OF, unordered list of values, one for each type in the SET, or an unordered list of zero or more values of a particular type, for SET OF    */
#define DER_TAG_UTF8String 0x0CU    /* UTF8 string */
#define DER_TAG_PrintableString 0x13U   /* A-Za-z0-9 space '()+,-./:=?  */
#define DER_TAG_TeletexString 0x14U /* TeletexString */
#define DER_TAG_IA5String 0x16U /* IA5 String */
#define DER_TAG_VisibleString 0x1AU /* Visible string */
#define DER_TAG_UniversalString 0x1CU /* UniversalString */
#define DER_TAG_BmpString 0x1EU /* BMPString */

/* The UTCTime and GeneralizedTime Tags are also used in other modules, so we define them in der.h */

/** Number of fixed OID components. An OID has at least two components. */
#define DER_OID_MIN_COMPONENTS_NUM 2U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
/** Describes one element in the DER context. */
typedef struct
{
    /* context data */
    /** This context is associated with the content */
    EscDer_ContextT contents;

    /* Identifier members */
    /** Tag of this element */
    Esc_UINT32 tag;
    /** Esc_UINT32 Class of the element */
    Esc_UINT8 elemClass;
    /** Is TRUE, if element is constructed */
    Esc_BOOL isConstructed;
} DER_Element;

static const Esc_UINT8*
EscDerCtx_GetCurrentCode(
    const EscDer_ContextT* ctx );

static Esc_UINT32
EscDerCtx_GetLength(
    const EscDer_ContextT* ctx );

static Esc_ERROR
EscDerCtx_GetNextByte(
    EscDer_ContextT* ctx,
    Esc_UINT8* outVal );

static Esc_ERROR
EscDerCtx_SkipBytes(
    EscDer_ContextT* ctx,
    Esc_UINT32 numBytes );

static void
EscDerCtx_Clone(
    const EscDer_ContextT* ctx,
    EscDer_ContextT* newCtx );

static Esc_ERROR
EscDerElem_ReadCtxCheck(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag,
    Esc_UINT8 cla,
    Esc_BOOL isConstr );

static Esc_ERROR
EscDerElem_ReadCtxCheck_UP(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag );

static Esc_ERROR
EscDerElem_ReadCtxCheck_UC(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag );

static Esc_ERROR
EscDerElem_ReadFromCtx(
    DER_Element* elem,
    EscDer_ContextT* ctx );

static Esc_ERROR
EscDerElem_ReadLength(
    EscDer_ContextT* ctx,
    Esc_UINT32* outLen );

static Esc_ERROR
EscDerElem_ReadIdentifier(
    DER_Element* elem,
    EscDer_ContextT* ctx );

static Esc_ERROR
EscDerElem_NGO(
    EscDer_ContextT* ctx,
    const Esc_UINT8* octString[],
    Esc_UINT32* StrL,
    Esc_UINT32 tag );

static Esc_ERROR
EscDerElem_OidCheckFirst(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents );

static Esc_ERROR
EscDerElem_OidCheckRemaining(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents );

static Esc_ERROR
EscDerElem_NextOidSubident(
    EscDer_ContextT* ctx,
    Esc_UINT32* subIdentifier );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/***************************************************************************
 Primitives for context operations. No other operations shall access the
 EscDer_ContextT members directly
 ***************************************************************************/

/**
Returns a pointer to the current DER code to read or 0, if none is available
*/
static const Esc_UINT8*
EscDerCtx_GetCurrentCode(
    const EscDer_ContextT* ctx )
{
    Esc_UINT32 pos = ctx->currentPos;
    const Esc_UINT8* derCode;

    if (pos < ctx->len)
    {
        derCode = &ctx->derCode[pos];
    }
    else
    {
        derCode = Esc_NULL_PTR;
    }

    return derCode;
}

/**
Encapsulates the length attribute
*/
static Esc_UINT32
EscDerCtx_GetLength(
    const EscDer_ContextT* ctx )
{
    Esc_UINT32 l;
    l = ctx->len;
    return l;
}

/**
Skips the specified number of bytes in the context.
*/
static Esc_ERROR
EscDerCtx_SkipBytes(
    EscDer_ContextT* ctx,
    Esc_UINT32 numBytes )
{
    Esc_ERROR returnCode = Esc_READ_BEYOND_END;
    Esc_UINT32 pos;

    pos = ctx->currentPos + numBytes;

    if (pos <= ctx->len)
    {
        ctx->currentPos = pos;
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
Reads one byte from the current position in the context
and advances the position by one.
The functions is stable against reading too many bytes
\param[out] outVal Will contain the next byte
*/
static Esc_ERROR
EscDerCtx_GetNextByte(
    EscDer_ContextT* ctx,
    Esc_UINT8* outVal )
{
    Esc_ERROR returnCode = Esc_READ_BEYOND_END;
    const Esc_UINT8* currentCode;

    currentCode = EscDerCtx_GetCurrentCode( ctx );
    if (currentCode != Esc_NULL_PTR)
    {
        *outVal = *currentCode;
        returnCode = EscDerCtx_SkipBytes( ctx, 1U );
    }

    return returnCode;
}

/**
Creates a exact copy of ctx.

\param[out] The newly created context.
*/
static void
EscDerCtx_Clone(
    const EscDer_ContextT* ctx,
    EscDer_ContextT* newCtx )
{
    newCtx->derCode = ctx->derCode;
    newCtx->len = ctx->len;
    newCtx->currentPos = ctx->currentPos;
}

/***************************************************************************
 Primitives for element operations.
 ***************************************************************************/

/**
 * Reads the next byte from the context and checks the class and tag.
 * After the function call, the context points to the length.
 * Only internally used by the der_elem_* functions.
 * \see Sec. 8.1.2
 */
static Esc_ERROR
EscDerElem_ReadIdentifier(
    DER_Element* elem,
    EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode;
    Esc_UINT8 identByte;

    returnCode = EscDerCtx_GetNextByte( ctx, &identByte );
    if (returnCode == Esc_NO_ERROR)
    {
        /* Class of the identifier */
        elem->elemClass = identByte & DER_CLASS_MASK;

        /* Check if it primitive or constructed ? */
        if ( (identByte & DER_IDENT_CONSTRUCTED) == DER_IDENT_CONSTRUCTED )
        {
            elem->isConstructed = TRUE;
        }
        else
        {
            elem->isConstructed = FALSE;
        }

        /* Tag */
        elem->tag = ( (Esc_UINT32)identByte ) & DER_TAG_MASK;

        /* Check if tag is smaller or equal 30. 31 and bigger is not supported */
        if (elem->tag != 0x1fU)
        {
            returnCode = Esc_NO_ERROR;
        }
        else
        {
            returnCode = Esc_UNSUPPORTED_TAG;
        }
    }

    return returnCode;
}

/**
 * Fills in the length for up to 32 bit.
 * After the function call, the context points to the contents.
 * Only internally used by the EscDerElem_* functions.
 * \param[out] outLen Will contain the resulting length.
 */
static Esc_ERROR
EscDerElem_ReadLength(
    EscDer_ContextT* ctx,
    Esc_UINT32* outLen )
{
    const Esc_UINT8 IS_LONG_FORM = 0x80U;   /* sec. 8.1.3.5 */
    const Esc_UINT8 IS_INDEFINITE_LENGTH = 0x80U;   /* sec. 8.1.3.6 */
    const Esc_UINT8 LEN_MASK = 0x7fU;

    Esc_ERROR returnCode;
    Esc_UINT8 lenByte;

    returnCode = EscDerCtx_GetNextByte( ctx, &lenByte );

    if (returnCode == Esc_NO_ERROR)
    {
        if ( (lenByte & IS_LONG_FORM) == 0U )
        {
            /* Short form (sec. 8.1.3.4) */
            Esc_UINT8 l;
            l = lenByte & LEN_MASK;
            *outLen = (Esc_UINT32)l;
        }
        else if (lenByte == IS_INDEFINITE_LENGTH)
        {
            /* indefinite form (sec. 8.1.3.6) */
            returnCode = Esc_PARSE_ERROR;
        }
        else
        {
            /* long form (sec. 8.1.3.5) */
            Esc_UINT8 i;
            Esc_UINT32 len = 0x00U;
            Esc_UINT8 lenSize;      /* size of the length in byte */
            lenSize = lenByte & LEN_MASK;

            if (lenSize > 4U)
            {
                returnCode = Esc_PARSE_ERROR;
            }

            /* assemble the length bytes */
            for (i = 0U; (i < lenSize) && (returnCode == Esc_NO_ERROR); i++)
            {
                returnCode = EscDerCtx_GetNextByte( ctx, &lenByte );
                len <<= 8;
                len |= (Esc_UINT32)lenByte;
            }

            *outLen = len;
        }
    }

    return returnCode;
}

/**
Reads the next element from the context. Advancing the context to the
start of the next element.
\param[out] elem Will be filled with information about the next Element
*/
static Esc_ERROR
EscDerElem_ReadFromCtx(
    DER_Element* elem,
    EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode;
    Esc_UINT32 len = 0U;

    returnCode = EscDerElem_ReadIdentifier( elem, ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDerElem_ReadLength( ctx, &len );
        if (returnCode == Esc_NO_ERROR)
        {
            const Esc_UINT8* cont;

            /* create a new context for this element */
            cont = EscDerCtx_GetCurrentCode( ctx );
            returnCode = EscDer_Init( &elem->contents, cont, len );
            if (returnCode == Esc_NO_ERROR)
            {
                /* Advance context pointer to the start of the next element,
                   functions fails if not enough bytes are left */
                returnCode = EscDerCtx_SkipBytes( ctx, len );
            }
        }
    }

    return returnCode;
}

/**
Reads the next element from the context. Advancing the context to the
start of the next element.
Checks will be performed for tag, class and is constructed flag.
\param[out] elem Will be filled with information about the next Element
*/
static Esc_ERROR
EscDerElem_ReadCtxCheck(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag,
    Esc_UINT8 cla,
    Esc_BOOL isConstr )
{
    Esc_ERROR returnCode;

    returnCode = EscDerElem_ReadFromCtx( elem, ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        if ( (elem->elemClass != cla) ||
             (elem->isConstructed != isConstr) ||
             (elem->tag != identTag) )
        {
            returnCode = Esc_PARSE_ERROR;
        }
    }

    return returnCode;
}

/**
Reads the next element from the context. Advancing the context to the
start of the next element.
Checks will be performed if identifier is of class UNIVERSAL and
primitive.
\param[out] elem Will be filled with information about the next Element
*/
static Esc_ERROR
EscDerElem_ReadCtxCheck_UP(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag )
{
    return EscDerElem_ReadCtxCheck( elem, ctx, identTag, DER_CLASS_UNIVERSAL, FALSE );
}

/**
Reads the next element from the context. Advancing the context to the
start of the next element.
Checks will be performed if identifier is of class UNIVERSAL and
constructed.
\param[out] elem Will be filled with information about the next Element
*/
static Esc_ERROR
EscDerElem_ReadCtxCheck_UC(
    DER_Element* elem,
    EscDer_ContextT* ctx,
    Esc_UINT32 identTag )
{
    return EscDerElem_ReadCtxCheck( elem, ctx, identTag, DER_CLASS_UNIVERSAL, TRUE );
}

/***************************************************************************
 Helper functions
 ***************************************************************************/

/**
Reads a generic octetstring with the specified tag.
The class is assumed UNIVERSAL.
The function also checks command line parameters.
*/
static Esc_ERROR
EscDerElem_NGO(
    EscDer_ContextT* ctx,
    const Esc_UINT8* octString[],
    Esc_UINT32* StrL,
    Esc_UINT32 tag )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (octString != Esc_NULL_PTR) && (StrL != Esc_NULL_PTR) )
    {
        DER_Element el;
        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, tag );

        if (returnCode == Esc_NO_ERROR)
        {
            *octString = EscDerCtx_GetCurrentCode( &el.contents );
            *StrL = EscDerCtx_GetLength( &el.contents );
        }
    }

    return returnCode;
}

/**
Reads OID subidentifiers up to 28 bit
according to sec. 8.19.2
*/
static Esc_ERROR
EscDerElem_NextOidSubident(
    EscDer_ContextT* ctx,
    Esc_UINT32* subIdentifier )
{
    const Esc_UINT8 HAS_MORE_BITS = 0x80U;
    const Esc_UINT8 BIT_MASK = 0x7fU;

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 ident = 0U;
    Esc_UINT8 i;
    Esc_UINT8 lenByte = HAS_MORE_BITS;

    for (i = 0U; (i < 4U) && ( (lenByte & HAS_MORE_BITS) == HAS_MORE_BITS ) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscDerCtx_GetNextByte( ctx, &lenByte );

        if (returnCode == Esc_NO_ERROR)
        {
            /* add the length bits to the resulting length */
            Esc_UINT8 l;
            l = lenByte & BIT_MASK;
            ident <<= 7;
            ident |= (Esc_UINT32)l;
        }
    }

    /** Identifier is longer than 28 bit */
    if ( (lenByte & HAS_MORE_BITS) == HAS_MORE_BITS )
    {
        returnCode = Esc_PARSE_ERROR;
    }

    *subIdentifier = ident;

    return returnCode;
}

/**
Check first oid subidentifier
*/
static Esc_ERROR
EscDerElem_OidCheckFirst(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents )
{
    Esc_ERROR returnCode = Esc_PARSE_ERROR;

    if (numComponents >= DER_OID_MIN_COMPONENTS_NUM)
    {
        Esc_UINT32 expectedSubidentifier;
        Esc_UINT32 readSubidentifier = 0U;

        /* calculate subidentifier according to sec. 8.19.4 */
        expectedSubidentifier = (oidComponents[0] * 40U) + oidComponents[1];
        returnCode = EscDerElem_NextOidSubident( ctx, &readSubidentifier );

        if (returnCode == Esc_NO_ERROR)
        {
            if (readSubidentifier != expectedSubidentifier)
            {
                returnCode = Esc_INVALID_OBJECT_IDENTIFIER;
            }
        }
    }

    return returnCode;
}

/**
Check remaining OID subidentifiers
*/
static Esc_ERROR
EscDerElem_OidCheckRemaining(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT32 currentOidComp;

    /* we read component by component and compare */
    for (i = 0U; (i < numComponents) && (returnCode == Esc_NO_ERROR); i++)
    {
        if (EscDer_HasMoreBytes( ctx ) == FALSE)
        {
            returnCode = Esc_READ_BEYOND_END;
        }
        else
        {
            returnCode = EscDerElem_NextOidSubident( ctx, &currentOidComp );
            if (returnCode == Esc_NO_ERROR)
            {
                if (currentOidComp != oidComponents[i])
                {
                    returnCode = Esc_INVALID_OBJECT_IDENTIFIER;
                }
            }
        }
    }

    return returnCode;
}

/***************************************************************************
 Exported functions
 ***************************************************************************/
Esc_ERROR
EscDer_Init(
    EscDer_ContextT* ctx,
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLen )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        ctx->currentPos = 0U;

        if ( (codeLen > 0U) && (derCode != Esc_NULL_PTR) )
        {
            ctx->derCode = derCode;
            ctx->len = codeLen;
        }
        else
        {
            ctx->derCode = Esc_NULL_PTR;
            ctx->len = 0U;
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextBoolean(
    EscDer_ContextT* ctx,
    Esc_UINT8* boolVal )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (boolVal != Esc_NULL_PTR) )
    {
        DER_Element el;
        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_BOOLEAN );
        if (returnCode == Esc_NO_ERROR)
        {
            /* Only the length 1 is allowed */
            if (EscDerCtx_GetLength( &el.contents ) == 0x01U)
            {
                returnCode = EscDerCtx_GetNextByte( &el.contents, boolVal );
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextOctetString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* octString[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, octString, StrL, DER_TAG_OCTET_STRING );
}

Esc_ERROR
EscDer_NextIntegerLongBe(
    EscDer_ContextT* ctx,
    const Esc_UINT8* intVal[],
    Esc_UINT32* intValLen )
{
    return EscDerElem_NGO( ctx, intVal, intValLen, DER_TAG_INTEGER );
}

Esc_ERROR
EscDer_NextInteger(
    EscDer_ContextT* ctx,
    Esc_UINT32* intVal )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT32 val = 0U;
    const Esc_UINT8* intPtr;
    Esc_UINT32 intLen;

    if ( (ctx != Esc_NULL_PTR) && (intVal != Esc_NULL_PTR) )
    {
        returnCode = EscDer_NextIntegerLongBe( ctx, &intPtr, &intLen );
        if (returnCode == Esc_NO_ERROR)
        {
            /* does it fit into an integer? */
            if (intLen <= 4U)
            {
                Esc_UINT8 i;

                for (i = 0U; i < intLen; i++)
                {
                    val <<= 8;
                    val |= (Esc_UINT32)intPtr[i];
                }

                *intVal = val;
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                returnCode = Esc_PARSE_ERROR;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextNull(
    EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_NULL );
        if (returnCode == Esc_NO_ERROR)
        {
            /* The length is always 0 */
            if (EscDerCtx_GetLength( &el.contents ) == 0x00U)
            {
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                returnCode = Esc_PARSE_ERROR;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextBitString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* bitstring[],
    Esc_UINT32* numBits )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (bitstring != Esc_NULL_PTR) && (numBits != Esc_NULL_PTR) )
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_BIT_STRING );

        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT8 numPaddingBits;

            returnCode = EscDerCtx_GetNextByte( &el.contents, &numPaddingBits );

            /* maximum 7 padding bits at the end */
            if ( (returnCode == Esc_NO_ERROR) && (numPaddingBits <= 0x7U) )
            {
                Esc_UINT32 StrL;

                *bitstring = EscDerCtx_GetCurrentCode( &el.contents );

                StrL = EscDerCtx_GetLength( &el.contents ) - 1U;    /* minus the padding count byte we already have */
                *numBits = (StrL * 8U) - numPaddingBits;

                returnCode = Esc_NO_ERROR;
            }
            else
            {
                returnCode = Esc_PARSE_ERROR;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextIa5String(
    EscDer_ContextT* ctx,
    const Esc_UINT8* ia5String[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, ia5String, StrL, DER_TAG_IA5String );
}

Esc_ERROR
EscDer_NextVisibleString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* visibleString[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, visibleString, StrL, DER_TAG_VisibleString );
}

Esc_ERROR
EscDer_NextUTF8String(
    EscDer_ContextT* ctx,
    const Esc_UINT8* UTF8String[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, UTF8String, StrL, DER_TAG_UTF8String );
}

Esc_ERROR
EscDer_NextUtcTime(
    EscDer_ContextT* ctx,
    const Esc_UINT8* timeString[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, timeString, StrL, DER_TAG_UTCTime );
}

Esc_ERROR
EscDer_NextGeneralizedTime(
    EscDer_ContextT* ctx,
    const Esc_UINT8* timeString[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, timeString, StrL, DER_TAG_GeneralizedTime );
}

Esc_ERROR
EscDer_NextPrintableString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* printableString[],
    Esc_UINT32* StrL )
{
    return EscDerElem_NGO( ctx, printableString, StrL, DER_TAG_PrintableString );
}

Esc_ERROR
EscDer_NextAnyString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* outString[],
    Esc_UINT32* StrL )
{
    Esc_UINT32 tag;
    Esc_UINT32 cla;
    Esc_ERROR returnCode;

    returnCode = EscDer_GetIdentifier( ctx, &tag, &cla );

    if (returnCode == Esc_NO_ERROR)
    {
        if ( (tag == DER_TAG_IA5String) ||
             (tag == DER_TAG_VisibleString) ||
             (tag == DER_TAG_PrintableString) ||
             (tag == DER_TAG_TeletexString) ||
             (tag == DER_TAG_BmpString) ||
             (tag == DER_TAG_UniversalString) ||
             (tag == DER_TAG_UTF8String) )
        {
            /* BITSTRING is not a ASCII String (Octectstring) */
            returnCode = EscDerElem_NGO( ctx, outString, StrL, tag );
        }
        else
        {
            returnCode = Esc_PARSE_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextOid(
    EscDer_ContextT* ctx,
    Esc_UINT32 identifiers[],
    Esc_UINT32 maxIdentifiers,
    Esc_UINT32* outNumIdentifiers )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (identifiers != Esc_NULL_PTR) && (outNumIdentifiers != Esc_NULL_PTR) )
    {
        DER_Element el;

        *outNumIdentifiers = 0x00U;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_OBJECT_IDENTIFIER );
        while ( (returnCode == Esc_NO_ERROR) && (EscDer_HasMoreBytes( &el.contents ) != FALSE) )
        {
            if (*outNumIdentifiers < maxIdentifiers)
            {
                /* read next identifier */
                returnCode = EscDerElem_NextOidSubident( &el.contents, &identifiers[*outNumIdentifiers] );
                (*outNumIdentifiers)++;
            }
            else
            {
                /* no more space to store remaining identifiers */
                returnCode = Esc_PARSE_ERROR;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextOidCheck(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) || (oidComponents == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (numComponents < 2U)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_OBJECT_IDENTIFIER );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscDerElem_OidCheckFirst( &el.contents, oidComponents, numComponents );
            if (returnCode == Esc_NO_ERROR)
            {
                Esc_UINT32 numRemaining = numComponents - DER_OID_MIN_COMPONENTS_NUM;
                returnCode = EscDerElem_OidCheckRemaining( &el.contents,
                        &oidComponents[DER_OID_MIN_COMPONENTS_NUM], numRemaining );
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextOidRel(
    EscDer_ContextT* ctx,
    Esc_UINT32 identifiers[],
    Esc_UINT32 maxIdentifiers,
    Esc_UINT32* outNumIdentifiers )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (identifiers != Esc_NULL_PTR) && (outNumIdentifiers != Esc_NULL_PTR) )
    {
        DER_Element el;

        *outNumIdentifiers = 0x00U;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_OBJECT_IDENTIFIER_REL );
        while ( (returnCode == Esc_NO_ERROR) && (EscDer_HasMoreBytes( &el.contents ) != FALSE) )
        {
            if (*outNumIdentifiers < maxIdentifiers)
            {
                /* read next identifier */
                returnCode = EscDerElem_NextOidSubident( &el.contents, &identifiers[*outNumIdentifiers] );
                (*outNumIdentifiers)++;
            }
            else
            {
                /* no more space to store remaining identifiers */
                returnCode = Esc_PARSE_ERROR;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextOidRelCheck(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (oidComponents != Esc_NULL_PTR) )
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UP( &el, ctx, DER_TAG_OBJECT_IDENTIFIER_REL );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscDerElem_OidCheckRemaining( &el.contents, oidComponents, numComponents );
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextSequence(
    EscDer_ContextT* ctx,
    EscDer_ContextT* outSequence )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (outSequence != Esc_NULL_PTR) )
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UC( &el, ctx, DER_TAG_SEQUENCE );
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 len;
            const Esc_UINT8* derCode;

            derCode = EscDerCtx_GetCurrentCode( &el.contents );
            len = EscDerCtx_GetLength( &el.contents );

            returnCode = EscDer_Init( outSequence, derCode, len );
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextSet(
    EscDer_ContextT* ctx,
    EscDer_ContextT* outSet )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (outSet != Esc_NULL_PTR) )
    {
        DER_Element el;

        returnCode = EscDerElem_ReadCtxCheck_UC( &el, ctx, DER_TAG_SET );
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 len;
            const Esc_UINT8* derCode;

            derCode = EscDerCtx_GetCurrentCode( &el.contents );
            len = EscDerCtx_GetLength( &el.contents );

            returnCode = EscDer_Init( outSet, derCode, len );
        }
    }

    return returnCode;
}

/*
Checks if more bytes are available to read from the context.
*/
Esc_BOOL
EscDer_HasMoreBytes(
    const EscDer_ContextT* ctx )
{
    Esc_BOOL hasMore;

    if (ctx->currentPos < ctx->len)
    {
        hasMore = TRUE;
    }
    else
    {
        hasMore = FALSE;
    }

    return hasMore;
}

Esc_ERROR
EscDer_PeekElement(
    const EscDer_ContextT* ctx,
    Esc_UINT32 expectedTag,
    Esc_UINT32 expectedClass,
    Esc_BOOL *hasElement)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    *hasElement = FALSE;

    if (EscDer_HasMoreBytes(ctx) != FALSE)
    {
        Esc_UINT32 foundTag = 0U;
        Esc_UINT32 foundClass = 0U;

        returnCode = EscDer_GetIdentifier(ctx, &foundTag, &foundClass);
        if (returnCode == Esc_NO_ERROR)
        {
            if ( (foundTag == expectedTag) && (foundClass == expectedClass) )
            {
                *hasElement = TRUE;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextTaggedValue(
    EscDer_ContextT* ctx,
    Esc_UINT32 tag,
    EscDer_ContextT* taggedContent )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (taggedContent != Esc_NULL_PTR) )
    {
        DER_Element el;
        returnCode = EscDerElem_ReadCtxCheck( &el, ctx, tag, DER_CLASS_CONTEXT, TRUE );
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 len;
            const Esc_UINT8* derCode;

            derCode = EscDerCtx_GetCurrentCode( &el.contents );
            len = EscDerCtx_GetLength( &el.contents );

            returnCode = EscDer_Init( taggedContent, derCode, len );
        }
    }

    return returnCode;
}

Esc_ERROR
EscDer_NextSkip(
    EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        DER_Element el;
        returnCode = EscDerElem_ReadFromCtx( &el, ctx );
    }

    return returnCode;
}

Esc_ERROR
EscDer_GetIdentifier(
    const EscDer_ContextT* ctx,
    Esc_UINT32* tag,
    Esc_UINT32* cla )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (tag != Esc_NULL_PTR) && (cla != Esc_NULL_PTR) )
    {
        EscDer_ContextT tmpCtx;
        DER_Element elem;

        EscDerCtx_Clone( ctx, &tmpCtx );
        returnCode = EscDerElem_ReadFromCtx( &elem, &tmpCtx );
        if (returnCode == Esc_NO_ERROR)
        {
            *tag = elem.tag;
            *cla = elem.elemClass;
        }
    }

    return returnCode;
}

const Esc_UINT8*
EscDer_GetCurrentCode(
    const EscDer_ContextT* ctx )
{
    const Esc_UINT8* derCode;

    if (ctx == Esc_NULL_PTR)
    {
        derCode = Esc_NULL_PTR;
    }
    else
    {
        derCode = EscDerCtx_GetCurrentCode( ctx );
    }

    return derCode;
}

Esc_UINT32
EscDer_GetCurrentPosition(
    const EscDer_ContextT* ctx )
{
    Esc_UINT32 pos;

    if (ctx == Esc_NULL_PTR)
    {
        pos = 0U;
    }
    else
    {
        pos = ctx->currentPos;
    }

    return pos;
}

Esc_ERROR
EscDer_AssertEnd(
    const EscDer_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (EscDer_HasMoreBytes(ctx) != FALSE)
    {
        returnCode = Esc_PARSE_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
