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
   Only primitives can be decoded, not constructed values yet.

   All functions return Esc_NO_ERROR on success.

   The first function to call is EscDer_Init, afterwards
   the DER code is traversed as a stream. Reading a primitive
   from the DER code, moves the stream further. So no element
   can be read twice.

   After returning an error, the context is in an undefined state,
   EscDer_Init must be called again.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_DER_H_
#define ESC_DER_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Coordinated Universal Time */
#define DER_TAG_UTCTime         0x17U

/** Generalized Time */
#define DER_TAG_GeneralizedTime 0x18U

/** Tag: Boolean (true, false) */
#define DER_TAG_BOOLEAN         0x01U

/** Tag: Integer */
#define DER_TAG_INTEGER         0x02U


/** Class: Universal */
#define DER_CLASS_UNIVERSAL     0x00U

/** Class: Context-Specific */
#define DER_CLASS_CONTEXT       0x80U


/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** DER Context data. Don't access its members directly. */
typedef struct
{
    /** Pointer to the DER code to read from */
    const Esc_UINT8* derCode;
    /** Length in bytes of derCode */
    Esc_UINT32 len;
    /** Position to read the next byte from */
    Esc_UINT32 currentPos;
} EscDer_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the DER context.

\param[out] ctx The initialized context.
\param[in] derCode The DER code to parse. The pointer must remain valid
    for all subsequent EscDer_* calls.
\param[in] codeLen The number of available bytes of code.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_Init(
    EscDer_ContextT* ctx,
    const Esc_UINT8 derCode[],
    Esc_UINT32 codeLen );

/**
Reads a Esc_BOOLEAN value from the context.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] boolVal Will contain the boolean value.
    Note that every boolVal !=0 is considered true.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextBoolean(
    EscDer_ContextT* ctx,
    Esc_UINT8* boolVal );

/**
Reads an INTEGER value from the context
up to 32 bit length

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] intVal Will contain the integer value.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextInteger(
    EscDer_ContextT* ctx,
    Esc_UINT32* intVal );

/**
Reads an INTEGER value from the context
with unlimited length.
Byte format is big endian.

As the DER byte format is already big endian, just a pointer
to the DER code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] intVal Will return a pointer to the integer value inside the DER code.
    The value is big endian encoded.
\param[out] intValLen Will be updated with the length of intVal in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextIntegerLongBe(
    EscDer_ContextT* ctx,
    const Esc_UINT8* intVal[],
    Esc_UINT32* intValLen );

/**
Reads a BIT STRING value from the context.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] bitstring Will return a pointer to the bitstring value inside the DER code.
\param[out] numBits The number of bits of the bitstring.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextBitString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* bitstring[],
    Esc_UINT32* numBits );

/**
Reads the next null token from the context.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscDer_NextNull(
    EscDer_ContextT* ctx );

/**
Reads an OCTET_STRING value from the context
with unlimited length.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] octString Will return a pointer to the octet string value inside the DER code.
\param[out] StrL Will be updated with the length of octString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextOctetString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* octString[],
    Esc_UINT32* StrL );

/**
Reads a IA5String value from the context
with unlimited length.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] ia5String Will return a pointer to the IA5String inside the DER code.
\param[out] StrL Will be updated with the length of ia5String in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextIa5String(
    EscDer_ContextT* ctx,
    const Esc_UINT8* ia5String[],
    Esc_UINT32* StrL );

/**
Reads a VisibleString value from the context
with unlimited length.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] visibleString Will return a pointer to the VisibleString inside the DER code.
\param[out] StrL Will be updated with the length of visibleString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextVisibleString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* visibleString[],
    Esc_UINT32* StrL );

/**
Reads a UTF8String value from the context
with unlimited length.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] UTF8String Will return a pointer to the UTF8String inside the DER code.
\param[out] StrL Will be updated with the length of visibleString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextUTF8String(
    EscDer_ContextT* ctx,
    const Esc_UINT8* UTF8String[],
    Esc_UINT32* StrL );

/**
Reads a PrintableString value from the context
with unlimited length.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] printableString Will return a pointer to the PrintableString inside the DER code.
\param[out] StrL Will be updated with the length of PrintableString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextPrintableString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* printableString[],
    Esc_UINT32* StrL );

/**
Reads a octet string value from the context
with unlimited length. An octet string is usually an ASCII string.

In fact, just a pointer to the EscDer_ContextT code is returned.

The string can be of type VisibleString, PrintableString or Ia5String.
BitStrings are not included.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] outString Will return a pointer to the String inside the DER code.
\param[out] StrL Will be updated with the length of String in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextAnyString(
    EscDer_ContextT* ctx,
    const Esc_UINT8* outString[],
    Esc_UINT32* StrL );

/**
Reads the UTC time from the context with variable length,
as the time might be represented in different formats.

The most common formats are "YYMMDD000000Z", "YYMMDD0000Z" and "YYMMDDHHMMSSZ",
where the first one is the official one.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] timeString Will return a pointer to the time inside the DER code.
\param[out] StrL Will be updated with the length of printableString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextUtcTime(
    EscDer_ContextT* ctx,
    const Esc_UINT8* timeString[],
    Esc_UINT32* StrL );

/**
Reads the Generalized time from the context with variable length,
as the time might be represented in different formats.

The most common formats are "YYYYMMDD000000Z", "YYYYMMDD0000Z" and "YYYYMMDDHHMMSSZ",
where the first one is the official one.

In fact, just a pointer to the EscDer_ContextT code is returned.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] timeString Will return a pointer to the time inside the DER code.
\param[out] StrL Will be updated with the length of printableString in byte.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextGeneralizedTime(
    EscDer_ContextT* ctx,
    const Esc_UINT8* timeString[],
    Esc_UINT32* StrL );

/**
Reads an OBJECT IDENTIFIER value from the context
with unlimited length.

The first subidentifier is the combined form of
the first identifier components using the formula
(X*40)+Y.

\see ISO/IEC 8825-1:2003 Section 8.19.4

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] identifiers Will contain the identifiers of the next oid.
\param[out] maxIdentifiers The maximum number of identifiers to write to.
\param[out] outNumIdentifiers The actual number of identifiers written.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextOid(
    EscDer_ContextT* ctx,
    Esc_UINT32 identifiers[],
    Esc_UINT32 maxIdentifiers,
    Esc_UINT32* outNumIdentifiers );

/**
Reads a OBJECT IDENTIFIER (0x06) value from the context
and compares them with the OID components passed.

The first two OID components are passed separately,
not as a combined subidentifier.


\see ISO/IEC 8825-1:2003 Section 8.19.4

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[in] oidComponents Contains the OID components to check.
\param[in] numComponents The number of components to check.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextOidCheck(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents );

/**
Reads a RELATIVE OID (0x0D) value from the context
with unlimited length.

\see ISO/IEC 8825-1:2003 Section 8.20

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] identifiers Will contain the identifiers of the next oid.
\param[out] maxIdentifiers The maximum number of identifiers to write to.
\param[out] outNumIdentifiers The actual numbe of identifiers written.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextOidRel(
    EscDer_ContextT* ctx,
    Esc_UINT32 identifiers[],
    Esc_UINT32 maxIdentifiers,
    Esc_UINT32* outNumIdentifiers );

/**
Reads a RELATIVE OID (0x0D) value from the context
and compares them with the OID components passed.

\see ISO/IEC 8825-1:2003 Section 8.20

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[in] oidComponents Contains the OID components to check.
\param[in] numComponents The number of components to check.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextOidRelCheck(
    EscDer_ContextT* ctx,
    const Esc_UINT32 oidComponents[],
    Esc_UINT32 numComponents );

/**
Reads a sequence from the DER Context. The sequence is
a new DER context itself, which can be used to access its elements.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] outSequence A new context to access the elements of the sequence.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextSequence(
    EscDer_ContextT* ctx,
    EscDer_ContextT* outSequence );

/**
Reads a set from the DER Context. The set is
a new DER context itself, which can be used to access its elements.

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[out] outSet A new context to access the elements of the set.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextSet(
    EscDer_ContextT* ctx,
    EscDer_ContextT* outSet );


/**
Checks if more bytes are available to read from the context.

\param[in]  ctx     The current context.

\return TRUE if more bytes can be read, FALSE otherwise.
*/
Esc_BOOL
EscDer_HasMoreBytes(
    const EscDer_ContextT* ctx );

/**
 * Test whether the next element has the given class and tag. This function does not
 * alter the context. It can be used to check for optional elements.
 *
 * \param[in]   ctx             The current parsing context.
 * \param[in]   expectedTag     The expected tag of the next element.
 * \param[in]   expectedClass   The expected class of the next element.
 * \param[out]  hasElement      Set to TRUE if the next element is of the given class/tag. FALSE otherwise.
 *
 * \return Esc_NO_ERROR if no error occurred. The hasElement parameter can be evaluated in this case.
 */
Esc_ERROR
EscDer_PeekElement(
    const EscDer_ContextT* ctx,
    Esc_UINT32 expectedTag,
    Esc_UINT32 expectedClass,
    Esc_BOOL *hasElement);

/**
Reads the next tagged value and returns a context to
to read its contents.
No application tagging supported.

\see ISO/IEC 8825-1:2003 Section 8.14

\param[in] ctx The current context.
\param[out] ctx The updated context.
\param[in] tag The tag to read.
\param[out] taggedContent The content returned content of the tagged value.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextTaggedValue(
    EscDer_ContextT* ctx,
    Esc_UINT32 tag,
    EscDer_ContextT* taggedContent );

/**
Skips the next element of the code,
no matter which type it is.

\param[in] ctx The current context.
\param[out] ctx The updated context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_NextSkip(
    EscDer_ContextT* ctx );

/**
Reads the next identifier,
without changing the context state.

\param[in] ctx The current context.
\param[out] tag The tag of the next identifier.
\param[out] cla The class of the next identifier.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDer_GetIdentifier(
    const EscDer_ContextT* ctx,
    Esc_UINT32* tag,
    Esc_UINT32* cla );

/**
Returns a pointer to the current location of the code.
\param[in] ctx The current context.

\return A pointer to the next byte of code of the current context.
*/
extern const Esc_UINT8*
EscDer_GetCurrentCode(
    const EscDer_ContextT* ctx );

/**
Returns the current offset to the start of the context.
\param[in] ctx The current context.

\return The number of bytes read so far.
*/
Esc_UINT32
EscDer_GetCurrentPosition(
    const EscDer_ContextT* ctx );

/**
Check if the parsing the current element reached the end.
The function assumes that the end is reached and returns an
error if this is not the case.
\param[in] ctx The current context.

\retval Esc_NO_ERROR if the end is reached.
\retval Esc_PARSE_ERROR if more bytes are left or another error occurred.
 */
Esc_ERROR
EscDer_AssertEnd(
    const EscDer_ContextT* ctx );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
