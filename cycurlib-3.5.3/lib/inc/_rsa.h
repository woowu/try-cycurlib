/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Common types and functions for RSA.

   $Rev: 494 $
 */
/***************************************************************************/

#ifndef ESC__RSA_H_
#define ESC__RSA_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "rsa_cfg.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if Esc_HAS_INT64 == 1
/** RSA base for calculation (16 or 32 bits) */
#    define EscRsa_RSA_BASE 32U
/** half word for calculation (e.g., factor; 16 or 32 bit) */
typedef Esc_UINT32 EscRsa_HWORD;
/** full word for calculation (e.g., result; 32 or 64 bit) */
typedef Esc_UINT64 EscRsa_FWORD;
#else
/** RSA base for calculation (16 or 32 bits) */
#    define EscRsa_RSA_BASE 16U
/** half word for calculation (e.g., factor; 16 or 32 bit) */
typedef Esc_UINT16 EscRsa_HWORD;
/** full word for calculation (e.g., result; 32 or 64 bit) */
typedef Esc_UINT32 EscRsa_FWORD;
#endif


/** Size of RSA modulus in bits calculated from bytes */
#define EscRsa_KEY_BITS_FROMBYTES(b) ( (b) * 8U)

/** Size of RSA modulus in bytes calculated from bits */
#define EscRsa_KEY_BYTES_FROMBITS(b) ( (b) / 8U )

/** Size of maximum RSA modulus in bytes */
#define EscRsa_KEY_BYTES_MAX ( EscRsa_KEY_BYTES_FROMBITS( EscRsa_KEY_BITS_MAX ) )

/** Size of one RSA Word in byte */
#define EscRsa_WORD_SIZE (EscRsa_RSA_BASE / 8U)

/** Size of RSA modulus in words calculated from bits */
#define EscRsa_RSA_SIZE_WORDS_FROMBITS(b)  ((b) / EscRsa_RSA_BASE)

/** Computes the size in words of a long FE from key size (in bits) */
#define EscRsa_RSA_SIZE_WORDS_LONG_FROMBITS(b) ( (2U * EscRsa_RSA_SIZE_WORDS_FROMBITS(b)) )

/** Size of maximum RSA modulus in words */
#define EscRsa_RSA_SIZE_WORDS_MAX (EscRsa_RSA_SIZE_WORDS_FROMBITS(EscRsa_KEY_BITS_MAX) )

/** Size of maximum RSA Half values (eg. CRT coefficients) in bytes */
#define EscRsa_KEY_BYTES_MAX_HALF (EscRsa_KEY_BYTES_MAX / 2U)

/** The maximum value of one HWORD */
#define EscRsa_MAX_VAL ( ( ( (EscRsa_FWORD)1U ) << EscRsa_RSA_BASE ) - 1U )

/** Length of single multiplication results in words */
#define EscRsa_RSA_SIZE_WORDS_LONG_MAX ( (2U * EscRsa_RSA_SIZE_WORDS_FROMBITS(EscRsa_KEY_BITS_MAX)) )

/** Extracts the high part of FWORD w and returns it as a FWORD */
#define EscRsa_HI_FWORD( w ) ( ( (w) >> EscRsa_RSA_BASE ) & EscRsa_MAX_VAL )

/** Extracts the high part of FWORD w and returns it as a HWORD */
#define EscRsa_HI_HWORD( w ) ( (EscRsa_HWORD)( ( (w) >> EscRsa_RSA_BASE ) & EscRsa_MAX_VAL ) )

/** Extracts the low part of FWORD w and returns it as a FWORD */
#define EscRsa_LO_FWORD( w ) ( (w) & EscRsa_MAX_VAL )

/** Extracts the low part of FWORD w and returns it as a HWORD */
#define EscRsa_LO_HWORD( w ) ( (EscRsa_HWORD)( (w) & EscRsa_MAX_VAL ) )

/** Return min(x,y) */
#define EscRsa_MIN( x, y ) ( ( (x) < (y) ) ? (x) : (y) )

#if EscRsa_USE_SLIDING_WINDOW == 1
/** Number of precomputed elements for the sliding window algorithm */
#   define EscRsa_NUM_WINDOW_ELEMENTS ( (Esc_UINT16)( (Esc_UINT16)1U << (EscRsa_WINDOW_SIZE - 1U) ) )
#endif

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** RSA field element. */
typedef struct
{
    /** RSA field element in 16bit / 32bit words */
    EscRsa_HWORD words[EscRsa_RSA_SIZE_WORDS_MAX];
    /* No carry needed */
} EscRsa_FieldElementT;

/**
 * RSA key size struct
 * holding the key size pre-calculated in bits, bytes, words, and longwords
 */
typedef struct
{
    /** Size of tested RSA modulus in bits */
    Esc_UINT16 bits;
    /** Size of tested RSA modulus in bytes */
    Esc_UINT16 bytes;
    /** Size of tested RSA modulus in words */
    Esc_UINT16 words;
    /** Size of tested RSA modulus in longwords/doublewords */
    Esc_UINT32 wordsLong;
} EscRsa_KeySizeT;

/** Multiplication result field element. */
typedef struct
{
    /** RSA field element of double size */
    EscRsa_HWORD words[EscRsa_RSA_SIZE_WORDS_LONG_MAX];
    /* No carry needed */
} EscRsa_FieldElementLongT;

/** References to operands to exponentiation, multiplication and reduction */
typedef struct
{
    /** Data to calculate c = x^e mod m */

    /** Multiplication result */
    EscRsa_FieldElementLongT* c;

    /** Modulus */
    const EscRsa_FieldElementT* m;

    /** x */
    EscRsa_FieldElementT* x;
} EscRsa_MultiplyDataT;

#if EscRsa_USE_MONTGOM_MUL == 1
/** Montgomery parameters */
typedef struct
{
    /** Modulus */
    EscRsa_FieldElementT mod;
    /** negative inverse of mod[0] */
    EscRsa_HWORD m;
} EscRsa_MontGomElementT;
#endif

/** A public key */
typedef struct
{
    /** Modulus.
        Note that the six most significant bits of the modulus must not all be zero! */
    EscRsa_FieldElementT modulus;

    /** Public exponent */
    Esc_UINT32 pubExp;

    /** Key Size in Bits*/
    Esc_UINT16 keySizeBits;
} EscRsa_PubKeyT;

#if EscRsa_CRT_ENABLED == 1
/** CRT part of a private key */
typedef struct
{
    /** Private first prime p */
    EscRsa_FieldElementT p;
    /** Private second prime q */
    EscRsa_FieldElementT q;
    /** Private d mod (p-1) */
    EscRsa_FieldElementT dmp1;
    /** Private d mod (q-1) */
    EscRsa_FieldElementT dmq1;
    /** Private q^(-1) mod p */
    EscRsa_FieldElementT iqmp;
} EscRsa_PrivKeyCrtT;
#endif

/** A private key */
typedef struct
{
    /** Flag to indicate whether CRT is used or not */
    Esc_BOOL usesCrt;

    /** The corresponding public key */
    EscRsa_PubKeyT pubKey;

    /** The private key part */
    union
    {
        /** Private exponent */
        EscRsa_FieldElementT privExp;

#if EscRsa_CRT_ENABLED == 1
        /** CRT components p, q, dmp1, dmq1, qinv */
        EscRsa_PrivKeyCrtT crt;
#endif
    } privKey;
} EscRsa_PrivKeyT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

#if (EscRsa_USE_MONTGOM_MUL == 0) || (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
/**
Copy a field element to a long field element. The upper part of the long field
element is set to zero.

\param[out] dst         Destination long field element.
\param[in]  src         Source field element.
\param[in]  wordSize    Number of words in the field element.
 */
void
EscRsaFe_ToLongFe(
    EscRsa_FieldElementLongT* dst,
    const EscRsa_FieldElementT* src,
    const Esc_UINT16 wordSize );
#endif

/**
Assign lower part of a long field element to a field element.
dst := lower_half(src)

\param[out] dst         Destination field element.
\param[in]  src         Source long field element.
\param[in]  wordSize    Number of words in the field element.
*/
void
EscRsaFe_FromLongFe(
    EscRsa_FieldElementT* dst,
    const EscRsa_FieldElementLongT* src,
    const Esc_UINT16 wordSize );

#if (EscRsa_USE_SLIDING_WINDOW == 1) || (EscRsa_USE_MONTGOM_MUL == 1) || (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
/**
Copy a field element.
dst := src

\param[out] dst         Destination field element.
\param[in]  src         Source field element.
\param[in]  wordSize    Number of words in each field element.
 */
void
EscRsaFe_Assign(
    EscRsa_FieldElementT* dst,
    const EscRsa_FieldElementT* src,
    const Esc_UINT16 wordSize );
#endif

#if EscRsa_USE_MONTGOM_MUL == 1
/**
Compute Montgomery multiplication.
x = x * y mod m

\param[in,out]  x           First factor and result.
\param[in]      y           Second factor.
\param[in]      mg          Montgomery parameters computed via EscRsa_MontGom_Init()
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_MontGom(
    EscRsa_FieldElementT* x,
    const EscRsa_FieldElementT* y,
    const EscRsa_MontGomElementT* mg,
    const Esc_UINT16 wordSize );

/**
Initialize Montgomery multiplication.

\param[in]      pm          pm->m must point to the Montgomery modulus.
\param[out]     mg          The computed Montgomery parameters.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsa_MontGom_Init(
    const EscRsa_MultiplyDataT* pm,
    EscRsa_MontGomElementT* mg,
    const Esc_UINT16 wordSize );

#endif

#if (EscRsa_USE_MONTGOM_MUL == 0) || ( ( EscRsa_GENRSA_ENABLED == 1) && (EscRsa_USE_SLIDING_WINDOW == 0 ) )
/**
Compute the square of a field element.
pm->c := pm->c * pm->c mod m

\param[in,out]  pm          Operand to square and result (both referenced via pm->c)
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_SquareClassically(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );
#endif

#if (EscRsa_USE_SLIDING_WINDOW == 1) && ( ( EscRsa_USE_MONTGOM_MUL == 0) || (EscRsa_GENRSA_ENABLED == 1 ) )
/**
Compute the square of a field element.
c := c * c mod m

\param[in,out]  pm          Refers to the operands c and m.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_SquareSlidingWindow(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize );
#endif

/**
Compute modular reduction.
c := c mod m

\param[in,out]  pm          Refers to the operands c and m.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_ModularReduction(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/**
Convert byte array to field element. The byte array is assumed
to be in big endian byte order.

\param[out] dest    Resulting field element.
\param[in]  source  The byte array to convert.
\param[in]  lenByte Length of the byte array in bytes. This must be a multiple of
                    EscRsa_WORD_SIZE (number of bytes in a word).
*/
void
EscRsaFe_FromBytesBE(
    EscRsa_FieldElementT* dest,
    const Esc_UINT8 source[],
    const Esc_UINT16 lenByte);

/**
Convert field element to byte array. The result is stored
in big endian byte order.

\param[out] dest    Resulting byte array.
\param[in]  source  Field element to convert.
\param[in]  len     Length of the byte array in bytes.
*/
void
EscRsaFe_ToBytesBE(
    Esc_UINT8 dest[],
    const EscRsa_FieldElementT* source,
    Esc_UINT16 len);

/**
Multiply two field elements (without reduction).
c := c * x

\param[in,out]  pm          Refers to the operands c and m.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_MultiplyClassically(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/**
Multiply two field elements with reduction.
c := c * x mod m

\param[in,out]  pm          Refers to the operands c and m.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_Multiply(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/**
Test whether a bit in the given field element is set (1) or not (0).

\param[in]      e           The field element whose bit shall be tested.
\param[in]      thebit      Index of the bit. Index 0 corresponds to the MSB.
\param[in]      wordSize    Length of e in words.

\return TRUE if the bit is set, FALSE otherwise.
*/
Esc_BOOL
EscRsaFe_IsBitSet(
    const EscRsa_FieldElementT* e,
    Esc_UINT32 thebit,
    const Esc_UINT16 wordSize  );

/**
Derive the length in bytes, words and double words from the length in bits.

\param[in]      lenBits     The length in bits.
\param[out]     keySize     A struct containing the computed lengths.
*/
void
EscRsa_AssignKeyStruct(
    const Esc_UINT16 lenBits,
    EscRsa_KeySizeT* keySize);

#if EscRsa_CRT_ENABLED == 1
/**
Add two field elements.
a := a + b

\param[in,out]  a           First summand and result.
\param[in]      b           Second summand.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_Add(
    EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize );
#endif

/**
Compare two field elements.

\param[in,out]  a           First operand.
\param[in]      b           Second operand.
\param[in]      wordSize    Number of words in each field element.

\return  +1 if a>b
\return  -1 if a<b
\return   0 if a==b
*/
Esc_SINT8
EscRsaFe_AbsoluteCompare(
    const EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize );

/**
Test whether a field element equals zero.

\param[in]  a           The field element to compare.
\param[in]  wordSize    Length of field element in words.

\return TRUE if the field element equals zero, FALSE otherwise.
 */
Esc_BOOL
EscRsaFe_IsZero(
    const EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize );

#if (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
/**
Subtract two field elements.
a := a - b

\param[in,out]  a           Minuend and result.
\param[in]      b           Subtrahend.
\param[in]      wordSize    Number of words in each field element.
*/
void
EscRsaFe_Subtract(
    EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize );
#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
