/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief   Field arithmetic for all ECC based algorithms (Weierstrass and Twisted Edwards).

   Byteorder of the long numbers is Little endian

   $Rev: 2750 $
 */
/***************************************************************************/

#ifndef ESC__FEARITH_H_
#define ESC__FEARITH_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION                                    *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Number of bits in one word */
#define EscFeArith_WORD_BITS 32U

#if Esc_HAS_INT64 == 1
/** low 32 bit word from 64 bit */
#    define EscFeArith_LO64( a ) ( (Esc_UINT32)( (a) & 0xFFFFFFFFU ) )
/** high 32 bit word from 64 bit */
#    define EscFeArith_HI64( a ) ( (Esc_UINT32)( ( (a) >> 32 ) & 0xFFFFFFFFU ) )
/** return min(x,y) */
#    define EscFeArith_MIN( x, y ) ( ( (x) < (y) ) ? (x) : (y) )
#else
/** low 16 bit word from 32 bit */
#    define EscFeArith_LO32( a ) ( (Esc_UINT16)( (a) & 0xFFFFU ) )
/** high 16 bit word from 32 bit */
#    define EscFeArith_HI32( a ) ( (Esc_UINT16)( ( (a) >> 16 ) & 0xFFFFU ) )
#endif

/** Bit mask in which the highest bit of a 32 bit word is set */
#define EscFeArith_32BIT_WORD_MSB_SET 0x80000000U
/** Bit mask in which all bits of a 32 bit word are set */
#define EscFeArith_32BIT_WORD_ALL_SET 0xFFFFFFFFU

/** ID for curve secp192r1 (also known as NIST P-192) */
#define EscFeArith_CURVE_SECP_192         1U
/** ID for curve secp224r1 (also known as NIST P-224) */
#define EscFeArith_CURVE_SECP_224         2U
/** ID for curve secp256r1 (also known as NIST P-256) */
#define EscFeArith_CURVE_SECP_256         3U
/** ID for curve secp384r1 (also known as NIST P-384) */
#define EscFeArith_CURVE_SECP_384         4U
/** ID for curve secp521r1 (also known as NIST P-521) */
#define EscFeArith_CURVE_SECP_521         5U

/** ID for curve brainpoolP160r1 */
#define EscFeArith_CURVE_BRAINPOOL_P160   6U
/** ID for curve brainpoolP192r1 */
#define EscFeArith_CURVE_BRAINPOOL_P192   7U
/** ID for curve brainpoolP224r1 */
#define EscFeArith_CURVE_BRAINPOOL_P224   8U
/** ID for curve brainpoolP256r1 */
#define EscFeArith_CURVE_BRAINPOOL_P256   9U
/** ID for curve brainpoolP320r1 */
#define EscFeArith_CURVE_BRAINPOOL_P320   10U
/** ID for curve brainpoolP384r1 */
#define EscFeArith_CURVE_BRAINPOOL_P384   11U
/** ID for curve brainpoolP512r1 */
#define EscFeArith_CURVE_BRAINPOOL_P512   12U

/** The curve ID with the highest value. This must be kept in sync with the ID values for Weierstrass curves above. */
#define EscFeArith_MAX_CURVE_ID     (EscFeArith_CURVE_BRAINPOOL_P512)

/** ID for curve Curve22519 */
#define EscFeArith_CURVE_ED25519          13U


/* Enable/disable support for the Twisted Edwards curve used for Ed25519.
   The Ed25519 and the point arithmetic module for Twisted Edwards curves
   support this curve only, therefore this define must be enabled. */
#ifndef EscEcc_CURVE_ED25519_ENABLED
/** Enables/disables support for the Ed25519 curve */
#   define EscEcc_CURVE_ED25519_ENABLED    1
#endif


#if (EscEcc_SECP_521_ENABLED == 1)
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  66U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  18U
#elif (EscEcc_BRAINPOOL_P512_ENABLED == 1)
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  64U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  17U
#elif ((EscEcc_SECP_384_ENABLED == 1) || (EscEcc_BRAINPOOL_P384_ENABLED == 1))
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  48U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  13U
#elif (EscEcc_BRAINPOOL_P320_ENABLED == 1)
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  40U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  11U
#elif ((EscEcc_SECP_256_ENABLED == 1) || (EscEcc_BRAINPOOL_P256_ENABLED == 1) || (EscEcc_CURVE_ED25519_ENABLED == 1) )
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  32U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  9U
#elif ((EscEcc_SECP_224_ENABLED == 1) || (EscEcc_BRAINPOOL_P224_ENABLED == 1))
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  28U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  8U
#elif ((EscEcc_SECP_192_ENABLED == 1) || (EscEcc_BRAINPOOL_P192_ENABLED == 1))
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  24U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  7U
#elif (EscEcc_BRAINPOOL_P160_ENABLED == 1)
/** Maximum Key Length in Bytes */
#   define EscFeArith_KEY_BYTES_MAX  20U
/** Maximum Key Length in Words */
#   define EscFeArith_MAX_WORDS  6U
#endif

/** Maximum multiplication precision a * b = c. len(c) = len(a) + len(b) */
#define EscFeArith_MAX_LONG_WORDS (2U * EscFeArith_MAX_WORDS)


/*lint -esym(750,EscFeArith_PADZEROS_FROM_*) we allow unused macros in the case that only a partial set of ECC curves are enabled for a better readability and to save some ifdef cascades. */

/**
 * @name Padding patterns
 * Padding patterns depending on the curve configuration.
 * Used for the declaration of curve parameters in the point arithmetic modules.
 * @{
 */
#if EscFeArith_MAX_WORDS == 18U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_9 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_11 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_13 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_17 0x00000000UL,
#elif EscFeArith_MAX_WORDS == 17U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_9 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_11 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_13 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_17
#elif EscFeArith_MAX_WORDS == 13U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_9 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_11 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_13
#elif EscFeArith_MAX_WORDS == 11U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8 0x00000000UL, 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_9 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_11
#elif EscFeArith_MAX_WORDS == 9U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL, 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_9
#elif EscFeArith_MAX_WORDS == 8U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL, 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7 0x00000000UL,
#   define EscFeArith_PADZEROS_FROM_8
#elif EscFeArith_MAX_WORDS == 7U
#   define EscFeArith_PADZEROS_FROM_6 0x00000000UL
#   define EscFeArith_PADZEROS_FROM_7
#elif EscFeArith_MAX_WORDS == 6U
#   define EscFeArith_PADZEROS_FROM_6
#else
#   error "EscFeArith_MAX_WORDS in undefined behavior"
#endif
/** @} */


#if ( (EscEcc_ECDSA_ENABLED == 1) && (EscEcc_USE_SHAMIRS_TRICK == 1) )
/** Enable the definition of the functions containing Shamir's Trick
 * depending on the configuration */
#   define EscFeArith_ENABLE_SHAMIRS_TRICK 1
#else
/** Disable the definition of the functions containing Shamir's Trick
 * depending on the configuration */
#   define EscFeArith_ENABLE_SHAMIRS_TRICK 0
#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Select used curve. See curve identifiers above for valid values. */
typedef Esc_UINT8 EscFeArith_CurveId;


/** Size struct holding the key size and word size in different units. */
typedef struct
{
    /** Curve's key size in bits */
    Esc_UINT16 keySizeBits;
    /** Curve's key size in bytes */
    Esc_UINT8 keySizeBytes;
    /** Curve's key size in words */
    Esc_UINT8 keySizeWords;
    /** Maximum number of words of a EscFeArith_FieldElementT */
    Esc_UINT8 maxWords;
    /** Maximum number of double words of a EscFeArith_FieldElementT */
    Esc_UINT8 maxWordsLong;
} EscFeArith_SizeT;


/** A field element with long number arithmetic */
typedef struct
{
    /** the words of the long number */
    Esc_UINT32 word[EscFeArith_MAX_WORDS];
} EscFeArith_FieldElementT;


/** A long field element with long number arithmetic,
which is the result of a multiplication. */
typedef struct
{
    /** the words of the long number */
    Esc_UINT32 word[EscFeArith_MAX_LONG_WORDS];
} EscFeArith_FieldElementLongT;

/** Field parameters */
typedef struct
{
    /** Precalculated P, used in barrett reduction */
    EscFeArith_FieldElementT precalc_my_p;
    /** Prime */
    EscFeArith_FieldElementT prime_p;
    /** Length of p in words */
    Esc_UINT8 pLen;
} EscFeArith_FieldT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

 /**
 * Adds two arrays of with a length of len with carry.
 *
 * \param[out] carry_out The carry.
 * \param[out] c The result of the addition.
 * \param[in] a Summand a.
 * \param[in] b Summand b.
 * \param[in] len Length of both summands.
 */
void
EscFeArithWd_AddCLoop(
    Esc_UINT32* carry_out,
    Esc_UINT32 c[],
    const Esc_UINT32 a[],
    const Esc_UINT32 b[],
    const Esc_UINT8 len );

/**
 * Subtracts two arrays of with a length of len with carry.
 *
 * \param[out] c The result of the subtraction.
 * \param[out] borrow_out The borrow.
 * \param[in] a Minuend a.
 * \param[in] b subtrahend b.
 * \param[in] len Length of both input values.
 */
void
EscFeArithWd_SubBLoop(
    Esc_UINT32 c[],
    Esc_UINT32* borrow_out,
    const Esc_UINT32 a[],
    const Esc_UINT32 b[],
    const Esc_UINT8 len );

/* Field arithmetic */
/**
 * Converts a field element to a byte array (big endian)
 *
 * \param[in] input Field element to convert.
 * \param[out] output Converted FE in byte array. Must have curve->keySizeBytes.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_ToUint8(
    const EscFeArith_FieldElementT* input,
    Esc_UINT8 output[],
    const EscFeArith_SizeT* curveSize );

/**
 * Converts big endian byte array to a field element
 *
 * \param[in] input Big endian byte array.
 * \param[in] inputLen Length of byte array.
 * \param[out] output Resulting FE.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_FromUint8(
    const Esc_UINT8 input[],
    Esc_UINT32 inputLen,
    EscFeArith_FieldElementT* output,
    const EscFeArith_SizeT* curveSize );

#if EscEcc_ECDSA_ENABLED == 1
/**
 * Converts a field element a long field element.
 * a = b, unused most significant words are set to zero.
 *
 * \param[out] a resulting long field element.
 * \param[in] b Input field element.
 * \param[in] lenWords Length of input field element.
 */
void
EscFeArith_ToLongElement(
    EscFeArith_FieldElementLongT* a,
    const EscFeArith_FieldElementT* b,
    const Esc_UINT8 lenWords );
#endif


/**
 * Set field element to zero.
 *
 * \param[out] a Resulting field element = 0.
 */
void
EscFeArith_SetZero(
    EscFeArith_FieldElementT* a );

/**
 * Set field element to one.
 *
 * \param[out] a Resulting field element = 1.
 */
void
EscFeArith_SetOne(
    EscFeArith_FieldElementT* a );

/**
 * Checks a field element for zero.
 *
 * \param[in] a Field element to check.
 * \param[in] lenWords Length of input field element.
 *
 * \retval TRUE if the field element equals zero
 * \retval FALSE if the field element is not zero.
 */
Esc_BOOL
EscFeArith_IsZero(
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords );

/**
 * Checks a field element for one.
 *
 * \param[in] a Field element to check.
 * \param[in] lenWords Length of input field element.
 *
 * \retval TRUE if the field element equals one
 * \retval FALSE if the field element is not one.
 */
Esc_BOOL
EscFeArith_IsOne(
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords );

/**
 * Compares two field elements.
 *
 * \param[in] a Field element a.
 * \param[in] b Field element b.
 * \param[in] lenWords Length of both input field elements.
 *
 * \retval +1 if field element a is greater than b (a > b).
 * \retval -1 if field element a is smaller than b (a < b).
 * \retval 0 if field elements have the same value (a == b).
 */
Esc_SINT8
EscFeArith_AbsoluteCompare(
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const Esc_UINT8 lenWords );

/**
 * Copy a field element to another one.
 *
 * Field Elements c and a can point to the same location (aliased).
 *
 * \param[out] c Copy of the input field element a.
 * \param[in] a Field element to copy.
 * \param[in] lenWords Length of both field elements.
 */
void
EscFeArith_Assign(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords );

/**
 * Shifts a field element to the right by one bit.
 *
 * \param[in,out] a Field element to shift.
 * \param[in] lenWords Length of field element.
 */
void
EscFeArith_ShiftRight(
    EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords );

/**
 * Adds two field elements under modulus, c = a + b mod p.
 *
 * Field Element c and one of the two operands (a or b) can point to the same location (aliased).
 *
 * \param[out] c Resulting field element.
 * \param[in] a Summand a.
 * \param[in] b Summand b.
 * \param[in] fGP Underlying field (includes modulus p).
 * \param[in] lenWords Length of both field elements.
 */
void
EscFeArith_ModularAdd(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords );

/**
 * Subtracts two field elements under modulus c = a - b mod p.
 *
 * Field Element c and one of the two operands (a or b) can point to the same location (aliased).
 *
 * \param[out] c Resulting field element.
 * \param[in] a Minuend a.
 * \param[in] b subtrahend b.
 * \param[in] fGP Underlying field (includes modulus p).
 * \param[in] lenWords Length of both field elements.
 */
void
EscFeArith_ModularSub(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords );

/**
 * Reduce a field element z with modulus p using Barrett Reduction, r = z mod p
 *
 * \param[out] r Resulting field element.
 * \param[in] z Long field element to reduce
 * \param[in] fGP Underlying field (includes modulus p).
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_ReduceBarrett(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP,
    const EscFeArith_SizeT* curveSize );

/**
 * Multiplies two field elements under modulus p (prime of the ECC domain parameters), c = a * b mod p.
 *
 * Field Element c and the two operands (a and/or b) can point to the same location (aliased).
 *
 * \param[out] c Resulting field element.
 * \param[in] a Field element a.
 * \param[in] b Field element b.
 * \param[in] modulus Used modulus field. The prime of the domain parameters.
 * \param[in] curveId Curve ID of used curve.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_MultiplyModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize );

/**
 * Square a field element under modulus p (prime of the ECC domain parameters), c = a * a mod p.
 *
 * Resulting field Element c and the operand a can point to the same location (aliased).
 *
 * \param[out] c Resulting field element.
 * \param[in] a Field element a.
 * \param[in] modulus Used modulus field. The prime of the domain parameters.
 * \param[in] curveId Curve ID of used curve.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_SquareModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize );


#if ((EscEcc_ECDSA_ENABLED == 1) || (EscEcc_CURVE_ED25519_ENABLED == 1) )
/**
 * Multiplies two field elements under modulus n (base point order of the ECC domain parameters), c = a * b mod n.
 *
 * Field Element c and the two operands (a and/or b) can point to the same location (aliased).
 *
 * \param[out] c Resulting field element.
 * \param[in] a Field element a.
 * \param[in] b Field element b.
 * \param[in] modulus Used modulus field. The base point order of the domain parameters.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_MultiplyModN(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* modulus,
    const EscFeArith_SizeT* curveSize );
#endif


#if (EscEcc_USE_SLIDING_WINDOW == 1) || (EscFeArith_ENABLE_SHAMIRS_TRICK == 1)
/**
 * Checks the given bit in a field element for zero.
 *
 * \param[in] c Field element.
 * \param[in] index Bit to check.
 *
 * \retval TRUE if the bit index of the field element c is set.
 * \retval FALSE if the bit index of the field element c is not set.
 */
Esc_BOOL
EscFeArith_isBitSet(
    const EscFeArith_FieldElementT* c,
    Esc_SINT16 index );
#endif


#if (EscEcc_CURVE_ED25519_ENABLED == 1)
/**
 * Computes the power of a field element by the given exponent. c = a^e mod p.
 *
 * Uses time variant Square-And-Multiply algorithm.
 *
 * Field Element c and a can point to the same location (aliased). Exponent must not be 0!
 *
 * \param[out] c Resulting field element.
 * \param[in] a Field element a.
 * \param[in] exponent The exponent e.
 * \param[in] exponentLen Length of the exponent.
 * \param[in] modulus Used modulus field. The prime of the domain parameters.
 * \param[in] curveId Curve ID of used curve.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_PowModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 exponent[],
    Esc_UINT32 exponentLen,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize );


/**
 * Modular inversion of a field element.
 *
 * Field Elements c and a can point to the same location (aliased).
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] c Resulting field element.
 * \param[in]  a Input field element. Must not be 0, and smaller than the prime of fGP.
 * \param[in]  fGP Used field.
 * \param[in]  lenWords Length of used words in the field elements.
 */
void
EscFeArith_ModularInvert(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords );


/**
 * Converts big endian byte array to a field element
 *
 * \param[in] input Big endian byte array.
 * \param[in] inputLen Length of byte array.
 * \param[out] output Resulting long FE.
 * \param[in] curveSize Curve sizes.
 */
void
EscFeArith_LongFromUint8(
    const Esc_UINT8 input[],
    Esc_UINT32 inputLen,
    EscFeArith_FieldElementLongT* output,
    const EscFeArith_SizeT* curveSize );


/**
 * Swap the endianness of a field element.
 * Input array must not point to the output array!
 *
 * \param[out] output Byte array with swapped endianness.
 * \param[in] input Byte array which will be swapped.
 * \param[in] inputLen Length of byte arrays.
 */
void
EscFeArith_SwapEndiannessUint8(
    Esc_UINT8 output[],
    const Esc_UINT8 input[],
    Esc_UINT32 inputLen );

#endif /* EscEcc_CURVE_ED25519_ENABLED */


/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif
