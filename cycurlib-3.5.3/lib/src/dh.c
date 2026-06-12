/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Diffie Hellman key exchange

   $Rev: 2149 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "dh.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#if EscDh_USE_SLIDING_WINDOW == 1
/** Number of precomputed elements for the sliding window algorithm */
#   define EscDh_NUM_WINDOW_ELEMENTS ( (Esc_UINT16)( (Esc_UINT16)1U << (EscDh_WINDOW_SIZE - 1U) ) )
#endif
/***************************************************************
Extracts the high part of FWORD w and returns it as a FWORD
 ***************************************************************/
#define EscDh_HI_FWORD( w ) ( ( (w) >> EscDh_DH_BASE ) & EscDh_MAX_VAL )

/***************************************************************
Extracts the high part of FWORD w and returns it as a HWORD
 ***************************************************************/
#define EscDh_HI_HWORD( w ) ( (EscDh_HWORD)( ( (w) >> EscDh_DH_BASE ) & EscDh_MAX_VAL ) )

/***************************************************************
Extracts the low part of FWORD w and returns it as a FWORD
 ***************************************************************/
#define EscDh_LO_FWORD( w ) ( (w) & EscDh_MAX_VAL )

/***************************************************************
Extracts the low part of FWORD w and returns it as a HWORD
 ***************************************************************/
#define EscDh_LO_HWORD( w ) ( (EscDh_HWORD)( (w) & EscDh_MAX_VAL ) )

/***************************************************************
Return min(x,y)
 ***************************************************************/
#define EscDh_MIN( x, y ) ( ( (x) < (y) ) ? (x) : (y) )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/* Multiplication result field element. */
typedef struct
{
    EscDh_HWORD words[EscDh_DH_SIZE_WORDS_LONG_MAX];
    /* No carry needed */
} EscDh_FieldElementLongT;

typedef struct
{
    /** Data to calculate c = x^e mod m */

    /** Multiplication result */
    EscDh_FieldElementLongT* c;

    /** Modulus */
    const EscDh_FieldElementT* m;

    /** x */
    EscDh_FieldElementT* x;
} EscDh_MultiplyDataT;

/**
 * DH Key Size struct
 * holding the key size pre-calculated in bits, bytes, words, and longwords
 */
typedef struct
{
    /** Size of tested DH modulus in bits */
    Esc_UINT16 bits;
    /** Size of tested DH modulus in bytes */
    Esc_UINT16 bytes;
    /** Size of tested DH modulus in words */
    Esc_UINT16 words;
    /** Size of tested DH modulus in longwords/doublewords */
    Esc_UINT16 wordsLong;
} EscDh_KeySizeT;

typedef struct
{
    /** Modulus */
    EscDh_FieldElementT mod;
    /** negative inverse of mod[0] */
    EscDh_HWORD m;
} EscDh_MontGomElementT;


/********************** Assignment Functions *******************************/

/**
 * Convert a byte array (big endian) into a field element (little endian word array).
 *
 * \param[out]  dest    The converted field element.
 * \param[in]   source  The buffer holding the value as byte array.
 * \param[in]   lenByte The length of the source buffer in bytes.
 */
static void
EscDhFe_FromBytesBE(
    EscDh_FieldElementT* dest,
    const Esc_UINT8 source[],
    const Esc_UINT16 lenByte);

/**
 * Convert a field element (little endian word array) into a byte array (big endian).
 *
 * \param[out]  dest        The converted byte array.
 * \param[in]   source      The field element to be converted.
 * \param[in]   maxLength   The length of the buffer in dest.
 * \param[out]  length      The number of bytes written into dest.
 */
static void
EscDhFe_ToBytesBE(
    Esc_UINT8 dest[],
    const EscDh_FieldElementT* source,
    Esc_UINT16 maxLength,
    Esc_UINT16 *length);

/**
 * Assign long element src to element dst.
 *
 * \param[out]  dst         The target element dst.
 * \param[in]   src         The source long element src.
 * \param[in]   wordSize    Length of the field elements in words..
 */
static void
EscDhFe_FromLongFe(
    EscDh_FieldElementT* dst,
    const EscDh_FieldElementLongT* src,
    const Esc_UINT16 wordSize );

/**
 * Compare if a given field element equals a single word (i.e. the least significant
 * word of matches the given word and the remaining words are all zero).
 *
 * \param[in]   a           Field element to compare.
 * \param[in]   value       Word to compare field element with.
 * \param[in]   wordSize    Length of the field element in words..
 */
static Esc_BOOL
EscDhFe_IsEqualToWord(
    const EscDh_FieldElementT* a,
    const EscDh_HWORD value,
    const Esc_UINT16 wordSize );

/**
 * Assign element src to element dst.
 *
 * \param[in]   dst         Destination of assignment.
 * \param[in]   src         Source of assignment.
 * \param[in]   wordSize    Length of the field elements in words..
 */
static void
EscDhFe_Assign(
    EscDh_FieldElementT* dst,
    const EscDh_FieldElementT* src,
    const Esc_UINT16 wordSize );

/********************** Basic Math *****************************************/

/**
 * Modular reduction. Implemented from (HAC, Algorithm 14.20)
 * c := c mod m
 * m must be != 0
 *
 * \param[in, out]  pm          Parameters and result of the modular multiplication.
 * \param[in]       wordSize    Length of the field elements in words..
 */
static void
EscDhFe_ModularReduction(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/**
 * Compare two field elements a and b.
 *
 * \param[in]   a       First field element to compare.
 * \param[in]   b       Second field element to compare.
 *
 * \return +1: a > b
 * \return -1: a < b
 * \return  0: a == b
 */
static Esc_SINT8
EscDhFe_AbsoluteCompare(
    const EscDh_FieldElementT* a,
    const EscDh_FieldElementT* b,
    const Esc_UINT16 wordSize );

/**
 * Check whether a bit is set in a field element.
 *
 * \param[in]   e           The field element whose bit shall be checked.
 * \param[in]   thebit      Index of the bit. Bit 0 is the MSB!
 * \param[in]   wordSize    Length of the field elements in words..
 *
 * \return TRUE if the bit is set, FALSE otherwise.
 */
static Esc_BOOL
EscDhFe_IsBitSet(
    const EscDh_FieldElementT* e,
    Esc_UINT16 thebit,
    const Esc_UINT16 wordSize  );

/**
 * Compute the power of a field element by the given exponent.
 * x = x^e mod m
 *
 * \param[in, out]  pm      Base/modulus for power calculation.
 * \param[in]       e       Exponent. Must not be 0!
 * \param[in]       keySize Struct containing the key size in bits, bytes, words and long words.
 */
static void
EscDhFe_BigPow(
    const EscDh_MultiplyDataT* pm,
    const EscDh_FieldElementT* e,
    const EscDh_KeySizeT* keySize  );

/**
 * Fill a struct containing the key size in bits, bytes, words and long words.
 *
 * \param[in]   lenBits The key size in bits.
 * \param[out]  keySize The resulting structs containing sizes derived from lenBits.
 */
static void
EscDhAssignKeyStruct(
    const Esc_UINT16 lenBits,
    EscDh_KeySizeT* keySize);

/**
 * Montgomery Multiplication w/ CIOS algorithm, x := x * y mod m
 * see Analyzing and Comparing Montgomery Multiplication Algorithms, Cetin Kaya Koc and Tolga Acar
 *
 * \param[in, out]  x           First operand of multiplication. The result is stored here.
 * \param[in]       y           Second operand of multiplication.
 * \param[in]       mg          Pre-computed montgomery data related to the modulus.
 * \param[in]       wordSize    Length of the field elements in words..
 **/
static void
EscDhFe_MontGom(
    EscDh_FieldElementT* x,
    const EscDh_FieldElementT* y,
    const EscDh_MontGomElementT* mg,
    const Esc_UINT16 wordSize );

/**
 * Pre-computations for Montgomery multiplication.
 *
 * \param[in]   pm          The DH modulus pointed to by pm->m.
 * \param[out]  mg          Initialized Montgomery Element.
 * \param[in]   wordSize    Length of the field elements in words..
 */
static void
EscDh_MontGom_Init(
    const EscDh_MultiplyDataT* pm,
    EscDh_MontGomElementT* mg,
    const Esc_UINT16 wordSize );

/**
 * Modular multiplication without Montgomery.
 * c = c * x mod m
 *
 * \param[in, out]      pm          Parameters and result of the modular multiplication.
 * \param[in]           wordSize    Length of the field elements in words..
 */
static void
EscDhFe_Multiply(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/**
 * Multiply two field elements c := c * x.
 * We use the integer multiplication algorithm from Menzenes, et. al.
 * "Elliptic Curve Cryptography". Algorithm 2.9. The algorithm is endianness independent.
 *
 * \param[in, out]      pm          Parameters and result of the multiplication.
 * \param[in]           wordSize    Length of the field elements in words..
 */
static void
EscDhFe_MultiplyClassically(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  );

/********************** Diffie-Hellman internal functions ******************/

/**
 * This function validates a public key.
 *
 * Check, that:
 * - publicKey lies within the interval [2,p-1]
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[in] publicKey Public key.
 *
 * \return Esc_NO_ERROR if the public key is valid.
 * \return Esc_INVALID_PUBLIC_KEY if the public key is invalid.
 */
static Esc_ERROR
EscDh_PublicKeyValidation(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PublicKeyT* publicKey );

/**
 * This function validates a private key.
 *
 * Check that:
 * - publicKey is larger than 1
 *
 * \return Esc_NO_ERROR if the private key is valid.
 * \return Esc_INVALID_PRIVATE_KEY if the private key is invalid.
 */
static Esc_ERROR
EscDh_PrivateKeyValidation(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PrivateKeyT* privateKey );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static void
EscDhFe_FromBytesBE(
    EscDh_FieldElementT* dest,
    const Esc_UINT8 source[],
    const Esc_UINT16 lenByte)
{
    Esc_UINT16 i;
    EscDh_HWORD* dstArray = &dest->words[0U];
    EscDh_HWORD word;
    Esc_UINT16 wordIndex = 0U;
    Esc_UINT16 offset = lenByte;    /* offset points one byte BEHIND the buffer! */

    /* Convert full words */
    while (offset >= EscDh_WORD_SIZE)
    {
        word = (EscDh_HWORD) 0U;
        for (i = 0U; i < EscDh_WORD_SIZE; i++)
        {
            word <<= 8U;
            word |= source[(offset - EscDh_WORD_SIZE) + i];
        }

        dstArray[wordIndex] = word;
        wordIndex++;

        offset -= (Esc_UINT16)EscDh_WORD_SIZE;
    }

    /* Convert last incomplete word */
    if (offset > 0U)
    {
        word = (EscDh_HWORD) 0U;
        for (i = 0U; i < offset; i++)
        {
            word <<= 8U;
            word |= source[i];
        }

        dstArray[wordIndex] = word;
        wordIndex++;
    }

    for (; wordIndex < EscDh_DH_SIZE_WORDS_MAX; wordIndex++)
    {
        dstArray[wordIndex] = (EscDh_HWORD) 0U;
    }
}

static void
EscDhFe_ToBytesBE(
    Esc_UINT8 dest[],
    const EscDh_FieldElementT* source,
    Esc_UINT16 maxLength,
    Esc_UINT16 *length)
{
    Esc_UINT16 i;
    Esc_UINT16 len;
    EscDh_HWORD v = 0U;

    /* Skip leading zero bytes (determine actual length) */
    for (len = maxLength; len > 0U; len--)
    {
        Esc_UINT16 offset = len - 1U;

        v = source->words[offset >> (EscDh_WORD_SIZE / 2U)];
        v >>= ( (Esc_UINT16)( (offset & (EscDh_WORD_SIZE - 1U)) << 3U ) ) & 0xFFU;

        if ( ((Esc_UINT8 )v ) != 0U )
        {
            break;
        }
    }

    /* Convert from field element to bytes */
    for (i = 0U; i < len; i++)
    {
        v = source->words[i >> (EscDh_WORD_SIZE / 2U)];
        v >>= ( (Esc_UINT16)( ( i & (EscDh_WORD_SIZE - 1U) ) << 3U ) ) & 0xFFU;
        dest[(len - 1U) - i] = (Esc_UINT8) v;
    }

    /* Zeroize v */
    Esc_CLEAR_LOCAL_VAR(v);

    *length = len;
}

static void
EscDhFe_FromLongFe(
    EscDh_FieldElementT* dst,
    const EscDh_FieldElementLongT* src,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;

    /** The value fits into dst */
    Esc_ASSERT( src->words[wordSize] == 0U );

    /* copy src */
    for (i = 0U; i < wordSize; i++)
    {
        dst->words[i] = src->words[i];
    }
    /* Zeroize remaining words */
    for (; i < EscDh_DH_SIZE_WORDS_MAX; i++)
    {
        dst->words[i] = 0U;
    }
}

static Esc_BOOL
EscDhFe_IsEqualToWord(
    const EscDh_FieldElementT* a,
    const EscDh_HWORD value,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;
    Esc_BOOL isEqual = TRUE;

    if (a->words[0] != value)
    {
        isEqual = FALSE;
    }
    else
    {
        /* for i from 0 to t do a[i] =? 0 */
        for (i = 1U; i < wordSize; i++)
        {
            if (a->words[i] != 0U)
            {
                /* not zero */
                isEqual = FALSE;
                break;
            }
        }
    }

    return isEqual;
}

static void
EscDhFe_Assign(
    EscDh_FieldElementT* dst,
    const EscDh_FieldElementT* src,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;
    /* copy src */
    for (i = 0U; i < wordSize; i++)
    {
        dst->words[i] = src->words[i];
    }
    /* Zeroize remaining words */
    for (; i < EscDh_DH_SIZE_WORDS_MAX; i++)
    {
        dst->words[i] = 0U;
    }
}

static void
EscDhFe_ModularReduction(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    Esc_SINT16 mwords_msb;
    Esc_SINT16 i;
    Esc_UINT16 j;
    EscDh_HWORD q;
    EscDh_HWORD carry;
    EscDh_FWORD ciAndCmin1;
    EscDh_HWORD* cwords;
    const EscDh_HWORD* mwords;
    Esc_BOOL finished;

    cwords = pm->c->words;
    mwords = pm->m->words;
    mwords_msb = (Esc_SINT16)wordSize - 1;
    while ( (mwords_msb > 0) && (mwords[mwords_msb] == 0U) )
    {
        mwords_msb--;
    }
    Esc_ASSERT( mwords_msb >= 0 );
    Esc_ASSERT( wordSize > 1 );

    /* We can safely skip step 2. of the algorithm, since the while condition can only be
     * triggered if message > (mod-1)^2 , which can not occur in our DH implementation. */

    for (i = ( (Esc_SINT16)(2 * (Esc_SINT16)wordSize) - 1 ); i > mwords_msb; i--)
    {
        /* if x_i == m_k-1 then q=b-1 else q=(x_i*b + x_i-1) div m_k-1 */
        /* Calc (x_i*b + x_i-1) already, we need it later too */
        ciAndCmin1 = ( (EscDh_FWORD)cwords[i] << EscDh_DH_BASE ) | ( (EscDh_FWORD)cwords[i - 1] );

        if (cwords[i] == mwords[mwords_msb])
        {
            q = (EscDh_HWORD)EscDh_MAX_VAL;
        }
        else
        {
            q = (EscDh_HWORD)( (ciAndCmin1) / (EscDh_FWORD)mwords[mwords_msb] );
        }

        /* while q*(m[k-1] * b + m[k-2]) > x[i]*b^2 + x[i-1] *b + x[i-2] do q--; */
        finished = FALSE;
        while (finished == FALSE)
        {
            EscDh_FWORD qcHi;
            EscDh_FWORD qcLo;

            qcHi = (EscDh_FWORD)q * (EscDh_FWORD)mwords[mwords_msb];
            if (mwords_msb > 0)
            {
                qcLo = (EscDh_FWORD)q * (EscDh_FWORD)mwords[mwords_msb - 1];
            }
            else
            {
                qcLo = 0U;
            }
            qcHi += EscDh_HI_FWORD( qcLo );

            /* qcHi contains the upper two bytes of q*(m[k-1] * b + m[k-2]),
               ciAndCmin1 the upper two bytes of x[i]*b^2 + x[i-1] */
            if (qcHi < ciAndCmin1)
            {
                /* q*(m[k-1] * b + m[k-2]) < x[i]*b^2 + x[i-1] *b + x[i-2] */
                finished = TRUE;
            }
            else if ( (qcHi == ciAndCmin1) && (EscDh_LO_HWORD( qcLo ) <= cwords[i - 2]) )
            {
                /* q*(m[k-1] * b + m[k-2]) <= x[i]*b^2 + x[i-1] *b + x[i-2] */
                finished = TRUE;
            }
            else
            {
                q--;
            }
        }

        /* x = x-q*m*b^(i-k) */
        carry = 0U;
        for (j = 0U; j <= (Esc_UINT16)mwords_msb; j++)
        {
            EscDh_FWORD xhi;
            Esc_UINT16 cIdx;

            xhi = ( (EscDh_FWORD)q * (EscDh_FWORD)mwords[j] ) + (EscDh_FWORD)carry;
            carry = EscDh_HI_HWORD( xhi );
            cIdx = (Esc_UINT16)( ( ( (Esc_UINT16)i - (Esc_UINT16)mwords_msb ) - 1U ) + j );
            xhi = (EscDh_FWORD)cwords[cIdx] - EscDh_LO_FWORD( xhi );
            cwords[cIdx] = EscDh_LO_HWORD( xhi );

            if (EscDh_HI_FWORD( xhi ) != 0U)
            {
                carry++;
            }
        }

        /* if (x<0) then x=x+m*b^(i-k) */
        if (cwords[i] < carry)
        {
            carry = 0U;

            for (j = 0U; j <= (Esc_UINT16)mwords_msb; j++)
            {
                EscDh_FWORD xhi;
                Esc_UINT16 cIdx;

                cIdx = (Esc_UINT16)( ( ( (Esc_UINT16)i - (Esc_UINT16)mwords_msb ) - 1U ) + j );
                xhi = (EscDh_FWORD)cwords[cIdx] + ( (EscDh_FWORD)mwords[j] ) + (EscDh_FWORD)carry;
                carry = EscDh_HI_HWORD( xhi );
                cwords[cIdx] = EscDh_LO_HWORD( xhi );
            }
        }
        cwords[i] = 0U;
    }
}

static Esc_BOOL
EscDhFe_IsBitSet(
    const EscDh_FieldElementT* e,
    Esc_UINT16 thebit,
    const Esc_UINT16 wordSize  )
{
    Esc_BOOL isSet;
    Esc_UINT16 wordIndex = (wordSize - 1U) - (thebit / EscDh_DH_BASE);
    EscDh_HWORD mask = ( (EscDh_HWORD)1UL << ( (EscDh_HWORD)(EscDh_DH_BASE - 1U) - ((EscDh_HWORD)thebit % EscDh_DH_BASE) ) );

    if ( (( e->words[ wordIndex ]) & mask) != (EscDh_HWORD) 0U )
    {
        isSet = TRUE;
    }
    else
    {
        isSet = FALSE;
    }

    return isSet;
}

static Esc_SINT8
EscDhFe_AbsoluteCompare(
    const EscDh_FieldElementT* a,
    const EscDh_FieldElementT* b,
    const Esc_UINT16 wordSize )
{
    Esc_SINT16 i;
    Esc_SINT8 compResult = 0;

    /* compare the corresponding words until a different word pair is found */
    for (i = (Esc_SINT16)( (Esc_SINT16)wordSize - 1 ); (compResult == 0) && (i >= 0); i--)
    {
        /* next lower pair */
        if (a->words[i] > b->words[i])
        {
            /* a > b */
            compResult = 1;
        }
        else if (a->words[i] < b->words[i])
        {
            /* a < b */
            compResult = -1;
        }
        else
        {
            /* do nothing */
        }
    }

    return compResult;
}

#if EscDh_USE_SLIDING_WINDOW == 1

static void
EscDhFe_BigPow(
    const EscDh_MultiplyDataT* pm,
    const EscDh_FieldElementT* e,
    const EscDh_KeySizeT* keySize )
{
    EscDh_FieldElementT x_, y_, one, x_2;
    EscDh_MontGomElementT mg;
    Esc_UINT16 thebit = 0U;
    Esc_UINT16 i, n, windowsize, j;
    Esc_UINT16 exponent;
    Esc_UINT16 bitSize = keySize->bits;
    Esc_UINT16 wordSize = keySize->words;
    Esc_UINT16 wordLongSize = keySize->wordsLong;

    /* array w/ size 2^k_m */
    EscDh_FieldElementT fe_array[EscDh_NUM_WINDOW_ELEMENTS];
    /* build word one */
    for (i = 1U; i < wordSize; i++)
    {
        one.words[i] = 0U;
    }
    one.words[0] = 1U;

    /* build R = 2^mod_bit_size */
    for (i = 0U; i < wordLongSize; i++)
    {
        pm->c->words[i] = 0U;
    }
    pm->c->words[wordSize] = 1U;

    EscDhFe_ModularReduction( pm, wordSize );
    /* x_ = R mod n */
    EscDhFe_FromLongFe( &x_, pm->c, wordSize );
    /* pm.c = c * x mod m  =  R * x mod m */
    EscDhFe_Multiply( pm, wordSize );
    /* y_ = x * R */
    EscDhFe_FromLongFe( &y_, pm->c, wordSize );

    /* Initialize Montgomery variables */
    EscDh_MontGom_Init( pm, &mg, wordSize );

    EscDhFe_Assign( &fe_array[0], &y_, wordSize );
    EscDhFe_MontGom( &y_, &y_, &mg, wordSize );
    EscDhFe_Assign( &x_2, &fe_array[0], wordSize );
    /* precomputation - i < 2^k_m */
    for (i = 1U; i < EscDh_NUM_WINDOW_ELEMENTS; i++)
    {
        EscDhFe_MontGom( &x_2, &y_, &mg, wordSize );
        EscDhFe_Assign( &fe_array[i], &x_2, wordSize );
    }
    EscDhFe_Assign( &x_, &fe_array[0], wordSize );
    while (EscDhFe_IsBitSet( e, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }
    thebit++;

    while (thebit < bitSize)
    {
        /* if Exponent = 0 double only */
        if (EscDhFe_IsBitSet( e, thebit, wordSize ) == FALSE)
        {
            EscDhFe_MontGom( &x_, &x_, &mg, wordSize );
            thebit++;
        }
        else
        {
            /* build window */
            exponent = 0U;
            n = (Esc_UINT16)(EscDh_WINDOW_SIZE - 1U);
            windowsize = EscDh_WINDOW_SIZE;
            for (j = thebit; ( j < (thebit + EscDh_WINDOW_SIZE) ) && (j < bitSize); j++)
            {
                /* build temporary exponent */
                if ( EscDhFe_IsBitSet( e, j, wordSize ) )
                {
                    exponent |= (Esc_UINT16)( 1UL << n );
                }
                n--;
            }
            thebit += EscDh_WINDOW_SIZE;
            /* make window odd and adjust i, reduce window size */
            while ( (exponent % 2U) == 0U )
            {
                exponent = exponent >> 1U;
                thebit--;
                windowsize--;
            }

            /* double */
            for (j = 0U; j < windowsize; j++)
            {
                EscDhFe_MontGom( &x_, &x_, &mg, wordSize );
            }

            /* Assert that exponent/2 is within bounds of fe_array */
            Esc_ASSERT( (exponent / 2) < EscDh_NUM_WINDOW_ELEMENTS );

            /* add */
            EscDhFe_MontGom( &x_, &fe_array[(Esc_UINT16)(exponent / 2U)], &mg, wordSize );
        }
    }
    EscDhFe_MontGom( &x_, &one, &mg, wordSize );
    EscDhFe_Assign( pm->x, &x_, wordSize );
}

#else /* EscDh_USE_SLIDING_WINDOW */

static void
EscDhFe_BigPow(
    const EscDh_MultiplyDataT* pm,
    const EscDh_FieldElementT* e,
    const EscDh_KeySizeT* keySize )
{
    EscDh_FieldElementT x_, y_, one;
    EscDh_MontGomElementT mg;
    Esc_UINT16 thebit = 0U;
    Esc_UINT16 i;
    Esc_UINT16 bitSize = keySize->bits;
    Esc_UINT16 wordSize = keySize->words;
    Esc_UINT16 wordLongSize = keySize->wordsLong;

    /* build word one */
    for (i = 1U; i < wordSize; i++)
    {
        one.words[i] = 0U;
    }
    one.words[0] = 1U;

    /* build R = 2^mod_bit_size */
    for (i = 0U; i < wordLongSize; i++)
    {
        pm->c->words[i] = 0U;
    }
    pm->c->words[wordSize] = 1U;

    EscDhFe_ModularReduction( pm, wordSize );
    /* x_ = R mod n */
    EscDhFe_FromLongFe( &x_, pm->c, wordSize );
    /* pm.c = c * x mod m  =  R * x mod m */
    EscDhFe_Multiply( pm, wordSize );
    /* y_ = x * R */
    EscDhFe_FromLongFe( &y_, pm->c, wordSize );

    /* Initialize Montgomery variables */
    EscDh_MontGom_Init( pm, &mg, wordSize );

    /* find first bit in exponent != 0 */
    while (EscDhFe_IsBitSet( e, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }

    /* square and multiply */
    while (thebit < bitSize)
    {
        /* c := c * c mod m */
        EscDhFe_MontGom( &x_, &x_, &mg, wordSize );

        /* if e_i = 1 then c := c * x mod m */
        if ( EscDhFe_IsBitSet( e, thebit, wordSize ) != FALSE )
        {
            /* c := c * x mod m */
            EscDhFe_MontGom( &x_, &y_, &mg, wordSize );
        }
        thebit++;
    }
    EscDhFe_MontGom( &x_, &one, &mg, wordSize );
    /* x := c. We could actually copy the result directly into the
       output byte array, but stick to this for maintainability. */
    EscDhFe_Assign( pm->x, &x_, wordSize );
}

#endif

static void
EscDhAssignKeyStruct(
    const Esc_UINT16 lenBits,
    EscDh_KeySizeT* keySize)
{
    keySize->bits = lenBits;
    keySize->bytes = (Esc_UINT16)EscDh_KEY_BYTES_FROMBITS((Esc_UINT32)lenBits);
    keySize->words = (Esc_UINT16)EscDh_DH_SIZE_WORDS_FROMBITS((Esc_UINT32)lenBits);
    keySize->wordsLong = (Esc_UINT16)EscDh_DH_SIZE_WORDS_LONG_FROMBITS((Esc_UINT32)lenBits);
}

static void
EscDh_MontGom_Init(
    const EscDh_MultiplyDataT* pm,
    EscDh_MontGomElementT* mg,
    const Esc_UINT16 wordSize )
{
    Esc_UINT8 i;
    EscDh_HWORD y[EscDh_DH_BASE + 1U];
    /* assign modulus */
    EscDhFe_Assign( &mg->mod, pm->m, wordSize );
    mg->m = pm->m->words[0U];
    /* calculate negative inverse of least significant word of the modulus mod 2^word_size
       see EUROCRYPT 90, Lecture Notes in ComputerScience, No. 473, pages 230-244 */
    y[1] = 1U;
    for (i = 2U; i <= EscDh_DH_BASE; i++)
    {
        if (i != EscDh_DH_BASE)
        {
            y[0U] = (EscDh_HWORD)( (mg->m * y[i - 1U]) % ( (EscDh_HWORD)( 1UL << i ) ) );
        }
        else
        {
            y[0U] = (EscDh_HWORD)(mg->m * y[i - 1U]);
        }

        if ( y[0U] < (EscDh_HWORD)( 1UL << (i - 1U) ) )
        {
            y[i] = y[i - 1U];
        }
        else
        {
            y[i] = y[i - 1U] + ( (EscDh_HWORD)( 1UL << (i - 1U) ) );
        }
    }
    /* calculate -y[EscDh_DH_BASE] mod 2^WORD_SIZE */
    mg->m = (EscDh_HWORD) ~y[EscDh_DH_BASE];
    mg->m++;
}


static void
EscDhFe_MontGom(
    EscDh_FieldElementT* x,
    const EscDh_FieldElementT* y,
    const EscDh_MontGomElementT* mg,
    const Esc_UINT16 wordSize )
{
    /* Initialization */
    EscDh_HWORD i, j, n, uv_tmp;
    EscDh_FWORD uv;
    EscDh_HWORD c[EscDh_DH_SIZE_WORDS_MAX + 2U];
    EscDh_HWORD t[EscDh_DH_SIZE_WORDS_MAX + 2U];

    /* zero c array */
    for (i = 0U; i < ( EscDh_DH_SIZE_WORDS_MAX + 2U); i++)
    {
        c[i] = 0U;
    }

    /* CIOS algorithm */
    for (i = 0U; i < wordSize; i++)
    {
        uv = 0U;

        for (j = 0U; j < wordSize; j++)
        {
            uv_tmp = EscDh_HI_HWORD( uv );
            uv = (EscDh_FWORD)uv_tmp + ( (EscDh_FWORD)x->words[j] * (EscDh_FWORD)y->words[i] ) + (EscDh_FWORD)c[j];
            c[j] = EscDh_LO_HWORD( uv );
        }

        uv_tmp = EscDh_HI_HWORD( uv );
        uv = (EscDh_FWORD)c[wordSize] + (EscDh_FWORD)uv_tmp;
        c[wordSize] = EscDh_LO_HWORD( uv );
        c[wordSize + 1U] = EscDh_HI_HWORD( uv );
        n = (EscDh_HWORD)(c[0U] * mg->m);

        uv = (EscDh_FWORD)c[0U] + ( (EscDh_FWORD)n * (EscDh_FWORD)mg->mod.words[0U] );
        for (j = 1U; j < wordSize; j++)
        {
            uv_tmp = EscDh_HI_HWORD( uv );
            uv = (EscDh_FWORD)uv_tmp + ( (EscDh_FWORD)n * (EscDh_FWORD)mg->mod.words[j] ) + (EscDh_FWORD)c[j];
            c[j - 1U] = EscDh_LO_HWORD( uv );
        }

        uv_tmp = EscDh_HI_HWORD( uv );
        uv = (EscDh_FWORD)c[wordSize] + (EscDh_FWORD)uv_tmp;
        c[wordSize - 1U] = EscDh_LO_HWORD( uv );
        c[wordSize] = c[wordSize + 1U] + EscDh_HI_HWORD( uv );
    }

    /* third step of Montgomery, subtract modulus if necessary */
    uv = 0U;
    for (i = 0U; i < wordSize; i++)
    {
        /* subtract mod and save carry in highword of uv (tricky one ;) ) */
        uv_tmp = (EscDh_HWORD)( (EscDh_HWORD)( ~EscDh_HI_HWORD( uv ) ) + 1U );
        uv = ( (EscDh_FWORD)c[i] - (EscDh_FWORD)mg->mod.words[i] ) - (EscDh_FWORD)uv_tmp;
        t[i] = EscDh_LO_HWORD( uv );
    }
    /* last carry */
    uv_tmp = (EscDh_HWORD)( (EscDh_HWORD)( ~EscDh_HI_HWORD( uv ) ) + 1U );
    uv = (EscDh_FWORD)c[wordSize] - (EscDh_FWORD)uv_tmp;
    t[wordSize] = EscDh_LO_HWORD( uv );

    /* c > mod ? return t:return c */
    if (EscDh_HI_HWORD( uv ) == 0U)
    {
        for (i = 0U; i < wordSize; i++)
        {
            x->words[i] = t[i];
        }
    }
    else
    {
        for (i = 0U; i < wordSize; i++)
        {
            x->words[i] = c[i];
        }
    }
}

static void
EscDhFe_Multiply(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    EscDhFe_MultiplyClassically( pm, wordSize );

    /* classical modular reduction */
    EscDhFe_ModularReduction( pm, wordSize );
}

static void
EscDhFe_MultiplyClassically(
    const EscDh_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    EscDh_HWORD i;
    EscDh_HWORD j;
    EscDh_HWORD min;
    EscDh_FWORD t;
    EscDh_HWORD b_0, a_0;
    EscDh_FWORD uv_t;
    EscDh_FWORD uv;

    EscDh_FieldElementT inC;
    const EscDh_HWORD* awords;
    const EscDh_HWORD* bwords;
    EscDh_HWORD* cwords;

    awords = inC.words;
    bwords = pm->x->words;
    cwords = pm->c->words;

    uv_t = 0U;
    t = 0U;

    /* 1.) make a copy of c, clear c. inC:= c; c := 0 */
    Esc_ASSERT( cwords[wordSize] == 0U );      /* single precision */
    EscDhFe_FromLongFe( &inC, pm->c, wordSize );

    for (i = 0U; i < (2U * (EscDh_HWORD)wordSize ); i++)
    {
        b_0 = EscDh_MIN( ( (EscDh_HWORD)wordSize - 1U), i );
        a_0 = i - b_0;
        min = EscDh_MIN( (EscDh_HWORD)(wordSize - a_0), (b_0 + 1U) );
        for (j = 0U; j < min; j++)
        {
            /* a[a_o +j] * b[b_o - j] */
            uv = (EscDh_FWORD)awords[a_0 + j] * (EscDh_FWORD)bwords[b_0 - j];
            /* sum on uv_t */
            uv_t += uv;
            /* if overflow save carry to t */
            if (uv_t < uv)
            {
                t++;
            }
        }

        /* c[i] = v, v = u, u = t, t = 0 */
        cwords[i] = EscDh_LO_HWORD( uv_t );
        uv_t >>= EscDh_DH_BASE;
        uv_t |= t << EscDh_DH_BASE;
        t = 0U;
    }
}

/**
 * This function validates the public key.
 */
static Esc_ERROR
EscDh_PublicKeyValidation(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PublicKeyT* publicKey )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 wordSize = (Esc_UINT16)EscDh_DH_SIZE_WORDS_FROMBYTES(ctx->pLength);

    /* Check that 1 < publicKey < p */

    if ( (EscDhFe_IsEqualToWord(publicKey, (EscDh_HWORD) 0U, wordSize) != FALSE) ||
         (EscDhFe_IsEqualToWord(publicKey, (EscDh_HWORD) 1U, wordSize) != FALSE) )
    {
        returnCode = Esc_INVALID_PUBLIC_KEY;
    }

    if (EscDhFe_AbsoluteCompare(publicKey, &ctx->p, wordSize) != -1)
    {
        returnCode = Esc_INVALID_PUBLIC_KEY;
    }

    return returnCode;
}

static Esc_ERROR
EscDh_PrivateKeyValidation(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PrivateKeyT* privateKey )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 wordSize = (Esc_UINT16)EscDh_DH_SIZE_WORDS_FROMBYTES(ctx->pLength);

    /* Check that 1 < privateKey */

    if ( (EscDhFe_IsEqualToWord(privateKey, (EscDh_HWORD) 0U, wordSize) != FALSE) ||
         (EscDhFe_IsEqualToWord(privateKey, (EscDh_HWORD) 1U, wordSize) != FALSE) )
    {
        returnCode = Esc_INVALID_PRIVATE_KEY;
    }

    return returnCode;
}

/****************************************************************************************
 ****************************************************************************************
 * Below are the public functions
 ****************************************************************************************
 ****************************************************************************************
 */

Esc_ERROR
EscDh_InitDomainParameters(
    EscDh_DomainParametersT* ctx,
    const Esc_UINT8 p[],
    const Esc_UINT16 pLength,
    const Esc_UINT8 g[],
    const Esc_UINT16 gLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (p == Esc_NULL_PTR) || (g == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (pLength > EscDh_KEY_BYTES_MAX) ||
              ( (pLength != 128U) &&  /* 1024 bit */
                (pLength != 256U) &&  /* 2048 bit */
                (pLength != 384U) ) ) /* 3072 bit */
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else if ( (gLength > EscDh_KEY_BYTES_MAX) || (gLength == 0U) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else if ( (p[pLength - 1U] % 2U) == 0U )
    {
        /* p must be prime. This check only tests that it is odd for the following
         * code to work properly.
         */
        returnCode = Esc_INVALID_PARAMETER;
    }
    else if ( (p[0] == 0U) && (p[1] == 0U) )
    {
        /* Our implementation of the modular reduction requires that the most significant
         * word must be non-zero. This is done to skip step 2) of algorithm 14.20 in the HAC
         * safely. The check is based on the first two bytes which become one EscDh_HWORD
         * if Esc_HAS_INT64 is disabled.
         */
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        EscDh_FieldElementT pMinusOne;
        Esc_UINT16 numKeyWords = (Esc_UINT16)EscDh_DH_SIZE_WORDS_FROMBYTES(pLength);

        /* Convert g and p to internal representation (field elements) and select length of q */

        EscDhFe_FromBytesBE(&ctx->p, p, pLength);
        EscDhFe_FromBytesBE(&ctx->g, g, gLength);

        ctx->pLength = pLength;

        /* Verify that 2 <= g < p-1 */

        EscDhFe_Assign(&pMinusOne, &ctx->p, numKeyWords);
        pMinusOne.words[0U] &= (EscDh_HWORD)(~(EscDh_HWORD)1U);

        if ((EscDhFe_IsEqualToWord( &ctx->g, (EscDh_HWORD) 0U, numKeyWords ) == TRUE) ||
            (EscDhFe_IsEqualToWord( &ctx->g, (EscDh_HWORD) 1U, numKeyWords ) == TRUE) ||
            (EscDhFe_AbsoluteCompare( &ctx->g, &pMinusOne, numKeyWords ) != -1) )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    return returnCode;
}

/**
 * This function generates the corresponding public key.
 */
Esc_ERROR
EscDh_KeyGeneration(
    const EscDh_DomainParametersT* ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscDh_PublicKeyT* publicKey,
    EscDh_PrivateKeyT* privateKey )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 random[EscDh_KEY_BYTES_MAX];
    Esc_UINT16 attempts = 0U;
    EscDh_KeySizeT keySize;
    Esc_UINT16 qLength = 0U;

    /* Check parameters and derive a length q for the private key
     * from the length of the modulus
     */

    if ( (ctx == Esc_NULL_PTR) || (prngFunc == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR) || (privateKey == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ctx->pLength == 128U)
    {
        qLength = 20U; /* 160 bit */
    }
    else if (ctx->pLength == 256U)
    {
        qLength = 28U; /* 224 bit */
    }
    else if (ctx->pLength == 384U)
    {
        qLength = 32U; /* 256 bit */
    }
    else
    {
        returnCode = Esc_INTERNAL_FUNCTION_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            /* Generate private key */

            returnCode = prngFunc(prngState, random, qLength);
            if (returnCode == Esc_NO_ERROR)
            {
                /* Convert private key to internal representation. This will also do some
                 * basic checks on the private key.
                 */
                returnCode = EscDh_PrivKeyFromBytes(ctx, privateKey, random, qLength);
            }

            /* Generate public key */

            if (returnCode == Esc_NO_ERROR)
            {
                EscDh_MultiplyDataT mult;
                EscDh_FieldElementLongT mult_value_long;
                EscDh_FieldElementT mult_value;

                EscDhAssignKeyStruct( (Esc_UINT16)(ctx->pLength * 8U), &keySize);

                /* Calculate public key as g ^ privateKey mod p */
                EscDhFe_Assign(&mult_value, &ctx->g, keySize.words);

                mult.c = &mult_value_long;
                mult.m = &ctx->p;
                mult.x = &mult_value;

                EscDhFe_BigPow( &mult, privateKey, &keySize );
                EscDhFe_Assign(publicKey, &mult_value, keySize.words);

                /* Check public key */
                returnCode = EscDh_PublicKeyValidation(ctx, publicKey);
            }

            attempts++;

        } while ( ( (returnCode == Esc_INVALID_PUBLIC_KEY) || /* Recoverable error, try with another random number */
                    (returnCode == Esc_INVALID_PRIVATE_KEY) ) /* Recoverable error, try with another random number */
                  && (attempts < EscDh_GENERATION_ATTEMPTS) );
    }

    /* Map failures due to bogus random numbers to one error code. */
    if ( (returnCode == Esc_INVALID_PUBLIC_KEY) ||
         (returnCode == Esc_INVALID_PRIVATE_KEY) )
    {
        returnCode = Esc_KEY_GENERATION_FAILED;
    }

    return returnCode;
}

/**
 * This function computes the shared secret z based on DH.
 */
Esc_ERROR
EscDh_ComputeSharedSecret(
    const EscDh_DomainParametersT* ctx,
    Esc_UINT8 z[],
    Esc_UINT16 *zLength,
    const EscDh_PublicKeyT* publicKey,
    const EscDh_PrivateKeyT* privateKey )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Check parameters */
    if ( (ctx == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR) || (z == Esc_NULL_PTR) ||
         (privateKey == Esc_NULL_PTR) || (zLength == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PublicKeyValidation(ctx, publicKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PrivateKeyValidation(ctx, privateKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* shared secret z = pk ^ sk mod p */

        EscDh_KeySizeT keySize;
        EscDh_MultiplyDataT mult;
        EscDh_FieldElementLongT mult_value_long;
        EscDh_FieldElementT mult_value;

        EscDhAssignKeyStruct( (Esc_UINT16)(ctx->pLength * 8U), &keySize);

        EscDhFe_Assign(&mult_value, publicKey, keySize.words);

        mult.c = &mult_value_long;
        mult.m = &ctx->p;
        mult.x = &mult_value;

        EscDhFe_BigPow( &mult, privateKey, &keySize );
        EscDhFe_ToBytesBE(z, &mult_value, keySize.bytes, zLength);

        /* Zeroize stack variables */
        Esc_CLEAR_LOCAL_VAR(mult);
        Esc_CLEAR_LOCAL_VAR(mult_value_long);
        Esc_CLEAR_LOCAL_VAR(mult_value);
    }

    return returnCode;
}

Esc_ERROR
EscDh_PrivKeyFromBytes(
    const EscDh_DomainParametersT* ctx,
    EscDh_PrivateKeyT* privateKey,
    const Esc_UINT8 keyBytes[],
    Esc_UINT16 keyBytesLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (privateKey == Esc_NULL_PTR) || (keyBytes == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBytesLength == 0U) || (keyBytesLength > EscDh_KEY_BYTES_MAX) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        EscDhFe_FromBytesBE(privateKey, keyBytes, keyBytesLength);
        returnCode = EscDh_PrivateKeyValidation(ctx, privateKey);
    }

    return returnCode;
}

Esc_ERROR
EscDh_PubKeyFromBytes(
    const EscDh_DomainParametersT* ctx,
    EscDh_PublicKeyT* publicKey,
    const Esc_UINT8 keyBytes[],
    Esc_UINT16 keyBytesLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR) || (keyBytes == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBytesLength == 0U) || (keyBytesLength > ctx->pLength) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        EscDhFe_FromBytesBE(publicKey, keyBytes, keyBytesLength);
        returnCode = EscDh_PublicKeyValidation(ctx, publicKey);
    }

    return returnCode;
}

Esc_ERROR
EscDh_BytesFromPrivKey(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PrivateKeyT* privateKey,
    Esc_UINT8 keyBytes[],
    Esc_UINT16 *keyLength)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (privateKey == Esc_NULL_PTR) || (keyBytes == Esc_NULL_PTR) || (keyLength == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        EscDhFe_ToBytesBE(keyBytes, privateKey, ctx->pLength, keyLength);
    }

    return returnCode;
}

Esc_ERROR
EscDh_BytesFromPubKey(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PublicKeyT* publicKey,
    Esc_UINT8 keyBytes[],
    Esc_UINT16 *keyLength)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR) || (keyBytes == Esc_NULL_PTR) || (keyLength == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        EscDhFe_ToBytesBE(keyBytes, publicKey, ctx->pLength, keyLength);
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
