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
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_fearith.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/* Word arithmetic */
#if Esc_HAS_INT64 == 0
static void
EscFeArithWd_Inc(
    Esc_UINT32* hi,
    Esc_UINT32* lo,
    Esc_UINT32 increment );

#endif
static void
EscFeArithWd_AddC(
    Esc_UINT32* carry,
    Esc_UINT32* c,
    const Esc_UINT32 a,
    const Esc_UINT32 b );

static void
EscFeArithWd_SubB(
    Esc_UINT32* borrow,
    Esc_UINT32* c,
    Esc_UINT32 a,
    Esc_UINT32 b );

#if Esc_HAS_INT64 == 0
static void
EscFeArithWd_Multiply(
    Esc_UINT32* c_high,
    Esc_UINT32* c_low,
    Esc_UINT32 a,
    Esc_UINT32 b );
#endif


/* Field arithmetic */
/**
 * Multiplies two field elements c = a * b.
 *
 * \param[out] c Resulting long field element.
 * \param[in] a Field element a.
 * \param[in] b Field element b.
 * \param[in] curveSize Curve sizes.
 */
static void
EscFeArith_Multiply(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_SizeT* curveSize );

#if Esc_HAS_INT64 == 1
/**
 * Square a field element c = a * a.
 *
 * \param[out] c Resulting long field element.
 * \param[in] a Field element a.
 * \param[in] curveSize Curve sizes.
 */
static void
EscFeArith_SquareShort(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_SizeT* curveSize );
#endif

static void
EscFeArith_MultiplyShort(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_SizeT* curveSize );

/**
 * Reduces a field element by the given modulus. Depending on the specified curve,
 * a different algorithm is used.
 *
 * \param[out] result Reduced field element.
 * \param[in] value Long field element to be reduced.
 * \param[in] modulus The modulus used for the reduction.
 * \param[in] curveId ID of the curve to be used.
 * \param[in] curveSize Curve sizes.
 */
static void
EscFeArith_Reduce(
    EscFeArith_FieldElementT* result,
    const EscFeArith_FieldElementLongT* value,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize);

#if (EscEcc_SECP_192_ENABLED == 1)
static void
EscFeArith_ReduceNIST_192(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
static void
EscFeArith_ReduceNIST_224(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
static void
EscFeArith_ReduceNIST_256(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
static void
EscFeArith_ReduceNIST_384(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
static void
EscFeArith_ReduceNIST_521(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );
#endif

#if (EscEcc_CURVE_ED25519_ENABLED == 1)
/**
 * Reduce a field element z with modulus p using fast reduction technique for (pseudo) Mersenne prime numbers, r = z mod p
 *
 * \param[out] r Resulting field element
 * \param[in] z Long field element to reduce
 * \param[in] fGP Underlying field (includes modulus p)
 */
static void
EscFeArith_ReduceCurve_25519(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP );

/**
 * Shifts a field element to the left.
 *
 * Field Elements in and out can point to the same location (aliased).
 *
 * \param[out] out Shifted Field element.
 * \param[in] in Field element to shift.
 * \param[in] lenWords Length of both field elements.
 * \param[in] shifts Number of bits which should be shifted. Maximum allowed shift is 31 bits.
 */
static void
EscFeArith_ShiftLeft(
    EscFeArith_FieldElementT* out,
    const EscFeArith_FieldElementT* in,
    const Esc_UINT8 lenWords,
    Esc_UINT8 shifts );

#endif

static void
EscFeArith_MemsetZero(
    Esc_UINT32 dest[],
    Esc_UINT32 length );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*****************************************************************
 Increments a 64 bit value whose low FWORDs is in *lo and high FWORDs
 is in *hi by the value increment.
 *****************************************************************/
#if Esc_HAS_INT64 == 0
static void
EscFeArithWd_Inc(
    Esc_UINT32* hi,
    Esc_UINT32* lo,
    Esc_UINT32 increment )
{
    *lo += increment;

    if ( *lo < increment )
    {
        /* Overflow */
        (*hi)++;
    }
}
#endif

/*****************************************************************
 Adds two FWORDs to another FWORD + carry
 c = a + b + carry
 *****************************************************************/
static void
EscFeArithWd_AddC(
    Esc_UINT32* carry,
    Esc_UINT32* c,
    const Esc_UINT32 a,
    const Esc_UINT32 b )
{
#if Esc_HAS_INT64 == 1
    Esc_UINT64 u64_temp = (Esc_UINT64)a + (Esc_UINT64)b + (Esc_UINT64) * carry;
    *carry = EscFeArith_HI64( u64_temp );
    *c = EscFeArith_LO64( u64_temp );
#else
    *c = *carry;
    *carry = 0U;
    EscFeArithWd_Inc( carry, c, a );
    EscFeArithWd_Inc( carry, c, b );
#endif
}

/*****************************************************************
Adds two arrays of FWORDs with a length of len
 with carry
*****************************************************************/
void
EscFeArithWd_AddCLoop(
    Esc_UINT32* carry_out,
    Esc_UINT32 c[],
    const Esc_UINT32 a[],
    const Esc_UINT32 b[],
    const Esc_UINT8 len)
{
    Esc_UINT16 i;
    *carry_out = 0U;
    for (i = 0U; i < len; i++)
    {
        EscFeArithWd_AddC( carry_out, &c[i], a[i], b[i] );
    }
}

/*****************************************************************
Calculates c = a - b + borrow
****************************************************************/
static void
EscFeArithWd_SubB(
    Esc_UINT32* borrow,
    Esc_UINT32* c,
    Esc_UINT32 a,
    Esc_UINT32 b )
{
    Esc_UINT32 inv_b = ~b;

    EscFeArithWd_AddC( borrow, c, a, inv_b );
}

/*****************************************************************
Subtracts two arrays of FWORDs with a length of len,
 with borrow
*****************************************************************/
void
EscFeArithWd_SubBLoop(
    Esc_UINT32 c[],
    Esc_UINT32* borrow_out,
    const Esc_UINT32 a[],
    const Esc_UINT32 b[],
    const Esc_UINT8 len )
{
    Esc_UINT16 i;

    *borrow_out = 1U;
    for (i = 0U; i < len; i++)
    {
        EscFeArithWd_SubB( borrow_out, &c[i], a[i], b[i] );
    }
}

/*****************************************************************
Calculates c = a * b
****************************************************************/
#if Esc_HAS_INT64 == 0
static void
EscFeArithWd_Multiply(
    Esc_UINT32* c_high,
    Esc_UINT32* c_low,
    Esc_UINT32 a,
    Esc_UINT32 b )
{
    Esc_UINT16 a1, a0;
    Esc_UINT16 b1, b0;
    Esc_UINT32 uv;
    Esc_UINT16 u;
    Esc_UINT16 c2, c1, c0;

    /*
       We use an inlined version of the classical
       multiplication algorithm:
     */
    a0 = EscFeArith_LO32( a );
    a1 = EscFeArith_HI32( a );
    b0 = EscFeArith_LO32( b );
    b1 = EscFeArith_HI32( b );

    /* i=0, j=0 */
    uv = (Esc_UINT32)a0 * (
            Esc_UINT32)b0;
    u = EscFeArith_HI32( uv );
    c0 = EscFeArith_LO32( uv );

    /* j=1 */
    uv = ( (Esc_UINT32)a0 * (Esc_UINT32)b1 ) + (Esc_UINT32)u;
    c1 = EscFeArith_LO32( uv );
    c2 = EscFeArith_HI32( uv );

    /* i=1, j=0 */
    uv = (Esc_UINT32)c1 + ( (Esc_UINT32)a1 * (Esc_UINT32)b0 );
    u = EscFeArith_HI32( uv );

    /* j=1 */
    *c_low = (Esc_UINT32)c0 + (uv << 16);
    *c_high = (Esc_UINT32)c2 + ( (Esc_UINT32)a1 * (Esc_UINT32)b1 ) + (Esc_UINT32)u;
}

#endif

/******************************************
 * substitute for memset(dest, 0, length) *
 ******************************************/
static void
EscFeArith_MemsetZero(
    Esc_UINT32 dest[],
    Esc_UINT32 length )
{
    Esc_UINT32 i;

    for (i = 0U; i < length; i++)
    {
        dest[i] = 0U;
    }
}

/*****************************************************
 * Convert EscFeArith_FieldElementT to Esc_UINT8     *
 *****************************************************/
void
EscFeArith_ToUint8(
    const EscFeArith_FieldElementT* input,  /* field element to convert */
    Esc_UINT8 output[],                 /* result */
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT16 i;
    Esc_UINT32 input_w32;
    Esc_UINT16 keyWords = curveSize->keySizeWords;
    Esc_UINT16 lastByteIndex = (Esc_UINT16)curveSize->keySizeBytes - 1U;

#if (EscEcc_SECP_521_ENABLED == 1)
    if (curveSize->keySizeBits == 521U)
    {
        /* copy the first two bytes from the Field Element */
        input_w32 = input->word[keyWords - 1U];
        output[1] = (Esc_UINT8)( (input_w32) );
        output[0] = (Esc_UINT8)( (input_w32) >> 8 );

        keyWords--;
    }
#endif

    for (i = 0U; i < keyWords; i++)
    {
        input_w32 = input->word[i];

        output[(lastByteIndex - (4U * i))]      = (Esc_UINT8)( (input_w32) );
        output[(lastByteIndex - (4U * i)) - 1U] = (Esc_UINT8)( (input_w32) >> 8U );
        output[(lastByteIndex - (4U * i)) - 2U] = (Esc_UINT8)( (input_w32) >> 16U );
        output[(lastByteIndex - (4U * i)) - 3U] = (Esc_UINT8)( (input_w32) >> 24U );
    }

}

/********************************************************
 * Convert Esc_UINT8 to EscFeArith_FieldElementT            *
 ********************************************************/
void
EscFeArith_FromUint8(
    const Esc_UINT8 input[],        /* Esc_UINT8 array to convert */
    Esc_UINT32 inputLen,
    EscFeArith_FieldElementT* output,   /* result */
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT32 usedInputBytes, nonFullWordBytes, feWord;
    Esc_UINT16 i, paddingWords, feWordIndex;

    if ( inputLen >= curveSize->keySizeBytes )
    {
        usedInputBytes = curveSize->keySizeBytes;
        paddingWords = 0U;
    }
    else
    {
        /* Pad the input value with zero at the leftmost bytes (rightmost FE words).
           Byte padding inside a word is done later, here we compute only the full padding words. */
        usedInputBytes = inputLen;
        /* compute number of padding words by rounding up the division */
        paddingWords = (curveSize->keySizeWords - (((Esc_UINT16)usedInputBytes + 3U) / 4U));
    }
    nonFullWordBytes = usedInputBytes & 0x03U;
    feWordIndex = (curveSize->keySizeWords - (Esc_UINT16)1U);

    /* Padding words */
    for ( i = 0; i < paddingWords; i++ )
    {
        output->word[feWordIndex - i] = 0U;
    }
    feWordIndex -= paddingWords;

    /* Convert first bytes to non-full word, if required */
    feWord = 0U;
    if (( nonFullWordBytes) != 0U )
    {
        for ( i = 0; i < nonFullWordBytes; i++ )
        {
            feWord <<= 8;
            feWord |= input[i];
        }
        output->word[feWordIndex] = feWord;
        feWordIndex--;
        usedInputBytes -= nonFullWordBytes;
    }

    /* Converting remaining bytes to full FEs */
    feWord = 0U;
    for ( i = 0U; i < usedInputBytes; i++ )
    {
        /* Big endian byte array [0,1,2,3,4,5,6,7] => FE:
            [4,5,6,7][0,1,2,3] */
        feWord <<= 8;
        feWord |= input[i + nonFullWordBytes];
        if ( (i & 0x03U) == 0x03U )
        {
            output->word[feWordIndex] = feWord;
            feWordIndex--;
            feWord = 0U;
        }
    }

    for (i = curveSize->keySizeWords; i < curveSize->maxWords; i++)
    {
        output->word[i] = 0U;
    }
}

#if EscEcc_ECDSA_ENABLED == 1
/****************************************************
 * Convert EscFeArith_FieldElementT to                  *
 * EscFeArith_FieldElementLongT                         *
 ****************************************************/
void
EscFeArith_ToLongElement(
    EscFeArith_FieldElementLongT* a,
    const EscFeArith_FieldElementT* b,
    const Esc_UINT8 lenWords )
{
    Esc_UINT16 i;

    for (i = 0U; i < lenWords; i++)
    {
        a->word[i] = b->word[i];
    }
    for (i = lenWords; i < EscFeArith_MAX_LONG_WORDS; i++)
    {
        a->word[i] = 0U;
    }
}

#endif

/*****************************
 * set field element to zero *
 *****************************/
void
EscFeArith_SetZero(
    EscFeArith_FieldElementT* a )
{
    EscFeArith_MemsetZero( a->word, EscFeArith_MAX_WORDS );
}

/****************************
 * set field element to one *
 ****************************/
void
EscFeArith_SetOne(
    EscFeArith_FieldElementT* a )
{
    a->word[0] = 1U;

    EscFeArith_MemsetZero( &a->word[1], (EscFeArith_MAX_WORDS - 1U) );
}

/**********************************
 * check if field element is zero *
 **********************************/
Esc_BOOL
EscFeArith_IsZero(
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords )
{
    Esc_UINT8 i;
    Esc_BOOL isZero = TRUE;

    /* for i from 0 to t do a[i] =? 0 */
    for (i = 0U; i < lenWords; i++)
    {
        if (a->word[i] != 0U)
        {
            /* not zero */
            isZero = FALSE;
            break;
        }
    }

    return isZero;
}

/***********************************
 * checks if field element is one  *
 **********************************/
Esc_BOOL
EscFeArith_IsOne(
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords )
{
    Esc_BOOL isOne = TRUE;

    /* a[0] =? 1 */
    if (a->word[0] != 1U)
    {
        isOne = FALSE;
    }
    else
    {
        Esc_UINT8 i;
        /* for i from 1 to t-1 do a[i] =? 0 */
        for (i = 1U; i < lenWords; i++)
        {
            if (a->word[i] != 0U)
            {
                /* not one */
                isOne = FALSE;
                break;
            }
        }
    }

    return isOne;
}

/*******************************************
 * compares two field elements `a' and `b' *
  +1: a>b
  -1: a<b
   0: a==b
 *******************************************/
Esc_SINT8
EscFeArith_AbsoluteCompare(
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const Esc_UINT8 lenWords )
{
    Esc_SINT8 i;
    Esc_SINT8 compResult = 0;

    Esc_ASSERT( lenWords < 128U );

    /* compare the corresponding words until a different word pair is found */
    for (i = ((Esc_SINT8)lenWords - 1); (compResult == 0) && (i >= 0); i--)
    {
        /* next lower pair */
        if (a->word[i] > b->word[i])
        {
            /* a > b */
            compResult = 1;
        }
        else if (a->word[i] < b->word[i])
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

/************************************************************
 * assigns a field element to another field element         *
 ************************************************************/
void
EscFeArith_Assign(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords )
{
    Esc_UINT8 i;

    for (i = 0U; i < lenWords; i++)
    {
        c->word[i] = a->word[i];
    }
}

/****************************************************
 * shifts field element right by 1 bit              *
 ****************************************************/
void
EscFeArith_ShiftRight(
    EscFeArith_FieldElementT* a,
    const Esc_UINT8 lenWords )
{
    Esc_UINT8 i;
    Esc_UINT32 v;

    /* shift first words */
    for (i = 0U; i < (lenWords - 1U); i++)
    {
        v = a->word[i] >> 1;
        v ^= a->word[i + 1U] << 31;

        a->word[i] = v;
    }

    /* shift last word */
    a->word[lenWords - 1U] >>= 1;
}


/******************************************
 * multiplies two field elements c = a * b
 ******************************************/
static void
EscFeArith_Multiply(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT8 i, j;
    const Esc_UINT8 maxWords = curveSize->maxWords;
    Esc_UINT32 u, v;
    Esc_UINT32 prevU;       /* previous u */

#if Esc_HAS_INT64 == 1
    /* row-wise multiplication */
    Esc_UINT8 min;
    Esc_UINT32 carry, t;
    Esc_UINT8 b_0, a_0;
    Esc_UINT64 uv_t;
    Esc_UINT64 uv;
    uv_t = 0U;
    t = 0U;

    for (i = 0U; i < (2U * maxWords); i++)
    {
        b_0 = EscFeArith_MIN( (maxWords - 1U), i );
        a_0 = i - b_0;
        min = EscFeArith_MIN( (Esc_UINT8)(maxWords - a_0), (b_0 + 1U) );
        for (j = 0U; j < min; j++)
        {
            /* a[a_o +j] * b[b_o - j] */
            uv = (Esc_UINT64)a->word[a_0 + j] * (Esc_UINT64)b->word[b_0 - j];
            /* sum on uv_t */
            uv_t += uv;
            /* if overflow save carry to t */
            if (uv_t < uv)
            {
                t++;
            }
        }

        /* c[i] = v, v = u, u = t, t = 0 */
        c->word[i] = EscFeArith_LO64( uv_t );
        carry = EscFeArith_HI64( uv_t );
        uv_t = carry;
        uv_t |= (Esc_UINT64)(t) << 32U;
        t = 0U;
    }

#else
    /* HAC Alg. 14.12 */
    /* 1.) c = 0 */
    for (i = 0U; i < curveSize->maxWordsLong; i++)
    {
        c->word[i] = 0U;
    }
    /* 2.) for i = 0 to curveSize->maxWords */
    for (i = 0U; i < maxWords; i++)
    {
        /* 2.1) u = 0 */
        u = 0U;

        /* 2.2) for j = 0 to curveSize->maxWords do */
        for (j = 0U; j < maxWords; j++)
        {
            prevU = u;

            /* (uv) = a[j] * b[i] */
            EscFeArithWd_Multiply( &u, &v, a->word[j], b->word[i] );

            /* (uv) = a[j] * b[i] + u */
            EscFeArithWd_Inc( &u, &v, prevU );

            /* (uv) = c[i+j] + a[j] * b[i] + u */
            EscFeArithWd_Inc( &u, &v, c->word[i + j] );

            /* c[i+j] = v */
            c->word[i + j] = v;
        }

        /* 2.3) c[i+curveSize->maxWords] = u */
        c->word[i + maxWords] = u;
    }
#endif
    /* Zeroize u, prevU, v */
    Esc_CLEAR_LOCAL_VAR(u);
    Esc_CLEAR_LOCAL_VAR(prevU);
    Esc_CLEAR_LOCAL_VAR(v);
}

/***********************************************************************
 * square a field element c = a * a
 Highest word will not be used (this is only used used for the Barrett
 reduction).
 ***********************************************************************/
#if Esc_HAS_INT64 == 1
static void
EscFeArith_SquareShort(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT8 i, j;
    const Esc_UINT8 t2 = curveSize->maxWordsLong;
    /* specifies the number of used words in multiplication */
    Esc_UINT8 t = curveSize->maxWords - 1U;

    Esc_UINT64 carry;
    Esc_UINT64 uv;
    Esc_UINT32 u, v;

    /* check if highest word is really not used */
    Esc_ASSERT(a->word[t] == 0U);

    /* 1.0 */
    for (i = 0U; i < t2; ++i)
    {
        c->word[i] = 0U;
    }

    /* 2.0 */
    for (i = 0U; i < t; ++i)
    {
        Esc_UINT64 tmpCarry = 0U;

        /* 2.1 */
        Esc_UINT64 x_i = (Esc_UINT64)a->word[i];
        uv = (Esc_UINT64)c->word[2U*i] + (x_i * x_i);
        u = EscFeArith_HI64(uv);
        v = EscFeArith_LO64(uv);
        c->word[2U*i] = v;
        carry = u;

        /* 2.2 */
        for (j = (i + 1U); j < t; ++j)
        {
            uv = (Esc_UINT64)a->word[j] * (Esc_UINT64)a->word[i];
            if (uv & 0x8000000000000000ULL)
            {
                tmpCarry = (Esc_UINT64) 0x100000000ULL;
            }
            else
            {
                tmpCarry = 0;
            }
            uv <<= 1;
            uv += (Esc_UINT64)c->word[i+j];
            uv += carry;

            /* Overflow caused by previous addition. We can reset to tmpCarry to 0x100000000 instead of incrementing it, because
             * the overall result cannot overflow twice (see also Note 14.17 (i) in the Handbook of Applied Cryptography.
             */
            if (uv < carry)
            {
                tmpCarry = (Esc_UINT64) 0x100000000ULL;
            }

            u = EscFeArith_HI64(uv);
            v = EscFeArith_LO64(uv);
            c->word[i+j] = v;
            carry = u | tmpCarry;
        }

        /* 2.3 */
        c->word[i+t] += u;
        if (c->word[i+t] < u)
        {
            c->word[i+t+1U] += 1U;
        }

        if (tmpCarry != 0U)
        {
            c->word[i+t+1U] += 1U;
        }
    }
}
#endif

/***********************************************************************
 * multiplies two field elements c = a * b
 Highest word will only be used if one operand is the prime number -->
 adjusted loop borders for optimization
 Note: To calculate with all words use EscFeArith_Multiply !!!
 ***********************************************************************/
static void
EscFeArith_MultiplyShort(
    EscFeArith_FieldElementLongT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT8 i, j;
    const Esc_UINT8 maxWordsLong = curveSize->maxWordsLong;
    /* specifies the number of used words in multiplication */
    Esc_UINT8 mulMaxWords = curveSize->maxWords - 1U;
    Esc_UINT32 u, v;
    Esc_UINT32 prevU;       /* previous u */

#if Esc_HAS_INT64 == 1
    Esc_UINT8 min;
    Esc_UINT8 b_0, a_0;
    Esc_UINT32 carry;
    Esc_UINT32 t;
    Esc_UINT64 uv_t = 0U;
    Esc_UINT64 uv;
#endif

    /* check if highest words are really not used */
    Esc_ASSERT( (a->word[mulMaxWords] == 0U) && (b->word[mulMaxWords] == 0U) );

    /* if Esc_UINT64 type is supported, use row-wise multiplication (a lot faster) */
#if Esc_HAS_INT64 == 1

    /* Clear upper 2 words because they won't be calculated */
    c->word[maxWordsLong - 1U] = 0U;
    c->word[maxWordsLong - 2U] = 0U;

    for (i = 0U; i < ( 2U * (mulMaxWords) ); i++)
    {
        t = 0U;
        b_0 = EscFeArith_MIN( (mulMaxWords - 1U), i );
        a_0 = i - b_0;
        min = EscFeArith_MIN( (Esc_UINT8)(mulMaxWords - a_0), (b_0 + 1U) );
        for (j = 0U; j < min; j++)
        {
            /* a[a_o +j] * b[b_o - j] */
            uv = (Esc_UINT64)a->word[a_0 + j] * (Esc_UINT64)b->word[b_0 - j];
            /* sum on uv_t */
            uv_t += uv;
            /* if overflow save carry to t */
            if (uv_t < uv)
            {
                t++;
            }
        }

        /* c[i] = v, v = u, u = t, t = 0 */
        c->word[i] = EscFeArith_LO64( uv_t );
        carry = EscFeArith_HI64( uv_t );
        uv_t = carry;
        uv_t |= (Esc_UINT64)(t) << 32U;
    }

    /* if Esc_UINT64 type is not supported, use classical multiplication */
#else  /* Esc_HAS_INT64 */
       /* HAC Alg. 14.12 */
       /* 1.) c = 0 */
    for (i = 0U; i < maxWordsLong; i++)
    {
        c->word[i] = 0U;
    }
    /* 2.) for i = 0 to curveSize->maxWords */
    for (i = 0U; i < (mulMaxWords); i++)
    {
        /* 2.1) u = 0 */
        u = 0U;

        /* 2.2) for j = 0 to (mulMaxWords) do */
        for (j = 0U; j < (mulMaxWords); j++)
        {
            prevU = u;

            /* (uv) = a[j] * b[i] */
            EscFeArithWd_Multiply( &u, &v, a->word[j], b->word[i] );

            /* (uv) = a[j] * b[i] + u */
            EscFeArithWd_Inc( &u, &v, prevU );

            /* (uv) = c[i+j] + a[j] * b[i] + u */
            EscFeArithWd_Inc( &u, &v, c->word[i + j] );

            /* c[i+j] = v */
            c->word[i + j] = v;
        }

        /* 2.3) c[i+mulMaxWords] = u */
        c->word[i + (mulMaxWords)] = u;
    }
#endif /* Esc_HAS_INT64 */
    /* Zeroize u, prevU, v */
    Esc_CLEAR_LOCAL_VAR(u);
    Esc_CLEAR_LOCAL_VAR(prevU);
    Esc_CLEAR_LOCAL_VAR(v);
}

static void
EscFeArith_Reduce(
    EscFeArith_FieldElementT* result,
    const EscFeArith_FieldElementLongT* value,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize)
{
    /*lint -save -e9081 We violate the too few cases for switch rule depending on the curve configuration.
      This saves us some ifdefs cascades and improves the readability. */
    switch (curveId)
    {
#if (EscEcc_SECP_192_ENABLED == 1)
        case EscFeArith_CURVE_SECP_192:
            EscFeArith_ReduceNIST_192( result, value, modulus );
            break;
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
        case EscFeArith_CURVE_SECP_224:
            EscFeArith_ReduceNIST_224( result, value, modulus );
            break;
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
        case EscFeArith_CURVE_SECP_256:
            EscFeArith_ReduceNIST_256( result, value, modulus );
            break;
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
        case EscFeArith_CURVE_SECP_384:
            EscFeArith_ReduceNIST_384( result, value, modulus );
            break;
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
        case EscFeArith_CURVE_SECP_521:
            EscFeArith_ReduceNIST_521( result, value, modulus );
            break;
#endif

#if (EscEcc_CURVE_ED25519_ENABLED == 1)
        case EscFeArith_CURVE_ED25519:
            EscFeArith_ReduceCurve_25519( result, value, modulus );
            break;
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P160:
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P192:
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P224:
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P256:
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P320:
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P384:
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P512:
#endif

        default:
            EscFeArith_ReduceBarrett( result, value, modulus, curveSize );
            break;
    }
    /*lint -restore */
}

/******************************************
 * add two field elements under modulus p *
 ******************************************/
void
EscFeArith_ModularAdd(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords )
{
    Esc_UINT32 carry, borrow;

    /* 1.) & 2.)                                                */
    /* for i from 0 to t-1 do c[i] = add_with_carry(a[i], b[i]) */
    EscFeArithWd_AddCLoop( &carry, c->word, a->word, b->word, lenWords );

    /* 4.) while c >= p, do c = c - p */
    while ( (carry == 1U) || (EscFeArith_AbsoluteCompare( c, &fGP->prime_p, lenWords ) >= 0 ) )
    {
        /* for i from 0 to t-1 do c[i] = subtract_with_borrow(c[i], p[i])  */
        EscFeArithWd_SubBLoop( c->word, &borrow, c->word, fGP->prime_p.word, lenWords );
        carry -= borrow;
    }
}

/************************************************
 * subtracts two field elements under modulus p *
 ************************************************/
void
EscFeArith_ModularSub(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords )
{
    Esc_UINT32 borrow, carry;

    /* 1.) & 2.) */
    /* for i from 0 to t-1 do c[i] = subtract_with_borrow(a[i], b[i])  */
    EscFeArithWd_SubBLoop( c->word, &borrow, a->word, b->word, lenWords );

    /* 3.) while carry bit is set (i.e. borrow == 0), add p to c = {c[t-1],..,c[1],c[0]} */
    while (borrow == 0U)
    {
        /* for i from 0 to t-1 do c[i] = add_with_carry(c[i], p[i]) */
        EscFeArithWd_AddCLoop( &carry, c->word, c->word, fGP->prime_p.word, lenWords );
        borrow += carry;
    }
}

/********************************************************
 * reduce a field element z with modulus p using Barrett*
 * r = z mod p                                          *
 ********************************************************/
void
EscFeArith_ReduceBarrett(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP,
    const EscFeArith_SizeT* curveSize )
{
    /* C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Algorithm 2.14, Barret Reduction */
    Esc_UINT8 i;
    Esc_UINT32 borrow;
    const Esc_UINT8 maxWords = curveSize->maxWords;

    EscFeArith_FieldElementT tmp;
    EscFeArith_FieldElementLongT tmpLong;
    EscFeArith_FieldElementT q;
    EscFeArith_FieldElementT r1, r2;

    /* reduction */
    /* 1.) q = floor(floor(z / (b ^(k-1))) * mu / b^(k+1)) */

    /* tmp = floor(z / (b ^(k-1))) */
    for (i = 0U; i < (fGP->pLen + 1U); i++)
    {
        tmp.word[i] = z->word[(fGP->pLen - 1U) + i];
    }
    /* Zerorize remaining words of all used FEs in this function.
       ReduceBarrett is only called with fGP = 'base_point_order_n' or
       fGP = 'EscFeArith_PRIME_P'(defined ecc_curves32.c) as the modulo.
       Since these fields have a length of curveSize->maxWords-1, this
       loop is never be used!
       Leave this for maintainability and possible changes in future ECC versions */
    for (; i < maxWords; i++)
    {
        tmp.word[i] = 0U;
        r1.word[i] = 0U;
        r2.word[i] = 0U;
    }

    /* tmpLong = tmp * my_p  = floor(z / (b ^(k-1))) * mu */
    /* use Big-version here because precalc_my_p has full word size */
    /*lint -e{772} Tmp is initialized correctly */
    EscFeArith_Multiply( &tmpLong, &tmp, &fGP->precalc_my_p, curveSize );

    /* q = floor(tmpLong / b^(k+1)) = floor(floor(z / (b ^(k-1))) * mu / b^(k+1)) */
    Esc_ASSERT( ( (fGP->pLen + 1U) + maxWords ) <= curveSize->maxWordsLong );
    for (i = 0U; i < maxWords; i++)
    {
        q.word[i] = tmpLong.word[(fGP->pLen + 1U) + i];
    }

    /* 2.) r = z % (b^(k+1)) - ((q * p) % (b^(k+1)) */

    /* r1 = (z % (b^(k+1)) */
    for (i = 0U; i < (fGP->pLen + 1U); i++)
    {
        r1.word[i] = z->word[i];
    }

    /* tmpLong = q * p */
    /*lint -e{772} q is initialized correctly */
    EscFeArith_Multiply( &tmpLong, &q, &fGP->prime_p, curveSize );

    /* r2 = tmpLong % (b^(k+1)) = (q * p) % (b^(k+1)) */
    for (i = 0U; i < (fGP->pLen + 1U); i++)
    {
        r2.word[i] = tmpLong.word[i];
    }

    /*r = r1 - r2 = (z % (b^(k+1)) - ((q * p) % (b^(k+1))) */
    /*lint -e{772} r1 and r2 are initialized correctly */
    if (EscFeArith_AbsoluteCompare( &r1, &r2, maxWords ) < 0)
    {
        /* Include Step 3. if r<0, r := r + b^(k+1) */

        /* Setting r1.word[ fGP->pLen + 1U ] = 1U; for computing  r1 := r1 + b^(k+1)
           is not possible since fGP-pLen + 1U could exceed the length of a field
           element.

           Naive approach: r = r1 + b^(k+1) - r2

           We compute: r = b^(k+1)-1 - (r2 - r1 - 1) [ <-- this is computed by us]
                         = b^(k+1)-1 -  r2 + r1 + 1
                         = b^(k+1)   -  r2 + r1      [which is the same as computed in the naive approach]

           In the our computation there is no element which could exceed curveSize->maxWords,
           especially b^(k+1)-1 fits within curveSize->maxWords words.
        */

        /* r2 = r2 - r1*/
        EscFeArithWd_SubBLoop( r2.word, &borrow, r2.word, r1.word, maxWords );

        /* r2 = r2 - 1 */
        EscFeArith_SetOne( &tmp );
        EscFeArithWd_SubBLoop( r2.word, &borrow, r2.word, tmp.word, maxWords );

        /* r1 = b^(k+1)-1 */
        for (i = 0U; i < maxWords; i++)
        {
            r1.word[i] = 0xFFFFFFFFU;
        }
    }
    EscFeArithWd_SubBLoop( r->word, &borrow, r1.word, r2.word, maxWords );

    /* 4.) while r>=p do : r:= r - p */
    while (EscFeArith_AbsoluteCompare( r, &fGP->prime_p, maxWords ) >= 0)
    {
        /* r := r - p */
        EscFeArithWd_SubBLoop( r->word, &borrow, r->word, fGP->prime_p.word, maxWords );
    }
    /* 5.) return r */
}

/************************************************
 * multiply two field elements under modulus p  *
 ************************************************/

void
EscFeArith_SquareModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize )
{
    EscFeArith_FieldElementLongT longC;

    /* square */
#if Esc_HAS_INT64 == 1
    EscFeArith_SquareShort( &longC, a, curveSize );
#else
    EscFeArith_MultiplyShort( &longC, a, a, curveSize );
#endif

    /* reduce */
    EscFeArith_Reduce(c, &longC, modulus, curveId, curveSize);
}


void
EscFeArith_MultiplyModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize )
{
    EscFeArith_FieldElementLongT longC;

    /* multiply */
    EscFeArith_MultiplyShort( &longC, a, b, curveSize );

    /* reduce */
    EscFeArith_Reduce(c, &longC, modulus, curveId, curveSize);
}

/************************************************
 * multiply two field elements under modulus n  *
 ************************************************/
#if ((EscEcc_ECDSA_ENABLED == 1) || (EscEcc_CURVE_ED25519_ENABLED == 1) )
void
EscFeArith_MultiplyModN(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldElementT* b,
    const EscFeArith_FieldT* modulus,
    const EscFeArith_SizeT* curveSize )
{
    EscFeArith_FieldElementLongT longC;

    /* Multiply */
    EscFeArith_MultiplyShort( &longC, a, b, curveSize );

    /* Reduce with Barrett reduction */
    EscFeArith_ReduceBarrett( c, &longC, modulus, curveSize );

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_VAR(longC);
}
#endif

/***************************************
 * optimized reduction for NIST-Primes *
 ***************************************/

#if (EscEcc_SECP_192_ENABLED == 1)
static void
EscFeArith_ReduceNIST_192(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    /* c_x = 2^64
       s1 = (c_2, c_1, c_0) s2 = (0, c_3, c_3) s3 = (c_4, c_4, 0) s4 = c_5, c_5, c_5)
       calculate (s1 + s2 + s3 + s4) mod p_192 */
    Esc_UINT8 i;
    EscFeArith_FieldElementT s2;
    EscFeArith_FieldElementT s3;
    EscFeArith_FieldElementT s4;

    EscFeArith_SetZero( &s2 );
    EscFeArith_SetZero( &s3 );
    s4.word[6U] = 0U;
    r->word[6U] = 0U;

    for (i = 0U; i < 6U; i++)
    {
        r->word[i] = z->word[i];
    }
    for (i = 6U; i < 8U; i++)
    {
        s2.word[i - 6U] = z->word[i];
        s2.word[i - 4U] = z->word[i];
    }
    for (i = 8U; i < 10U; i++)
    {
        s3.word[i - 6U] = z->word[i];
        s3.word[i - 4U] = z->word[i];
    }
    for (i = 10U; i < 12U; i++)
    {
        s4.word[i - 10U] = z->word[i];
        s4.word[i - 8U] = z->word[i];
        s4.word[i - 6U] = z->word[i];
    }

    EscFeArith_ModularAdd( r, r, &s2, fGP, 7U );
    EscFeArith_ModularAdd( r, r, &s3, fGP, 7U );
    EscFeArith_ModularAdd( r, r, &s4, fGP, 7U );
}

#endif

#if (EscEcc_SECP_224_ENABLED == 1)
static void
EscFeArith_ReduceNIST_224(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    /* Algorithm 2.28, Guide to Elliptic Curve Cryptography */
    Esc_UINT8 i;
    EscFeArith_FieldElementT s2;
    EscFeArith_FieldElementT s3;
    EscFeArith_FieldElementT s4;
    EscFeArith_FieldElementT s5;

    EscFeArith_SetZero( &s2 );
    EscFeArith_SetZero( &s3 );
    EscFeArith_SetZero( &s5 );
    r->word[7U] = 0U;
    s4.word[7U] = 0U;

    for (i = 0U; i < 7U; i++)
    {
        r->word[i] = z->word[i];
    }
    for (i = 0U; i < 7U; i++)
    {
        s4.word[i] = z->word[i + 7U];
    }
    for (i = 3U; i < 7U; i++)
    {
        s2.word[i] = z->word[i + 4U];
    }
    for (i = 0U; i < 3U; i++)
    {
        s5.word[i] = z->word[i + 11U];
        s3.word[i + 3U] = z->word[i + 11U];
    }

    EscFeArith_ModularAdd( r, r, &s2, fGP, 8U );
    EscFeArith_ModularAdd( r, r, &s3, fGP, 8U );
    EscFeArith_ModularSub( r, r, &s4, fGP, 8U );
    EscFeArith_ModularSub( r, r, &s5, fGP, 8U );
}

#endif

#if (EscEcc_SECP_256_ENABLED == 1)

static Esc_UINT32
EscFeArith_Add256(
        const Esc_UINT32 *a,
        const Esc_UINT32 *b,
        Esc_UINT32 *c )
{
    Esc_UINT32 carry;
    Esc_UINT32 r; /* allows a, b or c to point to same value. */
    Esc_UINT8 i;

    r = a[0] + b[0];
    carry = (r < a[0]) ? (Esc_UINT32)1U : (Esc_UINT32)0U;
    c[0] = r;

    for (i = 1; i < 8U; i++)
    {
        r = a[i] + b[i];
        if (r < a[i])
        {
            r += carry; /* local carry produced: can absorb carry in. */
            carry = 1;
        }
        else
        {
            r += carry;
            carry = (r < carry) ? (Esc_UINT32)1U : (Esc_UINT32)0U;
        }
        c[i] = r;
    }
    return carry;
}

static void
EscFeArith_CarryReduce256(
        Esc_UINT32 *a )
{
    /* modulus:
    static const Esc_UINT32 Esc_P_Modulus256[8] =
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0xFFFFFFFF };
    */

    /* +2^(8*32) mod modulus, (literally, the two's complement of the modulus): */
    static const Esc_UINT32 Esc_P_Carry256[8] =
        { 0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
          0xFFFFFFFEU, 0x00000000U };

    if (EscFeArith_Add256(a, Esc_P_Carry256, a))
    {
        /*lint --esym(534, EscFeArith_Add256)
         * The return value of EscFeArith_Add256 can be ignored in the second call as there
         * will be no more carry, since the top word of Esc_P_Carry256 is 0.
         */
        EscFeArith_Add256(a, Esc_P_Carry256, a);
    }
}

static Esc_UINT32
EscFeArith_CarryProp(
        Esc_UINT32 start,
        Esc_UINT32 fieldSize,
        Esc_UINT32 *c )
{
    Esc_UINT32 carry = 1U;

    do
    {
        c[start] += 1U;
        if (c[start] != (Esc_UINT32) 0)
        {
            carry = 0U;
            break;
        }
        start += 1U;
    }
    while (start < fieldSize);

    return carry;
}

static Esc_UINT32
EscFeArith_BorrowProp(
        Esc_UINT32 start,
        Esc_UINT32 fieldSize,
        Esc_UINT32 *c )
{
    Esc_UINT32 borrow = 1U;

    do
    {
        if (c[start]-- != (Esc_UINT32) 0)
        {
            borrow = 0U;
            break;
        }
        start += 1U;
    }
    while (start < fieldSize);

    return borrow;
}

/* Reduce a[8], i.e. 9th most significant word, by folding it into the lower 8 words,
 * making use of the efficient prime reduction.
 */
static void
EscFeArith_WordRed256 (
        Esc_UINT32* a )
{
    Esc_UINT32 carry = (Esc_UINT32) 0;
    Esc_UINT32 w;
    Esc_UINT32 tmp;

    w = a[8];
    a[8] = (Esc_UINT32) 0;

    /* modulus:  2^256  - 2^224 + 2^192 + 2^96 - 2^0
     * so:       2^256 == 2^224 - 2^192 - 2^96 + 2^0
     */

    a[0] += w;
    if (a[0] < w)
    { /* +2^0 */
        a[1] += 1U;
        if (a[1] == (Esc_UINT32) 0)
        {
            carry += EscFeArith_CarryProp(2, 8, a);
        }
    }
    tmp = a[3];
    a[3] -= w;
    if (a[3] > tmp)
    { /* -2^96 */
        if (a[4]-- == (Esc_UINT32) 0)
        {
            carry -= EscFeArith_BorrowProp(5, 8, a);
        }
    }
    tmp = a[6];
    a[6] -= w;
    if (a[6] > tmp)
    { /* -2^192 */
        if (a[7]-- == (Esc_UINT32) 0)
        {
            carry--;
        }
    }
    a[7] += w;
    if (a[7] < w)
    { /* +2^224 */
        carry++;
    }
    if (carry)
    { /* carry cannot be negative. */
        EscFeArith_CarryReduce256(a);
    }
}

/* Reduce a double-sized array modulo NIST P-256 one word at a time.
 * Note: the final 8-word array may, with a slim chance, be larger than p.
 */
static void
EscFeArith_SizeRed256(
        Esc_UINT32 *a )
{
    Esc_UINT32 *toRed;
    /*lint -e{946} relational operator is allowed between pointers pointing to the same object,
     * which is the case here for toRed and a.
     */
    /*
     * 1st iteration points WordRed256 to a[7], which means a[15] would be folded into a[14] .. a[7]
     * 2nd iteration points            to a[6],             a[14]                      a[13] .. a[6]
     * and so on till                     a[0],             a[8]                       a[7]  .. a[0]
     */
    for (toRed = &a[8 - 1]; toRed >= a; --toRed)
    {
        EscFeArith_WordRed256(toRed);
    }
}

/*
 * Reduce a 16-word value to 8-word value modulo p (almost)
 * by reducing the size word by word, see EscFeArith_SizeRed256().
 */
static void
EscFeArith_ReduceNIST_256(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    Esc_UINT32 toRed[64U];
    (void) fGP;
    /* copy value to be reduced */
    Esc_memcpy((Esc_UINT8 *)toRed, (const Esc_UINT8 *)z->word, 64U);

    /* Size-reduce modulo p */
    EscFeArith_SizeRed256(toRed);
    Esc_memcpy((Esc_UINT8 *)r->word, (Esc_UINT8 *)toRed, 32U);
    r->word[8] = 0;
}

#endif

#if (EscEcc_SECP_384_ENABLED == 1)
static void
EscFeArith_ReduceNIST_384(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    /* c = 2^32
       Algorithm 2.30, Guide to Elliptic Curve Cryptography */
    EscFeArith_FieldElementT s2;
    EscFeArith_FieldElementT s3;
    EscFeArith_FieldElementT s4;
    EscFeArith_FieldElementT s5;
    EscFeArith_FieldElementT s6;
    EscFeArith_FieldElementT s7;
    EscFeArith_FieldElementT s8;
    EscFeArith_FieldElementT s9;
    EscFeArith_FieldElementT s10;

    Esc_UINT8 i;

    r->word[12U] = 0U;
    for (i = 0U; i < 12U; i++)
    {
        r->word[i] = z->word[i];
    }
    EscFeArith_SetZero( &s2 );
    for (i = 4U; i < 7U; i++)
    {
        s2.word[i] = z->word[i + 17U];
    }
    s3.word[12U] = 0U;
    for (i = 0U; i < 12U; i++)
    {
        s3.word[i] = z->word[i + 12U];
    }
    s4.word[12U] = 0U;
    for (i = 3U; i < 12U; i++)
    {
        s4.word[i] = z->word[i + 9U];
    }
    s4.word[0U] = z->word[21U];
    s4.word[1U] = z->word[22U];
    s4.word[2U] = z->word[23U];
    for (i = 4U; i < 12U; i++)
    {
        s5.word[i] = z->word[i + 8U];
    }
    s5.word[0U] = 0U;
    s5.word[1U] = z->word[23U];
    s5.word[2U] = 0U;
    s5.word[3U] = z->word[20U];
    s5.word[12U] = 0U;
    EscFeArith_SetZero( &s6 );
    for (i = 4U; i < 8U; i++)
    {
        s6.word[i] = z->word[i + 16U];
    }
    EscFeArith_SetZero( &s7 );
    s7.word[0U] = z->word[20U];
    s7.word[3U] = z->word[21U];
    s7.word[4U] = z->word[22U];
    s7.word[5U] = z->word[23U];
    for (i = 1U; i < 12U; i++)
    {
        s8.word[i] = z->word[i + 11U];
    }
    s8.word[0U] = z->word[23U];
    s8.word[12U] = 0U;
    EscFeArith_SetZero( &s9 );
    for (i = 1U; i < 5U; i++)
    {
        s9.word[i] = z->word[i + 19U];
    }
    EscFeArith_SetZero( &s10 );
    s10.word[3U] = z->word[23U];
    s10.word[4U] = z->word[23U];

    EscFeArith_ModularAdd( r, r, &s2, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s2, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s3, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s4, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s5, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s6, fGP, 13U );
    EscFeArith_ModularAdd( r, r, &s7, fGP, 13U );
    EscFeArith_ModularSub( r, r, &s8, fGP, 13U );
    EscFeArith_ModularSub( r, r, &s9, fGP, 13U );
    EscFeArith_ModularSub( r, r, &s10, fGP, 13U );
}

#endif

#if (EscEcc_SECP_521_ENABLED == 1)
static void
EscFeArith_ReduceNIST_521(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    /* c = 2^1
       Algorithm 2.31, Guide to Elliptic Curve Cryptography */
    EscFeArith_FieldElementT s2;

    Esc_UINT8 i;

    r->word[17U] = 0U;

    for (i = 0U; i < 17U; i++)
    {
        r->word[i] = (z->word[i + 16U] >> 9U);
        r->word[i] = ( r->word[i] | (z->word[i + 17U] << 23U) );
    }

    s2.word[17U] = 0U;

    for (i = 0U; i < 17U; i++)
    {
        s2.word[i] = z->word[i];
    }
    /* we want the bits 512 to 520 only */
    s2.word[16U] = (s2.word[16U] & (Esc_UINT32)0x1FF);

    EscFeArith_ModularAdd( r, r, &s2, fGP, 18U );
}

#endif


#if (EscEcc_USE_SLIDING_WINDOW == 1) || (EscFeArith_ENABLE_SHAMIRS_TRICK == 1)
/*************************************************
 * return true if bit on position "index" is set *
 *************************************************/
Esc_BOOL
EscFeArith_isBitSet(
    const EscFeArith_FieldElementT* c,
    Esc_SINT16 index )
{
    Esc_BOOL isSet;
    if ( ( ( c->word[(Esc_UINT16)index >> 5U] >> ( (Esc_UINT16)index & 0x1fU ) ) & 1U ) == 1U )
    {
        isSet = TRUE;
    }
    else
    {
        isSet = FALSE;
    }

    return isSet;
}

#endif


#if (EscEcc_CURVE_ED25519_ENABLED == 1)
static void
EscFeArith_ReduceCurve_25519(
    EscFeArith_FieldElementT* r,
    const EscFeArith_FieldElementLongT* z,
    const EscFeArith_FieldT* fGP )
{
    /* Fast reduction due to the pseudo Mersenne prime number p = 2^255 - 19. Result = (high * 19) + low mod p */
    Esc_UINT32 highPart;
    Esc_UINT32 carry;
    EscFeArith_FieldElementT tmpFe;
    Esc_UINT8 i;

    /* High part */
    for (i = 0U; i < 9U; i++)
    {
        r->word[i] = (z->word[i + 7U] >> 31U);
        r->word[i] = ( r->word[i] | (z->word[i + 8U] << 1U) );
    }

    /* (high * 19) can be expressed by (high << 4) + (high << 1) + high */
    EscFeArith_ShiftLeft( &tmpFe, r, 9U, 1U );
    EscFeArithWd_AddCLoop( &carry, r->word, r->word, tmpFe.word, 9U );
    EscFeArith_ShiftLeft( &tmpFe, &tmpFe, 9U, 3U );
    EscFeArithWd_AddCLoop( &carry, r->word, r->word, tmpFe.word, 9U );

    /* Result has a maximum of 260 bits. Again, get the partial high part, multiply with 19 and add it to the partial low part */
    highPart = 19U * (((r->word[7] & 0x80000000U) >> 31U) | (r->word[8] << 1U));
    EscFeArith_SetZero( &tmpFe );
    tmpFe.word[0] = highPart;

    /* low part -> mask out most significant 5 bits */
    r->word[7] = r->word[7] & 0x7FFFFFFFUL;
    r->word[8] = 0UL;

    /* Add partial low part and partial high part to get the high part * 19 of the input value */
    EscFeArithWd_AddCLoop( &carry, r->word, r->word, tmpFe.word, 9U );

    /* Low part */
    tmpFe.word[8U] = 0U;

    for (i = 0U; i < 8U; i++)
    {
        tmpFe.word[i] = z->word[i];
    }
    /* We want the bits 224 to 254 only, zeroize remaining bits */
    tmpFe.word[7U] = (tmpFe.word[7U] & 0x7FFFFFFFUL);

    /* (high * 19) + low mod p */
    EscFeArith_ModularAdd( r, r, &tmpFe, fGP, 9U );
}


/****************************************************
 * Shifts field element to the left                 *
 ****************************************************/
static void
EscFeArith_ShiftLeft(
    EscFeArith_FieldElementT* out,
    const EscFeArith_FieldElementT* in,
    const Esc_UINT8 lenWords,
    Esc_UINT8 shifts )
{
    Esc_UINT8 i, bitshift;

    Esc_ASSERT( shifts < EscFeArith_WORD_BITS );

    bitshift = EscFeArith_WORD_BITS - shifts;

    /* Shift first words */
    for (i = (lenWords - 1U); i >= 1U; i--)
    {
        out->word[i] = (in->word[i] << shifts) | (in->word[i - 1U] >> bitshift);
    }

    /* Shift last word */
    out->word[0] = in->word[0] << shifts;
}


void
EscFeArith_PowModP(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const Esc_UINT8 exponent[],
    Esc_UINT32 exponentLen,
    const EscFeArith_FieldT* modulus,
    EscFeArith_CurveId curveId,
    const EscFeArith_SizeT* curveSize )
{
    Esc_SINT32 bytePos;
    Esc_UINT8 bitPos, byte, currentMsb;
    EscFeArith_FieldElementT tmp;

    /* Set tmp FE to one */
    EscFeArith_SetOne( &tmp );

    for ( bytePos = ((Esc_SINT32)exponentLen - 1); bytePos >= 0; bytePos--)
    {
        byte = exponent[bytePos];
        for ( bitPos = 8U; bitPos > 0U; bitPos-- )
        {
            /* get always MSB of current byte */
            currentMsb = byte >> 7U;
            /* adjust MSBit for next iteration */
            byte <<= 1U;

            /* Square */
            EscFeArith_SquareModP( &tmp, &tmp, modulus, curveId, curveSize );

            /* Multiply */
            if ( currentMsb == 1U )
            {
                EscFeArith_MultiplyModP( &tmp, &tmp, a, modulus, curveId, curveSize );
            }
        }
    }

    EscFeArith_Assign( c, &tmp, curveSize->maxWords );
}


/**
 * Invert a field element with modulus p applying the Binary Extended Euclidean algorithm.
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 2.22
 */
void
EscFeArith_ModularInvert(
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords )
{
    Esc_UINT32 carry;
    Esc_BOOL isFinished;
    /* Temporary Field Elements */
    EscFeArith_FieldElementT u, v, x1, x2;

    EscFeArith_Assign( &u, a, lenWords );
    EscFeArith_Assign( &v, &fGP->prime_p, lenWords );
    EscFeArith_SetZero( &x2 );
    EscFeArith_SetOne( &x1 );

    isFinished = FALSE;

    if ( EscFeArith_IsOne( &u, lenWords ) )
    {
        isFinished = TRUE;
    }
    else if ( EscFeArith_IsOne( &v, lenWords ) )
    {
        isFinished = TRUE;
    }
    else
    {
        /* nothing */
    }

    while (isFinished == FALSE)
    {
        while ( (u.word[0] & 1U) == 0U )
        {
            EscFeArith_ShiftRight( &u, lenWords );
            if ( (x1.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &x1, lenWords );
            }
            else
            {
                EscFeArithWd_AddCLoop( &carry, x1.word, x1.word, fGP->prime_p.word, lenWords );
                EscFeArith_ShiftRight( &x1, lenWords );
            }
        }

        while ( (v.word[0] & 1U) == 0U )
        {
            EscFeArith_ShiftRight( &v, lenWords );
            if ( (x2.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &x2, lenWords );
            }
            else
            {
                EscFeArithWd_AddCLoop( &carry, x2.word, x2.word, fGP->prime_p.word, lenWords );
                EscFeArith_ShiftRight( &x2, lenWords );
            }
        }

        if (EscFeArith_AbsoluteCompare( &u, &v, lenWords ) > -1)
        {
            EscFeArithWd_SubBLoop( u.word, &carry, u.word, v.word, lenWords );
            EscFeArith_ModularSub( &x1, &x1, &x2, fGP, lenWords );
        }
        else
        {
            EscFeArithWd_SubBLoop( v.word, &carry, v.word, u.word, lenWords );
            EscFeArith_ModularSub( &x2, &x2, &x1, fGP, lenWords );
        }

        if ( EscFeArith_IsOne( &u, lenWords ) )
        {
            isFinished = TRUE;
        }
        else if ( EscFeArith_IsOne( &v, lenWords ) )
        {
            isFinished = TRUE;
        }
        else
        {
            /* nothing */
        }
    }

    if ( EscFeArith_IsOne( &u, lenWords ) )
    {
        EscFeArith_Assign( c, &x1, lenWords );
    }
    else
    {
        EscFeArith_Assign( c, &x2, lenWords );
    }
}


/********************************************************
 * Convert Esc_UINT8 to EscFeArith_FieldElementT            *
 ********************************************************/
void
EscFeArith_LongFromUint8(
    const Esc_UINT8 input[],        /* Esc_UINT8 array to convert */
    Esc_UINT32 inputLen,
    EscFeArith_FieldElementLongT* output,   /* result */
    const EscFeArith_SizeT* curveSize )
{
    Esc_UINT32 usedInputBytes, nonFullWordBytes, feWord;
    Esc_UINT16 i, paddingWords, feWordIndex;

    if ( inputLen >= (2U * (Esc_UINT32)curveSize->keySizeBytes) )
    {
        usedInputBytes = 2U * (Esc_UINT32)curveSize->keySizeBytes;
        paddingWords = 0U;
    }
    else
    {
        /* Pad the input value with zero at the leftmost bytes (rightmost FE words).
           Byte padding inside a word is done later, here we compute only the full padding words. */
        usedInputBytes = inputLen;
        /* compute number of padding words by rounding up the division */
        paddingWords = ( (2U * (Esc_UINT16)curveSize->keySizeWords) - (((Esc_UINT16)usedInputBytes + 3U) / 4U));
    }
    nonFullWordBytes = usedInputBytes & 0x03U;
    feWordIndex = ( (2U * (Esc_UINT16)curveSize->keySizeWords) - (Esc_UINT16)1U);

    /* Padding words */
    for ( i = 0; i < paddingWords; i++ )
    {
        output->word[feWordIndex - i] = 0U;
    }
    feWordIndex -= paddingWords;

    /* Convert first bytes to non-full word, if required */
    feWord = 0U;
    if (( nonFullWordBytes) != 0U )
    {
        for ( i = 0; i < nonFullWordBytes; i++ )
        {
            feWord <<= 8;
            feWord |= input[i];
        }
        output->word[feWordIndex] = feWord;
        feWordIndex--;
        usedInputBytes -= nonFullWordBytes;
    }

    /* Converting remaining bytes to full FEs */
    feWord = 0U;
    for ( i = 0U; i < usedInputBytes; i++ )
    {
        /* Big endian byte array [0,1,2,3,4,5,6,7] => FE:
            [4,5,6,7][0,1,2,3] */
        feWord <<= 8;
        feWord |= input[i + nonFullWordBytes];
        if ( (i & 0x03U) == 0x03U )
        {
            output->word[feWordIndex] = feWord;
            feWordIndex--;
            feWord = 0U;
        }
    }

    for (i = (2U * (Esc_UINT16)curveSize->keySizeWords); i < curveSize->maxWordsLong; i++)
    {
        output->word[i] = 0U;
    }
}


void
EscFeArith_SwapEndiannessUint8(
    Esc_UINT8 output[],
    const Esc_UINT8 input[],
    Esc_UINT32 inputLen )
{
    Esc_UINT32 i;

    for ( i = 0U; i < inputLen; i++ )
    {
        output[i] = input[(inputLen - 1U) - i];
    }
}

#endif /* EscEcc_CURVE_ED25519_ENABLED */

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
