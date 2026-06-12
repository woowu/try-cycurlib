/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Elliptic Curve Arithmetic, non-sliced variants.

   $Rev: 2750 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "eccarith_s0.h"
#include "ecc_cfg.h"
#include "_fearith.h"
#include "_ptarithws.h"
#include "mem_mgt.h"

#if EscEcc_USE_FIXED_BASE == 1
#include "ecc_precomp.h"
#endif

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
#if (EscEcc_SECP_256_ENABLED == 1) && (EscFeArith_ENABLE_SHAMIRS_TRICK == 1)

/* The naf representation of number of n bits is n+1 (at maximum)*/
#define EscEccArith_NAF_LENGTH 257U

/* The average number of non-zero digits in a window naf of size 4 is 1/(4+1).
 * The allocated number of 16-bit words is 1/4 to be on the safe side
 * */
#define EscEccArith_WINDOW_NAF_LENGTH 64U

typedef struct
{
    /** the words of the long number */
    Esc_UINT16 word[EscEccArith_WINDOW_NAF_LENGTH];
} EscEccArith_NafW;

/**
 * The following precomputed points are needed for the window naf calculations in the function
 *  "EscEccArithS0_Pt_JacDualMulAddBinInit"
 *  The precomputed points are 1*G, 3*G, 5*G, 7*G.
 * Index in the following table is obtained by pattern/2;
 * pattern = 1 => index 0
 *           3 =>       1
 *           5 =>       2
 *           7 =>       3
 */
/*lint --esym(9003, naf_precomp)
* Ignoring advisory about defining the following variable within the only function that uses them.
* It is preferred to not clutter that function.
*/
static const EscPtArithWs_PointT naf_precomp[4] =
{
    { /* 1G */
        EscPtArith_TYPE_JACOBIAN,
        {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  EscFeArith_PADZEROS_FROM_8 }},
        {{0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL, EscFeArith_PADZEROS_FROM_8}},
        {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, EscFeArith_PADZEROS_FROM_8 }}
    },
    { /* 3G */
        EscPtArith_TYPE_JACOBIAN,
        {{0xc6e7fd6cUL, 0xfb41661bUL, 0xefada985UL, 0xe6c6b721UL, 0x1d4bf165UL, 0xc8f7ef95UL, 0xa6330a44UL, 0x5ecbe4d1UL,  EscFeArith_PADZEROS_FROM_8 }},
        {{0xa27d5032UL, 0x9a79b127UL, 0x384fb83dUL, 0xd82ab036UL, 0x1a64a2ecUL, 0x374b06ceUL, 0x4998ff7eUL, 0x8734640cUL, EscFeArith_PADZEROS_FROM_8}},
        {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, EscFeArith_PADZEROS_FROM_8 }}
    },
    { /* 5G */
        EscPtArith_TYPE_JACOBIAN,
        {{0xc3d033edUL, 0x21554a0dUL, 0x1f5be524UL, 0xef8c82fdUL, 0x8668fdfUL, 0xd784c856UL, 0x515140d2UL, 0x51590b7aUL,  EscFeArith_PADZEROS_FROM_8 }},
        {{0xfda16da4UL, 0xd1d0bb44UL, 0xd4d80888UL, 0xd012f00UL, 0xbf8a7926UL, 0x8ae1bf36UL, 0x904a727dUL, 0xe0c17da8UL, EscFeArith_PADZEROS_FROM_8}},
        {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, EscFeArith_PADZEROS_FROM_8 }}
    },
    { /* 7G */
        EscPtArith_TYPE_JACOBIAN,
        {{0x3187b2a3UL, 0x30062870UL, 0xa80fef5bUL, 0x7ef9f8b8UL, 0x7c01fb60UL, 0x25bb3066UL, 0xa0bf7b46UL, 0x8e533b6fUL,  EscFeArith_PADZEROS_FROM_8 }},
        {{0xc1f400b4UL, 0xc55e1a86UL, 0xcb041b21UL, 0x53c73633UL, 0xa6f59000UL, 0x6d069f83UL, 0xe0331836UL, 0x73eb1dbdUL, EscFeArith_PADZEROS_FROM_8}},
        {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, EscFeArith_PADZEROS_FROM_8 }}
   },
};
#endif /*EscEcc_SECP_256_ENABLED */

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

#if EscEcc_USE_FIXED_BASE == 1
/**
 * Extract one n-bit word from the field element k with n being the fixed-base
 * window size defined in EscEcc_FIXED_BASE_WINDOW_SIZE.
 *
 * \param[out]  K       The extracted word.
 * \param[in]   k       The field element to extract the word from.
 * \param[in]   index   The index defining which word shall be extracted.
 *                      Zero is the least significant n-bit word.
 */
static void
EscEccArithS0_Pt_GetK(
    Esc_UINT8 * K,
    const EscFeArith_FieldElementT * k,
    const Esc_UINT32 index);
#endif

#if (EscEcc_SECP_256_ENABLED == 1) && (EscFeArith_ENABLE_SHAMIRS_TRICK== 1)

/* number of 32-bit words in a field element on a 256-bit curve */
#define EscFeArith_256_MAX_WORDS        9U
/* number of 32-bit words in a multiplication output of elements on a 256-bit curve */
#define EscFeArith_256_MAX_LONG_WORDS  (2U * EscFeArith_256_MAX_WORDS)

/*
 * Calculate the window naf (with window size = 4) of a field element k.
 * this function produces a list of naf windows in the struct kWin.
 * The number of stored element is numWins elements.
 *
 * The Windows each contain 3 pieces of information, encoded into a 16-bit word
 * per window:
 *
 *   pattern - the value of the window stored in bits 0-5. Since the window size is 4, only 3 bits
 *   out of the 6 bits are used
 *   sign - the sign to be applied to pattern stored in bit 6.
 *   pos - the bit position of pattern. pos is stored in bits 7-15.
 *
 *   \param[out]  kWin          The window naf representation of k.
 *   \parm[out]   numWin        The number of non zero digits in the window naf representation of k
 *   \param[in]   k             The field element k.
 */

static void EscEccArith_WindowNaf256(
    const EscFeArith_FieldElementT *k,
    Esc_UINT32 *numWins,
    EscEccArith_NafW* kWin);

/*
 * Calculate the binary naf of a field element a.
 * this function stores the binary naf of each bit in a as two bits in aNaf.
 *
 *   \param[out]  aNaf          The binary naf representation of a.
 *   \param[in]   a             The field element a.
 */

static void EscEccArith_BinaryNaf256 (
    const EscFeArith_FieldElementT *a,
    EscFeArith_FieldElementLongT *aNaf);

/**
 * Add patternValue to k and propagate the carry
 */
static void EscFeArith_CarryProp(
    Esc_UINT32 *carry,
    EscFeArith_FieldElementT* k);

#endif /* EscEcc_SECP_256_ENABLED */

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
#if (EscEcc_SECP_256_ENABLED == 1) && (EscFeArith_ENABLE_SHAMIRS_TRICK == 1)
static void
EscFeArith_CarryProp(
    Esc_UINT32 *carry,
    EscFeArith_FieldElementT* k)
{
    Esc_UINT8 i;
    Esc_UINT32 temp;

    for (i = 1; i < (Esc_UINT8)EscFeArith_256_MAX_WORDS; i++)
    {
        temp = k->word[i];
        k->word[i] = k->word[i] + *carry;
        *carry = 0;
        if (k->word[i] < temp)
        {
            (*carry)++;
        }
    }
}
#endif /* EscEcc_SECP_256_ENABLED */

/**
 * Invert a field element with modulus p applying the Binary Extended Euclidean algorithm.
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 2.22
 */
void
EscEccArithS0_Fe_ModularInvertInit(
    EscEccArithS0_Fe_ModularInvertContext* ctx,
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords )
{
    Esc_UINT32 carry;
    Esc_BOOL isFinished;

    EscFeArith_Assign( &ctx->u, a, lenWords );
    EscFeArith_Assign( &ctx->v, &fGP->prime_p, lenWords );
    EscFeArith_SetZero( &ctx->x2 );
    EscFeArith_SetOne( &ctx->x1 );

    isFinished = FALSE;

    if ( EscFeArith_IsOne( &ctx->u, lenWords ) )
    {
        isFinished = TRUE;
    }
    else if ( EscFeArith_IsOne( &ctx->v, lenWords ) )
    {
        isFinished = TRUE;
    }
    else
    {
        /* nothing */
    }

    while (isFinished == FALSE)
    {
        while ( (ctx->u.word[0] & 1U) == 0U )
        {
            EscFeArith_ShiftRight( &ctx->u, lenWords );
            if ( (ctx->x1.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &ctx->x1, lenWords );
            }
            else
            {
                EscFeArithWd_AddCLoop( &carry, ctx->x1.word, ctx->x1.word, fGP->prime_p.word, lenWords );
                EscFeArith_ShiftRight( &ctx->x1, lenWords );
            }
        }

        while ( (ctx->v.word[0] & 1U) == 0U )
        {
            EscFeArith_ShiftRight( &ctx->v, lenWords );
            if ( (ctx->x2.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &ctx->x2, lenWords );
            }
            else
            {
                EscFeArithWd_AddCLoop( &carry, ctx->x2.word, ctx->x2.word, fGP->prime_p.word, lenWords );
                EscFeArith_ShiftRight( &ctx->x2, lenWords );
            }
        }

        if (EscFeArith_AbsoluteCompare( &ctx->u, &ctx->v, lenWords ) > -1)
        {
            EscFeArithWd_SubBLoop( ctx->u.word, &carry, ctx->u.word, ctx->v.word, lenWords );
            EscFeArith_ModularSub( &ctx->x1, &ctx->x1, &ctx->x2, fGP, lenWords );
        }
        else
        {
            EscFeArithWd_SubBLoop( ctx->v.word, &carry, ctx->v.word, ctx->u.word, lenWords );
            EscFeArith_ModularSub( &ctx->x2, &ctx->x2, &ctx->x1, fGP, lenWords );
        }

        if ( EscFeArith_IsOne( &ctx->u, lenWords ) )
        {
            isFinished = TRUE;
        }
        else if ( EscFeArith_IsOne( &ctx->v, lenWords ) )
        {
            isFinished = TRUE;
        }
        else
        {
            /* nothing */
        }
    }

    if ( EscFeArith_IsOne( &ctx->u, lenWords ) )
    {
        EscFeArith_Assign( c, &ctx->x1, lenWords );
    }
    else
    {
        EscFeArith_Assign( c, &ctx->x2, lenWords );
    }
}

Esc_ERROR
EscEccArithS0_Fe_ModularInvertRun(
    EscEccArithS0_Fe_ModularInvertContext* ctx )
{
    Esc_UNUSED_PARAM (ctx);

    return Esc_NO_ERROR;
}


void
EscEccArithS0_Pt_ToAffineInit(
    EscEccArithS0_Pt_ToAffineContext* ctx,
    EscPtArithWs_PointT* pA,
    const EscPtArithWs_PointT* pJ,
    const EscPtArithWs_CurveT* curve)
{
    /* Shortcuts to curve attributes */
    EscFeArith_CurveId curveId = curve->curveId;
    const EscFeArith_SizeT* curveSize = &curve->curveSize;
    const EscFeArith_FieldT* ecc_field_params = &curve->ecc_field_params;
    Esc_ASSERT( pJ->type == EscPtArith_TYPE_JACOBIAN );

    if ( EscPtArithWs_IsInfinity( pJ, curve ) )
    {
        /* set pA type */
        pA->type = EscPtArith_TYPE_AFFINE;
        /* pA = (0) */
        EscPtArithWs_SetInfinity( pA );
    }
    else
    {
        /* pJ(1/z) : 1I */
        EscEccArithS0_Fe_ModularInvertInit( &ctx->modInvertCtx, &ctx->fe_z_inv1_3, &pJ->z, &curve->ecc_field_params, curve->curveSize.maxWords );
        /* pJ(1/z^2) : 1S */
        EscFeArith_SquareModP( &ctx->fe_z_inv2, &ctx->fe_z_inv1_3, ecc_field_params, curveId, curveSize );
        /* pJ(1/z^3) : 1M */
        EscFeArith_MultiplyModP( &ctx->fe_z_inv1_3, &ctx->fe_z_inv1_3, &ctx->fe_z_inv2, ecc_field_params, curveId, curveSize );
        /* pA(x) = pJ(x/z^2) : 1M */
        EscFeArith_MultiplyModP( &pA->x, &pJ->x, &ctx->fe_z_inv2, ecc_field_params, curveId, curveSize );
        /* pA(y) = pJ(y/z^3) : 1M */
        EscFeArith_MultiplyModP( &pA->y, &pJ->y, &ctx->fe_z_inv1_3, ecc_field_params, curveId, curveSize );
        /* pA(z) = 0 */
        EscFeArith_SetZero( &pA->z );
        /* set pA type */
        pA->type = EscPtArith_TYPE_AFFINE;
    }
}

Esc_ERROR
EscEccArithS0_Pt_ToAffineRun(
    EscEccArithS0_Pt_ToAffineContext* ctx )
{
    Esc_UNUSED_PARAM (ctx);

    return Esc_NO_ERROR;
}


/***********************************************
 * scalar multiplication of unknown pA1 with k *
 ***********************************************/

#if EscEcc_USE_FIXED_BASE == 1
static void
EscEccArithS0_Pt_GetK(
    Esc_UINT8 * K,
    const EscFeArith_FieldElementT * k,
    const Esc_UINT32 index)
{
    /** select word */
    Esc_UINT32 word = (index * EscEcc_FIXED_BASE_WINDOW_SIZE) / 32U;
    /** select the index inside the word */
    Esc_UINT32 innerIndex = index % (32U / EscEcc_FIXED_BASE_WINDOW_SIZE);
    /** prepare an and mask of EscEcc_FIXED_BASE_WINDOW_SIZE length */
    Esc_UINT32 mask = (1U << EscEcc_FIXED_BASE_WINDOW_SIZE) - 1U;
    /** little endian -> inner_index = 0 is rightmost, so inner_index is nearly the shift amount*/
    Esc_UINT32 shiftAmount = innerIndex * EscEcc_FIXED_BASE_WINDOW_SIZE;

    *K = (Esc_UINT8) ((k->word[word] >> shiftAmount) & mask);
}
#endif


void
EscEccArithS0_Pt_JacobianMultiplyBinaryInit(
    EscEccArithS0_Pt_JacobianMultiplyBinaryContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve )
{
    const Esc_UINT8 maxWords = curve->curveSize.maxWords;

#if EscEcc_USE_SLIDING_WINDOW == 1
    Esc_ASSERT( pA1->type == EscPtArith_TYPE_AFFINE );

    /* check P = (0) */
    if ( EscPtArithWs_IsZero( pA1, curve ) == FALSE )
    {
        Esc_SINT16 bitIndex, j, windowsize;
        Esc_UINT16 exponent, n;

        /* precomputation - bitIndex < ((2^k_m) / 2) + 1 */
        ctx->precompArray[0].type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_Assign( &ctx->precompArray[0].x, &pA1->x, maxWords );
        EscFeArith_Assign( &ctx->precompArray[0].y, &pA1->y, maxWords );
        EscFeArith_SetOne( &ctx->precompArray[0].z );

        /* pJ = (0) */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        /* Compute 2 x pJ, use last element of precomp array as temporary location */
        EscPtArithWs_JacobianDouble( &ctx->precompArray[EscEcc_NUM_WINDOW_ELEMENTS - 1], &ctx->precompArray[0], curve );

        for (j = 1; j < (Esc_SINT16)EscEcc_NUM_WINDOW_ELEMENTS; j++)
        {
            EscPtArithWs_JacobianAdd( &ctx->precompArray[j], &ctx->precompArray[j - 1], &ctx->precompArray[EscEcc_NUM_WINDOW_ELEMENTS - 1], curve );
        }

        bitIndex = (Esc_SINT16)( (Esc_SINT16)maxWords * (Esc_SINT16)EscFeArith_WORD_BITS ) - 1;

        while (bitIndex >= 0)
        {
            /* if Exponent = 0 double only */
            if (EscFeArith_isBitSet( k, bitIndex ) == FALSE)
            {
                EscPtArithWs_JacobianDouble( pJ, pJ, curve );
                bitIndex--;
            }
            else
            {
                /* build window */
                exponent = 0U;
                n = (Esc_UINT16)(EscEcc_WINDOW_SIZE - 1U);
                windowsize = (Esc_SINT16)EscEcc_WINDOW_SIZE;
                for (j = bitIndex; ( j > (bitIndex - (Esc_SINT16)EscEcc_WINDOW_SIZE) ) && (j >= 0); j--)
                {
                    /* build temporary exponent */
                    if (EscFeArith_isBitSet( k, j ) == TRUE)
                    {
                        exponent += (Esc_UINT16)( 1UL << n );
                    }
                    n--;
                }
                bitIndex -= (Esc_SINT16)EscEcc_WINDOW_SIZE;
                /* make window odd and adjust bitIndex, reduce window size */
                while ( (exponent % 2U) == 0U )
                {
                    exponent = (Esc_UINT16)(exponent / 2U);
                    bitIndex++;
                    windowsize--;
                }

                /* double */
                for (j = 0; j < windowsize; j++)
                {
                    EscPtArithWs_JacobianDouble( pJ, pJ, curve );
                }

                /* Assert that exponent/2 is within bounds of precompArray */
                Esc_ASSERT( (exponent / 2U) < EscEcc_NUM_WINDOW_ELEMENTS );

                /* add */
                EscPtArithWs_JacobianAdd( pJ, pJ, &ctx->precompArray[exponent / 2U], curve );
            }
        }
    }
    else
    {
        /* return Zero point */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );
    }

#else /* EscEcc_USE_SLIDING_WINDOW */
    Esc_ASSERT( pA1->type == EscPtArith_TYPE_AFFINE );

    ctx->pTemp.type = EscPtArith_TYPE_JACOBIAN;
    /* pJx = pXx */
    EscFeArith_Assign( &ctx->pTemp.x, &pA1->x, maxWords );
    /* pJy = pXy */
    EscFeArith_Assign( &ctx->pTemp.y, &pA1->y, maxWords );
    /* pJz = 1 */
    EscFeArith_SetOne( &ctx->pTemp.z );

    /* check P = (0) */
    if ( EscPtArithWs_IsZero( pA1, curve ) == FALSE )
    {
        Esc_SINT16 i;
        Esc_UINT32 temp;
        /* set pJ = 0 */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        for (i = (Esc_SINT16)maxWords - 1; i >= 0; i--)
        {
            Esc_UINT16 j;

            temp = k->word[i];

            for (j = 0U; j < EscFeArith_WORD_BITS; j++)
            {
                EscPtArithWs_JacobianDouble( pJ, pJ, curve );

                if ( (temp & 0x80000000U) != 0U )          /* highest bit set */
                {
                    EscPtArithWs_JacobianAdd( pJ, pJ, &ctx->pTemp, curve );
                }
                temp <<= 1;
            }
        }
        /* Zeroize temp */
        Esc_CLEAR_LOCAL_VAR(temp);
    }
    else
    {
        /* return Zero point */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );
    }
#endif /* EscEcc_USE_SLIDING_WINDOW */
}

Esc_ERROR
EscEccArithS0_Pt_JacobianMultiplyBinaryRun(
    EscEccArithS0_Pt_JacobianMultiplyBinaryContext* ctx )
{
    Esc_UNUSED_PARAM (ctx);

    return Esc_NO_ERROR;
}

void
EscEccArithS0_Pt_BasePointMultInit(
    EscEccArithS0_Pt_BasePointMultContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_CurveT* curve )
{
#if EscEcc_USE_FIXED_BASE == 1
    /* Fixed base implementation according to Hankerson, et. al,
     * "Guide to Elliptic Curve Cryptography", Alg. 3.41
     */

    EscPtArithWs_PointT pP;
    Esc_UINT8 i, j, chunks;

    pP.type = EscPtArith_TYPE_JACOBIAN;
    EscPtArithWs_SetInfinity(&pP);

    /* set pJ type */
    pJ->type = EscPtArith_TYPE_JACOBIAN;
    EscPtArithWs_SetInfinity(pJ);

    /* extract bit chunks K_i */
    chunks = (Esc_UINT8) ((curve->curveSize.maxWords * 32U) / EscEcc_FIXED_BASE_WINDOW_SIZE);
    for (i = 0; i < chunks; i++)
    {
        EscEccArithS0_Pt_GetK(&ctx->K[i], k, i);
    }

    /** loop over the base */
    for (j = (Esc_UINT8)(((1U << EscEcc_FIXED_BASE_WINDOW_SIZE)-1U)); j > 0U ; --j)
    {
        /** loop over the chunks */
        for (i = 0U; i < chunks; ++i)
        {
            if (ctx->K[i] == j)
            {
                const EscPtArithWs_PointT *precomp;
                EscEcc_GetPrecomputedPoint(&precomp, curve->curveId, i);
                EscPtArithWs_JacobianAdd(&pP, &pP, precomp, curve);
            }
        }

        EscPtArithWs_JacobianAdd(pJ, pJ, &pP, curve);
    }
#else
    /* Forward to general point multiplication */
    EscEccArithS0_Pt_JacobianMultiplyBinaryInit(
        &ctx->jacMulBinCtx,
        pJ,
        k,
        &curve->base_point_G,
        curve);
#endif
}

Esc_ERROR
EscEccArithS0_Pt_BasePointMultRun(
    EscEccArithS0_Pt_BasePointMultContext* ctx )
{
    Esc_UNUSED_PARAM (ctx);

    return Esc_NO_ERROR;
}

/**
 * Calculate k0 * G + k1 * Q with Shamir's trick. *
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 3.48 with w  = 1
 */
#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1

/**
 * In fact, for secp256, the calculation is based on common accumulator for doubling,
 * with separate w-NAF addition for the generator G and binary NAF addition for Q,
 * the unknown point.
 */
#if EscEcc_SECP_256_ENABLED == 1

/**
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 3.30
 */
static void
EscEccArith_BinaryNaf256(
    const EscFeArith_FieldElementT *a,
    EscFeArith_FieldElementLongT *aNaf)
{
    EscFeArith_FieldElementT aCopy;
    Esc_UINT32 bitMask = 0;
    Esc_UINT8 wordCounter = 0U;
    Esc_UINT32 pattern;
    Esc_UINT32 temp = 0U;
    Esc_UINT32 carry = 0U;

    Esc_memclear(aNaf->word, sizeof(aNaf->word));
    EscFeArith_Assign(&aCopy, a, (Esc_UINT8)EscFeArith_256_MAX_WORDS); /* copy to modify */

    while (EscFeArith_IsZero(&aCopy, EscFeArith_256_MAX_WORDS) != TRUE)
    { /* produce NAF bits from low to high */
        pattern = aCopy.word[0] & (Esc_UINT32) 0x03;
        if (pattern == (Esc_UINT32)1U)
        { /* + one */
            aNaf->word[wordCounter] += (pattern << bitMask); /* set one in NAF */
            aCopy.word[0] = aCopy.word[0] ^ pattern;
        }
        if (pattern == (Esc_UINT32)3U)
        { /* -one */
            aNaf->word[wordCounter] += (pattern << bitMask); /* add sign bit to NAF */
            temp = aCopy.word[0];
            aCopy.word[0] = aCopy.word[0] + 1U; /* remove -1 from aCopy, i.e. add +1 */
            carry = (aCopy.word[0] < temp) ? (Esc_UINT32)1U : (Esc_UINT32)0U;
            if (carry > 0U)
            {
                EscFeArith_CarryProp(&carry, &aCopy); /* carry propagation */
            }
        }

        bitMask += 2U;
        if (bitMask == EscFeArith_WORD_BITS)
        { /* each NAF bit encoded in 2 bits; check if we're into next word. */
            bitMask = (Esc_UINT32) 0x00;
            ++wordCounter;
        }
        EscFeArith_ShiftRight(&aCopy, (Esc_UINT8)EscFeArith_256_MAX_WORDS);
    }
}

/**
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 3.35
 * with w = 4 for 256-bit scalars
 */
static void
EscEccArith_WindowNaf256(
    const EscFeArith_FieldElementT* k,
    Esc_UINT32 *numWins,
    EscEccArith_NafW* kWin)
{
    Esc_UINT8 pattern;
    Esc_UINT8 sign;
    Esc_UINT32 pos = 0;
    Esc_UINT16 wins = 0;
    EscFeArith_FieldElementT kCopy;
    Esc_UINT32 temp = 0U;
    Esc_UINT32 carry = 0U;

    EscFeArith_Assign(&kCopy, k, EscFeArith_256_MAX_WORDS); /* copy to modify */

    while (EscFeArith_IsZero(&kCopy, EscFeArith_256_MAX_WORDS) != TRUE)
    {
        pattern = (Esc_UINT8)(kCopy.word[0] & 0x0fU);
        if (pattern & 0x01U)
        {
            sign = 0U; /*  means positive (until checked if negative)*/
            if (pattern & 0x08U)
            {
                sign = 1U;  /* means negative */
                pattern = (~pattern & 0x0FU) + 1U;/* 2's complement of the lower 4 bits of pattern */
                kWin->word[wins] = pattern;
                temp = kCopy.word[0];
                kCopy.word[0] = kCopy.word[0] + pattern; /* remove -pattern from kWin, i.e. add + pattern */
                carry = (kCopy.word[0] < temp) ? (Esc_UINT32)1U : (Esc_UINT32)0U;
                if (carry > 0U)
                {
                    EscFeArith_CarryProp(&carry, &kCopy); /* carry propagation */
                }
            }
            else
            {
                kWin->word[wins] = pattern;  /* store pattern in the bit # 0-5 of a 16 bit word */
                kCopy.word[0] = kCopy.word[0] ^ (Esc_UINT32) pattern;
            }
            kWin->word[wins] += ((Esc_UINT16)sign << 6U); /* store sign in bit # 6 of a 16 bit word */
            kWin->word[wins] += (Esc_UINT16)(pos << 7U); /* store position in the bits # 7 - 15 bits of a 16 bit word */
            wins++;
        }
        EscFeArith_ShiftRight(&kCopy, EscFeArith_256_MAX_WORDS);
        pos++;
    }
    *numWins = wins;
}

static void
EscEccArithS0_Pt_JacDualMulAddBinInit256(
    EscEccArithS0_Pt_JacDualMulAddBinContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k0,
    const EscPtArithWs_PointT* pA0,
    const EscFeArith_FieldElementT* k1,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve)
{

    const Esc_UINT8 maxWords = curve->curveSize.maxWords;
    Esc_UINT16 i;
    EscFeArith_FieldElementLongT k1Naf;
    EscEccArith_NafW k0NafW;
    Esc_UINT32 numWins;
    Esc_UINT32 k1Index;
    Esc_UINT32 k0Index = 0U;
    Esc_UINT32 k1Pattern = 0U;
    Esc_UINT16 k0Position = 0U;
    Esc_UINT8 k0Pattern = 0U;
    Esc_UINT8 k0Sign = 0U;
    Esc_UINT32 borrowOut = 0U;
    EscPtArithWs_PointT precomputedPoint;
    Esc_UINT32 bitMask = 0x03;
    Esc_UINT16 bitShift = 0x00;
    /* Use an available point in the context that was used in Shamir's trick */
    EscPtArithWs_PointT *pNegA1 = &ctx->pQPlusG;

    const EscFeArith_FieldT* ecc_field_params = &curve->ecc_field_params;

    /*Zeroize k0NafW */
    for (i = 0; i < EscEccArith_WINDOW_NAF_LENGTH; i++)
    {
        k0NafW.word[i] = 0U;
    }

    /*Zeroize k1Naf */
    Esc_memclear(k1Naf.word, sizeof(k1Naf.word));

    EscEccArith_WindowNaf256(k0, &numWins, &k0NafW);
    EscEccArith_BinaryNaf256(k1, &k1Naf);

    Esc_ASSERT(pA0->type == EscPtArith_TYPE_AFFINE);
    Esc_ASSERT(pA1->type == EscPtArith_TYPE_AFFINE);

    /* Convert input point P0 in jacobian coordinates */
    ctx->pPA0.type = EscPtArith_TYPE_JACOBIAN;
    EscFeArith_Assign(&ctx->pPA0.x, &pA0->x, maxWords);
    EscFeArith_Assign(&ctx->pPA0.y, &pA0->y, maxWords);
    EscFeArith_SetOne(&ctx->pPA0.z);

    /* Convert input point P1 in jacobian coordinates */
    ctx->pPA1.type = EscPtArith_TYPE_JACOBIAN;
    EscFeArith_Assign(&ctx->pPA1.x, &pA1->x, maxWords);
    EscFeArith_Assign(&ctx->pPA1.y, &pA1->y, maxWords);
    EscFeArith_SetOne(&ctx->pPA1.z);

    /* set pJ to infinity */
    pJ->type = EscPtArith_TYPE_JACOBIAN;
    EscPtArithWs_SetInfinity(pJ);

    /* precompute -Q (which is -pA1)*/
    precomputedPoint.type = EscPtArith_TYPE_JACOBIAN;
    EscFeArithWd_SubBLoop(pNegA1->y.word, &borrowOut, ecc_field_params->prime_p.word,
                          ctx->pPA1.y.word, maxWords);
    EscFeArith_Assign(&pNegA1->x, &ctx->pPA1.x, maxWords);
    EscFeArith_SetOne(&pNegA1->z);

    if (numWins != 0U)
    {
        k0Index = numWins - 1U; /* offset to account for index starting at 0. */
    }
    k1Index = EscFeArith_256_MAX_LONG_WORDS - 2U; /* offset since the word length is 18 words */

    for (i = 0U; i < EscEccArith_NAF_LENGTH ; i++)
    {
        k0Position = (Esc_UINT16) (k0NafW.word[k0Index] & 0xff80U); /* get the last 9 bits of the word (i.e., the position) */
        k0Position >>= 7U;
        k0Pattern = (Esc_UINT8) (k0NafW.word[k0Index] & 0x0007U); /* get the first 3 bits of the word (i.e., the pattern) */
        k0Sign = (Esc_UINT8) (k0NafW.word[k0Index] & 0x0040U); /* get bit number 6 of the word (i.e., the sign) */
        k0Sign >>= 6U;
        k1Pattern = k1Naf.word[k1Index] & bitMask;
        k1Pattern >>= bitShift;

        EscPtArithWs_JacobianDouble(pJ, pJ, curve);

        if (k1Pattern == 1U)
        {
            EscPtArithWs_JacobianAdd(pJ, pJ, &ctx->pPA1, curve);
        }
        else if (k1Pattern == 3U) /*  k1Pattern == -1 */
        {
            EscPtArithWs_JacobianAdd(pJ, pJ, pNegA1, curve);
        }
        else
        {
            /* Do nothing */
        }

        if (k0Position == ((EscEccArith_NAF_LENGTH -1U) - i))
        {
            /* fetch precomputed point; index = k0Pattern/2 */
            EscFeArith_Assign(&precomputedPoint.x, &naf_precomp[k0Pattern >> 1].x, maxWords);
            /* if sign is +ve, assign y, otherwise, negate y */
            if (k0Sign == 0U)
            {
                EscFeArith_Assign(&precomputedPoint.y, &naf_precomp[k0Pattern >> 1].y, maxWords);
            }
            else
            {
                EscFeArithWd_SubBLoop(precomputedPoint.y.word, &borrowOut,
                                      ecc_field_params->prime_p.word, naf_precomp[k0Pattern >> 1].y.word,
                                      maxWords);
            }
            EscFeArith_SetOne(&precomputedPoint.z);

            /* This condition is important to handle the case when k0 is zero */
            if (k0Pattern != 0U)
            {
                EscPtArithWs_JacobianAdd(pJ, pJ, &precomputedPoint, curve);
            }

            if (k0Index != 0U)
            {
                k0Index--;
            }
        }


        bitMask >>= 2U;
        if (bitShift != 0U)
        {
            bitShift -= 2U;
        }
        if (bitMask == 0U)
        {
            bitShift = (Esc_UINT16)(EscFeArith_WORD_BITS - 2U);
            bitMask = 0x03U << bitShift;
            k1Index--;
        }
    }
}
#endif /* EscEcc_SECP_256_ENABLED */

void
EscEccArithS0_Pt_JacDualMulAddBinInit(
    EscEccArithS0_Pt_JacDualMulAddBinContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k0,
    const EscPtArithWs_PointT* pA0,
    const EscFeArith_FieldElementT* k1,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve )
{
#if EscEcc_SECP_256_ENABLED == 1
    if (curve->curveId == EscFeArith_CURVE_SECP_256)
    {
        EscEccArithS0_Pt_JacDualMulAddBinInit256(ctx, pJ, k0, pA0, k1, pA1, curve);
    }
    else
    {
#endif
        const Esc_UINT8 maxWords = curve->curveSize.maxWords;
        Esc_SINT16 i;

        Esc_ASSERT( pA0->type == EscPtArith_TYPE_AFFINE );
        Esc_ASSERT( pA1->type == EscPtArith_TYPE_AFFINE );

        /* Convert input point P0 in jacobian coordinates */
        ctx->pPA0.type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_Assign( &ctx->pPA0.x, &pA0->x, maxWords );
        EscFeArith_Assign( &ctx->pPA0.y, &pA0->y, maxWords );
        EscFeArith_SetOne( &ctx->pPA0.z );

        /* Convert input point P1 in jacobian coordinates */
        ctx->pPA1.type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_Assign( &ctx->pPA1.x, &pA1->x, maxWords );
        EscFeArith_Assign( &ctx->pPA1.y, &pA1->y, maxWords );
        EscFeArith_SetOne( &ctx->pPA1.z );

        /* set pJ to infinity */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        /* precompute Q + G */
        EscPtArithWs_JacobianAdd( &ctx->pQPlusG, &ctx->pPA0, &ctx->pPA1, curve );

        /* Convert precomputed value to affine form to speed-up subsequent point additions.
         * The non-sliced ToAffine function does all computations in the init() step.
         */
        EscEccArithS0_Pt_ToAffineInit(&ctx->toAffineCtx, &ctx->pQPlusG, &ctx->pQPlusG, curve);
        ctx->pQPlusG.type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_SetOne( &ctx->pQPlusG.z );

        i = ( (Esc_SINT16)maxWords * (Esc_SINT16)EscFeArith_WORD_BITS ) - 1;

        /* skip common leading zeros of k0 and k1 */
        while ( !( (EscFeArith_isBitSet( k0, i ) == TRUE) || (EscFeArith_isBitSet( k1, i ) == TRUE) ) )
        {
            i--;
        }

        for (;;)
        {
            if ( EscFeArith_isBitSet( k0, i ) )
            {
                if ( EscFeArith_isBitSet( k1, i ) )
                {
                    /* k0=1 k1=1 */
                    EscPtArithWs_JacobianAdd( pJ, pJ, &ctx->pQPlusG, curve );
                }
                else
                {
                    /* k0=1 k1=0 */
                    EscPtArithWs_JacobianAdd( pJ, pJ, &ctx->pPA0, curve );
                }
            }
            else
            {
                if ( EscFeArith_isBitSet( k1, i ) )
                {
                    /* k0=0 k1=1 */
                    EscPtArithWs_JacobianAdd( pJ, pJ, &ctx->pPA1, curve );
                }
            }
            i--;

            if (i < 0)
            {
                break;
            }

            EscPtArithWs_JacobianDouble( pJ, pJ, curve );
        }
#if EscEcc_SECP_256_ENABLED == 1
    }
#endif
}

Esc_ERROR
EscEccArithS0_Pt_JacDualMulAddBinRun(
    EscEccArithS0_Pt_JacDualMulAddBinContext* ctx )
{
    Esc_UNUSED_PARAM (ctx);

    return Esc_NO_ERROR;
}
#endif /* EscEcc_ENABLE_SHAMIRS_TRICK */

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
