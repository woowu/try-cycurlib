/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Elliptic Curve Arithmetic, sliced variants.

   $Rev: 2750 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "eccarith_s1.h"
#include "ecc_cfg.h"
#include "_fearith.h"
#include "_ptarithws.h"

#if EscEcc_USE_FIXED_BASE == 1
#include "ecc_precomp.h"
#endif

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/*lint -esym(750,EscEccArithS1_STATE_JAC*) -esym(750,EscEccArithS1_STATE_BASE*) Depending on the configuration, some state symbols may not be used */

/** States for the Modular inversion */
#define EscEccArithS1_STATE_MODULARINVERT_NEXT_LOOP       10
#define EscEccArithS1_STATE_MODULARINVERT_FINISH          11

/** States for the point conversion */
#define EscEccArithS1_STATE_TOAFFINE_MODINVERT            20
#define EscEccArithS1_STATE_TOAFFINE_MULTIPY              21
#define EscEccArithS1_STATE_TOAFFINE_FINISH               22

/** States for the point multiplication (Double-Add and SLiding window) */
#define EscEccArithS1_STATE_JACMULTIPLY_PROCESS_NEXT_WORD 30
#define EscEccArithS1_STATE_JACMULTIPLY_DOUBLE            31
#define EscEccArithS1_STATE_JACMULTIPLY_ADD               32
#define EscEccArithS1_STATE_JACMULTIPLY_FINISH            33
/** States for the point multiplication (only used for sliding window) */
#define EscEccArithS1_STATE_JACMULTIPLY_PRECOMPLOOP       40
#define EscEccArithS1_STATE_JACMULTIPLY_NEXTWINDOW        41
#define EscEccArithS1_STATE_JACMULTIPLY_DOUBLE_ADD        42

/** States for the dual multiply (Shamir's trick) */
#define EscEccArithS1_STATE_JACDUALMUL_COMPUTE_QP         50
#define EscEccArithS1_STATE_JACDUALMUL_CONVERT_AFFINE     51
#define EscEccArithS1_STATE_JACDUALMUL_PREPARE_LOOP       52
#define EscEccArithS1_STATE_JACDUALMUL_NEXT_LOOP          53
#define EscEccArithS1_STATE_JACDUALMUL_DOUBLE             54

/** States for the base point multiplication */
#define EscEccArithS1_STATE_BASEMULT_GETK                 60
#define EscEccArithS1_STATE_BASEMULT_BASELOOP             61
#define EscEccArithS1_STATE_BASEMULT_ADD_TEMP             62


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
EscEccArithS1_Pt_GetK(
    Esc_UINT8 * K,
    const EscFeArith_FieldElementT * k,
    const Esc_UINT32 index);
#endif

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if EscEcc_USE_FIXED_BASE == 1
static void
EscEccArithS1_Pt_GetK(
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

/**
 * Invert a field element with modulus p applying the Binary Extended Euclidean algorithm.
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 2.22
 */
void
EscEccArithS1_Fe_ModularInvertInit(
    EscEccArithS1_Fe_ModularInvertContext* ctx,
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords )
{
    /* Set context elements */
    ctx->c = c;
    ctx->fGP = fGP;
    ctx->lenWords = lenWords;

    EscFeArith_Assign( &ctx->u, a, ctx->lenWords );
    EscFeArith_Assign( &ctx->v, &fGP->prime_p, ctx->lenWords );
    EscFeArith_SetZero( &ctx->x2 );
    EscFeArith_SetOne( &ctx->x1 );

    if ( (EscFeArith_IsOne( &ctx->u, ctx->lenWords ) == TRUE ) || (EscFeArith_IsOne( &ctx->v, ctx->lenWords ) == TRUE ) )
    {
        ctx->state = EscEccArithS1_STATE_MODULARINVERT_FINISH;
    }
    else
    {
        ctx->state = EscEccArithS1_STATE_MODULARINVERT_NEXT_LOOP;
    }
}

Esc_ERROR
EscEccArithS1_Fe_ModularInvertRun(
    EscEccArithS1_Fe_ModularInvertContext* ctx )
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT32 carry;

    switch( ctx->state )
    {
        case EscEccArithS1_STATE_MODULARINVERT_NEXT_LOOP:
            while ( (ctx->u.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &ctx->u, ctx->lenWords );
                if ( (ctx->x1.word[0] & 1U) == 0U )
                {
                    EscFeArith_ShiftRight( &ctx->x1, ctx->lenWords );
                }
                else
                {
                    EscFeArithWd_AddCLoop( &carry, ctx->x1.word, ctx->x1.word, ctx->fGP->prime_p.word, ctx->lenWords );
                    EscFeArith_ShiftRight( &ctx->x1, ctx->lenWords );
                }
            }

            while ( (ctx->v.word[0] & 1U) == 0U )
            {
                EscFeArith_ShiftRight( &ctx->v, ctx->lenWords );
                if ( (ctx->x2.word[0] & 1U) == 0U )
                {
                    EscFeArith_ShiftRight( &ctx->x2, ctx->lenWords );
                }
                else
                {
                    EscFeArithWd_AddCLoop( &carry, ctx->x2.word, ctx->x2.word, ctx->fGP->prime_p.word, ctx->lenWords );
                    EscFeArith_ShiftRight( &ctx->x2, ctx->lenWords );
                }
            }

            if (EscFeArith_AbsoluteCompare( &ctx->u, &ctx->v, ctx->lenWords ) > -1)
            {
                EscFeArithWd_SubBLoop( ctx->u.word, &carry, ctx->u.word, ctx->v.word, ctx->lenWords );
                EscFeArith_ModularSub( &ctx->x1, &ctx->x1, &ctx->x2, ctx->fGP, ctx->lenWords );
            }
            else
            {
                EscFeArithWd_SubBLoop( ctx->v.word, &carry, ctx->v.word, ctx->u.word, ctx->lenWords );
                EscFeArith_ModularSub( &ctx->x2, &ctx->x2, &ctx->x1, ctx->fGP, ctx->lenWords );
            }

            if ( (EscFeArith_IsOne( &ctx->u, ctx->lenWords ) == TRUE) || (EscFeArith_IsOne( &ctx->v, ctx->lenWords ) == TRUE) )
            {
                ctx->state = EscEccArithS1_STATE_MODULARINVERT_FINISH;
            }

            break;
        case EscEccArithS1_STATE_MODULARINVERT_FINISH:
            if ( EscFeArith_IsOne( &ctx->u, ctx->lenWords ) )
            {
                EscFeArith_Assign( ctx->c, &ctx->x1, ctx->lenWords );
            }
            else
            {
                EscFeArith_Assign( ctx->c, &ctx->x2, ctx->lenWords );
            }

            returnCode = Esc_NO_ERROR;

            break;
        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

/****************************************
 * convert a point into an affine point *
 ****************************************/
void
EscEccArithS1_Pt_ToAffineInit(
    EscEccArithS1_Pt_ToAffineContext* ctx,
    EscPtArithWs_PointT* pA,
    const EscPtArithWs_PointT* pJ,
    const EscPtArithWs_CurveT* curve )
{
    Esc_ASSERT( pJ->type == EscPtArith_TYPE_JACOBIAN );

    if ( EscPtArithWs_IsInfinity( pJ, curve ) )
    {
        /* set pA type */
        pA->type = EscPtArith_TYPE_AFFINE;
        /* pA = (0) */
        EscPtArithWs_SetInfinity( pA );

        ctx->state = EscEccArithS1_STATE_TOAFFINE_FINISH;
    }
    else
    {
        ctx->pA = pA;
        ctx->pJ = pJ;
        ctx->curve = curve;

        EscEccArithS1_Fe_ModularInvertInit( &ctx->modInvertCtx, &ctx->fe_z_inv1_3, &ctx->pJ->z, &ctx->curve->ecc_field_params, ctx->curve->curveSize.maxWords );

        ctx->state = EscEccArithS1_STATE_TOAFFINE_MODINVERT;
    }
}

Esc_ERROR
EscEccArithS1_Pt_ToAffineRun(
    EscEccArithS1_Pt_ToAffineContext* ctx )
{
    Esc_ERROR returnCode = Esc_AGAIN;
    /* Shortcuts to curve attributes */
    EscFeArith_CurveId curveId = ctx->curve->curveId;
    const EscFeArith_SizeT* curveSize = &ctx->curve->curveSize;
    const EscFeArith_FieldT* ecc_field_params = &ctx->curve->ecc_field_params;

    switch( ctx->state )
    {
        case EscEccArithS1_STATE_TOAFFINE_MODINVERT:

            /* pJ(1/z) : 1I */
            returnCode = EscEccArithS1_Fe_ModularInvertRun( &ctx->modInvertCtx );

            if ( returnCode == Esc_NO_ERROR )
            {
                /* Finish computation, next state */
                ctx->state = EscEccArithS1_STATE_TOAFFINE_MULTIPY;
                returnCode = Esc_AGAIN;
            }

            break;
        case EscEccArithS1_STATE_TOAFFINE_MULTIPY:
            /* pJ(1/z^2) : 1S */
            EscFeArith_SquareModP( &ctx->fe_z_inv2, &ctx->fe_z_inv1_3, ecc_field_params, curveId, curveSize );
            /* pJ(1/z^3) : 1M */
            EscFeArith_MultiplyModP( &ctx->fe_z_inv1_3, &ctx->fe_z_inv1_3, &ctx->fe_z_inv2, ecc_field_params, curveId, curveSize );
            /* pA(x) = pJ(x/z^2) : 1M */
            EscFeArith_MultiplyModP( &ctx->pA->x, &ctx->pJ->x, &ctx->fe_z_inv2, ecc_field_params, curveId, curveSize );
            /* pA(y) = pJ(y/z^3) : 1M */
            EscFeArith_MultiplyModP( &ctx->pA->y, &ctx->pJ->y, &ctx->fe_z_inv1_3, ecc_field_params, curveId, curveSize );
            /* pA(z) = 0 */
            EscFeArith_SetOne( &ctx->pA->z );
            /* set pA type */
            ctx->pA->type = EscPtArith_TYPE_AFFINE;

            /* Finish */
            returnCode = Esc_NO_ERROR;

            break;
        case EscEccArithS1_STATE_TOAFFINE_FINISH:
            returnCode = Esc_NO_ERROR;

            break;
        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;

}


/***********************************************
 * scalar multiplication of unknown pA1 with k *
 ***********************************************/
#if EscEcc_USE_SLIDING_WINDOW == 1
void EscEccArithS1_Pt_JacobianMultiplyBinaryInit(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve )
{
    Esc_ASSERT( pA1->type == EscPtArith_TYPE_AFFINE );

    /* check P = (0) */
    if ( EscPtArithWs_IsZero( pA1, curve ) )
    {
        /* Finish, pJ = (0) */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        ctx->state = EscEccArithS1_STATE_JACMULTIPLY_FINISH;
    }
    else
    {
        ctx->precompArray[0].type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_Assign( &ctx->precompArray[0].x, &pA1->x, curve->curveSize.maxWords );
        EscFeArith_Assign( &ctx->precompArray[0].y, &pA1->y, curve->curveSize.maxWords );
        EscFeArith_SetOne( &ctx->precompArray[0].z );

        /* pJ = (0) */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        /* Compute 2 x pJ, use last element of precomp array as temporary location */
        EscPtArithWs_JacobianDouble( &ctx->precompArray[EscEcc_NUM_WINDOW_ELEMENTS - 1], &ctx->precompArray[0], curve );

        /* Use the bitIndex variable as a temp loop counter for the pre-computation */
        ctx->bitIndex = 1;
        ctx->pJ = pJ;
        ctx->k = k;
        ctx->curve = curve;
        ctx->state = EscEccArithS1_STATE_JACMULTIPLY_PRECOMPLOOP;
    }
}

Esc_ERROR EscEccArithS1_Pt_JacobianMultiplyBinaryRun(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx )
{
    Esc_ERROR returnCode = Esc_AGAIN;

    switch( ctx->state )
    {
        case EscEccArithS1_STATE_JACMULTIPLY_PRECOMPLOOP:
            /* precomputation - i < ((2^k_m) / 2) + 1 */
            if ( ctx->bitIndex < (Esc_SINT16)EscEcc_NUM_WINDOW_ELEMENTS )
            {
                EscPtArithWs_JacobianAdd( &ctx->precompArray[ctx->bitIndex], &ctx->precompArray[ctx->bitIndex - 1], &ctx->precompArray[EscEcc_NUM_WINDOW_ELEMENTS - 1], ctx->curve );
                ctx->bitIndex++;
            }
            else
            {
                ctx->bitIndex = (Esc_SINT16)( (Esc_SINT16)ctx->curve->curveSize.maxWords * (Esc_SINT16)EscFeArith_WORD_BITS ) - 1;
                /* Next state, actual computation */
                ctx->state = EscEccArithS1_STATE_JACMULTIPLY_NEXTWINDOW;
            }
            break;
        case EscEccArithS1_STATE_JACMULTIPLY_NEXTWINDOW:
            if ( ctx->bitIndex >= 0 )
            {
                /* if Exponent = 0 double only */
                if (EscFeArith_isBitSet( ctx->k, ctx->bitIndex ) == FALSE)
                {
                    EscPtArithWs_JacobianDouble( ctx->pJ, ctx->pJ, ctx->curve );
                    ctx->bitIndex--;
                }
                else
                {
                    /* Build a new window */
                    Esc_UINT16 n;
                    Esc_SINT16 j;

                    ctx->exponent = 0U;
                    n = (Esc_UINT16)(EscEcc_WINDOW_SIZE - 1U);
                    ctx->windowsize = (Esc_SINT16)EscEcc_WINDOW_SIZE;
                    for (j = ctx->bitIndex; ( j > (ctx->bitIndex - (Esc_SINT16)EscEcc_WINDOW_SIZE) ) && (j >= 0); j--)
                    {
                        /* build temporary exponent */
                        if (EscFeArith_isBitSet( ctx->k, j ) == TRUE)
                        {
                            ctx->exponent += (Esc_UINT16)( 1UL << n );
                        }
                        n--;
                    }
                    ctx->bitIndex -= (Esc_SINT16)EscEcc_WINDOW_SIZE;
                    /* make window odd and adjust bitIndex, reduce window size */
                    while ( (ctx->exponent % 2U) == 0U )
                    {
                        ctx->exponent = (Esc_UINT16)(ctx->exponent / 2U);
                        ctx->bitIndex++;
                        ctx->windowsize--;
                    }
                    /* Assert that exponent/2 is within bounds of precompArray */
                    Esc_ASSERT( (ctx->exponent / 2U) < EscEcc_NUM_WINDOW_ELEMENTS );
                    ctx->bitIndexWindow = 0;
                    ctx->state = EscEccArithS1_STATE_JACMULTIPLY_DOUBLE_ADD;
                }
            }
            else
            {
                /* Computation is finished */
                returnCode = Esc_NO_ERROR;
            }

            break;
        case EscEccArithS1_STATE_JACMULTIPLY_DOUBLE_ADD:
            if ( ctx->bitIndexWindow < ctx->windowsize )
            {
                /* Double */
                EscPtArithWs_JacobianDouble( ctx->pJ, ctx->pJ, ctx->curve );
                ctx->bitIndexWindow++;
            }
            else
            {
                /* Add */
                EscPtArithWs_JacobianAdd( ctx->pJ, ctx->pJ, &ctx->precompArray[ctx->exponent / 2U], ctx->curve );
                ctx->state = EscEccArithS1_STATE_JACMULTIPLY_NEXTWINDOW;
            }

            break;
        case EscEccArithS1_STATE_JACMULTIPLY_FINISH:
            /* Finish, result point is already set */ 
            returnCode = Esc_NO_ERROR;

            break;
        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}
#else
void EscEccArithS1_Pt_JacobianMultiplyBinaryInit(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve )
{
    Esc_ASSERT( pA1->type == EscPtArith_TYPE_AFFINE );

    /* check P = (0) */
    if ( EscPtArithWs_IsZero( pA1, curve ) )
    {
        /* Finish, pJ = (0) */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        ctx->state = EscEccArithS1_STATE_JACMULTIPLY_FINISH;
    }
    else
    {
        /* Set temporary point */
        ctx->pTemp.type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_Assign( &ctx->pTemp.x, &pA1->x, curve->curveSize.maxWords );
        EscFeArith_Assign( &ctx->pTemp.y, &pA1->y, curve->curveSize.maxWords );
        EscFeArith_SetOne( &ctx->pTemp.z );

        /* pJ = (0) */
        pJ->type = EscPtArith_TYPE_JACOBIAN;
        EscPtArithWs_SetInfinity( pJ );

        /* Copy pointers to the context */
        ctx->pJ = pJ;
        ctx->k = k;
        ctx->curve = curve;

        ctx->wordIndex = (Esc_SINT16)ctx->curve->curveSize.maxWords - 1;

        /* Next state */
        ctx->state = EscEccArithS1_STATE_JACMULTIPLY_PROCESS_NEXT_WORD;
    }
}

Esc_ERROR EscEccArithS1_Pt_JacobianMultiplyBinaryRun(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx )
{
    Esc_ERROR returnCode = Esc_AGAIN;

    switch( ctx->state )
    {
        case EscEccArithS1_STATE_JACMULTIPLY_PROCESS_NEXT_WORD:
            ctx->bitIndex = 0U;
            ctx->tempWord = ctx->k->word[ctx->wordIndex];

            if ( ctx->wordIndex >= 0 )
            {
                /* process next bit */
                ctx->state = EscEccArithS1_STATE_JACMULTIPLY_DOUBLE;
            }
            else
            {
                /* Finish all words. Result is stored in pJ */
                returnCode = Esc_NO_ERROR;
            }

            break;
        case EscEccArithS1_STATE_JACMULTIPLY_DOUBLE:
            /* Double */
            EscPtArithWs_JacobianDouble( ctx->pJ, ctx->pJ, ctx->curve );

            /* next state */
            ctx->state = EscEccArithS1_STATE_JACMULTIPLY_ADD;

            break;
        case EscEccArithS1_STATE_JACMULTIPLY_ADD:

            if ( (ctx->tempWord & 0x80000000U) != 0U )          /* highest bit set */
            {
                /* Add */
                EscPtArithWs_JacobianAdd( ctx->pJ, ctx->pJ, &ctx->pTemp, ctx->curve );
            }
            ctx->tempWord <<= 1;

            if ( ctx->bitIndex < (EscFeArith_WORD_BITS-1U) )
            {
                /* process next bit */
                ctx->bitIndex++;
                ctx->state = EscEccArithS1_STATE_JACMULTIPLY_DOUBLE;
            }
            else
            {
                /* process next word */
                ctx->wordIndex--;
                ctx->state = EscEccArithS1_STATE_JACMULTIPLY_PROCESS_NEXT_WORD;
            }

            break;
        case EscEccArithS1_STATE_JACMULTIPLY_FINISH:
            /* Finish, result point is already set */ 
            returnCode = Esc_NO_ERROR;

            break;
        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#endif /* EscEcc_USE_SLIDING_WINDOW */

void
EscEccArithS1_Pt_BasePointMultInit(
    EscEccArithS1_Pt_BasePointMultContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_CurveT* curve )
{
#if EscEcc_USE_FIXED_BASE == 1
    /* Fixed base implementation according to Hankerson, et. al,
     * "Guide to Elliptic Curve Cryptography", Alg. 3.41
     */

    /* Set state and copy pointers to context */
    ctx->state = EscEccArithS1_STATE_BASEMULT_GETK;
    ctx->result = pJ;
    ctx->k = k;
    ctx->curve = curve;
#else
    /* Forward to general point multiplication */
    EscEccArithS1_Pt_JacobianMultiplyBinaryInit(
        &ctx->jacMulBinCtx,
        pJ,
        k,
        &curve->base_point_G,
        curve);
#endif
}

Esc_ERROR
EscEccArithS1_Pt_BasePointMultRun(
    EscEccArithS1_Pt_BasePointMultContext* ctx )
{
#if EscEcc_USE_FIXED_BASE == 1
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_BOOL pointAdded;
    Esc_UINT8 i;

    switch (ctx->state)
    {
        case EscEccArithS1_STATE_BASEMULT_GETK:
            /* Initialize temporary point */
            ctx->tempPoint.type = EscPtArith_TYPE_JACOBIAN;
            EscPtArithWs_SetInfinity(&ctx->tempPoint);

            /* Initialize result point */
            ctx->result->type = EscPtArith_TYPE_JACOBIAN;
            EscPtArithWs_SetInfinity(ctx->result);

            /* Extract bit chunks K_i */
            ctx->numChunks = (Esc_UINT8) ((ctx->curve->curveSize.maxWords * 32U) / EscEcc_FIXED_BASE_WINDOW_SIZE);
            for (i = 0U; i < ctx->numChunks; i++)
            {
                EscEccArithS1_Pt_GetK(&ctx->K[i], ctx->k, i);
            }

            /* Initialize counter values */
            ctx->baseCnt = (Esc_UINT8) ((1U << EscEcc_FIXED_BASE_WINDOW_SIZE) - 1U);
            ctx->chunkCnt = 0U;

            ctx->state = EscEccArithS1_STATE_BASEMULT_BASELOOP;
            break;

        case EscEccArithS1_STATE_BASEMULT_BASELOOP:
            pointAdded = FALSE;

            /** Loop over the chunks until all chunk are processed or until first point addition is done */
            for ( ; (ctx->chunkCnt < ctx->numChunks) && (pointAdded == FALSE); ++ctx->chunkCnt)
            {
                if (ctx->K[ctx->chunkCnt] == ctx->baseCnt)
                {
                    const EscPtArithWs_PointT *precomp;
                    EscEcc_GetPrecomputedPoint(&precomp, ctx->curve->curveId, ctx->chunkCnt);
                    EscPtArithWs_JacobianAdd(&ctx->tempPoint, &ctx->tempPoint, precomp, ctx->curve);
                    pointAdded = TRUE;
                }
            }

            /* All chunks processed? */
            if (ctx->chunkCnt >= ctx->numChunks)
            {
                /* Reset chunk counter for next loop invocation */
                ctx->chunkCnt = 0U;

                /* Add temporary point to result in a separate slice */
                ctx->state = EscEccArithS1_STATE_BASEMULT_ADD_TEMP;
            }
            break;

        case EscEccArithS1_STATE_BASEMULT_ADD_TEMP:
            /* Add temporary point to result */
            EscPtArithWs_JacobianAdd(ctx->result, ctx->result, &ctx->tempPoint, ctx->curve);

            /* End of outer base loop */
            ctx->baseCnt--;
            if (ctx->baseCnt == 0U)
            {
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                ctx->state = EscEccArithS1_STATE_BASEMULT_BASELOOP;
            }
            break;

        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
#else
    /* Forward to general point multiplication */
    return EscEccArithS1_Pt_JacobianMultiplyBinaryRun(&ctx->jacMulBinCtx);
#endif
}

/**
 * Calculate k0 * G + k1 * Q with Shamir's trick. *
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 3.48 with w  = 1
 */
#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
void
EscEccArithS1_Pt_JacDualMulAddBinInit(
    EscEccArithS1_Pt_JacDualMulAddBinContext *ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k0,
    const EscPtArithWs_PointT* pA0,
    const EscFeArith_FieldElementT* k1,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve )
{
    const Esc_UINT8 maxWords = curve->curveSize.maxWords;

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

    ctx->pJ = pJ;
    ctx->k0 = k0;
    ctx->k1 = k1;
    ctx->curve = curve;

    ctx->state = EscEccArithS1_STATE_JACDUALMUL_COMPUTE_QP;
}

Esc_ERROR
EscEccArithS1_Pt_JacDualMulAddBinRun(
    EscEccArithS1_Pt_JacDualMulAddBinContext *ctx )
{
    Esc_ERROR returnCode = Esc_AGAIN;

    switch( ctx->state )
    {
        case EscEccArithS1_STATE_JACDUALMUL_COMPUTE_QP:
            /* precompute Q + G */
            EscPtArithWs_JacobianAdd( &ctx->pQPlusG, &ctx->pPA0, &ctx->pPA1, ctx->curve );

            /* initialize conversion of Q+G to affine */
            EscEccArithS1_Pt_ToAffineInit( &ctx->toAffineCtx, &ctx->pQPlusG, &ctx->pQPlusG, ctx->curve );

            ctx->state = EscEccArithS1_STATE_JACDUALMUL_CONVERT_AFFINE;
            break;

        case EscEccArithS1_STATE_JACDUALMUL_CONVERT_AFFINE:
            returnCode = EscEccArithS1_Pt_ToAffineRun( &ctx->toAffineCtx );
            if (returnCode == Esc_NO_ERROR)
            {
                /* Double/add assume points in Jacobian form */
                ctx->pQPlusG.type = EscPtArith_TYPE_JACOBIAN;
                EscFeArith_SetOne( &ctx->pQPlusG.z );

                returnCode = Esc_AGAIN;
                ctx->state = EscEccArithS1_STATE_JACDUALMUL_PREPARE_LOOP;
            }
            break;

        case EscEccArithS1_STATE_JACDUALMUL_PREPARE_LOOP:
            ctx->bitIndex = ( (Esc_SINT16)ctx->curve->curveSize.maxWords * (Esc_SINT16)EscFeArith_WORD_BITS ) - 1;
            /* skip common leading zeros of k0 and k1 */
            while ( !( (EscFeArith_isBitSet( ctx->k0, ctx->bitIndex ) == TRUE)
                    || (EscFeArith_isBitSet( ctx->k1, ctx->bitIndex ) == TRUE) ) )
            {
                ctx->bitIndex--;
            }
            ctx->state = EscEccArithS1_STATE_JACDUALMUL_NEXT_LOOP;
            break;

        case EscEccArithS1_STATE_JACDUALMUL_NEXT_LOOP:
            if ( EscFeArith_isBitSet( ctx->k0, ctx->bitIndex ) )
            {
                if ( EscFeArith_isBitSet( ctx->k1, ctx->bitIndex ) )
                {
                    EscPtArithWs_JacobianAdd( ctx->pJ, ctx->pJ, &ctx->pQPlusG, ctx->curve );
                }
                else
                {
                    EscPtArithWs_JacobianAdd( ctx->pJ,ctx-> pJ, &ctx->pPA0, ctx->curve );
                }
            }
            else
            {
                if ( EscFeArith_isBitSet( ctx->k1, ctx->bitIndex ) )
                {
                    EscPtArithWs_JacobianAdd( ctx->pJ, ctx->pJ, &ctx->pPA1, ctx->curve );
                }
            }

            ctx->bitIndex--;
            if (ctx->bitIndex < 0)
            {
                /* Finish */
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                ctx->state = EscEccArithS1_STATE_JACDUALMUL_DOUBLE;
            }
            break;

        case EscEccArithS1_STATE_JACDUALMUL_DOUBLE:
            EscPtArithWs_JacobianDouble( ctx->pJ, ctx->pJ, ctx->curve );
            ctx->state = EscEccArithS1_STATE_JACDUALMUL_NEXT_LOOP;
            break;

        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}
#endif /* EscFeArith_ENABLE_SHAMIRS_TRICK */

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
