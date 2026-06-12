/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Elliptic Curve Diffie/Hellman (ECDH) and
                Elliptic Curve Digital Signature Algorithm (ECDSA)
                GF(p) point arithmetic
                GF(p) multi-precision integer arithmetic implementations

   $Rev: 4105 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "ecc.h"
#include "ecc_cfg.h"
#include "_fearith.h"
#include "_ptarithws.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/*lint -esym(750,EscEcc_STATE_*) Depending on the configuration, some state symbols may not be used */

/** Invalid state, Init required */
#define EscEcc_STATE_INVALID                        0
/** States for the EC Signature Generation */
#define EscEcc_STATE_SIGGEN_COMPUTE_K              10
#define EscEcc_STATE_SIGGEN_COMPUTE_PX             11
#define EscEcc_STATE_SIGGEN_CONVERT_PX             12
#define EscEcc_STATE_SIGGEN_COMPUTE_R              13
#define EscEcc_STATE_SIGGEN_COMPUTE_S              14
#define EscEcc_STATE_SIGGEN_FINISH                 15
/** States for the EC Signature Verification (common states) */
#define EscEcc_STATE_SIGVER_COMPUTE_W              20
#define EscEcc_STATE_SIGVER_COMPUTE_U1U2           21
#define EscEcc_STATE_SIGVER_CONVERT_POINT          22
#define EscEcc_STATE_SIGVER_FINISH                 23
/** States for the EC Signature Verification (for non-Shamir's trick variant) */
#define EscEcc_STATE_SIGVER_COMPUTE_POINT1         24
#define EscEcc_STATE_SIGVER_COMPUTE_POINT2         25
#define EscEcc_STATE_SIGVER_ADD_POINTS             26
/** States for the EC Signature Verification (for Shamir's trick variant) */
#define EscEcc_STATE_SIGVER_COMPUTE_POINT12        27
/** States for the ECDH */
#define EscEcc_STATE_ECDH_COMPUTE_PX               30
#define EscEcc_STATE_ECDH_CONVERT_PX               31
/** States for the EC Key Generation */
#define EscEcc_STATE_KEYGEN_COMPUTE_PQ             40
#define EscEcc_STATE_KEYGEN_CONVERT_PQ             41

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if EscEcc_ECDH_ENABLED == 1
Esc_ERROR
EscEcc_ComputeSharedSecretInit(
    EscEcc_SharedSecretContext *ctx,
    Esc_UINT8 sharedSecret[],
    Esc_UINT32* sharedSecretLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_PublicKeyT* pQB,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Parameter check */
    if ( (ctx == Esc_NULL_PTR) || (sharedSecret == Esc_NULL_PTR) || (sharedSecretLen == Esc_NULL_PTR) || (privKey == Esc_NULL_PTR) || (pQB == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Lookup curve */
    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscEcc_STATE_INVALID;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }

    if ( (returnCode == Esc_NO_ERROR) && (*sharedSecretLen < ctx->curve->curveSize.keySizeBytes) )
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }

    if ( (returnCode == Esc_NO_ERROR) && (privKeyLen != ctx->curve->curveSize.keySizeBytes) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* allocate field element for privKey */
        EscFeArith_FromUint8( privKey, privKeyLen, &ctx->dA_ecc_field_element, &ctx->curve->curveSize );

        /* convert public key to EscEcc_FieldElementTs */
        ctx->pX.type = EscPtArith_TYPE_AFFINE;
        EscFeArith_FromUint8( pQB->x, ctx->curve->curveSize.keySizeBytes, &ctx->pX.x, &ctx->curve->curveSize );
        EscFeArith_FromUint8( pQB->y, ctx->curve->curveSize.keySizeBytes, &ctx->pX.y, &ctx->curve->curveSize );

        /* Init point multiplication */
        EscEcc_Pt_JacobianMultiplyBinaryInit( &ctx->serialCtx.jacobMulBinCtx, &ctx->pX, &ctx->dA_ecc_field_element, &ctx->pX, ctx->curve );

        ctx->sharedSecret = sharedSecret;
        ctx->sharedSecretLen = sharedSecretLen;
        ctx->state = EscEcc_STATE_ECDH_COMPUTE_PX;
    }

    return returnCode;
}


Esc_ERROR
EscEcc_ComputeSharedSecretRun(
    EscEcc_SharedSecretContext *ctx )
{
    Esc_ERROR returnCode;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = Esc_AGAIN;

        switch (ctx->state)
        {
            case EscEcc_STATE_ECDH_COMPUTE_PX:
                returnCode = EscEcc_Pt_JacobianMultiplyBinaryRun( &ctx->serialCtx.jacobMulBinCtx );

                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, init next Function, next state */
                    EscEcc_Pt_ToAffineInit( &ctx->serialCtx.toAffineCtx, &ctx->pX, &ctx->pX, ctx->curve );
                    ctx->state = EscEcc_STATE_ECDH_CONVERT_PX;
                    returnCode = Esc_AGAIN;
                }
                break;
            case EscEcc_STATE_ECDH_CONVERT_PX:
                returnCode = EscEcc_Pt_ToAffineRun( &ctx->serialCtx.toAffineCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation. Final operations. */
                    if ( EscPtArithWs_IsZero( &ctx->pX, ctx->curve ) )
                    {
                        returnCode = Esc_INTERNAL_FUNCTION_ERROR;
                    }
                    else
                    {
                        /* 03.) shared secret value z = pX->x */
                        *(ctx->sharedSecretLen) = ctx->curve->curveSize.keySizeBytes;
                        EscFeArith_ToUint8( &ctx->pX.x, ctx->sharedSecret, &ctx->curve->curveSize );
                    }
                }
                break;
            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscEcc_STATE_INVALID;
        }
    }

    return returnCode;
}

#endif /* EscEcc_ECDH */


Esc_ERROR
EscEcc_KeyGenerationInit(
    EscEcc_KeyGenerationContext *ctx,
    EscEcc_PublicKeyT* pQ,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (pQ == Esc_NULL_PTR) || (privKey == Esc_NULL_PTR) || (privKeyLen == Esc_NULL_PTR) || (getRandomFunc == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Lookup curve */
    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscEcc_STATE_INVALID;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }

    if ( (returnCode == Esc_NO_ERROR) && (*privKeyLen < ctx->curve->curveSize.keySizeBytes) )
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPtArithWs_CalculateRandomK(randomState, getRandomFunc, ctx->curve, &ctx->d_ecc_field_element);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* calculate public key pQ = d * G mod p */
        EscEcc_Pt_BasePointMultInit( &ctx->serialCtx.basePointMultCtx, &ctx->pQ_point, &ctx->d_ecc_field_element, ctx->curve);

        ctx->privKey = privKey;
        ctx->privKeyLen = privKeyLen;
        ctx->pQ = pQ;
        ctx->state = EscEcc_STATE_KEYGEN_COMPUTE_PQ;
    }

    return returnCode;
}

Esc_ERROR
EscEcc_KeyGenerationRun(
    EscEcc_KeyGenerationContext *ctx )
{
    Esc_ERROR returnCode;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = Esc_AGAIN;

        switch (ctx->state)
        {
            case EscEcc_STATE_KEYGEN_COMPUTE_PQ:
                /* calculate public key pQ = d * G mod p */
                returnCode = EscEcc_Pt_BasePointMultRun( &ctx->serialCtx.basePointMultCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, init next Function, next state */
                    EscEcc_Pt_ToAffineInit( &ctx->serialCtx.toAffineCtx, &ctx->pQ_point, &ctx->pQ_point, ctx->curve );
                    ctx->state = EscEcc_STATE_KEYGEN_CONVERT_PQ;
                    returnCode = Esc_AGAIN;
                }
            break;
            case EscEcc_STATE_KEYGEN_CONVERT_PQ:
                /* convert Jacobian pQ into affine pQ mod p */
                returnCode = EscEcc_Pt_ToAffineRun( &ctx->serialCtx.toAffineCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    *(ctx->privKeyLen) = ctx->curve->curveSize.keySizeBytes;
                    /* convert private and public key to Esc_UINT8 */
                    EscFeArith_ToUint8( &ctx->d_ecc_field_element, ctx->privKey, &ctx->curve->curveSize );
                    EscFeArith_ToUint8( &ctx->pQ_point.x, ctx->pQ->x, &ctx->curve->curveSize );
                    EscFeArith_ToUint8( &ctx->pQ_point.y, ctx->pQ->y, &ctx->curve->curveSize );
                }
                break;
            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscEcc_STATE_INVALID;
        }
    }

    return returnCode;
}


#if EscEcc_ECDSA_ENABLED == 1
Esc_ERROR
EscEcc_SignatureVerificationInit(
    EscEcc_SigVerContext *ctx,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const EscEcc_SignatureT* signature,
    const EscEcc_PublicKeyT* pQ,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Parameter check */
    if ( (ctx == Esc_NULL_PTR) || (msgHash == Esc_NULL_PTR) || (signature == Esc_NULL_PTR) || (pQ == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Lookup curve */
    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscEcc_STATE_INVALID;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->pQ_point.type = EscPtArith_TYPE_AFFINE;
        EscFeArith_FromUint8( pQ->x, ctx->curve->curveSize.keySizeBytes, &ctx->pQ_point.x, &ctx->curve->curveSize );
        EscFeArith_FromUint8( pQ->y, ctx->curve->curveSize.keySizeBytes, &ctx->pQ_point.y, &ctx->curve->curveSize );

        EscFeArith_FromUint8( signature->r_bytes, ctx->curve->curveSize.keySizeBytes, &ctx->r, &ctx->curve->curveSize );
        EscFeArith_FromUint8( signature->s_bytes, ctx->curve->curveSize.keySizeBytes, &ctx->s, &ctx->curve->curveSize );
        EscFeArith_FromUint8( msgHash, msgHashLen, &ctx->hash_u1, &ctx->curve->curveSize );
#if (EscEcc_SECP_521_ENABLED == 1)
        if ( ctx->curve->curveSize.keySizeBits == 521U )
        {
            /* For NIST P521 we have to make sure that only 521 bits (leftmost log_2(n)) bits from the hash are used.
               The most significant 23 bits from the most significant word are cleared. */
            ctx->hash_u1.word[ctx->curve->curveSize.keySizeWords - 1U] &= 0x000001FFU;
        }
#endif

        /* 1.) obtain an authentic copy of A's public key (E,G,n,Q) */
        /* 2.) verify that r and s are integers in the interval [ 1, n - 1 ] */

        /* check r */
        if ( (EscFeArith_AbsoluteCompare( &ctx->r, &ctx->curve->base_point_order_n.prime_p, ctx->curve->curveSize.maxWords ) != -1) || /* r >= n */
             (EscFeArith_IsZero( &ctx->r, ctx->curve->curveSize.maxWords ) != FALSE) )                                                 /* r == 0 */
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* check s */
        if ( (EscFeArith_AbsoluteCompare( &ctx->s, &ctx->curve->base_point_order_n.prime_p, ctx->curve->curveSize.maxWords ) != -1) || /* s >= n */
             (EscFeArith_IsZero( &ctx->s, ctx->curve->curveSize.maxWords ) != FALSE) )                                                 /* s == 0 */
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 3.) compute w = s^(-1) mod n. We use u2 as a temporary storage for w. */
        EscEcc_Fe_ModularInvertInit( &ctx->serialCtx.modInvertCtx, &ctx->u2, &ctx->s, &ctx->curve->base_point_order_n, ctx->curve->curveSize.maxWords );
        ctx->state = EscEcc_STATE_SIGVER_COMPUTE_W;
    }

    return returnCode;
}


Esc_ERROR
EscEcc_SignatureVerificationRun(
    EscEcc_SigVerContext *ctx )
{
    Esc_ERROR returnCode;

    /* Parameter check */
    if ( ctx == Esc_NULL_PTR )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = Esc_AGAIN;

        switch (ctx->state)
        {
            case EscEcc_STATE_SIGVER_COMPUTE_W:
                returnCode = EscEcc_Fe_ModularInvertRun( &ctx->serialCtx.modInvertCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, next state */
                    ctx->state = EscEcc_STATE_SIGVER_COMPUTE_U1U2;
                    returnCode = Esc_AGAIN;
                }

                break;
            case EscEcc_STATE_SIGVER_COMPUTE_U1U2:
                /* 4.a) compute u1 = h(m) * w mod n */
                EscFeArith_MultiplyModN( &ctx->hash_u1, &ctx->hash_u1, &ctx->u2, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

                /* 4.b) compute u2 = r * w mod n */
                EscFeArith_MultiplyModN( &ctx->u2, &ctx->r, &ctx->u2, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

#if EscEcc_USE_SHAMIRS_TRICK == 1
                /* Init JacobianDualMultiplyAdd */
                EscEcc_Pt_JacDualMulAddBinInit( &ctx->serialCtx.jacDualMulBinCtx, &ctx->pX1, &ctx->hash_u1, &ctx->curve->base_point_G, &ctx->u2, &ctx->pQ_point, ctx->curve );
                ctx->state = EscEcc_STATE_SIGVER_COMPUTE_POINT12;
#else
                /* Init JacobianMultiply */
                EscEcc_Pt_JacobianMultiplyBinaryInit( &ctx->serialCtx.jacobMulBinCtx, &ctx->pX1, &ctx->hash_u1, &ctx->curve->base_point_G, ctx->curve );
                ctx->state = EscEcc_STATE_SIGVER_COMPUTE_POINT1;
#endif
                break;
#if EscEcc_USE_SHAMIRS_TRICK == 1
            case EscEcc_STATE_SIGVER_COMPUTE_POINT12:
                returnCode = EscEcc_Pt_JacDualMulAddBinRun( &ctx->serialCtx.jacDualMulBinCtx );

                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, init toAffine, next state */
                    EscEcc_Pt_ToAffineInit( &ctx->serialCtx.toAffineCtx, &ctx->pX1, &ctx->pX1, ctx->curve );
                    ctx->state = EscEcc_STATE_SIGVER_CONVERT_POINT;
                    returnCode = Esc_AGAIN;
                }
                break;
#else
            case EscEcc_STATE_SIGVER_COMPUTE_POINT1:
                returnCode = EscEcc_Pt_JacobianMultiplyBinaryRun( &ctx->serialCtx.jacobMulBinCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, init next JacobianMultiply, next state */
                    EscEcc_Pt_JacobianMultiplyBinaryInit( &ctx->serialCtx.jacobMulBinCtx, &ctx->pX2, &ctx->u2, &ctx->pQ_point, ctx->curve );
                    ctx->state = EscEcc_STATE_SIGVER_COMPUTE_POINT2;
                    returnCode = Esc_AGAIN;
                }
                break;
            case EscEcc_STATE_SIGVER_COMPUTE_POINT2:
                returnCode = EscEcc_Pt_JacobianMultiplyBinaryRun( &ctx->serialCtx.jacobMulBinCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, next state */
                    ctx->state = EscEcc_STATE_SIGVER_ADD_POINTS;
                    returnCode = Esc_AGAIN;
                }

                break;
            case EscEcc_STATE_SIGVER_ADD_POINTS:
                EscPtArithWs_JacobianAdd( &ctx->pX1, &ctx->pX1, &ctx->pX2, ctx->curve );
                /* Finish computation, init toAffine, next state */
                EscEcc_Pt_ToAffineInit( &ctx->serialCtx.toAffineCtx, &ctx->pX1, &ctx->pX1, ctx->curve );
                ctx->state = EscEcc_STATE_SIGVER_CONVERT_POINT;

                break;
#endif /* EscEcc_USE_SHAMIRS_TRICK */

            case EscEcc_STATE_SIGVER_CONVERT_POINT:
                returnCode = EscEcc_Pt_ToAffineRun( &ctx->serialCtx.toAffineCtx );
                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, next state */
                    ctx->state = EscEcc_STATE_SIGVER_FINISH;
                    returnCode = Esc_AGAIN;
                }

                break;
            case EscEcc_STATE_SIGVER_FINISH:
            {
                EscFeArith_FieldElementLongT x1Longx;
                /* 5.b) compute v = x0 mod n */
                /* we need a long version of x1 */
                EscFeArith_ToLongElement( &x1Longx, &ctx->pX1.x, ctx->curve->curveSize.maxWords );
                EscFeArith_ReduceBarrett( &ctx->s, &x1Longx, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

                /* 6.) accept signature if and only if v = r, we use s for temporary storage for v. */
                if (EscFeArith_AbsoluteCompare( &ctx->s, &ctx->r, ctx->curve->curveSize.maxWords ) != 0)
                {
                    returnCode = Esc_INVALID_SIGNATURE;
                }
                else
                {
                    returnCode = Esc_NO_ERROR;
                }
                break;
            }
            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscEcc_STATE_INVALID;
        }
    }

    return returnCode;
}


Esc_ERROR
EscEcc_SignatureGenerationInit(
    EscEcc_SigGenContext *ctx,
    EscEcc_SignatureT* signature,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    void* randomState,             /* used to calculate k according to Algo B.5.2 from FIPS186-4 (page 64) */
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Parameter check */
    if ( (ctx == Esc_NULL_PTR) || (signature == Esc_NULL_PTR) || (msgHash == Esc_NULL_PTR) || (privKey == Esc_NULL_PTR) || (getRandomFunc == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Lookup curve */
    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscEcc_STATE_INVALID;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }

    /* We currently do not allow any hash lengths > 64 bytes due to issues with P-521 */
    if ( (returnCode == Esc_NO_ERROR) && (msgHashLen > 64U) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }

    if ( (returnCode == Esc_NO_ERROR) && (privKeyLen != ctx->curve->curveSize.keySizeBytes) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* convert to EscEcc_FieldElementT */
        EscFeArith_FromUint8( privKey, privKeyLen, &ctx->d_ecc_field_element, &ctx->curve->curveSize );
        EscFeArith_FromUint8( msgHash, msgHashLen, &ctx->msg_hash_ecc_field_element, &ctx->curve->curveSize );

#if (EscEcc_SECP_521_ENABLED == 1)
        if ( ctx->curve->curveSize.keySizeBits == 521U )
        {
            /* For NIST P521 we have to make sure that only 521 bits (leftmost log_2(n)) bits from the hash are used.
               The most significant 23 bits from the most significant word are cleared. */
            ctx->msg_hash_ecc_field_element.word[ctx->curve->curveSize.keySizeWords - 1U] &= 0x000001FFU;
        }
#endif

        ctx->signature = signature;
        ctx->randomState = randomState;
        ctx->getRandomFunc = getRandomFunc;
        ctx->generateNonceCount = 0U;
        ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_K;
    }

    return returnCode;
}


Esc_ERROR
EscEcc_SignatureGenerationRun(
    EscEcc_SigGenContext *ctx )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = Esc_AGAIN;

        switch (ctx->state)
        {
            case EscEcc_STATE_SIGGEN_COMPUTE_K:
                returnCode = EscPtArithWs_CalculateRandomK(ctx->randomState, ctx->getRandomFunc, ctx->curve, &ctx->k_ecc_field_element);
                if (returnCode == Esc_NO_ERROR)
                {
                    /* Finish computation, init next Function, next state */
                    EscEcc_Pt_BasePointMultInit( &ctx->serialCtx.basePointMultCtx, &ctx->pX, &ctx->k_ecc_field_element, ctx->curve);

                    ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_PX;
                    returnCode = Esc_AGAIN;
                }
                /* If error occurs during calculation of k the possible reasons are: error code from underlying PRNG
                   (e.g. entropy exhausted), or no fitting random value was returned for EscPtArithWs_MAX_RANDOM_CALLS
                   calls of the PRNG (possible corruptness of PRNG) */
                break;

            case EscEcc_STATE_SIGGEN_COMPUTE_PX:
                /* 2.) compute k * G = ( x1 , y1 ) */
                /* pX = k * G mod p */
                returnCode = EscEcc_Pt_BasePointMultRun( &ctx->serialCtx.basePointMultCtx );

                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, init next Function, next state */
                    EscEcc_Pt_ToAffineInit( &ctx->serialCtx.toAffineCtx, &ctx->pX, &ctx->pX, ctx->curve );
                    ctx->state = EscEcc_STATE_SIGGEN_CONVERT_PX;
                    returnCode = Esc_AGAIN;
                }
                break;

            case EscEcc_STATE_SIGGEN_CONVERT_PX:
                returnCode = EscEcc_Pt_ToAffineRun( &ctx->serialCtx.toAffineCtx );

                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, next state */
                    ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_R;
                    returnCode = Esc_AGAIN;
                }
                break;

            case EscEcc_STATE_SIGGEN_COMPUTE_R:
            {
                /* Temporary Long Field Element */
                EscFeArith_FieldElementLongT x1Longx;

                /* r = pX.x1 mod n */
                EscFeArith_ToLongElement( &x1Longx, &ctx->pX.x, ctx->curve->curveSize.maxWords );
                EscFeArith_ReduceBarrett( &ctx->r_s, &x1Longx, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

                /* if r = 0, then go to step 1 (because s = k^(-l) * { h(m) + d * r} mod n
                 * does not involve the private key d! */
                if ( EscFeArith_IsZero( &ctx->r_s, ctx->curve->curveSize.maxWords ) )
                {
                    /* In case of r = 0, go back to step 1. */
                    ctx->generateNonceCount++;
                    if (ctx->generateNonceCount < EscEcc_MAX_GENERATE_NONCE_CALLS )
                    {
                        ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_K;
                    }
                    else
                    {
                        /* Threshold for random value computations exceeded. */
                        returnCode = Esc_INTERNAL_FUNCTION_ERROR;
                    }
                }
                else
                {
                    /* Finish computation, init next Function, next state */
                    EscEcc_Fe_ModularInvertInit( &ctx->serialCtx.modInvertCtx, &ctx->k_ecc_field_element, &ctx->k_ecc_field_element, &ctx->curve->base_point_order_n, ctx->curve->curveSize.maxWords );
                    ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_S;
                }
                break;
            }
            case EscEcc_STATE_SIGGEN_COMPUTE_S:
                /* 3.) compute k^(-1) mod n. Use same k for the the resulting inverse. */
                /* fe_k = k^(-1) mod n */
                returnCode = EscEcc_Fe_ModularInvertRun( &ctx->serialCtx.modInvertCtx );

                if ( returnCode == Esc_NO_ERROR )
                {
                    /* Finish computation, next state */
                    ctx->state = EscEcc_STATE_SIGGEN_FINISH;
                    returnCode = Esc_AGAIN;
                }
                break;

            case EscEcc_STATE_SIGGEN_FINISH:
                /* 6.) signature for the message m is the pair of integers (r, s). Copy part r. */
                EscFeArith_ToUint8( &ctx->r_s, ctx->signature->r_bytes, &ctx->curve->curveSize );

                /* 4.) compute s = k^(-l) * { h(m) + d * r} mod n (where h(m) is the hashed message) */

                /* s = d * r mod n */
                EscFeArith_MultiplyModN( &ctx->r_s, &ctx->d_ecc_field_element, &ctx->r_s, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

                /* s = h(m) + s mod n */
                EscFeArith_ModularAdd( &ctx->r_s, &ctx->msg_hash_ecc_field_element, &ctx->r_s, &ctx->curve->base_point_order_n, ctx->curve->curveSize.maxWords );

                /* s = k^(-l) * s mod n  */
                EscFeArith_MultiplyModN( &ctx->r_s, &ctx->k_ecc_field_element, &ctx->r_s, &ctx->curve->base_point_order_n, &ctx->curve->curveSize );

                /* 5.) if s = 0, then go to step 1 (if s = 0, then s^(-1) mod n does not exist,
                 *     but s^(-1) is required in step 2 of signature verification)  */
                if ( EscFeArith_IsZero( &ctx->r_s, ctx->curve->curveSize.maxWords ) )
                {
                    /* In case of s = 0, go back to step 1. */
                    ctx->generateNonceCount++;
                    if (ctx->generateNonceCount < EscEcc_MAX_GENERATE_NONCE_CALLS )
                    {
                        ctx->state = EscEcc_STATE_SIGGEN_COMPUTE_K;
                    }
                    else
                    {
                        /* Threshold for random value computations exceeded. */
                        returnCode = Esc_INTERNAL_FUNCTION_ERROR;
                    }
                }
                else
                {
                    /* 6.) signature for the message m is the pair of integers (r, s) */
                    EscFeArith_ToUint8( &ctx->r_s, ctx->signature->s_bytes, &ctx->curve->curveSize );
                    /* Zerorize remaining bytes of signature byte arrays */
                    for ( i = ctx->curve->curveSize.keySizeBytes; i < EscFeArith_KEY_BYTES_MAX; i++ )
                    {
                        ctx->signature->r_bytes[i] = 0U;
                        ctx->signature->s_bytes[i] = 0U;
                    }

                    returnCode = Esc_NO_ERROR;
                }
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscEcc_STATE_INVALID;
        }
    }

    return returnCode;
}

#endif /* EscEcc_ECDSA */


/*******************************************
 * generates public and private key        *
 *******************************************/
Esc_ERROR
EscEcc_KeyGeneration(
    EscEcc_PublicKeyT* pQ,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode;
    EscEcc_KeyGenerationContext ctx;

    /* Initialize key generation */
    returnCode = EscEcc_KeyGenerationInit( &ctx, pQ, privKey, privKeyLen, randomState, getRandomFunc, curveId );

    /* Run sliced key generation */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscEcc_KeyGenerationRun( &ctx );
        } while (returnCode == Esc_AGAIN);
    }

    /* Zeroize key generation context as it contains the private key*/
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/**
 * Validate public key. C.f. ANSI X9.62-2005 Section A.4.2.
 * Invert a field element with modulus p applying the Binary Extended Euclidean algorithm.
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 2.22
 */
Esc_ERROR
EscEcc_PublicKeyValidation(
    const EscEcc_PublicKeyT* pQ,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    const EscPtArithWs_CurveT* curve = Esc_NULL_PTR;
    EscPtArithWs_PointT pQ_point;
    EscFeArith_FieldElementT T1;
    EscFeArith_FieldElementT T2;

    if (pQ == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Lookup curve */
    if (returnCode == Esc_NO_ERROR)
    {
        curve = EscPtArithWs_GetCurve(curveId);
        if (curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        pQ_point.type = EscPtArith_TYPE_AFFINE;

        /* convert to EscEcc_FieldElementT */
        EscFeArith_FromUint8( pQ->x, curve->curveSize.keySizeBytes, &pQ_point.x, &curve->curveSize );
        EscFeArith_FromUint8( pQ->y, curve->curveSize.keySizeBytes, &pQ_point.y, &curve->curveSize );

        /* A.) check Q != (0) */
        if (EscPtArithWs_IsInfinity( &pQ_point, curve ) == TRUE)
        {
            returnCode = Esc_INVALID_ECC_KEY;
        }
        /* B.) check that Q(x,y) consists of properly represented elements of GF(p) */
        else if (EscFeArith_AbsoluteCompare( &pQ_point.x, &curve->ecc_field_params.prime_p, curve->curveSize.maxWords ) != -1)
        {
            returnCode = Esc_INVALID_ECC_KEY;
        }
        else if (EscFeArith_AbsoluteCompare( &pQ_point.y, &curve->ecc_field_params.prime_p, curve->curveSize.maxWords ) != -1)
        {
            returnCode = Esc_INVALID_ECC_KEY;
        }
        else
        {
            /* C.) check Q on curve cGP: y^2 = x^3 + a * x + b */

            /* 01.) T1 = x^2 mod p */
            EscFeArith_SquareModP( &T1, &pQ_point.x, &curve->ecc_field_params, curve->curveId, &curve->curveSize );

            /* 02.) T1 = x^3 mod p */
            EscFeArith_MultiplyModP( &T1, &T1, &pQ_point.x, &curve->ecc_field_params, curve->curveId, &curve->curveSize );

            /* 03.) T2 = a * x mod p */
            EscFeArith_MultiplyModP( &T2, &curve->coefficient_a, &pQ_point.x, &curve->ecc_field_params, curve->curveId, &curve->curveSize );

            /* 04.) T1 = T1 + T2 <=> x^3 + a * x mod p */
            EscFeArith_ModularAdd( &T1, &T1, &T2, &curve->ecc_field_params, curve->curveSize.maxWords );

            /* 05.) T1 = T1 + b <=> x^3 + a * x + b mod p */
            EscFeArith_ModularAdd( &T1, &T1, &curve->coefficient_b, &curve->ecc_field_params, curve->curveSize.maxWords );

            /* 06.) T2 = y^2 mod p */
            EscFeArith_SquareModP( &T2, &pQ_point.y, &curve->ecc_field_params, curve->curveId, &curve->curveSize );

            /* 07.) T1 =? T2 <=> y^2 =? x^3 + a * x + b mod p */
            if (EscFeArith_AbsoluteCompare( &T1, &T2, curve->curveSize.maxWords ) == 0)
            {
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                returnCode = Esc_INVALID_ECC_KEY;
            }
            /* D.) is not required for used chosen SECP and Brainpool curves with cofactor h = 1, see Section I.3.2. */
        }
    }

    return returnCode;
}

#if EscEcc_ECDSA_ENABLED == 1
/***********************************************
 * Generate the signature for a hashed message *
 ***********************************************/
Esc_ERROR
EscEcc_SignatureGeneration(
    EscEcc_SignatureT* signature,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    void* randomState,             /* used to calculate k according to Algo B.5.2 from FIPS186-4 (page 64) */
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode;
    EscEcc_SigGenContext ctx;

    /* Initialize computation */
    returnCode = EscEcc_SignatureGenerationInit(&ctx, signature, msgHash, msgHashLen, privKey, privKeyLen, randomState, getRandomFunc, curveId );

    /* Run sliced Signature Generation */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscEcc_SignatureGenerationRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    /* Zeroize Signature Generation context as it contains the private key */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/*****************************************
 * Verify signature for a hashed message *
 *****************************************/
Esc_ERROR
EscEcc_SignatureVerification(
    const Esc_UINT8 msgHash[],          /* hash of signing message */
    Esc_UINT32 msgHashLen,
    const EscEcc_SignatureT* signature, /* ECC signature           */
    const EscEcc_PublicKeyT* pQ,        /* public key Q            */
    const EscEcc_CurveId curveId )      /* used curve              */
{
    Esc_ERROR returnCode;
    EscEcc_SigVerContext ctx;

    /* Initialize computation */
    returnCode = EscEcc_SignatureVerificationInit(&ctx, msgHash, msgHashLen, signature, pQ, curveId );

    /* Run sliced Signature Verification */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscEcc_SignatureVerificationRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}
#endif /* EscEcc_ECDSA */

#if EscEcc_ECDH_ENABLED == 1
/*****************************************
 * compute shared secret z based on ECDH *
 *****************************************/
Esc_ERROR
EscEcc_ComputeSharedSecret(
    Esc_UINT8 sharedSecret[],
    Esc_UINT32* sharedSecretLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_PublicKeyT* pQB,
    const EscEcc_CurveId curveId )
{
    Esc_ERROR returnCode;
    EscEcc_SharedSecretContext ctx;

    /* Initialize computation */
    returnCode = EscEcc_ComputeSharedSecretInit( &ctx, sharedSecret, sharedSecretLen, privKey, privKeyLen, pQB, curveId );

    /* Run sliced Shared Secret computation */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscEcc_ComputeSharedSecretRun( &ctx );
        } while (returnCode == Esc_AGAIN);
    }

    /* Zeroize shared secret context as it contains the shared secret*/
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}
#endif /* EscEcc_ECDH */

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
