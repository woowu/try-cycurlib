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

#ifndef ESC_ECCARITH_S1_H_
#define ESC_ECCARITH_S1_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"
#include "_fearith.h"
#include "_ptarithws.h"
#include "random.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/
/** Modular inversion context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Temporary Field Element u. */
    EscFeArith_FieldElementT u;
    /** Temporary Field Element v. */
    EscFeArith_FieldElementT v;
    /** Temporary Field Element x1. */
    EscFeArith_FieldElementT x1;
    /** Temporary Field Element x2. */
    EscFeArith_FieldElementT x2;
    /** Pointer to the result buffer c */
    EscFeArith_FieldElementT* c;
    /** Pointer to the used field */
    const EscFeArith_FieldT* fGP;
    /** Length of words used for the field elements. */
    Esc_UINT8 lenWords;
} EscEccArithS1_Fe_ModularInvertContext;

/** Jacobian to affine conversion context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Pointer to the result resulting point buffer. */
    EscPtArithWs_PointT* pA;
    /** Pointer to the input point. */
    const EscPtArithWs_PointT* pJ;
    /** Pointer to the used curve */
    const EscPtArithWs_CurveT* curve;
    /** Temporary Field Element for storing pJ(1/z) and pJ(1/z^3). */
    EscFeArith_FieldElementT fe_z_inv1_3;
    /** Temporary Field Element for storing pJ(1/z^2). */
    EscFeArith_FieldElementT fe_z_inv2;
    /** Context for the modular inversion. */
    EscEccArithS1_Fe_ModularInvertContext modInvertCtx;
} EscEccArithS1_Pt_ToAffineContext;

/** Point multiplication context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;

    /** Pointer to the scalar multiplicand */
    const EscFeArith_FieldElementT* k;
    /** Pointer to the result point buffer */
    EscPtArithWs_PointT* pJ;
    /** Pointer to the used curve */
    const EscPtArithWs_CurveT* curve;

#if EscEcc_USE_SLIDING_WINDOW == 1
    /** Point array for precomputations */
    EscPtArithWs_PointT precompArray[EscEcc_NUM_WINDOW_ELEMENTS];
    /** Bit index for current processed bit */
    Esc_SINT16 bitIndex;
    /** Exponent window */
    Esc_UINT16 exponent;
    /** Size of current window */
    Esc_SINT16 windowsize;
    /** BitIndex inside current window */
    Esc_SINT16 bitIndexWindow;
#else
    /** Bit index for current processed bit */
    Esc_UINT16 bitIndex;
    /** Temporary point for double and add */
    EscPtArithWs_PointT pTemp;

    /** Word index for current processed bit */
    Esc_SINT16 wordIndex;
    /** Copy of the current processed word of the exponent */
    Esc_UINT32 tempWord;
#endif

} EscEccArithS1_Pt_JacobianMultiplyBinaryContext;

/** Context for multiplication with base point. */
typedef struct
{
#if EscEcc_USE_FIXED_BASE == 1
    /** Array to store the scalar of the multiplication in n-bit words where n
     * is the size of the fixed-base window.
     */
    Esc_UINT8 K[(EscFeArith_MAX_WORDS * 32U) / EscEcc_FIXED_BASE_WINDOW_SIZE];

    /** State of the computation */
    Esc_UINT8 state;

    /** Number of chunks */
    Esc_UINT8 numChunks;
    /** Base loop counter */
    Esc_UINT8 baseCnt;
    /** Chunk loop counter */
    Esc_UINT8 chunkCnt;

    /** Pointer to the point holding the result */
    EscPtArithWs_PointT *result;
    /** Temporary working point */
    EscPtArithWs_PointT tempPoint;

    /** Pointer to the scalar operand of the multiplication */
    const EscFeArith_FieldElementT* k;
    /** The curve of the multiplication */
    const EscPtArithWs_CurveT* curve;

#else
    /** General multiplication context */
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext jacMulBinCtx;
#endif
} EscEccArithS1_Pt_BasePointMultContext;

#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
/** Dual multiply/double scalar context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;

    /** Pointer to the first scalar multiplicand */
    const EscFeArith_FieldElementT* k0;
    /** Pointer to the second scalar multiplicand */
    const EscFeArith_FieldElementT* k1;
    /** Pointer to the result point buffer */
    EscPtArithWs_PointT* pJ;
    /** Pointer to the used curve */
    const EscPtArithWs_CurveT* curve;
    /** Temporary point for the input point A0 in jacobian form */
    EscPtArithWs_PointT pPA0;
    /** Temporary point for the input point A1 in jacobian form */
    EscPtArithWs_PointT pPA1;
    /** Temporary point for A0 + A1 */
    EscPtArithWs_PointT pQPlusG;
    /** Bit index for current processed bit */
    Esc_SINT16 bitIndex;
    /** Context to convert pQPlusG to affine form */
    EscEccArithS1_Pt_ToAffineContext toAffineCtx;
} EscEccArithS1_Pt_JacDualMulAddBinContext;
#endif

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/
/**
 * Init the modular inversion of a field element.
 *
 * Field Elements c and a can point to the same location (aliased).
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx Modular inversion context.
 * \param[out] c Resulting field element.
 * \param[in]  a Input field element. Must not be 0, and smaller than the prime of fGP.
 * \param[in]  fGP Used field.
 * \param[in]  lenWords Length of used words in the field elements.
 */
void
EscEccArithS1_Fe_ModularInvertInit(
    EscEccArithS1_Fe_ModularInvertContext* ctx,
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords );

/**
 * Run the modular inversion of a field element.
 *
 * \param[in,out] ctx Modular inversion context.
 *
 * \retval Esc_AGAIN       The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR    The computation finished successfully.
 */
Esc_ERROR
EscEccArithS1_Fe_ModularInvertRun(
    EscEccArithS1_Fe_ModularInvertContext* ctx );

/**
 * Init point conversion from a Jacobian point into an affine point.
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx Point conversion context.
 * \param[out] pA Resulting affine point (x,y).
 * \param[in]  pJ Jacobian point to convert (x,y,z).
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS1_Pt_ToAffineInit(
    EscEccArithS1_Pt_ToAffineContext* ctx,
    EscPtArithWs_PointT* pA,
    const EscPtArithWs_PointT* pJ,
    const EscPtArithWs_CurveT* curve );

/**
 * Point conversion from a Jacobian point into an affine point.
 *
 * \param[in,out] ctx Point conversion context.
 *
 * \retval Esc_AGAIN       The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR    The computation finished successfully.
 */
Esc_ERROR
EscEccArithS1_Pt_ToAffineRun(
    EscEccArithS1_Pt_ToAffineContext * ctx );

/**
 * Init point multiplication with a scalar.
 *
 * Points pJ and pA1 can point to the same location (aliased).
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx Point multiplication context.
 * \param[out] pJ Resulting Jacobian point (x,y,z).
 * \param[in]  k Scalar multiplicand.
 * \param[in]  pA1 affine point multiplicand (x,y).
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS1_Pt_JacobianMultiplyBinaryInit(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve );

/**
 * Point multiplication with a scalar.
 *
 * \param[in,out] ctx Point multiplication context.
 *
 * \retval Esc_AGAIN       The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR    The computation finished successfully.
 */
Esc_ERROR
EscEccArithS1_Pt_JacobianMultiplyBinaryRun(
    EscEccArithS1_Pt_JacobianMultiplyBinaryContext *ctx );

/**
 * Multiply base point with a scalar.
 *
 * \param[out] ctx Point multiplication context.
 * \param[out] pJ Resulting Jacobian point (x,y,z).
 * \param[in]  k Scalar multiplicand.
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS1_Pt_BasePointMultInit(
    EscEccArithS1_Pt_BasePointMultContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_CurveT* curve );

/**
 * Multiply base point with a scalar.
 *
 * \param[out] ctx Point multiplication context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS1_Pt_BasePointMultRun(
    EscEccArithS1_Pt_BasePointMultContext* ctx );


#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
/**
 * Dual point/double scalar multiplication with two scalars.
 * Will compute the result of k0*P0 + k1*P1. Also known as Shamir's trick.
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx Dual Multiply context.
 * \param[out] pJ Resulting Jacobian point (x,y,z).
 * \param[in]  k0 First scalar multiplicand.
 * \param[in]  pA0 First affine point multiplicand (x,y).
 * \param[in]  k1 Second scalar multiplicand.
 * \param[in]  pA1 Second affine point multiplicand (x,y).
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS1_Pt_JacDualMulAddBinInit(
    EscEccArithS1_Pt_JacDualMulAddBinContext *ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k0,
    const EscPtArithWs_PointT* pA0,
    const EscFeArith_FieldElementT* k1,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve );

/**
 * Dual point/double scalar multiplication with two scalars.
 * Will compute the result of k0*P0 + k1*P1. Also known as Shamir's trick.
 *
 * \param[in,out] ctx Dual Multiply context.
 *
 * \retval Esc_AGAIN       The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR    The computation finished successfully.
 */
Esc_ERROR
EscEccArithS1_Pt_JacDualMulAddBinRun(
    EscEccArithS1_Pt_JacDualMulAddBinContext *ctx);
#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECCARITH_S1_H_ */
