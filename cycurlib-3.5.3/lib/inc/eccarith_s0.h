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

#ifndef ESC_ECCARITH_S0_H_
#define ESC_ECCARITH_S0_H_

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
    /** Temporary Field Element u. */
    EscFeArith_FieldElementT u;
    /** Temporary Field Element v. */
    EscFeArith_FieldElementT v;
    /** Temporary Field Element x1. */
    EscFeArith_FieldElementT x1;
    /** Temporary Field Element x2. */
    EscFeArith_FieldElementT x2;
} EscEccArithS0_Fe_ModularInvertContext;

/** Jacobian to affine conversion context. */
typedef struct
{
    /** Temporary Field Element for storing pJ(1/z) and pJ(1/z^3). */
    EscFeArith_FieldElementT fe_z_inv1_3;
    /** Temporary Field Element for storing pJ(1/z^2). */
    EscFeArith_FieldElementT fe_z_inv2;
    /** Modular inversion context. */
    EscEccArithS0_Fe_ModularInvertContext modInvertCtx;
} EscEccArithS0_Pt_ToAffineContext;

/** Point multiplication context. */
typedef struct
{
#if EscEcc_USE_SLIDING_WINDOW == 1
    /** Point array for precomputations */
    EscPtArithWs_PointT precompArray[EscEcc_NUM_WINDOW_ELEMENTS];
#else
    /** Temporary point for double and add */
    EscPtArithWs_PointT pTemp;
#endif
} EscEccArithS0_Pt_JacobianMultiplyBinaryContext;

/** Context for multiplication with base point. */
typedef struct
{
#if EscEcc_USE_FIXED_BASE == 1
    /** Array to store the scalar of the multiplication in n-bit words where n
     * is the size of the fixed-base window.
     */
    Esc_UINT8 K[(EscFeArith_MAX_WORDS * 32U) / EscEcc_FIXED_BASE_WINDOW_SIZE];
#else
    /** General multiplication context */
    EscEccArithS0_Pt_JacobianMultiplyBinaryContext jacMulBinCtx;
#endif
} EscEccArithS0_Pt_BasePointMultContext;

#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
/** Dual multiply/double scalar context. */
typedef struct
{
    /** Temporary point for the input point A0 in Jacobian form */
    EscPtArithWs_PointT pPA0;
    /** Temporary point for the input point A1 in Jacobian form */
    EscPtArithWs_PointT pPA1;
    /** Temporary point for A0 + A1 */
    EscPtArithWs_PointT pQPlusG;
    /** Context to convert pQPlusG to affine form */
    EscEccArithS0_Pt_ToAffineContext toAffineCtx;
} EscEccArithS0_Pt_JacDualMulAddBinContext;
#endif

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/
/**
 * Modular inversion of a field element.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * Field Elements c and a can point to the same location (aliased).
 *
 * \param[out] ctx Modular inversion context.
 * \param[out] c Resulting field element.
 * \param[in]  a Input field element. Must not be 0, and smaller than the prime of fGP.
 * \param[in]  fGP Used field.
 * \param[in]  lenWords Length of used words in the field elements.
 */
void
EscEccArithS0_Fe_ModularInvertInit(
    EscEccArithS0_Fe_ModularInvertContext* ctx,
    EscFeArith_FieldElementT* c,
    const EscFeArith_FieldElementT* a,
    const EscFeArith_FieldT* fGP,
    const Esc_UINT8 lenWords );

/**
 * Modular inversion of a field element.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Modular inversion context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS0_Fe_ModularInvertRun(
    EscEccArithS0_Fe_ModularInvertContext* ctx );

/**
 * Point conversion from a Jacobian point into an affine point.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Point conversion context.
 * \param[out] pA Resulting affine point (x,y).
 * \param[in]  pJ Jacobian point to convert (x,y,z).
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS0_Pt_ToAffineInit(
    EscEccArithS0_Pt_ToAffineContext* ctx,
    EscPtArithWs_PointT* pA,
    const EscPtArithWs_PointT* pJ,
    const EscPtArithWs_CurveT* curve );

/**
 * Point conversion from a Jacobian point into an affine point.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Point conversion context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS0_Pt_ToAffineRun(
    EscEccArithS0_Pt_ToAffineContext* ctx );

/**
 * Point multiplication with a scalar.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * Points pJ and pA1 can point to the same location (aliased).
 *
 * \param[out] ctx Point multiplication context.
 * \param[out] pJ Resulting Jacobian point (x,y,z).
 * \param[in]  k Scalar multiplicand.
 * \param[in]  pA1 affine point multiplicand (x,y).
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS0_Pt_JacobianMultiplyBinaryInit(
    EscEccArithS0_Pt_JacobianMultiplyBinaryContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve );

/**
 * Point multiplication with a scalar.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Point multiplication context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS0_Pt_JacobianMultiplyBinaryRun(
    EscEccArithS0_Pt_JacobianMultiplyBinaryContext* ctx );

/**
 * Multiply base point with a scalar.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Point multiplication context.
 * \param[out] pJ Resulting Jacobian point (x,y,z).
 * \param[in]  k Scalar multiplicand.
 * \param[in]  curve Pointer to the underlying curve.
 */
void
EscEccArithS0_Pt_BasePointMultInit(
    EscEccArithS0_Pt_BasePointMultContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k,
    const EscPtArithWs_CurveT* curve );

/**
 * Multiply base point with a scalar.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Point multiplication context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS0_Pt_BasePointMultRun(
    EscEccArithS0_Pt_BasePointMultContext* ctx );

#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
/**
 * Dual point/double scalar multiplication with two scalars.
 * Computes the result of k0*P0 + k1*P1. Also known as Shamir's trick.
 *
 * Non-sliced version does complete algorithm in the Init function.
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
EscEccArithS0_Pt_JacDualMulAddBinInit(
    EscEccArithS0_Pt_JacDualMulAddBinContext* ctx,
    EscPtArithWs_PointT* pJ,
    const EscFeArith_FieldElementT* k0,
    const EscPtArithWs_PointT* pA0,
    const EscFeArith_FieldElementT* k1,
    const EscPtArithWs_PointT* pA1,
    const EscPtArithWs_CurveT* curve );

/**
 * Dual point/double scalar multiplication with two scalars.
 * Computes the result of k0*P0 + k1*P1. Also known as Shamir's trick.
 *
 * Non-sliced version does complete algorithm in the Init function.
 *
 * \param[out] ctx Dual Multiply context.
 *
 * \return Esc_NO_ERROR always.
 */
Esc_ERROR
EscEccArithS0_Pt_JacDualMulAddBinRun(
    EscEccArithS0_Pt_JacDualMulAddBinContext* ctx );
#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECCARITH_S0_H_ */
