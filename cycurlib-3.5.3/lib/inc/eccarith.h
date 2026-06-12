/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Elliptic Curve Arithmetic interface.
                Provides abstraction for sliced and non-sliced variants.

   $Rev: 2750 $
 */
/***************************************************************************/

#ifndef ESC_ECCARITH_H_
#define ESC_ECCARITH_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"

#if EscEcc_SLICING_ENABLED == 0
#   include "eccarith_s0.h"
#else
#   include "eccarith_s1.h"
#endif

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Create short-cuts to have differentiation between sliced and non-sliced interface */

#if EscEcc_SLICING_ENABLED == 0

/** Initialize modular inversion */
#define EscEcc_Fe_ModularInvertInit            EscEccArithS0_Fe_ModularInvertInit
/** Run modular inversion */
#define EscEcc_Fe_ModularInvertRun             EscEccArithS0_Fe_ModularInvertRun
/** Initialize point conversion from Jacobian to affine */
#define EscEcc_Pt_ToAffineInit                 EscEccArithS0_Pt_ToAffineInit
/** Run point conversion from Jacobian to affine */
#define EscEcc_Pt_ToAffineRun                  EscEccArithS0_Pt_ToAffineRun
/** Initialize point multiplication with base point */
#define EscEcc_Pt_BasePointMultInit            EscEccArithS0_Pt_BasePointMultInit
/** Run point multiplication with base point */
#define EscEcc_Pt_BasePointMultRun             EscEccArithS0_Pt_BasePointMultRun
/** Initialize point multiplication */
#define EscEcc_Pt_JacobianMultiplyBinaryInit   EscEccArithS0_Pt_JacobianMultiplyBinaryInit
/** Run point multiplication */
#define EscEcc_Pt_JacobianMultiplyBinaryRun    EscEccArithS0_Pt_JacobianMultiplyBinaryRun
/** Initialize dual multiply (Shamir's trick) */
#define EscEcc_Pt_JacDualMulAddBinInit         EscEccArithS0_Pt_JacDualMulAddBinInit
/** Run dual multiply (Shamir's trick) */
#define EscEcc_Pt_JacDualMulAddBinRun          EscEccArithS0_Pt_JacDualMulAddBinRun

#else

/** Initialize modular inversion */
#define EscEcc_Fe_ModularInvertInit            EscEccArithS1_Fe_ModularInvertInit
/** Run modular inversion */
#define EscEcc_Fe_ModularInvertRun             EscEccArithS1_Fe_ModularInvertRun
/** Initialize point conversion from Jacobian to affine */
#define EscEcc_Pt_ToAffineInit                 EscEccArithS1_Pt_ToAffineInit
/** Run point conversion from Jacobian to affine */
#define EscEcc_Pt_ToAffineRun                  EscEccArithS1_Pt_ToAffineRun
/** Initialize point multiplication with base point */
#define EscEcc_Pt_BasePointMultInit            EscEccArithS1_Pt_BasePointMultInit
/** Run point multiplication with base point */
#define EscEcc_Pt_BasePointMultRun             EscEccArithS1_Pt_BasePointMultRun
/** Initialize point multiplication */
#define EscEcc_Pt_JacobianMultiplyBinaryInit   EscEccArithS1_Pt_JacobianMultiplyBinaryInit
/** Run point multiplication */
#define EscEcc_Pt_JacobianMultiplyBinaryRun    EscEccArithS1_Pt_JacobianMultiplyBinaryRun
/** Initialize dual multiply (Shamir's trick) */
#define EscEcc_Pt_JacDualMulAddBinInit         EscEccArithS1_Pt_JacDualMulAddBinInit
/** Run dual multiply (Shamir's trick) */
#define EscEcc_Pt_JacDualMulAddBinRun          EscEccArithS1_Pt_JacDualMulAddBinRun

#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

#if EscEcc_SLICING_ENABLED == 0

/** Modular inversion context */
typedef EscEccArithS0_Fe_ModularInvertContext             EscEcc_Fe_ModularInvertContext;
/** Jacobian to affine conversion context */
typedef EscEccArithS0_Pt_ToAffineContext                  EscEcc_Pt_ToAffineContext;
/** Point multiplication context */
typedef EscEccArithS0_Pt_JacobianMultiplyBinaryContext    EscEcc_Pt_JacobianMultiplyBinaryContext;
/** Context for point multiplication with base point */
typedef EscEccArithS0_Pt_BasePointMultContext             EscEcc_Pt_BasePointMultContext;
#if EscFeArith_ENABLE_SHAMIRS_TRICK  == 1
/** Dual Multiplication (Shamir's trick) context */
typedef EscEccArithS0_Pt_JacDualMulAddBinContext          EscEcc_Pt_JacDualMulAddBinContext;
#endif

#else

/** Modular inversion context */
typedef EscEccArithS1_Fe_ModularInvertContext             EscEcc_Fe_ModularInvertContext;
/** Jacobian to affine conversion context */
typedef EscEccArithS1_Pt_ToAffineContext                  EscEcc_Pt_ToAffineContext;
/** Point multiplication context */
typedef EscEccArithS1_Pt_JacobianMultiplyBinaryContext    EscEcc_Pt_JacobianMultiplyBinaryContext;
/** Context for point multiplication with base point */
typedef EscEccArithS1_Pt_BasePointMultContext             EscEcc_Pt_BasePointMultContext;
#if EscFeArith_ENABLE_SHAMIRS_TRICK  == 1
/** Dual Multiplication (Shamir's trick) context */
typedef EscEccArithS1_Pt_JacDualMulAddBinContext          EscEcc_Pt_JacDualMulAddBinContext;
#endif

#endif

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/


/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECCARITH_H_ */
