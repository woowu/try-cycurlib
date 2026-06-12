/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Pre-computed ECC tables to speed-up multiplication with the base point.

   $Rev: 2750 $
 */
/***************************************************************************/

#ifndef ESC_PRECOMP_H_
#define ESC_PRECOMP_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "ecc_cfg.h"

#if EscEcc_USE_FIXED_BASE == 1

#include "ecc.h"
#include "_ptarithws.h"

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

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

#if (EscEcc_SECP_192_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_SECP_192_precomputedValues[56];
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_SECP_224_precomputedValues[64];
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_SECP_256_precomputedValues[72];
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_SECP_384_precomputedValues[104];
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_SECP_521_precomputedValues[144];
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P160_precomputedValues[48];
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P192_precomputedValues[56];
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P224_precomputedValues[64];
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P256_precomputedValues[72];
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P320_precomputedValues[88];
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P384_precomputedValues[104];
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
extern const EscPtArithWs_PointT EscEcc_BRAINPOOL_P512_precomputedValues[136];
#endif


/**
 * This function returns a pre-computed point from a curve for the fixed base algorithm.
 * 
 * \param[out] output Pointer which will point to the precomputed value. 
 * \param[in] curveId The selected elliptic curve.
 * \param[in] pointIndex The index of the requested point.
 *                       Must be in the range from 0 to (curve.maxWords * 32 / EscEcc_FIXED_BASE_WINDOW_SIZE).
 * 
 */
void
EscEcc_GetPrecomputedPoint(
    const EscPtArithWs_PointT** output,
    EscEcc_CurveId curveId, 
    Esc_UINT8 pointIndex);

#endif /* EscEcc_USE_FIXED_BASE == 1 */

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_PRECOMP_H_ */
