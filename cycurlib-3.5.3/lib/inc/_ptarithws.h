/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Point arithmetic for Weierstrass elliptic curves like the NIST P curves or brainpool P curves.

   Byteorder of the long numbers is Little endian

   $Rev: 2750 $
 */
/***************************************************************************/

#ifndef ESC__PTARITHWS_H_
#define ESC__PTARITHWS_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"
#include "_fearith.h"

#include "random.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION                                    *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** As the internal generation of random nonces for signing and key generation depend on random values,
    this is the maximum number of calls to the provided random function until a
    Esc_INTERNAL_FUNCTION_ERROR is thrown to prevent infinite loops */
#define EscPtArithWs_MAX_RANDOM_CALLS 15U

/** Affine coordinates point type */
#define EscPtArith_TYPE_AFFINE     0U
/** Jacobian coordinates point type */
#define EscPtArith_TYPE_JACOBIAN   2U

/** Size of the fixed-base window in bits */
#define EscEcc_FIXED_BASE_WINDOW_SIZE 4U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Elliptic curve point */
typedef struct
{
    /** Type of the curve */
    Esc_UINT8 type;
    /** X-Coordinate */
    EscFeArith_FieldElementT x;
    /** Y-Coordinate */
    EscFeArith_FieldElementT y;
    /** Z-Coordinate */
    EscFeArith_FieldElementT z;
} EscPtArithWs_PointT;


/** Elliptic curve */
typedef struct
{
    /** Coefficient a */
    EscFeArith_FieldElementT coefficient_a;
    /** Coefficient b */
    EscFeArith_FieldElementT coefficient_b;
    /** Base point G */
    EscPtArithWs_PointT base_point_G;
    /** Curve order n */
    EscFeArith_FieldT base_point_order_n;
    /** Field parameters */
    EscFeArith_FieldT ecc_field_params;
    /** Curve sizes */
    EscFeArith_SizeT curveSize;
    /** Curve ID **/
    EscFeArith_CurveId curveId;
} EscPtArithWs_CurveT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

#if (EscEcc_SECP_192_ENABLED == 1)
/** The elliptic curve secp192r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveSecp192r1;
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
/** The elliptic curve secp224r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveSecp224r1;
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
/** The elliptic curve secp256r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveSecp256r1;
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
/** The elliptic curve secp384r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveSecp384r1;
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
/** The elliptic curve secp521r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveSecp521r1;
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
/** The elliptic curve brainpoolP160r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool160;
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
/** The elliptic curve brainpoolP192r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool192;
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
/** The elliptic curve brainpoolP224r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool224;
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
/** The elliptic curve brainpoolP256r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool256;
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
/** The elliptic curve brainpoolP320r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool320;
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
/** The elliptic curve brainpoolP384r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool384;
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
/** The elliptic curve brainpoolP512r1 */
extern const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool512;
#endif


/**
 * Lookup the curve parameter definitions by curve ID.
 *
 * \param[in] id    The ID of the curve.
 *
 * \return Curve structure containing all relevant curve parameters.
 *         If the curve ID is invalid or if the curve was not activated
 *         at compilation time then 0 is returned.
 */
const EscPtArithWs_CurveT*
EscPtArithWs_GetCurve(
    const EscFeArith_CurveId id );


/**
 * Sets the given point to the point of infinity.
 *
 * \param[out] pX Point which is set to infinity.
 */
void
EscPtArithWs_SetInfinity(
    EscPtArithWs_PointT* pX );

/**
 * Checks if the given point is zero.
 *
 * \param[out] pX Point which is checked for zero.
 * \param[in] curve Underlying curve.
 *
 * \retval TRUE if the point pX is zero.
 * \retval FALSE if the point pX is not zero.
 */
Esc_BOOL
EscPtArithWs_IsZero(
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve );

/**
 * Checks if the given point is the point of infinity.
 *
 * \param[in] pX Point which is checked.
 * \param[in] curve Underlying curve.
 *
 * \retval TRUE if the point pX is the point of infinity.
 * \retval FALSE if the point pX is not the point of infinity.
 */
Esc_BOOL
EscPtArithWs_IsInfinity(
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve );

/**
 * Copy a point to another one.
 *
 * Points pY and pX can point to the same location (aliased).
 *
 * \param[out] pY Copy of the input point pX.
 * \param[in] pX Point to copy.
 * \param[in] curve Underlying curve.
 */
void
EscPtArithWs_Assign(
    EscPtArithWs_PointT* pY,
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve );

/**
 * Doubles a Jacobian point, pJ = 2 * pJ0.
 *
 * Points pJ and pJ0 can point to the same location (aliased).
 *
 * \param[out] pJ Jacobian point for the result.
 * \param[in] pJ0 Point to double.
 * \param[in] curve Underlying curve.
 */
void
EscPtArithWs_JacobianDouble(
    EscPtArithWs_PointT* pJ,
    const EscPtArithWs_PointT* pJ0,
    const EscPtArithWs_CurveT* curve );

/**
 * Adds two Jacobian points, pJ = pJ1 + pJ2.
 *
 * Points pJ and one of the two operands (pJ1 or pJ2) can point to the same location (aliased).
 *
 * \param[out] pJ Jacobian point for the result.
 * \param[in] pJ1 Summand pJ1.
 * \param[in] pJ2 Summand pJ2.
 * \param[in] curve Underlying curve.
 */
void
EscPtArithWs_JacobianAdd(
    EscPtArithWs_PointT* pJ,
    const EscPtArithWs_PointT* pJ1,
    const EscPtArithWs_PointT* pJ2,
    const EscPtArithWs_CurveT* curve );

/**
 * Calculate random k according to Algo B.5.2 from FIPS 186-4 (page 64)
 *
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h
 * \param[in] curve The selected elliptic curve.
 * \param[out] k The generated random value k
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscPtArithWs_CalculateRandomK(
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscPtArithWs_CurveT* curve,
    EscFeArith_FieldElementT* k);


/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif
