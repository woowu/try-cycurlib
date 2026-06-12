/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Point arithmetic for the twisted Edwards curve used by Ed25519.
   
                Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 with:
                d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
                Base point: ( 15112221349535400772501151409588531511454012693041857206046113283949847762202,
                              46316835694926478169428394003475163141307993866256225615783033603165251855960 );

   \see         [1] Extended Twisted Edwards Coordinates:
                    Hisil et al. - Twisted Edwards Curves Revisited (2008)
                [2] Ed25519 and choice of the used Twisted Edwards Curve:
                    Bernstein et al. - High-speed high-security signatures (2012)
                [3] Twisted Edwards Curves and projective coordinates:
                    Bernstein et al. - Twisted Edwards Curves (2008)
                [4] Hankerson, Menezes, Vanstone - Guide to Elliptic Curce Cryptography (2004)
                [5] Montgomery Powering Ladder:
                    Joye, Yen: - The Montgomery Powering Ladder (2003)

   $Rev: 2799 $
 */
/***************************************************************************/

#ifndef ESC__PTARITHTE25519_H_
#define ESC__PTARITHTE25519_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"
#include "_fearith.h"

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

/** Point (== group element) in the form of extended projective twisted Edwards coordinates */
typedef struct {
    /** X-coordinate */
    EscFeArith_FieldElementT x;
    /** Y-coordinate */
    EscFeArith_FieldElementT y;
    /** T-coordinate */
    EscFeArith_FieldElementT t;
    /** Z-coordinate */
    EscFeArith_FieldElementT z;
} EscPtArithTe25519_PointT;


/** Twisted Edwards curve */
typedef struct
{
    /** Coefficient d */
    EscFeArith_FieldElementT coefficient_d;
    /** Base point G */
    EscPtArithTe25519_PointT base_point_G;
    /** Curve order n */
    EscFeArith_FieldT base_point_order_n;
    /** Modulus of the curve */
    EscFeArith_FieldT ecc_field_params;
    /** Curve size */
    EscFeArith_SizeT curveSize;
    /** Curve ID */
    EscFeArith_CurveId curveId;
} EscPtArithTe25519_CurveT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

#if (EscEcc_CURVE_ED25519_ENABLED == 1)
/** The elliptic curve Curve25519 */
extern const EscPtArithTe25519_CurveT EscPtArithTe25519_curve25519;
#endif


/**
 * Convert a byte array with the compressed point (y coordinate and sign bit for x) into a point.
 *
 * Fast decompression according to [2] Section 5.
 *
 * \param[out] out Resulting point.
 * \param[in] in 32 byte array with the compressed point.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscPtArithTe25519_PointFromUint8(
    EscPtArithTe25519_PointT* out,
    const Esc_UINT8 in[] );


/**
 * Convert a point from extended projective twisted Edwards coordinates into a byte array with the compressed point.
 *
 * \param[out] out 32 byte array with the compressed point.
 * \param[in] in Point to convert.
 */
void
EscPtArithTe25519_PointToUint8(
    Esc_UINT8 out[],
    const EscPtArithTe25519_PointT in[] );


/**
 * Point multiplication with a scalar.
 * Points r and p must not point to the same location!
 *
 * Timing invariant algorithm Montgomery Powering Ladder (cf. Figure 7 from [5]) is used.
 *
 * \param[out] r Resulting point (x,y,z,t).
 * \param[in] scalar Scalar multiplicand.
 * \param[in] p Point multiplicand (x,y,z,t).
 */
void
EscPtArithTe25519_ScalarMul(
    EscPtArithTe25519_PointT* r,
    const Esc_UINT8 scalar[],
    const EscPtArithTe25519_PointT* p );


/**
 * Double-scalar point multiplication.
 *
 * Points r and p0 or p1 must not point to the same location!
 *
 * Timing invariant Algorithm 3.48 from [4] ('Shamir's trick') is used.
 *
 * \param[out] r Resulting point (x,y,z,t).
 * \param[in] scalarK0 Scalar multiplicand for point P0.
 * \param[in] p0 Point multiplicand P0 (x,y,z,t).
 * \param[in] scalarK1 Scalar multiplicand for point P1.
 * \param[in] p1 Point multiplicand P1 (x,y,z,t).
 */
void
EscPtArithTe25519_DoubleScalarMul(
    EscPtArithTe25519_PointT* r,
    const Esc_UINT8 scalarK0[],
    const EscPtArithTe25519_PointT* p0,
    const Esc_UINT8 scalarK1[],
    const EscPtArithTe25519_PointT* p1 );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
