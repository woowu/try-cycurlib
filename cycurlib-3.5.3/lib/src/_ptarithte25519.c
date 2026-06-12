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
   
                Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 
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

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_ptarithte25519.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of one coordinate. */
#define EscPtArithTe25519_COORDINATE_BYTES 32U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * Adds two points on the curve.
 * [1] Section 3.1. - Algorithm (5) with assumption k = 2*d
 *
 * Input and output points may be aliased.
 *
 * \param[out] out Resulting point.
 * \param[in] a First summand point.
 * \param[in] b Second summand point.
 * \param[in] computeT If == TRUE the output coordinate T is computed for
                receiving a point in extended projective twisted Edwards coordinate form.
                If == FALSE, T is not computed which results in a projective twisted Edwards coordinate form.
 */
static void
EscPtArithTe25519_Add(
    EscPtArithTe25519_PointT* out,
    const EscPtArithTe25519_PointT* a,
    const EscPtArithTe25519_PointT* b,
    Esc_BOOL computeT );


/**
 * Doubles a point on the curve.
 * [1] Section 3.3, Algorithm (7).
 * This algorithm does not need the T coordinate.
 * Input and output point may be aliased.
 *
 * \param[out] out Resulting point (extended projective form)
 * \param[in] in Input point to double (projective or extended projective form)
 */
static void
EscPtArithTe25519_Double(
    EscPtArithTe25519_PointT* out,
    const EscPtArithTe25519_PointT* in );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/* CAUTION! - Little-Endian representation: i.e., all arrays are like  */
/* (a[0], a[1], .. , a[n]) there a[0] is the lowest and a[n] the highest word */

#if (EscEcc_CURVE_ED25519_ENABLED == 1)
/***************************************************************************
 * 4.1 Curve25519 *
 ***************************************************************************/

const EscPtArithTe25519_CurveT EscPtArithTe25519_curve25519 =
{
    /*EscEcc_COEFFICIENT_D */ { {0x135978a3UL, 0x75eb4dcaUL, 0x4141d8abUL, 0x00700a4dUL, 0x7779e898UL, 0x8cc74079UL, 0x2b6ffe73UL, 0x52036ceeUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
    {
        /*EscEcc_BASE_POINT_G_X*/ { {0x8f25d51aUL, 0xc9562d60UL, 0x9525a7b2UL, 0x692cc760UL, 0xfdd6dc5cUL, 0xc0a4e231UL, 0xcd6e53feUL, 0x216936d3UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x66666658UL, 0x66666666UL, 0x66666666UL, 0x66666666UL, 0x66666666UL, 0x66666666UL, 0x66666666UL, 0x66666666UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_G_T*/ { {0xa5b7dda3UL, 0x6dde8ab3UL, 0x775152f5UL, 0x20f09f80UL, 0x64abe37dUL, 0x66ea4e8eUL, 0xd78b7665UL, 0x67875f0fUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
    },
    {
        /*EscEcc_MY_N*/ { {0x0a2c131bUL, 0xed9ce5a3UL, 0x086329a7UL, 0x2106215dUL, 0xffffffebUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x0000000fUL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_order_n*/ { {0x5cf5d3edUL, 0x5812631aUL, 0xa2f79cd6UL, 0x14def9deUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x10000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_NLEN*/ 8U,
    },
    {
        /*EscEcc_MY_P*/ { {0x0000004cUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000002UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_PRIME_P*/ { {0xffffffedUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x7fffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_PLEN*/ 8U,
    },
    {
        256U,   /* key size in bits */
        32U,    /* key size in bytes */
        8U,     /* key size in words */
        9U,     /* max words of a FE */
        18U,    /* max words of a long FE */
    },
    EscFeArith_CURVE_ED25519
};
#endif

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/* [1] Section 3.1. - Algorithm (5) with assumption k = 2*d
 * Computation of coordinate t can activated or deactivated, which results into an implicit conversion
 * from extended projective twisted Edwards coordinates to projective twisted Edwards coordinates
 * (cf. Section 4.3 from [1]). Order of computations are changed for saving stack.
 */
static void
EscPtArithTe25519_Add(
    EscPtArithTe25519_PointT* out,
    const EscPtArithTe25519_PointT* a,
    const EscPtArithTe25519_PointT* b,
    Esc_BOOL computeT )
{
    EscFeArith_FieldElementT aFe, bFe, c_eFe, d_hFe;

    /* Shortcuts to curve attributes */
    const EscFeArith_FieldT* modulus = &EscPtArithTe25519_curve25519.ecc_field_params;
    EscFeArith_CurveId curveId = EscPtArithTe25519_curve25519.curveId;
    const EscFeArith_SizeT* curveSize = &EscPtArithTe25519_curve25519.curveSize;

    /* A = (Y1-X1)*(Y2-X2), use E as temp variable. */
    EscFeArith_ModularSub( &aFe, &a->y, &a->x, modulus, curveSize->maxWords );
    EscFeArith_ModularSub( &c_eFe, &b->y, &b->x, modulus, curveSize->maxWords );
    EscFeArith_MultiplyModP( &aFe, &aFe, &c_eFe, modulus, curveId, curveSize );
    /* B = (Y1+X1)*(Y2+X2), use E as temp variable. */
    EscFeArith_ModularAdd( &bFe, &a->x, &a->y, modulus, curveSize->maxWords );
    EscFeArith_ModularAdd( &c_eFe, &b->x, &b->y, modulus, curveSize->maxWords );
    EscFeArith_MultiplyModP( &bFe, &bFe, &c_eFe, modulus, curveId, curveSize );
    /* C = T1*2*d*T2 */
    EscFeArith_ModularAdd( &c_eFe, &a->t, &a->t, modulus, curveSize->maxWords );
    EscFeArith_MultiplyModP( &c_eFe, &c_eFe, &b->t, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &c_eFe, &c_eFe, &EscPtArithTe25519_curve25519.coefficient_d, modulus, curveId, curveSize );
    /* D = Z1*2*Z2 */
    EscFeArith_ModularAdd( &d_hFe, &a->z, &a->z, modulus, curveSize->maxWords );
    EscFeArith_MultiplyModP( &d_hFe, &d_hFe, &b->z, modulus, curveId, curveSize );
    /* F = D-C */
    EscFeArith_ModularSub( &out->t, &d_hFe, &c_eFe, modulus, curveSize->maxWords );
    /* G = D+C */
    EscFeArith_ModularAdd( &out->z, &d_hFe, &c_eFe, modulus, curveSize->maxWords );
    /* E = B-A */
    EscFeArith_ModularSub( &c_eFe, &bFe, &aFe, modulus, curveSize->maxWords );
    /* H = B+A */
    EscFeArith_ModularAdd( &d_hFe, &bFe, &aFe, modulus, curveSize->maxWords );
    /* X3 = E*F */
    EscFeArith_MultiplyModP( &out->x, &c_eFe, &out->t, modulus, curveId, curveSize );
    /* Y3 = G*H */
    EscFeArith_MultiplyModP( &out->y, &out->z, &d_hFe, modulus, curveId, curveSize );
    /* Z3 = F*G */
    EscFeArith_MultiplyModP( &out->z, &out->t, &out->z, modulus, curveId, curveSize );
    
    /* Compute T iff required. */
    if ( computeT == TRUE )
    {
        /* T3 = E*H */
        EscFeArith_MultiplyModP( &out->t, &c_eFe, &d_hFe, modulus, curveId, curveSize );
    }
}


/* [1] Section 3.3, Algorithm (7).
    Algorithm does not need coordinate t from input point. */
static void
EscPtArithTe25519_Double(
    EscPtArithTe25519_PointT* out,
    const EscPtArithTe25519_PointT* in )
{
    EscFeArith_FieldElementT aFe, bFe, cFe, dFe;

    /* Shortcuts to curve attributes */
    const EscFeArith_FieldT* modulus = &EscPtArithTe25519_curve25519.ecc_field_params;
    EscFeArith_CurveId curveId = EscPtArithTe25519_curve25519.curveId;
    const EscFeArith_SizeT* curveSize = &EscPtArithTe25519_curve25519.curveSize;

    /* A = X1^2 */
    EscFeArith_SquareModP( &aFe, &in->x, modulus, curveId, curveSize );
    /* B = Y1^2 */
    EscFeArith_SquareModP( &bFe, &in->y, modulus, curveId, curveSize );
    /* C = 2 * Z1^2 */
    EscFeArith_SquareModP( &cFe, &in->z, modulus, curveId, curveSize );
    EscFeArith_ModularAdd( &cFe, &cFe, &cFe, modulus, curveSize->maxWords );
    /* D = a * A. a = -1 for Ed25519 */
    EscFeArith_SetZero( &dFe );
    EscFeArith_ModularSub( &dFe, &dFe, &aFe, modulus, curveSize->maxWords );
    /* E = ((X1 + Y1)^2) - A - B. Reuse A for E */
    EscFeArith_ModularAdd( &out->x, &in->x, &in->y, modulus, curveSize->maxWords );
    EscFeArith_SquareModP( &out->x, &out->x, modulus, curveId, curveSize );
    EscFeArith_ModularSub( &out->x, &out->x, &aFe, modulus, curveSize->maxWords );
    EscFeArith_ModularSub( &aFe, &out->x, &bFe, modulus, curveSize->maxWords );
    /* G = D+B */
    EscFeArith_ModularAdd( &out->z, &dFe, &bFe, modulus, curveSize->maxWords );
    /* F = G-C */
    EscFeArith_ModularSub( &out->t, &out->z, &cFe, modulus, curveSize->maxWords );
    /* H = D-B. Reuse B for H */
    EscFeArith_ModularSub( &bFe, &dFe, &bFe, modulus, curveSize->maxWords );
    /* X3 = E*F */
    EscFeArith_MultiplyModP( &out->x, &aFe, &out->t, modulus, curveId, curveSize );
    /* Y3 = G*H */
    EscFeArith_MultiplyModP( &out->y, &bFe, &out->z, modulus, curveId, curveSize );
    /* Z3 = F*G */
    EscFeArith_MultiplyModP( &out->z, &out->z, &out->t, modulus, curveId, curveSize );
    /*T3 = E*H */
    EscFeArith_MultiplyModP( &out->t, &aFe, &bFe, modulus, curveId, curveSize );
}


Esc_ERROR
EscPtArithTe25519_PointFromUint8(
    EscPtArithTe25519_PointT * out,
    const Esc_UINT8 in[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscFeArith_FieldElementT uFe, vFe, v3Fe, vxxFe;
    Esc_UINT8 inSwap[EscPtArithTe25519_COORDINATE_BYTES];

    /* (p-5)/8 used for exponentiation */
    static const Esc_UINT8 exp[EscPtArithTe25519_COORDINATE_BYTES] =
    {
        0xfdU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
        0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x0fU
    };

    /* SquareRoot(-1) mod p */
    static const EscFeArith_FieldElementT sqrtOne =
    {
        { 0x4a0ea0b0UL, 0xc4ee1b27UL, 0xad2fe478UL, 0x2f431806UL, 0x3dfbd7a7UL,
          0x2b4d0099UL, 0x4fc1df0bUL, 0x2b832480UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 }
    };

    const EscFeArith_FieldT* modulus = &EscPtArithTe25519_curve25519.ecc_field_params;
    EscFeArith_CurveId curveId = EscPtArithTe25519_curve25519.curveId;
    const EscFeArith_SizeT* curveSize = &EscPtArithTe25519_curve25519.curveSize;

    /* Get the y coordinate. Compressed coordinates for Curve25519 are are stored in little-endian.
       Swap endianess for our arithmetic module. */
    EscFeArith_SwapEndiannessUint8( inSwap, in, EscPtArithTe25519_COORDINATE_BYTES );
    /* Coordinate is compressed -> first bit is the sign of x, mask it out */
    inSwap[0] &= 0x7fU;
    EscFeArith_FromUint8( inSwap, EscPtArithTe25519_COORDINATE_BYTES, &out->y, &EscPtArithTe25519_curve25519.curveSize );

    /* Set Z = 1 */
    EscFeArith_SetOne( &out->z );

    /* u = y^2 */
    EscFeArith_SquareModP( &uFe, &out->y, modulus, curveId, curveSize );

    /* v = d * y^2 */
    EscFeArith_MultiplyModP( &vFe, &uFe, &EscPtArithTe25519_curve25519.coefficient_d, modulus, curveId, curveSize );

    /* u = y^2-1 */
    EscFeArith_ModularSub( &uFe, &uFe, &out->z, modulus, curveSize->maxWords );

    /* v = dy^2+1 */
    EscFeArith_ModularAdd( &vFe, &vFe, &out->z, modulus, curveSize->maxWords );

    /* v3 = v^3 */
    EscFeArith_SquareModP( &v3Fe, &vFe, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &v3Fe, &v3Fe, &vFe, modulus, curveId, curveSize );

    /* x = uv^7 */
    EscFeArith_SquareModP( &out->x, &v3Fe, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &out->x, &out->x, &vFe, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &out->x, &out->x, &uFe, modulus, curveId, curveSize );

    /* x = (uv^7)^((q-5)/8) */
    EscFeArith_PowModP(&out->x, &out->x, exp, EscPtArithTe25519_COORDINATE_BYTES, modulus, curveId, curveSize );

    /* x = uv^3(uv^7)^((q-5)/8) */
    EscFeArith_MultiplyModP( &out->x, &out->x, &v3Fe, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &out->x, &out->x, &uFe, modulus, curveId, curveSize );

    /* Check if we already have computed the correct square root or not */
    /* vx^2 */
    EscFeArith_SquareModP( &vxxFe, &out->x, modulus, curveId, curveSize );
    EscFeArith_MultiplyModP( &vxxFe, &vxxFe, &vFe, modulus, curveId, curveSize );

    /* vx^2 - u. Use v for temp Fe */
    EscFeArith_ModularSub( &vFe, &vxxFe, &uFe, modulus, curveSize->maxWords );
    if ( EscFeArith_IsZero( &vFe, curveSize->maxWords) == FALSE )
    {
        /* (vx^2 - u) != 0 means that either 1.) y is not a square mod p. or 2.) vx^2 == -u */
        EscFeArith_ModularAdd( &vFe, &vxxFe, &uFe, modulus, curveSize->maxWords );
        if ( EscFeArith_IsZero( &vFe, curveSize->maxWords) == FALSE )
        {
            /* Case 1.) y is not an encoded public key */
            returnCode = Esc_INTERNAL_FUNCTION_ERROR;
        }
        else
        {
            /* Case 2.) Compute x * sqrt(-1) mod p to get the correct square root */
            EscFeArith_MultiplyModP( &out->x, &out->x, &sqrtOne, modulus, curveId, curveSize );
        }
    }

    if ( returnCode == Esc_NO_ERROR )
    {
        /* Set the sign depending on the stored sign bit in last byte 31. Signedness of a field element is defined in [2] Section 2 (odd == negative). */
        if ( (Esc_UINT8)(out->x.word[0] & 0x01U) != (in[31] >> 7U) )
        {
            /* out = -in = 0 - in. Use vxxFe for temp Fe. */
            EscFeArith_SetZero( &vxxFe );
            EscFeArith_ModularSub( &out->x, &vxxFe, &out->x, modulus, curveSize->maxWords );
        }

        /* Compute coordinate T = X*Y */
        EscFeArith_MultiplyModP( &out->t, &out->x, &out->y, modulus, curveId, curveSize );
    }

    return returnCode;
}


void
EscPtArithTe25519_PointToUint8(
    Esc_UINT8 out[],
    const EscPtArithTe25519_PointT in[] )
{
    Esc_UINT8 yCoordinate[EscPtArithTe25519_COORDINATE_BYTES];
    EscFeArith_FieldElementT tempFe, zInvFe;

    /* Conversion from extended twisted Edwards to projective twisted Edwards coordinates
       is done by simply ignoring T ([1, Section 3]).
       Conversion from projective twisted Edwards coordinates to affine coordinates is done with the formula:
       (x,y) = (X/Z, Y/Z) ([3, Section 6]. */
    EscFeArith_ModularInvert( &zInvFe, &in->z, &EscPtArithTe25519_curve25519.ecc_field_params, EscPtArithTe25519_curve25519.curveSize.maxWords );

    /* Compute y-coordinate */
    EscFeArith_MultiplyModP( &tempFe, &in->y, &zInvFe, &EscPtArithTe25519_curve25519.ecc_field_params, EscPtArithTe25519_curve25519.curveId, &EscPtArithTe25519_curve25519.curveSize );

    /* Copy y-coordinate into UINT8 array */
    EscFeArith_ToUint8( &tempFe, yCoordinate, &EscPtArithTe25519_curve25519.curveSize );
    EscFeArith_SwapEndiannessUint8( out, yCoordinate, EscPtArithTe25519_COORDINATE_BYTES );

    /* Compute x-coordinate */
    EscFeArith_MultiplyModP( &tempFe, &in->x, &zInvFe, &EscPtArithTe25519_curve25519.ecc_field_params, EscPtArithTe25519_curve25519.curveId, &EscPtArithTe25519_curve25519.curveSize );
    /* Merge the sign of the x-coordinate: y | ((x & 1) << 255) */
    out[31] |= (Esc_UINT8)((tempFe.word[0] & 0x01U) << 7U);
}


/**
 * Calculate k0 * P0 with Montgomery Powering Ladder. *
 * Cf. Figure 7 in [5].
 */
void
EscPtArithTe25519_ScalarMul(
    EscPtArithTe25519_PointT* r,
    const Esc_UINT8 scalar[],
    const EscPtArithTe25519_PointT* p )
{
    Esc_SINT8 bytePos;
    Esc_UINT8 bitPos, byte, currentMsb;
    EscPtArithTe25519_PointT ptR0, ptR1;
    EscPtArithTe25519_PointT* pointRArray[2U];

    /* Set P0 to the neutral element (0,1,0,1). Cf. [1] Section 3 */
    EscFeArith_SetZero( &ptR0.x );
    EscFeArith_SetOne( &ptR0.y );
    EscFeArith_SetZero( &ptR0.t );
    EscFeArith_SetOne( &ptR0.z);

    /* Set P1 to the input point */
    ptR1 = *p;

    pointRArray[0] = &ptR0;
    pointRArray[1] = &ptR1;

    /* Montgomery Powering ladder with indices instead of branches */
    for ( bytePos = 31; bytePos >= 0 ; bytePos--)
    {
        byte = scalar[bytePos];
        for (bitPos = 8U; bitPos > 0U; bitPos--)
        {
            /* Get always MSB of current byte */
            currentMsb = byte >> 7U;
            /* Adjust MSBit for next iteration */
            byte <<=1U;

            /* t must always be computed since we do not know in which algorithm the output point is used next. */
            EscPtArithTe25519_Add( pointRArray[1U - currentMsb], &ptR0, &ptR1, TRUE );
            EscPtArithTe25519_Double( pointRArray[currentMsb], pointRArray[currentMsb] );
        }
    }

    /* Copy result to output point */
    *r = ptR0;
}


/**
 * Calculate k0 * P0 + k1 * P1 with Shamir's trick. *
 * C.f Hankerson, et. al, "Guide to Elliptic Curve Cryptography", Alg. 3.48 with w  = 1
 */
void
EscPtArithTe25519_DoubleScalarMul(
    EscPtArithTe25519_PointT* r,
    const Esc_UINT8 scalarK0[],
    const EscPtArithTe25519_PointT* p0,
    const Esc_UINT8 scalarK1[],
    const EscPtArithTe25519_PointT* p1 )
{
    Esc_SINT8 bytePos;
    Esc_UINT8 bitPos, byteK0, byteK1, index;

    EscPtArithTe25519_PointT ptNeutral, ptPrecompP0P1;
    /* Array is adressed with current bits of K0 and K1 as index,
       e.g. current bits = 1 | 1 means precompArray[3] is used for addition. */
    const EscPtArithTe25519_PointT* precompArray[4U];

    /* 1.) Precompute P0 + P1 */
    EscPtArithTe25519_Add(&ptPrecompP0P1, p0, p1, TRUE );

    /* 3.) Set r to neutral (0,1,0,1). Cf. [1] Section 3 */
    EscFeArith_SetZero( &r->x );
    EscFeArith_SetOne( &r->y );
    EscFeArith_SetZero( &r->t );
    EscFeArith_SetOne( &r->z );

    /* Set neutral element */
    ptNeutral = *r;

    precompArray[0] = &ptNeutral;
    precompArray[1] = p1;
    precompArray[2] = p0;
    precompArray[3] = &ptPrecompP0P1;
    
    /* 4.) For all bits in the scalars do: */
    for ( bytePos = 31; bytePos >= 0 ; bytePos--)
    {
        byteK0 = scalarK0[bytePos];
        byteK1 = scalarK1[bytePos];
        for (bitPos = 8U; bitPos > 0U; bitPos--)
        {
            /* Get current bits of the two scalars and concatenate them to get the index of the precomputation array. */
            index = ((byteK0 >> 6U) & 0x02U) | (byteK1 >> 7U);

            /* Adjust MSBit for next iteration */
            byteK0 <<=1U;
            byteK1 <<=1U;

            /* 4.1 Double */
            EscPtArithTe25519_Double( r, r );

            /* 4.2 Add */
            if ( (bytePos == 0) && (bitPos == 1U) )
            {
                /* 5.) Compute final result with t coordinate */
                EscPtArithTe25519_Add(r, r, precompArray[index], TRUE );
            }
            else
            {
                EscPtArithTe25519_Add(r, r, precompArray[index], FALSE );
            }
        }
    }
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
