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
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "ecc_cfg.h"
#include "_ptarithws.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

static Esc_UINT32
EscPtArithWs_WdFromOctets(
    const Esc_UINT8 octets[],
    Esc_UINT32 idx );


/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/* CAUTION! - Little-Endian representation: i.e., all arrays are like  */
/* (a[0], a[1], .. , a[n]) there a[0] is the lowest and a[n] the highest word */

#if (EscEcc_SECP_192_ENABLED == 1)
/***************************************************************************
 * 4.2 SECP192R1 (y^2 = x^3 + ax + b over GF(p) with p = 2^192 - 2^64 - 1)  *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveSecp192r1 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xfffffffcUL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, EscFeArith_PADZEROS_FROM_6 } },
    /*EscEcc_COEFFICIENT_B*/ { {0xc146b9b1UL, 0xfeb8deecUL, 0x72243049UL, 0x0fa7e9abUL, 0xe59c80e7UL, 0x64210519UL, EscFeArith_PADZEROS_FROM_6 } },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x82ff1012UL, 0xf4ff0afdUL, 0x43a18800UL, 0x7cbf20ebUL, 0xb03090f6UL, 0x188da80eUL, EscFeArith_PADZEROS_FROM_6 } },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x1e794811UL, 0x73f977a1UL, 0x6b24cdd5UL, 0x631011edUL, 0xffc8da78UL, 0x07192b95UL, EscFeArith_PADZEROS_FROM_6 } },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6 } },
    },
    {
        /*EscEcc_MY_N*/ { {0x4B2DD7CFUL, 0xEB94364EUL, 0x662107C9UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_BASE_POINT_order_n*/ { {0xb4d22831UL, 0x146bc9b1UL, 0x99def836UL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_NLEN*/ 6U,
    },
    {
        /*EscEcc_MY_P*/ { {0x00000001UL, 0x00000000UL, 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_PRIME_P*/ { {0xffffffffUL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_PLEN*/ 6U,
    },
    {
        192U,   /* key size in bits */
        24U,    /* key size in bytes */
        6U,     /* key size in words */
        7U,
        14U,
    },
    EscFeArith_CURVE_SECP_192
};
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
/***************************************************************************
 * 4.3 SECP224 (y^2 = x^3 + ax + b over GF(p) with p = 2   ^224-2^96 + 1) *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveSecp224r1 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, EscFeArith_PADZEROS_FROM_7 } },
    /*EscEcc_COEFFICIENT_B*/ { {0x2355ffb4UL, 0x270b3943UL, 0xd7bfd8baUL, 0x5044b0b7UL, 0xf5413256UL, 0x0c04b3abUL, 0xb4050a85UL, EscFeArith_PADZEROS_FROM_7 } },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x115c1d21UL, 0x343280d6UL, 0x56c21122UL, 0x4a03c1d3UL, 0x321390b9UL, 0x6bb4bf7fUL, 0xb70e0cbdUL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x85007e34UL, 0x44d58199UL, 0x5a074764UL, 0xcd4375a0UL, 0x4c22dfe6UL, 0xb5f723fbUL, 0xbd376388UL, EscFeArith_PADZEROS_FROM_7 } },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7 } },
    },
    {
        /*EscEcc_MY_N*/ { {0xa3a3d5c3UL, 0xec22d6baUL, 0x1f470fc1UL, 0x0000e95dUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_8 } },
        /*EscEcc_BASE_POINT_order_n*/ { {0x5c5c2a3dUL, 0x13dd2945UL, 0xe0b8f03eUL, 0xffff16a2UL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8 } },
        /*EscEcc_NLEN*/ 7U,
    },
    {
        /*EscEcc_MY_P*/ { {0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_PRIME_P*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_PLEN*/ 7U,
    },
    {
        224U,   /* key size in bits */
        28U,    /* key size in bytes */
        7U,     /* key size in words */
        8U,
        16U,
    },
    EscFeArith_CURVE_SECP_224
};
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
/***************************************************************************
 * 4.4 SECP256R1 (y^2 = x^3 + ax + b over GF(p) with p = 2^224(2^32-1) +2^192+2^96 - 1) *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveSecp256r1 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xfffffffcUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
    /*EscEcc_COEFFICIENT_B*/ { {0x27d2604bUL, 0x3bce3c3eUL, 0xcc53b0f6UL, 0x651d06b0UL, 0x769886bcUL, 0xb3ebbd55UL, 0xaa3a93e7UL, 0x5ac635d8UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
    },
    {
        /*EscEcc_MY_N*/ { {0xeedf9bfeUL, 0x012ffd85UL, 0xdf1a6c21UL, 0x43190552UL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_BASE_POINT_order_n*/ { {0xfc632551UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_NLEN*/ 8U,
    },
    {
        /*EscEcc_MY_P*/ { {0x00000003UL, 0x00000000UL, 0xffffffffUL, 0xfffffffeUL, 0xfffffffeUL, 0xfffffffeUL, 0xffffffffUL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_PRIME_P*/ { {0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9 } },
        /*EscEcc_PLEN*/ 8U,
    },
    {
        256U,   /* key size in bits */
        32U,    /* key size in bytes */
        8U,     /* key size in words */
        9U,
        18U,
    },
    EscFeArith_CURVE_SECP_256
};
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
/***************************************************************************
 * 4.5 SECP384R1 (y^2 = x^3 + ax + b over GF(p) with p = p = 2^384 - 2^128 - 2^96 + 2^32 - 1) *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveSecp384r1 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xfffffffcUL, 0x00000000UL, 0x00000000UL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    /*EscEcc_COEFFICIENT_B*/ { {0xd3ec2aefUL, 0x2a85c8edUL, 0x8a2ed19dUL, 0xc656398dUL, 0x5013875aUL, 0x0314088fUL, 0xfe814112UL, 0x181d9c6eUL, 0xe3f82d19UL, 0x988e056bUL, 0xe23ee7e4UL, 0xb3312fa7UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x72760AB7UL, 0x3A545E38UL, 0xBF55296CUL, 0x5502F25DUL, 0x82542A38UL, 0x59F741E0UL, 0x8BA79B98UL, 0x6E1D3B62UL, 0xF320AD74UL, 0x8EB1C71EUL, 0xBE8B0537UL, 0xAA87CA22UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x90EA0E5FUL, 0x7A431D7CUL, 0x1D7E819DUL, 0x0A60B1CEUL, 0xB5F0B8C0UL, 0xE9DA3113UL, 0x289A147CUL, 0xF8F41DBDUL, 0x9292DC29UL, 0x5D9E98BFUL, 0x96262C6FUL, 0x3617DE4AUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    },
    {
        /*EscEcc_MY_N*/ { {0x333ad68dUL, 0x1313e695UL, 0xb74f5885UL, 0xa7e5f24dUL, 0x0bc8d220UL, 0x389cb27eUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_order_n*/ { {0xCCC52973UL, 0xECEC196AUL, 0x48B0A77AUL, 0x581A0DB2UL, 0xF4372DDFUL, 0xC7634D81UL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_NLEN*/ 12U,
    },
    {
        /*EscEcc_MY_P*/ { {0x00000001UL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_PRIME_P*/ { {0xffffffffUL, 0x00000000UL, 0x00000000UL, 0xffffffffUL, 0xfffffffeUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_PLEN*/ 12U,
    },
    {
        384U,   /* key size in bits */
        48U,    /* key size in bytes */
        12U,    /* key size in words */
        13U,
        26U,
    },
    EscFeArith_CURVE_SECP_384
};
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
/***************************************************************************
 * 4.6 SECP521R1 (y^2 = x^3 + ax + b over GF(p) with p = p = 2^521 - 1) *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveSecp521r1 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xFFFFFFFCUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x000001FFUL, 0x00000000UL} },
    /*EscEcc_COEFFICIENT_B*/ { {0x6B503F00UL, 0xEF451FD4UL, 0x3D2C34F1UL, 0x3573DF88UL, 0x3BB1BF07UL, 0x1652C0BDUL, 0xEC7E937BUL, 0x56193951UL, 0x8EF109E1UL, 0xB8B48991UL, 0x99B315F3UL, 0xA2DA725BUL, 0xB68540EEUL, 0x929A21A0UL, 0x8E1C9A1FUL, 0x953EB961UL, 0x00000051UL, 0x00000000UL} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0xc2e5bd66UL, 0xf97e7e31UL, 0x856a429bUL, 0x3348b3c1UL, 0xa2ffa8deUL, 0xfe1dc127UL, 0xefe75928UL, 0xa14b5e77UL, 0x6b4d3dbaUL, 0xf828af60UL, 0x053fb521UL, 0x9c648139UL, 0x2395b442UL, 0x9e3ecb66UL, 0x0404e9cdUL, 0x858e06b7UL, 0x000000c6UL, 0x00000000UL} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x9fd16650UL, 0x88be9476UL, 0xa272c240UL, 0x353c7086UL, 0x3fad0761UL, 0xc550b901UL, 0x5ef42640UL, 0x97ee7299UL, 0x273e662cUL, 0x17afbd17UL, 0x579b4468UL, 0x98f54449UL, 0x2c7d1bd9UL, 0x5c8a5fb4UL, 0x9a3bc004UL, 0x39296a78UL, 0x00000118UL, 0x00000000UL} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL} },
    },
    {
        /*EscEcc_MY_N*/ { {0xf501c8d1UL, 0xe6fdc408UL, 0x12385bb1UL, 0xee145124UL, 0x8d91dd98UL, 0x968bf112UL, 0xffadc23dUL, 0x1a65200cUL, 0x5e1f1034UL, 0x00016b9eUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00800000UL} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x91386409UL, 0xBB6FB71EUL, 0x899C47AEUL, 0x3BB5C9B8UL, 0xF709A5D0UL, 0x7FCC0148UL, 0xBF2F966BUL, 0x51868783UL, 0xFFFFFFFAUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x000001FFUL, 0x00000000UL} },
        /*EscEcc_NLEN*/ 17U,
    },
    {
        /*EscEcc_MY_P*/ { {0x00000000UL, 0x00004000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00800000UL} },
        /*EscEcc_PRIME_P*/ { {0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x000001FFUL, 0x00000000UL} },
        /*EscEcc_PLEN*/ 17U,
    },
    {
        521U,   /* key size in bits */
        66U,    /* key size in bytes */
        17U,    /* key size in words */
        18U,
        36U,
    },
    EscFeArith_CURVE_SECP_521
};
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
/***************************************************************************
 * 4.7 brainpoolP160r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool160 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xE8F7C300UL, 0xDA745D97UL, 0xE2BE61BAUL, 0xA280EB74UL, 0x340E7BE2UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
    /*EscEcc_COEFFICIENT_B*/ { {0xD8675E58UL, 0xBDEC95C8UL, 0x134FAA2DUL, 0x95423412UL, 0x1E589A85UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0xBDBCDBC3UL, 0x31EB5AF7UL, 0x62938C46UL, 0xEA3F6A4FUL, 0xBED5AF16UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x16DA6321UL, 0x669C9763UL, 0x38F94741UL, 0x7A1A8EC3UL, 0x1667CB47UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
    },
    {
        /*EscEcc_MY_N*/ { {0x033bc7e6UL, 0xb54e9909UL, 0xf1272478UL, 0x86396600UL, 0x18d392edUL, 0x00000001UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x9E60FC09UL, 0xD4502940UL, 0x60DF5991UL, 0x737059DCUL, 0xE95E4A5FUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_NLEN*/ 5U,
    },
    {
        /*EscEcc_MY_P*/ { {0xc26fb1efUL, 0xa5d79737UL, 0xf1269ff8UL, 0x86396600UL, 0x18d392edUL, 0x00000001UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_PRIME_P*/ { {0x9515620FUL, 0x95B3D813UL, 0x60DFC7ADUL, 0x737059DCUL, 0xE95E4A5FUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_6} },
        /*EscEcc_PLEN*/ 5U,
    },
    {
        160U,   /* key size in bits */
        20U,    /* key size in bytes */
        5U,     /* key size in words */
        6U,
        12U,
    },
    EscFeArith_CURVE_BRAINPOOL_P160
};
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
/***************************************************************************
 * 4.8 brainpoolP192r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool192 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xC69A28EFUL, 0xCAE040E5UL, 0xFE8685C1UL, 0x9C39C031UL, 0x76B1E0E1UL, 0x6A911740UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
    /*EscEcc_COEFFICIENT_B*/ { {0x6FBF25C9UL, 0xCA7EF414UL, 0x4F4496BCUL, 0xDC721D04UL, 0x7C28CCA3UL, 0x469A28EFUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x53375FD6UL, 0x0A2F5C48UL, 0x6CB0F090UL, 0x53B033C5UL, 0xAAB6A487UL, 0xC0A0647EUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0xFA299B8FUL, 0xE6773FA2UL, 0xC1490002UL, 0x8B5F4828UL, 0x6ABD5BB8UL, 0x14B69086UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
    },
    {
        /*EscEcc_MY_N*/ { {0x5e71f108UL, 0x3a674578UL, 0x68d2f9a8UL, 0x675bc2ffUL, 0xff1728c8UL, 0x500fea39UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x9AC4ACC1UL, 0x5BE8F102UL, 0x9E9E916BUL, 0xA7A3462FUL, 0x932A36CDUL, 0xC302F41DUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_NLEN*/ 6U,
    },
    {
        /*EscEcc_MY_P*/ { {0x10b1ac0aUL, 0x6639fecfUL, 0xc2462077UL, 0x675bc2fdUL, 0xff1728c8UL, 0x500fea39UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_PRIME_P*/ { {0xE1A86297UL, 0x8FCE476DUL, 0x93D18DB7UL, 0xA7A34630UL, 0x932A36CDUL, 0xC302F41DUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_7} },
        /*EscEcc_PLEN*/ 6U,
    },
    {
        192U,   /* key size in bits */
        24U,    /* key size in bytes */
        6U,     /* key size in words */
        7U,
        14U,
    },
    EscFeArith_CURVE_BRAINPOOL_P192
};
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
/***************************************************************************
 * 4.9 brainpoolP224r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool224 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xCAD29F43UL, 0xB0042A59UL, 0x4E182AD8UL, 0xC1530B51UL, 0x299803A6UL, 0xA9CE6C1CUL, 0x68A5E62CUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
    /*EscEcc_COEFFICIENT_B*/ { {0x386C400BUL, 0x66DBB372UL, 0x3E2135D2UL, 0xA92369E3UL, 0x870713B1UL, 0xCFE44138UL, 0x2580F63CUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0xEE12C07DUL, 0x4C1E6EFDUL, 0x9E4CE317UL, 0xA87DC68CUL, 0x340823B2UL, 0x2C7E5CF4UL, 0x0D9029ADUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x761402CDUL, 0xCAA3F6D3UL, 0x354B9E99UL, 0x4ECDAC24UL, 0x24C6B89EUL, 0x72C0726FUL, 0x58AA56F7UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
    },
    {
        /*EscEcc_MY_N*/ { {0x1c8a5ba1UL, 0x590a94d3UL, 0xbee15bc3UL, 0x603f1e9fUL, 0x4e1d543fUL, 0x8fd22299UL, 0x2fc099f7UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_BASE_POINT_order_n*/ { {0xA5A7939FUL, 0x6DDEBCA3UL, 0xD116BC4BUL, 0x75D0FB98UL, 0x2A183025UL, 0x26436686UL, 0xD7C134AAUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_NLEN*/ 7U,
    },
    {
        /*EscEcc_MY_P*/ { {0xb36f5f4fUL, 0xef60dc4dUL, 0x33da784fUL, 0x603de8fdUL, 0x4e1d543fUL, 0x8fd22299UL, 0x2fc099f7UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_PRIME_P*/ { {0x7EC8C0FFUL, 0x97DA89F5UL, 0xB09F0757UL, 0x75D1D787UL, 0x2A183025UL, 0x26436686UL, 0xD7C134AAUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_8} },
        /*EscEcc_PLEN*/ 7U,
    },
    {
        224U,   /* key size in bits */
        28U,    /* key size in bytes */
        7U,     /* key size in words */
        8U,
        16U,
    },
    EscFeArith_CURVE_BRAINPOOL_P224
};
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
/***************************************************************************
 * 4.10 brainpoolP256r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool256 =
{
    /*EscEcc_COEFFICIENT_A */ { {0xF330B5D9UL, 0xE94A4B44UL, 0x26DC5C6CUL, 0xFB8055C1UL, 0x417AFFE7UL, 0xEEF67530UL, 0xFC2C3057UL, 0x7D5A0975UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
    /*EscEcc_COEFFICIENT_B*/ { {0xFF8C07B6UL, 0x6BCCDC18UL, 0x5CF7E1CEUL, 0x95841629UL, 0xBBD77CBFUL, 0xF330B5D9UL, 0xE94A4B44UL, 0x26DC5C6CUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x9ACE3262UL, 0x3A4453BDUL, 0xE3BD23C2UL, 0xB9DE27E1UL, 0xFC81B7AFUL, 0x2C4B482FUL, 0xCB7E57CBUL, 0x8BD2AEB9UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x2F046997UL, 0x5C1D54C7UL, 0x2DED8E54UL, 0xC2774513UL, 0x14611DC9UL, 0x97F8461AUL, 0xC3DAC4FDUL, 0x547EF835UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
    },
    {
        /*EscEcc_MY_N*/ { {0xccd10716UL, 0x50d73b46UL, 0x5fdf55eaUL, 0x9bf0088cUL, 0x322a7bf4UL, 0xbb73aba8UL, 0xa1c55b7eUL, 0x818c1131UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x974856A7UL, 0x901E0E82UL, 0xB561A6F7UL, 0x8C397AA3UL, 0x9D838D71UL, 0x3E660A90UL, 0xA1EEA9BCUL, 0xA9FB57DBUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_NLEN*/ 8U,
    },
    {
        /*EscEcc_MY_P*/ { {0x1180dd0cUL, 0xb62ae630UL, 0xff6a2fa9UL, 0x9b4f54a0UL, 0x322a7bf2UL, 0xbb73aba8UL, 0xa1c55b7eUL, 0x818c1131UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_PRIME_P*/ { {0x1F6E5377UL, 0x2013481DUL, 0xD5262028UL, 0x6E3BF623UL, 0x9D838D72UL, 0x3E660A90UL, 0xA1EEA9BCUL, 0xA9FB57DBUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_9} },
        /*EscEcc_PLEN*/ 8U,
    },
    {
        256U,   /* key size in bits */
        32U,    /* key size in bytes */
        8U,     /* key size in words */
        9U,
        18U,
    },
    EscFeArith_CURVE_BRAINPOOL_P256
};
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
/***************************************************************************
 * 4.11 brainpoolP320r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool320 =
{
    /*EscEcc_COEFFICIENT_A */ { {0x7D860EB4UL, 0x92F375A9UL, 0x85FFA9F4UL, 0x66190EB0UL, 0xF5EB79DAUL, 0xA2A73513UL, 0x6D3F3BB8UL, 0x83CCEBD4UL, 0x8FBAB0F8UL, 0x3EE30B56UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
    /*EscEcc_COEFFICIENT_B*/ { {0x8FB1F1A6UL, 0x6F5EB4ACUL, 0x88453981UL, 0xCC31DCCDUL, 0x9554B49AUL, 0xE13F4134UL, 0x40688A6FUL, 0xD3AD1986UL, 0x9DFDBC42UL, 0x52088394UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x39E20611UL, 0x10AF8D0DUL, 0x10A599C7UL, 0xE7871E2AUL, 0x0A087EB6UL, 0xF20137D1UL, 0x8EE5BFE6UL, 0x5289BCC4UL, 0xFB53D8B8UL, 0x43BD7E9AUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x692E8EE1UL, 0xD35245D1UL, 0xAAAC6AC7UL, 0xA9C77877UL, 0x117182EAUL, 0x0743FFEDUL, 0x7F77275EUL, 0xAB409324UL, 0x45EC1CC8UL, 0x14FDD055UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
    },
    {
        /*EscEcc_MY_N*/ { {0xafa14203UL, 0x059081eaUL, 0xa154e856UL, 0x80461c1bUL, 0xf8341fe6UL, 0x22b851a6UL, 0x89ad9837UL, 0x4195c155UL, 0xaf1aa120UL, 0x360e55a5UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x44C59311UL, 0x8691555BUL, 0xEE8658E9UL, 0x2D482EC7UL, 0xB68F12A3UL, 0xF98FCFA5UL, 0xD201E065UL, 0xE13C785EUL, 0x36BC4FB7UL, 0xD35E4720UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_NLEN*/ 10U,
    },
    {
        /*EscEcc_MY_P*/ { {0xddc4b621UL, 0x2d8c7cafUL, 0x3d5ab45aUL, 0x55d42a20UL, 0x2237985cUL, 0x22b851a5UL, 0x89ad9837UL, 0x4195c155UL, 0xaf1aa120UL, 0x360e55a5UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_PRIME_P*/ { {0xF1B32E27UL, 0xFCD412B1UL, 0x7893EC28UL, 0x4F92B9ECUL, 0xF6F40DEFUL, 0xF98FCFA6UL, 0xD201E065UL, 0xE13C785EUL, 0x36BC4FB7UL, 0xD35E4720UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_11} },
        /*EscEcc_PLEN*/ 10U,
    },
    {
        320U,   /* key size in bits */
        40U,    /* key size in bytes */
        10U,    /* key size in words */
        11U,
        22U,
    },
    EscFeArith_CURVE_BRAINPOOL_P320
};
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
/***************************************************************************
 * 4.12 brainpoolP384r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool384 =
{
    /*EscEcc_COEFFICIENT_A */ { {0x22CE2826UL, 0x04A8C7DDUL, 0x503AD4EBUL, 0x8AA5814AUL, 0xBA91F90FUL, 0x139165EFUL, 0x4FB22787UL, 0xC2BEA28EUL, 0xCE05AFA0UL, 0x3C72080AUL, 0x3D8C150CUL, 0x7BC382C6UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    /*EscEcc_COEFFICIENT_B*/ { {0xFA504C11UL, 0x3AB78696UL, 0x95DBC994UL, 0x7CB43902UL, 0x3EEB62D5UL, 0x2E880EA5UL, 0x07DCD2A6UL, 0x2FB77DE1UL, 0x16F0447CUL, 0x8B39B554UL, 0x22CE2826UL, 0x04A8C7DDUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0x47D4AF1EUL, 0xEF87B2E2UL, 0x36D646AAUL, 0xE826E034UL, 0x0CBD10E8UL, 0xDB7FCAFEUL, 0x7EF14FE3UL, 0x8847A3E7UL, 0xB7C13F6BUL, 0xA2A63A81UL, 0x68CF45FFUL, 0x1D1C64F0UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x263C5315UL, 0x42820341UL, 0x77918111UL, 0x0E464621UL, 0xF9912928UL, 0xE19C054FUL, 0xFEEC5864UL, 0x62B70B29UL, 0x95CFD552UL, 0x5CB1EB8EUL, 0x20F9C2A4UL, 0x8ABE1D75UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
    },
    {
        /*EscEcc_MY_N*/ { {0xf8a71f8aUL, 0x600adcccUL, 0x7a652109UL, 0x189fdb46UL, 0x165031e7UL, 0xc506f2feUL, 0xcae56ee1UL, 0xdda2c449UL, 0x3cc6fa65UL, 0xff25adfdUL, 0x6d8ec6b8UL, 0xd1b575b1UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_BASE_POINT_order_n*/ { {0xE9046565UL, 0x3B883202UL, 0x6B7FC310UL, 0xCF3AB6AFUL, 0xAC0425A7UL, 0x1F166E6CUL, 0xED5456B3UL, 0x152F7109UL, 0x50E641DFUL, 0x0F5D6F7EUL, 0xA3386D28UL, 0x8CB91E82UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_NLEN*/ 12U,
    },
    {
        /*EscEcc_MY_P*/ { {0x84a26716UL, 0x10a03bf6UL, 0x7a71566fUL, 0x9047bce0UL, 0xf1c4d721UL, 0x9ed590ceUL, 0xcae56edeUL, 0xdda2c449UL, 0x3cc6fa65UL, 0xff25adfdUL, 0x6d8ec6b8UL, 0xd1b575b1UL, 0x00000001UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_PRIME_P*/ { {0x3107EC53UL, 0x87470013UL, 0x901D1A71UL, 0xACD3A729UL, 0x7FB71123UL, 0x12B1DA19UL, 0xED5456B4UL, 0x152F7109UL, 0x50E641DFUL, 0x0F5D6F7EUL, 0xA3386D28UL, 0x8CB91E82UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_13} },
        /*EscEcc_PLEN*/ 12U,
    },
    {
        384U,   /* key size in bits */
        48U,    /* key size in bytes */
        12U,    /* key size in words */
        13U,
        26U,
    },
    EscFeArith_CURVE_BRAINPOOL_P384
};
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
/***************************************************************************
 * 4.13 brainpoolP512r1 *
 ***************************************************************************/
const EscPtArithWs_CurveT EscPtArithWs_curveBrainpool512 =
{
    /*EscEcc_COEFFICIENT_A */ { {0x77FC94CAUL, 0xE7C1AC4DUL, 0x2BF2C7B9UL, 0x7F1117A7UL, 0x8B9AC8B5UL, 0x0A2EF1C9UL, 0xA8253AA1UL, 0x2DED5D5AUL, 0xEA9863BCUL, 0xA83441CAUL, 0x3DF91610UL, 0x94CBDD8DUL, 0xAC234CC5UL, 0xE2327145UL, 0x8B603B89UL, 0x7830A331UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
    /*EscEcc_COEFFICIENT_B*/ { {0x8016F723UL, 0x2809BD63UL, 0x5EBAE5DDUL, 0x984050B7UL, 0xDC083E67UL, 0x77FC94CAUL, 0xE7C1AC4DUL, 0x2BF2C7B9UL, 0x7F1117A7UL, 0x8B9AC8B5UL, 0x0A2EF1C9UL, 0xA8253AA1UL, 0x2DED5D5AUL, 0xEA9863BCUL, 0xA83441CAUL, 0x3DF91610UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
    {
        EscPtArith_TYPE_AFFINE,
        /*EscEcc_BASE_POINT_G_X*/ { {0xBCB9F822UL, 0x8B352209UL, 0x406A5E68UL, 0x7C6D5047UL, 0x93B97D5FUL, 0x50D1687BUL, 0xE2D0D48DUL, 0xFF3B1F78UL, 0xF4D0098EUL, 0xB43B62EEUL, 0xB5D916C1UL, 0x85ED9F70UL, 0x9C4C6A93UL, 0x5A21322EUL, 0xD82ED964UL, 0x81AEE4BDUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_BASE_POINT_G_Y*/ { {0x3AD80892UL, 0x78CD1E0FUL, 0xA8F05406UL, 0xD1CA2B2FUL, 0x8A2763AEUL, 0x5BCA4BD8UL, 0x4A5F485EUL, 0xB2DCDE49UL, 0x881F8111UL, 0xA000C55BUL, 0x24A57B1AUL, 0xF209F700UL, 0xCF7822FDUL, 0xC0EABFA9UL, 0x566332ECUL, 0x7DDE385DUL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_BASE_POINT_G_Z*/ { {0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
    },
    {
        /*EscEcc_MY_N*/ { {0xdb57db37UL, 0x2fafac64UL, 0x15d5c4ceUL, 0x0eaf0d90UL, 0x59ee4710UL, 0x9ff38f5fUL, 0x1a235d44UL, 0xdb9470c6UL, 0xf5bf92f7UL, 0x666ad8f2UL, 0xcc44ef09UL, 0x8373af60UL, 0x03461e1eUL, 0x15d5ea2fUL, 0xd6daeb8aUL, 0x7f8d7f4eUL, 0x00000001UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_BASE_POINT_order_n*/ { {0x9CA90069UL, 0xB5879682UL, 0x085DDADDUL, 0x1DB1D381UL, 0x7FAC1047UL, 0x41866119UL, 0x4CA92619UL, 0x553E5C41UL, 0x70330870UL, 0xD6639CCAUL, 0xB3C9D20EUL, 0xCB308DB3UL, 0x33C9FC07UL, 0x3FD4E6AEUL, 0xDBE9C48BUL, 0xAADD9DB8UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_NLEN*/ 16U,
    },
    {
        /*EscEcc_MY_P*/ { {0xe911e8d9UL, 0x17e2cf84UL, 0x603556d1UL, 0x71d621c4UL, 0x4e73ea8cUL, 0xe47d9303UL, 0x823152c5UL, 0x42ff2b38UL, 0xf5bf92f5UL, 0x666ad8f2UL, 0xcc44ef09UL, 0x8373af60UL, 0x03461e1eUL, 0x15d5ea2fUL, 0xd6daeb8aUL, 0x7f8d7f4eUL, 0x00000001UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_PRIME_P*/ { {0x583A48F3UL, 0x28AA6056UL, 0x2D82C685UL, 0x2881FF2FUL, 0xE6A380E6UL, 0xAECDA12AUL, 0x9BC66842UL, 0x7D4D9B00UL, 0x70330871UL, 0xD6639CCAUL, 0xB3C9D20EUL, 0xCB308DB3UL, 0x33C9FC07UL, 0x3FD4E6AEUL, 0xDBE9C48BUL, 0xAADD9DB8UL, 0x00000000UL, EscFeArith_PADZEROS_FROM_17} },
        /*EscEcc_PLEN*/ 16U,
    },
    {
        512U,   /* key size in bits */
        64U,    /* key size in bytes */
        16U,    /* key size in words */
        17U,
        34U,
    },
    EscFeArith_CURVE_BRAINPOOL_P512
};
#endif


/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/


const EscPtArithWs_CurveT*
EscPtArithWs_GetCurve(const EscFeArith_CurveId id)
{
    const EscPtArithWs_CurveT *result = Esc_NULL_PTR;

    switch (id)
    {
#if (EscEcc_SECP_192_ENABLED == 1)
        case EscFeArith_CURVE_SECP_192:
            result = &EscPtArithWs_curveSecp192r1;
            break;
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
        case EscFeArith_CURVE_SECP_224:
            result = &EscPtArithWs_curveSecp224r1;
            break;
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
        case EscFeArith_CURVE_SECP_256:
            result = &EscPtArithWs_curveSecp256r1;
            break;
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
        case EscFeArith_CURVE_SECP_384:
            result = &EscPtArithWs_curveSecp384r1;
            break;
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
        case EscFeArith_CURVE_SECP_521:
            result = &EscPtArithWs_curveSecp521r1;
            break;
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P160:
            result = &EscPtArithWs_curveBrainpool160;
            break;
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P192:
            result = &EscPtArithWs_curveBrainpool192;
            break;
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P224:
            result = &EscPtArithWs_curveBrainpool224;
            break;
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P256:
            result = &EscPtArithWs_curveBrainpool256;
            break;
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P320:
            result = &EscPtArithWs_curveBrainpool320;
            break;
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P384:
            result = &EscPtArithWs_curveBrainpool384;
            break;
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
        case EscFeArith_CURVE_BRAINPOOL_P512:
            result = &EscPtArithWs_curveBrainpool512;
            break;
#endif

        default:
            /* Result is already set to NULL to indicate an error */
            break;
    }

    return result;
}


/******************************************************
Converts an octet string in Big Endian format into a Esc_UINT32 value in little Endian
 ******************************************************/
static Esc_UINT32
EscPtArithWs_WdFromOctets(
    const Esc_UINT8 octets[],
    Esc_UINT32 idx )
{
    Esc_UINT32 v;
    v = ( ( (Esc_UINT32)octets[idx + 3U] ) |
          ( (Esc_UINT32)octets[idx + 2U] << 8 ) |
          ( (Esc_UINT32)octets[idx + 1U] << 16 ) |
          ( (Esc_UINT32)octets[idx] << 24 )
          );
    return v;
}


/**************************
 * sets point to infinity *
 **************************/
void
EscPtArithWs_SetInfinity(
    EscPtArithWs_PointT* pX )
{
    if (pX->type == EscPtArith_TYPE_AFFINE)
    {
        /* pX = (0,0,0) */
        EscFeArith_SetZero( &pX->x );
        EscFeArith_SetZero( &pX->y );
        EscFeArith_SetZero( &pX->z );
    }
    else
    {
        /* pX->type == EscPtArith_TYPE_JACOBIAN */
        /* pX = (1,1,0) */
        EscFeArith_SetOne( &pX->x );
        EscFeArith_SetOne( &pX->y );
        EscFeArith_SetZero( &pX->z );
    }
}

/*****************************
 * checks if a point is zero *
 *****************************/
Esc_BOOL
EscPtArithWs_IsZero(
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve )
{
    Esc_BOOL isZero = TRUE;

    if (EscFeArith_IsZero( &pX->x, curve->curveSize.maxWords ) == FALSE)
    {
        isZero = FALSE;
    }
    else if (EscFeArith_IsZero( &pX->y, curve->curveSize.maxWords ) == FALSE)
    {
        isZero = FALSE;
    }
    else
    {
        if ( (pX->type == EscPtArith_TYPE_JACOBIAN) )
        {
            if (EscFeArith_IsZero( &pX->z, curve->curveSize.maxWords ) == FALSE)
            {
                isZero = FALSE;
            }
        }
    }

    return isZero;
}

/******************************************************
 * check if a point of the given curve is at infinity *
 ******************************************************/
Esc_BOOL
EscPtArithWs_IsInfinity(
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve )
{
    Esc_BOOL isInfinity;

    /* check if infinity */
    if (pX->type == EscPtArith_TYPE_AFFINE)
    {
        /* pX =? (0,0) */
        isInfinity = EscPtArithWs_IsZero( pX, curve );
    }
    else
    {
        /* pX->type == EscPtArith_TYPE_JACOBIAN */
        /* pX =? (lamba^2,lamba^3,0) */
        isInfinity = EscFeArith_IsZero( &pX->z, curve->curveSize.maxWords );
    }

    return isInfinity;
}

/******************
 * assign a point *
 ******************/
void
EscPtArithWs_Assign(
    EscPtArithWs_PointT* pY,
    const EscPtArithWs_PointT* pX,
    const EscPtArithWs_CurveT* curve )
{
    /* assign type */
    pY->type = pX->type;

    /* assign coordinates */
    EscFeArith_Assign( &pY->x, &pX->x, curve->curveSize.maxWords );
    EscFeArith_Assign( &pY->y, &pX->y, curve->curveSize.maxWords );
    EscFeArith_Assign( &pY->z, &pX->z, curve->curveSize.maxWords );
}

/*************************************************************************************
 * doubles a jacobian projection point                                               *
 * for A = -3 (NIST):     Algorithm 3.21 from "Guide to Elliptic Curve Cryptography" *
 * for any A (Brainpool): Algorithm A.10.4 from IEEE P1363-2000                      *
 *************************************************************************************/
void
EscPtArithWs_JacobianDouble(
    EscPtArithWs_PointT* pJ,
    const EscPtArithWs_PointT* pJ0,
    const EscPtArithWs_CurveT* curve )
{
    /* Shortcuts to curve attributes */
    EscFeArith_CurveId curveId = curve->curveId;
    const EscFeArith_SizeT* curveSize = &curve->curveSize;
    const Esc_UINT8 maxWords = curveSize->maxWords;
    const EscFeArith_FieldT* ecc_field_params = &curve->ecc_field_params;
    Esc_ASSERT( pJ0->type == EscPtArith_TYPE_JACOBIAN );

    /* set pJ type */
    pJ->type = EscPtArith_TYPE_JACOBIAN;

    /* check for point at infinity */
    if ( EscPtArithWs_IsInfinity( pJ0, curve ) )
    {
        EscPtArithWs_SetInfinity( pJ );
    }
    else if ( EscFeArith_IsZero( &pJ0->y, maxWords ) )
    {
        EscPtArithWs_SetInfinity( pJ );
    }
    else if ( EscFeArith_IsZero( &pJ0->z, maxWords ) )
    {
        EscPtArithWs_SetInfinity( pJ );
    }
    else
    {
#if (EscEcc_ANY_NIST_CURVE_ENABLED)
        /*************************************************************************************
         * doubles a jacobian projection point                                               *
         * for A = -3 (NIST):     Bernstein/Lange 2001 Algorithm from                        *
         * "http:/ /www.hyperelliptic.org/EFD/oldefd/jacobian.html#DBL"
         * Cost: 3M + 5S + 8add + 1times3 + 1times4 + 2times8
          1     delta:=Z1^2;
          2     gamma:=Y1^2;
          3     beta:=X1*gamma;
          4     alpha:=3*(X1-delta)*(X1+delta);
          5     X3:=alpha^2-8*beta;
          6     Z3:=(Y1+Z1)^2-gamma-delta;
          7     Y3:=alpha*(4*beta-X3)-8*gamma^2;
         *
         *************************************************************************************/
        if ((curve->curveId >= EscFeArith_CURVE_SECP_192)
                && (curve->curveId <= EscFeArith_CURVE_SECP_521))
        {
            /* Special version of NIST curves. Assumes A = -3 mod p */

            EscFeArith_FieldElementT delta;
            EscFeArith_FieldElementT gamma;
            EscFeArith_FieldElementT beta;

            EscFeArith_FieldElementT alpha;

            EscFeArith_FieldElementT tempOne;
            EscFeArith_FieldElementT tempTwo;

            /* 1.) delta <- Z1^2 */
            EscFeArith_SquareModP(&delta, &pJ0->z, ecc_field_params, curveId, curveSize);

            /* 2.) gamma <- Y1^2 */
            EscFeArith_SquareModP(&gamma, &pJ0->y, ecc_field_params, curveId, curveSize);

            /* 3.) beta <- X1 * gamma */
            EscFeArith_MultiplyModP(&beta, &pJ0->x, &gamma, ecc_field_params, curveId, curveSize);

            /* 4.) alpha = 3*(X1-delta)*(X1+delta) */
            EscFeArith_ModularSub(&tempOne, &pJ0->x, &delta, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&tempTwo, &pJ0->x, &delta, ecc_field_params, maxWords);
            EscFeArith_MultiplyModP(&alpha, &tempOne, &tempTwo, ecc_field_params, curveId,
                                    curveSize);
            EscFeArith_ModularAdd(&tempOne, &alpha, &alpha, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&alpha, &alpha, &tempOne, ecc_field_params, maxWords);

            /* 5.) X3:=alpha^2-8*beta */
            EscFeArith_SquareModP(&pJ->x, &alpha, ecc_field_params, curveId, curveSize);
            EscFeArith_ModularAdd(&tempOne, &beta, &beta, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&tempTwo, &tempOne, &tempOne, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&tempOne, &tempTwo, &tempTwo, ecc_field_params, maxWords);
            EscFeArith_ModularSub(&pJ->x, &pJ->x, &tempOne, ecc_field_params, maxWords);

            /* 6.) Z3:=(Y1+Z1)^2-gamma-delta */
            EscFeArith_ModularAdd(&pJ->z, &pJ0->y, &pJ0->z, ecc_field_params, maxWords);
            EscFeArith_SquareModP(&pJ->z, &pJ->z, ecc_field_params, curveId, curveSize);
            EscFeArith_ModularSub(&pJ->z, &pJ->z, &gamma, ecc_field_params, maxWords);
            EscFeArith_ModularSub(&pJ->z, &pJ->z, &delta, ecc_field_params, maxWords);

            /* 7.) Y3:=alpha*(4*beta-X3)-8*gamma^2 */
            EscFeArith_ModularSub(&pJ->y, &tempTwo, &pJ->x, ecc_field_params, maxWords);
            EscFeArith_MultiplyModP(&pJ->y, &pJ->y, &alpha, ecc_field_params, curveId, curveSize);
            EscFeArith_SquareModP(&gamma, &gamma, ecc_field_params, curveId, curveSize);
            EscFeArith_ModularAdd(&tempOne, &gamma, &gamma, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&tempTwo, &tempOne, &tempOne, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&tempOne, &tempTwo, &tempTwo, ecc_field_params, maxWords);
            EscFeArith_ModularSub(&pJ->y, &pJ->y, &tempOne, ecc_field_params, maxWords);
        }
#endif /* EscEcc_ANY_NIST_CURVE_ENABLED */

#if (EscEcc_ANY_BRAINPOOL_CURVE_ENABLED)
        if ( (curve->curveId >= EscFeArith_CURVE_BRAINPOOL_P160) && (curve->curveId <= EscFeArith_CURVE_BRAINPOOL_P512) )
        {
            /* Generic version for arbitrary values of A */

            EscFeArith_FieldElementT T1;
            EscFeArith_FieldElementT T2;
            EscFeArith_FieldElementT T3;
            EscFeArith_FieldElementT T4;
            EscFeArith_FieldElementT T5;

            /* 04.) If T2 = 0 or T3 = 0 then output (1, 1, 0) and stop */
            /* checked above */

            /*        T5 <- Z^2 */
            EscFeArith_SquareModP( &T5, &pJ0->z, ecc_field_params, curveId, curveSize );
            /*        T5 <- T5^2 */
            EscFeArith_SquareModP( &T5, &T5, ecc_field_params, curveId, curveSize );
            /*        T5 <- a * T5 */
            EscFeArith_MultiplyModP( &T5, &curve->coefficient_a, &T5, ecc_field_params, curveId, curveSize );
            /*        T3 <- X^2 */
            EscFeArith_SquareModP( &T3, &pJ0->x, ecc_field_params, curveId, curveSize );
            /*        T4 <- 3 * T4 */
            EscFeArith_ModularAdd( &T4, &T3, &T3, ecc_field_params, maxWords );
            EscFeArith_ModularAdd( &T4, &T4, &T3, ecc_field_params, maxWords );

            /*        T4 <- T4 + T5 = M */
            EscFeArith_ModularAdd( &T4, &T4, &T5, ecc_field_params, maxWords );
            /* 06.) T3 <- Y * Z */
            EscFeArith_MultiplyModP( &T3, &pJ0->y, &pJ0->z, ecc_field_params, curveId, curveSize );
            /* 07.) Z2 <- 2 * T3 */
            EscFeArith_ModularAdd( &pJ->z, &T3, &T3, ecc_field_params, maxWords );
            /* 08.) T2 <- Y^2 */
            EscFeArith_SquareModP( &T2, &pJ0->y, ecc_field_params, curveId, curveSize );
            /* 09.) T5 <- X * T2 */
            EscFeArith_MultiplyModP( &T5, &pJ0->x, &T2, ecc_field_params, curveId, curveSize );
            /* 10.) T5 <- 4 * T5 = S */
            EscFeArith_ModularAdd( &T5, &T5, &T5, ecc_field_params, maxWords );
            EscFeArith_ModularAdd( &T5, &T5, &T5, ecc_field_params, maxWords );
            /* 11.) T1 <- T4^2 */
            EscFeArith_SquareModP( &T1, &T4, ecc_field_params, curveId, curveSize );
            /* 12.) X2 <- T1 - 2 * T5 */
            EscFeArith_ModularSub( &T1, &T1, &T5, ecc_field_params, maxWords );
            EscFeArith_ModularSub( &pJ->x, &T1, &T5, ecc_field_params, maxWords );
            /* 13.) T2 <- T2^2 */
            EscFeArith_SquareModP( &T2, &T2, ecc_field_params, curveId, curveSize );
            /* 14.) T2 <- 8 * T2 = T */
            EscFeArith_ModularAdd( &T2, &T2, &T2, ecc_field_params, maxWords );
            EscFeArith_ModularAdd( &T2, &T2, &T2, ecc_field_params, maxWords );
            EscFeArith_ModularAdd( &T2, &T2, &T2, ecc_field_params, maxWords );
            /* 15.) T5 <- T5 - T1 */
            EscFeArith_ModularSub( &T5, &T5, &pJ->x, ecc_field_params, maxWords );
            /* 16.) T5 <- T4 * T5 */
            EscFeArith_MultiplyModP( &T5, &T4, &T5, ecc_field_params, curveId, curveSize );
            /* 17.) Y2 <- T5 - T2 */
            EscFeArith_ModularSub( &pJ->y, &T5, &T2, ecc_field_params, maxWords );
        }
#endif
    }
}

/**********************************************************
 * Jacobian-Jacobian and Mixed jacobian-Affine addition   *
 * Algorithm from 2007 Bernstein/Lange
 * http:/ /www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
 * http:/ /www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
 * (older pages:
 * http:/ /www.hyperelliptic.org/EFD/oldefd/jacobian.html#ADD
 * http:/ /www.hyperelliptic.org/EFD/oldefd/jacobian.html#mADD*)
 *     Cost: 11M + 5S + 9add + 4*2.
 *     (the last term is changed to 3*2 + 1*4, which is effectively 5*2,
 *     to calculate H^2 needed when Z2 = 1)
 *
 1       Z1Z1 = Z1^2
 2       Z2Z2 = Z2^2
 3       U1 = X1*Z2Z2
 4       U2 = X2*Z1Z1
 5       S1 = Y1*Z2*Z2Z2
 6       S2 = Y2*Z1*Z1Z1
 7       H = U2-U1
 8       I = (2*H)^2
 9       J = H*I
10       r = 2*(S2-S1)
11       V = U1*I
12       X3 = r^2-J-2*V
13       Y3 = r*(V-X3)-2*S1*J
14       Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
 * for Z = 1:
 *   Cost: 7M + 4S + 9add + 3*2 + 1*4.
 1       Z1Z1 = Z1^2
 4       U2 = X2*Z1Z1
 6       S2 = Y2*Z1*Z1Z1
 7       H = U2-X1
 8a      HH = H^2
 8b      I = 4*HH
 9       J = H*I
10       r = 2*(S2-Y1)
11       V = X1*I
12       X3 = r^2-J-2*V
13       Y3 = r*(V-X3)-2*Y1*J
14       Z3 = (Z1+H)^2-Z1Z1-HH
 **********************************************************/
void
EscPtArithWs_JacobianAdd(
    EscPtArithWs_PointT* pJ,
    const EscPtArithWs_PointT* pJ1,
    const EscPtArithWs_PointT* pJ2,
    const EscPtArithWs_CurveT* curve )
{
    /* Shortcuts to curve attributes */
    EscFeArith_CurveId curveId = curve->curveId;
    const EscFeArith_SizeT* curveSize = &curve->curveSize;
    const Esc_UINT8 maxWords = curveSize->maxWords;
    const EscFeArith_FieldT* ecc_field_params = &curve->ecc_field_params;

    /* pJ1 =? (0) */
    if ( EscPtArithWs_IsInfinity( pJ1, curve ) )
    {
        /* pJ <- pJ2 */
        EscPtArithWs_Assign( pJ, pJ2, curve );
    }
    /* pJ2 =? (0) */
    else if ( EscPtArithWs_IsInfinity( pJ2, curve ) )
    {
        /* pJ <- pJ1 */
        EscPtArithWs_Assign( pJ, pJ1, curve );
    }
    else
    {
        Esc_BOOL Z2_is_1;
        EscFeArith_FieldElementT Z1Z1;
/*         EscFeArith_FieldElementT U2; */
#define U2 H
/*         EscFeArith_FieldElementT S2; */
#define S2 r
        EscFeArith_FieldElementT H;
        EscFeArith_FieldElementT HH;
/*         EscFeArith_FieldElementT I; */
#define I V
        EscFeArith_FieldElementT J;
        EscFeArith_FieldElementT r;
        EscFeArith_FieldElementT V;
        EscFeArith_FieldElementT U1;
        EscFeArith_FieldElementT S1;
        EscFeArith_FieldElementT Z2Z2;
/*         EscFeArith_FieldElementT Z2Z2Z2; */
#define Z2Z2Z2 S1
        /* set pJ type. */
        pJ->type = EscPtArith_TYPE_JACOBIAN;

        Z2_is_1 = EscFeArith_IsOne( &pJ2->z, maxWords );
        /*  if Z1 != 1 then */
        if (Z2_is_1 == FALSE)
        {
            /* 2.)   Z2Z2 <- Z2^2 */
            EscFeArith_SquareModP( &Z2Z2, &pJ2->z, ecc_field_params, curveId, curveSize );
            /* Z2Z2Z2 <- Z2 * Z2^2 */
            EscFeArith_MultiplyModP( &Z2Z2Z2, &pJ2->z, &Z2Z2, ecc_field_params, curveId, curveSize );
            /* 3.) U1 <- X1 * Z2Z2 */
            EscFeArith_MultiplyModP( &U1, &pJ1->x, &Z2Z2, ecc_field_params, curveId, curveSize );
            /* 5.) S1 <- Y1 * Z2Z2Z2 */
            EscFeArith_MultiplyModP( &S1, &pJ1->y, &Z2Z2Z2, ecc_field_params, curveId, curveSize );
        }
        else
        {
            /* 3.) U1 <- X1 (if Z2 = 1) */
            EscFeArith_Assign( &U1, &pJ1->x, maxWords );
            /* 5.) S1 <- Y1 (if Z2 = 1) */
            EscFeArith_Assign( &S1, &pJ1->y, maxWords );
        }

        /* 1.) Z1Z1 <- Z1^2 */
        EscFeArith_SquareModP( &Z1Z1, &pJ1->z, ecc_field_params, curveId, curveSize );
        /* 4.) U2 <- X2 * Z1Z1  */
        EscFeArith_MultiplyModP( &U2, &pJ2->x, &Z1Z1, ecc_field_params, curveId, curveSize );
        /* 6.) S2 <- Y2 * Z1 * Z1Z1 */
        EscFeArith_MultiplyModP( &S2, &pJ1->z, &Z1Z1, ecc_field_params, curveId, curveSize );
        EscFeArith_MultiplyModP( &S2, &pJ2->y, &S2, ecc_field_params, curveId, curveSize );
        /* 7.) H <- U2 - U1 */
        EscFeArith_ModularSub( &H, &U2, &U1, ecc_field_params, maxWords );
        /* 10.) r <- 2*(S2 - S1) */
        EscFeArith_ModularSub( &r, &S2, &S1, ecc_field_params, maxWords );
        EscFeArith_ModularAdd( &r, &r, &r, ecc_field_params, maxWords );

        /*  if H = 0 (denominator) then */
        if ( EscFeArith_IsZero( &H, maxWords ) )
        {
            if ( EscFeArith_IsZero( &r, maxWords ) )
            {
                /* if r = 0 (numerator) then pJ1 = pJ2, perform doubling: */
                /* double pJ1 */
                EscPtArithWs_JacobianDouble( pJ, pJ1, curve );
            }
            else
            {
                /* else output infinity (1, 1, 0) and stop */
                /* pJ = (0) */
                EscPtArithWs_SetInfinity( pJ );
            }
        }
        else
        {
            /* 8.a.) HH <- H^2 */
            EscFeArith_SquareModP(&HH, &H, ecc_field_params, curveId, curveSize);
            /* 8.b.) I <- 4*HH */
            EscFeArith_ModularAdd(&I, &HH, &HH, ecc_field_params, maxWords);
            EscFeArith_ModularAdd(&I, &I, &I, ecc_field_params, maxWords);
            /* 9.) J <- H*I */
            EscFeArith_MultiplyModP( &J, &H, &I, ecc_field_params, curveId, curveSize );
            /* 11.) V <- U1*I */
            EscFeArith_MultiplyModP( &V, &U1, &I, ecc_field_params, curveId, curveSize );

            /* 12.) X3 <- r^2 -J - 2 * V  */
            EscFeArith_SquareModP(&pJ->x, &r, ecc_field_params, curveId, curveSize);
            EscFeArith_ModularAdd( &U1, &V, &V, ecc_field_params, maxWords );
            EscFeArith_ModularSub( &pJ->x, &pJ->x, &U1, ecc_field_params, maxWords );
            EscFeArith_ModularSub( &pJ->x, &pJ->x, &J, ecc_field_params, maxWords );

            /* 13.) Y3 <- r * (V- X3) - 2 * S1 * J  */
            EscFeArith_ModularSub(&pJ->y, &V, &pJ->x, ecc_field_params, maxWords);
            EscFeArith_MultiplyModP( &pJ->y, &pJ->y, &r, ecc_field_params, curveId, curveSize );
            EscFeArith_MultiplyModP( &U1, &S1, &J, ecc_field_params, curveId, curveSize );
            EscFeArith_ModularAdd(&U1, &U1, &U1, ecc_field_params, maxWords);
            EscFeArith_ModularSub(&pJ->y, &pJ->y, &U1, ecc_field_params, maxWords);

            if (Z2_is_1 == FALSE)
            {
                /*lint --e{645} Z2Z2 would have been initialized in the block
                 * above with same if (Z2_is_1 == FALSE).
                 */
                /* 14.) Z3 <- ( (Z1 + Z2) ^ 2 - Z1Z1 - Z2Z2 ) * H  */
                EscFeArith_ModularAdd(&pJ->z, &pJ1->z, &pJ2->z, ecc_field_params, maxWords);
                EscFeArith_SquareModP(&pJ->z, &pJ->z, ecc_field_params, curveId, curveSize);
                EscFeArith_ModularSub(&pJ->z, &pJ->z, &Z1Z1, ecc_field_params, maxWords);
                EscFeArith_ModularSub(&pJ->z, &pJ->z, &Z2Z2, ecc_field_params, maxWords);
                EscFeArith_MultiplyModP(&pJ->z, &pJ->z, &H, ecc_field_params, curveId, curveSize);
            }
            else
            {
                /* 14.) Z3 <-  (Z1 + H) ^ 2 - Z1Z1 - HH  */
                EscFeArith_ModularAdd(&pJ->z, &H, &pJ1->z, ecc_field_params, maxWords);
                EscFeArith_SquareModP(&pJ->z, &pJ->z, ecc_field_params, curveId, curveSize);
                EscFeArith_ModularSub(&pJ->z, &pJ->z, &Z1Z1, ecc_field_params, maxWords);
                EscFeArith_ModularSub(&pJ->z, &pJ->z, &HH, ecc_field_params, maxWords);
            }
        }                       /* !EscFeArith_IsZero( &T4 ) */
    }                           /* pJ0 != (0) && pJ1 != (0) */
}

/****************************************************************
 * calculate k according to Algo B.5.2 from FIPS186-4 (page 64) *
 ****************************************************************/
Esc_ERROR
EscPtArithWs_CalculateRandomK(
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscPtArithWs_CurveT* curve,
    EscFeArith_FieldElementT* k)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 rand[EscFeArith_MAX_WORDS * 4U];
    EscFeArith_FieldElementT n_minus_one;
    Esc_UINT32 zeroBitMask, temp, randomErrorCount;
    Esc_SINT8 compResult;

    /* Set the least significant word of the FE to zero to prevent s compiler warning about a "maybe uninitialized variable".
       The Assign() function will write curve->base_point_order_n.pLen words which is always > 0. */
    n_minus_one.word[0] = 0U;
    /* calculate n-1. base_point_order_n is a prime value and always odd, therefore a minus one in the LSByte will work here. */
    EscFeArith_Assign(&n_minus_one, &curve->base_point_order_n.prime_p, curve->base_point_order_n.pLen);
    Esc_ASSERT( (n_minus_one.word[0] & 0x01U) == 1U );
    n_minus_one.word[0] = n_minus_one.word[0] - 1U;

    /* calculate mask to remove all bits above the msb of n-1 */
    zeroBitMask = EscFeArith_32BIT_WORD_ALL_SET; /* 32bit mask, all bits set */
    temp = EscFeArith_32BIT_WORD_MSB_SET;        /* 32bit mask, msb set */

    Esc_ASSERT( n_minus_one.word[curve->base_point_order_n.pLen - 1U] != 0U );

    while ( (n_minus_one.word[curve->base_point_order_n.pLen - 1U] & temp) == 0U)
    {
        zeroBitMask >>= 1U;
        temp >>= 1U;
    }

    /* fill unused words in k with zeroes */
    for (temp = curve->base_point_order_n.pLen; temp < EscFeArith_MAX_WORDS; temp++)
    {
        k->word[temp] = 0U;
    }

    /* generate random k */
    /* k is valid if 0 < k < n */
    randomErrorCount = 0U;
    do
    {
        /* fill rand with enough random bytes */
        returnCode = getRandomFunc(randomState, rand, (4U * (Esc_UINT32)curve->base_point_order_n.pLen) );
        if (returnCode != Esc_NO_ERROR)
        {
            break;
        }
        /* Convert random byte array into random FE k. */
        for (temp = 0U; temp < curve->base_point_order_n.pLen; temp++)
        {
            k->word[temp] = EscPtArithWs_WdFromOctets( rand, temp * 4U );
        }

        /* mask out all bits over the msb of n-1 */
        k->word[curve->base_point_order_n.pLen - 1U] &= zeroBitMask;

        /* compare k and n-1 */
        compResult = EscFeArith_AbsoluteCompare( k, &n_minus_one, curve->base_point_order_n.pLen );
        randomErrorCount++;
    } while ( (randomErrorCount < EscPtArithWs_MAX_RANDOM_CALLS) &&
              ((compResult >= 0) || (EscFeArith_IsZero(k, curve->curveSize.maxWords) == TRUE)) );

    if (randomErrorCount > EscPtArithWs_MAX_RANDOM_CALLS)
    {
        returnCode = Esc_INTERNAL_FUNCTION_ERROR;
    }


    /* Zeroize stack variables */
    Esc_memclear(rand, sizeof(rand));

    return returnCode;
}

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
