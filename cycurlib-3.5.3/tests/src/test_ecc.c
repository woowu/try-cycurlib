/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief ECC Selftest

   $Rev: 4177 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_ecc.h"
#include "selftest.h"
#include "_ptarithws.h"
#include "ecc.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
#define dual_point_mul_test_number 10U
/***************************************************************************
 * 3. TYPE DEFINITIONS                                                     *
 ***************************************************************************/
/** test vectors for ECC */
typedef struct
{
    /** secret key */
    const Esc_UINT8 *sec_key;
    /** public key x coordinate */
    const Esc_UINT8 *pubkey_x;
    /** public key y coordinate */
    const Esc_UINT8 *pubkey_y;
#if EscEcc_ECDSA_ENABLED == 1
    /** ECDSA hash value */
    const Esc_UINT8 *hash;
    /** ECDSA hash length in bytes */
    Esc_UINT32 hashLen;
    /** ECDSA random value */
    const Esc_UINT8 *random;
    /** ECDSA signature r value */
    const Esc_UINT8 *ecdsa_sig_r;
    /** ECDSA signature s value */
    const Esc_UINT8 *ecdsa_sig_s;
#endif
    /** selected ECC curve */
    EscEcc_CurveId curve;
} s_ecc_tst_vector;

typedef struct
{
    const EscFeArith_FieldElementT k0;
    const EscFeArith_FieldElementT k1;
    const EscPtArithWs_PointT p;
} dual_point_mul_tst_vector;

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/
#if EscEcc_ECDSA_ENABLED == 1
#if (EscEcc_SECP_256_ENABLED == 1 && EscFeArith_ENABLE_SHAMIRS_TRICK == 1)
dual_point_mul_tst_vector tst_dual_point_multiplication[dual_point_mul_test_number] =
{
{
    /* That is P */
    { {0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, 0xffffffffUL, 0x00000000UL} },
    { {0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000001UL, 0xffffffffUL, 0x00000000UL} },
    {
    2U,
    {{0x7157bca6UL, 0x931f1c94UL, 0xf7ba8eUL, 0x8fdd0151UL, 0xc50950c1UL, 0xd5f31232UL, 0x27920a4aUL, 0x52e5aff5UL,  0x0UL }},
    {{0x6266cdb9UL, 0x42a516d5UL, 0x55574a11UL, 0xa97da02aUL, 0xb5fa683UL, 0x2f56e59dUL, 0x3c515216UL, 0x244843b6UL,  0x0UL }},
    {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0UL }}
    }
},
{
    /*That is n */
    { {0xfc632551UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    { {0xfc632551UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    {
    2U,
   {{0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,  0x0UL }},
   {{0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,  0x0UL }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
    }
},
{
    /*That is n - 1 */
    { {0xfc632550UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    { {0xfc632550UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    {
    2U,
    {{0x47669978UL, 0xa60b48fcUL, 0x77f21b35UL, 0xc08969e2UL, 0x4b51ac3UL, 0x8a523803UL, 0x8d034f7eUL, 0x7cf27b18UL,  0x0UL }},
    {{0xdd878c2eUL, 0x61fb4862UL, 0xc3167dd6UL, 0x4582521aUL, 0x608bcf24UL, 0xd6c26539UL, 0x24712fc0UL, 0xf888aaeeUL,  0x0UL }},
    {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
    }
},
{
    /*That is n + 1 */
    { {0xfc632552UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    { {0xfc632552UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    {
    2U,
    {{0x47669978UL, 0xa60b48fcUL, 0x77f21b35UL, 0xc08969e2UL, 0x4b51ac3UL, 0x8a523803UL, 0x8d034f7eUL, 0x7cf27b18UL,  0x0UL }},
    {{0x227873d1UL, 0x9e04b79dUL, 0x3ce98229UL, 0xba7dade6UL, 0x9f7430dbUL, 0x293d9ac6UL, 0xdb8ed040UL, 0x7775510UL,  0x0UL }},
    {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
    }
},
{
/*That is n + 1 */
   { {0xfc632552UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
   {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   {
   /*That is the generator point G */
   2U,
   {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL  }},
   {{0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL,  0x0UL  }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
   }
},
{
/*That is n + 1 */
   {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   { {0xfc632552UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
   {
   /*That is the generator point G */
   2U,
   {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL  }},
   {{0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL,  0x0UL  }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
   }
},
{
    /*That is n - 1 */
    { {0xfc632550UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
    {
    2U,
    /*That is the generator point - G */
    {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL }},
    {{0xc840ae0aUL, 0x3449bf97UL, 0x94cea131UL, 0xd431cca9UL, 0x83f061e9UL, 0x711814b5UL, 0x1e58065UL, 0xb01cbd1cUL,  0x0UL}},
    {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
    }
},
{
    /*That is n - 1 */
    {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
    { {0xfc632550UL, 0xf3b9cac2UL, 0xa7179e84UL, 0xbce6faadUL, 0xffffffffUL, 0xffffffffUL, 0x00000000UL, 0xffffffffUL, 0x00000000UL} },
    {
    2U,
    /*That is the generator point - G */
    {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL }},
    {{0xc840ae0aUL, 0x3449bf97UL, 0x94cea131UL, 0xd431cca9UL, 0x83f061e9UL, 0x711814b5UL, 0x1e58065UL, 0xb01cbd1cUL,  0x0UL}},
    {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
    }
},
{
/*That is  1 */
   {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   {
   /*That is the generator point G */
   2U,
   {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL  }},
   {{0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL,  0x0UL  }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
   }
},
{
/*That is  1 */
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   {{0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }},
   {
   /*That is the generator point G */
   2U,
   {{0xd898c296UL, 0xf4a13945UL, 0x2deb33a0UL, 0x77037d81UL, 0x63a440f2UL, 0xf8bce6e5UL, 0xe12c4247UL, 0x6b17d1f2UL,  0x0UL  }},
   {{0x37bf51f5UL, 0xcbb64068UL, 0x6b315eceUL, 0x2bce3357UL, 0x7c0f9e16UL, 0x8ee7eb4aUL, 0xfe1a7f9bUL, 0x4fe342e2UL,  0x0UL  }},
   {{0x1U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U, 0x0U }}
   }
}
};
#endif /* (EscEcc_SECP_256_ENABLED == 1 && EscFeArith_ENABLE_SHAMIRS_TRICK == 1) */
#endif /*EscEcc_ECDSA_ENABLED */

/*******************************************************************
 * ECC Compliancetest-vectors                                      *
 *******************************************************************
 * Byte-Order: Big endian
 *******************************************************************/

#if (EscEcc_SECP_192_ENABLED == 1)

static const Esc_UINT8 EscEcc_secp192_test_secretKey[] =
{
    0x31U, 0x28U, 0xd2U, 0xb4U, 0xb1U, 0xc9U, 0x6bU, 0xcaU,
    0xb2U, 0x1dU, 0x94U, 0x13U, 0xabU, 0x34U, 0x02U, 0x14U,
    0x8eU, 0xdaU, 0x65U, 0x37U, 0x4aU, 0x83U, 0x37U, 0xd7U
};
static const Esc_UINT8 EscEcc_secp192_test_pubkey_x[] =
{
    0x3eU, 0x31U, 0x7fU, 0xceU, 0x05U, 0xa7U, 0x44U, 0x1bU,
    0x05U, 0xf1U, 0xf4U, 0x82U, 0xd8U, 0xd9U, 0x0bU, 0x75U,
    0xadU, 0x6aU, 0x83U, 0x27U, 0xe4U, 0x6dU, 0x11U, 0xeeU
};
static const Esc_UINT8 EscEcc_secp192_test_pubkey_y[] =
{
    0x6bU, 0x75U, 0x40U, 0xc4U, 0x0fU, 0xb2U, 0x89U, 0x19U,
    0xdfU, 0xcbU, 0xdcU, 0xe7U, 0xaeU, 0x06U, 0x75U, 0xeeU,
    0x33U, 0x83U, 0x34U, 0x9bU, 0x92U, 0x24U, 0xf1U, 0xfbU
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_secp192_test_hash[] =
{
    0x42U, 0xc0U, 0x1dU, 0x71U, 0x0cU, 0x1eU, 0x4eU, 0x29U,
    0x22U, 0x69U, 0x21U, 0x5bU, 0x05U, 0x91U, 0xeaU, 0x60U,
    0xcfU, 0x05U, 0x07U, 0xfdU, 0x79U, 0x29U, 0x6cU, 0x19U
};
static const Esc_UINT8 EscEcc_secp192_test_random[] =
{
    0xd6U, 0xa9U, 0x58U, 0x06U, 0x73U, 0x4eU, 0xedU, 0xe4U,
    0x61U, 0x59U, 0x25U, 0x48U, 0x80U, 0x75U, 0xcbU, 0xc6U,
    0xb4U, 0xbeU, 0x24U, 0x74U, 0x10U, 0x27U, 0x47U, 0xbcU
};
static const Esc_UINT8 EscEcc_secp192_test_ecdsa_sig_r[] =
{
    0xc6U, 0x0dU, 0xbdU, 0x29U, 0x5cU, 0x5eU, 0x40U, 0x1cU,
    0xa9U, 0x1eU, 0x51U, 0x46U, 0xc7U, 0x16U, 0x36U, 0x29U,
    0x5aU, 0x5bU, 0x34U, 0x44U, 0x60U, 0xbcU, 0x64U, 0xbbU
};
static const Esc_UINT8 EscEcc_secp192_test_ecdsa_sig_s[] =
{
    0x6fU, 0x67U, 0xc0U, 0xdcU, 0xc7U, 0x0dU, 0x62U, 0xabU,
    0x0fU, 0x3eU, 0xd7U, 0xd0U, 0x4eU, 0x03U, 0x1aU, 0xf6U,
    0x36U, 0x5cU, 0x23U, 0xafU, 0x85U, 0xd3U, 0x25U, 0x14U
};
#   endif
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
static const Esc_UINT8 EscEcc_secp224_test_secretKey[] =
{
    0x61U, 0xc8U, 0x76U, 0xa9U, 0xf9U, 0xd9U, 0x17U, 0xf0U,
    0x53U, 0x17U, 0xcdU, 0xf8U, 0x37U, 0xa3U, 0x61U, 0xfdU,
    0xbdU, 0x64U, 0x82U, 0x2eU, 0x5aU, 0x19U, 0xf5U, 0x65U,
    0x08U, 0x03U, 0xdbU, 0xe5U
};
static const Esc_UINT8 EscEcc_secp224_test_pubkey_x[] =
{
    0x25U, 0xeaU, 0x43U, 0x4bU, 0xa4U, 0x11U, 0x5bU, 0xcaU,
    0x5fU, 0x8fU, 0xc5U, 0x88U, 0x23U, 0xc0U, 0xa0U, 0xe6U,
    0x7dU, 0x9cU, 0xdcU, 0xd4U, 0xa4U, 0xeaU, 0x9cU, 0xedU,
    0x1cU, 0x9eU, 0xc0U, 0xacU
};
static const Esc_UINT8 EscEcc_secp224_test_pubkey_y[] =
{
    0xe6U, 0xb0U, 0xa9U, 0xcfU, 0x48U, 0x3cU, 0xfbU, 0xacU,
    0xe3U, 0xedU, 0x35U, 0xf9U, 0x3eU, 0x66U, 0x4aU, 0x02U,
    0xb2U, 0x38U, 0x8dU, 0xc4U, 0x56U, 0x95U, 0x75U, 0xf7U,
    0xdfU, 0xdaU, 0x25U, 0x8bU
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_secp224_test_hash[] =
{
    0x26U, 0x0aU, 0x3eU, 0xf9U, 0x4cU, 0xc4U, 0x32U, 0x51U,
    0x32U, 0x8aU, 0x7dU, 0xc1U, 0x74U, 0x93U, 0x90U, 0x57U,
    0xbaU, 0x34U, 0xfcU, 0xb7U
};
static const Esc_UINT8 EscEcc_secp224_test_random[] =
{
    0x92U, 0x78U, 0xa3U, 0xcbU, 0xfdU, 0x32U, 0xa7U, 0xe8U,
    0x01U, 0xa7U, 0x0eU, 0xcfU, 0xebU, 0x57U, 0xcdU, 0xc5U,
    0x6cU, 0x7fU, 0xe5U, 0x64U, 0xa2U, 0x1dU, 0x8cU, 0x6cU,
    0xebU, 0xcdU, 0xa1U, 0x61U
};
static const Esc_UINT8 EscEcc_secp224_test_ecdsa_sig_r[] =
{
    0x64U, 0x9cU, 0x8cU, 0x0aU, 0x33U, 0x11U, 0xe6U, 0x17U,
    0x5bU, 0xf0U, 0xf8U, 0x27U, 0xcbU, 0xc5U, 0x80U, 0x82U,
    0x3fU, 0xc1U, 0x4dU, 0x67U, 0xf4U, 0xa8U, 0x0aU, 0xf0U,
    0x60U, 0xf1U, 0x76U, 0x4eU
};
static const Esc_UINT8 EscEcc_secp224_test_ecdsa_sig_s[] =
{
    0x76U, 0xf3U, 0x06U, 0xa0U, 0x14U, 0x02U, 0xc4U, 0xfbU,
    0xe2U, 0x43U, 0x39U, 0x88U, 0xa8U, 0x0fU, 0x51U, 0x6dU,
    0x5dU, 0xc0U, 0xe7U, 0x8dU, 0xfaU, 0x99U, 0x6eU, 0x69U,
    0xe1U, 0x5cU, 0x82U, 0x88U
};
#   endif
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
static const Esc_UINT8 EscEcc_secp256_test_secretKey[] =
{
    0x55U, 0xd5U, 0x26U, 0x25U, 0x41U, 0x3cU, 0x0cU, 0x1aU,
    0xb1U, 0xb9U, 0x0aU, 0x7aU, 0x4aU, 0x38U, 0xa2U, 0x44U,
    0x06U, 0xf2U, 0xe1U, 0xf1U, 0x77U, 0x22U, 0xaaU, 0x7cU,
    0x1cU, 0xb7U, 0xb7U, 0x74U, 0xf6U, 0x63U, 0xcdU, 0xcaU
};
static const Esc_UINT8 EscEcc_secp256_test_pubkey_x[] =
{
    0xddU, 0xfcU, 0x2aU, 0x0eU, 0xbfU, 0x52U, 0x8dU, 0x61U,
    0x89U, 0xb0U, 0x89U, 0x89U, 0xb5U, 0xe7U, 0x6eU, 0x8aU,
    0x31U, 0x02U, 0xf6U, 0x01U, 0x41U, 0x1dU, 0xa9U, 0xa4U,
    0xbcU, 0xf3U, 0xdbU, 0x30U, 0x37U, 0x03U, 0xb6U, 0x3bU
};
static const Esc_UINT8 EscEcc_secp256_test_pubkey_y[] =
{
    0x17U, 0x50U, 0x56U, 0xa3U, 0xd1U, 0x95U, 0xacU, 0x74U,
    0xfcU, 0x85U, 0x70U, 0x0fU, 0xf1U, 0xc5U, 0x36U, 0x18U,
    0x35U, 0xbbU, 0x31U, 0xd1U, 0x60U, 0xfdU, 0x1fU, 0x74U,
    0xa8U, 0x5bU, 0x12U, 0x15U, 0x8dU, 0xb4U, 0xfcU, 0xc5U
};
#   if EscEcc_ECDSA_ENABLED == 1

static const Esc_UINT8 EscEcc_secp256_test_hash[] =
{
    0x26U, 0x0aU, 0x3eU, 0xf9U, 0x4cU, 0xc4U, 0x32U, 0x51U,
    0x32U, 0x8aU, 0x7dU, 0xc1U, 0x74U, 0x93U, 0x90U, 0x57U,
    0xbaU, 0x34U, 0xfcU, 0xb7U
};
static const Esc_UINT8 EscEcc_secp256_test_random[] =
{
    0x24U, 0xdfU, 0x6aU, 0x46U, 0xadU, 0x26U, 0x76U, 0x3aU,
    0x3aU, 0xd0U, 0xa6U, 0xd0U, 0x09U, 0x9eU, 0xdbU, 0xdeU,
    0xb8U, 0xa6U, 0xa1U, 0xccU, 0x0cU, 0xc3U, 0xbdU, 0x6dU,
    0xd7U, 0x88U, 0x6eU, 0xffU, 0x25U, 0x7dU, 0x96U, 0xa6U
};
static const Esc_UINT8 EscEcc_secp256_test_ecdsa_sig_r[] =
{
    0x10U, 0x04U, 0x84U, 0xf4U, 0x1dU, 0x00U, 0x8dU, 0x57U,
    0x18U, 0xeeU, 0x50U, 0x24U, 0x2fU, 0x57U, 0x3dU, 0xe2U,
    0xaaU, 0x0dU, 0x4dU, 0x97U, 0x87U, 0xecU, 0x8dU, 0x47U,
    0x5dU, 0xdeU, 0xa2U, 0x84U, 0xcbU, 0xeeU, 0xa9U, 0x79U
};
static const Esc_UINT8 EscEcc_secp256_test_ecdsa_sig_s[] =
{
    0x93U, 0x25U, 0xb7U, 0xd7U, 0xf7U, 0x7bU, 0x86U, 0x04U,
    0x2cU, 0xc2U, 0xb6U, 0x22U, 0x72U, 0x2dU, 0xf9U, 0xbaU,
    0xbaU, 0xc4U, 0x98U, 0xd6U, 0x26U, 0x80U, 0xc0U, 0xfdU,
    0x5cU, 0xf8U, 0xb0U, 0x67U, 0xb8U, 0x63U, 0xe0U, 0x2aU
};
#   endif
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
static const Esc_UINT8 EscEcc_secp384_test_secretKey[] =
{
    0x6fU, 0x77U, 0x10U, 0x76U, 0x58U, 0x5dU, 0xe3U, 0x67U,
    0xf9U, 0x18U, 0xa6U, 0x80U, 0x0bU, 0xbbU, 0xa1U, 0x2eU,
    0x51U, 0x42U, 0x9cU, 0x8eU, 0xa1U, 0x8eU, 0x19U, 0x75U,
    0x14U, 0x6aU, 0xe2U, 0x09U, 0xb5U, 0x23U, 0x62U, 0x44U,
    0xb3U, 0x25U, 0xa7U, 0x3aU, 0x21U, 0xceU, 0x27U, 0x9aU,
    0x39U, 0x67U, 0xbeU, 0x32U, 0x17U, 0xdcU, 0x27U, 0x63U
};
static const Esc_UINT8 EscEcc_secp384_test_pubkey_x[] =
{
    0xdeU, 0xb3U, 0xd7U, 0x2dU, 0xe4U, 0xf6U, 0x94U, 0x85U,
    0xa0U, 0xd6U, 0x07U, 0x97U, 0x82U, 0x3aU, 0xfcU, 0x51U,
    0x06U, 0xb8U, 0xacU, 0xbfU, 0x5fU, 0x4eU, 0x75U, 0x2cU,
    0x86U, 0x7bU, 0xb3U, 0x67U, 0x17U, 0x27U, 0x4eU, 0xe5U,
    0x6bU, 0xa5U, 0x65U, 0x72U, 0xf4U, 0xeeU, 0xecU, 0x3cU,
    0x10U, 0x5aU, 0x40U, 0xcbU, 0x9cU, 0x30U, 0xd7U, 0x17U
};
static const Esc_UINT8 EscEcc_secp384_test_pubkey_y[] =
{
    0x30U, 0xa8U, 0x8aU, 0xbeU, 0x60U, 0x98U, 0x26U, 0x63U,
    0xccU, 0xaaU, 0xfdU, 0xa1U, 0x3bU, 0x82U, 0x27U, 0xcbU,
    0x9bU, 0xa4U, 0x5dU, 0x87U, 0x9cU, 0x79U, 0xbbU, 0xf8U,
    0x6aU, 0xf3U, 0x43U, 0xe8U, 0xefU, 0x01U, 0x5cU, 0xe3U,
    0xb1U, 0x77U, 0x9aU, 0x6bU, 0x80U, 0xf3U, 0x0eU, 0x0cU,
    0x87U, 0xefU, 0xbdU, 0xd2U, 0x2aU, 0x8bU, 0xd5U, 0x75U
};

#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_secp384_test_hash[] =
{
    0x00U, 0xd8U, 0xd0U, 0x9cU, 0x6cU, 0xc2U, 0x50U, 0x78U,
    0x71U, 0x25U, 0x3eU, 0xbaU, 0x6aU, 0x81U, 0x06U, 0x47U,
    0x30U, 0x78U, 0x76U, 0x3eU, 0x99U, 0xa9U, 0xb7U, 0xfcU,
    0x34U, 0xbaU, 0x57U, 0x90U, 0x93U, 0x60U, 0x78U, 0xc7U,
    0xccU, 0x25U, 0x07U, 0x74U, 0xc1U, 0x7dU, 0x83U, 0x25U,
    0x12U, 0x4cU, 0x9eU, 0xa6U, 0x00U, 0x00U, 0x00U, 0x00U
};
static const Esc_UINT8 EscEcc_secp384_test_random[] =
{
    0x26U, 0x96U, 0x7dU, 0x25U, 0xffU, 0x6eU, 0x88U, 0xd7U,
    0x6dU, 0xbdU, 0xc3U, 0x0cU, 0xccU, 0xa1U, 0xa6U, 0xb8U,
    0xdeU, 0xdbU, 0x9eU, 0x09U, 0xd0U, 0xa6U, 0xd0U, 0x3aU,
    0x3aU, 0x76U, 0x26U, 0xadU, 0x46U, 0x6aU, 0xdfU, 0x24U,
    0x0cU, 0xccU, 0xa1U, 0xa6U, 0x7dU, 0xa3U, 0xa7U, 0x6dU,
    0xbdU, 0x6aU, 0xdfU, 0x24U, 0x0cU, 0xccU, 0xa6U, 0x9eU
};
static const Esc_UINT8 EscEcc_secp384_test_ecdsa_sig_r[] =
{
    0x77U, 0x67U, 0xcbU, 0x9fU, 0x16U, 0xe1U, 0xa3U, 0x0eU,
    0x48U, 0x16U, 0x31U, 0x96U, 0x9bU, 0x43U, 0xf2U, 0x3fU,
    0xfcU, 0x1dU, 0x39U, 0xc9U, 0x8aU, 0x3fU, 0x40U, 0x6dU,
    0xf3U, 0x3aU, 0x7eU, 0xf4U, 0x57U, 0x57U, 0xe8U, 0xc9U,
    0x57U, 0xccU, 0xd8U, 0x3dU, 0x1aU, 0xa3U, 0x07U, 0xc7U,
    0xf1U, 0xd2U, 0x5aU, 0xffU, 0xdcU, 0xc0U, 0x05U, 0x51U
};
static const Esc_UINT8 EscEcc_secp384_test_ecdsa_sig_s[] =
{
    0x4bU, 0x9aU, 0x21U, 0x41U, 0x95U, 0x55U, 0xb0U, 0xd3U,
    0x9dU, 0x1aU, 0xbeU, 0xf6U, 0xf8U, 0x80U, 0x62U, 0x05U,
    0xd7U, 0x04U, 0xbcU, 0xb4U, 0x65U, 0x30U, 0x28U, 0xbfU,
    0xf4U, 0xe0U, 0xe0U, 0x94U, 0xa4U, 0xbdU, 0xdfU, 0xf6U,
    0x83U, 0xc0U, 0x11U, 0xabU, 0x52U, 0x6eU, 0x00U, 0xa4U,
    0x07U, 0x1eU, 0xe5U, 0x09U, 0xabU, 0x28U, 0x75U, 0xa2U
};
#   endif
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
/* NIST CAVP test vector from 186-3ecdsatestvectors/SigGen.txt */
static const Esc_UINT8 EscEcc_secp521_test_secretKey[] =
{
    0x00U, 0xf7U, 0x49U, 0xd3U, 0x27U, 0x04U, 0xbcU, 0x53U,
    0x3cU, 0xa8U, 0x2cU, 0xefU, 0x0aU, 0xcfU, 0x10U, 0x3dU,
    0x8fU, 0x4fU, 0xbaU, 0x67U, 0xf0U, 0x8dU, 0x26U, 0x78U,
    0xe5U, 0x15U, 0xedU, 0x7dU, 0xb8U, 0x86U, 0x26U, 0x7fU,
    0xfaU, 0xf0U, 0x2fU, 0xabU, 0x00U, 0x80U, 0xdcU, 0xa2U,
    0x35U, 0x9bU, 0x72U, 0xf5U, 0x74U, 0xccU, 0xc2U, 0x9aU,
    0x0fU, 0x21U, 0x8cU, 0x86U, 0x55U, 0xc0U, 0xccU, 0xcfU,
    0x9fU, 0xeeU, 0x6cU, 0x5eU, 0x56U, 0x7aU, 0xa1U, 0x4cU,
    0xb9U, 0x26U
};
static const Esc_UINT8 EscEcc_secp521_test_pubkey_x[] =
{
    0x00U, 0x61U, 0x38U, 0x7fU, 0xd6U, 0xb9U, 0x59U, 0x14U,
    0xe8U, 0x85U, 0xf9U, 0x12U, 0xedU, 0xfbU, 0xb5U, 0xfbU,
    0x27U, 0x46U, 0x55U, 0x02U, 0x7fU, 0x21U, 0x6cU, 0x40U,
    0x91U, 0xcaU, 0x83U, 0xe1U, 0x93U, 0x36U, 0x74U, 0x0fU,
    0xd8U, 0x1aU, 0xedU, 0xfeU, 0x04U, 0x7fU, 0x51U, 0xb4U,
    0x2bU, 0xdfU, 0x68U, 0x16U, 0x11U, 0x21U, 0x01U, 0x3eU,
    0x0dU, 0x55U, 0xb1U, 0x17U, 0xa1U, 0x4eU, 0x43U, 0x03U,
    0xf9U, 0x26U, 0xc8U, 0xdeU, 0xbbU, 0x77U, 0xa7U, 0xfdU,
    0xaaU, 0xd1U
};
static const Esc_UINT8 EscEcc_secp521_test_pubkey_y[] =
{
    0x00U, 0xe7U, 0xd0U, 0xc7U, 0x5cU, 0x38U, 0x62U, 0x6eU,
    0x89U, 0x5cU, 0xa2U, 0x15U, 0x26U, 0xb9U, 0xf9U, 0xfdU,
    0xf8U, 0x4dU, 0xceU, 0xcbU, 0x93U, 0xf2U, 0xb2U, 0x33U,
    0x39U, 0x05U, 0x50U, 0xd2U, 0xb1U, 0x46U, 0x3bU, 0x7eU,
    0xe3U, 0xf5U, 0x8dU, 0xf7U, 0x34U, 0x64U, 0x35U, 0xffU,
    0x04U, 0x34U, 0x19U, 0x95U, 0x83U, 0xc9U, 0x7cU, 0x66U,
    0x5aU, 0x97U, 0xf1U, 0x2fU, 0x70U, 0x6fU, 0x23U, 0x57U,
    0xdaU, 0x4bU, 0x40U, 0x28U, 0x8dU, 0xefU, 0x88U, 0x8eU,
    0x59U, 0xe6U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_secp521_test_hash[] =
{
    0x65U, 0xf8U, 0x34U, 0x08U, 0x09U, 0x22U, 0x61U, 0xbdU,
    0xa5U, 0x99U, 0x38U, 0x9dU, 0xf0U, 0x33U, 0x82U, 0xc5U,
    0xbeU, 0x01U, 0xa8U, 0x1fU, 0xe0U, 0x0aU, 0x36U, 0xf3U,
    0xf4U, 0xbbU, 0x65U, 0x41U, 0x26U, 0x3fU, 0x80U, 0x16U,
    0x27U, 0xc4U, 0x40U, 0xe5U, 0x08U, 0x09U, 0x71U, 0x2bU,
    0x0cU, 0xacU, 0xe7U, 0xc2U, 0x17U, 0xe6U, 0xe5U, 0x05U,
    0x1aU, 0xf8U, 0x1dU, 0xe9U, 0xbfU, 0xecU, 0x32U, 0x04U,
    0xdcU, 0xd6U, 0x3cU, 0x4fU, 0x9aU, 0x74U, 0x10U, 0x47U
};
static const Esc_UINT8 EscEcc_secp521_test_random[] =
{
    0x00U, 0x3aU, 0xf5U, 0xabU, 0x6cU, 0xaaU, 0x29U, 0xa6U,
    0xdeU, 0x86U, 0xa5U, 0xbaU, 0xb9U, 0xaaU, 0x83U, 0xc3U,
    0xb1U, 0x6aU, 0x17U, 0xffU, 0xcdU, 0x52U, 0xb5U, 0xc6U,
    0x0cU, 0x76U, 0x9bU, 0xe3U, 0x05U, 0x3cU, 0xddU, 0xdeU,
    0xacU, 0x60U, 0x81U, 0x2dU, 0x12U, 0xfeU, 0xcfU, 0x46U,
    0xcfU, 0xe1U, 0xf3U, 0xdbU, 0x9aU, 0xc9U, 0xdcU, 0xf8U,
    0x81U, 0xfcU, 0xecU, 0x3fU, 0x0aU, 0xa7U, 0x33U, 0xd4U,
    0xecU, 0xbbU, 0x83U, 0xc7U, 0x59U, 0x3eU, 0x86U, 0x4cU,
    0x6dU, 0xf1U
};
static const Esc_UINT8 EscEcc_secp521_test_ecdsa_sig_r[] =
{
    0x00U, 0x4dU, 0xe8U, 0x26U, 0xeaU, 0x70U, 0x4aU, 0xd1U,
    0x0bU, 0xc0U, 0xf7U, 0x53U, 0x8aU, 0xf8U, 0xa3U, 0x84U,
    0x3fU, 0x28U, 0x4fU, 0x55U, 0xc8U, 0xb9U, 0x46U, 0xafU,
    0x92U, 0x35U, 0xafU, 0x5aU, 0xf7U, 0x4fU, 0x2bU, 0x76U,
    0xe0U, 0x99U, 0xe4U, 0xbcU, 0x72U, 0xfdU, 0x79U, 0xd2U,
    0x8aU, 0x38U, 0x0fU, 0x8dU, 0x4bU, 0x4cU, 0x91U, 0x9aU,
    0xc2U, 0x90U, 0xd2U, 0x48U, 0xc3U, 0x79U, 0x83U, 0xbaU,
    0x05U, 0xaeU, 0xa4U, 0x2eU, 0x2dU, 0xd7U, 0x9fU, 0xddU,
    0x33U, 0xe8U
};
static const Esc_UINT8 EscEcc_secp521_test_ecdsa_sig_s[] =
{
    0x00U, 0x87U, 0x48U, 0x8cU, 0x85U, 0x9aU, 0x96U, 0xfeU,
    0xa2U, 0x66U, 0xeaU, 0x13U, 0xbfU, 0x6dU, 0x11U, 0x4cU,
    0x42U, 0x9bU, 0x16U, 0x3bU, 0xe9U, 0x7aU, 0x57U, 0x55U,
    0x90U, 0x86U, 0xedU, 0xb6U, 0x4aU, 0xedU, 0x4aU, 0x18U,
    0x59U, 0x4bU, 0x46U, 0xfbU, 0x9eU, 0xfcU, 0x7fU, 0xd2U,
    0x5dU, 0x8bU, 0x2dU, 0xe8U, 0xf0U, 0x9cU, 0xa0U, 0x58U,
    0x7fU, 0x54U, 0xbdU, 0x28U, 0x72U, 0x99U, 0xf4U, 0x7bU,
    0x2fU, 0xf1U, 0x24U, 0xaaU, 0xc5U, 0x66U, 0xe8U, 0xeeU,
    0x3bU, 0x43U
};
#   endif
#endif

/* Input values are randomly generated with Java, output values
 * are generated with BouncyCastle 1.46 */
#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP160_test_secretKey[] =
{
    0x17U, 0x0cU, 0x66U, 0x78U, 0xe1U, 0x61U, 0xd7U, 0xa9U,
    0x43U, 0x92U, 0xb3U, 0x58U, 0x3bU, 0x27U, 0xbdU, 0xb3U,
    0x02U, 0x78U, 0xaeU, 0x3dU
};
static const Esc_UINT8 EscEcc_BP160_test_pubkey_x[] =
{
    0xa5U, 0xdbU, 0xe5U, 0x84U, 0x8aU, 0xa9U, 0xd5U, 0xa6U,
    0xcaU, 0xf9U, 0x36U, 0x4eU, 0x9fU, 0x90U, 0xa1U, 0x6dU,
    0x43U, 0xa8U, 0x50U, 0x46U
};
static const Esc_UINT8 EscEcc_BP160_test_pubkey_y[] =
{
    0xe5U, 0x04U, 0x84U, 0x05U, 0x78U, 0xeaU, 0xc2U, 0xdeU,
    0xdcU, 0x8aU, 0xbcU, 0x3fU, 0x3eU, 0xc1U, 0xbaU, 0xdcU,
    0x12U, 0x38U, 0x33U, 0x84U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP160_test_hash[] =
{
    0xd0U, 0xa3U, 0x74U, 0x2cU, 0x90U, 0x8cU, 0xc0U, 0x94U,
    0xafU, 0x0cU, 0xd5U, 0xebU, 0xf7U, 0x86U, 0xacU, 0x94U,
    0x55U, 0x1cU, 0xe2U, 0x47U
};
static const Esc_UINT8 EscEcc_BP160_test_random[] =
{
    0x62U, 0xcfU, 0x8aU, 0x57U, 0xa5U, 0x6bU, 0x6dU, 0x36U,
    0x6cU, 0x36U, 0x86U, 0x0bU, 0x69U, 0x47U, 0xfaU, 0x7fU,
    0x1cU, 0x43U, 0x98U, 0x02U
};
static const Esc_UINT8 EscEcc_BP160_test_ecdsa_sig_r[] =
{
    0x5eU, 0x2bU, 0x56U, 0x97U, 0x22U, 0x41U, 0xa9U, 0xd7U,
    0x5bU, 0xafU, 0x6fU, 0xcaU, 0x89U, 0x98U, 0x30U, 0x53U,
    0xd9U, 0x8aU, 0x2fU, 0xe0U
};
static const Esc_UINT8 EscEcc_BP160_test_ecdsa_sig_s[] =
{
    0x47U, 0xc5U, 0x23U, 0x51U, 0xbdU, 0x0eU, 0xeaU, 0xa1U,
    0x56U, 0xecU, 0xe1U, 0x62U, 0xb3U, 0x78U, 0x31U, 0xe2U,
    0x82U, 0x29U, 0xccU, 0xa7U
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP192_test_secretKey[] =
{
    0x99U, 0x56U, 0xadU, 0x7dU, 0xdaU, 0xeaU, 0xf9U, 0xf3U,
    0xb2U, 0xfaU, 0x7aU, 0x61U, 0x8dU, 0x6eU, 0xc6U, 0xc4U,
    0x9aU, 0xa6U, 0xbcU, 0xe1U, 0x59U, 0xa7U, 0xf6U, 0x78U
};
static const Esc_UINT8 EscEcc_BP192_test_pubkey_x[] =
{
    0x4bU, 0x5bU, 0x10U, 0xdcU, 0x0dU, 0xb5U, 0xbdU, 0xc7U,
    0x37U, 0x0dU, 0x2eU, 0xd3U, 0xf5U, 0x63U, 0x08U, 0x08U,
    0xdbU, 0x83U, 0x90U, 0x72U, 0xd2U, 0x01U, 0x42U, 0x4dU
};
static const Esc_UINT8 EscEcc_BP192_test_pubkey_y[] =
{
    0x1cU, 0x89U, 0xf5U, 0x9aU, 0x05U, 0xd0U, 0x1dU, 0x34U,
    0x48U, 0x08U, 0x25U, 0x1aU, 0x30U, 0x77U, 0x01U, 0x36U,
    0xf2U, 0x3cU, 0xf8U, 0x7dU, 0xe0U, 0xf4U, 0x89U, 0xb6U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP192_test_hash[] =
{
    0x35U, 0x9fU, 0x6fU, 0x86U, 0x72U, 0x51U, 0x96U, 0x09U,
    0x58U, 0x08U, 0x7aU, 0x70U, 0xc5U, 0x13U, 0xb4U, 0xa7U,
    0xb4U, 0x98U, 0x16U, 0x17U, 0x8dU, 0xc5U, 0x1fU, 0xb4U
};
static const Esc_UINT8 EscEcc_BP192_test_random[] =
{
    0x89U, 0xa4U, 0x15U, 0xdbU, 0x82U, 0xdaU, 0xf7U, 0x68U,
    0xa0U, 0xb0U, 0x8cU, 0xbcU, 0xcbU, 0xedU, 0x34U, 0x7eU,
    0x01U, 0x49U, 0x80U, 0x05U, 0xddU, 0x0bU, 0xb0U, 0xa1U
};
static const Esc_UINT8 EscEcc_BP192_test_ecdsa_sig_r[] =
{
    0x2dU, 0x0aU, 0x53U, 0x25U, 0x0bU, 0x27U, 0x21U, 0xacU,
    0x58U, 0xfaU, 0xd9U, 0x60U, 0xf3U, 0x75U, 0xf6U, 0xd6U,
    0x56U, 0x87U, 0x6eU, 0xc8U, 0x5cU, 0xbcU, 0x05U, 0x58U
};
static const Esc_UINT8 EscEcc_BP192_test_ecdsa_sig_s[] =
{
    0x9eU, 0x88U, 0x63U, 0xf6U, 0x10U, 0xcdU, 0xf7U, 0x9aU,
    0xc6U, 0x2bU, 0xc3U, 0x79U, 0x3fU, 0x42U, 0x06U, 0xd3U,
    0x29U, 0x99U, 0xa8U, 0xccU, 0xc5U, 0x40U, 0x79U, 0xd7U
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP224_test_secretKey[] =
{
    0x59U, 0xacU, 0x5eU, 0xfaU, 0xc2U, 0xa4U, 0x74U, 0x5bU,
    0x46U, 0xdeU, 0xc7U, 0xe1U, 0x90U, 0x4eU, 0xb2U, 0x08U,
    0xa3U, 0x4fU, 0x08U, 0x81U, 0x53U, 0xa4U, 0x40U, 0x6dU,
    0x7eU, 0x56U, 0xe1U, 0x42U
};
static const Esc_UINT8 EscEcc_BP224_test_pubkey_x[] =
{
    0x32U, 0xbbU, 0x8bU, 0x18U, 0xa8U, 0x57U, 0x99U, 0xd8U,
    0x33U, 0xe3U, 0x89U, 0xdcU, 0x5eU, 0x3fU, 0x3fU, 0xddU,
    0xecU, 0xe8U, 0x81U, 0xc2U, 0x20U, 0x22U, 0x8fU, 0xc5U,
    0xebU, 0x1dU, 0xa6U, 0x4dU
};
static const Esc_UINT8 EscEcc_BP224_test_pubkey_y[] =
{
    0x17U, 0x3bU, 0x66U, 0x13U, 0xb0U, 0xf8U, 0x16U, 0x47U,
    0x41U, 0x1bU, 0x4aU, 0xb4U, 0xcfU, 0xc5U, 0xdcU, 0x59U,
    0x1bU, 0xf8U, 0xe8U, 0xbaU, 0xbdU, 0xddU, 0xb8U, 0xa3U,
    0x05U, 0x17U, 0x07U, 0xe9U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP224_test_hash[] =
{
    0xf7U, 0xfeU, 0xb2U, 0x71U, 0xa1U, 0x1dU, 0xe9U, 0x93U,
    0x1fU, 0xf7U, 0x2fU, 0xdeU, 0x29U, 0xc1U, 0x3fU, 0xd1U,
    0x40U, 0x69U, 0x8eU, 0x51U, 0xb8U, 0xefU, 0xc4U, 0xebU,
    0xd4U, 0xe4U, 0x47U, 0xabU
};
static const Esc_UINT8 EscEcc_BP224_test_random[] =
{
    0xafU, 0x62U, 0x26U, 0x7fU, 0x8cU, 0x92U, 0x33U, 0x5aU,
    0x91U, 0x13U, 0x67U, 0x15U, 0x33U, 0xb7U, 0x4eU, 0x04U,
    0x61U, 0x62U, 0x3bU, 0xd7U, 0x35U, 0x41U, 0xdaU, 0x0eU,
    0xf7U, 0xfeU, 0x6aU, 0xaeU
};
static const Esc_UINT8 EscEcc_BP224_test_ecdsa_sig_r[] =
{
    0x72U, 0x01U, 0xbbU, 0x30U, 0xa2U, 0x8eU, 0xffU, 0x4eU,
    0xedU, 0x08U, 0xd6U, 0xc8U, 0x6dU, 0xf6U, 0xf4U, 0xb3U,
    0x34U, 0x7aU, 0x55U, 0x33U, 0xb7U, 0x07U, 0x88U, 0x11U,
    0x10U, 0x09U, 0x11U, 0x5cU
};
static const Esc_UINT8 EscEcc_BP224_test_ecdsa_sig_s[] =
{
    0x62U, 0xa3U, 0x61U, 0x48U, 0xb3U, 0x68U, 0x38U, 0x7cU,
    0x71U, 0x7cU, 0x08U, 0xc7U, 0x73U, 0x66U, 0x9eU, 0x7aU,
    0xc1U, 0xfbU, 0xb5U, 0x8aU, 0x8aU, 0x3aU, 0x28U, 0xe3U,
    0x81U, 0x10U, 0x9bU, 0xd7U
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP256_test_secretKey[] =
{
    0x47U, 0xabU, 0xf2U, 0x34U, 0x54U, 0xb1U, 0xe5U, 0x14U,
    0x8bU, 0x95U, 0x9dU, 0x89U, 0xe1U, 0x9cU, 0x47U, 0x40U,
    0x07U, 0x88U, 0x3cU, 0x32U, 0x8dU, 0x7aU, 0x12U, 0x6aU,
    0x64U, 0x82U, 0x61U, 0x1aU, 0x5dU, 0xb9U, 0xb0U, 0xb7U
};
static const Esc_UINT8 EscEcc_BP256_test_pubkey_x[] =
{
    0x01U, 0x18U, 0x23U, 0x66U, 0xd5U, 0xf0U, 0x04U, 0x3fU,
    0xbdU, 0xe0U, 0xaeU, 0xbeU, 0xb3U, 0xbeU, 0xe9U, 0xabU,
    0x7bU, 0xb0U, 0xb6U, 0x42U, 0xb4U, 0x76U, 0xbbU, 0x1bU,
    0xa9U, 0xabU, 0x60U, 0x51U, 0x5aU, 0xe1U, 0x69U, 0xdeU
};
static const Esc_UINT8 EscEcc_BP256_test_pubkey_y[] =
{
    0x30U, 0xfbU, 0xfdU, 0xa5U, 0x52U, 0x77U, 0xb6U, 0xf9U,
    0xa0U, 0xe9U, 0xb6U, 0x55U, 0x58U, 0xf0U, 0x02U, 0x28U,
    0x7aU, 0x4fU, 0x95U, 0xb0U, 0xdaU, 0x98U, 0x72U, 0x8eU,
    0x4aU, 0x6aU, 0x72U, 0x35U, 0xcaU, 0xcdU, 0xaeU, 0x51U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP256_test_hash[] =
{
    0xbeU, 0x55U, 0xa1U, 0x15U, 0x5aU, 0xffU, 0x6cU, 0xedU,
    0x3dU, 0x45U, 0x0fU, 0xa1U, 0x6eU, 0x73U, 0xebU, 0x86U,
    0xe4U, 0xdbU, 0x54U, 0xb2U, 0xfbU, 0x97U, 0xf7U, 0x7bU,
    0x26U, 0x68U, 0x4eU, 0xe8U, 0x81U, 0xc2U, 0xc3U, 0xa6U
};
static const Esc_UINT8 EscEcc_BP256_test_random[] =
{
    0x31U, 0x9cU, 0xfaU, 0x09U, 0x1eU, 0x88U, 0x32U, 0xb0U,
    0x17U, 0x99U, 0xa2U, 0x67U, 0x38U, 0x2aU, 0xe5U, 0x62U,
    0x10U, 0x92U, 0xcaU, 0x4bU, 0xb3U, 0xb6U, 0x25U, 0x5fU,
    0x8cU, 0xd0U, 0xeaU, 0x7fU, 0xabU, 0x35U, 0xf3U, 0xe1U
};
static const Esc_UINT8 EscEcc_BP256_test_ecdsa_sig_r[] =
{
    0x3fU, 0x98U, 0x7aU, 0xbcU, 0xebU, 0x39U, 0xe5U, 0xb0U,
    0xc3U, 0xb3U, 0xd1U, 0x4fU, 0x20U, 0xe1U, 0x55U, 0x1aU,
    0xebU, 0x01U, 0xb3U, 0xcaU, 0x14U, 0x70U, 0xd0U, 0x56U,
    0xccU, 0x22U, 0x0aU, 0x0fU, 0xdeU, 0x0cU, 0xccU, 0xf1U
};
static const Esc_UINT8 EscEcc_BP256_test_ecdsa_sig_s[] =
{
    0x11U, 0x3eU, 0x1fU, 0xd0U, 0x11U, 0x5fU, 0x91U, 0xd7U,
    0x72U, 0x2bU, 0xfbU, 0xbaU, 0xf9U, 0x8bU, 0x36U, 0xc1U,
    0x0eU, 0x6eU, 0xb0U, 0xf5U, 0x68U, 0xc0U, 0xaaU, 0x31U,
    0xbfU, 0x3cU, 0x22U, 0xddU, 0x8aU, 0x69U, 0xdaU, 0x03U
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP320_test_secretKey[] =
{
    0x52U, 0xf6U, 0xecU, 0x8fU, 0x76U, 0x9fU, 0xd7U, 0x65U,
    0x8aU, 0x66U, 0xe9U, 0xa7U, 0x6eU, 0x94U, 0x67U, 0x6cU,
    0x31U, 0xd1U, 0xa8U, 0x0cU, 0x73U, 0xc9U, 0x07U, 0x8eU,
    0xa1U, 0xf6U, 0x32U, 0x19U, 0xbaU, 0xc9U, 0x46U, 0x4cU,
    0x19U, 0x39U, 0x4bU, 0xceU, 0xc0U, 0x2fU, 0x66U, 0x98U
};
static const Esc_UINT8 EscEcc_BP320_test_pubkey_x[] =
{
    0x20U, 0xf0U, 0x87U, 0xa6U, 0x7fU, 0x9aU, 0xf4U, 0x33U,
    0xcfU, 0xd0U, 0xa5U, 0x1cU, 0xc8U, 0x93U, 0x98U, 0x8eU,
    0x4dU, 0x05U, 0xafU, 0x3dU, 0x0cU, 0x99U, 0x3bU, 0x9cU,
    0xe1U, 0x89U, 0x40U, 0x2bU, 0xfaU, 0x60U, 0x8bU, 0x4aU,
    0x64U, 0xa9U, 0x4cU, 0xc7U, 0x33U, 0x16U, 0xe8U, 0xfdU
};
static const Esc_UINT8 EscEcc_BP320_test_pubkey_y[] =
{
    0x54U, 0xa7U, 0xa0U, 0x61U, 0x89U, 0xe2U, 0x8aU, 0x5fU,
    0x2dU, 0xbfU, 0x1dU, 0xd6U, 0x98U, 0x5cU, 0x99U, 0xadU,
    0x04U, 0x94U, 0x9cU, 0x6bU, 0x97U, 0x5bU, 0x69U, 0x37U,
    0x88U, 0x4aU, 0xd0U, 0x0fU, 0xaaU, 0x74U, 0x23U, 0xeeU,
    0x47U, 0xfbU, 0x8dU, 0x07U, 0x11U, 0xf9U, 0xe8U, 0xfaU
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP320_test_hash[] =
{
    0xf2U, 0x9aU, 0x0eU, 0xc0U, 0xe0U, 0x0aU, 0xe2U, 0x4dU,
    0xb1U, 0x8cU, 0xc1U, 0x8bU, 0x59U, 0xa8U, 0xccU, 0x8cU,
    0xc1U, 0xa9U, 0x6dU, 0x8fU, 0x45U, 0xc3U, 0x39U, 0xa4U,
    0xebU, 0xd8U, 0x30U, 0x66U, 0xfdU, 0xe8U, 0xc3U, 0x8bU,
    0x1cU, 0xa5U, 0xa7U, 0x04U, 0x55U, 0x82U, 0xbdU, 0x1cU
};
static const Esc_UINT8 EscEcc_BP320_test_random[] =
{
    0x6eU, 0xbfU, 0x2bU, 0x34U, 0x17U, 0x6bU, 0xf4U, 0x49U,
    0x42U, 0x21U, 0x3fU, 0x2dU, 0x05U, 0x37U, 0x08U, 0xfcU,
    0xd6U, 0xceU, 0x97U, 0x60U, 0xa9U, 0x5eU, 0xbfU, 0xceU,
    0xaeU, 0x77U, 0x8eU, 0xbfU, 0xe3U, 0x55U, 0x05U, 0x1fU,
    0x20U, 0xd3U, 0x59U, 0x37U, 0xb1U, 0x30U, 0x52U, 0x4dU
};
static const Esc_UINT8 EscEcc_BP320_test_ecdsa_sig_r[] =
{
    0x93U, 0xceU, 0x3dU, 0xc9U, 0xa4U, 0x11U, 0xe5U, 0xfeU,
    0x36U, 0x90U, 0x8dU, 0xeaU, 0x9dU, 0xeaU, 0x2aU, 0x96U,
    0x77U, 0xbdU, 0x2aU, 0xa4U, 0x0dU, 0x90U, 0x95U, 0x33U,
    0x29U, 0x4dU, 0x30U, 0x40U, 0x73U, 0x4cU, 0x48U, 0xddU,
    0x5cU, 0x74U, 0xcdU, 0x8dU, 0x69U, 0xe3U, 0xf8U, 0xe8U
};
static const Esc_UINT8 EscEcc_BP320_test_ecdsa_sig_s[] =
{
    0x37U, 0x00U, 0xb0U, 0x6aU, 0x16U, 0xfbU, 0x88U, 0x33U,
    0x6fU, 0x8fU, 0xa0U, 0xb4U, 0x23U, 0x8cU, 0xeeU, 0x22U,
    0x5fU, 0xc2U, 0x28U, 0x66U, 0xd6U, 0xcbU, 0x8dU, 0x94U,
    0x4eU, 0xedU, 0x5dU, 0xe5U, 0x31U, 0xb1U, 0xa8U, 0x66U,
    0x0aU, 0x51U, 0x1aU, 0xecU, 0x33U, 0x2dU, 0x8bU, 0x09U
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP384_test_secretKey[] =
{
    0x4aU, 0x32U, 0xbbU, 0xa8U, 0x92U, 0x51U, 0x18U, 0x10U,
    0x3aU, 0xaeU, 0x8aU, 0x45U, 0xacU, 0xc6U, 0x8aU, 0x40U,
    0x1aU, 0x3bU, 0x2cU, 0x40U, 0x42U, 0x56U, 0xd3U, 0x5fU,
    0x6eU, 0x74U, 0xb9U, 0x40U, 0xecU, 0xafU, 0x5bU, 0x6cU,
    0x76U, 0xd4U, 0x9eU, 0x09U, 0x35U, 0x0bU, 0xd9U, 0x6dU,
    0x5fU, 0x46U, 0x9cU, 0xa5U, 0x90U, 0xe9U, 0x2bU, 0x7cU
};
static const Esc_UINT8 EscEcc_BP384_test_pubkey_x[] =
{
    0x17U, 0x5aU, 0x65U, 0xc0U, 0x9cU, 0xfbU, 0x60U, 0xc8U,
    0x91U, 0x48U, 0x2cU, 0xe2U, 0x88U, 0x61U, 0x1cU, 0x68U,
    0x81U, 0x9bU, 0xf5U, 0xa4U, 0x34U, 0x27U, 0x84U, 0xe3U,
    0xf4U, 0xeaU, 0x4bU, 0xe4U, 0xa1U, 0x3bU, 0x44U, 0xa0U,
    0x84U, 0x83U, 0xf8U, 0xe8U, 0x0aU, 0xffU, 0x81U, 0xf5U,
    0xe5U, 0x07U, 0xb3U, 0x70U, 0x6fU, 0x0dU, 0x01U, 0x41U
};
static const Esc_UINT8 EscEcc_BP384_test_pubkey_y[] =
{
    0x75U, 0xb0U, 0x73U, 0x6aU, 0x3fU, 0x9bU, 0x07U, 0x54U,
    0x20U, 0x6cU, 0x44U, 0x86U, 0xf6U, 0xdcU, 0x73U, 0xccU,
    0x4fU, 0xb4U, 0x67U, 0xccU, 0xe4U, 0xdcU, 0x18U, 0x0bU,
    0x17U, 0x27U, 0x2eU, 0xd5U, 0x14U, 0x51U, 0x60U, 0xfbU,
    0x90U, 0x78U, 0x8dU, 0xbaU, 0x37U, 0x44U, 0xe7U, 0x6aU,
    0x66U, 0x52U, 0x33U, 0x70U, 0xb4U, 0x0cU, 0x4fU, 0x15U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP384_test_hash[] =
{
    0xc0U, 0x96U, 0x4cU, 0x25U, 0xb8U, 0x4fU, 0x95U, 0x13U,
    0xf0U, 0x79U, 0x69U, 0x30U, 0xefU, 0x08U, 0x55U, 0x13U,
    0x12U, 0x32U, 0x04U, 0xa0U, 0x65U, 0xbcU, 0xb9U, 0x19U,
    0xf3U, 0x7eU, 0x8fU, 0x54U, 0x26U, 0xb2U, 0xb3U, 0x0cU,
    0x02U, 0xe0U, 0xd7U, 0x8fU, 0x68U, 0xc0U, 0x2bU, 0x86U,
    0x64U, 0x36U, 0x49U, 0x34U, 0xcaU, 0x0dU, 0x0aU, 0x35U
};
static const Esc_UINT8 EscEcc_BP384_test_random[] =
{
    0x22U, 0xd5U, 0x50U, 0xdcU, 0x45U, 0x29U, 0x88U, 0x9eU,
    0xa8U, 0x50U, 0x60U, 0x94U, 0xc1U, 0x0fU, 0x85U, 0x3bU,
    0x5aU, 0x96U, 0x51U, 0x04U, 0xb6U, 0x12U, 0x8eU, 0x38U,
    0x8dU, 0x74U, 0xe7U, 0x61U, 0xd8U, 0x87U, 0x29U, 0x78U,
    0x87U, 0xc6U, 0x98U, 0x00U, 0x58U, 0x9fU, 0x7eU, 0x6bU,
    0x61U, 0xe7U, 0x5bU, 0x70U, 0xb2U, 0x8aU, 0x6eU, 0xd2U
};
static const Esc_UINT8 EscEcc_BP384_test_ecdsa_sig_r[] =
{
    0x52U, 0x2bU, 0x9aU, 0xffU, 0x9dU, 0x6bU, 0x89U, 0x2aU,
    0xb1U, 0x7bU, 0x9cU, 0xeaU, 0xffU, 0xccU, 0xd3U, 0x3cU,
    0x78U, 0x19U, 0x57U, 0x75U, 0x26U, 0xcaU, 0x78U, 0x3fU,
    0x4bU, 0x34U, 0x55U, 0xcaU, 0x83U, 0x99U, 0x16U, 0x0cU,
    0x28U, 0x15U, 0x09U, 0x32U, 0x02U, 0xe5U, 0xa3U, 0xe7U,
    0x97U, 0xb2U, 0xebU, 0x1aU, 0x79U, 0xebU, 0x0dU, 0xb7U
};
static const Esc_UINT8 EscEcc_BP384_test_ecdsa_sig_s[] =
{
    0x4fU, 0x1fU, 0x95U, 0x67U, 0x09U, 0xd0U, 0x81U, 0x05U,
    0x7fU, 0x98U, 0x66U, 0x46U, 0x6eU, 0x75U, 0xdfU, 0x73U,
    0x91U, 0xd0U, 0xd1U, 0xdaU, 0xcaU, 0x37U, 0x57U, 0xa2U,
    0x1fU, 0x09U, 0xf1U, 0xb3U, 0xf2U, 0x99U, 0x5bU, 0xbdU,
    0xefU, 0xfdU, 0xceU, 0x69U, 0x46U, 0xc3U, 0x44U, 0xb9U,
    0xb4U, 0xb7U, 0xb1U, 0x4cU, 0xfeU, 0xe1U, 0x6fU, 0x1eU
};
#   endif
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
static const Esc_UINT8 EscEcc_BP512_test_secretKey[] =
{
    0x61U, 0xbbU, 0xecU, 0x6fU, 0x25U, 0xccU, 0x5bU, 0x6dU,
    0xd0U, 0x58U, 0x85U, 0xe6U, 0xd3U, 0xe9U, 0x4bU, 0x2aU,
    0x85U, 0x3cU, 0x49U, 0xb2U, 0x13U, 0xcfU, 0xd5U, 0x7aU,
    0x47U, 0x52U, 0xd1U, 0xb6U, 0x76U, 0xdaU, 0x92U, 0xecU,
    0x43U, 0x41U, 0x94U, 0xbaU, 0x45U, 0xf1U, 0xadU, 0xd1U,
    0x58U, 0xd8U, 0x31U, 0xb4U, 0x19U, 0x69U, 0x57U, 0x11U,
    0x46U, 0x52U, 0xfcU, 0xcdU, 0xbdU, 0xe5U, 0x76U, 0x02U,
    0x43U, 0xaeU, 0xaaU, 0xafU, 0x73U, 0xceU, 0x6fU, 0x53U
};
static const Esc_UINT8 EscEcc_BP512_test_pubkey_x[] =
{
    0x78U, 0xd4U, 0xd7U, 0xf9U, 0x1bU, 0xd1U, 0x12U, 0xccU,
    0x45U, 0x04U, 0xe3U, 0x7aU, 0x82U, 0x70U, 0x1fU, 0x83U,
    0x13U, 0x4eU, 0x63U, 0x2bU, 0x0aU, 0x98U, 0xbdU, 0x3bU,
    0x25U, 0xb7U, 0xd0U, 0xc9U, 0xbfU, 0x4bU, 0xa3U, 0x81U,
    0xb2U, 0xabU, 0x51U, 0x45U, 0x57U, 0x05U, 0x38U, 0x88U,
    0xfbU, 0xa1U, 0x46U, 0x11U, 0x3bU, 0x36U, 0x8eU, 0xe7U,
    0x8dU, 0xabU, 0xaaU, 0xd6U, 0xbcU, 0x2eU, 0x1cU, 0x03U,
    0x59U, 0xccU, 0x14U, 0x30U, 0x33U, 0xb7U, 0x3cU, 0xe6U
};
static const Esc_UINT8 EscEcc_BP512_test_pubkey_y[] =
{
    0x02U, 0xc2U, 0xf7U, 0xd5U, 0x04U, 0xb9U, 0x16U, 0x6bU,
    0x54U, 0xb1U, 0xd8U, 0xadU, 0x42U, 0x76U, 0x67U, 0x47U,
    0x07U, 0x46U, 0x1eU, 0x4aU, 0x7aU, 0xa9U, 0xe7U, 0x88U,
    0x35U, 0x47U, 0x37U, 0x00U, 0xb8U, 0x44U, 0x54U, 0xc1U,
    0x53U, 0xcbU, 0x5eU, 0x25U, 0x99U, 0xb5U, 0xb9U, 0xebU,
    0xb2U, 0x20U, 0x16U, 0x55U, 0x7eU, 0x1bU, 0x76U, 0x4fU,
    0xb6U, 0x5cU, 0xe2U, 0x59U, 0x56U, 0xfaU, 0x6cU, 0x98U,
    0x5fU, 0x28U, 0x02U, 0x0eU, 0x78U, 0xd3U, 0x70U, 0xa8U
};
#   if EscEcc_ECDSA_ENABLED == 1
static const Esc_UINT8 EscEcc_BP512_test_hash[] =
{
    0x63U, 0xf9U, 0x37U, 0xb1U, 0x90U, 0x17U, 0xf8U, 0x79U,
    0xf7U, 0xf6U, 0x50U, 0xf0U, 0xefU, 0x88U, 0x1eU, 0xb7U,
    0x3fU, 0x16U, 0x36U, 0xe5U, 0xceU, 0x81U, 0x0aU, 0x15U,
    0x21U, 0x47U, 0x43U, 0x0aU, 0xb0U, 0x11U, 0x1bU, 0xa9U,
    0x2dU, 0x9fU, 0x65U, 0xf1U, 0xd5U, 0x8cU, 0x64U, 0x65U,
    0x86U, 0xbfU, 0xbfU, 0x8cU, 0x09U, 0x6dU, 0x51U, 0x45U,
    0x12U, 0xf1U, 0x5fU, 0x0cU, 0xd0U, 0xd2U, 0xe2U, 0xf1U,
    0x16U, 0xa0U, 0xe8U, 0x8bU, 0x4aU, 0xd6U, 0x0bU, 0x31U
};
static const Esc_UINT8 EscEcc_BP512_test_random[] =
{
    0x01U, 0x16U, 0x68U, 0x41U, 0x98U, 0xd0U, 0x44U, 0xc0U,
    0x4cU, 0xf8U, 0x14U, 0xf6U, 0xcdU, 0xc5U, 0xe2U, 0x91U,
    0x97U, 0xe5U, 0x97U, 0x16U, 0xacU, 0xabU, 0x7eU, 0x94U,
    0xc1U, 0xeeU, 0x08U, 0xdbU, 0x35U, 0xe9U, 0x4fU, 0x25U,
    0x01U, 0xc3U, 0xb7U, 0x5eU, 0xa8U, 0xe4U, 0xe0U, 0xd2U,
    0x30U, 0x8eU, 0x1dU, 0x85U, 0x36U, 0x61U, 0x74U, 0xfaU,
    0x21U, 0xc6U, 0xddU, 0x19U, 0x77U, 0x22U, 0x73U, 0xd8U,
    0x64U, 0xe7U, 0x23U, 0x65U, 0xcdU, 0x2cU, 0x89U, 0xedU
};
static const Esc_UINT8 EscEcc_BP512_test_ecdsa_sig_r[] =
{
    0x53U, 0x74U, 0xb0U, 0xc6U, 0x3aU, 0xdaU, 0x04U, 0x00U,
    0x42U, 0xfdU, 0x64U, 0x38U, 0xbfU, 0x2cU, 0x21U, 0x29U,
    0x6aU, 0xeeU, 0xdeU, 0x82U, 0xc9U, 0x7cU, 0x52U, 0xe9U,
    0xa4U, 0x4aU, 0x71U, 0xaeU, 0x98U, 0x7bU, 0x22U, 0xa2U,
    0x6dU, 0x09U, 0x37U, 0xfaU, 0x9fU, 0xb3U, 0x12U, 0xd4U,
    0x50U, 0x03U, 0xfeU, 0xb9U, 0xc9U, 0x31U, 0x00U, 0xc6U,
    0x0fU, 0x53U, 0x8aU, 0xa6U, 0x0cU, 0x11U, 0x35U, 0x30U,
    0xc3U, 0xdaU, 0xd7U, 0x46U, 0x77U, 0x0eU, 0x8fU, 0xa5U
};
static const Esc_UINT8 EscEcc_BP512_test_ecdsa_sig_s[] =
{
    0xa2U, 0xc0U, 0x73U, 0xf0U, 0x80U, 0x41U, 0x0cU, 0xdaU,
    0x2dU, 0x66U, 0x85U, 0xceU, 0x21U, 0x35U, 0x70U, 0xb3U,
    0x36U, 0x87U, 0xcbU, 0xaaU, 0x89U, 0xfcU, 0x54U, 0x9cU,
    0x9eU, 0xbdU, 0xc5U, 0x94U, 0x4fU, 0x80U, 0xe6U, 0x05U,
    0x61U, 0x9cU, 0x54U, 0x4bU, 0x3cU, 0x10U, 0x66U, 0x84U,
    0x10U, 0xe7U, 0x9eU, 0x02U, 0xc5U, 0x3aU, 0x4bU, 0x18U,
    0x63U, 0xc0U, 0xf9U, 0x45U, 0x48U, 0xeaU, 0xcdU, 0x5bU,
    0xdfU, 0xa7U, 0x2dU, 0x04U, 0xd5U, 0x45U, 0x7cU, 0x38U
};
#   endif
#endif

/*lint -esym(9003,EscEcc_allTestVectors) We allow local objects outside the block scope for large testvectors (increases readibility) */
static const s_ecc_tst_vector EscEcc_allTestVectors[] =
{
#if (EscEcc_SECP_192_ENABLED == 1)
    {
        EscEcc_secp192_test_secretKey,
        EscEcc_secp192_test_pubkey_x,
        EscEcc_secp192_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_secp192_test_hash,
        24U,
        EscEcc_secp192_test_random,
        EscEcc_secp192_test_ecdsa_sig_r,
        EscEcc_secp192_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_SECP_192
    },
#endif
#if (EscEcc_SECP_224_ENABLED == 1)
    {
        EscEcc_secp224_test_secretKey,
        EscEcc_secp224_test_pubkey_x,
        EscEcc_secp224_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_secp224_test_hash,
        20U,
        EscEcc_secp224_test_random,
        EscEcc_secp224_test_ecdsa_sig_r,
        EscEcc_secp224_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_SECP_224
    },
#endif
#if (EscEcc_SECP_256_ENABLED == 1)
    {
        EscEcc_secp256_test_secretKey,
        EscEcc_secp256_test_pubkey_x,
        EscEcc_secp256_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_secp256_test_hash,
        20U,
        EscEcc_secp256_test_random,
        EscEcc_secp256_test_ecdsa_sig_r,
        EscEcc_secp256_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_SECP_256
    },
#endif
#if (EscEcc_SECP_384_ENABLED == 1)
    {
        EscEcc_secp384_test_secretKey,
        EscEcc_secp384_test_pubkey_x,
        EscEcc_secp384_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_secp384_test_hash,
        48U,
        EscEcc_secp384_test_random,
        EscEcc_secp384_test_ecdsa_sig_r,
        EscEcc_secp384_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_SECP_384
    },
#endif
#if (EscEcc_SECP_521_ENABLED == 1)
    {
        EscEcc_secp521_test_secretKey,
        EscEcc_secp521_test_pubkey_x,
        EscEcc_secp521_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_secp521_test_hash,
        64U,
        EscEcc_secp521_test_random,
        EscEcc_secp521_test_ecdsa_sig_r,
        EscEcc_secp521_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_SECP_521
    },
#endif

/* Input values are randomly generated with Java, output values
 * are generated with BouncyCastle 1.46 */
#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
    {
        EscEcc_BP160_test_secretKey,
        EscEcc_BP160_test_pubkey_x,
        EscEcc_BP160_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP160_test_hash,
        20U,
        EscEcc_BP160_test_random,
        EscEcc_BP160_test_ecdsa_sig_r,
        EscEcc_BP160_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P160
    },
#endif
#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
    {
        EscEcc_BP192_test_secretKey,
        EscEcc_BP192_test_pubkey_x,
        EscEcc_BP192_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP192_test_hash,
        24U,
        EscEcc_BP192_test_random,
        EscEcc_BP192_test_ecdsa_sig_r,
        EscEcc_BP192_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P192
    },
#endif
#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
    {
        EscEcc_BP224_test_secretKey,
        EscEcc_BP224_test_pubkey_x,
        EscEcc_BP224_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP224_test_hash,
        28U,
        EscEcc_BP224_test_random,
        EscEcc_BP224_test_ecdsa_sig_r,
        EscEcc_BP224_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P224
    },
#endif
#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
    {
        EscEcc_BP256_test_secretKey,
        EscEcc_BP256_test_pubkey_x,
        EscEcc_BP256_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP256_test_hash,
        32U,
        EscEcc_BP256_test_random,
        EscEcc_BP256_test_ecdsa_sig_r,
        EscEcc_BP256_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P256
    },
#endif
#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
    {
        EscEcc_BP320_test_secretKey,
        EscEcc_BP320_test_pubkey_x,
        EscEcc_BP320_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP320_test_hash,
        40U,
        EscEcc_BP320_test_random,
        EscEcc_BP320_test_ecdsa_sig_r,
        EscEcc_BP320_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P320
    },
#endif
#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
    {
        EscEcc_BP384_test_secretKey,
        EscEcc_BP384_test_pubkey_x,
        EscEcc_BP384_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP384_test_hash,
        48U,
        EscEcc_BP384_test_random,
        EscEcc_BP384_test_ecdsa_sig_r,
        EscEcc_BP384_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P384
    },
#endif
#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
    {
        EscEcc_BP512_test_secretKey,
        EscEcc_BP512_test_pubkey_x,
        EscEcc_BP512_test_pubkey_y,
#   if EscEcc_ECDSA_ENABLED == 1
        EscEcc_BP512_test_hash,
        64U,
        EscEcc_BP512_test_random,
        EscEcc_BP512_test_ecdsa_sig_r,
        EscEcc_BP512_test_ecdsa_sig_s,
#   endif
        EscEcc_CURVE_BRAINPOOL_P512
    }
#endif
}; /*end test vector*/

/***************************************************************************
 * 5. DECLARATIONS                                                         *
 ***************************************************************************/
static Esc_ERROR
EscTstEcc_ComplianceTestKey(
    s_ecc_tst_vector* tst_vec );

static Esc_ERROR
EscTstEcc_ParametersKey(
    s_ecc_tst_vector* tst_vec );

/**
 * This function converts an array from the test vectors to an array which will
 * result in the correct test vector if returned from the PRNG function inside the calculateRandomK() function.
 * Practically it reverts the calculateRandomK() function.
 * This function is called inside the fakeRandomXXX() which are called inside calculateRandomK().
 *
 * \param[out] dest Array to be written.
 * \param[in] destLen Length of output buffer.
 * \param[in] source Source buffer.
 * \param[in] sourceLen Length of source buffer.
 */
static void
EscTstEcc_FakeRandomConvertArray(
    Esc_UINT8 dest[],
    Esc_UINT32 destLen,
    const Esc_UINT8 source[],
    Esc_UINT32 sourceLen );

/**
 * This function can be provided as a PRNG to the ECC Key Generation function.
 * It will get the secret key of the current testvector and convert it in a such that
 * the calculateRandomK will generate the private and public keys from current testvector.
 *
 * \param[in] randomState Used to pass the pointer to the current testvector..
 * \param[out] rnd Testvector which is converted via EscTstEcc_FakeRandomConvertArray().
 * \param[in] len Length of requested random array.
 */
static Esc_ERROR
EscTstEcc_FakeRandomSecKey(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

#if EscEcc_ECDSA_ENABLED == 1
/**
 * This function can be provided as a PRNG to the ECC Signature Generation function.
 * It will get the random nonce of the current testvector and convert it in a such that
 * the calculateRandomK will generate the signature from current testvector.
 *
 * \param[in] randomState Used to pass the pointer to the current testvector..
 * \param[out] rnd Testvector which is converted via EscTstEcc_FakeRandomConvertArray().
 * \param[in] len Length of requested random array.
 */
static Esc_ERROR
EscTstEcc_FakeRandomTstVec(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

static Esc_ERROR
EscTstEcc_CompTestSignature(
    s_ecc_tst_vector* tst_vec );

#if EscEcc_SLICING_ENABLED == 0
#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
#if EscEcc_SECP_256_ENABLED == 1
/**
 * This function tests dual point multiplications and the underlying binary NAF and window NAF.
 * This function is introduced because the function "EscFeArith_CarryProp" was not covered by the ECDSA
 * signature verification in the ECDSA test vector.
 */
static Esc_ERROR
EscTstEcc_DualPointMulTest(
    void);
#endif /* EscFeArith_ENABLE_SHAMIRS_TRICK  */
#endif /* EscEcc_SECP_256_ENABLED */
#endif

static Esc_ERROR
EscTstEcc_ParametersSignature(
    s_ecc_tst_vector* tst_vec );
#endif

#if EscEcc_ECDH_ENABLED == 1
/**
 * This function can be provided as a PRNG to the ECC Key Generation function.
 * It will get the public key coordinate x of the current testvector and convert it in a such that
 * the calculateRandomK will generate the key pair with the x coordinate as the new private key.
 *
 * \param[in] randomState Used to pass the pointer to the current testvector.
 * \param[out] rnd Testvector which is converted via EscTstEcc_FakeRandomConvertArray().
 * \param[in] len Length of requested random array.
 */
static Esc_ERROR
EscTstEcc_FakeRandomPubX(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/**
 * This function can be provided as a PRNG to the ECC Key Generation function.
 * It will get the public key coordinate y of the current testvector and convert it in a such that
 * the calculateRandomK will generate the key pair with the y coordinate as the new private key.
 *
 * \param[in] randomState Used to pass the pointer to the current testvector..
 * \param[out] rnd Testvector which is converted via EscTstEcc_FakeRandomConvertArray().
 * \param[in] len Length of requested random array.
 */
static Esc_ERROR
EscTstEcc_FakeRandomPubY(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

static Esc_ERROR
EscTstEcc_SharedSecret(
    s_ecc_tst_vector* tst_vec );

static Esc_ERROR
EscTstEcc_ParametersSharedSecret(
    const s_ecc_tst_vector* tst_vec );
#endif

/***************************************************************************
 * 6. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
static void
EscTstEcc_FakeRandomConvertArray(
    Esc_UINT8 dest[],
    Esc_UINT32 destLen,
    const Esc_UINT8 source[],
    Esc_UINT32 sourceLen )
{
    Esc_UINT32 i;
    /* fill in source as [ B31|B30|B29|B28, ... B7|B6|B5|B4,, B3|B2|B1|B0 ] */
    if (sourceLen == 66U)
    {
        Esc_UINT32 word = sourceLen; /* 66 bytes for 521 bit */

        for (i = 0; i < (sourceLen - 2U); ++i)
        {
            if ((i % 4U) == 0U)
            {
                word -= 4U;
            }
            dest[i] = source[word + (i % 4U)];
        }

        for (; i < destLen; ++i)
        {
            dest[i] = 0U;
        }
        dest[sourceLen] = source[0];
        dest[sourceLen + 1U] = source[1];
    }
    else
    {
        for (i = 0; i < sourceLen; ++i)
        {
            Esc_UINT32 idx = (sourceLen - 1U) - i;
            Esc_UINT32 word = idx / 4U;
            dest[i] = source[(word * 4U) + 3U - (idx % 4U)];
        }
        for (; i < destLen; ++i)
        {
            dest[i] = 0U;
        }
    }
}

/*lint -save -e9087 -e9079 -e954 The Lint warning about Rule 11.3 is a false/positive. We cast a void pointer to object.
  Therefore we violate the cast from void pointer to object type rule (11.5, adv.) intentionally.
  This cast is safe since the void pointer is only for interface compatibility and points to the casted type.
  The const qualifier can not be not used for interface compatibility with the PRNG function. */
#if EscEcc_ECDH_ENABLED == 1
static Esc_ERROR
EscTstEcc_FakeRandomPubX(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    s_ecc_tst_vector* tst_vec = (s_ecc_tst_vector*) randomState;
    const EscPtArithWs_CurveT *curve = EscPtArithWs_GetCurve(tst_vec->curve);

    EscTstEcc_FakeRandomConvertArray(rnd, len, tst_vec->pubkey_x, curve->curveSize.keySizeBytes );

    return Esc_NO_ERROR;
}

static Esc_ERROR
EscTstEcc_FakeRandomPubY(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    s_ecc_tst_vector* tst_vec = (s_ecc_tst_vector*) randomState;
    const EscPtArithWs_CurveT *curve = EscPtArithWs_GetCurve(tst_vec->curve);

    EscTstEcc_FakeRandomConvertArray(rnd, len, tst_vec->pubkey_y, curve->curveSize.keySizeBytes );

    return Esc_NO_ERROR;
}
#endif

#if EscEcc_ECDSA_ENABLED == 1
static Esc_ERROR
EscTstEcc_FakeRandomTstVec(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    s_ecc_tst_vector* tst_vec = (s_ecc_tst_vector*) randomState;
    const EscPtArithWs_CurveT *curve = EscPtArithWs_GetCurve(tst_vec->curve);

    EscTstEcc_FakeRandomConvertArray(rnd, len, tst_vec->random, curve->curveSize.keySizeBytes );

    return Esc_NO_ERROR;
}
#endif

static Esc_ERROR
EscTstEcc_FakeRandomSecKey(
    void* randomState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    s_ecc_tst_vector* tst_vec = (s_ecc_tst_vector*) randomState;
    const EscPtArithWs_CurveT *curve = EscPtArithWs_GetCurve(tst_vec->curve);

    EscTstEcc_FakeRandomConvertArray(rnd, len, tst_vec->sec_key, curve->curveSize.keySizeBytes );
    return Esc_NO_ERROR;
}
/*lint -restore */


static Esc_ERROR
EscTstEcc_ComplianceTestKey(
    s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT16 i;
    Esc_UINT8 privK[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT32 privateKeyLen = EscFeArith_KEY_BYTES_MAX;

    EscEcc_PublicKeyT pt_public_key;
    const EscPtArithWs_CurveT *curve;
    Esc_UINT16 keySizeBytes;

    /* Get curve */

    curve = EscPtArithWs_GetCurve(tst_vec->curve);
    Esc_ASSERT(curve);
    keySizeBytes = curve->curveSize.keySizeBytes;

    EscTst_PrintString( "ECC Key Generation test\n" );

    /* Generate key pair */

    /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility.
      Cast is safe since the void pointer is casted back before using. */
    returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, &privateKeyLen, (void*)tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare priv key length */
        EscTst_PrintWord( "Expected private key length", keySizeBytes );
        EscTst_PrintWord( "Calculated private key length", privateKeyLen );

        if ( keySizeBytes != privateKeyLen )
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare priv key */
        EscTst_PrintArray( "Expected Private Key", tst_vec->sec_key, keySizeBytes );
        EscTst_PrintArray( "Calculated Private Key", privK, privateKeyLen );

        if (EscTst_Memcmp( tst_vec->sec_key, privK, privateKeyLen ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare x-coordinate */
        EscTst_PrintArray( "Expected Public Key x", tst_vec->pubkey_x, keySizeBytes );
        EscTst_PrintArray( "Calculated Public Key x", pt_public_key.x, keySizeBytes );

        if (EscTst_Memcmp( pt_public_key.x, tst_vec->pubkey_x, (Esc_UINT32)keySizeBytes ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare y-coordinate */
        EscTst_PrintArray( "Expected Public Key y", tst_vec->pubkey_y, keySizeBytes );
        EscTst_PrintArray( "Calculated Public Key y", pt_public_key.y, keySizeBytes );

        if (EscTst_Memcmp( pt_public_key.y, tst_vec->pubkey_y, (Esc_UINT32)keySizeBytes ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "\nApplying EscEcc_PublicKeyValidation\n" );
        returnCode = EscEcc_PublicKeyValidation( &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    /* Negative Tests */

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set point to infinity */
        for (i = 0U; i < keySizeBytes; i++)
        {
            pt_public_key.x[i] = 0U;
            pt_public_key.y[i] = 0U;
        }

        EscTst_PrintString( "\nApplying EscEcc_PublicKeyValidation with a faulty public key\n" );
        returnCode = EscEcc_PublicKeyValidation( &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_ECC_KEY );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set x-coordinate greater than p */
        for (i = 0U; i < keySizeBytes; i++)
        {
            pt_public_key.x[i] = 0xFFU;
            pt_public_key.y[i] = 0U;
        }

        EscTst_PrintString( "\nApplying EscEcc_PublicKeyValidation with a faulty public key\n" );
        returnCode = EscEcc_PublicKeyValidation( &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_ECC_KEY );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set y-coordinate greater than p */
        for (i = 0U; i < keySizeBytes; i++)
        {
            pt_public_key.x[i] = 0U;
            pt_public_key.y[i] = 0xFFU;
        }

        EscTst_PrintString( "\nApplying EscEcc_PublicKeyValidation with a faulty public key\n" );
        returnCode = EscEcc_PublicKeyValidation( &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_ECC_KEY );
    }

    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintString( "FAILED!!!\n\n\n" );
    }
    else
    {
        EscTst_PrintString( "Correct\n\n\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstEcc_ParametersKey(
    s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    EscEcc_PublicKeyT pt_public_key;
    Esc_UINT8 privK[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT32 privateKeyLen = EscFeArith_KEY_BYTES_MAX;

    /* Test EscEcc_KeyGeneration() */

    EscTst_PrintString( "EscEcc_KeyGeneration() with correct parameters\n" );
    returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, &privateKeyLen, tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );
    returnCode = EscTst_CheckResultSuccess(returnCode);

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with pQ = 0\n" );
        returnCode = EscEcc_KeyGeneration( Esc_NULL_PTR, privK, &privateKeyLen, tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with d = 0\n" );
        returnCode = EscEcc_KeyGeneration( &pt_public_key, Esc_NULL_PTR, &privateKeyLen, tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with privKeyLen = 0\n" );
        returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, Esc_NULL_PTR, tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with privKeyLen too small (1)\n" );
        privateKeyLen = 1U;
        returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, &privateKeyLen, tst_vec, EscTstEcc_FakeRandomSecKey, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE );
        privateKeyLen = EscFeArith_KEY_BYTES_MAX;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with randomFunc = 0\n" );
        returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, &privateKeyLen, tst_vec, Esc_NULL_PTR, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_KeyGeneration() with invalid curve ID\n" );
        returnCode = EscEcc_KeyGeneration( &pt_public_key, privK, &privateKeyLen, tst_vec, EscTstEcc_FakeRandomSecKey, (EscEcc_CurveId)0xFFU );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    /* Test EscEcc_PublicKeyValidation() with invalid parameters */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_PublicKeyValidation() with pQ = 0\n" );
        returnCode = EscEcc_PublicKeyValidation( Esc_NULL_PTR , tst_vec->curve);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_PublicKeyValidation() with invalid curve ID\n" );
        returnCode = EscEcc_PublicKeyValidation( &pt_public_key, (EscEcc_CurveId)0xFFU);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    return returnCode;
}

#if EscEcc_ECDSA_ENABLED == 1
static Esc_ERROR
EscTstEcc_CompTestSignature(
    s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT16 i;
    const EscPtArithWs_CurveT *curve;
    Esc_UINT16 keySizeBytes;
    EscEcc_SignatureT ecc_sig;

    /* Reference public key for verification */
    EscEcc_PublicKeyT tst_public_key;

    /* Get size of curve in bytes */
    curve = EscPtArithWs_GetCurve(tst_vec->curve);
    Esc_ASSERT(curve);
    keySizeBytes = curve->curveSize.keySizeBytes;

    /* Assign the Reference Public Key */
    for (i=0U; i<keySizeBytes; i++)
    {
        tst_public_key.x[i] = tst_vec->pubkey_x[i];
        tst_public_key.y[i] = tst_vec->pubkey_y[i];
    }

    EscTst_PrintString( "\n\nECC Signature Generation test\n" );

    EscTst_PrintArray( "Private Key", tst_vec->sec_key, keySizeBytes );
    EscTst_PrintArray( "Message-Hash", tst_vec->hash, tst_vec->hashLen );
    EscTst_PrintArray( "Random k", tst_vec->random, keySizeBytes );

    /* Compute signature */
    returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare r part of signature */
        EscTst_PrintArray( "Expected Signature.r_bytes", tst_vec->ecdsa_sig_r, keySizeBytes );
        EscTst_PrintArray( "Calculated Signature.r_bytes", ecc_sig.r_bytes, keySizeBytes );

        if (EscTst_Memcmp( tst_vec->ecdsa_sig_r, ecc_sig.r_bytes, (Esc_UINT32)keySizeBytes ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare s part of signature */
        EscTst_PrintArray( "Expected Signature.s_bytes", tst_vec->ecdsa_sig_s, keySizeBytes );
        EscTst_PrintArray( "Calculated Signature.s_bytes", ecc_sig.s_bytes, keySizeBytes );

        if (EscTst_Memcmp( tst_vec->ecdsa_sig_s, ecc_sig.s_bytes, (Esc_UINT32)keySizeBytes ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    /* Signature verification */
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Verify generated signature\n" );
        /*lint -e{772} tst_public_key is initialized */
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_sig, &tst_public_key, tst_vec->curve );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Correct\n\n\n" );
    }
    else
    {
        EscTst_PrintString( "FAILED!!!\n\n\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstEcc_ParametersSignature(
    s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT16 i;
    const EscPtArithWs_CurveT *curve;
    EscEcc_SignatureT ecc_sig;
    EscEcc_PublicKeyT pt_public_key;
    EscEcc_SignatureT ecc_invalid_sig;

    /* Get the curve */
    curve = EscPtArithWs_GetCurve(tst_vec->curve);
    Esc_ASSERT(curve);

    /* Assign the Reference Public Key */
    for (i=0U; i<curve->curveSize.keySizeBytes; i++)
    {
        pt_public_key.x[i] = tst_vec->pubkey_x[i];
        pt_public_key.y[i] = tst_vec->pubkey_y[i];
    }

    /* Test signature generation */

    EscTst_PrintString( "EscEcc_SignatureGeneration() with correct parameters\n" );
    returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
    returnCode = EscTst_CheckResultSuccess(returnCode);

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with ecc_sig = 0\n" );
        returnCode = EscEcc_SignatureGeneration( Esc_NULL_PTR, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with msg_hash = 0\n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, Esc_NULL_PTR, tst_vec->hashLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with d = 0\n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, Esc_NULL_PTR, curve->curveSize.keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with invalid priv key Length curve.keySizeBytes +1 \n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, ((Esc_UINT32)curve->curveSize.keySizeBytes + 1U), tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with invalid priv key Length curve.keySizeBytes -1 \n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, ((Esc_UINT32)curve->curveSize.keySizeBytes - 1U), tst_vec, EscTstEcc_FakeRandomTstVec, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with randomFunc = 0\n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, tst_vec, Esc_NULL_PTR, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureGeneration() with invalid curve ID\n" );
        returnCode = EscEcc_SignatureGeneration( &ecc_sig, tst_vec->hash, tst_vec->hashLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, tst_vec, EscTstEcc_FakeRandomTstVec, (EscEcc_CurveId)0xFFU );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    /* Test signature verification */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with correct parameters\n" );
        /*lint -e{772} pt_public_key is initialized */
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with msg_hash = 0\n" );
        returnCode = EscEcc_SignatureVerification( Esc_NULL_PTR, tst_vec->hashLen, &ecc_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with ecc_sig = 0\n" );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, Esc_NULL_PTR, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with pQ = 0\n" );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_sig, Esc_NULL_PTR, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with invalid curve ID\n" );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_sig, &pt_public_key, (EscEcc_CurveId)0xFFU );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with r = 0\n" );
        EscTst_Memset( ecc_invalid_sig.r_bytes, sizeof(ecc_invalid_sig.r_bytes), 0U );
        EscTst_Memcpy( ecc_invalid_sig.s_bytes, ecc_sig.s_bytes, sizeof(ecc_invalid_sig.s_bytes) );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_invalid_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with s = 0\n" );
        EscTst_Memcpy( ecc_invalid_sig.r_bytes, ecc_sig.r_bytes, sizeof(ecc_invalid_sig.r_bytes) );
        EscTst_Memset( ecc_invalid_sig.s_bytes, sizeof(ecc_invalid_sig.s_bytes), 0U );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_invalid_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with r > n\n" );
        EscTst_Memset( ecc_invalid_sig.r_bytes, sizeof(ecc_invalid_sig.r_bytes), 0xFFU );
        EscTst_Memcpy( ecc_invalid_sig.s_bytes, ecc_sig.s_bytes, sizeof(ecc_invalid_sig.s_bytes) );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_invalid_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_SignatureVerification() with s > n\n" );
        EscTst_Memcpy( ecc_invalid_sig.r_bytes, ecc_sig.r_bytes, sizeof(ecc_invalid_sig.r_bytes) );
        EscTst_Memset( ecc_invalid_sig.s_bytes, sizeof(ecc_invalid_sig.s_bytes), 0xFFU );
        returnCode = EscEcc_SignatureVerification( tst_vec->hash, tst_vec->hashLen, &ecc_invalid_sig, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    return returnCode;
}
#if EscEcc_SLICING_ENABLED == 0
#if EscFeArith_ENABLE_SHAMIRS_TRICK == 1
#if EscEcc_SECP_256_ENABLED == 1
static Esc_ERROR
EscTstEcc_DualPointMulTest(
    void)
{
    Esc_ERROR returnCode;
    EscEccArithS0_Pt_JacDualMulAddBinContext ctx;
    const EscPtArithWs_CurveT *curve;
    EscPtArithWs_PointT pJ;
    EscPtArithWs_PointT pA;
    Esc_UINT8 i;

    returnCode = Esc_NO_ERROR;
    /* Get curve */
    curve = EscPtArithWs_GetCurve(EscEcc_CURVE_SECP_256);
    EscTst_PrintString( "Dual Point Multiplication Test\n" );
    for (i = 0; i < dual_point_mul_test_number; i++)
    {
        EscEccArithS0_Pt_JacDualMulAddBinInit(&ctx, &pJ, &tst_dual_point_multiplication[i].k0,
                                              &curve->base_point_G,
                                              &tst_dual_point_multiplication[i].k1,
                                              &curve->base_point_G, curve);
        EscEccArithS0_Pt_ToAffineInit(&ctx.toAffineCtx, &pA, &pJ, curve);
        pA.type = EscPtArith_TYPE_JACOBIAN;
        EscFeArith_SetOne(&pA.z);
        EscTst_PrintString( "Verify dual point multiplication result\n" );
        if ((EscTst_MemcmpWord(pA.x.word, tst_dual_point_multiplication[i].p.x.word,
                               curve->curveSize.maxWords) == FALSE)
                || (EscTst_MemcmpWord(pA.y.word, tst_dual_point_multiplication[i].p.y.word,
                                      curve->curveSize.maxWords) == FALSE)
                || (EscTst_MemcmpWord(pA.z.word, tst_dual_point_multiplication[i].p.z.word,
                                      curve->curveSize.maxWords) == FALSE))
        {
            returnCode = Esc_KAT_FAILED;
            EscTst_PrintString( "FAILED!!!\n\n\n" );
            return returnCode;
        }
        EscTst_PrintString( "Correct\n\n\n" );
    }
    return returnCode;
}
#endif /* EscFeArith_ENABLE_SHAMIRS_TRICK */
#endif /* EscEcc_SECP_256_ENABLED */
#endif
#endif

#if EscEcc_ECDH_ENABLED == 1
static Esc_ERROR
EscTstEcc_SharedSecret(
    s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    EscEcc_PublicKeyT pt_public_key_A, pt_public_key_B;
    Esc_UINT8 private_key_A[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT8 private_key_B[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT8 calc_secret_A[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT8 calc_secret_B[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT32 privateKeyLenA = EscFeArith_KEY_BYTES_MAX;
    Esc_UINT32 privateKeyLenB = EscFeArith_KEY_BYTES_MAX;
    Esc_UINT32 sharedSecretLenA = EscFeArith_KEY_BYTES_MAX;
    Esc_UINT32 sharedSecretLenB = EscFeArith_KEY_BYTES_MAX;

    const EscPtArithWs_CurveT *curve;

    /* Get curve */
    curve = EscPtArithWs_GetCurve(tst_vec->curve);
    Esc_ASSERT(curve);

    EscTst_PrintString( "\nECC shared secret test\n\n" );

    /* Generate key pairs for A and B. Since we don't want to use a real random number generator in the selftest,
       we use the x coordinate and the y coordinate of the public key from the test vector as a private key for A and B respectively. */
    returnCode = EscEcc_KeyGeneration( &pt_public_key_A, private_key_A, &privateKeyLenA, tst_vec, EscTstEcc_FakeRandomPubX, tst_vec->curve );

    EscTst_PrintArray( "Secret key of A", private_key_A, privateKeyLenA );
    EscTst_PrintArray( "Public Key of A (x-Coord)", pt_public_key_A.x, curve->curveSize.keySizeBytes );
    EscTst_PrintArray( "Public Key of A (y-Coord)", pt_public_key_A.y, curve->curveSize.keySizeBytes );

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscEcc_KeyGeneration( &pt_public_key_B, private_key_B, &privateKeyLenB, tst_vec, EscTstEcc_FakeRandomPubY, tst_vec->curve );

        EscTst_PrintArray( "Secret Key of B", private_key_B, privateKeyLenB );
        EscTst_PrintArray( "Public Key of B (x-Coord)", pt_public_key_B.x, curve->curveSize.keySizeBytes );
        EscTst_PrintArray( "Public Key of B (y-Coord)", pt_public_key_B.y, curve->curveSize.keySizeBytes );
    }

    /* Compute shared secret for A and B, and check if they match */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscEcc_ComputeSharedSecret( calc_secret_A, &sharedSecretLenA, private_key_A, privateKeyLenA, &pt_public_key_B, tst_vec->curve );
        EscTst_PrintArray( "Shared secret of A", calc_secret_A, sharedSecretLenA );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscEcc_ComputeSharedSecret( calc_secret_B, &sharedSecretLenB, private_key_B, privateKeyLenB, &pt_public_key_A, tst_vec->curve );
        EscTst_PrintArray( "Shared secret of B", calc_secret_B, sharedSecretLenB );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if ( (sharedSecretLenA != sharedSecretLenB) || (sharedSecretLenA != curve->curveSize.keySizeBytes) )
        {
            returnCode = Esc_KAT_FAILED;
            EscTst_PrintString( "Failure: different shared secret length or incorrect lengths!\n" );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if ( EscTst_Memcmp( calc_secret_A, calc_secret_B, sharedSecretLenA ) == FALSE )
        {
            returnCode = Esc_KAT_FAILED;
            EscTst_PrintString( "Failure: different shared secrets!\n" );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Correct\n" );
    }
    else
    {
        EscTst_PrintString( "Failure!\n" );
    }

    return returnCode;
}

static Esc_ERROR
EscTstEcc_ParametersSharedSecret(
    const s_ecc_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT16 i;
    const EscPtArithWs_CurveT *curve;
    EscEcc_PublicKeyT pt_public_key;
    Esc_UINT8 sharedSecret[EscFeArith_KEY_BYTES_MAX];
    Esc_UINT32 sharedSecretLen = EscFeArith_KEY_BYTES_MAX;

    /* Get size of curve in bytes */
    curve = EscPtArithWs_GetCurve(tst_vec->curve);
    Esc_ASSERT(curve);

    /* Assign the Reference Public Key */
    for (i=0U; i<curve->curveSize.keySizeBytes; i++)
    {
        pt_public_key.x[i] = tst_vec->pubkey_x[i];
        pt_public_key.y[i] = tst_vec->pubkey_y[i];
    }

    /* Test ECDH */

    EscTst_PrintString( "EscEcc_ComputeSharedSecret() with correct parameters\n" );
    /*lint -e{772} pt_public_key is initialized */
    returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, &pt_public_key, tst_vec->curve );
    returnCode = EscTst_CheckResultSuccess(returnCode);
    sharedSecretLen = EscFeArith_KEY_BYTES_MAX;

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with sharedSecret = 0\n" );
        returnCode = EscEcc_ComputeSharedSecret( Esc_NULL_PTR, &sharedSecretLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with sharedSecretLen = 0\n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], Esc_NULL_PTR, tst_vec->sec_key, curve->curveSize.keySizeBytes, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with sharedSecretLen too small (1)\n" );
        sharedSecretLen = 1U;
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE );
        sharedSecretLen = EscFeArith_KEY_BYTES_MAX;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with private key = 0\n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, Esc_NULL_PTR, curve->curveSize.keySizeBytes, &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with invalid priv key Length curve.keySizeBytes +1 \n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, ((Esc_UINT32)curve->curveSize.keySizeBytes + 1U), &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with invalid priv key Length curve.keySizeBytes -1 \n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, ((Esc_UINT32)curve->curveSize.keySizeBytes - 1U), &pt_public_key, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with public key  = 0\n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, Esc_NULL_PTR, tst_vec->curve );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEcc_ComputeSharedSecret() with invalid curve ID\n" );
        returnCode = EscEcc_ComputeSharedSecret( &sharedSecret[0], &sharedSecretLen, tst_vec->sec_key, curve->curveSize.keySizeBytes, &pt_public_key, (EscEcc_CurveId)0xFFU );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    return returnCode;
}

#endif /* EscEcc_ECDH_ENABLED */

Esc_ERROR
EscTstEcc_Perform(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT16 numTests = (Esc_UINT16)(sizeof(EscEcc_allTestVectors) / sizeof(EscEcc_allTestVectors[0]));

    for (i=0U; (i < numTests) && (returnCode == Esc_NO_ERROR); i++)
    {
#if EscTst_ENABLE_LOGGING
        const EscPtArithWs_CurveT *curve;

        curve = EscPtArithWs_GetCurve(EscEcc_allTestVectors[i].curve);
        Esc_ASSERT(curve);

        EscTst_PrintWord( "ECC test curveID: ", EscEcc_allTestVectors[i].curve );
        EscTst_PrintWord( " Key length in bits: ", curve->curveSize.keySizeBits );
        EscTst_PrintWord( " Key length in words: ", curve->curveSize.keySizeWords );
#endif
/*lint -save -e9005 We cast the const away for interface compatibility. Vector is used as a PRNG state later. */
        returnCode = EscTstEcc_ComplianceTestKey((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstEcc_ParametersKey((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);
        }
#if EscEcc_ECDSA_ENABLED == 1
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstEcc_CompTestSignature((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstEcc_ParametersSignature((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);
        }
#if (EscEcc_SECP_256_ENABLED == 1 && EscFeArith_ENABLE_SHAMIRS_TRICK == 1 && EscEcc_SLICING_ENABLED == 0)
        if (EscEcc_allTestVectors[i].curve == EscFeArith_CURVE_SECP_256)
        {
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscTstEcc_DualPointMulTest();
            }
        }
#endif
#endif /* EscEcc_ECDSA_ENABLED */

#if EscEcc_ECDH_ENABLED == 1
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstEcc_SharedSecret((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstEcc_ParametersSharedSecret((s_ecc_tst_vector*)&EscEcc_allTestVectors[i]);
        }
#endif /* EscEcc_ECDH_ENABLED */
/*lint -restore */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString(" Tests Success\n\n******************************\n\n");
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
