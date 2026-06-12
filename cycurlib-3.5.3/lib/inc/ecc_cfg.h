/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Configuration for ECC module

   $Rev: 2750 $
 */
/***************************************************************************/

#ifndef ESC_ECC_CFG_H_
#define ESC_ECC_CFG_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/* Enable/disable support for secp/NIST curves */

#ifndef EscEcc_SECP_192_ENABLED
/** Enables/disables support for curve secp192r1 (also known as NIST P-192) */
#   define EscEcc_SECP_192_ENABLED     1
#endif

#ifndef EscEcc_SECP_224_ENABLED
/** Enables/disables support for curve secp224r1 (also known as NIST P-224) */
#   define EscEcc_SECP_224_ENABLED     0
#endif

#ifndef EscEcc_SECP_256_ENABLED
/** Enables/disables support for curve secp256r1 (also known as NIST P-256) */
#   define EscEcc_SECP_256_ENABLED     0
#endif

#ifndef EscEcc_SECP_384_ENABLED
/** Enables/disables support for curve secp384r1 (also known as NIST P-384) */
#   define EscEcc_SECP_384_ENABLED     0
#endif

#ifndef EscEcc_SECP_521_ENABLED
/** Enables/disables support for curve secp521r1 (also known as NIST P-521) */
#   define EscEcc_SECP_521_ENABLED     0
#endif

/* Enable/disable support for Brainpool curves */

#ifndef EscEcc_BRAINPOOL_P160_ENABLED
/** Enables/disables support for curve brainpoolP160r1 */
#   define EscEcc_BRAINPOOL_P160_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P192_ENABLED
/** Enables/disables support for curve brainpoolP192r1 */
#   define EscEcc_BRAINPOOL_P192_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P224_ENABLED
/** Enables/disables support for curve brainpoolP224r1 */
#   define EscEcc_BRAINPOOL_P224_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P256_ENABLED
/** Enables/disables support for curve brainpoolP256r1 */
#   define EscEcc_BRAINPOOL_P256_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P320_ENABLED
/** Enables/disables support for curve brainpoolP320r1 */
#   define EscEcc_BRAINPOOL_P320_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P384_ENABLED
/** Enables/disables support for curve brainpoolP384r1 */
#   define EscEcc_BRAINPOOL_P384_ENABLED    0
#endif

#ifndef EscEcc_BRAINPOOL_P512_ENABLED
/** Enables/disables support for curve brainpoolP512r1 */
#   define EscEcc_BRAINPOOL_P512_ENABLED    0
#endif

/* Default configuration for slicing */
#ifndef EscEcc_SLICING_ENABLED
/** Enable Slicing for ECDSA and ECDH */
#   define EscEcc_SLICING_ENABLED   0
#endif

/* Default configuration for ECDH */
#ifndef EscEcc_ECDH_ENABLED
/** Enable ECDH */
#    define EscEcc_ECDH_ENABLED     1
#endif

/* Default configuration for ECDSA */
#ifndef EscEcc_ECDSA_ENABLED
/** Enable ECDSA */
#    define EscEcc_ECDSA_ENABLED    1
#endif

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscEcc_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm in ECDSA and ECDH.
Increases speed, but also increases code size and stack used */
#       define EscEcc_USE_SLIDING_WINDOW 1
#   endif

#   ifndef EscEcc_USE_SHAMIRS_TRICK
/** Enable for using the 'Shamir's trick' for ECDSA signature verification.
This has only an effect if ECDSA is enabled (EscEcc_ECDSA_ENABLED == 1). */
#       define EscEcc_USE_SHAMIRS_TRICK 1
#   endif

#   ifndef EscEcc_USE_FIXED_BASE
/** Enable to use a pre-computed table for speeding up ECC key pair generation and
ECDSA signature generation */
#       define EscEcc_USE_FIXED_BASE 1
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscEcc_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm in ECDSA and ECDH.
Increases speed, but also increases code size and stack used */
#       define EscEcc_USE_SLIDING_WINDOW 0
#   endif

#   ifndef EscEcc_USE_SHAMIRS_TRICK
/** Enable for using the 'Shamir's trick' for ECDSA signature verification.
This has only an effect if ECDSA is enabled (EscEcc_ECDSA_ENABLED == 1). */
#       define EscEcc_USE_SHAMIRS_TRICK 0
#   endif

#   ifndef EscEcc_USE_FIXED_BASE
/** Enable to use a pre-computed table for speeding up ECC key pair generation and
ECDSA signature generation */
#       define EscEcc_USE_FIXED_BASE 0
#   endif
#endif

#ifndef EscEcc_WINDOW_SIZE
/** Window size for the Sliding Window algorithm
    (only used if EscEcc_USE_SLIDING_WINDOW == 1).
    The higher the window size, the higher the RAM usage! */
#   define EscEcc_WINDOW_SIZE 4U
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** The number of activated curves */
#define EscEcc_NUMBER_CURVES \
    (EscEcc_SECP_192_ENABLED + \
     EscEcc_SECP_224_ENABLED + \
     EscEcc_SECP_256_ENABLED + \
     EscEcc_SECP_384_ENABLED + \
     EscEcc_SECP_521_ENABLED + \
     EscEcc_BRAINPOOL_P160_ENABLED + \
     EscEcc_BRAINPOOL_P192_ENABLED + \
     EscEcc_BRAINPOOL_P224_ENABLED + \
     EscEcc_BRAINPOOL_P256_ENABLED + \
     EscEcc_BRAINPOOL_P320_ENABLED + \
     EscEcc_BRAINPOOL_P384_ENABLED + \
     EscEcc_BRAINPOOL_P512_ENABLED )

/** Shortcut to check whether any NIST curve is enabled */
#define EscEcc_ANY_NIST_CURVE_ENABLED (\
    (EscEcc_SECP_192_ENABLED == 1) || \
    (EscEcc_SECP_224_ENABLED == 1) || \
    (EscEcc_SECP_256_ENABLED == 1) || \
    (EscEcc_SECP_384_ENABLED == 1) || \
    (EscEcc_SECP_521_ENABLED == 1) )

/** Shortcut to check whether any Brainpool curve is enabled */
#define EscEcc_ANY_BRAINPOOL_CURVE_ENABLED (\
    (EscEcc_BRAINPOOL_P160_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P192_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P224_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P256_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P320_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P384_ENABLED == 1) || \
    (EscEcc_BRAINPOOL_P512_ENABLED == 1) )

#if EscEcc_USE_SLIDING_WINDOW == 1
/** Number of precomputed elements for the sliding window algorithm */
#   define EscEcc_NUM_WINDOW_ELEMENTS  ( (Esc_SINT16)( 1U << (EscEcc_WINDOW_SIZE - 1U) ) )
#endif

/** Test configuration */
#if (EscEcc_NUMBER_CURVES == 0)
#   error "At least one Weierstrass curve must be enabled"
#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECC_CFG_H_ */
