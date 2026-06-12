/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Configuration of RSA


   $Rev: 2690 $
 */
/***************************************************************************/

#ifndef  ESC_RSA_CFG_H_
#define  ESC_RSA_CFG_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/** Size of max. RSA modulus (in bit): 1024, 1536, 2048, 3072, 4096 */
#ifndef EscRsa_KEY_BITS_MAX
#   define EscRsa_KEY_BITS_MAX      1024U
#endif

#ifndef EscRsa_GENRSA_ENABLED
/** Enable RSA key generation. */
#   define EscRsa_GENRSA_ENABLED    0
#endif

#ifndef EscRsa_PRIMETEST_ITER
/** Number of iterations of the Miller-Rabin primality test.
    Only used during key generation. */
#   define EscRsa_PRIMETEST_ITER    5U
#endif

#ifndef EscRsa_CRT_ENABLED
/** Enable decryption using the Chinese Remainder Theorem (CRT) */
#   define EscRsa_CRT_ENABLED       0
#endif

#ifndef EscRsa_SLICING_ENABLED
/** Enable slicing */
#   define EscRsa_SLICING_ENABLED   0
#endif

/***************************************************************
 Set optimization flags according to global speed define.
 The default configuration optimizes for verifications with a
 short exponent of 2^16+1 = 65537
 The following configurations yield the best performance in
 the given use case:
    Signature verification / decryption (short public exponents):
        Enable Montgomery multiplication for the standard
        exponent 65537. Disable Montgomery multiplication
        for VERY short exponents (3).
    Signature generation / encryption (long private exponents):
        Enable Montgomery multiplication and Sliding window.
 ***************************************************************/

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscRsa_USE_MONTGOM_MUL
/** Enable the Montgomery Reduction.
    Increases the speed unless the VERY short exponents (3) are used.
    This option affects the exponentiation for both long exponents and
    short exponents ( ModExpPub() / ModExpPriv() ). */
#       define EscRsa_USE_MONTGOM_MUL       1
#   endif

#   ifndef EscRsa_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm
    Increases speed, but also increases code size and stack used.
    This option affects the exponentiation for private (long) exponents ( ModExpPriv() ). */
#       define EscRsa_USE_SLIDING_WINDOW    0
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscRsa_USE_MONTGOM_MUL
/** Enable the Montgomery Reduction.
    Increases the speed unless the VERY short exponents (3) are used.
    This option affects the exponentiation for both long exponents and
    short exponents ( ModExpPub() / ModExpPriv() ). */
#       define EscRsa_USE_MONTGOM_MUL       0
#   endif

#   ifndef EscRsa_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm
    Increases speed, but also increases code size and stack used.
    This option affects the exponentiation for private (long) exponents ( ModExpPriv() ). */
#       define EscRsa_USE_SLIDING_WINDOW    0
#   endif
#endif

#ifndef EscRsa_WINDOW_SIZE
/** Window size for the Sliding Window algorithm
    Only used if the sliding window algorithm is enabled (EscRsa_USE_SLIDING_WINDOW == 1).
    The higher the window size, the higher the RAM usage! */
#   define EscRsa_WINDOW_SIZE   4U
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

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
#endif
