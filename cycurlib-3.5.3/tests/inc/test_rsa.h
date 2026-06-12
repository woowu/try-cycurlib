/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief RSA Selftest

   Checks pre-computed test patterns.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_TEST_RSA_H_
#define ESC_TEST_RSA_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "cycurlib_config.h"
#include "rsa.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef EscTstRsa_KEY_BITS_TEST
/** Size of RSA modulus which is tested in the selftest (in bits): 1024, 1536, 2048, 3072, or 4096*/
#   define EscTstRsa_KEY_BITS_TEST 1024U
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if ( EscTstRsa_KEY_BITS_TEST > EscRsa_KEY_BITS_MAX )
#   error "TEST_BITS are higher than MAX allowed BITS"
#endif

/** Size of tested RSA modulus in bytes */
#define EscTstRsa_KEY_BYTES_TEST (EscRsa_KEY_BYTES_FROMBITS( EscTstRsa_KEY_BITS_TEST ) )
/** Size of RSA values for CRT (half of the modulus length) in bytes */
#define EscTstRsa_KEY_BYTES_HALF_TEST (EscTstRsa_KEY_BYTES_TEST / 2U)
/** Size of tested RSA modulus in words */
#define EscTstRsa_RSA_SIZE_WORDS_TEST ( EscRsa_RSA_SIZE_WORDS_FROMBITS ( EscTstRsa_KEY_BITS_TEST ) )

#if (EscTstRsa_KEY_BITS_TEST != 1024U) && \
    (EscTstRsa_KEY_BITS_TEST != 1536U) && \
    (EscTstRsa_KEY_BITS_TEST != 2048U) && \
    (EscTstRsa_KEY_BITS_TEST != 3072U) && \
    (EscTstRsa_KEY_BITS_TEST != 4096U)
#    error "The size of the RSA key must be defined to 1024, 1536, 2048, 3072 or 4096"
#endif

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
RSA selftests

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscTstRsa_Perform(
    void );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
