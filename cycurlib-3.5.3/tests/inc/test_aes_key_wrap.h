/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-Key Wrap Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.

   $Rev: 2711 $
 */
/***************************************************************************/

#ifndef ESC_TEST_AES_KEY_WRAP_H_
#define ESC_TEST_AES_KEY_WRAP_H_

#ifdef  __cplusplus
extern "C" {
#endif


/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "cycurlib_config.h"

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
function to perform predefined vector testing (NIST SP 800-38F and RFC 3394)
no parameters as function is self-contained.
*/
Esc_ERROR
EscTstAesKeyWrap_Perform(
    void);


/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
