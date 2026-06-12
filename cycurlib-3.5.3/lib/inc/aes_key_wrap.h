/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES Key Wrap implementation described from NIST SP 800-38F and RFC 3394

   \see  NIST SP 800-38F and RFC 3394


*/
/***************************************************************************/
#ifndef ESC_AES_KEY_WRAP_H_
#define ESC_AES_KEY_WRAP_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/


/***************************************************************************
 * 3. CONSTANTS                                                            *
 ***************************************************************************/


/***************************************************************************
 * 4. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
AES key wrapping function, takes input key and provides encrypted cipher text.
\param[in] kek key encryption key, unsigned Esc_UINT8
\param[in] kekLen length of key encryption key in bits
\param[in] iv can be null, if null, default of a6 will be used; 8 bytes
\param[in] in input key to be wrapped
\param[out] out buffer to store wrapped key; 8 bytes larger than input
\param[in] len length of input key in bytes. Must be at least 16 bytes and
               must be a multiple of 8.

\return Esc_NO_ERROR on success
*/
Esc_ERROR
EscAesKeyWrap_wrapKey(
    const Esc_UINT8 *kek,
    Esc_UINT16 kekLen,
    const Esc_UINT8 *iv,
    const Esc_UINT8 *in,
    Esc_UINT8 *out,
    Esc_UINT32 len);

/**
AES key unwrap key function, takes encrypted key and provided clear text of key
\param[in] kek key encryption key
\param[in] kekLen length of key encryption key in bits
\param[in] iv initialization vector, can be null and default of a6 will be used; 8 bytes
\param[in] in wrapped key to be decrypted
\param[out] out storage location for unwrapped key; 8 bytes smaller than input
\param[in] len length of input wrapped key in bytes. Must be at least 24 bytes and
               must be a multiple of 8.

\return Esc_NO_ERROR on success
*/
Esc_ERROR
EscAesKeyWrap_unwrapKey(
    const Esc_UINT8 *kek,
    Esc_UINT16 kekLen,
    const Esc_UINT8 *iv,
    const Esc_UINT8 *in,
    Esc_UINT8 *out,
    Esc_UINT32 len);

#ifdef  __cplusplus
}
#endif

#endif
/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
