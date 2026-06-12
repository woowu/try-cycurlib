/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file        poly1305.h

   \brief       Poly1305 implementation, according to RFC-7539.

   Poly1305 is a one-time authenticator, also called one-time MAC.

   \see RFC-7539

   $Rev: 0001 $
 */
/***************************************************************************/

#ifndef ESC_POLY1305_H_
#define ESC_POLY1305_H_

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

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Length of session key in bytes. */
#define EscPoly1305_KEY_BYTES 32U

/** Maximum MAC length for Poly1305 */
#define EscPoly1305_MAX_MAC_LENGTH 16U

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** MAC context for poly1305 */
typedef struct
{
    /** poly1305 'r' value */
    Esc_UINT8 r[17];
    /** poly1305 's' value */
    Esc_UINT8 s[17];
    /** poly1305 'accumulator' value */
    Esc_UINT8 a[17];
    /** input buffer */
    Esc_UINT8 buffer[16];
    /** counter for bytes in input buffer */
    Esc_UINT8 leftover;
    /** flag to indicate finalized state */
    Esc_UINT8 final;
} EscPoly1305_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the Poly1305 calculation according to RFC-7539.

\warning: Poly1305 is a one-time authenticator. The key consist of two 16 bytes parts, r and s.
The pair (r,s) MUST be unique, and MUST be unpredictable for each invocation.
One way to obtain a secure key is to use the function EscChaCha20Poly1305_KeyGen() from
the module chacha20_poly1305.
The recommended option is to use the Authenticated Encryption with Associated Data (AEAD)
mode from the same module which is a construction of the Poly1305 and ChaCha20.


\param[in, out] ctx         Pointer to memory allocated for Poly1305 context.
\param[in] key              Pointer to one-time key bytes to use. Must have a size of EscPoly1305_KEY_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscPoly1305_Init(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 key[] );

/**
This function updates the Poly1305 calculation with data to be authenticated.

\param[in, out] ctx         Pointer to Poly1305 context.
\param[in] message          Pointer to message bytes.
\param[in] messageLength    Message length in bytes.

\return Esc_NO_ERROR if everything works fine.
\return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
*/
Esc_ERROR
EscPoly1305_Update(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 message[],
    const Esc_UINT32 messageLength );

/**
This function finalizes the Poly1305 calculation and updates the MAC according to RFC-7539.

Can only be called once per context. After Finish has been called, no further Updates are possible.

\param[in, out] ctx         Pointer to Poly1305 context.
\param[out] mac             Pointer to memory allocated for the MAC output.
\param[in] macLength        The desired Length of the output MAC stored in buffer "mac".
                            This parameter can be used to truncate the MAC such that only
                            the first bytes are copied to the output buffer. The length must
                            not be zero and must not exceed the maximum MAC size
                            EscPoly1305_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
\return Esc_INVALID_PARAMETER if the desired MAC length is not allowed.
\return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
\return Esc_UNEXPECTED_FUNCTION_CALL if finalize has already been called before.
*/
Esc_ERROR
EscPoly1305_Finish(
    EscPoly1305_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
This function calculates the full Poly1305 MAC for the given data in one function according to RFC-7539.

\param[in] key              Pointer to key bytes to use. Must have a size of EscPoly1305_KEY_BYTES.
\param[in] message          Pointer to message bytes.
\param[in] messageLength    Message length in bytes.
\param[out] mac             Pointer to memory allocated for the MAC output.
\param[in] macLength        The desired Length of the output MAC stored in buffer "mac".
                            This parameter can be used to truncate the MAC such that only
                            the first bytes are copied to the output buffer. The length must
                            not be zero and must not exceed the maximum MAC size
                            EscPoly1305_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
\return Esc_INVALID_PARAMETER if the desired MAC length is not allowed.
\return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
\return Esc_UNEXPECTED_FUNCTION_CALL if finalize has already been called before.
*/
Esc_ERROR
EscPoly1305_Calc(
    const Esc_UINT8 key[],
    const Esc_UINT8 message[],
    const Esc_UINT32 messageLength,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
