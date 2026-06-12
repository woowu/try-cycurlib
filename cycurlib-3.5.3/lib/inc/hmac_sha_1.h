/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-SHA-1 implementation, according to FIPS-180-2 and RFC 2104

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_HMAC_SHA_1_H_
#define ESC_HMAC_SHA_1_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "sha_1.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Maximum MAC length for HMAC-SHA1 */
#define EscHmacSha1_MAX_MAC_LENGTH  (EscSha1_DIGEST_LEN)

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** HMAC context for HMAC_SHA-1 */
typedef struct
{
    /** SHA-1 hash context */
    EscSha1_ContextT sha_ctx;

    /**
    this buffer holds the hmac key - the key will be hashed during the
    initialization when it's length is greater than EscSha1_BLOCK_BYTES bytes.
    */
    Esc_UINT8 hmac_key[EscSha1_BLOCK_BYTES];

    /** Length of the hmac_key */
    Esc_UINT8 hmac_keyLength;
} EscHmacSha1_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the HMAC-SHA-1 values.

\param[in] ctx Pointer to HMAC context.
\param[in] key Pointer to HMAC key.
\param[in] keyLength Length of HMAC key. Must be at least 1 byte.
\param[out] ctx Updated HMAC context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha1_Init(
    EscHmacSha1_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength );

/**
This function updates HMAC context for a block of data

\param[in] ctx Pointer to input HMAC-SHA1 context.
\param[in] message Pointer to input data chunk.
\param[in] messageLength Length in number of bytes of input data chunk.
\param[out] ctx Pointer to updated HMAC-SHA1 context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha1_Update(
    EscHmacSha1_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the MAC

\param[in] ctx Pointer to the context.
\param[out] mac Buffer to store HMAC value of macLength bytes.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                      This parameter can be used to truncate the MAC such that only
                      the first bytes are copied to the output buffer. The length must
                      not be zero and must not exceed the maximum MAC size
                      EscHmacSha1_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha1_Finish(
    EscHmacSha1_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
Calculate HMAC based on SHA-1 for the input data

\param[in] key Secret MAC key.
\param[in] keyLength Length of key in bytes. Must be at least 1 byte.
\param[in] message Data to be authenticated with the MAC.
\param[in] messageLength Length of data in bytes.
\param[out] mac Buffer to store HMAC value of macLength bytes. Can be the same as the message buffer.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                     This parameter can be used to truncate the MAC such that only
                     the first bytes are copied to the output buffer. The length must
                     not be zero and must not exceed the maximum MAC size
                     EscHmacSha1_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha1_Calc(
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
