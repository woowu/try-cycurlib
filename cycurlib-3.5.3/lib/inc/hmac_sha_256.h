/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-SHA-2 implementation, according to FIPS-180-2 and RFC 2104

   \see     RFC 2104
   \see     FIPS-180-2

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_HMAC_SHA_256_H_
#define ESC_HMAC_SHA_256_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "sha_256.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Maximum MAC length for HMAC-SHA224 */
#define EscHmacSha224_MAX_MAC_LENGTH  (EscSha224_DIGEST_LEN)

/** Maximum MAC length for HMAC-SHA256 */
#define EscHmacSha256_MAX_MAC_LENGTH  (EscSha256_DIGEST_LEN)

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** HMAC context for HMAC_SHA-2 */
typedef struct
{
    /** SHA-2 hash context */
    EscSha256_ContextT sha_ctx;

    /**
    this buffer holds the HMAC key - the key will be hashed during the
    initialization when it's length is greater than EscSha256_BLOCK_BYTES bytes.
    */
    Esc_UINT8 hmac_key[EscSha256_BLOCK_BYTES];

    /** Length of the hmac_key */
    Esc_UINT8 hmac_keyLength;
} EscHmacSha256_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the HMAC-SHA-2 values.

\param[in] isSha224 If set to TRUE, HMAC-SHA-224 is used instead of HMAC-SHA-256.
\param[in] ctx Pointer to HMAC context.
\param[in] key Pointer to HMAC key.
\param[in] keyLength Length of HMAC key. Must be at least 1 byte.
\param[out] ctx Updated HMAC context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha256_Init(
    Esc_BOOL isSha224,
    EscHmacSha256_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength );

/**
This function updates HMAC context for a block of data

\param[in] ctx Pointer to input HMAC SHA2 context.
\param[in] message Pointer to input data chunk.
\param[in] messageLength Length in number of bytes of input data chunk.
\param[out] ctx Pointer to updated SHA2 context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha256_Update(
    EscHmacSha256_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the HMAC.

\param[in] ctx Pointer to the context.
\param[out] mac Buffer to store HMAC value of macLength bytes.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                      This parameter can be used to truncate the MAC such that only
                      the first bytes are copied to the output buffer. The length must
                      not be zero and must not exceed the maximum MAC size
                      (either EscHmacSha224_MAX_MAC_LENGTH or EscHmacSha256_MAX_MAC_LENGTH depending
                      on how the context was initialized with EscHmacSha256_init()).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha256_Finish(
    EscHmacSha256_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
Calculate HMAC based on SHA-2 for the input data

\param[in] isSha224 If set to TRUE, HMAC-SHA-224 is used instead of HMAC-SHA-256.
\param[in] key Secret MAC key.
\param[in] keyLength Length of key in bytes. Must be at least 1 byte.
\param[in] message Data to be authenticated with the MAC.
\param[in] messageLength Length of data in bytes.
\param[out] mac Buffer to store HMAC value of macLength bytes. Can be the same as the message buffer.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                      This parameter can be used to truncate the MAC such that only
                      the first bytes are copied to the output buffer. The length must
                      not be zero and must not exceed the maximum MAC size
                      (either EscHmacSha224_MAX_MAC_LENGTH or EscHmacSha256_MAX_MAC_LENGTH depending
                      on which SHA variant is selected with isSha224).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacSha256_Calc(
    Esc_BOOL isSha224,
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
