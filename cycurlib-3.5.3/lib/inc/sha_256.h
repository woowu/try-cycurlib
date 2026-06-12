/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-224 and SHA-256 implementation.
   A maximum of 2^32-2 Bytes can be hashed.

   \see      FIPS-180-2 at
   csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_SHA_256_H_
#define ESC_SHA_256_H_

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

/** Length of SHA-224 digest in byte */
#define EscSha224_DIGEST_LEN    28U

/** Length of SHA-256 digest in byte */
#define EscSha256_DIGEST_LEN    32U

/** Length of one hash block in bytes */
#define EscSha256_BLOCK_BYTES   64U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Hash context for SHA-224 and SHA-256. */
typedef struct
{
    /** Hash values H from FIPS-180-2. */
    Esc_UINT32 hash[8];
    /** Current block. */
    Esc_UINT8 block[EscSha256_BLOCK_BYTES];
    /** Number of bytes in block used. */
    Esc_UINT8 blockLen;
    /** Total length of the message in byte. */
    Esc_UINT32 totalLen;
    /** Digest length in bytes. */
    Esc_UINT8 digestLen;
} EscSha256_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the SHA values according to FIPS-180-2.

\see FIPS-180-2

\param[in] isSha224 If set to TRUE, SHA-224 is used instead of SHA-256.
\param[out] ctx pointer to SHA context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha256_Init(
    Esc_BOOL isSha224,
    EscSha256_ContextT* ctx );

/**
This function updates SHA context for a block of data.

\see FIPS-180-2

\param[in] ctx Pointer to input SHA context.
\param[out] ctx Pointer to updated SHA context.
\param[in] message Pointer to input data chunk.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data chunk.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha256_Update(
    EscSha256_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the hash.

\see FIPS-180-2

\param[in] ctx Pointer to last SHA context.
\param[out] ctx Pointer to updated SHA context.
\param[out] digest Buffer to store digest value of digestLength bytes.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed the maximum digest size
                         (either EscSha224_DIGEST_LEN or EscSha256_DIGEST_LEN depending
                         on how the context was initialized with EscSha256_init()).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha256_Finish(
    EscSha256_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/**
This function calculates and returns a EscSha256_Calc hash.

\see FIPS-180-2

\param[in] isSha224 If set to TRUE, SHA-224 is used instead of SHA-256.
\param[in] message Pointer to input data.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data.
\param[out] digest Buffer to store digest value of digestLength bytes. Can be the same as the message buffer.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed the maximum digest size
                         (either EscSha224_DIGEST_LEN or EscSha256_DIGEST_LEN depending
                         on which sha-version is selected with isSha224).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha256_Calc(
    Esc_BOOL isSha224,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
