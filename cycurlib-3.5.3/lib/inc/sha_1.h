/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-1 implementation (FIPS-180-2 resp. RFC 2202 compliant)
                A maximum of 2^32-2 Byte can be hashed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_SHA_1_H_
#define ESC_SHA_1_H_

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

/** Length of digest in byte. */
#define EscSha1_DIGEST_LEN  20U

/** Length of one hash block in bytes. */
#define EscSha1_BLOCK_BYTES 64U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Hash context for SHA-1 */
typedef struct
{
    /** Hash values H from FIPS-180-2. */
    Esc_UINT32 hash[5];
    /** Current block. */
    Esc_UINT8 block[EscSha1_BLOCK_BYTES];
    /** Number of bytes in block used. */
    Esc_UINT8 blockLen;
    /** Total length of the message in byte. */
    Esc_UINT32 totalLen;
} EscSha1_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the SHA values according to FIPS-180-2.

\see FIPS-180-2

\param[out] ctx Pointer to SHA-1 context.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscSha1_Init(
    EscSha1_ContextT* ctx );

/**
This function updates SHA-1 context for a block of data.

\see FIPS-180-2

\param[in] ctx Pointer to input SHA-1 context.
\param[out] ctx Pointer to updated SHA-1 context.
\param[in] message Pointer to input data chunk.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data chunk.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscSha1_Update(
    EscSha1_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the digest.

\see FIPS-180-2

\param[in] ctx Pointer to last SHA-1 context.
\param[out] ctx Pointer to updated SHA-1 context.
\param[out] digest Buffer to store digest value of digestLength bytes.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscSha1_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscSha1_Finish(
    EscSha1_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength);

/**
This function calculates and returns a digest.

\see FIPS-180-2

\param[in] message Pointer to input data.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data.
\param[out] digest Buffer to store digest value of digestLength bytes. Can be the same as the message buffer.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscSha1_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscSha1_Calc(
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
