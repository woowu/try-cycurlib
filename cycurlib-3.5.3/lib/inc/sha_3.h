/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-3 implementation

   \see         FIPS-202 at nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

   $Rev: 2106 $
 */
/***************************************************************************/

#ifndef ESC_SHA_3_H_
#define ESC_SHA_3_H_

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

/* Identifiers for the different SHA-3 versions */
/** SHA3-224 **/
#define EscSha3_224     0U
/** SHA3-256 **/
#define EscSha3_256     1U
/** SHA3-384 **/
#define EscSha3_384     2U
/** SHA3-512 **/
#define EscSha3_512     3U

/** The maximum block size for SHA-3 is EscSha3_224_BLOCK_SIZE */
#define EscSha3_MAX_BLOCK_SIZE    EscSha3_224_BLOCK_SIZE

/** Length of SHA3-224 digest */
#define EscSha3_224_DIGEST_LEN 28U
/** Length of SHA3-224 blockSize */
#define EscSha3_224_BLOCK_SIZE 144U

/** Length of SHA3-256 digest */
#define EscSha3_256_DIGEST_LEN 32U
/** Length of SHA3-256 blockSize */
#define EscSha3_256_BLOCK_SIZE 136U

/** Length of SHA3-384 digest */
#define EscSha3_384_DIGEST_LEN 48U
/** Length of SHA3-384 blockSize */
#define EscSha3_384_BLOCK_SIZE 104U

/** Length of SHA3-512 digest */
#define EscSha3_512_DIGEST_LEN 64U
/** Length of SHA3-512 blockSize */
#define EscSha3_512_BLOCK_SIZE 72U

/** Number of lanes in the state */
#define EscSha3_NUM_LANES_IN_STATE  25U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/
#if Esc_HAS_INT64 == 1
/** Word type 64 bit. */
typedef Esc_UINT64 EscSha3_Lane;
#else
/** A 64 bit word split up into twice 32 bit. */
typedef struct
{
    /** High word. */
    Esc_UINT32 high;
    /** Low word. */
    Esc_UINT32 low;
} EscSha3_Lane;
#endif

/** Hash context for SHA3 */
typedef struct
{
    /** Current SHA3 state. */
    EscSha3_Lane state[EscSha3_NUM_LANES_IN_STATE];
    /** Current message block. */
    Esc_UINT8 block[EscSha3_MAX_BLOCK_SIZE];
    /** Number of bytes in block used. */
    Esc_UINT8 numCachedBytes;
    /** Block length for the used SHA3 version. */
    Esc_UINT8 blockLen;
    /** Digest length in bytes. */
    Esc_UINT8 digestLen;
} EscSha3_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the SHA values according to FIPS-180-2.

\param[in] shaFunction Sets the used version of SHA-3, see defines for SHA-3 versions.
\param[out] ctx pointer to SHA context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha3_Init(
    Esc_UINT8 shaFunction,
    EscSha3_ContextT* ctx );

/**
This function updates SHA context for messageLength bytes by hashing full blocks and storing the leftover bytes.

\param[in,out] ctx Pointer to SHA-3 context.
\param[in] message Pointer to input data chunk.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data chunk.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha3_Update(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final padding and returns the hash.

\param[in,out] ctx Pointer to last SHA-3 context.
\param[out] digest Buffer to store digest value of digestLength bytes.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed the digest size for the used SHA-3 version.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha3_Finish(
    EscSha3_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/**
This function calculates and returns a SHA-3 hash.

\see FIPS-180-2

\param[in] shaFunction Sets the used version of SHA-3, see defines for SHA-3 versions.
\param[in] message Pointer to input message.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input message.
\param[out] digest Buffer to store the computed hash value. Can be the same as the message buffer.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed the digest size for the used SHA-3 version.
                         See also EscSha3_XXX_DIGEST_LEN defines.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscSha3_Calc(
    Esc_UINT8 shaFunction,
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
