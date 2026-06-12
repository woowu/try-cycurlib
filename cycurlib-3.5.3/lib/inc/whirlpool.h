/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Whirlpool implementation
                A maximum of 2^32-2 Byte can be hashed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_WHIRLPOOL_H_
#define ESC_WHIRLPOOL_H_

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

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscWhirlpool_8BIT_OPTIMIZATION
/** Increases speed significantly on costs of 1/4KB tables */
#       define EscWhirlpool_8BIT_OPTIMIZATION 1
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscWhirlpool_8BIT_OPTIMIZATION
/** Increases speed significantly on costs of 1/4KB tables */
#       define EscWhirlpool_8BIT_OPTIMIZATION 0
#   endif
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Length of digest in byte. */
#define EscWhirlpool_DIGEST_LEN     64U

/** Length of one hash block in bytes. */
#define EscWhirlpool_BLOCK_BYTES    64U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Hash context for Whirlpool */
typedef struct
{
    /** Hash values. */
    Esc_UINT8 hash[EscWhirlpool_DIGEST_LEN];
    /** Current block. */
    Esc_UINT8 block[EscWhirlpool_BLOCK_BYTES];
    /** Number of bytes in block used. */
    Esc_UINT8 blockLen;
    /** Total length of the message in byte. */
    Esc_UINT32 totalLen;
} EscWhirlpool_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the Whirlpool values.

\param[out] ctx Pointer to Whirlpool context.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscWhirlpool_Init(
    EscWhirlpool_ContextT* ctx );

/**
This function updates Whirlpool context for a block of data.

\param[in] ctx Pointer to input Whirlpool context.
\param[out] ctx Pointer to updated Whirlpool context.
\param[in] message Pointer to input data chunk.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data chunk.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscWhirlpool_Update(
    EscWhirlpool_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the digest.

\param[in] ctx Pointer to last Whirlpool context.
\param[out] ctx Pointer to updated Whirlpool context.
\param[out] digest Buffer to store digest value of digestLength bytes.
\param[in]  digestLength The desired length of the hash to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscWhirlpool_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscWhirlpool_Finish(
    EscWhirlpool_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/**
This function calculates and returns a digest.

\param[in] message Pointer to input data.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Number of bytes of input data.
\param[out] digest Buffer to store digest value of digestLength bytes. Can be the same as the message buffer.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscWhirlpool_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
/***************************************************************************/
Esc_ERROR
EscWhirlpool_Calc(
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
#endif /* WHIRLPOOL_H_ */
