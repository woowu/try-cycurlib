/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       RIPEMD-160 implementation.

   According to:
   ISO/IEC FDIS 10118-3 Final Draft 2003, Chapter 7
   algorithm from:
   - Hans Dobbertin, Antoon Bosselaers, Bart Preneel:
   - "RIPEMD-160:A Strengthened Version of RIPEMD"

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_RIPEMD_160_H_
#define ESC_RIPEMD_160_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

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

/** Length of RIPEMD-160 digest in byte */
#define EscRipemd160_DIGEST_LEN     20U

/** Length of one hash block in bytes. */
#define EscRipemd160_BLOCK_BYTES    64U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Hash context for RIPEMD-160 */
typedef struct
{
    /** high word of 64-bit value for bytes count */
    Esc_UINT32 total_bytes_Hi;
    /** low word of 64-bit value for bytes count  */
    Esc_UINT32 total_bytes_Lo;
    /** 5 x 32-bit hash words */
    Esc_UINT32 vector[5];
    /** 64 byte buffer */
    Esc_UINT8 buffer[EscRipemd160_BLOCK_BYTES];
} EscRipemd160_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the RIPEMD-160 values

\param[out] ctx Pointer to hash context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRipemd160_Init(
    EscRipemd160_ContextT* ctx );

/**
This function updates hash context for a block of data

\param[in] ctx Pointer to input RIPEMD context.
\param[in] message Array input data chunk.
                      May be a NULL pointer if messageLength is 0.
\param[in] messageLength Length in number of bytes of input data chunk.
\param[out] ctx Pointer to updated RIPEMD context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRipemd160_Update(
    EscRipemd160_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the hash

\param[in] ctx Pointer to last hash context.
\param[out] ctx Updated hash context.
\param[out] digest Buffer to store digest value of digestLength bytes.
\param[in]  digestLength The desired length of the hash to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscRipemd160_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRipemd160_Finish(
    EscRipemd160_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/**
This function calculates and returns a RIPEMD-160 hash

\param[in] message Pointer to input data.
                   May be a NULL pointer if messageLength is 0.
\param[in] messageLength Length in number of bytes of the message.
\param[out] digest Buffer to store digest value of digestLength bytes. Can be the same as the message buffer.
\param[in]  digestLength The desired length of the digest to be stored in the buffer "digest".
                         This parameter can be used to truncate the digest such that only
                         the first bytes are copied to the output buffer. The value must
                         not be zero and must not exceed EscRipemd160_DIGEST_LEN.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRipemd160_Calc(
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
