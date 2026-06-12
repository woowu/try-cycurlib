/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-RIPEMD-160 implementation, RFC 2104 compliant

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef  ESC_HMAC_RIPEMD_160_H_
#define  ESC_HMAC_RIPEMD_160_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "ripemd_160.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Maximum MAC length for HMAC-RIPEMD160 */
#define EscHmacRipemd160_MAX_MAC_LENGTH  (EscRipemd160_DIGEST_LEN)

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** HMAC-RIPEMD context */
typedef struct
{
    /** RIPEMD context */
    EscRipemd160_ContextT rmd_ctx;

    /**
    this buffer holds the hmac key - the key will be hashed during the
    initialization when it's length is greater than 64 bytes.
    */
    Esc_UINT8 hmac_key[EscRipemd160_BLOCK_BYTES];
    /** Length of the hmac_key */
    Esc_UINT8 hmac_keyLength;
} EscHmacRipemd160_ContextT;

/***************************************************************************
* 6. FUNCTION PROTOTYPES                                                  *
***************************************************************************/

/**
This function initializes the HMAC-RIPEMD-160 values

\param[in] ctx Pointer to HMAC context.
\param[in] key Array with HMAC key.
\param[in] keyLength Length of HMAC key. Must be > 0.
\param[out] ctx Pointer to HMAC context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacRipemd160_Init(
    EscHmacRipemd160_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength );

/**
This function updates HMAC context for a block of data.

\param[in] ctx Pointer to input HMAC-RIPEMD context.
\param[in] message Array of input data chunk.
\param[in] messageLength Length in number of bytes of input data chunk.
\param[out] ctx Pointer to updated HMAC-RIPEMD context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacRipemd160_Update(
    EscHmacRipemd160_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
This function does the final wrap-up and returns the HMAC.

\param[in] ctx Pointer to the context.
\param[out] mac Buffer to store HMAC value of macLength bytes. Can be the same as the message buffer.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                      This parameter can be used to truncate the MAC such that only
                      the first bytes are copied to the output buffer. The length must
                      not be zero and must not exceed the maximum MAC size
                      EscHmacRipemd160_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacRipemd160_Finish(
    EscHmacRipemd160_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
This function calculates the HMAC based on RIPEMD-160 for the input data.

\param[in] key Secret MAC key.
\param[in] keyLength Length of key in bytes. Must be > 0.
\param[in] message Data to be authenticated with the MAC.
\param[in] messageLength Length of data in bytes.
\param[out] mac Buffer to write the MAC to.
\param[in] macLength The desired Length of the output HMAC stored in buffer "mac".
                      This parameter can be used to truncate the MAC such that only
                      the first bytes are copied to the output buffer. The length must
                      not be zero and must not exceed the maximum MAC size
                      EscHmacRipemd160_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHmacRipemd160_Calc(
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
