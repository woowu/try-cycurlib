/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHE AES-MP & KDF implementation

   \see         SHE functional specification v1.1 01.04.2009

   Based on AES-128.

   $Rev$
 */
/***************************************************************************/

#ifndef ESC_SHE_MP_H_
#define ESC_SHE_MP_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_aes.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** constant for KEY_UPDATE_ENC */
#define EscShe_KEY_UPDATE_ENC_C      ((Esc_UINT8)0x01)
/** constant for KEY_UPDATE_MAC */
#define EscShe_KEY_UPDATE_MAC_C      ((Esc_UINT8)0x02)
/** constant for DEBUG_KEY */
#define EscShe_DEBUG_KEY_C           ((Esc_UINT8)0x03)
/** constant for PRNG_KEY */
#define EscShe_PRNG_KEY_C            ((Esc_UINT8)0x04)
/** constant for PRNG_SEED_KEY */
#define EscShe_PRNG_SEED_KEY_C       ((Esc_UINT8)0x05)

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function calculates the compression function as specified in the
 * SHE functional specification using the Miyaguchi Preneel construction.
 * The input message will be padded and split into blocks automatically.
 *
 * \param[in] message    The message to be compressed.
 * \param[in] bitLength  The size of the message in bits, does not need to
 *                       be aligned to full bytes.
 * \param[out] digest    The final output of the compression function.
 *
 * \return Esc_NO_ERROR if everything is fine.
 */
Esc_ERROR
EscSheMpComp(
    const Esc_UINT8 message[],
    const Esc_UINT32 bitLength,
    Esc_UINT8 digest[16]);

/**
 * This function calculates the key derivation as specified in the
 * SHE functional specification as KDF(K, C) = AES-MP(K | C).
 *
 * \param [in] key      The input key for the key derivation function.
 *                      Has to be 128 bit / 16 bytes in size.
 * \param [in] type     The type of input key as one of the constants.
 * \param [out] derived The derived key as a 16 byte array.
 *
 * \return Esc_NO_ERROR if everything is fine.
 */
Esc_ERROR
EscSheMpKdf(
    const Esc_UINT8 key[16],
    const Esc_UINT8 type,
    Esc_UINT8 derived[16]);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
