/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES implementation (FIPS-197 compliant)
   CTR mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_CTR_H_
#define ESC_AES_CTR_H_

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

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** AES context in CTR mode. */
typedef struct
{
    /** Context */
    EscAes_ContextT aesCtx;

    /** The length of the counter in bytes. */
    Esc_UINT8 counterBytes;

    /** 128-bit initialization vector. */
    Esc_UINT8 iv[EscAes_IV_BYTES];

    /** keyStream */
    Esc_UINT8 keyStream[EscAes_BLOCK_BYTES];

    /** counter for remaining unused KeyStream */
    Esc_UINT8 keyStreamCounter;

} EscAesCtr_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the CTR Context with the corresponding AES key.

The form of the IV is nonce|counter.

The nonce consists of the IVs bytes at indices 0..(nonceLength-1).
The IV bytes at indices nonceLength..(EscAes_IV_BYTES-1) set the initial
counter value having the least significant byte at position EscAes_IV_BYTES-1.

\param[out] ctx The AES CTR context.
\param[in] keyBits Bit length of the AES key. Can be 128, 192 or 256.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
               128 bits => 16 bytes
               192 bits => 24 bytes
               256 bits => 32 bytes
\param[in] iv IV consisting of the nonce and the initial counter value. Length must be EscAes_IV_BYTES.
\param[in] nonceLength The length of the nonce in byte. Can be 0..EscAes_IV_BYTES-1.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCtr_Init(
    EscAesCtr_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT8 nonceLength );

/**
Applies AES CTR mode to the data.

The same function can be applied for encryption and decryption.

For encryption, source is the plaintext and dest the resulting ciphertext.

For decryption, source is the ciphertext and dest the resulting plaintext.
Decrypts/Encrypts arbitrary length data in CTR mode and updates the AES context.

The context must be initialized with EscAesCtr_Init.

\param[in] ctx The previous AES CTR context.
\param[out] ctx The updated AES CTR context.
\param[in] source Plaintext for encryption, ciphertext for encryption.
\param[out] dest Ciphertext for encryption, plaintext for decryption.
\param[in] length Length of data to be encrypted/decrypted in bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCtr_Apply(
    EscAesCtr_ContextT* ctx,
    const Esc_UINT8 source[],
    Esc_UINT8 dest[],
    Esc_UINT32 length );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
