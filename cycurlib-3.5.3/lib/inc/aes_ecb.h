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
   ECB-Mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_ECB_H_
#define ESC_AES_ECB_H_

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

/** AES context ECB. */
typedef EscAes_ContextT EscAesEcb_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the ECB Context with the corresponding AES key.

\param[out] ctx The AES ECB context.
\param[in] keyBits Bit length of the AES key. Can be 128, 192 or 256.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                192 bits => 24 bytes
                256 bits => 32 bytes

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesEcb_Init(
    EscAesEcb_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] );

/**
Encrypts one or more data blocks in ECB mode.
This function can be called several times in order to split the encryption of large data blocks.

The context must be initialized with EscAesEcb_Init.

Plain pointer can be the same as cipher pointer.

\param[in] ctx The AES ECB context.
\param[in] plain Plaintext to encrypt.
\param[out] cipher Array to write ciphertext to.
\param[in] length Length of plain and cipher data in bytes. Has to be multiple of EscAes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesEcb_Encrypt(
    const EscAesEcb_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length );


/**
Decrypts one or more data blocks in ECB mode.
This function can be called several times in order to split the decryption of large data blocks.

The context must be initialized with EscAesEcb_Init.
Plain pointer can be the same as cipher pointer.

\param[in] ctx The AES ECB context.
\param[in] cipher Cipher data bytes array.
\param[out] plain Will contain the plaintext after the function call.
\param[in] length Length of plain and cipher data in bytes. Has to be multiple of EscAes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesEcb_Decrypt(
    const EscAesEcb_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
