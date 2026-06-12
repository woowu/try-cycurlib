/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Blowfish implementation ECB mode
   \see         www.schneier.com/blowfish.html

   $Rev: 1458 $
 */
/***************************************************************************/

#ifndef ESC_BLOWFISH_ECB_H_
#define ESC_BLOWFISH_ECB_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_blowfish.h"

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

/** Blowfish context ECB. */
typedef struct
{
    /** The computed key. */
    EscBfish_KeySchedT sched;
} EscBfishEcb_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the ECB Context with the corresponding Blowfish key.

\param[out] ecbCtx The Blowfish ECB context.
\param[in] key Key bytes array. Array of size keyLen.
\param[in] keyLen The key length in bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscBfishEcb_Init(
    EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 key[],
    const Esc_UINT8 keyLen );

/**
Encrypts one Blowfish block in ECB mode.

Block size is EscBfish_BLOCK_BYTES.
The context must be initialized with EscBfishEcb_Init.

The parameters plain and cipher can point to the same location.

\param[in] ecbCtx Context initialized with EscBfishEcb_Init.
\param[in] plain Plaintext to encrypt. Must be exactly EscBfish_BLOCK_BYTES bytes.
\param[out] cipher Encrypted plaintext. Must be exactly EscBfish_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscBfishEcb_Encrypt(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] );

/**
Decrypts one Blowfish block in ECB mode.

Block size is EscBfish_BLOCK_BYTES.
The context must be initialized with EscBfishEcb_Init.

The parameters plain and cipher can point to the same location.

\param[in] ecbCtx Context initialized with EscBfishEcb_Init.
\param[in] cipher Ciphertext to decrypt. Must be exactly EscBfish_BLOCK_BYTES bytes.
\param[out] plain Decrypted ciphertext. Must be exactly EscBfish_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscBfishEcb_Decrypt(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] );

/**
Encrypts one Blowfish block in ECB mode.

Block size is EscBfish_BLOCK_BYTES.
The context must be initialized with EscBfishEcb_Init.

The parameters plain and cipher can point to the same location.

This function performs no parameter check and is intended for internal use.

\param[in] ecbCtx Context initialized with EscBfishEcb_Init.
\param[in] plain Plaintext to encrypt. Must be exactly EscBfish_BLOCK_BYTES bytes.
\param[out] cipher Encrypted plaintext. Must be exactly EscBfish_BLOCK_BYTES bytes.
*/
void
EscBfishEcb_EncryptFast(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] );

/**
Decrypts one Blowfish block in ECB mode.

Block size is EscBfish_BLOCK_BYTES.
The context must be initialized with EscBfishEcb_Init.

The parameters plain and cipher can point to the same location.

This function performs no parameter check and is intended for internal use.

\param[in] ecbCtx Context initialized with EscBfishEcb_Init.
\param[in] cipher Ciphertext to decrypt. Must be exactly EscBfish_BLOCK_BYTES bytes.
\param[out] plain Decrypted ciphertext. Must be exactly EscBfish_BLOCK_BYTES bytes.
*/
void
EscBfishEcb_DecryptFast(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif /* ESC_BLOWFISH_ECB_H_ */
