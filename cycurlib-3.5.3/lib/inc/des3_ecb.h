/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       3-DES implementation ECB mode

   \see FIPS PUB 46-3

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_DES3_ECB_H_
#define ESC_DES3_ECB_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_des.h"

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

/** 3-DES context ECB. */
typedef struct
{
    /** The key schedule for key K1. */
    EscDes_KeySchedT sched1;
    /** The key schedule for key K2. */
    EscDes_KeySchedT sched2;
    /** The key schedule for key K3. */
    EscDes_KeySchedT sched3;
} EscDes3Ecb_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the ECB Context with the corresponding 3-DES key.

This function does not check the key for weaknesses nor does it
check the parity bits.

To check if a key is a known weak key, use the function EscDesKeytest_IsKeyWeak().
\see des_keytest.h

\param[out] ecbCtx The 3-DES ECB context.
\param[in] key1 TDEA Key1. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] key2 TDEA Key2. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] key3 TDEA Key3. Key bytes array. Array of size EscDes_KEY_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Ecb_Init(
    EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[],
    const Esc_UINT8 key3[] );

/**
Encrypts one 3-DES block in ECB mode.

Performs the TDEA encryption operation:<BR>
I - DES_E_K1 - DES_D_K2 - DES_E_K3 - O

Block size is EscDes_BLOCK_BYTES.
The context must be initialized with EscDes3Ecb_Init.

The parameters plain and cipher can point to the same location.

\param[in] ecbCtx Context initialized with EscDes3Ecb_Init.
\param[in] plain Plaintext to encrypt. Must be exactly EscDes_BLOCK_BYTES bytes.
\param[out] cipher Encrypted plaintext. Must be exactly EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Ecb_Encrypt(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] );

/**
Decrypts one 3-DES block in ECB mode.

Performs the TDEA encryption operation:<BR>
I - DES_D_K3 - DES_E_K2 - DES_D_K1 - O

Block size is EscDes_BLOCK_BYTES.
The context must be initialized with EscDes3Ecb_Init.

The parameters plain and cipher can point to the same location.

\param[in] ecbCtx Context initialized with EscDes3Ecb_Init.
\param[in] cipher Ciphertext to decrypt. Must be exactly EscDes_BLOCK_BYTES bytes.
\param[out] plain Decrypted ciphertext. Must be exactly EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Ecb_Decrypt(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] );

/**
Encrypts one 3-DES block in ECB mode.

Performs the TDEA encryption operation:<BR>
I - DES_E_K1 - DES_D_K2 - DES_E_K3 - O

Block size is EscDes_BLOCK_BYTES.
The context must be initialized with EscDes3Ecb_Init.

The parameters plain and cipher can point to the same location.

This function performs no parameter check and is intended for internal use.

\param[in] ecbCtx Context initialized with EscDes3Ecb_Init.
\param[in] plain Plaintext to encrypt. Must be exactly EscDes_BLOCK_BYTES bytes.
\param[out] cipher Encrypted plaintext. Must be exactly EscDes_BLOCK_BYTES bytes.
*/
void
EscDes3Ecb_EncryptFast(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] );

/**
Decrypts one 3-DES block in ECB mode.

Performs the TDEA encryption operation:<BR>
I - DES_D_K3 - DES_E_K2 - DES_D_K1 - O

Block size is EscDes_BLOCK_BYTES.
The context must be initialized with EscDes3Ecb_Init.

The parameters plain and cipher can point to the same location.

This function performs no parameter check and is intended for internal use.

\param[in] ecbCtx Context initialized with EscDes3Ecb_Init.
\param[in] cipher Ciphertext to decrypt. Must be exactly EscDes_BLOCK_BYTES bytes.
\param[out] plain Decrypted ciphertext. Must be exactly EscDes_BLOCK_BYTES bytes.
*/
void
EscDes3Ecb_DecryptFast(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
