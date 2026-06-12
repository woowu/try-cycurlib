/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       3-DES implementation CBC mode
   \see FIPS PUB 46-3

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_DES3_CBC_H_
#define ESC_DES3_CBC_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "des3_ecb.h"

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

/** DES context CBC. */
typedef struct
{
    /** Context in ECB mode. */
    EscDes3Ecb_ContextT ecbCtx;

    /** 64-bit initialization vector   */
    Esc_UINT8 iv[EscDes_BLOCK_BYTES];
} EscDes3Cbc_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the CBC Context with the corresponding DES key and IV.

This function does not check the key for weaknesses nor does it
check the parity bits.

To check if a key is a known weak key, use the function EscDesKeytest_IsKeyWeak().
\see des_keytest.h

\param[out] cbcCtx The DES CBC context.
\param[in] key1 TDEA Key1. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] key2 TDEA Key2. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] key3 TDEA Key3. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] iv 64-bit initialization vector. Array of EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Cbc_Init(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[],
    const Esc_UINT8 key3[],
    const Esc_UINT8 iv[] );

/**
Decrypts one or more data blocks and updates the DES context.

The context must be initialized with EscDes3Cbc_Init.
Plain pointer can be the same as cipher pointer.

\param[in] cbcCtx The previous DES CBC context.
\param[out] cbcCtx The updated DES CBC context.
\param[in] cipher Cipher data bytes array.
\param[out] plain Will contain the plaintext after the function call.
\param[in] length Length of plain and cipher data in bytes. Has to be multiple of EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Cbc_Decrypt(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length );

/**
Encrypts one or more data blocks and updates the DES context.

The context must be initialized with EscDes3Cbc_Init.

plain pointer can be the same as cipher pointer.

\param[in] cbcCtx The previous DES CBC context.
\param[out] cbcCtx The updated DES CBC context.
\param[in] plain Plaintext to encrypt.
\param[out] cipher Array to write ciphertext to.
\param[in] length Length of plain and cipher data in bytes. Has to be multiple of EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Cbc_Encrypt(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length );

/**
Sets a new IV for the DES3 CBC context.

\param[out] cbcCtx The DES3 CBC context.
\param[in] iv 64-bit initialization vector. Array of EscDes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscDes3Cbc_SetIV(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 iv[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
