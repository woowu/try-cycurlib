/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-XTS implementation

   \see         IEEE 1619

   Key sizes of 128 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_XTS_H_
#define ESC_AES_XTS_H_

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

/** AES context in XTS mode. */
typedef struct
{
    /** Context 1 */
    EscAes_ContextT ctx1;

    /** Context 2 */
    EscAes_ContextT ctx2;
} EscAesXts_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the AES-XTS Context with the corresponding AES keys.

\param[out] ctx The AES XTS context.
\param[in] keyBits Bit length of the AES key. Can be 128 or 256.
\param[in] key1 First key byte array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                256 bits => 32 bytes
\param[in] key2 Second key byte array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                256 bits => 32 bytes

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesXts_Init(
    EscAesXts_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[] );

/**
Decrypts one data unit (i.e., sector).

The context must be initialized with EscAesXts_Init.

\param[in] ctx initialized AES XTS context.
\param[in] cipher Ciphertext to decrypt.
\param[out] plain Array to write plaintext to encrypt.
\param[in] length Length of plain and cipher data in bytes. Has to be at least EscAes_BLOCK_BYTES bytes.
\param[in] tweak tweak value. Array of size EscAes_BLOCK_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesXts_Decrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length,
    const Esc_UINT8 tweak[] );

#if Esc_HAS_INT64 == 1
/**
Decrypts one data unit (i.e., sector) based on the sector number.

The context must be initialized with EscAesXts_Init.

plain pointer and cipher pointer may not overlap.

\param[in] ctx initialized AES XTS context.
\param[in] cipher Ciphertext to decrypt.
\param[out] plain Array to write plaintext to encrypt.
\param[in] length Length of plain and cipher data in bytes. Has to be at least EscAes_BLOCK_BYTES bytes.
\param[in] data_unit_number sector number.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesXts_DecryptSector(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length,
    Esc_UINT64 data_unit_number );

#endif

/**
Encrypts one data unit (i.e., sector).

The context must be initialized with EscAesXts_Init.

\param[in] ctx initialized AES XTS context.
\param[in] plain Plaintext to encrypt.
\param[out] cipher Array to write ciphertext to.
\param[in] length Length of plain and cipher data in bytes. Has to be at least EscAes_BLOCK_BYTES bytes.
\param[in] tweak tweak value. Array of size EscAes_BLOCK_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesXts_Encrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length,
    const Esc_UINT8 tweak[] );

#if Esc_HAS_INT64 == 1
/**
Encrypts one data unit (i.e., sector) based on the sector number.

The context must be initialized with EscAesXts_Init.

plain pointer and cipher pointer may not overlap.

\param[in] ctx initialized AES XTS context.
\param[in] plain Plaintext to encrypt.
\param[out] cipher Array to write ciphertext to.
\param[in] length Length of plain and cipher data in bytes. Has to be at least EscAes_BLOCK_BYTES bytes.
\param[in] data_unit_number sector number.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesXts_EncryptSector(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length,
    Esc_UINT64 data_unit_number );

#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_AES_XTS_H_ */
