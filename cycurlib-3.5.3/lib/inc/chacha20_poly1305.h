/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file        chacha20_poly1305.h

   \brief       ChaCha20_Poly1305 implementation, according to RFC-7539.

   \see RFC-7539

   $Rev: 0001 $
 */
/***************************************************************************/

#ifndef ESC_CHACHA20_POLY1305_H_
#define ESC_CHACHA20_POLY1305_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "chacha20.h"
#include "poly1305.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/


/** Length of key in bytes. */
#define EscChaCha20Poly1305_KEY_BYTES 32U

/** Length of the nonce in bytes. */
#define EscChaCha20Poly1305_NONCE_BYTES 12U

/** Length of the tag in bytes. */
#define EscChaCha20Poly1305_TAG_BYTES 16U

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
* 5. TYPE DEFINITIONS                                                      *
***************************************************************************/

/** State enum for ChaCha20 Poly1305 */
typedef enum
{
    CHACHA20_POLY1305_START,
    CHACHA20_POLY1305_UPDATE_AAD,
    CHACHA20_POLY1305_UPDATE_ENCRYPT,
    CHACHA20_POLY1305_UPDATE_DECRYPT,
    CHACHA20_POLY1305_INVALID
} EscChaCha20_StateT;

/** Context for ChaCha20 Poly1305 */
typedef struct
{
    /** Internal ChaCha20 state. */
    EscChaCha20_ContextT ctx_c;

    /** Internal Poly1305 state */
    EscPoly1305_ContextT ctx_p;

    /** Counter for length of aad as high and low nibble */
    Esc_UINT32 aadLen[2];

    /** Counter for length of plaintext as high and low nibble */
    Esc_UINT32 plaintextLength[2];

    /** Used ChaCha20 key */
    Esc_UINT8 key[EscChaCha20Poly1305_KEY_BYTES];

    /** Current state of ChaCha20_Poly1305 construct */
    EscChaCha20_StateT state;
} EscChaCha20Poly1305_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function generates the Poly1305 key using ChaCha20 according to RFC-7539, Section 2.6.
 *
 *
 * \param[in] key              Pointer to 32 byte / 256 bit chacha20 key.
 * \param[in] nonce            Pointer to 12 byte / 96 bit nonce. MUST be unique for every call with the same key!
 *                             Therefore it MUST NOT be randomly generated, instead a counter is recommended here.
 * \param[out] polyKey         Pointer to 32 byte / 256 bit memory allocated for the PolyKey output.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
*/
Esc_ERROR
EscChaCha20Poly1305_KeyGen(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 polyKey[] );

/**
 * This function initializes the ChaCha20-Poly1305 context. It must be called prior to
 * starting an encryption or decryption.
 *
 * \param[in,out] ctx       Initialized ChaCha20Poly1305 context
 * \param[in] key           Key bytes array with 32 byte / 256 bit ChaCha20 key.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 */
Esc_ERROR
EscChaCha20Poly1305_Init(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 key[] );

/**
 * Start a new encryption/decryption. The context must have been initialized before calling
 * this function. If this function was executed successfully, the caller can continue
 * with processing additional authenticated data (EscChaCha20Poly1305_AssociatedData_Update)
 * or with encrypting/decrypting data (EscChaCha20Poly1305_Encrypt_Update/EscChaCha20Poly1305_Decrypt_Update).
 *
 * \param[in, out] ctx  Initialized ChaCha20Poly1305 context
 * \param[in] nonce     Pointer to 12 byte / 96 bit nonce. MUST be unique for every call with the same key!
 *                      Therefore it MUST NOT be randomly generated, instead a counter is recommended here.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */
Esc_ERROR
EscChaCha20Poly1305_startEncryptDecrypt(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 nonce[] );

/**
 * Updates associated data (i.e. data that is authenticated, but not encrypted).
 * If associated data is available this function must be called after EscChaCha20Poly1305_startEncryptDecrypt,
 * until all associated data is processed. Calling this function is optional, but it
 * cannot be called once the encryption/decryption started
 * (EscChaCha20Poly1305_Encrypt_Update or EscChaCha20Poly1305_Decrypt_Update was called).
 *
 * \param[in, out] ctx      ChaCha20-Poly1305 context
 * \param[in]      aad      The next block of associated data
 * \param[in]      aadLen   Length of associated data block in byte
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_OUT_OF_RANGE if more than 2^64 associated data bytes have been added.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */
Esc_ERROR
EscChaCha20Poly1305_UpdateAad(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen );

/**
 * Encrypts one or more data blocks.
 *
 * Plaintext can be identical to the cipher pointer.
 *
 * \param[in, out] ctx  ChaCha20-Poly1305 context
 * \param[in] plain     Plaintext to encrypt.
 * \param[out] cipher   Array to write ciphertext to.
 *                      Has to be the same size as the plaintext array.
 * \param[in] length    Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_OUT_OF_RANGE if more than 256 GB data bytes have been encrypted.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */
Esc_ERROR
EscChaCha20Poly1305_Encrypt_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length );

/**
 * This function finishes the encryption, invalidates the context, and returns the authentication tag.
 *
 * \param[in, out] ctx The ChaCha20-Poly1305 context.
 * \param[out] tag     Array to store the calculated authentication tag.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */

Esc_ERROR
EscChaCha20Poly1305_Encrypt_Finish(
    EscChaCha20Poly1305_ContextT* ctx,
    Esc_UINT8 tag[] );

/**
 * Decrypts one or more data blocks.
 *
 * Ciphertext can be identical to the plain pointer.
 *
 * \param[in, out] ctx  ChaCha20-Poly1305 context
 * \param[in] cipher    Ciphertext to decrypt.
 * \param[out] plain    Array to write plaintext to.
 *                      Has to be the same size as the ciphertext array.
 * \param[in] length    Length of cipher and plain data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_OUT_OF_RANGE if more than 256 GB data bytes have been decrypted.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */
Esc_ERROR
EscChaCha20Poly1305_Decrypt_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    const Esc_UINT32 length );

/**
 * This function finishes the decryption, invalidates the context, and verifies the authentication tag.
 *
 * \param[in, out] ctx  ChaCha20-Poly1305 context
 * \param[in] tag       Array of the stored authentication tag.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \retval Esc_INVALID_MAC if the given tag does not match the computed one.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if the context is in an invalid state for this operation.
 */
Esc_ERROR
EscChaCha20Poly1305_Decrypt_Finish(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 tag[] );


/**
 * This function calculates ciphertext and message tag using CHACHA20_POLY1305 according to RFC-7539.
 * In-place encryption is supported (i.e. plaintext is overwritten with ciphertext if the same array is passed for both).
 *
 *
 * \param[in] key       Pointer to 32 byte / 256 bit chacha20 key.
 * \param[in] nonce     Pointer to 12 byte / 96 bit nonce. MUST be unique for every call with the same key!
 *                      Therefore it MUST NOT be randomly generated, instead a counter is recommended here.
 * \param[in] aad       Pointer to byte array containing the additional authenticated data.
 * \param[in] aadLen    Additional authenticated data length in bytes.
 * \param[in] plain     Pointer to byte array containing the plaintext.
 * \param[in] length    Plaintext length in bytes.
 * \param[out] cipher   Pointer to memory allocated for ChaCha20 encrypted ciphertext, same size as plaintext.
 * \param[out] tag      Pointer to memory allocated for 16 byte / 128 bit Poly1305 calculated message tag.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
*/
Esc_ERROR
EscChaCha20Poly1305_Encrypt(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    const Esc_UINT32 length,
    Esc_UINT8 cipher[],
    Esc_UINT8 tag[] );

/**
 * This function decrypts and verifies the given ciphertext and message tag using CHACHA20_POLY1305 according to RFC-7539.
 * In-place decryption is supported (i.e. ciphertext is overwritten with plaintext if the same array is passed for both).
 *
 * \param[in] key       Pointer to 32 byte / 256 bit chacha20 key.
 * \param[in] nonce     Pointer to 12 byte / 96 bit nonce.
 * \param[in] aad       Pointer to byte array containing the additional authenticated data.
 * \param[in] aadLen    Additional authenticated data length in bytes.
 * \param[in] cipher    Pointer to byte array containing the ciphertext.
 * \param[in] length    Ciphertext length in bytes.
 * \param[out] plain    Pointer to memory allocated for ChaCha20 decrypted plaintext, same size as ciphertext.
 * \param[in] tag       Pointer to 16 byte / 128 bit message tag.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_NULL_POINTER_ERROR if an input parameter is NULL.
 * \return Esc_INVALID_MAC if the message tag verification failed.
*/
Esc_ERROR
EscChaCha20Poly1305_Decrypt(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen,
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length,
    Esc_UINT8 plain[],
    const Esc_UINT8 tag[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
