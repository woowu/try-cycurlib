/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       EAX implementation based on AES.

   \see         NIST SP 800-38B

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3678 $
 */
/***************************************************************************/

#ifndef ESC_EAX_AES_H_
#define ESC_EAX_AES_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_aes.h"
#include "cmac_aes.h"
#include "aes_ctr.h"
#include "mem_mgt.h"

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

/** Context in EAX mode for the blockwise operation. */
typedef struct
{
    /** Current key */
    Esc_UINT8 key[EscAes_MAX_KEY_BYTES];
    /** Length of the key and macStartingArray in bytes */
    Esc_UINT32 keyLen;
    /** Length of the tag in bytes. */
    Esc_UINT8 tagLen;
    /** aes_ctr context */
    EscAesCtr_ContextT aesCtrCtx;
    /** cmac_aes context for nonce */
    EscCmacAes_ContextT cmacAesCtxNonce;
    /** cmac_aes context for ciphertext */
    EscCmacAes_ContextT cmacAesCtxCipher;
    /** cmac_aes context for header */
    EscCmacAes_ContextT cmacAesCtxHeader;
    /** Mac for nonce */
    Esc_UINT8 macNonce[EscAes_BLOCK_BYTES];
    /** Mac for header */
    Esc_UINT8 macHeader[EscAes_BLOCK_BYTES];
    /** All data for nonce updated */
    Esc_BOOL nonceFinished;
    /** All data for header updated */
    Esc_BOOL headerFinished;
    /** All data for payload updated */
    Esc_BOOL payloadFinished;
} EscAesEax_ContextT;


/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function initializes the AES-EAX context to set a key.
 * It is the first function which must be called for encryption/decryption with AES-EAX.
 *
 * \param[out] ctx          Initialized AES-EAX context
 * \param[in]  keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in]  key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                          128 bits => 16 bytes
 *                          192 bits => 24 bytes
 *                          256 bits => 32 bytes
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Init(
    EscAesEax_ContextT* ctx,
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[] );

/**
 * Start a new encryption or decryption. The context must have been initialized
 * with EscAesEax_Init() before calling this function.
 *
 * \param[out] ctx          Initialized AES-EAX context
 * \param[in]  tagLen       Length of the tag in bytes.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_startEncryptDecrypt(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 tagLen );

/**
 * Updates nonce
 * If nonce is available this function must be called after EscAesEax_startEncryptDecrypt,
 * until all nonce data is processed
 *
 * \param[in, out] ctx      AES-EAX context
 * \param[in]  nonce      The next block of associated data
 * \param[in]  nonceLen   Length of associated data block in byte
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Nonce_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen );

/**
 * Generates the Message Authentication Code over nonce
 * Result is stored in the internal field of the AES_EAX context
 * Must be called after final call of EscAesEax_Nonce_Update
 *
 * \param[in]  ctx      AES-EAX context
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Nonce_Finish(
    EscAesEax_ContextT* ctx );

/**
 * Updates header
 * If header is available this function must be called after EscAesEax_startEncryptDecrypt,
 * until all header data is processed
 *
 * \param[in, out] ctx      AES-EAX context
 * \param[in]  header      The next block of associated data
 * \param[in]  headerLen   Length of associated data block in byte
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Header_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen );

/**
 * Generates the Message Authentication Code over header
 * Result is stored in the internal field of the AES_EAX context
 * Must be called after final call of EscAesEax_Header_Update
 *
 * \param[in]  ctx      AES-EAX context
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Header_Finish(
    EscAesEax_ContextT* ctx );

/**
 * Encrypts data
 * Must be called after EscAesEax_Nonce_Finish and EscAesEax_Header_Finish until all data is encrypted
 *
 * \param[in, out] ctx  AES-EAX context
 * \param[in] plain     Plaintext to encrypt, might be NULL if length is zero
 * \param[out] cipher   Array to write ciphertext to.
 *                      Has to be the same size as the plaintext array.
 * \param[in] length    Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Encrypt_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length );

/**
 * Finishes the encryption and generates the Message Authentication Code
 * Must be called after final call of EscAesEax_Encrypt_Update
 *
 * \param[in]  ctx          AES-EAX context
 * \param[out] macTag       Array to store the calculated authentication tag
 * \param[in]  macTagLen    Length of a MAC tag.
 *                          Has to be same size as the MAC length given in start encrypt/decrypt function.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Encrypt_Finish(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen );

/**
 * Decrypts data
 * Must be called after EscAesEax_Nonce_Finish and EscAesEax_Header_Finish until all data is decrypted
 *
 * \param[in, out] ctx      AES-EAX context
 * \param[in]      cipher   Cipher block to decrypt, might be NULL if length is zero
 * \param[out]     plain    Array to write decrypted ciphertext to
 *                          Has to be the same size as the plaintext array
 * \param[in]      length   Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Decrypt_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length );

/**
 * Finishes the decryption and verifies a Message Authentication Code
 * Must be called after final call of EscAesEax_Decrypt_Update
 *
 * \param[in]  ctx          AES-EAX context
 * \param[in]  macTag       MAC tag
 * \param[in]  macTagLen    Length of a MAC tag.
 *                          Has to be same size as the MAC length given in start encrypt/decrypt function.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_INVALID_MAC if the given tag does not match the computed one.
 */
Esc_ERROR
EscAesEax_Decrypt_Finish(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen );

/**
 * Encrypts one or more data blocks.
 *
 * \param[in] keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                         128 bits => 16 bytes
 *                         192 bits => 24 bytes
 *                         256 bits => 32 bytes
 * \param[in] nonce        The nonce used in the decryption.
 * \param[in] nonceLen     Length of nonce in bytes.
 * \param[in] header       Additional authenticated data.
 * \param[in] headerLen    Length of header array in bytes.
 * \param[in] plain        Plaintext array.
 * \param[in] plainLen     Length of plainText array in bytes.
 * \param[in] tagLen       Length of the tag in bytes.
 * \param[out] cipher      Array to store ciphertext and tag to.
 *                         The array has to be at least (plaintextLen + tagLen) bytes.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesEax_Encrypt(
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 cipher[] );

/**
 * Decrypts one or more data blocks and check the appended MAC for validity.
 * The decrypted plaintext is written to the plainText array even if the MAC
 * is not valid. Nevertheless, in such a case the error Esc_INVALID_MAC
 * is returned.
 *
 * \param[in] keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                         128 bits => 16 bytes
 *                         192 bits => 24 bytes
 *                         256 bits => 32 bytes
 * \param[in] nonce        The nonce used in the decryption.
 * \param[in] nonceLen     Length of nonce in bytes.
 * \param[in] header       Additional authenticated data.
 * \param[in] headerLen    Length of header array in bytes.
 * \param[in] cipher       Ciphertext array.
 * \param[in] cipherLen    Length of cipherText array in bytes.
 * \param[in] tagLen       Length of the tag in bytes.
 * \param[out] plain       Array to store plaintext to.
 *                         The array has to be at least (cipherLen - tagLen) bytes.
 *
 * \return Esc_NO_ERROR if everything works fine or invalid MAC.
*/
Esc_ERROR
EscAesEax_Decrypt(
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 plain[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
