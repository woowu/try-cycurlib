/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-GCM implementation (Galois/Counter Mode)

   \see NIST Special Publication 800-38D
   csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

   \see _aes.h

   The following papers and standards are referenced:
   - The Galois/Counter Mode of Operation (GCM), David A. McGrew and John Viega

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_GCM_H_
#define ESC_AES_GCM_H_

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

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscAesGcm_USE_TABLES
/** Increases speed significantly on costs of two tables of overall 4-5KB */
#       define EscAesGcm_USE_TABLES 1
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscAesGcm_USE_TABLES
/** Increases size significantly on costs of speed */
#       define EscAesGcm_USE_TABLES 0
#   endif
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Context in GCM mode for the blockwise operation. */
typedef struct
{
    /** AES Context */
    EscAes_ContextT aesCtx;
    /** The hash subkey */
    Esc_UINT8 H[EscAes_BLOCK_BYTES];
#if EscAesGcm_USE_TABLES == 1
    /** The hash subkey table */
    Esc_UINT8 M0[256U][EscAes_BLOCK_BYTES];
#endif
    /** The counter block */
    Esc_UINT8 counter[EscAes_BLOCK_BYTES];
    /** The first encrypted counter block */
    Esc_UINT8 first[EscAes_BLOCK_BYTES];
    /** Length of the additional authentication data in bytes */
    Esc_UINT32 aadLen;
    /** Current key */
    Esc_UINT8 key[EscAes_BLOCK_BYTES];
    /** Number of bytes in key block used. */
    Esc_UINT8 keyLen;
    /** Intermediate tag, according to the standard, the maximum size is 128 bit */
    Esc_UINT8 tag[EscAes_BLOCK_BYTES];
    /** Intermediate value for tag computation */
    Esc_UINT8 tagBlockPosition;
    /** Length of the payload in bytes */
    Esc_UINT32 payload_length;
    /** Expecting associated data */
    Esc_BOOL aDataFlag;
} EscAesGcm_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function initializes the AES-GCM context. It must be called prior to
 * starting an encryption or decryption.
 *
 * \param[out] ctx      Initialized AES-GCM context
 * \param[in] keyBits   Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key       Key bytes array. The size of the key depends on the keyBits parameter:
 *                      128 bits => 16 bytes
 *                      192 bits => 24 bytes
 *                      256 bits => 32 bytes
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_Init(
    EscAesGcm_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] );

/**
 * Start a new encryption/decryption. The context must have been initialized before calling
 * this function. If this function was executed successfully, the caller can continue
 * with processing additional authenticated data (EscAesGcm_AssociatedData_Update) or with
 * encrypting/decrypting data (EscAesGcm_Encrypt_Update/EscAesGcm_Decrypt_Update).
 *
 * \param[out] ctx      Initialized AES-GCM context
 * \param[in] iv        Initialization vector
 * \param[in] ivLen     Length of the initialization vector in bytes. Must be non-zero.
 *                      NIST recommends to use at most 96 bits for the IV, but the implementation
 *                      does not enforce this.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_startEncryptDecrypt(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 iv[],
    const Esc_UINT32 ivLen );


/**
 * Updates associated data (i.e. data that is authenticated, but not encrypted).
 * If associated data is available this function must be called after EscAesGcm_startEncryptDecrypt,
 * until all associated data is processed. Calling this function is optional, but it
 * cannot be called once the encryption/decryption started
 * (EscAesGcm_Encrypt_Update or EscAesGcm_Decrypt_Update was called).
 *
 * \param[in, out] ctx      AES-GCM context
 * \param[in]      aad      The next block of associated data
 * \param[in]      aadLen   Length of associated data block in byte
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_AssociatedData_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen );

/**
 * Encrypts one or more data blocks.
 *
 * Plaintext can be identical to the cipher pointer.
 *
 * \param[in] ctx    The previous AES GCM context.
 * \param[out] ctx   The updated AES GCM context.
 * \param[in] plain     Plaintext to encrypt.
 * \param[out] cipher   Array to write ciphertext to.
 *                      Has to be the same size as the plaintext array.
 * \param[in] length    Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_Encrypt_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length );

/**
 * This function finishes the encryption, invalidates the context, and returns the authentication tag.
 *
 * \param[in] ctx   The previous AES GCM context.
 * \param[out] ctx  The updated AES GCM context. It is invalid now.
 * \param[out] tag     Array to store the calculated authentication tag.
 * \param[in] tagLen   Number of bytes to write to tag.
 *                     Conforming to NIST 800-38D, only the values 16, 15, 14, 13 and 12 are allowed.
 *                     For certain applications, the tag length may be 8 or 4.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_Encrypt_Finish(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 tag[],
    const Esc_UINT8 tagLen );

/**
 * Decrypts one or more data blocks.
 *
 * Plaintext and can be identical to the cipher pointer.
 *
 * \param[in] ctx    The previous AES GCM context.
 * \param[out] ctx   The updated AES GCM context.
 * \param[out] plain    Array to write decrypted ciphertext to.
 * \param[in] cipher    Ciphertext to decrypt.
 * \param[in] length    Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_Decrypt_Update(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 plain[],
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length );


/**
 * This function finishes the decryption, invalidates the context, and verifies the authentication tag.
 *
 * \param[in] ctx   The previous AES GCM context.
 * \param[out] ctx  The updated AES GCM context. It is invalid now.
 * \param[in] tag      Array of the stored authentication tag.
 * \param[in] tagLen   Size of the tag in bytes.
 *                     Conforming to NIST 800-38D, only the values 16, 15, 14, 13 and 12 are allowed.
 *                     For certain applications, the tag length may be 8 or 4.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \retval Esc_INVALID_MAC if the given tag does not match the computed one.
 */
Esc_ERROR
EscAesGcm_Decrypt_Finish(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 tag[],
    const Esc_UINT8 tagLen );

/**
 * Encrypts one or more data blocks (convenience function to execute all steps at once).
 *
 * \param[in] keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                         128 bits => 16 bytes
 *                         192 bits => 24 bytes
 *                         256 bits => 32 bytes
 * \param[in] iv           Initialization vector.
 * \param[in] ivLen        Length of iv array in bytes.
 * \param[in] aad          Additional authenticated data.
 * \param[in] aadLen       Length of aad array in bytes.
 * \param[in] plain        Plaintext array.
 * \param[in] plainLen     Length of plainText array in bytes.
 * \param[out] cipher      Array to write ciphertext to.
 *                         Has to be the same size as the plainText array.
 * \param[out] tag         Calculated Authentication tag.
 * \param[in] tagLen       Length of authentication tag in bytes.
 *                         Conforming to NIST 800-38D, only the values 16, 15, 14, 13 and 12 are allowed.
 *                         For certain applications, the tag length may be 8 or 4.
 *
 * \note The pointers plainText and cipherText may be the same.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesGcm_Encrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT32 ivLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 cipher[],
    Esc_UINT8 tag[],
    Esc_UINT8 tagLen );

/**
 * Decrypts one or more data blocks (convenience function to execute all steps at once).
 *
 * \param[in] keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                         128 bits => 16 bytes
 *                         192 bits => 24 bytes
 *                         256 bits => 32 bytes
 * \param[in] iv           Initialization vector.
 * \param[in] ivLen        Length of the initialization vector in bytes. Must be non-zero.
 *                         NIST recommends to use at most 96 bits for the IV, but the implementation
 *                         does not enforce this.
 * \param[in] aad          Additional authenticated data.
 * \param[in] aadLen       Length of aad array in bytes.
 * \param[in] cipher       Ciphertext array.
 * \param[in] cipherLen    Length of cipherText array in bytes.
 * \param[out] plain       Array to write decrypted ciphertext to.
 *                         Has to be the same size of the cipherText array.
 * \param[in] tag          Authentication tag to verify.
 * \param[in] tagLen       Length of authentication tag.
 *                         Conforming to NIST 800-38D, only the values 16, 15, 14, 13 and 12 are allowed.
 *                         For certain applications, the tag length may be 8 or 4.
 *
 * \note The pointers plainText and cipherText may be the same.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \retval Esc_INVALID_MAC if the given tag does not match the computed one.
 */
Esc_ERROR
EscAesGcm_Decrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT32 ivLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 plain[],
    const Esc_UINT8 tag[],
    Esc_UINT8 tagLen );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif /* ESC_AES_GCM_H_ */
