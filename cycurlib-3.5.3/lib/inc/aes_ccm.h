/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief   AES implementation (FIPS-197 compliant)
            CCM-Mode (NIST Special Publication 800-38C)

   \see     NIST SP 800-38C


  $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_CCM_H_
#define ESC_AES_CCM_H_

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

/** Size of the used blocks - see NIST SP 800-38C */
#define EscAesCcm_BLOCKSIZE 16U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Context in CCM mode for the blockwise operation. */
typedef struct
{
    /** Length of the plaintext */
    Esc_UINT32 plainLen;
    /** Pointer to nonce array */
    const Esc_UINT8* nonce;
    /** Length of the nonce in bytes. Can take the following values:
        7, 8, 9, 10, 11, 12, 13, whereby the maximum of q + len_nonce is 15 */
    Esc_UINT8 nonceLen;
    /** Length of the associated data */
    Esc_UINT32 aadLen;
    /** Length of the tag in byte. Can take the following values:
        4, 6, 8, 10, 12, 14, 16 */
    Esc_UINT8 tagLen;
    /** Aes context */
    EscAes_ContextT aesCtx;
    /** Block for S0 */
    Esc_UINT8 S0[EscAesCcm_BLOCKSIZE];
    /** dataLen can be represented in q bytes, q = 2, 3 or 4 */
    Esc_UINT8 q;
    /** Block for Y_r */
    Esc_UINT8 Yr[EscAesCcm_BLOCKSIZE];
    /** Number of bytes in Yr used */
    Esc_UINT8 YrLen;
    /** Used data */
    Esc_UINT32 usedData;
    /** Previous counter block */
    Esc_UINT8 CtrI[EscAesCcm_BLOCKSIZE];
    /** Expecting associated data */
    Esc_BOOL aDataFlag;
} EscAesCcm_ContextT;


/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function initializes the AES-CCM context to set a key.
 * It is the first function which must be called for encryption/decryption with AES-CCM.
 *
 * \param[out] ctx          Initialized AES-CCM context
 * \param[in]  keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in]  key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                          128 bits => 16 bytes
 *                          192 bits => 24 bytes
 *                          256 bits => 32 bytes
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_Init(
    EscAesCcm_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[]);

/**
 * Start a new encryption or decryption. The context must have been initialized
 * with EscAesCcm_Init() before calling this function.
 *
 * \param[out] ctx          Initialized AES-CCM context
 * \param[in]  nonce        Nonce
 * \param[in]  nonceLen     Length of the nonce in bytes. Can take the following values:
 *                          7, 8, 9, 10, 11, 12, 13, whereby the maximum of q + len_nonce is 15
 *                          where q is the number of bytes, plainLen can be represented in
 * \param[in]  plainLen     Length of the plaintext (for decryption length of ciphertext minus length of MAC)
 * \param[in]  aadLen       Length of the additional authentication data in bytes (may be zero)
 * \param[in]  tagLen       Length of the tag in bytes. Can take the following values:
 *                          4, 6, 8, 10, 12, 14, 16
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_startEncryptDecrypt(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    Esc_UINT32 plainLen,
    Esc_UINT32 aadLen,
    Esc_UINT8 tagLen );

/**
 * Updates associated data
 * If associated data is available this function must be called after EscAesCcm_Init,
 * until all associated data is processed
 *
 * \param[in, out] ctx      AES-CCM context
 * \param[in]      aad      The next block of associated data
 * \param[in]      aadLen   Length of associated data block in byte
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_AssociatedData_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen );

/**
 * Encrypts data
 * Must be called after EscAesCcm_Init if no associated data is available until all data is encrypted
 * Must be called after final call of EscAesCcm_AssociatedData_Update until all data is encrypted
 *
 * \param[in, out] ctx  AES-CCM context
 * \param[in] plain     Plaintext to encrypt, might be NULL if length is zero
 * \param[out] cipher   Array to write ciphertext to.
 *                      Has to be the same size as the plaintext array.
 * \param[in] length    Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_Encrypt_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length );

/**
 * Generates the Message Authentication Code
 * Must be called after final call of EscAesCcm_Encrypt_Update
 *
 * \param[in]  ctx  AES-CCM context
 * \param[out] tag  Array to store the calculated authentication tag
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_Encrypt_Finish(
    EscAesCcm_ContextT* ctx,
    Esc_UINT8 tag[] );

/**
 * Decrypts data
 * Must be called after EscAesCcm_Init if no associated data is available until all data is decrypted
 * Must be called after final call of EscAesCcm_AssociatedData_Update until all data is decrypted
 *
 * \param[in, out] ctx      AES-CCM context
 * \param[in]      cipher   Cipherblock to decrypt, might be NULL if length is zero
 * \param[out]     plain    Array to write decrypted ciphertext to
 *                          Has to be the same size as the plaintext array
 * \param[in]      length   Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_Decrypt_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length );

/**
 * Verifies a Message Authentication Code
 * Must be called after final call of EscAesCcm_Decrypt_Update
 *
 * \param[in]  ctx  AES-CCM context
 * \param[in]  tag  Array of the stored authentication tag
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_INVALID_MAC if the given tag does not match the computed one.
 */
Esc_ERROR
EscAesCcm_Decrypt_Finish(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 tag[] );

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
 * \param[in] aad          Additional authenticated data.
 * \param[in] aadLen       Length of aad array in bytes.
 * \param[in] plain        Plaintext array.
 * \param[in] plainLen     Length of plainText array in bytes.
 *                         The plainLen can be presented in q bytes, where q can take the
 *                         following values: 2, 3, 4. The maximum of q + nonceLen is 15.
 * \param[in] tagLen       Length of the tag in bytes.
 *                         Can take the following values: 4, 6, 8, 10, 12, 14, 16.
 * \param[out] cipher      Array to store ciphertext and tag to.
 *                         The array has to be at least (plaintextLen + tagLen) bytes.
 *
 * \note The pointers plainText and cipherText may be the same.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscAesCcm_Encrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 cipher[] );

/**
 * Decrypts one or more data blocks and check the appended MAC for validity.
 * Differently from the NIST SP the encrypted plaintext is written to the plainText
 * array even if the MAC is not valid. Nevertheless, in such a case the error Esc_INVALID_MAC
 * is returned.
 *
 * \param[in] keyBits      Bit length of the AES key. Can be 128, 192 or 256.
 * \param[in] key          Key bytes array. The size of the key depends on the keyBits parameter:
 *                         128 bits => 16 bytes
 *                         192 bits => 24 bytes
 *                         256 bits => 32 bytes
 * \param[in] nonce        The nonce used in the decryption.
 * \param[in] nonceLen     Length of nonce in bytes.
 * \param[in] aad          Additional authenticated data.
 * \param[in] aadLen       Length of aad array in bytes.
 * \param[in] cipher       Ciphertext array.
 * \param[in] cipherLen    Length of cipherText array in bytes.
 * \param[in] tagLen       Length of the tag in bytes.
 *                         Can take the following values: 4, 6, 8, 10, 12, 14, 16.
 * \param[out] plain       Array to store plaintext to.
 *                         The array has to be at least (cipherLen - tagLen) bytes.
 *
 * \note The pointers plainText and cipherText may be the same.
 *
 * \return Esc_NO_ERROR if everything works fine or invalid MAC.
*/
Esc_ERROR
EscAesCcm_Decrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
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

#endif /* ESC_AES_CCM_H_ */
