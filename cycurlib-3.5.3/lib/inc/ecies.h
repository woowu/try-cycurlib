/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       ECIES implementation according to the IEEE Std 1363a

   \see         IEEE Std 1363-2000 and IEEE Std 1363a
                All quoted references refer to the IEEE standard

   KDF (KDF2) + XOR Encryption is used.
   DHAES and NON-DHAES Mode is supported
   SHA-1 and SHA-256 is supported for KDF and HMAC
   EscEcc_ECDH_ENABLED in ecc.h must be set to 1 for using ECIES!

  $Rev: 3679 $
 */
/***************************************************************************/

#ifndef ESC_ECIES_H_
#define ESC_ECIES_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "ecc.h"
#include "_fearith.h"
#include "_ptarithws.h"
#include "mem_mgt.h"

#if EscEcc_ECDH_ENABLED == 1

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/** Enables the SHA-1 */
#define EscEcies_USE_SHA1   1

/** Enables the SHA-256 */
#define EscEcies_USE_SHA256 2

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/* User definable configuration */
 #ifndef EscEcies_DHAES_ENABLED
/**
 * If disabled, NON-DHAES Mode is used for compatibility with ANSI X9.63.
 * In this mode the scheme is malleable and is not secure against an
 * adaptively chosen ciphertext attack (CCA2) (see D.5.3.3 - Note 1)
 **/
#   define EscEcies_DHAES_ENABLED 0
#endif

#ifndef EscEcies_HASH_TYPE
/** Determines the hash algorithm for the key derivation function and the HMAC.
    Supported values:
    - EscEcies_USE_SHA1
    - EscEcies_USE_SHA256
*/
#    define EscEcies_HASH_TYPE (EscEcies_USE_SHA1)
#endif

#ifndef EscEcies_MAC_KEY_BYTES
/** Set the used key length for the MAC tag in bytes */
#   define EscEcies_MAC_KEY_BYTES 16U
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
#    include "sha_1.h"
#    include "hmac_sha_1.h"
/** Length of the output of one hash operation (depends on the used hash algorithm) */
#    define EscEcies_HASH_LEN EscSha1_DIGEST_LEN
/** Length of the MAC Tag */
#    define EscEcies_MAC_TAG_LEN EscHmacSha1_MAX_MAC_LENGTH
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
#   include "sha_256.h"
#   include "hmac_sha_256.h"

/** Length of the output of one hash operation (depends on the used hash algorithm) */
#   define EscEcies_HASH_LEN (EscSha256_DIGEST_LEN)
/** Length of the MAC Tag */
#   define EscEcies_MAC_TAG_LEN (EscHmacSha256_MAX_MAC_LENGTH)
#else
#   error "EscEcies_HASH_TYPE is not supported!"
#endif

/** Maximum length of the encoded ECC public key */
#define EscEcies_PUBLIC_KEY_LEN_MAX ( (2U * EscFeArith_KEY_BYTES_MAX) + 1U )

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** ECIES context. */
typedef struct
{
    /** Are KDF parameters used */
    Esc_BOOL useKDFParameter;
    /** Encryption/decryption counter for the KDF parameters */
    Esc_UINT32 counterKDFParameter;
    /** Sender's public key */
    EscEcc_PublicKeyT pubKey;
    /** The shared secret which will be computed with the senders private
        and the receivers public key */
#if EscEcies_DHAES_ENABLED == 1
    Esc_UINT8 sharedSecret[EscEcies_PUBLIC_KEY_LEN_MAX + EscFeArith_KEY_BYTES_MAX];
#else
    Esc_UINT8 sharedSecret[EscFeArith_KEY_BYTES_MAX];
#endif
    /** Selected Ecc curve */
    const EscPtArithWs_CurveT *curve;
    /** Length of the key material for the KDF function */
    Esc_UINT32 keyMaterialLen;
    /** Length of the plaintext */
    Esc_UINT32 plainLen;
    /** Number of encrypted/decrypted bytes so far */
    Esc_UINT32 usedData;
    /** Block counter used for KDF */
    Esc_UINT32 counterBlock;
    /** Cursor position of the key (MAC or encrypt/decrypt) in a block */
    Esc_UINT32 currentKeyPosition;
    /** HMAC context for encryption/decryption */
#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
    EscHmacSha1_ContextT hmacCtx;
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
    EscHmacSha256_ContextT hmacCtx;
#endif
} EscEcies_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/
/**
 * Initializes the encryption counter and generates the sender's key pair.

 * The public key is not validated here since it can be omitted if the key is already authenticated.
 * If the public key must be validated beforehand, the function EscEcc_PublicKeyValidation from the ECC module can be used.
 * For the public key requirements cf. D.5.3.5 and D.5.1.6.

 * \param[out] ctx The ECIES context.
 * \param[in] recPublicKey The Receiver's public key.
 * \param[out] privKey The generated private key of the sender.
 * \param[in,out] privKeyLen In: Size of the privKey buffer in bytes. EscFeArith_KEY_BYTES_MAX can
                              be used as the maximum size allowed by configuration.
                             Out: Size of the private key in bytes
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h
 * \param[in] curveId The ID of the selected elliptic curve.
 * \param[in] useKDFParam Are KDF parameters used

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Init_Encrypt(
    EscEcies_ContextT* ctx,
    const EscEcc_PublicKeyT* recPublicKey,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam );

/**
 * Initializes decryption counter and computes the shared secret

 * \param[out] ctx The ECIES context.
 * \param[in] ciphertext The ciphertext with the encoded public key of the sender
 * \param[in] ciphertextLen Length of the ciphertext in bytes. This must be at least
           enough bytes to store the encoded public key (2 * curve.keySizeBytes + 1).
 * \param[in] privKey The private Key of the receiver.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] curveId The ID of the selected elliptic curve.
 * \param[in] useKDFParam Are KDF parameters used

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Init_Decrypt(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 ciphertext[],
    Esc_UINT32 ciphertextLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam );

/**
 * Starts a new encryption. The context must have been initialized
 * with EscEcies_Init_Encrypt before calling this function.

 * Encodes and saves public key at the start of the ciphertext.
 * Calculates the length of a public key. This value should be used for encryption update function.
 * If the output of the encryption is stored in one array, that array contains:
 * public key | encrypted plaintext | mac tag
 * Encryption update function should start from publicKeyLen
 * Generates MAC key and initializes HMAC context for sha1 or sha256.
 * Sets block counter and cursor inside of a block after MAC key generation, for encryption.
 *
 * \param[in, out] ctx           The ECIES context.
 * \param[in] plaintextLen       Size of the entire plaintext buffer in bytes.
 * \param[out] ciphertext        The ciphertext. First publicKeyLen are set to a public key in this function.
 * \param[in, out] ciphertextLen In: Length of the ciphertext buffer in bytes.
 *                               Out: Size of the ciphertext in bytes.
 * \param[out] publicKeyLen      Length of a public key. Encryption starts from this position.

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_StartEncrypt(
    EscEcies_ContextT* ctx,
    Esc_UINT32 plaintextLen,
    Esc_UINT8 ciphertext[],
    Esc_UINT32* ciphertextLen,
    Esc_UINT32* publicKeyLen );

/**
 * Start a new decryption. The context must have been initialized
 * with EscEcies_Init_Decrypt before calling this function.

 * If the output of the decryption is stored in one array, that array contains:
 * public key | encrypted plaintext | mac tag
 * Decryption update function should start from publicKeyLen
 * Generates MAC key and initializes HMAC context for sha1 or sha256.
 * Sets block counter and cursor inside of a block after MAC key generation, for decryption.

 * \param[in, out] ctx The ECIES context.
 * \param[in] publicKey The public key.
 * \param[in, out] publicKeyLen Length of the public key in bytes.
 *                              In: Length of the public key buffer
 *                                  Can be higher than the actual length of a public key
 *                                  Cannot be higher than EscEcies_PUBLIC_KEY_LEN_MAX
 *                                  Cannot be lower than the actual length of a public key
 *                              Out: Actual length of a public key
 * \param[in] ciphertextLen Length of the entire ciphertext in bytes.
 * \param[out] plaintextLen Computed length of the plaintext buffer in bytes.

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_StartDecrypt(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 publicKey[],
    Esc_UINT32* publicKeyLen,
    Esc_UINT32 ciphertextLen,
    Esc_UINT32* plaintextLen );

/**
 * Encrypts data and updates hmac context
 * Must be called after EscEcies_StartEncrypt until all data is encrypted
 *
 * \param[in, out] ctx     The ECIES context
 * \param[in] plaintext    Plaintext to encrypt.
 * \param[out] ciphertext  Array to write ciphertext to.
 *                         Has to be the same size as the plaintext array.
 * \param[in] plaintextLen Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Encrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 plaintext[],
    Esc_UINT8 ciphertext[],
    Esc_UINT32 plaintextLen );

/**
 * Decrypts data and updates hmac context
 * Must be called after EscEcies_StartDecrypt until all data is decrypted
 * MAC tag is not the part of the ciphertext
 * MAC tag is passed in the finish function
 *
 * \param[in, out] ctx     The ECIES context
 * \param[in] ciphertext   Ciphertext to decrypt.
 * \param[out] plaintext   Array to write plaintext to.
 *                         Has to be the same size as the ciphertext array.
 * \param[in] ciphertextLen Length of plain and cipher data in bytes, might be zero.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Decrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 ciphertext[],
    Esc_UINT8 plaintext[],
    Esc_UINT32 ciphertextLen );

/**
 * Generates the Message Authentication Code
 * Must be called after final call of EscEcies_EncryptUpdate
 *
 * \param[in] ctx           The ECIES context
 * \param[out] macTag       Array to store the calculated authentication tag
 * \param[in]  macTagLen    Length of the array of the stored authentication tag
 *                          Has to be equal to EscEcies_MAC_TAG_LEN
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Encrypt_Finish(
    EscEcies_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen );

/**
 * Verifies a Message Authentication Code
 * Must be called after final call of EscEcies_DecryptUpdate
 *
 * \param[in]  ctx          The ECIES context
 * \param[in]  macTag       Array of the stored authentication tag
 * \param[in]  macTagLen    Length of the array of the stored authentication tag
 *                          Has to be equal to EscEcies_MAC_TAG_LEN
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_INVALID_MAC if the given tag does not match the computed one.
 */
Esc_ERROR
EscEcies_Decrypt_Finish(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen );

/**
 * Encrypts data.
 * If useKDFParam is TRUE, this implementation uses the KDF parameters
 * as an encryption counter as proposed in 11.3.2 - Note 1 and D.5.3.3
 * Please refer to 11.3.2 - Note 1 and D.5.3.3

 * \param[in] plaintext The plaintext.
 * \param[in] plaintextLen Length of the plaintext in bytes.
 * \param[out] ciphertext Array to store ciphertext.
 * \param[in,out] ciphertextLen In: Size of the ciphertext buffer in Bytes.
                             Out: Size of the computed ciphertext in bytes.
 * \param[in] recPublicKey The Receiver's public key. The key is validated by this function.
 * \param[out] privKey The private Key of the sender.
 * \param[in,out] privKeyLen In: Size of the privKey buffer in bytes. EscFeArith_KEY_BYTES_MAX can
                              be used as the maximum size allowed by configuration.
                          Out: Size of the private key in bytes
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h
 * \param[in] curveId The ID of the selected elliptic curve.
 * \param[in] useKDFParam Are KDF parameters used

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Encrypt(
    const Esc_UINT8 plaintext[],
    Esc_UINT32 plaintextLen,
    Esc_UINT8 ciphertext[],
    Esc_UINT32* ciphertextLen,
    const EscEcc_PublicKeyT* recPublicKey,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam );

/**
 * Decrypts data and checks the appended MAC for validity. Multiple ciphertext blocks must be
 * decrypted in the same order as the encryption took place.
 * If useKDFParam is TRUE, this implementation uses the KDF parameters
 * as a decryption counter as proposed in 11.3.2 - Note 1 and D.5.3.3

 * \param[in] ciphertext The ciphertext. Has to be the complete ciphertext with the encoded public key and MAC tag.
 * \param[in] ciphertextLen Length of the ciphertext in bytes.
 * \param[out] plaintext Array to store the plaintext of size plaintextLen.
 * \param[out] plaintextLen Length of the computed plaintext in bytes.
 * \param[in] privKey The private Key of the receiver.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] curveId The ID of the selected elliptic curve.
 * \param[in] useKDFParam Are KDF parameters used

 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcies_Decrypt(
    const Esc_UINT8 ciphertext[],
    Esc_UINT32 ciphertextLen,
    Esc_UINT8 plaintext[],
    Esc_UINT32* plaintextLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam );
/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#endif /* EscEcc_ECDH_ENABLED */

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECIES_H_ */
