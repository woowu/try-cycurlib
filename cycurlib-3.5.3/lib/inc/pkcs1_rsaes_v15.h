/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 RSAES-v1_5 encryption and decryption

   Byte format of all long numbers is Big-Endian.

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf


   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_PKCS1_RSAES_V15_H_
#define ESC_PKCS1_RSAES_V15_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "rsa.h"
#include "pkcs1.h"

#include "random.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Number of bytes which will be padded as fixed bytes to the message */
#define EscPkcs1RsaEsV15_FIXED_PADDING_LENGTH       3U
/** The minimum number of bytes which will be padded as random bytes to the message */
#define EscPkcs1RsaEsV15_MIN_RANDOM_PADDING_LENGTH  8U
/** The minimum number of bytes which will be padded to the message */
#define EscPkcs1RsaEsV15_MIN_PADDING_LENGTH      (EscPkcs1RsaEsV15_MIN_RANDOM_PADDING_LENGTH + EscPkcs1RsaEsV15_FIXED_PADDING_LENGTH)
/** The maximum size of the plaintext message derived from key bytes */
#define EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH_FOR_KEYBYTES(b)      ((b) - (EscPkcs1RsaEsV15_MIN_PADDING_LENGTH))

/** The maximum message given the largest configured RSA key size.
 * Depending on the used key, the actual maximum message size may be smaller.
 */
#define EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH      (EscRsa_KEY_BYTES_MAX - EscPkcs1RsaEsV15_MIN_PADDING_LENGTH)

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Encryption state */
typedef struct
{
    /** The state of the computation */
    Esc_UINT8 state;
    /** RSA modular exponentiation context */
    EscRsa_PubContext rsaCtx;

    /** Callback for the PRNG */
    EscRandom_GetRandom prngFunc;
    /** Parameter passed to the PRNG */
    void* prngState;
    /** The message to be encrypted */
    const Esc_UINT8 *message;
    /** Length of the message in bytes */
    Esc_UINT32 messageLen;
    /** The RSA public key */
    const EscRsa_PubKeyT* pubKey;
    /** Output buffer for the cipher text */
    Esc_UINT8 *cipher;
    /** The written length of the ciphertext is written
        via this pointer at the end of the computation */
    Esc_UINT32 *cipherLen;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaEsV15_EncryptContext;

/** Decryption state */
typedef struct
{
    /** The state of the computation */
    Esc_UINT8 state;
    /** RSA modular exponentiation context */
    EscRsa_PrivContext rsaCtx;
    /** Buffer to store the padded message */
    Esc_UINT8 em[EscRsa_KEY_BYTES_MAX];

    /** Output buffer for the plain text */
    Esc_UINT8 *message;
    /** Length of the output buffer in bytes */
    Esc_UINT32 *messageLen;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaEsV15_DecryptContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES (encryption / decryption in a single call)       *
 ***************************************************************************/

/**
Encrypts a message according to RSAES-PKCS#1 v1.5.
\see Section 7.2.1

\param[in] prngFunc         PRNG function as specified in random.h.
                            The PRNG must have been seeded before it is passed to this function!
\param[in] prngState        State of the PRNG function. This may be NULL if the PRNG is stateless.
\param[in] message          Message to be encrypted.
\param[in] messageLen       Size of the message in bytes.
\param[in] pubKey           Public key structure.
\param[out] cipher          Buffer to write the ciphertext to.
\param[in,out] cipherLen    In: Length of buffer provided by parameter cipher. The buffer should be as large
                            as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscPkcs1RsaEsV15_Encrypt(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen);

/**
Decrypts a message according to RSAES-PKCS#1 v1.5.

\see Section 7.2.2

\param[in] cipher           Ciphertext to be decrypted.
\param[in] cipherLen        Length of the ciphertext in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[out] message         Decrypted message.
\param[in,out] messageLen   In: Size of the message buffer in bytes. EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the message in bytes
\param[in] privKey          Private key structure.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscPkcs1RsaEsV15_Decrypt(
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey );

/***************************************************************************
 * 7. FUNCTION PROTOTYPES (stepwise encryption / decryption)               *
 ***************************************************************************/

/**
Encrypts a message according to RSAES-PKCS#1 v1.5.
\see Section 7.2.1

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in] ctx              The context structure which stores the state of the encryption.
\param[in] prngFunc         PRNG function as specified in random.h.
                            The PRNG must have been seeded before it is passed to this function!
\param[in] prngState        State of the PRNG function. This may be NULL if the PRNG is stateless.
\param[in] message          Message to be encrypted.
\param[in] messageLen       Size of the message in bytes.
\param[in] pubKey           Public key structure.
\param[out] cipher          Buffer to write the ciphertext to.
\param[in,out] cipherLen    In: Length of buffer provided by parameter cipher. The buffer should be as large
                            as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer. This is written at the end of the
                            computation when EscPkcs1RsaEsV15_EncryptRun() is finished.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaEsV15_EncryptInit(
    EscPkcs1RsaEsV15_EncryptContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen);

/**
Run encryption. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the encryption.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue encryption.
\retval Esc_NO_ERROR if encryption finished successfully.
                     The ciphertext was written to the buffer passed to EscPkcs1RsaEsV15_EncryptInit().
 */
Esc_ERROR
EscPkcs1RsaEsV15_EncryptRun(
    EscPkcs1RsaEsV15_EncryptContext *ctx);

/**
Decrypts a message according to RSAES-PKCS#1 v1.5.

\see Section 7.2.2

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in] ctx              The context structure which stores the state of the encryption.
\param[in] cipher           Ciphertext to be decrypted.
\param[in] cipherLen        Length of the ciphertext in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[out] message         Decrypted message.
\param[in,out] messageLen   In: Size of the message buffer in bytes. EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the message in bytes. This is written at the end of the
                                computation when EscPkcs1RsaEsV15_DecryptRun() is finished.
\param[in] privKey          Private key structure.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscPkcs1RsaEsV15_DecryptInit(
    EscPkcs1RsaEsV15_DecryptContext *ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey);

/**
Run decryption. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the decryption.

\retval Esc_AGAIN if this function needs to be called again to continue decryption.
\retval Esc_NO_ERROR if decryption finished successfully.
                     The ciphertext was written to the buffer passed to EscPkcs1RsaEsV15_DecryptInit().
\retval Esc_DECRYPTION_FAILED The ciphertext could not be decrypted correctly.
 */
Esc_ERROR
EscPkcs1RsaEsV15_DecryptRun(
    EscPkcs1RsaEsV15_DecryptContext *ctx);

/***************************************************************************
 * 8. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
