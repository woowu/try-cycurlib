/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 RSAES-OAEP encryption and decryption
                with MGF1 as the mask generation function

   Byte format of all long numbers is Big-Endian.

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf


   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_PKCS1_RSAES_OAEP_H_
#define ESC_PKCS1_RSAES_OAEP_H_

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

#ifndef EscPkcs1RsaEsOaep_SHA1_ENABLED
/** Enables the SHA-1 */
#   define EscPkcs1RsaEsOaep_SHA1_ENABLED     1
#endif

#ifndef EscPkcs1RsaEsOaep_SHA224_ENABLED
/** Enables the SHA-224 */
#   define EscPkcs1RsaEsOaep_SHA224_ENABLED   1
#endif

#ifndef EscPkcs1RsaEsOaep_SHA256_ENABLED
/** Enables the SHA-256 */
#   define EscPkcs1RsaEsOaep_SHA256_ENABLED   1
#endif

#ifndef EscPkcs1RsaEsOaep_SHA384_ENABLED
/** Enables the SHA-384 */
#   define EscPkcs1RsaEsOaep_SHA384_ENABLED   1
#endif

#ifndef EscPkcs1RsaEsOaep_SHA512_ENABLED
/** Enables the SHA-512 */
#   define EscPkcs1RsaEsOaep_SHA512_ENABLED   1
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Searching for the maximum hash buffer lengths */
#if EscPkcs1RsaEsOaep_SHA512_ENABLED == 1
#   include "sha_512.h"
/** Set the maximum buffer length to the digest length */
#   define EscPkcs1RsaEsOaep_MAX_DIGEST_LEN (EscSha512_DIGEST_LEN)
#endif

#if EscPkcs1RsaEsOaep_SHA384_ENABLED == 1
#   include "sha_512.h"

#   ifndef EscPkcs1RsaEsOaep_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MAX_DIGEST_LEN (EscSha384_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA256_ENABLED == 1
#   include "sha_256.h"

#   ifndef EscPkcs1RsaEsOaep_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MAX_DIGEST_LEN (EscSha256_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA224_ENABLED == 1
#   include "sha_256.h"

#   ifndef EscPkcs1RsaEsOaep_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MAX_DIGEST_LEN (EscSha224_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA1_ENABLED == 1
#   include "sha_1.h"

#   ifndef EscPkcs1RsaEsOaep_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MAX_DIGEST_LEN (EscSha1_DIGEST_LEN)
#   endif
#endif

/* Check if at least one hash algorithm is enabled */
#ifndef EscPkcs1RsaEsOaep_MAX_DIGEST_LEN
#   error "No hash algorithm is enabled for PKCS1-OAEP!"
#endif

/* Searching for the minimum hash buffer lengths */
#if EscPkcs1RsaEsOaep_SHA1_ENABLED == 1
/** Set the minimum buffer length to the digest length */
#   define EscPkcs1RsaEsOaep_MIN_DIGEST_LEN (EscSha1_DIGEST_LEN)
#endif

#if EscPkcs1RsaEsOaep_SHA224_ENABLED == 1
#   ifndef EscPkcs1RsaEsOaep_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MIN_DIGEST_LEN (EscSha224_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA256_ENABLED == 1
#   ifndef EscPkcs1RsaEsOaep_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MIN_DIGEST_LEN (EscSha256_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA384_ENABLED == 1
#   ifndef EscPkcs1RsaEsOaep_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MIN_DIGEST_LEN (EscSha384_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaEsOaep_SHA512_ENABLED == 1
#   ifndef EscPkcs1RsaEsOaep_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaEsOaep_MIN_DIGEST_LEN (EscSha512_DIGEST_LEN)
#   endif
#endif

/** The maximum message given the largest configured RSA key size and the smallest digest length.
 * Depending on the used key and digest type, the actual maximum message size may be smaller.
 */
#define EscPkcs1RsaEsOaep_MAX_MESSAGE_LENGTH (EscRsa_KEY_BYTES_MAX - (2U * EscPkcs1RsaEsOaep_MIN_DIGEST_LEN) - 2U)

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
    /** The optional label to be used with OAEP */
    const Esc_UINT8 *label;
    /** Length of the label in bytes */
    Esc_UINT32 labelLen;
    /** The RSA public key */
    const EscRsa_PubKeyT* pubKey;
    /** Output buffer for the cipher text */
    Esc_UINT8 *cipher;
    /** The written length of the ciphertext is written
        via this pointer at the end of the computation */
    Esc_UINT32 *cipherLen;
    /** Type of hash function to be used */
    Esc_UINT8 digestType;
    /** Length of the hash function's digest in bytes */
    Esc_UINT32 digestLength;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaEsOaep_EncryptContext;

/** Decryption state */
typedef struct
{
    /** The state of the computation */
    Esc_UINT8 state;
    /** RSA modular exponentiation context */
    EscRsa_PrivContext rsaCtx;
    /** Buffer to store the padded message */
    Esc_UINT8 em[EscRsa_KEY_BYTES_MAX];

    /** The optional label to be used with OAEP */
    const Esc_UINT8 *label;
    /** Length of the label in bytes */
    Esc_UINT32 labelLen;
    /** Output buffer for the plain text */
    Esc_UINT8 *message;
    /** Length of the output buffer in bytes */
    Esc_UINT32 *messageLen;
    /** Type of hash function to be used */
    Esc_UINT8 digestType;
    /** Length of the hash function's digest in bytes */
    Esc_UINT32 digestLength;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaEsOaep_DecryptContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES (encryption / decryption in a single call)       *
 ***************************************************************************/

/**
Encrypts a message according to RSAES-OAEP.
\see Section 7.1.1

\param[in] prngFunc         PRNG function as specified in random.h.
                            The PRNG must have been seeded before it is passed to this function!
\param[in] prngState        State of the PRNG function. This may be NULL if the PRNG is stateless.
\param[in] message          Message to be encrypted.
\param[in] messageLen       Size of the message in bytes.
\param[in] label            Label to be assigned. This parameter is optional and may be set to NULL.
\param[in] labelLen         Size of the label in bytes. Must be 0 if label is set to NULL.
\param[in] pubKey           Public key structure.
\param[out] cipher          Buffer to write the ciphertext to.
\param[in,out] cipherLen    In: Length of buffer provided by parameter cipher. The buffer should be as large
                            as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer.
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscPkcs1RsaEsOaep_Encrypt(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen,
    Esc_UINT8 digestType );

/**
Decrypts a message according to RSAEP-OAEP.

\see Section 7.1.2

\param[in] cipher           Ciphertext to be decrypted.
\param[in] cipherLen        Length of the ciphertext in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[in] label            Label to be verified. This parameter is optional and may be set to NULL.
\param[in] labelLen         Size of the label in bytes. Must be 0 if label is set to NULL.
\param[out] message         Decrypted message.
\param[in,out] messageLen   In: Size of the message buffer in bytes. EscPkcs1RsaEsOaep_MAX_MESSAGE_LENGTH can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the message in bytes
\param[in] privKey          Private key structure.
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR if everything works fine or Esc_DECRYPTION_ERROR if decryption fails.
*/
Esc_ERROR
EscPkcs1RsaEsOaep_Decrypt(
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 digestType );

/***************************************************************************
 * 7. FUNCTION PROTOTYPES (stepwise encryption / decryption)               *
 ***************************************************************************/

/**
Initialize encryption of a message according to RSAES-OAEP.
\see Section 7.1.1

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in] ctx              The context structure which stores the state of the encryption.
\param[in] prngFunc         PRNG function as specified in random.h.
                            The PRNG must have been seeded before it is passed to this function!
\param[in] prngState        State of the PRNG function. This may be NULL if the PRNG is stateless.
\param[in] message          Message to be encrypted.
\param[in] messageLen       Size of the message in bytes.
\param[in] label            Label to be assigned. This parameter is optional and may be set to NULL.
\param[in] labelLen         Size of the label in bytes. Must be 0 if label is set to NULL.
\param[in] pubKey           Public key structure.
\param[out] cipher          Buffer to write the ciphertext to.
\param[in,out] cipherLen    In: Length of buffer provided by parameter cipher. The buffer should be as large
                            as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer. This is written at the end of the
                            computation when EscPkcs1RsaEsOaep_EncryptRun() is finished.
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaEsOaep_EncryptInit(
    EscPkcs1RsaEsOaep_EncryptContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen,
    Esc_UINT8 digestType );

/**
Run encryption. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the encryption.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue encryption.
\retval Esc_NO_ERROR if encryption finished successfully.
                     The ciphertext was written to the buffer passed to EscPkcs1RsaEsOaep_EncryptInit().
 */
Esc_ERROR
EscPkcs1RsaEsOaep_EncryptRun(
    EscPkcs1RsaEsOaep_EncryptContext *ctx);

/**
Initialize decryption of a message according to RSAES-OAEP.

\see Section 7.1.2

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in] ctx              The context structure which stores the state of the decryption.
\param[in] cipher           Ciphertext to be decrypted.
\param[in] cipherLen        Length of the ciphertext in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[in] label            Label to be verified. This parameter is optional and may be set to NULL.
\param[in] labelLen         Size of the label in bytes. Must be 0 if label is set to NULL.
\param[out] message         Decrypted message.
\param[in,out] messageLen   In: Size of the message buffer in bytes. EscPkcs1RsaEsOaep_MAX_MESSAGE_LENGTH can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the message in bytes. This is written at the end of the
                                 computation when EscPkcs1RsaEsOaep_DecryptRun() is finished.
\param[in] privKey          Private key structure.
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaEsOaep_DecryptInit(
    EscPkcs1RsaEsOaep_DecryptContext *ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 digestType );

/**
Run decryption. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the decryption.

\retval Esc_AGAIN if this function needs to be called again to continue decryption.
\retval Esc_NO_ERROR if decryption finished successfully.
                     The ciphertext was written to the buffer passed to EscPkcs1RsaEsOaep_DecryptInit().
\retval Esc_DECRYPTION_FAILED The ciphertext could not be decrypted correctly.
 */
Esc_ERROR
EscPkcs1RsaEsOaep_DecryptRun(
    EscPkcs1RsaEsOaep_DecryptContext *ctx);

/***************************************************************************
 * 8. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
