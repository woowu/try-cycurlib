/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 RSASSA-PSS signature signature scheme
                with MGF1 as the mask generation function

   Byte format of all long numbers is Big-Endian.


   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf


   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_PKCS1_RSASSA_PSS_H_
#define ESC_PKCS1_RSASSA_PSS_H_

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
 * 2. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef EscPkcs1RsaSsaPss_SHA1_ENABLED
/** Enables the SHA-1 */
#   define EscPkcs1RsaSsaPss_SHA1_ENABLED     1
#endif

#ifndef EscPkcs1RsaSsaPss_SHA224_ENABLED
/** Enables the SHA-224 */
#   define EscPkcs1RsaSsaPss_SHA224_ENABLED   1
#endif

#ifndef EscPkcs1RsaSsaPss_SHA256_ENABLED
/** Enables the SHA-256 */
#   define EscPkcs1RsaSsaPss_SHA256_ENABLED   1
#endif

#ifndef EscPkcs1RsaSsaPss_SHA384_ENABLED
/** Enables the SHA-384 */
#   define EscPkcs1RsaSsaPss_SHA384_ENABLED   1
#endif

#ifndef EscPkcs1RsaSsaPss_SHA512_ENABLED
/** Enables the SHA-512 */
#   define EscPkcs1RsaSsaPss_SHA512_ENABLED   1
#endif

#ifndef EscPkcs1RsaSsaPss_MAX_SALT_LEN
/** The maximum length of the used salt. By default we use the length of the hash value */
#   define EscPkcs1RsaSsaPss_MAX_SALT_LEN (EscPkcs1RsaSsaPss_MAX_DIGEST_LEN)
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Searching for the maximum Hash buffer lengths */
#if EscPkcs1RsaSsaPss_SHA512_ENABLED == 1
#   include "sha_512.h"
/** Set the maximum buffer length to the digest length */
#   define EscPkcs1RsaSsaPss_MAX_DIGEST_LEN (EscSha512_DIGEST_LEN)
#endif

#if EscPkcs1RsaSsaPss_SHA384_ENABLED == 1
#   include "sha_512.h"

#   ifndef EscPkcs1RsaSsaPss_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MAX_DIGEST_LEN (EscSha384_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA256_ENABLED == 1
#   include "sha_256.h"

#   ifndef EscPkcs1RsaSsaPss_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MAX_DIGEST_LEN (EscSha256_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA224_ENABLED == 1
#   include "sha_256.h"

#   ifndef EscPkcs1RsaSsaPss_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MAX_DIGEST_LEN (EscSha224_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA1_ENABLED == 1
#   include "sha_1.h"

#   ifndef EscPkcs1RsaSsaPss_MAX_DIGEST_LEN
/** Set the maximum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MAX_DIGEST_LEN (EscSha1_DIGEST_LEN)
#   endif
#endif

/* Check if at least one hash algorithm is enabled */
#ifndef EscPkcs1RsaSsaPss_MAX_DIGEST_LEN
#   error "No Hash algorithm is enabled for PKCS1-PSS!"
#endif

/* Searching for the minimum hash buffer lengths */
#if EscPkcs1RsaSsaPss_SHA1_ENABLED == 1
/** Set the minimum buffer length to the digest length */
#   define EscPkcs1RsaSsaPss_MIN_DIGEST_LEN (EscSha1_DIGEST_LEN)
#endif

#if EscPkcs1RsaSsaPss_SHA224_ENABLED == 1
#   ifndef EscPkcs1RsaSsaPss_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MIN_DIGEST_LEN (EscSha224_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA256_ENABLED == 1
#   ifndef EscPkcs1RsaSsaPss_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MIN_DIGEST_LEN (EscSha256_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA384_ENABLED == 1
#   ifndef EscPkcs1RsaSsaPss_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MIN_DIGEST_LEN (EscSha384_DIGEST_LEN)
#   endif
#endif

#if EscPkcs1RsaSsaPss_SHA512_ENABLED == 1
#   ifndef EscPkcs1RsaSsaPss_MIN_DIGEST_LEN
/** Set the minimum buffer length to the digest length */
#      define EscPkcs1RsaSsaPss_MIN_DIGEST_LEN (EscSha512_DIGEST_LEN)
#   endif
#endif

/* Check salt parameter */
#if (EscPkcs1RsaSsaPss_MAX_SALT_LEN) > ( (EscRsa_KEY_BYTES_MAX - EscPkcs1RsaSsaPss_MIN_DIGEST_LEN) - 2U)
#   error "PKCS1-PSS: Illegal maximum salt length!"
#endif


/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** State of the signature verification */
typedef struct
{
    /** The state of the computation */
    Esc_UINT8 state;
    /** RSA modular exponentiation context */
    EscRsa_PubContext rsaCtx;
    /** Buffer to hold the encoded message EM after RSA exponentiation */
    Esc_UINT8 em[EscRsa_KEY_BYTES_MAX];

    /** Pointer to the hash digest of the message.
        Must remain valid/allocated until the verification is finished! */
    const Esc_UINT8* digest;
    /** Type of hash to be used */
    Esc_UINT8 digestType;
    /** Length of the digest in bytes*/
    Esc_UINT32 digestLength;
    /** Length of the salt in bytes */
    Esc_UINT32 saltLength;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
    /** Size of the encoded message (EM) in bits */
    Esc_UINT32 emBits;
} EscPkcs1RsaSsaPss_VerifyContext;

/** State of the signature generation */
typedef struct
{
    /** The state of the computation */
    Esc_UINT8 state;
    /** RSA modular exponentiation context */
    EscRsa_PrivContext rsaCtx;

    /** Pointer to the hash digest of the message.
        Must remain valid/allocated until the verification is finished! */
    const Esc_UINT8* digest;
    /** Pointer to the RSA private key.
        Must remain valid/allocated until the verification is finished! */
    const EscRsa_PrivKeyT* privKey;

    /** Pointer to the signature.
        Must remain valid/allocated until the verification is finished! */
    Esc_UINT8 *signature;
    /** Pointer to the where the output length will be stored at the end of the computation. */
    Esc_UINT32 *signatureLen;
    /** Callback for the PRNG */
    EscRandom_GetRandom prngFunc;
    /** Parameter passed to the PRNG */
    void* prngState;
    /** Type of hash to be used */
    Esc_UINT8 digestType;
    /** Length of the digest in bytes*/
    Esc_UINT32 digestLength;
    /** Length of the salt in bytes */
    Esc_UINT32 saltLength;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
    /** Size of the encoded message (EM) in bits */
    Esc_UINT32 emBits;
} EscPkcs1RsaSsaPss_SignContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES (verification / signing in a single call)        *
 ***************************************************************************/

/**
Signs a message according to RSASSA-PSS-Sign.

\see Section 8.1.1

\param[in] prngFunc         Random function as specified in random.h
\param[in] prngState        Random state which may be required by your random implementation.
\param[in] digest           Digest of the message to be signed. The length depends on the digestType parameter.
                            See also pkcs1.h for the possible digest lengths.
\param[in] privKey          Private key structure.
\param[out] signature       Buffer to store the computed signature.
\param[in,out] signatureLen In: Length of buffer provided by parameter signature. The buffer must be at least
                                as large as the key size of the public key (e.g. for RSA-1024, it should be
                                1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer.
\param[in] saltLen          The length of the random salt. Maximum is given through (size of modulus - digest length - 2).
                            The recommended value is the digest length (e.g. EscShaXXX_DIGEST_LEN).
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscPkcs1RsaSsaPss_Sign(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType );

/**
Verifies a message according to RSASSA-PSS-Verify.

\see Section 8.1.2

\param[in] digest           Digest of the message to be verified. The length depends on the digestType parameter.
                            See also pkcs1.h for the possible digest lengths.
\param[in] pubKey           Public key structure.
\param[in] signature        Signature to be verified, of size EscRsa_KEY_BYTES.
\param[in] signatureLen     Length of the signature in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[in] saltLen          The length of the random salt. Maximum is given through (size of modulus - digest length - 2).
                            The recommended value is the digest length (e.g. EscShaXXX_DIGEST_LEN).
\param[in] digestType       The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR if everything works fine or Esc_INVALID_SIGNATURE if verification fails.
*/
Esc_ERROR
EscPkcs1RsaSsaPss_Verify(
    const Esc_UINT8 digest[],
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType );

/***************************************************************************
 * 7. FUNCTION PROTOTYPES (stepwise verification / signing)                *
 ***************************************************************************/

/**
Initialize signature verification according to RSASSA-PSS-Verify.

\see Section 8.1.2

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in]  ctx             The context structure which stores the state of the verification.
\param[in]  digest          Digest of the message to be verified. The length depends on the digestType parameter.
                            See also pkcs1.h for the possible digest lengths.
\param[in]  pubKey          Public key structure.
\param[in]  signature       Signature to be verified, of size EscRsa_KEY_BYTES.
\param[in]  signatureLen    Length of the signature in bytes. This must match the modulus
                            size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[in]  saltLen         The length of the random salt. Maximum is given through (size of modulus - digest length - 2).
                            The recommended value is the digest length (e.g. EscShaXXX_DIGEST_LEN).
\param[in]  digestType      The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaSsaPss_VerifyInit(
    EscPkcs1RsaSsaPss_VerifyContext *ctx,
    const Esc_UINT8 digest[],
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType );

/**
Run signature verification. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the verification.

\retval Esc_AGAIN if this function needs to be called again to continue verification.
\retval Esc_NO_ERROR if the signature is valid.
\retval Esc_INVALID_SIGNATURE if the signature is invalid.
 */
Esc_ERROR
EscPkcs1RsaSsaPss_VerifyRun(
    EscPkcs1RsaSsaPss_VerifyContext *ctx);

/**
Initializes signature generation according to RSASSA-PSS-Sign.

\see Section 8.1.1

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in]      ctx             The context structure which stores the state of the verification.
\param[in]      prngFunc        Random function as specified in random.h
\param[in]      prngState       Random state which may be required by your random implementation.
\param[in]      digest          Digest of the message to be signed.
                                The length depends on the digestType parameter.
                                See also pkcs1.h for the possible digest lengths.
\param[in]      privKey         Private key structure.
\param[out]     signature       Buffer to store the computed signature.
\param[in,out]  signatureLen    In: Length of buffer provided by parameter signature. The buffer must be at least
                                    as large as the key size of the public key (e.g. for RSA-1024, it should be
                                    1024 / 8 = 128 bytes).
                                Out: Number of bytes written to the buffer.This is written at the end of the
                                     computation when EscPkcs1RsaSsaPss_SignRun() finished.
\param[in]      saltLen         The length of the random salt. Maximum is given through
                                (size of modulus - digest length - 2). The recommended value is
                                the digest length (e.g. EscShaXXX_DIGEST_LEN).
\param[in]      digestType      The type of the digest.
                                One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaSsaPss_SignInit(
    EscPkcs1RsaSsaPss_SignContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType );

/**
Run signature generation. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the signature generation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue signature generation.
\retval Esc_NO_ERROR if signature generation finished successfully.
                     The signature was written to the buffer passed to EscPkcs1RsaSsaPss_SignInit().
 */
Esc_ERROR
EscPkcs1RsaSsaPss_SignRun(
    EscPkcs1RsaSsaPss_SignContext *ctx);

/***************************************************************************
 * 8. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
