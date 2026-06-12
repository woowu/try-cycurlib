/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 RSASSA-PKCS1-v1_5 signature scheme

   Implementation of RSASSA-PKCS1-v1_5 verification and generation.
   Byte format of all long numbers is Big-Endian.

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf


   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_PKCS1_RSASSA_V15_H_
#define ESC_PKCS1_RSASSA_V15_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "rsa.h"
#include "pkcs1.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef EscPkcs1RsaSsaV15_MD2_ENABLED
/** Support for MD2 digest. */
#   define EscPkcs1RsaSsaV15_MD2_ENABLED       1
#endif

#ifndef EscPkcs1RsaSsaV15_MD5_ENABLED
/** Support for MD5 digest . */
#   define EscPkcs1RsaSsaV15_MD5_ENABLED       1
#endif

#ifndef EscPkcs1RsaSsaV15_SHA1_ENABLED
/** Support for SHA1 digest. */
#   define EscPkcs1RsaSsaV15_SHA1_ENABLED      1
#endif

#ifndef EscPkcs1RsaSsaV15_SHA224_ENABLED
/** Support for SHA224 digest. */
#   define EscPkcs1RsaSsaV15_SHA224_ENABLED    1
#endif

#ifndef EscPkcs1RsaSsaV15_SHA256_ENABLED
/** Support for SHA256 digest. */
#   define EscPkcs1RsaSsaV15_SHA256_ENABLED    1
#endif

#ifndef EscPkcs1RsaSsaV15_SHA384_ENABLED
/** Support for SHA384 digest. */
#   define EscPkcs1RsaSsaV15_SHA384_ENABLED    1
#endif

#ifndef EscPkcs1RsaSsaV15_SHA512_ENABLED
/** Support for SHA512 digest. */
#   define EscPkcs1RsaSsaV15_SHA512_ENABLED    1
#endif

#ifndef EscPkcs1RsaSsaV15_RIPEMD160_ENABLED
/** Support for RIPEMD-160 digest. */
#   define EscPkcs1RsaSsaV15_RIPEMD160_ENABLED 1
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if EscPkcs1RsaSsaV15_MD2_ENABLED == 1
/** MD2 algorithm. The length of hashDigest is 16 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_MD2          0U
#endif

#if EscPkcs1RsaSsaV15_MD5_ENABLED == 1
/** MD5 algorithm. The length of hashDigest is 16 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_MD5          1U
#endif

#if EscPkcs1RsaSsaV15_SHA1_ENABLED == 1
/** SHA-1 algorithm. The length of hashDigest is 20 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA1         2U
#endif

#if EscPkcs1RsaSsaV15_SHA224_ENABLED == 1
/** SHA-224 algorithm. The length of hashDigest is 28 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA224       3U
#endif

#if EscPkcs1RsaSsaV15_SHA256_ENABLED == 1
/** SHA-256 algorithm. The length of hashDigest is 32 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA256       4U
#endif

#if EscPkcs1RsaSsaV15_SHA384_ENABLED == 1
/** SHA-384 algorithm. The length of hashDigest is 48 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA384       5U
#endif

#if EscPkcs1RsaSsaV15_SHA512_ENABLED == 1
/** SHA-512 algorithm. The length of hashDigest is 64 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA512       6U
#endif

#if EscPkcs1RsaSsaV15_RIPEMD160_ENABLED == 1
/** RIPEMD-160 algorithm. The length of hashDigest is 20 byte. */
#   define EscPkcs1RsaSsaV15_DIGEST_TYPE_R160         7U
#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Describes a digest. */
typedef struct
{
    /** The length of the digest in bytes. */
    Esc_UINT8 digestLen;
    /** The length of digestInfo in bytes. */
    Esc_UINT8 digestInfoLen;
    /** The DER encoded digestInfo. */
    const Esc_UINT8* digestInfo;
} EscPkcs1RsaSsaV15_DigestDescriptionT;

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
    /** A descriptor containing information about the used digest type */
    const EscPkcs1RsaSsaV15_DigestDescriptionT *digestDesc;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaSsaV15_VerifyContext;

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
    /** A descriptor containing information about the used digest type */
    const EscPkcs1RsaSsaV15_DigestDescriptionT *digestDesc;
    /** The RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
} EscPkcs1RsaSsaV15_SignContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES (verification / signing in a single call)        *
 ***************************************************************************/

/**
Signs a message according to RSASSA-PKCS1-v1_5_Sign.

The RSA Key Length is configured in rsa_cfg.h.

\see PKCS#1 v2.1, section 8.2.1
\see rsa_cfg.h

\param[in] digest           Digest of the message to be signed. The length depends on the digestType parameter.
                            See also pkcs1.h for the possible digest lengths.
\param[in] privKey          Private key structure.
\param[out] signature       Buffer to store the computed signature.
\param[in,out] signatureLen In: Length of buffer provided by parameter signature. The buffer should be as large
                                as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                            Out: Number of bytes written to the buffer.
\param[in] digestType       The type of the digest. One of the EscPkcs1RsaSsaV15_DIGEST_TYPE_xxx defines.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscPkcs1RsaSsaV15_Sign(
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT8 digestType );

/**
Verifies the signature of a message according to RSASSA-PKCS1-v1_5_Verify.

The RSA key length is configured in rsa_cfg.h.

\see PKCS#1 v2.1, section 8.2.2
\see rsa_cfg.h

\param[in] signature    Signature created with RSASSA-PKCS1-v1_5_Sign.
\param[in] signatureLen Length of the signature in bytes. This must match the modulus
                        size of the given private key (e.g. for RSA-1024, a length of 1024 / 8 = 128 bytes).
\param[in] pubKey       The public RSA key.
\param[in] digest       Digest of the message to be verified. The length depends on the digestType parameter.
                        See also pkcs1.h for the possible digest lengths.
\param[in] digestType   The type of the digest. One of the EscPkcs1RsaSsaV15_DIGEST_TYPE_xxx defines.

\return Esc_NO_ERROR if everything works fine or Esc_INVALID_SIGNATURE if verification fails.
*/
Esc_ERROR
EscPkcs1RsaSsaV15_Verify(
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 digest[],
    Esc_UINT8 digestType );


/***************************************************************************
 * 7. FUNCTION PROTOTYPES (stepwise verification / signing)                *
 ***************************************************************************/

/**
Signs a message according to RSASSA-PKCS1-v1_5_Sign.

The RSA Key Length is configured in rsa_cfg.h.

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\see PKCS#1 v2.1, section 8.2.1
\see rsa_cfg.h

\param[in]      ctx           The context structure which stores the state of the signature generation.
\param[in]      digest        Digest of the message to be signed. The length depends on the digestType parameter.
                              See also pkcs1.h for the possible digest lengths.
\param[in]      privKey       Private key structure.
\param[out]     signature     Buffer to store the computed signature.
\param[in,out]  signatureLen  In:  Length of buffer provided by parameter signature. The buffer should be as large
                                   as the key size of the public key (e.g. for RSA-1024, it should be 1024 / 8 = 128 bytes).
                              Out: Number of bytes written to the buffer. This is written at the end of the
                                   computation when EscPkcs1RsaSsaV15_SignRun() finished.
\param[in]      digestType    The type of the digest. One of the EscPkcs1RsaSsaV15_DIGEST_TYPE_xxx defines (see pkcs1.h).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscPkcs1RsaSsaV15_SignInit(
    EscPkcs1RsaSsaV15_SignContext *ctx,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT8 digestType );

/**
Run signature generation. Each call may only compute a small part of the overall
computation. Consequently, this function needs to be called until it returns
an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the signature generation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue signature generation.
\retval Esc_NO_ERROR if signature generation finished successfully.
                     The signature was written to the buffer passed to EscPkcs1RsaSsaV15_SignInit().
 */
Esc_ERROR
EscPkcs1RsaSsaV15_SignRun(
    EscPkcs1RsaSsaV15_SignContext *ctx);

/**
Initialize signature verification of a message according to RSASSA-PKCS1-v1_5_Verify.

The RSA key length is configured in rsa_cfg.h.

\warning        This function does NOT create deep copies of any pointer passed to it!
                Therefore, the data behind each pointer must remain allocated/unchanged
                until the computation is finished!

\param[in]  ctx             The context structure which stores the state of the verification.
\param[in]  signature       The signature to be verified.
\param[in]  signatureLen    Length of the signature in bytes.
\param[in]  pubKey          The public RSA key. See rsa.h for conversion routines.
\param[in]  digest          Digest of the message to be verified. The length depends on the digestType parameter.
                            See also pkcs1.h for the possible digest lengths.
\param[in]  digestType      The type of the digest. One of the EscPkcs1RsaSsaV15_DIGEST_TYPE_xxx defines.

\return Esc_NO_ERROR on successful initialization.
*/
Esc_ERROR
EscPkcs1RsaSsaV15_VerifyInit(
    EscPkcs1RsaSsaV15_VerifyContext *ctx,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 digest[],
    Esc_UINT8 digestType);

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
EscPkcs1RsaSsaV15_VerifyRun(
    EscPkcs1RsaSsaV15_VerifyContext *ctx);

/***************************************************************************
 * 8. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
