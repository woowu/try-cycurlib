/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       EdDSA signature scheme.

   \details     EdDSA is a Schnorr signature scheme by Bernstein et al.
                using a twisted Edwards curve.

                This implementation currently supports ed25519 variants with SHA-512.

   \see         Bernstein et al. - High-speed high-security signatures (2012)
                RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
                draft-irtf-cfrg-eddsa-05 - RFC 8032 Draft

   $Rev: 2799 $
 */
/***************************************************************************/

#ifndef ESC_EDDSA_H_
#define ESC_EDDSA_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "random.h"
#include "_fearith.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Hash defines */

/** SHA-512 algorithm. The length of the hash's digest is 64 byte. */
#define EscEdDsa_DIGEST_TYPE_SHA512 0U


/* Length defines, depending on current configuration */

/** Maximmum length of EdDSA signature in bytes. */
#define EscEdDsa_SIGNATURE_BYTES_MAX (2U * EscFeArith_KEY_BYTES_MAX)

/** Maximum EdDSA key length in bytes. */
#define EscEdDsa_KEY_BYTES_MAX EscFeArith_KEY_BYTES_MAX


/** The external CurveId identifier. Is actually the id type define in the Field arithmetic module */
typedef EscFeArith_CurveId EscEd_CurveId;

/** ID for curve ED-25519 (Edwards curve from Curve25519) */
#define EscEdDsa_CURVE_ED25519   EscFeArith_CURVE_ED25519


/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function generates a fresh private key and the corresponding public key.
 *
 * - Gets random key (k).
 * - Hash k ( H(k) )
 * - Constructs a from H(k)
 * - Computes pubKey A = a * B (B == base point)
 *
 * \param[out] pubKey The generated public key.
 * \param[in,out] pubKeyLen In: Size of the pubKey buffer in bytes. EscEdDsa_KEY_BYTES_MAX can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the public key in bytes
 * \param[out] privKey The generated private key.
 * \param[in,out] privKeyLen In: Size of the privKey buffer in bytes. EscEdDsa_KEY_BYTES_MAX can
                                    be used as the maximum size allowed by configuration.
                             Out: Size of the private key in bytes
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h.
 * \param[in] digestType The type of the digest. Currently only EscEdDsa_DIGEST_TYPE_SHA512 is supported.
 * \param[in] curveId The ID of the selected Edwards curve. Currently only EscEdDsa_CURVE_ED25519 is supported
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEdDsa_KeyGeneration(
    Esc_UINT8 pubKey[],
    Esc_UINT32* pubKeyLen,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId );

/**
 * Derive the public key from a given private key. This function can be used
 * as an alternative to EscEdDsa_KeyGeneration() if a private key is already available,
 * but the corresponding public key still needs to be computed.
 *
 * \param[out] pubKey The generated public key.
 * \param[in,out] pubKeyLen In: Size of the pubKey buffer in bytes. EscEdDsa_KEY_BYTES_MAX can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the public key in bytes
 * \param[in] privKey The given private key.
 * \param[in] privKeyLen Size of the private key in bytes.
 * \param[in] digestType The type of the digest. Currently only EscEdDsa_DIGEST_TYPE_SHA512 is supported.
 * \param[in] curveId The ID of the selected Edwards curve. Currently only EscEdDsa_CURVE_ED25519 is supported
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEdDsa_DerivePubKeyFromPrivKey(
    Esc_UINT8 pubKey[],
    Esc_UINT32* pubKeyLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId );

/**
 * This function generates the EdDSA signature for a given message.
 *
 * Description about the different ed25519 variants and their usage:
 *
 * # ed25519 as defined in the Bernstein paper (PureEdDSA), RFC 8032 or the RFC draft choose:
 *      preHashed: FALSE
 *      context: Esc_NULL_PTR
 *      contextLen: 0
 *      message: original message, non-Hashed
 *
 * # ed25519ctx as defined in RFC 8032
 *      preHashed: FALSE
 *      context: Buffer with context
 *      contextLen: Length of context string, between 1 and 255 bytes.
 *      message: original message, non-Hashed
 *
 * # ed25519ph as defined in RFC 8032
 *      preHashed: TRUE
 *      context: Buffer with context or Esc_NULL_PTR
 *      contextLen: Length of context string, between 0 and 255 bytes.
 *      message: SHA512 digest of the original message (hash the message before signing)
 *
 * # ed25519ph as defined in RFC Draft v05, also called Hashed-EdDSA in Bernstein papers
 *      preHashed: FALSE
 *      context: Esc_NULL_PTR
 *      contextLen: 0
 *      message: SHA512 digest of the original message (hash the message before signing)
 *
 * The of usage of a context string should be carefully evaluated, cf. RFC 8032, Section 8.3.
 *
 * \param[in] preHashed Boolean flag, TRUE if a PreHash variant of RFC8032, e.g. ed25519ph, is used.
 * \param[out] signature The generated EdDSA signature.
 * \param[in,out] signatureLen In: Size of the signature buffer in bytes. EscEdDsa_SIGNATURE_BYTES_MAX can
                                be used as the maximum size allowed by configuration.
                            Out: Size of the signature in bytes
 * \param[in] message Message to be signed.
 * \param[in] messageLen Length of the message in bytes.
 * \param[in] privKey The private key.
 * \param[in] privKeyLen Length of the private key in bytes. Length must match with the selected curve.
 * \param[in] pubKey The public key.
 * \param[in] pubKeyLen Length of the private key in bytes. Length must match with the selected curve.
 * \param[in] digestType The type of the digest. Currently only EscEdDsa_DIGEST_TYPE_SHA512 is supported.
 * \param[in] curveId The ID of the selected Edwards curve. Currently only EscEdDsa_CURVE_ED25519 is supported
 * \param[in] context Buffer which contains a context string. Should be set to Esc_NULL_PTR if contextLen == 0.
 * \param[in] contextLen Length of the context string. Length between 0 and 255 bytes are allowed.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEdDsa_SignatureGeneration(
    Esc_BOOL preHashed,
    Esc_UINT8 signature[],
    Esc_UINT32* signatureLen,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const Esc_UINT8 pubKey[],
    Esc_UINT32 pubKeyLen,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId,
    const Esc_UINT8 context[],
    Esc_UINT8 contextLen );


/**
 * This function verifies the corresponding signature for a given message.
 *
 * # ed25519 as defined in the Bernstein paper (PureEdDSA), RFC 8032 or the RFC draft choose:
 *      preHashed: FALSE
 *      context: Esc_NULL_PTR
 *      contextLen: 0
 *      message: original message, non-Hashed
 *
 * # ed25519ctx as defined in RFC 8032
 *      preHashed: FALSE
 *      context: Buffer with context
 *      contextLen: Length of context string, between 1 and 255 bytes.
 *      message: original message, non-Hashed
 *
 * # ed25519ph as defined in RFC 8032
 *      preHashed: TRUE
 *      context: Buffer with context or Esc_NULL_PTR
 *      contextLen: Length of context string, between 0 and 255 bytes.
 *      message: SHA512 digest of the original message (hash the message before signing)
 *
 * # ed25519ph as defined in RFC Draft v05, also called Hashed-EdDSA in Bernstein papers
 *      preHashed: FALSE
 *      context: Esc_NULL_PTR
 *      contextLen: 0
 *      message: SHA512 digest of the original message (hash the message before signing)
 *
 * The of usage of a context string should be carefully evaluated, cf. RFC 8032, Section 8.3.
 *
 * \param[in] preHashed Boolean flag, TRUE if a PreHash variant of RFC8032, e.g. ed25519ph, is used.
 * \param[in] message The signed message.
 * \param[in] messageLen Length of the message in bytes.
 * \param[in] signature EdDSA signature.
 * \param[in] signatureLen Length of the signature in bytes. Length must match with the selected curve.
 * \param[in] pubKey The public key.
 * \param[in] pubKeyLen Length of the public key in bytes. Length must match with the selected curve.
 * \param[in] digestType The type of the digest. Currently only EscEdDsa_DIGEST_TYPE_SHA512 is supported.
 * \param[in] curveId The ID of the selected Edwards curve. Currently only EscEdDsa_CURVE_ED25519 is supported
 * \param[in] context Buffer which contains a context string. Should be set to Esc_NULL_PTR if contextLen == 0.
 * \param[in] contextLen Length of the context string. Length between 0 and 255 bytes are allowed.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_NO_ERROR             The provided signature is valid.
 * \retval Esc_INVALID_SIGNATURE    The provided signature is invalid.
 */
Esc_ERROR
EscEdDsa_SignatureVerification(
    Esc_BOOL preHashed,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    const Esc_UINT8 pubKey[],
    Esc_UINT32 pubKeyLen,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId,
    const Esc_UINT8 context[],
    Esc_UINT8 contextLen );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
