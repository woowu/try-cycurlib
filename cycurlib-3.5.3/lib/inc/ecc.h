/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Elliptic Curve Cryptography (ECC)

   Elliptic Curve Diffie/Hellman (ECDH)
   Elliptic Curve Digital Signature Algorithm (ECDSA)
   Elliptic Curve Key Generation

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_ECC_H_
#define ESC_ECC_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "ecc_cfg.h"
#include "_fearith.h"
#include "_ptarithws.h"
#include "eccarith.h"
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

 /** As Signature- and KeyGeneration depend on random nonces with a specific structure, this is the maximum
    number of calls to the random nonce generation function until a Esc_INTERNAL_FUNCTION_ERROR is thrown
    to prevent infinite loops */
#define EscEcc_MAX_GENERATE_NONCE_CALLS 4U

/** Maximum key length in bytes. Is actually defined in the Field arithmetic module */
#define EscEcc_KEY_BYTES_MAX EscFeArith_KEY_BYTES_MAX

/** The external CurveId identifier. Is actually the id type define in the Field arithmetic module */
typedef EscFeArith_CurveId EscEcc_CurveId;

/** The external curve IDs. Actually defined the Field arithmetic module */
/** ID for curve secp192r1 (also known as NIST P-192) */
#define EscEcc_CURVE_SECP_192 EscFeArith_CURVE_SECP_192
/** ID for curve secp224r1 (also known as NIST P-224) */
#define EscEcc_CURVE_SECP_224 EscFeArith_CURVE_SECP_224
/** ID for curve secp256r1 (also known as NIST P-256) */
#define EscEcc_CURVE_SECP_256 EscFeArith_CURVE_SECP_256
/** ID for curve secp384r1 (also known as NIST P-384) */
#define EscEcc_CURVE_SECP_384 EscFeArith_CURVE_SECP_384
/** ID for curve secp521r1 (also known as NIST P-521) */
#define EscEcc_CURVE_SECP_521 EscFeArith_CURVE_SECP_521

/** ID for curve brainpoolP160r1 */
#define EscEcc_CURVE_BRAINPOOL_P160   EscFeArith_CURVE_BRAINPOOL_P160
/** ID for curve brainpoolP192r1 */
#define EscEcc_CURVE_BRAINPOOL_P192   EscFeArith_CURVE_BRAINPOOL_P192
/** ID for curve brainpoolP224r1 */
#define EscEcc_CURVE_BRAINPOOL_P224   EscFeArith_CURVE_BRAINPOOL_P224
/** ID for curve brainpoolP256r1 */
#define EscEcc_CURVE_BRAINPOOL_P256   EscFeArith_CURVE_BRAINPOOL_P256
/** ID for curve brainpoolP320r1 */
#define EscEcc_CURVE_BRAINPOOL_P320   EscFeArith_CURVE_BRAINPOOL_P320
/** ID for curve brainpoolP384r1 */
#define EscEcc_CURVE_BRAINPOOL_P384   EscFeArith_CURVE_BRAINPOOL_P384
/** ID for curve brainpoolP512r1 */
#define EscEcc_CURVE_BRAINPOOL_P512   EscFeArith_CURVE_BRAINPOOL_P512

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

 /** Public key for ECC */
typedef struct
{
    /** Pointer to x */
    Esc_UINT8 x[EscFeArith_KEY_BYTES_MAX];
    /** Pointer to y */
    Esc_UINT8 y[EscFeArith_KEY_BYTES_MAX];
} EscEcc_PublicKeyT;

/** ECDSA signature */
typedef struct
{
    /** Bytes of r */
    Esc_UINT8 r_bytes[EscFeArith_KEY_BYTES_MAX];
    /** Bytes of s */
    Esc_UINT8 s_bytes[EscFeArith_KEY_BYTES_MAX];
} EscEcc_SignatureT;
 
#if EscEcc_ECDH_ENABLED == 1
/** ECDH context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Shared Secret buffer for ECDH result. */
    Esc_UINT8* sharedSecret;
    /** Pointer to the length of the resulting shared secret. */
    Esc_UINT32* sharedSecretLen;
    /** ECC curve which was selected by caller */
    const EscPtArithWs_CurveT* curve;
    /** Field Element which stores the private key. */
    EscFeArith_FieldElementT dA_ecc_field_element;
    /** Temporary point buffer for storing the input and result of the point multiplication. */
    EscPtArithWs_PointT pX;
    /** Union for large contexts which are not used at the same time (one context includes the other) */
    union {
        /** Context for the point multiplication */
        EscEcc_Pt_JacobianMultiplyBinaryContext jacobMulBinCtx;
        /** Context for the Jacobian to affine conversion */
        EscEcc_Pt_ToAffineContext toAffineCtx;
    } serialCtx;
} EscEcc_SharedSecretContext;
#endif

/** Key generation context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Buffer for generated private key */
    Esc_UINT8* privKey;
    /** Pointer to the length of the generated private key. */
    Esc_UINT32* privKeyLen;
    /** Pointer to the generated public key. */
    EscEcc_PublicKeyT* pQ;
    /** ECC curve which was selected by caller */
    const EscPtArithWs_CurveT* curve;
    /** Field Element which stores the generated private key. */
    EscFeArith_FieldElementT d_ecc_field_element;
    /** Temporary point buffer for storing the generated public key point. */
    EscPtArithWs_PointT pQ_point;

    /** Union for large contexts which are not used at the same time (one context includes the other) */
    union {
        /** Context for the point multiplication */
        EscEcc_Pt_JacobianMultiplyBinaryContext jacobMulBinCtx;
        /** Context for the Jacobian to affine conversion */
        EscEcc_Pt_ToAffineContext toAffineCtx;
        /** Context for the multiplication with the base point */
        EscEcc_Pt_BasePointMultContext basePointMultCtx;
    } serialCtx;
} EscEcc_KeyGenerationContext;

#if EscEcc_ECDSA_ENABLED == 1
/** ECDSA signature verification context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** ECC curve which was selected by caller */
    const EscPtArithWs_CurveT* curve;
    /** Public key point */
    EscPtArithWs_PointT pQ_point;
    /** Field Element which stores the signature part r. */
    EscFeArith_FieldElementT r;
    /** Field Element which stores the signature part s. */
    EscFeArith_FieldElementT s;
    /** Temporary Field Element which stores the hashed message and the value u1. */
    EscFeArith_FieldElementT hash_u1;
    /** Temporary Field Element which stores the value u2. */
    EscFeArith_FieldElementT u2;
    /** Temporary point */
    EscPtArithWs_PointT pX1;
#if EscEcc_USE_SHAMIRS_TRICK == 0
    /** Temporary point */
    EscPtArithWs_PointT pX2;
#endif

    /** Union for large contexts which are not used at the same time (one context includes the other) */
    union {
#if EscEcc_USE_SHAMIRS_TRICK == 1
        /** Context for the dual Multiply (Shamir's trick) algorithm. */
        EscEcc_Pt_JacDualMulAddBinContext jacDualMulBinCtx;
#else
        /** Context for the point multiplication */
        EscEcc_Pt_JacobianMultiplyBinaryContext jacobMulBinCtx;
#endif
        /** Context for the modular inversion */
        EscEcc_Fe_ModularInvertContext modInvertCtx;
        /** Context for the jacobian to affine conversion */
        EscEcc_Pt_ToAffineContext toAffineCtx;
    } serialCtx;
} EscEcc_SigVerContext;


/** ECDSA signature generation context. */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Pointer to the signature struct */
    EscEcc_SignatureT* signature;
    /** Random state which may be required by your random implementation. */
    void* randomState;
    /** Random function as specified in random.h. */
    EscRandom_GetRandom getRandomFunc;

    /** ECC curve which was selected by caller */
    const EscPtArithWs_CurveT* curve;
    /** Counter for random number generation for k-calculation */
    Esc_UINT8 generateNonceCount;
    /** Field Element which stores the hash. */
    EscFeArith_FieldElementT msg_hash_ecc_field_element;
    /** Field Element which stores the private key. */
    EscFeArith_FieldElementT d_ecc_field_element;
    /** Field Element which stores the random value k and the inverse. */
    EscFeArith_FieldElementT k_ecc_field_element;
    /** Temporary point buffer for storing the result of the point multiplication. */
    EscPtArithWs_PointT pX;
    /** Field Element which stores the signature part r and s. */
    EscFeArith_FieldElementT r_s;

    /** Union for large contexts which are not used at the same time (one context includes the other) */
    union {
        /** Context for the point multiplication */
        EscEcc_Pt_JacobianMultiplyBinaryContext jacobMulBinCtx;
        /** Context for the modular inversion */
        EscEcc_Fe_ModularInvertContext modInvertCtx;
        /** Context for the Jacobian to affine conversion */
        EscEcc_Pt_ToAffineContext toAffineCtx;
        /** Context for the multiplication with the base point */
        EscEcc_Pt_BasePointMultContext basePointMultCtx;
    } serialCtx;
} EscEcc_SigGenContext;
#endif /* EscEcc_ECDSA_ENABLED */

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/
/**
 * This function generates a fresh private key and the corresponding public key.
 *
 * - Q = d * G
 * - Public Key:  Q
 * - Private Key: d
 * - Basepoint:   G
 *
 * \param[out] pQ Public key.
 * \param[out] privKey Private key of length curve.keySizeBytes (maximum allowed size is EscEcc_KEY_BYTES_MAX bits).
 * \param[in,out] privKeyLen In: Size of the privKey buffer in bytes. EscEcc_KEY_BYTES_MAX can
                                    be used as the maximum size allowed by configuration.
                             Out: Size of the private key in bytes
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_KeyGeneration(
    EscEcc_PublicKeyT* pQ,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId );


/**
 * This function validates a public key with respect to the selected curve.
 * Elliptic Curve Public Key Validation according to ANSI X9.62-2005 Section A.4.2.
 *
 * Check, that:
 * - Q != (0)
 * - Qx & Qy are properly represented elements in GF(p)
 * - Q lies on elliptic curve defined by a & b
 *
 * Note that a point multiplication with the base point order with a
 * subsequent check for zero is not required for Brainpool or NIST prime curves.
 *
 * \param[in] pQ Public key point (affine).
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine or validation error
 */
Esc_ERROR
EscEcc_PublicKeyValidation(
    const EscEcc_PublicKeyT* pQ,
    const EscEcc_CurveId curveId );

#if EscEcc_ECDSA_ENABLED == 1
/**
 * This function generates the corresponding signature for a hashed message.
 * ECDSA Signature Generation according to ANSI X9.62-2005 Section 7.3.
 *
 * \param[out] signature ECC signature.
 * \param[in] msgHash Hash of the message to be signed.
 * \param[in] msgHashLen Length of the hash in bytes. If the hash is shorter than the key size of the selected curve,
                the leftmost (most significant) bits are padded with zero. If longer, only the leftmost (most significant)
                bits of the hash are used.
                Note: The maximum hash length is currently limited to 64 bytes.
 * \param[in] privKey Private key.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_SignatureGeneration(
    EscEcc_SignatureT* signature,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId );

/**
 * This function verifies the corresponding signature for a hashed message.
 * ECDSA Signature Verification according to ANSI X9.62-2005 Section 7.4.1.
 *
 * \warning This function does NOT validate the public key pQ! You can use EscEcc_PublicKeyValidation()
 *          to check if the public key is valid.
 *
 * \param[in] msgHash Hash of the signed message.
 * \param[in] msgHashLen Length of the hash in bytes. If the hash is shorter than the key size of the selected curve,
                the leftmost (most significant) bits are padded with zero. If longer, only the leftmost (most significant)
                bits of the hash are used.
 * \param[in] signature ECC signature.
 * \param[in] pQ Public key point Q.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_NO_ERROR             The provided signature is valid.
 * \retval Esc_INVALID_SIGNATURE    The provided signature is invalid.
 */
Esc_ERROR
EscEcc_SignatureVerification(
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const EscEcc_SignatureT* signature,
    const EscEcc_PublicKeyT* pQ,
    const EscEcc_CurveId curveId );

#endif /* EscEcc_ECDSA_ENABLED */

#if EscEcc_ECDH_ENABLED == 1
/**
 * This function computes the shared secret z based on ECDH.
 *
 * - P = dA * QB
 * - Shared Secret:    z = P->x
 * - Private Key of A: dA (privKey)
 * - Public Key of B:  QB
 *
 * \warning This function does NOT validate the public key pQB! You can use EscEcc_PublicKeyValidation()
 *          to check if the public key is valid.
 *
 * \param[out] sharedSecret Shared secret z.
 * \param[in,out] sharedSecretLen In: Size of the sharedSecret buffer in bytes. EscEcc_KEY_BYTES_MAX can
                                      be used as the maximum size allowed by configuration.
                                  Out: Size of the shared secret in bytes
 * \param[in] privKey Private key.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] pQB Public key of B.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_ComputeSharedSecret(
    Esc_UINT8 sharedSecret[],
    Esc_UINT32* sharedSecretLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_PublicKeyT* pQB,
    const EscEcc_CurveId curveId );

#endif /* EscEcc_ECDH_ENABLED */


/**
 * Initialize the key generation for generation of a private and public key.
 *
 * - Q = d * G
 * - Public Key:  Q
 * - Private Key: d
 * - Basepoint:   G
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx The ECC key generation context.
 * \param[out] pQ Public key.
 * \param[out] privKey Private key of length curve.keySizeBytes (maximum allowed size is EscEcc_KEY_BYTES_MAX bits).
 * \param[in,out] privKeyLen In: Size of the privKey buffer in bytes. EscEcc_KEY_BYTES_MAX can
                                    be used as the maximum size allowed by configuration.
                             Out: Size of the private key in bytes
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_KeyGenerationInit(
    EscEcc_KeyGenerationContext *ctx,
    EscEcc_PublicKeyT* pQ,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId );

/**
 * Run the key generation.
 *
 * \param[in,out] ctx The ECC key generation context.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_AGAIN    The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR If key generation finished successfully. The result is stored in
                        the key elements passed to EscEcc_KeyGenerationInit().
 */
Esc_ERROR
EscEcc_KeyGenerationRun(
    EscEcc_KeyGenerationContext *ctx );

#if EscEcc_ECDSA_ENABLED == 1
/**
 * Initialize ECDSA signature generation according to ANSI X9.62-2005 Section 7.3.
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx The ECC signature generation context.
 * \param[out] signature ECC signature.
 * \param[in] msgHash Hash of the message to be signed.
 * \param[in] msgHashLen Length of the hash in bytes. If the hash is shorter than the key size of the selected curve,
                         the leftmost (most significant) bits are padded with zero. If longer, only the leftmost (most significant)
                         bits of the hash are used.
                         Note: The maximum hash length is currently limited to 64 bytes.
 * \param[in] privKey Private key.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] randomState Random state which may be required by your random implementation.
 * \param[in] getRandomFunc Random function as specified in random.h
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_SignatureGenerationInit(
    EscEcc_SigGenContext *ctx,
    EscEcc_SignatureT* signature,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId );

/**
 * Run ECDSA signature generation according to ANSI X9.62-2005 Section 7.3.
 *
 * \param[in,out] ctx The ECC signature generation context.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_AGAIN       The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR    The computation finished successfully. The result is stored in
 *                         the signature element passed to EscEcc_SignatureGenerationInit().
 */
Esc_ERROR
EscEcc_SignatureGenerationRun(
    EscEcc_SigGenContext *ctx );

/**
 * Initialize ECDSA signature verification according to ANSI X9.62-2005 Section 7.4.1.
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx The ECC signature generation context.
 * \param[in] msgHash Hash of the signed message.
 * \param[in] msgHashLen Length of the hash in bytes. If the hash is shorter than the key size of the selected curve,
                the leftmost (most significant) bits are padded with zero. If longer, only the leftmost (most significant)
                bits of the hash are used.
 * \param[in] signature ECC signature.
 * \param[in] pQ Public key point Q.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_SignatureVerificationInit(
    EscEcc_SigVerContext *ctx,
    const Esc_UINT8 msgHash[],
    Esc_UINT32 msgHashLen,
    const EscEcc_SignatureT* signature,
    const EscEcc_PublicKeyT* pQ,
    const EscEcc_CurveId curveId );

/**
 * Run ECDSA signature verification according to ANSI X9.62-2005 Section 7.4.1.
 *
 * \param[in,out] ctx The ECC signature generation context.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_AGAIN                The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR             The signature provided in EscEcc_SignatureVerificationInit is valid.
 * \retval Esc_INVALID_SIGNATURE    The signature provided in EscEcc_SignatureVerificationInit is invalid.
 */
Esc_ERROR
EscEcc_SignatureVerificationRun(
    EscEcc_SigVerContext *ctx );
#endif

#if EscEcc_ECDH_ENABLED == 1
/**
 * Init shared secret computation based on ECDH.
 *
 * - P = dA * QB
 * - Shared Secret:    z = P->x
 * - Private Key of A: dA (privKey)
 * - Public Key of B:  QB
 *
 * \warning This function does NOT validate the public key pQB! You can use EscEcc_PublicKeyValidation()
 *          to check if the public key is valid.
 *
 * \warning This function does NOT create deep copies of any pointer passed to it!
 *          Therefore, the data behind each pointer must remain allocated/unchanged
 *          until the computation is finished!
 *
 * \param[out] ctx The ECDH context.
 * \param[out] sharedSecret Shared secret z.
 * \param[in,out] sharedSecretLen In: Size of the sharedSecret buffer in bytes. EscEcc_KEY_BYTES_MAX can
                                      be used as the maximum size allowed by configuration.
                                  Out: Size of the shared secret in bytes
 * \param[in] privKey Private key.
 * \param[in] privKeyLen Length of the private key in bytes. This must match the selected curve (curve.keySizeBytes).
 * \param[in] pQB Public key of B.
 * \param[in] curveId The ID of the selected elliptic curve.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscEcc_ComputeSharedSecretInit(
    EscEcc_SharedSecretContext *ctx,
    Esc_UINT8 sharedSecret[],
    Esc_UINT32* sharedSecretLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_PublicKeyT* pQB,
    const EscEcc_CurveId curveId );

/**
 * Run shared secret computation based on ECDH.
 *
 * \param[in,out] ctx The ECDH context.
 *
 * \return Any of the below return codes or a corresponding error code on failure.
 * \retval Esc_AGAIN    The computation is not finished and the function must be called again.
 * \retval Esc_UNEXPECTED_FUNCTION_CALL The context is not the correct state for this call. Start with the Init function.
 * \retval Esc_NO_ERROR The computation finished successfully. The result is stored in sharedSecret buffer passed to EscEcc_ComputeSharedSecretInit().
 */
Esc_ERROR
EscEcc_ComputeSharedSecretRun(
    EscEcc_SharedSecretContext *ctx );

#endif /* EscEcc_ECDH_ENABLED */

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_ECC_H_ */
