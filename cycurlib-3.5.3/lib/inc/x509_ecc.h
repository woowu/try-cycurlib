/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       X.509 Parser supporting ECDSA

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_X509_SHA2_ECC_H_
#define ESC_X509_SHA2_ECC_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "x509.h"

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)

#include "der.h"
#include "sha_256.h"
#include "ecc.h"

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

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/* local functions prototypes - not intended to be used directly */


/**
Reads the signature of a given x.509 certificate.

\param[in] ctx Context of the DER encoded x.509 certificate.
\param[out] ctx Updated context of the DER encoded x.509 certificate.
\param[out] cert Updated x.509 certificate structure.
\return Esc_NO_ERROR if everything works fine.
\note Local function prototype - not intended to be used directly.
*/
Esc_ERROR
EscX509Sha2Ecc_ParseSignature(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
Parse the parameters of an ECC public key's AlgorithmIdentifier.

\param[in]  certCtx     The DER context pointing directly behind the algorithm OID.
\param[out] curveId     The curve ID.

\return Esc_NO_ERROR if the parameters were parsed successfully.
 */
Esc_ERROR
EscX509Sha2Ecc_ParseCurveFromAlgoParams(
    EscDer_ContextT* certCtx,
    EscEcc_CurveId *curveId );

/**
Verify an ECDSA signature.

\param[in]  digest      The digest of the signed data (i.e. hash over the TBS part of the certificate).
\param[in]  digestLen   Length of the digest in bytes.
\param[in]  signature   The signature of the certificate.
\param[in]  verificationKey The public key to verify the signature.

\returns Esc_NO_ERROR if the signature is correct.
\returns Esc_INVALID_SIGNATURE if the signature is incorrect.
 */
Esc_ERROR
EscX509Sha2Ecc_VerifySignature(
    const Esc_UINT8 digest[],
    Esc_UINT32 digestLen,
    const EscX509_SignatureT *signature,
    const EscX509_PubKeyT *verificationKey);

/**
Reads the public key of a given x.509 certificate.

\param[in, out] keySeq Context of the DER encoded x.509 certificate.
\param[out] cert Updated x.509 certificate structure.
\return Esc_NO_ERROR if everything works fine.
\note Local function prototype - not intended to be used directly.
\note We only support named curves.
*/
Esc_ERROR
EscX509Sha2Ecc_ParsePubKey(
    EscDer_ContextT* keySeq,
    EscX509_CertificateT* cert );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#endif /* EscX509_ALGORITHM_ECDSA_ENABLED == 1 */

#ifdef  __cplusplus
}
#endif

#endif /* ESC_X509_SHA2_ECC_H_ */
