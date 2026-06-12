/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       x.509 Parser supporting SHA1 and SHA2 with RSA

   Supported algorithms:
       - sha1WithRSAEncryption
       - sha224WithRSAEncryption
       - sha256WithRSAEncryption
       - sha384WithRSAEncryption
       - sha512WithRSAEncryption

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_X509_RSA_H_
#define ESC_X509_RSA_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "x509.h"

#if (EscX509_ALGORITHM_RSA_ENABLED)

#include "der.h"
#include "rsa.h"

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1)
#include "pkcs1_rsassa_v15.h"
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
#include "pkcs1_rsassa_pss.h"
#endif

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
EscX509Rsa_ParseSignature(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
Reads the public key of a given x.509 certificate.

\param[in] keySeq DER context pointing to SubjectPublicKeyInfo.subjectPublicKey.
\param[out] cert Updated x.509 certificate structure.
\return Esc_NO_ERROR if everything works fine.
\note Local function prototype - not intended to be used directly.
*/
Esc_ERROR
EscX509Rsa_ParsePubKey(
    EscDer_ContextT* keySeq,
    EscX509_CertificateT* cert );

/**
Verify an RSA signature (either PKCS1-RSASSA-V1_5 or PKCS1-RSASSA-PSS).

\param[in]  digest      The digest of the signed data (i.e. hash over the TBS part of the certificate).
\param[in]  digestLen   Length of the digest in bytes.
\param[in]  signature   The signature of the certificate.
\param[in]  verificationKey The public key to verify the signature.

\returns Esc_NO_ERROR if the signature is correct.
\returns Esc_INVALID_SIGNATURE if the signature is incorrect.
 */
Esc_ERROR
EscX509Rsa_VerifySignature(
    const Esc_UINT8 digest[],
    Esc_UINT32 digestLen,
    const EscX509_SignatureT *signature,
    const EscX509_PubKeyT *verificationKey);

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
/**
Parse the PSS parameters of an AlgorithmIdentifier.

\param[in]  keySeq      The DER context pointing directly behind the algorithm OID.
\param[in]  signature   The signature struct to be filled while parsing. The hash function is
                        added to the signature type and the salt length is set.

\return Esc_NO_ERROR if the parameters were parsed successfully.
 */
Esc_ERROR
EscX509Rsa_ParsePssParameters(
    EscDer_ContextT* keySeq,
    EscX509_SignatureT *signature);
#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#endif /* EscX509_ALGORITHM_RSA_ENABLED */

#ifdef  __cplusplus
}
#endif

#endif /* ESC_X509_RSA_H_ */
