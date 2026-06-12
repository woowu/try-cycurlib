/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       x.509 Parser

   $Rev: 3832 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "x509.h"

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
#   include "x509_ecc.h"
#endif

#if (EscX509_ALGORITHM_RSA_ENABLED)
#   include "x509_rsa.h"
#endif

#if (EscX509_HASH_SHA1_ENABLED == 1)
#   include "sha_1.h"
#endif

#if (EscX509_HASH_SHA224_ENABLED == 1) || (EscX509_HASH_SHA256_ENABLED == 1)
#   include "sha_256.h"
#endif

#if (EscX509_HASH_SHA384_ENABLED == 1) || (EscX509_HASH_SHA512_ENABLED == 1)
#   include "sha_512.h"
#endif

/*
   Certificate ::= SEQUENCE {
   tbsCertificate          TBSCertificate,
   signatureAlgorithm      AlgorithmIdentifier,
   signature               BIT STRING
   }

   TBSCertificate ::= SEQUENCE {
   version          [ 0 ]  Version DEFAULT v1(0),
   serialNumber            CertificateSerialNumber,
   signature               AlgorithmIdentifier,
   issuer                  Name,
   validity                Validity,
   subject                 Name,
   subjectPublicKeyInfo    SubjectPublicKeyInfo,
   issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
   subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
   extensions        [ 3 ] Extensions OPTIONAL
   }

   Validity ::= SEQUENCE {
   notBefore               UTCTIME,
   notAfter                UTCTIME
   }

   RSAPublicKey ::= SEQUENCE {
   modulus            INTEGER,    -- n
   publicExponent     INTEGER  }  -- e
   }

   DigestInfo ::= SEQUENCE {
   digestAlgorithm AlgorithmIdentifier,
   digest OCTET STRING
   }

   ALGORITHM-IDENTIFIER ::= CLASS {
   &id OBJECT IDENTIFIER UNIQUE,
   &Type OPTIONAL
   }    WITH SYNTAX { OID &id [PARAMETERS &Type] }
   -- Note: the parameter InfoObjectSet in the following definitions allows a
   -- distinct information object set to be specified for sets of algorithms
   -- such as:
   -- DigestAlgorithms ALGORITHM-IDENTIFIER ::= {
   -- { OID id-md2 PARAMETERS NULL }|
   -- { OID id-md5 PARAMETERS NULL }|
   -- { OID id-EscSha1_Calc PARAMETERS NULL }
   -- }
   --
   AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet } ::= SEQUENCE {
   algorithm
   ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
   parameters
   ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}{@.algorithm}) OPTIONAL
   }

   sha-1WithRSAEncryption OBJECT IDENTIFIER  ::=  {
   iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
   pkcs-1(1) 5  }

   Name ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::= SET OF AttributeValueAssertion

   AttributeValueAssertion ::= SEQUENCE {
   attributeType           OBJECT IDENTIFIER,
   attributeValue          ANY
   }

   Name ::= SEQUENCE SIZE(1..5) OF RelativeDistinguishedName
   RelativeDistinguishedName ::= SET SIZE(1) OF AttributeTypeAndValue
   AttributeTypeAndValue ::= { OID, C | O | OU | CN }

   countryName     ::= SEQUENCE { { 2 5 4 6 }, StringType( SIZE( 2 ) ) }
   organization    ::= SEQUENCE { { 2 5 4 10 }, StringType( SIZE( 1...64 ) ) }
   organizationalUnitName
   ::= SEQUENCE { { 2 5 4 11 }, StringType( SIZE( 1...64 ) ) }
   commonName      ::= SEQUENCE { { 2 5 4 3 }, StringType( SIZE( 1...64 ) ) }
   localityName    ::= SEQUENCE { { 2 5 4 7 }, StringType( SIZE( 1...64 ) ) }
   stateOrProvinceName  ::= SEQUENCE { { 2 5 4 8 }, StringType( SIZE( 1...64 ) ) }
   emailAddress    ::= SEQUENCE { { 1 2 840 113549 1 9 1 }, IA5String } -- not used

 */

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of OID array for extension OIDs */
#define EscX509_MAX_EXTENSION_OID_COMPONENTS    10U

/** Length of OID array for algorithm OIDs */
#define EscX509_MAX_ALGORITHM_OID_COMPONENTS    10U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * Parse the signature algorithm of the certificate (i.e. the AlgorithmIdentifier).
 * The signature algorithm is compared against a list of known OIDs depending on
 * the configuration of the parser.
 *
 * \param[in,out]   ctx         The DER context pointing to the AlgorithmIdentifier of the signature algorithm.
 * \param[out]      signature   The abstract signature. The type is set in the signature
 *                              and in the case of PSS, the salt length is set, too.
 *
 * \retval Esc_NO_ERROR if successful.
 * \retval Esc_INVALID_SIGN_ALGORITHM on failure.
 */
static Esc_ERROR
EscX509_ParseSignatureAlgorithm(
    EscDer_ContextT* ctx,
    EscX509_SignatureT *signature);

/**
 * Parse the public key algorithm of the certificate (i.e. the AlgorithmIdentifier).
 * The signature algorithm is compared against a list of known OIDs depending on
 * the configuration of the parser.
 *
 * \param[in,out]   ctx     The DER context pointing to the AlgorithmIdentifier of the public key algorithm.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 * \retval Esc_INVALID_PUBKEY_ALGORITHM on failure.
 */
static Esc_ERROR
EscX509_ParsePublicKeyAlgorithm(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
 * Parse the list of extensions of the certificate.
 *
 * \param[in,out]   ctx     The DER context pointing to the extension list.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseExtensions(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
 * Parse the keyUsage extension.
 *
 * \param[in,out]   ctx     The DER context pointing to the extension.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseKeyUsageExtension(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
 * Parse the basicConstraints extension. The pathLenConstraint is limited to 2^32-1.
 *
 * \param[in,out]   ctx     The DER context pointing to the extension.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseBasicConstraintsExtension(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
 * Parse the to-be-signed (TBS) part of the certificate.
 *
 * \param[in,out]   ctx     The DER context pointing to the tbsCertificate field.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseTbsCertificate(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert );

/**
 * Initialize the certificate structure.
 *
 * \param[in,out]   cert    The certificate struct to be initialized.
 */
static void
EscX509_InitCertificate(
    EscX509_CertificateT* cert );

/**
 * Parse the version field of the certificate.
 *
 * \param[in,out]   ctx     The DER context pointing to the version field.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 * \retval Esc_PARSE_ERROR if the version does not match v1, v2 or v3.
 */
static Esc_ERROR
EscX509_ParseVersion(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert );

/**
 * Parse a distinguished name. This is used for issuer and subject.
 *
 * \param[in,out]   certCtx     The DER context pointing to the issuer or subject.
 * \param[out]      rawPointer  The pointer and length to the encoded (with tag and length!) issuer and subject.
 * \param[out]      dn          The struct holding information about the attributes.
 *                              This parameter can be set to NULL if EscX509_PARSE_INFO is disabled.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseDistinguishedName(
    EscDer_ContextT* certCtx,
    EscX509_StringT* rawPointer,
    EscX509_DistinguishedNameT* dn );

#if EscX509_PARSE_INFO == 1
/**
 * Initialize an EscX509_DistinguishedNameT struct. The pointer is set to Esc_NULL_PTR
 * and the length is set to 0.
 *
 * \param[out]  dn  The struct to be initialized.
 */
static void
EscX509_InitDistinguishedName(
    EscX509_DistinguishedNameT* dn );

/**
 * Parse the validity period of the certificate, i.e. the notBefore and notAfter fields.
 *
 * \param[in,out]   certCtx The DER context pointing to the validity sequence.
 * \param[in,out]   cert    The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseValidity(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert );


/**
 * Parse an AttributeValueAssertion. This is an attribute of the issuer/subject, for example
 * the common name (CN). Unknown values are ignored.
 *
 * \param[in,out]   currentSet  The DER context pointing to the current set of attributes.
 * \param[in,out]   cert        The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseAttributeValueAss(
    EscDer_ContextT* currentSet,
    EscX509_DistinguishedNameT* dn );

/**
 * Get an attribute from the parsed certificate.
 *
 * \param[in]   distName    The distinguished name, either subject or issuer.
 * \param[in]   attrId      The ID of the attribute to return.
 * \param[out]  attr        The pointer to the attribute or Esc_NULL_PTR if it is not present
 *                          in the certificate.
 *
 * \return The length of the attribute in bytes.
 *         A value of zero means it is not present in the certificate.
 */
static Esc_UINT32
EscX509_GetAttribute(
    const EscX509_DistinguishedNameT *distName,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr);

#endif /* EscX509_PARSE_INFO */

/**
 * This is the actual entry point of certificate parsing. Esc509_Parse() does some basic checks
 * and then calls this function.
 *
 * \param[in,out]   certSequence    The DER context pointing to the start of the certificate.
 * \param[out]      cert            The certificate struct holding the parse result.
 *
 * \retval Esc_NO_ERROR if successful.
 */
static Esc_ERROR
EscX509_ParseCertificateInternal(
    EscDer_ContextT* certSequence,
    EscX509_CertificateT* cert );

/**
 * Lookup an extension identifier in the list of known extension OIDs.
 *
 * \param[in]   extSeq          The DER context pointing to the extension OID.
 * \param[out]  extensionId     The EscX509_EXTENSION_* identifier corresponding to the extension (if found).
 *                              This is set to zero if it was not found.
 *
 * \retval Esc_NO_ERROR if parsing was successful.
 *                      This includes the case that the extension was not found.
 */
static Esc_ERROR
EscX509_FindExtensionIdentifier(
    EscDer_ContextT* extSeq,
    Esc_UINT16 *extensionId);


/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*lint -esym(9003,EscX509_ExtensionOids,EscX509_PubKeyAlgoOids,EscX509_SignAlgoOids) Keep the constant data structures global for improved readability */

/* Algorithm OIDs The first two components are combined, i.e. X * 40 + Y. This is what EscDer_NextOid() expects */

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA1_ENABLED == 1)
/* OID ecdsaWithSHA1 */
static const Esc_UINT32 EscX509_oidEcdsaWithSha1[] =
{
    /*  ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) 1 } */
    42U, 840U, 10045U, 4U, 1U
};
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA224_ENABLED == 1)
/* OID ecdsaWithSHA224 */
static const Esc_UINT32 EscX509_oidEcdsaWithSha224[] =
{
    /*  ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 1 } */
    42U, 840U, 10045U, 4U, 3U, 1U
};
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA256_ENABLED == 1)
/* OID ecdsaWithSHA256 */
static const Esc_UINT32 EscX509_oidEcdsaWithSha256[] =
{
    /*  ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 } */
    42U, 840U, 10045U, 4U, 3U, 2U
};
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA384_ENABLED == 1)
/* OID ecdsaWithSHA384 */
static const Esc_UINT32 EscX509_oidEcdsaWithSha384[] =
{
    /*  ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 } */
    42U, 840U, 10045U, 4U, 3U, 3U
};
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA512_ENABLED == 1)
/* OID ecdsaWithSHA512 */
static const Esc_UINT32 EscX509_oidEcdsaWithSha512[] =
{
    /*  ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 } */
    42U, 840U, 10045U, 4U, 3U, 4U
};
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA1_ENABLED == 1)
/* OID sha-1WithRsaEncryption */
static const Esc_UINT32 EscX509_oidSha1WithRsaEncryption[] =
{
    /* sha-1WithRSAEncryption OBJECT IDENTIFIER  ::=  {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5  } */
    42U, 840U, 113549U, 1U, 1U, 5U
};
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA224_ENABLED == 1)
/* OID sha224WithRsaEncryption */
static const Esc_UINT32 EscX509_oidSha224WithRsaEncryption[] =
{
    /* sha224WithRSAEncryption OBJECT IDENTIFIER  ::=  {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 14 } */
    42U, 840U, 113549U, 1U, 1U, 14U
};
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA256_ENABLED == 1)
/* OID sha256WithRsaEncryption */
static const Esc_UINT32 EscX509_oidSha256WithRsaEncryption[] =
{
    /* sha256WithRSAEncryption OBJECT IDENTIFIER  ::=  {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 11  } */
    42U, 840U, 113549U, 1U, 1U, 11U
};
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA384_ENABLED == 1)
/* OID sha384WithRsaEncryption */
static const Esc_UINT32 EscX509_oidSha384WithRsaEncryption[] =
{
    /* sha256WithRSAEncryption OBJECT IDENTIFIER  ::=  {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 12  } */
    42U, 840U, 113549U, 1U, 1U, 12U
};
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA512_ENABLED == 1)
/* OID sha512WithRsaEncryption */
static const Esc_UINT32 EscX509_oidSha512WithRsaEncryption[] =
{
    /* sha256WithRSAEncryption OBJECT IDENTIFIER  ::=  {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 13  } */
    42U, 840U, 113549U, 1U, 1U, 13U
};
#endif


#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
static const Esc_UINT32 EscX509_oidRsassaPss[] =
{
    /* id-RSASSA-PSS OBJECT IDENTIFIER ::= {
      iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 10 } */
    42U, 840U, 113549U, 1U, 1U, 10U
};
#endif

#if (EscX509_ALGORITHM_RSA_ENABLED)
/* OID rsaEncryption */
static const Esc_UINT32 EscX509_oidRsaEncryption[] =
{
    /*
       pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
       rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1}  */
    42U, 840U, 113549U, 1U, 1U, 1U
};
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
/** id-ecPublicKey */
static const Esc_UINT32 EscX509_oidEcPublicKey[] =
{
    /*  ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) 10045 }
       id-public-key-type OBJECT IDENTIFIER  ::= { ansi-X9.62 2 }
       id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 } */
    42U, 840U, 10045U, 2U, 1U
};
#endif

/* Extension OIDs The first two components are combined, i.e. X * 40 + Y. This is what EscDer_NextOid() expects */

static const Esc_UINT32 EscX509_oidKeyUsage[] =
{
    /* keyUsage ::= { joint-iso-itu(2) ds(5) certificateExtension(29) 15 } */
    85U, 29U, 15U
};

static const Esc_UINT32 EscX509_oidBasicConstraints[] =
{
    /* basicConstraints ::= { joint-iso-itu(2) ds(5) certificateExtension(29) 19 } */
    85U, 29U, 19U
};

/* Lookup table OID -> Signature algorithm ID */

static const EscX509_AlgorithmOid EscX509_SignAlgoOids[] =
{

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA1_ENABLED == 1)
    {
        EscX509_oidEcdsaWithSha1,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcdsaWithSha1),
        EscX509_ALGORITHM_ECDSA | EscX509_HASH_SHA1,
    },
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA224_ENABLED == 1)
    {
        EscX509_oidEcdsaWithSha224,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcdsaWithSha224),
        EscX509_ALGORITHM_ECDSA | EscX509_HASH_SHA224,
    },
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA256_ENABLED == 1)
    {
        EscX509_oidEcdsaWithSha256,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcdsaWithSha256),
        EscX509_ALGORITHM_ECDSA | EscX509_HASH_SHA256,
    },
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA384_ENABLED == 1)
    {
        EscX509_oidEcdsaWithSha384,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcdsaWithSha384),
        EscX509_ALGORITHM_ECDSA | EscX509_HASH_SHA384,
    },
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1) && (EscX509_HASH_SHA512_ENABLED == 1)
    {
        EscX509_oidEcdsaWithSha512,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcdsaWithSha512),
        EscX509_ALGORITHM_ECDSA | EscX509_HASH_SHA512,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA1_ENABLED == 1)
    {
        EscX509_oidSha1WithRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidSha1WithRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15 | EscX509_HASH_SHA1,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA224_ENABLED == 1)
    {
        EscX509_oidSha224WithRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidSha224WithRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15 | EscX509_HASH_SHA224,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA256_ENABLED == 1)
    {
        EscX509_oidSha256WithRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidSha256WithRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15 | EscX509_HASH_SHA256,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA384_ENABLED == 1)
    {
        EscX509_oidSha384WithRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidSha384WithRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15 | EscX509_HASH_SHA384,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) && (EscX509_HASH_SHA512_ENABLED == 1)
    {
        EscX509_oidSha512WithRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidSha512WithRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15 | EscX509_HASH_SHA512,
    },
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
    {
        EscX509_oidRsassaPss,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidRsassaPss),
        EscX509_ALGORITHM_RSA_PKCS1PSS,
    },
#endif
};

/* Lookup OID -> Public Key algorithm ID */

static const EscX509_AlgorithmOid EscX509_PubKeyAlgoOids[] =
{
#if (EscX509_ALGORITHM_RSA_ENABLED)
    {
        EscX509_oidRsaEncryption,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidRsaEncryption),
        EscX509_ALGORITHM_RSA_PKCS1V15,
    },
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
    {
        EscX509_oidEcPublicKey,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidEcPublicKey),
        EscX509_ALGORITHM_ECDSA,
    },
#endif
};

/* Lookup OID -> Extension ID */

static const EscX509_ExtensionOid EscX509_ExtensionOids[] =
{
    {
        EscX509_oidKeyUsage,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidKeyUsage),
        EscX509_EXTENSION_KEYUSAGE
    },

    {
        EscX509_oidBasicConstraints,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509_oidBasicConstraints),
        EscX509_EXTENSION_BASIC_CONSTRAINTS
    }
};

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if EscX509_PARSE_INFO == 1

static Esc_ERROR
EscX509_ParseValidity(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    Esc_UINT32 tag;
    Esc_UINT32 cla;

    EscDer_ContextT seq;

    /*
        Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

        Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }
     */

    returnCode = EscDer_NextSequence( certCtx, &seq );
    if (returnCode == Esc_NO_ERROR)
    {
        /* Get notBefore date */
        returnCode = EscDer_GetIdentifier( &seq, &tag, &cla );
        if (returnCode == Esc_NO_ERROR)
        {
            /* Check if we have UTC or Generalized format */
            switch (tag)
            {
                case DER_TAG_UTCTime:
                    returnCode = EscDer_NextUtcTime( &seq, &cert->notBefore.stringBytes, &cert->notBefore.stringLen );
                    break;

                case DER_TAG_GeneralizedTime:
                    returnCode = EscDer_NextGeneralizedTime( &seq, &cert->notBefore.stringBytes, &cert->notBefore.stringLen );
                    break;

                default:
                    returnCode = Esc_PARSE_ERROR;
                    break;
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Get notAfter date */
            returnCode = EscDer_GetIdentifier( &seq, &tag, &cla );
            if (returnCode == Esc_NO_ERROR)
            {
                switch (tag)
                {
                    case DER_TAG_UTCTime:
                        returnCode = EscDer_NextUtcTime( &seq, &cert->notAfter.stringBytes, &cert->notAfter.stringLen );
                        break;

                    case DER_TAG_GeneralizedTime:
                        returnCode = EscDer_NextGeneralizedTime( &seq, &cert->notAfter.stringBytes, &cert->notAfter.stringLen );
                        break;

                    default:
                        returnCode = Esc_PARSE_ERROR;
                        break;
                }
            }
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&seq);
    }

    return returnCode;
}

static void
EscX509_InitDistinguishedName(
    EscX509_DistinguishedNameT* dn )
{
    dn->country.stringBytes = Esc_NULL_PTR;
    dn->country.stringLen = 0U;

    dn->organization.stringBytes = Esc_NULL_PTR;
    dn->organization.stringLen = 0U;

    dn->organizationalUnit.stringBytes = Esc_NULL_PTR;
    dn->organizationalUnit.stringLen = 0U;

    dn->commonName.stringBytes = Esc_NULL_PTR;
    dn->commonName.stringLen = 0U;

    dn->locality.stringBytes = Esc_NULL_PTR;
    dn->locality.stringLen = 0U;

    dn->stateOrProvince.stringBytes = Esc_NULL_PTR;
    dn->stateOrProvince.stringLen = 0U;
}

static Esc_ERROR
EscX509_ParseAttributeValueAss(
    EscDer_ContextT* currentSet,
    EscX509_DistinguishedNameT* dn )
{
    /*
       AttributeValueAssertion ::= SEQUENCE {
       attributeType           OBJECT IDENTIFIER,
       attributeValue          ANY
       }
     */
    Esc_ERROR returnCode;
    EscDer_ContextT seq;

    /* AttributeValueAssertion ::= SEQUENCE { */
    returnCode = EscDer_NextSequence( currentSet, &seq );
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 oid[10];
        Esc_UINT32 oidLen = 0U;

        /* attributeType OBJECT IDENTIFIER, */
        returnCode = EscDer_NextOid( &seq, oid, 10U, &oidLen );
        if (returnCode == Esc_NO_ERROR)
        {
            EscX509_StringT *targetStr = Esc_NULL_PTR;

            if ( (oidLen == 3U) && (oid[0] == ( (2U * 40U) + 5U )) && (oid[1] == 4U) )
            {
                switch (oid[2])
                {
                    case 3U:       /* commonName      ::= SEQUENCE { { 2 5 4 3 }, StringType( SIZE( 1...64 ) ) } */
                        targetStr = &dn->commonName;
                        break;
                    case 6U:       /* countryName     ::= SEQUENCE { { 2 5 4 6 }, StringType( SIZE( 2 ) ) } */
                        targetStr = &dn->country;
                        break;
                    case 7U:       /* localityName    ::= SEQUENCE { { 2 5 4 7 }, StringType( SIZE( 1...64 ) ) } */
                        targetStr = &dn->locality;
                        break;
                    case 8U:       /* stateOrProvinceName  ::= SEQUENCE { { 2 5 4 8 }, StringType( SIZE( 1...64 ) ) } */
                        targetStr = &dn->stateOrProvince;
                        break;
                    case 10U:      /* organization    ::= SEQUENCE { { 2 5 4 10 }, StringType( SIZE( 1...64 ) ) } */
                        targetStr = &dn->organization;
                        break;
                    case 11U:      /* organizationalUnitName ::= SEQUENCE { { 2 5 4 11 }, StringType( SIZE( 1...64 ) ) } */
                        targetStr = &dn->organizationalUnit;
                        break;
                    default:
                        /* just ignore the field */
                        break;
                }
            }

            /* Process string if a known OID was found */
            if (targetStr != Esc_NULL_PTR)
            {
                /* Save current pointer */
                const Esc_UINT8 *prevPointer = targetStr->stringBytes;

                /* Update pointer and length */
                returnCode = EscDer_NextAnyString( &seq, &targetStr->stringBytes, &targetStr->stringLen );

                /* Check if we found an attribute of the same type previously */
                if (prevPointer != Esc_NULL_PTR)
                {
                    /* We found already an attribute of the same type. Clear length.
                     * The pointer will be cleared after all attributes were processed. */
                    targetStr->stringLen = 0U;
                }
            }
            else
            {
                /* Unknown OID - skip */
                returnCode = EscDer_NextSkip(&seq);
            }
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&seq);
    }

    return returnCode;
}

#endif /* EscX509_PARSE_INFO */

static Esc_ERROR
EscX509_ParseDistinguishedName(
    EscDer_ContextT* certCtx,
    EscX509_StringT* rawPointer,
    EscX509_DistinguishedNameT* dn )
{
    /*
       Name ::= SEQUENCE OF RelativeDistinguishedName
       RelativeDistinguishedName ::= SET OF AttributeValueAssertion

       AttributeValueAssertion ::= SEQUENCE {
       attributeType           OBJECT IDENTIFIER,
       attributeValue          ANY
       }
     */
    Esc_ERROR returnCode;
    EscDer_ContextT rdnSeq;
    Esc_UINT32 oldPos;

#if EscX509_PARSE_INFO != 1
    /* The DN structure is not used if parsing attributes is disabled */
    Esc_UNUSED_PARAM(dn);
#endif

    oldPos = EscDer_GetCurrentPosition(certCtx);

    /* Store pointer to encoded distinguished name */
    rawPointer->stringBytes = EscDer_GetCurrentCode(certCtx);

    /* Enter sequence */
    returnCode = EscDer_NextSequence( certCtx, &rdnSeq );

    /* Name ::= SEQUENCE OF RelativeDistinguishedName */
    if (returnCode == Esc_NO_ERROR)
    {
#if EscX509_PARSE_INFO == 1
        EscDer_ContextT currentSet;

        /* RelativeDistinguishedName ::= SET OF AttributeValueAssertion */
        while ( (returnCode == Esc_NO_ERROR) && (EscDer_HasMoreBytes(&rdnSeq) != FALSE) )
        {
            /* Parse next set inside sequence */
            returnCode = EscDer_NextSet( &rdnSeq, &currentSet );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscX509_ParseAttributeValueAss( &currentSet, dn );
            }

            /* Check that current set ends here */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscDer_AssertEnd(&currentSet);
            }
        }
#endif

        /* Compute length of encoded distinguished name */
        rawPointer->stringLen = EscDer_GetCurrentPosition(certCtx) - oldPos;
    }


#if EscX509_PARSE_INFO == 1
    /* Check if we found attributes more than once. If that is the case, the length
     * of the attribute was set to zero. We need to clear the pointer, too.
     */
    if (returnCode == Esc_NO_ERROR)
    {
        if (dn->commonName.stringLen == 0U)
        {
            dn->commonName.stringBytes = Esc_NULL_PTR;
        }

        if (dn->country.stringLen == 0U)
        {
            dn->country.stringBytes = Esc_NULL_PTR;
        }

        if (dn->locality.stringLen == 0U)
        {
            dn->locality.stringBytes = Esc_NULL_PTR;
        }

        if (dn->organization.stringLen == 0U)
        {
            dn->organization.stringBytes = Esc_NULL_PTR;
        }

        if (dn->organizationalUnit.stringLen == 0U)
        {
            dn->organizationalUnit.stringBytes = Esc_NULL_PTR;
        }

        if (dn->stateOrProvince.stringLen == 0U)
        {
            dn->stateOrProvince.stringBytes = Esc_NULL_PTR;
        }
    }
#endif

    return returnCode;
}

static Esc_ERROR
EscX509_ParseVersion(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    EscDer_ContextT taggedCtx;
    Esc_BOOL hasVersion;

    returnCode = EscDer_PeekElement(certCtx, 0U, DER_CLASS_CONTEXT, &hasVersion);

    /* version          [ 0 ]  Version DEFAULT v1(0)
       Version ::= INTEGER { v1(0), v2(1), v3(2) }
     */

    if (returnCode == Esc_NO_ERROR)
    {
        if (hasVersion != FALSE)
        {
            returnCode = EscDer_NextTaggedValue( certCtx, 0U, &taggedCtx );
            if (returnCode == Esc_NO_ERROR)
            {
                Esc_UINT32 version = 0U;

                returnCode = EscDer_NextInteger( &taggedCtx, &version );
                if (returnCode == Esc_NO_ERROR)
                {
                    if (version > 2U)
                    {
                        returnCode = Esc_PARSE_ERROR;
                    }
                    else
                    {
                        /* the version is always one higher than the integer */
                        cert->version = (Esc_UINT8) (version + 1U);
                    }
                }
            }
        }
        else
        {
            /* Use default: v1 */
            cert->version = 1U;
        }
    }

    return returnCode;
}

static void
EscX509_InitCertificate(
    EscX509_CertificateT* cert )
{
    /** Clear optional values */
#if EscX509_PARSE_INFO == 1
    EscX509_InitDistinguishedName( &cert->issuer );
    EscX509_InitDistinguishedName( &cert->subject );
#endif

    /** Clear pointers to encoded subject/issuer */
    cert->rawIssuer.stringBytes = Esc_NULL_PTR;
    cert->rawIssuer.stringLen = 0U;
    cert->rawSubject.stringBytes = Esc_NULL_PTR;
    cert->rawSubject.stringLen = 0U;

    /** Clear extensions */
    cert->extensions = 0U;
    cert->keyUsage = 0U;
    cert->isCa = FALSE;
    cert->pathLenConstraint = -1;
}

static Esc_ERROR
EscX509_ParseTbsCertificate(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    EscDer_ContextT tbsCertificate;
    Esc_UINT32 currentPosition;
    /*
       TBSCertificate ::= SEQUENCE {
       version          [ 0 ]  Version DEFAULT v1(0),
       serialNumber            CertificateSerialNumber,
       signature               AlgorithmIdentifier,
       issuer                  Name,
       validity                Validity,
       subject                 Name,
       subjectPublicKeyInfo    SubjectPublicKeyInfo,
       issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
       subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
       extensions        [ 3 ] Extensions OPTIONAL
       }
     */
    currentPosition = EscDer_GetCurrentPosition( ctx );
    cert->tbsCertificate.certStart = EscDer_GetCurrentCode( ctx );

    /* enter TBSCertificate */
    returnCode = EscDer_NextSequence( ctx, &tbsCertificate );

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseVersion( &tbsCertificate, cert );
    }

#if EscX509_PARSE_INFO == 1
    if (returnCode == Esc_NO_ERROR)
    {
        /* Parse serial number */
        returnCode = EscDer_NextIntegerLongBe(
                        &tbsCertificate,
                        &cert->serialNumber.intBytes,
                        &cert->serialNumber.intLen );
    }
#else
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSkip( &tbsCertificate ); /* serialNumber */
    }
#endif

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseSignatureAlgorithm( &tbsCertificate, &cert->signature );
    }

#if EscX509_PARSE_INFO == 1
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseDistinguishedName( &tbsCertificate, &cert->rawIssuer, &cert->issuer );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseValidity( &tbsCertificate, cert );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseDistinguishedName( &tbsCertificate, &cert->rawSubject, &cert->subject );
    }
#else
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseDistinguishedName( &tbsCertificate, &cert->rawIssuer, Esc_NULL_PTR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSkip( &tbsCertificate );    /* Validity */
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_ParseDistinguishedName( &tbsCertificate, &cert->rawSubject, Esc_NULL_PTR );
    }
#endif

    if (returnCode == Esc_NO_ERROR)
    {
        EscDer_ContextT keySeq;

        returnCode = EscDer_NextSequence( &tbsCertificate, &keySeq );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscX509_ParsePublicKeyAlgorithm(&keySeq, cert);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            switch (cert->pubKey.pubKeyAlgorithm & EscX509_SIGN_MASK)
            {
#if (EscX509_ALGORITHM_RSA_ENABLED)
                case EscX509_ALGORITHM_RSA_PKCS1V15:
                    returnCode = EscX509Rsa_ParsePubKey( &keySeq, cert );
                    break;
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
                case EscX509_ALGORITHM_ECDSA:
                    returnCode = EscX509Sha2Ecc_ParsePubKey( &keySeq, cert );
                    break;
#endif

                default:
                    returnCode = Esc_INVALID_PUBKEY_ALGORITHM;
                    break;
            }
        }

        /* Check that sequence ends here */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscDer_AssertEnd(&keySeq);
        }
    }

    /* Skip unique identifiers if present */

    if ( (returnCode == Esc_NO_ERROR) && (cert->version > 1U) )
    {
        Esc_BOOL hasIdentifier = FALSE;

        returnCode = EscDer_PeekElement(&tbsCertificate, 1U, DER_CLASS_CONTEXT, &hasIdentifier);
        if ( (returnCode == Esc_NO_ERROR) && (hasIdentifier != FALSE) )
        {
            returnCode = EscDer_NextSkip(&tbsCertificate);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscDer_PeekElement(&tbsCertificate, 2U, DER_CLASS_CONTEXT, &hasIdentifier);
            if ( (returnCode == Esc_NO_ERROR) && (hasIdentifier != FALSE) )
            {
                returnCode = EscDer_NextSkip(&tbsCertificate);
            }
        }
    }

    /* Extensions */

    if ( (returnCode == Esc_NO_ERROR) && (cert->version > 2U) )
    {
        Esc_BOOL hasExtensions = FALSE;

        returnCode = EscDer_PeekElement(&tbsCertificate, 3U, DER_CLASS_CONTEXT, &hasExtensions);
        if ( (returnCode == Esc_NO_ERROR) && (hasExtensions != FALSE) )
        {
            returnCode = EscX509_ParseExtensions(&tbsCertificate, cert);
        }
    }

    /* Check that the tbsCertificate ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&tbsCertificate);
    }

    /* Store length */
    if (returnCode == Esc_NO_ERROR)
    {
        cert->tbsCertificate.certLen = EscDer_GetCurrentPosition( ctx ) - currentPosition;
    }

    return returnCode;
}

static Esc_ERROR
EscX509_ParseSignatureAlgorithm(
    EscDer_ContextT* ctx,
    EscX509_SignatureT *signature)
{
    Esc_ERROR returnCode;
    EscDer_ContextT algSeq;

    returnCode = EscDer_NextSequence( ctx, &algSeq );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_FindAlgorithmIdentifier(
                        &algSeq,
                        EscX509_SignAlgoOids,
                        EscX509_NUM_ARRAY_ELEMENTS(EscX509_SignAlgoOids),
                        &signature->signAlgorithm);
    }

    /* If not found then translate DER return code into a more meaningful x509 error */
    if (returnCode == Esc_INVALID_OBJECT_IDENTIFIER)
    {
        returnCode = Esc_INVALID_SIGN_ALGORITHM;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        switch (signature->signAlgorithm & EscX509_SIGN_MASK)
        {
#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
            case EscX509_ALGORITHM_ECDSA:
                /* No parameters expected */
                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1V15:
                /* No parameters expected */
                returnCode = EscDer_NextNull(&algSeq);
                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1PSS:
                returnCode = EscX509Rsa_ParsePssParameters(&algSeq, signature);
                break;
#endif

            default:
                returnCode = Esc_INVALID_SIGN_ALGORITHM;
                break;
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&algSeq);
    }

    return returnCode;
}

static Esc_ERROR
EscX509_ParsePublicKeyAlgorithm(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    EscDer_ContextT algSeq;

    returnCode = EscDer_NextSequence( ctx, &algSeq );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_FindAlgorithmIdentifier(
                        &algSeq,
                        EscX509_PubKeyAlgoOids,
                        EscX509_NUM_ARRAY_ELEMENTS(EscX509_PubKeyAlgoOids),
                        &cert->pubKey.pubKeyAlgorithm);
    }

    /* If not found then translate DER return code into a more meaningful x509 error */
    if (returnCode == Esc_INVALID_OBJECT_IDENTIFIER)
    {
        returnCode = Esc_INVALID_PUBKEY_ALGORITHM;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        switch (cert->pubKey.pubKeyAlgorithm)
        {
#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
            case EscX509_ALGORITHM_ECDSA:
                returnCode = EscX509Sha2Ecc_ParseCurveFromAlgoParams(&algSeq, &cert->pubKey.key.eccKey.curveId);
                break;
#endif

#if (EscX509_ALGORITHM_RSA_ENABLED)
            case EscX509_ALGORITHM_RSA_PKCS1V15:
                /* No parameters expected */
                returnCode = EscDer_NextNull(&algSeq);
                break;
#endif

            default:
                returnCode = Esc_INVALID_PUBKEY_ALGORITHM;
                break;
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&algSeq);
    }

    return returnCode;
}

Esc_ERROR
EscX509_FindAlgorithmIdentifier(
    EscDer_ContextT* algSeq,
    const EscX509_AlgorithmOid table[],
    Esc_UINT32 numTableEntries,
    EscX509_AlgoT *algorithm)
{
    Esc_ERROR returnCode;
    Esc_UINT32 oid[EscX509_MAX_ALGORITHM_OID_COMPONENTS];
    Esc_UINT32 numComponents = 0U;
    Esc_UINT32 i, j;

    *algorithm = 0U;

    /* Get OID */
    returnCode = EscDer_NextOid(algSeq, oid, EscX509_NUM_ARRAY_ELEMENTS(oid), &numComponents);

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = Esc_INVALID_OBJECT_IDENTIFIER;

        /* Search the table for the OID */
        for (i=0U; i<numTableEntries; i++)
        {
            const EscX509_AlgorithmOid *oidInfo = &table[i];
            Esc_BOOL equal = TRUE;

            if (numComponents == oidInfo->oidCompsLen)
            {
                /* Compare component by component */
                for (j=0U; j<numComponents; j++)
                {
                    if (oid[j] != oidInfo->oidComps[j])
                    {
                        equal = FALSE;
                        break;
                    }
                }
            }
            else
            {
                equal = FALSE;
            }

            if (equal)
            {
                /* Found the OID. */
                *algorithm = oidInfo->algo;
                returnCode = Esc_NO_ERROR;
                break;
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscX509_ParseExtensions(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert)
{
    EscDer_ContextT tagCtx;
    EscDer_ContextT extListCtx;
    Esc_BOOL hasMoreBytes = FALSE;
    Esc_ERROR returnCode;

    /* Enter tagged value */
    returnCode = EscDer_NextTaggedValue(ctx, 3U, &tagCtx);

    /* Enter sequence with extensions */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSequence(&tagCtx, &extListCtx);
        hasMoreBytes = EscDer_HasMoreBytes(&extListCtx);
    }

    /* Parse each sequence */
    while ( (returnCode == Esc_NO_ERROR) && (hasMoreBytes != FALSE) )
    {
        Esc_UINT16 extensionId = 0U;
        Esc_UINT8 isCritical = 0U;
        EscDer_ContextT extCtx;

        /* Enter sequence */
        returnCode = EscDer_NextSequence(&extListCtx, &extCtx);

        /* Parse OID */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscX509_FindExtensionIdentifier(&extCtx, &extensionId);
        }

        /* Check if the same extension was already encountered previously */
        if ( (cert->extensions & extensionId) != 0U )
        {
            returnCode = Esc_PARSE_ERROR;
        }

        /* Check optional critical flag */
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 tag;
            Esc_UINT32 cla;

            returnCode = EscDer_GetIdentifier(&extCtx, &tag, &cla);
            if (returnCode == Esc_NO_ERROR)
            {
                if ( (cla == DER_CLASS_UNIVERSAL) && (tag == DER_TAG_BOOLEAN) )
                {
                    returnCode = EscDer_NextBoolean(&extCtx, &isCritical);
                }
            }
        }

        /* Parse extension */
        if (returnCode == Esc_NO_ERROR)
        {
            switch (extensionId)
            {
                case EscX509_EXTENSION_KEYUSAGE:
                    returnCode = EscX509_ParseKeyUsageExtension(&extCtx, cert);
                    /* Check that sequence ends here */
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscDer_AssertEnd(&extCtx);
                    }
                    break;

                case EscX509_EXTENSION_BASIC_CONSTRAINTS:
                    returnCode = EscX509_ParseBasicConstraintsExtension(&extCtx, cert);
                    /* Check that sequence ends here */
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscDer_AssertEnd(&extCtx);
                    }
                    break;

                default:
                    /* Unknown extension. If critical then reject certificate. Ignore the extension otherwise. */
                    if (isCritical != 0U)
                    {
                        returnCode = Esc_PARSE_ERROR;
                    }
                    break;
            }
        }

        /* Mark that the extension is set in the certificate */
        if (returnCode == Esc_NO_ERROR)
        {
            cert->extensions |= extensionId;
        }

        hasMoreBytes = EscDer_HasMoreBytes(&extListCtx);
    }

    return returnCode;
}

static Esc_ERROR
EscX509_ParseKeyUsageExtension(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    Esc_UINT32 octetStrLen = 0U;
    const Esc_UINT8 *octetStr;
    EscDer_ContextT octetCtx;
    const Esc_UINT8 *bitStr;
    Esc_UINT32 numBits = 0U;

    /* Enter encapsulating octet string */

    returnCode = EscDer_NextOctetString(ctx, &octetStr, &octetStrLen);
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_Init(&octetCtx, octetStr, octetStrLen);
    }

    /* Get bit string */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextBitString(&octetCtx, &bitStr, &numBits);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        cert->keyUsage = 0U;

        /* Left-align bits in a 16-bit word */

        if (numBits > 9U)
        {
            returnCode = Esc_PARSE_ERROR;
        }
        else if (numBits == 9U)
        {
            /*lint -e{644} bitStr is initialized by the EscDer_NextBitString function */
            cert->keyUsage  = (Esc_UINT16)bitStr[0] << 8U;
            cert->keyUsage |= (Esc_UINT16)bitStr[1];
            cert->keyUsage &= 0xFF80U;  /* Clear unused bits */
        }
        else /* numBits <= 8 */
        {
            Esc_UINT16 unusedBits = (Esc_UINT16)(8U - numBits);

            cert->keyUsage  = (Esc_UINT16)bitStr[0];
            /* Clear unused bits */
            cert->keyUsage = (Esc_UINT16)((Esc_UINT32)cert->keyUsage << unusedBits);
            cert->keyUsage = (Esc_UINT16)(cert->keyUsage >> unusedBits);
            /* Left-align */
            cert->keyUsage <<= 8U;
        }

        /* At least one bit must be set */
        if (cert->keyUsage == 0U)
        {
            returnCode = Esc_PARSE_ERROR;
        }
    }

    /* Check that encapsulating octet string ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        /*lint -e{645} octetCtx is initialized if returnCode == Esc_NO_ERROR */
        returnCode = EscDer_AssertEnd(&octetCtx);
    }

    return returnCode;
}

static Esc_ERROR
EscX509_ParseBasicConstraintsExtension(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    Esc_UINT32 octetStrLen = 0U;
    const Esc_UINT8 *octetStr;
    EscDer_ContextT octetCtx;
    EscDer_ContextT bcCtx;

    /* Enter encapsulating octet string */

    returnCode = EscDer_NextOctetString(ctx, &octetStr, &octetStrLen);
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_Init(&octetCtx, octetStr, octetStrLen);
    }

    /* Enter BasicConstraints sequence */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_NextSequence(&octetCtx, &bcCtx);
    }

    /*lint -save -esym(645,bcCtx) bcCtx is initialized iff returnCode == Esc_NO_ERROR which is ensured for any further access to bcCtx */

    /* Get optional cA flag */

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_BOOL hasCaFlag = FALSE;

        /* Default is false */
        cert->isCa = FALSE;

        returnCode = EscDer_PeekElement(&bcCtx, DER_TAG_BOOLEAN, DER_CLASS_UNIVERSAL, &hasCaFlag);
        if ( (returnCode == Esc_NO_ERROR) && (hasCaFlag != FALSE) )
        {
            Esc_UINT8 flag = 0U;
            returnCode = EscDer_NextBoolean(&bcCtx, &flag);
            if ( (returnCode == Esc_NO_ERROR) && (flag != 0U) )
            {
                cert->isCa = TRUE;
            }
        }
    }

    /* Get optional pathLenConstraint integer */

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_BOOL hasPathLen = FALSE;

        /* Set to not present */
        cert->pathLenConstraint = -1;

        returnCode = EscDer_PeekElement(&bcCtx, DER_TAG_INTEGER, DER_CLASS_UNIVERSAL, &hasPathLen);
        if ( (returnCode == Esc_NO_ERROR) && (hasPathLen != FALSE) )
        {
            Esc_UINT32 pathLen = 0U;
            returnCode = EscDer_NextInteger(&bcCtx, &pathLen);

            if (returnCode == Esc_NO_ERROR)
            {
                cert->pathLenConstraint = (Esc_SINT32) pathLen;
            }
        }
    }
    /*lint -restore */

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&bcCtx);
    }

    /* Check that encapsulating octet string ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        /*lint -e{645} octetCtx is initialized if returnCode == Esc_NO_ERROR */
        returnCode = EscDer_AssertEnd(&octetCtx);
    }

    return returnCode;
}


static Esc_ERROR
EscX509_ParseCertificateInternal(
    EscDer_ContextT* certSequence,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;

    /*
       Certificate ::= SEQUENCE {
       tbsCertificate          TBSCertificate,
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING
       }

     */
    /* We are already inside the sequence. Get the three elements. */

    returnCode = EscX509_ParseTbsCertificate( certSequence, cert );
    if (returnCode == Esc_NO_ERROR)
    {
        /* We parsed the signature AlgorithmIdentifier already INSIDE the tbsCertificate.
         * Here, we parse to a temporary element and compare that both are the same.
         */
        EscX509_SignatureT tempSig;

        returnCode = EscX509_ParseSignatureAlgorithm( certSequence, &tempSig );
        if (returnCode == Esc_NO_ERROR)
        {
            if (tempSig.signAlgorithm != cert->signature.signAlgorithm)
            {
                returnCode = Esc_PARSE_ERROR;
            }
#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
            if ( ((tempSig.signAlgorithm & EscX509_SIGN_MASK) == EscX509_ALGORITHM_RSA_PKCS1PSS) &&
                 (tempSig.signature.rsaSignature.saltLength != cert->signature.signature.rsaSignature.saltLength) )
            {
                returnCode = Esc_PARSE_ERROR;
            }
#endif
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        switch (cert->signature.signAlgorithm & EscX509_SIGN_MASK)
        {
#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
            case EscX509_ALGORITHM_ECDSA:
                returnCode = EscX509Sha2Ecc_ParseSignature( certSequence, cert );
                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1V15:
                returnCode = EscX509Rsa_ParseSignature( certSequence, cert );
                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1PSS:
                returnCode = EscX509Rsa_ParseSignature( certSequence, cert );
                break;
#endif

            default:
                returnCode = Esc_INVALID_SIGN_ALGORITHM;
                break;
        }
    }

    return returnCode;
}

static Esc_ERROR
EscX509_FindExtensionIdentifier(
    EscDer_ContextT* extSeq,
    Esc_UINT16 *extensionId)
{
    Esc_ERROR returnCode;
    Esc_UINT32 oid[EscX509_MAX_EXTENSION_OID_COMPONENTS];
    Esc_UINT32 numComponents = 0U;
    Esc_UINT32 i, j;
    const Esc_UINT32 numOids = EscX509_NUM_ARRAY_ELEMENTS(EscX509_ExtensionOids);

    *extensionId = 0U;

    /* Get OID */
    returnCode = EscDer_NextOid(extSeq, oid, EscX509_NUM_ARRAY_ELEMENTS(oid), &numComponents);

    if (returnCode == Esc_NO_ERROR)
    {
        for (i=0U; i<numOids; i++)
        {
            const EscX509_ExtensionOid *oidInfo = &EscX509_ExtensionOids[i];
            Esc_BOOL equal = TRUE;

            if (numComponents == oidInfo->oidCompsLen)
            {
                for (j=0U; j<numComponents; j++)
                {
                    if (oid[j] != oidInfo->oidComps[j])
                    {
                        equal = FALSE;
                        break;
                    }
                }
            }
            else
            {
                equal = FALSE;
            }

            if (equal)
            {
                /* Found the OID. */
                *extensionId = oidInfo->extension;
                break;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscX509_Parse(
    EscX509_CertificateT* cert,
    const Esc_UINT8 certCode[],
    Esc_UINT32 certCodeLen )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    EscDer_ContextT mainCtx;
    EscDer_ContextT certificate;
    /*
       Certificate ::= SEQUENCE {
       tbsCertificate          TBSCertificate,
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING
       }
     */

    if ( (cert != Esc_NULL_PTR) && (certCode != Esc_NULL_PTR) )
    {
        returnCode = EscDer_Init( &mainCtx, certCode, certCodeLen );
        if (returnCode == Esc_NO_ERROR)
        {
            EscX509_InitCertificate( cert );

            returnCode = EscDer_NextSequence( &mainCtx, &certificate );
            if (returnCode == Esc_NO_ERROR)
            {
                Esc_UINT32 calcCertLen;

                /* Calculate length of parsed certificate */
                calcCertLen = EscDer_GetCurrentPosition( &mainCtx );

                /* Check if the length matches. */
                if (calcCertLen == certCodeLen)
                {
                    /* Get the three elements of the sequence */
                    returnCode = EscX509_ParseCertificateInternal( &certificate, cert );
                }
                else
                {
                    returnCode = Esc_INVALID_CERT_LENGTH;
                }
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscX509_VerifyWithKey(
    const EscX509_CertificateT* cert,
    const EscX509_PubKeyT* verificationKey )
{
    Esc_UINT8 digest[EscX509_MAX_DIGEST_LEN];
    Esc_UINT32 digestLen;

    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (cert == Esc_NULL_PTR) || (verificationKey == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    /* Compute hash */

    if (returnCode == Esc_NO_ERROR)
    {
        switch (cert->signature.signAlgorithm & EscX509_HASH_MASK)
        {
#if (EscX509_HASH_SHA1_ENABLED == 1)
            case EscX509_HASH_SHA1:
                digestLen = EscSha1_DIGEST_LEN;
                returnCode = EscSha1_Calc( cert->tbsCertificate.certStart, cert->tbsCertificate.certLen, digest, EscSha1_DIGEST_LEN );
                break;
#endif

#if (EscX509_HASH_SHA224_ENABLED == 1)
            case EscX509_HASH_SHA224:
                digestLen = EscSha224_DIGEST_LEN;
                returnCode = EscSha256_Calc( TRUE, cert->tbsCertificate.certStart, cert->tbsCertificate.certLen, digest, EscSha224_DIGEST_LEN );
                break;
#endif

#if (EscX509_HASH_SHA256_ENABLED == 1)
            case EscX509_HASH_SHA256:
                digestLen = EscSha256_DIGEST_LEN;
                returnCode = EscSha256_Calc( FALSE, cert->tbsCertificate.certStart, cert->tbsCertificate.certLen, digest, EscSha256_DIGEST_LEN );
                break;
#endif

#if (EscX509_HASH_SHA384_ENABLED == 1)
            case EscX509_HASH_SHA384:
                digestLen = EscSha384_DIGEST_LEN;
                returnCode = EscSha512_Calc( TRUE, cert->tbsCertificate.certStart, cert->tbsCertificate.certLen, digest, EscSha384_DIGEST_LEN );
                break;
#endif

#if (EscX509_HASH_SHA512_ENABLED == 1)
            case EscX509_HASH_SHA512:
                digestLen = EscSha512_DIGEST_LEN;
                returnCode = EscSha512_Calc( FALSE, cert->tbsCertificate.certStart, cert->tbsCertificate.certLen, digest, EscSha512_DIGEST_LEN );
                break;
#endif

            default:
                returnCode = Esc_INVALID_SIGN_ALGORITHM;
                break;
        }
    }

    /*lint -save -esym(645,digest) digest is initialized iff returnCode == Esc_NO_ERROR which is ensured for any further access to digest */
    /* Check that signature type matches public key type and call signature verification */

    if (returnCode == Esc_NO_ERROR)
    {
        switch (cert->signature.signAlgorithm & EscX509_SIGN_MASK)
        {
            /*lint --e{644} digestLen is initialized */
#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1V15:
                if (verificationKey->pubKeyAlgorithm == EscX509_ALGORITHM_RSA_PKCS1V15)
                {
                    returnCode = EscX509Rsa_VerifySignature(digest, digestLen, &cert->signature, verificationKey);
                }
                else
                {
                    returnCode = Esc_INVALID_SIGN_ALGORITHM;
                }

                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1PSS:
                if (verificationKey->pubKeyAlgorithm == EscX509_ALGORITHM_RSA_PKCS1V15)
                {
                    returnCode = EscX509Rsa_VerifySignature(digest, digestLen, &cert->signature, verificationKey);
                }
                else
                {
                    returnCode = Esc_INVALID_SIGN_ALGORITHM;
                }
                break;
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
            case EscX509_ALGORITHM_ECDSA:
                if (verificationKey->pubKeyAlgorithm == EscX509_ALGORITHM_ECDSA)
                {
                    returnCode = EscX509Sha2Ecc_VerifySignature(digest, digestLen, &cert->signature, verificationKey);
                }
                else
                {
                    returnCode = Esc_INVALID_SIGN_ALGORITHM;
                }
                break;
#endif

            default:
                returnCode = Esc_INVALID_SIGN_ALGORITHM;
                break;
        }
    }

    /*lint -restore */

    return returnCode;
}


Esc_UINT8
EscX509_GetVersion(
    const EscX509_CertificateT* cert)
{
    return cert->version;
}

#if EscX509_PARSE_INFO == 1

Esc_UINT32
EscX509_GetSerialNumber(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **serialNum)
{
    *serialNum = cert->serialNumber.intBytes;
    return cert->serialNumber.intLen;
}

static Esc_UINT32
EscX509_GetAttribute(
    const EscX509_DistinguishedNameT *distName,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr)
{
    Esc_UINT32 length = 0U;

    switch (attrId)
    {
        case EscX509_ATTR_COUNTRY:
            *attr = distName->country.stringBytes;
            length = distName->country.stringLen;
            break;

        case EscX509_ATTR_ORGANIZATION:
            *attr = distName->organization.stringBytes;
            length = distName->organization.stringLen;
            break;

        case EscX509_ATTR_ORGANIZATIONAL_UNIT:
            *attr = distName->organizationalUnit.stringBytes;
            length = distName->organizationalUnit.stringLen;
            break;

        case EscX509_ATTR_COMMON_NAME:
            *attr = distName->commonName.stringBytes;
            length = distName->commonName.stringLen;
            break;

        case EscX509_ATTR_LOCALITY_NAME:
            *attr = distName->locality.stringBytes;
            length = distName->locality.stringLen;
            break;

        case EscX509_ATTR_STATE_OR_PROVINCE:
            *attr = distName->stateOrProvince.stringBytes;
            length = distName->stateOrProvince.stringLen;
            break;

        default:
            *attr = Esc_NULL_PTR;
            /* length is already set to 0 */
            break;
    }

    return length;
}

Esc_UINT32
EscX509_GetIssuerAttr(
    const EscX509_CertificateT* cert,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr)
{
    return EscX509_GetAttribute(&cert->issuer, attrId, attr);
}

Esc_UINT32
EscX509_GetValidityStart(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **dateString)
{
    *dateString = cert->notBefore.stringBytes;
    return cert->notBefore.stringLen;
}

Esc_UINT32
EscX509_GetValidityEnd(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **dateString)
{
    *dateString = cert->notAfter.stringBytes;
    return cert->notAfter.stringLen;
}

Esc_UINT32
EscX509_GetSubjectAttr(
    const EscX509_CertificateT* cert,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr)
{
    return EscX509_GetAttribute(&cert->subject, attrId, attr);
}

#endif

Esc_BOOL
EscX509_HasExtension(
    const EscX509_CertificateT* cert,
    Esc_UINT16 extension)
{
    Esc_BOOL result;

    if ( (cert->extensions & extension) != 0U )
    {
        result = TRUE;
    }
    else
    {
        result = FALSE;
    }

    return result;
}

Esc_BOOL
EscX509_HasKeyUsageFlagsSet(
    const EscX509_CertificateT* cert,
    Esc_UINT16 keyUsageFlags)
{
    Esc_BOOL result;

    if ( (cert->keyUsage & keyUsageFlags) == keyUsageFlags )
    {
        result = TRUE;
    }
    else
    {
        result = FALSE;
    }

    return result;
}

Esc_BOOL
EscX509_IsCaFlagSet(
    const EscX509_CertificateT* cert)
{
    return cert->isCa;
}

Esc_SINT32
EscX509_GetPathLenConstraint(
    const EscX509_CertificateT* cert)
{
    return cert->pathLenConstraint;
}

const Esc_UINT8*
EscX509_GetEncodedSubject(
    const EscX509_CertificateT* cert,
    Esc_UINT32* subjectLen)
{
    *subjectLen = cert->rawSubject.stringLen;
    return cert->rawSubject.stringBytes;
}

const Esc_UINT8*
EscX509_GetEncodedIssuer(
    const EscX509_CertificateT* cert,
    Esc_UINT32* issuerLen)
{
    *issuerLen = cert->rawIssuer.stringLen;
    return cert->rawIssuer.stringBytes;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
