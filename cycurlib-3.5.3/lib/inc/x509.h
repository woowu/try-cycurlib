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

   Supported algorithms:
       - sha1WithRSAEncryption
       - sha224WithRSAEncryption
       - sha256WithRSAEncryption
       - sha384WithRSAEncryption
       - sha512WithRSAEncryption
       - ecdsa-with-SHA1
       - ecdsa-with-SHA224
       - ecdsa-with-SHA256
       - ecdsa-with-SHA384
       - ecdsa-with-SHA512

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_X509_H_
#define ESC_X509_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "der.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/* User definable configuration */

#ifndef EscX509_PARSE_INFO
/** Parse all accessible certificate attributes. If undefined,
    only the public key, extensions and the signature will be parsed. */
#   define EscX509_PARSE_INFO 1
#endif

/* Support for signature / public key algorithms */

#ifndef EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED
/** Enable support for parsing RSA PKCS#1 v1.5 signatures and public keys */
#   define EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED   1
#endif

#ifndef EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED
/** Enable support for parsing RSA PKCS#1-PSS signatures and public keys */
#   define EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED   0
#endif

#ifndef EscX509_ALGORITHM_ECDSA_ENABLED
/** Enable support for parsing ECDSA signatures and ECC public keys */
#   define EscX509_ALGORITHM_ECDSA_ENABLED          0
#endif

/* Support for hash functions */

#ifndef EscX509_HASH_SHA1_ENABLED
/** Enable support for signatures using SHA-1 as hash function */
#   define EscX509_HASH_SHA1_ENABLED        0
#endif

#ifndef EscX509_HASH_SHA224_ENABLED
/** Enable support for signatures using SHA2-224 as hash function */
#   define EscX509_HASH_SHA224_ENABLED      1
#endif

#ifndef EscX509_HASH_SHA256_ENABLED
/** Enable support for signatures using SHA2-256 as hash function */
#   define EscX509_HASH_SHA256_ENABLED      1
#endif

#ifndef EscX509_HASH_SHA384_ENABLED
/** Enable support for signatures using SHA2-384 as hash function */
#   define EscX509_HASH_SHA384_ENABLED      0
#endif

#ifndef EscX509_HASH_SHA512_ENABLED
/** Enable support for signatures using SHA2-512 as hash function */
#   define EscX509_HASH_SHA512_ENABLED      0
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 0) && \
    (EscX509_ALGORITHM_ECDSA_ENABLED == 0) && \
    (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 0)
#   error "At least one signature algorithm must be enabled in the X509 configuration"
#endif

#if (EscX509_HASH_SHA1_ENABLED == 0) && \
    (EscX509_HASH_SHA224_ENABLED == 0) && \
    (EscX509_HASH_SHA256_ENABLED == 0) && \
    (EscX509_HASH_SHA384_ENABLED == 0) && \
    (EscX509_HASH_SHA512_ENABLED == 0)
#   error "At least one hash algorithm must be enabled in the X509 configuration"
#endif

/** Derive whether RSA is enabled in general */
#define EscX509_ALGORITHM_RSA_ENABLED  \
    ((EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1) || (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1))

/** Algorithm IDs are represented as bit field in the parser. One part specifies public key algorithms such as
 * RSA/ECC and the other part identifies the hash function. This macro determines the bit position at which
 * the algorithm identifiers start in the bit field.
 */
#define EscX509_BIT_OFFSET_ALGO     5U

/** A bit mask to get only the hash function from an algorithm identifier */
#define EscX509_HASH_MASK           0x1FU

/** A bit mask to get only the public key algorithm from an algorithm identifier */
#define EscX509_SIGN_MASK           ((EscX509_AlgoT)0x07U << EscX509_BIT_OFFSET_ALGO)

/** No hash algorithm specified */
#define EscX509_HASH_NONE       0x00U

/** Identifier for SHA-1 hash algorithm detected by X509 parsing */
#define EscX509_HASH_SHA1       0x01U

/** Identifier for SHA2-224 hash algorithm detected by X509 parsing */
#define EscX509_HASH_SHA224     0x02U

/** Identifier for SHA2-256 hash algorithm detected by X509 parsing */
#define EscX509_HASH_SHA256     0x04U

/** Identifier for SHA2-384 hash algorithm detected by X509 parsing */
#define EscX509_HASH_SHA384     0x08U

/** Identifier for SHA2-512 hash algorithm detected by X509 parsing */
#define EscX509_HASH_SHA512     0x10U


/** Identifier for RSA-PKCS#1v1.5 signature algorithm detected by X509 parsing */
#define EscX509_ALGORITHM_RSA_PKCS1V15  ((EscX509_AlgoT)0x01U << EscX509_BIT_OFFSET_ALGO)

/** Identifier for RSA-PKCS#1-PSS signature algorithm detected by X509 parsing */
#define EscX509_ALGORITHM_RSA_PKCS1PSS  ((EscX509_AlgoT)0x02U << EscX509_BIT_OFFSET_ALGO)

/** Identifier for ECDSA signature algorithm detected by X509 parsing */
#define EscX509_ALGORITHM_ECDSA         ((EscX509_AlgoT)0x04U << EscX509_BIT_OFFSET_ALGO)


/** Identifier for the KeyUsage extension */
#define EscX509_EXTENSION_KEYUSAGE              0x01U

/** Identifier for the BasicConstraints extension */
#define EscX509_EXTENSION_BASIC_CONSTRAINTS     0x02U



/* Key Usage flags */

/** Key usage bit: Verifying signatures other than signatures on certificates/CRLs */
#define EscX509_KEYUSAGE_DIGITAL_SIGNATURE      0x8000U
/** Key usage bit: Verifying signatures other than signatures on certificates/CRLs
 * for non-repudiation */
#define EscX509_KEYUSAGE_NON_REPUDIATION        0x4000U
/** Key usage bit: Encipher keys (e.g. for key transport) */
#define EscX509_KEYUSAGE_KEY_ENCIPHERMENT       0x2000U
/** Key usage bit: Encipher data */
#define EscX509_KEYUSAGE_DATA_ENCIPHERMENT      0x1000U
/** Key usage bit: Key agreement, e.g. Diffie-Hellman */
#define EscX509_KEYUSAGE_KEY_AGREEMENT          0x0800U
/** Key usage bit: Verify signatures on certificates */
#define EscX509_KEYUSAGE_KEY_CERT_SIGN          0x0400U
/** Key usage bit: Verify signatures on CRLs */
#define EscX509_KEYUSAGE_CRL_SIGN               0x0200U
/** Key usage bit: Only encipher data while performing key agreement  */
#define EscX509_KEYUSAGE_ENCIPHER_ONLY          0x0100U
/** Key usage bit: Only decipher data while performing key agreement  */
#define EscX509_KEYUSAGE_DECIPHER_ONLY          0x0080U

/* Subject/issuer attribute IDs */

/** Attribute: Country name. (C) */
#define EscX509_ATTR_COUNTRY                0x01U
/** Attribute: Organization name. (O) */
#define EscX509_ATTR_ORGANIZATION           0x02U
/** Attribute: Organizational unit name. (OU) */
#define EscX509_ATTR_ORGANIZATIONAL_UNIT    0x03U
/** Attribute: Common name. (CN) */
#define EscX509_ATTR_COMMON_NAME            0x04U
/** Attribute: Locality name. (L) */
#define EscX509_ATTR_LOCALITY_NAME          0x05U
/** Attribute: State or province name. (ST) */
#define EscX509_ATTR_STATE_OR_PROVINCE      0x06U


#if EscX509_HASH_SHA512_ENABLED == 1
/** Maximum digest length considering the configuration of hash functions */
#   define EscX509_MAX_DIGEST_LEN   64U
#elif EscX509_HASH_SHA384_ENABLED == 1
/** Maximum digest length considering the configuration of hash functions */
#   define EscX509_MAX_DIGEST_LEN   48U
#elif EscX509_HASH_SHA256_ENABLED == 1
/** Maximum digest length considering the configuration of hash functions */
#   define EscX509_MAX_DIGEST_LEN   32U
#elif EscX509_HASH_SHA224_ENABLED == 1
/** Maximum digest length considering the configuration of hash functions */
#   define EscX509_MAX_DIGEST_LEN   28U
#elif EscX509_HASH_SHA1_ENABLED == 1
/** Maximum digest length considering the configuration of hash functions */
#   define EscX509_MAX_DIGEST_LEN   20U
#else
#   error "At least one hash function must be enabled in the X509 parser"
#endif

/** Helper macros to get the number of elements of an array */
#define EscX509_NUM_ARRAY_ELEMENTS(x) (sizeof(x) / sizeof(x[0]))

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Integral type for enumeration of algorithms */
typedef Esc_UINT32 EscX509_AlgoT;

#if (EscX509_ALGORITHM_RSA_ENABLED)

/** An RSA public key */
typedef struct
{
    /** Pointer to the modulus in big endian format.*/
    const Esc_UINT8* modulus;
    /** Number of bits inside the public key */
    Esc_UINT16 modulusBits;

    /** Contains the public exponent */
    Esc_UINT32 pubExp;
} EscX509_PubKeyRsaT;

/** An RSA signature */
typedef struct
{
    /** Pointer to the signature */
    const Esc_UINT8* signBytes;
    /** Number of bits of the signature */
    Esc_UINT32 signLenBits;

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
    /** Salt length in bytes. Only used for PSS. */
    Esc_UINT32 saltLength;
#endif
} EscX509_SignatureRsaT;

#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)

#include "ecc.h"

/** An ECC public key */
typedef struct
{
    /** Pointer to the bytes of the x coordinate */
    const Esc_UINT8* x;
    /** Number of bytes x points to */
    Esc_UINT32 xLen;
    /** Pointer to the bytes of the y coordinate */
    const Esc_UINT8* y;
    /** Number of bytes y points to */
    Esc_UINT32 yLen;
    /** Used ECC curve ID of this key */
    EscEcc_CurveId curveId;
} EscX509_PubKeyEccT;

/** An ECDSA signature */
typedef struct
{
    /** Pointer to the bytes of r */
    const Esc_UINT8* r;
    /** Number of bytes r points to */
    Esc_UINT32 rLen;
    /** Pointer to the bytes of s */
    const Esc_UINT8* s;
    /** Number of bytes s points to */
    Esc_UINT32 sLen;
} EscX509_SignatureEcdsaT;

#endif

/** Abstract public key */
typedef struct
{
    /** Union encapsulating the specific key (RSA or ECC) */
    union
    {
#if (EscX509_ALGORITHM_RSA_ENABLED)
        /** An RSA public key */
        EscX509_PubKeyRsaT rsaKey;
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
        /** An ECC public key */
        EscX509_PubKeyEccT eccKey;
#endif
    } key;

    /** The algorithm that the public key can be used for */
    EscX509_AlgoT pubKeyAlgorithm;
} EscX509_PubKeyT;

/** Abstract signature */
typedef struct
{
    /** Union encapsulating the specific signature (RSA or ECC) */
    union
    {
#if (EscX509_ALGORITHM_RSA_ENABLED)
        /** An RSA signature */
        EscX509_SignatureRsaT rsaSignature;
#endif

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)
        /** An ECDSA signature */
        EscX509_SignatureEcdsaT ecdsaSignature;
#endif
    } signature;

    /** The signature algorithm used for the signature */
    EscX509_AlgoT signAlgorithm;
} EscX509_SignatureT;

/** Represents a long integer */
typedef struct
{
    /** Bytes of the integer in big endian format */
    const Esc_UINT8* intBytes;
    /** Number of bytes intBytes points to */
    Esc_UINT32 intLen;
} EscX509_IntegerT;

/** Represents a human readable string.
The string is not zero terminated. */
typedef struct
{
    /** Points to the first byte of the string or NULL if stringLen is 0U. */
    const Esc_UINT8* stringBytes;
    /** Number of bytes of the string */
    Esc_UINT32 stringLen;
} EscX509_StringT;

/** Relative distinguished name. */
typedef struct
{
    /** Country name. (C) */
    EscX509_StringT country;
    /** Organization name. (O) */
    EscX509_StringT organization;
    /** Organizational unit name. (OU) */
    EscX509_StringT organizationalUnit;
    /** Common name. (CN) */
    EscX509_StringT commonName;
    /** Locality name. (L)*/
    EscX509_StringT locality;
    /** State or province name. (ST) */
    EscX509_StringT stateOrProvince;
} EscX509_DistinguishedNameT;

/** The part of the certificate used for hashkey calculation.
Required to verify the certificate. */
typedef struct
{
    /** Start of the tbsCertificate */
    const Esc_UINT8* certStart;
    /** Length of the tbsCertificate in byte */
    Esc_UINT32 certLen;
} EscX509_TbsCertificateT;

/** A x.509 certificate. */
typedef struct
{
    /** TBSCertificate element for hashkey calculation */
    EscX509_TbsCertificateT tbsCertificate;

    /** Version of the certificate. */
    Esc_UINT8 version;

#if EscX509_PARSE_INFO == 1
    /** Certificates serial number. */
    EscX509_IntegerT serialNumber;
    /** Issuer of the certificate. */
    EscX509_DistinguishedNameT issuer;
    /** UTCTime notBefore */
    EscX509_StringT notBefore;
    /** UTCTime notAfter */
    EscX509_StringT notAfter;
    /** Subject which is certified. */
    EscX509_DistinguishedNameT subject;
#endif

    /** Raw pointer to issuer (includes tag/length) */
    EscX509_StringT rawIssuer;

    /** Raw pointer to subject (includes tag/length) */
    EscX509_StringT rawSubject;

    /** Public key of the certificate */
    EscX509_PubKeyT pubKey;

    /** The certificates signature */
    EscX509_SignatureT signature;

    /* Extensions */

    /** Bit field to flag which extensions are present in the certificate */
    Esc_UINT16 extensions;

    /** Key Usage extension: Key usage bit field */
    Esc_UINT16 keyUsage;

    /** Basic Constraints extension: CA flag */
    Esc_BOOL isCa;

    /** Basic Constraints extension: pathLenConstraint. A negative value means the pathLen is not
     * present in the certificate. */
    Esc_SINT32 pathLenConstraint;

} EscX509_CertificateT;

/** This struct maps an OID to an algorithm identifier */
typedef struct
{
    /** The OID components as 32-bit word array */
    const Esc_UINT32 *oidComps;

    /** Length of the OID array in components */
    Esc_UINT8 oidCompsLen;

    /** The algorithm identified by the OID */
    EscX509_AlgoT algo;
} EscX509_AlgorithmOid;

/** This struct maps an OID to an extension identifier */
typedef struct
{
    /** The OID components as 32-bit word array */
    const Esc_UINT32 *oidComps;

    /** Length of the OID array in components */
    Esc_UINT8 oidCompsLen;

    /** The extension bit flag */
    Esc_UINT16 extension;
} EscX509_ExtensionOid;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Parses a certificate and returns it's content in the specified
X509_certificate structure. The pointers of the X509_certificate
point to locations inside certCode array, so it must not be deleted.

The parser does not support certificates with a version number unequal to V3.
Furthermore, all fields like the issuer and subject must be present in the certCode.

\param[out] cert The parsed certificate.
\param[in] certCode Pointer to the beginning of a DER encoded x.509 certificate.
\param[in] certCodeLen Exact number of bytes of the certificate.
\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscX509_Parse(
    EscX509_CertificateT* cert,
    const Esc_UINT8 certCode[],
    Esc_UINT32 certCodeLen );

/**
Verifies a parsed certificate against a verification key.

\param[in] cert The parsed certificate.
\param[in] verificationKey The key to verify the certificate against.
\return Esc_NO_ERROR if everything works fine or Esc_INVALID_SIGNATURE if verification fails.
*/
Esc_ERROR
EscX509_VerifyWithKey(
    const EscX509_CertificateT* cert,
    const EscX509_PubKeyT* verificationKey );



/**
 * Get X509 version of the certificate.
 *
 * \param[in]   cert    The parsed certificate (filled via EscX509_Parse).
 *
 * \return X509 version of the certificate (either 1, 2 or 3).
 */
Esc_UINT8
EscX509_GetVersion(
    const EscX509_CertificateT* cert);

#if EscX509_PARSE_INFO == 1

/**
 * Get the serial number from the parsed certificate.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[out]  serialNum   Pointer to the serial number.
 *
 * \return length of the serial number in bytes.
 */
Esc_UINT32
EscX509_GetSerialNumber(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **serialNum);

/**
 * Get an attribute of the issuer from the parsed certificate.
 *
 * \param[in]   cert    The parsed certificate (filled via EscX509_Parse).
 * \param[in]   attrId  ID of the attribute. Can be any of:
 *                          EscX509_ATTR_COUNTRY
 *                          EscX509_ATTR_ORGANIZATION
 *                          EscX509_ATTR_ORGANIZATIONAL_UNIT
 *                          EscX509_ATTR_COMMON_NAME
 *                          EscX509_ATTR_LOCALITY_NAME
 *                          EscX509_ATTR_STATE_OR_PROVINCE
 * \param[out]  attr    Pointer to the issuer's attribute in the certificate.
 *                      If the attribute does not exist in the certificate or appears multiple times,
 *                      this parameter is set to Esc_NULL_PTR.
 *
 * \return length of the attribute in bytes or 0 if the attribute does not exist in the certificate
 *         or appears multiple times.
 */
Esc_UINT32
EscX509_GetIssuerAttr(
    const EscX509_CertificateT* cert,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr);

/**
 * Get the start time/date of the validity period from the parsed certificate.
 * This is the notBefore field in the X509 certificate.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[out]  dateString  Pointer to the time/date string.
 *
 * \return length of the time/date string in bytes.
 */
Esc_UINT32
EscX509_GetValidityStart(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **dateString);

/**
 * Get the end time/date of the validity period from the parsed certificate.
 * This is the notAfter field in the X509 certificate.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[out]  dateString  Pointer to the time/date string.
 *
 * \return length of the time/date string in bytes.
 */
Esc_UINT32
EscX509_GetValidityEnd(
    const EscX509_CertificateT* cert,
    const Esc_UINT8 **dateString);

/**
 * Get an attribute of the subject from the parsed certificate.
 *
 * \param[in]   cert    The parsed certificate (filled via EscX509_Parse).
 * \param[in]   attrId  ID of the attribute. Can be any of:
 *                          EscX509_ATTR_COUNTRY
 *                          EscX509_ATTR_ORGANIZATION
 *                          EscX509_ATTR_ORGANIZATIONAL_UNIT
 *                          EscX509_ATTR_COMMON_NAME
 *                          EscX509_ATTR_LOCALITY_NAME
 *                          EscX509_ATTR_STATE_OR_PROVINCE
 * \param[out]  attr    Pointer to the subject's attribute in the certificate.
 *                      If the attribute does not exist in the certificate or appears multiple times,
 *                      this parameter is set to Esc_NULL_PTR.
 *
 * \return length of the attribute in bytes or 0 if the attribute does not exist in the certificate
 *         or appears multiple times.
 */
Esc_UINT32
EscX509_GetSubjectAttr(
    const EscX509_CertificateT* cert,
    Esc_UINT8 attrId,
    const Esc_UINT8 **attr);

#endif

/**
 * Check if the parsed certificate has a specific extension.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[in]   extension   Must be one of the following:
 *                          keyUsage:           EscX509_EXTENSION_KEYUSAGE
 *                          basicConstraints:   EscX509_EXTENSION_BASIC_CONSTRAINTS
 *
 * \return TRUE if the certificate contains the extension, FALSE otherwise.
 */
Esc_BOOL
EscX509_HasExtension(
    const EscX509_CertificateT* cert,
    Esc_UINT16 extension);

/**
 * Check if the parsed certificate has the given key usage bits set.
 * This information is taken from the keyUsage extension. If the keyUsage extension
 * is NOT present in the certificate then this function will always return FALSE.
 *
 * \param[in]   cert            The parsed certificate (filled via EscX509_Parse).
 * \param[in]   keyUsageFlags   The flags to be checked. Can be a combination (with bitwise OR, i.e. "|")
 *                              of the following values (see also EscX509_KEYUSAGE_* defines above):
 *                                  EscX509_KEYUSAGE_DIGITAL_SIGNATURE
 *                                  EscX509_KEYUSAGE_NON_REPUDIATION
 *                                  EscX509_KEYUSAGE_KEY_ENCIPHERMENT
 *                                  EscX509_KEYUSAGE_DATA_ENCIPHERMENT
 *                                  EscX509_KEYUSAGE_KEY_AGREEMENT
 *                                  EscX509_KEYUSAGE_KEY_CERT_SIGN
 *                                  EscX509_KEYUSAGE_CRL_SIGN
 *                                  EscX509_KEYUSAGE_ENCIPHER_ONLY
 *                                  EscX509_KEYUSAGE_DECIPHER_ONLY
 *
 * \return TRUE if the certificate contains the keyUsage extension
 *         and has all flags given in keyUsageFlags set, FALSE otherwise.
 */
Esc_BOOL
EscX509_HasKeyUsageFlagsSet(
    const EscX509_CertificateT* cert,
    Esc_UINT16 keyUsageFlags);

/**
 * Check if the isCa flag is set in the parsed certificate.
 * This information is taken from the basicConstraints extension. If the basicConstraints extension
 * is NOT present in the certificate then this function will always return FALSE.
 *
 * \param[in]   cert            The parsed certificate (filled via EscX509_Parse).
 *
 * \return TRUE if the basicConstraints extension is present and the isCa flag is set,
 *         FALSE otherwise.
 */
Esc_BOOL
EscX509_IsCaFlagSet(
    const EscX509_CertificateT* cert);

/**
 * Get the pathLenConstraint from the parsed certificate.
 * This information is taken from the basicConstraints extension. If the basicConstraints extension
 * is NOT present in the certificate then this function will always return -1.
 *
 * \param[in]   cert            The parsed certificate (filled via EscX509_Parse).
 *
 * \return the pathLenConstraint if both the basicConstraints extension and the pathLenConstraint
 *         are present, -1 otherwise.
 */
Esc_SINT32
EscX509_GetPathLenConstraint(
    const EscX509_CertificateT* cert);


/**
 * Get the encoded subject. This includes the tag and length of the subject.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[out]  subjectLen  Length of the encoded subject in bytes.
 *
 * \return A pointer to the encoded subject.
 */
const Esc_UINT8*
EscX509_GetEncodedSubject(
    const EscX509_CertificateT* cert,
    Esc_UINT32* subjectLen);

/**
 * Get the encoded issuer. This includes the tag and length of the issuer.
 *
 * \param[in]   cert        The parsed certificate (filled via EscX509_Parse).
 * \param[out]  issuerLen   Length of the encoded issuer in bytes.
 *
 * \return A pointer to the encoded issuer.
 */
const Esc_UINT8*
EscX509_GetEncodedIssuer(
    const EscX509_CertificateT* cert,
    Esc_UINT32* issuerLen);


/* ------------------ INTERNAL - DO NOT CALL DIRECTLY ------------------------------------*/

/**
Parse the following OID and compare it with a list of known OIDs
representing algorithm identifiers.

\param[in, out] algSeq  Context of the DER encoded x.509 certificate. This context should point
                        directly to the algorithm identifier OID in the certificate.
\param[in]      table   An array containing references to known OIDs and algorithm IDs.
                        This is basically a map from OID to EscX509_AlgoT.
\param[in]      numTableEntries Number of elements in the array.
\param[out]     algorithm Algorithm identifier representing the parsed OID.

\returns Esc_NO_ERROR if the OID was found in the list of known algorithm IDs.
\returns Esc_INVALID_OBJECT_IDENTIFIER if the OID was not found.
*/
Esc_ERROR
EscX509_FindAlgorithmIdentifier(
    EscDer_ContextT* algSeq,
    const EscX509_AlgorithmOid table[],
    Esc_UINT32 numTableEntries,
    EscX509_AlgoT *algorithm);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
