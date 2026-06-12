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
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

/*lint -efile(766,x509_rsa.h) If RSA support is deactivated the included header is not used. */

#include "x509_rsa.h"

#if (EscX509_ALGORITHM_RSA_ENABLED)

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

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * Parse an RSA public key and store pointers to it in the given certificate
 * structure.
 *
 * \param[in,out]   certCtx     The DER context pointing to the RSA key (behind the AlgorithmIdentifier).
 * \param[out]      cert        The certificate struct to which the parsed information is stored.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscX509Rsa_ParseRsaKey(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert );

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)

/**
 * Parse a hash algorithm (sequence consisting of an OID and NULL for optional parameters).
 *
 * \param[in,out]   certCtx     The DER context pointing to the hash algorithm sequence.
 * \param[out]      cert        The certificate struct to which the parsed information is stored.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscX509Rsa_ParseHashAlgo(
    EscDer_ContextT *taggedCtx,
    EscX509_AlgoT *hashAlgo);

/**
 * Parse an MGF algorithm.
 *
 * \param[in,out]   certCtx     The DER context pointing to the MGF algorithm.
 * \param[out]      cert        The certificate struct to which the parsed information is stored.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscX509Rsa_ParseMgf(
    EscDer_ContextT *taggedCtx,
    EscX509_AlgoT *mgfHashAlgo);

#endif

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*lint -esym(9003,EscX509Rsa_HashAlgoOids,EscX509Rsa_OID_Mgf1) Keep the constant data structures global for improved readability */


#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)

/* Hash OID - The first two components are combined, i.e. X * 40 + Y. This is what EscDer_NextOid() expects */

#if (EscX509_HASH_SHA1_ENABLED == 1)
/* OID SHA-1 */
static const Esc_UINT32 EscX509Rsa_OID_sha1[] =
{
    /* id-sha1 OBJECT IDENTIFIER ::= {
      iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) sha1(26) } */
    43U, 14U, 3U, 2U, 26U
};
#endif

#if (EscX509_HASH_SHA224_ENABLED == 1)
/* OID SHA2-224 */
static const Esc_UINT32 EscX509Rsa_OID_sha224[] =
{
    /* id-sha224 OBJECT IDENTIFIER ::= {
      joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha224(4) } */
    96U, 840U, 1U, 101U, 3U, 4U, 2U, 4U
};
#endif

#if (EscX509_HASH_SHA256_ENABLED == 1)
/* OID SHA2-256 */
static const Esc_UINT32 EscX509Rsa_OID_sha256[] =
{
    /* id-sha256 OBJECT IDENTIFIER ::= {
       joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha256(1) } */
    96U, 840U, 1U, 101U, 3U, 4U, 2U, 1U
};
#endif

#if (EscX509_HASH_SHA384_ENABLED == 1)
/* OID SHA2-384 */
static const Esc_UINT32 EscX509Rsa_OID_sha384[] =
{
    /* id-sha384 OBJECT IDENTIFIER ::= {
       joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha384(2) } */
    96U, 840U, 1U, 101U, 3U, 4U, 2U, 2U
};
#endif

#if (EscX509_HASH_SHA512_ENABLED == 1)
/* OID SHA2-512 */
static const Esc_UINT32 EscX509Rsa_OID_sha512[] =
{
    /* id-sha512 OBJECT IDENTIFIER ::= {
       joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha512(3) } */
    96U, 840U, 1U, 101U, 3U, 4U, 2U, 3U
};
#endif



/* OID MGF1 */
static const Esc_UINT32 EscX509Rsa_OID_Mgf1[] =
{
    /* id-RSASSA-PSS OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 8 } */
    1U, 2U, 840U, 113549U, 1U, 1U, 8U
};

static const EscX509_AlgorithmOid EscX509Rsa_HashAlgoOids[] =
{
#if (EscX509_HASH_SHA1_ENABLED == 1)
    {
        EscX509Rsa_OID_sha1,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_sha1),
        EscX509_HASH_SHA1,
    },
#endif

#if (EscX509_HASH_SHA224_ENABLED == 1)
    {
        EscX509Rsa_OID_sha224,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_sha224),
        EscX509_HASH_SHA224,
    },
#endif

#if (EscX509_HASH_SHA256_ENABLED == 1)
    {
        EscX509Rsa_OID_sha256,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_sha256),
        EscX509_HASH_SHA256,
    },
#endif

#if (EscX509_HASH_SHA384_ENABLED == 1)
    {
        EscX509Rsa_OID_sha384,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_sha384),
        EscX509_HASH_SHA384,
    },
#endif

#if (EscX509_HASH_SHA512_ENABLED == 1)
    {
        EscX509Rsa_OID_sha512,
        (Esc_UINT8) EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_sha512),
        EscX509_HASH_SHA512,
    },
#endif

};

#endif /* PSS enabled */

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

Esc_ERROR
EscX509Rsa_ParseSignature(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    EscX509_SignatureRsaT *signature = &cert->signature.signature.rsaSignature;

    return EscDer_NextBitString( ctx, &signature->signBytes, &signature->signLenBits );
}

static Esc_ERROR
EscX509Rsa_ParseRsaKey(
    EscDer_ContextT* certCtx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    EscDer_ContextT rsaSeq;

    EscX509_PubKeyRsaT *rsaKey = &cert->pubKey.key.rsaKey;

    /*
       RSAPublicKey (BIT STRING) ::= SEQUENCE {
       modulus            INTEGER,    -- n
       publicExponent     INTEGER  }  -- e
       }
     */
    /* Enter sequence */
    returnCode = EscDer_NextSequence( certCtx, &rsaSeq );
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 modLen;
        /* get integer modulus */
        returnCode = EscDer_NextIntegerLongBe( &rsaSeq, &rsaKey->modulus, &modLen );
        if (returnCode == Esc_NO_ERROR)
        {
            rsaKey->modulusBits = (Esc_UINT16)((Esc_UINT16)(modLen) * 8U);

            /* usually, there is a byte 0x00 at the beginning appended, remove it */
            if ( (rsaKey->modulusBits % 256U) == 8U )
            {
                if (rsaKey->modulus[0] == 0x00U)
                {
                    rsaKey->modulusBits -= 8U;
                    rsaKey->modulus = &rsaKey->modulus[1];
                }
            }

            /* get integer exponent */
            returnCode = EscDer_NextInteger( &rsaSeq, &rsaKey->pubExp );
        }
    }

    /* Check that bit string ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&rsaSeq);
    }

    return returnCode;
}

Esc_ERROR
EscX509Rsa_ParsePubKey(
    EscDer_ContextT* keySeq,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;

    /*
       subjectPublicKeyInfo    SubjectPublicKeyInfo,

       SubjectPublicKeyInfo ::= SEQUENCE {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING

       RSAPublicKey (BIT STRING) ::= SEQUENCE {
       modulus            INTEGER,    -- n
       publicExponent     INTEGER  }  -- e
       }
     */

    const Esc_UINT8* bitString;
    Esc_UINT32 numBits;

    /* get bitstring */
    returnCode = EscDer_NextBitString( keySeq, &bitString, &numBits );
    if (returnCode == Esc_NO_ERROR)
    {
        EscDer_ContextT rsaCtx;
        Esc_UINT32 numBytes;

        /* make context out of bitstring */
        numBytes = (numBits + 7U) / 8U;

        returnCode = EscDer_Init( &rsaCtx, bitString, numBytes );
        if (returnCode == Esc_NO_ERROR)
        {
            /* read the key */
            returnCode = EscX509Rsa_ParseRsaKey( &rsaCtx, cert );
        }

        /* Check that bit string ends here */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscDer_AssertEnd(&rsaCtx);
        }
    }

    return returnCode;
}

Esc_ERROR
EscX509Rsa_VerifySignature(
    const Esc_UINT8 digest[],
    Esc_UINT32 digestLen,
    const EscX509_SignatureT *signature,
    const EscX509_PubKeyT *verificationKey)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 digestType = 0U;
    EscRsa_PubKeyT pubKey;

    const EscX509_PubKeyRsaT *verificationRsaKey = &verificationKey->key.rsaKey;
    const EscX509_SignatureRsaT *rsaSig = &signature->signature.rsaSignature;

    Esc_UNUSED_PARAM(digestLen);

    if ( ( verificationRsaKey->modulusBits > (EscRsa_KEY_BITS_MAX) ) ||
          ( rsaSig->signLenBits > (EscRsa_KEY_BITS_MAX) ) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscRsa_PubKeyFromBytes(
                        &pubKey,
                        verificationRsaKey->modulusBits,
                        verificationRsaKey->modulus,
                        verificationRsaKey->pubExp );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        switch (signature->signAlgorithm & EscX509_HASH_MASK)
        {
#if (EscX509_HASH_SHA1_ENABLED == 1)
            case EscX509_HASH_SHA1:
                digestType = EscPkcs1_DIGEST_TYPE_SHA1;
                break;
#endif

#if (EscX509_HASH_SHA224_ENABLED == 1)
            case EscX509_HASH_SHA224:
                digestType = EscPkcs1_DIGEST_TYPE_SHA224;
                break;
#endif

#if (EscX509_HASH_SHA256_ENABLED == 1)
            case EscX509_HASH_SHA256:
                digestType = EscPkcs1_DIGEST_TYPE_SHA256;
                break;
#endif

#if (EscX509_HASH_SHA384_ENABLED == 1)
            case EscX509_HASH_SHA384:
                digestType = EscPkcs1_DIGEST_TYPE_SHA384;
                break;
#endif

#if (EscX509_HASH_SHA512_ENABLED == 1)
            case EscX509_HASH_SHA512:
                digestType = EscPkcs1_DIGEST_TYPE_SHA512;
                break;
#endif

            default:
                returnCode = Esc_INVALID_SIGN_ALGORITHM;
                break;
        }
    }

    /*lint -save -esym(645,pubKey) pubKey is initialized iff returnCode == Esc_NO_ERROR which is ensured for any further access to pubKey */

    if (returnCode == Esc_NO_ERROR)
    {
        switch (signature->signAlgorithm & EscX509_SIGN_MASK)
        {
#if (EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1V15:
                returnCode = EscPkcs1RsaSsaV15_Verify(
                        rsaSig->signBytes,
                        rsaSig->signLenBits / 8U,
                        &pubKey,
                        digest,
                        digestType );
                break;
#endif

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)
            case EscX509_ALGORITHM_RSA_PKCS1PSS:
                returnCode = EscPkcs1RsaSsaPss_Verify(
                        digest,
                        &pubKey,
                        rsaSig->signBytes,
                        rsaSig->signLenBits / 8U,
                        rsaSig->saltLength,
                        digestType );
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

#if (EscX509_ALGORITHM_RSA_PKCS1PSS_ENABLED == 1)

Esc_ERROR
EscX509Rsa_ParsePssParameters(
    EscDer_ContextT* keySeq,
    EscX509_SignatureT *signature)
{
    Esc_ERROR returnCode;
    EscDer_ContextT taggedCtx;
    EscDer_ContextT paramSeq;
    EscX509_AlgoT hashAlgo = EscX509_HASH_SHA1;

    returnCode = EscDer_NextSequence(keySeq, &paramSeq);

    /* hashAlgorithm    [0] HashAlgorithm   DEFAULT     sha1 */

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_BOOL hasHashAlgo = FALSE;

        returnCode = EscDer_PeekElement(&paramSeq, 0U, DER_CLASS_CONTEXT, &hasHashAlgo);
        if (returnCode == Esc_NO_ERROR)
        {
            if (hasHashAlgo != FALSE)
            {
                returnCode = EscDer_NextTaggedValue(&paramSeq, 0U, &taggedCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscX509Rsa_ParseHashAlgo(&taggedCtx, &hashAlgo);
                }
            }
        }

#if (EscX509_HASH_SHA1_ENABLED == 0)
        /* Check if the hash algorithm is SHA-1, but support is deactivated */
        if ( (returnCode == Esc_NO_ERROR) && (hashAlgo == EscX509_HASH_SHA1) )
        {
            returnCode = Esc_INVALID_SIGN_ALGORITHM;
        }
#endif

        if (returnCode == Esc_NO_ERROR)
        {
            signature->signAlgorithm |= hashAlgo;
        }
    }

    /* maskGenAlgorithm [1] MaskGenAlgorithm    DEFAULT mgf1SHA1 */

    if (returnCode == Esc_NO_ERROR)
    {
        /* We allow only MGF1 as mask generation function. Furthermore, the hash used
         * within PSS must be the same as used by the mask generation function. */

        EscX509_AlgoT mgfHashAlgo = EscX509_HASH_SHA1;
        Esc_BOOL hasMfg = FALSE;

        returnCode = EscDer_PeekElement(&paramSeq, 1U, DER_CLASS_CONTEXT, &hasMfg);
        if ( (returnCode == Esc_NO_ERROR) && (hasMfg != FALSE) )
        {
            returnCode = EscDer_NextTaggedValue(&paramSeq, 1U, &taggedCtx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscX509Rsa_ParseMgf(&taggedCtx, &mgfHashAlgo);
            }
        }

        if ( (returnCode == Esc_NO_ERROR) && (mgfHashAlgo != hashAlgo) )
        {
            /* Parsing found an MGF using a different hash function than used within PSS.
             * This is currently not supported.
             */
            returnCode = Esc_INVALID_SIGN_ALGORITHM;
        }
    }

    /* saltLength   [2] INTEGER     DEFAULT 20 */

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_BOOL hasSaltLen = FALSE;

        signature->signature.rsaSignature.saltLength = 20U;

        returnCode = EscDer_PeekElement(&paramSeq, 2U, DER_CLASS_CONTEXT, &hasSaltLen);
        if ( (returnCode == Esc_NO_ERROR) && (hasSaltLen != FALSE) )
        {
            returnCode = EscDer_NextTaggedValue(&paramSeq, 2U, &taggedCtx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscDer_NextInteger(&taggedCtx, &signature->signature.rsaSignature.saltLength);
            }
        }
    }

    /* trailerField [3] INTEGER     DEFAULT trailerFieldBC(1) */

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 trailerField = 1;
        Esc_BOOL hasTrailerField = FALSE;

        returnCode = EscDer_PeekElement(&paramSeq, 3U, DER_CLASS_CONTEXT, &hasTrailerField);
        if ( (returnCode == Esc_NO_ERROR) && (hasTrailerField != FALSE) )
        {
            returnCode = EscDer_NextTaggedValue(&paramSeq, 3U, &taggedCtx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscDer_NextInteger(&taggedCtx, &trailerField);
            }
        }

        /* We don't support any other trailer fields than 0xBC */
        if ( (returnCode == Esc_NO_ERROR) && (trailerField != 1U) )
        {
            returnCode = Esc_INVALID_SIGN_ALGORITHM;
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&paramSeq);
    }

    return returnCode;
}

static Esc_ERROR
EscX509Rsa_ParseHashAlgo(
    EscDer_ContextT *taggedCtx,
    EscX509_AlgoT *hashAlgo)
{
    Esc_ERROR returnCode;
    EscDer_ContextT hashSeq;

    returnCode = EscDer_NextSequence(taggedCtx, &hashSeq);
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509_FindAlgorithmIdentifier(
                        &hashSeq,
                        EscX509Rsa_HashAlgoOids,
                        EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_HashAlgoOids),
                        hashAlgo);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if (EscDer_HasMoreBytes(&hashSeq) != FALSE)
        {
            returnCode = EscDer_NextNull(&hashSeq);
        }
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&hashSeq);
    }

    return returnCode;
}

static Esc_ERROR
EscX509Rsa_ParseMgf(
    EscDer_ContextT *taggedCtx,
    EscX509_AlgoT *mgfHashAlgo)
{
    Esc_ERROR returnCode;
    EscDer_ContextT mgfSeq;

    returnCode = EscDer_NextSequence(taggedCtx, &mgfSeq);
    if (returnCode == Esc_NO_ERROR)
    {
        /* Only MGF1 is supported, we expect this here */
        returnCode = EscDer_NextOidCheck( &mgfSeq, EscX509Rsa_OID_Mgf1, EscX509_NUM_ARRAY_ELEMENTS(EscX509Rsa_OID_Mgf1) );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscX509Rsa_ParseHashAlgo(&mgfSeq, mgfHashAlgo);
    }

    /* Check that sequence ends here */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDer_AssertEnd(&mgfSeq);
    }

    return returnCode;
}

#endif /* PSS enabled */

#endif /* EscX509_ALGORITHM_RSA_PKCS1V15_ENABLED == 1 */

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
