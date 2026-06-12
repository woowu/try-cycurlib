/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       x.509 Parser supporting ECDSA

   $Rev: 3832 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

/*lint -efile(766,x509_ecc.h) If ECDSA support is deactivated the included header is not used. */

#include "x509_ecc.h"

#if (EscX509_ALGORITHM_ECDSA_ENABLED == 1)

#include "_ptarithws.h"

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

/** Check for ECDSA */
#if (EscEcc_ECDSA_ENABLED == 0)
#   error X509_sha2_ecc requires ECDSA. Please define 'EscEcc_ECDSA_ENABLED'.
#endif

/** Length of OID array */
#define EscX509Sha2_MAX_CURVE_IDENTIFIERS   9U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * Assigns and pads an UINT8 array with 0.
 *
 * \param[in]   dataIn Input
 * \param[in]   inLen  Input Length
 * \param[out]  dataOut Output of length outLen
 * \param[in]   outLen Length output ( padded if inLen < outLen)
 *
 * \note dataIn may not point to the same address as dataOut
 */
static void
EscX509Sha2Ecc_AssignAndPad0(
    const Esc_UINT8* dataIn,
    Esc_UINT32 inLen,
    Esc_UINT8* dataOut,
    Esc_UINT32 outLen );

/** X509 ECC curve identifiers */
typedef struct
{
    /** length of OID */
    Esc_UINT32 len;
    /** represented curve ID */
    EscEcc_CurveId curveId;
    /** oid the first Identifier is calculated using (X*40+Y) */
    Esc_UINT32 oid[EscX509Sha2_MAX_CURVE_IDENTIFIERS];
} EscX509_OID_T;

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*lint -esym(9003,EscX509Sha2Ecc_OID_CURVE) Keep the constant data structures global for improved readability */

/** This array contains all OIDs of the enabled curves.
 * The first value is the length of the array, the second value is the represented curve
 * and the third value is the first OID (X*40+Y) */
static const EscX509_OID_T EscX509Sha2Ecc_OID_CURVE[] =
{
#if (EscEcc_SECP_192_ENABLED == 1)
    /* OID secp192r1 */
    {
        /*  secp192r1 OBJECT IDENTIFIER ::= {
           iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 } */
        6U,
        EscEcc_CURVE_SECP_192,
        { 42U, 840U, 10045U, 3U, 1U, 1U, 0U, 0U, 0U },
    },
#endif

#if (EscEcc_SECP_224_ENABLED == 1)
    /* OID secp224r1 */
    {
        /*  secp224r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) certicom(132) curve(0) 33 } */
        4U,
        EscEcc_CURVE_SECP_224,
        { 43U, 132U, 0U, 33U, 0U, 0U, 0U, 0U, 0U },
    },
#endif

#if (EscEcc_SECP_256_ENABLED == 1)
    /* OID secp256r1 */
    {
        /*  secp256r1 OBJECT IDENTIFIER ::= {
           iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7 } */
        6U,
        EscEcc_CURVE_SECP_256,
        { 42U, 840U, 10045U, 3U, 1U, 7U, 0U, 0U, 0U },
    },
#endif

#if (EscEcc_SECP_384_ENABLED == 1)
    /* OID secp384r1 */
    {
        /*  secp384r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) certicom(132) curve(0) 34 } */
        4U,
        EscEcc_CURVE_SECP_384,
        { 43U, 132U, 0U, 34U, 0U, 0U, 0U, 0U, 0U },
    },
#endif

#if (EscEcc_SECP_521_ENABLED == 1)
    /* OID secp521r1 */
    {
        /*  secp521r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) certicom(132) curve(0) 35 } */
        4U,
        EscEcc_CURVE_SECP_521,
        { 43U, 132U, 0U, 35U, 0U, 0U, 0U, 0U, 0U },
    },
#endif

#if (EscEcc_BRAINPOOL_P160_ENABLED == 1)
    /* OID brainpoolP160r1 */
    {
        /*  brainpoolP160r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 1} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P160,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 1U },
    },
#endif

#if (EscEcc_BRAINPOOL_P192_ENABLED == 1)
    /* OID brainpoolP192r1 */
    {
        /*  brainpoolP192r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 3} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P192,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 3U },
    },
#endif

#if (EscEcc_BRAINPOOL_P224_ENABLED == 1)
    /* OID brainpoolP224r1 */
    {
        /*  brainpoolP224r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 5} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P224,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 5U },
    },
#endif

#if (EscEcc_BRAINPOOL_P256_ENABLED == 1)
    /* OID brainpoolP256r1 */
    {
        /*  brainpoolP256r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 7} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P256,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 7U },
    },
#endif

#if (EscEcc_BRAINPOOL_P320_ENABLED == 1)
    /* OID brainpoolP320r1 */
    {
        /*  brainpoolP320r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 9} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P320,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 9U },
    },
#endif

#if (EscEcc_BRAINPOOL_P384_ENABLED == 1)
    /* OID brainpoolP384r1 */
    {
        /*  brainpoolP384r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 11} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P384,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 11U },
    },
#endif

#if (EscEcc_BRAINPOOL_P512_ENABLED == 1)
    /* OID brainpoolP512r1 */
    {
        /*  brainpoolP512r1 OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) teletrust(36) algorithm(3) signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) 1 1 13} */
        9U,
        EscEcc_CURVE_BRAINPOOL_P512,
        { 43U, 36U, 3U, 3U, 2U, 8U, 1U, 1U, 13U },
    },
#endif
};

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

Esc_ERROR
EscX509Sha2Ecc_ParseSignature(
    EscDer_ContextT* ctx,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* bitString;
    Esc_UINT32 numBits;
    const EscPtArithWs_CurveT* curve = Esc_NULL_PTR;

    EscX509_SignatureEcdsaT *ecdsaSig = &cert->signature.signature.ecdsaSignature;

    /*
       ec-signature-value ::= SEQUENCE {
       r INTEGER,
       s INTEGER
       }

       X.509 certificates and CRLs represent signatures as a value of type BIT STRING. In these cases,
       the entire encoding of a value of type ec-signature-value shall be the value of the bit string
       (including tag and length field in case DER-encoding is being used)

     */

    /* get signature bitstring */
    returnCode = EscDer_NextBitString( ctx, &bitString, &numBits );
    if (returnCode == Esc_NO_ERROR)
    {
        EscDer_ContextT sigCtx;
        EscDer_ContextT sigSeq;
        Esc_UINT32 numBytes;

        /* make context out of bitstring */
        numBytes = (numBits + 7U) / 8U;

        returnCode = EscDer_Init( &sigCtx, bitString, numBytes );
        if (returnCode == Esc_NO_ERROR)
        {
            /* read the signature  */

            /* Enter sequence */
            returnCode = EscDer_NextSequence( &sigCtx, &sigSeq );
            if (returnCode == Esc_NO_ERROR)
            {
                /* get integer r */
                returnCode = EscDer_NextIntegerLongBe( &sigSeq, &ecdsaSig->r, &ecdsaSig->rLen );
                if (returnCode == Esc_NO_ERROR)
                {
                    if ( (ecdsaSig->rLen % 2U) == 1U )
                    {
                        /* sometimes there is a leading zero -> remove it */
                        if (ecdsaSig->r[0] == 0x00U)
                        {
                            ecdsaSig->r = &ecdsaSig->r[1];
                            ecdsaSig->rLen--;
                        }
                    }
                }

                /* get integer s */
                returnCode = EscDer_NextIntegerLongBe( &sigSeq, &ecdsaSig->s, &ecdsaSig->sLen );
                if (returnCode == Esc_NO_ERROR)
                {
                    if ( (ecdsaSig->sLen % 2U) == 1U )
                    {
                        /* sometimes there is a leading zero -> remove it */
                        if (ecdsaSig->s[0] == 0x00U)
                        {
                            ecdsaSig->s = &ecdsaSig->s[1];
                            ecdsaSig->sLen--;
                        }
                    }
                }

                /* Check lengths */
                curve = EscPtArithWs_GetCurve(cert->pubKey.key.eccKey.curveId);
                if (curve == Esc_NULL_PTR)
                {
                    returnCode = Esc_INVALID_CURVE;
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    /* check length of r and s with respect to the given curve. */
                    if ( (ecdsaSig->sLen <= curve->curveSize.keySizeBytes) && (ecdsaSig->sLen >= 1U) &&
                         (ecdsaSig->rLen <= curve->curveSize.keySizeBytes) && (ecdsaSig->rLen >= 1U) )
                    {
                        returnCode = Esc_NO_ERROR;
                    }
                    else
                    {
                        returnCode = Esc_INVALID_SIGNATURE;
                    }
                }
            }
        }
    }

    return returnCode;
}


Esc_ERROR
EscX509Sha2Ecc_ParseCurveFromAlgoParams(
    EscDer_ContextT* certCtx,
    EscEcc_CurveId *curveId)
{
    Esc_ERROR returnCode;

    Esc_UINT32 eccIdentifiers[EscX509Sha2_MAX_CURVE_IDENTIFIERS];
    Esc_UINT32 numIdentifiers=0U;
    Esc_UINT16 i, j;
    Esc_BOOL foundCurve = FALSE;

    /*
       according to www.ietf.org/internet-drafts/draft-ietf-pkix-new-asn1-01.txt
       note that we only support named curves

       pk-ecPublicKey PUBLIC-KEY ::= {
       IDENTIFIER id-ecPublicKey
       PARAMS EcpkParameters ARE required
       }

       EcpkParameters ::= CHOICE {
       ecParameters  ECParameters,
       namedCurve    OBJECT IDENTIFIER,
       implicitlyCA  NULL }

       ECParameters  ::= SEQUENCE {         -- Elliptic curve parameters
       version   ECPVer,
       fieldID   FieldID,
       curve     Curve,
       base      ECPoint,                -- Base point G
       order     INTEGER,                -- Order n of the base point
       cofactor  INTEGER  OPTIONAL }     -- The integer h = #E(Fq)/n

       ECPVer ::= INTEGER {ecpVer1(1)}
     */

    /* get the named ECC curve OID*/
    returnCode = EscDer_NextOid(certCtx, eccIdentifiers, EscX509Sha2_MAX_CURVE_IDENTIFIERS, &numIdentifiers);

    /* Test curve OIDs if we support it and set cert->curveId to the used one */
    if (returnCode == Esc_NO_ERROR)
    {
        for ( i = 0U; ((i < (Esc_UINT16)EscEcc_NUMBER_CURVES) && (foundCurve == FALSE) ); i++)
        {
            /*test first the length then byte wise*/
            if (EscX509Sha2Ecc_OID_CURVE[i].len == numIdentifiers)
            {
                foundCurve = TRUE;
                for ( j = 0U; ( j <numIdentifiers) && (foundCurve == TRUE); j++ )
                {
                    if (EscX509Sha2Ecc_OID_CURVE[i].oid[j] != eccIdentifiers[j])
                    {
                        foundCurve = FALSE;
                    }
                }
            }
        }

        if (foundCurve)
        {
            (*curveId) = EscX509Sha2Ecc_OID_CURVE[i-1U].curveId;
        }
        else
        {
            returnCode = Esc_INVALID_PUBKEY_ALGORITHM;
        }
    }

    return returnCode;
}


Esc_ERROR
EscX509Sha2Ecc_ParsePubKey(
    EscDer_ContextT* keySeq,
    EscX509_CertificateT* cert )
{
    Esc_ERROR returnCode;

    /*
       according to www.ecc-brainpool.org/download/2006-03-30_tr-ecc.pdf
       note that we only support named curves

       SubjectPublicKeyInfo ::= SEQUENCE {
       algorithm AlgorithmIdentifier{{ECPKAlgorithms}},
       subjectPublicKey BIT STRING
       }

       ECPKAlgorithms ALGORITHM ::= {
       ecPublicKeyType,
       ...
       }

       ecPublicKeyType ALGORITHM ::= {
       OID id-ecPublicKey PARMS Parameters
       }

       ALGORITHM ::= CLASS {
       &id OBJECT IDENTIFIER UNIQUE,
       &Type OPTIONAL
       }

       WITH SYNTAX { OID &id [PARMS &Type] }

       Parameters{CURVES:IOSet} ::= CHOICE {
       ecParameters ECParameters,
       namedCurve CURVES.&id({ExtendedCurveNames}),
       implicitlyCA NULL
       }

     */

    const Esc_UINT8* bitString;
    Esc_UINT32 numBits;
    EscX509_PubKeyEccT *eccKey = &cert->pubKey.key.eccKey;

    /* get bitstring */
    returnCode = EscDer_NextBitString( keySeq, &bitString, &numBits );
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 numBytes;
        const EscPtArithWs_CurveT *curve;
        Esc_UINT16 curvesKeyBytes;

        /* Lookup curve. Since EscX509Sha2Ecc_ParseCurveFromAlgoParams() returns only successfully if
         * if the curve ID is correct, we can safely assume that the lookup returns a valid pointer.
         */
        curve = EscPtArithWs_GetCurve(eccKey->curveId);
        Esc_ASSERT(curve);
        curvesKeyBytes = curve->curveSize.keySizeBytes;

        /* extract the public key out of bitstring, rounded up */
        numBytes = (numBits + 7U) / 8U;

        /* skip first byte of the public key (always 0x04) */
        eccKey->x = &bitString[1U];
        eccKey->xLen = ( (numBytes - 1U) / 2U );
        eccKey->y = &bitString[1U + eccKey->xLen];
        eccKey->yLen = eccKey->xLen;

        /* Check that:
            - number of bytes corresponds to (x,y coordinates plus leading 0x04)
            - first byte is 0x04 (uncompressed ECC public key) */
        if ( ((Esc_UINT16)numBytes == (1U + curvesKeyBytes + curvesKeyBytes)) &&
             (bitString[0] == 0x04U) )
        {
            returnCode = Esc_NO_ERROR;
        }
        else
        {
            returnCode = Esc_INVALID_PUBLIC_KEY;
        }
    }

    return returnCode;
}

static void
EscX509Sha2Ecc_AssignAndPad0(
    const Esc_UINT8* dataIn,
    Esc_UINT32 inLen,
    Esc_UINT8* dataOut,
    Esc_UINT32 outLen )
{
    Esc_UINT32 i;
    Esc_UINT32 min = (inLen < outLen) ? (outLen - inLen) : 0U;

    for (i = 0U; i < min; i++)
    {
        dataOut[i] = 0U;
    }

    for (; i < outLen; i++)
    {
        dataOut[i] = dataIn[i-min];
    }
}

Esc_ERROR
EscX509Sha2Ecc_VerifySignature(
    const Esc_UINT8 digest[],
    Esc_UINT32 digestLen,
    const EscX509_SignatureT *signature,
    const EscX509_PubKeyT *verificationKey)
{
    Esc_UINT32 curveKeyBytes;
    EscEcc_PublicKeyT pQ;
    EscEcc_SignatureT ecc_sig;
    const EscPtArithWs_CurveT *curve;
    const EscX509_PubKeyEccT *eccVerifyKey = &verificationKey->key.eccKey;
    const EscX509_SignatureEcdsaT *ecdsaSig = &signature->signature.ecdsaSignature;

    Esc_ERROR returnCode;

    /* Lookup curve. Since EscX509Sha2Ecc_ParseCurveFromAlgoParams() returns only successfully if
     * if the curve ID is correct, we can safely assume that the lookup returns a valid pointer.
     */
    curve = EscPtArithWs_GetCurve(eccVerifyKey->curveId);
    Esc_ASSERT(curve);
    curveKeyBytes = curve->curveSize.keySizeBytes;

    EscX509Sha2Ecc_AssignAndPad0( eccVerifyKey->x, eccVerifyKey->xLen, pQ.x, curveKeyBytes );
    EscX509Sha2Ecc_AssignAndPad0( eccVerifyKey->y, eccVerifyKey->yLen, pQ.y, curveKeyBytes );
    EscX509Sha2Ecc_AssignAndPad0( ecdsaSig->r, ecdsaSig->rLen, ecc_sig.r_bytes, curveKeyBytes );
    EscX509Sha2Ecc_AssignAndPad0( ecdsaSig->s, ecdsaSig->sLen, ecc_sig.s_bytes, curveKeyBytes );

    returnCode = EscEcc_SignatureVerification( digest, digestLen, &ecc_sig, &pQ, curve->curveId );

    return returnCode;
}

#endif /* EscX509_ALGORITHM_ECDSA_ENABLED == 1 */

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
