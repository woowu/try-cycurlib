/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       EdDsa signature scheme.

   \details     EdDSA is a Schnorr signature scheme by Bernstein et al.
                using a twisted Edwards curve.

                This implementation currently supports Ed25519-SHA-512 only and requests the complete message.
                In detail, this implementation supports the following signature scheme:
                Ed25519-SHA-512 as an instance of 'PureEdDSA'.

                In order to get a Hashed-Ed25519 simply hash the message and use
                the resulting digest as the message for this implementation.

                In the paper, hash outputs are little-endian interpreted.
                Therefore the endianess must be swapped to fit the CycurLIB
                arithmetic module which interprets arrays as big endian values.

   \see         [1] Extended Twisted Edwards Coordinates:
                    Hisil et al. - Twisted Edwards Curves Revisited (2008)
                [2] Ed25519 and choice of the used Twisted Edwards Curve:
                    Bernstein et al. - High-speed high-security signatures (2012)
                [3] RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)

   $Rev: 2799 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "eddsa.h"
#include "sha_512.h"
#include "_ptarithte25519.h"
#include "random.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of the used integers for signature generation and verification (values 'a', 'r', 'R', and 'S'). */
#define EscEdDsa_INTEGER_BYTES 32U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/** dom2 prefix string as defined in [3], Section 2.
 * "SigEd25519 no Ed25519 collisions"
 */
static const Esc_UINT8 dom2Prefix[32U] =
{
    0x53U, 0x69U, 0x67U, 0x45U, 0x64U, 0x32U, 0x35U, 0x35U,
    0x31U, 0x39U, 0x20U, 0x6eU, 0x6fU, 0x20U, 0x45U, 0x64U,
    0x32U, 0x35U, 0x35U, 0x31U, 0x39U, 0x20U, 0x63U, 0x6fU,
    0x6cU, 0x6cU, 0x69U, 0x73U, 0x69U, 0x6fU, 0x6eU, 0x73U
};

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

Esc_ERROR
EscEdDsa_KeyGeneration(
    Esc_UINT8 pubKey[],
    Esc_UINT32* pubKeyLen,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (pubKey == Esc_NULL_PTR) || (pubKeyLen == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) || (privKeyLen == Esc_NULL_PTR) ||
         (getRandomFunc == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    /* Check the curve ID */
    else if (curveId != EscEdDsa_CURVE_ED25519)
    {
        returnCode = Esc_INVALID_CURVE;
    }
    /* Check the digest type */
    else if (digestType != EscEdDsa_DIGEST_TYPE_SHA512)
    {
        returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
    }
    /* Check buffer length */
    else if ( (*pubKeyLen < EscPtArithTe25519_curve25519.curveSize.keySizeBytes) ||
              (*privKeyLen < EscPtArithTe25519_curve25519.curveSize.keySizeBytes) )
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }
    else
    {
        /* Get random key */
        returnCode = getRandomFunc(randomState, privKey, EscPtArithTe25519_curve25519.curveSize.keySizeBytes);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set private key size */
        *privKeyLen = EscPtArithTe25519_curve25519.curveSize.keySizeBytes;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Derive public key from private key */
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey(
                        pubKey,
                        pubKeyLen,
                        privKey,
                        *privKeyLen,
                        digestType,
                        curveId);
    }

    return returnCode;
}

Esc_ERROR
EscEdDsa_DerivePubKeyFromPrivKey(
    Esc_UINT8 pubKey[],
    Esc_UINT32* pubKeyLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    Esc_UINT8 digestType,
    const EscEd_CurveId curveId )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 integerA[EscSha512_DIGEST_LEN / 2U];
    EscPtArithTe25519_PointT ptPubKey;

    if ( (pubKey == Esc_NULL_PTR) || (pubKeyLen == Esc_NULL_PTR) || (privKey == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    /* Check the curve ID */
    else if (curveId != EscEdDsa_CURVE_ED25519)
    {
        returnCode = Esc_INVALID_CURVE;
    }
    /* Check the digest type */
    else if (digestType != EscEdDsa_DIGEST_TYPE_SHA512)
    {
        returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
    }
    /* Check buffer length */
    else if (*pubKeyLen < EscPtArithTe25519_curve25519.curveSize.keySizeBytes)
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }
    else if (privKeyLen < EscPtArithTe25519_curve25519.curveSize.keySizeBytes)
    {
        returnCode = Esc_INVALID_PRIVATE_KEY;
    }
    else
    {
        /* Hash the private key */
        /* SHA function checks only for NULL pointers. Since this cannot happen here, it is safe to ignore the return code */
        (void) EscSha512_Calc(
            FALSE,
            privKey,
            EscPtArithTe25519_curve25519.curveSize.keySizeBytes,
            integerA,
            (Esc_UINT8)(EscSha512_DIGEST_LEN / 2U) );

        /* Convert first part of the hash into a valid Ed25519 key with the
            formula for 'a' in Section 2, paragraph 'EdDSA keys and signatures'. */
        /* Clears the 3 LSBs of the least significant octet */
        integerA[0]  &= 0xf8U;
        /* Clears the MSB of the most significant octet */
        integerA[31] &= 0x7fU;
        /* Sets the second highest bit of the most significant octet to 1. */
        integerA[31] |= 0x40U;

        /* a * BasePoint */
        EscPtArithTe25519_ScalarMul(&ptPubKey, integerA, &EscPtArithTe25519_curve25519.base_point_G);
        EscPtArithTe25519_PointToUint8(pubKey, &ptPubKey);

        /* Set public key size */
        *pubKeyLen = EscPtArithTe25519_curve25519.curveSize.keySizeBytes;
    }

    return returnCode;
}


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
    Esc_UINT8 contextLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscSha512_ContextT sha512Ctx;
    EscFeArith_FieldElementLongT tmpLongFe;
    EscFeArith_FieldElementT aFe, rFe, tmpFe;
    EscPtArithTe25519_PointT ptR;
    Esc_UINT8 tmpHash[EscSha512_DIGEST_LEN];
    Esc_UINT8 tmpHashSwap[EscSha512_DIGEST_LEN];
    Esc_UINT8 privKeyHash[EscSha512_DIGEST_LEN];
    Esc_UINT8 phflag[1] = {0x00U};
    Esc_BOOL dom2;

    /* Check for null pointers */
    if ( (signature == Esc_NULL_PTR) || (signatureLen == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) || (pubKey == Esc_NULL_PTR) ||
         ( (message == Esc_NULL_PTR) && (messageLen != 0U) ) || /* Allow NULL pointer iff length is zero */
         ( (context == Esc_NULL_PTR) && (contextLen != 0U) ) )  /* Allow NULL pointer iff length is zero */
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    /* Check the curve ID */
    else if (curveId != EscEdDsa_CURVE_ED25519)
    {
        returnCode = Esc_INVALID_CURVE;
    }
    /* Check the digest type */
    else if (digestType != EscEdDsa_DIGEST_TYPE_SHA512)
    {
        returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
    }
    /* Check buffer length */
    else if ( *signatureLen < (2UL * (Esc_UINT32)EscPtArithTe25519_curve25519.curveSize.keySizeBytes) )
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }
    /* Check for input lengths */
    else if ( (privKeyLen != EscPtArithTe25519_curve25519.curveSize.keySizeBytes) ||
              (pubKeyLen != EscPtArithTe25519_curve25519.curveSize.keySizeBytes) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        if ( (preHashed == FALSE) && (contextLen == 0U) )
        {
            /* ed25519 - dom2() not required */
            dom2 = FALSE;
        }
        else
        {
            /* ed25519ph or ed25519ctx - dom2() required */
            dom2 = TRUE;

            if ( preHashed == FALSE )
            {
                /* ed25519ctx, contextLen != 0 is checked implicitly */
                phflag[0] = 0x00U;
            }
            else
            {
                /* ed25519ph */
                phflag[0] = 0x01U;
            }
        }

        /* Hash the seed k */
        /* SHA function checks only for NULL pointers. Since this cannot happen here, it is safe to ignore the return code */
        (void)EscSha512_Calc(FALSE, privKey, EscPtArithTe25519_curve25519.curveSize.keySizeBytes, privKeyHash, EscSha512_DIGEST_LEN);

        /* Convert first part of the hash into a valid Ed25519 key with the
            formula for 'a' in Section 2, paragraph 'EdDSA keys and signatures'. */
        /* Clears the 3 LSBs of the least significant octet */
        privKeyHash[0]  &= 0xf8U;
        /* Clears the MSB of the most significant octet */
        privKeyHash[31] &= 0x7fU;
        /* Sets the second highest bit of the most significant octet to 1. */
        privKeyHash[31] |= 0x40U;

        /* r = SHA-512(prefix || message) with prefix := second half of privKey hash */
        /* SHA functions check only for NULL pointers. Since this cannot happen here, it is safe to ignore the return code */
        (void)EscSha512_Init(FALSE, &sha512Ctx);

        if ( dom2 != FALSE )
        {
            /* dom2() */
            (void)EscSha512_Update(&sha512Ctx, dom2Prefix, 32U);        /* dom2prefix */
            (void)EscSha512_Update(&sha512Ctx, phflag, 1U);             /* octet(phFlag) */
            (void)EscSha512_Update(&sha512Ctx, &contextLen, 1U);        /* octet(OLEN(context)) */
            (void)EscSha512_Update(&sha512Ctx, context, contextLen);    /* context */
        }

        (void)EscSha512_Update(&sha512Ctx, &privKeyHash[EscEdDsa_INTEGER_BYTES], EscEdDsa_INTEGER_BYTES);
        (void)EscSha512_Update(&sha512Ctx, message, messageLen);
        (void)EscSha512_Finish(&sha512Ctx, tmpHash, EscSha512_DIGEST_LEN);

        /* R = r*B. r = 64 bytes but can be reduced mod l (group order) before used for the point multiplication. */

        /* r as Field Element. */
        EscFeArith_SwapEndiannessUint8( tmpHashSwap, tmpHash, EscSha512_DIGEST_LEN );
        EscFeArith_LongFromUint8( tmpHashSwap, EscSha512_DIGEST_LEN, &tmpLongFe, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_ReduceBarrett( &rFe, &tmpLongFe, &EscPtArithTe25519_curve25519.base_point_order_n, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_ToUint8( &rFe, tmpHashSwap, &EscPtArithTe25519_curve25519.curveSize );

        /* R = r * B */
        EscFeArith_SwapEndiannessUint8( tmpHash, tmpHashSwap, EscEdDsa_INTEGER_BYTES );
        EscPtArithTe25519_ScalarMul(&ptR, tmpHash, &EscPtArithTe25519_curve25519.base_point_G);
        EscPtArithTe25519_PointToUint8(&signature[0], &ptR);

        /* H(R, A, M) */
        (void)EscSha512_Init(FALSE, &sha512Ctx);

        if ( dom2 != FALSE )
        {
            /* dom2() */
            (void)EscSha512_Update(&sha512Ctx, dom2Prefix, 32U);        /* dom2prefix */
            (void)EscSha512_Update(&sha512Ctx, phflag, 1U);             /* octet(phFlag) */
            (void)EscSha512_Update(&sha512Ctx, &contextLen, 1U);        /* octet(OLEN(context)) */
            (void)EscSha512_Update(&sha512Ctx, context, contextLen);    /* context */
        }

        /* R is stored in first 32 byte part of signature */
        (void)EscSha512_Update(&sha512Ctx, &signature[0], EscEdDsa_INTEGER_BYTES);
        (void)EscSha512_Update(&sha512Ctx, pubKey, EscPtArithTe25519_curve25519.curveSize.keySizeBytes);
        (void)EscSha512_Update(&sha512Ctx, message, messageLen);
        (void)EscSha512_Finish(&sha512Ctx, tmpHash, EscSha512_DIGEST_LEN);

        /* H(RAM) as Field Element */
        EscFeArith_SwapEndiannessUint8( tmpHashSwap, tmpHash, EscSha512_DIGEST_LEN );
        EscFeArith_LongFromUint8( tmpHashSwap, EscSha512_DIGEST_LEN, &tmpLongFe, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_ReduceBarrett( &tmpFe, &tmpLongFe, &EscPtArithTe25519_curve25519.base_point_order_n, &EscPtArithTe25519_curve25519.curveSize );

        /* a = first half of the key hash in Field Element */
        EscFeArith_SwapEndiannessUint8( tmpHashSwap, privKeyHash, EscEdDsa_INTEGER_BYTES );
        EscFeArith_FromUint8( tmpHashSwap, EscEdDsa_INTEGER_BYTES, &aFe, &EscPtArithTe25519_curve25519.curveSize );

        /* H(RAM) * a */
        EscFeArith_MultiplyModN( &tmpFe, &tmpFe, &aFe, &EscPtArithTe25519_curve25519.base_point_order_n, &EscPtArithTe25519_curve25519.curveSize );

        /* Add r. S = (r + H(RAM) * a) mod l */
        EscFeArith_ModularAdd( &tmpFe, &rFe, &tmpFe, &EscPtArithTe25519_curve25519.base_point_order_n, EscPtArithTe25519_curve25519.curveSize.maxWords );

        /* Convert resulting S Field Element to UINT8 array */
        EscFeArith_ToUint8( &tmpFe, tmpHashSwap, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_SwapEndiannessUint8( &signature[EscEdDsa_INTEGER_BYTES], tmpHashSwap, EscEdDsa_INTEGER_BYTES );

        /* Set signature length */
        *signatureLen = 2UL * (Esc_UINT32)EscPtArithTe25519_curve25519.curveSize.keySizeBytes;
    }

    return returnCode;
}


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
    Esc_UINT8 contextLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    EscSha512_ContextT sha512Ctx;
    EscFeArith_FieldElementLongT tmpLongFe;
    EscFeArith_FieldElementT tmpFe;
    EscPtArithTe25519_PointT ptA, ptSB_HRAMA;
    Esc_UINT8 tmpHash[EscSha512_DIGEST_LEN];
    Esc_UINT8 tmpHashSwap[EscSha512_DIGEST_LEN];
    Esc_UINT8 phflag[1] = {0x00U};
    Esc_BOOL dom2;

    /* Check for null pointers */
    if ( (signature == Esc_NULL_PTR) || (pubKey == Esc_NULL_PTR) || 
         ( (message == Esc_NULL_PTR) && (messageLen != 0U) ) || /* Allow NULL pointer iff length is zero */
         ( (context == Esc_NULL_PTR) && (contextLen != 0U) ) )  /* Allow NULL pointer iff length is zero */
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    /* Check the curve ID */
    else if (curveId != EscEdDsa_CURVE_ED25519)
    {
        returnCode = Esc_INVALID_CURVE;
    }
    /* Check the digest type */
    else if (digestType != EscEdDsa_DIGEST_TYPE_SHA512)
    {
        returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
    }
    /* Check for input lengths */
    else if ( (signatureLen != (2UL * (Esc_UINT32)EscPtArithTe25519_curve25519.curveSize.keySizeBytes)) ||
              (pubKeyLen != EscPtArithTe25519_curve25519.curveSize.keySizeBytes) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        returnCode = EscPtArithTe25519_PointFromUint8(&ptA, pubKey);
        if ( returnCode != Esc_NO_ERROR)
        {
            /* Faulty encoded public key. */
            returnCode = Esc_INVALID_PUBLIC_KEY;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if ( (preHashed == FALSE) && (contextLen == 0U) )
        {
            /* ed25519 - dom2() not required */
            dom2 = FALSE;
        }
        else
        {
            /* ed25519ph or ed25519ctx - dom2() required */
            dom2 = TRUE;

            if ( preHashed == FALSE )
            {
                /* ed25519ctx, contextLen != 0 is checked implicitly */
                phflag[0] = 0x00U;
            }
            else
            {
                /* ed25519ph */
                phflag[0] = 0x01U;
            }
        }

        /* Using the optimized signature verification formula in combination with the double-scalar multiplication
           as proposed in [2] Section 5, 'Fast single-signature verification'. */
        /* H(R, A, M) */
        (void)EscSha512_Init(FALSE, &sha512Ctx);

        if ( dom2 != FALSE )
        {
            /* dom2() */
            (void)EscSha512_Update(&sha512Ctx, dom2Prefix, 32U);        /* dom2prefix */
            (void)EscSha512_Update(&sha512Ctx, phflag, 1U);             /* octet(phFlag) */
            (void)EscSha512_Update(&sha512Ctx, &contextLen, 1U);        /* octet(OLEN(context)) */
            (void)EscSha512_Update(&sha512Ctx, context, contextLen);    /* context */
        }

        (void)EscSha512_Update(&sha512Ctx, &signature[0], EscEdDsa_INTEGER_BYTES);
        (void)EscSha512_Update(&sha512Ctx, pubKey, EscEdDsa_INTEGER_BYTES);
        (void)EscSha512_Update(&sha512Ctx, message, messageLen);
        (void)EscSha512_Finish(&sha512Ctx, tmpHash, EscSha512_DIGEST_LEN);

        /* H(RAM) as Field Element. */
        EscFeArith_SwapEndiannessUint8( tmpHashSwap, tmpHash, EscSha512_DIGEST_LEN );
        EscFeArith_LongFromUint8( tmpHashSwap, EscSha512_DIGEST_LEN, &tmpLongFe, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_ReduceBarrett( &tmpFe, &tmpLongFe, &EscPtArithTe25519_curve25519.base_point_order_n, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_ToUint8( &tmpFe, tmpHashSwap, &EscPtArithTe25519_curve25519.curveSize );
        EscFeArith_SwapEndiannessUint8( tmpHash, tmpHashSwap, EscEdDsa_INTEGER_BYTES );

        /* Negate point A */
        EscFeArith_SetZero( &tmpFe );
        EscFeArith_ModularSub( &ptA.x, &tmpFe, &ptA.x, &EscPtArithTe25519_curve25519.ecc_field_params, EscPtArithTe25519_curve25519.curveSize.maxWords );
        EscFeArith_ModularSub( &ptA.t, &tmpFe, &ptA.t, &EscPtArithTe25519_curve25519.ecc_field_params, EscPtArithTe25519_curve25519.curveSize.maxWords );

        /* S*B + (HRAM * (-A)) == S * B - HRAM * A */
        EscPtArithTe25519_DoubleScalarMul( &ptSB_HRAMA, &signature[EscEdDsa_INTEGER_BYTES], &EscPtArithTe25519_curve25519.base_point_G, tmpHash, &ptA );

        /* Check if (S * B - H(RAM) * A) == R */
        EscPtArithTe25519_PointToUint8( tmpHash, &ptSB_HRAMA );
        for ( i = 0U; i < EscEdDsa_INTEGER_BYTES; i++ )
        {
            if ( tmpHash[i] != signature[i] )
            {
                returnCode = Esc_INVALID_SIGNATURE;
                break;
            }
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
