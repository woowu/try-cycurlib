/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 RSASSA-PSS signature signature scheme

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "pkcs1_rsassa_pss.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscPkcs1RsaSsaPss_ZEROES                8U
#define EscPkcs1RsaSsaPss_EMLEN_MAX             (EscRsa_KEY_BYTES_MAX)
#define EscPkcs1RsaSsaPss_EMSA_PSS_TRAILER      0xbcU
#define EscPkcs1RsaSsaPss_EMSA_PSS_SEPARATOR    0x01U
#define EscPkcs1RsaSsaPss_BITS_PER_BYTE         8U
#define EscPkcs1RsaSsaPss_M1_LEN_MAX            (EscPkcs1RsaSsaPss_MAX_DIGEST_LEN + EscPkcs1RsaSsaPss_MAX_SALT_LEN + EscPkcs1RsaSsaPss_ZEROES)
#define EscPkcs1RsaSsaPss_MSGLEN_MAX            (EscPkcs1RsaSsaPss_MAX_DIGEST_LEN + 4U)
#define EscPkcs1RsaSsaPss_DB_LEN_MAX            ( (EscPkcs1RsaSsaPss_EMLEN_MAX - EscPkcs1RsaSsaPss_MIN_DIGEST_LEN) - 1U )

/* Error state */
#define EscPkcs1RsaSsaPss_STATE_ERROR           0

/* States for signature verification */
#define EscPkcs1RsaSsaPss_STATE_VERIFY_RSA      10
#define EscPkcs1RsaSsaPss_STATE_VERIFY_DECODE   11

/* State for signature generation */
#define EscPkcs1RsaSsaPss_STATE_SIGN_ENCODE     20
#define EscPkcs1RsaSsaPss_STATE_SIGN_RSA        21

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** Converts an integer into an octet string (big endian). */
static void
EscPkcs1RsaSsaPss_I2OSP(
    Esc_UINT32 integer,
    Esc_UINT8 octet[] );

/** Function EMSA-PSS-ENCODE. Encodes a message according to EMSA-PSS */
static Esc_ERROR
EscPkcs1RsaSsaPss_EmsaPssEncode(
    const EscPkcs1RsaSsaPss_SignContext *ctx);

/** Function EMSA-PSS-Verify. Verifies the encoding of a message according to EMSA-PSS. */
static Esc_ERROR
EscPkcs1RsaSsaPss_EmsaPssVerify(
    const EscPkcs1RsaSsaPss_VerifyContext *ctx);

/** Mask generation function according to PKCS#1 v2.1.*/
static Esc_ERROR
EscPkcs1RsaSsaPss_MGF1(
    const Esc_UINT8 mgfSeed[],
    Esc_UINT8 mask[],
    Esc_UINT32 maskLen,
    Esc_UINT32 digestLen,
    Esc_UINT8 digestType );

/** Get length of digest */
static Esc_ERROR
EscPkcs1RsaSsaPss_GetDigestLength(
    Esc_UINT8 digestType,
    Esc_UINT32 *digestLength);

/**
Wrapper function for the used hash function

\param[in] msg      The message to be hashed
\param[in] msgLen   Length of the message
\param[out] digest  Digest of the message.
\param[in] digestType The type of the digest. One of the EscPkcs1_DIGEST_TYPE_XXX defines from pkcs1.h.
\param[in] digestLength Length of the digest. Can be used to truncate the result.

\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscPkcs1RsaSsaPss_Hash(
    const Esc_UINT8 msg[],
    Esc_UINT32 msgLen,
    Esc_UINT8 digest[],
    Esc_UINT8 digestType,
    Esc_UINT32 digestLength);

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** Converts an integer into an octet string. (big endian) */
static void
EscPkcs1RsaSsaPss_I2OSP(
    Esc_UINT32 integer,
    Esc_UINT8 octet[] )
{
    octet[0] = (Esc_UINT8)( (integer >> 24) & 0xffU );
    octet[1] = (Esc_UINT8)( (integer >> 16) & 0xffU );
    octet[2] = (Esc_UINT8)( (integer >> 8) & 0xffU );
    octet[3] = (Esc_UINT8)( (integer) & 0xffU );
}

/**
 * Mask generation function according to PKCS#1 v2.1.
 **/
static Esc_ERROR
EscPkcs1RsaSsaPss_MGF1(
    const Esc_UINT8 mgfSeed[],  /** seed from which the mask is generated */
    Esc_UINT8 mask[],
    Esc_UINT32 maskLen,
    Esc_UINT32 digestLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 msg[EscPkcs1RsaSsaPss_MSGLEN_MAX];
    Esc_UINT32 i;
    Esc_UINT32 counter = 0U;

    Esc_ASSERT(digestLen != 0U);

    for (i = 0U; i < digestLen; i++)
    {
        msg[i] = mgfSeed[i];
    }

    for (i = 0U; (returnCode == Esc_NO_ERROR) && (i < maskLen); i += digestLen)
    {
        Esc_UINT32 outputLen;
        Esc_UINT32 remaining = maskLen - i;

        /* C = I2OSP( counter, 4 ) */
        /* T = T || Hash( mgfSeed || C ) */
        EscPkcs1RsaSsaPss_I2OSP( counter, &msg[digestLen] );

        if (remaining < digestLen)
        {
            outputLen = remaining;
        }
        else
        {
            outputLen = digestLen;
        }

        returnCode = EscPkcs1RsaSsaPss_Hash( msg, (digestLen + 4U), &mask[i], digestType, outputLen );
        counter++;
    }

    return returnCode;
}

/** Get length of digest */
static Esc_ERROR
EscPkcs1RsaSsaPss_GetDigestLength(
    Esc_UINT8 digestType,
    Esc_UINT32 *digestLength)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* get the digest lengths */
    switch (digestType)
    {
#if EscPkcs1RsaSsaPss_SHA1_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA1:
            /* SHA-1 */
            *digestLength = EscSha1_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA224_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA224:
            /* SHA-224 */
            *digestLength = EscSha224_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA256_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA256:
            /* SHA-256 */
            *digestLength = EscSha256_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA384_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA384:
            /* SHA-384 */
            *digestLength = EscSha384_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA512_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA512:
            /* SHA-512 */
            *digestLength = EscSha512_DIGEST_LEN;
            break;
#endif
        default:
            returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
            break;
    }

    return returnCode;
}

/** Function EMSA-PSS-ENCODE. Encodes a message according to EMSA-PSS. */
static Esc_ERROR
EscPkcs1RsaSsaPss_EmsaPssEncode(
    const EscPkcs1RsaSsaPss_SignContext *ctx)
{
    Esc_UINT8 M1[EscPkcs1RsaSsaPss_M1_LEN_MAX];
    Esc_UINT32 i;
    Esc_ERROR returnCode;
    Esc_UINT32 dbLen;
    Esc_UINT32 emLen;

    emLen = (Esc_UINT32)ctx->keySizeBytes;
    dbLen = ( emLen - ctx->digestLength ) - 1U;

    /* 2./4./5. M' = 00 00 00 00 00 00 00 00 || Hash(M) || salt */
    for (i = 0U; i < EscPkcs1RsaSsaPss_ZEROES; i++)
    {
        M1[i] = 0x00U;
    }

    for (i = 0U; i < ctx->digestLength; i++)
    {
        M1[EscPkcs1RsaSsaPss_ZEROES + i] = ctx->digest[i];
    }

    returnCode = ctx->prngFunc( ctx->prngState, &M1[EscPkcs1RsaSsaPss_ZEROES + ctx->digestLength], ctx->saltLength );

    /* 12. EM = maskedDB || Hash(M') || 0xbc */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaSsaPss_Hash(
                        M1,
                        (ctx->digestLength + ctx->saltLength + EscPkcs1RsaSsaPss_ZEROES),
                        &ctx->signature[dbLen],
                        ctx->digestType,
                        ctx->digestLength);
        ctx->signature[emLen - 1U] = EscPkcs1RsaSsaPss_EMSA_PSS_TRAILER;
    }

    /* 9. dbMask = MGF( H, emLen - hLen - 1 ) */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaSsaPss_MGF1( &ctx->signature[dbLen], ctx->signature, dbLen, ctx->digestLength, ctx->digestType );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 7. PS consists of dbLen - saltLen - 1 zero octets */
        /* 8./10. maskedDB = DB XOR ( PS || 0x01 || salt ) */
        ctx->signature[(dbLen - ctx->saltLength) - 1U] ^= EscPkcs1RsaSsaPss_EMSA_PSS_SEPARATOR;

        for (i = 0U; i < ctx->saltLength; i++)
        {
            ctx->signature[(dbLen - ctx->saltLength) + i] ^= M1[EscPkcs1RsaSsaPss_ZEROES + ctx->digestLength + i];
        }

        /* 11. set the leftmost 8*emLen - ctx->emBits bits of the leftmost octect in maskedDB to zero */
        ctx->signature[0x00] &= (Esc_UINT8)( ( ( (Esc_UINT32)1U << ( EscPkcs1RsaSsaPss_BITS_PER_BYTE - ( (EscPkcs1RsaSsaPss_BITS_PER_BYTE * emLen) - ctx->emBits ) ) ) - 1U ) & 0xffU );
    }

    return returnCode;
}

/** Function EMSA-PSS-Verify. Verifies the encoding of a message according to EMSA-PSS. */
static Esc_ERROR
EscPkcs1RsaSsaPss_EmsaPssVerify(
    const EscPkcs1RsaSsaPss_VerifyContext *ctx)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 M1[EscPkcs1RsaSsaPss_M1_LEN_MAX];
    Esc_UINT8 DB[EscPkcs1RsaSsaPss_DB_LEN_MAX];
    Esc_UINT32 i;
    Esc_UINT32 dbLen;
    Esc_UINT32 emLen;

    emLen = (Esc_UINT32) ctx->keySizeBytes;
    dbLen = (emLen - ctx->digestLength) - 1U;

    /* 0. Set zeroes in M' */
    for (i = 0U; i < EscPkcs1RsaSsaPss_ZEROES; i++)
    {
        M1[i] = 0U;
    }

    /* 1. (the length is already restricted to the length of the digest),
       2. (mHash is stored in M' = EscPkcs1RsaSsaPss_ZEROES || -> mHash <- || salt) */
    for (i = 0U; i < ctx->digestLength; ++i)
    {
        M1[EscPkcs1RsaSsaPss_ZEROES + i] = ctx->digest[i];
    }

    /* 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop. An 'inconsistent' results in an invalid signature. */
    if ( ( ctx->digestLength + ctx->saltLength + 2U ) > emLen )
    {
        returnCode = Esc_INVALID_SIGNATURE;
    }

    /* 4. Test if the rightmost octet of EM has hexadecimal value 0xbc */
    if ( (returnCode == Esc_NO_ERROR) && (ctx->em[emLen - 1U] != EscPkcs1RsaSsaPss_EMSA_PSS_TRAILER) )
    {
        returnCode = Esc_INVALID_SIGNATURE;
    }

    /* 6. Test if the leftmost 8*emLen - ctx->emBits bits
       of the leftmost octet in maskedDB are all equal to zero*/
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT8 mask = (Esc_UINT8)( ( ( (Esc_UINT32)1U << ( EscPkcs1RsaSsaPss_BITS_PER_BYTE - ( (EscPkcs1RsaSsaPss_BITS_PER_BYTE * emLen) - ctx->emBits ) ) ) - 1U ) & 0xffU );
        if ( ( (ctx->em[0x00]) | mask ) != mask )
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 7. Let dbMask = MGF (H, emLen - hLen - 1). */
        returnCode = EscPkcs1RsaSsaPss_MGF1( &ctx->em[dbLen], DB, dbLen, ctx->digestLength, ctx->digestType );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 8. Let DB = maskedDB xor dbMask. */
        for (i = 0U; i < dbLen; i++)
        {
            /*lint -e{644} DB is initialized by the EscPkcs1RsaSsaPss_MGF1 function */
            DB[i] ^= ctx->em[i];
        }

        /* 9.Set the leftmost 8emLen - ctx->emBits bits of the leftmost octet in DB to zero. */
        DB[0] &= (Esc_UINT8)( ( ( (Esc_UINT32)1U << ( 8U - ( (8U * emLen) - ctx->emBits ) ) ) - 1U ) & 0xffU );

        /* 10.a Test if the emLen - hLen - sLen - 2 leftmost octets of DB are zero */
        for (i = 0U; i < ( ( (emLen - ctx->digestLength) - ctx->saltLength ) - 2U ); i++)
        {
            if (DB[i] != 0U)
            {
                returnCode = Esc_INVALID_SIGNATURE;
            }
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 10.b Test if the octet at position emLen - hLen - sLen - 1
       (the leftmost position is "position 1") has hexadecimal value 0x01 */
        if (DB[i] != EscPkcs1RsaSsaPss_EMSA_PSS_SEPARATOR)
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 12. Build M'= (0x)00 00 00 00 00 00 00 00 || mHash (Step 1) || salt*/
        /* M1 was already initialized with zeros */
        /* salt */
        for (i = 0U; i < ctx->saltLength; i++)
        {
            M1[EscPkcs1RsaSsaPss_ZEROES + ctx->digestLength + i] = DB[(dbLen - ctx->saltLength) + i];
        }

        /* 13. Let H' = Hash (M'), an octet string of length hLen. */
        returnCode = EscPkcs1RsaSsaPss_Hash(
                        M1,
                        ( EscPkcs1RsaSsaPss_ZEROES + ctx->digestLength + ctx->saltLength ),
                        M1,
                        ctx->digestType,
                        ctx->digestLength);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 14. Test if H = H' */
        for (i = 0U; (i < ctx->digestLength); i++)
        {
            if (M1[i] != ctx->em[dbLen + i])
            {
                returnCode = Esc_INVALID_SIGNATURE;
            }
        }
    }

    return returnCode;
}

/** Wrapper function for the used hash function */
static Esc_ERROR
EscPkcs1RsaSsaPss_Hash(
    const Esc_UINT8 msg[],
    Esc_UINT32 msgLen,
    Esc_UINT8 digest[],
    Esc_UINT8 digestType,
    Esc_UINT32 digestLength)
{
    Esc_ERROR returnCode;

    Esc_ASSERT(digestLength != 0U);
    Esc_ASSERT(digestLength <= 255);

    switch (digestType)
    {
#if EscPkcs1RsaSsaPss_SHA1_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA1:
            /* SHA-1 */
            returnCode = EscSha1_Calc( msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA224_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA224:
            /* SHA-224 */
            returnCode = EscSha256_Calc( TRUE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA256_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA256:
            /* SHA-256 */
            returnCode = EscSha256_Calc( FALSE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA384_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA384:
            /* SHA-384 */
            returnCode = EscSha512_Calc( TRUE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaSsaPss_SHA512_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA512:
            /* SHA-512 */
            returnCode = EscSha512_Calc( FALSE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
        default:
            returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
            break;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_Sign(
    EscRandom_GetRandom prngFunc,
    void *prngState,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaSsaPss_SignContext ctx;

    /* Initialize signature generation */
    returnCode = EscPkcs1RsaSsaPss_SignInit(
                     &ctx,
                     prngFunc,
                     prngState,
                     digest,
                     privKey,
                     signature,
                     signatureLen,
                     saltLen,
                     digestType);

    /* Execute generation until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaSsaPss_SignRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_Verify(
    const Esc_UINT8 digest[],
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaSsaPss_VerifyContext ctx;

    /* Initialize verification */
    returnCode = EscPkcs1RsaSsaPss_VerifyInit(
                     &ctx,
                     digest,
                     pubKey,
                     signature,
                     signatureLen,
                     saltLen,
                     digestType);

    /* Execute verification until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaSsaPss_VerifyRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_VerifyInit(
    EscPkcs1RsaSsaPss_VerifyContext *ctx,
    const Esc_UINT8 digest[],
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscRsa_HWORD bitPos = 0U;
    Esc_UINT8 bitIndex = 0U;
    Esc_UINT16 keySizeWords;

    /* Parameter checks */

    if ( (ctx == Esc_NULL_PTR) ||
         (digest == Esc_NULL_PTR) ||
         (pubKey == Esc_NULL_PTR) ||
         (signature == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaSsaPss_STATE_ERROR;

        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaSsaPss_GetDigestLength(digestType, &ctx->digestLength);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if ( (signatureLen != EscRsa_KEY_BYTES_FROMBITS((Esc_UINT32)pubKey->keySizeBits)) ||
                  (saltLen > EscPkcs1RsaSsaPss_MAX_SALT_LEN) )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }

        keySizeWords = EscRsa_RSA_SIZE_WORDS_FROMBITS(pubKey->keySizeBits);
        /* Set bit check mask to the MSB */
        bitPos = (EscRsa_HWORD)((EscRsa_HWORD)1U << (EscRsa_RSA_BASE-1U) );
        /* Get the actual length of the modulus. We do not allow moduli < (keySize - 6)! */
        while ( bitIndex < 6U )
        {
            if ( ( pubKey->modulus.words[keySizeWords-1U] & bitPos ) == bitPos)
            {
                /* highest bit is found, break the loop */
                break;
            }
            else
            {
                bitPos >>= 1U;
                bitIndex++;
            }
        }

        if ( bitIndex == 6U )
        {
            /* modulus is to small for the key size */
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT16 keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        Esc_UINT32 emBits = ((Esc_UINT32)pubKey->keySizeBits - bitIndex) - 1U;

        /* Store parameters in context */
        ctx->digest = digest;
        ctx->digestType = digestType;
        ctx->keySizeBytes = keySizeBytes;
        ctx->emBits = emBits;
        ctx->saltLength = saltLen;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize RSA modular exponentiation */
        returnCode = EscRsa_ModExpPubInit(&ctx->rsaCtx, pubKey, signature, ctx->em);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaSsaPss_STATE_VERIFY_RSA;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_VerifyRun(
    EscPkcs1RsaSsaPss_VerifyContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaSsaPss_STATE_VERIFY_RSA:
                /* Run RSA modular exponentiation until it is finished */
                returnCode = EscRsa_ModExpPubRun(&ctx->rsaCtx);

                if (returnCode == Esc_NO_ERROR)
                {
                    ctx->state = EscPkcs1RsaSsaPss_STATE_VERIFY_DECODE;
                    returnCode = Esc_AGAIN;
                }
                break;

            case EscPkcs1RsaSsaPss_STATE_VERIFY_DECODE:
                /* Verify padding */
                returnCode = EscPkcs1RsaSsaPss_EmsaPssVerify(ctx);
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaSsaPss_STATE_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_SignInit(
    EscPkcs1RsaSsaPss_SignContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT32 saltLen,
    Esc_UINT8 digestType)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keySizeBytes = 0U;
    EscRsa_HWORD bitPos = 0U;
    Esc_UINT8 bitIndex = 0U;
    Esc_UINT16 keySizeWords = 0U;

    /* Parameter checks */

    if ( (ctx == Esc_NULL_PTR) ||
         (prngFunc == Esc_NULL_PTR) ||
         (digest == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) ||
         (signature == Esc_NULL_PTR) ||
         (signatureLen == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaSsaPss_STATE_ERROR;

        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaSsaPss_GetDigestLength(digestType, &ctx->digestLength);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        keySizeWords = EscRsa_RSA_SIZE_WORDS_FROMBITS(privKey->pubKey.keySizeBits);
        keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(privKey->pubKey.keySizeBits);

        if ( (saltLen > EscPkcs1RsaSsaPss_MAX_SALT_LEN) ||
             ( (ctx->digestLength + saltLen + 2U) > keySizeBytes ) )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
        else if (*signatureLen < keySizeBytes)
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }
        else
        {
            /* Intentionally empty */
        }

        /* Set bit check mask to the MSB */
        bitPos = (EscRsa_HWORD)((EscRsa_HWORD)1U << (EscRsa_RSA_BASE-1U));
        /* Get the actual length of the modulus. We do not allow moduli < (keySize - 6)! */
        while ( bitIndex < 6U )
        {
            if ( ( privKey->pubKey.modulus.words[keySizeWords-1U] & bitPos ) == bitPos)
            {
                /* highest bit is found, break the loop */
                break;
            }
            else
            {
                bitPos >>= 1U;
                bitIndex ++;
            }
        }

        if (bitIndex == 6U)
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 emBits = ((Esc_UINT32)privKey->pubKey.keySizeBits - bitIndex) - 1U;

        /* Store parameters in context */
        ctx->privKey = privKey;
        ctx->prngFunc = prngFunc;
        ctx->prngState = prngState;
        ctx->emBits = emBits;
        ctx->keySizeBytes = keySizeBytes;
        ctx->signature = signature;
        ctx->signatureLen = signatureLen;
        ctx->digest = digest;
        ctx->digestType = digestType;
        ctx->saltLength = saltLen;

        ctx->state = EscPkcs1RsaSsaPss_STATE_SIGN_ENCODE;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaPss_SignRun(
    EscPkcs1RsaSsaPss_SignContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaSsaPss_STATE_SIGN_ENCODE:
                /* Encode message */
                returnCode = EscPkcs1RsaSsaPss_EmsaPssEncode(ctx);

                /* Initialize modular exponentiation */
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscRsa_ModExpPrivInit(&ctx->rsaCtx, ctx->privKey, ctx->signature, ctx->signature);
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaSsaPss_STATE_SIGN_RSA;
                }
                break;

            case EscPkcs1RsaSsaPss_STATE_SIGN_RSA:
                /* Run RSA modular exponentiation until it is finished */
                returnCode = EscRsa_ModExpPrivRun(&ctx->rsaCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    *(ctx->signatureLen) = ctx->keySizeBytes;
                }
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaSsaPss_STATE_ERROR;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
