/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 RSASSA-PKCS1-v1_5 signature scheme

   Implementation of RSASSA-PKCS1-v1_5 verification and generation.
   Byte format of all long numbers is Big-Endian.

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf


   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "pkcs1_rsassa_v15.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Offset of PS within EM */
#define EscPkcs1RsaSsaV15_PS_OFFSET     2U

/* Error state */
#define EscPkcs1RsaSsaV15_STATE_ERROR               0

/* States for signature verification */
#define EscPkcs1RsaSsaV15_STATE_VERIFY_RSA          10
#define EscPkcs1RsaSsaV15_STATE_VERIFY_DECODE       11

/* State for signature generation */
#define EscPkcs1RsaSsaV15_STATE_SIGN_ENCODE         20
#define EscPkcs1RsaSsaV15_STATE_SIGN_RSA            21

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

static Esc_ERROR
EscPkcs1RsaSsaV15_GetDigestDescr(
    Esc_UINT8 digestType,
    const EscPkcs1RsaSsaV15_DigestDescriptionT** descr );

static Esc_BOOL
EscPkcs1RsaSsaV15_MemIsDifferent(
    const Esc_UINT8 m1[],
    const Esc_UINT8 m2[],
    Esc_UINT8 memLen );

static Esc_ERROR
EscPkcs1RsaSsaV15_EmsaV15Verify(
    const Esc_UINT8* hashDigest,
    const Esc_UINT8 em[],
    const EscPkcs1RsaSsaV15_DigestDescriptionT* digestDescr,
    const Esc_UINT16 keySizeBytes );

/** Encodes a message according to EMSA-PKCS1-V1_5 */
static void
EscPkcs1RsaSsaV15_EmsaV15Encode(
    const Esc_UINT8 hashDigest[],
    const EscPkcs1RsaSsaV15_DigestDescriptionT* digestDescr,
    Esc_UINT8 em[],
    const Esc_UINT16 keySizeBytes );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/* Returns the digest description for a certain digest type. */
static Esc_ERROR
EscPkcs1RsaSsaV15_GetDigestDescr(
    Esc_UINT8 digestType,
    const EscPkcs1RsaSsaV15_DigestDescriptionT** descr )
{
/*
   Digest Infos from section 9.2, the note in PKCS#1 v2.2 and from IEEE-P1363a, 12.1.3.
   MD2: (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H.
   MD5: (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H.
   SHA-1: (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
   SHA-224: (0x)30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c || H
   SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
   SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
   SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
   RIPEMD-160: (0x)30 21 30 09 06 05 2b 24 03 02 01 05 00 04 14 || H.
 */

#if EscPkcs1RsaSsaV15_MD2_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_MD2[] =
    {
        0x30U, 0x20U, 0x30U, 0x0cU, 0x06U, 0x08U, 0x2aU, 0x86U,
        0x48U, 0x86U, 0xf7U, 0x0dU, 0x02U, 0x02U, 0x05U, 0x00U,
        0x04U, 0x10U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_MD2 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x10U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_MD2),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_MD2,
    };
#endif

#if EscPkcs1RsaSsaV15_MD5_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_MD5[] =
    {
        0x30U, 0x20U, 0x30U, 0x0cU, 0x06U, 0x08U, 0x2aU, 0x86U,
        0x48U, 0x86U, 0xf7U, 0x0dU, 0x02U, 0x05U, 0x05U, 0x00U,
        0x04U, 0x10U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_MD5 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x10U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_MD5),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_MD5,
    };
#endif

#if EscPkcs1RsaSsaV15_SHA1_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_SHA1[] =
    {
        0x30U, 0x21U, 0x30U, 0x09U, 0x06U, 0x05U, 0x2bU, 0x0eU,
        0x03U, 0x02U, 0x1aU, 0x05U, 0x00U, 0x04U, 0x14U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA1 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x14U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_SHA1),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_SHA1,
    };
#endif

#if EscPkcs1RsaSsaV15_SHA224_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_SHA224[] =
    {
        0x30U, 0x2dU, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U,
        0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x04U, 0x05U,
        0x00U, 0x04U, 0x1cU
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA224 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x1cU,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_SHA224),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_SHA224,
    };
#endif

#if EscPkcs1RsaSsaV15_SHA256_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_SHA256[] =
    {
        0x30U, 0x31U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U,
        0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x01U, 0x05U,
        0x00U, 0x04U, 0x20U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA256 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x20U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_SHA256),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_SHA256,
    };
#endif

#if EscPkcs1RsaSsaV15_SHA384_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_SHA384[] =
    {
        0x30U, 0x41U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U,
        0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x02U, 0x05U,
        0x00U, 0x04U, 0x30U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA384 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x30U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_SHA384),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_SHA384,
    };
#endif

#if EscPkcs1RsaSsaV15_SHA512_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_SHA512[] =
    {
        0x30U, 0x51U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U,
        0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x03U, 0x05U,
        0x00U, 0x04U, 0x40U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA512 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x40U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_SHA512),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_SHA512,
    };
#endif

#if EscPkcs1RsaSsaV15_RIPEMD160_ENABLED == 1
    /* The digest info. */
    static const Esc_UINT8 EscPkcs1RsaSsaV15_DIGEST_INFO_R160[] =
    {
        0x30U, 0x21U, 0x30U, 0x09U, 0x06U, 0x05U, 0x2bU, 0x24U,
        0x03U, 0x02U, 0x01U, 0x05U, 0x00U, 0x04U, 0x14U
    };

    /* The digest description. */
    static const EscPkcs1RsaSsaV15_DigestDescriptionT EscPkcs1RsaSsaV15_DIGEST_DESCR_R160 =
    {
        /* Esc_UINT8 digestLen */
        (Esc_UINT8)0x14U,

        /* Esc_UINT8 digestInfoLen */
        (Esc_UINT8)sizeof(EscPkcs1RsaSsaV15_DIGEST_INFO_R160),

        /* const Esc_UINT8 *digestInfo */
        EscPkcs1RsaSsaV15_DIGEST_INFO_R160,
    };
#endif

    Esc_ERROR returnCode = Esc_NO_ERROR;

    switch (digestType)
    {
#if EscPkcs1RsaSsaV15_MD2_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_MD2:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_MD2;
            break;
#endif

#if EscPkcs1RsaSsaV15_MD5_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_MD5:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_MD5;
            break;
#endif

#if EscPkcs1RsaSsaV15_SHA1_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA1:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA1;
            break;
#endif

#if EscPkcs1RsaSsaV15_SHA224_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA224:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA224;
            break;
#endif

#if EscPkcs1RsaSsaV15_SHA256_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA256:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA256;
            break;
#endif

#if EscPkcs1RsaSsaV15_SHA384_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA384:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA384;
            break;
#endif

#if EscPkcs1RsaSsaV15_SHA512_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_SHA512:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_SHA512;
            break;
#endif

#if EscPkcs1RsaSsaV15_RIPEMD160_ENABLED == 1
        case EscPkcs1RsaSsaV15_DIGEST_TYPE_R160:
            *descr = &EscPkcs1RsaSsaV15_DIGEST_DESCR_R160;
            break;
#endif

        default:
            returnCode = Esc_UNSUPPORTED_DIGEST_TYPE;
            break;
    }

    return returnCode;
}

/* Returns FALSE if m1 and m2 are equal. */
static Esc_BOOL
EscPkcs1RsaSsaV15_MemIsDifferent(
    const Esc_UINT8 m1[],
    const Esc_UINT8 m2[],
    Esc_UINT8 memLen )
{
    Esc_UINT8 i;
    Esc_BOOL isDifferent = FALSE;

    for (i = 0U; i < memLen; i++)
    {
        if (m1[i] != m2[i])
        {
            isDifferent = TRUE;
            break;
        }
    }

    return isDifferent;
}

/*
   Verify the EMSA encoding and compare the digest.
 */
static Esc_ERROR
EscPkcs1RsaSsaV15_EmsaV15Verify(
    const Esc_UINT8* hashDigest,
    const Esc_UINT8 em[],
    const EscPkcs1RsaSsaV15_DigestDescriptionT* digestDescr,
    const Esc_UINT16 keySizeBytes )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 digestValueStart;
    Esc_UINT16 digestInfoStart;
    Esc_UINT16 psLen;

    /* Calculate psLen. It has the length emLen - sizeof(T) - 3, with emLen = keySizeBytes */
    psLen = ( (keySizeBytes - 3U) - digestDescr->digestInfoLen ) - digestDescr->digestLen;
    /* PSLEN will be at least 8 octets according to PKCS#1 V2.1, 9.2 Step 4.
       This value can only be this low,
       if keySizeBytes has an absurd low value, e.g. RSA-512 */
    Esc_ASSERT( psLen >= 8U );

    /* Check the leading 00 || 01 and the trailing 00 */
    if ( (em[0] != 0x00U) || (em[1] != 0x01U) || (em[psLen + EscPkcs1RsaSsaV15_PS_OFFSET] != 0x00U) )
    {
        returnCode = Esc_INVALID_SIGNATURE;
    }
    else
    {
        Esc_UINT16 i;
        /* Check the padding PS. */
        for (i = EscPkcs1RsaSsaV15_PS_OFFSET; i < (psLen + EscPkcs1RsaSsaV15_PS_OFFSET); i++)
        {
            if (em[i] != 0xffU)
            {
                returnCode = Esc_INVALID_SIGNATURE;
                break;
            }
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        digestValueStart = (Esc_UINT16)keySizeBytes - (Esc_UINT16)digestDescr->digestLen;
        digestInfoStart = digestValueStart - (Esc_UINT16)digestDescr->digestInfoLen;

        /* Compare digest info and digest. */
        if (EscPkcs1RsaSsaV15_MemIsDifferent( digestDescr->digestInfo, &em[digestInfoStart], digestDescr->digestInfoLen ) != FALSE)
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }

        if (EscPkcs1RsaSsaV15_MemIsDifferent( hashDigest, &em[digestValueStart], digestDescr->digestLen ) != FALSE)
        {
            returnCode = Esc_INVALID_SIGNATURE;
        }
    }

    return returnCode;
}

/** Encodes a message according to EMSA-PKCS1-V1_5 */
static void
EscPkcs1RsaSsaV15_EmsaV15Encode(
    const Esc_UINT8 hashDigest[],  /** Message to encode */
    const EscPkcs1RsaSsaV15_DigestDescriptionT* digestDescr,
    Esc_UINT8 em[],
    const Esc_UINT16 keySizeBytes )
{
    Esc_UINT16 psLen;
    Esc_UINT16 digestValueStart;
    Esc_UINT16 digestInfoStart;
    Esc_UINT16 i;

    /* First two bytes */
    em[0U] = 0x00U;
    em[1U] = 0x01U;

    /* PS */

    /* Calculate psLen. It has the length emLen - sizeof(T) - 3, with emLen = EscRsa_KEY_BYTES */
    psLen = ( (keySizeBytes - 3U) - digestDescr->digestInfoLen ) - digestDescr->digestLen;
    /* PSLEN will be at least 8 octets according to PKCS#1 V2.1, 9.2 Step 4.
    This value can only be this low,
    if keySizeBytes has an absurd low value, e.g. RSA-512 */
    Esc_ASSERT( psLen >= 8U );

    for (i = EscPkcs1RsaSsaV15_PS_OFFSET; i < (psLen + EscPkcs1RsaSsaV15_PS_OFFSET); i++)
    {
        em[i] = 0xffU;
    }

    /* 0x00U */
    em[psLen + EscPkcs1RsaSsaV15_PS_OFFSET] = 0x00U;

    /* T */
    digestValueStart = (Esc_UINT16)keySizeBytes - (Esc_UINT16)digestDescr->digestLen;
    digestInfoStart = digestValueStart - (Esc_UINT16)digestDescr->digestInfoLen;

    for (i = 0U; i < (Esc_UINT16)digestDescr->digestInfoLen; i++)
    {
        em[digestInfoStart + i] = digestDescr->digestInfo[i];
    }

    for (i = 0U; i < (Esc_UINT16)digestDescr->digestLen; i++)
    {
        em[digestValueStart + i] = hashDigest[i];
    }
}

/*
   Signs a message according to
   RSASSA-PKCS1-v1_5_Sign.
 */
Esc_ERROR
EscPkcs1RsaSsaV15_Sign(
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaSsaV15_SignContext ctx;

    /* Initialize signature generation */
    returnCode = EscPkcs1RsaSsaV15_SignInit(
                     &ctx,
                     digest,
                     privKey,
                     signature,
                     signatureLen,
                     digestType);

    /* Execute generation until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaSsaV15_SignRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaV15_SignInit(
    EscPkcs1RsaSsaV15_SignContext *ctx,
    const Esc_UINT8 digest[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 signature[],
    Esc_UINT32 *signatureLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) ||
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
        ctx->state = EscPkcs1RsaSsaV15_STATE_ERROR;

        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Check expected signature length */
        Esc_UINT16 keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(privKey->pubKey.keySizeBits);
        ctx->keySizeBytes = keySizeBytes;

        if (*signatureLen < keySizeBytes)
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters in context */
        ctx->signature = signature;
        ctx->signatureLen = signatureLen;
        ctx->digest = digest;
        ctx->privKey = privKey;

        returnCode = EscPkcs1RsaSsaV15_GetDigestDescr(digestType, &ctx->digestDesc);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaSsaV15_STATE_SIGN_ENCODE;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaV15_SignRun(
    EscPkcs1RsaSsaV15_SignContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaSsaV15_STATE_SIGN_ENCODE:
                /* Encode message */
                EscPkcs1RsaSsaV15_EmsaV15Encode(ctx->digest, ctx->digestDesc, ctx->signature, ctx->keySizeBytes);

                returnCode = EscRsa_ModExpPrivInit(&ctx->rsaCtx, ctx->privKey, ctx->signature, ctx->signature);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaSsaV15_STATE_SIGN_RSA;
                }
                break;

            case EscPkcs1RsaSsaV15_STATE_SIGN_RSA:
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
            ctx->state = EscPkcs1RsaSsaV15_STATE_ERROR;
        }
    }

    return returnCode;
}


/*
   Verifies the signature of a message according to
   RSASSA-PKCS1-v1_5_Verify.
 */
Esc_ERROR
EscPkcs1RsaSsaV15_Verify(
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 digest[],
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaSsaV15_VerifyContext ctx;

    /* Initialize verification */
    returnCode = EscPkcs1RsaSsaV15_VerifyInit(
                     &ctx,
                     signature,
                     signatureLen,
                     pubKey,
                     digest,
                     digestType);

    /* Execute verification until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaSsaV15_VerifyRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaV15_VerifyInit(
    EscPkcs1RsaSsaV15_VerifyContext *ctx,
    const Esc_UINT8 signature[],
    Esc_UINT32 signatureLen,
    const EscRsa_PubKeyT* pubKey,
    const Esc_UINT8 digest[],
    Esc_UINT8 digestType)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) ||
         (signature == Esc_NULL_PTR) ||
         (pubKey == Esc_NULL_PTR) ||
         (digest == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaSsaV15_STATE_ERROR;

        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Check expected signature length */
        Esc_UINT16 keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        ctx->keySizeBytes = keySizeBytes;

        if (signatureLen != keySizeBytes)
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters in context */
        ctx->digest = digest;

        returnCode = EscPkcs1RsaSsaV15_GetDigestDescr(digestType, &ctx->digestDesc);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize RSA modular exponentiation */
        returnCode = EscRsa_ModExpPubInit(&ctx->rsaCtx, pubKey, signature, ctx->em);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaSsaV15_STATE_VERIFY_RSA;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaSsaV15_VerifyRun(
    EscPkcs1RsaSsaV15_VerifyContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaSsaV15_STATE_VERIFY_RSA:
                /* Run RSA modular exponentiation until it is finished */
                returnCode = EscRsa_ModExpPubRun(&ctx->rsaCtx);

                if (returnCode == Esc_NO_ERROR)
                {
                    ctx->state = EscPkcs1RsaSsaV15_STATE_VERIFY_DECODE;
                    returnCode = Esc_AGAIN;
                }
                break;

            case EscPkcs1RsaSsaV15_STATE_VERIFY_DECODE:
                /* Verify padding */
                returnCode = EscPkcs1RsaSsaV15_EmsaV15Verify( ctx->digest, ctx->em, ctx->digestDesc, ctx->keySizeBytes );
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaSsaV15_STATE_ERROR;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
