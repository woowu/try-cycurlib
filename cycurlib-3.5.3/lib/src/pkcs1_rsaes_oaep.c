/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 RSAES-OAEP encryption and decryption

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "pkcs1_rsaes_oaep.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscPkcs1RsaEsOaep_MASK_DB_LEN_MAX ( (EscRsa_KEY_BYTES_MAX - EscPkcs1RsaEsOaep_MIN_DIGEST_LEN) - 1U )
#define EscPkcs1RsaEsOaep_MASK_INPUT_LEN_MAX (EscPkcs1RsaEsOaep_MASK_DB_LEN_MAX + 4U)

#define EscPkcs1RsaEsOaep_MSG_LEN_MAX (EscPkcs1RsaEsOaep_MAX_DIGEST_LEN + 4U)

/* Error state */
#define EscPkcs1RsaEsOaep_STATE_ERROR                      0

/* States for encryption */
#define EscPkcs1RsaEsOaep_STATE_ENCRYPT_ENCODE             10
#define EscPkcs1RsaEsOaep_STATE_ENCRYPT_RSA                11

/* State for decryption */
#define EscPkcs1RsaEsOaep_STATE_DECRYPT_RSA                20
#define EscPkcs1RsaEsOaep_STATE_DECRYPT_DECODE             21

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** Converts an integer into an octet string. (big endian) */
static void
EscPkcs1RsaEsOaep_I2OSP(
    Esc_UINT32 integer,
    Esc_UINT8 octet[] );

/** Wrapper function for the used hash function */
static Esc_ERROR
EscPkcs1RsaEsOaep_Hash(
    const Esc_UINT8 msg[],
    Esc_UINT32 msgLen,
    Esc_UINT8 digest[],
    Esc_UINT8 digestType,
    Esc_UINT32 digestLength);

/** Function EME-OAEP-ENCODE. Encodes a message according to EME-OAEP. */
static Esc_ERROR
EscPkcs1RsaEsOaep_EmeOaepEncode(
    const EscPkcs1RsaEsOaep_EncryptContext *ctx);

/** Function EME-OAEP-DECODE. Decodes an EME-OAEP encoded message. */
static Esc_BOOL
EscPkcs1RsaEsOaep_EmeOaepDecode(
    const EscPkcs1RsaEsOaep_DecryptContext *ctx);

/** Mask generation function according to PKCS#1 v2.1.*/
static Esc_ERROR
EscPkcs1RsaEsOaep_MGF1(
    const Esc_UINT8 mgfSeed[],
    Esc_UINT8 mask[],
    Esc_UINT32 maskLen,
    Esc_UINT32 digestLen,
    Esc_UINT8 digestType );

/** Lookup digest length by digest type */
static Esc_ERROR
EscPkcs1RsaEsOaep_GetDigestLength(
    Esc_UINT8 digestType,
    Esc_UINT32 *digestLength);

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** Converts an integer into an octet string. (big endian) */
static void
EscPkcs1RsaEsOaep_I2OSP(
    Esc_UINT32 integer,
    Esc_UINT8 octet[] )
{
    octet[0] = (Esc_UINT8)( (integer >> 24) & 0xffU );
    octet[1] = (Esc_UINT8)( (integer >> 16) & 0xffU );
    octet[2] = (Esc_UINT8)( (integer >> 8) & 0xffU );
    octet[3] = (Esc_UINT8)( (integer) & 0xffU );
}

/** Wrapper function for the used hash function. */
static Esc_ERROR
EscPkcs1RsaEsOaep_Hash(
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
#if EscPkcs1RsaEsOaep_SHA1_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA1:
            /* SHA-1 */
            returnCode = EscSha1_Calc( msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA224_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA224:
            /* SHA-224 */
            returnCode = EscSha256_Calc( TRUE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA256_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA256:
            /* SHA-256 */
            returnCode = EscSha256_Calc( FALSE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA384_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA384:
            /* SHA-384 */
            returnCode = EscSha512_Calc( TRUE, msg, msgLen, digest, (Esc_UINT8) digestLength );
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA512_ENABLED == 1
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

/**
 * Mask generation function according to PKCS#1 v2.1.
 * The size of input is fixed to EscPkcs1RsaEsOaep_DIGEST_LEN.
 **/
static Esc_ERROR
EscPkcs1RsaEsOaep_MGF1(
    const Esc_UINT8 mgfSeed[],
    /** seed from which the mask is generated */
    Esc_UINT8 mask[],
    Esc_UINT32 maskLen,
    Esc_UINT32 digestLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 msg[EscPkcs1RsaEsOaep_MSG_LEN_MAX];
    Esc_UINT32 i;
    Esc_UINT32 counter = 0U;

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
        EscPkcs1RsaEsOaep_I2OSP( counter, &msg[digestLen] );

        if (remaining < digestLen)
        {
            outputLen = remaining;
        }
        else
        {
            outputLen = digestLen;
        }

        returnCode = EscPkcs1RsaEsOaep_Hash( msg, (Esc_UINT32)digestLen + 4U, &mask[i], digestType, outputLen );
        counter++;
    }

    return returnCode;
}

static Esc_ERROR
EscPkcs1RsaEsOaep_GetDigestLength(
    Esc_UINT8 digestType,
    Esc_UINT32 *digestLength)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    switch (digestType)
    {
#if EscPkcs1RsaEsOaep_SHA1_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA1:
            /* SHA-1 */
            *digestLength = EscSha1_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA224_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA224:
            /* SHA-224 */
            *digestLength = EscSha224_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA256_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA256:
            /* SHA-256 */
            *digestLength = EscSha256_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA384_ENABLED == 1
        case EscPkcs1_DIGEST_TYPE_SHA384:
            /* SHA-384 */
            *digestLength = EscSha384_DIGEST_LEN;
            break;
#endif
#if EscPkcs1RsaEsOaep_SHA512_ENABLED == 1
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

/** Function EME-OAEP-ENCODE. Encodes a message according to EME-OAEP.
    All quoted references refer to the section 7.1.1 from the PKCS#1 v2.1 standard. */
static Esc_ERROR
EscPkcs1RsaEsOaep_EmeOaepEncode(
    const EscPkcs1RsaEsOaep_EncryptContext *ctx)
{
    Esc_UINT8 seed[EscPkcs1RsaEsOaep_MAX_DIGEST_LEN];
    Esc_UINT8 digest[EscPkcs1RsaEsOaep_MAX_DIGEST_LEN];
    Esc_UINT32 i;
    Esc_ERROR returnCode;
    Esc_UINT32 maskedDbLen = 0U;
    Esc_UINT8 maskedDB[EscPkcs1RsaEsOaep_MASK_INPUT_LEN_MAX];

    /* 2.d) */
    returnCode = ctx->prngFunc( ctx->prngState, seed, ctx->digestLength );

    /* 2.e) dbMask = MGF1( seed, k - hLen - 1 ) */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaEsOaep_MGF1( seed, maskedDB, (ctx->keySizeBytes - ctx->digestLength) - 1U, ctx->digestLength, ctx->digestType);
    }

    /* 2.a) lHash = Hash( L ) */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaEsOaep_Hash( ctx->label, ctx->labelLen, digest, ctx->digestType, ctx->digestLength );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 2.b) PS consists of k - mLen - 2hLen - 2 zero octets */
        /* 2.c) / 2.f) maskedDB = ( lHash || PS || 0x01 || M ) XOR dbMask */
        for (i = 0U; i < ctx->digestLength; i++)
        {
            /*lint -e{644} maskedDB and digest are initialized by the EscPkcs1RsaEsOaep_MGF1 and EscPkcs1RsaEsOaep_Hash function */
            maskedDB[i] ^= digest[i];
        }

        maskedDB[( (ctx->keySizeBytes - ctx->messageLen) - ctx->digestLength ) - 2U] ^= 0x01U;

        for (i = 0U; i < ctx->messageLen; i++)
        {
            maskedDB[( ( (ctx->keySizeBytes - ctx->digestLength) - 1U ) - ctx->messageLen ) + i] ^= ctx->message[i];
        }

        /* 2.g) seedMask = MGF( maskedDB, hLen ) --> Hash( maskedDB || 00 00 00 00 ) */
        for (i = 0U; i < 4U; i++)
        {
            maskedDB[( (ctx->keySizeBytes - ctx->digestLength) - 1U ) + i] = 0x00U;
        }

        maskedDbLen = (ctx->keySizeBytes - ctx->digestLength) - 1U;
        returnCode = EscPkcs1RsaEsOaep_Hash( maskedDB, (Esc_UINT32)maskedDbLen + 4U, digest, ctx->digestType, ctx->digestLength );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* 2.g) / 2.i) EM = 0x00 || ( seed XOR seedMask ) || maskedDB */
        ctx->cipher[0x00] = 0x00U;

        for (i = 0U; i < ctx->digestLength; i++)
        {
            ctx->cipher[1U + i] = seed[i] ^ digest[i];
        }

        for (i = 0U; i < maskedDbLen; i++)
        {
            ctx->cipher[1U + ctx->digestLength + i] = maskedDB[i];
        }
    }

    return returnCode;
}

/** Function EME-OAEP-DECODE. Decodes an EME-OAEP encoded message.
    All quoted references refer to the section 7.1.2 from the PKCS#1 v2.1 standard. */
static Esc_BOOL
EscPkcs1RsaEsOaep_EmeOaepDecode(
    const EscPkcs1RsaEsOaep_DecryptContext *ctx)
{
    Esc_UINT8 seed[EscPkcs1RsaEsOaep_MAX_DIGEST_LEN];
    Esc_UINT8 digest[EscPkcs1RsaEsOaep_MAX_DIGEST_LEN];
    Esc_UINT32 i;
    Esc_BOOL hasFailed = FALSE;
    Esc_BOOL dummyflag = TRUE;
    Esc_UINT8 maskedDB[EscPkcs1RsaEsOaep_MASK_INPUT_LEN_MAX];
    Esc_UINT8 DB[EscPkcs1RsaEsOaep_MASK_DB_LEN_MAX];
    Esc_UINT32 maskedDbLen;

    /**
    * No termination/cutoff in case of errors here!
    *
    * RFC 3447
    * Note.  Care must be taken to ensure that an opponent cannot
    * distinguish the different error conditions in Step 3.g, whether by
    * error message or timing, or, more generally, learn partial
    * information about the encoded message EM.  Otherwise an opponent may
    * be able to obtain useful information about the decryption of the
    * ciphertext C, leading to a chosen-ciphertext attack such as the one
    * observed by Manger [36].
    */
    maskedDbLen = (ctx->keySizeBytes - ctx->digestLength) - 1U;

    /* 3.c) seedMask = MGF( maskedDB, hLen ) --> Hash( maskedDB || 00 00 00 00 ) */
    for (i = 0U; i < maskedDbLen; i++)
    {
        maskedDB[i] = ctx->em[1U + ctx->digestLength + i];
    }

    for (i = 0U; i < 4U; i++)
    {
        maskedDB[( (ctx->keySizeBytes - ctx->digestLength) - 1U ) + i] = 0x00U;
    }

    if (EscPkcs1RsaEsOaep_Hash( maskedDB, (Esc_UINT32)maskedDbLen + 4U, digest, ctx->digestType, ctx->digestLength ) != Esc_NO_ERROR)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    /* seed = maskedSeed XOR seedMask */
    for (i = 0U; i < ctx->digestLength; i++)
    {
        seed[i] = ctx->em[1U + i] ^ digest[i];
    }

    /* 3.e) dbMask = MGF1( seed, k - hLen - 1 ) */
    /*lint -e{772} seed is initialized correctly */
    if (EscPkcs1RsaEsOaep_MGF1( seed, DB, (ctx->keySizeBytes - ctx->digestLength) - 1U, ctx->digestLength, ctx->digestType) != Esc_NO_ERROR)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    /* 3.f) DB = maskedDB XOR dbMask */
    for (i = 0U; i < maskedDbLen; i++)
    {
        DB[i] ^= maskedDB[i];
    }

    /* 3.a) lHash' = Hash( L ) */
    if (EscPkcs1RsaEsOaep_Hash( ctx->label, ctx->labelLen, digest, ctx->digestType, ctx->digestLength ) != Esc_NO_ERROR)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    for (i = 0U; i < ctx->digestLength; i++)
    {
        if ( digest[i] != DB[i] )
        {
            hasFailed = TRUE;
        }
        else
        {
            dummyflag = FALSE;
        }
    }

    if (ctx->em[0x00] != 0x00U)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    /* find the end of padding PS */
    for (i = ctx->digestLength; ( i < (maskedDbLen - 1U) ) && (DB[i] == 0x00U); i++)
    {
    }

    if (DB[i] != 0x01U)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    *ctx->messageLen = (maskedDbLen - 1U) - i;

    for (i = 0U; i < *ctx->messageLen; i++)
    {
        ctx->message[i] = DB[(maskedDbLen - *ctx->messageLen) + i];
    }

    /* Here, hasFailed will still be FALSE if no error
     * condition was detected before. The dummy flag will also be FALSE */
    return (hasFailed | dummyflag);
}

Esc_ERROR
EscPkcs1RsaEsOaep_Encrypt(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaEsOaep_EncryptContext ctx;

    /* Initialize encryption */
    returnCode = EscPkcs1RsaEsOaep_EncryptInit(
                     &ctx,
                     prngFunc,
                     prngState,
                     message,
                     messageLen,
                     label,
                     labelLen,
                     pubKey,
                     cipher,
                     cipherLen,
                     digestType);

    /* Execute encryption until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaEsOaep_EncryptRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsOaep_Decrypt(
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    Esc_UINT8* message,
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 digestType )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaEsOaep_DecryptContext ctx;

    /* Initialize decryption */
    returnCode = EscPkcs1RsaEsOaep_DecryptInit(
                     &ctx,
                     cipher,
                     cipherLen,
                     label,
                     labelLen,
                     message,
                     messageLen,
                     privKey,
                     digestType);

    /* Execute decryption until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaEsOaep_DecryptRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsOaep_EncryptInit(
    EscPkcs1RsaEsOaep_EncryptContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen,
    Esc_UINT8 digestType)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keySizeBytes = 0U;

    if ( (ctx == Esc_NULL_PTR) ||
         (prngFunc == Esc_NULL_PTR) ||
         (message == Esc_NULL_PTR) ||
         (pubKey == Esc_NULL_PTR) ||
         ( (label == Esc_NULL_PTR) && (labelLen != 0U) ) ||     /* Allow NULL pointer if length is zero */
         (cipher == Esc_NULL_PTR) ||
         (cipherLen == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaEsOaep_STATE_ERROR;

        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaEsOaep_GetDigestLength(digestType, &ctx->digestLength);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        if ( *cipherLen < keySizeBytes )
        {
            /* Encryption result does not fit into buffer */
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }
        else if (keySizeBytes < ((2U * ctx->digestLength) + 2U))
        {
            /* The size of the hash digest is too large for the given key size. A different hash function must be used */
            returnCode = Esc_INVALID_PARAMETER;
        }
        else if ( messageLen > ( ( keySizeBytes - (2U * ctx->digestLength) ) - 2U) )
        {
            /* The message is too large to fit into (key size - minimal padding) */
            returnCode = Esc_MSG_TOO_LONG_FOR_PADDING;
        }
        else
        {
            /* Intentionally empty */
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters in context */
        ctx->prngFunc = prngFunc;
        ctx->prngState = prngState;
        ctx->message = message;
        ctx->messageLen = messageLen;
        ctx->pubKey = pubKey;
        ctx->label = label;
        ctx->labelLen = labelLen;
        ctx->cipher = cipher;
        ctx->cipherLen = cipherLen;
        ctx->keySizeBytes = keySizeBytes;
        ctx->digestType = digestType;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaEsOaep_STATE_ENCRYPT_ENCODE;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsOaep_EncryptRun(
    EscPkcs1RsaEsOaep_EncryptContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaEsOaep_STATE_ENCRYPT_ENCODE:
                /* Apply padding */
                returnCode = EscPkcs1RsaEsOaep_EmeOaepEncode(ctx);

                /* Initialize RSA operation */
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscRsa_ModExpPubInit(&ctx->rsaCtx, ctx->pubKey, ctx->cipher, ctx->cipher);
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaEsOaep_STATE_ENCRYPT_RSA;
                }
                break;

            case EscPkcs1RsaEsOaep_STATE_ENCRYPT_RSA:
                /* Run RSA until finished */
                returnCode = EscRsa_ModExpPubRun(&ctx->rsaCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    *(ctx->cipherLen) = ctx->keySizeBytes;
                }
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaEsOaep_STATE_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsOaep_DecryptInit(
    EscPkcs1RsaEsOaep_DecryptContext *ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    const Esc_UINT8 label[],
    Esc_UINT32 labelLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 digestType)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keySizeBytes = 0U;

    /* Check parameters */

    if ( (ctx == Esc_NULL_PTR) ||
         (message == Esc_NULL_PTR) ||
         (messageLen == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) ||
         ( (label == Esc_NULL_PTR) && (labelLen != 0U) ) ||     /* Allow NULL pointer if length is zero */
         (cipher == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaEsOaep_STATE_ERROR;

        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPkcs1RsaEsOaep_GetDigestLength(digestType, &ctx->digestLength);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(privKey->pubKey.keySizeBits);

        if ( ( keySizeBytes < ( ( 2U * ctx->digestLength) + 2U ) ) ||
             ( cipherLen != keySizeBytes ) )
        {
            /* The size of the hash digest is too large for the given key size
             * or the ciphertext length does not match the key size. */
            returnCode = Esc_INVALID_PARAMETER;
        }
        else if ( *messageLen < ( ( keySizeBytes - (2U * ctx->digestLength) ) - 2U ) )
        {
            /* The output buffer is too small */
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }
        else
        {
            /* Intentionally empty */
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters in context */
        ctx->label = label;
        ctx->labelLen = labelLen;
        ctx->message = message;
        ctx->messageLen = messageLen;
        ctx->digestType = digestType;
        ctx->keySizeBytes = keySizeBytes;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscRsa_ModExpPrivInit(&ctx->rsaCtx, privKey, cipher, ctx->em);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaEsOaep_STATE_DECRYPT_RSA;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsOaep_DecryptRun(
    EscPkcs1RsaEsOaep_DecryptContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_BOOL decodeFailed;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaEsOaep_STATE_DECRYPT_RSA:
                /* Run RSA until finished */
                returnCode = EscRsa_ModExpPrivRun(&ctx->rsaCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaEsOaep_STATE_DECRYPT_DECODE;
                }
                break;

            case EscPkcs1RsaEsOaep_STATE_DECRYPT_DECODE:
                /* Remove padding */
                decodeFailed = EscPkcs1RsaEsOaep_EmeOaepDecode(ctx);
                if (decodeFailed == FALSE)
                {
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    returnCode = Esc_DECRYPTION_ERROR;
                }
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaEsOaep_STATE_ERROR;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
