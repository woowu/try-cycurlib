/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 RSAES-v1_5 encryption and decryption

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "pkcs1_rsaes_v15.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** The first byte of the fixed padding */
#define EscPkcs1RsaEsV15_PADDING_FIRST             0x00U
/** The second byte of the fixed padding */
#define EscPkcs1RsaEsV15_PADDING_SECOND            0x02U
/** The message separator between padding and message */
#define EscPkcs1RsaEsV15_MS                        0x00U

/* Error state */
#define EscPkcs1RsaEsV15_STATE_ERROR                0

/* States for encryption */
#define EscPkcs1RsaEsV15_STATE_ENCRYPT_ENCODE       10
#define EscPkcs1RsaEsV15_STATE_ENCRYPT_RSA          11

/* State for decryption */
#define EscPkcs1RsaEsV15_STATE_DECRYPT_RSA          20
#define EscPkcs1RsaEsV15_STATE_DECRYPT_DECODE       21

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

static Esc_ERROR
EscPkcs1RsaEsV15_EmeRsaEsEncode(
    const EscPkcs1RsaEsV15_EncryptContext *ctx);

static Esc_BOOL
EscPkcs1RsaEsV15_EmeRsaEsDecode(
    const EscPkcs1RsaEsV15_DecryptContext *ctx);

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** Function EME-RSAES-ENCODE. Encodes a message according to EME-PKCS#1 v1.5 */
static Esc_ERROR
EscPkcs1RsaEsV15_EmeRsaEsEncode(
    const EscPkcs1RsaEsV15_EncryptContext *ctx)
{
    Esc_UINT32  i;
    Esc_UINT32  encodedMessageLen = 2U;
    Esc_UINT32  paddingLen = ( ctx->keySizeBytes - (ctx->messageLen + EscPkcs1RsaEsV15_FIXED_PADDING_LENGTH) );
    Esc_UINT8   padding;
    Esc_ERROR   returnCode = Esc_NO_ERROR;

    ctx->cipher[0U] = EscPkcs1RsaEsV15_PADDING_FIRST;
    ctx->cipher[1U] = EscPkcs1RsaEsV15_PADDING_SECOND;

    /* Generate up to paddingLen random, but nonzero, padding bytes */
    for (i = 0U; ( (returnCode == Esc_NO_ERROR) && (i < paddingLen) ); i++)
    {
        padding = 0U;

        do
        {
            returnCode = ctx->prngFunc( ctx->prngState, &padding, 1U );
        } while ( (padding == 0U) && (returnCode == Esc_NO_ERROR) );

        if (returnCode == Esc_NO_ERROR)
        {
            ctx->cipher[encodedMessageLen] = padding;
            encodedMessageLen++;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Append separating zero byte between padding and message. */
        ctx->cipher[encodedMessageLen] = EscPkcs1RsaEsV15_MS;
        encodedMessageLen++;

        /* Append original message. */
        for (i = 0U; i < ctx->messageLen; i++)
        {
            ctx->cipher[encodedMessageLen] = ctx->message[i];
            encodedMessageLen++;
        }
    }

    return returnCode;
}

/** Function EME-RSAES-DECODE. Decodes an EME-PKCS#1 v1.5 encoded message. */
static Esc_BOOL
EscPkcs1RsaEsV15_EmeRsaEsDecode(
    const EscPkcs1RsaEsV15_DecryptContext *ctx)
{
    Esc_UINT32 i = 0U;
    Esc_BOOL   hasFailed = FALSE;
    Esc_BOOL   dummyflag = TRUE;
    Esc_UINT32 byteCtr = 0U;
    Esc_UINT32 paddingLen = 0U;

    /**
    * No termination/cutoff in case of errors here!
    *
    * RFC 3447
    * Note.  Care shall be taken to ensure that an opponent cannot
    * distinguish the different error conditions in Step 3, whether by
    * error message or timing.  Otherwise an opponent may be able to obtain
    * useful information about the decryption of the ciphertext C, leading
    * to a strengthened version of Bleichenbacher's attack [6]; compare to
    * Manger's attack [36].
    *
    * Due to the compiling process, the timing requirement can not be
    * guaranteed! Further measures can only be made in assembly language.
    */
    if (ctx->em[byteCtr] != EscPkcs1RsaEsV15_PADDING_FIRST)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }
    byteCtr++;

    if (ctx->em[byteCtr] != EscPkcs1RsaEsV15_PADDING_SECOND)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }
    byteCtr++;

    /* Skip padding and message separator. */
    while (ctx->em[byteCtr] != EscPkcs1RsaEsV15_MS)
    {
        byteCtr++;
        paddingLen++;

        if (byteCtr >= ctx->keySizeBytes)
        {
            hasFailed = TRUE;
            break;
        }
    }

    /* Skip message separator */
    byteCtr++;

    /* Check for sufficient padding size. */
    if (paddingLen < EscPkcs1RsaEsV15_MIN_RANDOM_PADDING_LENGTH)
    {
        hasFailed = TRUE;
    }
    else
    {
        dummyflag = FALSE;
    }

    *ctx->messageLen = ctx->keySizeBytes - byteCtr;

    while (byteCtr < ctx->keySizeBytes)
    {
        if (i < EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH_FOR_KEYBYTES(ctx->keySizeBytes) )
        {
            ctx->message[i] = ctx->em[byteCtr];
        }
        else
        {
            /* Dummy assignment */
            ctx->message[0] = ctx->em[byteCtr];
        }
        i++;
        byteCtr++;
    }


    /* Here, hasFailed will still be FALSE if no error
     * condition was detected before. The dummy flag will also be FALSE */
    return (hasFailed | dummyflag);
}

Esc_ERROR
EscPkcs1RsaEsV15_Encrypt(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen)
{
    Esc_ERROR returnCode;
    EscPkcs1RsaEsV15_EncryptContext ctx;

    /* Initialize encryption */
    returnCode = EscPkcs1RsaEsV15_EncryptInit(
                     &ctx,
                     prngFunc,
                     prngState,
                     message,
                     messageLen,
                     pubKey,
                     cipher,
                     cipherLen);

    /* Execute encryption until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaEsV15_EncryptRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsV15_Decrypt(
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey )
{
    Esc_ERROR returnCode;
    EscPkcs1RsaEsV15_DecryptContext ctx;

    /* Initialize encryption */
    returnCode = EscPkcs1RsaEsV15_DecryptInit(
                     &ctx,
                     cipher,
                     cipherLen,
                     message,
                     messageLen,
                     privKey);

    /* Execute encryption until it is finished */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscPkcs1RsaEsV15_DecryptRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsV15_EncryptInit(
    EscPkcs1RsaEsV15_EncryptContext *ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 cipher[],
    Esc_UINT32 *cipherLen)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keySizeBytes = 0U;
    Esc_UINT32 maxMS;

    /* Check parameters */

    if ( (ctx == Esc_NULL_PTR) ||
         (prngFunc == Esc_NULL_PTR) ||
         (message == Esc_NULL_PTR) ||
         (pubKey == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) ||
         (cipherLen == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaEsV15_STATE_ERROR;

        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        keySizeBytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        maxMS = EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH_FOR_KEYBYTES(keySizeBytes);

        if (messageLen > maxMS)
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
        else if (*cipherLen < keySizeBytes)
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }
        else
        {
            /* Intentionally empty */
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters and set state */

        ctx->prngFunc = prngFunc;
        ctx->prngState = prngState;
        ctx->message = message;
        ctx->messageLen = messageLen;
        ctx->pubKey = pubKey;
        ctx->keySizeBytes = keySizeBytes;
        ctx->cipher = cipher;
        ctx->cipherLen = cipherLen;

        ctx->state = EscPkcs1RsaEsV15_STATE_ENCRYPT_ENCODE;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsV15_EncryptRun(
    EscPkcs1RsaEsV15_EncryptContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaEsV15_STATE_ENCRYPT_ENCODE:
                /* Apply padding */
                returnCode = EscPkcs1RsaEsV15_EmeRsaEsEncode(ctx);

                /* Start RSA operation */
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscRsa_ModExpPubInit(&ctx->rsaCtx, ctx->pubKey, ctx->cipher, ctx->cipher);
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaEsV15_STATE_ENCRYPT_RSA;
                }
                break;

            case EscPkcs1RsaEsV15_STATE_ENCRYPT_RSA:
                /* Run RSA until finished */
                returnCode = EscRsa_ModExpPubRun(&ctx->rsaCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    *ctx->cipherLen = ctx->keySizeBytes;
                }
                break;

            default:
                returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
                break;
        }

        if ( (returnCode != Esc_NO_ERROR) && (returnCode != Esc_AGAIN) )
        {
            /* Invalidate state on error */
            ctx->state = EscPkcs1RsaEsV15_STATE_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsV15_DecryptInit(
    EscPkcs1RsaEsV15_DecryptContext *ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 message[],
    Esc_UINT32* messageLen,
    const EscRsa_PrivKeyT* privKey)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keySizeByte = 0U;

    /* Parameter checks */

    if ( (ctx == Esc_NULL_PTR) ||
         (message == Esc_NULL_PTR) ||
         (messageLen == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Initialize current state with error state */
        ctx->state = EscPkcs1RsaEsV15_STATE_ERROR;

        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        keySizeByte = EscRsa_KEY_BYTES_FROMBITS(privKey->pubKey.keySizeBits);

        if ( (*messageLen) < EscPkcs1RsaEsV15_MAX_MESSAGE_LENGTH_FOR_KEYBYTES(keySizeByte) )
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }

        if (cipherLen != keySizeByte)
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Store parameters in context */
        ctx->message = message;
        ctx->messageLen = messageLen;
        ctx->keySizeBytes = keySizeByte;

        /* Initialize RSA operation */
        returnCode = EscRsa_ModExpPrivInit(&ctx->rsaCtx, privKey, cipher, ctx->em);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        ctx->state = EscPkcs1RsaEsV15_STATE_DECRYPT_RSA;
    }

    return returnCode;
}

Esc_ERROR
EscPkcs1RsaEsV15_DecryptRun(
    EscPkcs1RsaEsV15_DecryptContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_BOOL decodeFailed;

    if (ctx != Esc_NULL_PTR)
    {
        switch (ctx->state)
        {
            case EscPkcs1RsaEsV15_STATE_DECRYPT_RSA:
                /* Run RSA operation until it is finished */
                returnCode = EscRsa_ModExpPrivRun(&ctx->rsaCtx);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = Esc_AGAIN;
                    ctx->state = EscPkcs1RsaEsV15_STATE_DECRYPT_DECODE;
                }
                break;

            case EscPkcs1RsaEsV15_STATE_DECRYPT_DECODE:
                /* Check padding and store length */
                decodeFailed = EscPkcs1RsaEsV15_EmeRsaEsDecode(ctx);
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
            ctx->state = EscPkcs1RsaEsV15_STATE_ERROR;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
