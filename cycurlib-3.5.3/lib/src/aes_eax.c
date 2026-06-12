/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       EAX implementation based on AES according to NIST

   \see         NIST SP 800-38B

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3678 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_eax.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/
/** Length of the array that precedes during MAC calculation */
#define EscAesEax_MAC_STARTING_ARRAY_SIZE 16U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

static Esc_ERROR
EscAesEax_NonceHeader_Update(
    EscCmacAes_ContextT* cmacAesCtx,
    const Esc_UINT8 inputData[],
    Esc_UINT32 inputDataLen,
    Esc_BOOL finished );

static Esc_ERROR
EscAesEax_NonceHeader_Finish(
    EscCmacAes_ContextT* cmacAesCtx,
    Esc_UINT8 macOutput[],
    Esc_UINT8 macLen,
    Esc_BOOL* finished );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
 * Encrypt a plaintext and associated data with the EAX Mode
 */
Esc_ERROR
EscAesEax_Encrypt(
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 cipher[] )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    /* Set AES key */
    returnCode = EscAesEax_Init( &ctx, keyBits, key );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set and format input data and nonce */
        returnCode = EscAesEax_startEncryptDecrypt(&ctx, tagLen);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process nonce */
        if (nonceLen > 0U)
        {
            returnCode = EscAesEax_Nonce_Update( &ctx, nonce, nonceLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish(&ctx);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process header */
        if (headerLen > 0U)
        {
            returnCode = EscAesEax_Header_Update( &ctx, header, headerLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish(&ctx);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process plaintext */
        returnCode = EscAesEax_Encrypt_Update( &ctx, plain, cipher, plainLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Generate MAC */
        returnCode = EscAesEax_Encrypt_Finish( &ctx, &cipher[plainLen], tagLen );
    }

    return returnCode;
}

/**
 * Decrypt the payload and check the MAC of the input data with the EAX Mode.
 */
Esc_ERROR
EscAesEax_Decrypt(
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 plain[] )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    /* Check if data is large enough to contain the MAC */
    if (cipherLen < tagLen)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Initialize the Context */
        returnCode = EscAesEax_Init( &ctx, keyBits, key );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_startEncryptDecrypt(&ctx, tagLen);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process nonce */
        if (nonceLen > 0U)
        {
            returnCode = EscAesEax_Nonce_Update( &ctx, nonce, nonceLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish(&ctx);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process header */
        if (headerLen > 0U)
        {
            returnCode = EscAesEax_Header_Update( &ctx, header, headerLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish(&ctx);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process ciphertext */
        returnCode = EscAesEax_Decrypt_Update( &ctx, cipher, plain, (cipherLen - tagLen) );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Verify MAC */
        returnCode = EscAesEax_Decrypt_Finish( &ctx, &cipher[(cipherLen - tagLen)], tagLen );
    }

    return returnCode;
}

/**
 * This function initializes the AES-EAX context
 */
Esc_ERROR
EscAesEax_Init(
    EscAesEax_ContextT* ctx,
    Esc_UINT32 keyBits,
    const Esc_UINT8 key[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    Esc_UINT32 keyLen = (keyBits / 8U);

    if ( (ctx == Esc_NULL_PTR) ||
         (key == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBits > EscAes_MAX_KEY_BITS) ||
              ((keyBits != 128U) && (keyBits != 192U) && (keyBits != 256U)))
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        ctx->keyLen = keyLen;
        ctx->nonceFinished = FALSE;
        ctx->headerFinished = FALSE;
        ctx->payloadFinished = FALSE;
        Esc_memcpy(ctx->key, key, keyLen);

        /* Initialize CMAC AES context for nonce */
        returnCode = EscCmacAes_Init(&ctx->cmacAesCtxNonce, key, keyLen);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize CMAC AES context for header */
            returnCode = EscCmacAes_Init(&ctx->cmacAesCtxHeader, key, keyLen);

            if (returnCode == Esc_NO_ERROR)
            {
                /* Initialize CMAC AES context for ciphertext */
                returnCode = EscCmacAes_Init(&ctx->cmacAesCtxCipher, key, keyLen);
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_startEncryptDecrypt(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 tagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 macStartingArray[EscAesEax_MAC_STARTING_ARRAY_SIZE]; /* Array used as starting point for MAC */

    /* NULL pointer check, key is already checked in init */
    if ( (ctx == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (tagLen > EscAes_BLOCK_BYTES)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        ctx->tagLen = tagLen;

        /* Initialize mac starting array to 0...0 */
        Esc_memset(macStartingArray, (Esc_UINT8)0U, EscAesEax_MAC_STARTING_ARRAY_SIZE);

        /* Update nonce mac with starting array */
        returnCode = EscCmacAes_Update(&ctx->cmacAesCtxNonce, macStartingArray, EscAesEax_MAC_STARTING_ARRAY_SIZE);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Modify mac starting array to 0...1 */
            macStartingArray[EscAesEax_MAC_STARTING_ARRAY_SIZE - 1U] = (Esc_UINT8)1U;

            /* Update header mac with starting array */
            returnCode = EscCmacAes_Update(&ctx->cmacAesCtxHeader, macStartingArray, EscAesEax_MAC_STARTING_ARRAY_SIZE);

            if (returnCode == Esc_NO_ERROR)
            {
                /* Modify mac starting array to 0...2 */
                macStartingArray[EscAesEax_MAC_STARTING_ARRAY_SIZE - 1U] = (Esc_UINT8)2U;

                /* Update ciphertext mac with starting array */
                returnCode = EscCmacAes_Update(&ctx->cmacAesCtxCipher, macStartingArray, EscAesEax_MAC_STARTING_ARRAY_SIZE);
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscAesEax_NonceHeader_Update(
    EscCmacAes_ContextT* cmacAesCtx,
    const Esc_UINT8 inputData[],
    Esc_UINT32 inputDataLen,
    Esc_BOOL finished )
{
    Esc_ERROR returnCode;

    if ((cmacAesCtx == Esc_NULL_PTR) || (inputData == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (inputDataLen == 0U)
    {
        /* Allows length of zero */
        returnCode = Esc_NO_ERROR;
    }
    else if (finished == TRUE)
    {
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        returnCode = EscCmacAes_Update(cmacAesCtx, inputData, inputDataLen);
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Nonce_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 nonce[],
    Esc_UINT32 nonceLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = EscAesEax_NonceHeader_Update(&ctx->cmacAesCtxNonce, nonce, nonceLen, ctx->nonceFinished);
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Header_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 header[],
    Esc_UINT32 headerLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        returnCode = EscAesEax_NonceHeader_Update(&ctx->cmacAesCtxHeader, header, headerLen, ctx->headerFinished);
    }

    return returnCode;
}

static Esc_ERROR
EscAesEax_NonceHeader_Finish(
    EscCmacAes_ContextT* cmacAesCtx,
    Esc_UINT8 macOutput[],
    Esc_UINT8 macLen,
    Esc_BOOL* finished )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ((cmacAesCtx == Esc_NULL_PTR) || (macOutput == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (*finished == TRUE)
    {
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        returnCode = EscCmacAes_Finish(cmacAesCtx, macOutput, macLen);

        if (returnCode == Esc_NO_ERROR)
        {
            *finished = TRUE;
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Nonce_Finish(
    EscAesEax_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Finish nonce mac */
        returnCode = EscAesEax_NonceHeader_Finish(&ctx->cmacAesCtxNonce, ctx->macNonce, ctx->tagLen, &ctx->nonceFinished);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize CTR context for encryption of the payload */
            returnCode = EscAesCtr_Init(&ctx->aesCtrCtx, (Esc_UINT16)(ctx->keyLen * 8U), ctx->key,
                    ctx->macNonce, (Esc_UINT8)0U);
        }
    }
    return returnCode;
}

Esc_ERROR
EscAesEax_Header_Finish(
    EscAesEax_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_NonceHeader_Finish(&ctx->cmacAesCtxHeader, ctx->macHeader, ctx->tagLen, &ctx->headerFinished);
    }
    return returnCode;
}

Esc_ERROR
EscAesEax_Encrypt_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || ( ( (cipher == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->nonceFinished == FALSE) || (ctx->headerFinished == FALSE) || (ctx->payloadFinished == TRUE) )
    {
        /* Unexpected function call */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        if (length != 0U)
        {
            /* Encrypt the message */
            returnCode = EscAesCtr_Apply(&ctx->aesCtrCtx, plain, cipher, length);

            if (returnCode == Esc_NO_ERROR)
            {
                /* Update MAC for ciphertext */
                returnCode = EscCmacAes_Update(&ctx->cmacAesCtxCipher, cipher, length);
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Encrypt_Finish(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 macCipher[EscAes_BLOCK_BYTES]; /* Array used as starting point for MAC */

    if ((ctx == Esc_NULL_PTR) || (macTag == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->nonceFinished == FALSE) || (ctx->headerFinished == FALSE) )
    {
        /* Not enough data received and/or associated data was not fully updated */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else if (macTagLen != ctx->tagLen)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Initialize macCipher */
        Esc_memset(macCipher, (Esc_UINT8)0U, EscAes_BLOCK_BYTES);

        /* Finish MAC and save result in macCipher */
        returnCode = EscCmacAes_Finish(&ctx->cmacAesCtxCipher, macCipher, ctx->tagLen);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Calculate tag */
            for (i = 0; i < ctx->tagLen; i++)
            {
                macTag[i] = (ctx->macNonce[i] ^ ctx->macHeader[i]) ^ macCipher[i];
            }

            ctx->payloadFinished = TRUE;
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Decrypt_Update(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || ( ( (cipher == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->nonceFinished == FALSE) || (ctx->headerFinished == FALSE) || (ctx->payloadFinished == TRUE) )
    {
        /* Unexpected function call */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        if (length != 0U)
        {
            /* Encrypt the message */
            returnCode = EscAesCtr_Apply(&ctx->aesCtrCtx, cipher, plain, length);

            if (returnCode == Esc_NO_ERROR)
            {
                /* Update MAC for ciphertext */
                returnCode = EscCmacAes_Update(&ctx->cmacAesCtxCipher, cipher, length);
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesEax_Decrypt_Finish(
    EscAesEax_ContextT* ctx,
    const Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT8 newTag[EscAes_BLOCK_BYTES];
    Esc_UINT8 macCipher[EscAes_BLOCK_BYTES];

    if ((ctx == Esc_NULL_PTR) || (macTag == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ((ctx->nonceFinished == FALSE) || (ctx->headerFinished == FALSE))
    {
        /* Not enough data received and/or associated data was not fully updated */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else if (macTagLen != ctx->tagLen)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Initialize new_tag */
        Esc_memset(newTag, (Esc_UINT8)0U, EscAes_BLOCK_BYTES);

        /* Initialize macCipher */
        Esc_memset(macCipher, (Esc_UINT8)0U, EscAes_BLOCK_BYTES);

        /* Finish MAC and save result in ctx->macCipher */
        returnCode = EscCmacAes_Finish(&ctx->cmacAesCtxCipher, macCipher, ctx->tagLen);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Calculate new tag */
            for (i = 0; i < ctx->tagLen; i++)
            {
                newTag[i] = (ctx->macNonce[i] ^ ctx->macHeader[i]) ^ macCipher[i];
            }

            /* Check if new tag is valid */
            if (Esc_memcmp(macTag, newTag, ctx->tagLen) != 0U)
            {
                returnCode = Esc_INVALID_MAC;
            }

            ctx->payloadFinished = TRUE;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
