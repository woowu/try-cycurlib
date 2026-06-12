/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-SHA-2 implementation, according to FIPS-180-2 and RFC 2104

   $Rev: 3218 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "hmac_sha_512.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

Esc_ERROR
EscHmacSha512_Init(
    Esc_BOOL isSha384,
    EscHmacSha512_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 buf[EscSha512_BLOCK_BYTES];
    Esc_UINT32 i;

    /* parameter check */
    if ( (ctx == Esc_NULL_PTR) || (key == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (keyLength == 0U)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        if (keyLength > EscSha512_BLOCK_BYTES)
        {

            /* assign new key length */
            if (isSha384)
            {
                returnCode = EscSha512_Calc( isSha384, key, keyLength, ctx->hmac_key, EscSha384_DIGEST_LEN );
                ctx->hmac_keyLength = EscSha384_DIGEST_LEN;
            }
            else
            {
                returnCode = EscSha512_Calc( isSha384, key, keyLength, ctx->hmac_key, EscSha512_DIGEST_LEN );
                ctx->hmac_keyLength = EscSha512_DIGEST_LEN;
            }
        }
        else
        {
            for (i = 0U; i < keyLength; i++)
            {
                ctx->hmac_key[i] = key[i];
            }
            ctx->hmac_keyLength = (Esc_UINT8)keyLength;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize sha2_ctx */
            returnCode = EscSha512_Init( isSha384, &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* RFC 2104: Chapter 2: */
        /* sha2_ctx= (K XOR ipad) */
        /* ipad = the byte 0x36 repeated 64 times */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x36U);
        }
        for (; i < EscSha512_BLOCK_BYTES; i++)
        {
            buf[i] = 0x36U;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update with sha2_ctx key */
            /* H( K XOR ipad, data ) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha512_Update( &ctx->sha_ctx, buf, EscSha512_BLOCK_BYTES );
        }
    }

    return returnCode;
}

Esc_ERROR
EscHmacSha512_Update(
    EscHmacSha512_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) ) /* Allow NULL pointer if length is zero */
    {
        returnCode = EscSha512_Update( &ctx->sha_ctx, message, messageLength );
    }

    return returnCode;
}

Esc_ERROR
EscHmacSha512_Finish(
    EscHmacSha512_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 buf[EscSha512_BLOCK_BYTES];
    Esc_UINT8 innerHash[EscSha512_DIGEST_LEN];
    Esc_UINT32 i;
    Esc_BOOL isSha384;

    if ( (ctx == Esc_NULL_PTR) || (mac == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (macLength == 0U) || (macLength > ctx->sha_ctx.digestLen) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Get digest length info from current context */
        if (ctx->sha_ctx.digestLen == EscSha384_DIGEST_LEN)
        {
            isSha384 = TRUE;
        }
        else
        {
            isSha384 = FALSE;
        }

        /* finalize inner_sha2_ctx and write to inner_sha */
        /* digest= H(K XOR ipad, text) */
        returnCode = EscSha512_Finish( &ctx->sha_ctx, innerHash, ctx->sha_ctx.digestLen );

        /******************
        * outer_sha2_ctx *
        ******************/

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize outer_sha2_ctx */
            returnCode = EscSha512_Init( isSha384, &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* sha2_ctx= (K XOR opad) */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x5CU);
        }
        for (; i < EscSha512_BLOCK_BYTES; i++)
        {
            buf[i] = (Esc_UINT8)0x5CU;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha2_ctx with key */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha512_Update( &ctx->sha_ctx, buf, EscSha512_BLOCK_BYTES );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha2_ctx with inner_sha */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            returnCode = EscSha512_Update( &ctx->sha_ctx, innerHash, (Esc_UINT32)ctx->sha_ctx.digestLen );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* finalize outer_sha2_ctx and write to mac output */
            returnCode = EscSha512_Finish( &ctx->sha_ctx, mac, macLength );
        }
    }

    return returnCode;
}

/****************************************************
 * calculate HMAC based on SHA-2 for the input data *
 ****************************************************/
Esc_ERROR
EscHmacSha512_Calc(
    Esc_BOOL isSha384,
    const Esc_UINT8 key[],      /* key array               */
    Esc_UINT32 keyLength,       /* length of key in bytes  */
    const Esc_UINT8 message[],  /* message array              */
    Esc_UINT32 messageLength,   /* length of message in bytes */
    Esc_UINT8 mac[],            /* computed HMAC */
    Esc_UINT8 macLength )
{
    EscHmacSha512_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscHmacSha512_Init( isSha384, &ctx, key, keyLength );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscHmacSha512_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha512_Finish( &ctx, mac, macLength );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
