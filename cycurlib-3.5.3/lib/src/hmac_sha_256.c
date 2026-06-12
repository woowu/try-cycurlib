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

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "hmac_sha_256.h"
#include "mem_mgt.h"

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
EscHmacSha256_Init(
    Esc_BOOL isSha224,
    EscHmacSha256_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 buf[EscSha256_BLOCK_BYTES];
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
        if (keyLength > EscSha256_BLOCK_BYTES)
        {

            /* assign new key length */
            if (isSha224)
            {
                returnCode = EscSha256_Calc( isSha224, key, keyLength, ctx->hmac_key, EscSha224_DIGEST_LEN );
                ctx->hmac_keyLength = EscSha224_DIGEST_LEN;
            }
            else
            {
                returnCode = EscSha256_Calc( isSha224, key, keyLength, ctx->hmac_key, EscSha256_DIGEST_LEN );
                ctx->hmac_keyLength = EscSha256_DIGEST_LEN;
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
            returnCode = EscSha256_Init( isSha224, &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* RFC 2104: Chapter 2: */
        /* sha2_ctx= (K XOR ipad) */
        /* ipad = the byte 0x36 repeated 64 times */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x36U);
        }
        for (; i < EscSha256_BLOCK_BYTES; i++)
        {
            buf[i] = 0x36U;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update with sha2_ctx key */
            /* H( K XOR ipad, data ) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha256_Update( &ctx->sha_ctx, buf, EscSha256_BLOCK_BYTES );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(buf, sizeof(buf));

    return returnCode;
}

Esc_ERROR
EscHmacSha256_Update(
    EscHmacSha256_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) ) /* Allow NULL pointer if length is zero */
    {
        returnCode = EscSha256_Update( &ctx->sha_ctx, message, messageLength );
    }

    return returnCode;
}

Esc_ERROR
EscHmacSha256_Finish(
    EscHmacSha256_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 buf[EscSha256_BLOCK_BYTES];
    Esc_UINT8 innerHash[EscSha256_DIGEST_LEN];
    Esc_UINT32 i;
    Esc_BOOL isSha224;

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
        if (ctx->sha_ctx.digestLen == EscSha224_DIGEST_LEN)
        {
            isSha224 = TRUE;
        }
        else
        {
            isSha224 = FALSE;
        }

        /* finalize inner_sha2_ctx and write to inner_sha */
        /* digest= H(K XOR ipad, text) */
        returnCode = EscSha256_Finish( &ctx->sha_ctx, innerHash, ctx->sha_ctx.digestLen );

        /******************
        * outer_sha2_ctx *
        ******************/

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize outer_sha2_ctx */
            returnCode = EscSha256_Init( isSha224, &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* sha2_ctx= (K XOR opad) */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x5CU);
        }
        for (; i < EscSha256_BLOCK_BYTES; i++)
        {
            buf[i] = (Esc_UINT8)0x5CU;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha2_ctx with key */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha256_Update( &ctx->sha_ctx, buf, EscSha256_BLOCK_BYTES );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha2_ctx with inner_sha */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            returnCode = EscSha256_Update( &ctx->sha_ctx, innerHash, (Esc_UINT32)ctx->sha_ctx.digestLen );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* finalize outer_sha2_ctx and write to mac output */
            returnCode = EscSha256_Finish( &ctx->sha_ctx, mac, macLength );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(buf, sizeof(buf));
    Esc_memclear(innerHash, sizeof(innerHash));

    return returnCode;
}

/****************************************************
 * calculate HMAC based on SHA-2 for the input data *
 ****************************************************/
Esc_ERROR
EscHmacSha256_Calc(
    Esc_BOOL isSha224,
    const Esc_UINT8 key[],      /* key array               */
    Esc_UINT32 keyLength,       /* length of key in bytes  */
    const Esc_UINT8 message[],  /* message array              */
    Esc_UINT32 messageLength,   /* length of message in bytes */
    Esc_UINT8 mac[],            /* computed HMAC */
    Esc_UINT8 macLength )
{
    EscHmacSha256_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscHmacSha256_Init( isSha224, &ctx, key, keyLength );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscHmacSha256_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha256_Finish( &ctx, mac, macLength );
        }
    }

    /* Zeroize HMAC context */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
