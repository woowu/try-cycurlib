/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-SHA-1 implementation, according to FIPS-180-2 and RFC 2104

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "hmac_sha_1.h"
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
EscHmacSha1_Init(
    EscHmacSha1_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 buf[EscSha1_BLOCK_BYTES];
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
        if (keyLength > EscSha1_BLOCK_BYTES)
        {
            returnCode = EscSha1_Calc( key, keyLength, ctx->hmac_key, EscSha1_DIGEST_LEN );
            /* assign new key length */
            ctx->hmac_keyLength = EscSha1_DIGEST_LEN;
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
            /* Initialize sha1_ctx */
            returnCode = EscSha1_Init( &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* RFC 2104: Chapter 2: */
        /* sha1_ctx= (K XOR ipad) */
        /* ipad = the byte 0x36 repeated 64 times */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x36U);
        }
        for (; i < EscSha1_BLOCK_BYTES; i++)
        {
            buf[i] = 0x36U;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update with sha1_ctx key */
            /* H( K XOR ipad, data ) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha1_Update( &ctx->sha_ctx, buf, EscSha1_BLOCK_BYTES );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(buf, sizeof(buf));

    return returnCode;
}

Esc_ERROR
EscHmacSha1_Update(
    EscHmacSha1_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) ) /* Allow NULL pointer if length is zero */
    {
        returnCode = EscSha1_Update( &ctx->sha_ctx, message, messageLength );
    }

    return returnCode;
}

Esc_ERROR
EscHmacSha1_Finish(
    EscHmacSha1_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 buf[EscSha1_BLOCK_BYTES];
    Esc_UINT8 innerHash[EscSha1_DIGEST_LEN];
    Esc_UINT32 i;

    if ( (ctx == Esc_NULL_PTR) || (mac == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (macLength == 0U) || (macLength > EscHmacSha1_MAX_MAC_LENGTH) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* finalize inner_sha1_ctx and write to innerHash */
        /* digest= H(K XOR ipad, text) */
        returnCode = EscSha1_Finish( &ctx->sha_ctx, innerHash, EscSha1_DIGEST_LEN );

        /******************
        * outer_sha1_ctx *
        ******************/

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize outer_sha1_ctx */
            returnCode = EscSha1_Init( &ctx->sha_ctx );
        }

        /* build buffer with key and padding */
        /* sha1_ctx= H(K XOR opad) */
        for (i = 0U; i < ctx->hmac_keyLength; i++)
        {
            buf[i] = (ctx->hmac_key[i] ^ 0x5CU);
        }
        for (; i < EscSha1_BLOCK_BYTES; i++)
        {
            buf[i] = (Esc_UINT8)0x5CU;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha1_ctx with key */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            /*lint -e{772} buf is initialized correctly */
            returnCode = EscSha1_Update( &ctx->sha_ctx, buf, EscSha1_BLOCK_BYTES );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* update outer_sha1_ctx with inner_sha */
            /* H(K XOR opad, H(K XOR ipad, text)) */
            returnCode = EscSha1_Update( &ctx->sha_ctx, innerHash, EscSha1_DIGEST_LEN );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* finalize outer_sha1_ctx and write to MAC output */
            returnCode = EscSha1_Finish( &ctx->sha_ctx, mac, macLength );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(buf, sizeof(buf));
    Esc_memclear(innerHash, sizeof(innerHash));

    return returnCode;
}

/****************************************************
 * calculate HMAC based on SHA-1 for the input data *
 ****************************************************/
Esc_ERROR
EscHmacSha1_Calc(
    const Esc_UINT8 key[],         /* key array               */
    Esc_UINT32 keyLength,          /* length of key in bytes  */
    const Esc_UINT8 message[],     /* message array              */
    Esc_UINT32 messageLength,      /* length of message in bytes */
    Esc_UINT8 mac[],               /* computed HMAC */
    Esc_UINT8 macLength )          /* desired length of the output */
{
    EscHmacSha1_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscHmacSha1_Init( &ctx, key, keyLength );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscHmacSha1_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha1_Finish( &ctx, mac, macLength );
        }
    }

    /* Zeroize HMAC context */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
