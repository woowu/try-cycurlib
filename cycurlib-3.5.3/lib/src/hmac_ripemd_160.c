/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       HMAC-RIPEMD-160 implementation, RFC 2104 compliant

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "hmac_ripemd_160.h"
/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*********************************************************************
 * calculates HMAC based on RIPEMD-160 for the input data (RFC 2104) *
 *********************************************************************/
Esc_ERROR
EscHmacRipemd160_Init(
    EscHmacRipemd160_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 buf[EscRipemd160_BLOCK_BYTES];
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
        if (keyLength > EscRipemd160_BLOCK_BYTES)
        {
            /* Compute RIPEMD-160 hash of the key */
            returnCode = EscRipemd160_Calc( key, keyLength, ctx->hmac_key, EscRipemd160_DIGEST_LEN );

            /* assign new key length */
            ctx->hmac_keyLength = 20U;
        }
        else
        {
            for (i = 0U; i < keyLength; i++)
            {
                ctx->hmac_key[i] = key[i];
            }
            ctx->hmac_keyLength = (Esc_UINT8) keyLength;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Initialize inner_ctx */
            returnCode = EscRipemd160_Init( &ctx->rmd_ctx );
            if (returnCode == Esc_NO_ERROR)
            {
                /* build buffer with key and padding      */
                /* ctx= (K XOR ipad)                  */
                /* ipad = the byte 0x36 repeated 64 times */
                for (i = 0U; i < ctx->hmac_keyLength; i++)
                {
                    buf[i] = (Esc_UINT8)(ctx->hmac_key[i] ^ 0x36U);
                }
                for (; i < EscRipemd160_BLOCK_BYTES; i++)
                {
                    buf[i] = 0x36U;
                }

                /* update with inner_ctx key and data */
                /* H( K XOR ipad, data ) */
                /*lint -e{772} buf is initialized correctly */
                returnCode = EscRipemd160_Update( &ctx->rmd_ctx, buf, EscRipemd160_BLOCK_BYTES );
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscHmacRipemd160_Update(
    EscHmacRipemd160_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) ) /* Allow NULL pointer if length is zero */
    {
        /* H( K XOR ipad, data ) */
        returnCode = EscRipemd160_Update( &ctx->rmd_ctx, message, messageLength );
    }

    return returnCode;
}

Esc_ERROR
EscHmacRipemd160_Finish(
    EscHmacRipemd160_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_UINT8 buf[EscRipemd160_BLOCK_BYTES];
    Esc_UINT8 innerHash[EscRipemd160_DIGEST_LEN];
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;

    if ( (ctx == Esc_NULL_PTR) || (mac == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (macLength == 0U) || (macLength > EscHmacRipemd160_MAX_MAC_LENGTH) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* finalize inner_ctx and write to innerHash */
        /* innerHash= H(K XOR ipad, data) */
        returnCode = EscRipemd160_Finish( &ctx->rmd_ctx, innerHash, EscRipemd160_DIGEST_LEN );

        /*****************
        * outer_ctx *
        *****************/

        /* Initialize outer_ctx */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Init( &ctx->rmd_ctx );
            if (returnCode == Esc_NO_ERROR)
            {
                /* build buffer with key and padding */
                /* ctx= H(K XOR opad) */
                for (i = 0U; i < ctx->hmac_keyLength; i++)
                {
                    buf[i] = (ctx->hmac_key[i] ^ 0x5CU);
                }
                for (; i < EscRipemd160_BLOCK_BYTES; i++)
                {
                    buf[i] = 0x5CU;
                }

                /* update outer_ctx with key */
                /* H(K XOR opad, H(K XOR ipad, data)) */
                /*lint -e{772} buf is initialized correctly */
                returnCode = EscRipemd160_Update( &ctx->rmd_ctx, buf, EscRipemd160_BLOCK_BYTES );
            }
        }

        /* update outer_ctx with inner_hash */
        /* H(K XOR opad, H(K XOR ipad, data)) */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Update( &ctx->rmd_ctx, innerHash, EscRipemd160_DIGEST_LEN );
        }

        /* finalize outer_ctx and write to MAC output */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Finish( &ctx->rmd_ctx, mac, macLength );
        }
    }

    return returnCode;
}

Esc_ERROR
EscHmacRipemd160_Calc(
    const Esc_UINT8 key[],       /* key array               */
    Esc_UINT32 keyLength,        /* length of key in bytes  */
    const Esc_UINT8 message[],   /* message array              */
    Esc_UINT32 messageLength,    /* length of message in bytes */
    Esc_UINT8 mac[],             /* computed HMAC */
    Esc_UINT8 macLength )
{
    EscHmacRipemd160_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscHmacRipemd160_Init( &ctx, key, keyLength );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =  EscHmacRipemd160_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacRipemd160_Finish( &ctx, mac, macLength );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
