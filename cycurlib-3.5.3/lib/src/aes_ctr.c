/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES implementation (FIPS-197 compliant)
   CTR mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_ctr.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
static void
EscAesCrt_IncrementCounter(
    EscAesCtr_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/*********************************************************
 create context
 *********************************************************/
Esc_ERROR
EscAesCtr_Init(
    EscAesCtr_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT8 nonceLength )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) ||
         (key == Esc_NULL_PTR) ||
         (iv == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBits > EscAes_MAX_KEY_BITS) ||
              ((keyBits != 128U) && (keyBits != 192U) && (keyBits != 256U)))
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else if (nonceLength >= EscAes_IV_BYTES)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* The first bytes of IV contains the nonce. Don't count the nonce. */
        ctx->counterBytes = (Esc_UINT8)(EscAes_IV_BYTES - nonceLength);
        ctx->keyStreamCounter = 0;

        /* Set initialization vector */
        EscAes_CopyBlock( ctx->iv, iv );

        EscAes_Init( &ctx->aesCtx, keyBits, key );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

static void
EscAesCrt_IncrementCounter(
    EscAesCtr_ContextT* ctx )
{
    Esc_UINT8 ctrLen = ctx->counterBytes;
    Esc_UINT8* v = ctx->iv;
    Esc_UINT8 i;

    /* if ctrLen == 0, don't increment anything */
    for (i = 0U; i < ctrLen; i++)
    {
        Esc_UINT8 idx = (Esc_UINT8)(EscAes_IV_BYTES - 1U) - i;

        /* increment lowest significant byte */
        v[idx]++;

        if (v[idx] != 0U)
        {
            /* no overflow occurred, exit */
            break;
        }

        /* overflow occurred, increment the next byte */
    }
}

/************************************
 Encrypt/Decrypt a byte array in CTR mode
 ************************************/
Esc_ERROR
EscAesCtr_Apply(
    EscAesCtr_ContextT* ctx,
    const Esc_UINT8 source[],
    Esc_UINT8 dest[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 index = 0U;
    Esc_UINT32 remainingBytes;
    Esc_UINT32 i;

    if ( (ctx == Esc_NULL_PTR) ||
         (dest == Esc_NULL_PTR) ||
         (source == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        remainingBytes = length;
        /* use remaining keyStream for enc/decryption and re-set the counter and remaining bytes */
        if ( ctx->keyStreamCounter != 0U )
        {
            for (index = 0U; (index < ctx->keyStreamCounter) && (index < remainingBytes); index++)
            {
                dest[index] = ctx->keyStream[(EscAes_BLOCK_BYTES - ctx->keyStreamCounter) + index] ^ source[index];
            }
            remainingBytes -= index;
            ctx->keyStreamCounter -= (Esc_UINT8)index;
        }

        /* enc/decrypt whole blocks and reduce remaining bytes */
        for ( ; remainingBytes >= EscAes_BLOCK_BYTES; remainingBytes -= EscAes_BLOCK_BYTES)
        {
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->iv, ctx->keyStream );

            for ( i = 0U; i < EscAes_BLOCK_BYTES; i++)
            {
                dest[index+i] = ctx->keyStream[i] ^ source[index + i];
            }
            index += EscAes_BLOCK_BYTES;
            EscAesCrt_IncrementCounter( ctx );
        }

        /* enc/decrypt remaining bytes and keep keyStream and current keyStreamCounter */
        if ( remainingBytes != 0U )
        {
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->iv, ctx->keyStream );
            for (i = 0U; i < remainingBytes; i++)
            {
                dest[index + i] = ctx->keyStream[i] ^ source[index + i];
            }
            ctx->keyStreamCounter = (Esc_UINT8)(EscAes_BLOCK_BYTES - remainingBytes);
            EscAesCrt_IncrementCounter( ctx );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
