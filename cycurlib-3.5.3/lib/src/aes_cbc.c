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
   CBC-Mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_cbc.h"
#include "cycurlib_config.h"

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
/*********************************************************
 create context with 'key' and 'iv'
 *********************************************************/
Esc_ERROR
EscAesCbc_Init(
    EscAesCbc_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[] )
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
    else
    {
        /* set initialization vector */
        EscAes_CopyBlock( ctx->iv, iv );
        EscAes_Init( &ctx->aesCtx, keyBits, key );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/************************************
 decrypt a byte array in CBC mode
 ************************************/
Esc_ERROR
EscAesCbc_Decrypt(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 last_cipher[EscAes_BLOCK_BYTES];    /* buffer for one 16-byte block        */
    Esc_UINT8* last_iv;
    Esc_UINT32 blockPos;            /* Index of current block */
    Esc_UINT32 i;                   /* counter                             */

    if ( (ctx == Esc_NULL_PTR) ||
         (plain == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) )
    {
        /* parameter check failed */
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length % EscAes_BLOCK_BYTES) != 0U )
    {
        /* check length failed */
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        last_iv = ctx->iv;
        /* decrypt every 16-byte block */
        for (blockPos = 0U; blockPos < length; blockPos += (Esc_UINT32)EscAes_BLOCK_BYTES)
        {
            /* fill temporary buffer with cipher - needed because output and input buffers might be the same */
            EscAes_CopyBlock( last_cipher, &cipher[blockPos] );

            /* decrypt block */
            EscAes_DecryptBlock( &ctx->aesCtx, last_cipher, &plain[blockPos] );

            /* XOR buffer with previous cipher in last_iv */
            for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
            {
                plain[blockPos + i] ^= last_iv[i];
            }

            /* fill buffer 2 with previous cipher */
            EscAes_CopyBlock( last_iv, last_cipher );
        }
    }

    return returnCode;
}

/************************************
 encrypt a byte array in CBC mode
 ************************************/
Esc_ERROR
EscAesCbc_Encrypt(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode;
    Esc_UINT8* aesBuf;
    Esc_UINT32 blockPos;
    Esc_UINT32 i;

    if ( (ctx == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) || (cipher == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length % EscAes_BLOCK_BYTES) != 0U )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        aesBuf = ctx->iv;

        /* encrypt every 16-byte block */
        for (blockPos = 0U; blockPos < length; blockPos += (Esc_UINT32)EscAes_BLOCK_BYTES)
        {
            /* XOR plain with previous cipher */
            for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
            {
                aesBuf[i] ^= plain[blockPos + i];
            }

            EscAes_EncryptBlock( &ctx->aesCtx, aesBuf, aesBuf );

            EscAes_CopyBlock( &cipher[blockPos], aesBuf );
        }
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/*********************************************************
 Set IV of AES context to 'iv'
 *********************************************************/
Esc_ERROR
EscAesCbc_SetIV(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 iv[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (iv != Esc_NULL_PTR) )
    {
        /* set initialization vector */
        EscAes_CopyBlock( ctx->iv, iv );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
