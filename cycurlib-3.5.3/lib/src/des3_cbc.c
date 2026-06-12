/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       3-DES implementation CBC mode
   \see FIPS PUB 46-3

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "des3_cbc.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
static void
EscDes3Cbc_CopyBlock(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[] );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
Copy EscDes_BLOCK_BYTES bytes from 'source' to 'dest'
 */
static void
EscDes3Cbc_CopyBlock(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[] )
{
    Esc_UINT8 i;

    /* copy 16 bytes */
    for (i = 0U; i < EscDes_BLOCK_BYTES; i++)
    {
        dest[i] = source[i];
    }
}

/**
Initializes the CBC Context with the corresponding DES key and IV.
*/
Esc_ERROR
EscDes3Cbc_Init(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[],
    const Esc_UINT8 key3[],
    const Esc_UINT8 iv[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (cbcCtx != Esc_NULL_PTR) && (iv != Esc_NULL_PTR) )
    {
        /* set initialization vector */
        EscDes3Cbc_CopyBlock( cbcCtx->iv, iv );
        returnCode = EscDes3Ecb_Init( &cbcCtx->ecbCtx, key1, key2, key3 );
    }

    return returnCode;
}

/**
Decrypts one or more data blocks and updates the DES context.
*/
Esc_ERROR
EscDes3Cbc_Decrypt(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 last_cipher[EscDes_BLOCK_BYTES];    /* buffer for one 16-byte block */
    Esc_UINT8* last_iv;
    Esc_UINT32 blockPos;            /* Index of current block */
    Esc_UINT32 i;                   /* counter */

    /* parameter check */
    if ( (cbcCtx == Esc_NULL_PTR) ||
         (plain == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length % EscDes_BLOCK_BYTES) != 0U )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        last_iv = cbcCtx->iv;

        /* decrypt every 16-byte block */
        for (blockPos = 0U; blockPos < length; blockPos += (Esc_UINT32)EscDes_BLOCK_BYTES)
        {
            /* fill temporary buffer with cipher - needed because output and input buffers might be the same */
            EscDes3Cbc_CopyBlock( last_cipher, &cipher[blockPos] );

            /* decrypt block */
            EscDes3Ecb_DecryptFast( &cbcCtx->ecbCtx, last_cipher, &plain[blockPos] );

            /* XOR buffer 1 with previous cipher in buffer 2 */
            for (i = 0U; i < EscDes_BLOCK_BYTES; i++)
            {
                plain[blockPos + i] ^= last_iv[i];
            }

            /* fill buffer 2 with previous cipher */
            EscDes3Cbc_CopyBlock( last_iv, last_cipher );
        }
    }

    return returnCode;
}

/**
Encrypts one or more data blocks and updates the DES context.
*/
Esc_ERROR
EscDes3Cbc_Encrypt(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8* buf;
    Esc_UINT32 blockPos;
    Esc_UINT32 i;

    if ( (cbcCtx == Esc_NULL_PTR) ||
         (plain == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length % EscDes_BLOCK_BYTES) != 0U )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        buf = cbcCtx->iv;

        /* encrypt every 16-byte block */
        for (blockPos = 0U; blockPos < length; blockPos += (Esc_UINT32)EscDes_BLOCK_BYTES)
        {
            /* XOR plain with previous cipher */
            for (i = 0U; i < EscDes_BLOCK_BYTES; i++)
            {
                buf[i] ^= plain[blockPos + i];
            }

            EscDes3Ecb_EncryptFast( &cbcCtx->ecbCtx, buf, buf );
            EscDes3Cbc_CopyBlock( &cipher[blockPos], buf );
        }
    }

    return returnCode;
}

/*********************************************************
 Set IV of DES3 context to 'iv'
 *********************************************************/
Esc_ERROR
EscDes3Cbc_SetIV(
    EscDes3Cbc_ContextT* cbcCtx,
    const Esc_UINT8 iv[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if  ( (cbcCtx != Esc_NULL_PTR) && (iv != Esc_NULL_PTR) )
    {
        /* set initialization vector */
        EscDes3Cbc_CopyBlock( cbcCtx->iv, iv );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
