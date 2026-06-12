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
   CBC-MAC-Mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
*/
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_cbc_mac.h"

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
 create context with 'key' and zero IV
 *********************************************************/
Esc_ERROR
EscAesCbcMac_Init(
    EscAesCbc_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] )
{
    static const Esc_UINT8 iv[EscAes_IV_BYTES] =
    {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };

    Esc_ERROR returnCode;

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
        returnCode = EscAesCbc_Init( ctx, keyBits, key, iv );
    }

    return returnCode;
}

/*********************************************************
 create context with 'key' and iv
 *********************************************************/
Esc_ERROR
EscAesCbcMac_SetIV(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 iv[] )
{
    /* Parameters are already checked in EscAesCbc_SetIV() */
    return EscAesCbc_SetIV( ctx, iv );
}

/************************************
 Adds more message data to the CBC-MAC
 ************************************/
Esc_ERROR
EscAesCbcMac_Update(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8* aesBuf;
    Esc_UINT32 blockPos;
    Esc_UINT32 i;

    if ( (ctx == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) )
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
        }
    }

    return returnCode;
}

/************************************
 Return CBC-MAC
 ************************************/
Esc_ERROR
EscAesCbcMac_Finish(
    const EscAesCbc_ContextT* ctx,
    Esc_UINT8 mac[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && (mac != Esc_NULL_PTR) )
    {
        EscAes_CopyBlock( mac, ctx->iv );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**********************************************************************
 Calculate CBC-MAC for a complete data block without using a context.
 **********************************************************************/
Esc_ERROR
EscAesCbcMac_Calc(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    Esc_UINT8 mac[] )         /* computed MAC */
{
    EscAesCbc_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscAesCbcMac_Init( &ctx, keyBits, key );
    if (returnCode == Esc_NO_ERROR)
    {
        if (iv != Esc_NULL_PTR)
        {
            returnCode = EscAesCbcMac_SetIV( &ctx, iv );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesCbcMac_Update( &ctx, message, messageLen );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesCbcMac_Finish( &ctx, mac );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
