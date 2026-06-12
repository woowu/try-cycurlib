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
   ECB-Mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 2189 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_ecb.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/*********************************************************
 create context with 'key'
 *********************************************************/
Esc_ERROR
EscAesEcb_Init(
    EscAesEcb_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] )
{
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
        EscAes_Init( ctx, keyBits, key );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/*********************************************************
 Encrypts one ECB block. Exported function with parameter check.
 *********************************************************/
Esc_ERROR
EscAesEcb_Encrypt(
    const EscAesEcb_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

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
        Esc_UINT32 i;
        for (i = 0U; i < (length / EscAes_BLOCK_BYTES); ++i)
        {
            EscAes_EncryptBlock( ctx, &plain[EscAes_BLOCK_BYTES * i], &cipher[EscAes_BLOCK_BYTES * i] );
        }
    }

    return returnCode;
}

/*********************************************************
 Decrypts one ECB block. Exported function with parameter check.
 *********************************************************/
Esc_ERROR
EscAesEcb_Decrypt(
    const EscAesEcb_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

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
        Esc_UINT32 i;
        for (i = 0U; i < (length / EscAes_BLOCK_BYTES); ++i)
        {
            EscAes_DecryptBlock( ctx, &cipher[EscAes_BLOCK_BYTES * i], &plain[EscAes_BLOCK_BYTES * i] );
        }

    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
