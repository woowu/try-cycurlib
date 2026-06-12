/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Blowfish implementation ECB mode
   \see         www.schneier.com/blowfish.html

   $Rev: 1458 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "blowfish_ecb.h"

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

/**
Initializes the ECB Context with the corresponding Blowfish key.
*/
Esc_ERROR
EscBfishEcb_Init(
    EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 key[],
    const Esc_UINT8 keyLen )
{
    Esc_ERROR returnCode;

    if ( (ecbCtx == Esc_NULL_PTR) || (key == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyLen < EscBfish_MIN_KEY_BYTES) || (keyLen > EscBfish_MAX_KEY_BYTES) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        EscBfish_Init( &ecbCtx->sched, key, keyLen );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
Encrypts one Blowfish block in ECB mode.
*/
void
EscBfishEcb_EncryptFast(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] )
{
    Esc_UINT32 l;
    Esc_UINT32 r;

    Esc_ASSERT( ecbCtx != 0 );
    Esc_ASSERT( cipher != 0 );
    Esc_ASSERT( plain != 0 );

    EscBfish_SplitBlock( &l, &r, plain );
    EscBfish_Encrypt( &ecbCtx->sched, &l, &r );
    EscBfish_MergeBlocks( cipher, l, r );
}

/**
Decrypts one Blowfish block in ECB mode.
*/
void
EscBfishEcb_DecryptFast(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] )
{
    Esc_UINT32 l;
    Esc_UINT32 r;

    Esc_ASSERT( ecbCtx != 0 );
    Esc_ASSERT( cipher != 0 );
    Esc_ASSERT( plain != 0 );

    EscBfish_SplitBlock( &l, &r, cipher );
    EscBfish_Decrypt( &ecbCtx->sched, &l, &r );
    EscBfish_MergeBlocks( plain, l, r );
}

/**
Encrypts one Blowfish block in ECB mode.
*/
Esc_ERROR
EscBfishEcb_Encrypt(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ecbCtx != Esc_NULL_PTR) && (plain != Esc_NULL_PTR) && (cipher != Esc_NULL_PTR) )
    {
        EscBfishEcb_EncryptFast( ecbCtx, plain, cipher );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
Decrypts one Blowfish block in ECB mode.
*/
Esc_ERROR
EscBfishEcb_Decrypt(
    const EscBfishEcb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ecbCtx != Esc_NULL_PTR) && (plain != Esc_NULL_PTR) && (cipher != Esc_NULL_PTR) )
    {
        EscBfishEcb_DecryptFast( ecbCtx, cipher, plain );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
