/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       3-DES implementation ECB mode
   \see FIPS PUB 46-3

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "des3_ecb.h"
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
Initializes the ECB Context with the corresponding 3-DES key.
*/
Esc_ERROR
EscDes3Ecb_Init(
    EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[],
    const Esc_UINT8 key3[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ecbCtx != Esc_NULL_PTR) && (key1 != Esc_NULL_PTR) && (key2 != Esc_NULL_PTR) && (key3 != Esc_NULL_PTR) )
    {
        EscDes_Init( &ecbCtx->sched1, key1 );
        EscDes_Init( &ecbCtx->sched2, key2 );
        EscDes_Init( &ecbCtx->sched3, key3 );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
Encrypts one DES block in ECB mode.
*/
void
EscDes3Ecb_EncryptFast(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] )
{
    Esc_UINT32 l, r;
    Esc_ASSERT( ecbCtx != 0 );
    Esc_ASSERT( cipher != 0 );
    Esc_ASSERT( plain != 0 );

    EscDes_IntitialPermutation( &l, &r, plain );

    EscDes_EncryptRounds( &ecbCtx->sched1, &l, &r );
    EscDes_DecryptRounds( &ecbCtx->sched2, &r, &l );
    EscDes_EncryptRounds( &ecbCtx->sched3, &l, &r );

    EscDes_FinalPermutation( cipher, l, r );
}

/**
Decrypts one DES block in ECB mode.
*/
void
EscDes3Ecb_DecryptFast(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] )
{
    Esc_UINT32 l, r;
    Esc_ASSERT( ecbCtx != 0 );
    Esc_ASSERT( cipher != 0 );
    Esc_ASSERT( plain != 0 );

    EscDes_IntitialPermutation( &l, &r, cipher );

    EscDes_DecryptRounds( &ecbCtx->sched3, &l, &r );
    EscDes_EncryptRounds( &ecbCtx->sched2, &r, &l );
    EscDes_DecryptRounds( &ecbCtx->sched1, &l, &r );

    EscDes_FinalPermutation( plain, l, r );
}

/**
Encrypts one DES block in ECB mode.
*/
Esc_ERROR
EscDes3Ecb_Encrypt(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ecbCtx != Esc_NULL_PTR) && (plain != Esc_NULL_PTR) && (cipher != Esc_NULL_PTR) )
    {
        EscDes3Ecb_EncryptFast( ecbCtx, plain, cipher );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
Decrypts one DES block in ECB mode.
*/
Esc_ERROR
EscDes3Ecb_Decrypt(
    const EscDes3Ecb_ContextT* ecbCtx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ecbCtx != Esc_NULL_PTR) && (plain != Esc_NULL_PTR) && (cipher != Esc_NULL_PTR) )
    {
        EscDes3Ecb_DecryptFast( ecbCtx, cipher, plain );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
