/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       ChaCha20 implementation, according to RFC-7539.

   $Rev: 0001 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "chacha20.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/**
Convert 4 bytes from Esc_UINT8 array into one little-endian Esc_UINT32 word.

\param[in] p 4 byte array.

\return resulting Esc_UINT32
*/
#define EscChaCha20_U8TO32(p) ( (Esc_UINT32)(p)[0] | ((Esc_UINT32)(p)[1] << 8U) | ((Esc_UINT32)(p)[2] << 16U) | ((Esc_UINT32)(p)[3] << 24U) )

/** Maximum length of key bytes. */
#define EscChaCha20_MAX_KEY_WORDS 8U

/** Constants are defined as little endian encoding of "expand 32-byte k) and "expand 16-byte k" */
#define EscChaCha20_constant_0     0x61707865U  /* "expa" */
#define EscChaCha20_constant_1_256 0x3320646eU  /* "nd 3" */
#define EscChaCha20_constant_2_256 0x79622d32U  /* "2-by" */
#define EscChaCha20_constant_1_128 0x3120646eU  /* "nd 1" */
#define EscChaCha20_constant_2_128 0x79622d36U  /* "6-by" */
#define EscChaCha20_constant_3     0x6b206574U  /* "te k" */

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
Computes one keystream block and stores it in the context buffer.

\param[in, out] ctx Pointer to ChaCha20 context
*/
static void
EscChaCha20_block( 
    EscChaCha20_ContextT* ctx );

/**
Computes one quarter-round as described in Section 2.1. of the RFC-7539.

\param[in, out] a 32 bit word a
\param[in, out] b 32 bit word b
\param[in, out] c 32 bit word c
\param[in, out] d 32 bit word d
*/
static void
EscChaCha20_quarterround(
    Esc_UINT32* a,
    Esc_UINT32* b,
    Esc_UINT32* c,
    Esc_UINT32* d );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

Esc_ERROR
EscChaCha20_Init(
    EscChaCha20_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 blockCtr )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;

    if ( (ctx == Esc_NULL_PTR) ||
         (key == Esc_NULL_PTR) ||
         (nonce == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBits != 256U) && (keyBits != 128U) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        /* Set constants depending on the key size */
        ctx->state[0] = EscChaCha20_constant_0;
        if ( keyBits == 256U )
        {
            ctx->state[1] = EscChaCha20_constant_1_256;
            ctx->state[2] = EscChaCha20_constant_2_256;
        }
        else
        {
            ctx->state[1] = EscChaCha20_constant_1_128;
            ctx->state[2] = EscChaCha20_constant_2_128;
        }
        ctx->state[3] = EscChaCha20_constant_3;

        /* Set the key */
        for ( i = 0U; i < (keyBits / 32U); i++ )
        {
           ctx->state[4U + i] = EscChaCha20_U8TO32( &key[i * 4U] );
        }
        /* If key size == 128, repeat the key */
        for ( ; i < EscChaCha20_MAX_KEY_WORDS; i++ )
        {
           ctx->state[4U + i] = ctx->state[i];
        }

        /* Set the block counter */
        ctx->state[12] = blockCtr;

        /* Set the nonce */
        ctx->state[13] = EscChaCha20_U8TO32( &nonce[0] );
        ctx->state[14] = EscChaCha20_U8TO32( &nonce[4] );
        ctx->state[15] = EscChaCha20_U8TO32( &nonce[8] );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


Esc_ERROR
EscChaCha20_UpdateCnt(
    EscChaCha20_ContextT* ctx,
    Esc_UINT32 blockCtr )
{
    Esc_ERROR returnCode;

    if ( ctx == Esc_NULL_PTR )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        /* Set the block counter */
        ctx->state[12] = blockCtr;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


Esc_ERROR
EscChaCha20_Start(
    EscChaCha20_ContextT* ctx )
{
    Esc_ERROR returnCode;

    if ( ctx == Esc_NULL_PTR )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        /* Reset the keystream buffer, no keystream available. */
        ctx->keyStreamPosition = EscChaCha20_BLOCK_BYTES;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


Esc_ERROR
EscChaCha20_Update(
    EscChaCha20_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 output[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode;
    Esc_UINT32 i;
    Esc_UINT32 remainingBytes, currentByte, bytesToProcess;

    if ( (ctx == Esc_NULL_PTR) ||
         (input == Esc_NULL_PTR) ||
         (output == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        remainingBytes = length;
        currentByte = 0U;

        /* Use buffered keystream from last call */
        if ( ctx->keyStreamPosition < EscChaCha20_BLOCK_BYTES )
        {
            if ( remainingBytes < ( EscChaCha20_BLOCK_BYTES - ctx->keyStreamPosition ) )
            {
                bytesToProcess = remainingBytes;
            }
            else
            {
                bytesToProcess = EscChaCha20_BLOCK_BYTES - ctx->keyStreamPosition;
            }

            for ( currentByte = 0U; currentByte < bytesToProcess; currentByte++ )
            {
                output[currentByte] =
                        input[currentByte] ^ (Esc_UINT8)( ctx->keystream[ (ctx->keyStreamPosition / 4U) ] >> ((ctx->keyStreamPosition % 4U) * 8U) );
                ctx->keyStreamPosition++;
            }
            remainingBytes -= bytesToProcess;
        }

        /* Process all following full blocks */
        while ( remainingBytes >= EscChaCha20_BLOCK_BYTES )
        {
            /* Generate new keystream block */
            EscChaCha20_block( ctx );

            /* the whole block output is required as keyStream */
            /* xor input to keyStream and store result while performing little endianness casting */
            for ( i = 0U ; i < EscChaCha20_STATE_WORDS; i++ )
            {
                output[currentByte] = input[currentByte] ^ ( (Esc_UINT8)ctx->keystream[i] );
                currentByte++;

                output[currentByte] = input[currentByte] ^ (Esc_UINT8)(ctx->keystream[i] >> 8U);
                currentByte++;

                output[currentByte] = input[currentByte] ^ (Esc_UINT8)(ctx->keystream[i] >> 16U);
                currentByte++;

                output[currentByte] = input[currentByte] ^ (Esc_UINT8)(ctx->keystream[i] >> 24U);
                currentByte++;
            }
            remainingBytes -= EscChaCha20_BLOCK_BYTES;
            /* Set the keystream position for following calls */
            ctx->keyStreamPosition = EscChaCha20_BLOCK_BYTES;
        }

        /* Process last non-full block */
        if ( remainingBytes > 0U )
        {
            /* Generate new keystream block */
            EscChaCha20_block( ctx );

            for ( i = 0U; i < remainingBytes; i++ )
            {
                output[currentByte + i] = input[currentByte + i] ^ (Esc_UINT8)( ctx->keystream[ i / 4U ] >> ((i % 4U) * 8U) );
            }
            /* Set the keystream position for following calls */
            ctx->keyStreamPosition = i;
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


static void
EscChaCha20_quarterround(
    Esc_UINT32* a,
    Esc_UINT32* b,
    Esc_UINT32* c,
    Esc_UINT32* d )
{
    *a += *b;
    *d = *d ^ *a;
    *d = (*d << 16U) | (*d >> 16U);

    *c += *d;
    *b = *b^*c;
    *b = (*b << 12U) | (*b >> 20U);

    *a += *b;
    *d = *d^*a;
    *d = (*d << 8U) | (*d >> 24U);

    *c += *d;
    *b = *b^*c;
    *b = (*b << 7U) | (*b >> 25U);
}

static void
EscChaCha20_block(
    EscChaCha20_ContextT* ctx )
{
    Esc_UINT8 i;

    /* Copy init state - original state will be required in final addition */
    for ( i = 0U; i < EscChaCha20_STATE_WORDS; i++)
    {
        ctx->keystream[i] = ctx->state[i];
    }

    /* Perform 20 ChaCha rounds (10 "column rounds" interleaved with 10 "diagonal rounds") */
    for (i = 0U; i < 10U; i++)
    {
        EscChaCha20_quarterround( &ctx->keystream[0], &ctx->keystream[4], &ctx->keystream[ 8], &ctx->keystream[12] );
        EscChaCha20_quarterround( &ctx->keystream[1], &ctx->keystream[5], &ctx->keystream[ 9], &ctx->keystream[13] );
        EscChaCha20_quarterround( &ctx->keystream[2], &ctx->keystream[6], &ctx->keystream[10], &ctx->keystream[14] );
        EscChaCha20_quarterround( &ctx->keystream[3], &ctx->keystream[7], &ctx->keystream[11], &ctx->keystream[15] );
        EscChaCha20_quarterround( &ctx->keystream[0], &ctx->keystream[5], &ctx->keystream[10], &ctx->keystream[15] );
        EscChaCha20_quarterround( &ctx->keystream[1], &ctx->keystream[6], &ctx->keystream[11], &ctx->keystream[12] );
        EscChaCha20_quarterround( &ctx->keystream[2], &ctx->keystream[7], &ctx->keystream[ 8], &ctx->keystream[13] );
        EscChaCha20_quarterround( &ctx->keystream[3], &ctx->keystream[4], &ctx->keystream[ 9], &ctx->keystream[14] );
    }

    /* Add the init state to the working state  */
    for ( i = 0U; i < EscChaCha20_STATE_WORDS; i++)
    {
        ctx->keystream[i] += ctx->state[i];
    }

    /* Increment the block counter */
    ctx->state[12]++;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
