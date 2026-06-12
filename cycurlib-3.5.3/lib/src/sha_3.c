/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-3 implementation

   \see         FIPS-202 at nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

   $Rev: 2106 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "sha_3.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * XOR two lanes.
 *
 * \param[in]   a   First lane.
 * \param[in]   b   Second lane.
 * \param[out]  c   Result (a XOR b).
 */
static void
EscSha3_LaneXor(
    const EscSha3_Lane *a,
    const EscSha3_Lane *b,
    EscSha3_Lane *c);

/**
 * Rotate a lane left by n.
 *
 * \param[in]   a   Lane to rotate.
 * \param[in]   n   By how many positions to rotate.
 * \param[out]  b   Resulting rotated lane.
 */
static void
EscSha3_LaneRotateL(
    const EscSha3_Lane *a,
    Esc_UINT8 n,
    EscSha3_Lane *b);

/**
 * Compute the Chi function, i.e. d = a XOR ((b XOR 1) AND c)
 *
 * \param[in]   a   Lane operand a.
 * \param[in]   b   Lane operand b.
 * \param[in]   c   Lane operand c.
 * \param[out]  d   Result lane d.
 */
static void
EscSha3_ComputeChi(
    const EscSha3_Lane *a,
    const EscSha3_Lane *b,
    const EscSha3_Lane *c,
    EscSha3_Lane *d);

/**
 * Set the state and the number of cached bytes to zero.
 *
 * \param[in,out]   ctx     The SHA-3 context.
 */
static void
EscSha3_SetZero(
    EscSha3_ContextT* ctx );

/**
 * Convert an array of bytes to the internal state representation
 * (array of lanes). The block length is taken from the provided context.
 *
 * \param[in,out]   ctx     The SHA-3 context.
 * \param[in]       block   The byte array to convert from. The length should
 *                          correspond to the block length set during initialization
 *                          of the context.
 */
static void
EscSha3_ConvertBytesToState(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 block[] );

/**
 * Convert the state into an array of bytes of given length.
 * This function allows for truncation, i.e. writing only the first n bytes
 * of the state into the array.
 *
 * \param[in]       ctx             The SHA-3 context.
 * \param[out]      digest          The array to serialize the state to.
 * \param[in]       digestLength    Length of the number of bytes to write to the array.
 */
static void
EscSha3_ConvertStateToBytes(
    const EscSha3_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength );

/**
 * Hash a block of data.
 *
 * \param[in,out]   ctx     The SHA-3 context.
 * \param[in]       block   The block to be hashed. The size depends on the block
 *                          length set in the context during initialization.
 */
static void
EscSha3_Hash(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 block[] );

/**
 * Pad the last block of data. This function uses the block buffer in
 * the context structure.
 *
 * \param[in,out]   ctx     The SHA-3 context.
 */
static void
EscSha3_ApplyPadding(
    EscSha3_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*lint -esym(9003,EscSha3_Mod5,EscSha3_RhoRotationOffset,EscSha3_PiRearrange,EscSha3_RoundConstants)
  We keep the constant definitions at file scope for improved readability */

/* Lookup table for (x mod 5) with x in [0..8] */
static const Esc_UINT8 EscSha3_Mod5[] =
{
    0U, 1U, 2U, 3U, 4U, 0U, 1U, 2U, 3U
};

/* This table specifies for each of the 25 lanes in the state by how many it must be rotated in the Rho step */
static const Esc_UINT8 EscSha3_RhoRotationOffset[] =
{
    1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U, 14U, 27U, 41U, 56U, 8U, 25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

/* A cyclic permutation of lane positions used for the Pi step. The lane at position Sha3_PiRearrange[x] is moved to
 * position Sha3_PiRearrange[x-1]. */
static const Esc_UINT8 EscSha3_PiRearrange[] =
{
    10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U, 8U, 21U, 24U, 4U, 15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
};

/* The 24 round constants used in the Iota step. */
static const EscSha3_Lane EscSha3_RoundConstants[] =
{
#if (Esc_HAS_INT64 == 1)
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
#else
    { 0x00000000U, 0x00000001U },
    { 0x00000000U, 0x00008082U },
    { 0x80000000U, 0x0000808aU },
    { 0x80000000U, 0x80008000U },
    { 0x00000000U, 0x0000808bU },
    { 0x00000000U, 0x80000001U },
    { 0x80000000U, 0x80008081U },
    { 0x80000000U, 0x00008009U },
    { 0x00000000U, 0x0000008aU },
    { 0x00000000U, 0x00000088U },
    { 0x00000000U, 0x80008009U },
    { 0x00000000U, 0x8000000aU },
    { 0x00000000U, 0x8000808bU },
    { 0x80000000U, 0x0000008bU },
    { 0x80000000U, 0x00008089U },
    { 0x80000000U, 0x00008003U },
    { 0x80000000U, 0x00008002U },
    { 0x80000000U, 0x00000080U },
    { 0x00000000U, 0x0000800aU },
    { 0x80000000U, 0x8000000aU },
    { 0x80000000U, 0x80008081U },
    { 0x80000000U, 0x00008080U },
    { 0x00000000U, 0x80000001U },
    { 0x80000000U, 0x80008008U },
#endif
};

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/* a XOR b = c */
static void
EscSha3_LaneXor(
    const EscSha3_Lane *a,
    const EscSha3_Lane *b,
    EscSha3_Lane *c)
{
#if (Esc_HAS_INT64 == 1)
    *c = *a ^ *b;
#else
    c->high = a->high ^ b->high;
    c->low = a->low ^ b->low;
#endif
}

/* Rotate a by n and store result in b */
static void
EscSha3_LaneRotateL(
    const EscSha3_Lane *a,
    Esc_UINT8 n,
    EscSha3_Lane *b)
{
#if (Esc_HAS_INT64 == 1)
    *b = (*a << n) | (*a >> (64U - n));
#else
    if (n < 32U)
    {
        b->high = (a->high << n) | (a->low >> (32U - n));
        b->low = (a->low << n) | (a->high >> (32U - n));
    }
    else
    {
        b->high = (a->low << (n - 32U)) | (a->high >> (64U - n));
        b->low = (a->high << (n - 32U)) | (a->low >> (64U - n));
    }
#endif
}

/* Compute a XOR ((b xor 1) AND c) = d */
static void
EscSha3_ComputeChi(
    const EscSha3_Lane *a,
    const EscSha3_Lane *b,
    const EscSha3_Lane *c,
    EscSha3_Lane *d)
{
#if (Esc_HAS_INT64 == 1)
    *d = *a ^ ((~(*b)) & *c);
#else
    d->high = a->high ^ ((~b->high) & c->high);
    d->low = a->low ^ ((~b->low) & c->low);
#endif
}

static void
EscSha3_SetZero(
    EscSha3_ContextT* ctx )
{
    Esc_UINT8 i;

    for (i = 0U; i < EscSha3_NUM_LANES_IN_STATE; i++)
    {
#if (Esc_HAS_INT64 == 1)
        ctx->state[i] = 0U;
#else
        ctx->state[i].high = 0U;
        ctx->state[i].low = 0U;
#endif
    }

    ctx->numCachedBytes = 0U;
}

static void
EscSha3_ConvertBytesToState(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 i, j;
    EscSha3_Lane tempLane;
#if (Esc_HAS_INT64 == 1)
    tempLane = 0U;
#else
    tempLane.high = 0U;
    tempLane.low = 0U;
#endif

    for ( i = 0U; i < (ctx->blockLen / 8U); i++)
    {

#if (Esc_HAS_INT64 == 1)
        tempLane = 0U;
        for (j = 0U; j < 7U; j++)
        {
            tempLane |= block[(i * 8U) + (7U - j)];
            tempLane = (tempLane << 8U);
        }
        tempLane |= block[i * 8U];
#else
        tempLane.high = 0U;
        tempLane.low = 0U;

        for (j = 0U; j < 3U; j++)
        {
            tempLane.high |= block[(i*8U) + 7U - j];
            tempLane.high = (tempLane.high << 8U);
            tempLane.low |= block[(i * 8U) + 3U - j];
            tempLane.low = (tempLane.low << 8U);
        }
        tempLane.high |= block[(i * 8U) + 4U];
        tempLane.low |= block[i * 8U];
#endif

        /* xor message onto current state */
        EscSha3_LaneXor(&ctx->state[i], &tempLane, &ctx->state[i]);
    }
    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_VAR(tempLane);

}

static void
EscSha3_ConvertStateToBytes(
    const EscSha3_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_UINT8 i;

    for (i = 0U; i < digestLength; i++)
    {
#if (Esc_HAS_INT64 == 1)
        digest[i] = (Esc_UINT8) (ctx->state[i/8U] >> (8U * (i % 8U)));
#else
        if ((i % 8U) < 4U)
        {
            digest[i] = (Esc_UINT8) (ctx->state[i/8U].low >> (8U * (i % 8U)));
        }
        else
        {
            digest[i] = (Esc_UINT8) (ctx->state[i/8U].high >> (8U * ((i % 8U) - 4U)));
        }
#endif
    }
}

static void
EscSha3_Hash(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 i, x, y;
    EscSha3_Lane tempLane;
    EscSha3_Lane parity[5];

    /* convert message byte block into lanes */
    EscSha3_ConvertBytesToState(ctx, block);

    /* 24 rounds of the round function */
    for (i = 0U; i < 24U; i++)
    {
        /* Theta */
        for (x = 0U; x < 5U; x++)
        {
            /* compute parities for all columns by using whole lanes at once */
            EscSha3_LaneXor(&ctx->state[x], &ctx->state[x+5U], &parity[x]);
            EscSha3_LaneXor(&parity[x], &ctx->state[x+10U], &parity[x]);
            EscSha3_LaneXor(&parity[x], &ctx->state[x+15U], &parity[x]);
            EscSha3_LaneXor(&parity[x], &ctx->state[x+20U], &parity[x]);
        }
        for (x = 0U; x < 5U; x++)
        {
            EscSha3_LaneRotateL(&parity[EscSha3_Mod5[x+1U]], 1U, &tempLane);
            EscSha3_LaneXor(&parity[EscSha3_Mod5[x+4U]], &tempLane, &tempLane);
            for (y = 0U; y < 5U; y++)
            {
                EscSha3_LaneXor(&ctx->state[x + (y*5U)], &tempLane, &ctx->state[x + (y*5U)]);
            }
        }

        /* Rho + Pi */
        parity[1] = ctx->state[1];
        for (x = 0U; x < 24U; x++)
        {
            parity[0] = ctx->state[EscSha3_PiRearrange[x]];
            EscSha3_LaneRotateL(&parity[1], EscSha3_RhoRotationOffset[x], &tempLane);
            ctx->state[EscSha3_PiRearrange[x]] = tempLane;
            parity[1] = parity[0];
        }

        /* Chi */
        for (y = 0U; y <= 20U; y += 5U)
        {
            parity[0] = ctx->state[y];
            parity[1] = ctx->state[y + 1U];
            parity[2] = ctx->state[y + 2U];
            parity[3] = ctx->state[y + 3U];
            parity[4] = ctx->state[y + 4U];

            for (x = 0U; x < 5U; x++)
            {
                EscSha3_ComputeChi(&parity[x], &parity[EscSha3_Mod5[x + 1U]], &parity[EscSha3_Mod5[x + 2U]], &ctx->state[x + y]);
            }
        }

        /* Iota */
        EscSha3_LaneXor(&ctx->state[0], &EscSha3_RoundConstants[i], &ctx->state[0]);
    }

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_VAR(tempLane);
    Esc_CLEAR_LOCAL_ARRAY(parity);
}

static void
EscSha3_ApplyPadding(
    EscSha3_ContextT* ctx )
{
    if (ctx->numCachedBytes == (ctx->blockLen - 1U))
    {
        ctx->block[ctx->numCachedBytes] = 0x86U;
        ctx->numCachedBytes++;
    }

    if (ctx->numCachedBytes < (ctx->blockLen - 1U))
    {
        ctx->block[ctx->numCachedBytes] = 0x06U;
        ctx->numCachedBytes++;

        while(ctx->numCachedBytes < (ctx->blockLen - 1U))
        {
            ctx->block[ctx->numCachedBytes] = 0x00U;
            ctx->numCachedBytes++;
        }
        ctx->block[ctx->numCachedBytes] = 0x80U;
        ctx->numCachedBytes++;
    }

}

Esc_ERROR
EscSha3_Init(
    Esc_UINT8 shaFunction,
    EscSha3_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if (ctx == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        switch(shaFunction)
        {
            case EscSha3_224:
                ctx->digestLen = EscSha3_224_DIGEST_LEN;
                ctx->blockLen = EscSha3_224_BLOCK_SIZE;
                break;

            case EscSha3_256:
                ctx->digestLen = EscSha3_256_DIGEST_LEN;
                ctx->blockLen = EscSha3_256_BLOCK_SIZE;
                break;

            case EscSha3_384:
                ctx->digestLen = EscSha3_384_DIGEST_LEN;
                ctx->blockLen = EscSha3_384_BLOCK_SIZE;
                break;

            case EscSha3_512:
                ctx->digestLen = EscSha3_512_DIGEST_LEN;
                ctx->blockLen = EscSha3_512_BLOCK_SIZE;
                break;

            default:
                returnCode = Esc_INVALID_PARAMETER;
                break;
        }

        /* set state to zero */
        EscSha3_SetZero(ctx);

    }
    return returnCode;
}

Esc_ERROR
EscSha3_Update(
    EscSha3_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) && ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) )  /* Allow NULL pointer if length is zero */
    {
        Esc_UINT32 bytesLeft = messageLength;
        Esc_UINT32 dataPos = 0U;

        while (bytesLeft > 0U)
        {
            if ( (ctx->numCachedBytes == 0U) && (bytesLeft >= ctx->blockLen) )
            {
                /* Process full blocks directly from the input buffer */
                while (bytesLeft >= ctx->blockLen)
                {
                    EscSha3_Hash( ctx, &message[dataPos] );
                    dataPos += ctx->blockLen;
                    bytesLeft -= ctx->blockLen;
                }
            }
            else
            {
                Esc_UINT8 bytesToFill;

                /* fill block with remaining bytes */
                if ( bytesLeft >= ( (Esc_UINT32)ctx->blockLen - (Esc_UINT32)ctx->numCachedBytes ) )
                {
                    bytesToFill = ctx->blockLen - ctx->numCachedBytes;
                }
                else
                {
                    bytesToFill = (Esc_UINT8)bytesLeft;
                }

                bytesLeft -= bytesToFill;

                /* Copy the new bytes to the current block */
                while (bytesToFill > 0U)
                {
                    ctx->block[ctx->numCachedBytes] = message[dataPos];

                    ctx->numCachedBytes++;
                    dataPos++;
                    bytesToFill--;
                }

                /* if block is complete - hash */
                if (ctx->numCachedBytes == ctx->blockLen)
                {
                    EscSha3_Hash( ctx, ctx->block );
                    ctx->numCachedBytes = 0U;
                }
            }
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;

}

Esc_ERROR
EscSha3_Finish(
    EscSha3_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) || (digest == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (digestLength == 0U) || (digestLength > ctx->digestLen) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Pad message according to FIPS 202 Sec B.2 */
        EscSha3_ApplyPadding( ctx );

        /* Hash last block of message and padding */
        EscSha3_Hash( ctx, ctx->block );

        /* copy digest to output buffer */
        EscSha3_ConvertStateToBytes(ctx, digest, digestLength);

        /* Reset state */
        EscSha3_SetZero(ctx);

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha3_Calc(
    Esc_UINT8 shaFunction,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscSha3_ContextT ctx;

    returnCode = EscSha3_Init( shaFunction, &ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscSha3_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha3_Finish( &ctx, digest, digestLength );
        }
    }

    /* Zeroize SHA context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
