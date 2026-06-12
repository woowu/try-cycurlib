/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-1 implementation (FIPS-180-2 resp. RFC 2202 compliant)

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "sha_1.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of schedule in words. */
#define EscSha1MSched_NUM_WORDS 16U

/** Circular right rotation, as defined in function ROTL of section 3.2 point 4. */
#define EscSha1_ROTL( x, n ) ( ( (x) << (n) ) | ( (x) >> ( 32U - (n) ) ) )

/** Logical function Ch of sec. 4.1.1. */
#define EscSha1_FuncCh( x, y, z ) ( (z) ^ ( (x) & ( (y) ^ (z) ) ) )

/** Logical function Maj of sec. 4.1.1 */
#define EscSha1_FuncMaj( x, y, z ) ( ( (x) & (y) ) | ( (z) & ( (x) ^ (y) ) ) )

/** Logical function Parity of sec. 4.1.1 */
#define EscSha1_FuncParity( x, y, z ) ( (x) ^ (y) ^ (z) )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
/** Message schedule context according to sec. 6.1.2 step 1. */
typedef struct
{
    /**
    W_t. The array keeps the last 16 Wt.
    In the beginning w[0] = W_0, w[1] = W_1, etc.
    For t= 16, w[0] = W_16; t=17, w[1] = W-17, etc.
    */
    Esc_UINT32 w[EscSha1MSched_NUM_WORDS];
    /* Current t. */
    Esc_UINT8 t;
} EscSha1MSched_ContextT;

static void
EscSha1MSched_Init(
    EscSha1MSched_ContextT* sched,
    const Esc_UINT8 block[] );

static Esc_UINT32
EscSha1MSched_NextW(
    EscSha1MSched_ContextT* sched );

static void
EscSha1_UpdateHash(
    EscSha1_ContextT* ctx );

static void
EscSha1_UpdateHashFast(
    EscSha1_ContextT* ctx,
    const Esc_UINT8 block[] );

static void
EscSha1_ApplyPadding(
    EscSha1_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static void
EscSha1MSched_Init(
    EscSha1MSched_ContextT* sched,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 i;

    sched->t = 0U;

    /* W_0 .. W_15 is M_0..M-15, see sec. 6.1.2 step 1 */
    for (i = 0U; i < EscSha1MSched_NUM_WORDS; i++)
    {
        Esc_UINT8 offset;

        offset = (Esc_UINT8)(4U * i);
        sched->w[i] = ( ( (Esc_UINT32)block[offset] ) << 24 ) |
            ( ( (Esc_UINT32)block[offset + 1U] ) << 16 ) |
            ( ( (Esc_UINT32)block[offset + 2U] ) << 8 ) |
            ( (Esc_UINT32)block[offset + 3U] );
    }
}

static Esc_UINT32
EscSha1MSched_NextW(
    EscSha1MSched_ContextT* sched )
{
    Esc_UINT32 ret;
    Esc_UINT8 curT;

    /* W_t 6.1.2 step 1 */
    curT = sched->t;

    if (curT < 16U)
    {
        ret = sched->w[curT];
    }
    else                        /* sched->t >= 16U */
    {   /* we calculate the indexes. The number -x is congruent to +(16-x) in |F_16 */
        Esc_UINT8 iw_3 = (Esc_UINT8)( curT + (16U - 3U) ) & 0x0fU;   /* Index of W_t-3 */
        Esc_UINT8 iw_8 = (Esc_UINT8)( curT + (16U - 8U) ) & 0x0fU;   /* Index of W_t-8 */
        Esc_UINT8 iw_14 = (Esc_UINT8)( curT + (16U - 14U) ) & 0x0fU; /* Index of W_t-14 */
        Esc_UINT8 iw_16 = curT & 0x0fU; /* Index of W_t-16, and also t%16 */
        const Esc_UINT32* W;
        Esc_UINT32 rotArg;

        W = sched->w;

        rotArg = W[iw_3] ^ W[iw_8] ^ W[iw_14] ^ W[iw_16];

        ret = EscSha1_ROTL( rotArg, 1U );

        sched->w[iw_16] = ret;    /* the next W_t-1 */
    }

    sched->t++;                 /* point to next t */

    return ret;
}

/** Padding according to section 5.1.1 */
static void
EscSha1_ApplyPadding(
    EscSha1_ContextT* ctx )
{
    const Esc_UINT8 PAD_LENGTH_SIZE = 8U;   /* Size of the length in the padding in byte. (We keep the first 3 byte always zero) */
    Esc_UINT32 lengthBits;

    Esc_ASSERT( ctx->blockLen < EscSha1_BLOCK_BYTES );

    /* Append a 0x10. */
    ctx->block[ctx->blockLen] = 0x80U;
    ctx->blockLen++;
    if (ctx->blockLen == EscSha1_BLOCK_BYTES)
    {
        EscSha1_UpdateHash( ctx );
    }

    /* Check if there is enough space for the length. If not, fill the
       current block with zeros and hash it. */
    if ( ctx->blockLen > (EscSha1_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        while (ctx->blockLen < EscSha1_BLOCK_BYTES)
        {
            ctx->block[ctx->blockLen] = 0U;
            ctx->blockLen++;
        }

        EscSha1_UpdateHash( ctx );
    }

    /* Fill the block with zeros, except the last bytes for the length. */
    while ( ctx->blockLen < (EscSha1_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        ctx->block[ctx->blockLen] = 0U;
        ctx->blockLen++;
    }

    /* Append the length in bits. */
    lengthBits = ctx->totalLen;
    /* The length in the format 0 | 0 | 0 | b31..b29 | b28..b21 | b20..b13 | b12..b5 | b4..b0 000 */
    /* b4..b0 */
    ctx->block[EscSha1_BLOCK_BYTES - 1U] = (Esc_UINT8)( ( (Esc_UINT8)(lengthBits & 0x1fU) ) << 3 );
    lengthBits >>= 5;

    /* b12..b5 */
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 1U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b20..b13 */
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 2U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b28..b21 */
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 3U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b31..b29 */
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 4U] = (Esc_UINT8)(lengthBits & 0xffU);
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 5U] = 0U;
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 6U] = 0U;
    ctx->block[(EscSha1_BLOCK_BYTES - 1U) - 7U] = 0U;

    ctx->blockLen += PAD_LENGTH_SIZE;

    Esc_ASSERT( ctx->blockLen == EscSha1_BLOCK_BYTES );
}

/**
Hashes this single hash block.  The blockLen must be EscSha1_BLOCK_BYTES;
Does the inner loop of section 6.1.2.
*/
static void
EscSha1_UpdateHashFast(
    EscSha1_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    /* Constants from section 4.2.1 */
    static const Esc_UINT32 K[] = { 0x5a827999U, 0x6ed9eba1U, 0x8f1bbcdcU, 0xca62c1d6U };
    const Esc_UINT8* msg;
    Esc_UINT32* H;
    EscSha1MSched_ContextT sched;
    Esc_UINT8 t;
    Esc_UINT32 a, b, c, d, e;
    Esc_UINT32 T;

    msg = block;
    H = ctx->hash;

    /* Step 1 */
    EscSha1MSched_Init( &sched, msg );

    /* Step 2 */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    /* Step 3 */
    /* 0<=t<=19 */
    for (t = 0U; t <= 19U; t++)
    {
        T = EscSha1_ROTL( a, 5U ) + EscSha1_FuncCh( b, c, d ) + e + K[0] + EscSha1MSched_NextW( &sched );

        e = d;
        d = c;
        c = EscSha1_ROTL( b, 30U );
        b = a;
        a = T;
    }

    /* 20<=t<=39 */
    for (; t <= 39U; t++)
    {
        T = EscSha1_ROTL( a, 5U ) + EscSha1_FuncParity( b, c, d ) + e + K[1] + EscSha1MSched_NextW( &sched );

        e = d;
        d = c;
        c = EscSha1_ROTL( b, 30U );
        b = a;
        a = T;
    }

    /* 40<=t<=59 */
    for (; t <= 59U; t++)
    {
        T = EscSha1_ROTL( a, 5U ) + EscSha1_FuncMaj( b, c, d ) + e + K[2] + EscSha1MSched_NextW( &sched );

        e = d;
        d = c;
        c = EscSha1_ROTL( b, 30U );
        b = a;
        a = T;
    }

    /* 60<=t<=79 */
    for (; t <= 79U; t++)
    {
        T = EscSha1_ROTL( a, 5U ) + EscSha1_FuncParity( b, c, d ) + e + K[3] + EscSha1MSched_NextW( &sched );

        e = d;
        d = c;
        c = EscSha1_ROTL( b, 30U );
        b = a;
        a = T;
    }

    /* Step 4 */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;

    /* Reset blocklen */
    ctx->blockLen = 0U;

    /* Zeroize Message schedule context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(sched);
}

/**
Fast hashing of a single hash block.  The ctx->blockLen must be EscSha256_BLOCK_BYTES;
Does the inner loop of section 6.2.2.
*/
static void
EscSha1_UpdateHash(
    EscSha1_ContextT* ctx )
{
    Esc_ASSERT( ctx->blockLen == EscSha1_BLOCK_BYTES );

    EscSha1_UpdateHashFast( ctx, ctx->block );

    ctx->blockLen = 0U;
}

/***********************************************************************
 ***********************************************************************
 **** Exported functions
 ***********************************************************************
 ***********************************************************************/
Esc_ERROR
EscSha1_Init(
    EscSha1_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 i;
    const Esc_UINT8 HASH_SIZE = 5U;
    static const Esc_UINT32 INITIAL_HASH[5] =
    {
        0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U
    };

    if (ctx != Esc_NULL_PTR)
    {
        /* Set initial hash value Sec. 5.3.2 */
        for (i = 0U; i < HASH_SIZE; i++)
        {
            ctx->hash[i] = INITIAL_HASH[i];
        }

        ctx->blockLen = 0U;
        ctx->totalLen = 0U;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha1_Update(
    EscSha1_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) )       /* Allow NULL pointer if length is zero */
    {
        Esc_UINT32 bytesLeft = messageLength;
        Esc_UINT32 dataPos = 0U;

        while (bytesLeft > 0U)
        {
            if ( (ctx->blockLen == 0U) && (bytesLeft >= EscSha1_BLOCK_BYTES) )
            {
                Esc_UINT32 numFullBlocks = bytesLeft / EscSha1_BLOCK_BYTES;
                /* The number of bytes we process with UpdateHashFast() */
                Esc_UINT32 fullBlockBytes = numFullBlocks * EscSha1_BLOCK_BYTES;

                bytesLeft -= fullBlockBytes;
                ctx->totalLen += fullBlockBytes;

                while ( dataPos <= (messageLength - EscSha1_BLOCK_BYTES) )
                {
                    EscSha1_UpdateHashFast( ctx, &message[dataPos] );
                    dataPos += EscSha1_BLOCK_BYTES;
                }

                /* blockLen remains unchanged */
                Esc_ASSERT( ctx->blockLen == 0U );
            }
            else
            {
                Esc_UINT8 bytesToFill;
                /* fill block with remaining bytes, blockLen is now smaller than EscSha1_BLOCK_BYTES */
                if ( bytesLeft >= ( (Esc_UINT32)EscSha1_BLOCK_BYTES - (Esc_UINT32)ctx->blockLen ) )
                {
                    bytesToFill = EscSha1_BLOCK_BYTES - ctx->blockLen;
                }
                else
                {
                    bytesToFill = (Esc_UINT8)bytesLeft;
                }

                ctx->totalLen += bytesToFill;
                bytesLeft -= bytesToFill;
                /* Copy the new bytes to the current block */
                while (bytesToFill > 0U)
                {
                    ctx->block[ctx->blockLen] = message[dataPos];

                    ctx->blockLen++;
                    dataPos++;
                    bytesToFill--;
                }

                /* if block is complete - hash */
                if (ctx->blockLen == EscSha1_BLOCK_BYTES)
                {
                    EscSha1_UpdateHash( ctx );
                }
            }
        }

        Esc_ASSERT( ctx->blockLen < EscSha1_BLOCK_BYTES );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha1_Finish(
    EscSha1_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;
    Esc_UINT8 shift = 0U;
    Esc_UINT32 h = 0U;

    if ( (ctx == Esc_NULL_PTR) || (digest == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (digestLength == 0U) || (digestLength > EscSha1_DIGEST_LEN) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Pad data according to Sec. 5.1.1 */
        EscSha1_ApplyPadding( ctx );

        /* Hash last full block */
        EscSha1_UpdateHash( ctx );

        /* Copy digest back */
        for (i = 0U; i < digestLength; i++)
        {
            if ((i & 0x03U) == 0U)
            {
                h = ctx->hash[i >> 2U];
                shift = 24U;
            }

            digest[i] = (Esc_UINT8)((h >> shift) & 0xFFU);
            shift -= 8U;
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha1_Calc(
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscSha1_ContextT ctx;

    /* Parameter test is already done in the underlying functions */
    returnCode = EscSha1_Init( &ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscSha1_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha1_Finish( &ctx, digest, digestLength );
        }
    }

    /* Zeroize SHA context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
