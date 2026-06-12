/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-224 and SHA-256 implementation also known as SHA-2.

   \see      FIPS-180-2 at
   csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "sha_256.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of schedule in words. */
#define EscSha2MSched_NUM_WORDS 16U

/** Circular right rotation, as defined in function ROTR of section 3.2 point 4. */
#define EscSha256_ROTR( x, n ) ( ( (x) >> (n) ) | ( (x) << ( 32U - (n) ) ) )

/** Logical function Ch of sec. 4.1.2 */
#define EscSha256_FuncCh( x, y, z ) ( (z) ^ ( (x) & ( (y) ^ (z) ) ) )

/** Logical function Maj of sec. 4.1.2 */
#define EscSha256_FuncMaj( x, y, z ) ( ( (x) & (y) ) | ( (z) & ( (x) ^ (y) ) ) )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
/** Message schedule context according to sec. 6.2.2 step 1 */
typedef struct
{
    /**
    W_t. The array keeps the last 16 Wt.
    In the beginning w[0] = W_0, w[1] = W_1, etc.
    For t= 16, w[0] = W_16; t=17, w[1] = W-17, etc.
    */
    Esc_UINT32 w[EscSha2MSched_NUM_WORDS];
    /* Current t. */
    Esc_UINT8 t;
} EscSha2MSched_ContextT;

static void
EscSha2MSched_Init(
    EscSha2MSched_ContextT* sched,
    const Esc_UINT8 block[] );

static Esc_UINT32
EscSha2MSched_NextW(
    EscSha2MSched_ContextT* sched );

static void
EscSha256_UpdateHash(
    EscSha256_ContextT* ctx );

static void
EscSha256_UpdateHashFast(
    EscSha256_ContextT* ctx,
    const Esc_UINT8 block[] );

static void
EscSha256_ApplyPadding(
    EscSha256_ContextT* ctx );

static Esc_UINT32
EscSha256_UpSigma_0_256(
    Esc_UINT32 x );

static Esc_UINT32
EscSha256_UpSigma_1_256(
    Esc_UINT32 x );

static Esc_UINT32
EscSha256_LowSigma_0_256(
    Esc_UINT32 x );

static Esc_UINT32
EscSha256_LowSigma_1_256(
    Esc_UINT32 x );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** Logical function capital sigma from 0 to 256 of sec. 4.1.2 */
static Esc_UINT32
EscSha256_UpSigma_0_256(
    Esc_UINT32 x )
{
    Esc_UINT32 ret;

    ret = EscSha256_ROTR( x, 2U );
    ret ^= EscSha256_ROTR( x, 13U );
    ret ^= EscSha256_ROTR( x, 22U );

    return ret;
}

/** Logical function capital sigma from 1 to 256 of sec. 4.1.2 */
static Esc_UINT32
EscSha256_UpSigma_1_256(
    Esc_UINT32 x )
{
    Esc_UINT32 ret;

    ret = EscSha256_ROTR( x, 6U );
    ret ^= EscSha256_ROTR( x, 11U );
    ret ^= EscSha256_ROTR( x, 25U );

    return ret;
}

/** Logical function small sigma from 0 to 256 of sec. 4.1.2 */
static Esc_UINT32
EscSha256_LowSigma_0_256(
    Esc_UINT32 x )
{
    Esc_UINT32 ret;

    ret = EscSha256_ROTR( x, 7U );
    ret ^= EscSha256_ROTR( x, 18U );
    ret ^= (x >> 3);

    return ret;
}

/** Logical function small sigma from 1 to 256 of sec. 4.1.2 */
static Esc_UINT32
EscSha256_LowSigma_1_256(
    Esc_UINT32 x )
{
    Esc_UINT32 ret;

    ret = EscSha256_ROTR( x, 17U );
    ret ^= EscSha256_ROTR( x, 19U );
    ret ^= (x >> 10);

    return ret;
}

static void
EscSha2MSched_Init(
    EscSha2MSched_ContextT* sched,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 i;

    sched->t = 0U;

    /* W_0 .. W_15 is M_0..M-15, see sec. 6.2.2 step 1 */
    for (i = 0U; i < EscSha2MSched_NUM_WORDS; i++)
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
EscSha2MSched_NextW(
    EscSha2MSched_ContextT* sched )
{
    Esc_UINT32 ret;
    Esc_UINT8 curT;

    /* W_t 6.2.2 step 1 */

    curT = sched->t;

    if (curT < 16U)
    {
        ret = sched->w[curT];
    }
    else                        /* sched->t >= 16U */
    {   /* we calculate the indexes. The number -x is congruent to +(16-x) in |F_16 */
        Esc_UINT8 iw_2 = (Esc_UINT8)( curT + (16U - 2U) ) & 0x0fU;    /* Index of W_t-2 */
        Esc_UINT8 iw_7 = (Esc_UINT8)( curT + (16U - 7U) ) & 0x0fU;    /* Index of W_t-7 */
        Esc_UINT8 iw_15 = (Esc_UINT8)( curT + (16U - 15U) ) & 0x0fU;  /* Index of W_t-15 */
        Esc_UINT8 iw_16 = curT & 0x0fU; /* Index of W_t-16, and also t%16 */
        Esc_UINT32* W;

        W = sched->w;

        ret = EscSha256_LowSigma_1_256( W[iw_2] ) + W[iw_7] + EscSha256_LowSigma_0_256( W[iw_15] ) + W[iw_16];

        W[iw_16] = ret;           /* the next W_t-1 */
    }

    sched->t++;                 /* point to next t */

    return ret;
}

/** Padding according to section 5.1.1 */
static void
EscSha256_ApplyPadding(
    EscSha256_ContextT* ctx )
{
    const Esc_UINT8 PAD_LENGTH_SIZE = 8U;   /* Size of the length in the padding in byte. (We keep the first 3 byte always zero) */
    Esc_UINT32 lengthBits;

    Esc_ASSERT( ctx->blockLen < EscSha256_BLOCK_BYTES );

    /* Append a 0x10 */
    ctx->block[ctx->blockLen] = 0x80U;
    ctx->blockLen++;
    if (ctx->blockLen == EscSha256_BLOCK_BYTES)
    {
        EscSha256_UpdateHash( ctx );
    }

    /* Check if there is enough space for the length. If not, fill the
       current block with zeros and hash it */
    if ( ctx->blockLen > (EscSha256_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        while (ctx->blockLen < EscSha256_BLOCK_BYTES)
        {
            ctx->block[ctx->blockLen] = 0U;
            ctx->blockLen++;
        }

        EscSha256_UpdateHash( ctx );
    }

    /* Fill the block with zeros, except the last bytes for the length */
    while ( ctx->blockLen < (EscSha256_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        ctx->block[ctx->blockLen] = 0U;
        ctx->blockLen++;
    }

    /* Append the length in bits */
    lengthBits = ctx->totalLen;
    /* The length in the format 0 | 0 | 0 | b31..b29 | b28..b21 | b20..b13 | b12..b5 | b4..b0 000 */
    /* b4..b0 */
    ctx->block[EscSha256_BLOCK_BYTES - 1U] = (Esc_UINT8)( ( (Esc_UINT8)(lengthBits & 0x1fU) ) << 3 );
    lengthBits >>= 5;

    /* b12..b5 */
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 1U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b20..b13 */
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 2U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b28..b21 */
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 3U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b31..b29 */
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 4U] = (Esc_UINT8)(lengthBits & 0xffU);
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 5U] = 0U;
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 6U] = 0U;
    ctx->block[(EscSha256_BLOCK_BYTES - 1U) - 7U] = 0U;

    ctx->blockLen += PAD_LENGTH_SIZE;

    Esc_ASSERT( ctx->blockLen == EscSha256_BLOCK_BYTES );
}

/**
Fast hashing of a single hash block.  The block length (not ctx->blockLen)
must be EscSha256_BLOCK_BYTES;
Does the inner loop of section 6.2.2.
ctx->blocklLen is not reset in this function.
*/
static void
EscSha256_UpdateHashFast(
    EscSha256_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    static const Esc_UINT32 K[] =  /* Constants from section 4.2.2 */
    {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    const Esc_UINT8* msg;
    Esc_UINT32* H;
    EscSha2MSched_ContextT sched;
    Esc_UINT8 t;
    Esc_UINT32 a, b, c, d, e, f, g, h;
    Esc_UINT32 T1, T2;

    msg = block;
    H = ctx->hash;

    /* Step 1 */
    EscSha2MSched_Init( &sched, msg );

    /* Step 2 */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    /* Step 3 */
    for (t = 0U; t <= 63U; t++)
    {
        T1 = h + EscSha256_UpSigma_1_256( e ) + EscSha256_FuncCh( e, f, g ) + K[t] + EscSha2MSched_NextW( &sched );    /* W_t */
        T2 = EscSha256_UpSigma_0_256( a ) + EscSha256_FuncMaj( a, b, c );

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* Step 4 */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;

    /* Zeroize Message schedule context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(sched);
}

/**
Fast hashing of a single hash block.  The ctx->blockLen must be EscSha256_BLOCK_BYTES;
Does the inner loop of section 6.2.2.
*/
static void
EscSha256_UpdateHash(
    EscSha256_ContextT* ctx )
{
    Esc_ASSERT( ctx->blockLen == EscSha256_BLOCK_BYTES );

    EscSha256_UpdateHashFast( ctx, ctx->block );

    ctx->blockLen = 0U;
}

/***********************************************************************
 ***********************************************************************
 **** Exported functions
 ***********************************************************************
 ***********************************************************************/
Esc_ERROR
EscSha256_Init(
    Esc_BOOL isSha224,
    EscSha256_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 i;
    const Esc_UINT8 HASH_SIZE = 8U;
    static const Esc_UINT32 initialHash224[8] =
    {
        0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U, 0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U
    };
    static const Esc_UINT32 initialHash256[8] =
    {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    if (ctx != Esc_NULL_PTR)
    {
        if (isSha224)
        {
            /* Set initial hash value Sec. 5.3.2 */
            for (i = 0U; i < HASH_SIZE; i++)
            {
                ctx->hash[i] = initialHash224[i];
            }

            ctx->digestLen = EscSha224_DIGEST_LEN;
        }
        else
        {
            /* Set initial hash value Sec. 5.3.2 */
            for (i = 0U; i < HASH_SIZE; i++)
            {
                ctx->hash[i] = initialHash256[i];
            }

            ctx->digestLen = EscSha256_DIGEST_LEN;
        }


        ctx->blockLen = 0U;
        ctx->totalLen = 0U;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha256_Update(
    EscSha256_ContextT* ctx,
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
            if ( (ctx->blockLen == 0U) && (bytesLeft >= EscSha256_BLOCK_BYTES) )
            {
                Esc_UINT32 numFullBlocks = bytesLeft / EscSha256_BLOCK_BYTES;
                /* The number of bytes we process with UpdateHashFast() */
                Esc_UINT32 fullBlockBytes = numFullBlocks * EscSha256_BLOCK_BYTES;

                bytesLeft -= fullBlockBytes;
                ctx->totalLen += fullBlockBytes;

                while ( dataPos <= (messageLength - EscSha256_BLOCK_BYTES) )
                {
                    EscSha256_UpdateHashFast( ctx, &message[dataPos] );
                    dataPos += EscSha256_BLOCK_BYTES;
                }

                /* blockLen remains unchanged */
                Esc_ASSERT( ctx->blockLen == 0U );
            }
            else
            {
                Esc_UINT8 bytesToFill;
                /* fill block with remaining bytes, blockLen is now smaller than EscSha256_BLOCK_BYTES */
                if ( bytesLeft >= ( (Esc_UINT32)EscSha256_BLOCK_BYTES - (Esc_UINT32)ctx->blockLen ) )
                {
                    bytesToFill = EscSha256_BLOCK_BYTES - ctx->blockLen;
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
                if (ctx->blockLen == EscSha256_BLOCK_BYTES)
                {
                    EscSha256_UpdateHash( ctx );
                }
            }
        }

        Esc_ASSERT( ctx->blockLen < EscSha256_BLOCK_BYTES );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha256_Finish(
    EscSha256_ContextT* ctx,
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
    else if ( (digestLength == 0U) || (digestLength > ctx->digestLen) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Pad data according to Sec. 5.1.1 */
        EscSha256_ApplyPadding( ctx );

        /* Hash last full block */
        EscSha256_UpdateHash( ctx );

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
EscSha256_Calc(
    Esc_BOOL isSha224,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscSha256_ContextT ctx;

    /* Parameter test is already done in the underlying functions */
    returnCode = EscSha256_Init( isSha224, &ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscSha256_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha256_Finish( &ctx, digest, digestLength );
        }
    }

    /* Zeroize SHA context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
