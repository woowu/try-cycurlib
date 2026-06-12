/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       SHA-384 and SHA-512 implementation.

   \see      FIPS-180-2 at
   csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

   $Rev: 4105 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "sha_512.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of schedule in words */
#define EscSha512MSched_NUM_WORDS 16U

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
    EscSha512_WordT w[EscSha512MSched_NUM_WORDS];
    /* Current t. */
    Esc_UINT8 t;
} EscSha512MSched_ContextT;

static void
EscSha512MSched_Init(
    EscSha512MSched_ContextT* sched,
    const Esc_UINT8 block[] );

static void
EscSha512MSched_NextW(
    EscSha512_WordT* out,
    EscSha512MSched_ContextT* sched );

static void
EscSha512_UpdateHash(
    EscSha512_ContextT* ctx );

static void
EscSha512_UpdateHashFast(
    EscSha512_ContextT* ctx,
    const Esc_UINT8 block[] );

static void
EscSha512_ApplyPadding(
    EscSha512_ContextT* ctx );

static void
EscSha512_Assign(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_Add(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_XOR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_ROTR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    Esc_UINT8 n );

static void
EscSha512_SHR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    Esc_UINT8 n );

static void
EscSha512_FuncCh(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    const EscSha512_WordT* y,
    const EscSha512_WordT* z );

static void
EscSha512_FuncMaj(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    const EscSha512_WordT* y,
    const EscSha512_WordT* z );

static void
EscSha512_UpSigma_0_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_UpSigma_1_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_LowSigma_0_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

static void
EscSha512_LowSigma_1_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/* Constants from section 4.2.3 */
#if Esc_HAS_INT64 == 1
#    define EscSha512_K                                                                             \
    {                                                                                               \
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, \
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, \
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, \
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, \
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, \
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, \
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, \
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, \
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL, \
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, \
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, \
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, \
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, \
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, \
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, \
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, \
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, \
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL, \
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, \
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL  \
    }
#else
#    define EscSha512_K                                                                                                         \
    {                                                                                                                           \
        { 0x428a2f98U, 0xd728ae22U }, { 0x71374491U, 0x23ef65cdU }, { 0xb5c0fbcfU, 0xec4d3b2fU }, { 0xe9b5dba5U, 0x8189dbbcU }, \
        { 0x3956c25bU, 0xf348b538U }, { 0x59f111f1U, 0xb605d019U }, { 0x923f82a4U, 0xaf194f9bU }, { 0xab1c5ed5U, 0xda6d8118U }, \
        { 0xd807aa98U, 0xa3030242U }, { 0x12835b01U, 0x45706fbeU }, { 0x243185beU, 0x4ee4b28cU }, { 0x550c7dc3U, 0xd5ffb4e2U }, \
        { 0x72be5d74U, 0xf27b896fU }, { 0x80deb1feU, 0x3b1696b1U }, { 0x9bdc06a7U, 0x25c71235U }, { 0xc19bf174U, 0xcf692694U }, \
        { 0xe49b69c1U, 0x9ef14ad2U }, { 0xefbe4786U, 0x384f25e3U }, { 0x0fc19dc6U, 0x8b8cd5b5U }, { 0x240ca1ccU, 0x77ac9c65U }, \
        { 0x2de92c6fU, 0x592b0275U }, { 0x4a7484aaU, 0x6ea6e483U }, { 0x5cb0a9dcU, 0xbd41fbd4U }, { 0x76f988daU, 0x831153b5U }, \
        { 0x983e5152U, 0xee66dfabU }, { 0xa831c66dU, 0x2db43210U }, { 0xb00327c8U, 0x98fb213fU }, { 0xbf597fc7U, 0xbeef0ee4U }, \
        { 0xc6e00bf3U, 0x3da88fc2U }, { 0xd5a79147U, 0x930aa725U }, { 0x06ca6351U, 0xe003826fU }, { 0x14292967U, 0x0a0e6e70U }, \
        { 0x27b70a85U, 0x46d22ffcU }, { 0x2e1b2138U, 0x5c26c926U }, { 0x4d2c6dfcU, 0x5ac42aedU }, { 0x53380d13U, 0x9d95b3dfU }, \
        { 0x650a7354U, 0x8baf63deU }, { 0x766a0abbU, 0x3c77b2a8U }, { 0x81c2c92eU, 0x47edaee6U }, { 0x92722c85U, 0x1482353bU }, \
        { 0xa2bfe8a1U, 0x4cf10364U }, { 0xa81a664bU, 0xbc423001U }, { 0xc24b8b70U, 0xd0f89791U }, { 0xc76c51a3U, 0x0654be30U }, \
        { 0xd192e819U, 0xd6ef5218U }, { 0xd6990624U, 0x5565a910U }, { 0xf40e3585U, 0x5771202aU }, { 0x106aa070U, 0x32bbd1b8U }, \
        { 0x19a4c116U, 0xb8d2d0c8U }, { 0x1e376c08U, 0x5141ab53U }, { 0x2748774cU, 0xdf8eeb99U }, { 0x34b0bcb5U, 0xe19b48a8U }, \
        { 0x391c0cb3U, 0xc5c95a63U }, { 0x4ed8aa4aU, 0xe3418acbU }, { 0x5b9cca4fU, 0x7763e373U }, { 0x682e6ff3U, 0xd6b2b8a3U }, \
        { 0x748f82eeU, 0x5defb2fcU }, { 0x78a5636fU, 0x43172f60U }, { 0x84c87814U, 0xa1f0ab72U }, { 0x8cc70208U, 0x1a6439ecU }, \
        { 0x90befffaU, 0x23631e28U }, { 0xa4506cebU, 0xde82bde9U }, { 0xbef9a3f7U, 0xb2c67915U }, { 0xc67178f2U, 0xe372532bU }, \
        { 0xca273eceU, 0xea26619cU }, { 0xd186b8c7U, 0x21c0c207U }, { 0xeada7dd6U, 0xcde0eb1eU }, { 0xf57d4f7fU, 0xee6ed178U }, \
        { 0x06f067aaU, 0x72176fbaU }, { 0x0a637dc5U, 0xa2c898a6U }, { 0x113f9804U, 0xbef90daeU }, { 0x1b710b35U, 0x131c471bU }, \
        { 0x28db77f5U, 0x23047d84U }, { 0x32caab7bU, 0x40c72493U }, { 0x3c9ebe0aU, 0x15c9bebcU }, { 0x431d67c4U, 0x9c100d4cU }, \
        { 0x4cc5d4beU, 0xcb3e42b6U }, { 0x597f299cU, 0xfc657e2aU }, { 0x5fcb6fabU, 0x3ad6faecU }, { 0x6c44198cU, 0x4a475817U }  \
    }
#endif

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** out =  x */
static void
EscSha512_Assign(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
#if Esc_HAS_INT64 == 1
    *out = *x;
#else
    out->high = x->high;
    out->low = x->low;
#endif
}

/** out = out + x */
static void
EscSha512_Add(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
#if Esc_HAS_INT64 == 1
    *out += *x;
#else

    /* check if x.low + out.low > 0xffffffff */
    if ( out->low > (0xffffffffU - x->low) )
    {
        /* The low word will overflow, add carry before */
        out->high++;
    }
    out->low += x->low;
    out->high += x->high;
#endif
}

/** out = out EXOR x */
static void
EscSha512_XOR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
#if Esc_HAS_INT64 == 1
    *out ^= *x;
#else
    out->high ^= x->high;
    out->low ^= x->low;
#endif
}

/** Right shift */
static void
EscSha512_SHR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    Esc_UINT8 n )
{
    Esc_ASSERT( n < 32U );
#if Esc_HAS_INT64 == 1
    *out = (*x) >> n;
#else
    out->high = (x->high) >> n;
    out->low = ( x->high << (32U - n) ) | ( (x->low) >> n );
#endif
}

/** Circular right rotation, as defined in function ROTR of section 3.2 point 4. */
static void
EscSha512_ROTR(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    Esc_UINT8 n )
{
    Esc_ASSERT( (n != 32U) && (n < 64U) );

#if Esc_HAS_INT64 == 1
    *out = ( ( (*x) >> n ) | ( (*x) << (64U - n) ) );
#else

    if (n < 32U)
    {
        out->low = ( (x->low >> n) | ( x->high << (32U - n) ) );
        out->high = ( (x->high >> n) | ( x->low << (32U - n) ) );
    }
    else
    {
        /* n>32 , n==32 is not possible and would violate MISRA-C */
        /* We swap the two words */
        Esc_UINT8 m = n - 32U;
        out->high = ( (x->low >> m) | ( x->high << (32U - m) ) );
        out->low = ( (x->high >> m) | ( x->low << (32U - m) ) );
    }

#endif
}

/** Logical function Ch of sec. 4.1.3 */
static void
EscSha512_FuncCh(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    const EscSha512_WordT* y,
    const EscSha512_WordT* z )
{
#if Esc_HAS_INT64 == 1
    *out = ( (*x) & (*y) ) ^ ( ( ~(*x) ) & (*z) );
#else
    out->high = (x->high & y->high) ^ ( ( ~(x->high) ) & z->high );
    out->low = (x->low & y->low) ^ ( ( ~(x->low) ) & z->low );
#endif
}

/** Logical function Maj of sec. 4.1.3 */
static void
EscSha512_FuncMaj(
    EscSha512_WordT* out,
    const EscSha512_WordT* x,
    const EscSha512_WordT* y,
    const EscSha512_WordT* z )
{
#if Esc_HAS_INT64 == 1
    *out = ( (*x) & (*y) ) ^ ( (*x) & (*z) ) ^ ( (*y) & (*z) );
#else
    out->high = (x->high & y->high) ^ (x->high & z->high) ^ (y->high & z->high);
    out->low = (x->low & y->low) ^ (x->low & z->low) ^ (y->low & z->low);
#endif
}

/** Logical function capital sigma from 0 to 512 of sec. 4.1.3 */
static void
EscSha512_UpSigma_0_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
    EscSha512_WordT tmp;

    EscSha512_ROTR( out, x, 28U );

    EscSha512_ROTR( &tmp, x, 34U );
    EscSha512_XOR( out, &tmp );

    EscSha512_ROTR( &tmp, x, 39U );
    EscSha512_XOR( out, &tmp );
}

/** Logical function capital sigma from 1 to 512 of sec. 4.1.3 */
static void
EscSha512_UpSigma_1_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
    EscSha512_WordT tmp;

    EscSha512_ROTR( out, x, 14U );

    EscSha512_ROTR( &tmp, x, 18U );
    EscSha512_XOR( out, &tmp );

    EscSha512_ROTR( &tmp, x, 41U );
    EscSha512_XOR( out, &tmp );
}

/** Logical function small sigma from 0 to 512 of sec. 4.1.3 */
static void
EscSha512_LowSigma_0_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
    EscSha512_WordT tmp;

    EscSha512_ROTR( out, x, 1U );

    EscSha512_ROTR( &tmp, x, 8U );
    EscSha512_XOR( out, &tmp );

    EscSha512_SHR( &tmp, x, 7U );
    EscSha512_XOR( out, &tmp );
}

/** Logical function small sigma from 1 to 512 of sec. 4.1.3 */
static void
EscSha512_LowSigma_1_512(
    EscSha512_WordT* out,
    const EscSha512_WordT* x )
{
    EscSha512_WordT tmp;

    EscSha512_ROTR( out, x, 19U );

    EscSha512_ROTR( &tmp, x, 61U );
    EscSha512_XOR( out, &tmp );

    EscSha512_SHR( &tmp, x, 6U );
    EscSha512_XOR( out, &tmp );
}

static void
EscSha512MSched_Init(
    EscSha512MSched_ContextT* sched,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 i;

    sched->t = 0U;

    /* W_0 .. W_15 is M_0..M-15, see sec. 6.2.2 step 1 */
    for (i = 0U; i < EscSha512MSched_NUM_WORDS; i++)
    {
        Esc_UINT8 offset;
#if Esc_HAS_INT64 == 1
        offset = (Esc_UINT8)(8U * i);
        sched->w[i] = ( ( (Esc_UINT64)block[offset] ) << 56 ) |
            ( ( (Esc_UINT64)block[offset + 1U] ) << 48 ) |
            ( ( (Esc_UINT64)block[offset + 2U] ) << 40 ) |
            ( ( (Esc_UINT64)block[offset + 3U] ) << 32 ) |
            ( ( (Esc_UINT64)block[offset + 4U] ) << 24 ) |
            ( ( (Esc_UINT64)block[offset + 5U] ) << 16 ) |
            ( ( (Esc_UINT64)block[offset + 6U] ) << 8 ) |
            ( (Esc_UINT64)block[offset + 7U] );
#else
        offset = (Esc_UINT8)(8U * i);
        sched->w[i].high = ( ( (Esc_UINT32)block[offset] ) << 24 ) |
            ( ( (Esc_UINT32)block[offset + 1U] ) << 16 ) |
            ( ( (Esc_UINT32)block[offset + 2U] ) << 8 ) |
            ( (Esc_UINT32)block[offset + 3U] );

        sched->w[i].low = ( ( (Esc_UINT32)block[offset + 4U] ) << 24 ) |
            ( ( (Esc_UINT32)block[offset + 5U] ) << 16 ) |
            ( ( (Esc_UINT32)block[offset + 6U] ) << 8 ) |
            ( (Esc_UINT32)block[offset + 7U] );
#endif
    }
}

static void
EscSha512MSched_NextW(
    EscSha512_WordT* out,
    EscSha512MSched_ContextT* sched )
{
    Esc_UINT8 curT;

    /* W_t 6.2.2 step 1 */

    curT = sched->t;

    if (curT < 16U)
    {
        EscSha512_Assign( out, &sched->w[curT] );
    }
    else                        /* sched->t >= 16U */
    {   /* we calculate the indexes. The number -x is congruent to +(16-x) in |F_16 */
        Esc_UINT8 iw_2 = (Esc_UINT8)( curT + (16U - 2U) ) & 0x0fU;    /* Index of W_t-2 */
        Esc_UINT8 iw_7 = (Esc_UINT8)( curT + (16U - 7U) ) & 0x0fU;    /* Index of W_t-7 */
        Esc_UINT8 iw_15 = (Esc_UINT8)( curT + (16U - 15U) ) & 0x0fU;  /* Index of W_t-15 */
        Esc_UINT8 iw_16 = curT & 0x0fU; /* Index of W_t-16, and also t%16 */
        EscSha512_WordT* W;
        EscSha512_WordT tmp;

        W = sched->w;

        EscSha512_LowSigma_1_512( out, &W[iw_2] );

        EscSha512_Add( out, &W[iw_7] );

        EscSha512_LowSigma_0_512( &tmp, &W[iw_15] );
        EscSha512_Add( out, &tmp );

        EscSha512_Add( out, &W[iw_16] );

        EscSha512_Assign( &W[iw_16], out );      /* the next W_t-1 */
    }

    sched->t++;                 /* point to next t */
}

/** Padding according to section 5.1.2 */
static void
EscSha512_ApplyPadding(
    EscSha512_ContextT* ctx )
{
    const Esc_UINT8 PAD_LENGTH_SIZE = 16U;  /* Size of the length in the padding in byte. (We keep the first 3 byte always zero) */
    Esc_UINT32 lengthBits;

    Esc_ASSERT( ctx->blockLen < EscSha512_BLOCK_BYTES );

    /* Append a 0x10 */
    ctx->block[ctx->blockLen] = 0x80U;
    ctx->blockLen++;
    if (ctx->blockLen == EscSha512_BLOCK_BYTES)
    {
        EscSha512_UpdateHash( ctx );
    }

    /* Check if there is enough space for the length. If not, fill the
       current block with zeros and hash it */
    if ( ctx->blockLen > (EscSha512_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        while (ctx->blockLen < EscSha512_BLOCK_BYTES)
        {
            ctx->block[ctx->blockLen] = 0U;
            ctx->blockLen++;
        }

        EscSha512_UpdateHash( ctx );
    }

    /* Fill the block with zeros, except the last bytes for the length */
    while ( ctx->blockLen < (EscSha512_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        ctx->block[ctx->blockLen] = 0U;
        ctx->blockLen++;
    }

    /* Append the length in bits */
    lengthBits = ctx->totalLen;
    /* The length in the format
       0 | 0 | 0 | 0 | 0 | 0 | 0 |
       0 | 0 | 0 | b31..b29 | b28..b21 | b20..b13 | b12..b5 | b4..b0 000 */
    /* b4..b0 */
    ctx->block[EscSha512_BLOCK_BYTES - 1U] = (Esc_UINT8)( ( (Esc_UINT8)(lengthBits & 0x1fU) ) << 3 );
    lengthBits >>= 5;

    /* b12..b5 */
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 1U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b20..b13 */
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 2U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b28..b21 */
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 3U] = (Esc_UINT8)(lengthBits & 0xffU);
    lengthBits >>= 8;

    /* b31..b29 */
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 4U] = (Esc_UINT8)(lengthBits & 0xffU);
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 5U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 6U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 7U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 8U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 9U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 10U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 11U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 12U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 13U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 14U] = 0U;
    ctx->block[(EscSha512_BLOCK_BYTES - 1U) - 15U] = 0U;

    ctx->blockLen += PAD_LENGTH_SIZE;

    Esc_ASSERT( ctx->blockLen == EscSha512_BLOCK_BYTES );
}

/**
Hashes this single hash block.  The blockLen must be EscSha512_BLOCK_BYTES;
Does the inner loop of section 6.3.2.
*/
static void
EscSha512_UpdateHashFast(
    EscSha512_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    static const EscSha512_WordT K[] = EscSha512_K; /* Constants from section 4.2.3 */
    const Esc_UINT8* msg;
    EscSha512_WordT* H;
    EscSha512MSched_ContextT sched;
    Esc_UINT8 t;
    EscSha512_WordT a, b, c, d, e, f, g, h;
    EscSha512_WordT T1, T2;
    EscSha512_WordT tmp;

    msg = block;
    H = ctx->hash;

    /* Step 1 */
    EscSha512MSched_Init( &sched, msg );

    /* Step 2 */
    EscSha512_Assign( &a, &H[0] );
    EscSha512_Assign( &b, &H[1] );
    EscSha512_Assign( &c, &H[2] );
    EscSha512_Assign( &d, &H[3] );
    EscSha512_Assign( &e, &H[4] );
    EscSha512_Assign( &f, &H[5] );
    EscSha512_Assign( &g, &H[6] );
    EscSha512_Assign( &h, &H[7] );

    /* Step 3 */
    for (t = 0U; t <= 79U; t++)
    {
        /* T1 = h + sigma(e) + ch(e,f,g)+Kt+Wt */
        EscSha512_UpSigma_1_512( &T1, &e );    /* T1 = sigma(e) */
        EscSha512_Add( &T1, &h );    /* T1 = h + sigma(e) */
        EscSha512_FuncCh( &tmp, &e, &f, &g );
        EscSha512_Add( &T1, &tmp );    /* T1 = h + sigma(e) + ch(e,f,g) */
        EscSha512_Add( &T1, &K[t] );      /* T1 = h + sigma(e) + ch(e,f,g) + Kt */
        EscSha512MSched_NextW( &tmp, &sched );
        EscSha512_Add( &T1, &tmp );    /* T1 = h + sigma(e) + ch(e,f,g) + Kt + Wt */

        /* T2 = sigma(a) + maj(a,b,c) */
        EscSha512_UpSigma_0_512( &T2, &a );
        EscSha512_FuncMaj( &tmp, &a, &b, &c );
        EscSha512_Add( &T2, &tmp );

        EscSha512_Assign( &h, &g );
        EscSha512_Assign( &g, &f );
        EscSha512_Assign( &f, &e );

        EscSha512_Assign( &e, &d );
        EscSha512_Add( &e, &T1 );

        EscSha512_Assign( &d, &c );
        EscSha512_Assign( &c, &b );
        EscSha512_Assign( &b, &a );
        EscSha512_Assign( &a, &T1 );
        EscSha512_Add( &a, &T2 );
    }

    /* Step 4 */
    EscSha512_Add( &H[0], &a );
    EscSha512_Add( &H[1], &b );
    EscSha512_Add( &H[2], &c );
    EscSha512_Add( &H[3], &d );
    EscSha512_Add( &H[4], &e );
    EscSha512_Add( &H[5], &f );
    EscSha512_Add( &H[6], &g );
    EscSha512_Add( &H[7], &h );

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
EscSha512_UpdateHash(
    EscSha512_ContextT* ctx )
{
    Esc_ASSERT( ctx->blockLen == EscSha512_BLOCK_BYTES );

    EscSha512_UpdateHashFast( ctx, ctx->block );

    ctx->blockLen = 0U;
}

/***********************************************************************
 ***********************************************************************
 **** Exported functions
 ***********************************************************************
 ***********************************************************************/
Esc_ERROR
EscSha512_Init(
    Esc_BOOL isSha384,
    EscSha512_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 i;
    const Esc_UINT8 HASH_SIZE = 8U;
    static const EscSha512_WordT INITIAL_HASH_SHA384[8] =
    {
#if Esc_HAS_INT64 == 1
        0xcbbb9d5dc1059ed8ULL,
        0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL,
        0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL,
        0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL,
        0x47b5481dbefa4fa4ULL
#else
        { 0xcbbb9d5dU, 0xc1059ed8U },
        { 0x629a292aU, 0x367cd507U },
        { 0x9159015aU, 0x3070dd17U },
        { 0x152fecd8U, 0xf70e5939U },
        { 0x67332667U, 0xffc00b31U },
        { 0x8eb44a87U, 0x68581511U },
        { 0xdb0c2e0dU, 0x64f98fa7U },
        { 0x47b5481dU, 0xbefa4fa4U }
#endif
    };

    static const EscSha512_WordT INITIAL_HASH_SHA512[8] =
    {
#if Esc_HAS_INT64 == 1
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL
#else
        { 0x6a09e667U, 0xf3bcc908U },
        { 0xbb67ae85U, 0x84caa73bU },
        { 0x3c6ef372U, 0xfe94f82bU },
        { 0xa54ff53aU, 0x5f1d36f1U },
        { 0x510e527fU, 0xade682d1U },
        { 0x9b05688cU, 0x2b3e6c1fU },
        { 0x1f83d9abU, 0xfb41bd6bU },
        { 0x5be0cd19U, 0x137e2179U }
#endif
    };

    if (ctx != Esc_NULL_PTR)
    {
        ctx->blockLen = 0U;
        ctx->totalLen = 0U;

        if (isSha384)
        {
            /* Set initial hash value Sec. 5.3.2 */
            for (i = 0U; i < HASH_SIZE; i++)
            {
#if Esc_HAS_INT64 == 1
                ctx->hash[i] = INITIAL_HASH_SHA384[i];
#else
                ctx->hash[i].high = INITIAL_HASH_SHA384[i].high;
                ctx->hash[i].low = INITIAL_HASH_SHA384[i].low;
#endif
            }

            ctx->digestLen = EscSha384_DIGEST_LEN;
        }
        else
        {
            /* Set initial hash value Sec. 5.3.2 */
            for (i = 0U; i < HASH_SIZE; i++)
            {
#if Esc_HAS_INT64 == 1
                ctx->hash[i] = INITIAL_HASH_SHA512[i];
#else
                ctx->hash[i].high = INITIAL_HASH_SHA512[i].high;
                ctx->hash[i].low = INITIAL_HASH_SHA512[i].low;
#endif
            }

            ctx->digestLen = EscSha512_DIGEST_LEN;
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha512_Update(
    EscSha512_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) )       /* Allow NULL pointer iff length is zero */
    {
        Esc_UINT32 bytesLeft = messageLength;
        Esc_UINT32 dataPos = 0U;

        while (bytesLeft > 0U)
        {
            if ( (ctx->blockLen == 0U) && (bytesLeft >= EscSha512_BLOCK_BYTES) )
            {
                Esc_UINT32 numFullBlocks = bytesLeft / EscSha512_BLOCK_BYTES;
                /* The number of bytes we process with UpdateHashFast() */
                Esc_UINT32 fullBlockBytes = numFullBlocks * EscSha512_BLOCK_BYTES;

                bytesLeft -= fullBlockBytes;
                ctx->totalLen += fullBlockBytes;

                while ( dataPos <= (messageLength - EscSha512_BLOCK_BYTES) )
                {
                    EscSha512_UpdateHashFast( ctx, &message[dataPos] );
                    dataPos += EscSha512_BLOCK_BYTES;
                }

                /* blockLen remains unchanged */
                Esc_ASSERT( ctx->blockLen == 0U );
            }
            else
            {
                Esc_UINT8 bytesToFill;
                /* fill block with remaining bytes, blockLen is now smaller than EscSha512_BLOCK_BYTES */
                if ( bytesLeft >= ( (Esc_UINT32)EscSha512_BLOCK_BYTES - (Esc_UINT32)ctx->blockLen ) )
                {
                    bytesToFill = EscSha512_BLOCK_BYTES - ctx->blockLen;
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
                if (ctx->blockLen == EscSha512_BLOCK_BYTES)
                {
                    EscSha512_UpdateHash( ctx );
                }
            }
        }

        Esc_ASSERT( ctx->blockLen < EscSha512_BLOCK_BYTES );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha512_Finish(
    EscSha512_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;
    Esc_UINT8 shift = 0U;
#if Esc_HAS_INT64 == 1
    Esc_UINT64 h = 0U;
#else
    Esc_UINT32 h = 0U;
#endif /* Esc_HAS_INT64 */

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
        /* Pad data according to Sec. 5.1.2 */
        EscSha512_ApplyPadding( ctx );

        /* Hash last full block */
        EscSha512_UpdateHash( ctx );

        /* Copy digest back */
        for (i = 0U; i < digestLength; i++)
        {
#if Esc_HAS_INT64 == 1
            if ((i & 0x07U) == 0U)
            {
                h = ctx->hash[i >> 3U];
                shift = 56U;
            }
            digest[i] = (Esc_UINT8)((h >> shift) & 0xFFU);
            shift -= 8U;
#else
            if ((i & 0x07U) == 0U)
            {
                h = ctx->hash[i >> 3U].high;
                shift = 24U;
            }

            if ((i & 0x07U) == 0x04U)
            {
                h = ctx->hash[i >> 3U].low;
                shift = 24U;
            }

            digest[i] = (Esc_UINT8)((h >> shift) & 0xFFU);
            shift -= 8U;
#endif /* Esc_HAS_INT64 */
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscSha512_Calc(
    Esc_BOOL isSha384,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscSha512_ContextT ctx;

    /* init() checks only for NULL pointers.
     * Since this cannot happen here, it is safe to ignore the return code */
    (void)EscSha512_Init( isSha384, &ctx );

    /* Parameter test is already done in the underlying functions */
    returnCode = EscSha512_Update( &ctx, message, messageLength );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscSha512_Finish( &ctx, digest, digestLength );
    }

    /* Zeroize SHA context as it may contain secrets */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
