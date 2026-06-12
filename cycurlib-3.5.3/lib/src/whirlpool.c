/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Whirlpool implementation according to P. Barreto, V. Rijmen,
   "The Whirlpool hashing function," First open NESSIE Workshop, Leuven, 2000.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "whirlpool.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of one hash block in bytes. */
#define EscWhirlpool_COLS 8U

/** Length of one hash block in bytes. */
#define EscWhirlpool_ROWS 8U

/** Number of bits per byte. */
#define EscWhirlpool_BITS_PER_BYTES 8U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
#if EscWhirlpool_8BIT_OPTIMIZATION == 0
static Esc_UINT8
EscWhirlpool_FieldMult(
    Esc_UINT8 a,
    Esc_UINT8 b );

#endif
static void
EscWhirlpool_Theta(
    Esc_UINT8 m1[] );

static void
EscWhirlpool_ApplyRho(
    Esc_UINT8 value[],
    const Esc_UINT8 parameter[] );

static void
EscWhirlpool_KeySchedule(
    Esc_UINT8 key[],
    Esc_UINT8 c[],
    Esc_UINT8 round );

static void
EscWhirlpool_ComputeW(
    Esc_UINT8 W[],
    const Esc_UINT8 hash[],
    const Esc_UINT8 block[] );

static void
EscWhirlpool_UpdateHashFast(
    EscWhirlpool_ContextT* ctx,
    const Esc_UINT8 block[] );

static void
EscWhirlpool_UpdateHash(
    EscWhirlpool_ContextT* ctx );

static void
EscWhirlpool_ApplyPadding(
    EscWhirlpool_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/
/** Whirlpool substitution box */
static const Esc_UINT8 EscWhirlpool_SBOX[256] =
{
    0x18U, 0x23U, 0xC6U, 0xE8U, 0x87U, 0xB8U, 0x01U, 0x4FU, 0x36U, 0xA6U, 0xd2U, 0xF5U, 0x79U, 0x6FU, 0x91U, 0x52U,
    0x60U, 0xBcU, 0x9BU, 0x8EU, 0xA3U, 0x0cU, 0x7BU, 0x35U, 0x1dU, 0xE0U, 0xd7U, 0xc2U, 0x2EU, 0x4BU, 0xFEU, 0x57U,
    0x15U, 0x77U, 0x37U, 0xE5U, 0x9FU, 0xF0U, 0x4AU, 0xdAU, 0x58U, 0xc9U, 0x29U, 0x0AU, 0xB1U, 0xA0U, 0x6BU, 0x85U,
    0xBdU, 0x5dU, 0x10U, 0xF4U, 0xcBU, 0x3EU, 0x05U, 0x67U, 0xE4U, 0x27U, 0x41U, 0x8BU, 0xA7U, 0x7dU, 0x95U, 0xd8U,
    0xFBU, 0xEEU, 0x7cU, 0x66U, 0xddU, 0x17U, 0x47U, 0x9EU, 0xCAU, 0x2dU, 0xBFU, 0x07U, 0xAdU, 0x5AU, 0x83U, 0x33U,
    0x63U, 0x02U, 0xAAU, 0x71U, 0xc8U, 0x19U, 0x49U, 0xd9U, 0xF2U, 0xE3U, 0x5BU, 0x88U, 0x9AU, 0x26U, 0x32U, 0xB0U,
    0xE9U, 0x0FU, 0xd5U, 0x80U, 0xBEU, 0xcdU, 0x34U, 0x48U, 0xFFU, 0x7AU, 0x90U, 0x5FU, 0x20U, 0x68U, 0x1AU, 0xAEU,
    0xB4U, 0x54U, 0x93U, 0x22U, 0x64U, 0xF1U, 0x73U, 0x12U, 0x40U, 0x08U, 0xc3U, 0xEcU, 0xdBU, 0xA1U, 0x8dU, 0x3dU,
    0x97U, 0x00U, 0xcFU, 0x2BU, 0x76U, 0x82U, 0xd6U, 0x1BU, 0xB5U, 0xAFU, 0x6AU, 0x50U, 0x45U, 0xF3U, 0x30U, 0xEFU,
    0x3FU, 0x55U, 0xA2U, 0xEAU, 0x65U, 0xBAU, 0x2FU, 0xc0U, 0xdEU, 0x1cU, 0xFdU, 0x4dU, 0x92U, 0x75U, 0x06U, 0x8AU,
    0xB2U, 0xE6U, 0x0EU, 0x1FU, 0x62U, 0xd4U, 0xA8U, 0x96U, 0xF9U, 0xc5U, 0x25U, 0x59U, 0x84U, 0x72U, 0x39U, 0x4cU,
    0x5EU, 0x78U, 0x38U, 0x8cU, 0xd1U, 0xA5U, 0xE2U, 0x61U, 0xB3U, 0x21U, 0x9cU, 0x1EU, 0x43U, 0xc7U, 0xFcU, 0x04U,
    0x51U, 0x99U, 0x6dU, 0x0dU, 0xFAU, 0xdFU, 0x7EU, 0x24U, 0x3BU, 0xABU, 0xcEU, 0x11U, 0x8FU, 0x4EU, 0xB7U, 0xEBU,
    0x3cU, 0x81U, 0x94U, 0xF7U, 0xB9U, 0x13U, 0x2cU, 0xd3U, 0xE7U, 0x6EU, 0xc4U, 0x03U, 0x56U, 0x44U, 0x7FU, 0xA9U,
    0x2AU, 0xBBU, 0xc1U, 0x53U, 0xdcU, 0x0BU, 0x9dU, 0x6cU, 0x31U, 0x74U, 0xF6U, 0x46U, 0xAcU, 0x89U, 0x14U, 0xE1U,
    0x16U, 0x3AU, 0x69U, 0x09U, 0x70U, 0xB6U, 0xd0U, 0xEdU, 0xccU, 0x42U, 0x98U, 0xA4U, 0x28U, 0x5cU, 0xF8U, 0x86U,
};

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if EscWhirlpool_8BIT_OPTIMIZATION == 0
/* multiply two field elements in GF(2^8) with polynomial x^8 + x^4 + x^3 + x^2 + 1 */
static Esc_UINT8
EscWhirlpool_FieldMult(
    Esc_UINT8 a,
    Esc_UINT8 b )
{
    /* define the GF2^8 irreducible field polynomial 0x11D = x^8 + x^4 + x^3 + x^2 + 1,
       => 0x11DU & 0xFFU */
    static const Esc_UINT8 GF2_8_FIELD_POLYNOMIAL = 0x1DU;
    Esc_UINT8 b_;

    /* overflow value */
    Esc_UINT8 val = 0U;
    b_ = b;
    while (0U != a)
    {
        if ( 0U != (a & 0x01U) )
        {
            val ^= b_;
        }
        /* divide a by x */
        a >>= 1;
        /* multiply b by x */
        if ( 0U != (b_ & 0x80U) )
        {
            b_ = ( (Esc_UINT8)(b_ << 1) ) ^ GF2_8_FIELD_POLYNOMIAL;
        }
        else
        {
            b_ = (Esc_UINT8)(b_ << 1);
        }
    }

    return val;
}

/** Compute the theta function according to section 3.4
 * multiply matrix with matrix C = ((U V)(V U)) in the field GF(2)^8 */
/* multiply two matrices */
static void
EscWhirlpool_Theta(
    Esc_UINT8 m1[] )
{
    /** Circulant matrix C used in the linear diffusion function of section 3.4 */
    static const Esc_UINT8 C_DATA[EscWhirlpool_BLOCK_BYTES] =
    {
        0x01U, 0x01U, 0x04U, 0x01U, 0x08U, 0x05U, 0x02U, 0x09U,
        0x09U, 0x01U, 0x01U, 0x04U, 0x01U, 0x08U, 0x05U, 0x02U,
        0x02U, 0x09U, 0x01U, 0x01U, 0x04U, 0x01U, 0x08U, 0x05U,
        0x05U, 0x02U, 0x09U, 0x01U, 0x01U, 0x04U, 0x01U, 0x08U,
        0x08U, 0x05U, 0x02U, 0x09U, 0x01U, 0x01U, 0x04U, 0x01U,
        0x01U, 0x08U, 0x05U, 0x02U, 0x09U, 0x01U, 0x01U, 0x04U,
        0x04U, 0x01U, 0x08U, 0x05U, 0x02U, 0x09U, 0x01U, 0x01U,
        0x01U, 0x04U, 0x01U, 0x08U, 0x05U, 0x02U, 0x09U, 0x01U,
    };

    Esc_UINT8 temp[EscWhirlpool_BLOCK_BYTES];
    Esc_UINT8 i;
    Esc_UINT8 j;
    Esc_UINT8 k;

    for (i = 0U; i <= 7U; ++i)
    {
        for (j = 0U; j <= 7U; ++j)
        {
            temp[(EscWhirlpool_ROWS * i) + j] = 0U;
            for (k = 0U; k <= 7U; ++k)
            {
                temp[(EscWhirlpool_ROWS * i) + j] ^= EscWhirlpool_FieldMult( m1[(EscWhirlpool_ROWS * i) + k], C_DATA[(EscWhirlpool_ROWS * k) + j] );
            }
        }
    }

    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        m1[i] = temp[i];
    }
}

#else

/** Compute the theta function according to section 3.4 applying optimization for 8-bit processors
 * multiply matrix with matrix C in the field GF(2)^8 */
static void
EscWhirlpool_Theta(
    Esc_UINT8 m1[] )
{
    /** Lookup table used instead of the circulant matrix C in the 8bit processor optimization  */
    static const Esc_UINT8 X_TABLE[256] =
    {
        0x00U, 0x02U, 0x04U, 0x06U, 0x08U, 0x0aU, 0x0cU, 0x0eU, 0x10U, 0x12U, 0x14U, 0x16U, 0x18U, 0x1aU, 0x1cU, 0x1eU,
        0x20U, 0x22U, 0x24U, 0x26U, 0x28U, 0x2aU, 0x2cU, 0x2eU, 0x30U, 0x32U, 0x34U, 0x36U, 0x38U, 0x3aU, 0x3cU, 0x3eU,
        0x40U, 0x42U, 0x44U, 0x46U, 0x48U, 0x4aU, 0x4cU, 0x4eU, 0x50U, 0x52U, 0x54U, 0x56U, 0x58U, 0x5aU, 0x5cU, 0x5eU,
        0x60U, 0x62U, 0x64U, 0x66U, 0x68U, 0x6aU, 0x6cU, 0x6eU, 0x70U, 0x72U, 0x74U, 0x76U, 0x78U, 0x7aU, 0x7cU, 0x7eU,
        0x80U, 0x82U, 0x84U, 0x86U, 0x88U, 0x8aU, 0x8cU, 0x8eU, 0x90U, 0x92U, 0x94U, 0x96U, 0x98U, 0x9aU, 0x9cU, 0x9eU,
        0xa0U, 0xa2U, 0xa4U, 0xa6U, 0xa8U, 0xaaU, 0xacU, 0xaeU, 0xb0U, 0xb2U, 0xb4U, 0xb6U, 0xb8U, 0xbaU, 0xbcU, 0xbeU,
        0xc0U, 0xc2U, 0xc4U, 0xc6U, 0xc8U, 0xcaU, 0xccU, 0xceU, 0xd0U, 0xd2U, 0xd4U, 0xd6U, 0xd8U, 0xdaU, 0xdcU, 0xdeU,
        0xe0U, 0xe2U, 0xe4U, 0xe6U, 0xe8U, 0xeaU, 0xecU, 0xeeU, 0xf0U, 0xf2U, 0xf4U, 0xf6U, 0xf8U, 0xfaU, 0xfcU, 0xfeU,
        0x1dU, 0x1fU, 0x19U, 0x1bU, 0x15U, 0x17U, 0x11U, 0x13U, 0x0dU, 0x0fU, 0x09U, 0x0bU, 0x05U, 0x07U, 0x01U, 0x03U,
        0x3dU, 0x3fU, 0x39U, 0x3bU, 0x35U, 0x37U, 0x31U, 0x33U, 0x2dU, 0x2fU, 0x29U, 0x2bU, 0x25U, 0x27U, 0x21U, 0x23U,
        0x5dU, 0x5fU, 0x59U, 0x5bU, 0x55U, 0x57U, 0x51U, 0x53U, 0x4dU, 0x4fU, 0x49U, 0x4bU, 0x45U, 0x47U, 0x41U, 0x43U,
        0x7dU, 0x7fU, 0x79U, 0x7bU, 0x75U, 0x77U, 0x71U, 0x73U, 0x6dU, 0x6fU, 0x69U, 0x6bU, 0x65U, 0x67U, 0x61U, 0x63U,
        0x9dU, 0x9fU, 0x99U, 0x9bU, 0x95U, 0x97U, 0x91U, 0x93U, 0x8dU, 0x8fU, 0x89U, 0x8bU, 0x85U, 0x87U, 0x81U, 0x83U,
        0xbdU, 0xbfU, 0xb9U, 0xbbU, 0xb5U, 0xb7U, 0xb1U, 0xb3U, 0xadU, 0xafU, 0xa9U, 0xabU, 0xa5U, 0xa7U, 0xa1U, 0xa3U,
        0xddU, 0xdfU, 0xd9U, 0xdbU, 0xd5U, 0xd7U, 0xd1U, 0xd3U, 0xcdU, 0xcfU, 0xc9U, 0xcbU, 0xc5U, 0xc7U, 0xc1U, 0xc3U,
        0xfdU, 0xffU, 0xf9U, 0xfbU, 0xf5U, 0xf7U, 0xf1U, 0xf3U, 0xedU, 0xefU, 0xe9U, 0xebU, 0xe5U, 0xe7U, 0xe1U, 0xe3U,
    };

    Esc_UINT8 temp[EscWhirlpool_BLOCK_BYTES];
    Esc_UINT8 t0;
    Esc_UINT8 t1;
    Esc_UINT8 t2;
    Esc_UINT8 t3;
    Esc_UINT8 t4;
    Esc_UINT8 i;

    /* compute rows i iteratively */
    for (i = 0U; i <= 7U; ++i)
    {
        const Esc_UINT8 index = (Esc_UINT8)(EscWhirlpool_ROWS * i);

        t0 = m1[index + 1U] ^ m1[index + 3U] ^ m1[index + 5U] ^ m1[index + 7U];
        t1 = m1[index + 3U] ^ m1[index + 6U];
        t2 = m1[index + 5U] ^ m1[index];
        t3 = m1[index + 7U] ^ m1[index + 2U];
        t4 = m1[index + 1U] ^ m1[index + 4U];

        /* store even elements of row in temp */
        temp[index] = m1[index] ^ t0 ^ X_TABLE[m1[index + 2U] ^ X_TABLE[t1 ^ X_TABLE[t4]]];
        temp[index + 2U] = m1[index + 2U] ^ t0 ^ X_TABLE[m1[index + 4U] ^ X_TABLE[t2 ^ X_TABLE[t1]]];
        temp[index + 4U] = m1[index + 4U] ^ t0 ^ X_TABLE[m1[index + 6U] ^ X_TABLE[t3 ^ X_TABLE[t2]]];
        temp[index + 6U] = m1[index + 6U] ^ t0 ^ X_TABLE[m1[index] ^ X_TABLE[t4 ^ X_TABLE[t3]]];

        t0 = m1[index] ^ m1[index + 2U] ^ m1[index + 4U] ^ m1[index + 6U];
        t1 = m1[index + 4U] ^ m1[index + 7U];
        t2 = m1[index + 6U] ^ m1[index + 1U];
        t3 = m1[index] ^ m1[index + 3U];
        t4 = m1[index + 2U] ^ m1[index + 5U];

        temp[index + 1U] = m1[index + 1U] ^ t0 ^ X_TABLE[m1[index + 3U] ^ X_TABLE[t1 ^ X_TABLE[t4]]];
        temp[index + 3U] = m1[index + 3U] ^ t0 ^ X_TABLE[m1[index + 5U] ^ X_TABLE[t2 ^ X_TABLE[t1]]];
        temp[index + 5U] = m1[index + 5U] ^ t0 ^ X_TABLE[m1[index + 7U] ^ X_TABLE[t3 ^ X_TABLE[t2]]];
        temp[index + 7U] = m1[index + 7U] ^ t0 ^ X_TABLE[m1[index + 1U] ^ X_TABLE[t4 ^ X_TABLE[t3]]];
    }

    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        m1[i] = temp[i];
    }
}

#endif

/** Compute the rho function according to section 3.7,
 * i.e. rho[parameter](value) */
static void
EscWhirlpool_ApplyRho(
    Esc_UINT8 value[],
    const Esc_UINT8 parameter[] )
{
    Esc_UINT8 temp[EscWhirlpool_BLOCK_BYTES];
    Esc_UINT8 pos;
    Esc_UINT8 i;
    Esc_UINT8 j;

    /* Apply gamma function according to section 3.2, i.e. SBox to each byte in value */
    for (pos = 0U; pos < EscWhirlpool_BLOCK_BYTES; ++pos)
    {
        value[pos] = EscWhirlpool_SBOX[value[pos]];
    }

    /* Apply pi function according to section 3.3: cyclical permutation b_i,j = a_(i-j)mod 8,j */
    for (i = 0U; i < EscWhirlpool_ROWS; ++i)
    {
        for (j = 0U; j < EscWhirlpool_COLS; ++j)
        {
            temp[(EscWhirlpool_ROWS * i) + j] = value[( EscWhirlpool_ROWS * ( ( (i - j) + EscWhirlpool_ROWS ) & 0x07U ) ) + j];
        }
    }
    /* Copy result back to value */
    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        value[i] = temp[i];
    }
    /* Apply theta function according to section 3.4, i.e. linear diffusion */
    EscWhirlpool_Theta( value );

    /* Apply sigma[parameter] according to section 3.5: key addition */
    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        value[i] = value[i] ^ parameter[i];
    }
}

/** Compute the key schedule function according to section 3.8 */
static void
EscWhirlpool_KeySchedule(
    Esc_UINT8 key[],
    Esc_UINT8 c[],
    Esc_UINT8 round )
{
    Esc_UINT8 j;
    /* Get next round constant */
    for (j = 0U; j <= 7U; ++j)
    {
        c[j] = EscWhirlpool_SBOX[( EscWhirlpool_ROWS * (round - 1U) ) + j];
    }

    EscWhirlpool_ApplyRho( key, c );
}

/**
Update Hash with a single block according to section 3.9.
The blockLen must be EscWhirlpool_BLOCK_BYTES.
*/
static void
EscWhirlpool_ComputeW(
    Esc_UINT8 W[],
    const Esc_UINT8 hash[],
    const Esc_UINT8 block[] )
{
    /* round key */
    Esc_UINT8 key[EscWhirlpool_BLOCK_BYTES];
    /* round constant */
    Esc_UINT8 c[EscWhirlpool_BLOCK_BYTES];
    Esc_UINT8 i;
    Esc_UINT8 round;

    /* Initialize constant c_i with 0U,
     * key = K_0 = current hash,
     * and W with data in block.
     * Compute the sigma function according to section 3.5 */
    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        c[i] = 0U;
        key[i] = hash[i];
        W[i] = block[i] ^ key[i];
    }

    /* Compute the 10 Whirlpool rounds, inner loop of section 3.9 */
    for (round = 1U; round <= 10U; ++round)
    {
        /* Get next round key and constant */
        EscWhirlpool_KeySchedule( key, c, round );
        /* Compute the rho function according to section 3.7 */
        EscWhirlpool_ApplyRho( W, key );
    }
}

/**
Update Hash with a single block. The blockLen must be EscWhirlpool_BLOCK_BYTES.
*/
static void
EscWhirlpool_UpdateHashFast(
    EscWhirlpool_ContextT* ctx,
    const Esc_UINT8 block[] )
{
    Esc_UINT8 W[EscWhirlpool_BLOCK_BYTES];
    Esc_UINT8 i;

    /* Miyaguchi-Preneel compression function according to section 3.11 */
    EscWhirlpool_ComputeW( W, ctx->hash, block );

    for (i = 0U; i < EscWhirlpool_BLOCK_BYTES; ++i)
    {
        ctx->hash[i] ^= W[i];
        ctx->hash[i] ^= block[i];
    }
}

/**
Hashing of the single hash block stored in the Whirlpool context.
The ctx->blockLen must be EscWhirlpool_BLOCK_BYTES.
*/
static void
EscWhirlpool_UpdateHash(
    EscWhirlpool_ContextT* ctx )
{
    EscWhirlpool_UpdateHashFast( ctx, ctx->block );

    ctx->blockLen = 0U;
}

/** Padding according to section 3.10 */
static void
EscWhirlpool_ApplyPadding(
    EscWhirlpool_ContextT* ctx )
{
    const Esc_UINT8 PAD_LENGTH_SIZE = 32U;
    Esc_UINT32 lengthBits;
    Esc_UINT8 i;
    Esc_ASSERT( ctx->blockLen < EscWhirlpool_BLOCK_BYTES );

    /* Append a '1'-bit. */
    ctx->block[ctx->blockLen] = 0x80U;
    ctx->blockLen++;
    if (ctx->blockLen == EscWhirlpool_BLOCK_BYTES)
    {
        EscWhirlpool_UpdateHash( ctx );
    }

    /* Check if there is enough space for the length. If not, fill the
       current block with zeros and hash it. */
    if ( ctx->blockLen > (EscWhirlpool_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        while (ctx->blockLen < EscWhirlpool_BLOCK_BYTES)
        {
            ctx->block[ctx->blockLen] = 0U;
            ctx->blockLen++;
        }

        EscWhirlpool_UpdateHash( ctx );
    }

    /* Fill the block with zeros, except the last bytes for the length. */
    while ( ctx->blockLen < (EscWhirlpool_BLOCK_BYTES - PAD_LENGTH_SIZE) )
    {
        ctx->block[ctx->blockLen] = 0U;
        ctx->blockLen++;
    }

    /* Append the length in bits. */
    lengthBits = ctx->totalLen * EscWhirlpool_BITS_PER_BYTES;

    /* The length in the format 0 | 0 | 0 | b31..b24 | b23..b16 | b15..b8 | b7..b0 */
    for (i = 0U; i < PAD_LENGTH_SIZE; i++)
    {
        ctx->block[(EscWhirlpool_BLOCK_BYTES - 1U) - i] = (Esc_UINT8)(lengthBits & 0xffU);
        lengthBits >>= 8;
    }
}

/***********************************************************************
 ***********************************************************************
 **** Exported functions
 ***********************************************************************
 ***********************************************************************/
Esc_ERROR
EscWhirlpool_Init(
    EscWhirlpool_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 i;

    if (ctx != Esc_NULL_PTR)
    {
        /* Set initial hash value Sec. 5.3.2 */
        for (i = 0U; i < EscWhirlpool_DIGEST_LEN; i++)
        {
            ctx->hash[i] = 0x00U;
        }

        ctx->blockLen = 0U;
        ctx->totalLen = 0U;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscWhirlpool_Update(
    EscWhirlpool_ContextT* ctx,
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
            if ( (ctx->blockLen == 0U) && (bytesLeft >= EscWhirlpool_BLOCK_BYTES) )
            {
                Esc_UINT32 numFullBlocks = bytesLeft / EscWhirlpool_BLOCK_BYTES;
                /* The number of bytes we process with UpdateHash() */
                Esc_UINT32 fullBlockBytes = numFullBlocks * EscWhirlpool_BLOCK_BYTES;

                bytesLeft -= fullBlockBytes;
                ctx->totalLen += fullBlockBytes;
                /* Update Hash blockwise for the full blocks */
                while ( dataPos <= (messageLength - EscWhirlpool_BLOCK_BYTES) )
                {
                    EscWhirlpool_UpdateHashFast( ctx, &message[dataPos] );
                    dataPos += EscWhirlpool_BLOCK_BYTES;
                }

                /* blockLen has to remain unchanged */
                Esc_ASSERT( ctx->blockLen == 0U );
            }
            else
            {
                Esc_UINT8 bytesToFill;
                /* fill block with remaining bytes, blockLen is now smaller than EscWhirlpool_BLOCK_BYTES */
                if ( bytesLeft >= ( (Esc_UINT32)EscWhirlpool_BLOCK_BYTES - (Esc_UINT32)ctx->blockLen ) )
                {
                    bytesToFill = EscWhirlpool_BLOCK_BYTES - ctx->blockLen;
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
                if (ctx->blockLen == EscWhirlpool_BLOCK_BYTES)
                {
                    /* Update Hash with bytes stored in ctx->block */
                    EscWhirlpool_UpdateHash( ctx );
                }
            }
        }

        Esc_ASSERT( ctx->blockLen < EscWhirlpool_BLOCK_BYTES );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscWhirlpool_Finish(
    EscWhirlpool_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;

    if ( (ctx == Esc_NULL_PTR) || (digest == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (digestLength == 0U) || (digestLength > EscWhirlpool_DIGEST_LEN) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Pad last block according to Sec. 3.10 */
        EscWhirlpool_ApplyPadding( ctx );
        /* Update Hash with the last block */
        EscWhirlpool_UpdateHash( ctx );

        /* Return Hash in digest */
        for (i = 0U; i < digestLength; i++)
        {
            digest[i] = ctx->hash[i];
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscWhirlpool_Calc(
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscWhirlpool_ContextT ctx;

    /* Parameter tests are already done in the underlying functions */
    returnCode = EscWhirlpool_Init( &ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscWhirlpool_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscWhirlpool_Finish( &ctx, digest, digestLength );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
