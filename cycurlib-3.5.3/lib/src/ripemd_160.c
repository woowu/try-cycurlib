/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       RIPEMD-160 implementation according to:
   ISO/IEC FDIS 10118-3 Final Draft 2003, Chapter 7
   algorithm from:
   - Hans Dobbertin, Antoon Bosselaers, Bart Preneel:
   "RIPEMD-160:A Strengthened Version of RIPEMD"

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "ripemd_160.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/* the five basic functions G_1_15(), G_16_31(), G_32_47(), G_48_63(), G_64_79() */
#define G_1_15( x, y, z ) ( (x) ^ (y) ^ (z) )
#define G_16_31( x, y, z ) ( ( (x) & (y) ) | ( ~(x) & (z) ) )
#define G_32_47( x, y, z ) ( ( (x) | ~(y) ) ^ (z) )
#define G_48_63( x, y, z ) ( ( (x) & (z) ) | ( (y) & ~(z) ) )
#define G_64_79( x, y, z ) ( (x) ^ ( (y) | ~(z) ) )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
static void
EscRipemd160_Split2Bytes(
    Esc_UINT8 ptr[],
    Esc_UINT32 value );

static Esc_UINT32
EscRipemd160_CombineBytes(
    const Esc_UINT8 octets[] );

static void
EscRipemd160_Process(
    EscRipemd160_ContextT* ctx,
    const Esc_UINT8 byte_64_block[] );

static Esc_UINT32
EscRipemd160_RoundIncrement(
    Esc_UINT16 y,
    Esc_UINT32 bbb,
    Esc_UINT32 ccc,
    Esc_UINT32 ddd );

static Esc_UINT32
EscRipemd160_RotateLeft(
    Esc_UINT32 x,
    Esc_UINT8 n );

static void
EscRipemd160_IncrementUint64(
    Esc_UINT32* hi,
    Esc_UINT32* lo,
    Esc_UINT32 increment );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*****************************************************************
 Increments a 64 bit value whose low byte is in *lo and high byte
 is in *hi by the value increment.
 *****************************************************************/
static void
EscRipemd160_IncrementUint64(
    Esc_UINT32* hi,
    Esc_UINT32* lo,
    Esc_UINT32 increment )
{
    /* (a+b)>0xffffffff => a > 0xffffffff - b */
    if ( *lo > (0xffffffffU - increment) )
    {
        (*hi)++;
    }

    *lo += increment;
}

/*****************************************************************
 Rotates the value by n bits
 *****************************************************************/
static Esc_UINT32
EscRipemd160_RotateLeft(
    Esc_UINT32 x,
    Esc_UINT8 n )
{
    Esc_UINT32 ret;

    ret = x << n;
    ret |= (x & 0xFFFFFFFFU) >> (32U - n);

    return ret;
}

/*****************************************************************
 * split a 32-Bit word to 4 Bytes little endian *
 *****************************************************************/
static void
EscRipemd160_Split2Bytes(
    Esc_UINT8 ptr[],
    Esc_UINT32 value )
{
    Esc_UINT8 i;
    for (i = 0U; i <= 3U; i++)
    {
        ptr[i] = (Esc_UINT8)( ( value >> (i * 8U) ) & 0xffU );
    }
}

/*****************************************************************
 Combines 4 octets in little endian format two a Esc_UINT32
 *****************************************************************/
static Esc_UINT32
EscRipemd160_CombineBytes(
    const Esc_UINT8 octets[] )
{
    Esc_UINT32 v;
    v = ( ( (Esc_UINT32)octets[3] << 24 ) |
          ( (Esc_UINT32)octets[2] << 16 ) |
          ( (Esc_UINT32)octets[1] << 8 ) |
          ( (Esc_UINT32)octets[0] )
          );

    return v;
}

/********************************
 * initialize RIPEMD-160 values *
 ********************************/
Esc_ERROR
EscRipemd160_Init(
    EscRipemd160_ContextT* ctx )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        /* length = 0 */
        ctx->total_bytes_Lo = 0U;
        ctx->total_bytes_Hi = 0U;

        /* Initialize values */
        ctx->vector[0] = 0x67452301U;
        ctx->vector[1] = 0xEFCDAB89U;
        ctx->vector[2] = 0x98BADCFEU;
        ctx->vector[3] = 0x10325476U;
        ctx->vector[4] = 0xC3D2E1F0U;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/*******************************
 Selects the next round increment
 *******************************/
static Esc_UINT32
EscRipemd160_RoundIncrement(
    Esc_UINT16 y,
    Esc_UINT32 bbb,
    Esc_UINT32 ccc,
    Esc_UINT32 ddd )
{
    Esc_UINT32 inc;

    switch (y)
    {
        case 0:
            inc = G_1_15( bbb, ccc, ddd );
            break;
        case 1:
            inc = G_16_31( bbb, ccc, ddd );
            break;
        case 2:
            inc = G_32_47( bbb, ccc, ddd );
            break;
        case 3:
            inc = G_48_63( bbb, ccc, ddd );
            break;
        default:
            inc = G_64_79( bbb, ccc, ddd );
            break;
    }

    return inc;
}

/*******************************
 * processes one 64 byte block *
 *******************************/
static void
EscRipemd160_Process(
    EscRipemd160_ContextT* ctx,
    const Esc_UINT8 byte_64_block[] )
{
    Esc_UINT32 aa = 0U;
    Esc_UINT32 bb = 0U;
    Esc_UINT32 cc = 0U;
    Esc_UINT32 dd = 0U;
    Esc_UINT32 ee = 0U;
    Esc_UINT32 aaa = 0U;
    Esc_UINT32 bbb = 0U;
    Esc_UINT32 ccc = 0U;
    Esc_UINT32 ddd = 0U;
    Esc_UINT32 eee = 0U;
    Esc_UINT32 t;
    Esc_UINT32 W[16];
    Esc_UINT8 PM[16];

    /* counting variables */
    Esc_UINT16 i;
    Esc_UINT16 j;
    Esc_UINT16 x;
    Esc_UINT16 y;

    /* shift values t_i and t'_iused in round functions */
    /* see ISO/IEC FDIS 10118-3, chapter 7.1.4, p. 5+6 */
    static const Esc_UINT8 S[160] =
    {
        11U, 14U, 15U, 12U, 5U, 8U, 7U, 9U, 11U, 13U, 14U, 15U, 6U, 7U, 9U, 8U,
        7U, 6U, 8U, 13U, 11U, 9U, 7U, 15U, 7U, 12U, 15U, 9U, 11U, 7U, 13U, 12U,
        11U, 13U, 6U, 7U, 14U, 9U, 13U, 15U, 14U, 8U, 13U, 6U, 5U, 12U, 7U, 5U,
        11U, 12U, 14U, 15U, 14U, 15U, 9U, 8U, 9U, 14U, 5U, 6U, 8U, 6U, 5U, 12U,
        9U, 15U, 5U, 11U, 6U, 8U, 13U, 12U, 5U, 12U, 13U, 14U, 11U, 8U, 5U, 6U,
        8U, 9U, 9U, 11U, 13U, 15U, 15U, 5U, 7U, 7U, 8U, 11U, 14U, 14U, 12U, 6U,
        9U, 13U, 15U, 7U, 12U, 8U, 9U, 11U, 7U, 7U, 12U, 7U, 6U, 15U, 13U, 11U,
        9U, 7U, 15U, 11U, 8U, 6U, 6U, 14U, 12U, 13U, 5U, 14U, 13U, 13U, 7U, 5U,
        15U, 5U, 8U, 11U, 14U, 14U, 6U, 14U, 6U, 9U, 12U, 9U, 12U, 5U, 15U, 8U,
        8U, 5U, 12U, 9U, 12U, 5U, 14U, 6U, 8U, 13U, 6U, 5U, 15U, 13U, 11U, 11U
    };

    /* constant words used in round functions G_1_15 - G_64_79 */
    /* see ISO/IEC FDIS 10118-3, chapter 7.1.4, p. 5 */
    static const Esc_UINT32 CO[10] =
    {
        0UL,
        0x5a827999UL,
        0x6ed9eba1UL,
        0x8f1bbcdcUL,
        0xa953fd4eUL,
        0x50a28be6UL,
        0x5c4dd124UL,
        0x6d703ef3UL,
        0x7a6d76e9UL,
        0UL
    };

    /* Permutation table */
    static const Esc_UINT8 WL[16] =
    {
        7U, 4U, 13U, 1U, 10U, 6U, 15U, 3U,
        12U, 0U, 9U, 5U, 2U, 14U, 11U, 8U
    };

    /* concatenate 64 bytes to 16 x 32-bit words */
    for (i = 0U; i < 16U; i++)
    {
        W[i] = EscRipemd160_CombineBytes( &byte_64_block[i * 4U] );
        PM[i] = (Esc_UINT8)i;
    }

    /* ripe-md-160 rounds */
    i = 0U;
    for (j = 80U; j <= 160U; j += 80U)
    {
        /* Initialize working variables aaa..eee */
        aaa = ctx->vector[0];
        bbb = ctx->vector[1];
        ccc = ctx->vector[2];
        ddd = ctx->vector[3];
        eee = ctx->vector[4];

        while ( i < j )
        {
            /* ISO/IEC FDIS 10118-3, chapter 7.3, step 4a + 4c */
            y = i >> 4;
            x = i & 0xfU;
            aaa += W[PM[x]] + CO[y];

            /* select round function */
            if (i >= 80U)
            {
                y = 9U - y;
            }

            aaa += EscRipemd160_RoundIncrement( y, bbb, ccc, ddd );

            /* calculate permutation */
            PM[x] = WL[PM[x]];

            /* ISO/IEC FDIS 10118-3, chapter 7.3, step 4b + 4d */
            t = eee;
            eee = ddd;
            ddd = EscRipemd160_RotateLeft( ccc, 10U );
            ccc = bbb;
            bbb = EscRipemd160_RotateLeft( aaa, S[i] ) + t;
            aaa = t;
            i++;
        }

        if (j == 80U)
        {
            /* assign working variables for next iteration */
            aa = aaa;
            bb = bbb;
            cc = ccc;
            dd = ddd;
            ee = eee;

            for (t = 0U; t < 16U; t++)
            {
                PM[t] = (Esc_UINT8)( ( (9U * t) + 5U ) & 0xfU );
            }
        }
    }

    /* combine results of rounds */
    ddd += cc + ctx->vector[1];
    ctx->vector[1] = ctx->vector[2] + dd + eee;
    ctx->vector[2] = ctx->vector[3] + ee + aaa;
    ctx->vector[3] = ctx->vector[4] + aa + bbb;
    ctx->vector[4] = ctx->vector[0] + bb + ccc;
    ctx->vector[0] = ddd;
}

/*******************************************
 * update hash context for a chunk of data *
 *******************************************/
Esc_ERROR
EscRipemd160_Update(
    EscRipemd160_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    /* declarations */
    Esc_UINT32 left;                /* number of bytes left to process */
    Esc_UINT32 fill;                /* number of bytes to fill to a complete 64 byte block */
    Esc_UINT32 i;                   /* counting variable */
    Esc_UINT32 data_pos = 0U;

    /* parameter check */
    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) )       /* Allow NULL pointer if length is zero */
    {
        /* number of bytes left to process */
        left = ctx->total_bytes_Lo & 0x3FU;

        /* fill bytes remain to 64 byte block */
        fill = EscRipemd160_BLOCK_BYTES - left;

        /* total = total + messageLength */
        EscRipemd160_IncrementUint64( &ctx->total_bytes_Hi, &ctx->total_bytes_Lo, messageLength );

        /* if we have something in the buffer (left > 0) and  */
        /* the chunk has enough data to fill a 64 byte block (messageLength >= fill) */
        if ( (left > 0U) && (messageLength >= fill) )
        {
            /* fill buffer with data from new chunk */
            for (i = 0U; i < fill; i++)
            {
                ctx->buffer[left + i] = message[i];
            }

            /* process 64 byte buffer block */
            EscRipemd160_Process( ctx, ctx->buffer );

            /* move data pointer by fill */
            data_pos += fill;

            /* buffer is fully processed */
            left = 0U;
        }

        while ( (messageLength - data_pos) >= EscRipemd160_BLOCK_BYTES )
        {
            EscRipemd160_Process( ctx, &message[data_pos] );
            data_pos += EscRipemd160_BLOCK_BYTES;
        }

        /* if final bytes from message between 1..63 byte */
        /* append remainder to 64 byte into buffer resp. fill the empty buffer */
        for (i = 0U; i < (messageLength - data_pos); i++)
        {
            ctx->buffer[left + i] = message[data_pos + i];
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/****************************************
 * do final wrap-up and returns the hash *
 ****************************************/
Esc_ERROR
EscRipemd160_Finish(
    EscRipemd160_ContextT* ctx,
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT32 last;
    Esc_UINT32 padn;
    Esc_UINT8 msglen[8];
    Esc_UINT32 len1;
    Esc_UINT32 len2;
    Esc_UINT8 shift = 0U;
    Esc_UINT32 h = 0U;

    /* RIPEMD padding sequence */
    static const Esc_UINT8 rmd_padding[64] =
    {
        0x80U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };

    if ( (ctx == Esc_NULL_PTR) || (digest == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (digestLength == 0U) || (digestLength > EscRipemd160_DIGEST_LEN) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* divide length of data into bytes */
        /* ISO/IEC FDIS 10118-3, chapter 7.2, step 3 */
        len1 = ctx->total_bytes_Lo << 3;
        EscRipemd160_Split2Bytes( &msglen[0], len1 );
        len2 = (ctx->total_bytes_Lo >> 29) | (ctx->total_bytes_Hi << 3);
        EscRipemd160_Split2Bytes( &msglen[4], len2 );

        /* total = n x 64 bytes + last */
        /* 0 <= last < 64 */
        last = ctx->total_bytes_Lo & 0x3FU;

        /* number of padding zeros  */
        if (last < 56U)
        {
            padn = 56U - last;
        }
        else
        {
            padn = 120U - last;
        }

        /* update RIPEMD context with remaining buffer and padding to 64 bytes with bit sequence (1,0,...,0) */

        returnCode = EscRipemd160_Update( ctx, rmd_padding, padn );
        if (returnCode == Esc_NO_ERROR)
        {
            /* update RIPEMD context with total length */
            returnCode = EscRipemd160_Update( ctx, msglen, 8U );
            if (returnCode == Esc_NO_ERROR)
            {
                Esc_UINT8 i;
                /* assign final hash words */
                for (i = 0U; i < digestLength; i++)
                {
                    if ((i & 0x03U) == 0U)
                    {
                        h = ctx->vector[i >> 2U];
                        shift = 0U;
                    }

                    digest[i] = (Esc_UINT8)((h >> shift) & 0xFFU);
                    shift += 8U;
                }
            }
        }
    }

    /* successful */
    return returnCode;
}

/*****************************************
 * calculate and returns RIPEMD-160 hash *
 *****************************************/
Esc_ERROR
EscRipemd160_Calc(
    const Esc_UINT8 message[],      /* message for EscRipemd160_Calc calculation */
    Esc_UINT32 messageLength,       /* length of the message in bytes   */
    Esc_UINT8 digest[],
    Esc_UINT8 digestLength )
{
    Esc_ERROR returnCode;
    EscRipemd160_ContextT ctx;

    /* Parameter test is already done in the underlying functions */
    returnCode = EscRipemd160_Init( &ctx );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscRipemd160_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscRipemd160_Finish( &ctx, digest, digestLength );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
