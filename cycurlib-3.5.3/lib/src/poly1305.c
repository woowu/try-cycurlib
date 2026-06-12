/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
 \file        poly1305.c

 \brief       Poly1305 implementation, according to RFC-7539.

 $Rev: 0001 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "poly1305.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
This function adds the 17 bytes in a with b and stores the result in a.

\param[in, out] a     Input and Output array.
\param[in] b          Input array.
*/
static void
EscPoly1305_Add(
    Esc_UINT8 a[17],
    const Esc_UINT8 b[17] );

/**
This function processes carry bits from multiplication and reduces the
value ar with modulo p = 2^130 -5 and stores the result in a.
This reduction will not take values smaller than 2p into account. This will
be done in the final reduction during the EscPoly1305_FinalReduction() call.

Fast reduction due to the pseudo Mersenne prime number p = 2^130 - 5.
Result = (high * 5) + low

\param[in, out] a     Output array.
\param[in] ar         Input array.
*/
static void
EscPoly1305_IntermediateReduction(
    Esc_UINT8 a[17],
    const Esc_UINT32 ar[17] );

/**
This function processes one 16 byte message input block.

\param[in, out] ctx    Poly1305 context.
\param[in] block          Input 16 bytes message block.
*/
static void
EscPoly1305_Block(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 block[16] );

/**
Final reduction modulo p = p = 2^130 -5. If input is larger than p, subtract p.

\param[in, out] a    Value which will be reduced modulu p.
*/
static void
EscPoly1305_FinalReduction(
    Esc_UINT8 a[17] );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/** Length of one block in bytes */
#define EscPoly1305_BLOCK_SIZE 16U

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static void
EscPoly1305_Add(
    Esc_UINT8 a[17],
    const Esc_UINT8 b[17] )
{
    Esc_UINT16 u = 0;
    Esc_UINT8 i;
    for (i = 0; i < 17U; i++)
    {
        u += (Esc_UINT16) a[i] + (Esc_UINT16) b[i];
        a[i] = (Esc_UINT8) u & 0xffU;
        u >>= 8;
    }
    /* During Poly1305 computation no unwanted carry occur here.
      For usage in EscPoly1305_FinalReduction() wrap around without carry is intended. */
}

static void
EscPoly1305_IntermediateReduction(
    Esc_UINT8 a[17],
    const Esc_UINT32 ar[17] )
{
    Esc_UINT32 u = 0;
    Esc_UINT8 i;

    /* Set a to ar and process carry chain. */
    for (i = 0; i < 16U; i++)
    {
        u += ar[i];
        a[i] = (Esc_UINT8) u & 0xffU;
        u >>= 8;
    }
    u += ar[16];
    /* u = accumulated carry chain. Set most significant two bits (128 and 129) of a. */
    a[16] = (Esc_UINT8) u & 0x03U;
    /* multiply all bits above 130 (highpart) with 5 */
    u = 5U * (u >> 2);
    /* add multiplied highpart to low part (first 130 bits) */
    for (i = 0; i < 16U; i++)
    {
        u += a[i];
        a[i] = (Esc_UINT8) u & 0xffU;
        u >>= 8;
    }
    a[16] += (Esc_UINT8) u;
}

static void
EscPoly1305_Block(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 block[EscPoly1305_BLOCK_SIZE] )
{
    Esc_UINT32 ar[17], u;
    Esc_UINT8 c[17];
    Esc_UINT8 i, j;

    Esc_ASSERT( (ctx != Esc_NULL_PTR) && (block != Esc_NULL_PTR) );
    /* internal function, null pointer checks have been performed by caller */

    /* a = a + m */
    for (i = 0; i < 16U; i++)
    {
        c[i] = block[i];
    }
    c[16] = ctx->final ^ 1U;
    EscPoly1305_Add( ctx->a, c );

    /* a = a * r. Intermediate results are accumulated in 32 bit variables and
       processed later inside the EscPoly1305_IntermediateReduction() function. */
    for (i = 0; i < 17U; i++)
    {
        u = 0;
        /* Schoolbook multiplication with result values that are smaller than p. */
        for (j = 0; j <= i; j++)
        {
            u += (Esc_UINT32)(ctx->a[j]) * ctx->r[i - j];
        }
        /* Schoolbook multiplication with result values that are greater than p. Reduction mod p is integrated:
           (bits which above 130) * 5 + low part
           highpart is shifted by 130 bits to the right by shifting to the right by 17 bytes, then shift 6 bits the left.
           Leftshift by 6 bits => Mul 64, combined with Mul 5 == Mul 320 */
        for (j = i + 1U; j < 17U; j++)
        {
            /*lint -e{796} r[..] array access can not be out of bounds since max result of the calculation is 16. */
            /* 320 * v = (v << 6) * 5. */
            u += (Esc_UINT32)320U * ctx->a[j] * ctx->r[i + 17U - j];
        }
        ar[i] = u;
    }

    /* process carry bits and reduce mod p */
    EscPoly1305_IntermediateReduction( ctx->a, ar );
}

static void
EscPoly1305_FinalReduction(
    Esc_UINT8 a[17] )
{
    static const Esc_UINT8 minusp[17] = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc };
    Esc_UINT8 i;
    Esc_UINT8 t[17];

    Esc_ASSERT( a != Esc_NULL_PTR );
    /* internal function, null pointer checks have been performed by caller */

    /* store original accumulator value for later usage */
    for (i = 0; i < 17U; i++)
    {
        t[i] = a[i];
    }

    /* compute a = a + -p */
    EscPoly1305_Add( a, minusp );

    /* select a if a < p, or a + -p if a >= p. Actually we look for the 'sign' bit of a - p.
       If bit is zero, value a was greater than p, wraparound of a[16] occured during addition of -p.
       If bit is one, a is smaller than p, no wrap around of a[16]. */
    if ( (a[16] >> 7) != 0U )
    {
        /* use a */
        for (i = 0; i < 17U; i++)
        {
            a[i] = t[i];
        }
    }
    /* use a - p */
}

Esc_ERROR
EscPoly1305_Init(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 key[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    if ((ctx != Esc_NULL_PTR) && (key != Esc_NULL_PTR))
    {
        /* r = key & 0x 0ffffffc0ffffffc0ffffffc0fffffff. According to the RFC, integers are treated as little endian. */
        ctx->r[0] = key[0] & 0xffU;
        ctx->r[1] = key[1] & 0xffU;
        ctx->r[2] = key[2] & 0xffU;
        ctx->r[3] = key[3] & 0x0fU;
        ctx->r[4] = key[4] & 0xfcU;
        ctx->r[5] = key[5] & 0xffU;
        ctx->r[6] = key[6] & 0xffU;
        ctx->r[7] = key[7] & 0x0fU;
        ctx->r[8] = key[8] & 0xfcU;
        ctx->r[9] = key[9] & 0xffU;
        ctx->r[10] = key[10] & 0xffU;
        ctx->r[11] = key[11] & 0x0fU;
        ctx->r[12] = key[12] & 0xfcU;
        ctx->r[13] = key[13] & 0xffU;
        ctx->r[14] = key[14] & 0xffU;
        ctx->r[15] = key[15] & 0x0fU;
        ctx->r[16] = 0U;

        /* a = 0. s = second half of the key */
        for (i = 0; i < 16U; i++)
        {
            ctx->a[i] = 0U;
            ctx->s[i] = key[i + 16U];
        }
        ctx->a[16] = 0U;
        ctx->s[16] = 0U; /* we extend s by one byte to be able to use the same add function that is used to add the 17-byte 'minusp' value later on */

        ctx->leftover = 0U;
        ctx->final = 0;
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    return returnCode;
}


Esc_ERROR
EscPoly1305_Update(
    EscPoly1305_ContextT* ctx,
    const Esc_UINT8 message[],
    const Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 len = messageLength;
    Esc_UINT32 offset = 0U;
    Esc_UINT8 bytesToProcess;
    Esc_UINT8 i;

    if ((ctx != Esc_NULL_PTR) && ((message != Esc_NULL_PTR) || (len == 0U)))
    {
        if (ctx->final == 0U)
        {
            if (len > 0U)
            {
                /* process leftover bytes from last update if available */
                if (ctx->leftover != 0U)
                {
                    bytesToProcess = EscPoly1305_BLOCK_SIZE - ctx->leftover;
                    if (bytesToProcess > len)
                    {
                        bytesToProcess = (Esc_UINT8) len;
                    }

                    for (i = 0; i < bytesToProcess; i++)
                    {
                        ctx->buffer[ctx->leftover + i] = message[i];
                    }

                    ctx->leftover += bytesToProcess;
                    offset = bytesToProcess;
                    len -= bytesToProcess;
                    if (ctx->leftover >= EscPoly1305_BLOCK_SIZE)
                    { /* should only ever be '==', not '>' infact... but just to make sure...*/
                        Esc_ASSERT( ctx->leftover == EscPoly1305_BLOCK_SIZE );
                        EscPoly1305_Block( ctx, ctx->buffer );
                        ctx->leftover = 0;
                    }
                }

                /* process input data blocks */
                while (len >= EscPoly1305_BLOCK_SIZE)
                {
                    EscPoly1305_Block( ctx, &message[offset] );
                    offset += EscPoly1305_BLOCK_SIZE;
                    len -= EscPoly1305_BLOCK_SIZE;
                }

                /* store rest of input in leftover buffer */
                if ( len != 0U )
                {
                    for (i = 0; i < len; i++)
                    {
                        ctx->buffer[ctx->leftover + i] = message[offset + i];
                    }
                    ctx->leftover += (Esc_UINT8) len;
                }
            }
        }
        else
        {
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    return returnCode;
}


Esc_ERROR
EscPoly1305_Finish(
    EscPoly1305_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    if ((ctx != Esc_NULL_PTR) && (mac != Esc_NULL_PTR))
    {
        if (ctx->final == 0U)
        {
            if ((macLength <= EscPoly1305_MAX_MAC_LENGTH) && (macLength > 0U))
            {
                ctx->final = 1U;
                /* process leftover bytes from last update if available */
                if ( ctx->leftover != 0U )
                {
                    ctx->buffer[ctx->leftover] = 1;
                    ctx->leftover++;
                    while (ctx->leftover < EscPoly1305_BLOCK_SIZE)
                    {
                        ctx->buffer[ctx->leftover] = 0;
                        ctx->leftover++;
                    }
                    EscPoly1305_Block( ctx, ctx->buffer );
                }

                EscPoly1305_FinalReduction( ctx->a );

                /* mac = (a + s) % (1 << 128) */
                EscPoly1305_Add( ctx->a, ctx->s );

                /* store mac in output array */
                for (i = 0; i < macLength; i++)
                {
                    mac[i] = ctx->a[i];
                }
            }
            else
            {
                returnCode = Esc_INVALID_PARAMETER;
            }
        }
        else
        {
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    return returnCode;
}


Esc_ERROR
EscPoly1305_Calc(
    const Esc_UINT8 key[],
    const Esc_UINT8 message[],
    const Esc_UINT32 messageLength,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode;
    EscPoly1305_ContextT ctx;

    /* Checking for NULL parameters happens in the actual functions */
    returnCode = EscPoly1305_Init( &ctx, key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPoly1305_Update( &ctx, message, messageLength );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscPoly1305_Finish( &ctx, mac, macLength );
    }
    return returnCode;
}
/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
