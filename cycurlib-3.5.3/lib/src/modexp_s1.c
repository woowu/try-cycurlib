/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Modular exponentiation (sliced).

   $Rev: 2717 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "modexp_s1.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/*lint -esym(750,EscModExpS1_STATE_*) Depending on the configuration, some states may not be used */

/* States for public key operation */

#define EscModExpS1_STATE_PUB_INITIALIZED            1
#define EscModExpS1_STATE_PUB_MONTGOM_INIT           2
#define EscModExpS1_STATE_PUB_SQUARE                 3
#define EscModExpS1_STATE_PUB_MULTIPLY               4
#define EscModExpS1_STATE_PUB_FINISH_SQUARE_MULT     5
#define EscModExpS1_STATE_PUB_FINISHED               6
#define EscModExpS1_STATE_PUB_ERROR                  0

/* States for private key operation */

#define EscModExpS1_STATE_PRIV_INITALIZED            1
#define EscModExpS1_STATE_PRIV_MONTGOM_INIT          2
#define EscModExpS1_STATE_PRIV_PRECOMPUTE_START      3
#define EscModExpS1_STATE_PRIV_PRECOMPUTE_LOOP       4
#define EscModExpS1_STATE_PRIV_MAINLOOP              5
#define EscModExpS1_STATE_PRIV_DOUBLE_LOOP           6
#define EscModExpS1_STATE_PRIV_FINISH                7
#define EscModExpS1_STATE_PRIV_SQUARE                8
#define EscModExpS1_STATE_PRIV_MULTIPLY              9
#define EscModExpS1_STATE_PRIV_ERROR                 0

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

void
EscModExpS1_PubInit(
    EscModExpS1_PubContext *ctx,
    Esc_UINT32 exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    ctx->keySizeBits = keySizeBits;
    ctx->pubExp = exponent;
    ctx->modulus = modulus;
    ctx->x = inOut;

    ctx->thebit = 31;

    ctx->mult.c = &ctx->multiplication_result;
    ctx->mult.m = modulus;
    ctx->mult.x = inOut;

    ctx->state = EscModExpS1_STATE_PUB_INITIALIZED;
}

#if EscRsa_USE_MONTGOM_MUL == 1
Esc_ERROR
EscModExpS1_PubRun(
    EscModExpS1_PubContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT16 i;
    Esc_UINT16 wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(ctx->keySizeBits);
    Esc_UINT16 wordLongSize = (Esc_UINT16)(2U * wordSize);

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PUB_INITIALIZED:
            /* build R = 2^mod_bit_size */
            for (i = 0U; i < wordLongSize; i++)
            {
                ctx->mult.c->words[i] = 0U;
            }
            ctx->mult.c->words[wordSize] = 1U;

            EscRsaFe_ModularReduction( &ctx->mult, wordSize );

            ctx->state = EscModExpS1_STATE_PUB_MONTGOM_INIT;
            break;

        case EscModExpS1_STATE_PUB_MONTGOM_INIT:
            /* x_ = R mod n */
            EscRsaFe_FromLongFe( &ctx->x_, ctx->mult.c, wordSize );
            /* mult.c = c * x mod m  =  R * x mod m */
            EscRsaFe_Multiply( &ctx->mult, wordSize );
            /* y_ = x * R */
            EscRsaFe_FromLongFe( &ctx->y_, ctx->mult.c, wordSize );

            /* Initialize Montgomery variables */
            EscRsa_MontGom_Init( &ctx->mult, &ctx->mg, wordSize );

            /* find first bit in exponent != 0 */
            while ( ( ctx->pubExp & (Esc_UINT32)(1UL << (Esc_UINT8)ctx->thebit) ) == 0U )
            {
                ctx->thebit--;
            }

            ctx->state = EscModExpS1_STATE_PUB_SQUARE;
            break;

        case EscModExpS1_STATE_PUB_SQUARE:
            if (ctx->thebit >= 0)
            {
                /* c := c * c mod m */
                EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );

                /* if e_i = 1 then c := c * x mod m */
                if ( ( ctx->pubExp & (Esc_UINT32)(1UL << (Esc_UINT8)ctx->thebit) ) != 0U )
                {
                    ctx->state = EscModExpS1_STATE_PUB_MULTIPLY;
                }

                ctx->thebit--;
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PUB_FINISH_SQUARE_MULT;
            }
            break;

        case EscModExpS1_STATE_PUB_MULTIPLY:
            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
            ctx->state = EscModExpS1_STATE_PUB_SQUARE;
            break;

        case EscModExpS1_STATE_PUB_FINISH_SQUARE_MULT:
            /* build word one, we reuse buffer y_ */
            for (i = 1U; i < wordSize; i++)
            {
                ctx->y_.words[i] = 0U;
            }
            ctx->y_.words[0] = 1U;

            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
            EscRsaFe_Assign( ctx->mult.x, &ctx->x_, wordSize );

            ctx->state = EscModExpS1_STATE_PUB_FINISHED;
            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PUB_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#else /* EscRsa_USE_MONTGOM_MUL */

Esc_ERROR
EscModExpS1_PubRun(
    EscModExpS1_PubContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT16 wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(ctx->keySizeBits);

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PUB_INITIALIZED:
            /* c := x */
            EscRsaFe_ToLongFe( ctx->mult.c, ctx->mult.x, wordSize );

            /* find first bit in exponent != 0 */
            while ( ( ctx->pubExp & (Esc_UINT32)(1UL << (Esc_UINT8)ctx->thebit) ) == 0U )
            {
                ctx->thebit--;
            }

            /* c == x => MSB has already been processed */
            ctx->thebit--;

            ctx->state = EscModExpS1_STATE_PUB_SQUARE;
            break;

        case EscModExpS1_STATE_PUB_SQUARE:
            if (ctx->thebit >= 0)
            {
                /* c := c * c mod m */
                EscRsaFe_SquareClassically( &ctx->mult, wordSize );
                EscRsaFe_ModularReduction( &ctx->mult, wordSize );

                if ( ( ctx->pubExp & (Esc_UINT32)(1UL << (Esc_UINT8)ctx->thebit) ) != 0U )
                {
                    ctx->state = EscModExpS1_STATE_PUB_MULTIPLY;
                }

                ctx->thebit--;
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PUB_FINISH_SQUARE_MULT;
            }
            break;

        case EscModExpS1_STATE_PUB_MULTIPLY:
            /* c := c * x mod m */
            EscRsaFe_Multiply( &ctx->mult, wordSize );
            ctx->state = EscModExpS1_STATE_PUB_SQUARE;
            break;

        case EscModExpS1_STATE_PUB_FINISH_SQUARE_MULT:
            /* x := c */
            EscRsaFe_FromLongFe( ctx->mult.x, ctx->mult.c, wordSize );
            ctx->state = EscModExpS1_STATE_PUB_FINISHED;
            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PUB_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}
#endif /* EscRsa_USE_MONTGOM_MUL */

void
EscModExpS1_PrivInit(
    EscModExpS1_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    ctx->x = inOut;
    ctx->privExp = exponent;
    ctx->modulus = modulus;

    ctx->mult.m = modulus;
    ctx->mult.c = &ctx->multiplication_result;
    ctx->mult.x = inOut;

    ctx->state = EscModExpS1_STATE_PRIV_INITALIZED;

    EscRsa_AssignKeyStruct(keySizeBits, &ctx->keySize);
}

#if EscRsa_USE_MONTGOM_MUL == 1
#    if EscRsa_USE_SLIDING_WINDOW == 1

Esc_ERROR
EscModExpS1_PrivRun(
    EscModExpS1_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;

    Esc_UINT32 i;
    Esc_UINT16 wordSize = ctx->keySize.words;

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PRIV_INITALIZED:
            ctx->thebit = 0U;

            /* build R = 2^mod_bit_size */
            for (i = 0U; i < ctx->keySize.wordsLong; i++)
            {
                ctx->mult.c->words[i] = 0U;
            }
            ctx->mult.c->words[wordSize] = 1U;

            EscRsaFe_ModularReduction( &ctx->mult, wordSize );
            /* x_ = R mod n */
            EscRsaFe_FromLongFe( &ctx->x_, ctx->mult.c, wordSize );

            ctx->state = EscModExpS1_STATE_PRIV_MONTGOM_INIT;
            break;

        case EscModExpS1_STATE_PRIV_MONTGOM_INIT:

            /* pm.c = c * x mod m  =  R * x mod m */
            EscRsaFe_Multiply( &ctx->mult, wordSize );
            /* y_ = x * R */
            EscRsaFe_FromLongFe( &ctx->y_, ctx->mult.c, wordSize );

            /* Initialize Montgomery variables */
            EscRsa_MontGom_Init( &ctx->mult, &ctx->mg, wordSize );

            ctx->state = EscModExpS1_STATE_PRIV_PRECOMPUTE_START;
            break;

        case EscModExpS1_STATE_PRIV_PRECOMPUTE_START:

            EscRsaFe_Assign( &ctx->fe_array[0], &ctx->y_, wordSize );
            EscRsaFe_MontGom( &ctx->y_, &ctx->y_, &ctx->mg, wordSize );
            EscRsaFe_Assign( ctx->x, &ctx->fe_array[0], wordSize );

            ctx->state = EscModExpS1_STATE_PRIV_PRECOMPUTE_LOOP;
            ctx->loopCnt = 1U;
            break;

        case EscModExpS1_STATE_PRIV_PRECOMPUTE_LOOP:
            if (ctx->loopCnt < EscRsa_NUM_WINDOW_ELEMENTS)
            {
                EscRsaFe_MontGom( ctx->x, &ctx->y_, &ctx->mg, wordSize );
                EscRsaFe_Assign( &ctx->fe_array[ctx->loopCnt], ctx->x, wordSize );
                ctx->loopCnt++;
            }
            else
            {
                EscRsaFe_Assign( &ctx->x_, &ctx->fe_array[0], wordSize );

                while (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
                {
                    ctx->thebit++;
                }
                ctx->thebit++;

                ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            }
            break;

        case EscModExpS1_STATE_PRIV_MAINLOOP:

            if (ctx->thebit < ctx->keySize.bits)
            {
                /* if Exponent = 0 double only */
                if (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
                {
                    EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );
                    ctx->thebit++;
                }
                else
                {
                    Esc_UINT32 n = EscRsa_WINDOW_SIZE - 1U;

                    /* build window */
                    ctx->exponent = 0U;
                    ctx->windowSize = EscRsa_WINDOW_SIZE;
                    for (i = ctx->thebit; ( i < (ctx->thebit + EscRsa_WINDOW_SIZE) ) && (i < ctx->keySize.bits); i++)
                    {
                        /* build temporary exponent */
                        if ( EscRsaFe_IsBitSet( ctx->privExp, i, wordSize ) )
                        {
                            ctx->exponent |= (Esc_UINT32)1U << n;
                        }
                        n--;
                    }
                    ctx->thebit += EscRsa_WINDOW_SIZE;
                    /* make window odd and adjust i, reduce window size */
                    while ( (ctx->exponent % 2U) == 0U )
                    {
                        ctx->exponent = ctx->exponent >> 1U;
                        ctx->thebit--;
                        ctx->windowSize--;
                    }

                    ctx->loopCnt = 0U;
                    ctx->state = EscModExpS1_STATE_PRIV_DOUBLE_LOOP;

                    /* Assert that exponent/2 is within bounds of fe_array */
                    Esc_ASSERT( (ctx->exponent / 2) < EscRsa_NUM_WINDOW_ELEMENTS );
                }
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PRIV_FINISH;
            }
            break;

        case EscModExpS1_STATE_PRIV_DOUBLE_LOOP:

            if (ctx->loopCnt < ctx->windowSize)
            {
                EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );
                ctx->loopCnt++;
            }
            else
            {
                EscRsaFe_MontGom( &ctx->x_, &ctx->fe_array[(Esc_UINT16)(ctx->exponent / 2U)], &ctx->mg, wordSize );
                ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            }
            break;

        case EscModExpS1_STATE_PRIV_FINISH:
            /* build word one, we reuse buffer y_ */
            for (i = 1U; i < wordSize; i++)
            {
                ctx->y_.words[i] = 0U;
            }
            ctx->y_.words[0] = 1U;

            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
            EscRsaFe_Assign( ctx->x, &ctx->x_, wordSize );

            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PRIV_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#    else /* EscRsa_USE_SLIDING_WINDOW */
Esc_ERROR
EscModExpS1_PrivRun(
    EscModExpS1_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT32 i;
    Esc_UINT16 wordSize = ctx->keySize.words;

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PRIV_INITALIZED:
            /* build R = 2^mod_bit_size */
            for (i = 0U; i < ctx->keySize.wordsLong; i++)
            {
                ctx->mult.c->words[i] = 0U;
            }
            ctx->mult.c->words[wordSize] = 1U;

            EscRsaFe_ModularReduction( &ctx->mult, wordSize );
            /* x_ = R mod n */
            EscRsaFe_FromLongFe( &ctx->x_, ctx->mult.c, wordSize );
            /* pm.c = c * x mod m  =  R * x mod m */

            ctx->thebit = 0U;

            ctx->state = EscModExpS1_STATE_PRIV_MONTGOM_INIT;
            break;

        case EscModExpS1_STATE_PRIV_MONTGOM_INIT:
            /* pm.c = c * x mod m  =  R * x mod m */
            EscRsaFe_Multiply( &ctx->mult, wordSize );
            /* y_ = x * R */
            EscRsaFe_FromLongFe( &ctx->y_, ctx->mult.c, wordSize );

            /* Initialize Montgomery variables */
            EscRsa_MontGom_Init( &ctx->mult, &ctx->mg, wordSize );

            /* find first bit in exponent != 0 */
            while (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
            {
                ctx->thebit++;
            }

            ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            break;

        case EscModExpS1_STATE_PRIV_MAINLOOP:
            /* square and multiply */
            if (ctx->thebit < ctx->keySize.bits)
            {
                /* c := c * c mod m */
                EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );

                /* if e_i = 1 then c := c * x mod m */
                if ( EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) )
                {
                    ctx->state = EscModExpS1_STATE_PRIV_MULTIPLY;
                }
                ctx->thebit++;
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PRIV_FINISH;
            }
            break;

        case EscModExpS1_STATE_PRIV_MULTIPLY:
            /* c := c * x mod m */
            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
            ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            break;

        case EscModExpS1_STATE_PRIV_FINISH:
            /* build word one, we reuse buffer y_ */
            for (i = 1U; i < wordSize; i++)
            {
                ctx->y_.words[i] = 0U;
            }
            ctx->y_.words[0] = 1U;

            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
            EscRsaFe_Assign( ctx->mult.x, &ctx->x_, wordSize );

            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PRIV_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#    endif

#else /* EscRsa_USE_MONTGOM_MUL */
#    if EscRsa_USE_SLIDING_WINDOW == 1
/* sliding window */
Esc_ERROR
EscModExpS1_PrivRun(
    EscModExpS1_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT32 i;
    Esc_UINT16 wordSize = ctx->keySize.words;

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PRIV_INITALIZED:
            ctx->thebit = 0U;

            EscRsaFe_ToLongFe( ctx->mult.c, ctx->mult.x, wordSize );
            EscRsaFe_FromLongFe( &ctx->fe_array[0], ctx->mult.c, wordSize );
            EscRsaFe_SquareSlidingWindow( &ctx->mult, wordSize );

            ctx->state = EscModExpS1_STATE_PRIV_PRECOMPUTE_START;
            break;

        case EscModExpS1_STATE_PRIV_PRECOMPUTE_START:
            EscRsaFe_ModularReduction( &ctx->mult, wordSize );
            EscRsaFe_FromLongFe( ctx->mult.x, ctx->mult.c, wordSize );
            EscRsaFe_ToLongFe( ctx->mult.c, &ctx->fe_array[0], wordSize );

            ctx->state = EscModExpS1_STATE_PRIV_PRECOMPUTE_LOOP;
            ctx->loopCnt = 1U;
            break;

        case EscModExpS1_STATE_PRIV_PRECOMPUTE_LOOP:
            if (ctx->loopCnt < EscRsa_NUM_WINDOW_ELEMENTS)
            {
                EscRsaFe_Multiply( &ctx->mult, wordSize );
                EscRsaFe_FromLongFe( &ctx->fe_array[ctx->loopCnt], ctx->mult.c, wordSize );

                ctx->loopCnt++;
            }
            else
            {
                EscRsaFe_ToLongFe( ctx->mult.c, &ctx->fe_array[0], wordSize );

                while (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
                {
                    ctx->thebit++;
                }

                /* c == x => MSB has already been processed */
                ctx->thebit++;

                ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            }
            break;

        case EscModExpS1_STATE_PRIV_MAINLOOP:
            if (ctx->thebit < ctx->keySize.bits)
            {
                /* if Exponent = 0 double only */
                if (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
                {
                    EscRsaFe_SquareSlidingWindow( &ctx->mult, wordSize );
                    EscRsaFe_ModularReduction( &ctx->mult, wordSize );
                    ctx->thebit++;
                }
                else
                {
                    Esc_UINT32 n = EscRsa_WINDOW_SIZE - 1U;

                    /* build window */
                    ctx->exponent = 0U;
                    ctx->windowSize = EscRsa_WINDOW_SIZE;
                    for (i = ctx->thebit; ( i < (ctx->thebit + EscRsa_WINDOW_SIZE) ) && (i < ctx->keySize.bits); i++)
                    {
                        /* build temporary exponent */
                        if ( EscRsaFe_IsBitSet( ctx->privExp, i, wordSize ) )
                        {
                            ctx->exponent |= (Esc_UINT32)1U << n;
                        }
                        n--;
                    }
                    ctx->thebit += EscRsa_WINDOW_SIZE;
                    /* make window odd and adjust i, reduce window size */
                    while ( (ctx->exponent & 1U) == 0U )
                    {
                        ctx->exponent >>= 1U;
                        ctx->thebit--;
                        ctx->windowSize--;
                    }

                    ctx->loopCnt = 0U;
                    ctx->state = EscModExpS1_STATE_PRIV_DOUBLE_LOOP;
                }
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PRIV_FINISH;
            }
            break;

        case EscModExpS1_STATE_PRIV_DOUBLE_LOOP:
            if (ctx->loopCnt < ctx->windowSize)
            {
                EscRsaFe_SquareSlidingWindow( &ctx->mult, wordSize );
                EscRsaFe_ModularReduction( &ctx->mult, wordSize );
                ctx->loopCnt++;
            }
            else
            {
                /* Assert that exponent/2 is within bounds of fe_array */
                Esc_ASSERT( (ctx->exponent / 2) < EscRsa_NUM_WINDOW_ELEMENTS );

                /* multiply */
                EscRsaFe_Assign( ctx->mult.x, &ctx->fe_array[(Esc_UINT16)(ctx->exponent / 2U)], wordSize );
                EscRsaFe_Multiply( &ctx->mult, wordSize );

                ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            }
            break;

        case EscModExpS1_STATE_PRIV_FINISH:
            EscRsaFe_FromLongFe( ctx->mult.x, ctx->mult.c, wordSize );
            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PRIV_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#    else /* EscRsa_USE_SLIDING_WINDOW */
/* square and multiply */
Esc_ERROR
EscModExpS1_PrivRun(
    EscModExpS1_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;
    Esc_UINT16 wordSize = ctx->keySize.words;

    switch (ctx->state)
    {
        case EscModExpS1_STATE_PRIV_INITALIZED:
            ctx->thebit = 0U;

            /* c := x */
            EscRsaFe_ToLongFe( ctx->mult.c, ctx->mult.x, wordSize );

            /* find first bit in exponent != 0 */
            while (EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) == FALSE)
            {
                ctx->thebit++;
            }

            /* c == x => MSB has already been processed */
            ctx->thebit++;

            ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            break;

        case EscModExpS1_STATE_PRIV_MAINLOOP:
            if (ctx->thebit < ctx->keySize.bits)
            {
                /* c := c * c mod m */
                EscRsaFe_SquareClassically( &ctx->mult, wordSize );
                EscRsaFe_ModularReduction( &ctx->mult, wordSize );

                /* if e_i = 1 then c := c * x mod m */
                if ( EscRsaFe_IsBitSet( ctx->privExp, ctx->thebit, wordSize ) )
                {
                    ctx->state = EscModExpS1_STATE_PRIV_MULTIPLY;
                }
                ctx->thebit++;
            }
            else
            {
                ctx->state = EscModExpS1_STATE_PRIV_FINISH;
            }
            break;

        case EscModExpS1_STATE_PRIV_MULTIPLY:
            /* c := c * x mod m */
            EscRsaFe_Multiply( &ctx->mult, wordSize );
            ctx->state = EscModExpS1_STATE_PRIV_MAINLOOP;
            break;

        case EscModExpS1_STATE_PRIV_FINISH:
            EscRsaFe_FromLongFe( ctx->mult.x, ctx->mult.c, wordSize );
            returnCode = Esc_NO_ERROR;
            break;

        default:
            ctx->state = EscModExpS1_STATE_PRIV_ERROR;   /* Invalidate state */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}

#    endif
#endif

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
