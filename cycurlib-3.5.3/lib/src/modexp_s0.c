/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Modular exponentiation (not sliced).

   $Rev: 2717 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "modexp_s0.h"

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

/*********************************************************************
 * computes the power of a field element by the given exponent       *
 * x = x^e mod m                                                     *
 *                                                                   *
 * the exponent must not be 0                                        *
 *********************************************************************/
#if EscRsa_USE_MONTGOM_MUL == 1
#    if EscRsa_USE_SLIDING_WINDOW == 1
void
EscModExpS0_PrivInit(
    EscModExpS0_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    Esc_UINT32 thebit = 0U;
    Esc_UINT32 i, n, windowsize, j;
    Esc_UINT16 windowExponent;
    Esc_UINT16 wordSize;
    Esc_UINT32 wordLongSize;

    EscRsa_KeySizeT keySize;
    EscRsa_MultiplyDataT mult;

    EscRsa_AssignKeyStruct(keySizeBits, &keySize);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    wordSize = keySize.words;
    wordLongSize = keySize.wordsLong;

    /* build R = 2^mod_bit_size */
    for (i = 0U; i < wordLongSize; i++)
    {
        mult.c->words[i] = 0U;
    }
    mult.c->words[wordSize] = 1U;

    EscRsaFe_ModularReduction( &mult, wordSize );
    /* x_ = R mod n */
    EscRsaFe_FromLongFe( &ctx->x_, mult.c, wordSize );
    /* mult.c = c * x mod m  =  R * x mod m */
    EscRsaFe_Multiply( &mult, wordSize );
    /* y_ = x * R */
    EscRsaFe_FromLongFe( &ctx->y_, mult.c, wordSize );

    /* Initialize Montgomery variables */
    EscRsa_MontGom_Init( &mult, &ctx->mg, wordSize );

    EscRsaFe_Assign( &ctx->fe_array[0], &ctx->y_, wordSize );
    EscRsaFe_MontGom( &ctx->y_, &ctx->y_, &ctx->mg, wordSize );
    EscRsaFe_Assign( mult.x, &ctx->fe_array[0], wordSize );

    /* precomputation - i < 2^k_m */
    for (i = 1U; i < EscRsa_NUM_WINDOW_ELEMENTS; i++)
    {
        EscRsaFe_MontGom( mult.x, &ctx->y_, &ctx->mg, wordSize );
        EscRsaFe_Assign( &ctx->fe_array[i], mult.x, wordSize );
    }
    EscRsaFe_Assign( &ctx->x_, &ctx->fe_array[0], wordSize );
    while (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }
    thebit++;

    while (thebit < keySizeBits)
    {
        /* if Exponent = 0 double only */
        if (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
        {
            EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );
            thebit++;
        }
        else
        {
            /* build window */
            windowExponent = 0U;
            n = EscRsa_WINDOW_SIZE - 1U;
            windowsize = EscRsa_WINDOW_SIZE;
            for (j = thebit; ( j < (thebit + EscRsa_WINDOW_SIZE) ) && (j < keySizeBits); j++)
            {
                /* build temporary exponent */
                if ( EscRsaFe_IsBitSet( exponent, j, wordSize ) )
                {
                    windowExponent |= (Esc_UINT16)( 1UL << n );
                }
                n--;
            }
            thebit += EscRsa_WINDOW_SIZE;
            /* make window odd and adjust i, reduce window size */
            while ( (windowExponent % 2U) == 0U )
            {
                windowExponent = windowExponent >> 1U;
                thebit--;
                windowsize--;
            }

            /* double */
            for (j = 0U; j < windowsize; j++)
            {
                EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );
            }

            /* Assert that exponent/2 is within bounds of fe_array */
            Esc_ASSERT( (windowExponent / 2) < EscRsa_NUM_WINDOW_ELEMENTS );

            /* add */
            EscRsaFe_MontGom( &ctx->x_, &ctx->fe_array[(Esc_UINT16)(windowExponent / 2U)], &ctx->mg, wordSize );
        }
    }

    /* build word one in temp variable */
    for (i = 1U; i < wordSize; i++)
    {
        ctx->y_.words[i] = 0U;
    }
    ctx->y_.words[0] = 1U;

    EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
    EscRsaFe_Assign( mult.x, &ctx->x_, wordSize );
}

#    else /* EscRsa_USE_SLIDING_WINDOW */

void
EscModExpS0_PrivInit(
    EscModExpS0_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    Esc_UINT32 thebit = 0U;
    Esc_UINT16 i;
    Esc_UINT16 wordSize;
    Esc_UINT32 wordLongSize;

    EscRsa_MultiplyDataT mult;
    EscRsa_KeySizeT keySize;

    EscRsa_AssignKeyStruct(keySizeBits, &keySize);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    wordSize = keySize.words;
    wordLongSize = keySize.wordsLong;

    /* build R = 2^mod_bit_size */
    for (i = 0U; i < wordLongSize; i++)
    {
        mult.c->words[i] = 0U;
    }
    mult.c->words[wordSize] = 1U;

    EscRsaFe_ModularReduction( &mult, wordSize );
    /* x_ = R mod n */
    EscRsaFe_FromLongFe( &ctx->x_, mult.c, wordSize );
    /* mult.c = c * x mod m  =  R * x mod m */
    EscRsaFe_Multiply( &mult, wordSize );
    /* y_ = x * R */
    EscRsaFe_FromLongFe( &ctx->y_, mult.c, wordSize );

    /* Initialize Montgomery variables */
    EscRsa_MontGom_Init( &mult, &ctx->mg, wordSize );

    /* find first bit in exponent != 0 */
    while (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }

    /* square and multiply */
    while (thebit < keySizeBits)
    {
        /* c := c * c mod m */
        EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );

        /* if e_i = 1 then c := c * x mod m */
        if ( EscRsaFe_IsBitSet( exponent, thebit, wordSize ) )
        {
            /* c := c * x mod m */
            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
        }
        thebit++;
    }

    /* build word one in temp variable */
    for (i = 1U; i < wordSize; i++)
    {
        ctx->y_.words[i] = 0U;
    }
    ctx->y_.words[0] = 1U;

    EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
    EscRsaFe_Assign( mult.x, &ctx->x_, wordSize );
}

#    endif

#else /* EscRsa_USE_MONTGOM_MUL */
#    if EscRsa_USE_SLIDING_WINDOW == 1
/* sliding window */

void
EscModExpS0_PrivInit(
    EscModExpS0_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    Esc_UINT32 thebit = 0U;
    Esc_UINT32 i, n, windowsize, j;
    Esc_UINT16 windowExponent;
    Esc_UINT16 wordSize;

    EscRsa_MultiplyDataT mult;
    EscRsa_KeySizeT keySize;

    EscRsa_AssignKeyStruct(keySizeBits, &keySize);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    wordSize = keySize.words;

    EscRsaFe_ToLongFe( mult.c, mult.x, wordSize );
    EscRsaFe_FromLongFe( &ctx->fe_array[0], mult.c, wordSize );
    EscRsaFe_SquareSlidingWindow( &mult, wordSize );
    EscRsaFe_ModularReduction( &mult, wordSize );
    EscRsaFe_FromLongFe( mult.x, mult.c, wordSize );
    EscRsaFe_ToLongFe( mult.c, &ctx->fe_array[0], wordSize );

    /* precomputation - i < 2^k_m */
    for (i = 1U; i < EscRsa_NUM_WINDOW_ELEMENTS; i++)
    {
        EscRsaFe_Multiply( &mult, wordSize );
        EscRsaFe_FromLongFe( &ctx->fe_array[i], mult.c, wordSize );
    }
    EscRsaFe_ToLongFe( mult.c, &ctx->fe_array[0], wordSize );

    while (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }

    /* c == x => MSB has already been processed */
    thebit++;

    while (thebit < keySizeBits)
    {
        /* if Exponent = 0 double only */
        if (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
        {
            EscRsaFe_SquareSlidingWindow( &mult, wordSize );
            EscRsaFe_ModularReduction( &mult, wordSize );
            thebit++;
        }
        else
        {
            /* build window */
            windowExponent = 0U;
            n = EscRsa_WINDOW_SIZE - 1U;
            windowsize = EscRsa_WINDOW_SIZE;
            for (j = thebit; ( j < (thebit + EscRsa_WINDOW_SIZE) ) && (j < keySizeBits); j++)
            {
                /* build temporary exponent */
                if ( EscRsaFe_IsBitSet( exponent, j, wordSize ) )
                {
                    windowExponent |= (Esc_UINT16)( 1UL << n );
                }
                n--;
            }
            thebit += EscRsa_WINDOW_SIZE;
            /* make window odd and adjust i, reduce window size */
            while ( (windowExponent & 1U) == 0U )
            {
                windowExponent >>= 1U;
                thebit--;
                windowsize--;
            }

            /* square */
            for (j = 0U; j < windowsize; j++)
            {
                EscRsaFe_SquareSlidingWindow( &mult, wordSize );
                EscRsaFe_ModularReduction( &mult, wordSize );
            }

            /* Assert that exponent/2 is within bounds of fe_array */
            Esc_ASSERT( (windowExponent / 2) < EscRsa_NUM_WINDOW_ELEMENTS );

            /* multiply */
            EscRsaFe_Assign( mult.x, &ctx->fe_array[(Esc_UINT16)(windowExponent / 2U)], wordSize );
            EscRsaFe_Multiply( &mult, wordSize );
        }
    }
    EscRsaFe_FromLongFe( mult.x, mult.c, wordSize );
}

#    else /* EscRsa_USE_SLIDING_WINDOW */

void
EscModExpS0_PrivInit(
    EscModExpS0_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    EscRsa_MultiplyDataT mult;
    EscRsa_KeySizeT keySize;

    Esc_UINT16 wordSize;
    Esc_UINT32 thebit = 0U;

    EscRsa_AssignKeyStruct(keySizeBits, &keySize);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    wordSize = keySize.words;

    /* Perform square and multiply. We left-shift the exponent
       and examine the most significant bit */

    /* c := x */
    EscRsaFe_ToLongFe( mult.c, mult.x, wordSize );

    /* find first bit in exponent != 0 */
    while (EscRsaFe_IsBitSet( exponent, thebit, wordSize ) == FALSE)
    {
        thebit++;
    }

    /* c == x => MSB has already been processed */
    thebit++;

    /* square and multiply */
    while (thebit < keySizeBits)
    {
        /* c := c * c mod m */
        EscRsaFe_SquareClassically( &mult, wordSize );
        EscRsaFe_ModularReduction( &mult, wordSize );

        /* if e_i = 1 then c := c * x mod m */
        if ( EscRsaFe_IsBitSet( exponent, thebit, wordSize ) )
        {
            /* c := c * x mod m */
            EscRsaFe_Multiply( &mult, wordSize );
        }
        thebit++;
    }

    EscRsaFe_FromLongFe( mult.x, mult.c, wordSize );
}
#    endif
#endif

/*lint -e{818} Keep ctx non-const for a consistent interface */
Esc_ERROR
EscModExpS0_PrivRun(
    EscModExpS0_PrivContext *ctx)
{
    Esc_UNUSED_PARAM(ctx);

    /* Complete non-sliced implementation is done in the init() function */
    return Esc_NO_ERROR;
}

#if EscRsa_USE_MONTGOM_MUL == 1

void
EscModExpS0_PubInit(
    EscModExpS0_PubContext *ctx,
    Esc_UINT32 exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    EscRsa_MultiplyDataT mult;
    Esc_SINT8 thebit = 31;
    Esc_UINT16 i;

    /* Shortcuts */
    Esc_UINT16 wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(keySizeBits);
    Esc_UINT16 wordLongSize = (Esc_UINT16)(2U * wordSize);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    /* build R = 2^mod_bit_size */
    for (i = 0U; i < wordLongSize; i++)
    {
        mult.c->words[i] = 0U;
    }
    mult.c->words[wordSize] = 1U;

    EscRsaFe_ModularReduction( &mult, wordSize );
    /* x_ = R mod n */
    EscRsaFe_FromLongFe( &ctx->x_, mult.c, wordSize );
    /* mult.c = c * x mod m  =  R * x mod m */
    EscRsaFe_Multiply( &mult, wordSize );
    /* y_ = x * R */
    EscRsaFe_FromLongFe( &ctx->y_, mult.c, wordSize );

    /* Initialize Montgomery variables */
    EscRsa_MontGom_Init( &mult, &ctx->mg, wordSize );

    /* find first bit in exponent != 0 */
    while ( ( exponent & (Esc_UINT32)(1UL << (Esc_UINT8)thebit) ) == 0U )
    {
        thebit--;
    }

    /* square and multiply */
    while (thebit >= 0)
    {
        /* c := c * c mod m */
        EscRsaFe_MontGom( &ctx->x_, &ctx->x_, &ctx->mg, wordSize );

        /* if e_i = 1 then c := c * x mod m */
        if ( ( exponent & (Esc_UINT32)(1UL << (Esc_UINT8)thebit) ) != 0U )
        {
            /* c := c * x mod m */
            EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
        }
        thebit--;
    }

    /* build word one, we reuse buffer y_ */
    for (i = 1U; i < wordSize; i++)
    {
        ctx->y_.words[i] = 0U;
    }
    ctx->y_.words[0] = 1U;

    EscRsaFe_MontGom( &ctx->x_, &ctx->y_, &ctx->mg, wordSize );
    EscRsaFe_Assign( inOut, &ctx->x_, wordSize );
}

#else

void
EscModExpS0_PubInit(
    EscModExpS0_PubContext *ctx,
    Esc_UINT32 exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut)
{
    EscRsa_MultiplyDataT mult;
    Esc_SINT8 thebit = 31;

    /* Shortcuts */
    Esc_UINT16 wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(keySizeBits);

    mult.c = &ctx->multiplication_result;
    mult.m = modulus;
    mult.x = inOut;

    /* c := x */
    EscRsaFe_ToLongFe( mult.c, mult.x, wordSize );

    /* find first bit in exponent != 0 */
    while ( ( exponent & (Esc_UINT32)(1UL << (Esc_UINT8)thebit) ) == 0U )
    {
        thebit--;
    }

    /* c == x => MSB has already been processed */
    thebit--;

    /* square and multiply */
    while (thebit >= 0)
    {
        /* c := c * c mod m */
        EscRsaFe_SquareClassically( &mult, wordSize );
        EscRsaFe_ModularReduction( &mult, wordSize );

        /* if e_i = 1 then c := c * x mod m */
        if ( ( exponent & (Esc_UINT32)(1UL << (Esc_UINT8)thebit) ) != 0U )
        {
            /* c := c * x mod m */
            EscRsaFe_Multiply( &mult, wordSize );
        }
        thebit--;
    }

    /* x := c */
    EscRsaFe_FromLongFe( mult.x, mult.c, wordSize );
}

#endif

/*lint -e{818} Keep ctx non-const for a consistent interface */
Esc_ERROR
EscModExpS0_PubRun(
    EscModExpS0_PubContext *ctx)
{
    Esc_UNUSED_PARAM(ctx);

    /* Complete non-sliced implementation is done in the init() function */
    return Esc_NO_ERROR;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
