/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Common types and function for RSA.

   $Rev: 2690 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "_rsa.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/************************************************************************
 Assigns element src to long element dst
 dst := src
************************************************************************/
#if (EscRsa_USE_MONTGOM_MUL == 0) || (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
void
EscRsaFe_ToLongFe(
    EscRsa_FieldElementLongT* dst,
    const EscRsa_FieldElementT* src,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;

    /* copy src */
    for (i = 0U; i < wordSize; i++)
    {
        dst->words[i] = src->words[i];
    }
    /* Zeroize remaining words */
    for (; i < EscRsa_RSA_SIZE_WORDS_LONG_MAX; i++)
    {
        dst->words[i] = 0U;
    }
}
#endif

/************************************************************************
 Assigns long element src to element dst
 dst := src
************************************************************************/
void
EscRsaFe_FromLongFe(
    EscRsa_FieldElementT* dst,
    const EscRsa_FieldElementLongT* src,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;

    /** The value fits into dst */
    Esc_ASSERT( src->words[wordSize] == 0U );

    /* copy src */
    for (i = 0U; i < wordSize; i++)
    {
        dst->words[i] = src->words[i];
    }
    /* Zeroize remaining words */
    for (; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
    {
        dst->words[i] = 0U;
    }
}

/************************************************************************
 Assigns element src to element dst
 dst := src
************************************************************************/
#if (EscRsa_USE_SLIDING_WINDOW == 1) || (EscRsa_USE_MONTGOM_MUL == 1) || (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
void
EscRsaFe_Assign(
    EscRsa_FieldElementT* dst,
    const EscRsa_FieldElementT* src,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;
    /* copy src */
    for (i = 0U; i < wordSize; i++)
    {
        dst->words[i] = src->words[i];
    }
    /* Zeroize remaining words */
    for (; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
    {
        dst->words[i] = 0U;
    }
}
#endif

/*********************************
  Squares two field elements c := c * c
  The input c has the maximum length of RSA_SIZE_WORDS.
  By maintaining another copy of c in RAM,
  the multiplication algorithm can be used for this task.
 *********************************/
#if (EscRsa_USE_MONTGOM_MUL == 0) || ( ( EscRsa_GENRSA_ENABLED == 1) && (EscRsa_USE_SLIDING_WINDOW == 0 ) )
void
EscRsaFe_SquareClassically(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    /* declarations */
    EscRsa_HWORD min;
    EscRsa_HWORD b_0, a_0;
    EscRsa_HWORD i;
    EscRsa_HWORD j;
    EscRsa_FWORD uv;
    EscRsa_FWORD t = 0U;
    EscRsa_FWORD uv_t = 0U;

    EscRsa_FieldElementT inC;
    EscRsa_HWORD* cwords;

    cwords = pm->c->words;

    /* 1.) inC := c; c := 0 */
    Esc_ASSERT( cwords[wordSize] == 0U );      /* single precision */
    EscRsaFe_FromLongFe( &inC, pm->c, wordSize );

    Esc_ASSERT( wordSize % 8U == 0 );

    /* We only allow certain RSA modulus sizes and this is already checked in the calling functions.
     * Therefore, wordSize MUST be a multiple of 8. We still enclose the code of this function in an if-statement to
     * give a hint to the compiler (to allow for partial loop unrolling).
     */
    if ( (wordSize % 8U) == 0U)
    {
        for (i = 0U; i < (2U * (EscRsa_HWORD)wordSize); i++)
        {
            b_0 = EscRsa_MIN( ((EscRsa_HWORD)wordSize - 1U), i );
            a_0 = i - b_0;
            min = EscRsa_MIN( (EscRsa_HWORD)(wordSize - a_0), (b_0 + 1U) );
            for (j = 0U; j < min; j++)
            {
                /* a[a_o + j] * b[b_o - j] */
                uv = (EscRsa_FWORD)inC.words[a_0 + j] * (EscRsa_FWORD)inC.words[b_0 - j];
                /* sum on uv_t */
                uv_t += uv;
                /* if overflow save carry to t */
                if (uv_t < uv)
                {
                    t++;
                }
            }

            /* c[i] = v, v = u, u = t, t = 0 */
            cwords[i] = EscRsa_LO_HWORD( uv_t );
            uv_t >>= EscRsa_RSA_BASE;
            uv_t |= t << EscRsa_RSA_BASE;
            t = 0U;
        }
    }
}
#endif

#if (EscRsa_USE_SLIDING_WINDOW == 1) && ( ( EscRsa_USE_MONTGOM_MUL == 0) || (EscRsa_GENRSA_ENABLED == 1 ) )
/*********************************
  Squares two field elements c := c * c
  The input c has the maximum length of RSA_SIZE_WORDS.
  By maintaining another copy of c in RAM,
  the multiplication algorithm can be used for this task.
 *********************************/
void
EscRsaFe_SquareSlidingWindow(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize )
{
    /* declarations */
    Esc_UINT16 i;
    Esc_UINT16 j;
    EscRsa_FWORD uv;
    EscRsa_FWORD t = 0U;
    EscRsa_FWORD uv_t = 0U;

    EscRsa_FieldElementT inC;
    EscRsa_HWORD* cwords;

    cwords = pm->c->words;

    /* 1.) inC := c; c := 0 */
    Esc_ASSERT( cwords[wordSize] == 0U );      /* single precision */
    EscRsaFe_FromLongFe( &inC, pm->c, wordSize );

    if ( (wordSize % 8U) == 0U)
    {
        for (i = 0U; i < wordSize; i++)
        {
            const Esc_UINT16 max = (i + 1U) / 2U;
            const Esc_UINT16 half = i / 2U;

            for (j = 0U; j <= half; j++)
            {
                /* a[a_o + j] * b[b_o - j] */
                uv = (EscRsa_FWORD)inC.words[j] * (EscRsa_FWORD)inC.words[i - j];
                /* sum on uv_t */
                uv_t += uv;
                /* if overflow save carry to t */
                if (uv_t < uv)
                {
                    t++;
                }
                if (j < max)
                {
                    /* sum on uv_t */
                    uv_t += uv;
                    /* if overflow save carry to t */
                    if (uv_t < uv)
                    {
                        t++;
                    }
                }
            }

            /* c[i] = v, v = u, u = t, t = 0 */
            cwords[i] = EscRsa_LO_HWORD( uv_t );
            uv_t >>= EscRsa_RSA_BASE;
            uv_t |= t << EscRsa_RSA_BASE;
            t = 0U;
        }

        for (; i < (Esc_UINT16)(wordSize * 2U); i++)
        {
            const Esc_UINT16 max = (i + 1U) / 2U;
            const Esc_UINT16 half = i / 2U;

            for (j = (i + 1U) - wordSize; j <= half; j++)
            {
                /* a[a_o + j] * b[b_o - j] */
                uv = (EscRsa_FWORD)inC.words[j] * (EscRsa_FWORD)inC.words[i - j];
                /* sum on uv_t */
                uv_t += uv;
                /* if overflow save carry to t */
                if (uv_t < uv)
                {
                    t++;
                }
                if (j < max)
                {
                    /* sum on uv_t */
                    uv_t += uv;
                    /* if overflow save carry to t */
                    if (uv_t < uv)
                    {
                        t++;
                    }
                }
            }

            cwords[i] = EscRsa_LO_HWORD( uv_t );
            uv_t >>= EscRsa_RSA_BASE;
            uv_t |= t << EscRsa_RSA_BASE;
            t = 0U;
        }
    }
}
#endif /* EscRsa_USE_SLIDING_WINDOW */

/************************************************************************
Main reduction loop (HAC, Algorithm 14.20)
c := c mod m
m must be != 0
************************************************************************/
void
EscRsaFe_ModularReduction(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    Esc_SINT16 mwords_msb;
    Esc_SINT16 i;
    Esc_UINT16 j;
    EscRsa_HWORD q;
    EscRsa_HWORD carry;
    EscRsa_FWORD ciAndCmin1;
    EscRsa_HWORD* cwords;
    const EscRsa_HWORD* mwords;
    Esc_BOOL finished;

    cwords = pm->c->words;
    mwords = pm->m->words;

    Esc_ASSERT( wordSize % 8U == 0 );

    /* We only allow certain RSA modulus sizes and this is already checked in the calling functions.
     * Therefore, wordSize MUST be a multiple of 8. We still enclose the code of this function in an if-statement to
     * give a hint to the compiler (to allow for partial loop unrolling).
     */
    if ( (wordSize % 8U) == 0U)
    {
        Esc_ASSERT( wordSize > 1 );

        mwords_msb = (Esc_SINT16)wordSize - 1;
        while ( (mwords_msb > 0) && (mwords[mwords_msb] == 0U) )
        {
            mwords_msb--;
        }
        Esc_ASSERT( mwords_msb >= 0 );

        /* We can safely skip step 2. of the algorithm, since the while condition can only be triggered if message > (mod-1)^2 , which can not occur in our RSA implementation. */
        for (i = ( (Esc_SINT16)(2 * (Esc_SINT16)wordSize) - 1 ); i > mwords_msb; i--)
        {
            /* if x_i == m_k-1 then q=b-1 else q=(x_i*b + x_i-1) div m_k-1 */
            /* Calc (x_i*b + x_i-1) already, we need it later too */
            ciAndCmin1 = ( (EscRsa_FWORD)cwords[i] << EscRsa_RSA_BASE ) | ( (EscRsa_FWORD)cwords[i - 1] );

            if (cwords[i] == mwords[mwords_msb])
            {
                q = (EscRsa_HWORD)EscRsa_MAX_VAL;
            }
            else
            {
                q = (EscRsa_HWORD)( (ciAndCmin1) / (EscRsa_FWORD)mwords[mwords_msb] );
            }

            /* while q*(m[k-1] * b + m[k-2]) > x[i]*b^2 + x[i-1] *b + x[i-2] do q--; */
            finished = FALSE;
            while (finished == FALSE)
            {
                EscRsa_FWORD qcHi;
                EscRsa_FWORD qcLo;

                qcHi = (EscRsa_FWORD)q * (EscRsa_FWORD)mwords[mwords_msb];
                if (mwords_msb > 0)
                {
                    qcLo = (EscRsa_FWORD)q * (EscRsa_FWORD)mwords[mwords_msb - 1];
                }
                else
                {
                    qcLo = 0U;
                }
                qcHi += EscRsa_HI_FWORD( qcLo );

                /* qcHi contains the upper two bytes of q*(m[k-1] * b + m[k-2]),
                   ciAndCmin1 the upper two bytes of x[i]*b^2 + x[i-1] */
                if (qcHi < ciAndCmin1)
                {
                    /* q*(m[k-1] * b + m[k-2]) < x[i]*b^2 + x[i-1] *b + x[i-2] */
                    finished = TRUE;
                }
                else if ( (qcHi == ciAndCmin1) && (EscRsa_LO_HWORD( qcLo ) <= cwords[i - 2]) )
                {
                    /* q*(m[k-1] * b + m[k-2]) <= x[i]*b^2 + x[i-1] *b + x[i-2] */
                    finished = TRUE;
                }
                else
                {
                    q--;
                }
            }

            /* x = x-q*m*b^(i-k) */
            carry = 0U;
            for (j = 0U; j <= (Esc_UINT16)mwords_msb; j++)
            {
                EscRsa_FWORD xhi;
                Esc_UINT16 cIdx;

                xhi = ( (EscRsa_FWORD)q * (EscRsa_FWORD)mwords[j] ) + (EscRsa_FWORD)carry;
                carry = EscRsa_HI_HWORD( xhi );
                cIdx = (Esc_UINT16)( ( ( (Esc_UINT16)i - (Esc_UINT16)mwords_msb ) - 1U ) + j );
                xhi = (EscRsa_FWORD)cwords[cIdx] - EscRsa_LO_FWORD( xhi );
                cwords[cIdx] = EscRsa_LO_HWORD( xhi );

                if (EscRsa_HI_FWORD( xhi ) != 0U)
                {
                    carry++;
                }
            }

            /* if (x<0) then x=x+m*b^(i-k) */
            if (cwords[i] < carry)
            {
                carry = 0U;

                for (j = 0U; j <= (Esc_UINT16)mwords_msb; j++)
                {
                    EscRsa_FWORD xhi;
                    Esc_UINT16 cIdx;

                    cIdx = (Esc_UINT16)( ( ( (Esc_UINT16)i - (Esc_UINT16)mwords_msb ) - 1U ) + j );
                    xhi = (EscRsa_FWORD)cwords[cIdx] + ( (EscRsa_FWORD)mwords[j] ) + (EscRsa_FWORD)carry;
                    carry = EscRsa_HI_HWORD( xhi );
                    cwords[cIdx] = EscRsa_LO_HWORD( xhi );
                }
            }
            cwords[i] = 0U;
        }
    }
}

/************************************************************************
 * c = c * x mod m                                                           *
 ************************************************************************/
void
EscRsaFe_Multiply(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    EscRsaFe_MultiplyClassically( pm, wordSize );

    /* classical modular reduction */
    EscRsaFe_ModularReduction( pm, wordSize );
}

/** returns whether or not the specified bit is set */
Esc_BOOL
EscRsaFe_IsBitSet(
    const EscRsa_FieldElementT* e,
    Esc_UINT32 thebit,
    const Esc_UINT16 wordSize  )
{
    Esc_BOOL isSet;
    if ( ( (EscRsa_HWORD)( e->words[ ((Esc_UINT32)wordSize - 1U) - (thebit / EscRsa_RSA_BASE) ]) & (EscRsa_HWORD)( (EscRsa_HWORD)1UL << ( (EscRsa_RSA_BASE - 1U) - (thebit % EscRsa_RSA_BASE) ) ) ) != 0U )
    {
        isSet = TRUE;
    }
    else
    {
        isSet = FALSE;
    }

    return isSet;
}

/***************************************************************
 * Converts a byte array into a word array (big endian)        *
 ***************************************************************/
void
EscRsaFe_FromBytesBE(
    EscRsa_FieldElementT* dest,
    const Esc_UINT8 source[],
    const Esc_UINT16 lenByte)
{
    Esc_UINT16 i;
    EscRsa_HWORD* dstArray;

    /* This function only works for a multiple of the word size */
    Esc_ASSERT(lenByte % EscRsa_WORD_SIZE == 0U);

    dstArray = dest->words;

    for (i = 0U; i < (lenByte / EscRsa_WORD_SIZE); i++)
    {
        EscRsa_HWORD d;
        d = ( (EscRsa_HWORD)source[(lenByte - 1U) - (i * (Esc_UINT16)EscRsa_WORD_SIZE)] ) |
            ( (EscRsa_HWORD)( ( (EscRsa_HWORD)source[(lenByte - 1U) - ( (i * (Esc_UINT16)EscRsa_WORD_SIZE) + 1U )] ) << 8 ) );

#    if EscRsa_WORD_SIZE == 4U
        d |= ( (EscRsa_HWORD)( ( (EscRsa_HWORD)source[(lenByte - 1U) - ( (i * (Esc_UINT16)EscRsa_WORD_SIZE) + 2U )] ) << 16 ) ) |
            ( (EscRsa_HWORD)( ( (EscRsa_HWORD)source[(lenByte - 1U) - ( (i * (Esc_UINT16)EscRsa_WORD_SIZE) + 3U )] ) << 24 ) );
#    endif

        dstArray[i] = d;
    }
    for (; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
    {
        dstArray[i] = 0U;
    }
}

/***************************************************************
 * Converts a word array into a byte array (big endian)        *
 ***************************************************************/
void
EscRsaFe_ToBytesBE(
    Esc_UINT8 dest[],
    const EscRsa_FieldElementT* source,
    Esc_UINT16 len)
{
    Esc_UINT16 i;
    EscRsa_HWORD v;

    for (i = 0U; i < len; i++)
    {
        v = source->words[i >> (EscRsa_WORD_SIZE / 2U)];
        v >>= ( (Esc_UINT16)( ( i & (EscRsa_WORD_SIZE - 1U) ) << 3 ) ) & 0xFFU;
        dest[(len - 1U) - i] = (Esc_UINT8)v;
    }
}


/*********************************
  Multiplies two field elements c := c * x.
  We use the integer multiplication algorithm from Menzenes, et. al.
  "Elliptic Curve Cryptography". Algorithm 2.9.
  The algorithm is endianness independent.
 *********************************/
void
EscRsaFe_MultiplyClassically(
    const EscRsa_MultiplyDataT* pm,
    const Esc_UINT16 wordSize  )
{
    EscRsa_HWORD i;
    EscRsa_HWORD j;
    EscRsa_HWORD min;
    EscRsa_FWORD t;
    EscRsa_HWORD b_0, a_0;
    EscRsa_FWORD uv_t;
    EscRsa_FWORD uv;

    EscRsa_FieldElementT inC;
    const EscRsa_HWORD* awords;
    const EscRsa_HWORD* bwords;
    EscRsa_HWORD* cwords;

    awords = inC.words;
    bwords = pm->x->words;
    cwords = pm->c->words;

    uv_t = 0U;
    t = 0U;

    /* 1.) make a copy of c, clear c. inC:= c; c := 0 */
    Esc_ASSERT( cwords[wordSize] == 0U );      /* single precision */
    EscRsaFe_FromLongFe( &inC, pm->c, wordSize );

    Esc_ASSERT( wordSize % 8U == 0 );

    /* We only allow certain RSA modulus sizes and this is already checked in the calling functions.
     * Therefore, wordSize MUST be a multiple of 8. We still enclose the code of this function in an if-statement to
     * give a hint to the compiler (to allow for partial loop unrolling).
     */
    if ( (wordSize % 8U) == 0U)
    {

        for (i = 0U; i < (2U * (EscRsa_HWORD)wordSize ); i++)
        {
            b_0 = EscRsa_MIN( ( (EscRsa_HWORD)wordSize - 1U), i );
            a_0 = i - b_0;
            min = EscRsa_MIN( (EscRsa_HWORD)(wordSize - a_0), (b_0 + 1U) );
            for (j = 0U; j < min; j++)
            {
                /* a[a_o +j] * b[b_o - j] */
                uv = (EscRsa_FWORD)awords[a_0 + j] * (EscRsa_FWORD)bwords[b_0 - j];
                /* sum on uv_t */
                uv_t += uv;
                /* if overflow save carry to t */
                if (uv_t < uv)
                {
                    t++;
                }
            }

            /* c[i] = v, v = u, u = t, t = 0 */
            cwords[i] = EscRsa_LO_HWORD( uv_t );
            uv_t >>= EscRsa_RSA_BASE;
            uv_t |= t << EscRsa_RSA_BASE;
            t = 0U;
        }
    }
}

#if EscRsa_USE_MONTGOM_MUL == 1
void
EscRsa_MontGom_Init(
    const EscRsa_MultiplyDataT* pm,
    EscRsa_MontGomElementT* mg,
    const Esc_UINT16 wordSize )
{
    Esc_UINT8 i;
    EscRsa_HWORD y[EscRsa_RSA_BASE + 1U];
    /* assign modulus */
    EscRsaFe_Assign( &mg->mod, pm->m, wordSize );
    mg->m = pm->m->words[0U];
    /* calculate negative inverse of least significant word of the modulus mod 2^word_size
       see EUROCRYPT 90, Lecture Notes in ComputerScience, No. 473, pages 230-244 */
    y[1] = 1U;
    for (i = 2U; i <= EscRsa_RSA_BASE; i++)
    {
        if (i != EscRsa_RSA_BASE)
        {
            y[0U] = (EscRsa_HWORD)( (mg->m * y[i - 1U]) % ( (EscRsa_HWORD)( 1UL << i ) ) );
        }
        else
        {
            y[0U] = (EscRsa_HWORD)(mg->m * y[i - 1U]);
        }
        if ( y[0U] < (EscRsa_HWORD)( ( 1UL << (i - 1U) ) ) )
        {
            y[i] = y[i - 1U];
        }
        else
        {
            y[i] = y[i - 1U] + ( (EscRsa_HWORD)( 1UL << (i - 1U) ) );
        }
    }
    /* calculate -y[RSA_BASE] mod 2^WORD_SIZE */
    mg->m = (EscRsa_HWORD) ~y[EscRsa_RSA_BASE];
    mg->m++;
}


/** Montgomery Multiplication w/ CIOS algorithm, x = MontGom(x, y)
 *  see Analyzing and Comparing Montgomery Multiplication Algorithms, Cetin Kaya Koc and Tolga Acar
 **/
void
EscRsaFe_MontGom(
    EscRsa_FieldElementT* x,
    const EscRsa_FieldElementT* y,
    const EscRsa_MontGomElementT* mg,
    const Esc_UINT16 wordSize )
{
    /* Initialization */
    EscRsa_HWORD i, j, n, uv_tmp;
    EscRsa_FWORD uv;
    EscRsa_HWORD c[EscRsa_RSA_SIZE_WORDS_MAX + 2U];
    EscRsa_HWORD t[EscRsa_RSA_SIZE_WORDS_MAX + 2U];

    /* zero c array */
    for (i = 0U; i < ( EscRsa_RSA_SIZE_WORDS_MAX + 2U); i++)
    {
        c[i] = 0U;
    }

    Esc_ASSERT( wordSize % 8U == 0 );

    /* We only allow certain RSA modulus sizes and this is already checked in the calling functions.
     * Therefore, wordSize MUST be a multiple of 8. We still enclose the code of this function in an if-statement to
     * give a hint to the compiler (to allow for partial loop unrolling).
     */
    if ( (wordSize % 8U) == 0U)
    {

        /* CIOS algorithm */
        for (i = 0U; i < wordSize; i++)
        {
            uv = 0U;

            for (j = 0U; j < wordSize; j++)
            {
                uv_tmp = EscRsa_HI_HWORD( uv );
                uv = (EscRsa_FWORD)uv_tmp + ( (EscRsa_FWORD)x->words[j] * (EscRsa_FWORD)y->words[i] ) + (EscRsa_FWORD)c[j];
                c[j] = EscRsa_LO_HWORD( uv );
            }

            uv_tmp = EscRsa_HI_HWORD( uv );
            uv = (EscRsa_FWORD)c[wordSize] + (EscRsa_FWORD)uv_tmp;
            c[wordSize] = EscRsa_LO_HWORD( uv );
            c[wordSize + 1U] = EscRsa_HI_HWORD( uv );
            n = (EscRsa_HWORD)(c[0U] * mg->m);

            uv = (EscRsa_FWORD)c[0U] + ( (EscRsa_FWORD)n * (EscRsa_FWORD)mg->mod.words[0U] );
            for (j = 1U; j < wordSize; j++)
            {
                uv_tmp = EscRsa_HI_HWORD( uv );
                uv = (EscRsa_FWORD)uv_tmp + ( (EscRsa_FWORD)n * (EscRsa_FWORD)mg->mod.words[j] ) + (EscRsa_FWORD)c[j];
                c[j - 1U] = EscRsa_LO_HWORD( uv );
            }

            uv_tmp = EscRsa_HI_HWORD( uv );
            uv = (EscRsa_FWORD)c[wordSize] + (EscRsa_FWORD)uv_tmp;
            c[wordSize - 1U] = EscRsa_LO_HWORD( uv );
            c[wordSize] = c[wordSize + 1U] + EscRsa_HI_HWORD( uv );
        }

        /* third step of Montgomery, subtract modulus if necessary */
        uv = 0U;
        for (i = 0U; i < wordSize; i++)
        {
            /* subtract mod and save carry in highword of uv (tricky one ;) ) */
            uv_tmp = (EscRsa_HWORD)( (EscRsa_HWORD)( ~EscRsa_HI_HWORD( uv ) ) + 1U );
            uv = ( (EscRsa_FWORD)c[i] - (EscRsa_FWORD)mg->mod.words[i] ) - (EscRsa_FWORD)uv_tmp;
            t[i] = EscRsa_LO_HWORD( uv );
        }
        /* last carry */
        uv_tmp = (EscRsa_HWORD)( (EscRsa_HWORD)( ~EscRsa_HI_HWORD( uv ) ) + 1U );
        uv = (EscRsa_FWORD)c[wordSize] - (EscRsa_FWORD)uv_tmp;
        t[wordSize] = EscRsa_LO_HWORD( uv );

        /* c > mod ? return t:return c */
        if (EscRsa_HI_HWORD( uv ) == 0U)
        {
            for (i = 0U; i < wordSize; i++)
            {
                x->words[i] = t[i];
            }
        }
        else
        {
            for (i = 0U; i < wordSize; i++)
            {
                x->words[i] = c[i];
            }
        }
    }
}

#endif

/**
 * Function to assign the KeySize Struct
 */
void
EscRsa_AssignKeyStruct(
    const Esc_UINT16 lenBits,
    EscRsa_KeySizeT* keySize)
{
    keySize->bits = lenBits;
    keySize->bytes = EscRsa_KEY_BYTES_FROMBITS(lenBits);
    keySize->words = EscRsa_RSA_SIZE_WORDS_FROMBITS(lenBits);
    keySize->wordsLong = EscRsa_RSA_SIZE_WORDS_LONG_FROMBITS((Esc_UINT32)lenBits);
}

#if EscRsa_CRT_ENABLED == 1
/************************
 * Calculate a := a + b *
 ************************/
void
EscRsaFe_Add(
    EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize )
{
    EscRsa_FWORD carry = 0U;
    EscRsa_FWORD sum;
    Esc_UINT32 i;

    for (i = 0U; i < wordSize; i++)
    {
        sum = ( (EscRsa_FWORD)a->words[i] ) + ( (EscRsa_FWORD)b->words[i] ) + carry;
        carry = EscRsa_HI_FWORD( sum );
        a->words[i] = (EscRsa_HWORD)EscRsa_LO_FWORD( sum );
    }
}

#endif /* EscRsa_CRT_ENABLED */

/*******************************************
 * compares two field elements `a' and `b' *
  +1: a>b
  -1: a<b
   0: a==b
 *******************************************/
Esc_SINT8
EscRsaFe_AbsoluteCompare(
    const EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize )
{
    Esc_SINT16 i;
    Esc_SINT8 compResult = 0;

    /* compare the corresponding words until a different word pair is found */
    for (i = (Esc_SINT16)( (Esc_SINT16)wordSize - 1 ); (compResult == 0) && (i >= 0); i--)
    {
        /* next lower pair */
        if (a->words[i] > b->words[i])
        {
            /* a > b */
            compResult = 1;
        }
        else if (a->words[i] < b->words[i])
        {
            /* a < b */
            compResult = -1;
        }
        else
        {
            /* do nothing */
        }
    }

    return compResult;
}

/**********************************
 * check if field element is zero *
 * note: sign irrelevant          *
 **********************************/
Esc_BOOL
EscRsaFe_IsZero(
    const EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;
    Esc_BOOL isZero = TRUE;

    /* for i from 0 to t do a[i] =? 0 */
    for (i = 0U; i < wordSize; i++)
    {
        if (a->words[i] != 0U)
        {
            /* not zero */
            isZero = FALSE;
            break;
        }
    }

    return isZero;
}

#if (EscRsa_GENRSA_ENABLED == 1) || (EscRsa_CRT_ENABLED == 1)
/************************
 * Calculate a := a - b *
 ************************/
void
EscRsaFe_Subtract(
    EscRsa_FieldElementT* a,
    const EscRsa_FieldElementT* b,
    const Esc_UINT16 wordSize )
{
    EscRsa_FWORD carry = 1U;
    EscRsa_FWORD diff;
    Esc_UINT32 i;

    for (i = 0U; i < wordSize; i++)
    {
        diff = ( (EscRsa_FWORD)a->words[i] ) + ( (EscRsa_FWORD)(b->words[i] ^ EscRsa_MAX_VAL) ) + carry;
        carry = EscRsa_HI_FWORD( diff );
        a->words[i] = (EscRsa_HWORD)EscRsa_LO_FWORD( diff );
    }
}
#endif

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
