/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Pseudo Random Number Generator w/ SHA-*

   \see         NIST publication SP 800-90:
                Recommendation for Random Number Generation Using
                Deterministic Random Bit Generators - HASH_DRBG

 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "hash_drbg.h"
#include "mem_mgt.h"

/***************************************************************************
* 2. DEFINES                                                              *
***************************************************************************/

/* plausibility checks */
#if EscHashDrbg_ENTROPY_LEN < (EscHashDrbg_SECURITY_STRENGTH / 8U)
#    error "Entropy must be at least security strength!"
#endif

#if (EscHashDrbg_SECURITY_STRENGTH == 192U) || (EscHashDrbg_SECURITY_STRENGTH == 256U)
#    if (EscHashDrbg_SHA_TYPE == 1)
#        error "For security strength above 128 you have to use SHA-224 at least!"
#    endif
#else
#    if (EscHashDrbg_SECURITY_STRENGTH != 128U)
#        error "Security strength may only be one out of 128, 192, and 256!"
#    endif
#endif

#if EscHashDrbg_NONCE_LEN < (EscHashDrbg_SECURITY_STRENGTH / 16U)
#    error "Nonce must be at least half the security strength!"
#endif

#define EscHashDrbg_ROUNDS (EscHashDrbg_SEED_LEN / EscHashDrbg_BLOCK_LEN)
#define EscHashDrbg_REMAINDER (EscHashDrbg_SEED_LEN % EscHashDrbg_BLOCK_LEN)

/***************************************************************************
* 3. DEFINITIONS                                                          *
***************************************************************************/

/* Hash Wwapper function to avoid ifdefs for every Hash call */
static Esc_ERROR
EscHashDrbg_CalcHash(
    const Esc_UINT8 input[],
    Esc_UINT32 length,
    Esc_UINT8 result[] );

/* Function for deriving the new seed and the new state out of the input
 * entropy */
static Esc_ERROR
EscHashDrbg_DF(
    const Esc_UINT8 inputBytes[],
    Esc_UINT8 hashInput[],
    const Esc_UINT32 inputBytesLen,
    Esc_UINT8 output[] );

/* Function to generate the output (random) bits */
#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1
static Esc_ERROR
EscHashDrbg_HashGen(
    const Esc_UINT8 seed[],
    Esc_UINT32 len,
    Esc_UINT8 rnd[] );

#else
static Esc_ERROR
EscHashDrbg_HashGen(
    const Esc_UINT8 seed[],
    Esc_UINT8 rnd[] );

#endif

/* Function to generate the new internal PRNG state and reset the reseed counter */
static Esc_ERROR
EscHashDrbg_NewState(
    EscHashDrbg_ContextT* ctx );

/***************************************************************************
* 4. CONSTANTS                                                            *
***************************************************************************/

/***************************************************************************
* 5. IMPLEMENTATION OF FUNCTIONS                                          *
***************************************************************************/

static Esc_ERROR
EscHashDrbg_CalcHash(
    const Esc_UINT8 input[],
    Esc_UINT32 length,
    Esc_UINT8 result[] )
{
    Esc_ERROR returnCode;

#if (EscHashDrbg_SHA_TYPE == 1)
    /* calculate SHA1 */
    returnCode = EscSha1_Calc( input, length, result, EscSha1_DIGEST_LEN );
#elif (EscHashDrbg_SHA_TYPE == 224)
    /* calculate SHA-224 */
    returnCode = EscSha256_Calc( TRUE, input, length, result, EscSha224_DIGEST_LEN );
#elif (EscHashDrbg_SHA_TYPE == 256)
    /* calculate SHA-256 */
    returnCode = EscSha256_Calc( FALSE, input, length, result, EscSha256_DIGEST_LEN );
#elif (EscHashDrbg_SHA_TYPE == 384)
    /* calculate SHA-384 */
    returnCode = EscSha512_Calc( TRUE, input, length, result, EscSha384_DIGEST_LEN );
#elif (EscHashDrbg_SHA_TYPE == 512)
    /* calculate SHA-512 */
    returnCode = EscSha512_Calc( FALSE, input, length, result, EscSha512_DIGEST_LEN );
#else
    /* unsupported HASH Type */
    returnCode = Esc_INTERNAL_FUNCTION_ERROR;
#endif

    return returnCode;
}

static Esc_ERROR
EscHashDrbg_DF(
    const Esc_UINT8 inputBytes[],
    Esc_UINT8 hashInput[],
    const Esc_UINT32 inputBytesLen,
    Esc_UINT8 output[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 j, i = 0U;
    Esc_UINT8 hashResult[EscHashDrbg_BLOCK_LEN];

    /* Input array for hash function (hashInput):
     * (counter || length in bit of seed and state || inputBytes) */

    /* set counter, counter begins with 1 according to NIST recommendation 10.4 */
    hashInput[0] = 0x01U;

    /* set length in bit of seed and state (440 / 888) in big endian */
    hashInput[1] = 0x00U;
    hashInput[2] = 0x00U;
    hashInput[3] = (Esc_UINT8)(EscHashDrbg_SEED_LEN >> 5U);
    hashInput[4] = (Esc_UINT8)((EscHashDrbg_SEED_LEN << 3U) & 0xFFU);

    /* copy inputBytes into the hash input array */
    for (j = 0U; j < inputBytesLen; j++)
    {
        hashInput[j + 5U] = inputBytes[j];
    }

    /* fill the output array with the hash result. Output array has the length of
     * seed and state (EscHashDrbg_SEED_LEN), but the SHA output is only EscHashDrbg_BLOCK_LEN bytes. As a
     * result we use the SHA operation several times. */
    while ( (returnCode == Esc_NO_ERROR) && (i < EscHashDrbg_ROUNDS) )
    {
        /* output array has EscHashDrbg_SEED_LEN bytes (length of seed / state),
         * EscHashDrbg_ROUNDS times of full SHA output (EscHashDrbg_BLOCK_LEN bytes) and in
         * the last round the remaining bytes of the SHA output */
        returnCode = EscHashDrbg_CalcHash( hashInput, (inputBytesLen + 5U), &output[(i * EscHashDrbg_BLOCK_LEN)] );
        /* increment loop counter */
        i++;

        /* set next counter, counter begins with 1 according to NIST recommendation 10.4 */
        hashInput[0] = i + 1U;
    }

#if (EscHashDrbg_REMAINDER > 0U)

    if (returnCode == Esc_NO_ERROR)
    {
        /* last round, use only the first bytes of the SHA output */
        returnCode = EscHashDrbg_CalcHash( hashInput, (inputBytesLen + 5U), hashResult );

        /* copy the first bytes of SHA result into output array */
        for (j = 0U; j < EscHashDrbg_REMAINDER; j++)
        {
            output[(i * EscHashDrbg_BLOCK_LEN) + j] = hashResult[j];
        }
    }
#endif

    /* Zeroize stack variables */
    Esc_memclear(hashResult, sizeof(hashResult));

    return returnCode;
}

#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1
static Esc_ERROR
EscHashDrbg_HashGen(
    const Esc_UINT8 seed[],
    Esc_UINT32 len,
    Esc_UINT8 rnd[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 j = 0U;
    Esc_UINT32 carry, rounds, i;
    Esc_UINT8 hashResult[EscHashDrbg_BLOCK_LEN];
    Esc_UINT8 payload[EscHashDrbg_SEED_LEN];

    /* copy seed into temp array */
    for (i = 0U; i < EscHashDrbg_SEED_LEN; i++)
    {
        payload[i] = seed[i];
    }

    /* Generate hash blocks until requested number of bytes are reached */
    rounds = len / EscHashDrbg_BLOCK_LEN;

    while ( (returnCode == Esc_NO_ERROR) && (j < rounds) )
    {
        returnCode = EscHashDrbg_CalcHash( payload, EscHashDrbg_SEED_LEN, &rnd[(j * EscHashDrbg_BLOCK_LEN)] );

        /* Adding 0x01 to payload for next hash */
        i = 0U;
        carry = 0x01U;
        do
        {
            carry += (Esc_UINT16)payload[(EscHashDrbg_SEED_LEN - 1U) - i];
            /* copy new value */
            payload[(EscHashDrbg_SEED_LEN - 1U) - i] = (Esc_UINT8)(carry & 0xFFU);
            /* copy the upper 8 bit into carry */
            carry >>= 8U;
            i++;
        } while ( (carry != 0U) && (i < EscHashDrbg_SEED_LEN) );

        j++;
    }

    /* check if a remainder exist -> last round */
    if ( (returnCode == Esc_NO_ERROR) && ( (len % EscHashDrbg_BLOCK_LEN) != 0U ) )
    {
        returnCode = EscHashDrbg_CalcHash( payload, EscHashDrbg_SEED_LEN, hashResult );

        if (returnCode == Esc_NO_ERROR)
        {
            /* copy hash to remaining output bytes */
            for (i = 0U; i < (len % EscHashDrbg_BLOCK_LEN); i++)
            {
                rnd[(j * EscHashDrbg_BLOCK_LEN) + i] = hashResult[i];
            }
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(hashResult, sizeof(hashResult));
    Esc_memclear(payload, sizeof(payload));

    return returnCode;
}

#else
static Esc_ERROR
EscHashDrbg_HashGen(
    const Esc_UINT8 seed[],
    Esc_UINT8 rnd[] )
{
    return EscHashDrbg_CalcHash( seed, EscHashDrbg_SEED_LEN, rnd );
}

#endif

static Esc_ERROR
EscHashDrbg_NewState(
    EscHashDrbg_ContextT* ctx )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;
    Esc_UINT8 stateMaterial[1U + EscHashDrbg_SEED_LEN];
    Esc_UINT8 hashInput[EscHashDrbg_SEED_LEN + 6U];

    /* compute new state */
    stateMaterial[0] = 0x00U;
    for (i = 0U; i < EscHashDrbg_SEED_LEN; i++)
    {
        stateMaterial[i + 1U] = ctx->seed[i];
    }

    /* derive new state */
    returnCode = EscHashDrbg_DF( stateMaterial, hashInput, (EscHashDrbg_SEED_LEN + 1U), ctx->state );

    if (returnCode == Esc_NO_ERROR)
    {
        /* set reseed counter */
        ctx->counter = 1U;
    }

    /* Zeroize stack variables */
    Esc_memclear(stateMaterial, sizeof(stateMaterial));
    Esc_memclear(hashInput, sizeof(hashInput));

    return returnCode;
}

Esc_ERROR
EscHashDrbg_Init(
    EscHashDrbg_ContextT* ctx,
    const Esc_UINT8 entropy[],
    const Esc_UINT8 nonce[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT32 i;
    Esc_UINT8 seedMaterial[EscHashDrbg_ENTROPY_LEN + EscHashDrbg_NONCE_LEN];
    Esc_UINT8 hashInput[(EscHashDrbg_ENTROPY_LEN + EscHashDrbg_NONCE_LEN) + 5U];

    if ( (ctx != Esc_NULL_PTR) && (entropy != Esc_NULL_PTR) && (nonce != Esc_NULL_PTR) )
    {
        /* merge entropy array and nonce into one array */
        for (i = 0U; i < EscHashDrbg_ENTROPY_LEN; i++)
        {
            seedMaterial[i] = entropy[i];
        }
        for (i = 0U; i < EscHashDrbg_NONCE_LEN; i++)
        {
            seedMaterial[i + EscHashDrbg_ENTROPY_LEN] = nonce[i];
        }

        /* compute new seed */
        returnCode = EscHashDrbg_DF( seedMaterial, hashInput, (EscHashDrbg_ENTROPY_LEN + EscHashDrbg_NONCE_LEN), ctx->seed );

        if (returnCode == Esc_NO_ERROR)
        {
            /* compute new internal state and reset reseed counter */
            returnCode = EscHashDrbg_NewState( ctx );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(seedMaterial, sizeof(seedMaterial));
    Esc_memclear(hashInput, sizeof(hashInput));

    return returnCode;
}

Esc_ERROR
EscHashDrbg_Reseed(
    EscHashDrbg_ContextT* ctx,
    const Esc_UINT8 entropy[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT32 i;
    Esc_UINT8 seedMaterial[1U + EscHashDrbg_SEED_LEN + EscHashDrbg_ENTROPY_LEN];
    Esc_UINT8 hashInput[EscHashDrbg_SEED_LEN + EscHashDrbg_ENTROPY_LEN + 6U];

    if ( (ctx != Esc_NULL_PTR) && (entropy != Esc_NULL_PTR) )
    {
        /* merge Hash_df input into one array */
        seedMaterial[0] = 0x01U;
        for (i = 0U; i < EscHashDrbg_SEED_LEN; i++)
        {
            seedMaterial[i + 1U] = ctx->seed[i];
        }
        for (i = 0U; i < EscHashDrbg_ENTROPY_LEN; i++)
        {
            seedMaterial[EscHashDrbg_SEED_LEN + 1U + i] = entropy[i];
        }

        /* compute new seed */
        returnCode = EscHashDrbg_DF( seedMaterial, hashInput, (1U + EscHashDrbg_SEED_LEN + EscHashDrbg_ENTROPY_LEN), ctx->seed );

        if (returnCode == Esc_NO_ERROR)
        {
            /* compute new internal state and reset reseed counter */
            returnCode = EscHashDrbg_NewState( ctx );
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(seedMaterial, sizeof(seedMaterial));
    Esc_memclear(hashInput, sizeof(hashInput));

    return returnCode;
}


#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1
Esc_ERROR
EscHashDrbg_GetRandomWrapper(
    void* ctx,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len
    )
{
/*lint -save -e9087 -e9079 The Lint warning about Rule 11.3 is a false/positive. We cast a void pointer to object.
  Therefore we violate the cast from void pointer to object type rule (11.5, adv.) intentionally.
  This cast is safe since the void pointer is only for interface compatibility and points to the casted type. */
    return EscHashDrbg_GetRandom( (EscHashDrbg_ContextT *)ctx, rnd, len );
/*lint -restore */
}

Esc_ERROR
EscHashDrbg_GetRandom(
    EscHashDrbg_ContextT* ctx,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
#else
Esc_ERROR
EscHashDrbg_GetRandom(
    EscHashDrbg_ContextT* ctx,
    Esc_UINT8 rnd[] )
#endif
{
    Esc_ERROR returnCode;
    Esc_UINT32 i;
    Esc_UINT16 carry = 0U;
    Esc_UINT8 hash[EscHashDrbg_SEED_LEN + 1U];
    Esc_UINT8 hashResult[EscHashDrbg_BLOCK_LEN];

    if ( (ctx == Esc_NULL_PTR) || (rnd == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ctx->counter > EscHashDrbg_RESEED_INTERVAL)
    {
        returnCode = Esc_RNG_MUST_BE_RESEEDED;
    }
#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1
    else if (len == 0U)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
#endif
    else
    {
        /* get random bits */
#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1
        returnCode = EscHashDrbg_HashGen( ctx->seed, len, rnd );
#else
        returnCode = EscHashDrbg_HashGen( ctx->seed, rnd );
#endif

        if (returnCode == Esc_NO_ERROR)
        {
            /* construct new hash input */
            hash[0] = 0x03U;
            for (i = 0U; i < EscHashDrbg_SEED_LEN; i++)
            {
                hash[i + 1U] = ctx->seed[i];
            }
            returnCode = EscHashDrbg_CalcHash( hash, (1U + EscHashDrbg_SEED_LEN), hashResult );

            if (returnCode == Esc_NO_ERROR)
            {
                /* compute new seed */
                /* addition of the first 4 bytes with the counter value */
                for (i = 0U; i < 4U; i++)
                {
                    carry += (Esc_UINT16)(ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i]) +
                        (Esc_UINT16)(ctx->state[(EscHashDrbg_SEED_LEN - 1U) - i]) +
                        (Esc_UINT16)(hashResult[(EscHashDrbg_BLOCK_LEN - 1U) - i]) +
                        (Esc_UINT16)( ( ctx->counter >> (i * 8U) ) & 0xFFU );

                    /* write new seed element */
                    ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i] = (Esc_UINT8)(carry & 0xFFU);

                    /* copy the upper 8 bit into the carry */
                    carry >>= 8U;
                }

                /* addition of the first 20 bytes with temp array H */
                for (; i < EscHashDrbg_BLOCK_LEN; i++)
                {
                    carry += (Esc_UINT16)(ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i]) +
                        (Esc_UINT16)(ctx->state[(EscHashDrbg_SEED_LEN - 1U) - i]) +
                        (Esc_UINT16)(hashResult[(EscHashDrbg_BLOCK_LEN - 1U) - i]);

                    /* write new seed element */
                    ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i] = (Esc_UINT8)(carry & 0xFFU);

                    /* copy the upper 8 bit into the carry */
                    carry >>= 8U;
                }

                /* addition of the remaining 35 seed bytes with the state */
                for (; i < EscHashDrbg_SEED_LEN; i++)
                {
                    carry += (Esc_UINT16)(ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i]) +
                        (Esc_UINT16)(ctx->state[(EscHashDrbg_SEED_LEN - 1U) - i]);

                    /* write new seed element */
                    ctx->seed[(EscHashDrbg_SEED_LEN - 1U) - i] = (Esc_UINT8)(carry & 0xFFU);

                    /* copy the upper 8 bit into the carry */
                    carry >>= 8U;
                }
                /* discard the last carry */

                /* update reseed counter */
                ctx->counter++;
            }
        }
    }

    /* Zeroize stack variables */
    Esc_memclear(hash, sizeof(hash));
    Esc_memclear(hashResult, sizeof(hashResult));

    return returnCode;
}

/***************************************************************************
* 6. END                                                                  *
***************************************************************************/
