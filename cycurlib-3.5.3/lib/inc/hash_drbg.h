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

    \see        NIST publication SP 800-90:
                Recommendation for Random Number Generation Using
                Deterministic Random Bit Generators


    Pseudo random number generator implementation according to NIST SP 800-90
    "Hash_DRBG" Recommendation.
    The random number generator requires an entropy input with at least 128 bit.
    The quality of the entropy is very important for the usage of this PRNG!
    This PRNG has a security strength of 128 bit in comparing to symmetric key
    algorithms. For more information about the security strength see "NIST
    Special Publications 800-57" chapter 5.6.1.

    Also the PRNG requires a nonce with at least 64 bit extra entropy or a value
    that is expected to repeat no more often than a 64 bit random string would
    be expected to repeat. The remaining bits shall be filled with a
    personalization string, which makes every instance of this PRNG unique, for
    example the serial no. of the host device is a good value.

    $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_HASH_DRBG_H_
#define ESC_HASH_DRBG_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/* User definable configuration */

#ifndef EscHashDrbg_SECURITY_STRENGTH
/**
 * Determines the desired security strength in bits (128, 192, 256).
 * Is used in order to check if this strength can be reached with the following
 * define configuration.
 **/
#    define EscHashDrbg_SECURITY_STRENGTH 128U
#endif

#ifndef EscHashDrbg_ADJUSTABLE_OUT_LEN
/**
 * Enable (1) for variable PRNG output length. When disabled, fixed output
 * length is set to the SHA-module's output length.
 **/
#   define EscHashDrbg_ADJUSTABLE_OUT_LEN 1
#endif

#ifndef EscHashDrbg_RESEED_INTERVAL
/**
 * Maximum allowed function calls of EscHashDrbg_GetRandom before the reseed
 * function has to be called. Maximum is (2^32) -1 (Esc_UINT32). The default value
 * has been adopted from the NIST example pseudo code
 **/
#    define EscHashDrbg_RESEED_INTERVAL 100000U
#endif

#ifndef EscHashDrbg_ENTROPY_LEN
/**
 * Entropy length in bytes - must be the array size of values for INIT and RESEED
 * calls! Must be at least equal to the security strength!
 * For 128 bit security strength, entropy must to be at least 16 bytes
 **/
#    define EscHashDrbg_ENTROPY_LEN 16U
#endif

#ifndef EscHashDrbg_NONCE_LEN
/**
 * Nonce length in bytes - must be the array size of values for INIT and RESEED
 * calls! Must be at least half the security strength!
 * For 128 bit security strength, nonce must to be at least 8 bytes.
 **/
#    define EscHashDrbg_NONCE_LEN 8U
#endif

#ifndef EscHashDrbg_SHA_TYPE
/**
 * Determines the hash algorithm:
 *   1 = SHA1
 *   224 = SHA2-224
 *   256 = SHA2-256
 *   384 = SHA2-384
 *   512 = SHA2-512
 **/
#    define EscHashDrbg_SHA_TYPE 256
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Everything below this line is not to be configured */
#if ( ( EscHashDrbg_SHA_TYPE == 1) || (EscHashDrbg_SHA_TYPE == 224) || (EscHashDrbg_SHA_TYPE == 256 ) )
/**
 * seed length - according to the standard the length must be 440 bit for SHA-1,
 * SHA-224, and SHA-256
 **/
#    define EscHashDrbg_SEED_LEN 55U
#else
/**
 * seed length - according to the standard the length must be 888 bit for
 * SHA-384 and SHA-512
 **/
#    define EscHashDrbg_SEED_LEN 111U
#endif

#if (EscHashDrbg_SHA_TYPE == 1)
#    include "sha_1.h"
/** Length of the output of one hash operation (depending on the chosen hash algorithm)*/
#    define EscHashDrbg_BLOCK_LEN (EscSha1_DIGEST_LEN)
#elif (EscHashDrbg_SHA_TYPE == 224)
#    include "sha_256.h"
/** Length of the output of one hash operation (depending on the chosen hash algorithm)*/
#    define EscHashDrbg_BLOCK_LEN (EscSha224_DIGEST_LEN)
#elif (EscHashDrbg_SHA_TYPE == 256)
#    include "sha_256.h"
/** Length of the output of one hash operation (depending on the chosen hash algorithm)*/
#    define EscHashDrbg_BLOCK_LEN (EscSha256_DIGEST_LEN)
#elif (EscHashDrbg_SHA_TYPE == 384)
#    include "sha_512.h"
/** Length of the output of one hash operation (depending on the chosen hash algorithm)*/
#    define EscHashDrbg_BLOCK_LEN (EscSha384_DIGEST_LEN)
#elif (EscHashDrbg_SHA_TYPE == 512)
#    include "sha_512.h"
/** Length of the output of one hash operation (depending on the chosen hash algorithm)*/
#    define EscHashDrbg_BLOCK_LEN (EscSha512_DIGEST_LEN)
#else
#    error "EscHashDrbg_SHA_TYPE wrong!"
#endif

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/
/** PRNG context */
typedef struct
{
    /** seed vector   */
    Esc_UINT8 seed[EscHashDrbg_SEED_LEN];

    /** state vector   */
    Esc_UINT8 state[EscHashDrbg_SEED_LEN];

    /** reseed counter   */
    Esc_UINT32 counter;
} EscHashDrbg_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the PRNG.
This function has to be called once before using the PRNG!

\param[out] ctx The PRNG context.
\param[in]  entropy Pointer to the array with the entropy input. (EscHashDrbg_ENTROPY_LEN bytes)
\param[in]  nonce Pointer to the array with the nonce. (EscHashDrbg_NONCE_LEN bytes)

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHashDrbg_Init(
    EscHashDrbg_ContextT* ctx,
    const Esc_UINT8 entropy[],
    const Esc_UINT8 nonce[] );

/**
Compute a new seed and a new state with newly generated entropy.
This function must be called if the Reseed counter is higher than the define
EscHashDrbg_RESEED_INTERVAL according to the NIST Recommendation.

\param[out] ctx The PRNG context.
\param[in] entropy Random Number Array to add entropy to Seed and State. (EscHashDrbg_ENTROPY_LEN bytes)

\return Esc_NO_ERROR if everything works fine.
*/

Esc_ERROR
EscHashDrbg_Reseed(
    EscHashDrbg_ContextT* ctx,
    const Esc_UINT8 entropy[] );

#if EscHashDrbg_ADJUSTABLE_OUT_LEN == 1

/**
Returns a random number derived from the actual state. The internal state is updated.
The return data is depending on the define EscHashDrbg_ADJUSTABLE_OUT_LEN.

\param[out] ctx The PRNG context.
\param[out] rnd The random number. (EscHashDrbg_BLOCK_LEN bytes or the requested length)
\param[in]  len The length in bytes of the rnd array. According to the standard,
                at most 65536 bytes should be requested with a single call!

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHashDrbg_GetRandom(
    EscHashDrbg_ContextT* ctx,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/**
A wrapper to EscHashDrbg_GetRandom() which can be used if a callback of type
EscRandom_GetRandom is required (see random.h).

\param[out] ctx The PRNG context. Note that this is actually of type (EscHashDrbg_ContextT *), but
                declared as (void *) for compatibility to EscRandom_GetRandom.
\param[out] rnd The random number.
\param[in]  len The length in bytes of the rnd array.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHashDrbg_GetRandomWrapper(
    void* ctx,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

#else
/**
Returns a random number derived from the actual state. The internal state is updated.
The return data is depending on the define EscHashDrbg_ADJUSTABLE_OUT_LEN

\param[out] ctx The PRNG context.
\param[out] rnd The random number. (EscHashDrbg_BLOCK_LEN bytes)

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscHashDrbg_GetRandom(
    EscHashDrbg_ContextT* ctx,
    Esc_UINT8 rnd[] );

#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif
