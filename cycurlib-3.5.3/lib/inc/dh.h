/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Diffie-Hellman key exchange

   $Rev: 2210 $
 */
/***************************************************************************/

#ifndef ESC_DH_H_
#define ESC_DH_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "random.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/**
* Set the maximum bit length of prime p.
* Only the bit lengths 1024, 2048 and 3072 are supported.
*/
#ifndef EscDh_KEY_BITS_MAX
#   define EscDh_KEY_BITS_MAX   1024U
#endif

#ifndef EscDh_WINDOW_SIZE
/** Window size for the Sliding Window algorithm
    Only used if the sliding window algorithm is enabled (EscDh_USE_SLIDING_WINDOW == 1).
    The higher the window size, the higher the RAM usage! */
#   define EscDh_WINDOW_SIZE 4U
#endif

#ifndef EscDh_GENERATION_ATTEMPTS
/** Number of iterations of the parameter generation p and q. */
#   define EscDh_GENERATION_ATTEMPTS    20U
#endif

#if Esc_OPTIMIZE_SPEED == 1

#   ifndef EscDh_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm
    Increases speed, but also increases code size and stack used. */
#       define EscDh_USE_SLIDING_WINDOW 1
#   endif

#else

#   ifndef EscDh_USE_SLIDING_WINDOW
/** Enable for using the Sliding Window algorithm
    Increases speed, but also increases code size and stack used. */
#       define EscDh_USE_SLIDING_WINDOW 0
#   endif

#endif


/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if (EscDh_KEY_BITS_MAX != 1024U) && (EscDh_KEY_BITS_MAX != 2048U) && (EscDh_KEY_BITS_MAX != 3072U)
#    error "Invalid bit length for EscDh_KEY_BITS_MAX configured!"
#endif

#if Esc_HAS_INT64 == 1
/** DH base for calculation (16 or 32 bits) */
#   define EscDh_DH_BASE 32U
/** The maximum value of one HWORD */
#   define EscDh_MAX_VAL 0xFFFFFFFFU
/** half word for calculation (e.g., factor; 16 or 32 bit) */
typedef Esc_UINT32 EscDh_HWORD;
/** full word for calculation (e.g., result; 32 or 64 bit) */
typedef Esc_UINT64 EscDh_FWORD;
#else
/** DH base for calculation (16 or 32 bits) */
#   define EscDh_DH_BASE 16U
/** The maximum value of one HWORD */
#   define EscDh_MAX_VAL 0xFFFFU
/** half word for calculation (e.g., factor; 16 or 32 bit) */
typedef Esc_UINT16 EscDh_HWORD;
/** full word for calculation (e.g., result; 32 or 64 bit) */
typedef Esc_UINT32 EscDh_FWORD;
#endif

/** Size of DH modulus in bytes calculated from bits (rounded up)  */
#define EscDh_KEY_BYTES_FROMBITS(b) ( ((b) + 7U) / 8U )

/** Size of maximum DH modulus in bytes */
#define EscDh_KEY_BYTES_MAX ( EscDh_KEY_BYTES_FROMBITS( EscDh_KEY_BITS_MAX ) )

/** Size of one DH Word in byte */
#define EscDh_WORD_SIZE (EscDh_DH_BASE / 8U)

/** Size of DH modulus in words calculated from bits */
#define EscDh_DH_SIZE_WORDS_FROMBITS(b)  (EscDh_KEY_BYTES_FROMBITS( (b) ) / EscDh_WORD_SIZE)

/** Size of DH modulus in words calculated from bytes (rounded up) */
#define EscDh_DH_SIZE_WORDS_FROMBYTES(b)  ( ((b) + (EscDh_WORD_SIZE - 1U)) / EscDh_WORD_SIZE)

/** Computes the size in words of a long FE from key size (in Bits) */
#define EscDh_DH_SIZE_WORDS_LONG_FROMBITS(b) ( (2U * EscDh_DH_SIZE_WORDS_FROMBITS(b)) )

/** Size of maximum DH modulus in words */
#define EscDh_DH_SIZE_WORDS_MAX (EscDh_DH_SIZE_WORDS_FROMBITS(EscDh_KEY_BITS_MAX) )

/** Double size of maximum DH modulus in words (e.g. used for multiplications) */
#define EscDh_DH_SIZE_WORDS_LONG_MAX (2U * EscDh_DH_SIZE_WORDS_MAX)

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** A field element with long number arithmetic */
typedef struct
{
    /** the words of the long number */
    EscDh_HWORD words[EscDh_DH_SIZE_WORDS_MAX];
} EscDh_FieldElementT;

/** The Diffie-Hellman domain parameters. Required for all computations. */
typedef struct
{
    /** The prime modulus p */
    EscDh_FieldElementT p;
    /** The generator g of the group */
    EscDh_FieldElementT g;
    /** The length of p in bytes */
    Esc_UINT16 pLength;
} EscDh_DomainParametersT;

/** Diffie-Hellman public key */
typedef EscDh_FieldElementT EscDh_PublicKeyT;

/** Diffie-Hellman private key */
typedef EscDh_FieldElementT EscDh_PrivateKeyT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * This function initializes a Diffie-Hellman context with the domain parameters p and g.
 *
 * \param[out]  ctx     Diffie-Hellman context.
 * \param[in]   p       Prime modulus p. The two most significant bytes must not both be zero!
 * \param[in]   pLength Length of modulus p in bytes.
 *                      Must be either 128 (=1024 bit), 256 (=2048 bit) or 384 (=3072 bit)
 * \param[in]   g       Generator g. Its value must be in the range [2, p-2].
 * \param[in]   gLength Length of generator g in bytes. Must be in the range [1, pLength].
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_InitDomainParameters(
    EscDh_DomainParametersT* ctx,
    const Esc_UINT8 p[],
    const Esc_UINT16 pLength,
    const Esc_UINT8 g[],
    const Esc_UINT16 gLength );

/**
 * This function generates a random private and the corresponding public key.
 *
 * \param[in] ctx           Diffie-Hellman context, defining the domain parameters.
 * \param[in] prngFunc      PRNG function as specified in random.h.
 *                          The PRNG must have been seeded before it is passed to this function!
 * \param[in] prngState     State of the PRNG function. This may be NULL if the PRNG is stateless.
 * \param[out] publicKey    The generated public key will be stored in this struct.
 * \param[out] privateKey   The generated private key will be stored in this struct.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_KEY_GENERATION_FAILED if the random numbers led to invalid private/public keys.
 *                                   This error is recoverable if the PRNG is sane.
 */
Esc_ERROR
EscDh_KeyGeneration(
    const EscDh_DomainParametersT* ctx,
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscDh_PublicKeyT* publicKey,
    EscDh_PrivateKeyT* privateKey );

/**
 * This function computes the shared secret z.
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[out] z Buffer of length EscDh_KEY_BYTES_MAX bytes to write shared secret z to.
 * \param[out] zLength Length of the shared secret that was written to the buffer.
 * \param[in] publicKey Public key of the other party member.
 * \param[in] privateKey Your private key.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_ComputeSharedSecret(
    const EscDh_DomainParametersT* ctx,
    Esc_UINT8 z[],
    Esc_UINT16 *zLength,
    const EscDh_PublicKeyT* publicKey,
    const EscDh_PrivateKeyT* privateKey );

/**
 * Initializes a private key from a big endian byte array.
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[out] privateKey The private key struct.
 * \param[in] keyBytes Array which holds the key bytes.
 * \param[in] keyBytesLength Length of data in bytes. Must be at most EscDh_KEY_BYTES_MAX.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_PrivKeyFromBytes(
    const EscDh_DomainParametersT* ctx,
    EscDh_PrivateKeyT* privateKey,
    const Esc_UINT8 keyBytes[],
    Esc_UINT16 keyBytesLength );

/**
 * Initializes a public key from a big endian byte array.
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[out] publicKey The public key struct.
 * \param[in] keyBytes Array which holds the key bytes.
 * \param[in] keyBytesLength Length of data in bytes. Must be at most EscDh_KEY_BYTES_MAX.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_PubKeyFromBytes(
    const EscDh_DomainParametersT* ctx,
    EscDh_PublicKeyT* publicKey,
    const Esc_UINT8 keyBytes[],
    Esc_UINT16 keyBytesLength );

/**
 * Outputs the private key into a big endian byte array. Leading zeros are NOT
 * written into the buffer.
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[in] privateKey The private key.
 * \param[out] keyBytes A byte array of length EscDh_KEY_BYTES_MAX, the key will be stored here.
 * \param[out] keyLength Number of bytes that were written into the buffer.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_BytesFromPrivKey(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PrivateKeyT* privateKey,
    Esc_UINT8 keyBytes[],
    Esc_UINT16 *keyLength);

/**
 * Outputs the public key into a big endian byte array. Leading zeros are NOT
 * written into the buffer.
 *
 * \param[in] ctx Diffie-Hellman context, defining the domain parameters.
 * \param[in] publicKey The public key.
 * \param[out] keyBytes A byte array of length EscDh_KEY_BYTES_MAX, the key will be stored here.
 * \param[out] keyLength Number of bytes that were written into the buffer.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscDh_BytesFromPubKey(
    const EscDh_DomainParametersT* ctx,
    const EscDh_PublicKeyT* publicKey,
    Esc_UINT8 keyBytes[],
    Esc_UINT16 *keyLength);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_DH_H_ */
