/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Dummy random number generator. Do NOT use this in your application!

   $Rev: 2106 $
 */
/***************************************************************************/

/***************************************************************************
 * 0. WARNING                                                              *
 ***************************************************************************/

/*

   The provided functions are test implementations and are NOT SECURE!!!
   They must not be used in a real-world-implementation.

*/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "random.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#ifndef EscTstRandom_RND_LENGTH
/** The length of the used random data for the tests. May be overwritten for specific hosttests. */
#   define EscTstRandom_RND_LENGTH 20U
#endif

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/** Random context */
typedef struct
{
    /** random data */
    Esc_UINT8 rnd[EscTstRandom_RND_LENGTH];
} EscTstRandom_ContextT;

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
 * Initialize dummy PRNG used for tests.
 *
 * \param[in, out]  ctx     Context/state of PRNG.
 * \param[in]       rnd     The seed of length EscTstRandom_RND_LENGTH used to initialize the PRNG.
 *
 * \return Esc_NO_ERROR on success.
 */
Esc_ERROR
EscTstRandom_Init(
    EscTstRandom_ContextT* ctx,
    const Esc_UINT8 rnd[] );

/**
 * Return pseudo-random numbers (dummy implementation used for tests).
 * Note: This implementation is NOT cryptographically secure!
 *
 * \param[in]   prngState   Context/state of PRNG. This is actually of type EscTstRandom_ContextT,
 *                          but declared as (void *) for compatibility with EscRandom_GetRandom
 *                          (see random.h).
 * \param[out]  rnd         Buffer to fill with random values.
 * \param[in]   len         Length of buffer.
 */
Esc_ERROR
EscTstRandom_GetRandom(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
