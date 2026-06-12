/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Random number generator
   \attention   The implementation has to be adapted to your needs!

   $Rev: 2106 $
 */
/***************************************************************************/

/***************************************************************************
 * 0. WARNING                                                              *
 ***************************************************************************/

/*

   The provided functions are test implementations and are NOT SECURE.
   They must not be used in a real-world-implementation.

*/

/***************************************************************************
* 1. INCLUDES                                                             *
***************************************************************************/

#include "test_random.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/** Initialize random */
Esc_ERROR
EscTstRandom_Init(
    EscTstRandom_ContextT* ctx,
    const Esc_UINT8 rnd[] )
{

    Esc_UINT32 i;
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         (rnd != Esc_NULL_PTR) )
    {
        for (i = 0U; i < EscTstRandom_RND_LENGTH; i++)
        {
            ctx->rnd[i] = rnd[i];
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/** Returns an array of random data */
Esc_ERROR
EscTstRandom_GetRandom(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    /*lint --e(9087) --e(9079) The Lint warning about Rule 11.3 is a false/positive. We cast a void pointer to object.
      Therefore we violate the cast from void pointer to object type rule (11.5, adv.) intentionally.
      This cast is safe since the void pointer is only for interface compatibility and points to the casted type. */
    EscTstRandom_ContextT* ctx = (EscTstRandom_ContextT*)prngState;

    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    Esc_UINT32 i;

    if ( (rnd != Esc_NULL_PTR) && (ctx != Esc_NULL_PTR) )
    {
        for (i = 0U; i < len; i++)
        {

            rnd[i] = ctx->rnd[i % EscTstRandom_RND_LENGTH];

            ctx->rnd[i % EscTstRandom_RND_LENGTH] += (Esc_UINT8)i % 0xffU;
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
