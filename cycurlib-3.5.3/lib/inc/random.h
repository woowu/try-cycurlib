/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Types for random number generators

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_RANDOM_H_
#define ESC_RANDOM_H_

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

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * Function prototype for pseudo-random number generators (PRNGs).
 * Various functions in the CycurLIB expect such a PRNG to generate random numbers.
 * One implementation of this prototype is the Hash_DRBG contained in the CycurLIB.
 * See EscHashDrbg_GetRandomWrapper() in file hash_drbg.h.
 *
 * The PRNG is expected to be cryptographically secure! Implementations such as
 * rand() from the C standard library are NOT secure and should not be used in this context!
 *
 * \param[in]   prngState   Random state as your random implementation needs it.
 * \param[out]  rnd         Pointer to the array where the random data will be stored
 * \param[in]   len         Requested length of random data
 *
 * \return Esc_NO_ERROR if everything works fine
 */
typedef Esc_ERROR (*EscRandom_GetRandom)(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif /*
*/

#endif /*
*/
