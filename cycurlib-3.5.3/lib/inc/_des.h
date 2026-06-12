/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DES implementation generic code.

   All functions and data structures in this module are not supposed to
   be used by the by other DES modules. The must not be called by the
   user directly.


   \see FIPS PUB 46-3

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC__DES_H_
#define ESC__DES_H_

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

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#    ifndef EscDes_USE_BIG_TABLES
/** Increases speed significantly on costs of 1,5KB tables */
#        define EscDes_USE_BIG_TABLES 1
#    endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#    ifndef EscDes_USE_BIG_TABLES
/** Increases speed significantly on costs of 1,5KB tables */
#        define EscDes_USE_BIG_TABLES 0
#    endif
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** The length of an 56 bit DES key in bytes including parity bits.
 The parity bits are ignored. */
#define EscDes_KEY_BYTES 8U

/** Size of one DES block in bytes. */
#define EscDes_BLOCK_BYTES 8U

/** The number of rounds. */
#define EscDes_NUM_ROUNDS 16U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** The keys required for one round. */
typedef struct
{
    /** First part of the round key. */
    Esc_UINT32 k1;
    /** Second part of the round key. */
    Esc_UINT32 k2;
} EscDes_RoundKeyT;

/** The DES key schedule. */
typedef struct
{
    /** Encryption round keys */
    EscDes_RoundKeyT k[EscDes_NUM_ROUNDS];
} EscDes_KeySchedT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 Performs the initial permutation.

 This is an internal function, which should not be called by the user directly.

 \param[out] l Updated l, containing l_0 of the first round.
 \param[out] r Updated r, containing r_0 of the first round.
 \param[in] desBlock The input DES-Block.

 */
void
EscDes_IntitialPermutation(
    Esc_UINT32* l,
    Esc_UINT32* r,
    const Esc_UINT8 desBlock[] );

/**
 Performs the final permutation.

 This is an internal function, which should not be called by the user directly.

 \param[out] desBlock The result of the permutation.
 \param[in] l Containing l_16 of the last round.
 \param[in] r Containing r_16 of the last round.

 */
void
EscDes_FinalPermutation(
    Esc_UINT8 desBlock[],
    Esc_UINT32 l,
    Esc_UINT32 r );

/**
Processes the DES rounds forward.

This is an internal function, which should not be called by the user directly.

\param[in] sched The key schedule.
\param[in] pl Points to l_0 of the first round.
\param[in] pr Points to r_0 of the first round.
\param[out] pl Updated to l_16 of the last round.
\param[out] pr Updated to r_16 of the last round.

*/
void
EscDes_EncryptRounds(
    const EscDes_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr );

/**
Processes the DES rounds forward.

This is an internal function, which should not be called by the user directly.

\param[in] sched The key schedule.
\param[in] pl Points to l_16 of the last round.
\param[in] pr Points to r_16 of the last round.
\param[out] pl Updated to l_0 of the first round.
\param[out] pr Updated to r_0 of the first round.

*/
void
EscDes_DecryptRounds(
    const EscDes_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr );

/**
Initializes the ECB Context with the corresponding DES key.

This is an internal function, which should not be called by the user directly.

\param[in] sched Buffer, to store the key schedule to.
\param[out] sched The initialized key schedule.
\param[in] key The DES key to use. EscDes_KEY_BYTES byte.
*/
void
EscDes_Init(
    EscDes_KeySchedT* sched,
    const Esc_UINT8 key[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif
