/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Core functions of Blowfish implementation.

   All functions and data structures in this module are supposed to
   be used by other Blowfish modules. They must not be called by the
   user directly.


   \see         www.schneier.com/blowfish.html

   $Rev: 1458 $
 */
/***************************************************************************/

#ifndef ESC_BLOWFISH_H_
#define ESC_BLOWFISH_H_

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

/** Minimum size of Blowfish key in bytes as defined in the standard. */
#define EscBfish_MIN_KEY_BYTES 4U

/** Maximum size of Blowfish key in bytes as defined in the standard. */
#define EscBfish_MAX_KEY_BYTES 56U

/** Size of one Blowfish block in bytes. */
#define EscBfish_BLOCK_BYTES 8U

/** The number of Blowfish rounds. */
#define EscBfish_NUM_ROUNDS 16U

/** Number of Blowfish S-boxes */
#define EscBfish_NUM_SBOX 4U

/** Size of Blowfish S-boxes */
#define EscBfish_SIZE_SBOX 256U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** The Blowfish key schedule. */
typedef struct
{
    /** Blowfish P-array */
    Esc_UINT32 p[EscBfish_NUM_ROUNDS + 2U];
    /** Blowfish S-boxes */
    Esc_UINT32 s[EscBfish_NUM_SBOX][EscBfish_SIZE_SBOX];
} EscBfish_KeySchedT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 Splits 64-bit input block into two 32-bit blocks.

 This is an internal function, which should not be called by the user directly.

 \param[out] pl Updated pl, containing left 32-bit half of the Blowfish block.
 \param[out] pr Updated pr, containing right 32-bit half of the Blowfish block.
 \param[in] bfishBlock The input 64-bit Blowfish block.

 */
void
EscBfish_SplitBlock(
    Esc_UINT32* pl,
    Esc_UINT32* pr,
    const Esc_UINT8 bfishBlock[] );

/**
 Merges two 32-bit halves into 64-bit data block.

 This is an internal function, which should not be called by the user directly.

 \param[out] bfishBlock The output 64-bit Blowfish block.
 \param[in] pl Containing left 32-bit half of Blowfish block.
 \param[in] pr Containing right 32-bit half of Blowfish block.

 */
void
EscBfish_MergeBlocks(
    Esc_UINT8 bfishBlock[],
    Esc_UINT32 pl,
    Esc_UINT32 pr );

/**
 Calculates the key for encryption and decryption.

 This is an internal function, which should not be called by the user directly.

 \param[out] sched The key schedule.
 \param[in] key The input key word.
 \param[in] keyLen The length of the used key.

 */
void
EscBfish_Init(
    EscBfish_KeySchedT* sched,
    const Esc_UINT8 key[],
    const Esc_UINT8 keyLen );

/**
 Performs Blowfish encryption.

 This is an internal function, which should not be called by the user directly.

 \param[in] sched The key schedule.
 \param[in,out] pl Containing left 32-bit half of Blowfish block.
 \param[in,out] pr Containing right 32-bit half of Blowfish block.

 */
void
EscBfish_Encrypt(
    const EscBfish_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr );

/**
 Performs Blowfish decryption.

 This is an internal function, which should not be called by the user directly.

 \param[in] sched The key schedule.
 \param[in,out] pl Containing left 32-bit half of Blowfish block.
 \param[in,out] pr Containing right 32-bit half of Blowfish block.

 */
void
EscBfish_Decrypt(
    const EscBfish_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif /* ESC_BLOWFISH_H_ */
