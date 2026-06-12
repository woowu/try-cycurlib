/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       ChaCha20 implementation, according to RFC-7539.

   $Rev: 0001 $
 */
/***************************************************************************/

#ifndef ESC_CHACHA20_H_
#define ESC_CHACHA20_H_

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

/** Length of the nonce in bytes. */
#define EscChaCha20_NONCE_BYTES 12U

/** Length of state and keystream in 32 bit words. */
#define EscChaCha20_STATE_WORDS 16U

/** Length of state and keystream block in bytes. */
#define EscChaCha20_BLOCK_BYTES 64U

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

/** Context for ChaCha20 */
typedef struct
{
    /** Internal state. */
    Esc_UINT32 state[EscChaCha20_STATE_WORDS];

    /** Keystream buffer. */
    Esc_UINT32 keystream[EscChaCha20_STATE_WORDS];

    /** Current keystream byte position. */
    Esc_UINT32 keyStreamPosition;
} EscChaCha20_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
This function initializes the ChaCha20 state.

\param[in, out] ctx Pointer to ChaCha20 context
\param[in] keyBits Bit length of the key. Allowed values are: 256 (recommended) or 128.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                256 bits => 32 bytes
\param[in] nonce 96 Bit nonce, sometimes also called initialization vector IV.
                Has to be an array of EscChaCha20_NONCE_BYTES bytes.
\param[in] blockCtr 32 bit initial block counter.  This can be set to any number, but will usually be zero or one.
                It makes sense to use one if the zero block is used for something else, such as generating a
                one-time authenticator key as part of an AEAD algorithm.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscChaCha20_Init(
    EscChaCha20_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT32 blockCtr );


/**
Sets the block counter for an initialized ChaCha context.

Must not be called during the processing of a message. After a block counter update,
a call to EscChaCha20_Start() is required.

\param[in, out] ctx Pointer to ChaCha20 context.
\param[in] blockCtr 32 bit block counter.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscChaCha20_UpdateCnt(
    EscChaCha20_ContextT* ctx,
    Esc_UINT32 blockCtr );


/**
Starts the processing of a new message. Must be called for every new message.

\param[in, out] ctx Pointer to ChaCha20 context

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscChaCha20_Start(
    EscChaCha20_ContextT* ctx );


/**
Encrypts or decrypts data of arbitrary length.
However, processing a multiple of the ChaCha20 block size of 64 byte is performed faster.
Thus, if the calling application provides enough memory, requesting a block aligned length should be preferred.

This implementation has no Finish() function, the Update() call can handle all arbitrary message lengths.
For processing a new message the user has to call EscChaCha20_Start().

\pre The context must be initialized with EscChaCha20_Init() and EscChaCha20_Start().

\param[in, out] ctx Pointer to ChaCha20 context
\param[in] input Plaintext or ciphertext to process
\param[out] output Resulting plaintext or ciphertext
\param[in] length Length of input and output data.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscChaCha20_Update(
    EscChaCha20_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 output[],
    Esc_UINT32 length );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
