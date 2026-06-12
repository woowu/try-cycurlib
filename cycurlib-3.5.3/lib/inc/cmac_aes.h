/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       CMAC implementation based on AES according to NIST SP 800-38B.

   \see         NIST SP 800-38B

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_CMAC_AES_H_
#define ESC_CMAC_AES_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

 #include "_aes.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Maximum MAC length for CMAC-AES */
#define EscCmacAes_MAX_MAC_LENGTH  (EscAes_BLOCK_BYTES)

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** AES context in CMAC mode. */
typedef struct
{
    /** AES Context */
    EscAes_ContextT aesCtx;
    /** Current block. */
    Esc_UINT8 block[EscAes_BLOCK_BYTES];
    /** Number of bytes in block used. */
    Esc_UINT8 blockLen;
} EscCmacAes_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the CMAC context with the corresponding AES key.

\param[out] ctx The AES-CMAC context.
\param[in] key Key bytes array.
\param[in] keyLength Length of the key array. Must be one of the following:
                16 bytes (for CMAC-AES-128).
                24 bytes (for CMAC-AES-192).
                32 bytes (for CMAC-AES-256).

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacAes_Init(
    EscCmacAes_ContextT* ctx,
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength );

/**
Start a new MAC computation using the key provided in EscCmacAes_Init().
This function resets the internal state such that a new MAC can be
computed after EscCmacAes_Finish(). Calling this function after EscCmacAes_Init()
is not required.

\param[in] ctx The AES-CMAC context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacAes_Start(
    EscCmacAes_ContextT* ctx);

/**
Updates the AES-CMAC context with message data.

\param[in,out] ctx The AES-CMAC context.
\param[in] message The message to add to the authentication code.
\param[in] messageLength The length of the message in bytes. Does not need to match AES block boundaries.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacAes_Update(
    EscCmacAes_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
Returns the MAC value calculated using CMAC

\param[in,out] ctx The AES-CMAC context.
\param[out] mac Buffer to store CMAC value of macLength bytes.
\param[in] macLength The desired length of the resulting MAC, in bytes. This parameter can be used
                        to truncate the MAC such that only the first bytes are copied to the
                        output buffer. Must not be zero and must not be larger than
                        EscAes_BLOCK_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacAes_Finish(
    EscCmacAes_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
Returns the MAC value calculated using CMAC in one step.

\param[in] key Key bytes array.
\param[in] keyLength Length of the key array. Must be one of the following:
                16 bytes (for CMAC-AES-128).
                24 bytes (for CMAC-AES-192).
                32 bytes (for CMAC-AES-256).
\param[in] message The input message for the AES-CMAC.
\param[in] messageLength The length of message in bytes. Does not need to match AES block boundaries.
\param[out] mac Buffer to store CMAC value of macLength bytes. Can be the same as the message buffer.
\param[in] macLength The desired length of the resulting MAC, in bytes. This parameter can be used
                        to truncate the MAC such that only the first bytes are copied to the
                        output buffer. Must not be zero and must not be larger than
                        EscCmacAes_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacAes_Calc(
    const Esc_UINT8 key[],
    Esc_UINT32 keyLength,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
