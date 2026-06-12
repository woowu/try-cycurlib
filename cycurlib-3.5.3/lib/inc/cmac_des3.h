/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       CMAC implementation based on Triple-DES according to NIST SP 800-38B.

   \see         NIST SP 800-38B

   $Rev: 982 $
 */
/***************************************************************************/

#ifndef ESC_CMAC_DES3_H_
#define ESC_CMAC_DES3_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "des3_ecb.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Maximum MAC length for CMAC-DES3 */
#define EscCmacDes3_MAX_MAC_LENGTH  (EscDes_BLOCK_BYTES)

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** 3-DES context in CMAC mode. */
typedef struct
{
    /** Context in ECB mode. */
    EscDes3Ecb_ContextT ecbCtx;
    /** Current block. */
    Esc_UINT8 block[EscDes_BLOCK_BYTES];
    /** Number of bytes in block used. */
    Esc_UINT8 blockLen;
} EscCmacDes3_ContextT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the CMAC context with the corresponding DES3 key.

This function does not check the key for weaknesses nor does it
check the parity bits.

To check if a key is a known weak key, use the function EscDesKeytest_IsKeyWeak().
\see des_keytest.h

\param[out] ctx The DES3-CMAC context.
\param[in] k1 TDEA K1. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] k2 TDEA K2. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] k3 TDEA K3. Key bytes array. Array of size EscDes_KEY_BYTES.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacDes3_Init(
    EscCmacDes3_ContextT* ctx,
    const Esc_UINT8 k1[],
    const Esc_UINT8 k2[],
    const Esc_UINT8 k3[] );

/**
Start a new MAC computation using the key provided in EscCmacDes3_Init().
This function resets the internal state such that a new MAC can be
computed after EscCmacDes3_Finish(). Calling this function after EscCmacDes3_Init()
is not required.

\param[in] ctx The DES3-CMAC context.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacDes3_Start(
    EscCmacDes3_ContextT* ctx);

/**
Updates the DES3-CMAC context with message data.

\param[in] ctx The previous DES3-CMAC context.
\param[out] ctx The updated DES3-CMAC context.
\param[in] message The message to add to the authentication code.
\param[in] messageLength of message in byte. Does not need to match DES block boundaries.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacDes3_Update(
    EscCmacDes3_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength );

/**
Returns the MAC value calculated using CMAC

\param[in] ctx The previous DES3-CMAC context.
\param[out] ctx The updated DES3-CMAC context. It is invalid now.
\param[in] mac Buffer to store CMAC value of macLength bytes.
\param[in] macLength The desired length of the resulting MAC, in bytes. This parameter can be used
                        to truncate the MAC such that only the first bytes are copied to the
                        output buffer. Must not be zero and must not be larger than
                        EscCmacDes3_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacDes3_Finish(
    EscCmacDes3_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength );

/**
Calculate CMAC based on DES3 for the input data

\param[in] k1 TDEA K1. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] k2 TDEA K2. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] k3 TDEA K3. Key bytes array. Array of size EscDes_KEY_BYTES.
\param[in] message Input message which should be maced.
\param[in] messageLength Number of bytes of the input message.
\param[out] mac Buffer to store CMAC value of macLength bytes. Can be the same as the message buffer.
\param[in] macLength The desired length of the resulting MAC, in bytes. This parameter can be used
                        to truncate the MAC such that only the first bytes are copied to the
                        output buffer. Must not be zero and must not be larger than
                        EscCmacDes3_MAX_MAC_LENGTH.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCmacDes3_Calc(
    const Esc_UINT8 k1[],
    const Esc_UINT8 k2[],
    const Esc_UINT8 k3[],
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
