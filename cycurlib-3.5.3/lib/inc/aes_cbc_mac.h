/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES implementation (FIPS-197 compliant)
   CBC-MAC-Mode

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_AES_CBC_MAC_H_
#define ESC_AES_CBC_MAC_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "aes_cbc.h"

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
Initializes the CBC context with the corresponding AES key.

\note According to FIPS 113 and RFC 3566 IV is initialized to zero.

\param[out] ctx The AES CBC context.
\param[in] keyBits Bit length of the AES key. Can be 128, 192 or 256.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                192 bits => 24 bytes
                256 bits => 32 bytes

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCbcMac_Init(
    EscAesCbc_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] );

/**
Initializes the CBC context with the corresponding IV.

\param[out] ctx The AES CBC context.
\param[in] iv 128-bit initialization vector. Array of EscAes_IV_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCbcMac_SetIV(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 iv[] );

/**
Calculates CBC-MAC over one or more data blocks and updates the AES context.

The context must be initialized with EscAesCbcMac_Init.

\param[in] ctx The previous AES CBC context.
\param[out] ctx The updated AES CBC context.
\param[in] plain Message the MAC is computed for.
\param[in] length Length of plain data in bytes. Has to be multiple of EscAes_BLOCK_BYTES bytes
           and not 0.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCbcMac_Update(
    EscAesCbc_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT32 length );

/**
Returns the CBC-MAC.

The context must be initialized with EscAesCbcMac_Init.

\param[in] ctx The previous AES CBC context.
\param[out] mac Array of size EscAes_BLOCK_BYTES the MAC value is written to to.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCbcMac_Finish(
    const EscAesCbc_ContextT* ctx,
    Esc_UINT8 mac[] );

/**
Returns the CBC-MAC.

\param[in] keyBits Bit length of the AES key. Can be 128, 192 or 256.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                192 bits => 24 bytes
                256 bits => 32 bytes
\param[in] iv 128-bit initialization vector (IV). Array of EscAes_IV_BYTES bytes.
           This parameter may be a NULL-pointer. In this case an IV of zero is used.
\param[in] message Message the MAC is computed for.
\param[in] messageLen Length of message data in bytes. Has to be multiple of EscAes_BLOCK_BYTES bytes
                      and not 0.
\param[out] mac Array of size EscAes_BLOCK_BYTES the MAC value is written to.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscAesCbcMac_Calc(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    const Esc_UINT8 message[],
    Esc_UINT32 messageLen,
    Esc_UINT8 mac[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
