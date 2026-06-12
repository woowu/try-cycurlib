/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Miyaguchi-Preneel construction compression function and key
                derivation for SHE.

   \see

   Based on AES-128

   $Rev$
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "she_mp.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static
void
EscSheMpRound(
    const Esc_UINT8 key[16],
    const Esc_UINT8 message[16],
    Esc_UINT8 digest[16])
{
    EscAes_ContextT ctx;
    Esc_UINT8 cipher[16];
    Esc_UINT8 i;

    EscAes_Init(&ctx, 128U, key);
    EscAes_EncryptBlock(&ctx, message, cipher);
    for (i=0U; i<16U; i++)
    {
        digest[i] = cipher[i] ^ key[i] ^ message[i];
    }
}

Esc_ERROR
EscSheMpComp(
    const Esc_UINT8 message[],
    const Esc_UINT32 bitLength,
    Esc_UINT8 digest[16])
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 fullBlocks = bitLength / EscAes_BLOCK_BITS;
    Esc_UINT8 remainBits = (Esc_UINT8)(bitLength % EscAes_BLOCK_BITS);
    Esc_UINT8 bytePos = remainBits / 8U;
    Esc_UINT8 bitShift = 7U - (remainBits % 8U);
    Esc_UINT8 spill = ((remainBits % 8U) > 0U) ? 1U : 0U;
    Esc_UINT32 i = 0U;

    if ((message == Esc_NULL_PTR) || (digest == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        Esc_UINT8 padding[16] = {0U,};
        Esc_memset(digest, 0U, 16U);

        for (i=0; i < fullBlocks; i++)
        {
            EscSheMpRound(digest, &message[i*16U], digest);
        }

        if (remainBits > 0U)
        { /* copy left over bytes from original message to last/padding block */
            Esc_memcpy(padding, &message[fullBlocks * 16U], (Esc_UINT32)bytePos + spill);
        }
        /* set the '1' bit at the correct position */
        padding[bytePos] |= (Esc_UINT8)(1U << bitShift);

        if (remainBits > 88U)
        { /* if we have more than 88 bits, the 40 length bits won't fit into this block - so feed it to the function without length */
            EscSheMpRound(digest, padding, digest);
            /* re-initialize the padding to all zero in order to only set the length bits below */
            Esc_memset(padding, 0, 16U);
        }
        /* set the length bits at the correct position - note that the highest length byte will always be '0' from initialization since we only take a uint32 */
        padding[12] = ((Esc_UINT8)(bitLength >> 24U)&(0xffU));
        padding[13] = ((Esc_UINT8)(bitLength >> 16U)&(0xffU));
        padding[14] = ((Esc_UINT8)(bitLength >> 8U)&(0xffU));
        padding[15] = ((Esc_UINT8)(bitLength)&(0xffU));

        EscSheMpRound(digest, padding, digest);
    }
    return returnCode;
}

Esc_ERROR
EscSheMpKdf(
    const Esc_UINT8 key[16],
    const Esc_UINT8 type,
    Esc_UINT8 derived[16])
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    if ((key == Esc_NULL_PTR) || (derived == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ((type < EscShe_KEY_UPDATE_ENC_C) || (type > EscShe_PRNG_SEED_KEY_C))
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* according to the constants given in chapter 12 of the SHE functional specification, the input key
         * is always 16 bytes in size and the constants given have been padded and length bytes set accordingly */
        Esc_UINT8 constant[16] = {0x01, 0x00, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
        constant[1] = type;
        Esc_memset(derived, 0, 16);
        EscSheMpRound(derived, key, derived);
        EscSheMpRound(derived, constant, derived);
    }
    return returnCode;
}
/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
