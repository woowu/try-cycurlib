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
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "cmac_des3.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

static void
EscCmacDes3_LeftShiftBlock(
    Esc_UINT8 block[] );

static void
EscCmacDes3_ApplySubkey(
    EscCmacDes3_ContextT* ctx );

static void
EscCmacDes3_EncryptBlock(
    EscCmacDes3_ContextT* ctx );

static void
EscCmacDes3_UpdateLastBlock(
    EscCmacDes3_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/*********************************************************
 Does a left shift of one block by one bit. The rightmost bit
 will be zero.
 NIST 800-38B Chapter 5.1 paragraph 6
 *********************************************************/
static void
EscCmacDes3_LeftShiftBlock(
    Esc_UINT8 block[] )
{
    Esc_UINT8 i;

    /* Left shift all bytes except the last one */
    for (i = 0U; i < (EscDes_BLOCK_BYTES - 1U); i++)
    {
        Esc_UINT8 t;

        /* Left shift the current byte */
        block[i] = (Esc_UINT8)(block[i] << 1U);

        /* Borrow a bit from the next byte without using 'if' to improve
           side-channel resistance */
        t = (Esc_UINT8)(block[i + 1U] & 0x80U);
        t = (Esc_UINT8)(t >> 7);
        block[i] |= t;
    }

    /* Left shift the last byte, no borrowing needed */
    block[EscDes_BLOCK_BYTES - 1U] = (Esc_UINT8)(block[EscDes_BLOCK_BYTES - 1U] << 1);
}

/************************************
Encrypt the current block, resets blocklength
 ************************************/
static void
EscCmacDes3_EncryptBlock(
    EscCmacDes3_ContextT* ctx )
{
    EscDes3Ecb_EncryptFast( &ctx->ecbCtx, ctx->block, ctx->block );
    ctx->blockLen = 0U;
}

/************************************
Calculates subkey K1 or K2 and applies it to the residual data
 ************************************/
static void
EscCmacDes3_ApplySubkey(
    EscCmacDes3_ContextT* ctx )
{
    static const Esc_UINT8 ALL_ZERO[EscDes_BLOCK_BYTES] =     /* For CMAC, the IV is 000000... */
    {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };
    static const Esc_UINT8 CMAC_RB = 0x1BU; /* R_B value of chapter 5.3 */
    Esc_UINT8 k[EscDes_BLOCK_BYTES];      /* Contains L, K1 and K2 */
    Esc_UINT8 i;

    /*** Subkey generation, chapter 6.1. Calculate the k1 and k2 ***/
    /* 1. K1 = L = ciph(0) */
    EscDes3Ecb_EncryptFast( &ctx->ecbCtx, ALL_ZERO, k );

    /* 2. If MSB1(L) = 0, then K1 = L << 1;
       Else K1 = (L << 1) exor Rb */
    if ( (k[0] & 0x80U) == 0U )
    {
        EscCmacDes3_LeftShiftBlock( k );    /* K1 = L << 1 */
    }
    else
    {
        EscCmacDes3_LeftShiftBlock( k );    /* K1 = L << 1 */
        k[EscDes_BLOCK_BYTES - 1U] ^= CMAC_RB;    /* K1 = (L << 1) exor Rb */
    }

    /* If not a complete block, calculate K2 */
    if (ctx->blockLen != EscDes_BLOCK_BYTES)
    {
        /* 3. If MSB1(K1) = 0, then K2 = K1 << 1;
           Else K2 = (K1 << 1) exor Rb. */
        if ( (k[0] & 0x80U) == 0U )
        {
            EscCmacDes3_LeftShiftBlock( k );    /* K2 = K1 << 1 */
        }
        else
        {
            EscCmacDes3_LeftShiftBlock( k );    /* K2 = K1 << 1 */
            k[EscDes_BLOCK_BYTES - 1U] ^= CMAC_RB;    /* K2 = (K1 << 1) exor Rb */
        }
    }

    /* 4. Return K1 and K2 */

    /* Chapter 6.2:
       4. If Mn* is a complete block, let Mn = K1 exor Mn*;
       else, let Mn = K2 exor (Mn*||10j), where j = nb-Mlen-1. */
    /* k contains now K1 or K2, depending on the completeness of the last block,
       exor with the last block */
    for (i = 0U; i < EscDes_BLOCK_BYTES; i++)
    {
        ctx->block[i] ^= k[i];
    }
}

/************************************
Updates the last block, using the residual data and applying the subkey
 ************************************/
static void
EscCmacDes3_UpdateLastBlock(
    EscCmacDes3_ContextT* ctx )
{
    /* Chapter 6.2:
       4. If Mn* is a complete block, let Mn = K1 exor Mn*;
       else, let Mn = K2 exor (Mn*||10j), where j = nb-Mlen-1. */

    /* Is complete block? */
    if (ctx->blockLen != EscDes_BLOCK_BYTES)
    {
        /* First byte is 0x80, others are 0x00 */
        ctx->block[ctx->blockLen] ^= 0x80U;
    }

    /* Apply subkey */
    EscCmacDes3_ApplySubkey( ctx );

    /* Encrypt last block */
    EscCmacDes3_EncryptBlock( ctx );
}

/************************************
Initialize CMAC. Documentation references refer to NIST 800-38B
 ************************************/
Esc_ERROR
EscCmacDes3_Init(
    EscCmacDes3_ContextT* ctx,
    const Esc_UINT8 k1[],
    const Esc_UINT8 k2[],
    const Esc_UINT8 k3[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         (k1 != Esc_NULL_PTR) &&
         (k2 != Esc_NULL_PTR) &&
         (k3 != Esc_NULL_PTR) )
    {
        /* Initializes the block cipher and check for correct key parameter */
        returnCode = EscDes3Ecb_Init( &ctx->ecbCtx, k1, k2, k3 );

        if (returnCode == Esc_NO_ERROR)
        {
            /* initialize state */
            returnCode = EscCmacDes3_Start(ctx);
        }
    }

    return returnCode;
}

/************************************
Start a new MAC computation.
 ************************************/
Esc_ERROR
EscCmacDes3_Start(
    EscCmacDes3_ContextT* ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 i;

    if (ctx != Esc_NULL_PTR)
    {
        /* First cipherblock is 0000... (Chapter 6.2, Step 5) */
        for (i = 0U; i < EscDes_BLOCK_BYTES; i++)
        {
            ctx->block[i] = 0U;
        }

        /* No data at the beginning */
        ctx->blockLen = 0U;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/************************************
Adds more message data to the MAC
 ************************************/
Esc_ERROR
EscCmacDes3_Update(
    EscCmacDes3_ContextT* ctx,
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ( (ctx != Esc_NULL_PTR) &&
         ( (message != Esc_NULL_PTR) || (messageLength == 0U) ) ) /* Allow NULL pointer if length is zero */
    {
        Esc_UINT32 bytesLeft = messageLength;
        Esc_UINT32 msgPos = 0U;
        Esc_UINT8* b = ctx->block;

        while (bytesLeft > 0U)
        {
            Esc_UINT8 bytesToFill;

            /* if block is complete - encrypt */
            if (ctx->blockLen == EscDes_BLOCK_BYTES)
            {
                EscCmacDes3_EncryptBlock( ctx );
            }

            /* fill block with remaining bytes, blockLen is now smaller than EscDes_BLOCK_BYTES */
            if ( bytesLeft >= ( (Esc_UINT32)EscDes_BLOCK_BYTES - (Esc_UINT32)ctx->blockLen ) )
            {
                bytesToFill = EscDes_BLOCK_BYTES - ctx->blockLen;
            }
            else
            {
                bytesToFill = (Esc_UINT8)bytesLeft;
            }

            /* Copy the new bytes to the current block */
            while (bytesToFill > 0U)
            {
                /* Nist Chapter 6.2: 6. For i = 1 to n, let Ci = CIPHK(Ci-1 exor Mi). */
                b[ctx->blockLen] ^= message[msgPos];

                ctx->blockLen++;
                msgPos++;
                bytesToFill--;
                bytesLeft--;
            }
        }

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/************************************
Process residual block and copy MAC data to user
 ************************************/
Esc_ERROR
EscCmacDes3_Finish(
    EscCmacDes3_ContextT* ctx,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    /* See (chapter 6.2 ) */

    if ( (ctx == Esc_NULL_PTR) || (mac == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ((macLength > EscCmacDes3_MAX_MAC_LENGTH) || (macLength == 0U))
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* 4. Process residual block if any */
        EscCmacDes3_UpdateLastBlock( ctx );

        /* Copy MAC to output */
        /* 7. Let T = MSB(Tlen) */
        for (i = 0U; i < macLength; i++)
        {
            mac[i] = ctx->block[i];
        }
    }

    return returnCode;
}

/****************************************************
 * calculate CMAC based on DES3 for the input data *
 ****************************************************/
Esc_ERROR
EscCmacDes3_Calc(
    const Esc_UINT8 k1[],
    const Esc_UINT8 k2[],
    const Esc_UINT8 k3[],
    const Esc_UINT8 message[],
    Esc_UINT32 messageLength,
    Esc_UINT8 mac[],
    Esc_UINT8 macLength )
{
    EscCmacDes3_ContextT ctx;
    Esc_ERROR returnCode;

    /* Parameter test is done in the underlying functions */
    returnCode = EscCmacDes3_Init( &ctx, k1, k2, k3 );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacDes3_Update( &ctx, message, messageLength );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscCmacDes3_Finish( &ctx, mac, macLength );
        }
    }

    /* Zeroize DES3-CMAC context as it contains key rounds */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
