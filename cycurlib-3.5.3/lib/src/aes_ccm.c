/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
 \file

 \brief     AES implementation (FIPS-197 compliant)
            CCM-Mode (NIST Special Publication 800-38C)

 \see       NIST SP 800-38C


 $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                              *
 ****************************************************************************/

#include "aes_ccm.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscAesCcm_ADATA_BIT 0x40U
#define EscAesCcm_Esc_UINT32_SIZE 4U

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/


static void
EscAesCcm_Generate_S0(
    EscAesCcm_ContextT* ctx );

static void
EscAesCcm_Increase_Counter(
    Esc_UINT8 Counter[] );

static void
EscAesCcm_Generate_Y0(
    EscAesCcm_ContextT* ctx,
    Esc_UINT32 plainLen );

static void
EscAesCcm_AssociatedData_Init(
    EscAesCcm_ContextT* ctx );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
 * Encrypt a plaintext and associated data with the CCM Mode
 */
Esc_ERROR
EscAesCcm_Encrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 cipher[] )
{
    Esc_ERROR returnCode;
    EscAesCcm_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    /* Set AES key */
    returnCode = EscAesCcm_Init( &ctx, keyBits, key );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Set and format input data and nonce */
        returnCode = EscAesCcm_startEncryptDecrypt(
                &ctx,
                nonce,
                nonceLen,
                plainLen,
                aadLen,
                tagLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process associated data */
        if (aadLen > 0U)
        {
            returnCode = EscAesCcm_AssociatedData_Update( &ctx, aad, aadLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process plaintext */
        returnCode = EscAesCcm_Encrypt_Update( &ctx, plain, cipher, plainLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Generate MAC */
        returnCode = EscAesCcm_Encrypt_Finish( &ctx, &cipher[plainLen] );
    }

    /* Zeroize AES-CCM context as it contains key rounds */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/**
 * Decrypt the payload and check the MAC of the input data with the CCM Mode.
 */
Esc_ERROR
EscAesCcm_Decrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 tagLen,
    Esc_UINT8 plain[] )
{
    Esc_ERROR returnCode;
    EscAesCcm_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    /* Check if data is large enough to contain the MAC */
    if (cipherLen < tagLen)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Initialize the Context */
        returnCode = EscAesCcm_Init( &ctx, keyBits, key );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesCcm_startEncryptDecrypt(
                &ctx,
                nonce,
                nonceLen,
                cipherLen - tagLen,          /* Plaintext_Len = Cipher_Len - MAC_Len*/
                aadLen,
                tagLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process associated data */
        if (aadLen > 0U)
        {
            returnCode = EscAesCcm_AssociatedData_Update( &ctx, aad, aadLen );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Process ciphertext */
        returnCode = EscAesCcm_Decrypt_Update( &ctx, cipher, plain, cipherLen - tagLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Verify MAC */
        returnCode = EscAesCcm_Decrypt_Finish( &ctx, &cipher[cipherLen - tagLen] );
    }

    /* Zeroize AES-CCM context as it contains key rounds */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}


/* This function initializes the AES-CCM context */
Esc_ERROR
EscAesCcm_Init(
    EscAesCcm_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) ||
         (key == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBits > EscAes_MAX_KEY_BITS) ||
              ((keyBits != 128U) && (keyBits != 192U) && (keyBits != 256U)))
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        /* Initialize AES keys */
        EscAes_Init( &ctx->aesCtx, keyBits, key );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscAesCcm_startEncryptDecrypt(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 nonce[],
    Esc_UINT8 nonceLen,
    Esc_UINT32 plainLen,
    Esc_UINT32 aadLen,
    Esc_UINT8 tagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || (nonce == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        ctx->plainLen = plainLen;
        ctx->aadLen = aadLen;
        ctx->nonce = nonce;
        ctx->nonceLen = nonceLen;
        ctx->tagLen = tagLen;

        /* Parameter check */
        /* The maximum of q + len_nonce is EscAesCcm_BLOCKSIZE - 1 */
        if (plainLen > 0xffffU)
        {
            /* q must be at least 3 */
            if ( nonceLen > ( (EscAesCcm_BLOCKSIZE - 1U) - 3U ) )
            {
                returnCode = Esc_INVALID_PARAMETER;
            }
            else
            {
                if (plainLen > 0xffffffU)
                {
                    /* q must be at least 4 */
                    if ( nonceLen > ( (EscAesCcm_BLOCKSIZE - 1U) - 4U ) )
                    {
                        returnCode = Esc_INVALID_PARAMETER;
                    }
                }
            }
        }

        /* The length of the nonce can take the following values:
         7, 8, 9, 10, 11, 12, 13 (according to the NIST SP 800-38C) */
        if ( (nonceLen < 7U) || (nonceLen > 13U) )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }

        /* The length of the MAC can take the following values: 4, 6, 8, 10, 12, 14, 16
         * (according to the NIST SP 800-38C) */
        if ( (tagLen < 4U) || (tagLen > 16U) || ( (tagLen % 2U) != 0U ) )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* set q = (EscAesCcm_BLOCKSIZE - 1U) - nonce-length (according to the NIST SP 800-38C)
             * Because of the first B-Block: B0 = Flags  || nonce        || payload length
             *                length ( in Bytes): 1         nonce-length    q              */
            ctx->q = (Esc_UINT8)(EscAesCcm_BLOCKSIZE - 1U) - nonceLen;

            /** Compute Y0 */
            EscAesCcm_Generate_Y0( ctx, plainLen );

            /* if some associated data is used, calculate the needed bytes for the
             * encoded length (ulen) and format the associated data.
             * Maximum length of the associated data is 2^32 -1 bytes, as a result case 3 in
             * NIST SP 800-38C A.2.2 can not occur */
            if (aadLen > 0U)
            {
                EscAesCcm_AssociatedData_Init( ctx );
                ctx->aDataFlag = TRUE;
            }
            else
            {
                ctx->aDataFlag = FALSE;
            }
            /* Generate S0 and the first counter */
            EscAesCcm_Generate_S0( ctx );
            /* No associated data or payload has been provided so far */
            ctx->usedData = 0U;
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesCcm_AssociatedData_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen )
{
    Esc_ERROR returnCode;
    Esc_UINT32 i;
    if (aadLen == 0U)
    {
        /* Allows length of zero */
        returnCode = Esc_NO_ERROR;
    }
    else
    {
        /* NULL pointer check */
        if ( (ctx == Esc_NULL_PTR) || (aad == Esc_NULL_PTR) )
        {
            returnCode = Esc_NULL_POINTER_ERROR;
        }
        else if (ctx->aDataFlag == FALSE)
        {
            /* No associated data expected */
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
        else if ( (aadLen + ctx->usedData) > ctx->aadLen )
        {
            /* More associated data received than expected */
            returnCode = Esc_OUT_OF_RANGE;
        }
        else
        {
            /* Write the associated data */
            /* Y_i = enc(Y_(i-1) XOR B_i) */

            for (i = 0U; i < aadLen; i++)
            {
                /* Xor next byte to Y_i-1 */
                ctx->Yr[ctx->YrLen] ^= aad[i];
                /* Increase counter */
                ctx->YrLen++;

                if (ctx->YrLen >= EscAesCcm_BLOCKSIZE)
                {
                    /* Reset counter */
                    ctx->YrLen = 0U;
                    /* Encrypt to get Y_i */
                    EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );
                }
            }

            /* Increase used data */
            ctx->usedData += aadLen;

            /* Check if associated data was completely received */
            if (ctx->usedData == ctx->aadLen)
            {
                /* Encrypt remaining data if any existent */
                if (ctx->YrLen != 0U)
                {
                    /* Encrypt to get Y_i */
                    EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );
                    /* Reset counter */
                    ctx->YrLen = 0U;
                }
                /* Reset used data for payload */
                ctx->usedData = 0U;
                /* Set associated data flag to false
                 * No associated data can be processed afterwards */
                ctx->aDataFlag = FALSE;
            }
            returnCode = Esc_NO_ERROR;
        }
    }
    return returnCode;
}



Esc_ERROR
EscAesCcm_Encrypt_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode;
    Esc_UINT8 tmpBlock[EscAesCcm_BLOCKSIZE];
    Esc_UINT32 i;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || ( ( (cipher == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ctx->aDataFlag == TRUE)
    {
        /* Expecting associated data */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else if ( (ctx->usedData + length) > ctx->plainLen )
    {
        /* More payload received than expected */
        returnCode = Esc_OUT_OF_RANGE;
    }
    else
    {
        /* Generate encrypted counter */
        EscAes_EncryptBlock( &ctx->aesCtx, ctx->CtrI, tmpBlock );

        for (i = 0U; i < length; i++)
        {
            /* Update B_i */
            ctx->Yr[ctx->YrLen] ^= plain[i];
            /* Encrypt payload */
            cipher[i] = plain[i] ^ tmpBlock[ctx->YrLen];

            ctx->YrLen++;
            if (ctx->YrLen >= EscAesCcm_BLOCKSIZE)
            {
                /* Reset counter */
                ctx->YrLen = 0U;
                /* Encrypt to get Y_i */
                EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );

                /* Get next counter block */
                EscAesCcm_Increase_Counter( ctx->CtrI );
                EscAes_EncryptBlock( &ctx->aesCtx, ctx->CtrI, tmpBlock );
            }
        }
        /* Increase used data */
        ctx->usedData += length;
        returnCode = Esc_NO_ERROR;
    }
    return returnCode;
}


Esc_ERROR
EscAesCcm_Encrypt_Finish(
    EscAesCcm_ContextT* ctx,
    Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || (tag == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->usedData != ctx->plainLen) || (ctx->aDataFlag != FALSE) )
    {
        /* Not enough data received and/or associated data was not fully updated */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        returnCode = Esc_NO_ERROR;
        /* Generate Y_r if necessary */
        if (ctx->YrLen != 0U)
        {
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );
        }
        /* MAC = S_0 XOR Y_r */
        for (i = 0U; i < ctx->tagLen; i++)
        {
            tag[i] = ctx->S0[i] ^ ctx->Yr[i];
        }
    }
    return returnCode;
}


Esc_ERROR
EscAesCcm_Decrypt_Update(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length )
{
    Esc_ERROR returnCode;
    Esc_UINT8 tmpBlock[EscAesCcm_BLOCKSIZE];
    Esc_UINT32 i;

    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || ( ( (cipher == Esc_NULL_PTR) || (plain == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ctx->aDataFlag == TRUE)
    {
        /* Expecting associated data */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else if ( (ctx->usedData + length) > ctx->plainLen )
    {
        /* More data received than expected */
        returnCode = Esc_OUT_OF_RANGE;
    }
    else
    {
        /* Generate encrypted counter */
        EscAes_EncryptBlock( &ctx->aesCtx, ctx->CtrI, tmpBlock );
        for (i = 0U; i < length; i++)
        {
            /* Decrypt cipher */
            plain[i] = cipher[i] ^ tmpBlock[ctx->YrLen];
            /* Update B_i */
            ctx->Yr[ctx->YrLen] ^= plain[i];
            ctx->YrLen++;

            if (ctx->YrLen >= EscAesCcm_BLOCKSIZE)
            {
                /* Reset counter */
                ctx->YrLen = 0U;
                /* Encrypt to get Y_i */
                EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );

                /* Get next counter block */
                EscAesCcm_Increase_Counter( ctx->CtrI );
                EscAes_EncryptBlock( &ctx->aesCtx, ctx->CtrI, tmpBlock );
            }
        }
        /* Increase used data */
        ctx->usedData += length;
        returnCode = Esc_NO_ERROR;
    }
    return returnCode;
}

Esc_ERROR
EscAesCcm_Decrypt_Finish(
    EscAesCcm_ContextT* ctx,
    const Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;
    /* NULL pointer check */
    if ( (ctx == Esc_NULL_PTR) || (tag == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->usedData != ctx->plainLen) || (ctx->aDataFlag != FALSE) )
    {
        /* Not enough data received and/or associated data was not fully updated */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        returnCode = Esc_NO_ERROR;
        /* Generate Y_r if necessary */
        if (ctx->YrLen != 0U)
        {
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );
        }
        /* Compare calculated MAC with received MAC*/
        for (i = 0U; i < ctx->tagLen; i++)
        {
            if ( tag[i] != (ctx->S0[i] ^ ctx->Yr[i]) )
            {
                returnCode = Esc_INVALID_MAC;
            }
        }
    }
    return returnCode;
}


static void
EscAesCcm_AssociatedData_Init(
    EscAesCcm_ContextT* ctx )
{
    /* check the length of the associated data
     Case1: 0 < adata(in bits) < (2^16 - 2^8)
     Case2: (2^16 - 2^8) =< adata(in bits) < 2^32 */
    if (ctx->aadLen < 0xFF00U)
    {
        /* Use 2 byte for length of associated data */
        ctx->Yr[0U] ^= (Esc_UINT8)(ctx->aadLen >> 8);
        ctx->Yr[1U] ^= (Esc_UINT8)ctx->aadLen;
        ctx->YrLen = 2U;
    }
    else
    {
        /* Write padding */
        ctx->Yr[0U] ^= 0xffU;
        ctx->Yr[1U] ^= 0xfeU;

        /* Write length */
        ctx->Yr[2U] ^= (Esc_UINT8)(ctx->aadLen >> 24);
        ctx->Yr[3U] ^= (Esc_UINT8)(ctx->aadLen >> 16);
        ctx->Yr[4U] ^= (Esc_UINT8)(ctx->aadLen >> 8);
        ctx->Yr[5U] ^= (Esc_UINT8)ctx->aadLen;

        /* Use 4 byte for length of associated data plus 2 byte for padding*/
        ctx->YrLen = 6U;
    }
}

static void
EscAesCcm_Generate_S0(
    EscAesCcm_ContextT* ctx )
{
    Esc_UINT8 i;

    /* Counter Generation */

    /* construct flag byte */
    ctx->CtrI[0U] = 0U;

    /* encode q in 3 bits */
    ctx->CtrI[0U] |= (ctx->q - 1U) & 0x07U;

    /* store the nonce */
    for (i = 0U; i < ctx->nonceLen; i++)
    {
        ctx->CtrI[1U + i] = ctx->nonce[i];
    }

    /* construct Ctr_0 - only used for MAC */
    for (i = (1U + ctx->nonceLen); i < EscAesCcm_BLOCKSIZE; i++)
    {
        ctx->CtrI[i] = 0x00U;
    }

    /* Construct S_0 */
    EscAes_EncryptBlock( &ctx->aesCtx, ctx->CtrI, ctx->S0 );

    /* Generate next counter block */
    EscAesCcm_Increase_Counter( ctx->CtrI );
}

static void
EscAesCcm_Increase_Counter(
    Esc_UINT8 Counter[] )
{
    Counter[EscAesCcm_BLOCKSIZE - 1U]++;
    if (Counter[EscAesCcm_BLOCKSIZE - 1U] == 0U)
    {
        Counter[EscAesCcm_BLOCKSIZE - 2U]++;
        if (Counter[EscAesCcm_BLOCKSIZE - 2U] == 0U)
        {
            Counter[EscAesCcm_BLOCKSIZE - 3U]++;
            if (Counter[EscAesCcm_BLOCKSIZE - 3U] == 0U)
            {
                Counter[EscAesCcm_BLOCKSIZE - 4U]++;
            }
        }
    }
}

static void
EscAesCcm_Generate_Y0(
    EscAesCcm_ContextT* ctx,
    Esc_UINT32 plainLen )
{
    Esc_UINT8 cnt, zeroBytes;
    /* maximum length of payload_length is 4 */
    Esc_UINT8 plainLenArray[EscAesCcm_Esc_UINT32_SIZE];
    Esc_UINT8 plainLenArrayLen;
    Esc_UINT8 i;
    /* B0 = Flags || nonce || payload length */
    ctx->Yr[0U] = 0U;

    /* if associated data is present, set bit number 6 (Adata bit) */
    if (ctx->aadLen != 0U)
    {
        ctx->Yr[0U] |= EscAesCcm_ADATA_BIT;
    }

    /* encode the MAC length in 3 bits and store it in bits 3 to 5 */
    ctx->Yr[0U] |= (Esc_UINT8)( ( ( (ctx->tagLen - 2U) >> 1U ) & 0x07U ) << 3U );

    /* encode q in 3 bits and store it in bits 0 to 2 */
    ctx->Yr[0U] |= (ctx->q - 1U) & 0x07U;

    /* Store the nonce */
    for (i = 0U; i < ctx->nonceLen; i++)
    {
        ctx->Yr[(Esc_UINT8)(1U + i)] = ctx->nonce[i];
    }

    /* copy the data length (Esc_UINT32) in a big endian byte array
     * allowed sizes for the array: 2, 3, or 4 bytes */
    cnt = 0U;
    plainLenArrayLen = 0U;

    /* get number of leading zero bytes */
    if (plainLen > 0x00FFFFFFU)
    {
        cnt = 0U;
    }
    else if (plainLen > 0x0000FFFFU)
    {
        cnt = 1U;
    }
    else
    {
        cnt = 2U;
    }

    /* copy length in a byte array */
    for (i = cnt; i < EscAesCcm_Esc_UINT32_SIZE; i++)
    {
        plainLenArray[i - cnt] = (Esc_UINT8)( plainLen >> ( (3U - i) * 8U ) );
        plainLenArrayLen++;
    }

    /* Zeroize not used most significant bytes of the payload_length */
    zeroBytes = ctx->q - plainLenArrayLen;

    for (i = 0U; i < zeroBytes; i++)
    {
        ctx->Yr[(Esc_UINT8)( (EscAesCcm_BLOCKSIZE - ctx->q) + (Esc_UINT8)i )] = 0x00U;
    }

    /* Store the length of the payload */
    for (i = 0U; i < plainLenArrayLen; i++)
    {
        /*lint -e{771} plainLenArray is accessed for plainLenArrayLen bytes which is the exact number of initialized bytes. */
        ctx->Yr[(Esc_UINT8)(1U + ctx->nonceLen + zeroBytes + (Esc_UINT8)i)] = plainLenArray[i];
    }

    /* ctx->Yr = Y_0 */
    EscAes_EncryptBlock( &ctx->aesCtx, ctx->Yr, ctx->Yr );
    ctx->YrLen = 0U;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
