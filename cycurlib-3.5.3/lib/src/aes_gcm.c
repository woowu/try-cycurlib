/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-GCM implementation (Galois/Counter Mode)

   \see NIST Special Publication 800-38D
   csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

   \see _aes.h

   The following papers and standards are referenced:
   - The Galois/Counter Mode of Operation (GCM), David A. McGrew and John Viega

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_gcm.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#if EscAesGcm_USE_TABLES == 0
#   define EscAesGcm_FIELD_POLYNOMIAL  0xE1000000U
#endif

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/


#if EscAesGcm_USE_TABLES == 0
static void
EscAesGcm_GFAdd32(
    Esc_UINT32 X[],
    const Esc_UINT32 Y[] );

static void
EscAesGcm_GFRightshift32(
    Esc_UINT32 X[] );

#else

static void
EscAesGcm_GFAdd(
    Esc_UINT8 X[],
    const Esc_UINT8 Y[] );

#endif

static void
EscAesGcm_GFMul(
    const EscAesGcm_ContextT* ctx,
    Esc_UINT8 X[] );

static void
EscAesGcm_Incr(
    Esc_UINT8 Counter[] );

#if EscAesGcm_USE_TABLES == 1
static void
EscAesGcm_ComputeTableM0(
    EscAesGcm_ContextT* ctx );
#endif

static void
EscAesGcm_GHASH_Aad_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT8 result[],
    const Esc_UINT32 aadLen );

static void
EscAesGcm_GHASH_Aad_Finalize(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 result[] );

static void
EscAesGcm_GHASH_IV(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 IV[],
    Esc_UINT8 result[],
    const Esc_UINT32 lenIV );

static void
EscAesGcm_GHASH_EncDec_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 keyIndex,
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length );

static void
EscAesGcm_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

#if EscAesGcm_USE_TABLES == 0
static void
EscAesGcm_GFAdd32(
    Esc_UINT32 X[],
    const Esc_UINT32 Y[] )
{
    Esc_UINT8 i;

    for (i = 0U; i < 4U; i++)
    {
        X[i] ^= Y[i];
    }
}


/**
 * Right shift of an AES-block. Attention: the array is in big-endian
 * representation, so the most significant byte is at index 0.
 */
static void
EscAesGcm_GFRightshift32(
    Esc_UINT32 X[] )
{
    Esc_UINT8 i;

    for (i = 3U; i > 0U; i--)
    {
        X[i] = (X[i] >> 1) | (Esc_UINT32)( (X[i - 1U] & 1U) << 31 );
    }
    /* right shift last word, highest bit is 0 */
    X[0] >>= 1;
}

#else

/**
 * Adds two AES-blocks in the GF, X := X + Y
 */
static void
EscAesGcm_GFAdd(
    Esc_UINT8 X[],
    const Esc_UINT8 Y[] )
{
    Esc_UINT8 i;

    for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
    {
        X[i] ^= Y[i];
    }
}

#endif

/**
 * multiplies two AES-blocks in GF(2^128)
 * X := X * H
 * Algorithm 1 for size optimization and Algorithm 2 for speed optimization
 */
static void
EscAesGcm_GFMul(
    const EscAesGcm_ContextT* ctx,
    Esc_UINT8 X[] )
{
    Esc_SINT8 j;
    Esc_UINT8 i;
    Esc_UINT8 result[EscAes_BLOCK_BYTES] =
    {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };

#if EscAesGcm_USE_TABLES == 0
    Esc_UINT32 V[4];
    Esc_UINT32 tempResult[4] =
    {
        0U, 0U, 0U, 0U
    };

    /* copy H */
    for (i = 0U; i < 4U; i++)
    {
        V[i] = EscAes_Octets2Uint32(ctx->H, (Esc_UINT32)i * 4U);
    }

    /* go through bytes*/
    for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
    {
        /* and through bits */
        Esc_UINT8 currentBit = 128U; /* binary 10000000_2*/
        for (j = 0; j < 8; j++)
        {
            /* start with the leftmost bit X_127 .. X_0 */
            if ( (X[i] & currentBit ) > 0U )
            {
                EscAesGcm_GFAdd32( tempResult, V );
            }

            /* if rightmost bit is 1, add magic word to reduce in GF(2^128) */
            if ( (V[4U - 1U] & 1U) == 0U )
            {
                EscAesGcm_GFRightshift32( V );
            }
            else
            {
                EscAesGcm_GFRightshift32( V );
                V[0] ^= EscAesGcm_FIELD_POLYNOMIAL;
            }
            currentBit>>=1;
        }
    }
    EscAes_State2Uint32Array(result, tempResult);

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_ARRAY(tempResult);
    Esc_CLEAR_LOCAL_ARRAY(V);

#else

/**
 * Algorithm 2: Computes X = X * H using tables ctx->M0 and R.
 * McGrew and Viega, The Galois/Counter Mode of Operation, 2005
 */
    Esc_UINT8 A;

    static const Esc_UINT16 R[256U] =
    {
        0x0000U, 0x01C2U, 0x0384U, 0x0246U,
        0x0708U, 0x06CAU, 0x048CU, 0x054EU,
        0x0E10U, 0x0FD2U, 0x0D94U, 0x0C56U,
        0x0918U, 0x08DAU, 0x0A9CU, 0x0B5EU,
        0x1C20U, 0x1DE2U, 0x1FA4U, 0x1E66U,
        0x1B28U, 0x1AEAU, 0x18ACU, 0x196EU,
        0x1230U, 0x13F2U, 0x11B4U, 0x1076U,
        0x1538U, 0x14FAU, 0x16BCU, 0x177EU,
        0x3840U, 0x3982U, 0x3BC4U, 0x3A06U,
        0x3F48U, 0x3E8AU, 0x3CCCU, 0x3D0EU,
        0x3650U, 0x3792U, 0x35D4U, 0x3416U,
        0x3158U, 0x309AU, 0x32DCU, 0x331EU,
        0x2460U, 0x25A2U, 0x27E4U, 0x2626U,
        0x2368U, 0x22AAU, 0x20ECU, 0x212EU,
        0x2A70U, 0x2BB2U, 0x29F4U, 0x2836U,
        0x2D78U, 0x2CBAU, 0x2EFCU, 0x2F3EU,
        0x7080U, 0x7142U, 0x7304U, 0x72C6U,
        0x7788U, 0x764AU, 0x740CU, 0x75CEU,
        0x7E90U, 0x7F52U, 0x7D14U, 0x7CD6U,
        0x7998U, 0x785AU, 0x7A1CU, 0x7BDEU,
        0x6CA0U, 0x6D62U, 0x6F24U, 0x6EE6U,
        0x6BA8U, 0x6A6AU, 0x682CU, 0x69EEU,
        0x62B0U, 0x6372U, 0x6134U, 0x60F6U,
        0x65B8U, 0x647AU, 0x663CU, 0x67FEU,
        0x48C0U, 0x4902U, 0x4B44U, 0x4A86U,
        0x4FC8U, 0x4E0AU, 0x4C4CU, 0x4D8EU,
        0x46D0U, 0x4712U, 0x4554U, 0x4496U,
        0x41D8U, 0x401AU, 0x425CU, 0x439EU,
        0x54E0U, 0x5522U, 0x5764U, 0x56A6U,
        0x53E8U, 0x522AU, 0x506CU, 0x51AEU,
        0x5AF0U, 0x5B32U, 0x5974U, 0x58B6U,
        0x5DF8U, 0x5C3AU, 0x5E7CU, 0x5FBEU,
        0xE100U, 0xE0C2U, 0xE284U, 0xE346U,
        0xE608U, 0xE7CAU, 0xE58CU, 0xE44EU,
        0xEF10U, 0xEED2U, 0xEC94U, 0xED56U,
        0xE818U, 0xE9DAU, 0xEB9CU, 0xEA5EU,
        0xFD20U, 0xFCE2U, 0xFEA4U, 0xFF66U,
        0xFA28U, 0xFBEAU, 0xF9ACU, 0xF86EU,
        0xF330U, 0xF2F2U, 0xF0B4U, 0xF176U,
        0xF438U, 0xF5FAU, 0xF7BCU, 0xF67EU,
        0xD940U, 0xD882U, 0xDAC4U, 0xDB06U,
        0xDE48U, 0xDF8AU, 0xDDCCU, 0xDC0EU,
        0xD750U, 0xD692U, 0xD4D4U, 0xD516U,
        0xD058U, 0xD19AU, 0xD3DCU, 0xD21EU,
        0xC560U, 0xC4A2U, 0xC6E4U, 0xC726U,
        0xC268U, 0xC3AAU, 0xC1ECU, 0xC02EU,
        0xCB70U, 0xCAB2U, 0xC8F4U, 0xC936U,
        0xCC78U, 0xCDBAU, 0xCFFCU, 0xCE3EU,
        0x9180U, 0x9042U, 0x9204U, 0x93C6U,
        0x9688U, 0x974AU, 0x950CU, 0x94CEU,
        0x9F90U, 0x9E52U, 0x9C14U, 0x9DD6U,
        0x9898U, 0x995AU, 0x9B1CU, 0x9ADEU,
        0x8DA0U, 0x8C62U, 0x8E24U, 0x8FE6U,
        0x8AA8U, 0x8B6AU, 0x892CU, 0x88EEU,
        0x83B0U, 0x8272U, 0x8034U, 0x81F6U,
        0x84B8U, 0x857AU, 0x873CU, 0x86FEU,
        0xA9C0U, 0xA802U, 0xAA44U, 0xAB86U,
        0xAEC8U, 0xAF0AU, 0xAD4CU, 0xAC8EU,
        0xA7D0U, 0xA612U, 0xA454U, 0xA596U,
        0xA0D8U, 0xA11AU, 0xA35CU, 0xA29EU,
        0xB5E0U, 0xB422U, 0xB664U, 0xB7A6U,
        0xB2E8U, 0xB32AU, 0xB16CU, 0xB0AEU,
        0xBBF0U, 0xBA32U, 0xB874U, 0xB9B6U,
        0xBCF8U, 0xBD3AU, 0xBF7CU, 0xBEBEU
    };

    for (i = 15U; i > 0U; i--)
    {
        /* xor result with M0[X[i]] */
        EscAesGcm_GFAdd( result, ctx->M0[X[i]] );

        A = result[15U];
        for (j = 15; j > 0; j--)
        {
            result[j] = result[j - 1];
        }
        result[0] =  (Esc_UINT8)(R[A] >> 8U);
        result[1] ^= (Esc_UINT8)(R[A] & 0xffU);
    }

    /* xor result with M0[X[0]] */
    EscAesGcm_GFAdd( result, ctx->M0[X[0]] );
#endif

    /* Copy result back to X */
    EscAes_CopyBlock( X, result );

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_ARRAY(result);
}

/**
 * calculates the GHASH over AAD as specified in the paper
 */
static void
EscAesGcm_GHASH_Aad_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT8 result[],
    const Esc_UINT32 aadLen)
{
    Esc_UINT8 i;
    Esc_UINT32 byte = 0U;

    /* go through the whole additional data */
    while (byte < aadLen)
    {
        /* XOR result from last round with the additional data */
        for (i = ctx->tagBlockPosition; (i < EscAes_BLOCK_BYTES) && (byte < aadLen); i++)
        {
            result[i] ^= aad[byte];
            byte++;
        }
        ctx->tagBlockPosition = i % (Esc_UINT8)EscAes_BLOCK_BYTES;
        /* and multiply with the hash-key */
        if (ctx->tagBlockPosition == 0U)
        {
            EscAesGcm_GFMul( ctx, result );
        }
    }
}

static void
EscAesGcm_GHASH_Aad_Finalize(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 result[])
{
    if (ctx->aDataFlag == TRUE)
    {
        if ( ctx->tagBlockPosition != 0U)
        {
            /* finalize tag*/
            EscAesGcm_GFMul( ctx, result );
        }
        ctx->aDataFlag = FALSE;
    }
}

/**
 * calculates the GHASH over IV as specified in the paper
 */
static void
EscAesGcm_GHASH_IV(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 IV[],
    Esc_UINT8 result[],
    const Esc_UINT32 lenIV )
{
    Esc_UINT8 i;

    for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
    {
        result[i] = 0U;
    }

    /* use aad update function, reset of changed context values is done in calling function */

    ctx->aDataFlag = TRUE;
    ctx->tagBlockPosition = 0U;

    EscAesGcm_GHASH_Aad_Update( ctx, IV, result, lenIV );
    EscAesGcm_GHASH_Aad_Finalize( ctx, result );

    /* XOR the 32-bit length to the result, len_A (=0) on the left half, len_C on the right half */
    for (i = 0U; i < 4U; i++)
    {
        result[i + 12U] ^= (Esc_UINT8)( (lenIV * 8U) >> ( (3U - i) * 8U ) );
    }
    /* last multiply */
    EscAesGcm_GFMul( ctx, result );
}


/**
 * increments the counter modulo 2^32
 */
static void
EscAesGcm_Incr(
    Esc_UINT8 Counter[] )
{
    Counter[EscAes_BLOCK_BYTES - 1U]++;
    if (Counter[EscAes_BLOCK_BYTES - 1U] == 0U)
    {
        Counter[EscAes_BLOCK_BYTES - 2U]++;
        if (Counter[EscAes_BLOCK_BYTES - 2U] == 0U)
        {
            Counter[EscAes_BLOCK_BYTES - 3U]++;
            if (Counter[EscAes_BLOCK_BYTES - 3U] == 0U)
            {
                Counter[EscAes_BLOCK_BYTES - 4U]++;
            }
        }
    }
}

#if EscAesGcm_USE_TABLES == 1
/**
  * Algorithm 3: Computes the table M0 given an element H. Both are stored in the context.
  * See: McGrew and Viega, The Galois/Counter Mode of Operation, 2005
  */
static void
EscAesGcm_ComputeTableM0(
    EscAesGcm_ContextT* ctx )
{
    Esc_UINT16 i;
    Esc_UINT8 j;
    Esc_UINT8 k;

    /* copy H to M0 */
    for (k = 0U; k < EscAes_BLOCK_BYTES; k++)
    {
        ctx->M0[EscAes_BLOCK_BITS][k] = ctx->H[k];
    }

    i = 64U;
    while (i > 0U)
    {
        /* rightshift all bytes for multiplication with constant P=0b10 */
        ctx->M0[i][0U] = (ctx->M0[2U * i][0U] >> 1U);

        /* xor E1 if last bit was 1 */
        if (ctx->M0[2U * i][15U] & 1U)
        {
            ctx->M0[i][0U] ^= 0xE1U;
        }

        for (k = 1U; k < EscAes_BLOCK_BYTES; k++)
        {
            ctx->M0[i][k] = (ctx->M0[2U * i][k] >> 1U) | (Esc_UINT8)( (ctx->M0[2U * i][k - 1U] & 1U) << 7U );
        }

        i >>= 1U;
    }
    i = 2U;

    while (i < 256U)
    {
        for (j = 1U; j < i; j++)
        {
            /* M[i+j] = M[i] xor M[j] */
            for (k = 0U; k < EscAes_BLOCK_BYTES; k++)
            {
                ctx->M0[i + j][k] = ctx->M0[i][k] ^ ctx->M0[j][k];
            }
        }
        i <<= 1U;
    }

    /* M[0] = 0^128 */
    for (k = 0U; k < EscAes_BLOCK_BYTES; k++)
    {
        ctx->M0[0U][k] = 0U;
    }
}
#endif

/**
 * Initialize the AES-keys and the IV
 */
Esc_ERROR
EscAesGcm_Init(
    EscAesGcm_ContextT* ctx,
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
        EscAes_Init( &ctx->aesCtx, keyBits, key );
        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscAesGcm_startEncryptDecrypt(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 iv[],
    const Esc_UINT32 ivLen )
{
    static const Esc_UINT8 EscAesGcm_ZERO_BLOCK[EscAes_BLOCK_BYTES] =
    {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;

    if ( (iv == Esc_NULL_PTR) || (ctx == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ivLen < 1U)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* calculate hash key */
        EscAes_EncryptBlock( &ctx->aesCtx, EscAesGcm_ZERO_BLOCK, ctx->H );
#if EscAesGcm_USE_TABLES == 1
        /* calculate table M0 */
        EscAesGcm_ComputeTableM0( ctx );
#endif

        /* if ivLen = 12 just copy and pad with zeros, rightmost bit is 0x01U */
        if (ivLen == 12U)
        {
            for (i = 0U; i < 12U; i++)
            {
                ctx->counter[i] = iv[i];
            }

            for (; i < (EscAes_BLOCK_BYTES - 1U); i++)
            {
                ctx->counter[i] = 0U;
            }

            ctx->counter[EscAes_BLOCK_BYTES - 1U] = 0x01U;
        }
        else
        {
            /* apply GHASH and store resulting iv in the context */
            EscAesGcm_GHASH_IV( ctx, iv, ctx->counter, ivLen );
        }

        /* calculate first encrypted counter */
        EscAes_EncryptBlock( &ctx->aesCtx, ctx->counter, ctx->first );

        /* increment counter */
        EscAesGcm_Incr( ctx->counter );

        /* generate first block encryption key */
        EscAes_EncryptBlock( &ctx->aesCtx, ctx->counter, ctx->key );
        ctx->keyLen = 0U;


        /* enable aad */
        ctx->aDataFlag = TRUE;
        /* init tag */
        for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
        {
            ctx->tag[i] = 0U;
        }
        ctx->tagBlockPosition = 0U;
        ctx->aadLen = 0U;


        ctx->payload_length = 0U;
    }

    return returnCode;
}

Esc_ERROR
EscAesGcm_AssociatedData_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) ||
         ((aad == Esc_NULL_PTR) && (aadLen > 0U)) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (ctx->aDataFlag == FALSE)
    {
        /* No associated data expected */
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
        /* calculate Hash over AAD */
        EscAesGcm_GHASH_Aad_Update( ctx, aad, ctx->tag, aadLen );
        ctx->aadLen += aadLen;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


/**
 * This function encrypts/decrypts an arbitrary amount of data and updates the context
 */
static void
EscAesGcm_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length )
{
    Esc_UINT32 keyIndex;
    Esc_UINT32 plainIndex;
    Esc_UINT32 i = 0U;
    Esc_UINT32 j;

    Esc_ASSERT( length > 0U );

    keyIndex = ctx->keyLen;
    ctx->keyLen = (Esc_UINT8)( (length + keyIndex) % EscAes_BLOCK_BYTES );

    if ( (keyIndex + length) >= EscAes_BLOCK_BYTES )
    {
        Esc_UINT32 reverse_index =  ((EscAes_BLOCK_BYTES - keyIndex) % EscAes_BLOCK_BYTES);
        Esc_UINT32 numBlocks = (length - reverse_index) / EscAes_BLOCK_BYTES;
        /* is there an incomplete AES-block from a previous call? */
        if (keyIndex > 0U)
        {
            /* yes, then process the rest of the block */
            for (j = 0U; j < reverse_index; j++)
            {
                cipher[j] = ctx->key[keyIndex + j] ^ plain[j];
            }
            EscAesGcm_Incr( ctx->counter );
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->counter, ctx->key );
        }

        /* main loop, encrypt and increment counter, XOR the result with the plaintext */
        for (i = 0U; i < numBlocks; i++)
        {
            for (j = 0U; j < EscAes_BLOCK_BYTES; j++)
            {
                plainIndex = reverse_index + j + (i * EscAes_BLOCK_BYTES);
                cipher[plainIndex] = ctx->key[j] ^ plain[plainIndex];
            }
            EscAesGcm_Incr( ctx->counter );
            EscAes_EncryptBlock( &ctx->aesCtx, ctx->counter, ctx->key );
        }
        /* process last block which does not have to have full length */
        if (ctx->keyLen != 0U)
        {
            for (j = 0U; j < ctx->keyLen; j++)
            {
                plainIndex = reverse_index + j + (i * EscAes_BLOCK_BYTES);
                cipher[plainIndex] = ctx->key[j] ^ plain[plainIndex];
            }
        }
    }
    else
    {
        /* process last block which does not have to have full length */
        for (j = keyIndex; j < ctx->keyLen; j++)
        {
            cipher[ ( j - keyIndex ) + ( i * EscAes_BLOCK_BYTES ) ] = ctx->key[ j ] ^ plain[ ( j - keyIndex ) + ( i * EscAes_BLOCK_BYTES ) ];
        }
    }
}

/**
 * This function updates the GHASH with the encrypted/decrypted data.
 */
static void
EscAesGcm_GHASH_EncDec_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 keyIndex,
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length )
{
    Esc_UINT32 i = 0U;
    Esc_UINT32 j;
    Esc_UINT32 overhead;
    Esc_UINT32 newLength;

    Esc_ASSERT( length > 0U );

    newLength = keyIndex + length;
    overhead = newLength % EscAes_BLOCK_BYTES;

    if (newLength >= EscAes_BLOCK_BYTES)
    {
        const Esc_UINT32 reverse_index = ((EscAes_BLOCK_BYTES - keyIndex) % EscAes_BLOCK_BYTES);
        const Esc_UINT32 numBlocks = (length - reverse_index) / EscAes_BLOCK_BYTES;
        /* is there an incomplete AES-block from a previous call? */
        if (keyIndex > 0U)
        {
            /* yes, then process the rest of the block */
            for (j = 0U; j < reverse_index; j++)
            {
                ctx->tag[keyIndex + j] ^= cipher[j];
            }
            /* and multiply with the hash-key */
            EscAesGcm_GFMul( ctx, ctx->tag );
        }

        /* go through all complete AES-blocks */
        for (i = 0U; i < numBlocks; i++)
        {
            for (j = 0U; j < EscAes_BLOCK_BYTES; j++)
            {
                /* XOR result from last round with the additional dta */
                ctx->tag[j] ^= cipher[reverse_index + j + (i * EscAes_BLOCK_BYTES)];
            }
            /* and multiply with the hash-key */
            EscAesGcm_GFMul( ctx, ctx->tag );
        }

        /* process last block which does not have to have full length */
        if (overhead != 0U)
        {
            for (j = 0U; j < overhead; j++)
            {
                ctx->tag[j] ^= cipher[reverse_index + j + (i * EscAes_BLOCK_BYTES)];
            }
        }
    }
    else
    {
        /* process last block which does not have to have full length */
        for (j = keyIndex; j < overhead; j++)
        {
            ctx->tag[ j ] ^= cipher[ ( j - keyIndex ) + ( i * EscAes_BLOCK_BYTES ) ];
        }
    }

    ctx->payload_length += length;
}

Esc_ERROR
EscAesGcm_Encrypt_Update(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || ( ( (plain == Esc_NULL_PTR) || (cipher == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        if (length > 0U)
        {
            /* Save current keyLen for call to EscAesGcm_GHASH_EncDec_Update().
             * ctx->keyLen is modified by EscAesGcm_Update().
             */
            Esc_UINT8 keyIndex = ctx->keyLen;

            EscAesGcm_GHASH_Aad_Finalize( ctx, ctx->tag );
            EscAesGcm_Update( ctx, plain, cipher, length );
            EscAesGcm_GHASH_EncDec_Update( ctx, keyIndex, cipher, length );
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesGcm_Encrypt_Finish(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 tag[],
    const Esc_UINT8 tagLen )
{
    Esc_UINT8 i, j;
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) || (tag == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( ( (tagLen < 12U) && (tagLen != 4U) && (tagLen != 8U) ) ||
              (tagLen > 16U) )
    {
        /* NIST 800-38D Section 5.2.1.2: 128, 120, 112, 104, or 96. For certain applications, t may be 64 or 32 */
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        EscAesGcm_GHASH_Aad_Finalize( ctx, ctx->tag );
        /* if last block wasn't complete -> multiply with the hash-key */
        if (ctx->keyLen > 0U)
        {
            EscAesGcm_GFMul( ctx, ctx->tag );
        }

        /* XOR the 32-bit length to the result, len_A on the left half, len_C on the right half */
        j = 3U;
        for (i = 4U; i < 8U; i++)
        {
            ctx->tag[i] ^= (Esc_UINT8)( (ctx->aadLen * 8U) >> (j * 8U) );
            ctx->tag[i + 8U] ^= (Esc_UINT8)( (ctx->payload_length * 8U) >> (j * 8U) );
            j--;
        }

        /* last multiply */
        EscAesGcm_GFMul( ctx, ctx->tag );

        /* XOR the tag with the first encrypted counter */
        for (j = 0U; j < tagLen; j++)
        {
            tag[j] = ctx->tag[j] ^ ctx->first[j];
        }
        returnCode = Esc_NO_ERROR;
    }
    return returnCode;
}

/**
 * Encrypt a plaintext and additional auth. data with the GCM Mode
 */
Esc_ERROR
EscAesGcm_Encrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT32 ivLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    Esc_UINT32 plainLen,
    Esc_UINT8 cipher[],
    Esc_UINT8 tag[],
    Esc_UINT8 tagLen )
{
    Esc_ERROR returnCode;
    EscAesGcm_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    returnCode = EscAesGcm_Init( &ctx, keyBits, key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesGcm_startEncryptDecrypt( &ctx, iv, ivLen );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesGcm_AssociatedData_Update( &ctx, aad, aadLen );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Encrypt_Update( &ctx, plain, cipher, plainLen );
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscAesGcm_Encrypt_Finish( &ctx, tag, tagLen );
                }
            }
        }
    }

    /* Zeroize AES-GCM context */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

Esc_ERROR
EscAesGcm_Decrypt_Update(
    EscAesGcm_ContextT* ctx,
    Esc_UINT8 plain[],
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || ( ( (plain == Esc_NULL_PTR) || (cipher == Esc_NULL_PTR) ) && (length != 0U) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        if (length > 0U)
        {
            /* Save current keyLen for call to EscAesGcm_GHASH_EncDec_Update().
             * ctx->keyLen is modified by EscAesGcm_Update().
             */
            Esc_UINT8 keyIndex = ctx->keyLen;

            EscAesGcm_GHASH_Aad_Finalize( ctx, ctx->tag );
            EscAesGcm_GHASH_EncDec_Update( ctx, keyIndex, cipher, length );
            EscAesGcm_Update( ctx, cipher, plain, length );
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesGcm_Decrypt_Finish(
    EscAesGcm_ContextT* ctx,
    const Esc_UINT8 tag[],
    const Esc_UINT8 tagLen )
{
    Esc_UINT8 j;
    Esc_ERROR returnCode;

    if ( (tag == Esc_NULL_PTR) || (ctx == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        /* the tagLen is checked in Encrypt_Finish() */
        returnCode = EscAesGcm_Encrypt_Finish( ctx, ctx->tag, tagLen );

        if (returnCode == Esc_NO_ERROR)
        {
            /* compare it with the passed tag.
             * if they are not equal the authentication failed.
             */
            for (j = 0U; j < tagLen; j++)
            {
                if (tag[j] != ctx->tag[j])
                {
                    returnCode = Esc_INVALID_MAC;
                }
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscAesGcm_Decrypt(
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[],
    const Esc_UINT8 iv[],
    Esc_UINT32 ivLen,
    const Esc_UINT8 aad[],
    Esc_UINT32 aadLen,
    const Esc_UINT8 cipher[],
    Esc_UINT32 cipherLen,
    Esc_UINT8 plain[],
    const Esc_UINT8 tag[],
    Esc_UINT8 tagLen )
{
    Esc_ERROR returnCode;
    EscAesGcm_ContextT ctx;

    /* Parameters are already checked inside the called functions */

    returnCode = EscAesGcm_Init( &ctx, keyBits, key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesGcm_startEncryptDecrypt( &ctx, iv, ivLen );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesGcm_AssociatedData_Update( &ctx, aad, aadLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesGcm_Decrypt_Update( &ctx, plain, cipher, cipherLen );
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscAesGcm_Decrypt_Finish( &ctx, tag, tagLen );
                }
            }
        }
    }

    /* Zeroize AES-GCM context */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
