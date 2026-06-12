/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-XTS implementation

   \see         IEEE 1619

   Key sizes of 128 and 256 bits are allowed.

   $Rev: 4105 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_xts.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/* define the irreducible field polynomial 0x87 = x^128 + x^7 + x^2 + x + 1 */
#    define GF2_128_FIELD_POLYNOMIAL ( (Esc_UINT8)0x87U )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 *  Multiplication by a primitive element alpha (cf. IEEE 1619)
 *
 *  \param[in,out] a0 value to be multiplied
 */
static void
EscAesXts_MultiplyByAlpha(
    Esc_UINT8 a0[] );

/**
 *  XTS-AES decryption of a single 128-bit block (cf. IEEE 1619)
 *
 *  \param[in] ctx initialized XTS context
 *  \param[in] cipher cipher text (128 bit)
 *  \param[out] plain plain text (128 bit)
 *  \param[in,out] tweak value (128 bit) which will be increased
 *
 */
static void
EscAesXts_BlockDecrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT8 tweak[] );

/**
 *  XTS-AES encryption of a single 128-bit block (cf. IEEE 1619)
 *
 *  \param[in] ctx initialized XTS context
 *  \param[in] plain plain text (128 bit)
 *  \param[out] cipher cipher text (128 bit)
 *  \param[in,out] tweak value (128 bit) which will be increased
 *
 */
static void
EscAesXts_BlockEncrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT8 tweak[] );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*********************************************************
 create XTS context with two keys
 *********************************************************/
Esc_ERROR
EscAesXts_Init(
    EscAesXts_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key1[],
    const Esc_UINT8 key2[] )
{
    Esc_ERROR returnCode;

    if ( (ctx == Esc_NULL_PTR) ||
         (key1 == Esc_NULL_PTR) ||
         (key2 == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (keyBits > EscAes_MAX_KEY_BITS) ||
              ( (keyBits != 128U) && (keyBits != 256U) ) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        EscAes_Init( &ctx->ctx1, keyBits, key1 );
        EscAes_Init( &ctx->ctx2, keyBits, key2 );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

/**
 *  Multiplication by a primitive element alpha
 *
 *  \param[in] a0 value to be multiplied
 *  \param[out] a0 updated value
 */
static void
EscAesXts_MultiplyByAlpha(
    Esc_UINT8 a0[] )
{
    Esc_UINT8 x;
    Esc_UINT8 carry_out = 0U;
    Esc_UINT8 carry_in = 0U;

    for (x = 0U; x < EscAes_BLOCK_BYTES; x++)
    {
        carry_out = (a0[x] >> 7U) & 0x01U;
        a0[x] = ( (Esc_UINT8)(a0[x] << 1U) | carry_in ) & 0xFFU;
        carry_in = carry_out;
    }
    if (carry_out != 0U)
    {
        a0[0U] ^= GF2_128_FIELD_POLYNOMIAL;
    }

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_VAR(x);
    Esc_CLEAR_LOCAL_VAR(carry_in);
    Esc_CLEAR_LOCAL_VAR(carry_out);
}

/************************************
 encrypts a single block and implicitly increases the block number by left-shifting the tweak value by one
 ************************************/
static void
EscAesXts_BlockEncrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT8 tweak[] )
{
    Esc_UINT8 x;

    /* Step x.2: PP <-- P EXOR T */
    for (x = 0U; x < EscAes_BLOCK_BYTES; x++)
    {
        cipher[x] = plain[x] ^ tweak[x];
    }

    /* Step x.3: CC <-- AES-enc( Key_1, PP ) */
    EscAes_EncryptBlock( &ctx->ctx1, cipher, cipher );

    /* Step x.4: C <-- CC EXOR T */
    for (x = 0U; x < EscAes_BLOCK_BYTES; x++)
    {
        cipher[x] ^= tweak[x];
    }

    /* left shift the tweak value (increase block number) */
    EscAesXts_MultiplyByAlpha( tweak );
}

Esc_ERROR
EscAesXts_Encrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length,
    const Esc_UINT8 tweak[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 x;
    Esc_UINT32 blocks;
    Esc_UINT8 last_block_size;
    Esc_UINT8 PP[EscAes_BLOCK_BYTES];
    Esc_UINT8 CC[EscAes_BLOCK_BYTES];
    Esc_UINT8 T[EscAes_BLOCK_BYTES];

    if ( (ctx == Esc_NULL_PTR) ||
         (plain == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) ||
         (tweak == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length < EscAes_BLOCK_BYTES) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Step x.1: T <-- AES-enc( Key_2, i ) * alpha^j */
        EscAes_EncryptBlock( &ctx->ctx2, tweak, T );

        /* P = P_0 | ... | P_(m-1) | P_(m) */
        blocks = length / EscAes_BLOCK_BYTES;
        last_block_size = (Esc_UINT8)(length % EscAes_BLOCK_BYTES);
        if (last_block_size == 0U)
        {
            /* the last block may be between 0 and 127 bits long */
            blocks++;
        }

        for (x = 0U; x < (blocks - 1U); x++)
        {
            EscAesXts_BlockEncrypt( ctx, &plain[x * EscAes_BLOCK_BYTES], &cipher[x * EscAes_BLOCK_BYTES], T );
        }

        if (last_block_size > 0U)
        {
            /* Step 4.a: CC <-- XTS-AES-blockEnc( Key, P_(m-1), i, m-1 ) */
            EscAesXts_BlockEncrypt( ctx, &plain[(blocks - 1U) * EscAes_BLOCK_BYTES], CC, T );

            /* Step 4.b: C_m <-- first b bits of CC */
            /* Step 4.c: CP <-- last (128-b) bits of CC */
            /* Step 4.d: PP <-- P_m | CP */
            for (x = 0U; x < last_block_size; x++)
            {
                PP[x] = plain[(blocks * EscAes_BLOCK_BYTES) + x];
                cipher[(blocks * EscAes_BLOCK_BYTES) + x] = CC[x];
            }
            for (; x < EscAes_BLOCK_BYTES; x++)
            {
                PP[x] = CC[x];
            }

            /* Step 4.e: C_(m-1) <-- XTS-AES-blockEnc( Key, PP, i, m ) */
            /*lint -e{772} PP is initialized correctly */
            EscAesXts_BlockEncrypt( ctx, PP, &cipher[(blocks - 1U) * EscAes_BLOCK_BYTES], T );
        }

        /* Step 5: C = C_0 | ... | C_(m-1) | C_(m) */
    }

    /* Zeroize stack variables */
    Esc_memclear(PP, sizeof(PP));
    Esc_memclear(CC, sizeof(CC));
    Esc_memclear(T, sizeof(T));

    return returnCode;
}

#    if Esc_HAS_INT64 == 1
Esc_ERROR
EscAesXts_EncryptSector(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    Esc_UINT32 length,
    Esc_UINT64 data_unit_number )
{
    Esc_UINT8 tweak[EscAes_BLOCK_BYTES];
    Esc_UINT8 x;

    for (x = 0U; x < (Esc_UINT8)EscAes_BLOCK_BYTES; x++)
    {
        tweak[x] = (Esc_UINT8)(data_unit_number & 0xffU);
        data_unit_number >>= 8U;
    }

    return EscAesXts_Encrypt( ctx, plain, cipher, length, tweak );
}

#    endif

/************************************
 decrypts a single block and implicitly increases the block number by left-shifting the tweak value by one
 ************************************/
static void
EscAesXts_BlockDecrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT8 tweak[] )
{
    Esc_UINT8 x;

    /* Step x.2: CC <-- C EXOR T */
    for (x = 0U; x < EscAes_BLOCK_BYTES; x++)
    {
        plain[x] = cipher[x] ^ tweak[x];
    }

    /* Step x.3: PP <-- AES-dec( Key_1, CC ) */
    EscAes_DecryptBlock( &ctx->ctx1, plain, plain );

    /* Step x.4: P <-- PP EXOR T */
    for (x = 0U; x < EscAes_BLOCK_BYTES; x++)
    {
        plain[x] ^= tweak[x];
    }

    /* left shift the tweak value (increase block number) */
    EscAesXts_MultiplyByAlpha( tweak );
}

Esc_ERROR
EscAesXts_Decrypt(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length,
    const Esc_UINT8 tweak[] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 x;
    Esc_UINT32 blocks;
    Esc_UINT8 last_block_size;
    Esc_UINT8 PP[EscAes_BLOCK_BYTES];
    Esc_UINT8 CC[EscAes_BLOCK_BYTES];
    Esc_UINT8 T[EscAes_BLOCK_BYTES];

    if ( (ctx == Esc_NULL_PTR) ||
         (plain == Esc_NULL_PTR) ||
         (cipher == Esc_NULL_PTR) ||
         (tweak == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (length < EscAes_BLOCK_BYTES) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* Step x.1: T <-- AES-enc( Key_2, i ) * alpha^j */
        EscAes_EncryptBlock( &ctx->ctx2, tweak, T );

        /* C = C_0 | ... | C_(m-1) | C_(m) */
        blocks = length / EscAes_BLOCK_BYTES;
        last_block_size = (Esc_UINT8)(length % EscAes_BLOCK_BYTES);
        if (last_block_size == 0U)
        {
            /* the last block may be between 0 and 127 bits long */
            blocks++;
        }

        for (x = 0U; x < (blocks - 1U); x++)
        {
            /* Step 1.a: P_q <-- XTS-AES-blockDec( Key, C_q, i, q ) */
            EscAesXts_BlockDecrypt( ctx, &cipher[x * EscAes_BLOCK_BYTES], &plain[x * EscAes_BLOCK_BYTES], T );
        }

        if (last_block_size > 0U)
        {
            /* copy temporary tweak value */
            EscAes_CopyBlock( CC, T );

            /* left shift the temporary tweak value (increase block number) */
            EscAesXts_MultiplyByAlpha( CC );

            /* Step 4.d: PP <-- XTS-AES-blockDec( Key, C_(m-1), i, m ) */
            EscAesXts_BlockDecrypt( ctx, &cipher[(blocks - 1U) * EscAes_BLOCK_BYTES], PP, CC );

            /* Step 4.e: P_m <-- first b bits of PP */
            /* Step 4.f: CP <-- last (128-b) bits of PP */
            /* Step 4.g: CC <-- C_m | CP */
            for (x = 0U; x < last_block_size; x++)
            {
                CC[x] = cipher[(blocks * EscAes_BLOCK_BYTES) + x];
                plain[(blocks * EscAes_BLOCK_BYTES) + x] = PP[x];
            }
            for (; x < EscAes_BLOCK_BYTES; x++)
            {
                CC[x] = PP[x];
            }

            /* Step 4.h: P_(m-1) <-- XTS-AES-blockDec( Key, CC, i, m-1 ) */
            EscAesXts_BlockDecrypt( ctx, CC, &plain[(blocks - 1U) * EscAes_BLOCK_BYTES], T );
        }

        /* Step 5: P = P_0 | ... | P_(m-1) | P_(m) */
    }

    /* Zeroize stack variables */
    Esc_memclear(PP, sizeof(PP));
    Esc_memclear(CC, sizeof(CC));
    Esc_memclear(T, sizeof(T));

    return returnCode;
}

#    if Esc_HAS_INT64 == 1
Esc_ERROR
EscAesXts_DecryptSector(
    const EscAesXts_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    Esc_UINT32 length,
    Esc_UINT64 data_unit_number )
{
    Esc_UINT8 tweak[EscAes_BLOCK_BYTES];
    Esc_UINT8 x;

    for (x = 0U; x < (Esc_UINT8)EscAes_BLOCK_BYTES; x++)
    {
        tweak[x] = (Esc_UINT8)(data_unit_number & 0xffU);
        data_unit_number >>= 8U;
    }

    return EscAesXts_Decrypt( ctx, cipher, plain, length, tweak );
}

#    endif

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
