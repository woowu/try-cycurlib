/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
 \file        chacha20_poly1305.c

 \brief       ChaCha20_Poly1305 implementation, according to RFC-7539.

 $Rev: 0001 $
*/
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "chacha20_poly1305.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Length of one block in bytes. */
#define EscChaCha20Poly1305_BLOCK_BYTES 16U

/**
Convert Esc_UINT32 word to an 4 byte little endian Esc_UINT8 array.

\param[in] n        Esc_UINT32 word.
\param[out] a       Byte array with at least 4 allocated bytes from 'offset' on.
\param[out] offset  Offset to start in the array.
*/
/*lint -emacro(717,U32TO4ARR_LE) we allow do {...} while (0) statements for macros. */
#define U32TO4ARR_LE(n, a, offset) \
            do { \
                a[(offset)] = (Esc_UINT8)((n) & 0xffU); \
                a[(offset) + 1] = (Esc_UINT8)((n >> 8U) & 0xffU); \
                a[(offset) + 2] = (Esc_UINT8)((n >> 16U) & 0xffU); \
                a[(offset) + 3] = (Esc_UINT8)((n >> 24U) & 0xffU); \
            } while (FALSE)

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/**
 * This function pads the plain- or ciphertext (padding2) and calculates the final tag.
 *
 * \param[in, out] ctx       The ChaCha20Poly1305 context.
 * \param[in] tag            Pointer to 16 byte tag buffer.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if function is called in the wrong state.
*/
static Esc_ERROR
EscChaCha20Poly1305_CalcTag(
    EscChaCha20Poly1305_ContextT* ctx,
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES] );

/**
 * Encrypt or Decrypt data. Depending on the state, the input data is
 * encrypted or decrypted and the Poly context is updated.
 *
 * \param[in, out] ctx       The ChaCha20Poly1305 context.
 * \param[in] input          Data input.
 * \param[in] output         Data output.
 * \param[in] length         Data length.
 * \param[in] update_state   Target state after this function call.
 *
 * \return Esc_NO_ERROR if everything works fine.
 * \return Esc_UNEXPECTED_FUNCTION_CALL if function is called in the wrong state.
*/
static Esc_ERROR
EscChaCha20Poly1305_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 output[],
    const Esc_UINT32 length,
    const EscChaCha20_StateT update_state);

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/** Zero array used for padding1 and padding2 */
static const Esc_UINT8 EscChaCha20Poly1305_Zero[15] = { 0 };

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscChaCha20Poly1305_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 output[],
    const Esc_UINT32 length,
    const EscChaCha20_StateT update_state)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ((ctx != Esc_NULL_PTR) && (((input != Esc_NULL_PTR) && (output != Esc_NULL_PTR)) || (length == 0U)))
    {
        if (ctx->state == CHACHA20_POLY1305_UPDATE_AAD)
        {
            /* Add padding1 if required. */
            if ( (ctx->aadLen[0] % EscChaCha20Poly1305_BLOCK_BYTES) != 0U )
            {
                returnCode = EscPoly1305_Update(
                    &(ctx->ctx_p),
                    EscChaCha20Poly1305_Zero,
                    EscChaCha20Poly1305_BLOCK_BYTES - (ctx->aadLen[0] % EscChaCha20Poly1305_BLOCK_BYTES) );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                ctx->state = update_state;
            }
            else
            {
                ctx->state = CHACHA20_POLY1305_INVALID;
            }
        }
        if (ctx->state == update_state)
        {
            if (length != 0U)
            {
                ctx->plaintextLength[0] += length;
                if (ctx->plaintextLength[0] < length)
                {
                    ctx->plaintextLength[1]++;
                    /* maximum amount of plaintext that can be encrypted with chacha20_poly1305
                       is (2^32 - 1) * 64 bytes (3F FFFFFFC0 bytes or 256 Giga bytes) */
                    if (   ((ctx->plaintextLength[1] == 0x3fU) && (ctx->plaintextLength[0] > 0xffffffc0U))
                         || (ctx->plaintextLength[1] > 0x3fU) )
                    {
                        /* plaintext/ciphertext length too big */
                        returnCode = Esc_OUT_OF_RANGE;
                        ctx->state = CHACHA20_POLY1305_INVALID;
                    }
                }
                if (returnCode == Esc_NO_ERROR)
                {
                    if (update_state == CHACHA20_POLY1305_UPDATE_ENCRYPT)
                    {
                        /* ChaCha20 Update function checks only for NULL pointers. Since this cannot happen here, it is
                           safe to ignore the return code */
                        (void)EscChaCha20_Update( &(ctx->ctx_c), input, output, length );
                        /* Poly1305 Update function checks only for NULL pointers and for correct state. Since Null Ptr
                           cannot happen here, and correct order of calls is ensured, it is safe to ignore the return code */
                        (void)EscPoly1305_Update( &(ctx->ctx_p), output, length );
                    }
                    else
                    {
                        (void)EscPoly1305_Update( &(ctx->ctx_p), input, length );
                        (void)EscChaCha20_Update( &(ctx->ctx_c), input, output, length );
                    }
                }
            }
        }
        else
        {
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    return returnCode;
}

static Esc_ERROR
EscChaCha20Poly1305_CalcTag(
    EscChaCha20Poly1305_ContextT* ctx,
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES] )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 lengths[EscChaCha20Poly1305_BLOCK_BYTES];

    if ((ctx->state == CHACHA20_POLY1305_UPDATE_ENCRYPT) || (ctx->state == CHACHA20_POLY1305_UPDATE_DECRYPT))
    {
        if ( (ctx->plaintextLength[0] % EscChaCha20Poly1305_BLOCK_BYTES) != 0U )
        {
            /* Add padding2. */
            returnCode = EscPoly1305_Update(
                &(ctx->ctx_p),
                EscChaCha20Poly1305_Zero,
                EscChaCha20Poly1305_BLOCK_BYTES - (ctx->plaintextLength[0] % EscChaCha20Poly1305_BLOCK_BYTES) );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            /* Add AAD and plain/ciphertext lengths fields to the Poly1305 state. */
            U32TO4ARR_LE( ctx->aadLen[0], lengths, 0 );
            U32TO4ARR_LE( ctx->aadLen[1], lengths, 4 );
            U32TO4ARR_LE( ctx->plaintextLength[0], lengths, 8 );
            U32TO4ARR_LE( ctx->plaintextLength[1], lengths, 12 );
            returnCode = EscPoly1305_Update( &(ctx->ctx_p), lengths, EscChaCha20Poly1305_BLOCK_BYTES );

            if (returnCode == Esc_NO_ERROR)
            {
                /* Compute final tag. */
                returnCode = EscPoly1305_Finish( &(ctx->ctx_p), tag, EscChaCha20Poly1305_TAG_BYTES );
            }
        }
        /* Invalidate state so update or finish can not be called again */
        ctx->state = CHACHA20_POLY1305_INVALID;
    }
    else
    {
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }

    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_KeyGen(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    Esc_UINT8 polyKey[] )
{
    Esc_UINT8 in[32] = { 0 }; /* initialize to zero to get state by having chacha20 calculate block = in ^ state */
    EscChaCha20_ContextT ctx;
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ((key != Esc_NULL_PTR) && (nonce != Esc_NULL_PTR) && (polyKey != Esc_NULL_PTR))
    {
        returnCode = EscChaCha20_Init( &ctx, 256, key, nonce, 0 );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20_Start( &ctx );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20_Update( &ctx, in, polyKey, 32 );
        }
    }

    return returnCode;
}


Esc_ERROR
EscChaCha20Poly1305_Init(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 key[] )
{
    Esc_ERROR returnCode;
    Esc_UINT8 i;

    if ((ctx != Esc_NULL_PTR) && (key != Esc_NULL_PTR))
    {
        for (i = 0; i < EscChaCha20Poly1305_KEY_BYTES; i++)
        {
            ctx->key[i] = key[i];
        }
        ctx->aadLen[0] = 0U;
        ctx->aadLen[1] = 0U;
        ctx->plaintextLength[0] = 0U;
        ctx->plaintextLength[1] = 0U;
        ctx->state = CHACHA20_POLY1305_START;
        returnCode = Esc_NO_ERROR;
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_startEncryptDecrypt(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 nonce[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 polyKey[32] = { 0 };

    if ((ctx != Esc_NULL_PTR) && (nonce != Esc_NULL_PTR))
    {
        if (ctx->state == CHACHA20_POLY1305_START)
        {
            returnCode = EscChaCha20_Init( &(ctx->ctx_c), 256, ctx->key, nonce, 0 );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20_Start( &(ctx->ctx_c) );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                /* run first block to generate 32 bytes poly key */
                returnCode = EscChaCha20_Update( &(ctx->ctx_c), polyKey, polyKey, 32 );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                /* assign poly key, will only use 32 bytes */
                returnCode = EscPoly1305_Init( &(ctx->ctx_p), polyKey );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                /* Get remaining 32 bytes from ChaCha20 context buffer. Result is not used here,
                   but buffer must be emptied to get an initiliazed chacha20 state with counter = 1.
                   This Update() call is faster than a new chacha20 initialization with ctr = 1. */
                returnCode = EscChaCha20_Update( &(ctx->ctx_c), polyKey, polyKey, 32 );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                ctx->aadLen[0] = 0U;
                ctx->aadLen[1] = 0U;
                ctx->plaintextLength[0] = 0U;
                ctx->plaintextLength[1] = 0U;
                ctx->state = CHACHA20_POLY1305_UPDATE_AAD;
            }
            else
            {
                ctx->state = CHACHA20_POLY1305_INVALID;
            }
        }
        else
        {
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
    }

    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_UpdateAad(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ((ctx != Esc_NULL_PTR) && ((aad != Esc_NULL_PTR) || (aadLen == 0U)))
    {
        if (ctx->state == CHACHA20_POLY1305_UPDATE_AAD)
        {
            ctx->aadLen[0] += aadLen;
            if (ctx->aadLen[0] < aadLen)
            {
                ctx->aadLen[1]++;
                if (ctx->aadLen[1] == 0U)
                {
                    /* aad overflow */
                    returnCode = Esc_OUT_OF_RANGE;
                    ctx->state = CHACHA20_POLY1305_INVALID;
                }
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscPoly1305_Update( &(ctx->ctx_p), aad, aadLen );
            }
        }
        else
        {
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    return returnCode;
}


Esc_ERROR
EscChaCha20Poly1305_Encrypt_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[],
    const Esc_UINT32 length )
{
    /* Null Ptr checks are implemented in Update() function. */
    return EscChaCha20Poly1305_Update(ctx, plain, cipher, length, CHACHA20_POLY1305_UPDATE_ENCRYPT);
}

Esc_ERROR
EscChaCha20Poly1305_Encrypt_Finish(
    EscChaCha20Poly1305_ContextT* ctx,
    Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if ((ctx != Esc_NULL_PTR) && (tag != Esc_NULL_PTR))
    {
        returnCode = EscChaCha20Poly1305_CalcTag(ctx, tag);
    }

    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_Decrypt_Update(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[],
    const Esc_UINT32 length )
{
    /* Null Ptr checks are implemented in Update() function. */
    return EscChaCha20Poly1305_Update(ctx, cipher, plain, length, CHACHA20_POLY1305_UPDATE_DECRYPT);
}

Esc_ERROR
EscChaCha20Poly1305_Decrypt_Finish(
    EscChaCha20Poly1305_ContextT* ctx,
    const Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    Esc_UINT8 mac[EscChaCha20Poly1305_TAG_BYTES];
    Esc_UINT8 i;

    if ((ctx != Esc_NULL_PTR) && (tag != Esc_NULL_PTR))
    {
        returnCode = EscChaCha20Poly1305_CalcTag( ctx, mac );
        if (returnCode == Esc_NO_ERROR)
        {
            /* compare tag */
            for (i = 0; i < EscChaCha20Poly1305_TAG_BYTES; i++)
            {
                if (tag[i] != mac[i])
                {
                    returnCode = Esc_INVALID_MAC;
                }
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_Encrypt(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen,
    const Esc_UINT8 plain[],
    const Esc_UINT32 length,
    Esc_UINT8 cipher[],
    Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode;
    EscChaCha20Poly1305_ContextT ctx;

    returnCode = EscChaCha20Poly1305_Init( &ctx, key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, nonce );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, aad, aadLen );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx, plain, cipher, length );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
    }

    return returnCode;
}

Esc_ERROR
EscChaCha20Poly1305_Decrypt(
    const Esc_UINT8 key[],
    const Esc_UINT8 nonce[],
    const Esc_UINT8 aad[],
    const Esc_UINT32 aadLen,
    const Esc_UINT8 cipher[],
    const Esc_UINT32 length,
    Esc_UINT8 plain[],
    const Esc_UINT8 tag[] )
{
    Esc_ERROR returnCode;
    EscChaCha20Poly1305_ContextT ctx;

    returnCode = EscChaCha20Poly1305_Init( &ctx, key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, nonce );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, aad, aadLen );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =  EscChaCha20Poly1305_Decrypt_Update( &ctx, cipher, plain, length );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt_Finish( &ctx, tag );
    }

    return returnCode;

}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
