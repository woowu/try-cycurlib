/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES Key Wrap implementation described from NIST SP 800-38F and RFC 3394

   \see  NIST SP 800-38F and RFC 3394


*/
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_key_wrap.h"
#include "_aes.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. CONSTANTS                                                            *
 ***************************************************************************/
static const Esc_UINT8 aes_key_wrap_defaultIV[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/


/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
wrap key function according to RFC 3394
*/
Esc_ERROR
EscAesKeyWrap_wrapKey(
    const Esc_UINT8 *kek,
    Esc_UINT16 kekLen,
    const Esc_UINT8 *iv,
    const Esc_UINT8 *in,
    Esc_UINT8 *out,
    Esc_UINT32 len)
{
    /* declaration of variables */
    Esc_UINT8 *a;
    Esc_UINT8 *r;
    Esc_UINT8 b[16];
    Esc_UINT32 t, i, j;
    EscAes_ContextT ctx;
    Esc_ERROR retCode = Esc_NO_ERROR;
    const Esc_UINT8 *internalIv = iv;

    /*check input parameters for validity*/
    if ( (kekLen > EscAes_MAX_KEY_BITS) ||
         ((kekLen != 128U) && (kekLen != 192U) && (kekLen != 256U)))
    {
        retCode = Esc_INVALID_KEY_LENGTH; /*invalid AES key length, must be 128, 192, or 256*/
    }
    else if ((kek == Esc_NULL_PTR) || (in == Esc_NULL_PTR) || (out == Esc_NULL_PTR) )
    {
        retCode = Esc_NULL_POINTER_ERROR;
    }
    else if (((len % 8U)!=0U) || (len < 16U))
    {
        retCode = Esc_INVALID_PARAMETER; /*invalid input key length*/
    }
    else
    {
        /*initialize and check result of AES module*/
        EscAes_Init(&ctx, kekLen, kek);

        a = b;
        t = 1U;

        /*get first block of clear text into memory for processing, check if done properly*/
        Esc_memcpy(&out[8], in, len);

        if (!iv)   /*iv is null, set to default IV*/
        {
            internalIv = aes_key_wrap_defaultIV;
        }
        /*copy IV into first 64-bit block of text for processing*/
        Esc_memcpy(a, internalIv, 8U);

        /*start of main processing block for wrapping*/
        for (j = 0U; j < 6U; j++)
        {
            /*r = out + 8;*/
            r = &out[8];
            for (i = 0U; i < len; i+=8U )
            {
                Esc_memcpy(&b[8], &r[i], 8U);

                /*encrypt 64 bit block of data, check for errors*/
                EscAes_EncryptBlock(&ctx, b, b);

                b[4] ^= (Esc_UINT8) (t >> 24U);
                b[5] ^= (Esc_UINT8) (t >> 16U);
                b[6] ^= (Esc_UINT8) (t >>  8U);
                b[7] ^= (Esc_UINT8) t;

                /*move 64 bit block of text to next area to prepare for next round of processing*/
                Esc_memcpy(&r[i], &b[8], 8U);
                t++;
            }
        }
        /*moving final block of text into output*/
        Esc_memcpy(out, a, 8U);
    }

    /* Zeroize AES-ECM context as it contains key rounds */
    Esc_CLEAR_LOCAL_VAR(ctx);

    /* Zeroize other stack variables */
    Esc_CLEAR_LOCAL_ARRAY(b);

    return retCode;
}

/**
unwrap key function according to RFC 3394
*/
Esc_ERROR
EscAesKeyWrap_unwrapKey(
    const Esc_UINT8 *kek,
    Esc_UINT16 kekLen,
    const Esc_UINT8 *iv,
    const Esc_UINT8 *in,
    Esc_UINT8 *out,
    Esc_UINT32 len)
{
    /*Initialize and declare all variables*/
    Esc_UINT8 *a;
    Esc_UINT8 *r;
    Esc_UINT8 b[16];
    Esc_UINT16 comp;
    Esc_UINT32 i, j, t;
    EscAes_ContextT ctx;
    Esc_ERROR retCode = Esc_NO_ERROR;

    /*initial error checking of input parameters*/
    if ( (kekLen > EscAes_MAX_KEY_BITS) ||
         ((kekLen != 128U) && (kekLen != 192U) && (kekLen != 256U)))
    {
        retCode = Esc_INVALID_KEY_LENGTH; /*Invalid AES key length, must be 128, 192, or 256*/
    }
    else if ((kek == Esc_NULL_PTR) || (in == Esc_NULL_PTR) || (out == Esc_NULL_PTR) )
    {
        retCode = Esc_NULL_POINTER_ERROR;
    }
    else if (((len % 8U)!=0U) || (len < 24U))
    {
        retCode = Esc_INVALID_PARAMETER; /*invalid length*/
    }
    else
    {
        /*length is 1 64-bit block larger than clear text*/
        len -= 8U;
        /*Initialize and check success of AES module*/
        EscAes_Init(&ctx, kekLen, kek);
        a = b;

        /*calculate number of rounds to be executed, 6 * # of 64-bit clear text blocks*/
        t = 6U * (len >> 3);

        /*move initial cipher text into a for processing*/
        Esc_memcpy(a, in, 8U);

        /*move next 8 bytes of input into output for storage*/
        Esc_memcpy(out, &in[8], len);

        /*start unwrap rounds*/
        for (j = 0U; j < 6U; j++)
        {
            r = out;
            for (i = len; i >0U;  )
            {
                i -= 8U;

                b[4] ^= (Esc_UINT8) (t >> 24U);
                b[5] ^= (Esc_UINT8) (t >> 16U);
                b[6] ^= (Esc_UINT8) (t >>  8U);
                b[7] ^= (Esc_UINT8) t;

                Esc_memcpy( &b[8], &r[i], 8U);

                EscAes_DecryptBlock(&ctx, b, b);

                Esc_memcpy(&r[i], &b[8], 8U);
                t--;
            }
        }

        /*Compare with default IV if input IV is null*/
        if (!iv)
        {
            comp = Esc_memcmp(a, aes_key_wrap_defaultIV, 8U);
        }
        else
        {
            comp = Esc_memcmp(a, iv, 8U);
        }

        /*Verify that the unwrap is correct, the IV should equal A if done properly*/
        if (comp != 0U)  /*a should match IV if unwrapped properly*/
        {
            Esc_memset(out, 0U, 16U);

            retCode = Esc_IV_MISMATCH; /*a does not match IV, error happened*/
        }
        else
        {
            retCode = Esc_NO_ERROR;
        }
    }

    /* Zeroize AES-ECM context as it contains key rounds */
    Esc_CLEAR_LOCAL_VAR(ctx);

    /* Zeroize other stack variables */
    Esc_CLEAR_LOCAL_ARRAY(b);

    return retCode;
}

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
