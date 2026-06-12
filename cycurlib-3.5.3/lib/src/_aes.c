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
   Common functions. The functions are not supposed to be called
   by the user. Use one of the submodule functions instead.

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   The following standards are referenced:
   - FIPS PUB 197, NIST, November 26, 2001,
   csrc.nist.gov/publications/fips/fips197/fips-197.pdf

   $Rev: 4105 $
 */
/***************************************************************************/
/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "_aes.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/* define the GF2^8 irreducible field polynomial 0x11B = x^8 + x^4 + x^3 + x + 1,
   => 0x11BU & 0xFFU */
#define GF2_8_FIELD_POLYNOMIAL ( (Esc_UINT8)0x1BU )

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/
/** AES forward SBOX. Used for Encryption and Key schedule. */
const Esc_UINT8 EscAes_FORWARD_SBOX[256] =
{                                                                                                                   \
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U, \
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U, \
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U, \
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U, \
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U, \
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU, \
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U, \
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U, \
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U, \
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU, \
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U, \
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U, \
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU, \
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU, \
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU, \
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U, \
};
/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
Converts a 4 DWORD AES state to 16 bytes.
*/
void
EscAes_State2Uint32Array(
    Esc_UINT8 block[],
    const Esc_UINT32 state[] )
{
    Esc_UINT8 i;

    /* write result into plain text byte array */
    for (i = 0U; i < EscAes_Nb; i++)
    {
        block[i * EscAes_Nb] =        (Esc_UINT8)(state[i] >> 24);
        block[(i * EscAes_Nb) + 1U] = (Esc_UINT8)(state[i] >> 16);
        block[(i * EscAes_Nb) + 2U] = (Esc_UINT8)(state[i] >> 8);
        block[(i * EscAes_Nb) + 3U] = (Esc_UINT8) state[i];
    }
}

/******************************************************
Converts a octet string in little endian format into a Esc_UINT32 value
 ******************************************************/
Esc_UINT32
EscAes_Octets2Uint32(
    const Esc_UINT8 octets[],
    Esc_UINT32 idx )
{
    Esc_UINT32 v;
    v = ( ( (Esc_UINT32)octets[idx]      << 24 ) |
          ( (Esc_UINT32)octets[idx + 1U] << 16 ) |
          ( (Esc_UINT32)octets[idx + 2U] << 8 ) |
          ( (Esc_UINT32)octets[idx + 3U] )
          );

    return v;
}


/*********************************************************
 * multiply 'a' by 2 in GF(2)^8 and reduce if necessary  *
 * Described in FIPS-197 4.2.1                           *
 *********************************************************/
static Esc_UINT8
EscAes_Xtime(
    Esc_UINT8 a )
{
    /* left shift = mult by 0x02  */
    /* if MSB was 1 then reduce by field polynomial */
    Esc_UINT8 ret;
    Esc_UINT8 x;

    ret = (Esc_UINT8)(a << 1);

    if ( (a & 0x80U) != 0U )
    {
        x = GF2_8_FIELD_POLYNOMIAL;
    }
    else
    {
        x = 0U;
    }

    /* that's primitive for SPA resistance */
    ret ^= x;

    return ret;
}

/**
Calculates mix columns with u as input.
Returns cx[i] as output.
\see EfficientAesImplementation.pdf figure 6 and section 2.3.4
*/
Esc_UINT32
EscAes_MixColumns(
    Esc_UINT32 u )
{
    Esc_UINT32 v1;
    Esc_UINT32 v2;

    /* compute v1 (for xtime call) and v2
       v2 is a 32bit version of t -> (tttt)
       with t = BYTE0 ^ BYTE1 ^ BYTE2 ^ BYTE3 */
    v1 = u ^ EscAes_RotateLeft32( u, 8U );
    v2 = v1 ^ EscAes_RotateLeft32( v1, 16U );

    v2 ^= u;
    v2 ^= ( (Esc_UINT32)EscAes_Xtime( EscAes_BYTE_0( v1 ) ) ) << 24;
    v2 ^= ( (Esc_UINT32)EscAes_Xtime( EscAes_BYTE_1( v1 ) ) ) << 16;
    v2 ^= ( (Esc_UINT32)EscAes_Xtime( EscAes_BYTE_2( v1 ) ) ) << 8;
    v2 ^= ( (Esc_UINT32)EscAes_Xtime( EscAes_BYTE_3( v1 ) ) );

    return v2;
}

/**
Calculates inverse mix columns with in as input.
Returns res as output.
\see EfficientAesImplementation.pdf  section 2.4.4
*/
Esc_UINT32
EscAes_InvMixColumns(
    Esc_UINT32 u )
{
    Esc_UINT32 v;

    /* Apply C_new matrix, see EfficientAesImplementation.pdf figure 12 */
    v = u ^ (u >> 16);
    v = ( ( (Esc_UINT32)EscAes_Xtime( EscAes_Xtime( EscAes_BYTE_2( v ) ) ) ) << 8 ) |
        (Esc_UINT32)EscAes_Xtime( EscAes_Xtime( EscAes_BYTE_3( v ) ) );
    v = u ^ ( (v << 16) | v );
    v = EscAes_MixColumns( v );

    return v;
}

/*********************************************************
 copy 16 bytes from 'source' to 'dest'
 *********************************************************/
void
EscAes_CopyBlock(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[] )
{
    Esc_UINT8 i;

    /* copy 16 bytes */
    for (i = 0U; i < EscAes_BLOCK_BYTES; i++)
    {
        dest[i] = source[i];
    }
}

/*********************************************************
 Init AES_CONTEXT
 *********************************************************/

void
EscAes_Init(
    EscAes_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] )
{
    /**
     * In the FIPS-197 standard, EscAes_RCON starts at index 1. We add another
     * index 0 value, so that our array indexing is the same as in the
     * standard.
     **/
    static const Esc_UINT8 EscAes_RCON[10 + 1] =
    {
        0x00U /*unused index 0 */,
        0x01U, 0x02U, 0x04U, 0x08U, 0x10U,
        0x20U, 0x40U, 0x80U, 0x1BU, 0x36U
    };
    Esc_UINT32 i;                   /* counter                             */
    Esc_UINT32* w;                  /* Round Keys                          */
#if ( ( EscAes_USE_T_TABLES_SMALL == 1) || (EscAes_USE_T_TABLES_FULL == 1 ) )
    Esc_UINT32* wd;                 /* Transformed round keys for equivalent inverse cipher */
#endif
    Esc_UINT32 temp;                /* temp  r                             */

    /* calculate number of 32-bit key blocks (nk) and number of rounds (nr) */
    Esc_UINT8 nk = (Esc_UINT8)(keyBits / 32U);
    ctx->nr = nk + EscAes_Nb + 2U;
    /* get pointer to encryption round keys */
    w = &ctx->round_keys[0];
#if ( ( EscAes_USE_T_TABLES_SMALL == 1) || (EscAes_USE_T_TABLES_FULL == 1 ) )
    /* get pointer to transformed decryption keys */
    wd = &ctx->dec_keys[0];
#endif

    /* enc_round_key[0..Nk-1] is the original key */
    for (i = 0U; i < nk; i++)
    {
        Esc_UINT32 idx;
        idx = ( (Esc_UINT32)i ) * 4U;
        w[i] = EscAes_Octets2Uint32( key, idx );
#if ( ( EscAes_USE_T_TABLES_SMALL == 1) || (EscAes_USE_T_TABLES_FULL == 1 ) )
        if (i < EscAes_Nb)
        {
            /* First 4 key words stay the same */
            wd[i] = w[i];
        }
        else
        {
            /* transform key for equivalent inverse cipher by Usage of InvMixColumns, omit the last block  of keys */
            wd[i] = EscAes_InvMixColumns( w[i] );
        }
#endif
    }

    /* derive round_key[>=Nk] from previous round_keys */
    /* We can calculate RotWord(SubWord(temp)) instead of SubWord(RotWord(temp)) */
    for (i = nk; i < ( EscAes_Nb * (ctx->nr + 1UL) ); i++)
    {
        temp = w[i - 1U];

        if ( ((i % nk) == 0U) || ( ( keyBits == 256U ) && ( (i % nk) == 4U ) ) )
        {
            /* temp = SubWord(temp) */
            Esc_UINT32 subbed;
            subbed = EscAes_FORWARD_SBOX[EscAes_BYTE_3( temp )];
            subbed |= ( (Esc_UINT32)EscAes_FORWARD_SBOX[EscAes_BYTE_2( temp )] ) << 8;
            subbed |= ( (Esc_UINT32)EscAes_FORWARD_SBOX[EscAes_BYTE_1( temp )] ) << 16;
            subbed |= ( (Esc_UINT32)EscAes_FORWARD_SBOX[EscAes_BYTE_0( temp )] ) << 24;
            temp = subbed;

            if ( ( keyBits != 256U ) || ((i % nk) == 0U ) )
            {
                /* temp = RotWord(temp) => (rotate left by 8 bit) */
                temp = (temp << 8) | (temp >> 24);
                /* our EscAes_RCON starts at index one */
                temp ^= ( (Esc_UINT32)EscAes_RCON[(i / nk)] ) << 24;
            }
        }
        w[i] = w[i - nk] ^ temp;

#if ( ( EscAes_USE_T_TABLES_SMALL == 1) || (EscAes_USE_T_TABLES_FULL == 1 ) )
        if ( i < ( EscAes_Nb * (Esc_UINT32)ctx->nr ) )
        {
            /* transform key for equivalent inverse cipher by usage of InvMixColumns, omit the last block of keys */
            wd[i] = EscAes_InvMixColumns( w[i] );
        }
        else
        {
            /* last 4 key words stay the same */
            wd[i] = w[i];
        }
#endif
    }

    /* Zeroize temp */
    Esc_CLEAR_LOCAL_VAR(temp);
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
