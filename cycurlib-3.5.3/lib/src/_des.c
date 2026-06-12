/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DES implementation general code

   \see FIPS PUB 46-3

   $Rev: 4105 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "_des.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************
 Set optimization flags according to global speed define.
 ***************************************************************/

/*lint -emacro(9044,EscDes_ROTR32,EscDes_ROTL32) We allow the modifying of function parameters for function-like macros */
/** Rotates a 32 bit word left. */
#define EscDes_ROTL32( x, y ) ( ( (x) << (y) ) | ( (x) >> ( 32U - (y) ) ) )

/** Rotates a 32 bit word right. */
#define EscDes_ROTR32( x, y ) ( ( (x) >> (y) ) | ( (x) << ( 32U - (y) ) ) )

/** Permuted choice 1 */
#define EscDes_PERMUTED_CHOICE1_DATA       \
    {                                      \
        57U, 49U, 41U, 33U, 25U, 17U,  9U, \
        1U, 58U, 50U, 42U, 34U, 26U, 18U,  \
        10U,  2U, 59U, 51U, 43U, 35U, 27U, \
        19U, 11U,  3U, 60U, 52U, 44U, 36U, \
        63U, 55U, 47U, 39U, 31U, 23U, 15U, \
        7U, 62U, 54U, 46U, 38U, 30U, 22U,  \
        14U,  6U, 61U, 53U, 45U, 37U, 29U, \
        21U, 13U,  5U, 28U, 20U, 12U,  4U  \
    }

/** Permuted choice 2 */
#define EscDes_PERMUTED_CHOICE2_DATA  \
    {                                 \
        14U, 17U, 11U, 24U,  1U,  5U, \
        3U, 28U, 15U,  6U, 21U, 10U,  \
        23U, 19U, 12U,  4U, 26U,  8U, \
        16U,  7U, 27U, 20U, 13U,  2U, \
        41U, 52U, 31U, 37U, 47U, 55U, \
        30U, 40U, 51U, 45U, 33U, 48U, \
        44U, 49U, 39U, 56U, 34U, 53U, \
        46U, 42U, 50U, 36U, 29U, 32U  \
    }

/** Number left rotations of pc1 */
#define EscDes_NUM_ROT_DATA           \
    {                                 \
        1U,  2U,  4U,  6U,  8U, 10U,  \
        12U, 14U, 15U, 17U, 19U, 21U, \
        23U, 25U, 27U, 28U            \
    }

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

static Esc_UINT32
EscDes_OctetsToUint32(
    const Esc_UINT8 octets[] );

static void
EscDes_Uint32ToOctets(
    Esc_UINT8 octets[],
    Esc_UINT32 word );

#if EscDes_USE_BIG_TABLES == 0
static Esc_UINT32
EscDes_SPBox(
    Esc_UINT8 s,
    Esc_UINT8 colrow );
#endif


/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

#if EscDes_USE_BIG_TABLES == 1
/** The DES SP-boxes */
static const Esc_UINT32 EscDes_SPBOX[8][64] =
{
    {
        0x01010400U, 0x00000000U, 0x00010000U, 0x01010404U, 0x01010004U, 0x00010404U, 0x00000004U, 0x00010000U,
        0x00000400U, 0x01010400U, 0x01010404U, 0x00000400U, 0x01000404U, 0x01010004U, 0x01000000U, 0x00000004U,
        0x00000404U, 0x01000400U, 0x01000400U, 0x00010400U, 0x00010400U, 0x01010000U, 0x01010000U, 0x01000404U,
        0x00010004U, 0x01000004U, 0x01000004U, 0x00010004U, 0x00000000U, 0x00000404U, 0x00010404U, 0x01000000U,
        0x00010000U, 0x01010404U, 0x00000004U, 0x01010000U, 0x01010400U, 0x01000000U, 0x01000000U, 0x00000400U,
        0x01010004U, 0x00010000U, 0x00010400U, 0x01000004U, 0x00000400U, 0x00000004U, 0x01000404U, 0x00010404U,
        0x01010404U, 0x00010004U, 0x01010000U, 0x01000404U, 0x01000004U, 0x00000404U, 0x00010404U, 0x01010400U,
        0x00000404U, 0x01000400U, 0x01000400U, 0x00000000U, 0x00010004U, 0x00010400U, 0x00000000U, 0x01010004U
    },
    {
        0x80108020U, 0x80008000U, 0x00008000U, 0x00108020U, 0x00100000U, 0x00000020U, 0x80100020U, 0x80008020U,
        0x80000020U, 0x80108020U, 0x80108000U, 0x80000000U, 0x80008000U, 0x00100000U, 0x00000020U, 0x80100020U,
        0x00108000U, 0x00100020U, 0x80008020U, 0x00000000U, 0x80000000U, 0x00008000U, 0x00108020U, 0x80100000U,
        0x00100020U, 0x80000020U, 0x00000000U, 0x00108000U, 0x00008020U, 0x80108000U, 0x80100000U, 0x00008020U,
        0x00000000U, 0x00108020U, 0x80100020U, 0x00100000U, 0x80008020U, 0x80100000U, 0x80108000U, 0x00008000U,
        0x80100000U, 0x80008000U, 0x00000020U, 0x80108020U, 0x00108020U, 0x00000020U, 0x00008000U, 0x80000000U,
        0x00008020U, 0x80108000U, 0x00100000U, 0x80000020U, 0x00100020U, 0x80008020U, 0x80000020U, 0x00100020U,
        0x00108000U, 0x00000000U, 0x80008000U, 0x00008020U, 0x80000000U, 0x80100020U, 0x80108020U, 0x00108000U
    },
    {
        0x00000208U, 0x08020200U, 0x00000000U, 0x08020008U, 0x08000200U, 0x00000000U, 0x00020208U, 0x08000200U,
        0x00020008U, 0x08000008U, 0x08000008U, 0x00020000U, 0x08020208U, 0x00020008U, 0x08020000U, 0x00000208U,
        0x08000000U, 0x00000008U, 0x08020200U, 0x00000200U, 0x00020200U, 0x08020000U, 0x08020008U, 0x00020208U,
        0x08000208U, 0x00020200U, 0x00020000U, 0x08000208U, 0x00000008U, 0x08020208U, 0x00000200U, 0x08000000U,
        0x08020200U, 0x08000000U, 0x00020008U, 0x00000208U, 0x00020000U, 0x08020200U, 0x08000200U, 0x00000000U,
        0x00000200U, 0x00020008U, 0x08020208U, 0x08000200U, 0x08000008U, 0x00000200U, 0x00000000U, 0x08020008U,
        0x08000208U, 0x00020000U, 0x08000000U, 0x08020208U, 0x00000008U, 0x00020208U, 0x00020200U, 0x08000008U,
        0x08020000U, 0x08000208U, 0x00000208U, 0x08020000U, 0x00020208U, 0x00000008U, 0x08020008U, 0x00020200U
    },
    {
        0x00802001U, 0x00002081U, 0x00002081U, 0x00000080U, 0x00802080U, 0x00800081U, 0x00800001U, 0x00002001U,
        0x00000000U, 0x00802000U, 0x00802000U, 0x00802081U, 0x00000081U, 0x00000000U, 0x00800080U, 0x00800001U,
        0x00000001U, 0x00002000U, 0x00800000U, 0x00802001U, 0x00000080U, 0x00800000U, 0x00002001U, 0x00002080U,
        0x00800081U, 0x00000001U, 0x00002080U, 0x00800080U, 0x00002000U, 0x00802080U, 0x00802081U, 0x00000081U,
        0x00800080U, 0x00800001U, 0x00802000U, 0x00802081U, 0x00000081U, 0x00000000U, 0x00000000U, 0x00802000U,
        0x00002080U, 0x00800080U, 0x00800081U, 0x00000001U, 0x00802001U, 0x00002081U, 0x00002081U, 0x00000080U,
        0x00802081U, 0x00000081U, 0x00000001U, 0x00002000U, 0x00800001U, 0x00002001U, 0x00802080U, 0x00800081U,
        0x00002001U, 0x00002080U, 0x00800000U, 0x00802001U, 0x00000080U, 0x00800000U, 0x00002000U, 0x00802080U
    },
    {
        0x00000100U, 0x02080100U, 0x02080000U, 0x42000100U, 0x00080000U, 0x00000100U, 0x40000000U, 0x02080000U,
        0x40080100U, 0x00080000U, 0x02000100U, 0x40080100U, 0x42000100U, 0x42080000U, 0x00080100U, 0x40000000U,
        0x02000000U, 0x40080000U, 0x40080000U, 0x00000000U, 0x40000100U, 0x42080100U, 0x42080100U, 0x02000100U,
        0x42080000U, 0x40000100U, 0x00000000U, 0x42000000U, 0x02080100U, 0x02000000U, 0x42000000U, 0x00080100U,
        0x00080000U, 0x42000100U, 0x00000100U, 0x02000000U, 0x40000000U, 0x02080000U, 0x42000100U, 0x40080100U,
        0x02000100U, 0x40000000U, 0x42080000U, 0x02080100U, 0x40080100U, 0x00000100U, 0x02000000U, 0x42080000U,
        0x42080100U, 0x00080100U, 0x42000000U, 0x42080100U, 0x02080000U, 0x00000000U, 0x40080000U, 0x42000000U,
        0x00080100U, 0x02000100U, 0x40000100U, 0x00080000U, 0x00000000U, 0x40080000U, 0x02080100U, 0x40000100U
    },
    {
        0x20000010U, 0x20400000U, 0x00004000U, 0x20404010U, 0x20400000U, 0x00000010U, 0x20404010U, 0x00400000U,
        0x20004000U, 0x00404010U, 0x00400000U, 0x20000010U, 0x00400010U, 0x20004000U, 0x20000000U, 0x00004010U,
        0x00000000U, 0x00400010U, 0x20004010U, 0x00004000U, 0x00404000U, 0x20004010U, 0x00000010U, 0x20400010U,
        0x20400010U, 0x00000000U, 0x00404010U, 0x20404000U, 0x00004010U, 0x00404000U, 0x20404000U, 0x20000000U,
        0x20004000U, 0x00000010U, 0x20400010U, 0x00404000U, 0x20404010U, 0x00400000U, 0x00004010U, 0x20000010U,
        0x00400000U, 0x20004000U, 0x20000000U, 0x00004010U, 0x20000010U, 0x20404010U, 0x00404000U, 0x20400000U,
        0x00404010U, 0x20404000U, 0x00000000U, 0x20400010U, 0x00000010U, 0x00004000U, 0x20400000U, 0x00404010U,
        0x00004000U, 0x00400010U, 0x20004010U, 0x00000000U, 0x20404000U, 0x20000000U, 0x00400010U, 0x20004010U
    },
    {
        0x00200000U, 0x04200002U, 0x04000802U, 0x00000000U, 0x00000800U, 0x04000802U, 0x00200802U, 0x04200800U,
        0x04200802U, 0x00200000U, 0x00000000U, 0x04000002U, 0x00000002U, 0x04000000U, 0x04200002U, 0x00000802U,
        0x04000800U, 0x00200802U, 0x00200002U, 0x04000800U, 0x04000002U, 0x04200000U, 0x04200800U, 0x00200002U,
        0x04200000U, 0x00000800U, 0x00000802U, 0x04200802U, 0x00200800U, 0x00000002U, 0x04000000U, 0x00200800U,
        0x04000000U, 0x00200800U, 0x00200000U, 0x04000802U, 0x04000802U, 0x04200002U, 0x04200002U, 0x00000002U,
        0x00200002U, 0x04000000U, 0x04000800U, 0x00200000U, 0x04200800U, 0x00000802U, 0x00200802U, 0x04200800U,
        0x00000802U, 0x04000002U, 0x04200802U, 0x04200000U, 0x00200800U, 0x00000000U, 0x00000002U, 0x04200802U,
        0x00000000U, 0x00200802U, 0x04200000U, 0x00000800U, 0x04000002U, 0x04000800U, 0x00000800U, 0x00200002U
    },
    {
        0x10001040U, 0x00001000U, 0x00040000U, 0x10041040U, 0x10000000U, 0x10001040U, 0x00000040U, 0x10000000U,
        0x00040040U, 0x10040000U, 0x10041040U, 0x00041000U, 0x10041000U, 0x00041040U, 0x00001000U, 0x00000040U,
        0x10040000U, 0x10000040U, 0x10001000U, 0x00001040U, 0x00041000U, 0x00040040U, 0x10040040U, 0x10041000U,
        0x00001040U, 0x00000000U, 0x00000000U, 0x10040040U, 0x10000040U, 0x10001000U, 0x00041040U, 0x00040000U,
        0x00041040U, 0x00040000U, 0x10041000U, 0x00001000U, 0x00000040U, 0x10040040U, 0x00001000U, 0x00041040U,
        0x10001000U, 0x00000040U, 0x10000040U, 0x10040000U, 0x10040040U, 0x10000000U, 0x00040000U, 0x10001040U,
        0x00000000U, 0x10041040U, 0x00040040U, 0x10000040U, 0x10040000U, 0x10001000U, 0x10001040U, 0x00000000U,
        0x10041040U, 0x00041000U, 0x00041000U, 0x00001040U, 0x00001040U, 0x00040040U, 0x10000000U, 0x10041000U
    }
};
#endif /* EscDes_USE_BIG_TABLES */

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
/**
 Converts the octets in big endian format to Esc_UINT32.
 */
static Esc_UINT32
EscDes_OctetsToUint32(
    const Esc_UINT8 octets[] )
{
    Esc_UINT32 v;

    v = ( ( (Esc_UINT32)octets[0] << 24 ) |
          ( (Esc_UINT32)octets[1] << 16 ) |
          ( (Esc_UINT32)octets[2] << 8 ) |
          ( (Esc_UINT32)octets[3] )
          );

    return v;
}

/**
 Converts the octets from Esc_UINT32 to big endian format.
 */
static void
EscDes_Uint32ToOctets(
    Esc_UINT8 octets[],
    Esc_UINT32 word )
{
    Esc_UINT32 v;

    v = word;

    octets[3] = (Esc_UINT8)(v & 0xFFU);
    v >>= 8;
    octets[2] = (Esc_UINT8)(v & 0xFFU);
    v >>= 8;
    octets[1] = (Esc_UINT8)(v & 0xFFU);
    v >>= 8;
    octets[0] = (Esc_UINT8)(v & 0xFFU);
}

/**
 * Performs the initial permutation.
 */
void
EscDes_IntitialPermutation(
    Esc_UINT32* l,
    Esc_UINT32* r,
    const Esc_UINT8 desBlock[] )
{
    Esc_UINT32 v;
    Esc_UINT32 my_l;
    Esc_UINT32 my_r;

    Esc_ASSERT( l != 0 );
    Esc_ASSERT( r != 0 );

    my_l = EscDes_OctetsToUint32( desBlock );
    my_r = EscDes_OctetsToUint32( &desBlock[4] );

    my_r = EscDes_ROTL32( my_r, 4U );
    v = (my_l ^ my_r) & 0xf0f0f0f0U;
    my_l ^= v;
    my_r = EscDes_ROTR32( my_r ^ v, 20U );
    v = (my_l ^ my_r) & 0xffff0000U;
    my_l ^= v;
    my_r = EscDes_ROTR32( my_r ^ v, 18U );
    v = (my_l ^ my_r) & 0x33333333U;
    my_l ^= v;
    my_r = EscDes_ROTR32( my_r ^ v, 6U );
    v = (my_l ^ my_r) & 0x00ff00ffU;
    my_l ^= v;
    my_r = EscDes_ROTL32( my_r ^ v, 9U );
    v = (my_l ^ my_r) & 0xaaaaaaaaU;
    my_l = EscDes_ROTL32( my_l ^ v, 1U );
    my_r ^= v;

    *l = my_l;
    *r = my_r;
}

/**
 * Performs the final permutation.
 */
void
EscDes_FinalPermutation(
    Esc_UINT8 desBlock[],
    Esc_UINT32 l,
    Esc_UINT32 r )
{
    Esc_UINT32 v;

    r = EscDes_ROTR32( r, 1U );
    v = (l ^ r) & 0xaaaaaaaaU;
    r ^= v;
    l = EscDes_ROTR32( l ^ v, 9U );
    v = (l ^ r) & 0x00ff00ffU;
    r ^= v;
    l = EscDes_ROTL32( l ^ v, 6U );
    v = (l ^ r) & 0x33333333U;
    r ^= v;
    l = EscDes_ROTL32( l ^ v, 18U );
    v = (l ^ r) & 0xffff0000U;
    r ^= v;
    l = EscDes_ROTL32( l ^ v, 20U );
    v = (l ^ r) & 0xf0f0f0f0U;
    r ^= v;
    l = EscDes_ROTR32( l ^ v, 4U );

    EscDes_Uint32ToOctets( desBlock, r );
    EscDes_Uint32ToOctets( &desBlock[4], l );
}

#if EscDes_USE_BIG_TABLES == 0
/**
 Perform on-the-fly S/P-Layer instead of big SP-box
 */
static Esc_UINT32
EscDes_SPBox(
    Esc_UINT8 s,
    Esc_UINT8 colrow )
{
    /** The DES S-boxes, resorted from rccccr to rrcccc (rows/columns) */
    static const Esc_UINT8 EscDes_SBOX[8][64] =
    {
        /*S1: */
        {
            14U, 0U, 4U, 15U, 13U, 7U, 1U, 4U, 2U, 14U, 15U, 2U, 11U, 13U, 8U, 1U,
            3U, 10U, 10U, 6U, 6U, 12U, 12U, 11U, 5U, 9U, 9U, 5U, 0U, 3U, 7U, 8U,
            4U, 15U, 1U, 12U, 14U, 8U, 8U, 2U, 13U, 4U, 6U, 9U, 2U, 1U, 11U, 7U,
            15U, 5U, 12U, 11U, 9U, 3U, 7U, 14U, 3U, 10U, 10U, 0U, 5U, 6U, 0U, 13U,
        },
        /*S2: */
        {
            15U, 3U, 1U, 13U, 8U, 4U, 14U, 7U, 6U, 15U, 11U, 2U, 3U, 8U, 4U, 14U,
            9U, 12U, 7U, 0U, 2U, 1U, 13U, 10U, 12U, 6U, 0U, 9U, 5U, 11U, 10U, 5U,
            0U, 13U, 14U, 8U, 7U, 10U, 11U, 1U, 10U, 3U, 4U, 15U, 13U, 4U, 1U, 2U,
            5U, 11U, 8U, 6U, 12U, 7U, 6U, 12U, 9U, 0U, 3U, 5U, 2U, 14U, 15U, 9U,
        },
        /*S3: */
        {
            10U, 13U, 0U, 7U, 9U, 0U, 14U, 9U, 6U, 3U, 3U, 4U, 15U, 6U, 5U, 10U,
            1U, 2U, 13U, 8U, 12U, 5U, 7U, 14U, 11U, 12U, 4U, 11U, 2U, 15U, 8U, 1U,
            13U, 1U, 6U, 10U, 4U, 13U, 9U, 0U, 8U, 6U, 15U, 9U, 3U, 8U, 0U, 7U,
            11U, 4U, 1U, 15U, 2U, 14U, 12U, 3U, 5U, 11U, 10U, 5U, 14U, 2U, 7U, 12U,
        },
        /*S4: */
        {
            7U, 13U, 13U, 8U, 14U, 11U, 3U, 5U, 0U, 6U, 6U, 15U, 9U, 0U, 10U, 3U,
            1U, 4U, 2U, 7U, 8U, 2U, 5U, 12U, 11U, 1U, 12U, 10U, 4U, 14U, 15U, 9U,
            10U, 3U, 6U, 15U, 9U, 0U, 0U, 6U, 12U, 10U, 11U, 1U, 7U, 13U, 13U, 8U,
            15U, 9U, 1U, 4U, 3U, 5U, 14U, 11U, 5U, 12U, 2U, 7U, 8U, 2U, 4U, 14U,
        },
        /*S5: */
        {
            2U, 14U, 12U, 11U, 4U, 2U, 1U, 12U, 7U, 4U, 10U, 7U, 11U, 13U, 6U, 1U,
            8U, 5U, 5U, 0U, 3U, 15U, 15U, 10U, 13U, 3U, 0U, 9U, 14U, 8U, 9U, 6U,
            4U, 11U, 2U, 8U, 1U, 12U, 11U, 7U, 10U, 1U, 13U, 14U, 7U, 2U, 8U, 13U,
            15U, 6U, 9U, 15U, 12U, 0U, 5U, 9U, 6U, 10U, 3U, 4U, 0U, 5U, 14U, 3U,
        },
        /*S6: */
        {
            12U, 10U, 1U, 15U, 10U, 4U, 15U, 2U, 9U, 7U, 2U, 12U, 6U, 9U, 8U, 5U,
            0U, 6U, 13U, 1U, 3U, 13U, 4U, 14U, 14U, 0U, 7U, 11U, 5U, 3U, 11U, 8U,
            9U, 4U, 14U, 3U, 15U, 2U, 5U, 12U, 2U, 9U, 8U, 5U, 12U, 15U, 3U, 10U,
            7U, 11U, 0U, 14U, 4U, 1U, 10U, 7U, 1U, 6U, 13U, 0U, 11U, 8U, 6U, 13U,
        },
        /*S7: */
        {
            4U, 13U, 11U, 0U, 2U, 11U, 14U, 7U, 15U, 4U, 0U, 9U, 8U, 1U, 13U, 10U,
            3U, 14U, 12U, 3U, 9U, 5U, 7U, 12U, 5U, 2U, 10U, 15U, 6U, 8U, 1U, 6U,
            1U, 6U, 4U, 11U, 11U, 13U, 13U, 8U, 12U, 1U, 3U, 4U, 7U, 10U, 14U, 7U,
            10U, 9U, 15U, 5U, 6U, 0U, 8U, 15U, 0U, 14U, 5U, 2U, 9U, 3U, 2U, 12U,
        },
        /*S8: */
        {
            13U, 1U, 2U, 15U, 8U, 13U, 4U, 8U, 6U, 10U, 15U, 3U, 11U, 7U, 1U, 4U,
            10U, 12U, 9U, 5U, 3U, 6U, 14U, 11U, 5U, 0U, 0U, 14U, 12U, 9U, 7U, 2U,
            7U, 2U, 11U, 1U, 4U, 14U, 1U, 7U, 9U, 4U, 12U, 10U, 14U, 8U, 2U, 13U,
            0U, 15U, 6U, 12U, 10U, 9U, 13U, 0U, 15U, 3U, 3U, 5U, 5U, 6U, 8U, 11U
        },
    };

    /** Inverse P function */
    static const Esc_UINT8 EscDes_PBOX[32] =
    {
        8U, 16U, 22U, 30U, 12U, 27U, 1U, 17U, 23U, 15U, 29U, 5U, 25U, 19U, 9U, 0U,
        7U, 13U, 24U, 2U, 3U, 28U, 10U, 18U, 31U, 11U, 21U, 6U, 4U, 26U, 14U, 20U
    };
    Esc_UINT32 result = 0U;
    Esc_UINT8 j;
    for (j = 0U; j < 4U; j++)        /* For each output bit */
    {
        if ( ( EscDes_SBOX[s][colrow] & (Esc_UINT8)(8U >> j) ) != 0U )
        {
            result |= (Esc_UINT32)( (Esc_UINT32)1U << (31U - EscDes_PBOX[(4U * s) + j]) );
        }
    }
    /* rotate 1 left to match block layout */
    return (result << 1) | (result >> 31);
}

#endif

/**
Processes the DES rounds forward.
*/
void
EscDes_EncryptRounds(
    const EscDes_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr )
{
    Esc_UINT8 i;
    Esc_UINT32 v;
    Esc_UINT32 l, r;
    const EscDes_RoundKeyT* pk;

    Esc_ASSERT( sched != 0 );
    Esc_ASSERT( pl != 0 );
    Esc_ASSERT( pr != 0 );

    l = *pl;
    r = *pr;

    pk = sched->k;

    for (i = 0U; i < 8U; i++)
    {
#if EscDes_USE_BIG_TABLES == 1
        v = EscDes_ROTR32( r, 4U ) ^ pk[2U * i].k1;
        l ^= EscDes_SPBOX[6][v & 0x3fU] ^
            EscDes_SPBOX[4][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[2][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[0][(v >> 24) & 0x3fU];
        v = r ^ pk[2U * i].k2;
        l ^= EscDes_SPBOX[7][v & 0x3fU] ^
            EscDes_SPBOX[5][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[3][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[1][(v >> 24) & 0x3fU];

        v = EscDes_ROTR32( l, 4U ) ^ pk[(2U * i) + 1U].k1;
        r ^= EscDes_SPBOX[6][(v) & 0x3fU] ^
            EscDes_SPBOX[4][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[2][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[0][(v >> 24) & 0x3fU];
        v = l ^ pk[(2U * i) + 1U].k2;
        r ^= EscDes_SPBOX[7][(v) & 0x3fU] ^
            EscDes_SPBOX[5][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[3][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[1][(v >> 24) & 0x3fU];
#else /* EscDes_USE_BIG_TABLES */
        v = EscDes_ROTR32( r, 4U ) ^ pk[2U * i].k1;
        l ^= EscDes_SPBox( 6U, (Esc_UINT8)(v & 0x3fU) ) ^
            EscDes_SPBox( 4U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 2U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 0U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );
        v = r ^ pk[2U * i].k2;
        l ^= EscDes_SPBox( 7U, (Esc_UINT8)(v & 0x3fU) ) ^
            EscDes_SPBox( 5U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 3U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 1U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );

        v = EscDes_ROTR32( l, 4U ) ^ pk[(2U * i) + 1U].k1;
        r ^= EscDes_SPBox( 6U, (Esc_UINT8)( (v) & 0x3fU ) ) ^
            EscDes_SPBox( 4U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 2U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 0U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );
        v = l ^ pk[(2U * i) + 1U].k2;
        r ^= EscDes_SPBox( 7U, (Esc_UINT8)( (v) & 0x3fU ) ) ^
            EscDes_SPBox( 5U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 3U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 1U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );
#endif
    }

    *pl = l;
    *pr = r;
}

/**
Processes the DES rounds forward.
*/
void
EscDes_DecryptRounds(
    const EscDes_KeySchedT* sched,
    Esc_UINT32* pl,
    Esc_UINT32* pr )
{
    Esc_UINT8 i;
    Esc_UINT32 v;
    Esc_UINT32 l, r;
    const EscDes_RoundKeyT* pk;
    Esc_UINT8 keyIdx = 16U;

    Esc_ASSERT( sched != 0 );
    Esc_ASSERT( pl != 0 );
    Esc_ASSERT( pr != 0 );

    l = *pl;
    r = *pr;

    pk = sched->k;

    for (i = 0U; i < 8U; i++)
    {
        keyIdx--;

#if EscDes_USE_BIG_TABLES == 1
        v = EscDes_ROTR32( r, 4U ) ^ pk[keyIdx].k1;
        l ^= EscDes_SPBOX[6][(v) & 0x3fU] ^
            EscDes_SPBOX[4][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[2][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[0][(v >> 24) & 0x3fU];

        v = r ^ pk[keyIdx].k2;
        l ^= EscDes_SPBOX[7][(v) & 0x3fU] ^
            EscDes_SPBOX[5][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[3][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[1][(v >> 24) & 0x3fU];
#else /* EscDes_USE_BIG_TABLES */
        v = EscDes_ROTR32( r, 4U ) ^ pk[keyIdx].k1;
        l ^= EscDes_SPBox( 6U, (Esc_UINT8)(v & 0x3fU) ) ^
            EscDes_SPBox( 4U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 2U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 0U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );
        v = r ^ pk[keyIdx].k2;
        l ^= EscDes_SPBox( 7U, (Esc_UINT8)(v & 0x3fU) ) ^
            EscDes_SPBox( 5U, (Esc_UINT8)( (v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 3U, (Esc_UINT8)( (v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 1U, (Esc_UINT8)( (v >> 24) & 0x3fU ) );
#endif
        keyIdx--;
#if EscDes_USE_BIG_TABLES == 1
        v = EscDes_ROTR32( l, 4U ) ^ pk[keyIdx].k1;
        r ^= EscDes_SPBOX[6][(v) & 0x3fU] ^
            EscDes_SPBOX[4][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[2][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[0][(v >> 24) & 0x3fU];

        v = l ^ pk[keyIdx].k2;
        r ^= EscDes_SPBOX[7][(v) & 0x3fU] ^
            EscDes_SPBOX[5][(v >> 8) & 0x3fU] ^
            EscDes_SPBOX[3][(v >> 16) & 0x3fU] ^
            EscDes_SPBOX[1][(v >> 24) & 0x3fU];
#else /* EscDes_USE_BIG_TABLES */
        v = EscDes_ROTR32( l, 4U ) ^ pk[keyIdx].k1;
        r ^= EscDes_SPBox( 6U, (Esc_UINT8)( (v) & 0x3fU ) ) ^
            EscDes_SPBox( 4U, (Esc_UINT8)( (Esc_UINT32)(v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 2U, (Esc_UINT8)( (Esc_UINT32)(v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 0U, (Esc_UINT8)( (Esc_UINT32)(v >> 24) & 0x3fU ) );
        v = l ^ pk[keyIdx].k2;
        r ^= EscDes_SPBox( 7U, (Esc_UINT8)( (v) & 0x3fU ) ) ^
            EscDes_SPBox( 5U, (Esc_UINT8)( (Esc_UINT32)(v >> 8) & 0x3fU ) ) ^
            EscDes_SPBox( 3U, (Esc_UINT8)( (Esc_UINT32)(v >> 16) & 0x3fU ) ) ^
            EscDes_SPBox( 1U, (Esc_UINT8)( (Esc_UINT32)(v >> 24) & 0x3fU ) );
#endif
    }

    *pl = l;
    *pr = r;
}

/**
Initializes the ECB Context with the corresponding DES key.
*/
void
EscDes_Init(
    EscDes_KeySchedT* sched,
    const Esc_UINT8 key[] )
{
    Esc_UINT8 pc1m[56];
    Esc_UINT8 pcr[56];
    Esc_UINT8 ks[8];
    Esc_UINT8 i, j, k, l, m;
    static const Esc_UINT8 BYTEBIT[] =
    {
        0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
    };
    static const Esc_UINT8 PC1[] = EscDes_PERMUTED_CHOICE1_DATA;
    static const Esc_UINT8 PC2[] = EscDes_PERMUTED_CHOICE2_DATA;
    static const Esc_UINT8 ROTCOUNT[] = EscDes_NUM_ROT_DATA;

    Esc_ASSERT( sched != 0 );
    Esc_ASSERT( key != 0 );

    for (j = 0U; j < 56U; j++)         /* convert pc1 to bits of key */
    {
        l = PC1[j] - 1U;          /* integer bit location  */
        m = (Esc_UINT8)(l & 0x07U);        /* find bit              */
        /* find which key byte l is in */
        /* and which bit of that byte */
        /* and store 1-bit result */
        if ( (key[l >> 3] & BYTEBIT[m]) != 0U )
        {
            pc1m[j] = 1U;
        }
        else
        {
            pc1m[j] = 0U;
        }
    }

    /* key chunk for each iteration */
    for (i = 0U; i < EscDes_NUM_ROUNDS; i++)
    {
        /* Clear key schedule */
        for (k = 0U; k < 8U; k++)
        {
            ks[k] = 0U;
        }

        /* rotate pc1 the right amount */
        for (j = 0U; j < 56U; j++)
        {
            Esc_UINT8 maxL;
            if (j < 28U)
            {
                maxL = 28U;
            }
            else
            {
                maxL = 56U;
            }
            l = j + ROTCOUNT[i];
            if (l < maxL)
            {
                pcr[j] = pc1m[l];
            }
            else
            {
                pcr[j] = pc1m[l - 28U];
            }
        }

        /* rotate left and right halves independently */
        for (j = 0U; j < 48U; j++)         /* select bits individually */
        {   /* check bit that goes to ks[j] */
            if (pcr[PC2[j] - 1U] != 0U)
            {
                /* mask it in if it's there */
                l = j % 6U;
                ks[j / 6U] |= (Esc_UINT8)(BYTEBIT[l] >> 2);
            }
        }
        /* Now convert to odd/even interleaved form for use in F */
        sched->k[i].k1 = ( (Esc_UINT32)ks[0] << 24 ) |
            ( (Esc_UINT32)ks[2] << 16 ) |
            ( (Esc_UINT32)ks[4] << 8 ) |
            ( (Esc_UINT32)ks[6] );
        sched->k[i].k2 = ( (Esc_UINT32)ks[1] << 24 ) |
            ( (Esc_UINT32)ks[3] << 16 ) |
            ( (Esc_UINT32)ks[5] << 8 ) |
            ( (Esc_UINT32)ks[7] );
    }

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_ARRAY(pc1m);
    Esc_CLEAR_LOCAL_ARRAY(pcr);
    Esc_CLEAR_LOCAL_ARRAY(ks);
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
