/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief AES_CMAC Selftest.

   MACs a given payload and checks if the result matches
   a precalculated pattern.

   $Rev: 3832 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "test_cmac_aes.h"
#include "selftest.h"
#include "cmac_aes.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscTstCmacAes_MAX_DATALEN   64U

#define EscCmacAes_NUM_TESTCASES    4U


#if EscAes_MAX_KEY_BITS == 128U
#   define EscTstCmacAes_NUM_KEYSIZES    1U
#elif EscAes_MAX_KEY_BITS == 192U
#   define EscTstCmacAes_NUM_KEYSIZES    2U
#elif EscAes_MAX_KEY_BITS == 256U
#   define EscTstCmacAes_NUM_KEYSIZES    3U
#else
#   error "Invalid AES key size"
#endif

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

static const Esc_UINT16 keySizes[] =
{
    16U,    /* 128 bit */
    24U,    /* 192 bit */
    32U     /* 256 bit */
};

/** CMAC test vector */
typedef struct
{
    Esc_UINT8 key[EscAes_MAX_KEY_BYTES];
    Esc_UINT8 msg[EscTstCmacAes_MAX_DATALEN];
    Esc_UINT32 msgLen;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];
} EscTstCmacAes_testcaseT;

/*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
static const EscTstCmacAes_testcaseT cmac_test[EscTstCmacAes_NUM_KEYSIZES][EscCmacAes_NUM_TESTCASES] =
{
    /* key size 128 bit */
    {
        {
            /* Chapter D.1, Example 1 */
            {
                0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
                0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
            },   /* key */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            0U,                         /* msgLen */
            {
                0xbbU, 0x1dU, 0x69U, 0x29U, 0xe9U, 0x59U, 0x37U, 0x28U,
                0x7fU, 0xa3U, 0x7dU, 0x12U, 0x9bU, 0x75U, 0x67U, 0x46U
            }    /* MAC */
        },
        {
            /* Chapter D.1, Example 2 */
            {
                0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
                0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            16U,                         /* msgLen */
            {
                0x07U, 0x0aU, 0x16U, 0xb4U, 0x6bU, 0x4dU, 0x41U, 0x44U,
                0xf7U, 0x9bU, 0xddU, 0x9dU, 0xd0U, 0x4aU, 0x28U, 0x7cU
            }    /* MAC */
        },
        {
            /* Chapter D.1, Example 3 */
            {
                0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
                0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            40U,                        /* msgLen */
            {
                0xdfU, 0xa6U, 0x67U, 0x47U, 0xdeU, 0x9aU, 0xe6U, 0x30U,
                0x30U, 0xcaU, 0x32U, 0x61U, 0x14U, 0x97U, 0xc8U, 0x27U
            }    /* MAC */
        },
        {
            /* Chapter D.1, Example 4 */
            {
                0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
                0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU,
                0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U,
                0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U
            },   /*msg */
            64U,                        /* msgLen */
            {
                0x51U, 0xf0U, 0xbeU, 0xbfU, 0x7eU, 0x3bU, 0x9dU, 0x92U,
                0xfcU, 0x49U, 0x74U, 0x17U, 0x79U, 0x36U, 0x3cU, 0xfeU
            }    /* MAC */
        }
    },

#if EscAes_MAX_KEY_BITS >= 192U
    /* key size 192 bit */
    {
        {
            /* Chapter D.2, Example 5 */
            {
                0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U,
                0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U,
                0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU
            },   /* key */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            0U,                         /* msgLen */
            {
                0xd1U, 0x7dU, 0xdfU, 0x46U, 0xadU, 0xaaU, 0xcdU, 0xe5U,
                0x31U, 0xcaU, 0xc4U, 0x83U, 0xdeU, 0x7aU, 0x93U, 0x67U
            }    /* MAC */
        },
        {
            /* Chapter D.2, Example 6 */
            {
                0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U,
                0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U,
                0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            16U,                        /* msgLen */
            {
                0x9eU, 0x99U, 0xa7U, 0xbfU, 0x31U, 0xe7U, 0x10U, 0x90U,
                0x06U, 0x62U, 0xf6U, 0x5eU, 0x61U, 0x7cU, 0x51U, 0x84U
            }    /* MAC */
        },
        {
            /* Chapter D.2, Example 7 */
            {
                0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U,
                0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U,
                0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            40U,                        /* msgLen */
            {
                0x8aU, 0x1dU, 0xe5U, 0xbeU, 0x2eU, 0xb3U, 0x1aU, 0xadU,
                0x08U, 0x9aU, 0x82U, 0xe6U, 0xeeU, 0x90U, 0x8bU, 0x0eU
            }    /* MAC */
        },
        {
            /* Chapter D.2, Example 8 */
            {
                0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U,
                0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U,
                0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU,
                0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U,
                0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U
            },   /*msg */
            64U,                        /* msgLen */
            {
                0xa1U, 0xd5U, 0xdfU, 0x0eU, 0xedU, 0x79U, 0x0fU, 0x79U,
                0x4dU, 0x77U, 0x58U, 0x96U, 0x59U, 0xf3U, 0x9aU, 0x11U
            }    /* MAC */
        }
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    /* key size 256 bit */
    {
        {
            /* Chapter D.3, Example 9 */
            {
                0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
                0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
                0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
                0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U
            },   /* key */
            {
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            0U,                         /* msgLen */
            {
                0x02U, 0x89U, 0x62U, 0xf6U, 0x1bU, 0x7bU, 0xf8U, 0x9eU,
                0xfcU, 0x6bU, 0x55U, 0x1fU, 0x46U, 0x67U, 0xd9U, 0x83U
            }    /* MAC */
        },
        {
            /* Chapter D.3, Example 10 */
            {
                0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
                0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
                0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
                0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            16U,                         /* msgLen */
            {
                0x28U, 0xa7U, 0x02U, 0x3fU, 0x45U, 0x2eU, 0x8fU, 0x82U,
                0xbdU, 0x4bU, 0xf2U, 0x8dU, 0x8cU, 0x37U, 0xc3U, 0x5cU
            }    /* MAC */
        },
        {
            /* Chapter D.3, Example 11 */
            {
                0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
                0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
                0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
                0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
            },   /*msg */
            40U,                        /* msgLen */
            {
                0xaaU, 0xf3U, 0xd8U, 0xf1U, 0xdeU, 0x56U, 0x40U, 0xc2U,
                0x32U, 0xf5U, 0xb1U, 0x69U, 0xb9U, 0xc9U, 0x11U, 0xe6U
            }    /* MAC */
        },
        {
            /* Chapter D.3, Example 12 */
            {
                0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
                0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
                0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
                0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U
            },   /* key */
            {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
                0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
                0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
                0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU,
                0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U,
                0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U
            },   /*msg */
            64U,                        /* msgLen */
            {
                0xe1U, 0x99U, 0x21U, 0x90U, 0x54U, 0x9fU, 0x6eU, 0xd5U,
                0x69U, 0x6aU, 0x2cU, 0x05U, 0x6cU, 0x31U, 0x54U, 0x10U
            }    /* MAC */
        }
    }
#endif
};
/*lint -restore */

static Esc_ERROR
EscTstCmacAes_InitParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstCmacAes_StartParams(void);

static Esc_ERROR
EscTstCmacAes_UpdateParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstCmacAes_FinishParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstCmacAes_Compliance(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstCmacAes_CompBlockWise(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstCmacAes_CompRandomBlocks(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTestCmacAes_CalcParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTestCmacAes_TruncationTest(
    Esc_UINT8 keyIndex );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacAes_InitParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscCmacAes_ContextT ctx;

    EscTst_PrintString( "EscCmacAes_Init parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][0].key, keySizes[keyIndex] );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacAes_Init( Esc_NULL_PTR, cmac_test[keyIndex][0].key, keySizes[keyIndex] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscCmacAes_Init( &ctx, Esc_NULL_PTR, keySizes[keyIndex] );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With invalid keyLength\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are a key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][0].key, (EscAes_MAX_KEY_BYTES + 8U) );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacAes_StartParams(void)
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "EscCmacAes_Start parameter test\n" );

    EscTst_PrintString( "With ctx==0\n" );
    returnCode = EscCmacAes_Start( Esc_NULL_PTR );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacAes_UpdateParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscCmacAes_ContextT ctx;

    EscTst_PrintString( "EscCmacAes_Update parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][0].key, keySizes[keyIndex] );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacAes_Update( &ctx, cmac_test[keyIndex][0].msg, cmac_test[keyIndex][0].msgLen );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacAes_Update( Esc_NULL_PTR, cmac_test[keyIndex][0].msg, cmac_test[keyIndex][0].msgLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With message==0 and messageLength > 0\n" );
        returnCode = EscCmacAes_Update( &ctx, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstCmacAes_FinishParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscCmacAes_ContextT ctx;
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];

    EscTst_PrintString( "EscCmacAes_Finish parameter test on testcase 1\n" );

    EscTst_PrintString( "With correct parameters\n" );
    returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][0].key, keySizes[keyIndex] );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacAes_Update( &ctx, cmac_test[keyIndex][0].msg, cmac_test[keyIndex][0].msgLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscCmacAes_Finish( &ctx, mac, (Esc_UINT8)EscAes_BLOCK_BYTES );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With ctx==0\n" );
        returnCode = EscCmacAes_Finish( Esc_NULL_PTR, mac, (Esc_UINT8)EscAes_BLOCK_BYTES );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With mac==0\n" );
        returnCode = EscCmacAes_Finish( &ctx, Esc_NULL_PTR, (Esc_UINT8)EscAes_BLOCK_BYTES );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With maclen = 100\n" );
        returnCode = EscCmacAes_Finish( &ctx, mac, 100U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With maclen = 0\n" );
        returnCode = EscCmacAes_Finish( &ctx, mac, 0U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstCmacAes_Compliance(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT8 calcMac[EscAes_BLOCK_BYTES];
    EscCmacAes_ContextT ctx;

    for (i = 0U; (i < EscCmacAes_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "AES-CMAC Compliance testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacAes_Init()\n" );
        returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][i].key, keySizes[keyIndex] );
        returnCode = EscTst_CheckResultSuccess( returnCode );

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Update()\n" );
            returnCode = EscCmacAes_Update( &ctx, cmac_test[keyIndex][i].msg, cmac_test[keyIndex][i].msgLen );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Finish()\n" );
            returnCode = EscCmacAes_Finish( &ctx, calcMac, (Esc_UINT8)EscAes_BLOCK_BYTES );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }

        /* Repeat with Start() */

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Start()\n" );
            returnCode = EscCmacAes_Start( &ctx );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Update()\n" );
            returnCode = EscCmacAes_Update( &ctx, cmac_test[keyIndex][i].msg, cmac_test[keyIndex][i].msgLen );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Finish()\n" );
            returnCode = EscCmacAes_Finish( &ctx, calcMac, (Esc_UINT8)EscAes_BLOCK_BYTES );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }

        /* One-shot function Calc() */

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Calc()\n" );

            returnCode = EscCmacAes_Calc(
                    cmac_test[keyIndex][i].key,
                    keySizes[keyIndex],
                    cmac_test[keyIndex][i].msg,
                    cmac_test[keyIndex][i].msgLen,
                    calcMac,
                    (Esc_UINT8) EscAes_BLOCK_BYTES );

            returnCode = EscTst_CheckResultSuccess(returnCode);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );
            EscTst_PrintArray( "Expected MAC", cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES );

            if ( EscTst_Memcmp( calcMac, cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES ) )
            {
                EscTst_PrintString( "Correct\n\n\n" );
                returnCode = Esc_NO_ERROR;
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
    } /* end of testcase loop */

    return returnCode;
}

static Esc_ERROR
EscTstCmacAes_CompBlockWise(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i, j;
    Esc_UINT32 blocksize;
    Esc_UINT8 calcMac[EscAes_BLOCK_BYTES];
    EscCmacAes_ContextT ctx;

    for (i = 0U; (i < EscCmacAes_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "AES-CMAC Compliance - Blockwise - testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacAes_Init()\n" );
        returnCode = EscCmacAes_Init( &ctx,  cmac_test[keyIndex][i].key, keySizes[keyIndex] );

        for (j = 0U; ( j < (cmac_test[keyIndex][i].msgLen) ) && (returnCode == Esc_NO_ERROR); j += EscAes_BLOCK_BYTES)
        {
            if ( (cmac_test[keyIndex][i].msgLen - j) < EscAes_BLOCK_BYTES )
            {
                blocksize = cmac_test[keyIndex][i].msgLen - j;
            }
            else
            {
                blocksize = EscAes_BLOCK_BYTES;
            }

            EscTst_PrintString( "EscCmacAes_Update()\n" );

            /* Also call update with zero length before and after the actual update */

            returnCode = EscCmacAes_Update( &ctx, Esc_NULL_PTR, 0U );

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacAes_Update( &ctx, &cmac_test[keyIndex][i].msg[j], blocksize );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacAes_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Finish()\n" );
            returnCode = EscCmacAes_Finish( &ctx, calcMac, (Esc_UINT8)EscAes_BLOCK_BYTES );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );
                EscTst_PrintArray( "Expected MAC", cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES );

                if ( EscTst_Memcmp( calcMac, cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstCmacAes_CompRandomBlocks(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i, j;
    Esc_UINT32 blocksize = 0U;
    Esc_UINT32 bytesleft = 0U;
    Esc_UINT8 blocksizes[5] = { 0U, 3U, 5U, 7U, 10U };
    Esc_UINT8 calcMac[EscAes_BLOCK_BYTES];
    EscCmacAes_ContextT ctx;


    for (i = 0U; (i < EscCmacAes_NUM_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "AES-CMAC Compliance - Random Blocksize - testvector #", (i + 1U) );

        EscTst_PrintString( "EscCmacAes_Init()\n" );
        returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][i].key, keySizes[keyIndex] );

        bytesleft = cmac_test[keyIndex][i].msgLen;
        j = 0U;

        while ( (bytesleft > 0U) && (returnCode == Esc_NO_ERROR) )
        {
            if (j < (sizeof(blocksizes) / sizeof(blocksizes[0])))
            {
                /*lint -e{644} blocksizes is initialized at declaration */
                if (bytesleft < blocksizes[j])
                {
                    blocksize = bytesleft;
                }
                else
                {
                    blocksize = blocksizes[j];
                }
            }
            else
            {
                blocksize = bytesleft;
            }

            EscTst_PrintString( "EscCmacAes_Update()\n" );
            returnCode = EscCmacAes_Update( &ctx, &cmac_test[keyIndex][i].msg[cmac_test[keyIndex][i].msgLen - bytesleft], blocksize );

            bytesleft -= blocksize;
            j++;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscCmacAes_Finish()\n" );
            returnCode = EscCmacAes_Finish( &ctx, calcMac, (Esc_UINT8)EscAes_BLOCK_BYTES );

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintArray( "Received MAC", calcMac, EscAes_BLOCK_BYTES );
                EscTst_PrintArray( "Expected MAC", cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES );

                if ( EscTst_Memcmp( calcMac, cmac_test[keyIndex][i].mac, EscAes_BLOCK_BYTES ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTestCmacAes_CalcParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    Esc_UINT8 calcMac[EscAes_BLOCK_BYTES];

    EscTst_PrintString( "EscCmacAes_Calc() parameter test\n" );

    EscTst_PrintString( "With message==0 and messageLength>0\n" );
    returnCode = EscCmacAes_Calc(
            cmac_test[keyIndex][0].key,
            keySizes[keyIndex],
            Esc_NULL_PTR,
            1U,
            calcMac,
            (Esc_UINT8)EscAes_BLOCK_BYTES );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "With key==0\n" );
        returnCode = EscCmacAes_Calc(
                Esc_NULL_PTR,
                keySizes[keyIndex],
                cmac_test[keyIndex][0].msg,
                cmac_test[keyIndex][0].msgLen,
                calcMac,
                (Esc_UINT8)EscAes_BLOCK_BYTES );

        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTestCmacAes_TruncationTest(
    Esc_UINT8 keyIndex )
{
    static const Esc_CHAR* msg = "Test With Truncation";
    static const Esc_UINT8 cmacLengths[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscAes_BLOCK_BYTES - 4U),
        (Esc_UINT8)(EscAes_BLOCK_BYTES - 3U),
        (Esc_UINT8)(EscAes_BLOCK_BYTES - 2U),
        (Esc_UINT8)(EscAes_BLOCK_BYTES - 1U)
    };

    Esc_UINT32 numCmacLengths = sizeof(cmacLengths) / sizeof(cmacLengths[0]);

    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscCmacAes_ContextT ctx;
    Esc_UINT8 macResult[EscAes_BLOCK_BYTES];
    Esc_UINT8 mac[EscAes_BLOCK_BYTES];
    Esc_UINT8 i, j;
    Esc_UINT32 msgLen = EscTst_Strlen( msg );
    Esc_UINT8 zeroArray[EscAes_BLOCK_BYTES];

    EscTst_PrintString( "CMAC-AES Truncation test\n" );

    for (i = 0U; (i < numCmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 cmacLength = cmacLengths[i];
        EscTst_PrintWord( "CMAC length = ", cmacLength);

        for ( j = 0U; j < EscAes_BLOCK_BYTES; j++)
        {
            zeroArray[j] = 0U;
            mac[j] = 0U;
        }

        returnCode = EscCmacAes_Calc(
                cmac_test[keyIndex][0].key,
                keySizes[keyIndex],
                (const Esc_UINT8*)msg,
                msgLen,
                macResult,
                (Esc_UINT8)EscAes_BLOCK_BYTES );

        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscCmacAes_Init( &ctx, cmac_test[keyIndex][0].key, keySizes[keyIndex] );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscCmacAes_Update( &ctx, (const Esc_UINT8*)msg, msgLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscCmacAes_Finish( &ctx, mac, cmacLength );
            }
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", mac, (Esc_UINT32)cmacLength );
            EscTst_PrintArray( "Received Result", macResult, (Esc_UINT32)cmacLength );
            if ( EscTst_Memcmp( mac, macResult, (Esc_UINT32)cmacLength ) )
            {
                if ( EscTst_Memcmp( &mac[cmacLength], &zeroArray[cmacLength], EscAes_BLOCK_BYTES - (Esc_UINT32)cmacLength ) )
                {
                    EscTst_PrintString( "Correct\n\n\n" );
                }
                else
                {
                    EscTst_PrintString( "FAILED truncation!!!\n\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscTstCmacAes_Perform(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 j;

    for (j = 0; j < EscTstCmacAes_NUM_KEYSIZES; ++j)
    {
        EscTst_PrintWord( "Aes KEY BITS", keySizes[j] * 8U );
        EscTst_PrintString( "*******************************************************\n" );
        returnCode = EscTstCmacAes_InitParams(j);

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_StartParams();
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_UpdateParams(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_FinishParams(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_Compliance(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_CompBlockWise(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstCmacAes_CompRandomBlocks(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTestCmacAes_CalcParams(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTestCmacAes_TruncationTest(j);
        }

        if (returnCode != Esc_NO_ERROR)
        {
            break;
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
