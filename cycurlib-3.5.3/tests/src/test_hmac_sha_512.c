/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief HMAC-SHA-512 Selftest (384 and 512 bit), testcases from RFC 4231


   $Rev: 2711 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_hmac_sha_512.h"
#include "selftest.h"
#include "hmac_sha_512.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define NUMBER_OF_HMAC_SHA_2_TESTCASES 5U

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

typedef struct
{
    Esc_UINT8 len;
    Esc_UINT8 message[136];
} hmac_sha2_test_key;

static const hmac_sha2_test_key hmac_sha2_test_keys[NUMBER_OF_HMAC_SHA_2_TESTCASES] =
{
    {
        20U,
        {
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
            0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        4U,
        {
            0x4aU, 0x65U, 0x66U, 0x65U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        20U,
        {
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
            0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        131U,
        {
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    },
    {
        131U,
        {
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU, 0xaaU,
            0xaaU, 0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        }
    }
};

/* HMAC SHA-512 message */
static const Esc_CHAR* const hmac_msg[NUMBER_OF_HMAC_SHA_2_TESTCASES] =
{
    "Hi There",
    "what do ya want for nothing?",
    "Test With Truncation",
    "Test Using Larger Than Block-Size Key - Hash Key First",
    "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
};

/* HMAC SHA-2-384 expected values */
static const Esc_UINT8 hmac384_res[NUMBER_OF_HMAC_SHA_2_TESTCASES][EscSha384_DIGEST_LEN] =
{
    {
        0xafU, 0xd0U, 0x39U, 0x44U, 0xd8U, 0x48U, 0x95U, 0x62U, 0x6bU, 0x08U, 0x25U, 0xf4U, 0xabU, 0x46U, 0x90U, 0x7fU,
        0x15U, 0xf9U, 0xdaU, 0xdbU, 0xe4U, 0x10U, 0x1eU, 0xc6U, 0x82U, 0xaaU, 0x03U, 0x4cU, 0x7cU, 0xebU, 0xc5U, 0x9cU,
        0xfaU, 0xeaU, 0x9eU, 0xa9U, 0x07U, 0x6eU, 0xdeU, 0x7fU, 0x4aU, 0xf1U, 0x52U, 0xe8U, 0xb2U, 0xfaU, 0x9cU, 0xb6U
    },
    {
        0xafU, 0x45U, 0xd2U, 0xe3U, 0x76U, 0x48U, 0x40U, 0x31U, 0x61U, 0x7fU, 0x78U, 0xd2U, 0xb5U, 0x8aU, 0x6bU, 0x1bU,
        0x9cU, 0x7eU, 0xf4U, 0x64U, 0xf5U, 0xa0U, 0x1bU, 0x47U, 0xe4U, 0x2eU, 0xc3U, 0x73U, 0x63U, 0x22U, 0x44U, 0x5eU,
        0x8eU, 0x22U, 0x40U, 0xcaU, 0x5eU, 0x69U, 0xe2U, 0xc7U, 0x8bU, 0x32U, 0x39U, 0xecU, 0xfaU, 0xb2U, 0x16U, 0x49U
    },
    {
        0x3aU, 0xbfU, 0x34U, 0xc3U, 0x50U, 0x3bU, 0x2aU, 0x23U, 0xa4U, 0x6eU, 0xfcU, 0x61U, 0x9bU, 0xaeU, 0xf8U, 0x97U,
        0xf4U, 0xc8U, 0xe4U, 0x2cU, 0x93U, 0x4cU, 0xe5U, 0x5cU, 0xcbU, 0xaeU, 0x97U, 0x40U, 0xfcU, 0xbcU, 0x1aU, 0xf4U,
        0xcaU, 0x62U, 0x26U, 0x9eU, 0x2aU, 0x37U, 0xcdU, 0x88U, 0xbaU, 0x92U, 0x63U, 0x41U, 0xefU, 0xe4U, 0xaeU, 0xeaU
    },
    {
        0x4eU, 0xceU, 0x08U, 0x44U, 0x85U, 0x81U, 0x3eU, 0x90U, 0x88U, 0xd2U, 0xc6U, 0x3aU, 0x04U, 0x1bU, 0xc5U, 0xb4U,
        0x4fU, 0x9eU, 0xf1U, 0x01U, 0x2aU, 0x2bU, 0x58U, 0x8fU, 0x3cU, 0xd1U, 0x1fU, 0x05U, 0x03U, 0x3aU, 0xc4U, 0xc6U,
        0x0cU, 0x2eU, 0xf6U, 0xabU, 0x40U, 0x30U, 0xfeU, 0x82U, 0x96U, 0x24U, 0x8dU, 0xf1U, 0x63U, 0xf4U, 0x49U, 0x52U
    },
    {
        0x66U, 0x17U, 0x17U, 0x8eU, 0x94U, 0x1fU, 0x02U, 0x0dU, 0x35U, 0x1eU, 0x2fU, 0x25U, 0x4eU, 0x8fU, 0xd3U, 0x2cU,
        0x60U, 0x24U, 0x20U, 0xfeU, 0xb0U, 0xb8U, 0xfbU, 0x9aU, 0xdcU, 0xceU, 0xbbU, 0x82U, 0x46U, 0x1eU, 0x99U, 0xc5U,
        0xa6U, 0x78U, 0xccU, 0x31U, 0xe7U, 0x99U, 0x17U, 0x6dU, 0x38U, 0x60U, 0xe6U, 0x11U, 0x0cU, 0x46U, 0x52U, 0x3eU
    }
};

/* HMAC SHA-2-512 expected values */
static const Esc_UINT8 hmac512_res[NUMBER_OF_HMAC_SHA_2_TESTCASES][EscSha512_DIGEST_LEN] =
{
    {
        0x87U, 0xaaU, 0x7cU, 0xdeU, 0xa5U, 0xefU, 0x61U, 0x9dU, 0x4fU, 0xf0U, 0xb4U, 0x24U, 0x1aU, 0x1dU, 0x6cU, 0xb0U,
        0x23U, 0x79U, 0xf4U, 0xe2U, 0xceU, 0x4eU, 0xc2U, 0x78U, 0x7aU, 0xd0U, 0xb3U, 0x05U, 0x45U, 0xe1U, 0x7cU, 0xdeU,
        0xdaU, 0xa8U, 0x33U, 0xb7U, 0xd6U, 0xb8U, 0xa7U, 0x02U, 0x03U, 0x8bU, 0x27U, 0x4eU, 0xaeU, 0xa3U, 0xf4U, 0xe4U,
        0xbeU, 0x9dU, 0x91U, 0x4eU, 0xebU, 0x61U, 0xf1U, 0x70U, 0x2eU, 0x69U, 0x6cU, 0x20U, 0x3aU, 0x12U, 0x68U, 0x54U
    },
    {
        0x16U, 0x4bU, 0x7aU, 0x7bU, 0xfcU, 0xf8U, 0x19U, 0xe2U, 0xe3U, 0x95U, 0xfbU, 0xe7U, 0x3bU, 0x56U, 0xe0U, 0xa3U,
        0x87U, 0xbdU, 0x64U, 0x22U, 0x2eU, 0x83U, 0x1fU, 0xd6U, 0x10U, 0x27U, 0x0cU, 0xd7U, 0xeaU, 0x25U, 0x05U, 0x54U,
        0x97U, 0x58U, 0xbfU, 0x75U, 0xc0U, 0x5aU, 0x99U, 0x4aU, 0x6dU, 0x03U, 0x4fU, 0x65U, 0xf8U, 0xf0U, 0xe6U, 0xfdU,
        0xcaU, 0xeaU, 0xb1U, 0xa3U, 0x4dU, 0x4aU, 0x6bU, 0x4bU, 0x63U, 0x6eU, 0x07U, 0x0aU, 0x38U, 0xbcU, 0xe7U, 0x37U
    },
    {
        0x41U, 0x5fU, 0xadU, 0x62U, 0x71U, 0x58U, 0x0aU, 0x53U, 0x1dU, 0x41U, 0x79U, 0xbcU, 0x89U, 0x1dU, 0x87U, 0xa6U,
        0x50U, 0x18U, 0x87U, 0x07U, 0x92U, 0x2aU, 0x4fU, 0xbbU, 0x36U, 0x66U, 0x3aU, 0x1eU, 0xb1U, 0x6dU, 0xa0U, 0x08U,
        0x71U, 0x1cU, 0x5bU, 0x50U, 0xddU, 0xd0U, 0xfcU, 0x23U, 0x50U, 0x84U, 0xebU, 0x9dU, 0x33U, 0x64U, 0xa1U, 0x45U,
        0x4fU, 0xb2U, 0xefU, 0x67U, 0xcdU, 0x1dU, 0x29U, 0xfeU, 0x67U, 0x73U, 0x06U, 0x8eU, 0xa2U, 0x66U, 0xe9U, 0x6bU
    },
    {
        0x80U, 0xb2U, 0x42U, 0x63U, 0xc7U, 0xc1U, 0xa3U, 0xebU, 0xb7U, 0x14U, 0x93U, 0xc1U, 0xddU, 0x7bU, 0xe8U, 0xb4U,
        0x9bU, 0x46U, 0xd1U, 0xf4U, 0x1bU, 0x4aU, 0xeeU, 0xc1U, 0x12U, 0x1bU, 0x01U, 0x37U, 0x83U, 0xf8U, 0xf3U, 0x52U,
        0x6bU, 0x56U, 0xd0U, 0x37U, 0xe0U, 0x5fU, 0x25U, 0x98U, 0xbdU, 0x0fU, 0xd2U, 0x21U, 0x5dU, 0x6aU, 0x1eU, 0x52U,
        0x95U, 0xe6U, 0x4fU, 0x73U, 0xf6U, 0x3fU, 0x0aU, 0xecU, 0x8bU, 0x91U, 0x5aU, 0x98U, 0x5dU, 0x78U, 0x65U, 0x98U
    },
    {
        0xe3U, 0x7bU, 0x6aU, 0x77U, 0x5dU, 0xc8U, 0x7dU, 0xbaU, 0xa4U, 0xdfU, 0xa9U, 0xf9U, 0x6eU, 0x5eU, 0x3fU, 0xfdU,
        0xdeU, 0xbdU, 0x71U, 0xf8U, 0x86U, 0x72U, 0x89U, 0x86U, 0x5dU, 0xf5U, 0xa3U, 0x2dU, 0x20U, 0xcdU, 0xc9U, 0x44U,
        0xb6U, 0x02U, 0x2cU, 0xacU, 0x3cU, 0x49U, 0x82U, 0xb1U, 0x0dU, 0x5eU, 0xebU, 0x55U, 0xc3U, 0xe4U, 0xdeU, 0x15U,
        0x13U, 0x46U, 0x76U, 0xfbU, 0x6dU, 0xe0U, 0x44U, 0x60U, 0x65U, 0xc9U, 0x74U, 0x40U, 0xfaU, 0x8cU, 0x6aU, 0x58U
    }
};

/* SHA-512 */
static Esc_ERROR
EscTstHmacSha512_Compliance(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstHmacSha512_ComplianceChunkwise(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstHmacSha512_StepsParams(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstHmacSha512_FullParams(
    Esc_BOOL isSha384 );

static Esc_ERROR
EscTstHmacSha512_Truncation(
    Esc_BOOL isSha384 );
/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/


/* SHA-512 */
/**
\return Esc_NO_ERROR if everything works fine
*/
static Esc_ERROR
EscTstHmacSha512_Compliance(
    Esc_BOOL isSha384 )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_BOOL cmpResult;
    Esc_UINT8 digestLength;

    EscTst_PrintString( "\nHMAC-SHA-2 Compliance test\n" );
    if (isSha384)
    {
        EscTst_PrintString( "SHA-2 Bitlength = 384\n" );
        digestLength = EscSha384_DIGEST_LEN;
    }
    else
    {
        EscTst_PrintString( "SHA-2 Bitlength = 512\n" );
        digestLength = EscSha512_DIGEST_LEN;
    }

    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_2_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 sha_hash[EscSha512_DIGEST_LEN];      /* hash value */

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len );

        returnCode = EscHmacSha512_Calc(
                isSha384,
                hmac_sha2_test_keys[i].message,
                (Esc_UINT32)hmac_sha2_test_keys[i].len,
                (const Esc_UINT8*)hmac_msg[i],
                EscTst_Strlen( hmac_msg[i] ),
                sha_hash,
                digestLength );

        if (returnCode == Esc_NO_ERROR)
        {
            if (isSha384)
            {
                EscTst_PrintArray( "Expected Result", hmac384_res[i], EscSha384_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha384_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac384_res[i], EscSha384_DIGEST_LEN );
            }
            else
            {
                EscTst_PrintArray( "Expected Result", hmac512_res[i], EscSha512_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha512_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac512_res[i], EscSha512_DIGEST_LEN );
            }

            if (cmpResult)
            {
                EscTst_PrintString( "Correct\n\n\n" );
            }
            else
            {
                EscTst_PrintString( "FAILED!!!\n\n\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "FAILED!!!\n\n\n" );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha512_ComplianceChunkwise(
    Esc_BOOL isSha384 )
{
    Esc_UINT8 i;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 digestLength;
    Esc_BOOL cmpResult;

    EscTst_PrintString( "\nHMAC-SHA-2 Compliance test (chunk-wise)\n" );
    if (isSha384)
    {
        EscTst_PrintString( "SHA-2 Bitlength = 384\n" );
        digestLength = EscSha384_DIGEST_LEN;
    }
    else
    {
        EscTst_PrintString( "SHA-2 Bitlength = 512\n" );
        digestLength = EscSha512_DIGEST_LEN;
    }

    for (i = 0U; (i < NUMBER_OF_HMAC_SHA_2_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT32 msgLen;
        const Esc_UINT8 *message;
        Esc_UINT8 sha_hash[EscHmacSha512_MAX_MAC_LENGTH];      /* hash value */
        EscHmacSha512_ContextT ctx;

        EscTst_PrintString( "Message: \"" );
        EscTst_PrintString( hmac_msg[i] );
        EscTst_PrintString( "\"\n" );
        EscTst_PrintArray( "Key", hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len );

        msgLen = EscTst_Strlen(hmac_msg[i]);
        message = (const Esc_UINT8 *) hmac_msg[i];

        /* Init context */
        returnCode = EscHmacSha512_Init(isSha384, &ctx, hmac_sha2_test_keys[i].message, (Esc_UINT32)hmac_sha2_test_keys[i].len);

        /* Update in small chunk of increasing size */
        if (returnCode == Esc_NO_ERROR)
        {
            Esc_UINT32 remainingLen = msgLen;
            Esc_UINT32 chunkLen = 1U;
            Esc_UINT32 offset = 0U;

            while ( (returnCode == Esc_NO_ERROR) && (remainingLen > 0U) )
            {
                if (chunkLen > remainingLen)
                {
                    chunkLen = remainingLen;
                }

                /* Also call with zero-length updates in between */
                returnCode = EscHmacSha512_Update( &ctx, Esc_NULL_PTR, 0U );

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscHmacSha512_Update( &ctx, &message[offset], chunkLen );
                }

                remainingLen -= chunkLen;
                offset += chunkLen;
                chunkLen += 3U;
            }

            /* Final zero-length update before finish */
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha512_Update( &ctx, Esc_NULL_PTR, 0U );
            }
        }

        /* Finish MAC calculation */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha512_Finish(&ctx, sha_hash, digestLength);
        }

        /* Compare results */
        if (returnCode == Esc_NO_ERROR)
        {
            if (isSha384)
            {
                EscTst_PrintArray( "Expected Result", hmac384_res[i], EscSha384_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha384_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac384_res[i], EscSha384_DIGEST_LEN );
            }
            else
            {
                EscTst_PrintArray( "Expected Result", hmac512_res[i], EscSha512_DIGEST_LEN );
                EscTst_PrintArray( "Received Result", sha_hash, EscSha512_DIGEST_LEN );
                cmpResult = EscTst_Memcmp( sha_hash, hmac512_res[i], EscSha512_DIGEST_LEN );
            }

            if (cmpResult)
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

    return returnCode;
}


static Esc_ERROR
EscTstHmacSha512_StepsParams(
    Esc_BOOL isSha384 )
{
    Esc_ERROR returnCode;
    EscHmacSha512_ContextT ctx;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac[EscSha512_DIGEST_LEN];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;
    Esc_UINT8 digestLength;

    key = (const Esc_UINT8*)hmac_sha2_test_keys[1].message;
    keyLen = hmac_sha2_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    if (isSha384)
    {
        digestLength = EscSha384_DIGEST_LEN;
    }
    else
    {
        digestLength = EscSha512_DIGEST_LEN;
    }

    EscTst_PrintString( "EscHmacSha512_Init() with ctx==0\n" );
    returnCode = EscHmacSha512_Init( isSha384, Esc_NULL_PTR, key, keyLen );

    if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Init() with hmac_key==0\n" );
        returnCode = EscHmacSha512_Init( isSha384, &ctx, Esc_NULL_PTR, keyLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha512_Init() with key_length==0\n" );
            returnCode = EscHmacSha512_Init( isSha384, &ctx, key, 0U );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Update() with ctx==0\n" );
        returnCode = EscHmacSha512_Update( Esc_NULL_PTR, msg, msgLen );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha512_Update() with chunk_data==0\n" );
            returnCode = EscHmacSha512_Update( &ctx, Esc_NULL_PTR, msgLen );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscHmacSha512_Init( isSha384, &ctx, key, keyLen);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Finish() with ctx==0\n" );
        returnCode = EscHmacSha512_Finish( Esc_NULL_PTR, hmac, digestLength );

        if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
        {
            EscTst_PrintString( "EscHmacSha512_Finish() with hmac_hash==0\n" );
            returnCode = EscHmacSha512_Finish( &ctx, Esc_NULL_PTR, digestLength );
            if (EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR ) == Esc_NO_ERROR)
            {
                EscTst_PrintString( "EscHmacSha512_Finish() with hmac_hashLength==0\n" );
                returnCode = EscHmacSha512_Finish( &ctx, hmac, 0U );
                if (EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER ) == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "EscHmacSha512_Finish() with hmac_hashLength too long\n" );
                    returnCode = EscHmacSha512_Finish( &ctx, hmac, digestLength+1U );
                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
                }
            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha512_FullParams(
    Esc_BOOL isSha384 )
{
    Esc_ERROR returnCode;
    const Esc_UINT8* msg;
    Esc_UINT32 msgLen;
    Esc_UINT8 hmac[EscSha512_DIGEST_LEN];
    Esc_UINT32 keyLen;
    const Esc_UINT8* key;

    key = (const Esc_UINT8*)hmac_sha2_test_keys[1].message;
    keyLen = hmac_sha2_test_keys[1].len;
    msg = (const Esc_UINT8*)hmac_msg[1];
    msgLen = EscTst_Strlen( hmac_msg[1] );

    EscTst_PrintString( "EscHmacSha512_Calc() with all parameters\n" );
    returnCode = EscHmacSha512_Calc( isSha384, key, keyLen, msg, msgLen, hmac, EscSha384_DIGEST_LEN );
    returnCode = EscTst_CheckResultSuccess( returnCode );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Calc() with key==0\n" );
        returnCode = EscHmacSha512_Calc( isSha384, Esc_NULL_PTR, keyLen, msg, msgLen, hmac, EscSha384_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Calc() with message==0\n" );
        returnCode = EscHmacSha512_Calc( isSha384, key, keyLen, Esc_NULL_PTR, msgLen, hmac, EscSha384_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Calc() with hmac_hash==0\n" );
        returnCode = EscHmacSha512_Calc( isSha384, key, keyLen, msg, msgLen, Esc_NULL_PTR, EscSha384_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscHmacSha512_Calc() with key_length==0\n" );
        returnCode = EscHmacSha512_Calc( isSha384, key, 0U, msg, msgLen, hmac, EscSha384_DIGEST_LEN );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}

static Esc_ERROR
EscTstHmacSha512_Truncation(
    Esc_BOOL isSha384 )
{
    static const Esc_UINT8 key[20] =
    {
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU, 0x0cU,
        0x0cU, 0x0cU, 0x0cU, 0x0cU
    };
    static const Esc_CHAR* msg = "Test With Truncation";

    static const Esc_UINT8 hmacLengthsSha384[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacSha384_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacSha384_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacSha384_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacSha384_MAX_MAC_LENGTH - 1U)
    };

    static const Esc_UINT8 hmacLengthsSha512[] =
    {
        /* Smallest possible lengths */
        1U, 2U, 3U, 4U,

        /* Highest possible lengths */
        (Esc_UINT8)(EscHmacSha512_MAX_MAC_LENGTH - 4U),
        (Esc_UINT8)(EscHmacSha512_MAX_MAC_LENGTH - 3U),
        (Esc_UINT8)(EscHmacSha512_MAX_MAC_LENGTH - 2U),
        (Esc_UINT8)(EscHmacSha512_MAX_MAC_LENGTH - 1U)
    };

    Esc_UINT32 numHmacLengths;
    const Esc_UINT8 *hmacLengths;
    Esc_UINT8 maxHmacLength;

    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscHmacSha512_ContextT ctx;
    Esc_UINT32 msgLen = EscTst_Strlen( msg );
    Esc_UINT8 hmac[EscHmacSha512_MAX_MAC_LENGTH];
    Esc_UINT8 hmac512_resultTruncation[EscHmacSha512_MAX_MAC_LENGTH];
    Esc_UINT32 keyLen = 20U;
    Esc_UINT8 i, j;
    Esc_UINT8 zeroArray[EscHmacSha512_MAX_MAC_LENGTH];

    if (isSha384)
    {
        hmacLengths = hmacLengthsSha384;
        numHmacLengths = sizeof(hmacLengthsSha384) / sizeof(hmacLengthsSha384[0]);
        maxHmacLength = EscHmacSha384_MAX_MAC_LENGTH;
        EscTst_PrintString( "HMAC-SHA384 Truncation test\n" );
    }
    else
    {
        hmacLengths = hmacLengthsSha512;
        numHmacLengths = sizeof(hmacLengthsSha512) / sizeof(hmacLengthsSha512[0]);
        maxHmacLength = EscHmacSha512_MAX_MAC_LENGTH;
        EscTst_PrintString( "HMAC-SHA512 Truncation test\n" );
    }

    for (i = 0U; (i < numHmacLengths) && (returnCode == Esc_NO_ERROR); i++)
    {
        Esc_UINT8 hmacLength = hmacLengths[i];

        EscTst_PrintWord( "HMAC length = ", hmacLength);

        for (j = 0U; j < EscHmacSha512_MAX_MAC_LENGTH; j++)
        {
            zeroArray[j] = 0U;
            hmac[j] = 0U;
        }

        returnCode = EscHmacSha512_Calc(isSha384, key, keyLen, (const Esc_UINT8*)msg, msgLen, hmac512_resultTruncation, maxHmacLength);

        if ( returnCode == Esc_NO_ERROR )
        {
            returnCode = EscHmacSha512_Init( isSha384, &ctx, key, keyLen );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscHmacSha512_Update( &ctx, (const Esc_UINT8*)msg, msgLen );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscHmacSha512_Finish( &ctx, hmac, hmacLength );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintArray( "Expected Result", hmac512_resultTruncation, (Esc_UINT32)hmacLength );
            EscTst_PrintArray( "Received Result", hmac, (Esc_UINT32)hmacLength );
            if ( EscTst_Memcmp( hmac, hmac512_resultTruncation, (Esc_UINT32)hmacLength ) )
            {
                if ( EscTst_Memcmp( &hmac[hmacLength], &zeroArray[hmacLength], (Esc_UINT32)maxHmacLength - (Esc_UINT32)hmacLength ) )
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
EscTstHmacSha512_Perform(
    void )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "Testing HMAC-SHA-384" );

    returnCode = EscTstHmacSha512_Compliance(TRUE);

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_ComplianceChunkwise(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_StepsParams(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_FullParams(TRUE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_Truncation(TRUE);
    }


    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Testing HMAC-SHA-512" );
        returnCode = EscTstHmacSha512_Compliance(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_ComplianceChunkwise(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_StepsParams(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_FullParams(FALSE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstHmacSha512_Truncation(FALSE);
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
