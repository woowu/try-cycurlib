/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief EdDSA Selftest

   \details     Performs the eddsa test with all given test vectors from RFC 8032.
                Currently ed25519, ed25519ph and ed25519ctx are supported.

   $Rev: 0001 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "test_eddsa.h"
#include "selftest.h"
#include "sha_512.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/
/** Test vector for EdDsa */
typedef struct
{
    /** Curve ID */
    EscEd_CurveId curveId;
    /** Digest Type */
    Esc_UINT8 digestType;
    /** PH variant */
    Esc_BOOL preHashed;
    /** Length of private/public keys */
    Esc_UINT32 keyLen;
    /** Private key */
    const Esc_UINT8 privKey[32U];
    /** Public key */
    const Esc_UINT8 pubKey[32U];
    /** Input message value */
    const Esc_UINT8 *msg;
    /** Message length in bytes */
    Esc_UINT32 msgLen;
    /** EdDsa signature value */
    const Esc_UINT8 signature[64U];
    /** Context value */
    const Esc_UINT8 *context;
    /** Context length in bytes */
    Esc_UINT8 contextLen;
} s_eddsa_tst_vector;

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/* ed25519 tests */
static const Esc_UINT8 msg_TEST2[] =
{
    0x72U
};


static const Esc_UINT8 msg_TEST3[] =
{
    0xafU, 0x82U
};

static const Esc_UINT8 msg_TEST1024[] =
{
    0x08U, 0xb8U, 0xb2U, 0xb7U, 0x33U, 0x42U, 0x42U, 0x43U, 
    0x76U, 0x0fU, 0xe4U, 0x26U, 0xa4U, 0xb5U, 0x49U, 0x08U, 
    0x63U, 0x21U, 0x10U, 0xa6U, 0x6cU, 0x2fU, 0x65U, 0x91U, 
    0xeaU, 0xbdU, 0x33U, 0x45U, 0xe3U, 0xe4U, 0xebU, 0x98U, 
    0xfaU, 0x6eU, 0x26U, 0x4bU, 0xf0U, 0x9eU, 0xfeU, 0x12U, 
    0xeeU, 0x50U, 0xf8U, 0xf5U, 0x4eU, 0x9fU, 0x77U, 0xb1U, 
    0xe3U, 0x55U, 0xf6U, 0xc5U, 0x05U, 0x44U, 0xe2U, 0x3fU, 
    0xb1U, 0x43U, 0x3dU, 0xdfU, 0x73U, 0xbeU, 0x84U, 0xd8U, 
    0x79U, 0xdeU, 0x7cU, 0x00U, 0x46U, 0xdcU, 0x49U, 0x96U, 
    0xd9U, 0xe7U, 0x73U, 0xf4U, 0xbcU, 0x9eU, 0xfeU, 0x57U, 
    0x38U, 0x82U, 0x9aU, 0xdbU, 0x26U, 0xc8U, 0x1bU, 0x37U, 
    0xc9U, 0x3aU, 0x1bU, 0x27U, 0x0bU, 0x20U, 0x32U, 0x9dU, 
    0x65U, 0x86U, 0x75U, 0xfcU, 0x6eU, 0xa5U, 0x34U, 0xe0U, 
    0x81U, 0x0aU, 0x44U, 0x32U, 0x82U, 0x6bU, 0xf5U, 0x8cU, 
    0x94U, 0x1eU, 0xfbU, 0x65U, 0xd5U, 0x7aU, 0x33U, 0x8bU, 
    0xbdU, 0x2eU, 0x26U, 0x64U, 0x0fU, 0x89U, 0xffU, 0xbcU, 
    0x1aU, 0x85U, 0x8eU, 0xfcU, 0xb8U, 0x55U, 0x0eU, 0xe3U, 
    0xa5U, 0xe1U, 0x99U, 0x8bU, 0xd1U, 0x77U, 0xe9U, 0x3aU, 
    0x73U, 0x63U, 0xc3U, 0x44U, 0xfeU, 0x6bU, 0x19U, 0x9eU, 
    0xe5U, 0xd0U, 0x2eU, 0x82U, 0xd5U, 0x22U, 0xc4U, 0xfeU, 
    0xbaU, 0x15U, 0x45U, 0x2fU, 0x80U, 0x28U, 0x8aU, 0x82U, 
    0x1aU, 0x57U, 0x91U, 0x16U, 0xecU, 0x6dU, 0xadU, 0x2bU, 
    0x3bU, 0x31U, 0x0dU, 0xa9U, 0x03U, 0x40U, 0x1aU, 0xa6U, 
    0x21U, 0x00U, 0xabU, 0x5dU, 0x1aU, 0x36U, 0x55U, 0x3eU, 
    0x06U, 0x20U, 0x3bU, 0x33U, 0x89U, 0x0cU, 0xc9U, 0xb8U, 
    0x32U, 0xf7U, 0x9eU, 0xf8U, 0x05U, 0x60U, 0xccU, 0xb9U, 
    0xa3U, 0x9cU, 0xe7U, 0x67U, 0x96U, 0x7eU, 0xd6U, 0x28U, 
    0xc6U, 0xadU, 0x57U, 0x3cU, 0xb1U, 0x16U, 0xdbU, 0xefU, 
    0xefU, 0xd7U, 0x54U, 0x99U, 0xdaU, 0x96U, 0xbdU, 0x68U, 
    0xa8U, 0xa9U, 0x7bU, 0x92U, 0x8aU, 0x8bU, 0xbcU, 0x10U, 
    0x3bU, 0x66U, 0x21U, 0xfcU, 0xdeU, 0x2bU, 0xecU, 0xa1U, 
    0x23U, 0x1dU, 0x20U, 0x6bU, 0xe6U, 0xcdU, 0x9eU, 0xc7U, 
    0xafU, 0xf6U, 0xf6U, 0xc9U, 0x4fU, 0xcdU, 0x72U, 0x04U, 
    0xedU, 0x34U, 0x55U, 0xc6U, 0x8cU, 0x83U, 0xf4U, 0xa4U, 
    0x1dU, 0xa4U, 0xafU, 0x2bU, 0x74U, 0xefU, 0x5cU, 0x53U, 
    0xf1U, 0xd8U, 0xacU, 0x70U, 0xbdU, 0xcbU, 0x7eU, 0xd1U, 
    0x85U, 0xceU, 0x81U, 0xbdU, 0x84U, 0x35U, 0x9dU, 0x44U, 
    0x25U, 0x4dU, 0x95U, 0x62U, 0x9eU, 0x98U, 0x55U, 0xa9U, 
    0x4aU, 0x7cU, 0x19U, 0x58U, 0xd1U, 0xf8U, 0xadU, 0xa5U, 
    0xd0U, 0x53U, 0x2eU, 0xd8U, 0xa5U, 0xaaU, 0x3fU, 0xb2U, 
    0xd1U, 0x7bU, 0xa7U, 0x0eU, 0xb6U, 0x24U, 0x8eU, 0x59U, 
    0x4eU, 0x1aU, 0x22U, 0x97U, 0xacU, 0xbbU, 0xb3U, 0x9dU, 
    0x50U, 0x2fU, 0x1aU, 0x8cU, 0x6eU, 0xb6U, 0xf1U, 0xceU, 
    0x22U, 0xb3U, 0xdeU, 0x1aU, 0x1fU, 0x40U, 0xccU, 0x24U, 
    0x55U, 0x41U, 0x19U, 0xa8U, 0x31U, 0xa9U, 0xaaU, 0xd6U, 
    0x07U, 0x9cU, 0xadU, 0x88U, 0x42U, 0x5dU, 0xe6U, 0xbdU, 
    0xe1U, 0xa9U, 0x18U, 0x7eU, 0xbbU, 0x60U, 0x92U, 0xcfU, 
    0x67U, 0xbfU, 0x2bU, 0x13U, 0xfdU, 0x65U, 0xf2U, 0x70U, 
    0x88U, 0xd7U, 0x8bU, 0x7eU, 0x88U, 0x3cU, 0x87U, 0x59U, 
    0xd2U, 0xc4U, 0xf5U, 0xc6U, 0x5aU, 0xdbU, 0x75U, 0x53U, 
    0x87U, 0x8aU, 0xd5U, 0x75U, 0xf9U, 0xfaU, 0xd8U, 0x78U, 
    0xe8U, 0x0aU, 0x0cU, 0x9bU, 0xa6U, 0x3bU, 0xcbU, 0xccU, 
    0x27U, 0x32U, 0xe6U, 0x94U, 0x85U, 0xbbU, 0xc9U, 0xc9U, 
    0x0bU, 0xfbU, 0xd6U, 0x24U, 0x81U, 0xd9U, 0x08U, 0x9bU, 
    0xecU, 0xcfU, 0x80U, 0xcfU, 0xe2U, 0xdfU, 0x16U, 0xa2U, 
    0xcfU, 0x65U, 0xbdU, 0x92U, 0xddU, 0x59U, 0x7bU, 0x07U, 
    0x07U, 0xe0U, 0x91U, 0x7aU, 0xf4U, 0x8bU, 0xbbU, 0x75U, 
    0xfeU, 0xd4U, 0x13U, 0xd2U, 0x38U, 0xf5U, 0x55U, 0x5aU, 
    0x7aU, 0x56U, 0x9dU, 0x80U, 0xc3U, 0x41U, 0x4aU, 0x8dU, 
    0x08U, 0x59U, 0xdcU, 0x65U, 0xa4U, 0x61U, 0x28U, 0xbaU, 
    0xb2U, 0x7aU, 0xf8U, 0x7aU, 0x71U, 0x31U, 0x4fU, 0x31U, 
    0x8cU, 0x78U, 0x2bU, 0x23U, 0xebU, 0xfeU, 0x80U, 0x8bU, 
    0x82U, 0xb0U, 0xceU, 0x26U, 0x40U, 0x1dU, 0x2eU, 0x22U, 
    0xf0U, 0x4dU, 0x83U, 0xd1U, 0x25U, 0x5dU, 0xc5U, 0x1aU, 
    0xddU, 0xd3U, 0xb7U, 0x5aU, 0x2bU, 0x1aU, 0xe0U, 0x78U, 
    0x45U, 0x04U, 0xdfU, 0x54U, 0x3aU, 0xf8U, 0x96U, 0x9bU, 
    0xe3U, 0xeaU, 0x70U, 0x82U, 0xffU, 0x7fU, 0xc9U, 0x88U, 
    0x8cU, 0x14U, 0x4dU, 0xa2U, 0xafU, 0x58U, 0x42U, 0x9eU, 
    0xc9U, 0x60U, 0x31U, 0xdbU, 0xcaU, 0xd3U, 0xdaU, 0xd9U, 
    0xafU, 0x0dU, 0xcbU, 0xaaU, 0xafU, 0x26U, 0x8cU, 0xb8U, 
    0xfcU, 0xffU, 0xeaU, 0xd9U, 0x4fU, 0x3cU, 0x7cU, 0xa4U, 
    0x95U, 0xe0U, 0x56U, 0xa9U, 0xb4U, 0x7aU, 0xcdU, 0xb7U, 
    0x51U, 0xfbU, 0x73U, 0xe6U, 0x66U, 0xc6U, 0xc6U, 0x55U, 
    0xadU, 0xe8U, 0x29U, 0x72U, 0x97U, 0xd0U, 0x7aU, 0xd1U, 
    0xbaU, 0x5eU, 0x43U, 0xf1U, 0xbcU, 0xa3U, 0x23U, 0x01U, 
    0x65U, 0x13U, 0x39U, 0xe2U, 0x29U, 0x04U, 0xccU, 0x8cU, 
    0x42U, 0xf5U, 0x8cU, 0x30U, 0xc0U, 0x4aU, 0xafU, 0xdbU, 
    0x03U, 0x8dU, 0xdaU, 0x08U, 0x47U, 0xddU, 0x98U, 0x8dU, 
    0xcdU, 0xa6U, 0xf3U, 0xbfU, 0xd1U, 0x5cU, 0x4bU, 0x4cU, 
    0x45U, 0x25U, 0x00U, 0x4aU, 0xa0U, 0x6eU, 0xefU, 0xf8U, 
    0xcaU, 0x61U, 0x78U, 0x3aU, 0xacU, 0xecU, 0x57U, 0xfbU, 
    0x3dU, 0x1fU, 0x92U, 0xb0U, 0xfeU, 0x2fU, 0xd1U, 0xa8U, 
    0x5fU, 0x67U, 0x24U, 0x51U, 0x7bU, 0x65U, 0xe6U, 0x14U, 
    0xadU, 0x68U, 0x08U, 0xd6U, 0xf6U, 0xeeU, 0x34U, 0xdfU, 
    0xf7U, 0x31U, 0x0fU, 0xdcU, 0x82U, 0xaeU, 0xbfU, 0xd9U, 
    0x04U, 0xb0U, 0x1eU, 0x1dU, 0xc5U, 0x4bU, 0x29U, 0x27U, 
    0x09U, 0x4bU, 0x2dU, 0xb6U, 0x8dU, 0x6fU, 0x90U, 0x3bU, 
    0x68U, 0x40U, 0x1aU, 0xdeU, 0xbfU, 0x5aU, 0x7eU, 0x08U, 
    0xd7U, 0x8fU, 0xf4U, 0xefU, 0x5dU, 0x63U, 0x65U, 0x3aU, 
    0x65U, 0x04U, 0x0cU, 0xf9U, 0xbfU, 0xd4U, 0xacU, 0xa7U, 
    0x98U, 0x4aU, 0x74U, 0xd3U, 0x71U, 0x45U, 0x98U, 0x67U, 
    0x80U, 0xfcU, 0x0bU, 0x16U, 0xacU, 0x45U, 0x16U, 0x49U, 
    0xdeU, 0x61U, 0x88U, 0xa7U, 0xdbU, 0xdfU, 0x19U, 0x1fU, 
    0x64U, 0xb5U, 0xfcU, 0x5eU, 0x2aU, 0xb4U, 0x7bU, 0x57U, 
    0xf7U, 0xf7U, 0x27U, 0x6cU, 0xd4U, 0x19U, 0xc1U, 0x7aU, 
    0x3cU, 0xa8U, 0xe1U, 0xb9U, 0x39U, 0xaeU, 0x49U, 0xe4U, 
    0x88U, 0xacU, 0xbaU, 0x6bU, 0x96U, 0x56U, 0x10U, 0xb5U, 
    0x48U, 0x01U, 0x09U, 0xc8U, 0xb1U, 0x7bU, 0x80U, 0xe1U, 
    0xb7U, 0xb7U, 0x50U, 0xdfU, 0xc7U, 0x59U, 0x8dU, 0x5dU, 
    0x50U, 0x11U, 0xfdU, 0x2dU, 0xccU, 0x56U, 0x00U, 0xa3U, 
    0x2eU, 0xf5U, 0xb5U, 0x2aU, 0x1eU, 0xccU, 0x82U, 0x0eU, 
    0x30U, 0x8aU, 0xa3U, 0x42U, 0x72U, 0x1aU, 0xacU, 0x09U, 
    0x43U, 0xbfU, 0x66U, 0x86U, 0xb6U, 0x4bU, 0x25U, 0x79U, 
    0x37U, 0x65U, 0x04U, 0xccU, 0xc4U, 0x93U, 0xd9U, 0x7eU, 
    0x6aU, 0xedU, 0x3fU, 0xb0U, 0xf9U, 0xcdU, 0x71U, 0xa4U, 
    0x3dU, 0xd4U, 0x97U, 0xf0U, 0x1fU, 0x17U, 0xc0U, 0xe2U, 
    0xcbU, 0x37U, 0x97U, 0xaaU, 0x2aU, 0x2fU, 0x25U, 0x66U, 
    0x56U, 0x16U, 0x8eU, 0x6cU, 0x49U, 0x6aU, 0xfcU, 0x5fU, 
    0xb9U, 0x32U, 0x46U, 0xf6U, 0xb1U, 0x11U, 0x63U, 0x98U, 
    0xa3U, 0x46U, 0xf1U, 0xa6U, 0x41U, 0xf3U, 0xb0U, 0x41U, 
    0xe9U, 0x89U, 0xf7U, 0x91U, 0x4fU, 0x90U, 0xccU, 0x2cU, 
    0x7fU, 0xffU, 0x35U, 0x78U, 0x76U, 0xe5U, 0x06U, 0xb5U, 
    0x0dU, 0x33U, 0x4bU, 0xa7U, 0x7cU, 0x22U, 0x5bU, 0xc3U, 
    0x07U, 0xbaU, 0x53U, 0x71U, 0x52U, 0xf3U, 0xf1U, 0x61U, 
    0x0eU, 0x4eU, 0xafU, 0xe5U, 0x95U, 0xf6U, 0xd9U, 0xd9U, 
    0x0dU, 0x11U, 0xfaU, 0xa9U, 0x33U, 0xa1U, 0x5eU, 0xf1U, 
    0x36U, 0x95U, 0x46U, 0x86U, 0x8aU, 0x7fU, 0x3aU, 0x45U, 
    0xa9U, 0x67U, 0x68U, 0xd4U, 0x0fU, 0xd9U, 0xd0U, 0x34U, 
    0x12U, 0xc0U, 0x91U, 0xc6U, 0x31U, 0x5cU, 0xf4U, 0xfdU, 
    0xe7U, 0xcbU, 0x68U, 0x60U, 0x69U, 0x37U, 0x38U, 0x0dU, 
    0xb2U, 0xeaU, 0xaaU, 0x70U, 0x7bU, 0x4cU, 0x41U, 0x85U, 
    0xc3U, 0x2eU, 0xddU, 0xcdU, 0xd3U, 0x06U, 0x70U, 0x5eU, 
    0x4dU, 0xc1U, 0xffU, 0xc8U, 0x72U, 0xeeU, 0xeeU, 0x47U, 
    0x5aU, 0x64U, 0xdfU, 0xacU, 0x86U, 0xabU, 0xa4U, 0x1cU, 
    0x06U, 0x18U, 0x98U, 0x3fU, 0x87U, 0x41U, 0xc5U, 0xefU, 
    0x68U, 0xd3U, 0xa1U, 0x01U, 0xe8U, 0xa3U, 0xb8U, 0xcaU, 
    0xc6U, 0x0cU, 0x90U, 0x5cU, 0x15U, 0xfcU, 0x91U, 0x08U, 
    0x40U, 0xb9U, 0x4cU, 0x00U, 0xa0U, 0xb9U, 0xd0U
};

static const Esc_UINT8 msg_TEST_SHA_abc[] =
{
    0xddU, 0xafU, 0x35U, 0xa1U, 0x93U, 0x61U, 0x7aU, 0xbaU,
    0xccU, 0x41U, 0x73U, 0x49U, 0xaeU, 0x20U, 0x41U, 0x31U,
    0x12U, 0xe6U, 0xfaU, 0x4eU, 0x89U, 0xa9U, 0x7eU, 0xa2U,
    0x0aU, 0x9eU, 0xeeU, 0xe6U, 0x4bU, 0x55U, 0xd3U, 0x9aU,
    0x21U, 0x92U, 0x99U, 0x2aU, 0x27U, 0x4fU, 0xc1U, 0xa8U,
    0x36U, 0xbaU, 0x3cU, 0x23U, 0xa3U, 0xfeU, 0xebU, 0xbdU,
    0x45U, 0x4dU, 0x44U, 0x23U, 0x64U, 0x3cU, 0xe8U, 0x0eU,
    0x2aU, 0x9aU, 0xc9U, 0x4fU, 0xa5U, 0x4cU, 0xa4U, 0x9fU
};

/* ed25519ctx tests */

static const Esc_UINT8 msg_ctx_foo[] =
{
    0xf7U, 0x26U, 0x93U, 0x6dU, 0x19U, 0xc8U, 0x00U, 0x49U,
    0x4eU, 0x3fU, 0xdaU, 0xffU, 0x20U, 0xb2U, 0x76U, 0xa8U
};

static const Esc_UINT8 ctx_foo[] =
{
    0x66U, 0x6fU, 0x6fU
};

static const Esc_UINT8 msg_ctx_bar[] =
{
    0xf7U, 0x26U, 0x93U, 0x6dU, 0x19U, 0xc8U, 0x00U, 0x49U,
    0x4eU, 0x3fU, 0xdaU, 0xffU, 0x20U, 0xb2U, 0x76U, 0xa8U
};

static const Esc_UINT8 ctx_bar[] =
{
    0x62U, 0x61U, 0x72U
};

static const Esc_UINT8 msg_ctx_foo2[] =
{
    0x50U, 0x8eU, 0x9eU, 0x68U, 0x82U, 0xb9U, 0x79U, 0xfeU,
    0xa9U, 0x00U, 0xf6U, 0x2aU, 0xdcU, 0xeaU, 0xcaU, 0x35U
};

static const Esc_UINT8 ctx_foo2[] =
{
    0x66U, 0x6fU, 0x6fU
};

static const Esc_UINT8 msg_ctx_foo3[] =
{
    0xf7U, 0x26U, 0x93U, 0x6dU, 0x19U, 0xc8U, 0x00U, 0x49U,
    0x4eU, 0x3fU, 0xdaU, 0xffU, 0x20U, 0xb2U, 0x76U, 0xa8U
};

static const Esc_UINT8 ctx_foo3[] =
{
    0x66U, 0x6fU, 0x6fU
};


/* ed25519ph tests */

static const Esc_UINT8 msg_ph_abc[] =
{
    0x61U, 0x62U, 0x63U
};


/*lint -esym(9003,EscEdDsa_allTestVectors) We allow local objects outside the block scope for large testvectors (increases readibility) */
static const s_eddsa_tst_vector EscEdDsa_allTestVectors[] =
{

    /* ed25519 tests */

    /* RFC 8032 -----TEST 1 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U, 
            0xbaU, 0x84U, 0x4aU, 0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U, 
            0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U, 0x69U, 0x19U, 
            0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U
        },
        {   /* pubKey */
            0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U, 
            0xd5U, 0x4bU, 0xfeU, 0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU, 
            0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U, 0x23U, 0x25U, 
            0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU
        },
            /* msg */
        Esc_NULL_PTR,
            /* msgLen */
        0U,
        {   /* signature */
            0xe5U, 0x56U, 0x43U, 0x00U, 0xc3U, 0x60U, 0xacU, 0x72U, 
            0x90U, 0x86U, 0xe2U, 0xccU, 0x80U, 0x6eU, 0x82U, 0x8aU, 
            0x84U, 0x87U, 0x7fU, 0x1eU, 0xb8U, 0xe5U, 0xd9U, 0x74U, 
            0xd8U, 0x73U, 0xe0U, 0x65U, 0x22U, 0x49U, 0x01U, 0x55U, 
            0x5fU, 0xb8U, 0x82U, 0x15U, 0x90U, 0xa3U, 0x3bU, 0xacU, 
            0xc6U, 0x1eU, 0x39U, 0x70U, 0x1cU, 0xf9U, 0xb4U, 0x6bU, 
            0xd2U, 0x5bU, 0xf5U, 0xf0U, 0x59U, 0x5bU, 0xbeU, 0x24U, 
            0x65U, 0x51U, 0x41U, 0x43U, 0x8eU, 0x7aU, 0x10U, 0x0bU
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

    /* RFC 8032 -----TEST 2 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x4cU, 0xcdU, 0x08U, 0x9bU, 0x28U, 0xffU, 0x96U, 0xdaU, 
            0x9dU, 0xb6U, 0xc3U, 0x46U, 0xecU, 0x11U, 0x4eU, 0x0fU, 
            0x5bU, 0x8aU, 0x31U, 0x9fU, 0x35U, 0xabU, 0xa6U, 0x24U, 
            0xdaU, 0x8cU, 0xf6U, 0xedU, 0x4fU, 0xb8U, 0xa6U, 0xfbU
        },
        {   /* pubKey */
            0x3dU, 0x40U, 0x17U, 0xc3U, 0xe8U, 0x43U, 0x89U, 0x5aU, 
            0x92U, 0xb7U, 0x0aU, 0xa7U, 0x4dU, 0x1bU, 0x7eU, 0xbcU, 
            0x9cU, 0x98U, 0x2cU, 0xcfU, 0x2eU, 0xc4U, 0x96U, 0x8cU, 
            0xc0U, 0xcdU, 0x55U, 0xf1U, 0x2aU, 0xf4U, 0x66U, 0x0cU
        },
            /* msg */
        msg_TEST2,
            /* msgLen */
        sizeof(msg_TEST2),
        {   /* signature */
            0x92U, 0xa0U, 0x09U, 0xa9U, 0xf0U, 0xd4U, 0xcaU, 0xb8U, 
            0x72U, 0x0eU, 0x82U, 0x0bU, 0x5fU, 0x64U, 0x25U, 0x40U, 
            0xa2U, 0xb2U, 0x7bU, 0x54U, 0x16U, 0x50U, 0x3fU, 0x8fU, 
            0xb3U, 0x76U, 0x22U, 0x23U, 0xebU, 0xdbU, 0x69U, 0xdaU, 
            0x08U, 0x5aU, 0xc1U, 0xe4U, 0x3eU, 0x15U, 0x99U, 0x6eU, 
            0x45U, 0x8fU, 0x36U, 0x13U, 0xd0U, 0xf1U, 0x1dU, 0x8cU, 
            0x38U, 0x7bU, 0x2eU, 0xaeU, 0xb4U, 0x30U, 0x2aU, 0xeeU, 
            0xb0U, 0x0dU, 0x29U, 0x16U, 0x12U, 0xbbU, 0x0cU, 0x00U
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

    /* RFC 8032 -----TEST 3 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0xc5U, 0xaaU, 0x8dU, 0xf4U, 0x3fU, 0x9fU, 0x83U, 0x7bU, 
            0xedU, 0xb7U, 0x44U, 0x2fU, 0x31U, 0xdcU, 0xb7U, 0xb1U, 
            0x66U, 0xd3U, 0x85U, 0x35U, 0x07U, 0x6fU, 0x09U, 0x4bU, 
            0x85U, 0xceU, 0x3aU, 0x2eU, 0x0bU, 0x44U, 0x58U, 0xf7U
        },
        {   /* pubKey */
            0xfcU, 0x51U, 0xcdU, 0x8eU, 0x62U, 0x18U, 0xa1U, 0xa3U, 
            0x8dU, 0xa4U, 0x7eU, 0xd0U, 0x02U, 0x30U, 0xf0U, 0x58U, 
            0x08U, 0x16U, 0xedU, 0x13U, 0xbaU, 0x33U, 0x03U, 0xacU, 
            0x5dU, 0xebU, 0x91U, 0x15U, 0x48U, 0x90U, 0x80U, 0x25U
        },
            /* msg */
        msg_TEST3,
            /* msgLen */
        sizeof(msg_TEST3),
        {   /* signature */
            0x62U, 0x91U, 0xd6U, 0x57U, 0xdeU, 0xecU, 0x24U, 0x02U, 
            0x48U, 0x27U, 0xe6U, 0x9cU, 0x3aU, 0xbeU, 0x01U, 0xa3U, 
            0x0cU, 0xe5U, 0x48U, 0xa2U, 0x84U, 0x74U, 0x3aU, 0x44U, 
            0x5eU, 0x36U, 0x80U, 0xd7U, 0xdbU, 0x5aU, 0xc3U, 0xacU, 
            0x18U, 0xffU, 0x9bU, 0x53U, 0x8dU, 0x16U, 0xf2U, 0x90U, 
            0xaeU, 0x67U, 0xf7U, 0x60U, 0x98U, 0x4dU, 0xc6U, 0x59U, 
            0x4aU, 0x7cU, 0x15U, 0xe9U, 0x71U, 0x6eU, 0xd2U, 0x8dU, 
            0xc0U, 0x27U, 0xbeU, 0xceU, 0xeaU, 0x1eU, 0xc4U, 0x0aU
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

    /* RFC 8032 -----TEST 1024 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0xf5U, 0xe5U, 0x76U, 0x7cU, 0xf1U, 0x53U, 0x31U, 0x95U,
            0x17U, 0x63U, 0x0fU, 0x22U, 0x68U, 0x76U, 0xb8U, 0x6cU,
            0x81U, 0x60U, 0xccU, 0x58U, 0x3bU, 0xc0U, 0x13U, 0x74U,
            0x4cU, 0x6bU, 0xf2U, 0x55U, 0xf5U, 0xccU, 0x0eU, 0xe5U
        },
        {   /* pubKey */
            0x27U, 0x81U, 0x17U, 0xfcU, 0x14U, 0x4cU, 0x72U, 0x34U,
            0x0fU, 0x67U, 0xd0U, 0xf2U, 0x31U, 0x6eU, 0x83U, 0x86U,
            0xceU, 0xffU, 0xbfU, 0x2bU, 0x24U, 0x28U, 0xc9U, 0xc5U,
            0x1fU, 0xefU, 0x7cU, 0x59U, 0x7fU, 0x1dU, 0x42U, 0x6eU,
        },
            /* msg */
        msg_TEST1024,
            /* msgLen */
        sizeof(msg_TEST1024),
        {   /* signature */
            0x0aU, 0xabU, 0x4cU, 0x90U, 0x05U, 0x01U, 0xb3U, 0xe2U,
            0x4dU, 0x7cU, 0xdfU, 0x46U, 0x63U, 0x32U, 0x6aU, 0x3aU,
            0x87U, 0xdfU, 0x5eU, 0x48U, 0x43U, 0xb2U, 0xcbU, 0xdbU,
            0x67U, 0xcbU, 0xf6U, 0xe4U, 0x60U, 0xfeU, 0xc3U, 0x50U,
            0xaaU, 0x53U, 0x71U, 0xb1U, 0x50U, 0x8fU, 0x9fU, 0x45U,
            0x28U, 0xecU, 0xeaU, 0x23U, 0xc4U, 0x36U, 0xd9U, 0x4bU,
            0x5eU, 0x8fU, 0xcdU, 0x4fU, 0x68U, 0x1eU, 0x30U, 0xa6U,
            0xacU, 0x00U, 0xa9U, 0x70U, 0x4aU, 0x18U, 0x8aU, 0x03U
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

    /* RFC 8032 -----TEST SHA(abc) */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x83U, 0x3fU, 0xe6U, 0x24U, 0x09U, 0x23U, 0x7bU, 0x9dU,
            0x62U, 0xecU, 0x77U, 0x58U, 0x75U, 0x20U, 0x91U, 0x1eU,
            0x9aU, 0x75U, 0x9cU, 0xecU, 0x1dU, 0x19U, 0x75U, 0x5bU,
            0x7dU, 0xa9U, 0x01U, 0xb9U, 0x6dU, 0xcaU, 0x3dU, 0x42U,
        },
        {   /* pubKey */
             0xecU, 0x17U, 0x2bU, 0x93U, 0xadU, 0x5eU, 0x56U, 0x3bU,
             0xf4U, 0x93U, 0x2cU, 0x70U, 0xe1U, 0x24U, 0x50U, 0x34U,
             0xc3U, 0x54U, 0x67U, 0xefU, 0x2eU, 0xfdU, 0x4dU, 0x64U,
             0xebU, 0xf8U, 0x19U, 0x68U, 0x34U, 0x67U, 0xe2U, 0xbfU,
        },
            /* msg */
        msg_TEST_SHA_abc,
            /* msgLen */
        sizeof(msg_TEST_SHA_abc),
        {   /* signature */
             0xdcU, 0x2aU, 0x44U, 0x59U, 0xe7U, 0x36U, 0x96U, 0x33U,
             0xa5U, 0x2bU, 0x1bU, 0xf2U, 0x77U, 0x83U, 0x9aU, 0x00U,
             0x20U, 0x10U, 0x09U, 0xa3U, 0xefU, 0xbfU, 0x3eU, 0xcbU,
             0x69U, 0xbeU, 0xa2U, 0x18U, 0x6cU, 0x26U, 0xb5U, 0x89U,
             0x09U, 0x35U, 0x1fU, 0xc9U, 0xacU, 0x90U, 0xb3U, 0xecU,
             0xfdU, 0xfbU, 0xc7U, 0xc6U, 0x64U, 0x31U, 0xe0U, 0x30U,
             0x3dU, 0xcaU, 0x17U, 0x9cU, 0x13U, 0x8aU, 0xc1U, 0x7aU,
             0xd9U, 0xbeU, 0xf1U, 0x17U, 0x73U, 0x31U, 0xa7U, 0x04U,
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

    /* ed25519ctx tests */

    /* RFC 8032 -----foo */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x03U, 0x05U, 0x33U, 0x4eU, 0x38U, 0x1aU, 0xf7U, 0x8fU,
            0x14U, 0x1cU, 0xb6U, 0x66U, 0xf6U, 0x19U, 0x9fU, 0x57U,
            0xbcU, 0x34U, 0x95U, 0x33U, 0x5aU, 0x25U, 0x6aU, 0x95U,
            0xbdU, 0x2aU, 0x55U, 0xbfU, 0x54U, 0x66U, 0x63U, 0xf6U
        },
        {   /* pubKey */
            0xdfU, 0xc9U, 0x42U, 0x5eU, 0x4fU, 0x96U, 0x8fU, 0x7fU,
            0x0cU, 0x29U, 0xf0U, 0x25U, 0x9cU, 0xf5U, 0xf9U, 0xaeU,
            0xd6U, 0x85U, 0x1cU, 0x2bU, 0xb4U, 0xadU, 0x8bU, 0xfbU,
            0x86U, 0x0cU, 0xfeU, 0xe0U, 0xabU, 0x24U, 0x82U, 0x92U
        },
            /* msg */
        msg_ctx_foo,
            /* msgLen */
        sizeof(msg_ctx_foo),
        {   /* signature */
            0x55U, 0xa4U, 0xccU, 0x2fU, 0x70U, 0xa5U, 0x4eU, 0x04U,
            0x28U, 0x8cU, 0x5fU, 0x4cU, 0xd1U, 0xe4U, 0x5aU, 0x7bU,
            0xb5U, 0x20U, 0xb3U, 0x62U, 0x92U, 0x91U, 0x18U, 0x76U,
            0xcaU, 0xdaU, 0x73U, 0x23U, 0x19U, 0x8dU, 0xd8U, 0x7aU,
            0x8bU, 0x36U, 0x95U, 0x0bU, 0x95U, 0x13U, 0x00U, 0x22U,
            0x90U, 0x7aU, 0x7fU, 0xb7U, 0xc4U, 0xe9U, 0xb2U, 0xd5U,
            0xf6U, 0xccU, 0xa6U, 0x85U, 0xa5U, 0x87U, 0xb4U, 0xb2U,
            0x1fU, 0x4bU, 0x88U, 0x8eU, 0x4eU, 0x7eU, 0xdbU, 0x0dU
        },
            /* context */
        ctx_foo,
            /* contextLen */
        (Esc_UINT8)sizeof(ctx_foo),
    },

    /* RFC 8032 -----bar */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x03U, 0x05U, 0x33U, 0x4eU, 0x38U, 0x1aU, 0xf7U, 0x8fU,
            0x14U, 0x1cU, 0xb6U, 0x66U, 0xf6U, 0x19U, 0x9fU, 0x57U,
            0xbcU, 0x34U, 0x95U, 0x33U, 0x5aU, 0x25U, 0x6aU, 0x95U,
            0xbdU, 0x2aU, 0x55U, 0xbfU, 0x54U, 0x66U, 0x63U, 0xf6U
        },
        {   /* pubKey */
            0xdfU, 0xc9U, 0x42U, 0x5eU, 0x4fU, 0x96U, 0x8fU, 0x7fU,
            0x0cU, 0x29U, 0xf0U, 0x25U, 0x9cU, 0xf5U, 0xf9U, 0xaeU,
            0xd6U, 0x85U, 0x1cU, 0x2bU, 0xb4U, 0xadU, 0x8bU, 0xfbU,
            0x86U, 0x0cU, 0xfeU, 0xe0U, 0xabU, 0x24U, 0x82U, 0x92U
        },
            /* msg */
        msg_ctx_bar,
            /* msgLen */
        sizeof(msg_ctx_bar),
        {   /* signature */
            0xfcU, 0x60U, 0xd5U, 0x87U, 0x2fU, 0xc4U, 0x6bU, 0x3aU,
            0xa6U, 0x9fU, 0x8bU, 0x5bU, 0x43U, 0x51U, 0xd5U, 0x80U,
            0x8fU, 0x92U, 0xbcU, 0xc0U, 0x44U, 0x60U, 0x6dU, 0xb0U,
            0x97U, 0xabU, 0xabU, 0x6dU, 0xbcU, 0xb1U, 0xaeU, 0xe3U,
            0x21U, 0x6cU, 0x48U, 0xe8U, 0xb3U, 0xb6U, 0x64U, 0x31U,
            0xb5U, 0xb1U, 0x86U, 0xd1U, 0xd2U, 0x8fU, 0x8eU, 0xe1U,
            0x5aU, 0x5cU, 0xa2U, 0xdfU, 0x66U, 0x68U, 0x34U, 0x62U,
            0x91U, 0xc2U, 0x04U, 0x3dU, 0x4eU, 0xb3U, 0xe9U, 0x0dU
        },
            /* context */
        ctx_bar,
            /* contextLen */
        (Esc_UINT8)sizeof(ctx_bar),
    },

    /* RFC 8032 -----foo2 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0x03U, 0x05U, 0x33U, 0x4eU, 0x38U, 0x1aU, 0xf7U, 0x8fU,
            0x14U, 0x1cU, 0xb6U, 0x66U, 0xf6U, 0x19U, 0x9fU, 0x57U,
            0xbcU, 0x34U, 0x95U, 0x33U, 0x5aU, 0x25U, 0x6aU, 0x95U,
            0xbdU, 0x2aU, 0x55U, 0xbfU, 0x54U, 0x66U, 0x63U, 0xf6U
        },
        {   /* pubKey */
            0xdfU, 0xc9U, 0x42U, 0x5eU, 0x4fU, 0x96U, 0x8fU, 0x7fU,
            0x0cU, 0x29U, 0xf0U, 0x25U, 0x9cU, 0xf5U, 0xf9U, 0xaeU,
            0xd6U, 0x85U, 0x1cU, 0x2bU, 0xb4U, 0xadU, 0x8bU, 0xfbU,
            0x86U, 0x0cU, 0xfeU, 0xe0U, 0xabU, 0x24U, 0x82U, 0x92U
        },
            /* msg */
        msg_ctx_foo2,
            /* msgLen */
        sizeof(msg_ctx_foo2),
        {   /* signature */
            0x8bU, 0x70U, 0xc1U, 0xccU, 0x83U, 0x10U, 0xe1U, 0xdeU,
            0x20U, 0xacU, 0x53U, 0xceU, 0x28U, 0xaeU, 0x6eU, 0x72U,
            0x07U, 0xf3U, 0x3cU, 0x32U, 0x95U, 0xe0U, 0x3bU, 0xb5U,
            0xc0U, 0x73U, 0x2aU, 0x1dU, 0x20U, 0xdcU, 0x64U, 0x90U,
            0x89U, 0x22U, 0xa8U, 0xb0U, 0x52U, 0xcfU, 0x99U, 0xb7U,
            0xc4U, 0xfeU, 0x10U, 0x7aU, 0x5aU, 0xbbU, 0x5bU, 0x2cU,
            0x40U, 0x85U, 0xaeU, 0x75U, 0x89U, 0x0dU, 0x02U, 0xdfU,
            0x26U, 0x26U, 0x9dU, 0x89U, 0x45U, 0xf8U, 0x4bU, 0x0bU
        },
            /* context */
        ctx_foo2,
            /* contextLen */
        (Esc_UINT8)sizeof(ctx_foo2),
    },

    /* RFC 8032 -----foo3 */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        FALSE,
        32U,
        {   /* privkey */
            0xabU, 0x9cU, 0x28U, 0x53U, 0xceU, 0x29U, 0x7dU, 0xdaU,
            0xb8U, 0x5cU, 0x99U, 0x3bU, 0x3aU, 0xe1U, 0x4bU, 0xcaU,
            0xd3U, 0x9bU, 0x2cU, 0x68U, 0x2bU, 0xeaU, 0xbcU, 0x27U,
            0xd6U, 0xd4U, 0xebU, 0x20U, 0x71U, 0x1dU, 0x65U, 0x60U
        },
        {   /* pubKey */
            0x0fU, 0x1dU, 0x12U, 0x74U, 0x94U, 0x3bU, 0x91U, 0x41U,
            0x58U, 0x89U, 0x15U, 0x2eU, 0x89U, 0x3dU, 0x80U, 0xe9U,
            0x32U, 0x75U, 0xa1U, 0xfcU, 0x0bU, 0x65U, 0xfdU, 0x71U,
            0xb4U, 0xb0U, 0xddU, 0xa1U, 0x0aU, 0xd7U, 0xd7U, 0x72U
        },
            /* msg */
        msg_ctx_foo3,
            /* msgLen */
        sizeof(msg_ctx_foo3),
        {   /* signature */
            0x21U, 0x65U, 0x5bU, 0x5fU, 0x1aU, 0xa9U, 0x65U, 0x99U,
            0x6bU, 0x3fU, 0x97U, 0xb3U, 0xc8U, 0x49U, 0xeaU, 0xfbU,
            0xa9U, 0x22U, 0xa0U, 0xa6U, 0x29U, 0x92U, 0xf7U, 0x3bU,
            0x3dU, 0x1bU, 0x73U, 0x10U, 0x6aU, 0x84U, 0xadU, 0x85U,
            0xe9U, 0xb8U, 0x6aU, 0x7bU, 0x60U, 0x05U, 0xeaU, 0x86U,
            0x83U, 0x37U, 0xffU, 0x2dU, 0x20U, 0xa7U, 0xf5U, 0xfbU,
            0xd4U, 0xcdU, 0x10U, 0xb0U, 0xbeU, 0x49U, 0xa6U, 0x8dU,
            0xa2U, 0xb2U, 0xe0U, 0xdcU, 0x0aU, 0xd8U, 0x96U, 0x0fU
        },
            /* context */
        ctx_foo3,
            /* contextLen */
        (Esc_UINT8)sizeof(ctx_foo3),
    },

    /* ed25519ph tests */

    /* RFC 8032 -----abc */
    {
        EscEdDsa_CURVE_ED25519,
        EscEdDsa_DIGEST_TYPE_SHA512,
        TRUE,
        32U,
        {   /* privkey */
            0x83U, 0x3fU, 0xe6U, 0x24U, 0x09U, 0x23U, 0x7bU, 0x9dU,
            0x62U, 0xecU, 0x77U, 0x58U, 0x75U, 0x20U, 0x91U, 0x1eU,
            0x9aU, 0x75U, 0x9cU, 0xecU, 0x1dU, 0x19U, 0x75U, 0x5bU,
            0x7dU, 0xa9U, 0x01U, 0xb9U, 0x6dU, 0xcaU, 0x3dU, 0x42U
        },
        {   /* pubKey */
            0xecU, 0x17U, 0x2bU, 0x93U, 0xadU, 0x5eU, 0x56U, 0x3bU,
            0xf4U, 0x93U, 0x2cU, 0x70U, 0xe1U, 0x24U, 0x50U, 0x34U, 
            0xc3U, 0x54U, 0x67U, 0xefU, 0x2eU, 0xfdU, 0x4dU, 0x64U,
            0xebU, 0xf8U, 0x19U, 0x68U, 0x34U, 0x67U, 0xe2U, 0xbfU
        },
            /* msg */
        msg_ph_abc,
            /* msgLen */
        sizeof(msg_ph_abc),
        {   /* signature */
            0x98U, 0xa7U, 0x02U, 0x22U, 0xf0U, 0xb8U, 0x12U, 0x1aU,
            0xa9U, 0xd3U, 0x0fU, 0x81U, 0x3dU, 0x68U, 0x3fU, 0x80U,
            0x9eU, 0x46U, 0x2bU, 0x46U, 0x9cU, 0x7fU, 0xf8U, 0x76U,
            0x39U, 0x49U, 0x9bU, 0xb9U, 0x4eU, 0x6dU, 0xaeU, 0x41U,
            0x31U, 0xf8U, 0x50U, 0x42U, 0x46U, 0x3cU, 0x2aU, 0x35U,
            0x5aU, 0x20U, 0x03U, 0xd0U, 0x62U, 0xadU, 0xf5U, 0xaaU,
            0xa1U, 0x0bU, 0x8cU, 0x61U, 0xe6U, 0x36U, 0x06U, 0x2aU,
            0xaaU, 0xd1U, 0x1cU, 0x2aU, 0x26U, 0x08U, 0x34U, 0x06U
        },
            /* context */
        Esc_NULL_PTR,
            /* contextLen */
        0U,
    },

};

/***************************************************************************
 * 5. DECLARATIONS                                                         *
 ***************************************************************************/

/**
 * Dummy DRBG. Will return the bytes which are fed in via parameter prngState.
 *
 * \param[in] prngState Pointer to the byte array which should be returned by the DRBG.
 * \param[out] rnd Output array. Will be writen with the bytes from prngState.
 * \param[in] len Length of the input and output array.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_GetRandom(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/**
 * Test function for signature generation and verification.
 *
 * \param[in] tst_vec Pointer to one test vector.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_CompTestSignature(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Test function for key generation.
 *
 * \param[in] tst_vec Pointer to one test vector.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_CompKeyGeneration(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Test function for derivation of the public key from a given private key.
 *
 * \param[in] tst_vec Pointer to one test vector.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_CompPubKeyDerivation(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Test function for checking compliance of the verification function for invalid signatures.
 * Test is designed for Ed25519-SHA-512 only!
 *
 * \param[in] tst_vec Pointer to one test vector.
 *                    Test vector must contain a valid signature with msgLen != 0U.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_NegativeTestSignature_Ed25519(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Parameter test function for key generation.
 *
 * \param[in] tst_vec Pointer to one test vector.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_ParametersKey(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Parameter test function for public key derivation.
 *
 * \param[in] tst_vec Pointer to one test vector.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_ParametersPubKeyDerivation(
    const s_eddsa_tst_vector* tst_vec );

/**
 * Parameter test function for Signature Generation and Verification.
 *
 * \param[in] tst_vec Pointer to one test vector which should be used.
 *                    Test vector must contain a valid signature with msgLen != 0U.
 *
 * \return Esc_NO_ERROR if everything works fine.
 */
static Esc_ERROR
EscTstEdDsa_ParametersSignature(
    const s_eddsa_tst_vector* tst_vec );

/***************************************************************************
 * 6. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*lint -save -e818 The ctx parameter can not const due to interface compatibility. */
static Esc_ERROR
EscTstEdDsa_GetRandom(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    Esc_UINT32 i;
    /*lint --e(9079) We violate Rule 11.5 (adv.) here. Pointer cast is required for interface compatibility.
     Cast is safe since the void pointer was casted to void from uint8 pointer. */
    const Esc_UINT8* rndData = (Esc_UINT8*)(prngState);

    for ( i = 0U; i < len; i++) 
    {
        rnd[i] = rndData[i];
    }

    return Esc_NO_ERROR;
}
/*lint -restore */

/*lint -save -e9005 We cast the const away for interface compatibility. Vector is used as a PRNG state later. */
static Esc_ERROR
EscTstEdDsa_CompTestSignature(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 signatureBuffer[EscEdDsa_SIGNATURE_BYTES_MAX];
    Esc_UINT32 sigBytes = EscEdDsa_SIGNATURE_BYTES_MAX;
    Esc_UINT8 hashBuffer[EscSha512_DIGEST_LEN];
    const Esc_UINT8 *inputPointer;
    Esc_UINT32 inputLen;

    EscTst_PrintString( "\n\nEdDsa Signature Generation test\n" );

    EscTst_PrintArray( "Private Key", tst_vec->privKey, tst_vec->keyLen );
    EscTst_PrintArray( "Public Key", tst_vec->pubKey, tst_vec->keyLen );
    EscTst_PrintArray( "Message", tst_vec->msg, tst_vec->msgLen );

    if ( tst_vec->preHashed != FALSE )
    {
        /* Pre-Hash the message */
        (void)EscSha512_Calc(FALSE, tst_vec->msg, tst_vec->msgLen, hashBuffer, EscSha512_DIGEST_LEN);
        inputPointer = &hashBuffer[0];
        inputLen = EscSha512_DIGEST_LEN;
    }
    else
    {
        /* No pre-hashing required */
        inputPointer = &tst_vec->msg[0];
        inputLen = tst_vec->msgLen;
    }

    /* Compute signature */
    returnCode = EscEdDsa_SignatureGeneration(
            tst_vec->preHashed,
            signatureBuffer, &sigBytes,
            inputPointer, inputLen,
            tst_vec->privKey, tst_vec->keyLen,
            tst_vec->pubKey, tst_vec->keyLen,
            tst_vec->digestType, tst_vec->curveId,
            tst_vec->context, tst_vec->contextLen );
    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare signature */
        if ( sigBytes == (tst_vec->keyLen * 2U) )
        {
            EscTst_PrintArray( "Expected Signature", tst_vec->signature, sigBytes );
            EscTst_PrintArray( "Calculated Signature", signatureBuffer, sigBytes );

            if (EscTst_Memcmp( tst_vec->signature, signatureBuffer, (Esc_UINT32)sigBytes ) == FALSE)
            {
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Verify generated signature */
        returnCode = EscEdDsa_SignatureVerification(
                tst_vec->preHashed,
                inputPointer, inputLen,
                signatureBuffer, sigBytes,
                tst_vec->pubKey, tst_vec->keyLen,
                tst_vec->digestType, tst_vec->curveId,
                tst_vec->context, tst_vec->contextLen );
        if ( returnCode == Esc_NO_ERROR )
        {
            EscTst_PrintString( "\nVerify SUCCESS!\n" );
        } else
        {
            EscTst_PrintString( "\nVerify FAILED!\n" );
        }
    }

    return returnCode;
}


static Esc_ERROR
EscTstEdDsa_CompKeyGeneration(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 pubKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT8 privKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT32 pubKeyLen = EscEdDsa_KEY_BYTES_MAX;
    Esc_UINT32 privKeyLen = EscEdDsa_KEY_BYTES_MAX;

    EscTst_PrintString( "\n\nEdDsa Key Generation test\n" );

    EscTst_PrintArray( "Private Key Seed", tst_vec->privKey, tst_vec->keyLen );

    /* Generate private and public key from seed */
    /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility.
      Cast is safe since the void pointer is casted back before using. */
    returnCode = EscEdDsa_KeyGeneration(
            pubKey_gen, &pubKeyLen,
            privKey_gen, &privKeyLen,
            (void*) tst_vec->privKey, EscTstEdDsa_GetRandom,
            tst_vec->digestType, tst_vec->curveId );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare sizes of keys */
        if ( (pubKeyLen != tst_vec->keyLen) || (privKeyLen != tst_vec->keyLen) )
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare resulting private key */
        EscTst_PrintArray( "Computed Private Key", privKey_gen, tst_vec->keyLen );
        EscTst_PrintArray( "Stored Private Key", tst_vec->privKey, tst_vec->keyLen );
        if (EscTst_Memcmp( tst_vec->privKey, privKey_gen, tst_vec->keyLen ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare resulting public key */
        EscTst_PrintArray( "Computed Public Key", pubKey_gen, tst_vec->keyLen );
        EscTst_PrintArray( "Stored Public Key", tst_vec->pubKey, tst_vec->keyLen );
        if (EscTst_Memcmp( tst_vec->pubKey, pubKey_gen, tst_vec->keyLen ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstEdDsa_CompPubKeyDerivation(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 pubKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT32 pubKeyLen = EscEdDsa_KEY_BYTES_MAX;

    EscTst_PrintString( "\n\nEdDsa Public Key Derivation test\n" );

    EscTst_PrintArray( "Private Key Seed", tst_vec->privKey, tst_vec->keyLen );

    /* Derive public key from private key */
    returnCode = EscEdDsa_DerivePubKeyFromPrivKey(
            pubKey_gen, &pubKeyLen,
            tst_vec->privKey, tst_vec->keyLen,
            tst_vec->digestType, tst_vec->curveId );

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare sizes of keys */
        if (pubKeyLen != tst_vec->keyLen)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Compare resulting public key */
        EscTst_PrintArray( "Computed Public Key", pubKey_gen, tst_vec->keyLen );
        EscTst_PrintArray( "Stored Public Key", tst_vec->pubKey, tst_vec->keyLen );
        if (EscTst_Memcmp( tst_vec->pubKey, pubKey_gen, tst_vec->keyLen ) == FALSE)
        {
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}


static Esc_ERROR
EscTstEdDsa_NegativeTestSignature_Ed25519(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 tamperBuffer[64U];
    /* Use (-d mod p) as encoded y-coordinate for the public key. This will fail during decompression, because -d
       is not a square and consequently a square root can not be computed (cf. Section 5 from [2]). */
    static const Esc_UINT8 faultyPubKey[32U] = 
    {
        0x2dU, 0xfcU, 0x93U, 0x11U, 0xd4U, 0x90U, 0x01U, 0x8cU, 0x73U, 0x38U, 0xbfU, 0x86U, 0x88U, 0x86U, 0x17U, 0x67U,
        0xffU, 0x8fU, 0xf5U, 0xb2U, 0xbeU, 0xbeU, 0x27U, 0x54U, 0x8aU, 0x14U, 0xb2U, 0x35U, 0xecU, 0xa6U, 0x87U, 0x4aU
    };
    Esc_UINT32 sigLen = 2U * tst_vec->keyLen;

    EscTst_PrintString( "\n\nEd25519-SHA-512 Negative Verification test\n" );

    EscTst_PrintString( "\nFlip lowest bit in R-part of signature: " );

    /* copy correct signature into buffer and flip lowest bit in R-part */
    EscTst_Memcpy(tamperBuffer, tst_vec->signature, sigLen);
    tamperBuffer[0] ^= 0x01U;

    /* Verify generated signature */
    returnCode = EscEdDsa_SignatureVerification(
            tst_vec->preHashed,
            tst_vec->msg, tst_vec->msgLen,
            tamperBuffer, sigLen,
            tst_vec->pubKey, tst_vec->keyLen,
            tst_vec->digestType, tst_vec->curveId,
            tst_vec->context, tst_vec->contextLen );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Flip highest bit in S-part of signature: " );
        /* copy correct signature into buffer and flip highest bit in S-part (sign of compresses x-coordinate). */
        EscTst_Memcpy(tamperBuffer, tst_vec->signature, sigLen);
        tamperBuffer[63] ^= 0x80U;

        /* Verify generated signature */
        returnCode = EscEdDsa_SignatureVerification(
                tst_vec->preHashed,
                tst_vec->msg, tst_vec->msgLen,
                tamperBuffer, sigLen,
                tst_vec->pubKey, tst_vec->keyLen,
                tst_vec->digestType, tst_vec->curveId,
                tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Flip one arbitrary bit in S-part of signature: " );
        /* copy correct signature into buffer and flip arbitrary chosen bit in S-part. */
        EscTst_Memcpy(tamperBuffer, tst_vec->signature, sigLen);
        tamperBuffer[42] ^= 0x80U;

        /* Verify generated signature */
        returnCode = EscEdDsa_SignatureVerification(
                tst_vec->preHashed,
                tst_vec->msg, tst_vec->msgLen,
                tamperBuffer, sigLen,
                tst_vec->pubKey, tst_vec->keyLen,
                tst_vec->digestType, tst_vec->curveId,
                tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Flip one bit in message: " );
        /* Message must fit into tamperBuffer and at least one, if not raise assertion */
        Esc_ASSERT(tst_vec->msgLen <= 64U);
        Esc_ASSERT(tst_vec->msgLen > 0U);
        if ( (tst_vec->msgLen <= 64U) && (tst_vec->msgLen > 0U) )
        {
            /* copy correct message into buffer and flip arbitrary chosen bit. */
            EscTst_Memcpy(tamperBuffer, tst_vec->msg, tst_vec->msgLen);
            tamperBuffer[0] ^= 0x80U;

            /* Verify generated signature */
            returnCode = EscEdDsa_SignatureVerification(
                    tst_vec->preHashed,
                    tamperBuffer, tst_vec->msgLen,
                    tst_vec->signature, sigLen,
                    tst_vec->pubKey, tst_vec->keyLen,
                    tst_vec->digestType, tst_vec->curveId,
                    tst_vec->context, tst_vec->contextLen );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_SIGNATURE );
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Using a faulty encoded public key: " );

        /* Verify with faulty encoded key */
        returnCode = EscEdDsa_SignatureVerification(
                tst_vec->preHashed,
                tst_vec->msg, tst_vec->msgLen,
                tst_vec->signature, sigLen,
                faultyPubKey, tst_vec->keyLen,
                tst_vec->digestType, tst_vec->curveId,
                tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PUBLIC_KEY );
    }

    return returnCode;
}

/*lint -e{9087} We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
static Esc_ERROR
EscTstEdDsa_ParametersKey(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 pubKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT8 privKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT32 pubKeyLen = EscEdDsa_KEY_BYTES_MAX;
    Esc_UINT32 privKeyLen = EscEdDsa_KEY_BYTES_MAX;

    EscTst_PrintString( "\n\nEdDsa key generation parameter test\n" );

    EscTst_PrintString( "EscEdDsa_KeyGeneration() with pubKey = 0\n" );
    returnCode = EscEdDsa_KeyGeneration( Esc_NULL_PTR, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with pubKeyLen = 0\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, Esc_NULL_PTR, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with privKey = 0\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, Esc_NULL_PTR, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with privKeyLen = 0\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, Esc_NULL_PTR, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with randomFunc = 0\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, Esc_NULL_PTR, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with unsupported curveID\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, EscFeArith_CURVE_SECP_192 );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with not supported hash algorithm\n" );
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, 100U, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNSUPPORTED_DIGEST_TYPE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with a too small pub key buffer\n" );
        pubKeyLen = tst_vec->keyLen - 1U;
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE );
        pubKeyLen = EscEdDsa_KEY_BYTES_MAX;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_KeyGeneration() with a too small priv key buffer = 0\n" );
        privKeyLen = tst_vec->keyLen - 1U;
        returnCode = EscEdDsa_KeyGeneration( pubKey_gen, &pubKeyLen, privKey_gen, &privKeyLen, (void*) tst_vec->privKey, EscTstEdDsa_GetRandom, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE );
    }

    return returnCode;
}
/*lint -restore */

static Esc_ERROR
EscTstEdDsa_ParametersPubKeyDerivation(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 pubKey_gen[EscEdDsa_KEY_BYTES_MAX];
    Esc_UINT8 privKey[EscEdDsa_KEY_BYTES_MAX] = {0};
    Esc_UINT32 pubKeyLen = EscEdDsa_KEY_BYTES_MAX;
    Esc_UINT32 privKeyLen = EscEdDsa_KEY_BYTES_MAX;

    EscTst_PrintString( "\n\nEdDsa public key derivation parameter test\n" );

    EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with pubKey = NULL\n" );
    returnCode = EscEdDsa_DerivePubKeyFromPrivKey( Esc_NULL_PTR, &pubKeyLen, privKey, privKeyLen, tst_vec->digestType, tst_vec->curveId );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with pubKeyLen = NULL\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, Esc_NULL_PTR, privKey, privKeyLen, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 smallPubKeyLen = 1;

        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with too small buffer for public key\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, &smallPubKeyLen, privKey, privKeyLen, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with privKey == NULL\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, &pubKeyLen, Esc_NULL_PTR, privKeyLen, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with invalid private key size\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, &pubKeyLen, privKey, 1U, tst_vec->digestType, tst_vec->curveId );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PRIVATE_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with unsupported hash algorithm\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, &pubKeyLen, privKey, privKeyLen, 200U, tst_vec->curveId);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNSUPPORTED_DIGEST_TYPE);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_DerivePubKeyFromPrivKey() with unsupported curve ID\n" );
        returnCode = EscEdDsa_DerivePubKeyFromPrivKey( pubKey_gen, &pubKeyLen, privKey, privKeyLen, tst_vec->digestType, EscFeArith_CURVE_SECP_192);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE);
    }

    return returnCode;
}


static Esc_ERROR
EscTstEdDsa_ParametersSignature(
    const s_eddsa_tst_vector* tst_vec )
{
    Esc_ERROR returnCode;
    Esc_UINT8 signatureBuffer[EscEdDsa_SIGNATURE_BYTES_MAX];
    Esc_UINT32 sigBytes = EscEdDsa_SIGNATURE_BYTES_MAX;

    EscTst_PrintString( "\n\nEdDsa signature generation parameter test\n" );


    EscTst_PrintString( "EscEdDsa_SignatureGeneration() with signature = 0\n" );
    returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, Esc_NULL_PTR, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with signatureLen = 0\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, Esc_NULL_PTR, Esc_NULL_PTR, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with message = 0 and messageLength != 0\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, Esc_NULL_PTR, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with context = 0 and contextLength != 0\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with privKey = 0\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, Esc_NULL_PTR, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with pubKey = 0\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, Esc_NULL_PTR, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with with unsupported curveID\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, EscFeArith_CURVE_SECP_192, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with not supported hash algorithm\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, 100U, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNSUPPORTED_DIGEST_TYPE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with with a too small signature buffer\n" );
        sigBytes = (2U * tst_vec->keyLen) - 1U;
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INSUFFICIENT_BUFFER_SIZE );
        sigBytes = EscEdDsa_SIGNATURE_BYTES_MAX;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with wrong length of public key\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen - 1U, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureGeneration() with wrong length of private key\n" );
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen + 1U, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "\n\nEscEdDsa signature verification parameter test\n" );

        /* Compute one valid signature */
        returnCode = EscEdDsa_SignatureGeneration( tst_vec->preHashed, signatureBuffer, &sigBytes, tst_vec->msg, tst_vec->msgLen, tst_vec->privKey, tst_vec->keyLen, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with message = 0 and messageLength != 0\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, Esc_NULL_PTR, tst_vec->msgLen, signatureBuffer, sigBytes, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with context = 0 and contextLen != 0\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, Esc_NULL_PTR, 1U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with signature = 0\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, Esc_NULL_PTR, sigBytes, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with pubKey = 0\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes, Esc_NULL_PTR, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with with unsupported curveID\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, EscFeArith_CURVE_SECP_192, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_CURVE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with not supported hash algorithm\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes, tst_vec->pubKey, tst_vec->keyLen, 100U, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNSUPPORTED_DIGEST_TYPE );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with wrong length of the signature\n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes - 1U, tst_vec->pubKey, tst_vec->keyLen, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "EscEdDsa_SignatureVerification() with wrong length of public key \n" );
        returnCode = EscEdDsa_SignatureVerification( tst_vec->preHashed, tst_vec->msg, tst_vec->msgLen, signatureBuffer, sigBytes, tst_vec->pubKey, tst_vec->keyLen + 1U, tst_vec->digestType, tst_vec->curveId, tst_vec->context, tst_vec->contextLen );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }

    return returnCode;
}


Esc_ERROR
EscTstEdDsa_Perform(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;
    Esc_UINT16 numTests = (Esc_UINT16)(sizeof(EscEdDsa_allTestVectors) / sizeof(EscEdDsa_allTestVectors[0]));

    for (i=0U; (i < numTests) && (returnCode == Esc_NO_ERROR); i++)
    {
        /* Compliance test */
        returnCode = EscTstEdDsa_CompTestSignature(&EscEdDsa_allTestVectors[i]);
    }

    if ( returnCode == Esc_NO_ERROR)
    {
        /* Key Generation compliance test */
        returnCode = EscTstEdDsa_CompPubKeyDerivation(&EscEdDsa_allTestVectors[0]);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Public key derivation compliance test */
        returnCode = EscTstEdDsa_CompKeyGeneration(&EscEdDsa_allTestVectors[0]);
    }

    if ( returnCode == Esc_NO_ERROR)
    {
        /* Do the Ed25519-SHA-512 negative test with a vector with msg != NULL */
        Esc_ASSERT(1 < numTests);
        Esc_ASSERT(EscEdDsa_allTestVectors[1].msg != Esc_NULL_PTR);
        Esc_ASSERT(EscEdDsa_allTestVectors[1].curveId == EscEdDsa_CURVE_ED25519);
        Esc_ASSERT(EscEdDsa_allTestVectors[1].digestType == EscEdDsa_DIGEST_TYPE_SHA512);
        returnCode = EscTstEdDsa_NegativeTestSignature_Ed25519(&EscEdDsa_allTestVectors[1]);
    }

    if ( returnCode == Esc_NO_ERROR)
    {
        /* Key Generation Parameter Tests */
        returnCode = EscTstEdDsa_ParametersKey(&EscEdDsa_allTestVectors[0]);
    }

    if ( returnCode == Esc_NO_ERROR)
    {
        /* Public Key Derivation Parameter Tests */
        returnCode =  EscTstEdDsa_ParametersPubKeyDerivation(&EscEdDsa_allTestVectors[0]);
    }

    if ( returnCode == Esc_NO_ERROR)
    {
        /* Signature generation/verification parameter tests with a vector with msg != NULL */
        Esc_ASSERT(1 < numTests);
        Esc_ASSERT(EscEdDsa_allTestVectors[1].msg != Esc_NULL_PTR);
        returnCode = EscTstEdDsa_ParametersSignature(&EscEdDsa_allTestVectors[1]);
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
