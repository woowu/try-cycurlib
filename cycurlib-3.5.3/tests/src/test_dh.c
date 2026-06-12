/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       DH self test

   $Rev: 2226 $
 */
/***************************************************************************/

/***************************************************************************
    * 1. INCLUDES                                                             *
 ***************************************************************************/
/*lint -esym(9003,testcases) We allow local objects outside the block scope for large testvectors (increases readibility) */
/*lint -esym(9003,domainParam*) We allow local objects outside the block scope for large testvectors (increases readibility) */
#include "test_dh.h"
#include "test_random.h"

#include "selftest.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

typedef struct
{
    const Esc_UINT8 *ptr;
    Esc_UINT16 readIndex;
    Esc_UINT16 length;
} EscTstDh_ForwardRandomState;

/*
 * Test vectors taken from RFC 5115:
 * tools.ietf.org/html/rfc5114.html#appendix-A.1
 */
static const Esc_UINT8 domainParams1024p[] =
{
    0xB1U, 0x0BU, 0x8FU, 0x96U, 0xA0U, 0x80U, 0xE0U, 0x1DU, 0xDEU, 0x92U, 0xDEU, 0x5EU, 0xAEU, 0x5DU, 0x54U, 0xECU,
    0x52U, 0xC9U, 0x9FU, 0xBCU, 0xFBU, 0x06U, 0xA3U, 0xC6U, 0x9AU, 0x6AU, 0x9DU, 0xCAU, 0x52U, 0xD2U, 0x3BU, 0x61U,
    0x60U, 0x73U, 0xE2U, 0x86U, 0x75U, 0xA2U, 0x3DU, 0x18U, 0x98U, 0x38U, 0xEFU, 0x1EU, 0x2EU, 0xE6U, 0x52U, 0xC0U,
    0x13U, 0xECU, 0xB4U, 0xAEU, 0xA9U, 0x06U, 0x11U, 0x23U, 0x24U, 0x97U, 0x5CU, 0x3CU, 0xD4U, 0x9BU, 0x83U, 0xBFU,
    0xACU, 0xCBU, 0xDDU, 0x7DU, 0x90U, 0xC4U, 0xBDU, 0x70U, 0x98U, 0x48U, 0x8EU, 0x9CU, 0x21U, 0x9AU, 0x73U, 0x72U,
    0x4EU, 0xFFU, 0xD6U, 0xFAU, 0xE5U, 0x64U, 0x47U, 0x38U, 0xFAU, 0xA3U, 0x1AU, 0x4FU, 0xF5U, 0x5BU, 0xCCU, 0xC0U,
    0xA1U, 0x51U, 0xAFU, 0x5FU, 0x0DU, 0xC8U, 0xB4U, 0xBDU, 0x45U, 0xBFU, 0x37U, 0xDFU, 0x36U, 0x5CU, 0x1AU, 0x65U,
    0xE6U, 0x8CU, 0xFDU, 0xA7U, 0x6DU, 0x4DU, 0xA7U, 0x08U, 0xDFU, 0x1FU, 0xB2U, 0xBCU, 0x2EU, 0x4AU, 0x43U, 0x71U,
};

static const Esc_UINT8 domainParams1024g[] =
{
    0xA4U, 0xD1U, 0xCBU, 0xD5U, 0xC3U, 0xFDU, 0x34U, 0x12U, 0x67U, 0x65U, 0xA4U, 0x42U, 0xEFU, 0xB9U, 0x99U, 0x05U,
    0xF8U, 0x10U, 0x4DU, 0xD2U, 0x58U, 0xACU, 0x50U, 0x7FU, 0xD6U, 0x40U, 0x6CU, 0xFFU, 0x14U, 0x26U, 0x6DU, 0x31U,
    0x26U, 0x6FU, 0xEAU, 0x1EU, 0x5CU, 0x41U, 0x56U, 0x4BU, 0x77U, 0x7EU, 0x69U, 0x0FU, 0x55U, 0x04U, 0xF2U, 0x13U,
    0x16U, 0x02U, 0x17U, 0xB4U, 0xB0U, 0x1BU, 0x88U, 0x6AU, 0x5EU, 0x91U, 0x54U, 0x7FU, 0x9EU, 0x27U, 0x49U, 0xF4U,
    0xD7U, 0xFBU, 0xD7U, 0xD3U, 0xB9U, 0xA9U, 0x2EU, 0xE1U, 0x90U, 0x9DU, 0x0DU, 0x22U, 0x63U, 0xF8U, 0x0AU, 0x76U,
    0xA6U, 0xA2U, 0x4CU, 0x08U, 0x7AU, 0x09U, 0x1FU, 0x53U, 0x1DU, 0xBFU, 0x0AU, 0x01U, 0x69U, 0xB6U, 0xA2U, 0x8AU,
    0xD6U, 0x62U, 0xA4U, 0xD1U, 0x8EU, 0x73U, 0xAFU, 0xA3U, 0x2DU, 0x77U, 0x9DU, 0x59U, 0x18U, 0xD0U, 0x8BU, 0xC8U,
    0x85U, 0x8FU, 0x4DU, 0xCEU, 0xF9U, 0x7CU, 0x2AU, 0x24U, 0x85U, 0x5EU, 0x6EU, 0xEBU, 0x22U, 0xB3U, 0xB2U, 0xE5U,
};

static const EscTstDh_DomainParams domainParams1024 =
{
    domainParams1024p,
    (Esc_UINT16) sizeof(domainParams1024p),
    domainParams1024g,
    (Esc_UINT16) sizeof(domainParams1024g)
};

static const Esc_UINT8 privKeyA1024_0[] =
{
    0xB9U, 0xA3U, 0xB3U, 0xAEU, 0x8FU, 0xEFU, 0xC1U, 0xA2U, 0x93U, 0x04U, 0x96U, 0x50U, 0x70U, 0x86U, 0xF8U, 0x45U,
    0x5DU, 0x48U, 0x94U, 0x3EU
};

static const Esc_UINT8 pubKeyA1024_0[] =
{
    0x2AU, 0x85U, 0x3BU, 0x3DU, 0x92U, 0x19U, 0x75U, 0x01U, 0xB9U, 0x01U, 0x5BU, 0x2DU, 0xEBU, 0x3EU, 0xD8U, 0x4FU,
    0x5EU, 0x02U, 0x1DU, 0xCCU, 0x3EU, 0x52U, 0xF1U, 0x09U, 0xD3U, 0x27U, 0x3DU, 0x2BU, 0x75U, 0x21U, 0x28U, 0x1CU,
    0xBAU, 0xBEU, 0x0EU, 0x76U, 0xFFU, 0x57U, 0x27U, 0xFAU, 0x8AU, 0xCCU, 0xE2U, 0x69U, 0x56U, 0xBAU, 0x9AU, 0x1FU,
    0xCAU, 0x26U, 0xF2U, 0x02U, 0x28U, 0xD8U, 0x69U, 0x3FU, 0xEBU, 0x10U, 0x84U, 0x1DU, 0x84U, 0xA7U, 0x36U, 0x00U,
    0x54U, 0xECU, 0xE5U, 0xA7U, 0xF5U, 0xB7U, 0xA6U, 0x1AU, 0xD3U, 0xDFU, 0xB3U, 0xC6U, 0x0DU, 0x2EU, 0x43U, 0x10U,
    0x6DU, 0x87U, 0x27U, 0xDAU, 0x37U, 0xDFU, 0x9CU, 0xCEU, 0x95U, 0xB4U, 0x78U, 0x75U, 0x5DU, 0x06U, 0xBCU, 0xEAU,
    0x8FU, 0x9DU, 0x45U, 0x96U, 0x5FU, 0x75U, 0xA5U, 0xF3U, 0xD1U, 0xDFU, 0x37U, 0x01U, 0x16U, 0x5FU, 0xC9U, 0xE5U,
    0x0CU, 0x42U, 0x79U, 0xCEU, 0xB0U, 0x7FU, 0x98U, 0x95U, 0x40U, 0xAEU, 0x96U, 0xD5U, 0xD8U, 0x8EU, 0xD7U, 0x76U
};

static const Esc_UINT8 privKeyB1024_0[] =
{
    0x93U, 0x92U, 0xC9U, 0xF9U, 0xEBU, 0x6AU, 0x7AU, 0x6AU, 0x90U, 0x22U, 0xF7U, 0xD8U, 0x3EU, 0x72U, 0x23U, 0xC6U,
    0x83U, 0x5BU, 0xBDU, 0xDAU
};

static const Esc_UINT8 pubKeyB1024_0[] =
{
    0x71U, 0x7AU, 0x6CU, 0xB0U, 0x53U, 0x37U, 0x1FU, 0xF4U, 0xA3U, 0xB9U, 0x32U, 0x94U, 0x1CU, 0x1EU, 0x56U, 0x63U,
    0xF8U, 0x61U, 0xA1U, 0xD6U, 0xADU, 0x34U, 0xAEU, 0x66U, 0x57U, 0x6DU, 0xFBU, 0x98U, 0xF6U, 0xC6U, 0xCBU, 0xF9U,
    0xDDU, 0xD5U, 0xA5U, 0x6CU, 0x78U, 0x33U, 0xF6U, 0xBCU, 0xFDU, 0xFFU, 0x09U, 0x55U, 0x82U, 0xADU, 0x86U, 0x8EU,
    0x44U, 0x0EU, 0x8DU, 0x09U, 0xFDU, 0x76U, 0x9EU, 0x3CU, 0xECU, 0xCDU, 0xC3U, 0xD3U, 0xB1U, 0xE4U, 0xCFU, 0xA0U,
    0x57U, 0x77U, 0x6CU, 0xAAU, 0xF9U, 0x73U, 0x9BU, 0x6AU, 0x9FU, 0xEEU, 0x8EU, 0x74U, 0x11U, 0xF8U, 0xD6U, 0xDAU,
    0xC0U, 0x9DU, 0x6AU, 0x4EU, 0xDBU, 0x46U, 0xCCU, 0x2BU, 0x5DU, 0x52U, 0x03U, 0x09U, 0x0EU, 0xAEU, 0x61U, 0x26U,
    0x31U, 0x1EU, 0x53U, 0xFDU, 0x2CU, 0x14U, 0xB5U, 0x74U, 0xE6U, 0xA3U, 0x10U, 0x9AU, 0x3DU, 0xA1U, 0xBEU, 0x41U,
    0xBDU, 0xCEU, 0xAAU, 0x18U, 0x6FU, 0x5CU, 0xE0U, 0x67U, 0x16U, 0xA2U, 0xB6U, 0xA0U, 0x7BU, 0x3CU, 0x33U, 0xFEU
};

static const Esc_UINT8 sharedSecret1024_0[] =
{
    0x5CU, 0x80U, 0x4FU, 0x45U, 0x4DU, 0x30U, 0xD9U, 0xC4U, 0xDFU, 0x85U, 0x27U, 0x1FU, 0x93U, 0x52U, 0x8CU, 0x91U,
    0xDFU, 0x6BU, 0x48U, 0xABU, 0x5FU, 0x80U, 0xB3U, 0xB5U, 0x9CU, 0xAAU, 0xC1U, 0xB2U, 0x8FU, 0x8AU, 0xCBU, 0xA9U,
    0xCDU, 0x3EU, 0x39U, 0xF3U, 0xCBU, 0x61U, 0x45U, 0x25U, 0xD9U, 0x52U, 0x1DU, 0x2EU, 0x64U, 0x4CU, 0x53U, 0xB8U,
    0x07U, 0xB8U, 0x10U, 0xF3U, 0x40U, 0x06U, 0x2FU, 0x25U, 0x7DU, 0x7DU, 0x6FU, 0xBFU, 0xE8U, 0xD5U, 0xE8U, 0xF0U,
    0x72U, 0xE9U, 0xB6U, 0xE9U, 0xAFU, 0xDAU, 0x94U, 0x13U, 0xEAU, 0xFBU, 0x2EU, 0x8BU, 0x06U, 0x99U, 0xB1U, 0xFBU,
    0x5AU, 0x0CU, 0xACU, 0xEDU, 0xDEU, 0xAEU, 0xADU, 0x7EU, 0x9CU, 0xFBU, 0xB3U, 0x6AU, 0xE2U, 0xB4U, 0x20U, 0x83U,
    0x5BU, 0xD8U, 0x3AU, 0x19U, 0xFBU, 0x0BU, 0x5EU, 0x96U, 0xBFU, 0x8FU, 0xA4U, 0xD0U, 0x9EU, 0x34U, 0x55U, 0x25U,
    0x16U, 0x7EU, 0xCDU, 0x91U, 0x55U, 0x41U, 0x6FU, 0x46U, 0xF4U, 0x08U, 0xEDU, 0x31U, 0xB6U, 0x3CU, 0x6EU, 0x6DU
};

#if EscDh_KEY_BITS_MAX >= 2048U

/*
 * Tests taken from NIST CAVP (csrc.nist.gov/groups/STM/cavp/#06)
 * File: KASTestVectorsFFC2014/Test of 800-56A excluding KDF/FFC Static Scheme/KASValidityTest_FFCStatic_NOKC_ZZOnly_resp.fax
 */

static const Esc_UINT8 domainParams2048p[] =
{
    0xCAU, 0x60U, 0xD2U, 0x52U, 0x45U, 0xEFU, 0xBBU, 0xA8U, 0xC7U, 0xF6U, 0x1DU, 0x23U, 0x44U, 0xFDU, 0x69U, 0x2AU,
    0xA4U, 0x2DU, 0xF7U, 0x84U, 0x2BU, 0x83U, 0x13U, 0x1AU, 0xD8U, 0xE6U, 0xAFU, 0xD9U, 0x4FU, 0x51U, 0xADU, 0xF0U,
    0x1FU, 0xC7U, 0x9AU, 0x5DU, 0xB8U, 0x7CU, 0xE2U, 0xF7U, 0xC2U, 0x23U, 0x5FU, 0xECU, 0x41U, 0x6AU, 0xE9U, 0xD1U,
    0x26U, 0x8EU, 0x18U, 0x27U, 0xB1U, 0x79U, 0xA3U, 0x60U, 0x2AU, 0xDDU, 0x73U, 0x5DU, 0x16U, 0x7DU, 0x60U, 0x34U,
    0xCCU, 0x4FU, 0x6EU, 0x33U, 0x67U, 0x1EU, 0x6EU, 0x68U, 0xBBU, 0x53U, 0x40U, 0xFFU, 0xC7U, 0xE8U, 0x17U, 0x2EU,
    0xD1U, 0x83U, 0x88U, 0x1DU, 0x20U, 0xF7U, 0x73U, 0xE2U, 0x71U, 0xFFU, 0x5DU, 0xB5U, 0x52U, 0x4BU, 0xDCU, 0x3BU,
    0x8BU, 0xF3U, 0xEAU, 0x9EU, 0x50U, 0x5CU, 0x99U, 0x3CU, 0x78U, 0x79U, 0xB2U, 0xC3U, 0x57U, 0x5CU, 0x25U, 0xE0U,
    0xC6U, 0x68U, 0x00U, 0x26U, 0x69U, 0x98U, 0xECU, 0x45U, 0xA0U, 0xF8U, 0xFCU, 0xFBU, 0x44U, 0x88U, 0x4DU, 0x07U,
    0x15U, 0x6AU, 0xE6U, 0x3BU, 0x5BU, 0xE3U, 0x21U, 0x94U, 0x44U, 0x53U, 0xA5U, 0xC4U, 0x25U, 0x61U, 0x2AU, 0x6DU,
    0x76U, 0xD4U, 0x4FU, 0xDAU, 0x03U, 0x53U, 0x04U, 0x23U, 0xFFU, 0xE0U, 0x82U, 0x45U, 0xA8U, 0x67U, 0x02U, 0xF6U,
    0xB9U, 0xD7U, 0xBCU, 0x87U, 0x10U, 0x3CU, 0x40U, 0x94U, 0xD9U, 0xCBU, 0xB2U, 0xA6U, 0x9AU, 0x65U, 0x60U, 0x38U,
    0x6FU, 0x02U, 0x5CU, 0xEAU, 0x44U, 0x4CU, 0x27U, 0x79U, 0xA5U, 0x76U, 0xEFU, 0xDFU, 0xBEU, 0x47U, 0x02U, 0x09U,
    0xD0U, 0x91U, 0x60U, 0x9CU, 0x29U, 0xA3U, 0x32U, 0x14U, 0x02U, 0x99U, 0x3FU, 0x82U, 0x0AU, 0x67U, 0xDEU, 0x60U,
    0x44U, 0xA9U, 0xA3U, 0xEAU, 0xE9U, 0xC1U, 0x1DU, 0x88U, 0x2DU, 0xE1U, 0xC1U, 0x9AU, 0x8DU, 0xD8U, 0xF8U, 0xBDU,
    0xC4U, 0x19U, 0x3CU, 0x43U, 0x28U, 0x26U, 0xCAU, 0xC6U, 0x0BU, 0xEDU, 0x5EU, 0x69U, 0x1BU, 0x44U, 0x1AU, 0x4CU,
    0x69U, 0x95U, 0xD1U, 0xFEU, 0x31U, 0x17U, 0xA9U, 0x41U, 0x87U, 0x77U, 0xE7U, 0x67U, 0xAFU, 0xDCU, 0xDEU, 0xFFU,
};

static const Esc_UINT8 domainParams2048g[] =
{
    0x75U, 0x8DU, 0x43U, 0xFBU, 0x52U, 0x01U, 0x21U, 0xE1U, 0xADU, 0x3DU, 0x6AU, 0xF7U, 0x6EU, 0x9EU, 0x84U, 0xDAU,
    0x10U, 0x57U, 0x74U, 0x15U, 0x94U, 0xD1U, 0x4CU, 0xA7U, 0x5DU, 0x6CU, 0xA2U, 0x96U, 0x21U, 0x7DU, 0xF1U, 0x1FU,
    0x62U, 0xDBU, 0x87U, 0x03U, 0xF3U, 0xE2U, 0x12U, 0xC8U, 0xBBU, 0xD3U, 0x81U, 0xA9U, 0x61U, 0xA8U, 0x38U, 0x15U,
    0xF4U, 0x1EU, 0x41U, 0x35U, 0xC0U, 0x68U, 0xD2U, 0x74U, 0x17U, 0xD3U, 0x20U, 0xACU, 0xCEU, 0x62U, 0x85U, 0x39U,
    0x3DU, 0x8CU, 0x45U, 0x6BU, 0xF1U, 0x29U, 0x8CU, 0x29U, 0x54U, 0x54U, 0x26U, 0xEDU, 0xE5U, 0x1AU, 0xE1U, 0x29U,
    0x06U, 0x31U, 0x59U, 0xC9U, 0x46U, 0x7AU, 0xE7U, 0xFEU, 0xA7U, 0x58U, 0x64U, 0x86U, 0x3AU, 0x4BU, 0x2DU, 0x01U,
    0xFEU, 0xAFU, 0x6EU, 0x3DU, 0xA7U, 0x6CU, 0xAFU, 0x62U, 0xCFU, 0xDBU, 0x5DU, 0x63U, 0x75U, 0x1AU, 0x61U, 0x88U,
    0xF3U, 0x1BU, 0x11U, 0x91U, 0xF4U, 0x6CU, 0x0DU, 0xD1U, 0x41U, 0x07U, 0x9BU, 0x16U, 0xCFU, 0x54U, 0x5DU, 0x7CU,
    0x8DU, 0xB6U, 0x33U, 0x75U, 0x92U, 0x95U, 0xEFU, 0xEBU, 0x43U, 0x57U, 0xF8U, 0xC7U, 0xBBU, 0x23U, 0x00U, 0x6BU,
    0x5FU, 0x54U, 0x1EU, 0xB8U, 0xB7U, 0xD1U, 0x6FU, 0x8DU, 0x43U, 0xD6U, 0x5BU, 0x69U, 0x45U, 0x5EU, 0x15U, 0x97U,
    0x27U, 0xFAU, 0x28U, 0x1CU, 0xD8U, 0x0AU, 0x01U, 0xC4U, 0x37U, 0x69U, 0x22U, 0xA2U, 0xF0U, 0xDDU, 0xD3U, 0xE1U,
    0xF6U, 0x1FU, 0x42U, 0x29U, 0x7AU, 0x21U, 0x2FU, 0x9FU, 0x27U, 0xFDU, 0xE0U, 0xDEU, 0xD8U, 0x79U, 0x74U, 0xEBU,
    0x63U, 0xEBU, 0x1BU, 0xF3U, 0xF6U, 0x59U, 0x86U, 0xBCU, 0xE9U, 0x86U, 0x8AU, 0x88U, 0x59U, 0x01U, 0x96U, 0x77U,
    0x9FU, 0x95U, 0xE0U, 0x0AU, 0x87U, 0xBBU, 0x27U, 0x1AU, 0xB1U, 0x59U, 0xE0U, 0x9CU, 0x25U, 0x96U, 0xAEU, 0x58U,
    0xE5U, 0x07U, 0xABU, 0x28U, 0x5AU, 0x0BU, 0x0BU, 0x1CU, 0xF6U, 0x7AU, 0xACU, 0x8CU, 0x31U, 0xD5U, 0x1BU, 0xF8U,
    0xDAU, 0x4DU, 0x0EU, 0xF9U, 0x9CU, 0x7EU, 0x9DU, 0x5DU, 0x7CU, 0xFBU, 0x76U, 0x5FU, 0x75U, 0xCCU, 0x0AU, 0x63U,
};

static const EscTstDh_DomainParams domainParams2048 =
{
    domainParams2048p,
    (Esc_UINT16) sizeof(domainParams2048p),
    domainParams2048g,
    (Esc_UINT16) sizeof(domainParams2048g)
};

static const Esc_UINT8 privKeyA2048_0[] =
{
    0x90U, 0x17U, 0x29U, 0xDFU, 0xF8U, 0x2CU, 0x5CU, 0xFFU, 0xF8U, 0x87U, 0x14U, 0xE3U, 0x27U, 0xEAU, 0x3EU, 0xCCU,
    0x91U, 0xB1U, 0x96U, 0x69U, 0x7CU, 0x4AU, 0x21U, 0x4FU, 0xEEU, 0x61U, 0x42U, 0x22U,
};

static const Esc_UINT8 pubKeyA2048_0[] =
{
    0x8BU, 0xE4U, 0x2DU, 0x22U, 0xA5U, 0x95U, 0xC7U, 0xE0U, 0x0CU, 0x96U, 0xA1U, 0x7EU, 0x13U, 0x97U, 0x6CU, 0x91U,
    0xFDU, 0x8DU, 0xA0U, 0xB9U, 0xA6U, 0x7FU, 0xFCU, 0x5FU, 0x76U, 0x29U, 0x5CU, 0x07U, 0xDFU, 0x05U, 0x15U, 0x3DU,
    0x6CU, 0x4EU, 0xE1U, 0x4CU, 0xE3U, 0x73U, 0x1FU, 0x29U, 0x0FU, 0x3AU, 0xA0U, 0x6BU, 0xDDU, 0x35U, 0xE2U, 0xD5U,
    0xE0U, 0x69U, 0x22U, 0x7AU, 0x2EU, 0xEAU, 0x34U, 0xCBU, 0x0EU, 0x7CU, 0x83U, 0xD9U, 0x45U, 0x8AU, 0x9BU, 0x90U,
    0x4FU, 0x84U, 0xEFU, 0x08U, 0xCAU, 0xB7U, 0x28U, 0x1AU, 0xE6U, 0x8AU, 0x17U, 0xF1U, 0x8EU, 0x2AU, 0x18U, 0x32U,
    0x41U, 0xB6U, 0xF4U, 0xDDU, 0x7EU, 0xBAU, 0x7EU, 0xE2U, 0xB1U, 0xB2U, 0x72U, 0x79U, 0xEAU, 0x38U, 0xC6U, 0x85U,
    0x70U, 0xD9U, 0x74U, 0x70U, 0x20U, 0xD1U, 0x11U, 0xD5U, 0x59U, 0x63U, 0xA1U, 0x68U, 0x0AU, 0x87U, 0x0BU, 0xD9U,
    0x26U, 0x37U, 0xABU, 0xD2U, 0x4EU, 0x10U, 0x50U, 0xD9U, 0x65U, 0x84U, 0x82U, 0x3AU, 0x7EU, 0x22U, 0xEFU, 0x67U,
    0x5EU, 0x54U, 0x02U, 0x7DU, 0x20U, 0xBCU, 0xD7U, 0x1EU, 0xCAU, 0xB5U, 0xD2U, 0x09U, 0x3EU, 0x40U, 0x01U, 0xF8U,
    0x61U, 0x22U, 0x6BU, 0x39U, 0x85U, 0x63U, 0xA0U, 0x0BU, 0x88U, 0xD1U, 0xDBU, 0xFCU, 0xBAU, 0x12U, 0x31U, 0x5BU,
    0x92U, 0x85U, 0xEDU, 0x8CU, 0xBFU, 0x5DU, 0x18U, 0x3AU, 0x6FU, 0x27U, 0xC8U, 0x70U, 0x5BU, 0x2DU, 0x2DU, 0xA4U,
    0x56U, 0x35U, 0x82U, 0xB9U, 0xB6U, 0xC4U, 0x87U, 0x6FU, 0x3CU, 0xDCU, 0x6EU, 0x41U, 0xDDU, 0x59U, 0x3EU, 0x04U,
    0xBAU, 0xC5U, 0xA3U, 0xC4U, 0x59U, 0x8CU, 0xBEU, 0x3FU, 0x67U, 0xD3U, 0xBCU, 0x72U, 0x3DU, 0xE2U, 0xF1U, 0x3BU,
    0x48U, 0x47U, 0xB2U, 0x26U, 0x6BU, 0x7FU, 0x2AU, 0xE4U, 0xB7U, 0xF2U, 0xF3U, 0xC0U, 0x92U, 0xE0U, 0xFBU, 0x5CU,
    0x78U, 0xB6U, 0xD6U, 0x5AU, 0xFDU, 0x54U, 0x14U, 0x1EU, 0xC9U, 0xBAU, 0x29U, 0xECU, 0x60U, 0x7CU, 0xCDU, 0x8CU,
    0x13U, 0x29U, 0xBCU, 0xE1U, 0x66U, 0x02U, 0x9BU, 0x83U, 0x95U, 0x80U, 0x5EU, 0x6EU, 0x18U, 0x44U, 0x1CU, 0x97U,
};

static const Esc_UINT8 privKeyB2048_0[] =
{
    0x7AU, 0x0FU, 0xCBU, 0x52U, 0xB0U, 0x49U, 0x7AU, 0x68U, 0x30U, 0xA3U, 0xEFU, 0xE0U, 0x82U, 0x80U, 0x54U, 0xAAU,
    0x62U, 0x9FU, 0xC9U, 0x81U, 0x8BU, 0xB1U, 0x56U, 0x2CU, 0x4AU, 0x6BU, 0x1AU, 0xF6U,
};

static const Esc_UINT8 pubKeyB2048_0[] =
{
    0x3DU, 0xF2U, 0xF0U, 0x85U, 0xA4U, 0x34U, 0x91U, 0xC1U, 0x09U, 0x56U, 0x70U, 0x37U, 0xD6U, 0xD2U, 0x1FU, 0x75U,
    0xFFU, 0xF6U, 0xE1U, 0xB4U, 0x58U, 0xD8U, 0x1FU, 0x63U, 0xA2U, 0x9FU, 0x67U, 0x3CU, 0x67U, 0xF1U, 0xFCU, 0x64U,
    0x6FU, 0xA0U, 0x7AU, 0x93U, 0x8AU, 0x67U, 0x83U, 0x70U, 0xE2U, 0xC4U, 0x12U, 0xE2U, 0x24U, 0xD8U, 0xADU, 0x8CU,
    0xB5U, 0xD7U, 0xD0U, 0xD1U, 0xBDU, 0x2AU, 0x34U, 0x0DU, 0x07U, 0xD1U, 0x07U, 0x44U, 0x9DU, 0x7CU, 0x64U, 0x98U,
    0xC3U, 0x91U, 0x1CU, 0xB2U, 0x75U, 0x78U, 0x9FU, 0xEFU, 0x3EU, 0x27U, 0xC3U, 0x32U, 0x2CU, 0xADU, 0x23U, 0x76U,
    0xB7U, 0x4BU, 0xCEU, 0x8FU, 0xD0U, 0x45U, 0x83U, 0x1FU, 0x2DU, 0xB8U, 0x80U, 0x31U, 0x31U, 0xA6U, 0x50U, 0x2BU,
    0x7AU, 0x9BU, 0x6EU, 0x51U, 0x5EU, 0x93U, 0xC1U, 0x65U, 0x3CU, 0xC4U, 0x10U, 0xA2U, 0xFBU, 0xEAU, 0x6BU, 0xE0U,
    0xD0U, 0x5BU, 0x33U, 0x7FU, 0xE3U, 0xA9U, 0x92U, 0xD4U, 0xC8U, 0x71U, 0x81U, 0x5AU, 0xDBU, 0x32U, 0x18U, 0xD7U,
    0xBDU, 0x10U, 0xE2U, 0xBFU, 0x87U, 0x00U, 0x06U, 0xF4U, 0x56U, 0x58U, 0xC0U, 0xE8U, 0xE3U, 0xF1U, 0x5EU, 0x8EU,
    0x7BU, 0xD6U, 0x7CU, 0xCDU, 0x10U, 0x4BU, 0xF2U, 0x44U, 0x5BU, 0x26U, 0x81U, 0xA2U, 0x73U, 0x9EU, 0xFFU, 0xA2U,
    0x34U, 0xDCU, 0x56U, 0x7AU, 0xFEU, 0xECU, 0xE9U, 0xC4U, 0xA1U, 0xDEU, 0xBDU, 0xBBU, 0x0CU, 0x61U, 0x55U, 0x39U,
    0xEEU, 0xB7U, 0x56U, 0xB7U, 0xD4U, 0x96U, 0x6EU, 0xC8U, 0x35U, 0x4DU, 0x7AU, 0xDDU, 0x58U, 0x12U, 0xABU, 0xFDU,
    0xFDU, 0xD3U, 0xFBU, 0x82U, 0xB2U, 0x84U, 0xE0U, 0x0CU, 0x3CU, 0xBEU, 0x11U, 0xC1U, 0x95U, 0xB8U, 0x5AU, 0xEFU,
    0x81U, 0x8CU, 0x90U, 0xF0U, 0x22U, 0x05U, 0x75U, 0xE3U, 0xEBU, 0x62U, 0x9AU, 0x52U, 0x51U, 0x4BU, 0x25U, 0x42U,
    0x5BU, 0xD0U, 0x1CU, 0xB3U, 0x90U, 0x90U, 0x58U, 0x74U, 0xC2U, 0x41U, 0xD3U, 0xC9U, 0xDCU, 0x77U, 0x1AU, 0x35U,
    0x96U, 0x94U, 0xD7U, 0xBCU, 0x6BU, 0xACU, 0x42U, 0xB3U, 0xABU, 0xABU, 0xD7U, 0x80U, 0x05U, 0xA6U, 0x36U, 0x0CU,
};

static const Esc_UINT8 sharedSecret2048_0[] =
{
    0x8AU, 0x5BU, 0x80U, 0x88U, 0x67U, 0x61U, 0xBCU, 0xFEU, 0x35U, 0xC5U, 0x0BU, 0xD1U, 0x6AU, 0x52U, 0x95U, 0xD8U,
    0x80U, 0x71U, 0xADU, 0x11U, 0xD8U, 0x20U, 0x1BU, 0x0DU, 0xCAU, 0xC8U, 0x3DU, 0x18U, 0x36U, 0xC0U, 0x60U, 0x3EU,
    0x1CU, 0xEDU, 0x6AU, 0x7EU, 0x07U, 0x4EU, 0x57U, 0xCDU, 0x2BU, 0xC0U, 0x09U, 0xA7U, 0x47U, 0x23U, 0xA8U, 0x8FU,
    0x2DU, 0xDAU, 0x65U, 0x01U, 0x10U, 0xF2U, 0xB5U, 0xAFU, 0x80U, 0x05U, 0xF5U, 0xD5U, 0xB4U, 0x80U, 0x5CU, 0xA8U,
    0x16U, 0x9EU, 0xE7U, 0x38U, 0xC1U, 0x88U, 0xBEU, 0x53U, 0x3CU, 0x4FU, 0xACU, 0x44U, 0x4FU, 0xC7U, 0x0DU, 0xD2U,
    0x80U, 0xAAU, 0xD6U, 0xCBU, 0x81U, 0x8EU, 0xCEU, 0xE4U, 0x08U, 0xF7U, 0x55U, 0x6DU, 0xFBU, 0x0BU, 0x0AU, 0xF4U,
    0xF0U, 0x7BU, 0x26U, 0xD8U, 0x1DU, 0xC2U, 0x03U, 0x7AU, 0x3FU, 0xDFU, 0x57U, 0xF0U, 0xD2U, 0x03U, 0x73U, 0xB0U,
    0xE6U, 0x34U, 0x62U, 0xE2U, 0x0EU, 0xA5U, 0xBBU, 0x94U, 0x81U, 0x57U, 0x2DU, 0xD1U, 0xB2U, 0xB5U, 0xEFU, 0x26U,
    0x3DU, 0xD8U, 0x81U, 0x48U, 0xE8U, 0x71U, 0xE4U, 0x8EU, 0x81U, 0x46U, 0xCEU, 0xEBU, 0xC4U, 0x9DU, 0x98U, 0x6DU,
    0xC7U, 0x9FU, 0x42U, 0x68U, 0x3EU, 0xE0U, 0xD6U, 0x47U, 0x90U, 0xF4U, 0xCAU, 0xC7U, 0x9AU, 0x85U, 0x78U, 0x01U,
    0x69U, 0xDFU, 0x50U, 0xD2U, 0xEBU, 0x68U, 0xA6U, 0xFDU, 0x76U, 0xA9U, 0xC1U, 0x9BU, 0x20U, 0x25U, 0x47U, 0x01U,
    0xD0U, 0x98U, 0x08U, 0xC5U, 0xA0U, 0x72U, 0x84U, 0x5CU, 0x46U, 0x78U, 0x45U, 0xB4U, 0x92U, 0x87U, 0x53U, 0x39U,
    0x6CU, 0x18U, 0x43U, 0x40U, 0x7AU, 0xCAU, 0xCFU, 0x2BU, 0x6DU, 0x8DU, 0x9EU, 0x1FU, 0x6BU, 0x07U, 0xE9U, 0xE2U,
    0x72U, 0xD5U, 0x53U, 0x76U, 0x2EU, 0x4CU, 0xF8U, 0xC1U, 0x6DU, 0xA2U, 0xFBU, 0x68U, 0x3BU, 0x74U, 0xC2U, 0x10U,
    0x72U, 0x2CU, 0x4FU, 0xE5U, 0x76U, 0xA2U, 0x52U, 0x35U, 0x31U, 0x62U, 0xF9U, 0xA6U, 0x90U, 0xDEU, 0x6BU, 0x76U,
    0xF2U, 0x9DU, 0xB8U, 0xB8U, 0xF5U, 0x56U, 0x94U, 0x2AU, 0x57U, 0x49U, 0x9CU, 0xE3U, 0x10U, 0x45U, 0x93U, 0x51U
};

#endif

#if EscDh_KEY_BITS_MAX >= 3072U

/*
 * Test vectors generated with Bouncy Castle using MODP-3072 domain parameters
 */

static const Esc_UINT8 domainParams3072_p[] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xC9U, 0x0FU, 0xDAU, 0xA2U, 0x21U, 0x68U, 0xC2U, 0x34U,
    0xC4U, 0xC6U, 0x62U, 0x8BU, 0x80U, 0xDCU, 0x1CU, 0xD1U, 0x29U, 0x02U, 0x4EU, 0x08U, 0x8AU, 0x67U, 0xCCU, 0x74U,
    0x02U, 0x0BU, 0xBEU, 0xA6U, 0x3BU, 0x13U, 0x9BU, 0x22U, 0x51U, 0x4AU, 0x08U, 0x79U, 0x8EU, 0x34U, 0x04U, 0xDDU,
    0xEFU, 0x95U, 0x19U, 0xB3U, 0xCDU, 0x3AU, 0x43U, 0x1BU, 0x30U, 0x2BU, 0x0AU, 0x6DU, 0xF2U, 0x5FU, 0x14U, 0x37U,
    0x4FU, 0xE1U, 0x35U, 0x6DU, 0x6DU, 0x51U, 0xC2U, 0x45U, 0xE4U, 0x85U, 0xB5U, 0x76U, 0x62U, 0x5EU, 0x7EU, 0xC6U,
    0xF4U, 0x4CU, 0x42U, 0xE9U, 0xA6U, 0x37U, 0xEDU, 0x6BU, 0x0BU, 0xFFU, 0x5CU, 0xB6U, 0xF4U, 0x06U, 0xB7U, 0xEDU,
    0xEEU, 0x38U, 0x6BU, 0xFBU, 0x5AU, 0x89U, 0x9FU, 0xA5U, 0xAEU, 0x9FU, 0x24U, 0x11U, 0x7CU, 0x4BU, 0x1FU, 0xE6U,
    0x49U, 0x28U, 0x66U, 0x51U, 0xECU, 0xE4U, 0x5BU, 0x3DU, 0xC2U, 0x00U, 0x7CU, 0xB8U, 0xA1U, 0x63U, 0xBFU, 0x05U,
    0x98U, 0xDAU, 0x48U, 0x36U, 0x1CU, 0x55U, 0xD3U, 0x9AU, 0x69U, 0x16U, 0x3FU, 0xA8U, 0xFDU, 0x24U, 0xCFU, 0x5FU,
    0x83U, 0x65U, 0x5DU, 0x23U, 0xDCU, 0xA3U, 0xADU, 0x96U, 0x1CU, 0x62U, 0xF3U, 0x56U, 0x20U, 0x85U, 0x52U, 0xBBU,
    0x9EU, 0xD5U, 0x29U, 0x07U, 0x70U, 0x96U, 0x96U, 0x6DU, 0x67U, 0x0CU, 0x35U, 0x4EU, 0x4AU, 0xBCU, 0x98U, 0x04U,
    0xF1U, 0x74U, 0x6CU, 0x08U, 0xCAU, 0x18U, 0x21U, 0x7CU, 0x32U, 0x90U, 0x5EU, 0x46U, 0x2EU, 0x36U, 0xCEU, 0x3BU,
    0xE3U, 0x9EU, 0x77U, 0x2CU, 0x18U, 0x0EU, 0x86U, 0x03U, 0x9BU, 0x27U, 0x83U, 0xA2U, 0xECU, 0x07U, 0xA2U, 0x8FU,
    0xB5U, 0xC5U, 0x5DU, 0xF0U, 0x6FU, 0x4CU, 0x52U, 0xC9U, 0xDEU, 0x2BU, 0xCBU, 0xF6U, 0x95U, 0x58U, 0x17U, 0x18U,
    0x39U, 0x95U, 0x49U, 0x7CU, 0xEAU, 0x95U, 0x6AU, 0xE5U, 0x15U, 0xD2U, 0x26U, 0x18U, 0x98U, 0xFAU, 0x05U, 0x10U,
    0x15U, 0x72U, 0x8EU, 0x5AU, 0x8AU, 0xAAU, 0xC4U, 0x2DU, 0xADU, 0x33U, 0x17U, 0x0DU, 0x04U, 0x50U, 0x7AU, 0x33U,
    0xA8U, 0x55U, 0x21U, 0xABU, 0xDFU, 0x1CU, 0xBAU, 0x64U, 0xECU, 0xFBU, 0x85U, 0x04U, 0x58U, 0xDBU, 0xEFU, 0x0AU,
    0x8AU, 0xEAU, 0x71U, 0x57U, 0x5DU, 0x06U, 0x0CU, 0x7DU, 0xB3U, 0x97U, 0x0FU, 0x85U, 0xA6U, 0xE1U, 0xE4U, 0xC7U,
    0xABU, 0xF5U, 0xAEU, 0x8CU, 0xDBU, 0x09U, 0x33U, 0xD7U, 0x1EU, 0x8CU, 0x94U, 0xE0U, 0x4AU, 0x25U, 0x61U, 0x9DU,
    0xCEU, 0xE3U, 0xD2U, 0x26U, 0x1AU, 0xD2U, 0xEEU, 0x6BU, 0xF1U, 0x2FU, 0xFAU, 0x06U, 0xD9U, 0x8AU, 0x08U, 0x64U,
    0xD8U, 0x76U, 0x02U, 0x73U, 0x3EU, 0xC8U, 0x6AU, 0x64U, 0x52U, 0x1FU, 0x2BU, 0x18U, 0x17U, 0x7BU, 0x20U, 0x0CU,
    0xBBU, 0xE1U, 0x17U, 0x57U, 0x7AU, 0x61U, 0x5DU, 0x6CU, 0x77U, 0x09U, 0x88U, 0xC0U, 0xBAU, 0xD9U, 0x46U, 0xE2U,
    0x08U, 0xE2U, 0x4FU, 0xA0U, 0x74U, 0xE5U, 0xABU, 0x31U, 0x43U, 0xDBU, 0x5BU, 0xFCU, 0xE0U, 0xFDU, 0x10U, 0x8EU,
    0x4BU, 0x82U, 0xD1U, 0x20U, 0xA9U, 0x3AU, 0xD2U, 0xCAU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
};

static const Esc_UINT8 domainParams3072_g[] =
{
    0x02U,
};

static const EscTstDh_DomainParams domainParams3072 =
{
    domainParams3072_p,
    (Esc_UINT16) sizeof(domainParams3072_p),
    domainParams3072_g,
    (Esc_UINT16) sizeof(domainParams3072_g)
};

static const Esc_UINT8 privKeyA3072_0[] =
{
    0xA3U, 0x0EU, 0xD0U, 0x33U, 0xDAU, 0xC6U, 0x8DU, 0x9BU, 0x36U, 0x80U, 0x2CU, 0x8DU, 0x32U, 0x57U, 0x98U, 0x0EU,
    0x84U, 0x32U, 0x6AU, 0x2DU, 0x07U, 0x62U, 0x12U, 0x6BU, 0xC5U, 0x87U, 0x4BU, 0xA5U, 0xD4U, 0x44U, 0xF3U, 0xD9U,
};

static const Esc_UINT8 pubKeyA3072_0[] =
{
    0xE0U, 0x04U, 0xF4U, 0x90U, 0xE8U, 0x08U, 0x27U, 0x70U, 0x4BU, 0xACU, 0x90U, 0xAFU, 0x0BU, 0x2DU, 0x1CU, 0xE0U,
    0x6EU, 0x6DU, 0xB4U, 0x3CU, 0x15U, 0x46U, 0x84U, 0x9EU, 0x65U, 0x8BU, 0xA7U, 0x72U, 0x0DU, 0xF8U, 0xE3U, 0xCEU,
    0x05U, 0xD6U, 0x39U, 0xEEU, 0x3DU, 0x8DU, 0xB5U, 0x13U, 0x64U, 0xFBU, 0xFFU, 0x25U, 0x05U, 0x22U, 0x9AU, 0x16U,
    0x78U, 0x2BU, 0x16U, 0xE4U, 0x32U, 0x5EU, 0x26U, 0x10U, 0x01U, 0xA4U, 0x33U, 0x2FU, 0x4CU, 0x9FU, 0xBDU, 0xB8U,
    0xFEU, 0x03U, 0x3CU, 0xEFU, 0x85U, 0xDAU, 0x10U, 0xB1U, 0x7AU, 0xCEU, 0x44U, 0x90U, 0xC5U, 0xFCU, 0xD2U, 0x75U,
    0x13U, 0x6EU, 0x51U, 0x95U, 0xB8U, 0xC8U, 0x2EU, 0xAFU, 0x11U, 0x86U, 0x23U, 0x9BU, 0xD1U, 0x40U, 0xDEU, 0xA7U,
    0x70U, 0xB3U, 0x88U, 0x17U, 0xD5U, 0x4DU, 0xF3U, 0x7AU, 0xE3U, 0x31U, 0xF1U, 0xEAU, 0x1BU, 0x79U, 0x3AU, 0x74U,
    0xD3U, 0x15U, 0x4DU, 0x72U, 0xA9U, 0x0CU, 0x92U, 0xE1U, 0x6FU, 0x5CU, 0x5BU, 0xD1U, 0x2DU, 0x7FU, 0xC5U, 0x45U,
    0xC1U, 0x2EU, 0xEFU, 0xB0U, 0x11U, 0xD7U, 0x4FU, 0x2AU, 0xE8U, 0x3CU, 0xECU, 0x9FU, 0x41U, 0x4AU, 0x0FU, 0x3EU,
    0x3DU, 0xBFU, 0xCEU, 0xE2U, 0x58U, 0x79U, 0xD0U, 0x22U, 0xD5U, 0xFBU, 0x5FU, 0xF7U, 0x8DU, 0x93U, 0x4FU, 0x93U,
    0x1AU, 0xD9U, 0x49U, 0x5AU, 0x1AU, 0x40U, 0x4DU, 0x34U, 0xF0U, 0xD3U, 0x18U, 0xCEU, 0x35U, 0xBEU, 0x19U, 0x61U,
    0x21U, 0x90U, 0xE2U, 0xDEU, 0x59U, 0x05U, 0x4EU, 0xEAU, 0x2CU, 0x6FU, 0xD5U, 0x56U, 0xABU, 0xB2U, 0x06U, 0x8FU,
    0x5EU, 0xB4U, 0xE0U, 0x60U, 0x5CU, 0xC8U, 0x8BU, 0x25U, 0x28U, 0x6CU, 0x4CU, 0xEAU, 0xB0U, 0xFDU, 0xA2U, 0xEDU,
    0xA3U, 0x12U, 0x91U, 0x7EU, 0xE2U, 0xA5U, 0xFAU, 0x15U, 0x2AU, 0xDDU, 0x16U, 0x86U, 0x17U, 0xF2U, 0xB8U, 0x73U,
    0x69U, 0x40U, 0xF0U, 0xBBU, 0x40U, 0xA3U, 0xCDU, 0x41U, 0xADU, 0x61U, 0x2AU, 0x86U, 0xB0U, 0xFAU, 0x82U, 0xB0U,
    0x5FU, 0xD6U, 0xA7U, 0x2BU, 0x7FU, 0xA8U, 0x44U, 0xA6U, 0x86U, 0x80U, 0x0BU, 0xF4U, 0x97U, 0xE6U, 0xA0U, 0x24U,
    0x3AU, 0x01U, 0xF7U, 0x28U, 0x31U, 0xF1U, 0xCDU, 0x7EU, 0x9FU, 0xC4U, 0x9EU, 0x1CU, 0xBBU, 0xE0U, 0xDFU, 0xFDU,
    0x26U, 0xB8U, 0xC3U, 0x3CU, 0x02U, 0x5EU, 0x9AU, 0xA9U, 0x1FU, 0x4EU, 0xE2U, 0xD5U, 0x40U, 0x29U, 0x10U, 0xE8U,
    0x96U, 0xCFU, 0x4BU, 0x0BU, 0x79U, 0xD5U, 0x1DU, 0x70U, 0xFFU, 0xC7U, 0x9DU, 0x55U, 0xB7U, 0x6EU, 0x46U, 0x29U,
    0x89U, 0xACU, 0x2EU, 0x78U, 0xF2U, 0x78U, 0x24U, 0x09U, 0xE5U, 0xDAU, 0xE4U, 0x29U, 0x8DU, 0x1DU, 0x9FU, 0x97U,
    0xB4U, 0x3AU, 0x60U, 0xD0U, 0xAEU, 0x00U, 0x5EU, 0x58U, 0x1AU, 0x93U, 0x62U, 0x1CU, 0x79U, 0xB1U, 0x35U, 0x55U,
    0xBFU, 0xCBU, 0x1AU, 0xCAU, 0x11U, 0x3FU, 0xEFU, 0x23U, 0x33U, 0x07U, 0x7CU, 0x87U, 0xC2U, 0x85U, 0xC5U, 0xFAU,
    0xE2U, 0x06U, 0xA5U, 0xD0U, 0x81U, 0xF5U, 0x89U, 0xDDU, 0x0BU, 0x93U, 0xB1U, 0x8FU, 0xF7U, 0xD3U, 0xE9U, 0xF1U,
    0x93U, 0x95U, 0x3DU, 0x70U, 0x64U, 0xB4U, 0xADU, 0x2FU, 0x4CU, 0xABU, 0x3DU, 0x7FU, 0x21U, 0x76U, 0x87U, 0x08U,
};

static const Esc_UINT8 privKeyB3072_0[] =
{
    0x80U, 0xF9U, 0x66U, 0xE4U, 0x44U, 0x8CU, 0x15U, 0xABU, 0x32U, 0x73U, 0xE6U, 0x69U, 0x10U, 0xF5U, 0x95U, 0xFCU,
    0x28U, 0x13U, 0x58U, 0x90U, 0x6BU, 0x8EU, 0x48U, 0xA0U, 0xADU, 0x80U, 0x66U, 0x6EU, 0x46U, 0xF1U, 0x2DU, 0x7CU,
};

static const Esc_UINT8 pubKeyB3072_0[] =
{
    0xECU, 0x39U, 0x2AU, 0x86U, 0x99U, 0x85U, 0xE5U, 0xA4U, 0x02U, 0x1CU, 0x8AU, 0x73U, 0x77U, 0xA6U, 0x52U, 0x47U,
    0x4BU, 0x3EU, 0xB7U, 0xC7U, 0x8BU, 0xFEU, 0xABU, 0xC5U, 0xA0U, 0x94U, 0x84U, 0xB2U, 0x54U, 0xDEU, 0xAFU, 0x74U,
    0xB3U, 0x96U, 0x1BU, 0xE2U, 0x21U, 0x0AU, 0xB4U, 0xDBU, 0x6AU, 0x46U, 0x1EU, 0x0FU, 0xE7U, 0x10U, 0x87U, 0x63U,
    0xCBU, 0xCFU, 0x67U, 0x48U, 0xC2U, 0x51U, 0x90U, 0x95U, 0x3DU, 0x88U, 0x40U, 0xD6U, 0x10U, 0x9FU, 0xE1U, 0xBCU,
    0x69U, 0xE2U, 0x7BU, 0x21U, 0xB2U, 0x4CU, 0x96U, 0xBEU, 0xD9U, 0xCBU, 0x5EU, 0x7CU, 0xDBU, 0xCAU, 0x0EU, 0x2AU,
    0x88U, 0xA5U, 0x22U, 0x8EU, 0xA4U, 0x0AU, 0x31U, 0xB0U, 0x35U, 0x54U, 0xDAU, 0x92U, 0x71U, 0x1EU, 0xFFU, 0x59U,
    0xE8U, 0x57U, 0xFEU, 0x7AU, 0xB0U, 0xACU, 0x30U, 0x13U, 0xE9U, 0xC7U, 0x5FU, 0xF4U, 0x00U, 0xC2U, 0xB6U, 0x9FU,
    0x03U, 0x68U, 0xC9U, 0x40U, 0xB1U, 0xB5U, 0x36U, 0xC9U, 0x3EU, 0x51U, 0x8DU, 0xBFU, 0xA6U, 0x5DU, 0x04U, 0x89U,
    0x8EU, 0x8BU, 0x16U, 0xB4U, 0x93U, 0x96U, 0x20U, 0x53U, 0xB1U, 0xF4U, 0x54U, 0xB4U, 0x2EU, 0xAFU, 0x29U, 0x16U,
    0xF4U, 0xE4U, 0xBDU, 0x2FU, 0xCBU, 0x43U, 0xABU, 0x25U, 0x19U, 0xD4U, 0xE1U, 0x15U, 0xF7U, 0x1FU, 0xDCU, 0x6BU,
    0x79U, 0xA2U, 0x6DU, 0x2FU, 0x3AU, 0x88U, 0x3AU, 0x2EU, 0x18U, 0x80U, 0xA0U, 0xB9U, 0xEBU, 0xF5U, 0x04U, 0xD2U,
    0xCDU, 0xA3U, 0xBEU, 0xD9U, 0x15U, 0x60U, 0x44U, 0xD2U, 0xE4U, 0x34U, 0xA0U, 0x3AU, 0x8CU, 0xE8U, 0xB2U, 0x98U,
    0x2CU, 0xAAU, 0xEAU, 0x36U, 0x7CU, 0xD7U, 0x5BU, 0x0CU, 0x6AU, 0xAFU, 0x33U, 0xF3U, 0x04U, 0x39U, 0x41U, 0xD4U,
    0x33U, 0xE1U, 0x10U, 0xACU, 0x48U, 0xB4U, 0x74U, 0x5CU, 0x51U, 0x7EU, 0xEDU, 0xC2U, 0xCDU, 0xCAU, 0x1BU, 0x72U,
    0x45U, 0xF9U, 0x5AU, 0x62U, 0xC4U, 0x97U, 0xDAU, 0x30U, 0x12U, 0xC5U, 0x87U, 0xD5U, 0x6EU, 0x33U, 0x44U, 0xAFU,
    0x7AU, 0xEFU, 0x19U, 0xEAU, 0xF7U, 0x76U, 0x4CU, 0x1FU, 0x26U, 0xF3U, 0x77U, 0x89U, 0xC0U, 0xE0U, 0x37U, 0x31U,
    0x2CU, 0xE3U, 0x4EU, 0xE8U, 0x8EU, 0xAEU, 0x3FU, 0x57U, 0xA9U, 0x6DU, 0xBCU, 0x1AU, 0xB1U, 0x64U, 0xA9U, 0x69U,
    0x64U, 0x36U, 0xAEU, 0x88U, 0xC5U, 0x86U, 0xB3U, 0xF7U, 0x0FU, 0x2FU, 0x08U, 0xA1U, 0x4FU, 0xC6U, 0xA9U, 0x34U,
    0xD7U, 0x55U, 0x7BU, 0x28U, 0xEDU, 0xD8U, 0x84U, 0x34U, 0x9EU, 0xBFU, 0x24U, 0x68U, 0x08U, 0x8FU, 0x84U, 0xCFU,
    0x1EU, 0x5EU, 0x46U, 0x2CU, 0x41U, 0x5AU, 0x43U, 0x70U, 0x34U, 0x12U, 0x3EU, 0x39U, 0xBAU, 0xF2U, 0x38U, 0x55U,
    0x8CU, 0x1CU, 0x50U, 0x8BU, 0xB9U, 0x17U, 0x73U, 0xA6U, 0xF8U, 0xC4U, 0x41U, 0x6BU, 0x4CU, 0x94U, 0x9DU, 0xF6U,
    0xFFU, 0x34U, 0x4FU, 0x88U, 0x2EU, 0x2FU, 0x70U, 0x12U, 0x8EU, 0xB5U, 0x8DU, 0xA1U, 0xD5U, 0x3AU, 0xE9U, 0x19U,
    0x2CU, 0x5BU, 0x78U, 0x51U, 0x79U, 0x57U, 0xD9U, 0x76U, 0x81U, 0x3CU, 0x86U, 0xBCU, 0xB1U, 0x27U, 0x5CU, 0x44U,
    0x9CU, 0x64U, 0xFFU, 0x3AU, 0xDFU, 0xBCU, 0xA5U, 0xEBU, 0x78U, 0xDDU, 0x9BU, 0x0FU, 0x75U, 0x7FU, 0x0BU, 0x7FU,
};

static const Esc_UINT8 sharedSecret3072_0[] =
{
    0x0DU, 0xA5U, 0xAAU, 0x8FU, 0xC6U, 0x7EU, 0x94U, 0xD5U, 0xE0U, 0xA0U, 0xBFU, 0x44U, 0x95U, 0xA4U, 0xD7U, 0xDDU,
    0x8AU, 0xC9U, 0x48U, 0x7AU, 0x4FU, 0x86U, 0x3CU, 0x50U, 0xA3U, 0x82U, 0x90U, 0x83U, 0x44U, 0x2DU, 0x63U, 0x90U,
    0xB8U, 0x21U, 0x1FU, 0x54U, 0xE2U, 0x37U, 0x07U, 0xC9U, 0xAEU, 0xBBU, 0xA3U, 0x50U, 0x40U, 0x82U, 0x51U, 0xD8U,
    0x38U, 0x7FU, 0x4FU, 0x7BU, 0x16U, 0x2BU, 0x0BU, 0x89U, 0x57U, 0xB6U, 0x26U, 0xC3U, 0x1BU, 0xD1U, 0x88U, 0x93U,
    0xF4U, 0xE9U, 0x83U, 0x01U, 0xC9U, 0x64U, 0x6CU, 0xC5U, 0x44U, 0xA1U, 0x82U, 0xCDU, 0xB2U, 0xCFU, 0x85U, 0x68U,
    0xA9U, 0xE3U, 0x5AU, 0xB4U, 0x03U, 0x98U, 0x67U, 0x34U, 0xB6U, 0x08U, 0x72U, 0x82U, 0xDBU, 0x31U, 0xB8U, 0x60U,
    0xF3U, 0x39U, 0x5FU, 0x3BU, 0x21U, 0x41U, 0xAEU, 0x30U, 0xBDU, 0x17U, 0x75U, 0x13U, 0x85U, 0x27U, 0x48U, 0xE0U,
    0x33U, 0xB0U, 0x04U, 0x9BU, 0xA3U, 0x61U, 0x33U, 0xA2U, 0x39U, 0x1DU, 0xABU, 0x38U, 0x89U, 0x4AU, 0x31U, 0x89U,
    0x41U, 0xE9U, 0x74U, 0x37U, 0x74U, 0xDDU, 0x37U, 0xFCU, 0x64U, 0xF0U, 0xCEU, 0x89U, 0x40U, 0x93U, 0xE7U, 0x89U,
    0x1CU, 0xC0U, 0x29U, 0x0FU, 0x86U, 0x7BU, 0xE3U, 0x5BU, 0xB1U, 0x83U, 0x5CU, 0xF3U, 0xEBU, 0x56U, 0xDCU, 0x36U,
    0x18U, 0xDDU, 0x1FU, 0x9BU, 0x53U, 0x8AU, 0xE0U, 0xFBU, 0xABU, 0x68U, 0xB2U, 0x21U, 0xA7U, 0x00U, 0x98U, 0xC8U,
    0x70U, 0x69U, 0xB7U, 0xA4U, 0x72U, 0x41U, 0x3AU, 0x9AU, 0x4DU, 0x31U, 0x0AU, 0x4FU, 0xDAU, 0xA8U, 0xD4U, 0x08U,
    0x1EU, 0xE5U, 0x01U, 0xC3U, 0xB7U, 0x1FU, 0xC6U, 0x7BU, 0x28U, 0x2DU, 0x6BU, 0x2AU, 0x8AU, 0x7EU, 0x68U, 0x5DU,
    0x16U, 0x0DU, 0xE6U, 0x76U, 0xDEU, 0xD3U, 0x58U, 0xE8U, 0x83U, 0x0FU, 0x37U, 0x6EU, 0xD7U, 0x82U, 0x2BU, 0xADU,
    0x0DU, 0xE7U, 0x6EU, 0xBBU, 0x1FU, 0x31U, 0xCBU, 0xECU, 0x1FU, 0x24U, 0x6BU, 0x63U, 0x21U, 0xDAU, 0xD0U, 0x2EU,
    0xEDU, 0xCAU, 0x63U, 0xE0U, 0xA2U, 0xE8U, 0x3DU, 0xCFU, 0x75U, 0xCAU, 0xC0U, 0x15U, 0x3BU, 0xFAU, 0xFFU, 0x0EU,
    0x2DU, 0xE2U, 0x4FU, 0x7AU, 0x66U, 0xCEU, 0x51U, 0xA5U, 0x73U, 0xD9U, 0x3DU, 0xF4U, 0xC1U, 0x62U, 0x4BU, 0xEBU,
    0x04U, 0x6BU, 0xBBU, 0x8CU, 0xA8U, 0x0CU, 0x38U, 0x63U, 0x3EU, 0x1BU, 0xFCU, 0x12U, 0xA8U, 0xF6U, 0xACU, 0x19U,
    0x04U, 0xD0U, 0xCDU, 0xB4U, 0x20U, 0x64U, 0x9CU, 0x2CU, 0xC8U, 0x6FU, 0xE9U, 0x6EU, 0xFAU, 0x09U, 0xB0U, 0xF5U,
    0x87U, 0xDFU, 0xDFU, 0xF3U, 0xC6U, 0x3AU, 0x78U, 0x11U, 0x74U, 0x6EU, 0x14U, 0x76U, 0xB1U, 0x31U, 0x19U, 0x9CU,
    0x93U, 0xDDU, 0x86U, 0x00U, 0xEFU, 0x4BU, 0xFDU, 0x18U, 0x6FU, 0xC1U, 0x6FU, 0x41U, 0x2BU, 0xADU, 0x5CU, 0xB2U,
    0xA6U, 0x2CU, 0xDBU, 0x89U, 0x22U, 0x4CU, 0x09U, 0xEFU, 0xE5U, 0xBEU, 0xF0U, 0x0EU, 0xBDU, 0xD1U, 0xD0U, 0x98U,
    0x3FU, 0x83U, 0xD6U, 0xBAU, 0xC5U, 0x60U, 0x50U, 0x86U, 0x91U, 0x54U, 0x45U, 0xD8U, 0xA3U, 0x5FU, 0x15U, 0xF8U,
    0x04U, 0x0AU, 0x79U, 0x70U, 0x44U, 0xB7U, 0x96U, 0x00U, 0xF5U, 0xACU, 0x97U, 0xE8U, 0x73U, 0x82U, 0xA6U, 0x8FU,
};

#endif

static const EscTstDh_TestcaseT testcases[] =
{
    {
        /* domain parameters */
        &domainParams1024,

        /* private key A */
        privKeyA1024_0,
        (Esc_UINT16) sizeof(privKeyA1024_0),

        /* public key A */
        pubKeyA1024_0,
        (Esc_UINT16) sizeof(pubKeyA1024_0),

        /* private key B */
        privKeyB1024_0,
        (Esc_UINT16) sizeof(privKeyB1024_0),

        /* public key B */
        pubKeyB1024_0,
        (Esc_UINT16) sizeof(pubKeyB1024_0),

        /* shared secret */
        sharedSecret1024_0,
        (Esc_UINT16) sizeof(sharedSecret1024_0)
    },

#if EscDh_KEY_BITS_MAX >= 2048U
    {
        /* domain parameters */
        &domainParams2048,

        /* private key A */
        privKeyA2048_0,
        (Esc_UINT16) sizeof(privKeyA2048_0),

        /* public key A */
        pubKeyA2048_0,
        (Esc_UINT16) sizeof(pubKeyA2048_0),

        /* private key B */
        privKeyB2048_0,
        (Esc_UINT16) sizeof(privKeyB2048_0),

        /* public key B */
        pubKeyB2048_0,
        (Esc_UINT16) sizeof(pubKeyB2048_0),

        /* shared secret */
        sharedSecret2048_0,
        (Esc_UINT16) sizeof(sharedSecret2048_0)
    },
#endif

#if EscDh_KEY_BITS_MAX >= 3072U
    {
        /* domain parameters */
        &domainParams3072,

        /* private key A */
        privKeyA3072_0,
        (Esc_UINT16) sizeof(privKeyA3072_0),

        /* public key A */
        pubKeyA3072_0,
        (Esc_UINT16) sizeof(pubKeyA3072_0),

        /* private key B */
        privKeyB3072_0,
        (Esc_UINT16) sizeof(privKeyB3072_0),

        /* public key B */
        pubKeyB3072_0,
        (Esc_UINT16) sizeof(pubKeyB3072_0),

        /* shared secret */
        sharedSecret3072_0,
        (Esc_UINT16) sizeof(sharedSecret3072_0)
    },
#endif

};

static const EscTstDh_DomainParams *domainParameters[] =
{
    &domainParams1024,
#if EscDh_KEY_BITS_MAX >= 2048U
    &domainParams2048,
#endif
#if EscDh_KEY_BITS_MAX >= 3072U
    &domainParams3072,
#endif
};

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/

/* A test PRNG which always returns the same data cyclically. For example,
 * if the PRNG is seed with the bytes 01 02 03 04 and 10 bytes are requested
 * then the following is returned: 01 02 03 04 01 02 03 04 01 02
 */
static void
EscTstDh_ForwardRandomInit(
    EscTstDh_ForwardRandomState *state,
    const Esc_UINT8 *ptr,
    Esc_UINT16 length);

static Esc_ERROR
EscTstDh_ForwardRandomGet(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );

/* A test PRNG which always returns the error Esc_RNG_MUST_BE_RESEEDED.
 * Furthermore, a flag is set if the PRNG is called. This is used to check
 * that the PRNG is NOT called if the key generation's input is already broken.
 */
static Esc_ERROR
EscTstDh_DoNotCallPrng(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len );


static void
EscTstDh_FindFirstNonZeroByte(
    const Esc_UINT8 buffer[],
    Esc_UINT16 length,
    const Esc_UINT8 **nonZeroStart,
    Esc_UINT16 *nonZeroLength);

static Esc_ERROR
EscTstDh_ComputeSharedSecret(
    const EscTstDh_TestcaseT *testcase,
    const EscDh_DomainParametersT *dhCtx,
    const Esc_UINT8 pubKeyBytes[],
    Esc_UINT16 lengthPubKey,
    const Esc_UINT8 privKeyBytes[],
    Esc_UINT16 lengthPrivKey);

/* Compute the shared secret and check if it matches the reference value */
static Esc_ERROR
EscTstDh_KnownAnswerTest(
    void );

/* Call DH function with invalid parameters */
static Esc_ERROR
EscTstDh_InvalidParams(
    void );

/***************************************************************************
 * 4. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static void
EscTstDh_ForwardRandomInit(
    EscTstDh_ForwardRandomState *state,
    const Esc_UINT8 *ptr,
    Esc_UINT16 length)
{
    state->ptr = ptr;
    state->length = length;
    state->readIndex = 0U;
}

static Esc_ERROR
EscTstDh_ForwardRandomGet(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
/*lint -save -e9087 -e9079 The Lint warning about Rule 11.3 is a false/positive. We cast a void pointer to object.
  Therefore we violate the cast from void pointer to object type rule (11.5, adv.) intentionally.
  This cast is safe since the void pointer is only for interface compatibility and points to the casted type. */
    EscTstDh_ForwardRandomState *state = (EscTstDh_ForwardRandomState *)prngState;
/*lint -restore */
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 i;
    Esc_UINT16 readIndex = state->readIndex;

    for (i = 0U; i < len; ++i)
    {
        if (readIndex == state->length)
        {
            readIndex = 0U;
        }

        rnd[i] = state->ptr[readIndex];
        readIndex++;
    }

    state->readIndex = readIndex;
    return returnCode;
}

static Esc_ERROR
EscTstDh_DoNotCallPrng(
    void* prngState,
    Esc_UINT8 rnd[],
    const Esc_UINT32 len )
{
    /*lint -save -e9079 We violate the cast from void pointer to object type rule (11.5, adv.) intentionally.
      This cast is safe since the void pointer is only for interface compatibility and points to the casted type. */
    Esc_BOOL *wasCalled = (Esc_BOOL *)prngState;
    *wasCalled = TRUE;

    Esc_UNUSED_PARAM(rnd);
    Esc_UNUSED_PARAM(len);

    return Esc_RNG_MUST_BE_RESEEDED;
}

static void
EscTstDh_FindFirstNonZeroByte(
    const Esc_UINT8 buffer[],
    Esc_UINT16 length,
    const Esc_UINT8 **nonZeroStart,
    Esc_UINT16 *nonZeroLength)
{
    Esc_UINT16 i;
    Esc_UINT16 startIndex = 0U;

    *nonZeroLength = length;

    for (i = 0U; i < length; i++)
    {
        if (buffer[startIndex] != 0U)
        {
            break;
        }

        startIndex++;
        (*nonZeroLength)--;
    }

    *nonZeroStart = &buffer[startIndex];
}

static Esc_ERROR
EscTstDh_ComputeSharedSecret(
    const EscTstDh_TestcaseT *testcase,
    const EscDh_DomainParametersT *dhCtx,
    const Esc_UINT8 pubKeyBytes[],
    Esc_UINT16 lengthPubKey,
    const Esc_UINT8 privKeyBytes[],
    Esc_UINT16 lengthPrivKey)
{
    Esc_ERROR returnCode;

    EscDh_PublicKeyT publicKey;
    EscDh_PrivateKeyT privateKey;

    Esc_UINT8 buffer[EscDh_KEY_BYTES_MAX];
    Esc_UINT16 lengthZ = 0U;
    Esc_UINT16 lengthKey = 0U;

    EscTst_PrintString("Convert public key\n");

    returnCode = EscDh_PubKeyFromBytes(dhCtx, &publicKey, pubKeyBytes, lengthPubKey);
    returnCode = EscTst_CheckResultSuccess(returnCode);

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("Convert private key\n");

        returnCode = EscDh_PrivKeyFromBytes(dhCtx, &privateKey, privKeyBytes, lengthPrivKey);
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("Compute shared secret\n");

        returnCode = EscDh_ComputeSharedSecret(dhCtx, buffer, &lengthZ, &publicKey, &privateKey);
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Skip leading zeros that may appear in the reference result */
        const Esc_UINT8 *refSecretStart;
        Esc_UINT16 refSecretLength = 0U;

        EscTstDh_FindFirstNonZeroByte(
            &testcase->sharedSecret[0],
            testcase->lengthSharedSecret,
            &refSecretStart,
            &refSecretLength);

        if ( (refSecretLength != lengthZ) ||
             (EscTst_Memcmp( buffer, refSecretStart, (Esc_UINT32) refSecretLength ) == FALSE) )
        {
            EscTst_PrintString( "The shared secrets do not match the testcase!\n" );
            EscTst_PrintArray("Expected Shared Secret", refSecretStart, refSecretLength);
            EscTst_PrintArray("Got Shared Secret", buffer, lengthZ);

            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("Export public key\n");

        returnCode = EscDh_BytesFromPubKey(dhCtx, &publicKey, buffer, &lengthKey);
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Skip leading zeros that may appear in the reference result */
        const Esc_UINT8 *refPubKeyStart;
        Esc_UINT16 refPubKeyLength = 0U;

        EscTstDh_FindFirstNonZeroByte(
            pubKeyBytes,
            lengthPubKey,
            &refPubKeyStart,
            &refPubKeyLength);

        if ( (refPubKeyLength != lengthKey) ||
             (EscTst_Memcmp( buffer, refPubKeyStart, (Esc_UINT32) refPubKeyLength ) == FALSE) )
        {
            EscTst_PrintString( "The exported public key does not match the testcase!\n" );
            EscTst_PrintArray("Reference key", refPubKeyStart, refPubKeyLength);
            EscTst_PrintArray("Exported key", buffer, lengthKey);

            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("Export private key\n");

        returnCode = EscDh_BytesFromPrivKey(dhCtx, &privateKey, buffer, &lengthKey);
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Skip leading zeros that may appear in the reference result */
        const Esc_UINT8 *refPrivKeyStart;
        Esc_UINT16 refPrivKeyLength = 0U;

        EscTstDh_FindFirstNonZeroByte(
            privKeyBytes,
            lengthPrivKey,
            &refPrivKeyStart,
            &refPrivKeyLength);

        if ( (refPrivKeyLength != lengthKey) ||
             (EscTst_Memcmp( buffer, refPrivKeyStart, (Esc_UINT32) refPrivKeyLength ) == FALSE) )
        {
            EscTst_PrintString( "The exported private key does not match the testcase!\n" );
            EscTst_PrintArray("Reference key", refPrivKeyStart, refPrivKeyLength);
            EscTst_PrintArray("Exported key", buffer, lengthKey);

            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

Esc_ERROR
EscTstDh_KnownAnswerTestcase(
    const EscTstDh_TestcaseT *testcase)
{
    Esc_ERROR returnCode;
    EscDh_DomainParametersT dhCtx;

    EscTst_PrintString("Initializing domain parameters\n");

    returnCode = EscDh_InitDomainParameters(
            &dhCtx,
            testcase->param->p,
            testcase->param->pLength,
            testcase->param->g,
            testcase->param->gLength);

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("...OK!\n\n");
        EscTst_PrintString("Compute Shared Secret using public key A and private key B\n");

        returnCode = EscTstDh_ComputeSharedSecret(
                testcase,
                &dhCtx,
                testcase->pubA,
                testcase->lengthPubA,
                testcase->privB,
                testcase->lengthPrivB);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("...OK!\n\n");
        EscTst_PrintString("Compute Shared Secret using public key B and private key A\n");

        returnCode = EscTstDh_ComputeSharedSecret(
                testcase,
                &dhCtx,
                testcase->pubB,
                testcase->lengthPubB,
                testcase->privA,
                testcase->lengthPrivA);
    }

    return returnCode;
}

Esc_ERROR
EscTstDh_ConsistencyTest(
    const EscTstDh_DomainParams * const domainParams[],
    Esc_UINT16 numParams,
    Esc_UINT16 numIterations)
{
    Esc_ERROR returnCode;

    Esc_UINT16 i;
    Esc_UINT16 n;
    EscDh_DomainParametersT dhCtx;

    EscDh_PublicKeyT publicKeyA;
    EscDh_PublicKeyT publicKeyB;
    EscDh_PrivateKeyT privateKeyA;
    EscDh_PrivateKeyT privateKeyB;

    Esc_UINT8 sharedSecretA[EscDh_KEY_BYTES_MAX];
    Esc_UINT8 sharedSecretB[EscDh_KEY_BYTES_MAX];
    Esc_UINT16 lengthSecretA;
    Esc_UINT16 lengthSecretB;

    EscTstRandom_ContextT rndCtx;
    Esc_UINT8 seed[EscTstRandom_RND_LENGTH];

    EscTst_PrintString("DH Consistency Test\n");
    EscTst_PrintString( "****************************************\n\n" );

    /* Create some dummy seed and initialize the dummy PRNG from that */

    for (i = 0U; i < EscTstRandom_RND_LENGTH; i++)
    {
        seed[i] = (Esc_UINT8) i;
    }

    returnCode = EscTstRandom_Init(&rndCtx, seed);

    for (n = 0U; (returnCode == Esc_NO_ERROR) && (n < numIterations); n++)
    {
        for (i = 0U; (returnCode == Esc_NO_ERROR) && (i < numParams); i++)
        {
            const EscTstDh_DomainParams *params = domainParams[i];

            EscTst_PrintString("Initializing domain parameters\n");

            returnCode = EscDh_InitDomainParameters(
                    &dhCtx,
                    params->p,
                    params->pLength,
                    params->g,
                    params->gLength);

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString("...OK!\n\n");
                EscTst_PrintString("Generating key pair for A\n");

                /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
                returnCode = EscDh_KeyGeneration(
                        &dhCtx,
                        EscTstRandom_GetRandom,
                        (void *) &rndCtx,
                        &publicKeyA,
                        &privateKeyA );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString("...OK!\n\n");
                EscTst_PrintString("Generating key pair for B\n");

                /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
                returnCode = EscDh_KeyGeneration(
                        &dhCtx,
                        EscTstRandom_GetRandom,
                        (void *) &rndCtx,
                        &publicKeyB,
                        &privateKeyB );
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString("...OK!\n\n");
                EscTst_PrintString("Compute shared secret for A\n");

                returnCode = EscDh_ComputeSharedSecret(
                        &dhCtx,
                        sharedSecretA,
                        &lengthSecretA,
                        &publicKeyB,
                        &privateKeyA);
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString("...OK!\n\n");
                EscTst_PrintString("Compute shared secret for B\n");

                returnCode = EscDh_ComputeSharedSecret(
                        &dhCtx,
                        sharedSecretB,
                        &lengthSecretB,
                        &publicKeyA,
                        &privateKeyB);
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString("...OK!\n\n");
                /*lint -e{644} lengthSecretA and lengthSecretB are initialized */
                if ( (lengthSecretA != lengthSecretB) ||
                     (EscTst_Memcmp( sharedSecretA, sharedSecretB, (Esc_UINT32) lengthSecretA ) == FALSE) )
                {
                    EscTst_PrintString( "The shared secrets do not match!\n\n\n" );
                    EscTst_PrintArray("Shared secret A", sharedSecretA, lengthSecretA);
                    EscTst_PrintArray("Shared secret B", sharedSecretB, lengthSecretB);

                    returnCode = Esc_KAT_FAILED;
                }

            }
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstDh_KnownAnswerTest(
    void)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 numTestcases = (Esc_UINT16) sizeof(testcases) / (Esc_UINT16) sizeof(testcases[0]);
    Esc_UINT16 i;

    EscTst_PrintString("DH Known Answer Test (KAT)\n");
    EscTst_PrintString( "****************************************\n\n" );

    for (i = 0U; (i < numTestcases) && (returnCode == Esc_NO_ERROR); ++i)
    {
        EscTst_PrintWord("Testcase", i);
        returnCode = EscTstDh_KnownAnswerTestcase(&testcases[i]);
    }

    return returnCode;
}

static Esc_ERROR
EscTstDh_InvalidParams(
    void )
{
    Esc_ERROR returnCode;

    Esc_UINT8 buffer[EscDh_KEY_BYTES_MAX];
    Esc_UINT16 i;

    EscDh_DomainParametersT ctx;
    EscDh_PublicKeyT publicKey;
    EscDh_PrivateKeyT privateKey;

    Esc_UINT16 lengthZ = 0U;
    Esc_UINT16 lengthKey = 0U;

    EscTstDh_ForwardRandomState rngState;
    Esc_BOOL wasCalled = FALSE;

    static const Esc_UINT8 zeroBytes[] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U };

    static const Esc_UINT8 groupOrder[] =
    {
        0xF5U, 0x18U, 0xAAU, 0x87U, 0x81U, 0xA8U, 0xDFU, 0x27U, 0x8AU, 0xBAU, 0x4EU, 0x7DU, 0x64U, 0xB7U, 0xCBU, 0x9DU,
        0x49U, 0x46U, 0x23U, 0x53U
    };

    /************************ EscDh_InitDomainParameters *********************/

    EscTst_PrintString("DH Parameter Test\n");
    EscTst_PrintString( "****************************************\n\n" );

    EscTst_PrintString( "EscDh_InitDomainParameters\n" );

    EscTst_PrintString( "- ctx == NULL\n");
    returnCode = EscDh_InitDomainParameters(
            Esc_NULL_PTR,
            domainParams1024.p,
            domainParams1024.pLength,
            domainParams1024.g,
            domainParams1024.gLength);
    returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- p == NULL\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                Esc_NULL_PTR,
                domainParams1024.pLength,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- g == NULL\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                Esc_NULL_PTR,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- pLength == 0\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                0U,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- pLength > EscDh_KEY_BYTES_MAX\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                (Esc_UINT16)(EscDh_KEY_BYTES_MAX + 1U),
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- 0 < pLength < EscDh_KEY_BYTES_MAX, but not in [128, 256, 384]\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                127U,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- gLength == 0\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                domainParams1024.g,
                0U);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- gLength > EscDh_KEY_BYTES_MAX\n");
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                domainParams1024.g,
                (Esc_UINT16)(EscDh_KEY_BYTES_MAX + 1U));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- g = 0\n");
        for (i = 0U; i < (Esc_UINT16) sizeof(buffer); i++)
        {
            buffer[i] = 0U;
        }

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                buffer,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- g = 1\n");
        buffer[domainParams1024.gLength - 1U] = 1U;

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                buffer,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- g = (p-1)\n");

        /* We simply copy p and decrement the least significant to get g = (p-1).
         * The following assertions must hold true such that this can work.
         */
        Esc_ASSERT(domainParams1024.pLength == domainParams1024.gLength);
        Esc_ASSERT(domainParams1024.pLength > 0U);
        Esc_ASSERT(domainParams1024.p[domainParams1024.pLength - 1U] > 0U);

        for (i = 0U; i < domainParams1024.gLength; i++)
        {
            buffer[i] = domainParams1024.p[i];
        }
        /*lint -e{771} Buffer is initialized iff returnCode == Esc_NO_ERROR which is checked above. */
        buffer[domainParams1024.gLength - 1U]--;

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                buffer,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- p is even\n");
        for (i = 0U; i < domainParams1024.pLength; i++)
        {
            buffer[i] = domainParams1024.p[i];
        }
        buffer[domainParams1024.pLength - 1U] &= 0xFEU;

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                buffer,
                domainParams1024.pLength,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- most significant byte of p are zero\n");
        for (i = 0U; i < domainParams1024.pLength; i++)
        {
            buffer[i] = domainParams1024.p[i];
        }
        buffer[0] = 0U;

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                buffer,
                domainParams1024.pLength,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- most significant two bytes of p are zero\n");
        buffer[1] = 0U;

        returnCode = EscDh_InitDomainParameters(
                &ctx,
                buffer,
                domainParams1024.pLength,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    /* Call EscDh_InitDomainParameters() with correct parameters to have a
     * correctly initialized context.
     */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_InitDomainParameters(
                &ctx,
                domainParams1024.p,
                domainParams1024.pLength,
                domainParams1024.g,
                domainParams1024.gLength);
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    /************************ EscDh_KeyGeneration ****************************/

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_KeyGeneration\n");
        EscTst_PrintString("- ctx == NULL\n");

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                Esc_NULL_PTR,
                EscTstDh_DoNotCallPrng,
                (void *) &wasCalled,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);

        if (wasCalled)
        {
            EscTst_PrintString("PRNG was called unexpectedly!");
            returnCode = Esc_NEGATIVE_TEST_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- prngFunc == NULL\n");

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                Esc_NULL_PTR,
                (void *) &wasCalled,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- publicKey == NULL\n");

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                EscTstDh_DoNotCallPrng,
                (void *) &wasCalled,
                Esc_NULL_PTR,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);

        if (wasCalled)
        {
            EscTst_PrintString("PRNG was called unexpectedly!");
            returnCode = Esc_NEGATIVE_TEST_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- privateKey == NULL\n");

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                EscTstDh_DoNotCallPrng,
                (void *) &wasCalled,
                &publicKey,
                Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);

        if (wasCalled != FALSE)
        {
            EscTst_PrintString("PRNG was called unexpectedly!");
            returnCode = Esc_NEGATIVE_TEST_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- PRNG returns an error\n");

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                EscTstDh_DoNotCallPrng,
                (void *) &wasCalled,
                &publicKey,
                &privateKey);

        /* We expect that the error code from the PRNG is returned */
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_RNG_MUST_BE_RESEEDED);

        if (wasCalled == FALSE)
        {
            EscTst_PrintString("PRNG was not called!");
            returnCode = Esc_NEGATIVE_TEST_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- PRNG returns only zero-bytes\n");

        EscTstDh_ForwardRandomInit(&rngState, zeroBytes, (Esc_UINT16) sizeof(zeroBytes));

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                EscTstDh_ForwardRandomGet,
                (void *) &rngState,
                &publicKey,
                &privateKey);

        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_KEY_GENERATION_FAILED);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- PRNG returns the group order (lets public key generation fail)\n");

        EscTstDh_ForwardRandomInit(&rngState, groupOrder, (Esc_UINT16) sizeof(groupOrder));

        /*lint --e(9087) We violate Rule 11.3 (req.) here. Pointer cast is required for interface compatibility. Cast is safe since the void pointer is casted back before using. */
        returnCode = EscDh_KeyGeneration(
                &ctx,
                EscTstDh_ForwardRandomGet,
                (void *) &rngState,
                &publicKey,
                &privateKey);

        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_KEY_GENERATION_FAILED);
    }

    /************************ EscDh_ComputeSharedSecret **********************/

    /* Initialize public and private key with valid data */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PubKeyFromBytes(&ctx, &publicKey, pubKeyA1024_0, (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PrivKeyFromBytes(&ctx, &privateKey, privKeyB1024_0, (Esc_UINT16) sizeof(privKeyB1024_0));
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_ComputeSharedSecret\n");
        EscTst_PrintString("- ctx == NULL\n");

        returnCode = EscDh_ComputeSharedSecret(
                Esc_NULL_PTR,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- z == NULL\n");

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                Esc_NULL_PTR,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- zLength == NULL\n");

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                Esc_NULL_PTR,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- publicKey == NULL\n");

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                Esc_NULL_PTR,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- privateKey == NULL\n");

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals p)\n");

        /* The conversion function also checks if public key < p. Therefore, we must
         * ignore the return value here.
         */
        (void) EscDh_PubKeyFromBytes(&ctx, &publicKey, domainParams1024.p, domainParams1024.pLength);

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals 0)\n");
        for (i = 0U; i < EscDh_DH_SIZE_WORDS_MAX; i++)
        {
            publicKey.words[i] = 0U;
        }

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals 1)\n");
        publicKey.words[0] = 1U;

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    /* Re-initialize public key with valid data */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PubKeyFromBytes(&ctx, &publicKey, pubKeyA1024_0, (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid private key (private key = 0)\n");
        for (i = 0U; i < EscDh_DH_SIZE_WORDS_MAX; i++)
        {
            privateKey.words[i] = 0U;
        }

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PRIVATE_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid private key (private key = 1)\n");
        privateKey.words[0] = 1U;

        returnCode = EscDh_ComputeSharedSecret(
                &ctx,
                buffer,
                &lengthZ,
                &publicKey,
                &privateKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PRIVATE_KEY);
    }

    /************************ EscDh_PrivKeyFromBytes *************************/

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_PrivKeyFromBytes\n");
        EscTst_PrintString("- ctx == NULL\n");

        returnCode = EscDh_PrivKeyFromBytes(
                Esc_NULL_PTR,
                &privateKey,
                privKeyB1024_0,
                (Esc_UINT16) sizeof(privKeyB1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- privateKey == NULL\n");

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                Esc_NULL_PTR,
                privKeyB1024_0,
                (Esc_UINT16) sizeof(privKeyB1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytes == NULL\n");

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                &privateKey,
                Esc_NULL_PTR,
                (Esc_UINT16) sizeof(privKeyB1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytesLength == 0\n");

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                &privateKey,
                privKeyB1024_0,
                0U);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytesLength > EscDh_KEY_BYTES_MAX\n");

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                &privateKey,
                privKeyB1024_0,
                (Esc_UINT16)(EscDh_KEY_BYTES_MAX + 1U));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid private key (equals 0)\n");

        for (i = 0U; i < domainParams1024.pLength; i++)
        {
            buffer[i] = 0U;
        }

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                &privateKey,
                buffer,
                domainParams1024.pLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PRIVATE_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid private key (equals 1)\n");
        buffer[domainParams1024.pLength - 1U] = 1U;

        returnCode = EscDh_PrivKeyFromBytes(
                &ctx,
                &privateKey,
                buffer,
                domainParams1024.pLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PRIVATE_KEY);
    }

    /************************ EscDh_PubKeyFromBytes *************************/

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_PubKeyFromBytes\n");
        EscTst_PrintString("- ctx == NULL\n");

        returnCode = EscDh_PubKeyFromBytes(
                Esc_NULL_PTR,
                &publicKey,
                pubKeyA1024_0,
                (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- publicKey == NULL\n");

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                Esc_NULL_PTR,
                pubKeyA1024_0,
                (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytes == NULL\n");

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                Esc_NULL_PTR,
                (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytesLength == 0\n");

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                pubKeyA1024_0,
                0U);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytesLength > EscDh_KEY_BYTES_MAX\n");

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                pubKeyA1024_0,
                (Esc_UINT16)(EscDh_KEY_BYTES_MAX + 1U));
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PARAMETER);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals p)\n");
        for (i = 0U; i < domainParams1024.pLength; i++)
        {
            buffer[i] = domainParams1024.p[i];
        }

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                buffer,
                domainParams1024.pLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals 0)\n");
        for (i = 0U; i < domainParams1024.pLength; i++)
        {
            buffer[i] = 0U;
        }

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                buffer,
                domainParams1024.pLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- invalid public key (equals 1)\n");
        buffer[domainParams1024.pLength - 1U] = 0U;

        returnCode = EscDh_PubKeyFromBytes(
                &ctx,
                &publicKey,
                buffer,
                domainParams1024.pLength);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_INVALID_PUBLIC_KEY);
    }

    /************************ EscDh_BytesFromPrivKey *************************/

    /* Convert a valid private key first */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PrivKeyFromBytes(&ctx, &privateKey, privKeyB1024_0, (Esc_UINT16) sizeof(privKeyB1024_0));
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_BytesFromPrivKey\n");
        EscTst_PrintString("- ctx == NULL\n");

        returnCode = EscDh_BytesFromPrivKey(
                Esc_NULL_PTR,
                &privateKey,
                buffer,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- privateKey == NULL\n");

        returnCode = EscDh_BytesFromPrivKey(
                &ctx,
                Esc_NULL_PTR,
                buffer,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytes == NULL\n");

        returnCode = EscDh_BytesFromPrivKey(
                &ctx,
                &privateKey,
                Esc_NULL_PTR,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyLength == NULL\n");

        returnCode = EscDh_BytesFromPrivKey(
                &ctx,
                &privateKey,
                buffer,
                Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }


    /************************ EscDh_BytesFromPubKey *************************/

    /* Convert a valid public key first */

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscDh_PubKeyFromBytes(&ctx, &publicKey, pubKeyA1024_0, (Esc_UINT16) sizeof(pubKeyA1024_0));
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("EscDh_BytesFromPubKey\n");
        EscTst_PrintString("- ctx == NULL\n");

        returnCode = EscDh_BytesFromPubKey(
                Esc_NULL_PTR,
                &publicKey,
                buffer,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- publicKey == NULL\n");

        returnCode = EscDh_BytesFromPubKey(
                &ctx,
                Esc_NULL_PTR,
                buffer,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyBytes == NULL\n");

        returnCode = EscDh_BytesFromPubKey(
                &ctx,
                &publicKey,
                Esc_NULL_PTR,
                &lengthKey);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString("- keyLength == NULL\n");

        returnCode = EscDh_BytesFromPubKey(
                &ctx,
                &publicKey,
                buffer,
                Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed(&returnCode, Esc_NULL_POINTER_ERROR);
    }

    return returnCode;
}

Esc_ERROR
EscTstDh_Perform(
    void )
{
    Esc_ERROR returnCode;

    returnCode = EscTstDh_InvalidParams();

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstDh_KnownAnswerTest();
    }

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT16 numParams = (Esc_UINT16) sizeof(domainParameters) / (Esc_UINT16) sizeof(domainParameters[0]);

        returnCode = EscTstDh_ConsistencyTest(domainParameters, numParams, 1U);
    }

    return returnCode;
}

/***************************************************************************
 * 5. END                                                                  *
 ***************************************************************************/
