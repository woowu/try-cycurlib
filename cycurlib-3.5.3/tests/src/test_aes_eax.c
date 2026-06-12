/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES-EAX Selftest.

   Encrypts/Decrypts a given plaintext/ciphertext and checks if the result matches
   a precalculated ciphertext/plaintext pattern.


   $Rev: 3678 $
 */
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "aes_eax.h"
#include "selftest.h"
#include "test_aes_eax.h"
/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#define EscAesEax_NUMBER_OF_TESTCASES   8U
#define EscTstAesEax_MAX_BUFFER_SIZE    120U

#if EscAes_MAX_KEY_BITS == 128U
#   define EscTstAesEax_NUM_KEYSIZES    1U
#elif EscAes_MAX_KEY_BITS == 192U
#   define EscTstAesEax_NUM_KEYSIZES    2U
#elif EscAes_MAX_KEY_BITS == 256U
#   define EscTstAesEax_NUM_KEYSIZES    3U
#else
#   error "Invalid AES key size"
#endif

/***************************************************************************
 * 3. DECLARATIONS                                                          *
 ***************************************************************************/
static const Esc_UINT16 keySizes[] =
{
    128U,
    192U,
    256U
};

typedef struct
{
    Esc_UINT8 tst_key[EscAes_MAX_KEY_BYTES];
    Esc_UINT8 tst_payload[100];
    Esc_UINT32 tst_len_payload;
    Esc_UINT8 tst_nonce[100];
    Esc_UINT8 tst_len_nonce;
    Esc_UINT8 tst_header[100];
    Esc_UINT32 tst_len_header;
    Esc_UINT8 tst_len_tag;
    Esc_UINT8 tst_ciphertext[120];
    Esc_BOOL tst_result;
} EscTstAesEax_TestcaseT;

/**
 * Test the encryption and decryption functions of compliance with the
 * given testvectors from the NIST
 */
static Esc_ERROR
EscTstAesEax_ComplianceTest(
    Esc_UINT8 keyIndex );

/**
 * Test chunk-wise encryption and decryption.
 */
static Esc_ERROR
EscTstAesEax_ChunkTest(
    Esc_UINT8 keyIndex );

/**
 * Test chunk-wise encryption.
 */
static Esc_ERROR
EscTstAesEax_ChunkTestEncryption(
    Esc_UINT8 keyIndex,
    const EscTstAesEax_TestcaseT *vector,
    Esc_UINT32 chunkSize);

/**
 * Test chunk-wise decryption.
 */
static Esc_ERROR
EscTstAesEax_ChunkTestDecryption(
    Esc_UINT8 keyIndex,
    const EscTstAesEax_TestcaseT *vector,
    Esc_UINT32 chunkSize);

static Esc_ERROR
EscTstAesEax_InitTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_StartEncryptDecryptParams(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Nonce_UpdateTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Nonce_FinishTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Header_UpdateTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Header_FinishTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Encrypt_UpdateTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Encrypt_FinishTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Decrypt_UpdateTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_Decrypt_FinishTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_EncryptTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_DecryptTest(
    Esc_UINT8 keyIndex );
/**
 * Test blockwise encryption and decryption
 */
static Esc_ERROR
EscTstAesEax_BlockTest(
    Esc_UINT8 keyIndex );

static Esc_ERROR
EscTstAesEax_InitContext(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 keyIndex,
    EscTstAesEax_TestcaseT tst );

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
static const EscTstAesEax_TestcaseT AesEaxPositiveSampleWithHeader[EscTstAesEax_NUM_KEYSIZES] =
{
    /* key size 128 bit */
    {
        /* key */
        {
            0xB7U, 0x6CU, 0x64U, 0x0CU, 0x30U, 0x0BU, 0x38U, 0xF3U, 0x6EU, 0x5BU,
            0x65U, 0x02U, 0x4CU, 0x3DU, 0x79U, 0xF7U
        },
        /* plaintext  */
        {
            0x40U, 0xEBU, 0xFDU, 0x6DU, 0x88U, 0xF5U, 0x97U, 0x05U
        },
        /* plaintext length */
        8U,
        /* nonce */
        {
            0x6FU, 0xFBU, 0xB3U, 0x52U, 0x6DU, 0x9FU, 0xB4U, 0x5FU, 0xBAU, 0x1DU,
            0xCDU, 0xDBU, 0x39U, 0xCBU, 0x06U, 0xAEU
        },
        /* nonce length */
        16U,
        /* header/aad */
        {
            0x72U, 0x82U, 0xECU, 0xABU, 0xBAU, 0x74U, 0x6AU, 0x4EU
        },
        /* header length */
        8U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0xA8U, 0xC4U, 0xFDU, 0x2FU, 0x0CU, 0xC0U, 0xA4U, 0x7DU, 0xF1U, 0xCAU,
            0x8DU, 0x10U, 0xA8U, 0xB0U, 0xC9U, 0x2BU, 0x7BU, 0xFEU, 0x07U, 0x46U,
            0x11U, 0x6DU, 0xC1U, 0xC3U
        },
        /* result   */
        FALSE
    },

#if EscAes_MAX_KEY_BITS >= 192U

    /* key size 192 bit */
    {
        /* key */
        {
            0xD3U, 0x3DU, 0x84U, 0x3FU, 0x77U, 0x22U, 0x5BU, 0x7CU, 0xF6U, 0x55U,
            0xBCU, 0xA4U, 0x24U, 0xFFU, 0x06U, 0x25U, 0x84U, 0x1BU, 0xE0U, 0x0DU,
            0x97U, 0xDAU, 0x29U, 0x4EU
        },
        /* plaintext  */
        {
            0x7EU, 0xFCU, 0x4EU, 0x99U, 0x57U, 0x76U, 0xA2U, 0x22U
        },
        /* plaintext length */
        8U,
        /* nonce */
        {
            0x45U, 0x3AU, 0x4FU, 0xC8U, 0xD0U, 0x84U, 0xB4U, 0xFAU, 0x45U, 0x64U,
            0x33U, 0x74U, 0xBEU, 0xFAU, 0x59U, 0xA2U
        },
        /* nonce length */
        16U,
        /* header/aad */
        {
            0xC1U, 0xEAU, 0x67U, 0x8CU, 0x90U, 0x0EU, 0xAAU, 0xC6U
        },
        /* header length */
        8U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0xD9U, 0xB8U, 0x77U, 0x99U, 0x6EU, 0xAFU, 0xB6U, 0x50U, 0x20U, 0x62U,
            0xACU, 0x33U, 0xCEU, 0x31U, 0xFBU, 0x37U, 0x94U, 0x9EU, 0x8BU, 0x2EU,
            0x5AU, 0xAFU, 0xDCU, 0x80U
        },
        /* result   */
        FALSE
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U

    /* key size 256 bit */
    {
        /* key */
        {
            0xA4U, 0x3EU, 0xBBU, 0x64U, 0xFCU, 0xFAU, 0xBBU, 0xA5U, 0xC4U, 0xBDU,
            0x84U, 0x1AU, 0x11U, 0x68U, 0xB1U, 0xA2U, 0xA1U, 0x79U, 0x42U, 0x32U,
            0x69U, 0x64U, 0x0DU, 0xE4U, 0xD9U, 0x23U, 0xC4U, 0x2CU, 0x7CU, 0x9CU,
            0x81U, 0xD4U
        },
        /* plaintext  */
        {
            0x2FU, 0xC6U, 0xCEU, 0x9DU, 0x26U, 0x1DU, 0x32U, 0xBBU
        },
        /* plaintext length */
        8U,
        /* nonce */
        {
            0x8DU, 0x9BU, 0x9AU, 0xF6U, 0x9EU, 0xA9U, 0x60U, 0x81U, 0x34U, 0x2DU,
            0x9BU, 0x61U, 0x52U, 0x7AU, 0x22U, 0x85U
        },
        /* nonce length */
        16U,
        /* header/aad */
        {
            0xD2U, 0xFFU, 0x8DU, 0x6CU, 0xB5U, 0xCCU, 0x8EU, 0x1CU
        },
        /* header length */
        8U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0x4AU, 0xC8U, 0x3CU, 0x95U, 0x3BU, 0xFAU, 0x04U, 0x1FU, 0xDBU, 0x35U,
            0x76U, 0xBEU, 0xF1U, 0x47U, 0xBAU, 0xF4U, 0xEFU, 0x76U, 0x1FU, 0x9EU,
            0x90U, 0xF6U, 0xBEU, 0x2AU
        },
        /* result   */
        FALSE
    }
#endif
};

static const EscTstAesEax_TestcaseT AesEaxPositiveSampleNoHeader[EscTstAesEax_NUM_KEYSIZES] =
{
    /* key size 128 bit */
    {
        /* key      */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
            0x0eU, 0x0fU
        },
        /* payload  */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U
        },
        /* length   */
        8U,
        /* nonce    */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
            0x0eU, 0x0fU
        },
        /* length   */
        16U,
        /* a. data  */
        {
            0x00U
        },
        /* length   */
        0U,
        /* tag length */
        16U,
        /* output   */
        {
            0x29U, 0xd8U, 0x78U, 0xd1U, 0xa3U, 0xbeU, 0x85U, 0x7bU, 0x9eU, 0x1fU, 0x33U, 0x6eU, 0x2dU, 0x90U,
            0x58U, 0xeeU, 0x57U, 0xbfU, 0x18U, 0x1eU, 0xdfU, 0x49U, 0x39U, 0x5bU
        },
        /* result   */
        FALSE
    },

#if EscAes_MAX_KEY_BITS >= 192U

    /* key size 192 bit */
    {
        /* key */
        {
            0x6FU, 0xBCU, 0x16U, 0x36U, 0xA8U, 0x90U, 0xDBU, 0xADU, 0x79U, 0xA7U,
            0x7BU, 0xD6U, 0xE0U, 0x11U, 0x8FU, 0xDCU, 0x8DU, 0x6CU, 0xB0U, 0x40U,
            0xEDU, 0xD2U, 0x2EU, 0xC6U
        },
        /* plaintext  */
        {
            0x21U, 0x6DU, 0x78U, 0xC6U, 0x2BU, 0x0BU, 0xE1U, 0x74U
        },
        /* plaintext length */
        8U,
        /* nonce */
        {
            0xBBU, 0x9FU, 0x62U, 0x65U, 0x0FU, 0xEAU, 0x8EU, 0xB3U, 0x20U, 0x87U,
            0x65U, 0x0CU, 0x71U, 0x2BU, 0x89U, 0xF8U
        },
        /* nonce length */
        16U,
        /* header/aad */
        {
            0x00U
        },
        /* header length */
        0U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0xD0U, 0x1DU, 0xA9U, 0x63U, 0xBDU, 0xA2U, 0xF8U, 0xC8U, 0x3BU, 0xE4U,
            0x78U, 0xC8U, 0xBCU, 0x7CU, 0x1EU, 0x5FU, 0x7FU, 0x6EU, 0xE9U, 0x6EU,
            0x95U, 0x19U, 0xEBU, 0x62U
        },
        /* result   */
        FALSE
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U
    /* key size 256 bit */
    {
        /* key */
        {
            0xF5U, 0xC3U, 0x70U, 0x02U, 0x4DU, 0x31U, 0xFBU, 0x11U, 0x1DU, 0xFAU,
            0xE1U, 0x5BU, 0x93U, 0xEAU, 0x3DU, 0xC4U, 0xAFU, 0x4BU, 0x9CU, 0x35U,
            0x79U, 0x37U, 0x32U, 0x44U, 0xB0U, 0xC2U, 0x99U, 0x3AU, 0xB8U, 0xC4U,
            0xB5U, 0x15U
        },
        /* plaintext  */
        {
            0xD5U, 0x84U, 0xFCU, 0xE1U, 0x77U, 0xFBU, 0x89U, 0x7FU
        },
        /* plaintext length */
        8U,
        /* nonce */
        {
            0xC8U, 0x88U, 0x52U, 0x04U, 0x80U, 0xE3U, 0x1AU, 0x6AU, 0x0FU, 0xB7U,
            0xFFU, 0x7CU, 0xEDU, 0x74U, 0xC3U, 0x41U
        },
        /* nonce length */
        16U,
        /* header/aad */
        {
            0x00U
        },
        /* header length */
        0U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0xDAU, 0xF1U, 0xB2U, 0x5FU, 0x56U, 0x77U, 0x86U, 0x05U, 0x2FU, 0x62U,
            0x3EU, 0xCCU, 0xECU, 0x88U, 0xB9U, 0x56U, 0x03U, 0xD0U, 0x6CU, 0x8BU,
            0xFCU, 0x65U, 0x9CU, 0xEAU
        },
        /* result   */
        FALSE
    }
#endif
};

static const EscTstAesEax_TestcaseT AesEaxNegativeSampleNoHeader[EscTstAesEax_NUM_KEYSIZES] =
{
    /* key size 128 bit */
    {
        /* key      */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
            0x0eU, 0x0fU
        },
        /* payload  */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U
        },
        /* length   */
        8U,
        /* nonce    */
        {
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
            0x0eU, 0x0fU
        },
        /* length   */
        16U,
        /* a. data  */
        {
            0x00U
        },
        /* length   */
        0U,
        /* tag length */
        16U,
        /* output   */
        {
            0x00U, 0x00U, 0x78U, 0xd1U, 0xa3U, 0xbeU, 0x85U, 0x7bU, 0x9eU, 0x1fU, 0x33U, 0x6eU, 0x2dU, 0x90U,
            0x58U, 0xeeU, 0x57U, 0xbfU, 0x18U, 0x1eU, 0xdfU, 0x49U, 0x39U, 0x5bU
        },
        /* result   */
        TRUE
    },

#if EscAes_MAX_KEY_BITS >= 192U

    /* key size 192 bit */
    {
        /* key */
        {
            0xBAU, 0x6AU, 0xA0U, 0x0EU, 0x83U, 0x87U, 0x13U, 0x78U, 0x73U, 0x98U,
            0x7DU, 0xDAU, 0x98U, 0xE1U, 0xC6U, 0xD6U, 0x04U, 0x7BU, 0x8FU, 0xBCU,
            0x7CU, 0x18U, 0x78U, 0x29U
        },
        /* plaintext  */
        {
            0xD0U, 0x95U, 0x6CU, 0x6CU, 0x89U, 0xE1U, 0x4EU, 0xAEU, 0xD5U, 0x1DU,
            0xC0U, 0x1EU, 0xA4U, 0x2BU, 0x31U, 0x4FU, 0x97U, 0x92U, 0x01U, 0xE6U,
            0xAAU, 0x8FU
        },
        /* plaintext length */
        22U,
        /* nonce */
        {
            0x38U, 0x97U, 0x4BU, 0xBCU, 0x6BU, 0xCAU, 0x04U, 0xB6U, 0xFCU
        },
        /* nonce length */
        9U,
        /* header/aad */
        {
            0x00U
        },
        /* header length */
        0U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0x1CU, 0xB0U, 0x23U, 0xEBU, 0x10U, 0xCDU, 0x7BU, 0x42U, 0x31U, 0x84U,
            0xE9U, 0x54U, 0x7BU, 0x55U, 0xA0U, 0xB1U, 0x79U, 0x23U, 0x4EU, 0x4AU,
            0x70U, 0xEEU, 0xF3U, 0x22U, 0x39U, 0xFFU, 0x4DU, 0x76U, 0x3FU, 0x71U,
            0x8AU, 0x50U, 0x6AU, 0xD9U, 0x27U, 0x3AU, 0x2DU, 0xCCU
        },
        /* result   */
        FALSE
    },
#endif

#if EscAes_MAX_KEY_BITS == 256U

    /* key size 256 bit */
    {
        /* key */
        {
            0x6DU, 0xCFU, 0x39U, 0x04U, 0xFFU, 0x09U, 0x23U, 0x11U, 0x24U, 0x26U,
            0x2DU, 0x9EU, 0x2AU, 0x58U, 0xC2U, 0xC0U, 0xA3U, 0x90U, 0x8EU, 0x02U,
            0x58U, 0x1DU, 0x42U, 0x87U, 0x9CU, 0x4FU, 0x8BU, 0xE3U, 0x90U, 0xD4U,
            0x97U, 0xFDU
        },
        /* plaintext  */
        {
            0x9CU, 0x90U, 0x8DU, 0x86U, 0xECU, 0x8EU, 0x1CU, 0x4BU, 0x1BU, 0x1AU,
            0xC4U, 0x54U, 0x76U, 0x46U, 0xA4U, 0xF7U, 0x60U, 0x4FU, 0x89U, 0x0DU,
            0x13U, 0xDAU, 0x0DU
        },
        /* plaintext length */
        23U,
        /* nonce */
        {
            0xF0U, 0x82U, 0x19U, 0xC0U, 0xEDU, 0x1AU, 0x33U, 0x81U, 0xBDU, 0x93U,
            0x5CU, 0xC6U, 0x53U, 0xC6U, 0x8FU, 0xD0U, 0x7AU, 0xE5U, 0x67U, 0x1DU
        },
        /* nonce length */
        20U,
        /* header/aad */
        {
            0x00U
        },
        /* header length */
        0U,
        /* tag length */
        16U,
        /* expected output (ciphertext || tag) */
        {
            0xA0U, 0x4DU, 0x0AU, 0x91U, 0x90U, 0xE8U, 0xFBU, 0x55U, 0x10U, 0xAEU,
            0x6BU, 0x2CU, 0x82U, 0x14U, 0x10U, 0xA2U, 0xF1U, 0x9AU, 0x5AU, 0x87U,
            0x5CU, 0xB5U, 0x99U, 0x18U, 0xFFU, 0x7EU, 0xCEU, 0x48U, 0xFFU, 0x0DU,
            0xB5U, 0xA8U, 0x29U, 0xDFU, 0x03U, 0x7AU, 0x0FU, 0xAFU, 0x91U
        },
        /* result   */
        FALSE
    }
#endif
};
/*lint -restore */

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

static Esc_ERROR
EscTstAesEax_StartEncryptDecryptParams(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "\nEscAesEax_startEncryptDecrypt() parameter test\n" );

    EscTst_PrintString( " - with context == 0\n" );
    returnCode = EscAesEax_startEncryptDecrypt(
            Esc_NULL_PTR,
            AesEaxPositiveSampleNoHeader[keyIndex].tst_len_tag );

    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_InitTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;

    EscTst_PrintString( "\nEscAesEax_Init parameter test\n" );

    EscTst_PrintString( " - with context == 0\n" );
    returnCode = EscAesEax_Init( Esc_NULL_PTR, keySizes[keyIndex], AesEaxPositiveSampleNoHeader[keyIndex].tst_key );
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with key == 0\n" );
        returnCode = EscAesEax_Init( &context, keySizes[keyIndex], Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "- with invalid key size\n" );
        /* Key size is 64 bit larger than the configured maximum. This also tests cases
         * where are key size is used that is reasonable, but less than the maximum
         * (e.g. max = 128 => use 192)
         */
        returnCode = EscAesEax_Init( &context, (Esc_UINT16)(EscAes_MAX_KEY_BITS + 64U), AesEaxPositiveSampleNoHeader[keyIndex].tst_key  );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_KEY_LENGTH );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Nonce_UpdateTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT32 i;

    EscTst_PrintString( "\nEscAesEax_Nonce_Update test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Nonce_Update( Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with nonce == 0\n" );
        returnCode = EscAesEax_Nonce_Update( &context,
                Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - after nonce finish\n" );
        returnCode = EscAesEax_Nonce_Finish( &context );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Nonce_Update( &context,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with nonceLen == 0\n" );
        returnCode = EscAesEax_Nonce_Update( &context,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce,
                0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - bytewise nonce update\n" );
        for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
        {
            returnCode = EscAesEax_Nonce_Update( &context,
                    &AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce[i],
                    1U );
        }
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }
    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Nonce_FinishTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;

    EscTst_PrintString( "\nEscAesEax_Nonce_Finish test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Nonce_Finish( Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Header_UpdateTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT32 i;

    EscTst_PrintString( "\nEscAesEax_Header_Update test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Header_Update( Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_header,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with header == 0\n" );
        returnCode = EscAesEax_Header_Update( &context,
                Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - after header finish\n" );
        returnCode = EscAesEax_Header_Finish( &context );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Header_Update( &context,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_header,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with headerLen == 0\n" );
        returnCode = EscAesEax_Header_Update( &context,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_header,
                0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - bytewise header update\n" );
        for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header) && (returnCode == Esc_NO_ERROR); i++)
        {
            returnCode = EscAesEax_Header_Update( &context,
                    &AesEaxPositiveSampleWithHeader[keyIndex].tst_header[i],
                    1U );
        }
        returnCode = EscTst_CheckResultSuccess(returnCode);
    }
    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Header_FinishTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;

    EscTst_PrintString( "\nEscAesEax_Header_Finish test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Header_Finish( Esc_NULL_PTR );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Encrypt_UpdateTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[64];
    Esc_UINT32 i;
    EscTst_PrintString( "\nEscAesEax_Encrypt_Update test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleNoHeader[keyIndex] );

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( Esc_NULL_PTR,
                AesEaxPositiveSampleNoHeader[keyIndex].tst_payload,
                temp,
                AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( &context, Esc_NULL_PTR, temp, AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with cipher == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( &context,
                AesEaxPositiveSampleNoHeader[keyIndex].tst_payload,
                Esc_NULL_PTR,
                AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce and header expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Encrypt_Update( &context,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                    temp,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Header_Finish(&context);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Encrypt_Update( &context,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                        temp,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
            }
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with header expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Nonce_Finish(&context);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Encrypt_Update( &context,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                        temp,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Header_Finish(&context);
            }
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( &context, AesEaxPositiveSampleNoHeader[keyIndex].tst_payload, temp, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0 and payload == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( &context, Esc_NULL_PTR, temp, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0 and cipher == 0\n" );
        returnCode = EscAesEax_Encrypt_Update( &context, AesEaxPositiveSampleNoHeader[keyIndex].tst_payload, Esc_NULL_PTR, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - bytewise processing\n" );
        for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR);
             i++)
        {
            returnCode = EscAesEax_Encrypt_Update( &context,
                    &AesEaxPositiveSampleNoHeader[keyIndex].tst_payload[ i ],
                    &temp[ i ],
                    1U );
        }

        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - update after finish\n" );
        returnCode = EscAesEax_Encrypt_Finish(&context, &temp[AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload], AesEaxPositiveSampleNoHeader[keyIndex].tst_len_tag);

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Encrypt_Update( &context, AesEaxPositiveSampleNoHeader[keyIndex].tst_payload, temp, 1U );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
        }
    }
    return returnCode;
}



static Esc_ERROR
EscTstAesEax_Encrypt_FinishTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[64];

    EscTst_PrintString( "\nEscAesEax_Encrypt_Finish test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce or header expected\n" );
        returnCode = EscAesEax_Encrypt_Finish( &context, temp, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Encrypt_Finish( Esc_NULL_PTR, temp, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with tag == 0\n" );
        returnCode = EscAesEax_Encrypt_Finish( &context, Esc_NULL_PTR, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with tag len > EscAes_MAX_KEY_BYTES\n" );
        returnCode = EscAesEax_Encrypt_Finish( &context, temp, 100U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }
    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Decrypt_UpdateTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[64];
    Esc_UINT32 i;
    EscTst_PrintString( "\nEscAesEax_Decrypt_Update test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext,
                temp,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with ciphertext == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( &context, Esc_NULL_PTR, temp, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( &context,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext,
                Esc_NULL_PTR,
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce and header expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Decrypt_Update( &context,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                    temp,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Header_Finish(&context);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Decrypt_Update( &context,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                        temp,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
            }
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with header expected\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Nonce_Finish(&context);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Decrypt_Update( &context,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                        temp,
                        AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
                returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Header_Finish(&context);
            }
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( &context, AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext, temp, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0 and ciphertext == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( &context, Esc_NULL_PTR, temp, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with payload length == 0 and payload == 0\n" );
        returnCode = EscAesEax_Decrypt_Update( &context, AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext, Esc_NULL_PTR, 0U );
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - bytewise processing\n" );
        for (i = 0U;
             (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR);
             i++)
        {
            returnCode = EscAesEax_Decrypt_Update( &context,
                    &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[ i ],
                    &temp[ i ],
                    1U );
        }
        returnCode = EscTst_CheckResultSuccess( returnCode );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - update after finish\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscAesEax_Nonce_Update(&context, AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscAesEax_Nonce_Finish(&context);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscAesEax_Header_Update(&context, AesEaxPositiveSampleWithHeader[keyIndex].tst_header, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header);
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscAesEax_Header_Finish(&context);
                        if (returnCode == Esc_NO_ERROR)
                        {
                            returnCode = EscAesEax_Decrypt_Update( &context, AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext, temp, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload );
                            if (returnCode == Esc_NO_ERROR)
                            {
                                returnCode = EscAesEax_Decrypt_Finish(
                                        &context,
                                        &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload],
                                        AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );

                                if (returnCode == Esc_NO_ERROR)
                                {
                                    returnCode = EscAesEax_Decrypt_Update( &context, AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext, temp, 1U );
                                    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return returnCode;
}

static Esc_ERROR
EscTstAesEax_Decrypt_FinishTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[64];

    EscTst_PrintString( "\nEscAesEax_Decrypt_Finish test\n" );
    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - function call with nonce or header expected\n" );
        returnCode =
            EscAesEax_Decrypt_Finish( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload ],
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with context == 0\n" );
        returnCode =
            EscAesEax_Decrypt_Finish( Esc_NULL_PTR,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload],
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with tag == 0\n" );
        returnCode = EscAesEax_Decrypt_Finish( &context, Esc_NULL_PTR, AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with tag len > EscAes_MAX_KEY_BYTES\n" );
        returnCode = EscAesEax_Decrypt_Finish( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload],
                100U );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_PARAMETER );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with invalid tag\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxNegativeSampleNoHeader[keyIndex] );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_nonce,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_len_nonce );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Update( &context,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_header,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_len_header );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Decrypt_Update( &context,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_ciphertext,
                temp,
                AesEaxNegativeSampleNoHeader[keyIndex].tst_len_payload );

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode =
                EscAesEax_Decrypt_Finish( &context,
                    &AesEaxNegativeSampleNoHeader[keyIndex].tst_ciphertext[AesEaxNegativeSampleNoHeader[keyIndex].tst_len_payload],
                    AesEaxNegativeSampleNoHeader[keyIndex].tst_len_tag);
            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
        }
    }
    return returnCode;
}


static Esc_ERROR
EscTstAesEax_EncryptTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[EscTstAesEax_MAX_BUFFER_SIZE];
    Esc_UINT32 i;
    Esc_BOOL cmp;
    EscTst_PrintString( "\nEncryption with bytewise operation\n" );
    EscTst_PrintString( " - without header\n" );

    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleNoHeader[keyIndex] );

    for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_nonce[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Encrypt_Update( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_payload[i],
                &temp[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Encrypt_Finish( &context, &temp[AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload], AesEaxPositiveSampleNoHeader[keyIndex].tst_len_tag );

        if (returnCode == Esc_NO_ERROR)
        {
            cmp = EscTst_Memcmp( temp,
                    AesEaxPositiveSampleNoHeader[keyIndex].tst_ciphertext,
                    (AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload + AesEaxPositiveSampleNoHeader[keyIndex].tst_len_tag) );

            if (cmp == TRUE)
            {
                EscTst_PrintString( "   Correct\n\n" );
            }
            else
            {
                EscTst_PrintString( "   FAILED!!!\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "   FAILED!!!\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with header\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce[i],
                1U );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Header_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_header[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Encrypt_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_payload[i],
                &temp[i],
                1U );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Encrypt_Finish( &context, &temp[AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload], AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        if (returnCode == Esc_NO_ERROR)
        {
            cmp = EscTst_Memcmp( temp,
                    AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext,
                    (AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload + AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag) );
            if (cmp == TRUE)
            {
                EscTst_PrintString( "   Correct\n\n" );
            }
            else
            {
                EscTst_PrintString( "   FAILED!!!\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "   FAILED!!!\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_DecryptTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT context;
    Esc_UINT8 temp[EscTstAesEax_MAX_BUFFER_SIZE] = { 0U };
    Esc_BOOL cmp;
    Esc_UINT32 i;

    /*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
    static const EscTstAesEax_TestcaseT AesEaxNegativeSampleWithHeader[EscTstAesEax_NUM_KEYSIZES] =
    {
        /* key size 128 bit */
        {
            /* key */
            {
                0x01U, 0xF7U, 0x4AU, 0xD6U, 0x40U, 0x77U, 0xF2U, 0xE7U, 0x04U, 0xC0U,
                0xF6U, 0x0AU, 0xDAU, 0x3DU, 0xD5U, 0x23U
            },
            /* plaintext  */
            {
                0x1AU, 0x47U, 0xCBU, 0x49U, 0x33U
            },
            /* plaintext length */
            5U,
            /* nonce */
            {
                0x70U, 0xC3U, 0xDBU, 0x4FU, 0x0DU, 0x26U, 0x36U, 0x84U, 0x00U, 0xA1U,
                0x0EU, 0xD0U, 0x5DU, 0x2BU, 0xFFU, 0x5EU
            },
            /* nonce length */
            16U,
            /* header/aad */
            {
                0x23U, 0x4AU, 0x34U, 0x63U, 0xC1U, 0x26U, 0x4AU, 0xC6U
            },
            /* header length */
            8U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0x00U, 0x51U, 0xD5U, 0xBAU, 0xE0U, 0x3AU, 0x59U, 0xF2U, 0x38U, 0xA2U,
                0x3EU, 0x39U, 0x19U, 0x9DU, 0xC9U, 0x26U, 0x66U, 0x26U, 0xC4U, 0x0FU,
                0x80U
            },
            /* result */
            TRUE
        },

#if EscAes_MAX_KEY_BITS >= 192U

        /* key size 192 bit */
        {
            /* key */
            {
                0x08U, 0xE6U, 0xBCU, 0x8EU, 0x99U, 0x00U, 0x69U, 0x01U, 0xBFU, 0x77U,
                0xCAU, 0x32U, 0x9CU, 0x33U, 0x7EU, 0x82U, 0x3CU, 0x5DU, 0x6EU, 0xF8U,
                0x9BU, 0x7EU, 0x7BU, 0x80U
            },
            /* plaintext  */
            {
                0xC4U, 0x1AU, 0x49U, 0x5DU
            },
            /* plaintext length */
            4U,
            /* nonce */
            {
                0x62U, 0xA8U, 0x82U, 0xCFU, 0x59U, 0x57U, 0x81U, 0xE7U, 0xAFU
            },
            /* nonce length */
            9U,
            /* header/aad */
            {
                0xBDU, 0xC7U, 0x68U, 0xBAU, 0x1BU, 0xE2U, 0x05U, 0xE8U, 0x90U, 0xEBU,
                0x6CU, 0xFBU, 0x17U, 0x5AU, 0x6BU, 0xF9U, 0x09U, 0xDFU, 0x4AU, 0x13U,
                0xF8U, 0x1BU, 0x14U, 0xF7U, 0x63U, 0x0FU, 0xC0U, 0x0EU, 0x5DU, 0x5AU,
                0xC4U, 0x34U, 0x9EU, 0xDEU, 0xCEU
            },
            /* header length */
            35U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0xD3U, 0xCFU, 0x5AU, 0xC1U, 0xD1U, 0x8BU, 0x0AU, 0xBFU, 0xD8U, 0xBCU,
                0xEFU, 0x14U, 0x3FU, 0x07U, 0xBAU, 0x63U, 0x67U, 0xD3U, 0x90U, 0xEBU
            },
            /* result   */
            FALSE
        },
#endif

#if EscAes_MAX_KEY_BITS == 256U

        /* key size 256 bit */
        {
            /* key */
            {
                0x0EU, 0xF3U, 0x67U, 0x25U, 0x6DU, 0x37U, 0xB5U, 0xFFU, 0xC0U, 0x96U,
                0x2BU, 0xCBU, 0x46U, 0x2EU, 0x90U, 0xE9U, 0xB8U, 0xA4U, 0xCDU, 0x70U,
                0x8FU, 0x28U, 0xDDU, 0xD3U, 0x62U, 0x64U, 0x31U, 0x56U, 0x24U, 0xF4U,
                0xF8U, 0x85U
            },
            /* plaintext  */
            {
                0x08U, 0x62U, 0x7CU, 0x71U, 0xF5U, 0xBDU, 0x45U, 0x27U, 0x20U, 0xFEU,
                0x8AU, 0x2BU, 0x02U, 0x9CU, 0x31U, 0x2BU, 0x6BU
            },
            /* plaintext length */
            17U,
            /* nonce */
            {
                0x67U, 0xADU, 0xDEU, 0xEFU, 0x11U, 0xCFU, 0xDEU, 0x05U, 0x2DU, 0xCAU,
                0x75U, 0xD8U, 0x45U, 0x8FU, 0xDAU, 0x72U, 0x86U, 0x10U, 0x2AU, 0x29U,
                0x25U
            },
            /* nonce length */
            21U,
            /* header/aad */
            {
                0xFBU, 0x3CU, 0xC4U, 0xEEU, 0x40U, 0x13U, 0x3BU, 0x02U, 0x8EU, 0x0BU,
                0xF5U, 0xA1U, 0x9DU, 0xFAU, 0xC8U, 0xC0U, 0x5DU, 0x5DU, 0xF3U, 0xA8U,
                0xE1U, 0x9BU, 0xE0U, 0x73U, 0x77U, 0xBDU, 0xDAU, 0xE2U, 0xF0U, 0xD2U,
                0x2AU, 0x72U, 0xFFU, 0x90U
            },
            /* header length */
            34U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0x5EU, 0xC5U, 0xB3U, 0x34U, 0xEAU, 0x96U, 0xD9U, 0xCBU, 0x40U, 0xA9U,
                0x44U, 0xEBU, 0x32U, 0x2EU, 0x55U, 0x09U, 0x5EU, 0xE6U, 0xB6U, 0x11U,
                0x97U, 0xEEU, 0xABU, 0x8FU, 0xC5U, 0x24U, 0x3DU, 0x46U, 0x94U, 0x02U,
                0xB6U, 0x36U, 0x1BU
            },
            /* result   */
            FALSE
        }
#endif
    };
    /*lint -restore */

    EscTst_PrintString( "\nDecryption with bytewise operation\n" );
    EscTst_PrintString( " - without header, MAC valid\n" );

    returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleNoHeader[keyIndex] );

    for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_nonce[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Decrypt_Update( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_ciphertext[i],
                &temp[i],
                1U );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =
            EscAesEax_Decrypt_Finish( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_ciphertext[AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload],
                AesEaxPositiveSampleNoHeader[keyIndex].tst_len_tag );
        if (returnCode == Esc_NO_ERROR)
        {
            cmp = EscTst_Memcmp( temp,
                    AesEaxPositiveSampleNoHeader[keyIndex].tst_payload,
                    AesEaxPositiveSampleNoHeader[keyIndex].tst_len_payload );
            if (cmp == TRUE)
            {
                EscTst_PrintString( "   Correct\n\n" );
            }
            else
            {
                EscTst_PrintString( "   FAILED!!!\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "   FAILED!!!\n" );
            returnCode = Esc_KAT_FAILED;
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with header, MAC valid\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxPositiveSampleWithHeader[keyIndex] );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce[i],
                1U );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Header_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_header[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Decrypt_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[i],
                &temp[i],
                1U );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =
            EscAesEax_Decrypt_Finish( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_ciphertext[AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload],
                AesEaxPositiveSampleWithHeader[keyIndex].tst_len_tag );
        if ( (returnCode == Esc_NO_ERROR) )
        {
            if ( EscTst_Memcmp( temp,
                     AesEaxPositiveSampleWithHeader[keyIndex].tst_payload,
                     AesEaxPositiveSampleWithHeader[keyIndex].tst_len_payload ) )
            {
                EscTst_PrintString( "   Correct\n\n" );
            }
            else
            {
                EscTst_PrintString( "   FAILED!!!\n" );
                returnCode = Esc_KAT_FAILED;
            }
        }
        else
        {
            EscTst_PrintString( "   FAILED!!!\n" );
        }
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - without header, MAC invalid\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxNegativeSampleNoHeader[keyIndex] );
    }

    for (i = 0U; (i < AesEaxPositiveSampleNoHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleNoHeader[keyIndex].tst_nonce[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxNegativeSampleNoHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Decrypt_Update( &context,
                &AesEaxNegativeSampleNoHeader[keyIndex].tst_ciphertext[i],
                &temp[i],
                1U );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =
            EscAesEax_Decrypt_Finish( &context,
                &AesEaxNegativeSampleNoHeader[keyIndex].tst_ciphertext[AesEaxNegativeSampleNoHeader[keyIndex].tst_len_payload],
                AesEaxNegativeSampleNoHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( " - with header, MAC invalid\n" );
        returnCode = EscTstAesEax_InitContext( &context, keyIndex, AesEaxNegativeSampleWithHeader[keyIndex] );
    }
    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_nonce) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Nonce_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_nonce[i],
                1U );
    }

    for (i = 0U; (i < AesEaxPositiveSampleWithHeader[keyIndex].tst_len_header) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Header_Update( &context,
                &AesEaxPositiveSampleWithHeader[keyIndex].tst_header[i],
                1U );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Nonce_Finish( &context );
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Header_Finish( &context );
    }

    for (i = 0U; (i < AesEaxNegativeSampleWithHeader[keyIndex].tst_len_payload) && (returnCode == Esc_NO_ERROR); i++)
    {
        returnCode = EscAesEax_Decrypt_Update( &context,
                &AesEaxNegativeSampleWithHeader[keyIndex].tst_ciphertext[i],
                &temp[i],
                1U );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode =
            EscAesEax_Decrypt_Finish( &context,
                &AesEaxNegativeSampleWithHeader[keyIndex].tst_ciphertext[AesEaxNegativeSampleWithHeader[keyIndex].tst_len_payload],
                AesEaxNegativeSampleWithHeader[keyIndex].tst_len_tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_BlockTest(
    Esc_UINT8 keyIndex )
{
    Esc_ERROR returnCode;

    EscTst_PrintString( "\nTest for blockwise operation\n\n" );
    returnCode = EscTstAesEax_InitTest(keyIndex);

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_StartEncryptDecryptParams(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Nonce_UpdateTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Nonce_FinishTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Header_UpdateTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Header_FinishTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Encrypt_UpdateTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Encrypt_FinishTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Decrypt_UpdateTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_Decrypt_FinishTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_EncryptTest(keyIndex);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscTstAesEax_DecryptTest(keyIndex);
    }

    return returnCode;
}

/**
 * Test the encryption and decryption functions of compliance with the
 * given testvectors from the NIST
 */
static Esc_ERROR
EscTstAesEax_ComplianceTest(
    Esc_UINT8 keyIndex )
{
    /*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
    static const EscTstAesEax_TestcaseT AesEaxTestcase[EscTstAesEax_NUM_KEYSIZES][EscAesEax_NUMBER_OF_TESTCASES] =
    {
        /* key size 128 bit */
        {
            /* Testcase 0 */
            {
                /* key */
                {
                    0x23U, 0x39U, 0x52U, 0xDEU, 0xE4U, 0xD5U, 0xEDU, 0x5FU, 0x9BU, 0x9CU,
                    0x6DU, 0x6FU, 0xF8U, 0x0FU, 0xF4U, 0x78U
                },
                /* plaintext  */
                {
                    0x00U
                },
                /* plaintext length */
                0U,
                /* nonce */
                {
                    0x62U, 0xECU, 0x67U, 0xF9U, 0xC3U, 0xA4U, 0xA4U, 0x07U, 0xFCU, 0xB2U,
                    0xA8U, 0xC4U, 0x90U, 0x31U, 0xA8U, 0xB3U
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0x6BU, 0xFBU, 0x91U, 0x4FU, 0xD0U, 0x7EU, 0xAEU, 0x6BU
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xE0U, 0x37U, 0x83U, 0x0EU, 0x83U, 0x89U, 0xF2U, 0x7BU, 0x02U, 0x5AU,
                    0x2DU, 0x65U, 0x27U, 0xE7U, 0x9DU, 0x01U
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 1 */
            {
                /* key */
                {
                    0x91U, 0x94U, 0x5dU, 0x3fU, 0x4dU, 0xcbU, 0xeeU, 0x0bU, 0xf4U, 0x5eU,
                    0xf5U, 0x22U, 0x55U, 0xf0U, 0x95U, 0xa4U
                },
                /* plaintext  */
                {
                    0xf7U, 0xfbU
                },
                /* plaintext length */
                2U,
                /* nonce */
                {
                    0xbeU, 0xcaU, 0xf0U, 0x43U, 0xb0U, 0xa2U, 0x3dU, 0x84U, 0x31U, 0x94U,
                    0xbaU, 0x97U, 0x2cU, 0x66U, 0xdeU, 0xbdU
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0xfaU, 0x3bU, 0xfdU, 0x48U, 0x06U, 0xebU, 0x53U, 0xfaU
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x19U, 0xddU, 0x5cU, 0x4cU, 0x93U, 0x31U, 0x04U, 0x9dU, 0x0bU, 0xdaU,
                    0xb0U, 0x27U, 0x74U, 0x08U, 0xf6U, 0x79U, 0x67U, 0xe5U
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 2 */
            {
                /* key */
                {
                    0x01U, 0xF7U, 0x4AU, 0xD6U, 0x40U, 0x77U, 0xF2U, 0xE7U, 0x04U, 0xC0U,
                    0xF6U, 0x0AU, 0xDAU, 0x3DU, 0xD5U, 0x23U
                },
                /* plaintext  */
                {
                    0x1AU, 0x47U, 0xCBU, 0x49U, 0x33U
                },
                /* plaintext length */
                5U,
                /* nonce */
                {
                    0x70U, 0xC3U, 0xDBU, 0x4FU, 0x0DU, 0x26U, 0x36U, 0x84U, 0x00U, 0xA1U,
                    0x0EU, 0xD0U, 0x5DU, 0x2BU, 0xFFU, 0x5EU
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0x23U, 0x4AU, 0x34U, 0x63U, 0xC1U, 0x26U, 0x4AU, 0xC6U
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xD8U, 0x51U, 0xD5U, 0xBAU, 0xE0U, 0x3AU, 0x59U, 0xF2U, 0x38U, 0xA2U,
                    0x3EU, 0x39U, 0x19U, 0x9DU, 0xC9U, 0x26U, 0x66U, 0x26U, 0xC4U, 0x0FU,
                    0x80U
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 3 */
            {
                /* key */
                {
                    0x35U, 0xB6U, 0xD0U, 0x58U, 0x00U, 0x05U, 0xBBU, 0xC1U, 0x2BU, 0x05U,
                    0x87U, 0x12U, 0x45U, 0x57U, 0xD2U, 0xC2U
                },
                /* plaintext  */
                {
                    0x40U, 0xD0U, 0xC0U, 0x7DU, 0xA5U, 0xE4U
                },
                /* plaintext length */
                6U,
                /* nonce */
                {
                    0xFDU, 0xB6U, 0xB0U, 0x66U, 0x76U, 0xEEU, 0xDCU, 0x5CU, 0x61U, 0xD7U,
                    0x42U, 0x76U, 0xE1U, 0xF8U, 0xE8U, 0x16U
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0xAEU, 0xB9U, 0x6EU, 0xAEU, 0xBEU, 0x29U, 0x70U, 0xE9U
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x07U, 0x1DU, 0xFEU, 0x16U, 0xC6U, 0x75U, 0xCBU, 0x06U, 0x77U, 0xE5U,
                    0x36U, 0xF7U, 0x3AU, 0xFEU, 0x6AU, 0x14U, 0xB7U, 0x4EU, 0xE4U, 0x98U,
                    0x44U, 0xDDU
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 4 */
            {
                /* key */
                {
                    0xBDU, 0x8EU, 0x6EU, 0x11U, 0x47U, 0x5EU, 0x60U, 0xB2U, 0x68U, 0x78U,
                    0x4CU, 0x38U, 0xC6U, 0x2FU, 0xEBU, 0x22U
                },
                /* plaintext  */
                {
                    0x4DU, 0xE3U, 0xB3U, 0x5CU, 0x3FU, 0xC0U, 0x39U, 0x24U, 0x5BU, 0xD1U,
                    0xFBU, 0x7DU
                },
                /* plaintext length */
                12U,
                /* nonce */
                {
                    0x6EU, 0xACU, 0x5CU, 0x93U, 0x07U, 0x2DU, 0x8EU, 0x85U, 0x13U, 0xF7U,
                    0x50U, 0x93U, 0x5EU, 0x46U, 0xDAU, 0x1BU
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0xD4U, 0x48U, 0x2DU, 0x1CU, 0xA7U, 0x8DU, 0xCEU, 0x0FU
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x83U, 0x5BU, 0xB4U, 0xF1U, 0x5DU, 0x74U, 0x3EU, 0x35U, 0x0EU, 0x72U,
                    0x84U, 0x14U, 0xABU, 0xB8U, 0x64U, 0x4FU, 0xD6U, 0xCCU, 0xB8U, 0x69U,
                    0x47U, 0xC5U, 0xE1U, 0x05U, 0x90U, 0x21U, 0x0AU, 0x4FU
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 5 */
            {
                /* key */
                {
                    0x7CU, 0x77U, 0xD6U, 0xE8U, 0x13U, 0xBEU, 0xD5U, 0xACU, 0x98U, 0xBAU,
                    0xA4U, 0x17U, 0x47U, 0x7AU, 0x2EU, 0x7DU
                },
                /* plaintext  */
                {
                    0x8BU, 0x0AU, 0x79U, 0x30U, 0x6CU, 0x9CU, 0xE7U, 0xEDU, 0x99U, 0xDAU,
                    0xE4U, 0xF8U, 0x7FU, 0x8DU, 0xD6U, 0x16U, 0x36U
                },
                /* plaintext length */
                17U,
                /* nonce */
                {
                    0x1AU, 0x8CU, 0x98U, 0xDCU, 0xD7U, 0x3DU, 0x38U, 0x39U, 0x3BU, 0x2BU,
                    0xF1U, 0x56U, 0x9DU, 0xEEU, 0xFCU, 0x19U
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0x65U, 0xD2U, 0x01U, 0x79U, 0x90U, 0xD6U, 0x25U, 0x28U
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x02U, 0x08U, 0x3EU, 0x39U, 0x79U, 0xDAU, 0x01U, 0x48U, 0x12U, 0xF5U,
                    0x9FU, 0x11U, 0xD5U, 0x26U, 0x30U, 0xDAU, 0x30U, 0x13U, 0x73U, 0x27U,
                    0xD1U, 0x06U, 0x49U, 0xB0U, 0xAAU, 0x6EU, 0x1CU, 0x18U, 0x1DU, 0xB6U,
                    0x17U, 0xD7U, 0xF2U
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 6 */
            {
                /* key */
                {
                    0x5FU, 0xFFU, 0x20U, 0xCAU, 0xFAU, 0xB1U, 0x19U, 0xCAU, 0x2FU, 0xC7U,
                    0x35U, 0x49U, 0xE2U, 0x0FU, 0x5BU, 0x0DU
                },
                /* plaintext  */
                {
                    0x1BU, 0xDAU, 0x12U, 0x2BU, 0xCEU, 0x8AU, 0x8DU, 0xBAU, 0xF1U, 0x87U,
                    0x7DU, 0x96U, 0x2BU, 0x85U, 0x92U, 0xDDU, 0x2DU, 0x56U
                },
                /* plaintext length */
                18U,
                /* nonce */
                {
                    0xDDU, 0xE5U, 0x9BU, 0x97U, 0xD7U, 0x22U, 0x15U, 0x6DU, 0x4DU, 0x9AU,
                    0xFFU, 0x2BU, 0xC7U, 0x55U, 0x98U, 0x26U
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0x54U, 0xB9U, 0xF0U, 0x4EU, 0x6AU, 0x09U, 0x18U, 0x9AU
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x2EU, 0xC4U, 0x7BU, 0x2CU, 0x49U, 0x54U, 0xA4U, 0x89U, 0xAFU, 0xC7U,
                    0xBAU, 0x48U, 0x97U, 0xEDU, 0xCDU, 0xAEU, 0x8CU, 0xC3U, 0x3BU, 0x60U,
                    0x45U, 0x05U, 0x99U, 0xBDU, 0x02U, 0xC9U, 0x63U, 0x82U, 0x90U, 0x2AU,
                    0xEFU, 0x7FU, 0x83U, 0x2AU
                },
                /* result */
                FALSE
            }
            ,
            /* Testcase 7 */
            {
                /* key */
                {
                    0x83U, 0x95U, 0xfcU, 0xf1U, 0xe9U, 0x5bU, 0xebU, 0xd6U, 0x97U, 0xbdU,
                    0x01U, 0x0bU, 0xc7U, 0x66U, 0xaaU, 0xc3U
                },
                /* plaintext  */
                {
                    0xcaU, 0x40U, 0xd7U, 0x44U, 0x6eU, 0x54U, 0x5fU, 0xfaU, 0xedU, 0x3bU,
                    0xd1U, 0x2aU, 0x74U, 0x0aU, 0x65U, 0x9fU, 0xfbU, 0xbbU, 0x3cU, 0xeaU,
                    0xb7U
                },
                /* plaintext length */
                21U,
                /* nonce */
                {
                    0x22U, 0xe7U, 0xadU, 0xd9U, 0x3cU, 0xfcU, 0x63U, 0x93U, 0xc5U, 0x7eU,
                    0xc0U, 0xb3U, 0xc1U, 0x7dU, 0x6bU, 0x44U
                },
                /* nonce length */
                16U,
                /* header/aad */
                {
                    0x12U, 0x67U, 0x35U, 0xfcU, 0xc3U, 0x20U, 0xd2U, 0x5aU
                },
                /* header length */
                8U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xcbU, 0x89U, 0x20U, 0xf8U, 0x7aU, 0x6cU, 0x75U, 0xcfU, 0xf3U, 0x96U,
                    0x27U, 0xb5U, 0x6eU, 0x3EU, 0xD1U, 0x97U, 0xC5U, 0x52U, 0xD2U, 0x95U,
                    0xa7U, 0xcfU, 0xc4U, 0x6aU, 0xfcU, 0x25U, 0x3bU, 0x46U, 0x52U, 0xb1U,
                    0xafU, 0x37U, 0x95U, 0xb1U, 0x24U, 0xabU, 0x6eU
                },
                /* result */
                FALSE
            }
        },

#if EscAes_MAX_KEY_BITS >= 192U

        /* key size 192 bit */
        {
            /* Testcase 0 */
            {
                /* key */
                {
                    0x98U, 0x8DU, 0x1FU, 0x80U, 0x99U, 0xD7U, 0xB1U, 0x63U, 0x87U, 0xFBU,
                    0x67U, 0x9DU, 0x7FU, 0xB6U, 0xE4U, 0x91U, 0xEAU, 0xBFU, 0xD7U, 0x9FU,
                    0x97U, 0x4AU, 0x1CU, 0xBAU
                },
                /* plaintext  */
                {
                    0x10U, 0xA4U, 0xF6U, 0xD3U, 0xCBU, 0xF1U, 0x36U, 0x6EU, 0x4AU, 0x66U,
                    0x00U, 0x23U, 0x10U, 0x69U, 0x95U, 0xE6U, 0x86U
                },
                /* plaintext length */
                17U,
                /* nonce */
                {
                    0x88U, 0xC4U, 0x28U, 0x36U, 0xFFU, 0xEEU, 0x98U, 0xACU, 0x79U, 0x78U,
                    0xF8U, 0xBCU, 0x48U, 0xB9U, 0x9EU, 0x47U, 0xCEU, 0x2EU, 0x8AU, 0x2AU,
                    0x6CU, 0xD8U, 0xADU, 0xF8U, 0x74U, 0x95U, 0x2AU, 0xC5U, 0x2FU, 0x0FU,
                    0x74U, 0x45U, 0x1BU, 0xF6U, 0xAFU, 0x67U, 0x2EU, 0xD3U, 0x87U, 0x22U
                },
                /* nonce length */
                40U,
                /* header/aad */
                {
                    0xB9U, 0x4BU, 0x49U, 0xC0U, 0x6CU, 0x6FU, 0x3CU, 0x4EU, 0xBDU, 0x7FU,
                    0xAFU, 0xEDU, 0x07U, 0x7FU, 0x98U, 0xD8U, 0x12U, 0x79U, 0x5BU, 0x7AU,
                    0x20U, 0x28U, 0xB2U, 0x96U, 0x83U, 0x4EU, 0x22U, 0xD4U, 0x35U, 0xF8U,
                    0x81U, 0xE1U, 0xCCU, 0xBCU, 0x32U, 0x51U, 0x27U, 0xA1U, 0x64U, 0x88U,
                    0x59U, 0x6CU, 0x29U, 0x4EU, 0xD4U, 0x08U, 0x95U, 0x0CU, 0x5FU, 0x28U,
                    0x97U, 0x50U, 0x36U, 0xDEU, 0xA4U, 0xD4U, 0x23U, 0x3AU, 0x10U, 0xE2U,
                    0xC1U, 0xD0U, 0x70U, 0xFBU, 0xABU, 0xD9U, 0x45U, 0x20U, 0x0EU, 0x08U,
                    0x01U, 0x17U, 0x33U, 0x2DU, 0x78U, 0x2BU, 0x22U, 0xFDU, 0xB2U, 0x2AU,
                    0x18U
                },
                /* header length */
                81U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x04U, 0xC2U, 0xBDU, 0x49U, 0x8DU, 0x50U, 0x50U, 0x3BU, 0x7FU, 0x5CU,
                    0xB8U, 0xE2U, 0x43U, 0x99U, 0x13U, 0x3DU, 0x91U, 0xC2U, 0x9EU, 0xF1U,
                    0x50U, 0x71U, 0xB2U, 0xCDU, 0x3EU, 0x68U, 0x01U, 0x0DU, 0x95U, 0x66U,
                    0x49U, 0xB8U, 0xE8U
                },
                /* result   */
                FALSE
            },
            /* Testcase 1 */
            {
                /* key */
                {
                    0xB0U, 0x9DU, 0x29U, 0xFEU, 0xA3U, 0xE8U, 0xB8U, 0x68U, 0xBEU, 0x9CU,
                    0x61U, 0xC6U, 0x43U, 0x89U, 0xFDU, 0xD7U, 0x16U, 0xB7U, 0x2EU, 0xACU,
                    0xB4U, 0xD2U, 0xD5U, 0x49U
                },
                /* plaintext  */
                {
                    0x93U
                },
                /* plaintext length */
                1U,
                /* nonce */
                {
                    0x5CU, 0xC9U, 0x9EU, 0x40U, 0xD1U, 0xA6U, 0x77U, 0x14U, 0x97U, 0xB2U,
                    0x33U, 0xFAU, 0xADU, 0x9CU, 0xE3U, 0xE2U, 0x76U, 0x07U, 0xC5U, 0x42U,
                    0x47U, 0x4BU, 0x42U, 0x14U, 0xA0U, 0x54U, 0x5FU, 0x12U
                },
                /* nonce length */
                28U,
                /* header/aad */
                {
                    0x38U, 0x3FU, 0xACU, 0x06U, 0xE7U, 0xFEU, 0x29U, 0x3AU, 0xE4U, 0xC8U,
                    0x4EU, 0x3EU, 0x66U, 0x7EU
                },
                /* header length */
                14U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xC3U, 0x51U, 0x9EU, 0x36U, 0xD9U, 0xFDU, 0x6BU, 0x13U, 0x55U, 0xB2U,
                    0x3AU, 0x7AU, 0x6DU, 0xC0U, 0x7FU, 0xE7U, 0x4AU
                },
                /* result   */
                FALSE
            },
            /* Testcase 2 */
            {
                /* key */
                {
                    0x96U, 0xA5U, 0x7DU, 0x96U, 0xC9U, 0xB6U, 0x68U, 0xBAU, 0x05U, 0x54U,
                    0x70U, 0x83U, 0x72U, 0xC7U, 0xAEU, 0xF2U, 0x42U, 0x49U, 0x4DU, 0x83U,
                    0xEBU, 0x72U, 0x06U, 0xF2U
                },
                /* plaintext  */
                {
                    0xEBU, 0x73U, 0xC5U, 0xEBU, 0xDDU
                },
                /* plaintext length */
                5U,
                /* nonce */
                {
                    0x33U, 0xCDU, 0x00U, 0x0DU, 0x50U, 0xACU, 0x77U, 0x86U, 0x1DU, 0xCCU,
                    0x98U, 0x66U, 0x06U, 0x8BU, 0x9CU, 0xC6U, 0xA0U, 0x86U, 0xE3U, 0x8EU,
                    0xAEU, 0xECU, 0x0EU, 0x8BU, 0x88U, 0xE2U, 0x85U, 0x55U, 0xF3U, 0x8BU,
                    0xABU, 0xE2U, 0x17U, 0xB8U, 0x4EU, 0xE6U, 0x05U, 0x99U, 0xFAU, 0xB4U,
                    0x02U, 0x8EU, 0x31U, 0x6DU, 0x01U, 0x2FU, 0x50U, 0xEDU, 0x75U, 0x63U,
                    0x01U, 0x17U, 0xDDU, 0x72U, 0x4EU, 0xEAU, 0x6BU, 0xBFU, 0x5DU, 0x06U,
                    0x86U, 0x95U, 0x75U, 0xB1U, 0xE7U, 0x81U, 0xD3U, 0x2BU, 0x1FU, 0xEFU,
                    0xA5U, 0xBDU, 0xCFU, 0xDAU, 0xAAU, 0x6AU, 0x74U, 0x5FU, 0x49U, 0xCDU,
                    0x78U, 0x23U, 0x12U, 0x16U, 0x20U, 0xA0U, 0x2CU, 0xC1U, 0x20U, 0x73U,
                    0x1CU, 0xF2U, 0xFFU, 0x4EU, 0x53U
                },
                /* nonce length */
                95U,
                /* header/aad */
                {
                    0x24U, 0x8DU, 0x81U, 0x29U, 0x82U, 0x02U, 0xF1U, 0xC0U, 0xCAU, 0xB8U,
                    0x91U, 0x66U, 0x88U
                },
                /* header length */
                13U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x96U, 0x04U, 0xB0U, 0xBDU, 0x7AU, 0x99U, 0xA1U, 0x93U, 0x38U, 0x08U,
                    0xD0U, 0x54U, 0x78U, 0x69U, 0x69U, 0xA1U, 0xABU, 0x4BU, 0x2AU, 0xA9U,
                    0xC1U
                },
                /* result   */
                FALSE
            },
            /* Testcase 3 */
            {
                /* key */
                {
                    0x64U, 0xCBU, 0x5AU, 0xC7U, 0x2CU, 0xBDU, 0x5CU, 0x8AU, 0x41U, 0x58U,
                    0x87U, 0xE1U, 0x5EU, 0x78U, 0xC3U, 0xFDU, 0x79U, 0xBAU, 0xC2U, 0x8BU,
                    0xEFU, 0xE6U, 0x33U, 0xA7U
                },
                /* plaintext  */
                {
                    0xD3U, 0x4BU, 0xD3U, 0xC4U, 0x0FU, 0x10U, 0x9EU, 0x23U, 0xAAU, 0xECU,
                    0x3BU, 0x7BU, 0x67U, 0xF0U, 0x55U, 0x99U, 0xF4U
                },
                /* plaintext length */
                17U,
                /* nonce */
                {
                    0xDFU, 0x9BU, 0x13U, 0x57U, 0x73U, 0xB2U, 0x1DU, 0x87U, 0xA3U, 0xA0U,
                    0xA8U, 0xE5U, 0xA6U, 0x37U, 0xE9U, 0x5BU, 0xC9U, 0x43U, 0x32U, 0x00U,
                    0xA8U, 0x10U, 0x96U, 0x93U, 0xF3U, 0xC0U, 0x93U, 0x06U, 0x84U, 0x5FU,
                    0xE5U, 0x8EU, 0x04U, 0x95U, 0x9EU, 0xBDU, 0xB1U, 0x63U, 0xE2U, 0x6BU,
                    0x1EU, 0xF9U, 0x38U, 0x1DU, 0xBCU, 0x42U, 0x7EU, 0x3CU, 0xC5U, 0x6BU,
                    0x40U, 0xFEU, 0x4BU, 0xE1U, 0xA7U, 0x9DU, 0xE1U, 0x25U, 0xFBU, 0x93U,
                    0x9CU, 0xEAU, 0x49U, 0x6FU, 0xB1U, 0x42U, 0x3FU, 0x72U, 0xF0U, 0xF4U,
                    0xE2U, 0x2CU, 0xEEU, 0x8CU, 0xFDU, 0x1FU, 0x87U, 0x9BU, 0xD4U, 0xD5U,
                    0xB3U, 0x20U, 0xFFU, 0x5AU, 0x14U, 0xFBU, 0xB4U, 0xF7U, 0xDFU, 0xB0U,
                    0xABU
                },
                /* nonce length */
                91U,
                /* header/aad */
                {
                    0xB7U, 0x72U, 0xE9U, 0xD3U, 0xECU, 0xBEU, 0x3AU, 0xC5U, 0xCAU, 0x64U,
                    0x9CU, 0xFCU, 0xD9U, 0x72U, 0x63U, 0xAEU, 0xDDU, 0xC7U, 0x63U, 0x47U,
                    0x5CU, 0x7BU, 0x81U, 0x8DU, 0x8EU, 0xB3U
                },
                /* header length */
                26U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x26U, 0x58U, 0xFEU, 0xD7U, 0x9BU, 0xBAU, 0x4DU, 0xD1U, 0x16U, 0x81U,
                    0x18U, 0xE0U, 0x09U, 0x31U, 0x2CU, 0xB8U, 0xB6U, 0x3AU, 0x91U, 0x2AU,
                    0xE0U, 0x94U, 0xEBU, 0xB8U, 0xD7U, 0x18U, 0x67U, 0x32U, 0x7FU, 0x8EU,
                    0x5AU, 0xBFU, 0x92U
                },
                /* result   */
                FALSE
            },
            /* Testcase 4 */
            {
                /* key */
                {
                    0xECU, 0xD3U, 0x01U, 0x04U, 0xFFU, 0x30U, 0x4CU, 0x77U, 0x77U, 0x5DU,
                    0xE6U, 0x5EU, 0xE5U, 0x87U, 0x1CU, 0x55U, 0x92U, 0x80U, 0x64U, 0x6BU,
                    0x49U, 0xC6U, 0xAAU, 0xA6U
                },
                /* plaintext  */
                {
                    0x27U, 0x1DU, 0x25U, 0x0CU, 0x83U, 0x1FU, 0x38U, 0xA3U, 0x80U, 0x76U,
                    0x46U, 0x3AU, 0xFFU, 0x4BU, 0x66U, 0x39U, 0xC1U, 0xE4U, 0xBEU, 0xD2U,
                    0x2BU, 0xD5U, 0xA4U, 0xAEU, 0xC1U
                },
                /* plaintext length */
                25U,
                /* nonce */
                {
                    0x8CU, 0xE0U, 0x6BU, 0x94U, 0x2BU, 0xFFU, 0x54U, 0x01U, 0xE5U, 0xEAU,
                    0x07U, 0xDEU, 0xD8U, 0xCFU, 0x9EU, 0x72U, 0x2AU, 0xD1U, 0xB5U, 0x3AU,
                    0x0EU, 0x47U, 0x88U, 0x5BU, 0x28U, 0x48U, 0xCEU, 0xB6U, 0x1DU, 0x26U,
                    0xEFU, 0x1CU, 0xD1U, 0xA2U, 0xFBU, 0xDEU, 0x1DU, 0x54U, 0x61U, 0x0FU,
                    0x96U, 0x0AU, 0x43U, 0x62U, 0x9DU, 0x6EU, 0x93U, 0xA5U, 0x35U, 0x17U
                },
                /* nonce length */
                50U,
                /* header/aad */
                {
                    0x04U, 0x3BU, 0xDFU, 0xA6U, 0x6AU, 0x87U, 0x16U, 0x34U, 0x0AU, 0x78U,
                    0xC9U, 0x01U, 0xEDU, 0x8BU, 0x45U, 0x86U, 0xB9U, 0x89U, 0xA2U, 0x0BU,
                    0xEFU, 0x07U, 0xFBU, 0x25U, 0x6AU, 0xF1U, 0x5EU, 0xE8U, 0x2AU, 0x2DU,
                    0x9FU, 0x6FU, 0xE6U, 0x5BU, 0x0CU, 0xD0U, 0x11U, 0xFEU, 0xFEU, 0x8DU,
                    0x3DU, 0x3BU, 0x09U, 0x1FU, 0x7AU, 0xFBU, 0x8DU, 0xDAU, 0x9AU, 0x1DU,
                    0x81U, 0x4AU
                },
                /* header length */
                52U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x10U, 0xF5U, 0x01U, 0x12U, 0xC9U, 0xFBU, 0xD5U, 0x23U, 0x9FU, 0x2DU,
                    0xF7U, 0xCEU, 0x9CU, 0xFEU, 0xD0U, 0xC7U, 0xF0U, 0x77U, 0x92U, 0xD3U,
                    0xBEU, 0x05U, 0xADU, 0x8DU, 0x67U, 0x6BU, 0x69U, 0xF0U, 0x2DU, 0xD7U,
                    0xA1U, 0xD1U, 0xD6U, 0x6BU, 0x44U, 0x11U, 0x13U, 0x69U, 0x56U, 0x52U,
                    0x34U
                },
                /* result   */
                FALSE
            },
            /* Testcase 5 */
            {
                /* key */
                {
                    0x36U, 0x3CU, 0x5FU, 0xB1U, 0x3CU, 0x03U, 0x04U, 0x22U, 0x23U, 0x05U,
                    0x47U, 0x92U, 0x85U, 0x48U, 0x11U, 0x6CU, 0x0AU, 0x2FU, 0xAFU, 0x31U,
                    0x33U, 0x98U, 0xA0U, 0x9BU
                },
                /* plaintext  */
                {
                    0xAAU, 0xDFU, 0x85U, 0xF9U, 0xF9U, 0x53U, 0xEDU, 0x64U, 0xF0U, 0x8CU,
                    0xA4U, 0x49U, 0x8EU, 0x49U, 0xD1U, 0x0EU, 0xECU
                },
                /* plaintext length */
                17U,
                /* nonce */
                {
                    0x16U, 0x24U, 0x5FU, 0x9FU, 0x0AU, 0x2EU, 0xEFU, 0x27U, 0x09U, 0xECU,
                    0x89U, 0x07U, 0xF0U, 0xB1U, 0x81U, 0x27U, 0x69U, 0x0AU, 0xDDU, 0x30U,
                    0xE1U, 0x8EU, 0x69U, 0x29U, 0x12U, 0x7CU, 0x11U, 0x78U, 0x01U, 0xA5U,
                    0x55U, 0x42U, 0x09U, 0xC9U, 0xDBU, 0xDAU, 0xABU, 0xC9U, 0xD9U, 0x6CU,
                    0x3AU, 0x8FU, 0x9FU, 0x16U, 0x62U, 0xDEU, 0x53U, 0xEEU, 0xECU, 0xF6U,
                    0x6AU, 0x16U, 0xE5U, 0x07U, 0x44U, 0x82U, 0x7CU, 0x14U, 0x72U, 0x9CU,
                    0x2FU, 0xB6U, 0x7DU, 0x64U, 0x0DU, 0xFAU, 0x26U, 0x2DU, 0xA1U, 0x1CU,
                    0xD0U, 0xABU, 0x50U, 0x2DU, 0x56U, 0x88U, 0xA9U, 0xF1U, 0x6CU, 0x90U,
                    0xA1U, 0xA8U, 0xD8U, 0x36U
                },
                /* nonce length */
                84U,
                /* header/aad */
                {
                    0x1BU, 0x13U, 0xEEU, 0xBEU, 0x12U, 0xDDU, 0x7DU, 0xE6U, 0x1DU, 0xA8U,
                    0x21U, 0xC3U, 0x12U, 0x12U, 0x9BU, 0x10U, 0x90U, 0x22U, 0x00U, 0xDDU,
                    0x44U, 0x4EU, 0x37U, 0xB2U, 0xEDU, 0x2EU, 0x82U, 0x76U, 0x70U, 0x5CU,
                    0x40U, 0x22U, 0x7BU, 0xFDU, 0x7CU, 0x24U, 0x6EU, 0x42U, 0x3AU, 0x8CU,
                    0x2AU, 0x3EU, 0xADU, 0x90U, 0x23U, 0x29U, 0x6FU, 0x61U, 0x9CU, 0x45U
                },
                /* header length */
                50U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x49U, 0x27U, 0xA1U, 0x97U, 0x4FU, 0xFEU, 0x35U, 0x2CU, 0xD0U, 0x07U,
                    0xF3U, 0x88U, 0xB2U, 0xDCU, 0x38U, 0x6DU, 0x40U, 0xABU, 0xD4U, 0x31U,
                    0xD5U, 0xFFU, 0x8EU, 0xDEU, 0x60U, 0x33U, 0x5EU, 0x3BU, 0xE6U, 0x44U,
                    0xF7U, 0x99U, 0xE1U
                },
                /* result   */
                FALSE
            },
            /* Testcase 6 */
            {
                /* key */
                {
                    0x16U, 0x8AU, 0x48U, 0x0DU, 0x5AU, 0xDAU, 0x1DU, 0xFDU, 0x2FU, 0xA9U,
                    0x27U, 0xFCU, 0x95U, 0xA8U, 0xF8U, 0xE6U, 0xE5U, 0x2EU, 0xBCU, 0xDFU,
                    0x1BU, 0xF6U, 0xC2U, 0x2CU
                },
                /* plaintext  */
                {
                    0x96U
                },
                /* plaintext length */
                1U,
                /* nonce */
                {
                    0xF3U, 0x8EU, 0x6FU, 0x0BU, 0xD9U, 0x3CU, 0xA4U, 0x76U, 0xC4U, 0x05U,
                    0xAFU, 0xFAU, 0xA5U, 0x05U, 0x76U, 0xAAU, 0x32U, 0x6BU, 0x96U, 0xC1U,
                    0x3BU, 0xD3U, 0x8EU, 0x52U, 0xECU, 0xD1U, 0xCFU, 0xF6U, 0xBDU, 0x99U,
                    0x5EU, 0x0EU, 0x4EU, 0xE0U, 0x5AU, 0x05U, 0x05U, 0x4EU, 0x55U, 0x69U,
                    0x00U, 0x25U, 0x41U, 0xACU, 0x6FU, 0xCAU, 0x6FU, 0x63U, 0xD3U, 0xD9U,
                    0x86U, 0x37U, 0x07U, 0xA5U, 0x2DU, 0xA1U, 0xEFU, 0x92U, 0x13U, 0xEDU,
                    0x7FU
                },
                /* nonce length */
                61U,
                /* header/aad */
                {
                    0x99U, 0x43U, 0x2EU, 0x5AU, 0x05U, 0x17U, 0xAAU, 0xBEU, 0xE5U, 0xAEU,
                    0x4FU, 0xE2U, 0x30U, 0x73U, 0x11U, 0x89U, 0x03U, 0x8FU, 0xB8U, 0x36U,
                    0x7FU, 0x24U, 0x03U, 0x00U, 0xD1U, 0x39U, 0x3CU, 0xD9U, 0xAAU, 0xCCU,
                    0x8EU, 0x8DU, 0x1FU, 0xEFU, 0x9AU, 0x87U, 0x61U, 0xACU, 0x29U, 0x37U,
                    0xEEU, 0x09U, 0xCAU, 0xA9U, 0x75U, 0x5EU, 0xE4U, 0x8DU, 0x3DU, 0x3DU,
                    0xB8U, 0xD3U, 0x87U, 0x2CU, 0x50U, 0xB3U, 0xEAU, 0xDFU, 0xC6U, 0xADU,
                    0x9CU, 0xE0U, 0x49U, 0x6FU, 0x46U, 0xBDU, 0x7CU, 0x07U, 0xFAU, 0x1BU,
                    0xA5U
                },
                /* header length */
                71U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x2EU, 0x5AU, 0xB5U, 0x9AU, 0x80U, 0xACU, 0xEAU, 0xC8U, 0xCDU, 0x1BU,
                    0xEDU, 0xCFU, 0xF4U, 0x66U, 0xB0U, 0x98U, 0x58U
                },
                /* result   */
                FALSE
            },
            /* Testcase 7 */
            {
                /* key */
                {
                    0x10U, 0x79U, 0x7DU, 0xC0U, 0xE3U, 0x01U, 0x37U, 0xAFU, 0x5AU, 0xF7U,
                    0x9DU, 0x1AU, 0xECU, 0x54U, 0xC4U, 0xF0U, 0x13U, 0x61U, 0x50U, 0x32U,
                    0x35U, 0xA2U, 0x21U, 0xACU
                },
                /* plaintext  */
                {
                    0xEEU
                },
                /* plaintext length */
                1U,
                /* nonce */
                {
                    0xEBU, 0x1AU, 0xABU, 0x9BU, 0x63U, 0x04U, 0xFBU, 0x90U, 0x08U, 0x25U,
                    0xA7U, 0xA7U, 0x20U, 0x36U, 0x9AU, 0xDFU, 0xA5U, 0x3FU, 0x0AU, 0x32U,
                    0x22U, 0x80U, 0x15U, 0xB0U, 0xDDU, 0x79U, 0xD0U, 0x05U, 0xBEU, 0x0CU,
                    0x4AU, 0x17U, 0xF6U, 0xFFU, 0x31U, 0x71U, 0x35U, 0xC7U, 0x01U, 0x52U,
                    0x02U, 0x23U, 0x24U, 0x9EU, 0x3EU, 0x51U, 0x7EU, 0xB2U, 0x6BU, 0xCAU,
                    0xADU, 0x6AU, 0xD3U, 0x66U, 0xFBU, 0x9CU, 0x0DU, 0x70U, 0x75U, 0x7CU,
                    0xAFU, 0x87U, 0xDBU, 0xE9U, 0xCCU, 0x9BU, 0xB2U, 0xC8U, 0x58U, 0x9DU,
                    0x44U, 0xACU, 0xC9U, 0x61U, 0x49U, 0x9DU, 0xB7U, 0x65U, 0x68U, 0xC0U,
                    0xA1U, 0x3EU, 0x9BU, 0x78U, 0x7DU, 0xFDU, 0xCDU, 0xCDU, 0x5CU, 0xDFU,
                    0xC7U
                },
                /* nonce length */
                91U,
                /* header/aad */
                {
                    0xF7U, 0x7EU, 0x6AU, 0x5FU, 0xCAU, 0x90U, 0xD8U, 0x08U, 0xABU, 0x99U,
                    0xA8U, 0xB1U, 0x69U, 0x6AU, 0x99U, 0x54U, 0x63U, 0x56U, 0x56U, 0xA9U,
                    0x48U, 0x2DU, 0x73U, 0x11U, 0xFDU, 0x40U, 0x80U, 0xCAU, 0x94U, 0xF9U,
                    0xAAU, 0x9FU, 0x47U, 0x54U, 0x0BU, 0x24U, 0x79U, 0xF2U, 0x8AU, 0x5DU,
                    0xDEU, 0xF0U, 0xF8U, 0x62U, 0x44U, 0xF8U, 0x2CU, 0xD0U, 0x53U, 0xC6U,
                    0x87U, 0xC8U, 0x8CU, 0x21U, 0x52U, 0x8FU, 0x45U, 0xF6U, 0xCAU, 0xFDU,
                    0x0BU, 0x66U, 0xCBU, 0x1CU, 0x4FU, 0x65U, 0x62U, 0x89U, 0xCCU, 0xC4U,
                    0x3FU, 0x05U, 0xF9U, 0x53U, 0xF9U, 0xD5U, 0xCEU, 0xF8U, 0xFBU
                },
                /* header length */
                79U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x94U, 0xF7U, 0xD3U, 0x6BU, 0xB7U, 0xE0U, 0xDEU, 0x0DU, 0x9BU, 0x01U,
                    0xD3U, 0x2EU, 0xDDU, 0xC1U, 0xB8U, 0xB2U, 0xDDU
                },
                /* result   */
                FALSE
            }
        },
#endif

#if EscAes_MAX_KEY_BITS == 256U

        /* key size 256 bit */
        {
            /* Testcase 0 */
            {
                /* key */
                {
                    0x94U, 0xC6U, 0x0CU, 0xF3U, 0xD1U, 0x83U, 0x80U, 0xF3U, 0x88U, 0x93U,
                    0x69U, 0xF6U, 0xCEU, 0x9DU, 0x8EU, 0xECU, 0xCCU, 0x38U, 0xC8U, 0x82U,
                    0x2DU, 0x89U, 0x37U, 0xDDU, 0xE3U, 0xEFU, 0xE9U, 0x74U, 0xF6U, 0x8BU,
                    0xD2U, 0xA5U
                },
                /* plaintext  */
                {
                    0xADU, 0xD0U, 0x31U, 0xB7U, 0x35U, 0x9DU, 0x49U, 0x06U, 0xC0U, 0xEAU,
                    0xE8U, 0xF1U, 0x8BU, 0x76U, 0xC1U, 0x35U, 0x0AU, 0x63U, 0x10U, 0x68U,
                    0xEDU
                },
                /* plaintext length */
                21U,
                /* nonce */
                {
                    0xEDU, 0x0DU, 0x04U, 0x25U, 0x86U, 0x2EU, 0xE9U, 0x1AU, 0x89U, 0x16U,
                    0x3FU, 0xEEU, 0xEBU, 0xBBU, 0x4FU, 0xFAU, 0x28U, 0x74U, 0x97U, 0xB3U,
                    0x5AU, 0xF6U, 0x1FU, 0x56U, 0x74U, 0x65U, 0x78U, 0xBEU, 0xDBU, 0x66U,
                    0xA4U, 0x68U, 0xE8U, 0x32U, 0x1AU, 0x41U, 0xD7U
                },
                /* nonce length */
                37U,
                /* header/aad */
                {
                    0x54U, 0xF5U, 0x1EU, 0xF9U, 0x23U, 0xC3U, 0x75U, 0xE6U, 0x32U, 0xDBU,
                    0xC5U, 0x84U, 0x46U, 0xE8U, 0x5CU, 0x42U, 0x62U, 0x7AU, 0x6BU, 0x44U,
                    0x1DU, 0x04U, 0x01U, 0x57U, 0x3AU
                },
                /* header length */
                25U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xDCU, 0xFEU, 0x32U, 0x10U, 0x08U, 0x73U, 0x57U, 0x61U, 0x4DU, 0xA1U,
                    0xA5U, 0xEBU, 0x35U, 0x46U, 0x87U, 0xADU, 0xC9U, 0xDBU, 0x0DU, 0x1CU,
                    0xC4U, 0x8CU, 0x20U, 0x94U, 0x9DU, 0x52U, 0xF4U, 0xC8U, 0x04U, 0x3BU,
                    0x8BU, 0xD9U, 0x2FU, 0xCFU, 0x1AU, 0x5CU, 0x44U
                },
                /* result   */
                FALSE
            },
            /* Testcase 1 */
            {
                /* key */
                {
                    0xA9U, 0xADU, 0x96U, 0x93U, 0x06U, 0x51U, 0xB4U, 0x70U, 0xC2U, 0x18U,
                    0xB0U, 0x3BU, 0x92U, 0xE8U, 0x6DU, 0xFBU, 0xB9U, 0xA0U, 0xE8U, 0x8DU,
                    0x39U, 0x31U, 0x2FU, 0xCEU, 0x53U, 0x19U, 0x17U, 0x6CU, 0x22U, 0xFDU,
                    0xAFU, 0xEDU
                },
                /* plaintext  */
                {
                    0x45U, 0x3FU, 0xD2U, 0xC3U, 0x41U, 0x8AU, 0x48U, 0xE8U, 0xA9U, 0xE1U,
                    0x09U, 0xC4U, 0xDAU, 0x56U, 0x91U, 0x7DU, 0x93U, 0x4CU, 0x88U, 0xE2U,
                    0x02U, 0x61U, 0xC8U, 0x60U, 0xCCU, 0xD9U, 0x6FU, 0x83U, 0xF1U, 0xFDU,
                    0xB7U, 0x9AU, 0xF1U, 0x9CU, 0x90U, 0xB5U, 0x31U, 0xE4U, 0xEBU, 0x14U,
                    0xAEU, 0xC7U, 0x23U, 0x9BU, 0xCFU, 0x9DU, 0xC5U, 0xB0U, 0x8FU, 0xD1U,
                    0xCDU, 0x44U, 0x09U, 0xECU, 0xE0U, 0x90U, 0xDDU, 0x26U, 0xABU, 0xBFU,
                    0xDFU, 0xBFU, 0x91U, 0xDDU, 0x36U, 0x94U, 0x54U, 0x73U, 0xF5U, 0x8FU,
                    0x90U, 0x9AU, 0xAAU, 0x00U, 0x3FU, 0x30U, 0x9EU, 0x9BU, 0x30U, 0xBFU,
                    0xAFU, 0x5EU, 0x00U, 0x32U, 0x1DU
                },
                /* plaintext length */
                85U,
                /* nonce */
                {
                    0xAFU, 0xB2U, 0x9EU, 0x6EU, 0xBAU, 0xC7U, 0xFCU, 0xA6U, 0x71U, 0x0DU,
                    0xE3U, 0xA3U, 0x23U, 0xFAU, 0x3BU, 0x8FU, 0x84U, 0x07U, 0xE7U, 0x62U,
                    0x42U, 0x50U, 0xF7U, 0x47U, 0xF0U, 0x0EU, 0xEFU, 0x9AU, 0x23U, 0x6CU,
                    0xE9U, 0x97U, 0x4DU, 0x03U, 0x1BU, 0x31U, 0x8BU, 0xFAU, 0x5CU, 0x80U,
                    0xBBU, 0x79U, 0x59U, 0xE3U, 0xB8U, 0xB6U, 0xEBU
                },
                /* nonce length */
                47U,
                /* header/aad */
                {
                    0x2DU
                },
                /* header length */
                1U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x62U, 0x33U, 0x00U, 0xD0U, 0x3EU, 0xAAU, 0x2EU, 0x9EU, 0x0EU, 0x5AU,
                    0xACU, 0xB0U, 0x73U, 0x09U, 0x74U, 0x98U, 0xA4U, 0x7AU, 0xCAU, 0x24U,
                    0xCCU, 0x85U, 0x9BU, 0x31U, 0x19U, 0xEBU, 0x8CU, 0x4CU, 0xBCU, 0x5EU,
                    0x98U, 0xF8U, 0x56U, 0x14U, 0xD9U, 0xA0U, 0x21U, 0x8DU, 0x69U, 0x5EU,
                    0x2FU, 0xEAU, 0x04U, 0x69U, 0xCEU, 0x6AU, 0x85U, 0x7FU, 0x73U, 0x6FU,
                    0x38U, 0xC1U, 0xD2U, 0x5AU, 0x98U, 0x25U, 0x41U, 0xA3U, 0xA1U, 0xD3U,
                    0x36U, 0xE5U, 0x23U, 0x79U, 0xE2U, 0xA7U, 0xE8U, 0x24U, 0x5DU, 0x36U,
                    0x01U, 0x6FU, 0xA4U, 0x70U, 0xDFU, 0x4EU, 0xCEU, 0xADU, 0x21U, 0x69U,
                    0xFEU, 0xCBU, 0x3BU, 0x2DU, 0x36U, 0xD4U, 0x94U, 0x26U, 0x84U, 0x37U,
                    0x67U, 0x4FU, 0xDDU, 0xDDU, 0xAAU, 0x71U, 0xF7U, 0x5DU, 0x41U, 0x2BU,
                    0x27U
                },
                /* result   */
                FALSE
            },
            /* Testcase 2 */
            {
                /* key */
                {
                    0x4BU, 0xA0U, 0xB4U, 0xBDU, 0x64U, 0xD4U, 0x82U, 0xD2U, 0x44U, 0x7CU,
                    0x0EU, 0x42U, 0x8BU, 0xAAU, 0xCCU, 0x75U, 0xDAU, 0x65U, 0x12U, 0x1AU,
                    0x48U, 0x92U, 0xDCU, 0xE1U, 0xD0U, 0xC7U, 0xE5U, 0x33U, 0x7AU, 0x73U,
                    0x59U, 0x16U
                },
                /* plaintext  */
                {
                    0xFEU, 0x89U, 0x1BU, 0x15U, 0x87U, 0x78U, 0x87U, 0x96U, 0x0FU, 0x4BU,
                    0x62U, 0x0FU, 0x9AU, 0xABU, 0xFFU, 0x3FU, 0xA9U, 0x22U, 0xDFU, 0x1AU,
                    0xBDU, 0xC1U, 0xFAU, 0x2BU, 0xABU, 0x02U, 0xB2U, 0xDCU, 0x47U, 0x0AU,
                    0xB4U, 0xBDU, 0xC1U, 0x2CU, 0x95U, 0x70U, 0x8EU, 0x20U, 0x91U, 0x99U,
                    0x63U, 0x4DU, 0x81U, 0x47U, 0x84U, 0x47U, 0x30U, 0x79U, 0x0EU, 0x42U,
                    0xC6U, 0xCFU, 0xFEU, 0x15U, 0xECU, 0xD5U, 0x23U, 0xA7U
                },
                /* plaintext length */
                58U,
                /* nonce */
                {
                    0x05U, 0xC6U, 0x68U, 0xC6U, 0x86U, 0xB7U, 0x59U, 0x19U, 0x12U, 0xB5U,
                    0x11U, 0xCCU, 0x48U, 0x7AU, 0x23U, 0x28U, 0x8CU, 0xB1U, 0xACU, 0x9CU,
                    0x36U, 0x2DU
                },
                /* nonce length */
                22U,
                /* header/aad */
                {
                    0xF8U, 0xFBU, 0x83U, 0x03U, 0x1FU
                },
                /* header length */
                5U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xCDU, 0xCFU, 0x84U, 0x79U, 0x06U, 0xC2U, 0x68U, 0xC4U, 0xC8U, 0x90U,
                    0x04U, 0xB2U, 0x85U, 0xC4U, 0x96U, 0xA8U, 0x5DU, 0x11U, 0x2FU, 0xA2U,
                    0xDAU, 0x71U, 0x4EU, 0xA6U, 0xB8U, 0xDEU, 0x27U, 0xC9U, 0x3FU, 0xE3U,
                    0xA0U, 0x57U, 0x15U, 0x8FU, 0x44U, 0x5FU, 0xE0U, 0x4AU, 0x82U, 0x87U,
                    0xF5U, 0xEDU, 0xE0U, 0x21U, 0x85U, 0x35U, 0x95U, 0xE1U, 0x17U, 0x41U,
                    0x7DU, 0xA4U, 0x8DU, 0xD4U, 0xE4U, 0xA4U, 0xC1U, 0x5BU, 0x46U, 0xCDU,
                    0xD9U, 0x6EU, 0x13U, 0x76U, 0x3EU, 0x10U, 0x29U, 0xC9U, 0x40U, 0xE4U,
                    0x6AU, 0x22U, 0x8BU, 0x35U
                },
                /* result   */
                FALSE
            },
            /* Testcase 3 */
            {
                /* key */
                {
                    0x48U, 0x56U, 0x3BU, 0x5AU, 0x02U, 0x31U, 0xBDU, 0x95U, 0xA4U, 0xD5U,
                    0x09U, 0xADU, 0x25U, 0x0EU, 0x53U, 0x72U, 0xEDU, 0xBEU, 0x07U, 0x5EU,
                    0xC7U, 0x6FU, 0x05U, 0x3EU, 0x12U, 0x4EU, 0xC3U, 0x50U, 0x1EU, 0x81U,
                    0x6BU, 0xE0U
                },
                /* plaintext  */
                {
                    0x15U, 0xBFU, 0xCFU, 0x97U, 0x68U, 0x63U, 0xCFU, 0x67U, 0x13U, 0x80U,
                    0x0CU, 0x3EU, 0x6FU, 0x68U, 0xFBU, 0x44U, 0xCCU, 0x19U, 0x18U, 0xDFU,
                    0x6BU, 0x9EU, 0x63U, 0x94U, 0xBDU, 0x25U, 0xDCU, 0x69U, 0x69U, 0xDEU,
                    0x55U, 0x9FU, 0xB3U, 0xA2U, 0xBCU, 0x7DU, 0xCBU, 0x29U, 0xE0U, 0xF6U,
                    0xD8U, 0xD6U, 0xC1U, 0x5CU, 0x0FU, 0xCEU, 0x09U, 0x5DU, 0xDAU, 0x4BU,
                    0xC6U, 0xA6U, 0x56U, 0xE8U, 0x64U
                },
                /* plaintext length */
                55U,
                /* nonce */
                {
                    0x35U, 0x2EU, 0x3DU, 0x5FU, 0xFEU, 0x42U, 0x08U, 0xA1U, 0x6BU, 0xCAU,
                    0xFEU
                },
                /* nonce length */
                11U,
                /* header/aad */
                {
                    0x45U, 0xF6U, 0x38U, 0x82U, 0x1DU, 0xB9U, 0xFCU
                },
                /* header length */
                7U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x91U, 0x1CU, 0x0EU, 0xD2U, 0x92U, 0x31U, 0x81U, 0x6CU, 0x7DU, 0x00U,
                    0xBBU, 0x47U, 0xD6U, 0x7FU, 0x92U, 0x8BU, 0xE9U, 0xBCU, 0x21U, 0x73U,
                    0x62U, 0xF7U, 0x3FU, 0x40U, 0xABU, 0x7EU, 0xEDU, 0x9DU, 0x63U, 0x1FU,
                    0xA6U, 0x03U, 0x6CU, 0x65U, 0x1BU, 0xDDU, 0x6BU, 0x4EU, 0x8DU, 0xB3U,
                    0xD1U, 0xD1U, 0xBFU, 0x0AU, 0x05U, 0x83U, 0xFAU, 0x8FU, 0x13U, 0xF8U,
                    0xFBU, 0xDCU, 0x89U, 0x2EU, 0x9DU, 0x0FU, 0x00U, 0x46U, 0x5CU, 0x59U,
                    0x4AU, 0x50U, 0x26U, 0x6FU, 0xB6U, 0xBCU, 0xE5U, 0xDEU, 0x00U, 0x2DU,
                    0xE8U
                },
                /* result   */
                FALSE
            },
            /* Testcase 4 */
            {
                /* key */
                {
                    0x53U, 0xD4U, 0x34U, 0x55U, 0xBAU, 0xF2U, 0xD6U, 0xA2U, 0xB6U, 0x1DU,
                    0x31U, 0x18U, 0x9EU, 0x11U, 0xEAU, 0x70U, 0x28U, 0xCDU, 0xCEU, 0xE0U,
                    0x6CU, 0xEBU, 0xD5U, 0x52U, 0xC9U, 0xADU, 0x11U, 0xC4U, 0x69U, 0x8AU,
                    0xC9U, 0x2BU
                },
                /* plaintext  */
                {
                    0x5BU, 0xEBU, 0x18U, 0xB4U, 0xEFU, 0x2FU, 0x43U, 0x4EU, 0xE1U, 0x57U,
                    0xE1U, 0xA2U, 0x4BU, 0x67U, 0x92U, 0x2AU, 0x5EU, 0x12U, 0xFAU, 0x6CU,
                    0x3BU, 0x61U, 0x81U, 0xA2U, 0xF5U, 0x34U, 0xBAU, 0x87U, 0x49U, 0x41U,
                    0x98U, 0x96U, 0x0FU, 0x41U, 0x65U, 0xDEU, 0xD8U, 0xB1U, 0x14U, 0x0CU,
                    0xE2U, 0x60U, 0x6BU, 0x90U, 0x84U, 0xA4U, 0x4CU, 0xB4U, 0x40U, 0x60U,
                    0xCFU, 0xE5U, 0xF7U, 0xE5U, 0x7EU, 0xA1U, 0xA5U, 0xFFU, 0x8DU, 0xA4U,
                    0x10U, 0x52U, 0xD2U, 0x1AU, 0xA6U, 0x82U, 0x79U
                },
                /* plaintext length */
                67U,
                /* nonce */
                {
                    0xEEU, 0x6BU, 0x2BU, 0xE5U, 0x5CU, 0xFEU, 0x9BU, 0x23U, 0x84U, 0x35U,
                    0x59U, 0xB8U, 0x0EU, 0x5EU, 0x0AU, 0x07U, 0x32U, 0xF1U, 0x7EU, 0xC0U,
                    0xB6U, 0x94U, 0xE0U, 0xFEU, 0x37U, 0xF7U, 0xD7U, 0x7AU, 0x3EU, 0xE4U,
                    0x9CU, 0xA1U, 0x17U, 0xF1U, 0xF2U, 0xFBU, 0x0DU, 0xB4U, 0x15U
                },
                /* nonce length */
                39U,
                /* header/aad */
                {
                    0x4CU, 0x76U, 0x97U, 0xAAU, 0x28U, 0x63U, 0x73U, 0x61U, 0xCBU, 0x73U,
                    0xF8U, 0x2AU
                },
                /* header length */
                12U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x86U, 0xEFU, 0x03U, 0xF7U, 0xF9U, 0xF3U, 0x3AU, 0x71U, 0x3AU, 0x8BU,
                    0x7EU, 0xB9U, 0x42U, 0x89U, 0x4FU, 0xBDU, 0xD2U, 0xE5U, 0x88U, 0x91U,
                    0xC8U, 0x2EU, 0x4EU, 0x0DU, 0xFCU, 0xD3U, 0x88U, 0x33U, 0x5CU, 0x1CU,
                    0xF9U, 0x60U, 0xBFU, 0x66U, 0xDCU, 0xA6U, 0x75U, 0xBFU, 0xF4U, 0x80U,
                    0x88U, 0x01U, 0x04U, 0x00U, 0xC0U, 0x26U, 0x0CU, 0x60U, 0xC4U, 0x0FU,
                    0x43U, 0x3CU, 0x23U, 0x8EU, 0xE2U, 0xEBU, 0xA6U, 0xE8U, 0xEDU, 0xE1U,
                    0x00U, 0x82U, 0x25U, 0x26U, 0x21U, 0xE7U, 0x7FU, 0xC4U, 0x5CU, 0xC9U,
                    0xBBU, 0xEFU, 0x8FU, 0x00U, 0xE3U, 0x23U, 0xB7U, 0x5DU, 0x07U, 0xF5U,
                    0x17U, 0xF5U, 0xB4U
                },
                /* result   */
                FALSE
            },
            /* Testcase 5 */
            {
                /* key */
                {
                    0x04U, 0xF5U, 0x12U, 0x25U, 0x6DU, 0xC7U, 0x3CU, 0x18U, 0x0CU, 0x12U,
                    0xBFU, 0x21U, 0xD6U, 0x95U, 0x93U, 0xE2U, 0x88U, 0xACU, 0xA9U, 0xC3U,
                    0x60U, 0x02U, 0x11U, 0xC9U, 0xA7U, 0xF6U, 0xD3U, 0xECU, 0x41U, 0x43U,
                    0xE8U, 0xB5U
                },
                /* plaintext  */
                {
                    0x3DU, 0x0CU, 0xA0U, 0xC7U, 0xD9U, 0x90U, 0x69U, 0xDEU, 0x36U, 0x6AU,
                    0xEEU, 0x88U, 0x80U, 0x91U, 0xDFU, 0x48U, 0x1DU, 0xC2U
                },
                /* plaintext length */
                18U,
                /* nonce */
                {
                    0x05U, 0x3AU, 0xD6U, 0x2AU, 0x01U
                },
                /* nonce length */
                5U,
                /* header/aad */
                {
                    0x5CU, 0xF8U, 0xE2U, 0xCDU, 0x78U, 0x34U, 0x8DU, 0xBDU, 0xC1U, 0x9FU,
                    0x66U, 0xB4U, 0xA1U, 0x09U, 0xC2U, 0x4BU, 0x3AU, 0x31U, 0xF7U, 0x7FU,
                    0xB2U, 0x9BU, 0xB5U, 0xE6U, 0xB7U, 0x30U, 0xB9U, 0x27U, 0x72U, 0x96U,
                    0x09U, 0x18U, 0x60U, 0xF2U, 0xE6U, 0xCAU, 0x02U, 0x5EU, 0x01U, 0x1AU,
                    0x5BU, 0x10U, 0x51U, 0xF7U, 0x5FU, 0x0EU, 0x8CU, 0x61U, 0xCCU, 0x1DU,
                    0x44U, 0x14U, 0xF0U, 0x28U, 0xC5U, 0x69U, 0xD1U, 0x56U, 0xB9U, 0xFEU,
                    0xB7U, 0x7AU, 0xCFU, 0x07U, 0x4FU, 0x79U, 0x8AU, 0x19U, 0xE5U, 0x5CU,
                    0xC7U, 0xD0U
                },
                /* header length */
                72U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0xF3U, 0x58U, 0x8FU, 0x1AU, 0x30U, 0x45U, 0xF3U, 0xF2U, 0x2FU, 0xE6U,
                    0x3FU, 0x4FU, 0x23U, 0xB6U, 0x4BU, 0x02U, 0xE8U, 0x94U, 0x8CU, 0xB4U,
                    0x06U, 0xE8U, 0x62U, 0x52U, 0x82U, 0xC9U, 0x4EU, 0x26U, 0x81U, 0x01U,
                    0xB2U, 0x85U, 0xEDU, 0xC2U
                },
                /* result   */
                FALSE
            },
            /* Testcase 6 */
            {
                /* key */
                {
                    0xC9U, 0xD8U, 0xE9U, 0xF7U, 0xDAU, 0xFAU, 0xB0U, 0xBEU, 0x94U, 0xAFU,
                    0x84U, 0xCCU, 0xDDU, 0x13U, 0xDBU, 0x2FU, 0x27U, 0xBAU, 0x3EU, 0x04U,
                    0x0DU, 0x8CU, 0xBDU, 0x34U, 0x60U, 0xDDU, 0x11U, 0x7AU, 0x5BU, 0x5FU,
                    0x98U, 0x7FU
                },
                /* plaintext  */
                {
                    0x8FU, 0xEAU, 0x85U, 0xBDU, 0x18U, 0x25U, 0x28U, 0x32U, 0xA7U, 0xDEU,
                    0xCEU, 0x47U, 0x13U, 0xB5U, 0xB0U, 0xB3U, 0xE9U, 0x7FU, 0x5BU
                },
                /* plaintext length */
                19U,
                /* nonce */
                {
                    0x9DU, 0xF1U, 0x85U, 0x8EU, 0x39U, 0x76U, 0xA7U, 0x62U, 0xE8U, 0x4FU,
                    0x9EU, 0x8DU, 0x8EU, 0x52U, 0xF5U, 0xF7U, 0x11U, 0xA6U, 0x97U, 0x58U,
                    0xF3U, 0xBBU, 0x20U, 0xC4U, 0x88U, 0x52U, 0xBEU, 0x18U, 0xEDU, 0xC0U,
                    0x25U, 0xC9U, 0x07U, 0x9DU, 0x28U, 0x2BU, 0x27U, 0x0CU, 0x43U
                },
                /* nonce length */
                39U,
                /* header/aad */
                {
                    0x1DU, 0x62U, 0x02U, 0x21U, 0x24U, 0xB9U, 0xD1U, 0xABU, 0x39U, 0xF3U,
                    0x53U, 0x52U, 0x9DU, 0xA5U, 0x4FU, 0x0FU, 0x01U, 0xFEU, 0x61U, 0xFCU,
                    0x31U, 0x4EU, 0xEBU, 0x98U, 0xCEU, 0x63U, 0xCEU, 0x79U, 0x66U
                },
                /* header length */
                29U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x3CU, 0x5AU, 0xB4U, 0x93U, 0xD9U, 0xE7U, 0x8AU, 0x03U, 0x08U, 0x1FU,
                    0x2CU, 0xDDU, 0xCEU, 0x60U, 0x1FU, 0x79U, 0x6BU, 0x86U, 0x10U, 0xF3U,
                    0x60U, 0x85U, 0x38U, 0x78U, 0xF7U, 0xB0U, 0x34U, 0x0AU, 0x7CU, 0x3CU,
                    0xA3U, 0x1AU, 0x95U, 0xADU, 0x20U
                },
                /* result   */
                FALSE
            },
            /* Testcase 7 */
            {
                /* key */
                {
                    0xC0U, 0xF4U, 0x49U, 0xAFU, 0xB4U, 0x03U, 0x91U, 0xB9U, 0x58U, 0xB9U,
                    0x82U, 0xDDU, 0x83U, 0xC6U, 0xD5U, 0xA7U, 0x91U, 0x37U, 0x9CU, 0x11U,
                    0xB9U, 0xCBU, 0x85U, 0x76U, 0x92U, 0x96U, 0x72U, 0x61U, 0xCBU, 0x4EU,
                    0x12U, 0xC5U
                },
                /* plaintext  */
                {
                    0xA9U, 0x3FU, 0x97U, 0x6AU, 0x9AU, 0x3EU, 0xF8U, 0xAAU, 0xB6U, 0x71U,
                    0xF2U, 0x5BU, 0x14U, 0x17U, 0x6CU, 0xF4U, 0xA7U, 0xB5U, 0x3DU, 0x56U,
                    0x54U, 0x75U, 0x6FU, 0x74U, 0xD2U, 0xE8U, 0x04U, 0x15U, 0xE4U, 0x5BU,
                    0x0CU, 0x71U, 0x90U, 0x78U, 0xECU, 0xB5U, 0x45U, 0x8FU, 0x38U, 0x90U,
                    0x88U, 0x5CU, 0xA7U, 0xA5U, 0x69U, 0xC0U, 0x25U, 0xBAU, 0x62U, 0xD8U,
                    0xCDU, 0xECU, 0x20U, 0x5BU, 0x87U, 0x28U, 0xECU, 0xF7U, 0x8FU, 0x61U,
                    0xF2U, 0xA2U, 0x60U, 0xB3U, 0xECU, 0xC3U, 0xAFU, 0xD9U, 0x0EU, 0x13U,
                    0x2BU, 0xE9U, 0x37U, 0x4BU
                },
                /* plaintext length */
                74U,
                /* nonce */
                {
                    0x03U, 0xB5U, 0xDDU, 0x35U, 0xD2U, 0x41U, 0x35U, 0xA4U, 0xBAU, 0x8AU,
                    0x7FU, 0xBBU, 0x2DU, 0xB1U, 0x65U, 0x9AU, 0x73U, 0x75U, 0x9BU, 0x7EU,
                    0xC4U, 0xAAU, 0x37U, 0x56U
                },
                /* nonce length */
                24U,
                /* header/aad */
                {
                    0x29U, 0xEAU, 0x2EU, 0x1BU, 0xC5U, 0x1AU, 0x3DU, 0x88U, 0x8CU, 0x79U,
                    0x87U, 0x19U, 0xDBU, 0x70U, 0xECU, 0xDFU, 0x99U, 0xC6U, 0x99U, 0x12U,
                    0x7FU, 0xAAU, 0x25U, 0xBDU, 0x92U, 0x60U, 0x08U, 0xBBU, 0xD7U, 0xEFU,
                    0xE3U, 0x81U, 0x70U, 0x88U, 0x6BU, 0x1BU, 0x1DU, 0x4BU, 0xACU, 0xCCU,
                    0xF8U, 0xFEU, 0x23U, 0x64U, 0x4CU, 0xEFU, 0xD9U, 0x66U, 0x85U, 0x8DU,
                    0xFAU, 0x58U, 0xC1U, 0xCEU, 0x95U, 0x66U, 0x15U, 0xB8U, 0x62U, 0xD2U,
                    0x50U, 0x8FU, 0x11U, 0x73U, 0x9BU, 0x8BU, 0xA6U, 0xF0U, 0xA9U, 0xB8U,
                    0xEAU, 0xAAU, 0xA9U
                },
                /* header length */
                73U,
                /* tag length */
                16U,
                /* expected output (ciphertext || tag) */
                {
                    0x96U, 0x77U, 0x60U, 0xB8U, 0x69U, 0x4FU, 0xE3U, 0x7CU, 0x28U, 0x64U,
                    0x7EU, 0x9BU, 0x20U, 0xA5U, 0x04U, 0x50U, 0x54U, 0x1CU, 0xDBU, 0xE3U,
                    0x9BU, 0x81U, 0xBAU, 0x9AU, 0x18U, 0x62U, 0x31U, 0xBAU, 0xFDU, 0x6FU,
                    0xD5U, 0x3EU, 0x1FU, 0xB0U, 0xC7U, 0x4FU, 0x44U, 0x67U, 0xF2U, 0xEEU,
                    0x78U, 0x6BU, 0xD3U, 0x5BU, 0x83U, 0xBFU, 0xE8U, 0x7DU, 0x47U, 0xB7U,
                    0x96U, 0x4AU, 0x9DU, 0xA6U, 0xA3U, 0xFEU, 0xA3U, 0x1DU, 0x66U, 0xCCU,
                    0x86U, 0xF0U, 0xE5U, 0x97U, 0xC8U, 0x10U, 0xB4U, 0xDDU, 0x36U, 0x6DU,
                    0x25U, 0x70U, 0xE5U, 0x6CU, 0xB4U, 0x5BU, 0x34U, 0x5DU, 0xD1U, 0x9DU,
                    0x8FU, 0x0AU, 0xCDU, 0x9CU, 0xFCU, 0x38U, 0x6DU, 0x8AU, 0xF1U, 0x86U
                },
                /* result   */
                FALSE
            }
        }
#endif
    };
    /*lint -restore For testing, we allow not completely initialized elements */

    Esc_UINT8 ciphertext[EscTstAesEax_MAX_BUFFER_SIZE];

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT8 plain[EscTstAesEax_MAX_BUFFER_SIZE];
    const EscTstAesEax_TestcaseT* testcase;

    EscTst_PrintString( "Compliance Test\n" );

    for (i = 0U; (i < EscAesEax_NUMBER_OF_TESTCASES) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintWord( "Testcase ", i );
        testcase = &AesEaxTestcase[keyIndex][i];

        if (AesEaxTestcase[keyIndex][i].tst_result == FALSE)
        {
            /* Do the normal test */
            EscTst_PrintString( "Start encrypting ...\n" );
            returnCode = EscAesEax_Encrypt(
                    keySizes[keyIndex],
                    testcase->tst_key,
                    testcase->tst_nonce,
                    testcase->tst_len_nonce,
                    testcase->tst_header,
                    testcase->tst_len_header,
                    testcase->tst_payload,
                    testcase->tst_len_payload,
                    testcase->tst_len_tag,
                    ciphertext );


            if (returnCode == Esc_NO_ERROR)
            {
                if ( EscTst_Memcmp( ciphertext, AesEaxTestcase[keyIndex][i].tst_ciphertext, (AesEaxTestcase[keyIndex][i].tst_len_payload + AesEaxTestcase[keyIndex][i].tst_len_tag) ) )
                {
                    EscTst_PrintString( "Correct\n\n" );
                    returnCode = Esc_NO_ERROR;
                }
                else
                {
                    EscTst_PrintString( "FAILED!!!\n\n" );
                    returnCode = Esc_KAT_FAILED;
                }
            }

            /* Decrypt test */
            if (returnCode == Esc_NO_ERROR)
            {
                EscTst_PrintString( "Start decrypting ...\n" );

                returnCode = EscAesEax_Decrypt(
                        keySizes[keyIndex],
                        testcase->tst_key,
                        testcase->tst_nonce,
                        testcase->tst_len_nonce,
                        testcase->tst_header,
                        testcase->tst_len_header,
                        testcase->tst_ciphertext,
                        testcase->tst_len_payload + testcase->tst_len_tag,
                        testcase->tst_len_tag,
                        plain );

                if (returnCode == Esc_NO_ERROR)
                {
                    EscTst_PrintString( "Tag verification successful.\n" );

                    if ( EscTst_Memcmp( plain, AesEaxTestcase[keyIndex][i].tst_payload, AesEaxTestcase[keyIndex][i].tst_len_payload ) )
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
                else
                {
                    EscTst_PrintString( "Tag Verification FAILED!!!\n\n\n" );
                }
            }
        }
        else
        {
            /* Do the decrypt Fail test */
            EscTst_PrintString( "Start decrypting ...\n" );

            returnCode = EscAesEax_Decrypt(
                    keySizes[keyIndex],
                    testcase->tst_key,
                    testcase->tst_nonce,
                    testcase->tst_len_nonce,
                    testcase->tst_header,
                    testcase->tst_len_header,
                    testcase->tst_ciphertext,
                    testcase->tst_len_payload + testcase->tst_len_tag,
                    testcase->tst_len_tag,
                    plain );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_ChunkTestEncryption(
    Esc_UINT8 keyIndex,
    const EscTstAesEax_TestcaseT *vector,
    Esc_UINT32 chunkSize)
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT ctx;
    Esc_UINT8 buffer[EscTstAesEax_MAX_BUFFER_SIZE];

    /* Initialization */
    returnCode = EscAesEax_Init(&ctx, keySizes[keyIndex], vector->tst_key);
    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintWord("init failed for chunk size: ", chunkSize);
    }

    /* Start encryption (set parameters) */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_startEncryptDecrypt(
                &ctx,
                vector->tst_len_tag);
        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("start failed for chunk size: ", chunkSize);
        }
    }

    /* Feed in nonce chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_nonce;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Nonce_Update(
                    &ctx,
                    &vector->tst_nonce[offset],
                    length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("nonce update failed for chunk size: ", chunkSize);
        }

        returnCode = EscAesEax_Nonce_Finish(&ctx);

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("nonce finish failed for chunk size: ", chunkSize);
        }
    }

    /* Feed in header chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_header;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Header_Update(
                    &ctx,
                    &vector->tst_header[offset],
                    length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("header update failed for chunk size: ", chunkSize);
        }

        returnCode = EscAesEax_Header_Finish(&ctx);

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("header finish failed for chunk size: ", chunkSize);
        }
    }

    /* Encrypt chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_payload;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Encrypt_Update(&ctx, &vector->tst_payload[offset], &buffer[offset], length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("encrypt update failed for chunk size: ", chunkSize);
        }
    }

    /* Finalize encryption */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Encrypt_Finish(&ctx, &buffer[vector->tst_len_payload], vector->tst_len_tag );
        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("encrypt finish failed for chunk size: ", chunkSize);
        }
    }

    /* Compare result */
    if (returnCode == Esc_NO_ERROR)
    {
        if (EscTst_Memcmp(buffer, vector->tst_ciphertext, vector->tst_len_payload + vector->tst_len_tag) == FALSE)
        {
            EscTst_PrintWord("invalid encryption result for chunk size", chunkSize);
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_ChunkTestDecryption(
    Esc_UINT8 keyIndex,
    const EscTstAesEax_TestcaseT *vector,
    Esc_UINT32 chunkSize)
{
    Esc_ERROR returnCode;
    EscAesEax_ContextT ctx;
    Esc_UINT8 buffer[EscTstAesEax_MAX_BUFFER_SIZE];

    /* Initialization */
    returnCode = EscAesEax_Init(&ctx, keySizes[keyIndex], vector->tst_key);
    if (returnCode != Esc_NO_ERROR)
    {
        EscTst_PrintWord("init failed for chunk size: ", chunkSize);
    }

    /* Start encryption (set parameters) */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_startEncryptDecrypt(
                &ctx,
                vector->tst_len_tag);
        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("start failed for chunk size: ", chunkSize);
        }
    }

    /* Feed in nonce chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_nonce;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Nonce_Update(
                    &ctx,
                    &vector->tst_nonce[offset],
                    length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("nonce update failed for chunk size: ", chunkSize);
        }

        returnCode = EscAesEax_Nonce_Finish(&ctx);

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("nonce finish failed for chunk size: ", chunkSize);
        }
    }

    /* Feed in header chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_header;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Header_Update(
                    &ctx,
                    &vector->tst_header[offset],
                    length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("header update failed for chunk size: ", chunkSize);
        }

        returnCode = EscAesEax_Header_Finish(&ctx);

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("header finish failed for chunk size: ", chunkSize);
        }
    }

    /* Decrypt chunk-wise */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT32 remaining = vector->tst_len_payload;
        Esc_UINT32 offset = 0;

        while ( (returnCode == Esc_NO_ERROR) && (remaining > 0U) )
        {
            Esc_UINT32 length = chunkSize;
            if (length > remaining)
            {
                length = remaining;
            }

            returnCode = EscAesEax_Decrypt_Update(&ctx, &vector->tst_ciphertext[offset], &buffer[offset], length);

            remaining -= length;
            offset += length;
        }

        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("decrypt update failed for chunk size: ", chunkSize);
        }
    }

    /* Finalize decryption */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_Decrypt_Finish(&ctx, &vector->tst_ciphertext[vector->tst_len_payload], vector->tst_len_tag);
        if (returnCode != Esc_NO_ERROR)
        {
            EscTst_PrintWord("decrypt finish failed for chunk size: ", chunkSize);
        }
    }

    /* Compare result */
    if (returnCode == Esc_NO_ERROR)
    {
        if (EscTst_Memcmp(buffer, vector->tst_payload, vector->tst_len_payload) == FALSE)
        {
            EscTst_PrintWord("invalid decryption result for chunk size", chunkSize);
            returnCode = Esc_KAT_FAILED;
        }
    }

    return returnCode;
}


static Esc_ERROR
EscTstAesEax_ChunkTest(
    Esc_UINT8 keyIndex )
{
    /*lint -save -e785 -e9068 Key buffers are not always completely initialized, but only used up to the actual key size. */
    static const EscTstAesEax_TestcaseT vectors[] =
    {
        /* key size 128 bit */
        {
            /* key */
            {
                0x5FU, 0xFFU, 0x20U, 0xCAU, 0xFAU, 0xB1U, 0x19U, 0xCAU, 0x2FU, 0xC7U,
                0x35U, 0x49U, 0xE2U, 0x0FU, 0x5BU, 0x0DU
            },
            /* plaintext  */
            {
                0x1BU, 0xDAU, 0x12U, 0x2BU, 0xCEU, 0x8AU, 0x8DU, 0xBAU, 0xF1U, 0x87U,
                0x7DU, 0x96U, 0x2BU, 0x85U, 0x92U, 0xDDU, 0x2DU, 0x56U
            },
            /* plaintext length */
            18U,
            /* nonce */
            {
                0xDDU, 0xE5U, 0x9BU, 0x97U, 0xD7U, 0x22U, 0x15U, 0x6DU, 0x4DU, 0x9AU,
                0xFFU, 0x2BU, 0xC7U, 0x55U, 0x98U, 0x26U
            },
            /* nonce length */
            16U,
            /* header/aad */
            {
                0x54U, 0xB9U, 0xF0U, 0x4EU, 0x6AU, 0x09U, 0x18U, 0x9AU
            },
            /* header length */
            8U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0x2EU, 0xC4U, 0x7BU, 0x2CU, 0x49U, 0x54U, 0xA4U, 0x89U, 0xAFU, 0xC7U,
                0xBAU, 0x48U, 0x97U, 0xEDU, 0xCDU, 0xAEU, 0x8CU, 0xC3U, 0x3BU, 0x60U,
                0x45U, 0x05U, 0x99U, 0xBDU, 0x02U, 0xC9U, 0x63U, 0x82U, 0x90U, 0x2AU,
                0xEFU, 0x7FU, 0x83U, 0x2AU
            },
            /* result */
            FALSE
        },

#if EscAes_MAX_KEY_BITS >= 192U

        /* key size 192 bit */
        {
            /* key */
            {
                0xECU, 0xD3U, 0x01U, 0x04U, 0xFFU, 0x30U, 0x4CU, 0x77U, 0x77U, 0x5DU,
                0xE6U, 0x5EU, 0xE5U, 0x87U, 0x1CU, 0x55U, 0x92U, 0x80U, 0x64U, 0x6BU,
                0x49U, 0xC6U, 0xAAU, 0xA6U
            },
            /* plaintext  */
            {
                0x27U, 0x1DU, 0x25U, 0x0CU, 0x83U, 0x1FU, 0x38U, 0xA3U, 0x80U, 0x76U,
                0x46U, 0x3AU, 0xFFU, 0x4BU, 0x66U, 0x39U, 0xC1U, 0xE4U, 0xBEU, 0xD2U,
                0x2BU, 0xD5U, 0xA4U, 0xAEU, 0xC1U
            },
            /* plaintext length */
            25U,
            /* nonce */
            {
                0x8CU, 0xE0U, 0x6BU, 0x94U, 0x2BU, 0xFFU, 0x54U, 0x01U, 0xE5U, 0xEAU,
                0x07U, 0xDEU, 0xD8U, 0xCFU, 0x9EU, 0x72U, 0x2AU, 0xD1U, 0xB5U, 0x3AU,
                0x0EU, 0x47U, 0x88U, 0x5BU, 0x28U, 0x48U, 0xCEU, 0xB6U, 0x1DU, 0x26U,
                0xEFU, 0x1CU, 0xD1U, 0xA2U, 0xFBU, 0xDEU, 0x1DU, 0x54U, 0x61U, 0x0FU,
                0x96U, 0x0AU, 0x43U, 0x62U, 0x9DU, 0x6EU, 0x93U, 0xA5U, 0x35U, 0x17U
            },
            /* nonce length */
            50U,
            /* header/aad */
            {
                0x04U, 0x3BU, 0xDFU, 0xA6U, 0x6AU, 0x87U, 0x16U, 0x34U, 0x0AU, 0x78U,
                0xC9U, 0x01U, 0xEDU, 0x8BU, 0x45U, 0x86U, 0xB9U, 0x89U, 0xA2U, 0x0BU,
                0xEFU, 0x07U, 0xFBU, 0x25U, 0x6AU, 0xF1U, 0x5EU, 0xE8U, 0x2AU, 0x2DU,
                0x9FU, 0x6FU, 0xE6U, 0x5BU, 0x0CU, 0xD0U, 0x11U, 0xFEU, 0xFEU, 0x8DU,
                0x3DU, 0x3BU, 0x09U, 0x1FU, 0x7AU, 0xFBU, 0x8DU, 0xDAU, 0x9AU, 0x1DU,
                0x81U, 0x4AU
            },
            /* header length */
            52U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0x10U, 0xF5U, 0x01U, 0x12U, 0xC9U, 0xFBU, 0xD5U, 0x23U, 0x9FU, 0x2DU,
                0xF7U, 0xCEU, 0x9CU, 0xFEU, 0xD0U, 0xC7U, 0xF0U, 0x77U, 0x92U, 0xD3U,
                0xBEU, 0x05U, 0xADU, 0x8DU, 0x67U, 0x6BU, 0x69U, 0xF0U, 0x2DU, 0xD7U,
                0xA1U, 0xD1U, 0xD6U, 0x6BU, 0x44U, 0x11U, 0x13U, 0x69U, 0x56U, 0x52U,
                0x34U
            },
            /* result   */
            FALSE
        },
#endif

#if EscAes_MAX_KEY_BITS == 256U

        /* key size 256 bit */
        {
            /* key */
            {
                0x53U, 0xD4U, 0x34U, 0x55U, 0xBAU, 0xF2U, 0xD6U, 0xA2U, 0xB6U, 0x1DU,
                0x31U, 0x18U, 0x9EU, 0x11U, 0xEAU, 0x70U, 0x28U, 0xCDU, 0xCEU, 0xE0U,
                0x6CU, 0xEBU, 0xD5U, 0x52U, 0xC9U, 0xADU, 0x11U, 0xC4U, 0x69U, 0x8AU,
                0xC9U, 0x2BU
            },
            /* plaintext  */
            {
                0x5BU, 0xEBU, 0x18U, 0xB4U, 0xEFU, 0x2FU, 0x43U, 0x4EU, 0xE1U, 0x57U,
                0xE1U, 0xA2U, 0x4BU, 0x67U, 0x92U, 0x2AU, 0x5EU, 0x12U, 0xFAU, 0x6CU,
                0x3BU, 0x61U, 0x81U, 0xA2U, 0xF5U, 0x34U, 0xBAU, 0x87U, 0x49U, 0x41U,
                0x98U, 0x96U, 0x0FU, 0x41U, 0x65U, 0xDEU, 0xD8U, 0xB1U, 0x14U, 0x0CU,
                0xE2U, 0x60U, 0x6BU, 0x90U, 0x84U, 0xA4U, 0x4CU, 0xB4U, 0x40U, 0x60U,
                0xCFU, 0xE5U, 0xF7U, 0xE5U, 0x7EU, 0xA1U, 0xA5U, 0xFFU, 0x8DU, 0xA4U,
                0x10U, 0x52U, 0xD2U, 0x1AU, 0xA6U, 0x82U, 0x79U
            },
            /* plaintext length */
            67U,
            /* nonce */
            {
                0xEEU, 0x6BU, 0x2BU, 0xE5U, 0x5CU, 0xFEU, 0x9BU, 0x23U, 0x84U, 0x35U,
                0x59U, 0xB8U, 0x0EU, 0x5EU, 0x0AU, 0x07U, 0x32U, 0xF1U, 0x7EU, 0xC0U,
                0xB6U, 0x94U, 0xE0U, 0xFEU, 0x37U, 0xF7U, 0xD7U, 0x7AU, 0x3EU, 0xE4U,
                0x9CU, 0xA1U, 0x17U, 0xF1U, 0xF2U, 0xFBU, 0x0DU, 0xB4U, 0x15U
            },
            /* nonce length */
            39U,
            /* header/aad */
            {
                0x4CU, 0x76U, 0x97U, 0xAAU, 0x28U, 0x63U, 0x73U, 0x61U, 0xCBU, 0x73U,
                0xF8U, 0x2AU
            },
            /* header length */
            12U,
            /* tag length */
            16U,
            /* expected output (ciphertext || tag) */
            {
                0x86U, 0xEFU, 0x03U, 0xF7U, 0xF9U, 0xF3U, 0x3AU, 0x71U, 0x3AU, 0x8BU,
                0x7EU, 0xB9U, 0x42U, 0x89U, 0x4FU, 0xBDU, 0xD2U, 0xE5U, 0x88U, 0x91U,
                0xC8U, 0x2EU, 0x4EU, 0x0DU, 0xFCU, 0xD3U, 0x88U, 0x33U, 0x5CU, 0x1CU,
                0xF9U, 0x60U, 0xBFU, 0x66U, 0xDCU, 0xA6U, 0x75U, 0xBFU, 0xF4U, 0x80U,
                0x88U, 0x01U, 0x04U, 0x00U, 0xC0U, 0x26U, 0x0CU, 0x60U, 0xC4U, 0x0FU,
                0x43U, 0x3CU, 0x23U, 0x8EU, 0xE2U, 0xEBU, 0xA6U, 0xE8U, 0xEDU, 0xE1U,
                0x00U, 0x82U, 0x25U, 0x26U, 0x21U, 0xE7U, 0x7FU, 0xC4U, 0x5CU, 0xC9U,
                0xBBU, 0xEFU, 0x8FU, 0x00U, 0xE3U, 0x23U, 0xB7U, 0x5DU, 0x07U, 0xF5U,
                0x17U, 0xF5U, 0xB4U
            },
            /* result   */
            FALSE
        }
#endif
    };
    /*lint -restore Key buffers are not always completely initialized, but only used up to the actual key size. */

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 chunkSize;

    /* Encryption */

    EscTst_PrintString( "Chunk-wise encryption test\n" );

    for (chunkSize = 1U; (chunkSize <= 20U) && (returnCode == Esc_NO_ERROR); chunkSize++)
    {
        const EscTstAesEax_TestcaseT *vector = &vectors[keyIndex];
        returnCode = EscTstAesEax_ChunkTestEncryption(keyIndex, vector, chunkSize);
    }

    /* Decryption */

    if (returnCode == Esc_NO_ERROR)
    {
        EscTst_PrintString( "Chunk-wise decryption test\n" );

        for (chunkSize = 1U; (chunkSize <= 20U) && (returnCode == Esc_NO_ERROR); chunkSize++)
        {
            const EscTstAesEax_TestcaseT *vector = &vectors[keyIndex];
            returnCode = EscTstAesEax_ChunkTestDecryption(keyIndex, vector, chunkSize);
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstAesEax_InitContext(
    EscAesEax_ContextT* ctx,
    Esc_UINT8 keyIndex,
    EscTstAesEax_TestcaseT tst )
{
    Esc_ERROR returnCode;

    returnCode = EscAesEax_Init( ctx, keySizes[keyIndex], tst.tst_key );

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscAesEax_startEncryptDecrypt(
                ctx,
                tst.tst_len_tag );
    }

    return returnCode;
}

/**
 * Perform the selftest
 */
Esc_ERROR
EscTstAesEax_Perform(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 j;

    for (j = 0; (j < EscTstAesEax_NUM_KEYSIZES) && (returnCode == Esc_NO_ERROR); ++j)
    {
        EscTst_PrintWord( "AES KEY BITS", keySizes[j] );

        /* Check functions for compliance with the given test vectors from NIST */
        returnCode = EscTstAesEax_ComplianceTest(j);
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "CHUNK TEST" );
            returnCode = EscTstAesEax_ChunkTest(j);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTstAesEax_BlockTest(j);
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
