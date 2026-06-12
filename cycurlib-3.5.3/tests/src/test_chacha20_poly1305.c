/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
 \file

 \brief ChaCha20_Poly1305 Selftest

 Checks pre-computed test patterns.

 \see Compliance test vectors from RFC 7539, tools.ietf.org/html/rfc7539

 $Rev: 0000 $
 */
/***************************************************************************/

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "test_chacha20_poly1305.h"
#include "selftest.h"
#include "chacha20_poly1305.h"
#include "poly1305.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

/** Maximum size of a test message. Required for array allocation. */
#define EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE 512

/** Number of RFC-7539 compliance tests for ChaCha20_Poly1305_KeyGen */
#define EscTstChaCha20Poly1305_KeyGen_RFC7359_TESTS_NUM ( sizeof(EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS) / sizeof(EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[0]) )

/** Number of RFC-7539 compliance tests for ChaCha20_Poly1305 */
#define EscTstChaCha20Poly1305_RFC7359_TESTS_NUM ( sizeof(EscTstChaCha20Poly1305_RFC7539_TESTS) / sizeof(EscTstChaCha20Poly1305_RFC7539_TESTS[0]) )

/** Number of tests for ChaCha20_Poly1305 */
#define EscTstChaCha20Poly1305_NUM_TESTS ( sizeof(EscTstChaCha20Poly1305_TESTS) / sizeof(EscTstChaCha20Poly1305_TESTS[0]) )

/***************************************************************************
 * 3. DEFINITIONS                                                         *
 ***************************************************************************/

/** The structure of one Poly1305 KeyGen test case */
typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    const Esc_CHAR* title;
#endif
    Esc_UINT8 key[EscChaCha20Poly1305_KEY_BYTES];
    Esc_UINT8 nonce[EscChaCha20Poly1305_NONCE_BYTES];
    Esc_UINT8 out[EscPoly1305_KEY_BYTES];
} EscTstChaCha20Poly1305_KeyGen_TestT;

/** The structure of one ChaCha20_Poly1305 test case */
typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    const Esc_CHAR* title;
#endif
    const Esc_UINT8 *plaintext;
    const Esc_UINT32 plaintextLength;
    const Esc_UINT8 *aad;
    const Esc_UINT32 aadLength;
    const Esc_UINT8 key[EscChaCha20Poly1305_KEY_BYTES];
    const Esc_UINT8 nonce[EscChaCha20Poly1305_NONCE_BYTES];
    const Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES];
    const Esc_UINT8 *ciphertext;
} EscTstChaCha20Poly1305_TestT;

/** The function type for a ChaCha20_Poly1305 test function */
typedef Esc_ERROR
(*EscTstChaCha20Poly1305_TestFunctionsT)(
    void );

/** The structure for one ChaCha20_Poly1305 test */
typedef struct
{
#if EscTst_ENABLE_LOGGING == 1
    Esc_CHAR name[64];
#endif
    EscTstChaCha20Poly1305_TestFunctionsT TestFunction;
} EscTstChaCha20Poly1305_TestModuleT;

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/*
 Tests from RFC-7539 section 2.6.2.
 */
/*lint -esym(9003,EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS) We allow local objects outside the block scope for large test vectors (increases readability) */
static const EscTstChaCha20Poly1305_KeyGen_TestT EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[] =
{
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 section 2.6.2",
#    endif
        {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        },
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        },
        {
                0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
                0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46
        },
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 Appendix A.4. Test Vector #1",
#    endif
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        {
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
                0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7
        },
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 Appendix A.4. Test Vector #2",
#    endif
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        },
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        },
        {
                0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9, 0xe8, 0x76,
                0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd, 0xe3, 0xfb, 0xb7, 0x39
        },
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 Appendix A.4. Test Vector #3",
#    endif
        {
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
        },
        {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        },
        {
                0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29, 0xf9, 0x4b,
                0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa, 0xd2, 0x33, 0x10, 0xae
        },
    },
};

static const Esc_UINT8 plain_0[] =
{
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
};

static const Esc_UINT8 aad_0[] =
{
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
};

static const Esc_UINT8 cipher_0[] =
{
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};

static const Esc_UINT8 plain_1[] =
{
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20,
    0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66, 0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
    0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20,
    0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d,
    0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65,
    0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
    0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64,
    0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
    0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e,
    0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72,
    0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
    0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72,
    0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
    0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65,
    0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20,
    0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67,
    0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80, 0x9d
};

static const Esc_UINT8 aad_1[] =
{
    0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91
};

static const Esc_UINT8 cipher_1[] =
{
    0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
    0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
    0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
    0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
    0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
    0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
    0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
    0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
    0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
    0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
    0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
    0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
    0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
    0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
    0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
    0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
    0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b
};

/*
 Tests from RFC-7539 section 2.8.2.
 */
static const EscTstChaCha20Poly1305_TestT EscTstChaCha20Poly1305_RFC7539_TESTS[] =
{
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 section 2.6.2",
#    endif
        plain_0,
        114,
        aad_0,
        12,
        {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        },
        {
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
        },
        {
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
        },
        cipher_0
    },
    {
#    if EscTst_ENABLE_LOGGING == 1
        "RFC-7539 Appendix A.5. Test Vector #1",
#    endif
        plain_1,
        265,
        aad_1,
        12,
        {
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
        },
        {
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        },
        {
                0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38
        },
        cipher_1
    }
};

/***************************************************************************
 * 5. DECLARATIONS                                                         *
 ***************************************************************************/

/**
 * Known answer test for Key Gen with test vectors from RFC 7359.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_KeyGen_RFC7359(
    void );

/**
 * Known answer test with test vectors from RFC 7359.
 * Uses the OneShot function without context.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359(
    void );

/**
 * Known answer test with test vectors from RFC 7359.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359_CTX(
    void );

/**
 * Test processing a message in multiple steps of different size piece by piece.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_CompliancePiece(
    const EscTstChaCha20Poly1305_TestT* tst_vec );

/**
 * Test processing a message in multiple steps of different size piece by piece.
 * Uses the RF 7359 test vectors.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359_Piece(
    void );

/**
 * Test the internal state. Calls several functions in a wrong order.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_Function_Order(
    void );

/**
 * Test all functions for null pointer checks.
 *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_Null_Pointer(
    void );

/**
 * Runs all tests.
  *
 * \return Esc_NO_ERROR on success.
 */
static Esc_ERROR
EscTstChaCha20Poly1305_RunTests(
    void );

/***************************************************************************
 * 6. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/
static Esc_ERROR
EscTstChaCha20Poly1305_KeyGen_RFC7359(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 key[EscPoly1305_KEY_BYTES];
    Esc_UINT8 i;

    EscTst_Memset( key, EscPoly1305_KEY_BYTES, 0 );

    for (i = 0; i < EscTstChaCha20Poly1305_KeyGen_RFC7359_TESTS_NUM; i++)
    {
#if EscTst_ENABLE_LOGGING == 1
        EscTst_PrintString( "Testcase: " );
        EscTst_PrintString( EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[i].title );
        EscTst_PrintString( "\n" );
#endif
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_KeyGen( EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[i].key,
                                                     EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[i].nonce,
                                                     key );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_KeyGen_RFC7539_TESTS[i].out,
                                              EscPoly1305_KEY_BYTES,
                                              key,
                                              EscPoly1305_KEY_BYTES );
        }
    }

    return returnCode;
}

static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 resultBuffer[EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE];
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES];
    Esc_UINT8 i;

    EscTst_Memset( resultBuffer, EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE, 0 );
    EscTst_Memset( tag, EscChaCha20Poly1305_TAG_BYTES, 0 );

    for (i = 0; (i < EscTstChaCha20Poly1305_RFC7359_TESTS_NUM) && (returnCode == Esc_NO_ERROR) ; i++)
    {
        EscTst_PrintString( "Testcase: " );
        EscTst_PrintString( EscTstChaCha20Poly1305_RFC7539_TESTS[i].title );
        EscTst_PrintString( "\n" );

        /* encrypt and create tag */
        EscTst_PrintString( "- Encrypt and MAC -\n" );
        returnCode = EscChaCha20Poly1305_Encrypt( EscTstChaCha20Poly1305_RFC7539_TESTS[i].key,
                                                   EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce,
                                                   EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                   EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength,
                                                   EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintext,
                                                   EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                                   resultBuffer,
                                                   tag );
        returnCode = EscTst_CheckResultSuccess( returnCode );

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                              EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                              resultBuffer,
                                              EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_RFC7539_TESTS[i].tag,
                                              EscChaCha20Poly1305_TAG_BYTES,
                                              tag,
                                              EscChaCha20Poly1305_TAG_BYTES );
        }

        /* verify and decrypt */
        EscTst_PrintString( "- Verify and Decrypt -\n" );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt( EscTstChaCha20Poly1305_RFC7539_TESTS[i].key,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                                       resultBuffer,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].tag  );
            returnCode = EscTst_CheckResultSuccess( returnCode );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintext,
                                              EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                              resultBuffer,
                                              EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength);
        }
        /* verify and decrypt, failure case */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "- Verify and Decrypt, failure case -\n" );
            tag[0] ^= 0xffU;
            EscTst_Memset( resultBuffer, EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE, 0 );

            returnCode = EscChaCha20Poly1305_Decrypt( EscTstChaCha20Poly1305_RFC7539_TESTS[i].key,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                                       EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                                       resultBuffer,
                                                       tag );

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
        }
    }
    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359_CTX(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 resultBuffer[EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE];
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES];
    Esc_UINT8 i;
    EscChaCha20Poly1305_ContextT ctx;

    EscTst_Memset( resultBuffer, EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE, 0 );
    EscTst_Memset( tag, EscChaCha20Poly1305_TAG_BYTES, 0 );

    for (i = 0; (i < EscTstChaCha20Poly1305_RFC7359_TESTS_NUM) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTst_PrintString( "Testcase: " );
        EscTst_PrintString( EscTstChaCha20Poly1305_RFC7539_TESTS[i].title );
        EscTst_PrintString( "\n" );

        /* encrypt and create tag */
        EscTst_PrintString( "- Encrypt and MAC -\n" );
        returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].key );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode =  EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                        EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                        EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx,
                                                             EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintext,
                                                             resultBuffer,
                                                             EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
        }

        returnCode = EscTst_CheckResultSuccess( returnCode );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                     EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                     resultBuffer,
                                     EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( EscTstChaCha20Poly1305_RFC7539_TESTS[i].tag,
                                     EscChaCha20Poly1305_TAG_BYTES,
                                     tag,
                                     EscChaCha20Poly1305_TAG_BYTES );
        }

        /* verify and decrypt */
        EscTst_PrintString( "- Verify and Decrypt -\n" );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].key );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt_Update( &ctx,
                                                     EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                                     resultBuffer,
                                                     EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt_Finish( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].tag );
        }

        returnCode = EscTst_CheckResultSuccess( returnCode );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings(EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintext,
                                    EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength,
                                    resultBuffer,
                                    EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength);
        }

        /* verify and decrypt, failure case */
        if (returnCode == Esc_NO_ERROR)
        {
            EscTst_PrintString( "- Verify and Decrypt, failure case -\n" );
            tag[0] ^= 0xffU;
            EscTst_Memset( resultBuffer, EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE, 0 );

            returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].key );
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[i].nonce );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                        EscTstChaCha20Poly1305_RFC7539_TESTS[i].aad,
                                                        EscTstChaCha20Poly1305_RFC7539_TESTS[i].aadLength );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_Decrypt_Update( &ctx,
                                                             EscTstChaCha20Poly1305_RFC7539_TESTS[i].ciphertext,
                                                             resultBuffer,
                                                             EscTstChaCha20Poly1305_RFC7539_TESTS[i].plaintextLength );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_Decrypt_Finish( &ctx, tag );
            }

            returnCode = EscTst_CheckResultFailed( &returnCode, Esc_INVALID_MAC );
        }
    }
    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_CompliancePiece(
    const EscTstChaCha20Poly1305_TestT* tst_vec )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 resultBuffer[EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE];
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES];
    EscChaCha20Poly1305_ContextT ctx;
    Esc_UINT32 chunkSize;

    EscTst_PrintString( "\n Tests the vector piece by piece with different chunk lengths\n" );

    /* Test Encrypt */
    EscTst_PrintString( "\n Test Encrypt functions\n" );
    /* EscPoly1305_BLOCK_SIZE: 16U, ChaCha20 Block size: 64U */
    for (chunkSize = 1U; (chunkSize <= 64U) && (returnCode == Esc_NO_ERROR); chunkSize++)
    {
        Esc_UINT32 remainingLen;
        Esc_UINT32 currentLen;
        Esc_UINT32 offset;

        EscTst_PrintWord("chunksize: ", chunkSize );
        returnCode = EscChaCha20Poly1305_Init( &ctx, tst_vec->key );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode =  EscChaCha20Poly1305_startEncryptDecrypt( &ctx, tst_vec->nonce );
        }

        /* Start with AAD streaming */
        remainingLen = tst_vec->aadLength;
        offset = 0U;

        /* Call UpdateAad() with zero length and Null Ptr first */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, Esc_NULL_PTR, 0U );
        }

        /* Call UpdateAad() with given chunkSize until message is processed */
        while (remainingLen > 0U)
        {
            if (remainingLen > chunkSize)
            {
                currentLen = chunkSize;
            }
            else
            {
                currentLen = remainingLen;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, &tst_vec->aad[offset], currentLen );
            }

            remainingLen -= currentLen;
            offset += currentLen;
        }

        /* Call UpdateAad() with zero length again */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, &tst_vec->aad[offset], 0U );
        }

        /* Now process plaintext */
        remainingLen = tst_vec->plaintextLength;
        offset = 0U;

        /* Call Encrypt_Update() with zero length and Null Ptr for plaintext first */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx, Esc_NULL_PTR, &resultBuffer[offset], 0U );
        }

        /* Call Encrypt_Update() with given chunkSize until message is processed */
        while (remainingLen > 0U)
        {
            if (remainingLen > chunkSize)
            {
                currentLen = chunkSize;
            }
            else
            {
                currentLen = remainingLen;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx, &tst_vec->plaintext[offset], &resultBuffer[offset], currentLen );
            }

            remainingLen -= currentLen;
            offset += currentLen;
        }

        /* Call Encrypt_Update() with zero length and Null Ptr for ciphertext again */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx, &tst_vec->plaintext[offset], Esc_NULL_PTR, 0U );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
        }

        returnCode = EscTst_CheckResultSuccess( returnCode );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( tst_vec->ciphertext,
                                     tst_vec->plaintextLength,
                                     resultBuffer,
                                     tst_vec->plaintextLength );
        }
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( tst_vec->tag,
                                     EscChaCha20Poly1305_TAG_BYTES,
                                     tag,
                                     EscChaCha20Poly1305_TAG_BYTES );
        }
    }


    /* Test Decrypt */
    EscTst_PrintString( "\n Test Decrypt functions\n" );
    /* EscPoly1305_BLOCK_SIZE: 16U, ChaCha20 Block size: 64U */
    for (chunkSize = 1U; (chunkSize <= 64U) && (returnCode == Esc_NO_ERROR); chunkSize++)
    {
        Esc_UINT32 remainingLen;
        Esc_UINT32 currentLen;
        Esc_UINT32 offset;

        EscTst_PrintWord("chunksize: ", chunkSize );
        returnCode = EscChaCha20Poly1305_Init( &ctx, tst_vec->key );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode =  EscChaCha20Poly1305_startEncryptDecrypt( &ctx, tst_vec->nonce );
        }

        /* Start with AAD streaming */
        remainingLen = tst_vec->aadLength;
        offset = 0U;

        /* Call UpdateAad() with zero length first */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, &tst_vec->aad[offset], 0U );
        }

        /* Call UpdateAad() with given chunkSize until message is processed */
        while (remainingLen > 0U)
        {
            if (remainingLen > chunkSize)
            {
                currentLen = chunkSize;
            }
            else
            {
                currentLen = remainingLen;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, &tst_vec->aad[offset], currentLen );
            }

            remainingLen -= currentLen;
            offset += currentLen;
        }

        /* Call UpdateAad() with zero length again */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_UpdateAad( &ctx, &tst_vec->aad[offset], 0U );
        }

        /* Now process plaintext */
        remainingLen = tst_vec->plaintextLength;
        offset = 0U;

        /* Call Encrypt_Update() with zero length and Null Ptr for both buffers first */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt_Update( &ctx, Esc_NULL_PTR, Esc_NULL_PTR, 0U );
        }

        /* Call Encrypt_Update() with given chunkSize until message is processed */
        while (remainingLen > 0U)
        {
            if (remainingLen > chunkSize)
            {
                currentLen = chunkSize;
            }
            else
            {
                currentLen = remainingLen;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscChaCha20Poly1305_Decrypt_Update( &ctx, &tst_vec->ciphertext[offset], &resultBuffer[offset], currentLen );
            }

            remainingLen -= currentLen;
            offset += currentLen;
        }

        /* Call Encrypt_Update() with zero length again */
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt_Update( &ctx, &tst_vec->ciphertext[offset], &resultBuffer[offset], 0U );
        }

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscChaCha20Poly1305_Decrypt_Finish( &ctx, tst_vec->tag );
        }

        returnCode = EscTst_CheckResultSuccess( returnCode );
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscTst_CheckStrings( tst_vec->plaintext,
                                     tst_vec->plaintextLength,
                                     resultBuffer,
                                     tst_vec->plaintextLength );
        }
    }

    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_RFC7359_Piece(
    void )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    for (i = 0; (i < EscTstChaCha20Poly1305_RFC7359_TESTS_NUM) && (returnCode == Esc_NO_ERROR) ; i++)
    {
        returnCode = EscTstChaCha20Poly1305_CompliancePiece( &EscTstChaCha20Poly1305_RFC7539_TESTS[i] );
    }

    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_Function_Order(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 resultBuffer[EscTstChaCha20Poly1305_MAX_SIZE_MESSAGE];
    Esc_UINT8 tag[EscChaCha20Poly1305_TAG_BYTES];
    EscChaCha20Poly1305_ContextT ctx;

    EscTst_PrintString( "Testing double finish\n" );
    returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].key );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].nonce );
    }
    /* AAD is optional */
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx,
                                                         EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintext,
                                                         resultBuffer,
                                                         EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintextLength );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }

    EscTst_PrintString( "Testing update after finish\n" );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].key );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].nonce );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aad,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aadLength );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx,
                                                         EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintext,
                                                         resultBuffer,
                                                         EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintextLength );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Finish( &ctx, tag );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aad,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aadLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Update( &ctx,
                                                 EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintext,
                                                 resultBuffer,
                                                 EscTstChaCha20Poly1305_RFC7539_TESTS[0].plaintextLength );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }

    EscTst_PrintString( "Testing startEncryptDecrypt after update\n" );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Init( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].key );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].nonce );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( &ctx,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aad,
                                                    EscTstChaCha20Poly1305_RFC7539_TESTS[0].aadLength );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( &ctx, EscTstChaCha20Poly1305_RFC7539_TESTS[0].nonce );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_UNEXPECTED_FUNCTION_CALL );
    }

    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_Null_Pointer(
    void )
{
    Esc_ERROR returnCode;
    Esc_UINT8 dummy[64] = { 0 };

    /* keygen */
    EscTst_PrintString("Testing Keygen\n");
    returnCode = EscChaCha20Poly1305_KeyGen(Esc_NULL_PTR, dummy, dummy);
    returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_KeyGen(dummy, Esc_NULL_PTR, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_KeyGen(dummy, dummy, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* Init */
    EscTst_PrintString("Testing Init\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Init( Esc_NULL_PTR, dummy );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* StartEncryptDecrypt */
    EscTst_PrintString("Testing StartEncryptDecrypt\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_startEncryptDecrypt( Esc_NULL_PTR, dummy );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* UpdateAade */
    EscTst_PrintString("Testing Encrypt_Update\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_UpdateAad( Esc_NULL_PTR, dummy, 64 );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* Encrypt_Update */
    EscTst_PrintString("Testing Encrypt_Update\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Update( Esc_NULL_PTR, dummy, dummy, 64 );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* Encrypt_Finish */
    EscTst_PrintString("Testing Encrypt_Finish\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Encrypt_Finish( Esc_NULL_PTR, dummy );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* Decrypt_Finish */
    EscTst_PrintString("Testing Decrypt_Finish\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt_Finish( Esc_NULL_PTR, dummy );
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* Encrypt */
    EscTst_PrintString("Testing Encrypt\n");
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in Init */
        returnCode = EscChaCha20Poly1305_Encrypt(Esc_NULL_PTR, dummy, dummy, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in startEncryptDecrypt */
        returnCode = EscChaCha20Poly1305_Encrypt(dummy, Esc_NULL_PTR, dummy, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in UpdateAad */
        returnCode = EscChaCha20Poly1305_Encrypt(dummy, dummy, Esc_NULL_PTR, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in Encrypt_Update */
        returnCode = EscChaCha20Poly1305_Encrypt(dummy, dummy, dummy, 64, Esc_NULL_PTR, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in Encrypt_Update */
        returnCode = EscChaCha20Poly1305_Encrypt(dummy, dummy, dummy, 64, dummy, 64, Esc_NULL_PTR, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        /* Failure in Encrypt_Finish */
        returnCode = EscChaCha20Poly1305_Encrypt(dummy, dummy, dummy, 64, dummy, 64, dummy, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    /* decrypt */
    EscTst_PrintString("Testing Decrypt\n");
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(Esc_NULL_PTR, dummy, dummy, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(dummy, Esc_NULL_PTR, dummy, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(dummy, dummy, Esc_NULL_PTR, 64, dummy, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(dummy, dummy, dummy, 64, Esc_NULL_PTR, 64, dummy, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(dummy, dummy, dummy, 64, dummy, 64, Esc_NULL_PTR, dummy);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscChaCha20Poly1305_Decrypt(dummy, dummy, dummy, 64, dummy, 64, dummy, Esc_NULL_PTR);
        returnCode = EscTst_CheckResultFailed( &returnCode, Esc_NULL_POINTER_ERROR );
    }
    return returnCode;
}


static Esc_ERROR
EscTstChaCha20Poly1305_RunTests(
    void )
{
    /* The test cases */
    static const EscTstChaCha20Poly1305_TestModuleT EscTstChaCha20Poly1305_TESTS[] =
    {
        {
#if EscTst_ENABLE_LOGGING == 1
            "RFC 7359 section 2.6.2 KeyGen Compliance",
#endif
            EscTstChaCha20Poly1305_KeyGen_RFC7359
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "RFC 7359 section 2.8.2 AEAD Mode Compliance",
#endif
            EscTstChaCha20Poly1305_RFC7359
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "RFC 7359 section 2.8.2 AEAD Mode Compliance Context-Mode",
#endif
            EscTstChaCha20Poly1305_RFC7359_CTX
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "RFC 7359 section 2.8.2 AEAD Mode Compliance Piece by piece",
#endif
            EscTstChaCha20Poly1305_RFC7359_Piece
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "Function order check",
#endif
            EscTstChaCha20Poly1305_Function_Order
        },
        {
#if EscTst_ENABLE_LOGGING == 1
            "Null pointer parameter check",
#endif
            EscTstChaCha20Poly1305_Null_Pointer
        },
    };

    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 i;

    EscTst_PrintString( "Testing ChaCha20_Poly1305\n\n" );

    for (i = 0U; (i < EscTstChaCha20Poly1305_NUM_TESTS) && (returnCode == Esc_NO_ERROR); i++)
    {
        EscTstChaCha20Poly1305_TestFunctionsT TestFunction;

        EscTst_PrintString( "*** " );
        EscTst_PrintString( EscTstChaCha20Poly1305_TESTS[i].name );
        EscTst_PrintString( " ***\n" );

        TestFunction = EscTstChaCha20Poly1305_TESTS[i].TestFunction;
        returnCode = TestFunction();

        EscTst_PrintString( "\n" );
    }

    return returnCode;
}

Esc_ERROR
EscTstChaCha20Poly1305_Perform(
    void )
{
    Esc_ERROR returnCode;
    returnCode = EscTstChaCha20Poly1305_RunTests();

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
