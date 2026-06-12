/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Main configuration file for the CycurLIB.

   This file will be included in any CycurLIB module.
   It has to be adapted for each implementation.

   $Rev: 796 $
 */
/***************************************************************************/

#ifndef ESC_CYCURLIB_CONFIG_H_
#define ESC_CYCURLIB_CONFIG_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_error.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef Esc_USE_STDLIB_DECLARATIONS
/**
If enabled use type definitions from stdint.h / stdbool.h
*/
#   define Esc_USE_STDLIB_DECLARATIONS 1
#endif

#ifndef Esc_HAS_INT64
/**
Platform has Esc_UINT64 data types.
Can speed up ECC, RSA and SHA-512 performance substantially.
This define is also required for some functions of the AES_XTS module.
*/
#   define Esc_HAS_INT64 0
#endif

#ifndef Esc_OPTIMIZE_SPEED
/**
Enable speed optimized default configuration of algorithms, e.g.
    - AES
    - CRC_32
    - DH
    - ECC
    - RSA
    - Whirlpool
*/
#   define Esc_OPTIMIZE_SPEED 1
#endif

#ifndef Esc_NDEBUG
/** Defining Esc_NDEBUG to 1 disables asserts. */
#   define Esc_NDEBUG 1
#endif

/*********** FIPS ************/

/* Hash-DRBG for FIPS certification */

/** Hash-DRBG security strength */
#define EscHashDrbg_SECURITY_STRENGTH  256U
/** Hash-DRBG entropy length */
#define EscHashDrbg_ENTROPY_LEN         32U
/** Hash-DRBG nonce length */
#define EscHashDrbg_NONCE_LEN           16U

/* Fips ECC */
/** Enable ECC NIST curve P-192 (secp192r1) */
#define EscEcc_SECP_192_ENABLED         1
/** Enable ECC NIST curve P-224 (secp224r1) */
#define EscEcc_SECP_224_ENABLED         1
/** Enable ECC NIST curve P-256 (secp256r1) */
#define EscEcc_SECP_256_ENABLED         1
/** Enable ECC NIST curve P-384 (secp384r1) */
#define EscEcc_SECP_384_ENABLED         1
/** Enable ECC NIST curve P-521 (secp521r1) */
#define EscEcc_SECP_521_ENABLED         1

/** FIPS DH */
#define EscDh_KEY_BITS_MAX          2048U

/** FIPS ECDH */
#define EscEcc_ECDH_ENABLED             1

/** FIPS ECDSA */
#define EscEcc_ECDSA_ENABLED            1
/** FIPS ECDSA maximum digest length */
#define EscEcc_MAX_DIGEST_LEN         64U

/* FIPS RSA */
/** Enable RSA key generation */
#define EscRsa_GENRSA_ENABLED           1
/** RSA maximum key size in bits */
#define EscRsa_KEY_BITS_MAX         4096U
/** RSASSA v1.5: Disable Hash types: MD2 */
#define EscPkcs1RsaSsaV15_MD2_ENABLED           0
/** RSASSA v1.5: Disable Hash types: MD5 */
#define EscPkcs1RsaSsaV15_MD5_ENABLED           0
/** RSASSA v1.5: Disable Hash types: RIPEMD-160 */
#define EscPkcs1RsaSsaV15_RIPEMD160_ENABLED     0

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if Esc_NDEBUG == 1
/** In Release version we disable the Esc_ASSERT function. */
#    define Esc_ASSERT( p ) ( (void)0 )
#else
#    include <assert.h>
/** In Debug version we use the assert macro from the standard library */
#    define Esc_ASSERT( p ) assert( p )
#endif

/** Macro for unused parameters */
#define Esc_UNUSED_PARAM( x ) ( (void)(x) )

/** The NULL pointer */
#define Esc_NULL_PTR    ((void*)0)

#ifndef FALSE
/** Esc_BOOL value false. */
#   define FALSE       ( (Esc_BOOL) 0 )
#endif

#ifndef TRUE
/** Esc_BOOL value true. */
#   define TRUE       ( (Esc_BOOL) 1 )
#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/* C99 based type definitions for integral types */
#if Esc_USE_STDLIB_DECLARATIONS == 1
#   include <stdint.h>

#if Esc_HAS_INT64 == 1
/** 64 bit unsigned integer typedef */
typedef uint64_t    Esc_UINT64;
/** 64 bit signed integer typedef */
typedef int64_t     Esc_SINT64;
#endif

/** 32 bit unsigned integer typedef */
typedef uint32_t    Esc_UINT32;
/** 16 bit unsigned integer typedef */
typedef uint16_t    Esc_UINT16;
/** 8 bit unsigned integer typedef */
typedef uint8_t     Esc_UINT8;
/** 32 bit signed integer typedef */
typedef int32_t     Esc_SINT32;
/** 16 bit signed integer typedef */
typedef int16_t     Esc_SINT16;
/** 8 bit signed integer typedef */
typedef int8_t      Esc_SINT8;
#endif

/* The following typedefs are only used if the types from stdint.h
 * are not used (i.e. Esc_USE_STDLIB_DECLARATIONS is set to 0, see above).
 */
#if Esc_USE_STDLIB_DECLARATIONS == 0

#if Esc_HAS_INT64 == 1
/** 64 bit unsigned integer. Not MISRA compatible. */
typedef unsigned long long Esc_UINT64;
/** 64 bit signed integer. Not MISRA compatible. */
typedef signed long long Esc_SINT64;
#endif

/** 32 bit unsigned integer. */
typedef unsigned long Esc_UINT32;

/** 16 bit unsigned integer. */
typedef unsigned short Esc_UINT16;

/** 8 bit unsigned integer. */
typedef unsigned char Esc_UINT8;

/** 32 bit signed integer. */
typedef signed long Esc_SINT32;

/** 16 bit signed integer. */
typedef signed short Esc_SINT16;

/** 8 bit signed integer. */
typedef signed char Esc_SINT8;

#endif /* Esc_USE_STDLIB_DECLARATIONS == 0 */

/** Single character of a C-Style string. */
typedef char Esc_CHAR;

/** Type can only be TRUE (Non-zero) or FALSE (Zero). Boolean operations deliver the expected results. */
typedef Esc_UINT8 Esc_BOOL;

/** 8-bit unsigned integer for errors */
typedef Esc_UINT8 Esc_ERROR;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
