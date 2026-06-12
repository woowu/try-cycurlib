/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Error code definitions for the CycurLIB.

   This file will be included in any CycurLIB module.

   $Rev: 796 $
 */
/***************************************************************************/
/**
 * \ingroup group_error
 * @{
 */
#ifndef ESC_CYCURLIB_ERROR_H_
#define ESC_CYCURLIB_ERROR_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* --------------- Common error codes ---------------------- */

/**
 * No error => everything is ok
 */
#define Esc_NO_ERROR                        0U

/**
 * A NULL-pointer was passed to a function which requires a valid pointer .
 */
#define Esc_NULL_POINTER_ERROR              1U

/**
 * A function argument is wrong.
 */
#define Esc_INVALID_PARAMETER               2U

/**
 * A given MAC or GCM/CCM-tag is invalid.
 */
#define Esc_INVALID_MAC                     3U

/**
 * A signature verification failed due to an invalid signature.
 */
#define Esc_INVALID_SIGNATURE               4U

/**
 * An internal error occurred.
 */
#define Esc_INTERNAL_FUNCTION_ERROR         5U

/**
 * A given buffer is too small.
 */
#define Esc_INSUFFICIENT_BUFFER_SIZE        6U

/**
 * The given key length does not match any of the configured lengths.
 */
#define Esc_INVALID_KEY_LENGTH              7U

/**
 * The given public key is invalid.
 */
#define Esc_INVALID_PUBLIC_KEY              8U

/**
 * The given private key is invalid.
 */
#define Esc_INVALID_PRIVATE_KEY             9U

/**
 * Key generation failed.
 */
#define Esc_KEY_GENERATION_FAILED           10U

/**
 * Computation not finished. Must call the same function again.
 */
#define Esc_AGAIN                           11U

/* --------------- Related to DER parser ------------------- */

/**
 * The end of the input buffer was reached unexpectedly while parsing
 * DER-encoded data.
 */
#define Esc_READ_BEYOND_END                 20U

/**
 * The DER parser encountered an unsupported tag.
 */
#define Esc_UNSUPPORTED_TAG                 21U

/**
 * The DER-encoded data is malformed.
 */
#define Esc_PARSE_ERROR                     22U

/**
 * This code is only used by functions of the DER-parser which assume
 * that an OID matches a certain value.
 */
#define Esc_INVALID_OBJECT_IDENTIFIER       23U

/* --------------- Related to ECC -------------------------- */

/**
 * The key validation for the given ECC key failed.
 */
#define Esc_INVALID_ECC_KEY                 30U

/**
 * The curve identifier is invalid or the selected curve is not activated.
 */
#define Esc_INVALID_CURVE                   31U

/* --------------- Related to Hash-DRBG -------------------- */

/**
 * The Hash-DRBG must be reseeded before it can be used again.
 */
#define Esc_RNG_MUST_BE_RESEEDED            40U

/* --------------- Related to PKCS#1 / RSA ----------------- */

/**
 * Unsupported digest type for PKCS#1 specified.
 */
#define Esc_UNSUPPORTED_DIGEST_TYPE         50U

/**
 * The message is too long for the given padding method.
 */
#define Esc_MSG_TOO_LONG_FOR_PADDING        51U

/**
 * Decryption error occurred.
 */
#define Esc_DECRYPTION_ERROR                53U

/**
 * Key generation failed, because (p-1) or (q-1) is not co-prime to public exponent e.
 */
#define Esc_KEY_GENERATION_COPRIME_ERROR    54U

/* --------------- Related to X509 ------------------------- */

/**
 * The length of the certificate does not match the length
 * passed to the function.
 */
#define Esc_INVALID_CERT_LENGTH             60U

/**
 * An unsupported signature algorithm is specified in the certificate.
 */
#define Esc_INVALID_SIGN_ALGORITHM          61U

/**
 * An unsupported public key algorithm is specified in the certificate.
 */
#define Esc_INVALID_PUBKEY_ALGORITHM        62U

/* --------------- Related to the test library ------------- */

/**
 * A test succeeded which is supposed to fail.
 */
#define Esc_NEGATIVE_TEST_FAILED            70U

/**
 * A known-answer test failed.
 */
#define Esc_KAT_FAILED                      71U

/**
 * A type test failed. Therefore, the configuration of the basic types in the
 * file cycurlib_config.h is wrong for the given target platform.
 */
#define Esc_TYPE_TEST_FAILED                72U

/**
 * A Monte-Carlo test failed.
 */
#define Esc_MCT_FAILED                      74U

/* --------------- Misc Errors --------------------------- */

/**
 * Data to large for sufficient buffer
 */
#define Esc_OUT_OF_RANGE                    81U

/**
 * Other function call expected
 */
#define Esc_UNEXPECTED_FUNCTION_CALL        87U


/*------------------- AES key wrap errors -------------------*/

/**
 * Input IV does not match output IV for unwrap (authenticity check failed).
 */
#define Esc_IV_MISMATCH                     90U

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/** @} */

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
