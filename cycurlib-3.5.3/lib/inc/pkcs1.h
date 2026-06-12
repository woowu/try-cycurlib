/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       PKCS#1 v2.2 common header file

   \see         www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_PKCS1_H_
#define ESC_PKCS1_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "rsa.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** SHA-1 algorithm. The length of the hash's digest is 20 byte. */
#define EscPkcs1_DIGEST_TYPE_SHA1         2U

/** SHA-224 algorithm. The length of the hash's digest is 28 byte. */
#define EscPkcs1_DIGEST_TYPE_SHA224       3U

/** SHA-256 algorithm. The length of the hash's digest is 32 byte. */
#define EscPkcs1_DIGEST_TYPE_SHA256       4U

/** SHA-384 algorithm. The length of the hash's digest is 48 byte. */
#define EscPkcs1_DIGEST_TYPE_SHA384       5U

/** SHA-512 algorithm. The length of the hash's digest is 64 byte. */
#define EscPkcs1_DIGEST_TYPE_SHA512       6U

/***************************************************************************
* 5. TYPE DEFINITIONS                                                     *
***************************************************************************/

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
