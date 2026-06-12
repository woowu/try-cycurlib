/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Modular exponentiation interface.
                Provides abstraction for sliced and non-sliced variants.

   $Rev: 2716 $
 */
/***************************************************************************/

#ifndef ESC_MODEXP_H_
#define ESC_MODEXP_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "rsa_cfg.h"

#if EscRsa_SLICING_ENABLED == 0
#include "modexp_s0.h"
#else
#include "modexp_s1.h"
#endif

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/* Create short-cuts to have differentiation between sliced and non-sliced only here */

#if EscRsa_SLICING_ENABLED == 0

/** Initialize modular exponentiation for public (small) exponents */
#define EscModExp_PubInit      EscModExpS0_PubInit
/** Run modular exponentiation for public (small) exponents */
#define EscModExp_PubRun       EscModExpS0_PubRun
/** Initialize modular exponentiation for private (large) exponents */
#define EscModExp_PrivInit     EscModExpS0_PrivInit
/** Run modular exponentiation for private (large) exponents */
#define EscModExp_PrivRun      EscModExpS0_PrivRun

#else

/** Initialize modular exponentiation for public (small) exponents */
#define EscModExp_PubInit      EscModExpS1_PubInit
/** Run modular exponentiation for public (small) exponents */
#define EscModExp_PubRun       EscModExpS1_PubRun
/** Initialize modular exponentiation for private (large) exponents */
#define EscModExp_PrivInit     EscModExpS1_PrivInit
/** Run modular exponentiation for private (large) exponents */
#define EscModExp_PrivRun      EscModExpS1_PrivRun

#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

#if EscRsa_SLICING_ENABLED == 0

/** Modular exponentiation context (public keys) */
typedef EscModExpS0_PubContext      EscModExp_PubContext;
/** Modular exponentiation context (private keys) */
typedef EscModExpS0_PrivContext     EscModExp_PrivContext;

#else

/** Modular exponentiation context (public keys) */
typedef EscModExpS1_PubContext      EscModExp_PubContext;
/** Modular exponentiation context (private keys) */
typedef EscModExpS1_PrivContext     EscModExp_PrivContext;

#endif

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_MODEXP_H_ */
