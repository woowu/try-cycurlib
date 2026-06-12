/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Modular exponentiation (not sliced).

   $Rev: 2716 $
 */
/***************************************************************************/

#ifndef ESC_MODEXP_S0_H_
#define ESC_MODEXP_S0_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "rsa_cfg.h"
#include "_rsa.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Context to store state and intermediate results of
    modular exponentiation for public (small) exponents */
typedef struct
{
#if EscRsa_USE_MONTGOM_MUL == 1
    /** Temporary element */
    EscRsa_FieldElementT x_;
    /** Temporary element */
    EscRsa_FieldElementT y_;
    /** Montgomery parameters */
    EscRsa_MontGomElementT mg;
#endif

    /** Buffer to store multiplication results */
    EscRsa_FieldElementLongT multiplication_result;
} EscModExpS0_PubContext;

/** Context to store state and intermediate results of
    modular exponentiation for private (large) exponents */
typedef struct
{
#if EscRsa_USE_MONTGOM_MUL == 1
    /** Temporary element */
    EscRsa_FieldElementT x_;
    /** Temporary element */
    EscRsa_FieldElementT y_;
    /** Montgomery parameters */
    EscRsa_MontGomElementT mg;
#endif

#if EscRsa_USE_SLIDING_WINDOW == 1
    /** Array to store pre-computed multiplication results */
    EscRsa_FieldElementT fe_array[EscRsa_NUM_WINDOW_ELEMENTS];
#endif

    /** Buffer to store multiplication results */
    EscRsa_FieldElementLongT multiplication_result;
} EscModExpS0_PrivContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initialize modular exponentiation for public (small) exponents.
Modular exponentiation means: y = b^e mod m.

\param[in]  ctx         The context to store state and intermediate results of the computation.
\param[in]  exponent    The exponent e.
\param[in]  keySizeBits The size of the modulus in bits.
\param[in]  modulus     The modulus m.
\param[in,out] inOut    In: The base b of the modular exponentiation.
                        Out: The result y of the modular exponentiation.
 */
void
EscModExpS0_PubInit(
    EscModExpS0_PubContext *ctx,
    Esc_UINT32 exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut);

/**
Run modular exponentiation for public (small) exponents. The context must have
been initialized previously by calling EscModExpS0_PubInit().

\param[in]  ctx     The context to store state and intermediate results of the computation.

\return Esc_NO_ERROR if the computation finished successfully or a corresponding error code otherwise.
                     The result is stored in the inOut field element passed to EscModExpS0_PubInit().
*/
Esc_ERROR
EscModExpS0_PubRun(
    EscModExpS0_PubContext *ctx);

/**
Initialize modular exponentiation for private (large) exponents.
Modular exponentiation means: y = b^e mod m.

\param[in]  ctx         The context to store state and intermediate results of the computation.
\param[in]  exponent    The exponent e.
\param[in]  keySizeBits The size of the modulus in bits.
\param[in]  modulus     The modulus m.
\param[in,out] inOut    In: The base b of the modular exponentiation.
                        Out: The result y of the modular exponentiation.
 */
void
EscModExpS0_PrivInit(
    EscModExpS0_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut);

/**
Run modular exponentiation for private (large) exponents. The context must have
been initialized previously by calling EscModExpS0_PrivInit().

\param[in]  ctx     The context to store state and intermediate results of the computation.

\return Esc_NO_ERROR if the computation finished successfully or a corresponding error code otherwise.
                     The result is stored in the inOut field element passed to EscModExpS0_PrivInit().
 */
Esc_ERROR
EscModExpS0_PrivRun(
    EscModExpS0_PrivContext *ctx);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_MODEXP_S0_H_ */
