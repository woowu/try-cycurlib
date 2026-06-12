/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       Modular exponentiation (sliced).

   $Rev: 2716 $
 */
/***************************************************************************/

#ifndef ESC_MODEXP_S1_H_
#define ESC_MODEXP_S1_H_

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
    /** State of the computation */
    Esc_UINT8 state;
    /** Public exponent */
    Esc_UINT32 pubExp;
    /** Key size in bits */
    Esc_UINT16 keySizeBits;
    /** Modulus */
    const EscRsa_FieldElementT *modulus;
    /** Field element containing current value */
    EscRsa_FieldElementT *x;
    /** Index of the bit in the exponent that is currently processed */
    Esc_SINT8 thebit;
    /** Buffer to store multiplication results */
    EscRsa_FieldElementLongT multiplication_result;
    /** References to multiplication parameters */
    EscRsa_MultiplyDataT mult;

#if EscRsa_USE_MONTGOM_MUL == 1
    /** Temporary element */
    EscRsa_FieldElementT x_;
    /** Temporary element */
    EscRsa_FieldElementT y_;
    /** Montgomery parameters */
    EscRsa_MontGomElementT mg;
#endif
} EscModExpS1_PubContext;

/** Context to store state and intermediate results of
    modular exponentiation for private (large) exponents */
typedef struct
{
    /** State of the computation */
    Esc_UINT8 state;
    /** Field element containing current value */
    EscRsa_FieldElementT *x;
    /** Private exponent */
    const EscRsa_FieldElementT *privExp;
    /** Modulus */
    const EscRsa_FieldElementT *modulus;
    /** Index of the bit in the exponent that is currently processed */
    Esc_UINT32 thebit;
    /** The size of the modulus in bits, bytes, words and double-words */
    EscRsa_KeySizeT keySize;
    /** Buffer to store multiplication results */
    EscRsa_FieldElementLongT multiplication_result;
    /** References to multiplication parameters */
    EscRsa_MultiplyDataT mult;

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
    /** Loop counter */
    Esc_UINT32 loopCnt;
    /** Size of the current window */
    Esc_UINT32 windowSize;
    /** The current's window exponent value */
    Esc_UINT32 exponent;
#endif
} EscModExpS1_PrivContext;

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
EscModExpS1_PubInit(
    EscModExpS1_PubContext *ctx,
    Esc_UINT32 exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut);

/**
Run modular exponentiation for public (small) exponents. The context must have
been initialized previously by calling EscModExpS1_PubInit().
This variant is sliced which means that the function may need to be called multiple
times until a return code different from Esc_AGAIN is returned.

\param[in]  ctx     The context to store state and intermediate results of the computation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN       The computation is not finished and the function must be called again.
\retval Esc_NO_ERROR    The computation finished successfully. The result is stored in
                        the inOut field element passed to EscModExpS1_PubInit().
 */
Esc_ERROR
EscModExpS1_PubRun(
    EscModExpS1_PubContext *ctx);


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
EscModExpS1_PrivInit(
    EscModExpS1_PrivContext *ctx,
    const EscRsa_FieldElementT *exponent,
    Esc_UINT16 keySizeBits,
    const EscRsa_FieldElementT *modulus,
    EscRsa_FieldElementT *inOut);

/**
Run modular exponentiation for private (large) exponents. The context must have
been initialized previously by calling EscModExpS1_PrivInit().
This variant is sliced which means that the function may need to be called multiple
times until a return code different from Esc_AGAIN is returned.

\param[in]  ctx     The context to store state and intermediate results of the computation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN       The computation is not finished and the function must be called again.
\retval Esc_NO_ERROR    The computation finished successfully. The result is stored in
                        the inOut field element passed to EscModExpS1_PrivInit().
 */
Esc_ERROR
EscModExpS1_PrivRun(
    EscModExpS1_PrivContext *ctx);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* ESC_MODEXP_S1_H_ */
