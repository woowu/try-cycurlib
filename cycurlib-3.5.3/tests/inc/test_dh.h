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

   $Rev: 2106 $
 */
/***************************************************************************/

#ifndef ESC_TEST_DH_H_
#define ESC_TEST_DH_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "cycurlib_config.h"
#include "dh.h"

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

/** DH Domain parameters as byte arrays */
typedef struct
{
    /** Prime modulus p */
    const Esc_UINT8 *p;
    /** Length of modulus p in bytes */
    Esc_UINT16      pLength;
    /** Generator g */
    const Esc_UINT8 *g;
    /** Length of generator in bytes */
    Esc_UINT16      gLength;
} EscTstDh_DomainParams;

/** Test case data */
typedef struct
{
    /** Domain parameters used for this testcase */
    const EscTstDh_DomainParams* param;

    /** Private key of Alice */
    const Esc_UINT8 *privA;
    /** Length of Alice's private key in bytes */
    Esc_UINT16 lengthPrivA;

    /** Public key of Alice */
    const Esc_UINT8 *pubA;
    /** Length of Alice's public key in bytes */
    Esc_UINT16 lengthPubA;

    /** Private key of Bob */
    const Esc_UINT8 *privB;
    /** Length of Bob's private key in bytes */
    Esc_UINT16 lengthPrivB;

    /** Public key of Bob */
    const Esc_UINT8 *pubB;
    /** Length of Bob's public key in bytes */
    Esc_UINT16 lengthPubB;

    /** The shared secret Z */
    const Esc_UINT8 *sharedSecret;
    /** Length of the shared secret in bytes */
    Esc_UINT16 lengthSharedSecret;
} EscTstDh_TestcaseT;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
 * Dh self tests
 *
 * \return Esc_NO_ERROR if everything works fine
 */
Esc_ERROR
EscTstDh_Perform(
    void );

/**
 * Run a single DH Known-Answer-Test (KAT). Note that this function is used for more extensive
 * tests that are not part of the library. It should not be used directly.
 *
 * \param[in]   testcase    The parameters of the KAT.
 *
 * \return Esc_NO_ERROR if everything works fine
 */
Esc_ERROR
EscTstDh_KnownAnswerTestcase(
    const EscTstDh_TestcaseT *testcase);

/**
 * Generate a key pair for Alice and Bob, compute the shared secret for both
 * and check if they match. For each domain parameter, the test is executed for the
 * given number of iterations.
 *
 * \param[in]   domainParams        The domain parameters used in the test.
 * \param[in]   numParams           Number of domain parameters.
 * \param[in]   numIterations       Number of iterations to run the test for each domain parameter.
 *
 * \return Esc_NO_ERROR if everything works fine
 */
Esc_ERROR
EscTstDh_ConsistencyTest(
    const EscTstDh_DomainParams * const domainParams[],
    Esc_UINT16 numParams,
    Esc_UINT16 numIterations );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif

#endif
