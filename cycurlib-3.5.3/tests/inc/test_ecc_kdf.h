/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       ECC KDF Selftest.

    generates key of pre-selected lengths with preselected inputs according to
   NIST800-56Ar2 and NIST800-108

   $Rev: 2711 $
 */
/***************************************************************************/

#ifndef ESC_TEST_ECC_KDF_H_
#define ESC_TEST_ECC_KDF_H_

#ifdef  __cplusplus
extern "C" {
#endif


/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "cycurlib_config.h"
#include "ecc_kdf.h"


/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/



/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
function to perform predefined vector testing (NIST SP 800-38F and RFC 3394)
no parameters as function is self-contained.
*/
Esc_ERROR
EscTstEccKdf_Perform(
    void);


/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
