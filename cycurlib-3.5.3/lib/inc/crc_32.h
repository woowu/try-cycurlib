/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       CRC32 implementation according to IEEE 802.3


   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef  ESC_CRC_32_H_
#define  ESC_CRC_32_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef EscCrc32_INITIAL_VALUE
/** Initial value. */
#    define EscCrc32_INITIAL_VALUE 0xFFFFFFFFU
#endif

#ifndef EscCrc32_QUOTIENT
/** CRC32 polynomial. Only used in size optimized version (i.e. Esc_OPTIMIZED_SPEED is 0). */
#    define EscCrc32_QUOTIENT 0xEDB88320U
#endif

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscCrc32_USE_TABLE
/** Increases speed significantly on costs of one 1KB table */
#       define EscCrc32_USE_TABLE 1
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscCrc32_USE_TABLE
/** Increases speed significantly on costs of one 1KB table */
#       define EscCrc32_USE_TABLE 0
#   endif
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Initializes the crc32 checksum.

Initializes start value with 0xFFFFFFFF.

\param[out] crc Pointer to CRC checksum.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCrc32_Init(
    Esc_UINT32* crc );

/**
Calculate crc32 checksum according to IEEE 802.3.

Bytes are reversed before processing (least significant bit <--> most significant bit ...).

\param[in] message Message array.
\param[in] length Length of message in bytes.
\param[out] crc Pointer to CRC checksum.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCrc32_Compute(
    const Esc_UINT8 message[],
    Esc_UINT32* crc,
    Esc_UINT32 length );

/**
Finalize crc32 checksum according to IEEE 802.3.

32 bit result of processing is reversed before complementing.

\param[out] crc Pointer to CRC checksum.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscCrc32_Finalize(
    Esc_UINT32* crc );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif
