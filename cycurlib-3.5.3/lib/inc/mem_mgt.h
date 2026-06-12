/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
\file

\brief       basic memory management functions

memory set, memory copy, and memory compare for array manipulations


*/
/***************************************************************************/

#ifndef ESC_MEM_MGT_H_
#define ESC_MEM_MGT_H_


#ifdef  __cplusplus
extern "C" {
#endif  /*end c plus plus if*/


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

/***************************************************************************
* 4. DEFINES                                                              *
***************************************************************************/

/** Clear a variable by setting its memory to 0 */
#define Esc_CLEAR_LOCAL_VAR(x) Esc_memclear(&x, sizeof(x))
/** Clear an array by setting its members to 0 */
#define Esc_CLEAR_LOCAL_ARRAY(x) Esc_memclear(x, sizeof(x))

/***************************************************************************
* 6. FUNCTION PROTOTYPES                                                  *
***************************************************************************/

/**
Memory copy function

\param [out] destination: pointer to destination address of copied data
\param [in] source: pointer to address of source data to be copied
\param [in] len: length of data to be copied (bytes)
*/
void
Esc_memcpy(
    Esc_UINT8 *destination,
    const Esc_UINT8 *source,
    Esc_UINT32 len);


/**
Memory comparison function

\param [in] string1: pointer to location of first memory block
\param [in] string2: pointer to location of second memory block
\param [in] len: length of memory to be compared (in bytes)


\return [out] 0: blocks of memory are equal
         !0: difference between first unequal bytes
*/
Esc_UINT16
Esc_memcmp(
    const Esc_UINT8 *string1,
    const Esc_UINT8 *string2,
    Esc_UINT32 len);


/**
Memory setting function

\param [out] destination: pointer to address of memory block to be set
\param [in] value: unsigned character, value to set memory block to
\param [in] len: length of memory to be set (in bytes)
*/
void
Esc_memset(
    Esc_UINT8 *destination,
    Esc_UINT8 value,
    Esc_UINT32 len);

/**
Memory clearing function

This function clears (sets to 0) \p buffer.
It uses a volatile pointer so as to not be optimized out by the compiler.

\param [out] buffer: pointer to address of memory block to be cleared
\param [in] len: length of memory to be cleared (in bytes)
*/
void
Esc_memclear(
    volatile void *buffer,
    Esc_UINT32 len);

#ifdef  __cplusplus
}
#endif  /*end c plus plus if*/

#endif /*end ESC_ECC_KDF_H_ if*/
/***************************************************************************
* 7. END                                                                  *
***************************************************************************/
