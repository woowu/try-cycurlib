/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief Selftest of the CycurLIB for embedded use.

   The selftest is stored in a separate library,
   to allow optional combining and separation.

   This selftest follows the coding guidelines
   of the CycurLIB, i.e., MISRA-C:2012.

   $Rev: 4122 $
 */
/***************************************************************************/

#ifndef ESC_SELFTEST_H_
#define ESC_SELFTEST_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

#ifndef EscTst_ENABLE_LOGGING
/**
Set this define to 1 to enable the debug output of the CycurLIB selftest.
The default implementation for the output violates MISRA by
using printf of stdio.h.

Edit ESCLIB_PRINTF macro in /tests/src/selftest.c to adjust to your own implementation
if your platform does not support stdio.h.
*/
#   define EscTst_ENABLE_LOGGING 1
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
Selftest of the cycurLIB.

\return Esc_NO_ERROR if everything works fine
*/
Esc_ERROR
EscTst_Perform(
    void );

/**
Compares mem1 and mem2.

\param[in] mem1 One array to compare
\param[in] mem2 The other array to compare
\param[in] len The number of bytes to compare

\return TRUE if they are equal
*/
Esc_BOOL
EscTst_Memcmp(
    const Esc_UINT8 mem1[],
    const Esc_UINT8 mem2[],
    Esc_UINT32 len );

/**
Compares mem1 and mem2.

\param[in] mem1 One array to compare
\param[in] mem2 The other array to compare
\param[in] len The number of 16 bit words to compare

\return TRUE if they are equal
*/
Esc_BOOL
EscTst_Memcmp8_16(
    const Esc_UINT8 mem1[],
    const Esc_UINT16 mem2[],
    Esc_UINT32 len );

/**
Compares mem1 and mem2.

\param[in] mem1 One array to compare
\param[in] mem2 The other array to compare
\param[in] len The number of 32 bit words to compare

\return TRUE if they are equal
*/
Esc_BOOL
EscTst_Memcmp8_32(
    const Esc_UINT8 mem1[],
    const Esc_UINT32 mem2[],
    Esc_UINT32 len );

/**
Compares mem1 and mem2.

\param[in] mem1 One array to compare
\param[in] mem2 The other array to compare
\param[in] len The number of 32 bit words to compare

\return TRUE if they are equal
*/
Esc_BOOL
EscTst_MemcmpWord(
    const Esc_UINT32 mem1[],
    const Esc_UINT32 mem2[],
    Esc_UINT32 len );

/**
Checks if mem is zero.

\param[in] mem Array to check
\param[in] len The number of bytes to compare

\return TRUE if mem == 0, else FALSE.
*/
Esc_BOOL
EscTst_MemIsZero(
    const Esc_UINT8 mem[],
    Esc_UINT32 len );

/**
Sets all bytes in an array to a given value.

\param[in] mem The array whose elements shall be set.
\param[in] len Length of the array.
\param[in] value The value to set the elements to.
*/
void
EscTst_Memset(
    Esc_UINT8 mem[],
    Esc_UINT32 len,
    Esc_UINT8 value );

/**
Copy values from one array into another.

\param[in] dest Array to copy to.
\param[in] source Array to copy from.
\param[in] len Number of bytes to copy.
*/
void
EscTst_Memcpy(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[],
    Esc_UINT32 len );

/**
Calculates the length of a zero-terminated string

\param[in] s The string
\return The length in bytes
*/
Esc_UINT32
EscTst_Strlen(
    const Esc_CHAR s[] );

/***** Functions for logging output ****/

/**
Checks if return value receivedResult == 0.
Prints logging messages if enabled.

\param[in] receivedResult The return value to check.
\return TRUE if receivedResult != 0, else FALSE.
*/
Esc_ERROR
EscTst_CheckResultSuccess(
    Esc_ERROR receivedResult );

/**
Checks if result != expectedResult.
Prints logging messages if enabled.

\param[in,out] result       The return value to check. Updated after the check.
\param[in] expectedResult   The expected return value.

\return Esc_NO_ERROR the given result equals the expected one.
*/
Esc_ERROR
EscTst_CheckResultFailed(
    Esc_ERROR* result,
    Esc_ERROR expectedResult );

/**
Checks if the expected and received value are the same.
Prints logging messages if enabled.

\param[in] expected The expected value.
\param[in] received The received value.
\return TRUE if received != expected
*/
Esc_ERROR
EscTst_CheckWords(
    Esc_UINT32 expected,
    Esc_UINT32 received );

/**
Checks if the expected and received arrays are the same.
Prints logging messages if enabled.
\param[in] expected The expected value.
\param[in] expectedLen The length of the expected value in byte.
\param[in] received The received value.
\param[in] receivedLen The length of the received value in byte.
\return TRUE if received != expected
*/
Esc_ERROR
EscTst_CheckStrings(
    const Esc_UINT8 expected[],
    Esc_UINT32 expectedLen,
    const Esc_UINT8 received[],
    Esc_UINT32 receivedLen );

/**
Function to initialize an array with zeroes.
\param[in] array The array to be initialized.
\param[in] arrayLen The length of the array.
*/
void
EscTst_InitArray(
    Esc_UINT8 array[],
    Esc_UINT32 arrayLen );

/*lint -emacro(717,EscTst_Print*) we allow do {...} while (0) statements for print operations */
/**
Prints a debug message in the form:
printf("%s", msg);
\param[in] msg The string to print
\see EscTst_ENABLE_LOGGING
\note Function is disabled in release mode.
*/
#if EscTst_ENABLE_LOGGING == 1
void
EscTst_PrintString(
    const Esc_CHAR* msg );

#else
#    define EscTst_PrintString( msg )
#endif

/**
Prints a debug message in the form:
printf("%lu", val);
\param[in] val The value to print
\see EscTst_ENABLE_LOGGING
\note Function is disabled in release mode.
*/
#if EscTst_ENABLE_LOGGING == 1
void
EscTst_PrintWordOnly(
    Esc_UINT32 val );

#else
#    define EscTst_PrintWordOnly( val )
#endif

/**
Prints a debug message in the form:
printf("%s: %lu\n", val);
\param[in] msg The string to print
\param[in] val The value to print
\see EscTst_ENABLE_LOGGING
\note Function is disabled in release mode.
*/
#if EscTst_ENABLE_LOGGING == 1
void
EscTst_PrintWord(
    const Esc_CHAR* msg,
    Esc_UINT32 val );

#else
#    define EscTst_PrintWord( msg, val )
#endif

/**
Prints a debug message in the form:
printf("%s: 0x%08lx\n", msg, val);
\param[in] msg The string to print
\param[in] val The value to print
\see EscTst_ENABLE_LOGGING
\note Function is disabled in release mode.
*/
#if EscTst_ENABLE_LOGGING == 1
void
EscTst_PrintWordHex(
    const Esc_CHAR* msg,
    Esc_UINT32 val );

#else
#    define EscTst_PrintWordHex( msg, val )
#endif

/**
Dumps a array to the screen in hex form, 16 byte in a row.

Similar to:
printf("%s:\n\t %02lX ..%02lX ", msg, arr[0], arr[1], ...);
\param[in] msg The string to print
\param[in] arr The array to print.
\param[in] numBytes Number of bytes in arr to print.
\see EscTst_ENABLE_LOGGING
\note Function is disabled in release mode.
*/
#if EscTst_ENABLE_LOGGING == 1
void
EscTst_PrintArray(
    const Esc_CHAR* msg,
    const Esc_UINT8 arr[],
    Esc_UINT32 numBytes );

#else
#    define EscTst_PrintArray( msg, arr, numBytes )
#endif

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
