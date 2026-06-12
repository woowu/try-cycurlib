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

mememory set, memory copy, and memory compare for array manipulations


*/
/***************************************************************************/



/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "mem_mgt.h"

/***************************************************************************
* 3. DEFINITIONS                                                          *
***************************************************************************/

/***************************************************************************
* 4. CONSTANTS                                                            *
***************************************************************************/

/***************************************************************************
* 5. IMPLEMENTATION OF FUNCTIONS                                          *
***************************************************************************/



/*copies memory. same functionality as default C memcpy*/
void
Esc_memcpy(
    Esc_UINT8 *destination,
    const Esc_UINT8 *source,
    Esc_UINT32 len)
{
    Esc_UINT32 i;
    const Esc_UINT8 *sElement = source;
    for (i = 0U; i<len; i++)
    {
        destination[i] = sElement[i];
    }

}

/*compares two memory locations byte by byte*/
Esc_UINT16
Esc_memcmp(
    const Esc_UINT8 *string1,
    const Esc_UINT8 *string2,
    Esc_UINT32 len)
{
    Esc_UINT8 char1, char2;
    Esc_UINT16 retValue =0U;
    Esc_UINT32 i;
    for (i=0U; i < len; i++)
    {
        char1 = *string1;
        char2 = *string2;
        if (char1 != char2)
        {
            /*no break to prevent side-channel timing attacks*/
            retValue = ((Esc_UINT16)char1 - (Esc_UINT16)char2);
        }
        string1++;
        string2++;
    }
    return retValue;
}

/*sets a block of memory*/
void
Esc_memset(
    Esc_UINT8 *destination,
    Esc_UINT8 value,
    Esc_UINT32 len)
{
    Esc_UINT32 i;
    for (i = 0U; i<len; i++)
    {
        destination[i] = value;
    }
}

/*lint -save -e9079 Cast from void* is safe, because destination is only interpreted as byte array */
void
Esc_memclear(
    volatile void *buffer,
    Esc_UINT32 len)
{
    Esc_UINT32 i;
    volatile Esc_UINT8 *byteBuffer = (volatile Esc_UINT8 *) buffer;

    for (i=0U; i<len; i++)
    {
        byteBuffer[i] = 0U;
    }
}
/*lint -restore Cast from void* is safe, because destination is only interpreted as byte array */


/***************************************************************************
* 6. END                                                                  *
***************************************************************************/
