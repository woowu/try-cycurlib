/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
\file

\brief       ECC key derivation function

\see  NIST SP 800-56Ar2, specifically section 5.8

Note: Maximum input (shared private key + other information) cannot exceed
    max 32-bit (2^32 -1) integer in length


*/
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "ecc_kdf.h"

/***************************************************************************
* 2. DEFINES                                                              *
***************************************************************************/

/*convert 32-bit counter to byte array to be passed to hash function*/
static void
counterToArray(
    Esc_UINT8 *counterArray,
    const Esc_UINT32 counter);

/***************************************************************************
* 3. DEFINITIONS                                                          *
***************************************************************************/

/***************************************************************************
* 4. CONSTANTS                                                            *
***************************************************************************/

/***************************************************************************
* 5. IMPLEMENTATION OF FUNCTIONS                                          *
***************************************************************************/

Esc_ERROR
EscEccKdf_Generate(
    Esc_UINT8 *key,
    Esc_UINT32 keySize,
    const Esc_UINT8 *z,
    const Esc_UINT32 zLength,
    const Esc_UINT8 *otherInfo,
    const Esc_UINT32 otherInfoLength)
{
    /*Initialization and declaration of variables*/
    Esc_ERROR returnCode = Esc_NO_ERROR;
    EscSha256_ContextT ctx;
    /*reps is number of times to run loop, remainder is number of bytes to copy to end of key if not even with hash result length*/
    Esc_UINT32 i, counter=1U, remainder = (keySize & 31U), reps = (keySize/32U);
    Esc_UINT8 hashResult[32], counterArray[4];

    /*Initialize arrays*/
    Esc_memset(hashResult, 0U, 32U);
    Esc_memset(counterArray, 0U, 4U);

    if (keySize == 0U)
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else if ((zLength == 0U) || (otherInfoLength == 0U))
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else if ((key == Esc_NULL_PTR) || (z == Esc_NULL_PTR) || (otherInfo == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        /*calculates whole blocks of key
            key part[0-31] = HASH (counter | z | other info)
            key part[32-63] = HASH (counter | z | other info)
            until remainder is < size of (HASH return), 32 bytes
        */
        for (i = 0U; i < reps; i++)
        {
            returnCode = EscSha256_Init(0U, &ctx);
            if (returnCode == Esc_NO_ERROR)
            {
                counterToArray(counterArray, counter);
                returnCode = EscSha256_Update(&ctx, counterArray, 4U);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscSha256_Update(&ctx, z, zLength);
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscSha256_Update(&ctx, otherInfo, otherInfoLength);
                        if (returnCode == Esc_NO_ERROR)
                        {
                            returnCode = EscSha256_Finish(&ctx, &key[i*32U], 32U);
                            if (returnCode == Esc_NO_ERROR)
                            {
                                counter++;
                            }
                        }
                    }
                }
            }
            else
            {
                break;
            }

        }

        /*fill remaining XX bytes of key with left most bytes of HASH result*/
        returnCode = EscSha256_Init(0U, &ctx);
        if (returnCode == Esc_NO_ERROR)
        {
            counterToArray(counterArray, counter);
            returnCode = EscSha256_Update(&ctx, counterArray, 4U);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscSha256_Update(&ctx, z, zLength);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscSha256_Update(&ctx, otherInfo, otherInfoLength);
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscSha256_Finish(&ctx, hashResult, 32U);
                        if (returnCode == Esc_NO_ERROR)
                        {
                            Esc_memcpy(&key[keySize - remainder], hashResult, remainder);
                        }
                    }
                }
            }
        }
    }

    /* Zeroize stack variables */
    Esc_CLEAR_LOCAL_ARRAY(hashResult);

    /*return if any errors occurred*/
    return returnCode;
}


static void
counterToArray(
    Esc_UINT8 *counterArray,
    const Esc_UINT32 counter)
{
    /*break 32 bit number into 8 bit blocks*/
    counterArray[0] = (Esc_UINT8)(counter>>24);
    counterArray[1] = (Esc_UINT8)(counter>>16);
    counterArray[2] = (Esc_UINT8)(counter>>8);
    counterArray[3] = (Esc_UINT8)(counter);

}


/***************************************************************************
* 6. END                                                                  *
***************************************************************************/
