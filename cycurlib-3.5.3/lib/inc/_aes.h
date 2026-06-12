/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       AES implementation (FIPS-197 compliant)
   Common functions. The functions are not supposed to be called
   by the user. Use one of the submodule functions instead.

   \see FIPS-197

   Key sizes of 128, 192 and 256 bits are allowed.

   $Rev: 4191 $
 */
/***************************************************************************/

#ifndef ESC__AES_H_
#define ESC__AES_H_

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

#ifndef EscAes_MAX_KEY_BITS
/** Max size of AES key (in bit): 128, 192, 256 */
#    define EscAes_MAX_KEY_BITS 256U
#endif

/* Default configurations for speed optimization */
#if Esc_OPTIMIZE_SPEED == 1
#   ifndef EscAes_USE_T_TABLES_FULL
/** Uses T-Table implementation with all four tables (8 kB) */
#       define EscAes_USE_T_TABLES_FULL 1
#   endif

#   ifndef EscAes_USE_T_TABLES_SMALL
/** Uses T-Table implementation with one table (2 kB) */
#       define EscAes_USE_T_TABLES_SMALL 0
#   endif
#endif

/* Default configurations for size optimization */
#if Esc_OPTIMIZE_SPEED == 0
#   ifndef EscAes_USE_T_TABLES_FULL
/** Uses T-Table implementation with all four tables (8 kB) */
#       define EscAes_USE_T_TABLES_FULL 0
#   endif

#   ifndef EscAes_USE_T_TABLES_SMALL
/** Uses T-Table implementation with one table (2 kB) */
#       define EscAes_USE_T_TABLES_SMALL 0
#   endif
#endif

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

/** Size of the AES key in bytes. */
#define EscAes_MAX_KEY_BYTES (EscAes_MAX_KEY_BITS / 8U)

/** Size of AES block in bits. */
#define EscAes_BLOCK_BITS 128U

/** Size of one AES data block in bytes. */
#define EscAes_BLOCK_BYTES (EscAes_BLOCK_BITS / 8U)

/** Size of IV in bytes. */
#define EscAes_IV_BYTES (EscAes_BLOCK_BYTES)

/* Parameter checks. */
#if (EscAes_MAX_KEY_BITS != 128U) && (EscAes_MAX_KEY_BITS != 192U) && (EscAes_MAX_KEY_BITS != 256U)
#   error Not allowed max AES key size!
#endif

#if (EscAes_USE_T_TABLES_FULL == 1) && (EscAes_USE_T_TABLES_SMALL == 1)
#   error At most one of the following options may be enabled: EscAes_USE_T_TABLES_FULL, EscAes_USE_T_TABLES_SMALL
#endif

/** Number of columns (32-bit words) comprising the state. */
#define EscAes_Nb 4U

/** Max number of rounds. */
#define EscAes_MAX_Nr ((EscAes_MAX_KEY_BITS / 32U) + EscAes_Nb + 2U)

/** Get 1-th byte of 32 bit word in big endian byte order */
#define EscAes_BYTE_0( w32 ) ( (Esc_UINT8)( (w32) >> 24 ) )
/** Get 2-th byte of 32 bit word in big endian byte order */
#define EscAes_BYTE_1( w32 ) ( (Esc_UINT8)( (w32) >> 16 ) )
/** Get 3-th byte of 32 bit word in big endian byte order */
#define EscAes_BYTE_2( w32 ) ( (Esc_UINT8)( (w32) >>  8 ) )
/** Get 4-th byte of 32 bit word in big endian byte order */
#define EscAes_BYTE_3( w32 ) ( (Esc_UINT8)( (w32) ) )

/** Rotate left of 32bit value by n bits */
#define EscAes_RotateLeft32( w32, n ) ( ( ( (w32) << (n) ) | ( (w32) >> ( (32U) - (n) ) ) ) )

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** AES context */
typedef struct
{
    /** Number of rounds for used key size. */
    Esc_UINT8 nr;
    /** Encryption round keys */
    Esc_UINT32 round_keys[(EscAes_MAX_Nr + 1U) * 4U];
#if (EscAes_USE_T_TABLES_SMALL == 1) || (EscAes_USE_T_TABLES_FULL == 1)
    /** Decryption round keys */
    Esc_UINT32 dec_keys[(EscAes_MAX_Nr + 1U) * 4U];
#endif
} EscAes_ContextT;

/** AES forward SBOX. Used for Encryption and Key schedule. */
extern const Esc_UINT8 EscAes_FORWARD_SBOX[256];

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/
/**
Initializes the Context with the corresponding AES key.

\param[out] ctx The AES context.
\param[in] keyBits Bit length of the AES key. Can be 128, 192 or 256.
\param[in] key Key bytes array. The size of the key depends on the keyBits parameter:
                128 bits => 16 bytes
                192 bits => 24 bytes
                256 bits => 32 bytes
*/
void
EscAes_Init(
    EscAes_ContextT* ctx,
    Esc_UINT16 keyBits,
    const Esc_UINT8 key[] );


/**
Decrypts one AES block.

Block size is EscAes_BLOCK_BYTES.
The context must be initialized with EscAes_Init.

The parameters plain and cipher can point to the same location.

\param[in] ctx Context initialized with EscAes_Init.
\param[in] cipher Ciphertext to decrypt. Must be exactly EscAes_BLOCK_BYTES bytes.
\param[out] plain Decrypted ciphertext. Must be exactly EscAes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
void
EscAes_DecryptBlock(
    const EscAes_ContextT* ctx,
    const Esc_UINT8 cipher[],
    Esc_UINT8 plain[] );


/**
Encrypts one AES block.

Block size is EscAes_BLOCK_BYTES.
The context must be initialized with EscAes_Init.

The parameters plain and cipher can point to the same location.

\param[in] ctx Context initialized with EscAes_Init.
\param[in] plain Plaintext to encrypt. Must be exactly EscAes_BLOCK_BYTES bytes.
\param[out] cipher Encrypted plaintext. Must be exactly EscAes_BLOCK_BYTES bytes.

\return Esc_NO_ERROR if everything works fine.
*/
void
EscAes_EncryptBlock(
    const EscAes_ContextT* ctx,
    const Esc_UINT8 plain[],
    Esc_UINT8 cipher[] );


/**
Copies an EscAes_Nb word array into EscAes_BLOCK_BYTES bytes.

\param[out] block Array of EscAes_BLOCK_BYTES bytes. Will be filled with the words.
\param[in] state Four 32bit words.
*/
void
EscAes_State2Uint32Array(
    Esc_UINT8 block[],
    const Esc_UINT32 state[] );

/**
Copies 4 bytes into a word, big endian style.

\param[in] octets Byte array.
\param[in] idx Index of the first byte to be used. Word will consist of bytes idx to idx+3.

\return The 32bit word.
*/
Esc_UINT32
EscAes_Octets2Uint32(
    const Esc_UINT8 octets[],
    Esc_UINT32 idx );

/**
Applies the AES MixColumns operation on a single word.

\param[in] u The word to be processed.

\return The new word.
*/
Esc_UINT32
EscAes_MixColumns(
    Esc_UINT32 u );

/**
Applies the AES InverseMixColumns operation on a single word.

\param[in] u The word to be processed.

\return The new word.
*/
Esc_UINT32
EscAes_InvMixColumns(
    Esc_UINT32 u );

/**
Copies EscAes_BLOCK_BYTES bytes from source to destination.
Input and output must not overlap!

\param[out] dest The data destination.
\param[in] source The data source.

*/
void
EscAes_CopyBlock(
    Esc_UINT8 dest[],
    const Esc_UINT8 source[] );

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif

#endif
