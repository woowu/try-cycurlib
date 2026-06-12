/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
   \file

   \brief       RSA encryption and decryption
                RSA key generation and key conversion functions

   $Rev: 3832 $
 */
/***************************************************************************/

#ifndef ESC_RSA_H_
#define ESC_RSA_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "cycurlib_config.h"
#include "rsa_cfg.h"
#include "_rsa.h"
#include "modexp.h"

/***************************************************************************
 * 2. DEFINES REQUIRED BY CONFIGURATION (MUST NOT BE CHANGED!)             *
 ***************************************************************************/

/***************************************************************************
 * 3. CONFIGURATION                                                        *
 ***************************************************************************/

/***************************************************************************
 * 4. DEFINES                                                              *
 ***************************************************************************/

#if EscRsa_GENRSA_ENABLED == 1
/** A random number generator is required by the RSA Key Generation  */
#    include "random.h"
#endif

/** Check the maximum configured RSA key size */
#if ( ( EscRsa_KEY_BITS_MAX != 1024U ) && ( EscRsa_KEY_BITS_MAX != 1536U ) && ( EscRsa_KEY_BITS_MAX != 2048U ) && ( EscRsa_KEY_BITS_MAX != 3072U ) && ( EscRsa_KEY_BITS_MAX != 4096U ) )
#    error "The maximum size of the RSA key must match one of the following 1024, 1536, 2048, 3072 or 4096"
#endif

/***************************************************************************
 * 5. TYPE DEFINITIONS                                                     *
 ***************************************************************************/

/** Context structure for public key operations. This encapsulates the
    actual context for modular exponentiation and adds members for
    byte-to-field-element conversion. */
typedef struct
{
    /** Field element which stores the input (base value) and output (exponentiation result)
        of the modular exponentiation */
    EscRsa_FieldElementT inOutFe;
    /** The context of the modular exponentiation */
    EscModExp_PubContext modExpCtx;
    /** The size of the RSA key size in bytes */
    Esc_UINT16 keySizeBytes;
    /** Pointer to the array where the result is stored */
    Esc_UINT8 *result;
} EscRsa_PubContext;

/** Context structure for private key operations. This encapsulates the
    actual context for modular exponentiation and adds members for
    byte-to-field-element conversion. */
typedef struct
{
    /** Field element which stores the input (base value) and output (exponentiation result)
        of the modular exponentiation */
    EscRsa_FieldElementT inOutFe;
    /** The context of the modular exponentiation */
    EscModExp_PrivContext modExpCtx;
    /** The size of the RSA key size in bytes */
    Esc_UINT16 keySizeBytes;

    /** Flag to check whether CRT is used or not */
    Esc_BOOL usesCrt;
    /** Pointer to the array where the result is stored */
    Esc_UINT8 *result;

#if EscRsa_CRT_ENABLED == 1
    /** State of CRT computation */
    Esc_UINT8 state;

    /** Pointer to private key */
    const EscRsa_PrivKeyT *privKey;

    /** The key size in bits, bytes, words and double words */
    EscRsa_KeySizeT keySize;
    /** Half the key size in bits, bytes, words and double words */
    EscRsa_KeySizeT keySizeHalf;
    /** Buffer to store multiplication results */
    EscRsa_FieldElementLongT multiplication_result;
    /** References to multiplication parameters */
    EscRsa_MultiplyDataT mult;
    /** Temporary field element to store m mod p */
    EscRsa_FieldElementT mp;
    /** Temporary field element to store m mod q */
    EscRsa_FieldElementT mq;
    /** Temporary field element to store s */
    EscRsa_FieldElementT s;
#endif
} EscRsa_PrivContext;

/***************************************************************************
 * 6. FUNCTION PROTOTYPES                                                  *
 ***************************************************************************/

/**
Modular exponentiation with public (small) exponents, which is used for
RSA encryption or RSA signature verification.
The public key consists of a modulus and a public exponent plus the intended key size in bits.

result = input^(pubExp) mod modulus

Implements RSAVP1/RSAEP of the PKCS#1 standard.
This function should not be used directly, instead one of the PKCS#1 padding mechanisms should be used!

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

All byte arrays must have a size of (keySizeBits/8)!

\param[in] input Pointer to the input data.
\param[in] pubKey Pointer to public key.
\param[out] result Pointer to the result of the exponentiation.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_ModExpPub(
    const Esc_UINT8 input[],
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 result[] );

/**
Modular exponentiation with private (large) exponents, which is used for
RSA decryption or RSA signature generation.
The private key consists of a modulus plus the intended key size in bits (which are encapsulated in the public key) and a private exponent.

result = input^(privExp) mod modulus

Implements RSASP1/RSADP of the PKCS#1 standard.
This function should not be used directly, instead one of the PKCS#1 padding mechanisms should be used!

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

All byte arrays must have a size of (keySizeBits/8)!

\param[in] input Pointer to the data that is going to be signed/decrypted.
\param[in] privKey Pointer to private key.
\param[out] result Pointer to the result of the exponentiation.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_ModExpPriv(
    const Esc_UINT8 input[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 result[] );

#if EscRsa_CRT_ENABLED == 1
/**
Converts private and public key values as big endian byte arrays into one private key with CRT coefficients (EscRsa_PrivKeyT).

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
The modulus byte array must have a size of (keySizeBits/8)!
The byte arrays of p, q, and the CRT coefficients must have a size of
(keySizeBits/16), since these values are only half as large as the modulus.

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

\param[out] privKeyCrt Pointer to the resulting private key.
\param[in] keySizeBits Key size (length of the modulus) in bits. Must match one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[in] modulus Pointer to the modulus data.
\param[in] pubExp Public exponent of the RSA key pair.
\param[in] p Pointer to the p data.
\param[in] q Pointer to the q data.
\param[in] dmp1 Pointer to the dmp1 data.
\param[in] dmq1 Pointer to the dmq1 data.
\param[in] iqmp Pointer to the iqmp1 data.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_PrivKeyCrtFromBytes(
    EscRsa_PrivKeyT* privKeyCrt,
    const Esc_UINT16 keySizeBits,
    const Esc_UINT8 modulus[],
    const Esc_UINT32 pubExp,
    const Esc_UINT8 p[],
    const Esc_UINT8 q[],
    const Esc_UINT8 dmp1[],
    const Esc_UINT8 dmq1[],
    const Esc_UINT8 iqmp[] );


/**
Converts a private key with CRT coefficients (EscRsa_PrivKeyT) to big endian byte arrays.

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
The modulus byte array must have a size of (keySizeBits/8)!
The byte arrays of p, q, and the CRT coefficients must have a size of
(keySizeBits/16), since these values are only half as large as the modulus.

\param[in] privKeyCrt Pointer to the private key struct.
\param[out] keySizeBits Pointer to the key size (length of the modulus) in bits. Matches one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[out] modulus Pointer to the modulus array.
\param[out] pubExp Pointer to the public exponent of the RSA key pair.
\param[out] p Pointer to the p array.
\param[out] q Pointer to the q array.
\param[out] dmp1 Pointer to the dmp1 array.
\param[out] dmq1 Pointer to the dmq1 array.
\param[out] iqmp Pointer to the iqmp1 array.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_BytesFromPrivKeyCrt(
    const EscRsa_PrivKeyT* privKeyCrt,
    Esc_UINT16* keySizeBits,
    Esc_UINT8 modulus[],
    Esc_UINT32* pubExp,
    Esc_UINT8 p[],
    Esc_UINT8 q[],
    Esc_UINT8 dmp1[],
    Esc_UINT8 dmq1[],
    Esc_UINT8 iqmp[] );
#endif


/**
Converts private and public key values as big endian byte arrays into one private key (EscRsa_PrivKeyT).

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
All byte arrays must have a size of (keySizeBits/8)!

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

\param[out] privKey Pointer to the resulting private key.
\param[in] keySizeBits Key size (length of the modulus) in bits. Must match one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[in] modulus Pointer to the modulus data.
\param[in] pubExp Public exponent of the RSA key pair.
\param[in] privExp Pointer to the private exponent.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_PrivKeyFromBytes(
    EscRsa_PrivKeyT* privKey,
    const Esc_UINT16 keySizeBits,
    const Esc_UINT8 modulus[],
    const Esc_UINT32 pubExp,
    const Esc_UINT8 privExp[] );


/**
Converts public key values as big endian byte arrays into one public key with CRT coefficients (EscRsa_PubKeyT).

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
All byte arrays must have a size of (keySizeBits/8)!

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

\param[out] pubKey Pointer to the resulting private key.
\param[in] keySizeBits Key size (length of the modulus) in bits. Must match one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[in] modulus Pointer to the modulus data.
\param[in] pubExp Public exponent of the RSA key pair.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_PubKeyFromBytes(
    EscRsa_PubKeyT* pubKey,
    const Esc_UINT16 keySizeBits,
    const Esc_UINT8 modulus[],
    const Esc_UINT32 pubExp );

/**
Converts a private key (EscRsa_PrivKeyT) to big endian byte arrays.

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
All byte arrays must have a size of (keySizeBits/8)!

\param[in] privKey Pointer to the private key struct.
\param[out] keySizeBits Pointer to the key size (length of the modulus) in bits. Matches one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[out] modulus Pointer to the modulus data.
\param[out] pubExp Pointer to the public exponent of the RSA key pair.
\param[out] privExp Pointer to the private exponent.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_BytesFromPrivKey(
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT16* keySizeBits,
    Esc_UINT8 modulus[],
    Esc_UINT32* pubExp,
    Esc_UINT8 privExp[] );


/**
Converts a public key (EscRsa_PubKeyT) to big endian byte arrays.

This function does not check the validity of the key, e.g. GCD(e, phi(n)) == 1!
All byte arrays must have a size of (keySizeBits/8)!

\param[in] pubKey Pointer to the public key struct.
\param[out] keySizeBits Pointer to the key size (length of the modulus) in bits. Matches one
           of the following values: 1024, 1536, 2048, 3072 or 4096
\param[out] modulus Pointer to the modulus data.
\param[out] pubExp Pointer to the public exponent of the RSA key pair.

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_BytesFromPubKey(
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT16* keySizeBits,
    Esc_UINT8 modulus[],
    Esc_UINT32* pubExp );


#if EscRsa_GENRSA_ENABLED == 1

/**
RSA key generation.

\param[in] prngFunc     Random function as specified in random.h
\param[in] prngState    Random state which may be required by your random implementation.
\param[out] privKey     Pointer to the generated RSA private key.
                        Actually, an RSA private key includes the public key and is addressable with privKey.pubKey.
\param[in] pubExp       Public exponent of the RSA key pair, typically set to 65537U. Must be at least 3.
                        The GCD(pubExp, phi(n)) must be = 1! Since we do not know the modulus in advance,
                        it is recommended to use a prime here or call this function again until the returnCode is Esc_NO_ERROR.
\param[in] keySizeBits  Key size (length of the modulus) in bits. Must match one
                        of the following values: 1024, 1536, 2048, 3072 or 4096
\param[in] generateCrtKey If TRUE, the generated private key is generated to contain CRT parameters (p, q, d mod p-1, d mod q-1, q^(-1) mod p).
                          Using CRT requires that the configuration option EscRsa_CRT_ENABLED is enabled. Otherwise, a Esc_INVALID_PARAMETER
                          is returned. If this flag is set to false, the CRT is not used and only the private exponent is stored in the private key.
\return Esc_NO_ERROR if everything works fine.
\return Esc_KEY_GENERATION_COPRIME_ERROR if (p-1) or (q-1) is not co-prime to e. This is very unlikely to happen given a sane choice
                                         of e (e.g. 65537). This problem can typically be recovered by calling this function again.
*/
Esc_ERROR
EscRsa_KeyGeneration(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscRsa_PrivKeyT* privKey,
    Esc_UINT32 pubExp,
    Esc_UINT16 keySizeBits,
    Esc_BOOL generateCrtKey);

#endif /* EscRsa_GENRSA_ENABLED */

/**
Initialize modular exponentiation with public (small) exponents, which is used for
RSA encryption or RSA signature verification.
The public key consists of a modulus and a public exponent plus the intended key size in bits.

result = input^(pubExp) mod modulus

Implements RSAVP1/RSAEP of the PKCS#1 standard.

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

\warning    This function should not be used directly, instead one of the PKCS#1 padding mechanisms should be used!

\warning    This function does NOT create deep copies of any pointer passed to it!
            Therefore, the data behind each pointer must remain allocated/unchanged
            until the computation is finished!

\param[in] ctx      The context which stores the state of the computation.
\param[in] pubKey   Pointer to public key.
\param[in] input    The base of the exponentiation as a byte array in big-endian byte order.
                    The array must have a size of (keySizeBits/8)!
\param[out] result  The array to store the exponentiation result.
                    It must have a size of (keySizeBits/8) bytes!

\return Esc_NO_ERROR if everything works fine.
 */
Esc_ERROR
EscRsa_ModExpPubInit(
    EscRsa_PubContext *ctx,
    const EscRsa_PubKeyT *pubKey,
    const Esc_UINT8 input[],
    Esc_UINT8 result[]);

/**
Run modular exponentiation with public (small) exponents. Each call may only
compute a small part of the overall computation. Consequently, this function
needs to be called until it returns an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the exponentiation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue exponentiation.
\retval Esc_NO_ERROR if exponentiation finished successfully.
*/
Esc_ERROR
EscRsa_ModExpPubRun(
    EscRsa_PubContext *ctx);

/**
Initialize modular exponentiation with private (large) exponents, which is used for
RSA decryption or RSA signature generation. The private key consists of a modulus
plus the intended key size in bits (which are encapsulated in the public key) and a private exponent.

result = input^(privExp) mod modulus

Implements RSASP1/RSADP of the PKCS#1 standard.
This function should not be used directly, instead one of the PKCS#1 padding mechanisms should be used!

Note that the six most significant bits of the modulus must not all be zero!
For example, having a modulus size of 1024 bit with an MSB of 00000010 (binary)
effectively reduces the bit size to (1024 - 6) bit = 1018 bit. The implementation
requires that given a modulus size of X bits, the effective modulus must be
at least (X - 5) bits.

\warning    This function should not be used directly, instead one of the PKCS#1 padding mechanisms should be used!

\warning    This function does NOT create deep copies of any pointer passed to it!
            Therefore, the data behind each pointer must remain allocated/unchanged
            until the computation is finished!

\param[in] ctx      The context which stores the state of the computation.
\param[in] privKey  Pointer to private key.
\param[in] input    The base of the exponentiation as a byte array in big-endian byte order.
                    The array must have a size of (keySizeBits/8)!
\param[out] result  The array to store the exponentiation result.
                    It must have a size of (keySizeBits/8) bytes!

\return Esc_NO_ERROR if everything works fine.
*/
Esc_ERROR
EscRsa_ModExpPrivInit(
    EscRsa_PrivContext *ctx,
    const EscRsa_PrivKeyT *privKey,
    const Esc_UINT8 input[],
    Esc_UINT8 result[]);

/**
Run modular exponentiation with private (large) exponents. Each call may only
compute a small part of the overall computation. Consequently, this function
needs to be called until it returns an error code different from Esc_AGAIN.

\param[in]  ctx     The context structure which stores the state of the exponentiation.

\return Any of the below return codes on success or a corresponding error code on failure.
\retval Esc_AGAIN if this function needs to be called again to continue exponentiation.
\retval Esc_NO_ERROR if exponentiation finished successfully.
                     The result can be obtained by calling EscRsa_ModExpPrivFinish().
*/
Esc_ERROR
EscRsa_ModExpPrivRun(
    EscRsa_PrivContext *ctx);

/**
Perform sanity checks on a given public key.

\warning This includes only basic checks and cannot verify that the public
         key actually belongs to a sane private key.

\param[in]  key     The public key to be checked.

\retval Esc_NO_ERROR if the key is okay.
\retval Esc_INVALID_PUBLIC_KEY if the key is invalid.
\retval Esc_INVALID_KEY_LENGTH if the size is not supported or if it was disabled at compile-time.
 */
Esc_ERROR
EscRsa_CheckPublicKey(
    const EscRsa_PubKeyT *key);

/**
Perform sanity checks on a given private key.

\warning This includes only basic checks and cannot verify that all values
         of the private key are correct.

\param[in]  key     The private key to be checked.

\retval Esc_NO_ERROR if the key is okay.
\retval Esc_INVALID_PRIVATE_KEY if the key is invalid.
\retval Esc_INVALID_KEY_LENGTH if the size is not supported or if it was disabled at compile-time.
 */
Esc_ERROR
EscRsa_CheckPrivateKey(
    const EscRsa_PrivKeyT *key);

/***************************************************************************
 * 7. END                                                                  *
 ***************************************************************************/
#ifdef  __cplusplus
}
#endif
#endif /* ESC_RSA_H_ */
