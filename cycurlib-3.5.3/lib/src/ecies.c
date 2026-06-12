/***************************************************************************
 * This file is part of the cryptographic library CycurLIB                 *
 *                                                                         *
 * Copyright (C) 2016 ESCRYPT GmbH - All Rights Reserved                   *
 * www.escrypt.com                                                         *
 ***************************************************************************/

/***************************************************************************/
/*!
\file

\brief       ECIES implementation according to the IEEE Std 1363a

\see  IEEE Std 1363-2000 and IEEE Std 1363a
        All quoted references refer to the IEEE standard


$Rev: 3679 $
*/
/***************************************************************************/

/***************************************************************************
* 1. INCLUDES                                                              *
****************************************************************************/

#include "ecies.h"

/*lint -efile(766,ecies.h) If ECDH is not activated, ECIES is not
supported. */

#if EscEcc_ECDH_ENABLED == 1

/***************************************************************************
* 2. DEFINES                                                              *
***************************************************************************/

/** Length of a 32 bit integer in bytes. */
#define EscEcies_Esc_UINT32_SIZE 4U

/** Length of the KDF parameters. Used for the encryption counter */
#define EscEcies_KDF_PARAMETERS_LEN 4U

#if EscEcies_DHAES_ENABLED == 1
/** Length of the encoding parameters, 8 for DHAES. */
#   define EscEcies_ENCO_PARAMETERS_LEN 8U
#else
/** Length of the encoding parameters, 0 for non-DHAES. */
#   define EscEcies_ENCO_PARAMETERS_LEN 0U
#endif

/* Size of a chunk (block), to be encrypted at one point in time */
#if EscEcies_HASH_TYPE == EscEcies_USE_SHA1
#define EscEcies_BLOCK_SIZE_BYTES EscSha1_DIGEST_LEN
#else
#define EscEcies_BLOCK_SIZE_BYTES EscSha256_DIGEST_LEN
#endif

/** Check for assuring that the ciphertext can be used as a temporary buffer for the encoding parameters. */
#if (EscEcies_ENCO_PARAMETERS_LEN > EscEcies_MAC_TAG_LEN)
#error "Length of encoding parameters must be smaller or equal than the MAC tag!"
#endif

/***************************************************************************
* 3. DEFINITIONS                                                          *
***************************************************************************/

/**
* Converts a 32 bit integer to a 4 byte array
*/
static void
counterKDFParamToArray(
    Esc_UINT32 counterKDF,
    Esc_UINT8 kdfParameters[] );

/**
* Converts an EC point to an octet string according to 5.5.6.2.1
*/
static Esc_ERROR
EscEcies_EC2OSP_XY(
    const EscEcies_ContextT* ctx,
    Esc_UINT8 osPoint[],
    Esc_UINT32* osPointLen );

/**
* Converts an octet string to an EC point according to 5.5.6.2.1
*/
static Esc_ERROR
EscEcies_OS2ECP_XY(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 osPoint[],
    Esc_UINT32 osPointLen );

/**
* Key Derivation function "KDF2"  - according to 13.2
*/
static Esc_ERROR
EscEcies_KDF2_BLOCK(
    Esc_UINT8 derivedKey[],
    const Esc_UINT8 keyMaterial[],
    Esc_UINT32 keyMaterialLen,
    const Esc_UINT8 kdfParameters[],
    Esc_UINT32 counter );

/**
 * Starts encryption/decryption
 */
static Esc_ERROR
EscEcies_StartEncryptDecrypt(
    EscEcies_ContextT* ctx,
    Esc_UINT32 plaintextLen,
    const Esc_UINT8 publicKey[],
    Esc_UINT32 publicKeyLen );

/**
 * Encrypts/decrypts data, updates hmac
 */
static Esc_ERROR
EscEcies_EncryptDecrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 result[],
    Esc_UINT32 length,
    Esc_BOOL encrypt );

/**
 * Finishes the encryption/decryption and generates the MAC
 */
static Esc_ERROR
EscEcies_EncryptDecrypt_Finish(
    EscEcies_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen );

/***************************************************************************
* 4. CONSTANTS                                                            *
***************************************************************************/

/***************************************************************************
* 5. IMPLEMENTATION OF FUNCTIONS                                          *
***************************************************************************/

/**
* Converts a 32 bit integer to a 4 byte array
*/
static void
counterKDFParamToArray(
    Esc_UINT32 counterKDF,
    Esc_UINT8 kdfParameters[] )
{
    kdfParameters[0U] = (Esc_UINT8) (counterKDF >> 24U);
    kdfParameters[1U] = (Esc_UINT8) (counterKDF >> 16U);
    kdfParameters[2U] = (Esc_UINT8) (counterKDF >> 8U);
    kdfParameters[3U] = (Esc_UINT8) (counterKDF);
}

/**
* Converts an EC point to an octet string according to 5.5.6.2.1
*/
static Esc_ERROR
EscEcies_EC2OSP_XY(
    const EscEcies_ContextT* ctx,
    Esc_UINT8 osPoint[],
    Esc_UINT32* osPointLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 i;
    const Esc_UINT16 keyBytes = ctx->curve->curveSize.keySizeBytes;

    /* Set the first byte (called 'PC') to 0000 0100 (see 5.5.6.2.1) */
    osPoint[0U] = 0x04U;

    for (i = 0U; i < keyBytes; i++)
    {
        osPoint[i + 1U] = ctx->pubKey.x[i];
        osPoint[(keyBytes + 1U) + i] = ctx->pubKey.y[i];
    }
    *osPointLen = (2U * (Esc_UINT32)keyBytes ) + 1U;

    return returnCode;
}

/**
* Converts an octet string to an EC point according to 5.5.6.2.1
* Used only for public key extraction.
*/
static Esc_ERROR
EscEcies_OS2ECP_XY(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 osPoint[],
    Esc_UINT32 osPointLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 i;
    Esc_UINT16 keyBytes = ctx->curve->curveSize.keySizeBytes;

    if ( osPointLen < (((Esc_UINT32)keyBytes * 2U) + 1U ) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else if ( osPoint[0] != 0x04U )
    {
        returnCode = Esc_INVALID_PUBLIC_KEY;
    }
    else
    {
        for ( i = 0U; i < keyBytes; i++ )
        {
            ctx->pubKey.x[i] = osPoint[i + 1U];
            ctx->pubKey.y[i] = osPoint[(keyBytes + 1U) + i];
        }
    }

    return returnCode;
}

/**
* Key Derivation function "KDF2"  - according to 13.2
*/
static Esc_ERROR
EscEcies_KDF2_BLOCK(
    Esc_UINT8 derivedKey[],
    const Esc_UINT8 keyMaterial[],
    Esc_UINT32 keyMaterialLen,
    const Esc_UINT8 kdfParameters[],
    Esc_UINT32 counter )
{
    /*lint -save -e774 returnCode can change during #if switch; check on line 227 needed for this case, not constant expression*/
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 parameter_len;
    Esc_UINT8 counterArray[EscEcies_Esc_UINT32_SIZE];

#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
    EscSha1_ContextT ctx;
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
    EscSha256_ContextT ctx;
#else
#   error "EscEcies_HASH_TYPE is not supported!"
#endif

    if (returnCode == Esc_NO_ERROR)
    {
        /* check if we use KDF parameters or not */
        if (kdfParameters == Esc_NULL_PTR)
        {
            parameter_len = 0U;
        }
        else
        {
            parameter_len = EscEcies_KDF_PARAMETERS_LEN;
        }

        /* copy the counter into the hash input array */
        counterArray[0U] = (Esc_UINT8)(counter >> 24U);
        counterArray[1U] = (Esc_UINT8)(counter >> 16U);
        counterArray[2U] = (Esc_UINT8)(counter >> 8U);
        counterArray[3U] = (Esc_UINT8)(counter);

#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)

        returnCode = EscSha1_Init(&ctx);
        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha1_Update(&ctx, keyMaterial, keyMaterialLen);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscSha1_Update(&ctx, counterArray, 4U);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscSha1_Update(&ctx, kdfParameters, parameter_len);
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscSha1_Finish(&ctx, derivedKey, EscSha1_DIGEST_LEN);
                    }
                }
            }
        }

#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)

        if (returnCode == Esc_NO_ERROR)
        {
            returnCode = EscSha256_Init(FALSE, &ctx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = EscSha256_Update(&ctx, keyMaterial, keyMaterialLen);
                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscSha256_Update(&ctx, counterArray, 4U);
                    if (returnCode == Esc_NO_ERROR)
                    {
                        returnCode = EscSha256_Update(&ctx, kdfParameters, parameter_len);
                        if (returnCode == Esc_NO_ERROR)
                        {
                            returnCode = EscSha256_Finish(&ctx, derivedKey, EscSha256_DIGEST_LEN);
                        }
                    }
                }
            }
        }

#endif
    }
    return returnCode;
}
/*lint -restore*/

/**
* Validate public key, initialize encryption counter, generate the sender's key pair
*/
Esc_ERROR
EscEcies_Init_Encrypt(
    EscEcies_ContextT* ctx,
    const EscEcc_PublicKeyT* recPublicKey,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 sharedSecretLen;

    /* Parameter check. CurveId is checked in ECC functions */
    if ( (ctx != Esc_NULL_PTR) && (recPublicKey != Esc_NULL_PTR) && (privKey != Esc_NULL_PTR) && (privKeyLen != Esc_NULL_PTR) && (getRandomFunc != Esc_NULL_PTR) )
    {
        /* Set the encryption counter to zero and lookup curve */
        ctx->counterKDFParameter = 0U;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        ctx->useKDFParameter = useKDFParam;

        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* Generate a fresh key pair */
        returnCode = EscEcc_KeyGeneration( &ctx->pubKey, privKey, privKeyLen, randomState, getRandomFunc, curveId );
    }

    if (returnCode == Esc_NO_ERROR)
    {
#if EscEcies_DHAES_ENABLED == 1
        /* Shared Secret with ECDH (ECSVDP-DH) */
        Esc_UINT32 pklen = (2U * (Esc_UINT32)ctx->curve->curveSize.keySizeBytes) + 1U;
        sharedSecretLen = ((EscEcies_PUBLIC_KEY_LEN_MAX + EscFeArith_KEY_BYTES_MAX) - pklen);
        returnCode = EscEcc_ComputeSharedSecret( &ctx->sharedSecret[pklen], &sharedSecretLen, privKey, *privKeyLen, recPublicKey, curveId );
#else
        sharedSecretLen = EscFeArith_KEY_BYTES_MAX;
        /* Shared Secret with ECDH (ECSVDP-DH) */
        returnCode = EscEcc_ComputeSharedSecret( ctx->sharedSecret, &sharedSecretLen, privKey, *privKeyLen, recPublicKey, curveId );
#endif
        /* It is assumed that the sharedSecret has a length of the key size (acc. to the ECDH standard) */
        Esc_ASSERT( sharedSecretLen == ctx->curve->curveSize.keySizeBytes );
    }

    return returnCode;
}

/**
* Initialize decryption counter and compute the shared secret
*/
Esc_ERROR
EscEcies_Init_Decrypt(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 ciphertext[],
    Esc_UINT32 ciphertextLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 sharedSecretLen;

    /* Parameter check */
    if ( (ctx != Esc_NULL_PTR) && (ciphertext != Esc_NULL_PTR) && (privKey != Esc_NULL_PTR) )
    {
        /* set the encryption counter to zero and lookup the curve */
        ctx->counterKDFParameter = 0U;
        ctx->curve = EscPtArithWs_GetCurve(curveId);
        ctx->useKDFParameter = useKDFParam;

        if (ctx->curve == Esc_NULL_PTR)
        {
            returnCode = Esc_INVALID_CURVE;
        }
    }
    else
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        /* get the sender's public key from the ciphertext */
        returnCode = EscEcies_OS2ECP_XY( ctx, ciphertext, ciphertextLen );
    }

    if (returnCode == Esc_NO_ERROR)
    {
#if EscEcies_DHAES_ENABLED == 1
        /* Shared Secret with ECDH (ECSVDP-DH) */
        Esc_UINT32 pklen = (2U * (Esc_UINT32)ctx->curve->curveSize.keySizeBytes) + 1U;
        sharedSecretLen = ((EscEcies_PUBLIC_KEY_LEN_MAX + EscFeArith_KEY_BYTES_MAX) - pklen);
        returnCode = EscEcc_ComputeSharedSecret( &ctx->sharedSecret[pklen], &sharedSecretLen, privKey, privKeyLen, &ctx->pubKey, curveId );
#else
        /* Shared Secret with ECDH (ECSVDP-DH) */
        sharedSecretLen = EscFeArith_KEY_BYTES_MAX;
        returnCode = EscEcc_ComputeSharedSecret( ctx->sharedSecret, &sharedSecretLen, privKey, privKeyLen, &ctx->pubKey, curveId );
#endif
        /* It is assumed that the sharedSecret has a length of the key size (acc. to the ECDH standard) */
        Esc_ASSERT( sharedSecretLen == ctx->curve->curveSize.keySizeBytes );
    }

    return returnCode;
}

/**
 * Starts encryption/decryption
 */
static Esc_ERROR
EscEcies_StartEncryptDecrypt(
    EscEcies_ContextT* ctx,
    Esc_UINT32 plaintextLen,
    const Esc_UINT8 publicKey[],
    Esc_UINT32 publicKeyLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT32 keyBytes;
    Esc_UINT8 macKey[EscEcies_MAC_KEY_BYTES]; /* Array that contains MAC key */
    Esc_UINT8 sharedSecretKey[EscEcies_BLOCK_SIZE_BYTES]; /* Derived key from KDF */
    Esc_UINT32 nBlocks; /* Number of blocks for a MAC key */
    Esc_UINT32 macCounter = 0U; /* Number of derived MAC key bytes */
    Esc_UINT8 kdfParameters[EscEcies_KDF_PARAMETERS_LEN]; /* KDF parameters */

    if ( (ctx == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( publicKeyLen == 0U )
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }
    else
    {
        keyBytes = (Esc_UINT32)ctx->curve->curveSize.keySizeBytes;

        ctx->plainLen = plaintextLen;
        ctx->currentKeyPosition = 0U;
        ctx->usedData = 0U;
        ctx->keyMaterialLen = keyBytes; /* DHAES = 0 */
        ctx->counterBlock = 1U;

        /* Initialize util arrays */
        Esc_memset(macKey, (Esc_UINT8)0U, EscEcies_MAC_KEY_BYTES);
        Esc_memset(sharedSecretKey, (Esc_UINT8)0U, EscEcies_BLOCK_SIZE_BYTES);
        Esc_memset(kdfParameters, (Esc_UINT8)0U, EscEcies_KDF_PARAMETERS_LEN);

        /* Derive MAC key */
#if EscEcies_DHAES_ENABLED == 1
        /* Copy the Public Key into the KDF input */
        for (i = 0U; i < publicKeyLen; i++)
        {
            ctx->sharedSecret[i] = publicKey[i];
        }

        /* KDF input for DHAES = 1 */
        ctx->keyMaterialLen += publicKeyLen;
#else
        /* Initial counter for NON DHAES mode is after the encryption/decryption key */
        ctx->counterBlock += plaintextLen / EscEcies_BLOCK_SIZE_BYTES;
        ctx->currentKeyPosition = plaintextLen % EscEcies_BLOCK_SIZE_BYTES;
#endif
        nBlocks = ((Esc_UINT32)(EscEcies_MAC_KEY_BYTES + ctx->currentKeyPosition) / EscEcies_BLOCK_SIZE_BYTES);

        if ((((EscEcies_MAC_KEY_BYTES + ctx->currentKeyPosition) % EscEcies_BLOCK_SIZE_BYTES) > 0U))
        {
            nBlocks++;
        }

        /* Save mac key block by block */
        for (i = 0; ((i < nBlocks) && (returnCode == Esc_NO_ERROR)); i++)
        {
            if (ctx->useKDFParameter == TRUE)
            {
                /* If KDF parameters are used, set the KDF input */
                counterKDFParamToArray(ctx->counterKDFParameter, kdfParameters);
                returnCode = EscEcies_KDF2_BLOCK( sharedSecretKey, ctx->sharedSecret, ctx->keyMaterialLen,
                        kdfParameters, ctx->counterBlock );
            }
            else
            {
                returnCode = EscEcies_KDF2_BLOCK( sharedSecretKey, ctx->sharedSecret, ctx->keyMaterialLen,
                        Esc_NULL_PTR, ctx->counterBlock );
            }
            if (returnCode == Esc_NO_ERROR)
            {
                for ( ; macCounter < EscEcies_MAC_KEY_BYTES; macCounter++)
                {
                    /* If the end of a block is reached */
                    if (ctx->currentKeyPosition >= EscEcies_BLOCK_SIZE_BYTES)
                    {
                        ctx->counterBlock++;
                        ctx->currentKeyPosition = 0;
                        break;
                    }

                    macKey[macCounter] = sharedSecretKey[ctx->currentKeyPosition];
                    ctx->currentKeyPosition++;
                }
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
#if EscEcies_DHAES_ENABLED == 0
            /* Block position and cursor position inside of a block for encryption/decryption key */
            ctx->counterBlock = 1U;
            ctx->currentKeyPosition = 0U;
#endif

            /* Initialize HMAC */
#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
            /* Initialize HMAC with SHA-1 and MAC key */
            returnCode = EscHmacSha1_Init( &ctx->hmacCtx, macKey, EscEcies_MAC_KEY_BYTES );
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
            /* Initialize HMAC with SHA-256 and MAC key */
            returnCode = EscHmacSha256_Init( FALSE, &ctx->hmacCtx, macKey, EscEcies_MAC_KEY_BYTES );
#endif
        }
    }

    return returnCode;
}

Esc_ERROR
EscEcies_StartEncrypt(
    EscEcies_ContextT* ctx,
    Esc_UINT32 plaintextLen,
    Esc_UINT8 ciphertext[],
    Esc_UINT32* ciphertextLen,
    Esc_UINT32* publicKeyLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 keyBytes;

    if ((ctx == Esc_NULL_PTR) || (publicKeyLen == Esc_NULL_PTR) || (ciphertextLen == Esc_NULL_PTR) || (ciphertext == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        keyBytes = ctx->curve->curveSize.keySizeBytes;
        /* Check if the ciphertext has enough space to hold public key */
        if ( *ciphertextLen < (((Esc_UINT32)keyBytes * 2U) + 1U ) )
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Encode public key and save public key length in publicKeyLen */
            returnCode = EscEcies_EC2OSP_XY( ctx, ciphertext, publicKeyLen );

            if (returnCode == Esc_NO_ERROR)
            {
                /* Check if ciphertext can hold public key, plaintext encryption and mac tag */
                if (*ciphertextLen < (*publicKeyLen + plaintextLen + EscEcies_MAC_TAG_LEN))
                {
                    returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    returnCode = EscEcies_StartEncryptDecrypt( ctx, plaintextLen, ciphertext, *publicKeyLen );

                    if (returnCode == Esc_NO_ERROR)
                    {
                        *ciphertextLen = *publicKeyLen + plaintextLen + EscEcies_MAC_TAG_LEN;
                    }
                }
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscEcies_StartDecrypt(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 publicKey[],
    Esc_UINT32* publicKeyLen,
    Esc_UINT32 ciphertextLen,
    Esc_UINT32* plaintextLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 keyBytes;

    if ((ctx == Esc_NULL_PTR) || (publicKeyLen == Esc_NULL_PTR) || (plaintextLen == Esc_NULL_PTR) || (publicKey == Esc_NULL_PTR))
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (*publicKeyLen > EscEcies_PUBLIC_KEY_LEN_MAX)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        keyBytes = (Esc_UINT32)ctx->curve->curveSize.keySizeBytes;

        if (*publicKeyLen < ((2U * keyBytes) + 1U))
        {
            returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
        }

        if (returnCode == Esc_NO_ERROR)
        {
            *publicKeyLen = (2U * keyBytes) + 1U;

            if (ciphertextLen < (*publicKeyLen + EscEcies_MAC_TAG_LEN))
            {
                /* Check if ciphertext can hold public key and mac tag */
                returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
            }

            if (returnCode == Esc_NO_ERROR)
            {
                *plaintextLen = (ciphertextLen - *publicKeyLen) - EscEcies_MAC_TAG_LEN;
                returnCode = EscEcies_StartEncryptDecrypt( ctx, *plaintextLen, publicKey, *publicKeyLen );
            }
        }
    }

    return returnCode;
}

/**
 * Encrypts/decrypts data, updates hmac
 */
static Esc_ERROR
EscEcies_EncryptDecrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 input[],
    Esc_UINT8 result[],
    Esc_UINT32 length,
    Esc_BOOL encrypt )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT32 i;
    Esc_UINT32 nBlocks;
    Esc_UINT8 sharedSecretKey[EscEcies_BLOCK_SIZE_BYTES]; /* Key derived from KDF */
    Esc_UINT8 kdfParameters[EscEcies_KDF_PARAMETERS_LEN];
    Esc_UINT8 plainCounter = 0U; /* Number of encrypted/decrypted bytes */

    if ( (ctx == Esc_NULL_PTR) || ( ( ( input == Esc_NULL_PTR) || (result == Esc_NULL_PTR ) ) && ( length != 0U ) ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( (ctx->usedData + length) > ctx->plainLen )
    {
        returnCode = Esc_OUT_OF_RANGE;
    }
    else
    {
        if (length != 0U)
        {
            /* Initialize util arrays */
            Esc_memset(sharedSecretKey, (Esc_UINT8)0U, EscEcies_BLOCK_SIZE_BYTES);
            Esc_memset(kdfParameters, (Esc_UINT8)0U, EscEcies_KDF_PARAMETERS_LEN);

            /* Derive encryption/decryption key and do encryption/decryption */
            nBlocks = (length + ctx->currentKeyPosition) / EscEcies_BLOCK_SIZE_BYTES;

            if ((((length + ctx->currentKeyPosition) % EscEcies_BLOCK_SIZE_BYTES) > 0U))
            {
                nBlocks++;
            }

            /* Encryption/decryption block by block */
            for (i = 0; ((i < nBlocks) && (returnCode == Esc_NO_ERROR)); i++)
            {
                if (ctx->useKDFParameter == TRUE)
                {
                    /* If KDF parameters are used, set the KDF input */
                    counterKDFParamToArray(ctx->counterKDFParameter, kdfParameters);
                    returnCode = EscEcies_KDF2_BLOCK( sharedSecretKey, ctx->sharedSecret, ctx->keyMaterialLen,
                            kdfParameters, ctx->counterBlock );
                }
                else
                {
                    returnCode = EscEcies_KDF2_BLOCK( sharedSecretKey, ctx->sharedSecret, ctx->keyMaterialLen,
                            Esc_NULL_PTR, ctx->counterBlock );
                }

                if (returnCode == Esc_NO_ERROR)
                {
                    for ( ; plainCounter < length; plainCounter++)
                    {
                        /* If the end of a block is reached */
                        if (ctx->currentKeyPosition >= EscEcies_BLOCK_SIZE_BYTES)
                        {
                            ctx->counterBlock++;
                            ctx->currentKeyPosition = 0;
                            break;
                        }

                        result[plainCounter] = input[plainCounter] ^ sharedSecretKey[ctx->currentKeyPosition];
                        ctx->currentKeyPosition++;
                    }
                }
            }

            if (returnCode == Esc_NO_ERROR)
            {
                ctx->usedData += length;

                /* Update HMAC */
#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
                if (encrypt == TRUE)
                {
                    /* In encryption, input is plaintext. Mac is calculated over result (ciphertext) */
                    returnCode = EscHmacSha1_Update( &ctx->hmacCtx, result, length );
                }
                else
                {
                    /* In decryption, input is ciphertext. Mac is calculated over input (ciphertext) */
                    returnCode = EscHmacSha1_Update( &ctx->hmacCtx, input, length );
                }
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
                if (encrypt == TRUE)
                {
                    returnCode = EscHmacSha256_Update( &ctx->hmacCtx, result, length );
                }
                else
                {
                    returnCode = EscHmacSha256_Update( &ctx->hmacCtx, input, length );
                }
#endif
            }
        }
    }
    return returnCode;
}

Esc_ERROR
EscEcies_Encrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 plaintext[],
    Esc_UINT8 ciphertext[],
    Esc_UINT32 plaintextLen )
{
    return EscEcies_EncryptDecrypt_Update(ctx, plaintext, ciphertext, plaintextLen, TRUE);
}

Esc_ERROR
EscEcies_Decrypt_Update(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 ciphertext[],
    Esc_UINT8 plaintext[],
    Esc_UINT32 ciphertextLen )
{
    return EscEcies_EncryptDecrypt_Update(ctx, ciphertext, plaintext, ciphertextLen, FALSE);
}

/**
 * Generates the Message Authentication Code
 */
/*lint -save -e774 returnCode can change during #if switch*/
static Esc_ERROR
EscEcies_EncryptDecrypt_Finish(
    EscEcies_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    if ( (ctx == Esc_NULL_PTR) || (macTag == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if (macTagLen != EscEcies_MAC_TAG_LEN)
    {
        returnCode = Esc_INSUFFICIENT_BUFFER_SIZE;
    }
    else if ( ctx->usedData != ctx->plainLen )
    {
        returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
    }
    else
    {
#if EscEcies_DHAES_ENABLED == 1 /* DHAES Mode */
        /* Encoding Parameter */
        Esc_UINT8 encodingParametersLen[EscEcies_ENCO_PARAMETERS_LEN];
        /* Initialize encoding params */
        Esc_memset(encodingParametersLen, (Esc_UINT8)0U, EscEcies_ENCO_PARAMETERS_LEN);

#   if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
        returnCode = EscHmacSha1_Update( &ctx->hmacCtx, encodingParametersLen, EscEcies_ENCO_PARAMETERS_LEN );
#   elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
        returnCode = EscHmacSha256_Update( &ctx->hmacCtx, encodingParametersLen, EscEcies_ENCO_PARAMETERS_LEN );
#   endif
#endif

        if (returnCode == Esc_NO_ERROR)
        {
            /* If enc/dec is finished and it uses KDF parameters, KDF parameters are incremented */
            if (ctx->useKDFParameter == TRUE)
            {
                ctx->counterKDFParameter++;
            }

#if (EscEcies_HASH_TYPE == EscEcies_USE_SHA1)
            returnCode = EscHmacSha1_Finish( &ctx->hmacCtx, macTag, EscEcies_MAC_TAG_LEN );
#elif (EscEcies_HASH_TYPE == EscEcies_USE_SHA256)
            returnCode = EscHmacSha256_Finish( &ctx->hmacCtx, macTag, EscEcies_MAC_TAG_LEN );
#endif
        }
    }

    return returnCode;
}

/*lint -restore*/
Esc_ERROR
EscEcies_Encrypt_Finish(
    EscEcies_ContextT* ctx,
    Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen )
{
    return EscEcies_EncryptDecrypt_Finish(ctx, macTag, macTagLen);
}

Esc_ERROR
EscEcies_Decrypt_Finish(
    EscEcies_ContextT* ctx,
    const Esc_UINT8 macTag[],
    Esc_UINT32 macTagLen )
{
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT8 calculatedMac[EscEcies_MAC_TAG_LEN];

    if (macTag == Esc_NULL_PTR)
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else
    {
        Esc_memset(calculatedMac, (Esc_UINT8)0U, EscEcies_MAC_TAG_LEN);
        returnCode = EscEcies_EncryptDecrypt_Finish(ctx, calculatedMac, macTagLen);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Check if calculated MAC is valid */
            if (Esc_memcmp(macTag, calculatedMac, macTagLen) != 0U)
            {
                returnCode = Esc_INVALID_MAC;
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscEcies_Encrypt(
    const Esc_UINT8 plaintext[],
    Esc_UINT32 plaintextLen,
    Esc_UINT8 ciphertext[],
    Esc_UINT32* ciphertextLen,
    const EscEcc_PublicKeyT* recPublicKey,
    Esc_UINT8 privKey[],
    Esc_UINT32* privKeyLen,
    void* randomState,
    EscRandom_GetRandom getRandomFunc,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    /* The ECIES context */
    EscEcies_ContextT ctx;

    Esc_UINT32 publicKeyLen = 0U; /* Will be set in EscEcies_StartEncrypt */

    if ( (plaintext != Esc_NULL_PTR) && (ciphertext != Esc_NULL_PTR) && (ciphertextLen != Esc_NULL_PTR) &&
         (recPublicKey != Esc_NULL_PTR) && (privKey != Esc_NULL_PTR) && (privKeyLen != Esc_NULL_PTR) &&
         (getRandomFunc != Esc_NULL_PTR) )
    {
        /* Initialize ECIES */
        returnCode = EscEcies_Init_Encrypt( &ctx, recPublicKey, privKey, privKeyLen,
                randomState, getRandomFunc, curveId, useKDFParam );

        if (returnCode == Esc_NO_ERROR)
        {
            /* Start encryption */
            returnCode = EscEcies_StartEncrypt( &ctx, plaintextLen, ciphertext, ciphertextLen, &publicKeyLen );

            if (returnCode == Esc_NO_ERROR)
            {
                /* Encrypt data */
                returnCode = EscEcies_Encrypt_Update( &ctx, plaintext, &ciphertext[publicKeyLen], plaintextLen );

                if (returnCode == Esc_NO_ERROR)
                {
                    /* Generate MAC tag */
                    returnCode = EscEcies_Encrypt_Finish( &ctx, &ciphertext[publicKeyLen + plaintextLen], EscEcies_MAC_TAG_LEN );
                }
            }
        }
    }

    return returnCode;
}

Esc_ERROR
EscEcies_Decrypt(
    const Esc_UINT8 ciphertext[],
    Esc_UINT32 ciphertextLen,
    Esc_UINT8 plaintext[],
    Esc_UINT32* plaintextLen,
    const Esc_UINT8 privKey[],
    Esc_UINT32 privKeyLen,
    const EscEcc_CurveId curveId,
    Esc_BOOL useKDFParam )
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;
    /* The ECIES context */
    EscEcies_ContextT ctx;
    /* Length of the encoded public key. Actual value will be set in EscEcies_StartDecrypt */
    Esc_UINT32 publicKeyLen = EscEcies_PUBLIC_KEY_LEN_MAX;

    if ( (plaintext != Esc_NULL_PTR) && (ciphertext != Esc_NULL_PTR) && (privKey != Esc_NULL_PTR) )
    {
        /* Initialize ECIES */
        returnCode = EscEcies_Init_Decrypt(&ctx, ciphertext, ciphertextLen, privKey, privKeyLen, curveId, useKDFParam);

        if (returnCode == Esc_NO_ERROR)
        {
            /* Start decryption */
            returnCode = EscEcies_StartDecrypt(&ctx, ciphertext, &publicKeyLen, ciphertextLen, plaintextLen);

            if (returnCode == Esc_NO_ERROR)
            {
                /* Decrypt data */
                returnCode = EscEcies_Decrypt_Update(&ctx, &ciphertext[publicKeyLen], plaintext, *plaintextLen);

                if (returnCode == Esc_NO_ERROR)
                {
                    /* Verify MAC tag */
                    returnCode = EscEcies_Decrypt_Finish(&ctx, &ciphertext[publicKeyLen + *plaintextLen], EscEcies_MAC_TAG_LEN);
                }
            }
        }
    }

    return returnCode;
}

#endif /* EscEcc_ECDH_ENABLED */

/***************************************************************************
* 6. END                                                                  *
***************************************************************************/
