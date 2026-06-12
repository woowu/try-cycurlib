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

   $Rev: 4105 $
 */
/***************************************************************************/
/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/

#include "rsa.h"
#include "mem_mgt.h"

/***************************************************************************
 * 2. DEFINES                                                              *
 ***************************************************************************/

#if EscRsa_GENRSA_ENABLED == 1
/** Number of small primes that fit into a Esc_UINT8 (used for RSA key pair generation) */
#    define EscRsa_NUM_PRIMES 53U

/** Distance between p and q: ceil(2^0.1 << (EscRsa_RSA_BASE - 1)) */
#    if Esc_HAS_INT64 == 1
#        define EscRsa_PQ_LOWER_BOUND   2301615986U
#    else
#        define EscRsa_PQ_LOWER_BOUND   35120U
#    endif
#endif

/*lint -esym(750,EscRsa_STATE_CRT_*) Depending on the configuration, some state symbols may not be used */

/* CRT states */

#define EscRsa_STATE_CRT_INITIALIZED              1
#define EscRsa_STATE_CRT_M_POW_DMP1_P             2
#define EscRsa_STATE_CRT_PREPARE_M_POW_DMP1_Q     3
#define EscRsa_STATE_CRT_M_POW_DMP1_Q             4
#define EscRsa_STATE_CRT_COMPUTE_S                5
#define EscRsa_STATE_CRT_FINISH                   6

/***************************************************************
Checks a given RSA key length
 ***************************************************************/
#if (EscRsa_KEY_BITS_MAX == 1024U)
/** Tests given keysize against the maximum allowed key size */
    #define EscRsa_TEST_KEYSIZE_BITS(b) (( (b) == 1024U) )
#elif (EscRsa_KEY_BITS_MAX == 1536U)
/** Tests given keysize against the maximum allowed key size */
    #define EscRsa_TEST_KEYSIZE_BITS(b) (( (b) == 1024U) || ( (b) == 1536U) )
#elif (EscRsa_KEY_BITS_MAX == 2048U)
/** Tests given keysize against the maximum allowed key size */
    #define EscRsa_TEST_KEYSIZE_BITS(b) (( (b) == 1024U) || ( (b) == 1536U) || ( (b) == 2048U) )
#elif (EscRsa_KEY_BITS_MAX == 3072U)
/** Tests given keysize against the maximum allowed key size */
    #define EscRsa_TEST_KEYSIZE_BITS(b) (( (b) == 1024U) || ( (b) == 1536U) || ( (b) == 2048U) || ( (b) == 3072U) )
#elif (EscRsa_KEY_BITS_MAX == 4096U)
/** Tests given keysize against the maximum allowed key size */
    #define EscRsa_TEST_KEYSIZE_BITS(b) (( (b) == 1024U) || ( (b) == 1536U) || ( (b) == 2048U) || ( (b) == 3072U) || ( (b) == 4096U))
#endif

/***************************************************************************
 * 3. DEFINITIONS                                                          *
 ***************************************************************************/

#if EscRsa_CRT_ENABLED == 1
static Esc_ERROR
EscRsa_ModExpPrivRunCrt(
    EscRsa_PrivContext *ctx);
#endif

#if EscRsa_GENRSA_ENABLED == 1
static void
EscRsaFe_ShiftRight(
    EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize );

static void
EscRsaFe_SignedShiftRight(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const Esc_UINT16 wordSize );

static Esc_BOOL
EscRsaFe_IsOne(
    const EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize );

static void
EscRsaFe_SignedAdd(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const EscRsa_FieldElementT* b,
    const EscRsa_HWORD bSign,
    const Esc_UINT16 wordSize );

static void
EscRsaFe_SignedSubtract(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const EscRsa_FieldElementT* b,
    const EscRsa_HWORD bSign,
    const Esc_UINT16 wordSize );

static void
EscRsaFe_AddWord(
    EscRsa_FieldElementT* c,
    const EscRsa_HWORD a,
    const Esc_UINT16 wordSize );

static EscRsa_HWORD
EscRsaFe_ModWord(
    const EscRsa_FieldElementT* a,
    EscRsa_HWORD w,
    const Esc_UINT16 wordSize );

static Esc_BOOL
EscRsaFe_IsPositive(
    EscRsa_HWORD sign,
    const EscRsa_FieldElementT* fe,
    const Esc_UINT16 wordSize);

static Esc_ERROR
EscRsaFe_ModInv(
    const EscRsa_FieldElementT* x,
    const EscRsa_FieldElementT* y,
    EscRsa_FieldElementT* result,
    const Esc_UINT16 wordSize );

static Esc_ERROR
EscRsa_MillerRabin(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const EscRsa_FieldElementT* n,
    Esc_BOOL* prime,
    const EscRsa_KeySizeT* keySizeHalf );

static void
EscRsa_GeneratePrimeCandidate(
    EscRsa_FieldElementT* n,
    Esc_UINT16 numKeyWordsHalf );

#if EscRsa_CRT_ENABLED == 1
static Esc_ERROR
EscRsa_ComputeCrtValues(
    const EscRsa_FieldElementT *p,
    const EscRsa_FieldElementT *q,
    const EscRsa_FieldElementT *privExp,
    EscRsa_PrivKeyT *privateKey,
    Esc_UINT16 wordSize);
#endif

#endif

#if (EscRsa_GENRSA_ENABLED == 1)
static Esc_ERROR
EscRsa_GenerateKey(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscRsa_PubKeyT* pubKey,
    EscRsa_FieldElementT *p,
    EscRsa_FieldElementT *q,
    EscRsa_FieldElementT *privExp,
    Esc_UINT32 pubExp,
    Esc_UINT16 lenBits );
#endif

/***************************************************************************
 * 4. CONSTANTS                                                            *
 ***************************************************************************/

/***************************************************************************
 * 5. IMPLEMENTATION OF FUNCTIONS                                          *
 ***************************************************************************/

/*******************************************************************************
 * Modular exponentiation c = m^e mod n (expects big endian input and pub Key) *
 ******************************************************************************/

Esc_ERROR
EscRsa_CheckPublicKey(
    const EscRsa_PubKeyT *key)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (key != Esc_NULL_PTR)
    {
        Esc_UINT16 words = EscRsa_RSA_SIZE_WORDS_FROMBITS(key->keySizeBits);

        /* mask the upper 6 bits from an HWORD */
        EscRsa_HWORD checkMask = (EscRsa_HWORD)((EscRsa_HWORD)0x3F << (EscRsa_RSA_BASE - 6U));

        if (!EscRsa_TEST_KEYSIZE_BITS(key->keySizeBits))
        {
            returnCode = Esc_INVALID_KEY_LENGTH;
        }
        else if (key->pubExp < 3U)
        {
            returnCode = Esc_INVALID_PUBLIC_KEY;
        }
        else if ((key->modulus.words[words - 1U] & checkMask) == 0U)
        {
            returnCode = Esc_INVALID_PUBLIC_KEY;
        }
        else
        {
            returnCode = Esc_NO_ERROR;
        }
    }

    return returnCode;
}

Esc_ERROR
EscRsa_CheckPrivateKey(
    const EscRsa_PrivKeyT *key)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (key != Esc_NULL_PTR)
    {
        const EscRsa_PubKeyT *pubKey = &key->pubKey;
        Esc_UINT16 numWords = EscRsa_RSA_SIZE_WORDS_FROMBITS(pubKey->keySizeBits);

        /* Check contained public key first */
        returnCode = EscRsa_CheckPublicKey(pubKey);

        if (returnCode == Esc_INVALID_PUBLIC_KEY)
        {
            /* Map this error to Esc_INVALID_PRIVATE_KEY to avoid confusion about public/private keys */
            returnCode = Esc_INVALID_PRIVATE_KEY;
        }
        else if (returnCode != Esc_NO_ERROR)
        {
            /* Do nothing, but use return code from EscRsa_CheckPublicKey() */
        }
        else if (key->usesCrt == FALSE)
        {
            /* 0 < exponent < n */
            if ( (EscRsaFe_IsZero(&key->privKey.privExp, numWords) != FALSE) ||
                 (EscRsaFe_AbsoluteCompare( &key->privKey.privExp, &pubKey->modulus, numWords) != -1) )
            {
                returnCode = Esc_INVALID_PRIVATE_KEY;
            }
        }
        else
        {
#if EscRsa_CRT_ENABLED == 0
            returnCode = Esc_INVALID_PRIVATE_KEY;
#else
            Esc_UINT16 wordSizeHalf = numWords / 2U;

            /* 0 < dP < p */
            if ( (EscRsaFe_IsZero(&key->privKey.crt.dmp1, wordSizeHalf) != FALSE) ||
                 (EscRsaFe_AbsoluteCompare(&key->privKey.crt.dmp1, &key->privKey.crt.p, wordSizeHalf) != -1) )
            {
                returnCode = Esc_INVALID_PRIVATE_KEY;
            }

            /* 0 < dQ < q */
            if ( (EscRsaFe_IsZero(&key->privKey.crt.dmq1, wordSizeHalf) != FALSE) ||
                 (EscRsaFe_AbsoluteCompare(&key->privKey.crt.dmq1, &key->privKey.crt.q, wordSizeHalf) != -1) )
            {
                returnCode = Esc_INVALID_PRIVATE_KEY;
            }

            /* 0 < iqmp < p */
            if ( (EscRsaFe_IsZero(&key->privKey.crt.iqmp, wordSizeHalf) != FALSE) ||
                 (EscRsaFe_AbsoluteCompare(&key->privKey.crt.iqmp, &key->privKey.crt.p, wordSizeHalf) != -1) )
            {
                returnCode = Esc_INVALID_PRIVATE_KEY;
            }
#endif
        }
    }

    return returnCode;
}

Esc_ERROR
EscRsa_ModExpPub(
    const Esc_UINT8 input[],
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT8 result[] )
{
    Esc_ERROR returnCode;
    EscRsa_PubContext ctx;

    /* Initialize computation with public key and message */
    returnCode = EscRsa_ModExpPubInit(&ctx, pubKey, input, result);

    /* Run modular exponentiation (may be sliced) */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscRsa_ModExpPubRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    return returnCode;
}

/********************************************************************************
 * Modular exponentiation c = m^e mod n (expects big endian input and priv Key) *
 *******************************************************************************/
Esc_ERROR
EscRsa_ModExpPriv(
    const Esc_UINT8 input[],
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT8 result[] )
{
    Esc_ERROR returnCode;
    EscRsa_PrivContext ctx;

    /* Initialize computation with public key and message */
    returnCode = EscRsa_ModExpPrivInit(&ctx, privKey, input, result);

    /* Run modular exponentiation (may be sliced) */
    if (returnCode == Esc_NO_ERROR)
    {
        do
        {
            returnCode = EscRsa_ModExpPrivRun(&ctx);
        } while (returnCode == Esc_AGAIN);
    }

    /* Zeroize Private Key context */
    Esc_CLEAR_LOCAL_VAR(ctx);

    return returnCode;
}

#if EscRsa_CRT_ENABLED == 1
/********************************************************************************
 * Key <-> Bytes conversion functions                                           *
 *******************************************************************************/
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
    const Esc_UINT8 iqmp[] )
{
    Esc_ERROR returnCode;

    if ( (privKeyCrt == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) ||
         (p == Esc_NULL_PTR) ||
         (q == Esc_NULL_PTR) ||
         (dmp1 == Esc_NULL_PTR) ||
         (dmq1 == Esc_NULL_PTR) ||
         (iqmp == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        Esc_UINT16 byteSize = EscRsa_KEY_BYTES_FROMBITS( keySizeBits );
        Esc_UINT16 byteSizeHalf = byteSize / 2U;

        privKeyCrt->usesCrt = TRUE;

        /* Set the modulus */
        EscRsaFe_FromBytesBE( &privKeyCrt->pubKey.modulus, modulus, byteSize );
        /* Set public exponent */
        privKeyCrt->pubKey.pubExp = pubExp;
        /* Set keySizeBits */
        privKeyCrt->pubKey.keySizeBits = keySizeBits;
        /* Set p */
        EscRsaFe_FromBytesBE( &privKeyCrt->privKey.crt.p, p, byteSizeHalf );
        /* Set q */
        EscRsaFe_FromBytesBE( &privKeyCrt->privKey.crt.q, q, byteSizeHalf );
        /* Set dmp1 */
        EscRsaFe_FromBytesBE( &privKeyCrt->privKey.crt.dmp1, dmp1, byteSizeHalf );
        /* Set dmq1 */
        EscRsaFe_FromBytesBE( &privKeyCrt->privKey.crt.dmq1, dmq1, byteSizeHalf );
        /* Set iqmp */
        EscRsaFe_FromBytesBE( &privKeyCrt->privKey.crt.iqmp, iqmp, byteSizeHalf );

        returnCode = EscRsa_CheckPrivateKey(privKeyCrt);
    }

    return returnCode;
}

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
    Esc_UINT8 iqmp[] )
{
    Esc_ERROR returnCode;

    if ( (privKeyCrt == Esc_NULL_PTR) ||
         (keySizeBits == Esc_NULL_PTR) ||
         (pubExp == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) ||
         (p == Esc_NULL_PTR) ||
         (q == Esc_NULL_PTR) ||
         (dmp1 == Esc_NULL_PTR) ||
         (dmq1 == Esc_NULL_PTR) ||
         (iqmp == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(privKeyCrt->pubKey.keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else if ( privKeyCrt->usesCrt == FALSE )
    {
        returnCode = Esc_INVALID_PRIVATE_KEY;
    }
    else
    {
        Esc_UINT16 byteSize = EscRsa_KEY_BYTES_FROMBITS( privKeyCrt->pubKey.keySizeBits );

        /* Set the keySizeBits */
        *keySizeBits = privKeyCrt->pubKey.keySizeBits;
        /* Set the modulus */
        EscRsaFe_ToBytesBE( modulus, &privKeyCrt->pubKey.modulus, byteSize );
        /* Set public exponent */
        *pubExp = privKeyCrt->pubKey.pubExp;
        /* Set p */
        EscRsaFe_ToBytesBE( p, &privKeyCrt->privKey.crt.p, byteSize );
        /* Set q */
        EscRsaFe_ToBytesBE( q, &privKeyCrt->privKey.crt.q, byteSize );
        /* Set dmp1 */
        EscRsaFe_ToBytesBE( dmp1, &privKeyCrt->privKey.crt.dmp1, byteSize );
        /* Set dmq1 */
        EscRsaFe_ToBytesBE( dmq1, &privKeyCrt->privKey.crt.dmq1, byteSize );
        /* Set iqmp */
        EscRsaFe_ToBytesBE( iqmp, &privKeyCrt->privKey.crt.iqmp, byteSize );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}
#endif /* EscRsa_CRT_ENABLED */


Esc_ERROR
EscRsa_PrivKeyFromBytes(
    EscRsa_PrivKeyT* privKey,
    const Esc_UINT16 keySizeBits,
    const Esc_UINT8 modulus[],
    const Esc_UINT32 pubExp,
    const Esc_UINT8 privExp[] )
{
    Esc_ERROR returnCode;
    EscRsa_KeySizeT keySize;

    if ( (privKey == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) ||
         (privExp == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        privKey->usesCrt = FALSE;

        EscRsa_AssignKeyStruct(keySizeBits, &keySize);

        /* Set the modulus */
        EscRsaFe_FromBytesBE( &privKey->pubKey.modulus, modulus, keySize.bytes );
        /* Set public exponent */
        privKey->pubKey.pubExp = pubExp;
        /* Set keySizeBits */
        privKey->pubKey.keySizeBits = keySizeBits;
        /* Set privExp */
        EscRsaFe_FromBytesBE( &privKey->privKey.privExp, privExp, keySize.bytes );

        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    return returnCode;
}

Esc_ERROR
EscRsa_PubKeyFromBytes(
    EscRsa_PubKeyT* pubKey,
    const Esc_UINT16 keySizeBits,
    const Esc_UINT8 modulus[],
    const Esc_UINT32 pubExp )
{
    Esc_ERROR returnCode;

    if ( (pubKey == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        Esc_UINT16 byteSize = EscRsa_KEY_BYTES_FROMBITS( keySizeBits );
        /* Set the modulus */
        EscRsaFe_FromBytesBE( &pubKey->modulus, modulus, byteSize );
        /* Set public exponent */
        pubKey->pubExp = pubExp;
        /* Set keySizeBits */
        pubKey->keySizeBits = keySizeBits;

        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    return returnCode;
}

Esc_ERROR
EscRsa_BytesFromPrivKey(
    const EscRsa_PrivKeyT* privKey,
    Esc_UINT16* keySizeBits,
    Esc_UINT8 modulus[],
    Esc_UINT32* pubExp,
    Esc_UINT8 privExp[] )
{
    Esc_ERROR returnCode;

    if ( (privKey == Esc_NULL_PTR) ||
         (keySizeBits == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) ||
         (pubExp == Esc_NULL_PTR) ||
         (privExp == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(privKey->pubKey.keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else if ( privKey->usesCrt )
    {
        returnCode = Esc_INVALID_PRIVATE_KEY;
    }
    else
    {
        Esc_UINT16 byteSize = EscRsa_KEY_BYTES_FROMBITS( privKey->pubKey.keySizeBits );

        /* Set the keySizeBits */
        *keySizeBits = privKey->pubKey.keySizeBits;
        /* Set the modulus */
        EscRsaFe_ToBytesBE( modulus, &privKey->pubKey.modulus, byteSize );
        /* Set public exponent */
        *pubExp = privKey->pubKey.pubExp;
        /* Set private exponent */
        EscRsaFe_ToBytesBE( privExp, &privKey->privKey.privExp, byteSize );

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}

Esc_ERROR
EscRsa_BytesFromPubKey(
    const EscRsa_PubKeyT* pubKey,
    Esc_UINT16* keySizeBits,
    Esc_UINT8 modulus[],
    Esc_UINT32* pubExp )
{
    Esc_ERROR returnCode;

    if ( (pubKey == Esc_NULL_PTR) ||
         (keySizeBits == Esc_NULL_PTR) ||
         (modulus == Esc_NULL_PTR) ||
         (pubExp == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(pubKey->keySizeBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        Esc_UINT16 byteSize = EscRsa_KEY_BYTES_FROMBITS( pubKey->keySizeBits );

        /* Set the keySizeBits */
        *keySizeBits = pubKey->keySizeBits;
        /* Set the modulus */
        EscRsaFe_ToBytesBE( modulus, &pubKey->modulus, byteSize );
        /* Set public exponent */
        *pubExp = pubKey->pubExp;

        returnCode = Esc_NO_ERROR;
    }

    return returnCode;
}


#if EscRsa_GENRSA_ENABLED == 1
/********************************************************************************
 * RSA Key Generation functions                                                 *
 *******************************************************************************/

#if EscRsa_CRT_ENABLED == 1
static Esc_ERROR
EscRsa_ComputeCrtValues(
    const EscRsa_FieldElementT *p,
    const EscRsa_FieldElementT *q,
    const EscRsa_FieldElementT *privExp,
    EscRsa_PrivKeyT *privateKey,
    Esc_UINT16 wordSize)
{
    Esc_ERROR returnCode;
    EscRsa_FieldElementLongT multiplication_result;
    EscRsa_MultiplyDataT mult;
    Esc_UINT16 i;
    Esc_UINT16 wordSizeHalf = wordSize / 2U;

    /* Shortcuts */
    EscRsa_FieldElementT *iqmp = &privateKey->privKey.crt.iqmp;
    EscRsa_FieldElementT *dmp1 = &privateKey->privKey.crt.dmp1;
    EscRsa_FieldElementT *dmq1 = &privateKey->privKey.crt.dmq1;

    /* Store p and q in private key */
    EscRsaFe_Assign(&privateKey->privKey.crt.p, p, wordSize);
    EscRsaFe_Assign(&privateKey->privKey.crt.q, q, wordSize);

    /* Calculate d mod (p - 1) */
    EscRsaFe_Assign( dmp1, p, wordSize );
    dmp1->words[0U] &= (EscRsa_HWORD)(~(EscRsa_HWORD)1U);
    mult.c = &multiplication_result;
    mult.m = dmp1;
    EscRsaFe_ToLongFe( mult.c, privExp, wordSize );
    EscRsaFe_ModularReduction( &mult, wordSize );
    EscRsaFe_FromLongFe( dmp1, mult.c, wordSize );

    /* Calculate d mod (q - 1) */
    EscRsaFe_Assign( dmq1, q, wordSize );
    dmq1->words[0U] &= (EscRsa_HWORD)(~(EscRsa_HWORD)1U);
    mult.c = &multiplication_result;
    mult.m = dmq1;
    EscRsaFe_ToLongFe( mult.c, privExp, wordSize );
    EscRsaFe_ModularReduction( &mult, wordSize );
    EscRsaFe_FromLongFe( dmq1, mult.c, wordSize );

    /* Calculate q^-1 mod p */
    for (i = 0U; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
    {
        iqmp->words[i] = 0U;
    }
    returnCode = EscRsaFe_ModInv( p, q, iqmp, wordSizeHalf );

    return returnCode;
}
#endif

static Esc_ERROR
EscRsa_GenerateKey(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscRsa_PubKeyT* pubKey,
    EscRsa_FieldElementT *p,
    EscRsa_FieldElementT *q,
    EscRsa_FieldElementT *privExp,
    Esc_UINT32 pubExp,
    Esc_UINT16 lenBits )
{
    Esc_ERROR returnCode;

    EscRsa_KeySizeT keySizeHalf;
    EscRsa_FieldElementT e;
    EscRsa_FieldElementT temp;
    EscRsa_FieldElementLongT multiplication_result;
    EscRsa_MultiplyDataT mult;
    Esc_UINT8 candidate[EscRsa_KEY_BYTES_MAX_HALF];
    EscRsa_FWORD dist;
    Esc_BOOL prime;
    Esc_UINT16 i;
    Esc_UINT16 wordSize, wordSizeHalf, byteSizeHalf;

    if ( (pubExp < 3U) || ((pubExp & 1U) == 0U) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else if ( !EscRsa_TEST_KEYSIZE_BITS(lenBits) )
    {
        returnCode = Esc_INVALID_KEY_LENGTH;
    }
    else
    {
        /* The prime generator requires only half-size FEs */
        EscRsa_AssignKeyStruct(lenBits / 2U, &keySizeHalf);

        wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(lenBits);
        wordSizeHalf = keySizeHalf.words;
        byteSizeHalf = keySizeHalf.bytes;
        pubKey->keySizeBits = lenBits;

        /* Set public exponent */
        pubKey->pubExp = pubExp;

        /* Convert public exponent to field element */
        for (i = 0U; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
        {
            e.words[i] = 0U;
        }
#if EscRsa_WORD_SIZE == 4U
        e.words[0U] = pubExp;
#else
        e.words[0U] = (EscRsa_HWORD)(pubExp & EscRsa_MAX_VAL);
        e.words[1U] = (EscRsa_HWORD)(pubExp >> EscRsa_RSA_BASE);
#endif

        /* Generate prime P */

        /* Get a new candidate */
        returnCode = prngFunc( prngState, candidate, (Esc_UINT32)byteSizeHalf );
        if (returnCode == Esc_NO_ERROR)
        {
            /* Set two most significant bits. We use big endian UINT8 arrays. */
            candidate[0U] |= 0xc0U;
            /* Set least significant bit */
            candidate[byteSizeHalf - 1U] |= 1U;
            /* Convert to field element */
            EscRsaFe_FromBytesBE( p, candidate, byteSizeHalf );
        }

        prime = FALSE;
        while ( (prime == FALSE) && (returnCode == Esc_NO_ERROR) )
        {
            EscRsa_GeneratePrimeCandidate( p, keySizeHalf.words );

            returnCode = EscRsa_MillerRabin( prngFunc, prngState, p, &prime, &keySizeHalf );
            if ( prime == FALSE )
            {
                EscRsaFe_AddWord( p, 2U, wordSizeHalf );
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Check if p - 1 is co-prime to e */
            EscRsaFe_Assign( &temp, p, wordSizeHalf );
            temp.words[0U] &= (EscRsa_HWORD)(~(EscRsa_HWORD)1U);
            returnCode = EscRsaFe_ModInv( &e, &temp, &temp, wordSizeHalf );

            /* Map to a different error, because this is supposed to be recoverable */
            if (returnCode != Esc_NO_ERROR)
            {
                returnCode = Esc_KEY_GENERATION_COPRIME_ERROR;
            }
        }

        /* Generate prime Q */

        dist = 0U;
        prime = FALSE;

        while ( (returnCode == Esc_NO_ERROR) && (prime == FALSE) )
        {
            if ( dist <= EscRsa_PQ_LOWER_BOUND )
            {
                /* Get a new candidate */
                returnCode = prngFunc( prngState, candidate, (Esc_UINT32)byteSizeHalf );
                if (returnCode == Esc_NO_ERROR)
                {
                    /* Set two most significant bits. We use big endian UINT8 arrays. */
                    candidate[0U] |= 0xc0U;
                    /* Set least significant bit */
                    candidate[byteSizeHalf - 1U] |= 1U;
                    /* Convert to field element */
                    EscRsaFe_FromBytesBE( q, candidate, byteSizeHalf );
                }
            }

            if (returnCode == Esc_NO_ERROR)
            {
                EscRsa_GeneratePrimeCandidate( q, keySizeHalf.words );

                /* Check if q - 1 is co-prime to e */
                EscRsaFe_Assign( &temp, q, wordSizeHalf );
                temp.words[0U] &= (EscRsa_HWORD)(~(EscRsa_HWORD)1U);
                returnCode = EscRsaFe_ModInv( &e, &temp, &temp, wordSizeHalf );

                /* Map to a different error, because this is supposed to be recoverable */
                if (returnCode != Esc_NO_ERROR)
                {
                    returnCode = Esc_KEY_GENERATION_COPRIME_ERROR;
                }
            }

            if (returnCode == Esc_NO_ERROR)
            {
                /* Check distance between p and q */
                if ( (p->words[wordSizeHalf - 1U]) < (q->words[wordSizeHalf - 1U]) )
                {
                    dist = ( (EscRsa_FWORD)q->words[wordSizeHalf - 1U] ) << (EscRsa_RSA_BASE - 1U);
                    dist /= ( (EscRsa_FWORD)p->words[wordSizeHalf - 1U] );
                }
                else
                {
                    dist = ( (EscRsa_FWORD)p->words[wordSizeHalf - 1U] ) << (EscRsa_RSA_BASE - 1U);
                    dist /= ( (EscRsa_FWORD)q->words[wordSizeHalf - 1U] );
                }

                if ( dist > EscRsa_PQ_LOWER_BOUND )
                {
                    returnCode = EscRsa_MillerRabin( prngFunc, prngState, q, &prime, &keySizeHalf );
                    if ( prime == FALSE )
                    {
                        EscRsaFe_AddWord( q, 2U, wordSizeHalf );
                    }
                }
            }
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Calculate n = p * q */
            mult.c = &multiplication_result;
            mult.x = p;
            EscRsaFe_ToLongFe( mult.c, q, wordSizeHalf );
            EscRsaFe_MultiplyClassically( &mult, wordSize );
            EscRsaFe_FromLongFe( &pubKey->modulus, mult.c, wordSize);

            /* Calculate d = e^-1 mod phi(n) */
            /* phi(n) = (p - 1) * (q - 1) = p * q - p - q + 1 = n - p - q + 1 */
            EscRsaFe_Assign( &temp, &pubKey->modulus, wordSize );
            EscRsaFe_Subtract( &temp, p, wordSize );
            EscRsaFe_Subtract( &temp, q, wordSize );
            EscRsaFe_AddWord( &temp, 1U, wordSize );

            returnCode = EscRsaFe_ModInv( &temp, &e, privExp, wordSize );
        }
    }

    return returnCode;
}


Esc_ERROR
EscRsa_KeyGeneration(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    EscRsa_PrivKeyT* privKey,
    Esc_UINT32 pubExp,
    Esc_UINT16 keySizeBits,
    Esc_BOOL generateCrtKey)
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Declare temp buffers used for the key generation */
    EscRsa_FieldElementT p, q, privExp;

    if ( ( prngFunc == Esc_NULL_PTR ) ||
         ( privKey == Esc_NULL_PTR ) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

#if EscRsa_CRT_ENABLED == 0
    if (generateCrtKey != FALSE)
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
#endif

    if (returnCode == Esc_NO_ERROR)
    {
        privKey->usesCrt = generateCrtKey;

        returnCode = EscRsa_GenerateKey(
                prngFunc,
                prngState,
                &privKey->pubKey,
                &p,
                &q,
                &privExp,
                pubExp,
                keySizeBits);
    }

    /*lint -save -esym(645,privExp,p,q) p,q, and privKey are initialized iff returnCode == Esc_NO_ERROR which is ensured for every further access */
    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT16 wordSize = EscRsa_RSA_SIZE_WORDS_FROMBITS(keySizeBits);

        if (generateCrtKey)
        {
#if EscRsa_CRT_ENABLED == 1
            returnCode = EscRsa_ComputeCrtValues(
                    &p,
                    &q,
                    &privExp,
                    privKey,
                    wordSize);
#endif
        }
        else
        {
            EscRsaFe_Assign(&privKey->privKey.privExp, &privExp, wordSize);
        }
    }
    /*lint -restore */

    return returnCode;
}
#endif /* EscRsa_GENRSA_ENABLED */

#if EscRsa_CRT_ENABLED == 1
static Esc_ERROR
EscRsa_ModExpPrivRunCrt(
    EscRsa_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_AGAIN;

    /* WARNING: This code relies on the fact that the CRT key parts are zero-extended!
     * For instance, the prime q has only half the modulus size. It is assumed that
     * the upper half in the array is zero. This is currently assured in the conversion
     * functions.
     * Furthermore, the code relies on EscRsaFe_Assign() and EscRsaFe_FromLongFe() to
     * zero-extend.
     */

    switch (ctx->state)
    {
        case EscRsa_STATE_CRT_INITIALIZED:
            EscRsa_AssignKeyStruct(ctx->privKey->pubKey.keySizeBits, &ctx->keySize);
            EscRsa_AssignKeyStruct((ctx->privKey->pubKey.keySizeBits) / 2U, &ctx->keySizeHalf);

            ctx->mult.c = &ctx->multiplication_result;

            /* mp = m mod p */
            ctx->mult.m = &ctx->privKey->privKey.crt.p;

            EscRsaFe_ToLongFe( ctx->mult.c, &ctx->inOutFe, ctx->keySize.words );
            EscRsaFe_ModularReduction( &ctx->mult, ctx->keySize.words );
            EscRsaFe_FromLongFe( &ctx->mp, ctx->mult.c, ctx->keySizeHalf.words );

            /* mp = m^dmp1 mod p */
            EscModExp_PrivInit(&ctx->modExpCtx, &ctx->privKey->privKey.crt.dmp1, ctx->keySizeHalf.bits, ctx->mult.m, &ctx->mp);
            ctx->state = EscRsa_STATE_CRT_M_POW_DMP1_P;
            break;

        case EscRsa_STATE_CRT_M_POW_DMP1_P:
            returnCode = EscModExp_PrivRun(&ctx->modExpCtx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = Esc_AGAIN;
                ctx->state = EscRsa_STATE_CRT_PREPARE_M_POW_DMP1_Q;
            }
            break;

        case EscRsa_STATE_CRT_PREPARE_M_POW_DMP1_Q:
            /* mq = m mod q */
            ctx->mult.m = &ctx->privKey->privKey.crt.q;

            EscRsaFe_ToLongFe( ctx->mult.c, &ctx->inOutFe, ctx->keySize.words );
            EscRsaFe_ModularReduction( &ctx->mult, ctx->keySize.words );
            EscRsaFe_FromLongFe( &ctx->mq, ctx->mult.c, ctx->keySizeHalf.words );

            /* mq = m^dmq1 mod q */
            EscModExp_PrivInit(&ctx->modExpCtx, &ctx->privKey->privKey.crt.dmq1, ctx->keySizeHalf.bits, ctx->mult.m, &ctx->mq);
            ctx->state = EscRsa_STATE_CRT_M_POW_DMP1_Q;
            break;

        case EscRsa_STATE_CRT_M_POW_DMP1_Q:
            returnCode = EscModExp_PrivRun(&ctx->modExpCtx);
            if (returnCode == Esc_NO_ERROR)
            {
                returnCode = Esc_AGAIN;
                ctx->state = EscRsa_STATE_CRT_COMPUTE_S;
            }
            break;

        case EscRsa_STATE_CRT_COMPUTE_S:
            /* s = (iqmp * (mp - mq) mod p) * q + mq */
            EscRsaFe_Assign( &ctx->s, &ctx->mp, ctx->keySizeHalf.words );
            if (EscRsaFe_AbsoluteCompare( &ctx->mp, &ctx->mq, ctx->keySizeHalf.words ) == -1)
            {
                /* if mp < mq, add p to mp to ensure that (mp - mq) is positive */
                EscRsaFe_Add( &ctx->s, &ctx->privKey->privKey.crt.p, ctx->keySize.words );
            }
            EscRsaFe_Subtract( &ctx->s, &ctx->mq, ctx->keySize.words );

            ctx->mult.m = &ctx->privKey->privKey.crt.p;
            ctx->mult.x = &ctx->s;
            EscRsaFe_ToLongFe( ctx->mult.c, &ctx->privKey->privKey.crt.iqmp, ctx->keySize.words );
            EscRsaFe_Multiply( &ctx->mult, ctx->keySize.words );

            ctx->state = EscRsa_STATE_CRT_FINISH;
            break;


        case EscRsa_STATE_CRT_FINISH:
            EscRsaFe_Assign(ctx->mult.x, &ctx->privKey->privKey.crt.q, ctx->keySizeHalf.words);
            EscRsaFe_MultiplyClassically( &ctx->mult, ctx->keySize.words );
            EscRsaFe_FromLongFe(&ctx->inOutFe, ctx->mult.c, ctx->keySize.words );

            EscRsaFe_Add( &ctx->inOutFe, &ctx->mq, ctx->keySize.words );
            returnCode = Esc_NO_ERROR;
            break;

        default:
            returnCode = Esc_UNEXPECTED_FUNCTION_CALL;
            break;
    }

    return returnCode;
}
#endif

#if EscRsa_GENRSA_ENABLED == 1
/*****************************************
 * shifts field element right by one bit *
 *****************************************/
static void
EscRsaFe_ShiftRight(
    EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;

    /* shift first words */
    for (i = 0U; i < (wordSize - 1U); i++)
    {
        EscRsa_HWORD v;
        v = a->words[i] >> 1;
        v |= (EscRsa_HWORD)( a->words[i + 1U] << (EscRsa_RSA_BASE - 1U) );

        a->words[i] = v;
    }

    /* shift last word */
    a->words[wordSize - 1U] >>= 1;     /* most significant word */
}

/*****************************************
 * shifts field element right by one bit *
 *****************************************/
static void
EscRsaFe_SignedShiftRight(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const Esc_UINT16 wordSize )
{
    Esc_UINT16 i;
    EscRsa_HWORD v;

    /* shift first words */
    for (i = 0U; i < (wordSize - 1U); i++)
    {
        v = a->words[i] >> 1;
        v |= (EscRsa_HWORD)( a->words[i + 1U] << (EscRsa_RSA_BASE - 1U) );
        a->words[i] = v;
    }

    /* shift last word */
    v = a->words[wordSize - 1U] >> 1;
    v |= (EscRsa_HWORD)( *aSign << (EscRsa_RSA_BASE - 1U) );
    a->words[wordSize - 1U] = v;
    v = *aSign & ( (EscRsa_HWORD)( (EscRsa_HWORD)1U << (EscRsa_RSA_BASE - 1U) ) );
    *aSign >>= 1;
    *aSign |= v;
}

/**********************************
 * checks if field element is one *
 **********************************/
static Esc_BOOL
EscRsaFe_IsOne(
    const EscRsa_FieldElementT* a,
    const Esc_UINT16 wordSize )
{
    /* declarations */
    Esc_BOOL isOne = TRUE;

    /* a[0] =? 1 */
    if (a->words[0] != 1U)
    {
        isOne = FALSE;
    }
    else
    {
        Esc_UINT16 i;
        /* for i from 1 to t-1 do a[i] =? 0 */
        for (i = 1U; i < wordSize; i++)
        {
            if (a->words[i] != 0U)
            {
                /* not one */
                isOne = FALSE;
            }
        }
    }

    return isOne;
}

/************************
 * Calculate a := a + b *
 ************************/
static void
EscRsaFe_SignedAdd(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const EscRsa_FieldElementT* b,
    const EscRsa_HWORD bSign,
    const Esc_UINT16 wordSize )
{
    EscRsa_FWORD carry = 0U;
    EscRsa_FWORD sum;
    Esc_UINT32 i;

    for (i = 0U; i < wordSize; i++)
    {
        sum = ( (EscRsa_FWORD)a->words[i] ) + ( (EscRsa_FWORD)b->words[i] ) + carry;
        carry = EscRsa_HI_FWORD( sum );
        a->words[i] = (EscRsa_HWORD)EscRsa_LO_FWORD( sum );
    }
    sum = ( (EscRsa_FWORD) * aSign ) + ( (EscRsa_FWORD)(bSign) ) + carry;
    *aSign = (EscRsa_HWORD)EscRsa_LO_FWORD( sum );
}

/************************
 * Calculate a := a - b *
 ************************/
static void
EscRsaFe_SignedSubtract(
    EscRsa_FieldElementT* a,
    EscRsa_HWORD* aSign,
    const EscRsa_FieldElementT* b,
    const EscRsa_HWORD bSign,
    const Esc_UINT16 wordSize )
{
    EscRsa_FWORD carry = 1U;
    EscRsa_FWORD diff;
    Esc_UINT32 i;

    for (i = 0U; i < wordSize; i++)
    {
        diff = ( (EscRsa_FWORD)a->words[i] ) + ( (EscRsa_FWORD)(b->words[i] ^ EscRsa_MAX_VAL) ) + carry;
        carry = EscRsa_HI_FWORD( diff );
        a->words[i] = (EscRsa_HWORD)EscRsa_LO_FWORD( diff );
    }
    diff = ( (EscRsa_FWORD) * aSign ) + ( (EscRsa_FWORD)(bSign ^ EscRsa_MAX_VAL) ) + carry;
    *aSign = (EscRsa_HWORD)EscRsa_LO_FWORD( diff );
}

/*******************************************
 * Add a 16/32 bit word to a field element *
 *******************************************/
static void
EscRsaFe_AddWord(
    EscRsa_FieldElementT* c,
    const EscRsa_HWORD a,
    const Esc_UINT16 wordSize )
{
    EscRsa_HWORD* cwords;
    Esc_UINT32 i;

    cwords = c->words;

    cwords[0U] += a;
    if (cwords[0U] < a)
    {
        for (i = 1U; i < wordSize; i++)
        {
            cwords[i] += 1U;
            if (cwords[i] >= 1U)
            {
                break;
            }
        }
    }
}

/******************************************************
 * Compute modulo of field element and a small number *
 ******************************************************/
static EscRsa_HWORD
EscRsaFe_ModWord(
    const EscRsa_FieldElementT* a,
    EscRsa_HWORD w,
    const Esc_UINT16 wordSize )
{
    EscRsa_FWORD ret = 0U;
    Esc_SINT32 i;

    for (i = (Esc_SINT32)wordSize - 1; i >= 0; i--)
    {
        ret = ( (ret << EscRsa_RSA_BASE) | (EscRsa_FWORD)a->words[i] ) % (EscRsa_FWORD)w;
    }

    return (EscRsa_HWORD)ret;
}

/******************************************************
 * Test if extended field element is positive         *
 ******************************************************/
static Esc_BOOL
EscRsaFe_IsPositive(
    EscRsa_HWORD sign,
    const EscRsa_FieldElementT* fe,
    const Esc_UINT16 wordSize)
{
    Esc_BOOL ret = FALSE;

    /* If MSB not set ... */
    if ( (sign & ( (EscRsa_HWORD) ( (EscRsa_HWORD) 1U << ( EscRsa_RSA_BASE - 1U ) ) )) == 0U)
    {
        /* .. and the entire value is non-zero ... */
        if ( (sign > 0U) || (EscRsaFe_IsZero(fe, wordSize) == FALSE) )
        {
            /* ... then it's positive */
            ret = TRUE;
        }
    }

    return ret;
}

/*********************************************
 * Modular inverse using binary extended gcd
 * HAC Alg. 14.61 (including Errata)
 *********************************************/
static Esc_ERROR
EscRsaFe_ModInv(
    const EscRsa_FieldElementT* x,
    const EscRsa_FieldElementT* y,
    EscRsa_FieldElementT* result,
    const Esc_UINT16 wordSize )
{
    EscRsa_FieldElementT u;
    EscRsa_FieldElementT v;
    EscRsa_FieldElementT a;
    EscRsa_FieldElementT b;
    EscRsa_FieldElementT c;
    EscRsa_FieldElementT d;
    Esc_UINT32 i;
    EscRsa_HWORD aSign;
    EscRsa_HWORD bSign;
    EscRsa_HWORD cSign;
    EscRsa_HWORD dSign;
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Since ModInv is called in KeyGenerate only together with the public exponent e we skip step 2 and demand an odd exponent */
    if ( ((x->words[0] & 1U) == 0U ) && ( ((y->words[0] & 1U) == 0U ) ) )
    {
        returnCode = Esc_INVALID_PARAMETER;
    }
    else
    {
        /* initialize all Field Elements */
        for (i = 0U; i < EscRsa_RSA_SIZE_WORDS_MAX; i++)
        {
            u.words[i] = x->words[i];
            v.words[i] = y->words[i];
            a.words[i] = 0U;
            b.words[i] = 0U;
            c.words[i] = 0U;
            d.words[i] = 0U;
        }
        a.words[0U] = 1U;
        d.words[0U] = 1U;
        aSign = 0U;
        bSign = 0U;
        cSign = 0U;
        dSign = 0U;

        do
        {
            while ( (u.words[0U] & 1U) == 0U )
            {
                EscRsaFe_ShiftRight( &u, wordSize );
                if ( ( (a.words[0U] & 1U) == 1U ) || ( (b.words[0U] & 1U) == 1U ) )
                {
                    EscRsaFe_SignedAdd( &a, &aSign, y, 0U, wordSize );
                    EscRsaFe_SignedSubtract( &b, &bSign, x, 0U, wordSize );
                }
                EscRsaFe_SignedShiftRight( &a, &aSign, wordSize );
                EscRsaFe_SignedShiftRight( &b, &bSign, wordSize );
            }

            while ( (v.words[0U] & 1U) == 0U )
            {
                EscRsaFe_ShiftRight( &v, wordSize );
                if ( ( (c.words[0U] & 1U) == 1U ) || ( (d.words[0U] & 1U) == 1U ) )
                {
                    EscRsaFe_SignedAdd( &c, &cSign, y, 0U, wordSize );
                    EscRsaFe_SignedSubtract( &d, &dSign, x, 0U, wordSize );
                }
                EscRsaFe_SignedShiftRight( &c, &cSign, wordSize );
                EscRsaFe_SignedShiftRight( &d, &dSign, wordSize );
            }

            if (EscRsaFe_AbsoluteCompare( &u, &v, wordSize ) > -1)
            {
                EscRsaFe_Subtract( &u, &v, wordSize );
                EscRsaFe_SignedSubtract( &a, &aSign, &c, cSign, wordSize );
                EscRsaFe_SignedSubtract( &b, &bSign, &d, dSign, wordSize );
                /* "If B>0 then A <-- A+y and B <-- B-x." */
                if ( EscRsaFe_IsPositive(bSign, &b, wordSize) != FALSE )
                {
                    EscRsaFe_SignedAdd( &a, &aSign, y, 0U, wordSize );
                    EscRsaFe_SignedSubtract( &b, &bSign, x, 0U, wordSize );
                }
            }
            else
            {
                EscRsaFe_Subtract( &v, &u, wordSize );
                EscRsaFe_SignedSubtract( &c, &cSign, &a, aSign, wordSize );
                EscRsaFe_SignedSubtract( &d, &dSign, &b, bSign, wordSize );
                /* "If D>0 then C <-- C+y and D <-- D-x." */
                if ( EscRsaFe_IsPositive(dSign, &d, wordSize) != FALSE )
                {
                    EscRsaFe_SignedAdd( &c, &cSign, y, 0U, wordSize );
                    EscRsaFe_SignedSubtract( &d, &dSign, x, 0U, wordSize );
                }
            }
        } while (EscRsaFe_IsZero( &u, wordSize ) == FALSE);

        if (EscRsaFe_IsOne( &v, wordSize ) == FALSE)
        {
            returnCode = Esc_INTERNAL_FUNCTION_ERROR;
        }

        if (dSign)
        {
            EscRsaFe_SignedAdd( &d, &dSign, x, 0U, wordSize );
        }

        EscRsaFe_Assign( result, &d, wordSize );
    }

    return returnCode;
}

/*******************************
 * Miller-Rabin primality test *
 *******************************/
static Esc_ERROR
EscRsa_MillerRabin(
    EscRandom_GetRandom prngFunc,
    void* prngState,
    const EscRsa_FieldElementT* n,
    Esc_BOOL* prime,
    const EscRsa_KeySizeT* keySizeHalf )
{
    EscRsa_FieldElementT n1;
    EscRsa_FieldElementT r;
    EscRsa_FieldElementT y;
    EscRsa_FieldElementLongT multiplication_result;
    EscRsa_MultiplyDataT mult;
    Esc_UINT8 a[EscRsa_KEY_BYTES_MAX_HALF];
    Esc_UINT32 s;
    Esc_UINT32 i;
    Esc_UINT32 j;
    Esc_ERROR returnCode = Esc_NO_ERROR;
    Esc_UINT16 byteSize = keySizeHalf->bytes;
    Esc_UINT16 wordSize = keySizeHalf->words;
    EscModExp_PrivContext modExpCtx;

    /* n1 = n - 1, requires that n is odd */
    EscRsaFe_Assign( &n1, n, wordSize );
    n1.words[0] &= (EscRsa_HWORD)(~(EscRsa_HWORD)1U);

    /* r = n */
    EscRsaFe_Assign( &r, n, wordSize );

    /* Decompose candidate n into r and s with n - 1 = 2^s * r */
    s = 0U;
    do
    {
        EscRsaFe_ShiftRight( &r, wordSize );
        s++;
    } while ( (r.words[0] & 1U) == 0U );

    *prime = TRUE;
    i = 0U;
    while ( (*prime == TRUE) && (i < EscRsa_PRIMETEST_ITER) )
    {
        do
        {
            /* Get random witness a with 2 <= a <= n - 2 */
            returnCode = prngFunc( prngState, a, (Esc_UINT32)byteSize );
            if (returnCode != Esc_NO_ERROR)
            {
                break;
            }
            EscRsaFe_FromBytesBE( &y, a, byteSize );
        } while ( (EscRsaFe_IsZero( &y, wordSize ) == TRUE) ||
                  (EscRsaFe_IsOne( &y, wordSize ) == TRUE) ||
                  (EscRsaFe_AbsoluteCompare( &y, &n1, wordSize ) != -1) );

        /* y = a^r mod n */
        if (returnCode == Esc_NO_ERROR)
        {
            EscModExp_PrivInit(&modExpCtx, &r, keySizeHalf->bits, n, &y);
            do
            {
                returnCode = EscModExp_PrivRun(&modExpCtx);
            } while (returnCode == Esc_AGAIN);
        }

        /* Quit loop if any of the above operations failed.
         * MISRA allows one break statement per loop */
        if (returnCode != Esc_NO_ERROR)
        {
            break;
        }

        /*lint -e{772} y is initialized */
        if ( (EscRsaFe_IsOne( &y, wordSize ) == FALSE) && (EscRsaFe_AbsoluteCompare( &y, &n1, wordSize ) != 0) )
        {
            EscRsaFe_ToLongFe(&multiplication_result, &y, wordSize);
            j = 1U;

            while ( (j < s) && (EscRsaFe_AbsoluteCompare( &y, &n1, wordSize ) != 0) )
            {
                /* y = y^2 mod n */
                mult.c = &multiplication_result;
                mult.m = n;
                mult.x = &y;
#if EscRsa_USE_SLIDING_WINDOW == 1
                EscRsaFe_SquareSlidingWindow( &mult, wordSize );
#else
                EscRsaFe_SquareClassically( &mult, wordSize );
#endif
                EscRsaFe_ModularReduction( &mult, wordSize );

                /* The above functions for squaring and modular reduction put the result into
                 * the EscRsa_FieldElementLongT at "mult.c" such that we need to copy it
                 * into y.
                 */
                EscRsaFe_FromLongFe( &y, &multiplication_result, wordSize );

                if (EscRsaFe_IsOne( &y, wordSize ) == TRUE)
                {
                    *prime = FALSE;
                    break;
                }
                j++;
            }

            if ( (*prime == TRUE) && (EscRsaFe_AbsoluteCompare( &y, &n1, wordSize ) != 0) )
            {
                *prime = FALSE;
            }
        }
        i++;
    }

    return returnCode;
}


/*******************************************************
 * Generate random prime candidate with size of "keySizeHalf" *
 *******************************************************/
static void
EscRsa_GeneratePrimeCandidate(
    EscRsa_FieldElementT* n,
    Esc_UINT16 numKeyWordsHalf )
{
    static const Esc_UINT8 primes[EscRsa_NUM_PRIMES] =
    {
        3U,   5U,   7U,  11U,  13U,  17U,  19U,  23U,  29U,  31U,  37U,  41U,  43U,  47U,  53U,  59U,
        61U,  67U,  71U,  73U,  79U,  83U,  89U,  97U, 101U, 103U, 107U, 109U, 113U, 127U, 131U, 137U,
        139U, 149U, 151U, 157U, 163U, 167U, 173U, 179U, 181U, 191U, 193U, 197U, 199U, 211U, 223U, 227U,
        229U, 233U, 239U, 241U, 251U
    };

    Esc_UINT8 mods[EscRsa_NUM_PRIMES];
    EscRsa_HWORD delta;
    Esc_UINT32 i;
    Esc_BOOL prime = FALSE;

    /* This loop continues until it finds a candidate which is not a multiple of a low prime number.
     * This is a quick check to sort out composite numbers before calling the computationally intensive
     * Miller-Rabin test.
     */
    while (prime == FALSE)
    {
        /* Calculate candidate modulo prime number for all given small primes */
        for (i = 0U; i < EscRsa_NUM_PRIMES; i++)
        {
            mods[i] = (Esc_UINT8)EscRsaFe_ModWord( n, (EscRsa_HWORD)primes[i], numKeyWordsHalf );
        }

        /* Check if the candidate is divisble by any of the small primes. If not, increase candidate by 2. */
        delta = 0U;
        while ( (prime == FALSE) && ( delta < (EscRsa_MAX_VAL - primes[EscRsa_NUM_PRIMES - 1U]) ) )
        {
            prime = TRUE;
            for (i = 0U; i < EscRsa_NUM_PRIMES; i++)
            {
                if ( ( ( (EscRsa_HWORD)mods[i] + delta ) % (EscRsa_HWORD)primes[i] ) <= 1U )
                {
                    prime = FALSE;
                    delta += 2U;
                    break;
                }
            }
        }

        /* Add delta to candidate */
        EscRsaFe_AddWord( n, delta, numKeyWordsHalf );
    }
}
#endif /* EscRsa_GENRSA_ENABLED */

Esc_ERROR
EscRsa_ModExpPubInit(
    EscRsa_PubContext *ctx,
    const EscRsa_PubKeyT *pubKey,
    const Esc_UINT8 input[],
    Esc_UINT8 result[])
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Parameter checks */

    if ( (ctx == Esc_NULL_PTR) ||
         (pubKey == Esc_NULL_PTR) ||
         (input == Esc_NULL_PTR) ||
         (result == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscRsa_CheckPublicKey(pubKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        Esc_UINT16 bytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        Esc_UINT16 words = EscRsa_RSA_SIZE_WORDS_FROMBITS(pubKey->keySizeBits);

        ctx->keySizeBytes = bytes;
        ctx->result = result;

        /* Convert base to field element and check if it is less than the modulus */
        EscRsaFe_FromBytesBE( &ctx->inOutFe, input, bytes );
        if (EscRsaFe_AbsoluteCompare( &ctx->inOutFe, &pubKey->modulus, words ) != -1 )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        EscModExp_PubInit(&ctx->modExpCtx, pubKey->pubExp, pubKey->keySizeBits, &pubKey->modulus, &ctx->inOutFe);
    }

    return returnCode;
}

Esc_ERROR
EscRsa_ModExpPubRun(
    EscRsa_PubContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        returnCode = EscModExp_PubRun(&ctx->modExpCtx);
        if (returnCode == Esc_NO_ERROR)
        {
            /* Computation finished, convert result to byte array */
            EscRsaFe_ToBytesBE( ctx->result, &ctx->inOutFe, ctx->keySizeBytes );
        }
    }

    return returnCode;
}

Esc_ERROR
EscRsa_ModExpPrivInit(
    EscRsa_PrivContext *ctx,
    const EscRsa_PrivKeyT *privKey,
    const Esc_UINT8 input[],
    Esc_UINT8 result[])
{
    Esc_ERROR returnCode = Esc_NO_ERROR;

    /* Parameter checks */

    if ( (ctx == Esc_NULL_PTR) ||
         (privKey == Esc_NULL_PTR) ||
         (input == Esc_NULL_PTR) ||
         (result == Esc_NULL_PTR) )
    {
        returnCode = Esc_NULL_POINTER_ERROR;
    }

    if (returnCode == Esc_NO_ERROR)
    {
        returnCode = EscRsa_CheckPrivateKey(privKey);
    }

    if (returnCode == Esc_NO_ERROR)
    {
        const EscRsa_PubKeyT *pubKey = &privKey->pubKey;

        Esc_UINT16 bytes = EscRsa_KEY_BYTES_FROMBITS(pubKey->keySizeBits);
        Esc_UINT16 words = EscRsa_RSA_SIZE_WORDS_FROMBITS(pubKey->keySizeBits);

        ctx->keySizeBytes = bytes;
        ctx->usesCrt = privKey->usesCrt;
        ctx->result = result;

        /* Convert base to field element and check if it is less than the modulus */
        EscRsaFe_FromBytesBE( &ctx->inOutFe, input, bytes );
        if (EscRsaFe_AbsoluteCompare( &ctx->inOutFe, &pubKey->modulus, words ) != -1 )
        {
            returnCode = Esc_INVALID_PARAMETER;
        }
    }

    if (returnCode == Esc_NO_ERROR)
    {
        if (privKey->usesCrt)
        {
#if EscRsa_CRT_ENABLED == 1
            ctx->state = EscRsa_STATE_CRT_INITIALIZED;
            ctx->privKey = privKey;
#endif
        }
        else
        {
            EscModExp_PrivInit(
                &ctx->modExpCtx,
                &privKey->privKey.privExp,
                privKey->pubKey.keySizeBits,
                &privKey->pubKey.modulus,
                &ctx->inOutFe);
        }
    }

    return returnCode;
}

Esc_ERROR
EscRsa_ModExpPrivRun(
    EscRsa_PrivContext *ctx)
{
    Esc_ERROR returnCode = Esc_NULL_POINTER_ERROR;

    if (ctx != Esc_NULL_PTR)
    {
        if (ctx->usesCrt)
        {
#if EscRsa_CRT_ENABLED == 1
            returnCode = EscRsa_ModExpPrivRunCrt(ctx);
#endif
        }
        else
        {
            returnCode = EscModExp_PrivRun(&ctx->modExpCtx);
        }

        if (returnCode == Esc_NO_ERROR)
        {
            /* Computation finished, convert result to byte array */
            EscRsaFe_ToBytesBE( ctx->result, &ctx->inOutFe, ctx->keySizeBytes );
        }
    }

    return returnCode;
}

/***************************************************************************
 * 6. END                                                                  *
 ***************************************************************************/
