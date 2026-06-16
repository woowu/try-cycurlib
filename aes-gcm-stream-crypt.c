/** \copyright                (C) Copyright Landis + Gyr, 2026-2027
 * This source code and any compilation or derivative thereof is protected by intellectual
 * property rights (in particular copyright) and is the proprietary information of Landis+Gyr
 * and is confidential in nature.
 * Under no circumstances shall the content be copied, disseminated, amended or made accessible
 * (in whole or in part) to third parties nor used in any other way without the prior written
 * consent of Landis+Gyr.
 */

#include <string.h>
#include "aes-gcm-stream-crypt.h"

static void aes_gcm_crypt_decrypt_chunk(aes_gcm_crypt_t *crypt
        , size_t n)
{
    uint8_t plain_chunk[AES_GCM_CHUNK_SZ];

    if (!crypt->err)
        crypt->err = -EscAesGcm_Decrypt_Update(&crypt->ctx, plain_chunk
                , crypt->chunk, n);
    if (!crypt->err && crypt->wr_cb)
        crypt->err = crypt->wr_cb(plain_chunk, n, crypt->wr_cb_data)
            ? -100 : 0;
}

/*----------------------------------------------------------------------------*/

int aes_gcm_crypt_init(aes_gcm_crypt_t *crypt
        , const uint8_t *key, size_t key_len)
{
    memset(crypt, 0, sizeof(*crypt));
    crypt->key = key;
    crypt->key_len = key_len;
    return 0;
}

int aes_gcm_crypt_start(aes_gcm_crypt_t *crypt
        , const uint8_t *iv, size_t iv_len
        , const uint8_t *A, size_t aad_len
        , wr_chunk_cb wr_cb, void *wr_cb_data)
{
    crypt->wr_cb = wr_cb;
    crypt->wr_cb_data = wr_cb_data;
    crypt->n_chars = 0;
    memset(crypt->chunk, 0, sizeof(crypt->chunk));

    crypt->err = -EscAesGcm_Init(&crypt->ctx, crypt->key_len * 8, crypt->key);
    if (!crypt->err)
        crypt->err = -EscAesGcm_startEncryptDecrypt(&crypt->ctx, iv, iv_len);
    if (!crypt->err)
        crypt->err = -EscAesGcm_AssociatedData_Update(&crypt->ctx, A, aad_len);
    return crypt->err;
}

int aes_gcm_crypt_encrypt(aes_gcm_crypt_t *crypt
        , const uint8_t *data, size_t data_len)
{
    size_t offs;

    if (crypt->err) return crypt->err;

    offs = 0;
    while (!crypt->err && offs < data_len) {
        size_t len;

        len = data_len - offs < AES_GCM_CHUNK_SZ
            ? data_len - offs : AES_GCM_CHUNK_SZ;
        crypt->err = -EscAesGcm_Encrypt_Update(&crypt->ctx, data + offs
                , crypt->chunk, len);
        if (!crypt->err && crypt->wr_cb)
            crypt->err = crypt->wr_cb(crypt->chunk, len, crypt->wr_cb_data)
                ? -100 : 0;
        offs += len;
    }
    return crypt->err;
}

int aes_gcm_crypt_finish_encrypt(aes_gcm_crypt_t *crypt
        , uint8_t *T, size_t tag_len)
{
    if (!crypt->err)
        crypt->err = -EscAesGcm_Encrypt_Finish(&crypt->ctx, T, tag_len);
    return crypt->err;
}

int aes_gcm_crypt_decrypt_putchar(aes_gcm_crypt_t *crypt
        , uint8_t c)
{
    if (crypt->err) return crypt->err;
    crypt->chunk[crypt->n_chars++] = c;
    if (crypt->n_chars < sizeof(crypt->chunk)) return 0;

    crypt->n_chars = 0;
    if (!crypt->err)
        aes_gcm_crypt_decrypt_chunk(crypt, sizeof(crypt->chunk));
    return crypt->err;
}

int aes_gcm_crypt_finish_decrypt(aes_gcm_crypt_t *crypt
        , const uint8_t *T, size_t tag_len)
{
    if (crypt->err) return crypt->err;
    if (crypt->n_chars)
        aes_gcm_crypt_decrypt_chunk(crypt, crypt->n_chars);
    if (!crypt->err) {
        crypt->n_chars = 0;
        crypt->err = -EscAesGcm_Decrypt_Finish(&crypt->ctx, T, tag_len);
    }
    return crypt->err;
}

/*----------------------------------------------------------------------------*/

size_t aes_gcm_init_message(uint8_t *msg, const uint8_t *iv, size_t iv_len)
{
    memcpy(msg, iv, iv_len);
    return iv_len;
}

size_t aes_gcm_finalize_message(uint8_t *msg
        , const uint8_t *T, size_t tag_len)
{
    memcpy(msg, T, tag_len);
    return tag_len;
}
