#include <stdio.h>
#include <string.h>
#include "aes-gcm-stream-crypt.h"

int aes_gcm_crypt_init(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *key, size_t key_len)
{
    crypt->err = -EscAesGcm_Init(&crypt->ctx, key_len * 8, key);
    return crypt->err;
}

int aes_gcm_crypt_start(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *iv, size_t iv_len
        , const uint8_t *A, size_t aad_len
        , wr_chunk_cb wr_cb, void *wr_cb_data)
{
    crypt->wr_cb = wr_cb;
    crypt->wr_cb_data = wr_cb_data;
    if (!crypt->err)
        crypt->err = -EscAesGcm_startEncryptDecrypt(&crypt->ctx, iv, iv_len);
    if (!crypt->err)
        crypt->err = -EscAesGcm_AssociatedData_Update(&crypt->ctx, A, aad_len);
    return crypt->err;
}

int aes_gcm_crypt_encrypt(aes_gcm_stream_crypt_t *crypt
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
            crypt->err = crypt->wr_cb(crypt->chunk, len, crypt->wr_cb_data);
        offs += len;
    }
    return crypt->err;
}

int aes_gcm_crypt_finish_encrypt(aes_gcm_stream_crypt_t *crypt
        , uint8_t *tag_buf, size_t tag_buf_sz)
{
    if (!crypt->err)
        crypt->err = -EscAesGcm_Encrypt_Finish(&crypt->ctx, tag_buf, tag_buf_sz);
    return crypt->err;
}

int aes_gcm_crypt_decrypt_putchar(aes_gcm_stream_crypt_t *crypt
        , uint8_t c)
{
    (void)crypt;
    (void)c;
    return 0;
}

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
