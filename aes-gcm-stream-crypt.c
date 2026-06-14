#include <aes_gcm.h>
#include <stdio.h>
#include "aes-gcm-stream-crypt.h"

int aes_gcm_cryt_init(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *key, size_t key_len)
{
    crypt->key = key;
    crypt->key_len = key_len;
    return 0;
}

int aes_gcm_cryt_enc_data(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *iv, size_t iv_len
        , const uint8_t *A, size_t aad_len
        , uint8_t *chunk_buf, size_t chunk_buf_sz
        , uint8_t *tag_buf, size_t tag_buf_sz
        , const uint8_t *data, size_t data_len
        , wr_chunk_cb wr_cb, void *wr_cb_data)
{
    EscAesGcm_ContextT ctx;
    size_t offs;
    int err;

    err = EscAesGcm_Init(&ctx, crypt->key_len * 8, crypt->key);
    if (!err)
        err = EscAesGcm_startEncryptDecrypt(&ctx, iv, iv_len);
    if (!err)
        err = EscAesGcm_AssociatedData_Update(&ctx, A, aad_len);

    offs = 0;
    while (!err && offs < sizeof(data_len)) {
        size_t len;

        len = data_len - offs < chunk_buf_sz
            ? data_len - offs : chunk_buf_sz;
        err = EscAesGcm_Encrypt_Update(&ctx, data + offs
                , chunk_buf, len);
        offs += len;
    }
    if (!err)
        err = EscAesGcm_Encrypt_Update(&ctx, Esc_NULL_PTR, Esc_NULL_PTR, 0U);
    if (!err)
        err = EscAesGcm_Encrypt_Finish(&ctx, tag_buf, tag_buf_sz);
    (void)wr_cb;
    (void)wr_cb_data;
    return err;
}
