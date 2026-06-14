#ifndef __AES_GCM_STREAM_CRYPT_HPP
#define __AES_GCM_STREAM_CRYPT_HPP
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *A;
    size_t aad_len;
    size_t tag_len;
    uint8_t *enc_dec_buf;
    size_t enc_dec_buf_sz;
    uint8_t *T;
    size_t tag_sz;
} aes_gcm_stream_crypt_t;


#ifdef __cplusplus
extern "C" {
#endif

typedef int (* wr_chunk_cb)(const uint8_t *chunk, size_t len, void *cb_data);

int aes_gcm_cryt_init(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *key, size_t key_len);

/**
 * Encrypt data in one-shot by doing it chunk by chunk.
 * Pass the cipher chunk to the cb before encrypt the next chunk.
 * Finally, write T to the tag_buf.
 */
int aes_gcm_cryt_enc_data(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *iv, size_t iv_len
        , const uint8_t *A, size_t aad_len
        , uint8_t *chunk_buf, size_t chunk_buf_sz
        , uint8_t *tag_buf, size_t tag_buf_sz
        , const uint8_t *data, size_t data_len
        , wr_chunk_cb wr_cb, void *wr_cb_data);

size_t aes_gcm_init_message(uint8_t *msg, const uint8_t *iv, size_t iv_len);
size_t aes_gcm_finalize_message(uint8_t *msg
        , const uint8_t *T, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* __AES_GCM_STREAM_CRYPT_HPP */
