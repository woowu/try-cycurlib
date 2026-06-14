#ifndef __AES_GCM_STREAM_CRYPT_HPP
#define __AES_GCM_STREAM_CRYPT_HPP
#include <stdint.h>
#include <stddef.h>
#include <aes_gcm.h>

/* Wrap aes_gcm API to make it easier to be used in sending and receiving
 * messages in a stream fashion.
 */

#define AES_GCM_CHUNK_SZ 16

/* Callback for writing a encrypted or decrypted chunk.
 */
typedef int (* wr_chunk_cb)(const uint8_t *chunk, size_t len, void *cb_data);

typedef struct {
    EscAesGcm_ContextT ctx;
    uint8_t chunk[AES_GCM_CHUNK_SZ];
    wr_chunk_cb wr_cb;
    void * wr_cb_data;
    int err;

    /* Only for decryption
     */
    size_t n_chars;
} aes_gcm_stream_crypt_t;

#ifdef __cplusplus
extern "C" {
#endif

int aes_gcm_crypt_init(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *key, size_t key_len);
int aes_gcm_crypt_start(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *iv, size_t iv_len
        , const uint8_t *A, size_t aad_len
        , wr_chunk_cb wr_cb, void *wr_cb_data);

/**
 * Encrypt data by sending split chunks to the cipher. Each
 * decrypted chunk is sent to the wr_cb.
 */
int aes_gcm_crypt_encrypt(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *data, size_t data_len);

int aes_gcm_crypt_finish_encrypt(aes_gcm_stream_crypt_t *crypt
        , uint8_t *T, size_t tag_len);

/**
 * Send one byte from the encrypted data stream to the stream decryption
 * function. It, internally, may call the wr_cb to give decrypted chunk if
 * the size of accumulated cipher reaches the chunk size.
 */
int aes_gcm_crypt_decrypt_putchar(aes_gcm_stream_crypt_t *crypt
        , uint8_t c);

int aes_gcm_crypt_finish_decrypt(aes_gcm_stream_crypt_t *crypt
        , const uint8_t *T, size_t tag_len);

/**
 * Add IV as the header of an aes-gcm message.
 */
size_t aes_gcm_init_message(uint8_t *msg, const uint8_t *iv, size_t iv_len);

/**
 * Append T as auth-tag in the end of an aes-gcm message.
 */
size_t aes_gcm_finalize_message(uint8_t *msg
        , const uint8_t *T, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* __AES_GCM_STREAM_CRYPT_HPP */
