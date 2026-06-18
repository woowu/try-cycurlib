#include <stdio.h>
#include <string.h>
#include <aes_gcm.h>
#include <test_aes_gcm.h>
#include "aes-gcm-stream-crypt.h"

extern size_t memdump(unsigned char *buf, size_t size, const void *data, size_t len);

typedef struct {
    uint8_t buf[4096];
    size_t len;
} message_t;

static const uint8_t test_data[] = {
    0xd9U, 0x31U, 0x32U, 0x25U, 0xf8U, 0x84U, 0x06U, 0xe5U,
    0xa5U, 0x59U, 0x09U, 0xc5U, 0xafU, 0xf5U, 0x26U, 0x9aU,
    0x86U, 0xa7U, 0xa9U, 0x53U, 0x15U, 0x34U, 0xf7U, 0xdaU,
    0x2eU, 0x4cU, 0x30U, 0x3dU, 0x8aU, 0x31U, 0x8aU, 0x72U,
    0x1cU, 0x3cU, 0x0cU, 0x95U, 0x95U, 0x68U, 0x09U, 0x53U,
    0x2fU, 0xcfU, 0x0eU, 0x24U, 0x49U, 0xa6U, 0xb5U, 0x25U,
    0xb1U, 0x6aU, 0xedU, 0xf5U, 0xaaU, 0x0dU, 0xe6U, 0x57U,
    0xbaU, 0x63U, 0x7bU, 0x39U,
};
static const uint8_t key[] = {
    0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
    0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U,
    0xfeU, 0xffU, 0xe9U, 0x92U, 0x86U, 0x65U, 0x73U, 0x1cU,
    0x6dU, 0x6aU, 0x8fU, 0x94U, 0x67U, 0x30U, 0x83U, 0x08U,
};
static const uint8_t iv[] = {
    0x93U, 0x13U, 0x22U, 0x5dU, 0xf8U, 0x84U, 0x06U, 0xe5U,
    0x55U, 0x90U, 0x9cU, 0x5aU, 0xffU, 0x52U, 0x69U, 0xaaU,
};
static const uint8_t A[] = {
    0x00U, 0x03U, 0xfaU, 0xceU, 0xdeU, 0xadU, 0xbeU, 0xefU,
    0xfeU, 0xedU,
};

static uint8_t cipher[sizeof(test_data)];
static uint8_t T[12];
static uint8_t decrypted[sizeof(test_data)];

static message_t encrypted_msg;
static message_t decrypted_msg;

static unsigned char hexstr[sizeof(cipher)*4];

static int one_shot_encrypt()
{
    int err;

    err = EscAesGcm_Encrypt(
            sizeof(key) * 8,
            key,
            iv,
            sizeof(iv),
            A,
            sizeof(A),
            test_data,
            sizeof(test_data),
            cipher,
            T,
            sizeof(T));
    if (err) {
        fprintf(stderr, "One-shot encryption failed: %d\n", err);
        return -1;
    }
    memdump(hexstr, sizeof(hexstr), cipher, sizeof(cipher));
    fprintf(stdout, "cipher (%zu):\n%s\n", sizeof(cipher), hexstr);
    memdump(hexstr, sizeof(hexstr), T, sizeof(T));
    fprintf(stdout, "T (%zu):\n%s\n", sizeof(T), hexstr);
    fprintf(stdout, "One-shot encryption correct.\n");
    return 0;
}

static int one_shot_decrypt()
{
    int err;

    err = EscAesGcm_Decrypt(
            sizeof(key) * 8,
            key,
            iv,
            sizeof(iv),
            A,
            sizeof(A),
            cipher,
            sizeof(cipher),
            decrypted,
            T,
            sizeof(T));
    if (err) {
        fprintf(stderr, "One-shot decryption failed: %d\n", err);
        return -1;
    }
    if (memcmp(test_data, decrypted, sizeof(test_data))) {
        fprintf(stderr, "One-shot decryption plaintext mismatched!\n");
        return -1;
    }
    fprintf(stdout, "One-shot decryption correct.\n");
    return 0;
}

static int stream_encrypt()
{
    static const size_t chunk_size = 16;
    uint8_t stream_cipher[sizeof(test_data)];
    uint8_t stream_T[12];
    EscAesGcm_ContextT ctx;
    size_t offs;
    int err;

    err = EscAesGcm_Init(&ctx, sizeof(key) * 8, key);
    if (!err)
        err = EscAesGcm_startEncryptDecrypt(&ctx, iv, sizeof(iv));
    if (!err)
        err = EscAesGcm_AssociatedData_Update(&ctx, A, sizeof(A));
    offs = 0;
    while (!err && offs < sizeof(test_data)) {
        size_t len;

        len = sizeof(test_data) - offs < chunk_size
            ? sizeof(test_data) - offs : chunk_size;
        err = EscAesGcm_Encrypt_Update(&ctx, test_data + offs
                , stream_cipher + offs, len);
        offs += len;
    }
    if (!err)
        err = EscAesGcm_Encrypt_Finish(&ctx, stream_T, sizeof(stream_T));
    if (err) {
        fprintf(stderr, "Stream encryption failed: %d\n", err);
        return -1;
    }
    if (memcmp(stream_cipher, cipher, sizeof(cipher))) {
        fprintf(stderr, "stream encryption cipher mismatched\n");
        return -1;
    }
    if (memcmp(stream_T, T, sizeof(T))) {
        fprintf(stderr, "stream encryption T mismatched\n");
        return -1;
    }
    fprintf(stdout, "Stream encryption correct.\n");
    return 0;
}

static int stream_decrypt()
{
    static const size_t chunk_size = 16;
    uint8_t stream_plaintext[sizeof(test_data)];
    EscAesGcm_ContextT ctx;
    size_t offs;
    int err;

    err = EscAesGcm_Init(&ctx, sizeof(key) * 8, key);
    if (!err)
        err = EscAesGcm_startEncryptDecrypt(&ctx, iv, sizeof(iv));
    if (!err)
        err = EscAesGcm_AssociatedData_Update(&ctx, A, sizeof(A));
    offs = 0;
    while (!err && offs < sizeof(test_data)) {
        size_t len;

        len = sizeof(test_data) - offs < chunk_size
            ? sizeof(test_data) - offs : chunk_size;
        err = EscAesGcm_Decrypt_Update(&ctx, stream_plaintext + offs
                , cipher + offs, len);
        offs += len;
    }
    if (!err)
        err = EscAesGcm_Decrypt_Finish(&ctx, T, sizeof(T));
    if (err) {
        fprintf(stderr, "Stream decryption failed: %d\n", err);
        return -1;
    }
    if (memcmp(stream_plaintext, test_data, sizeof(test_data))) {
        fprintf(stderr, "Stream decryption plaintext mismatched!\n");
        return -1;
    }
    fprintf(stdout, "Stream decryption correct.\n");
    return 0;
}

static int wr_message(const uint8_t *chunk, size_t len, size_t offs
        , const uint8_t *source_data, void *cb_data)
{
    (void)offs;
    (void)source_data;

    message_t *message = (message_t*)cb_data;
    if (message->len + len > sizeof(message->buf)) {
        fprintf(stderr, "Message size overflow\n");
        return -1;
    }
    memcpy(message->buf + message->len, chunk, len);
    message->len += len;
    return 0;
}

static void print_message(const message_t *message)
{
    memdump(hexstr, sizeof(hexstr), message->buf, message->len);
    fprintf(stdout, "Message len %zu\n", message->len);
    fprintf(stdout, "%s\n", hexstr);
}

static int test_stream_crypt_enc()
{
    aes_gcm_crypt_t crypt; 
    int err;
    uint8_t tag_buf[12];

    err = aes_gcm_crypt_init(&crypt
            , key, sizeof(key));
    if (!err)
        err = aes_gcm_crypt_start(&crypt, iv, sizeof(iv), A, sizeof(A)
                , wr_message, &encrypted_msg);
    if (err) return -1;

    encrypted_msg.len = aes_gcm_init_message(encrypted_msg.buf, iv, sizeof(iv));
    err = aes_gcm_crypt_encrypt(&crypt
            , test_data, sizeof(test_data));
    if (err) {
        fprintf(stderr, "aes_gcm_crypt_encrypt error: %d\n", err);
        return -1;
    }
    err = aes_gcm_crypt_finish_encrypt(&crypt
        , tag_buf, sizeof(tag_buf));
    if (err) {
        fprintf(stderr, "aes_gcm_crypt_finish_encrypt error: %d\n", err);
        return -1;
    }
    encrypted_msg.len += aes_gcm_finalize_message(encrypted_msg.buf + encrypted_msg.len
            , tag_buf, sizeof(tag_buf));

    fprintf(stdout, "Encrypted message:\n");
    print_message(&encrypted_msg);
    if (encrypted_msg.len != sizeof(iv) + sizeof(test_data) + sizeof(T)) {
        fprintf(stderr, "Message length incorrect!\n");
        return -1;
    }
    if (memcmp(encrypted_msg.buf, iv, sizeof(iv))) {
        fprintf(stderr, "Message header incorrect!\n");
        return -1;
    }
    if (memcmp(encrypted_msg.buf + sizeof(iv), cipher, sizeof(test_data))) {
        fprintf(stderr, "Message payload incorrect!\n");
        return -1;
    }
    if (memcmp(encrypted_msg.buf + sizeof(iv) + sizeof(test_data)
                , T, sizeof(T))) {
        fprintf(stderr, "Message auth-tagincorrect!\n");
        return -1;
    }
    fprintf(stdout, "Message is correct\n");
    return err;
}

static int test_stream_crypt_dec()
{
    aes_gcm_crypt_t crypt; 
    int err;
    size_t payload_len;

    memset(&decrypted_msg, 0, sizeof(decrypted_msg));
    payload_len = encrypted_msg.len - sizeof(iv) - sizeof(T);

    err = aes_gcm_crypt_init(&crypt, key, sizeof(key));
    if (!err)
        err = aes_gcm_crypt_start(&crypt
                , encrypted_msg.buf, sizeof(iv) , A, sizeof(A)
                , wr_message, &decrypted_msg);
    if (err) return -1;

    for (size_t i = 0; i < payload_len; ++i)
        aes_gcm_crypt_decrypt_putchar(&crypt, encrypted_msg.buf[sizeof(iv) + i]);
    err = aes_gcm_crypt_finish_decrypt(&crypt, T, sizeof(T));
    if (err)
        fprintf(stderr, "test_stream_crypt_dec() failed\n");
    fprintf(stdout, "Decrypted message:\n");
    print_message(&decrypted_msg);
    if (err)
        fprintf(stderr, "Message decrypting error!\n");
    else if (memcmp(decrypted_msg.buf, test_data, sizeof(test_data)))
        fprintf(stderr, "Contents of decrypted message mismatched!\n");
    return err;
}

int main()
{
    if (one_shot_encrypt()) return -1;
    if (one_shot_decrypt()) return -1;
    if (stream_encrypt()) return -1;
    if (stream_decrypt()) return -1;

    /* Use aes_gcm_stream_crypt
     */

    if (test_stream_crypt_enc()) return -1;
    if (test_stream_crypt_dec()) return -1;

    fprintf(stdout, "All tests passed\n");
    return 0;
}
