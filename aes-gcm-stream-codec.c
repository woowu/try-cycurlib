#include <stdio.h>
#include <string.h>
#include "aes_gcm.h"
#include "test_aes_gcm.h"

extern size_t memdump(unsigned char *buf, size_t size, const void *data, size_t len);

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
static unsigned char hexstr[sizeof(cipher)*4];

int main()
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
    fprintf(stdout, "Encryption err=%d\n", err);
    memdump(hexstr, sizeof(hexstr), cipher, sizeof(cipher));
    fprintf(stdout, "cipher (%zu):\n%s\n", sizeof(cipher), hexstr);
    memdump(hexstr, sizeof(hexstr), T, sizeof(T));
    fprintf(stdout, "T (%zu):\n%s\n", sizeof(T), hexstr);

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
        fprintf(stderr, "Decryption erro: %d\n", err);
        return 0;
    }
    if (memcmp(test_data, decrypted, sizeof(test_data))) {
        fprintf(stderr, "Decrypted data not same with original plaintext!\n");
        return 0;
    }
    fprintf(stdout, "Decryption is correct.\n");

    return 0;
}
