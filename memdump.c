#include <stdio.h>

size_t memdump(unsigned char *buf, size_t size, const void *data, size_t len)
{
    static const size_t BYTES_PER_LINE = 16; 
    static const size_t BYTES_PER_GROUP = 2;

    const unsigned char *s = (const unsigned char *)data;
    char *d = (char *)buf;
    size_t nprint = 0;

    size_t i;
    for (i = 0; i < len && nprint < size - 1; ++i) {
        if (i && ! (i % BYTES_PER_LINE)) {
            sprintf(d, "\n");
            ++d;
            ++nprint;
        } else if (i && ! (i % BYTES_PER_GROUP)) {
            sprintf(d, " ");
            ++d;
            ++nprint;
        }
        sprintf(d, "%02x", *s++);
        d += 2;
        nprint += 2;
    }   
    if (nprint < size) *d++ = '\0';
    return i;
}
