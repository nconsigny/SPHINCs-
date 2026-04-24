/*
 * Deterministic randombytes — replaces the upstream /dev/urandom version so
 * tests/fixtures are reproducible.
 *
 * set_rng_buffer() loads up to 64 bytes; subsequent randombytes() calls
 * consume from that buffer.  After the buffer is exhausted, zeros are
 * returned (never happens in our code path — crypto_sign_signature only
 * draws SPX_N=16 bytes for optrand, and crypto_sign_keypair is unused).
 */

#include <string.h>
#include "randombytes.h"

#define RNG_CAP 64
static unsigned char rng_buf[RNG_CAP];
static unsigned long long rng_len = 0;
static unsigned long long rng_off = 0;

void set_rng_buffer(const unsigned char *buf, unsigned long long len)
{
    if (len > RNG_CAP) len = RNG_CAP;
    memcpy(rng_buf, buf, (size_t)len);
    rng_len = len;
    rng_off = 0;
}

void randombytes(unsigned char *x, unsigned long long xlen)
{
    while (xlen-- > 0) {
        if (rng_off < rng_len) {
            *x++ = rng_buf[rng_off++];
        } else {
            *x++ = 0;
        }
    }
}
