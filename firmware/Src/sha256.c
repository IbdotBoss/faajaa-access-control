/**
 * @file    sha256.c
 * @brief   Minimal SHA-256 and HMAC-SHA256 implementation.
 *
 * FIPS 180-4 compliant SHA-256.  No dynamic allocation.
 * Suitable for bare-metal / RTOS embedded targets.
 */
#include "sha256.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  SHA-256 constants (first 32 bits of fractional parts of cube       */
/*  roots of the first 64 primes)                                      */
/* ------------------------------------------------------------------ */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* ------------------------------------------------------------------ */
/*  Bit manipulation helpers                                           */
/* ------------------------------------------------------------------ */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)       (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x)      (ROTR(x, 7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

/* ------------------------------------------------------------------ */
/*  Process one 64-byte block                                          */
/* ------------------------------------------------------------------ */
static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;

    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4    ] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] <<  8)
             | ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /* Working variables */
    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    /* Compression */
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

void sha256_init(sha256_ctx *ctx)
{
    ctx->bitcount = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buffered = (size_t)((ctx->bitcount >> 3) % SHA256_BLOCK_SIZE);

    ctx->bitcount += (uint64_t)len << 3;

    /* If we have buffered data, try to complete a block */
    if (buffered > 0) {
        size_t need = SHA256_BLOCK_SIZE - buffered;
        if (len >= need) {
            memcpy(ctx->buffer + buffered, data, need);
            sha256_transform(ctx, ctx->buffer);
            data += need;
            len  -= need;
        } else {
            memcpy(ctx->buffer + buffered, data, len);
            return;
        }
    }

    /* Process full blocks directly from input */
    while (len >= SHA256_BLOCK_SIZE) {
        sha256_transform(ctx, data);
        data += SHA256_BLOCK_SIZE;
        len  -= SHA256_BLOCK_SIZE;
    }

    /* Buffer remainder */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    size_t buffered = (size_t)((ctx->bitcount >> 3) % SHA256_BLOCK_SIZE);

    /* Append 0x80 */
    ctx->buffer[buffered++] = 0x80;

    /* If not enough room for 8-byte length, pad and process */
    if (buffered > 56) {
        memset(ctx->buffer + buffered, 0, SHA256_BLOCK_SIZE - buffered);
        sha256_transform(ctx, ctx->buffer);
        buffered = 0;
    }

    /* Pad to 56 bytes */
    memset(ctx->buffer + buffered, 0, 56 - buffered);

    /* Append bit length (big-endian 64-bit) */
    uint64_t bits = ctx->bitcount;
    ctx->buffer[56] = (uint8_t)(bits >> 56);
    ctx->buffer[57] = (uint8_t)(bits >> 48);
    ctx->buffer[58] = (uint8_t)(bits >> 40);
    ctx->buffer[59] = (uint8_t)(bits >> 32);
    ctx->buffer[60] = (uint8_t)(bits >> 24);
    ctx->buffer[61] = (uint8_t)(bits >> 16);
    ctx->buffer[62] = (uint8_t)(bits >>  8);
    ctx->buffer[63] = (uint8_t)(bits);

    sha256_transform(ctx, ctx->buffer);

    /* Output digest (big-endian) */
    for (int i = 0; i < 8; i++) {
        digest[i * 4    ] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/*  HMAC-SHA256  (RFC 2104)                                            */
/* ------------------------------------------------------------------ */

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t key_hash[SHA256_DIGEST_SIZE];

    /* If key > block size, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_hash);
        key = key_hash;
        key_len = SHA256_DIGEST_SIZE;
    }

    /* Inner pad: key XOR 0x36 */
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }

    /* inner = SHA256(k_ipad || message) */
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner);

    /* Outer pad: key XOR 0x5c */
    memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }

    /* out = SHA256(k_opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}
