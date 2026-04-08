/**
 * @file    sha256.h
 * @brief   Minimal SHA-256 and HMAC-SHA256 for embedded use.
 *
 * FIPS 180-4 compliant.  No dynamic allocation, no external dependencies.
 */
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/**
 * Compute HMAC-SHA256(key, message) in one call.
 * @param key      HMAC key bytes
 * @param key_len  key length
 * @param msg      message bytes
 * @param msg_len  message length
 * @param out      output buffer (32 bytes)
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
