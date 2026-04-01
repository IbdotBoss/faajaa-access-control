/**
 * @file    security.h
 * @brief   Passkey validation, nonce generation, and admin token
 *          verification.  Crypto stubs for initial iteration.
 */
#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include "app_config.h"

/** One-time init (placeholder for future key loading). */
void security_init(void);

/**
 * Validate a passkey attempt against the stored reference.
 * @param ascii_digits  pointer to ASCII digit characters (e.g. '1','2','3','4')
 * @param len           number of characters
 * @return true if passkey matches.
 */
bool security_validate_passkey(const uint8_t *ascii_digits, uint16_t len);

/**
 * Generate a 16-byte nonce for admin challenge-response.
 * @param nonce_out  buffer of at least NONCE_SIZE bytes.
 *
 * TODO: replace stub with hardware RNG (RNG peripheral on STM32G474).
 */
void security_generate_nonce(uint8_t nonce_out[NONCE_SIZE]);

/**
 * Verify an admin approval token against the expected nonce.
 * @param token      received token bytes.
 * @param token_len  length of token.
 * @param nonce      the nonce that was issued for this request.
 * @return true if token is valid.
 *
 * TODO: implement HMAC-SHA256(admin_secret, nonce || 0x01) verification.
 */
bool security_verify_admin_token(const uint8_t *token, uint16_t token_len,
                                 const uint8_t *nonce);

#endif /* SECURITY_H */
