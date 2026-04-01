/**
 * @file    security.c
 * @brief   Security stubs — passkey check, nonce generation, token verify.
 *
 * This first iteration uses simplified implementations.  TODOs mark
 * where real cryptographic logic should replace the stubs.
 */
#include "security.h"
#include "stm32g4xx_hal.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */
void security_init(void)
{
    /*
     * TODO: load admin secret from protected flash / OTP.
     * TODO: initialise RNG peripheral for nonce generation.
     */
}

/* ------------------------------------------------------------------ */
/*  Passkey validation                                                 */
/* ------------------------------------------------------------------ */
bool security_validate_passkey(const uint8_t *ascii_digits, uint16_t len)
{
    const char *ref = PASSKEY_REF;
    uint16_t ref_len = (uint16_t)strlen(ref);

    /* Length check */
    if (len < PASSKEY_MIN_LEN || len > PASSKEY_MAX_LEN) {
        return false;
    }
    if (len != ref_len) {
        return false;
    }

    /*
     * Constant-time comparison to avoid timing side-channel.
     * Not critical at this stage but good practice.
     */
    uint8_t diff = 0;
    for (uint16_t i = 0; i < len; i++) {
        diff |= ascii_digits[i] ^ (uint8_t)ref[i];
    }
    return (diff == 0);
}

/* ------------------------------------------------------------------ */
/*  Nonce generation  (STUB)                                           */
/* ------------------------------------------------------------------ */
void security_generate_nonce(uint8_t nonce_out[NONCE_SIZE])
{
    /*
     * TODO: replace with hardware RNG.
     *
     * Stub: fill nonce from HAL_GetTick() XOR'd with a counter.
     * This is NOT cryptographically random — adequate only for
     * initial integration testing.
     */
    static uint32_t counter = 0;
    counter++;

    uint32_t seed = HAL_GetTick() ^ counter;
    for (uint8_t i = 0; i < NONCE_SIZE; i++) {
        nonce_out[i] = (uint8_t)(seed & 0xFF);
        /* simple rotation to spread bits */
        seed = (seed >> 7) | (seed << 25);
        seed ^= counter + i;
    }
}

/* ------------------------------------------------------------------ */
/*  Admin token verification  (STUB)                                   */
/* ------------------------------------------------------------------ */
bool security_verify_admin_token(const uint8_t *token, uint16_t token_len,
                                 const uint8_t *nonce)
{
    (void)token;
    (void)token_len;
    (void)nonce;

    /*
     * TODO: implement HMAC-SHA256 verification.
     *
     * Expected logic:
     *   1. Reconstruct expected = HMAC_SHA256(admin_secret, nonce || 0x01)
     *   2. Constant-time compare expected vs received token
     *   3. Return true only if match and token_len == 32
     *
     * For now, always return false so that admin approval flow can be
     * tested structurally without real crypto.
     */
    return false;
}
