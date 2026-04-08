/**
 * @file    security.c
 * @brief   Passkey check, hardware RNG nonce generation, HMAC-SHA256
 *          admin token verification.
 */
#include "security.h"
#include "sha256.h"
#include "stm32g4xx_hal.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Admin secret  (matches gui/admin_gui.py default --secret flag)     */
/* ------------------------------------------------------------------ */
static const uint8_t admin_secret[] = "FAC_ADMIN_SECRET_2026";
static const uint16_t admin_secret_len = sizeof(admin_secret) - 1;

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */
void security_init(void)
{
    /* Admin secret is a compile-time constant for the prototype.
     * Future: load from OTP / protected flash. */
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

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (uint16_t i = 0; i < len; i++) {
        diff |= ascii_digits[i] ^ (uint8_t)ref[i];
    }
    return (diff == 0);
}

/* ------------------------------------------------------------------ */
/*  Hardware RNG helper                                                */
/* ------------------------------------------------------------------ */
static uint32_t rng_read(void)
{
    while (!(RNG->SR & RNG_SR_DRDY)) {
        /* spin until a random word is ready */
    }
    return RNG->DR;
}

/* ------------------------------------------------------------------ */
/*  Nonce generation  (hardware RNG)                                   */
/* ------------------------------------------------------------------ */
void security_generate_nonce(uint8_t nonce_out[NONCE_SIZE])
{
    for (uint8_t i = 0; i < NONCE_SIZE; i += 4) {
        uint32_t rval = rng_read();
        uint8_t remaining = NONCE_SIZE - i;
        memcpy(&nonce_out[i], &rval, remaining >= 4 ? 4 : remaining);
    }
}

/* ------------------------------------------------------------------ */
/*  Admin token verification  (HMAC-SHA256)                            */
/* ------------------------------------------------------------------ */
bool security_verify_admin_token(const uint8_t *token, uint16_t token_len,
                                 const uint8_t *nonce)
{
    if (token_len != ADMIN_TOKEN_SIZE) {
        return false;
    }

    /* Build message: nonce || 0x01 (approve action byte) */
    uint8_t msg[NONCE_SIZE + 1];
    memcpy(msg, nonce, NONCE_SIZE);
    msg[NONCE_SIZE] = 0x01;

    /* Compute expected = HMAC-SHA256(admin_secret, msg) */
    uint8_t expected[SHA256_DIGEST_SIZE];
    hmac_sha256(admin_secret, admin_secret_len,
                msg, sizeof(msg), expected);

    /* Constant-time compare to avoid timing side-channel */
    uint8_t diff = 0;
    for (uint8_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        diff |= token[i] ^ expected[i];
    }
    return (diff == 0);
}
