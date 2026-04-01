/**
 * @file    app_config.h
 * @brief   Central configuration for the FAC firmware.
 *          Every compile-time constant lives here.
 */
#ifndef APP_CONFIG_H
#define APP_CONFIG_H

/* ------------------------------------------------------------------ */
/*  Protocol framing                                                   */
/* ------------------------------------------------------------------ */
#define PROTO_START_BYTE        0x7E
#define PROTO_END_BYTE          0x7F
#define PROTO_VERSION           0x01

#define PACKET_MAX_PAYLOAD      64
#define PACKET_HEADER_SIZE      7   /* VER+TYPE+FLAGS+REQID(2)+LEN(2)  */
#define PACKET_OVERHEAD         12  /* START(1)+header(7)+CRC(2)+END(1) */
#define PACKET_MAX_SIZE         (PACKET_OVERHEAD + PACKET_MAX_PAYLOAD)

/* ------------------------------------------------------------------ */
/*  Message types  (broker <-> MCU)                                    */
/* ------------------------------------------------------------------ */
#define MSG_PASS_TRY            0x01
#define MSG_PASS_RESULT         0x02
#define MSG_REQUEST_ADMIN       0x03
#define MSG_NONCE_ISSUED        0x04
#define MSG_ADMIN_APPROVE       0x05
#define MSG_ADMIN_DENY          0x06
#define MSG_STATUS_UPDATE       0x07
#define MSG_ERROR               0x08
#define MSG_LOCKOUT_NOTICE      0x09
#define MSG_PING                0x0A
#define MSG_PONG                0x0B

/* ------------------------------------------------------------------ */
/*  PASS_RESULT payload codes                                          */
/* ------------------------------------------------------------------ */
#define RESULT_DENIED           0x00
#define RESULT_GRANTED          0x01
#define RESULT_LOCKOUT_ACTIVE   0x02

/* ------------------------------------------------------------------ */
/*  STATUS_UPDATE state codes                                          */
/* ------------------------------------------------------------------ */
#define STATE_CODE_LOCKED_IDLE      0x10
#define STATE_CODE_VALIDATING       0x11
#define STATE_CODE_PENDING_ADMIN    0x12
#define STATE_CODE_UNLOCKED         0x13
#define STATE_CODE_DENIED           0x14
#define STATE_CODE_LOCKOUT          0x15
#define STATE_CODE_SYSTEM_FAULT     0x16

/* ------------------------------------------------------------------ */
/*  ERROR payload codes                                                */
/* ------------------------------------------------------------------ */
#define ERR_MALFORMED_PACKET        0x20
#define ERR_CRC_MISMATCH            0x21
#define ERR_INVALID_TRANSITION      0x22
#define ERR_NONCE_EXPIRED           0x23
#define ERR_NONCE_INVALID           0x24
#define ERR_ADMIN_TOKEN_INVALID     0x25
#define ERR_UNSUPPORTED_VERSION     0x26

/* ------------------------------------------------------------------ */
/*  Timeouts (milliseconds)                                            */
/* ------------------------------------------------------------------ */
#define UNLOCK_DURATION_MS          5000
#define DENIED_DISPLAY_MS           2000
#define ADMIN_NONCE_TIMEOUT_MS      30000
#define LOCKOUT_DURATION_MS         60000
#define DEBOUNCE_MS                 50

/* ------------------------------------------------------------------ */
/*  Security parameters                                                */
/* ------------------------------------------------------------------ */
#define PASSKEY_REF                 "1234"   /* TODO: move to protected storage */
#define PASSKEY_MIN_LEN             4
#define PASSKEY_MAX_LEN             6
#define MAX_FAIL_ATTEMPTS           3
#define NONCE_SIZE                  16
#define ADMIN_TOKEN_SIZE            32

/* ------------------------------------------------------------------ */
/*  Buffer sizes                                                       */
/* ------------------------------------------------------------------ */
#define UART_RX_BUF_SIZE            256
#define UART_TX_BUF_SIZE            128
#define EVENT_QUEUE_SIZE            8

/* ------------------------------------------------------------------ */
/*  GPIO pin mapping  (NUCLEO-G474RE)                                  */
/* ------------------------------------------------------------------ */
/* LD2 user LED on PA5 */
#define LED_LOCK_PORT               GPIOA
#define LED_LOCK_PIN                GPIO_PIN_5

/* B1 user button on PC13  (active LOW, external pull-up on Nucleo) */
#define BTN_USER_PORT               GPIOC
#define BTN_USER_PIN                GPIO_PIN_13

/* ------------------------------------------------------------------ */
/*  UART  (LPUART1 is the VCP on NUCLEO-G474RE: PA2 TX, PA3 RX)       */
/* ------------------------------------------------------------------ */
/* TODO: verify against CubeMX-generated MX_LPUART1_UART_Init().
 *       If your board revision routes VCP to USART2 instead,
 *       change these defines accordingly.                             */
#define FAC_UART_BAUD               115200

#endif /* APP_CONFIG_H */
