/**
 * @file    uart_comm.h
 * @brief   LPUART1 driver — interrupt RX into ring buffer, polling TX.
 */
#ifndef UART_COMM_H
#define UART_COMM_H

#include <stdint.h>
#include <stdbool.h>
#include "packet_codec.h"

/**
 * Initialise LPUART1 for 115200-8N1 and enable RXNE interrupt.
 * Call once at startup after HAL_Init() and SystemClock_Config().
 */
void uart_comm_init(void);

/**
 * Encode and transmit a packet (blocking / polling TX).
 * Suitable for small response packets.
 */
void uart_comm_send_packet(const fac_packet_t *pkt);

/**
 * Transmit raw bytes (blocking / polling TX).
 */
void uart_comm_send_raw(const uint8_t *data, uint16_t len);

/**
 * Read one byte from the ISR ring buffer (non-blocking).
 * @return  byte value (0–255) if available, or -1 if buffer empty.
 */
int uart_comm_read_byte(void);

/**
 * UART RX interrupt handler — call this from LPUART1_IRQHandler()
 * in stm32g4xx_it.c.
 */
void uart_comm_irq_handler(void);

#endif /* UART_COMM_H */
