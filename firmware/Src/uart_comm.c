/**
 * @file    uart_comm.c
 * @brief   LPUART1 driver with interrupt-driven RX ring buffer.
 *
 * The NUCLEO-G474RE routes the ST-LINK VCP to LPUART1 (PA2 TX, PA3 RX).
 *
 * TODO: If your board revision routes VCP to a different USART, update
 *       the handle and IRQ references below.
 */
#include "uart_comm.h"
#include "app_config.h"
#include "stm32g4xx_hal.h"

/* ------------------------------------------------------------------ */
/*  HAL handle  (created by CubeMX — we extern it here)                */
/* ------------------------------------------------------------------ */
extern UART_HandleTypeDef hlpuart1;

/* ------------------------------------------------------------------ */
/*  RX ring buffer                                                     */
/* ------------------------------------------------------------------ */
static volatile uint8_t  g_rx_ring[UART_RX_BUF_SIZE];
static volatile uint16_t g_rx_head = 0;   /* written by ISR  */
static          uint16_t g_rx_tail = 0;   /* read by main    */

/* ------------------------------------------------------------------ */
/*  TX buffer                                                          */
/* ------------------------------------------------------------------ */
static uint8_t g_tx_buf[UART_TX_BUF_SIZE];

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */
void uart_comm_init(void)
{
    g_rx_head = 0;
    g_rx_tail = 0;

    /*
     * Clear any stale UART error flags and drain RDR before enabling ISR.
     * The echo diagnostic (or previous session) may have left ORE / RXNE set.
     */
    __HAL_UART_CLEAR_FLAG(&hlpuart1, UART_CLEAR_OREF | UART_CLEAR_NEF
                                    | UART_CLEAR_FEF  | UART_CLEAR_PEF);
    if (__HAL_UART_GET_FLAG(&hlpuart1, UART_FLAG_RXNE)) {
        (void)hlpuart1.Instance->RDR;   /* dummy read to clear RXNE */
    }

    /*
     * Enable the RXNE (Receive Not Empty) interrupt.
     *
     * IMPORTANT: Priority 4 is ABOVE configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY
     * (5), so this ISR is NEVER masked by FreeRTOS BASEPRI during critical
     * sections.  This is safe because our ISR does NOT call any FreeRTOS API —
     * it only reads the LPUART data register and writes to a plain ring buffer.
     *
     * With priority 5 (the boundary), the ISR was masked during every
     * xSemaphoreTake / xSemaphoreGive / vTaskDelay, causing bytes to be lost.
     */
    __HAL_UART_ENABLE_IT(&hlpuart1, UART_IT_RXNE);
    HAL_NVIC_SetPriority(LPUART1_IRQn, 4, 0);
    HAL_NVIC_EnableIRQ(LPUART1_IRQn);
}

/* ------------------------------------------------------------------ */
/*  ISR — called from LPUART1_IRQHandler in stm32g4xx_it.c             */
/* ------------------------------------------------------------------ */
void uart_comm_irq_handler(void)
{
    /* Check RXNE flag */
    if (__HAL_UART_GET_FLAG(&hlpuart1, UART_FLAG_RXNE)) {
        uint8_t byte = (uint8_t)(hlpuart1.Instance->RDR & 0xFF);
        uint16_t next = (g_rx_head + 1) % UART_RX_BUF_SIZE;
        if (next != g_rx_tail) {        /* drop byte if buffer full */
            g_rx_ring[g_rx_head] = byte;
            g_rx_head = next;
        }
    }

    /* Clear overrun error if set (prevents IRQ storm) */
    if (__HAL_UART_GET_FLAG(&hlpuart1, UART_FLAG_ORE)) {
        __HAL_UART_CLEAR_OREFLAG(&hlpuart1);
    }
}

/* ------------------------------------------------------------------ */
/*  Single-byte read (non-blocking, for CSP process polling)           */
/* ------------------------------------------------------------------ */
int uart_comm_read_byte(void)
{
    if (g_rx_tail == g_rx_head) return -1;
    uint8_t byte = g_rx_ring[g_rx_tail];
    g_rx_tail = (g_rx_tail + 1) % UART_RX_BUF_SIZE;
    return (int)byte;
}

/* ------------------------------------------------------------------ */
/*  Transmit                                                           */
/* ------------------------------------------------------------------ */
void uart_comm_send_packet(const fac_packet_t *pkt)
{
    uint16_t len = packet_encode(pkt, g_tx_buf, sizeof(g_tx_buf));
    if (len > 0) {
        HAL_UART_Transmit(&hlpuart1, g_tx_buf, len, 100);
    }
}

void uart_comm_send_raw(const uint8_t *data, uint16_t len)
{
    HAL_UART_Transmit(&hlpuart1, (uint8_t *)data, len, 100);
}
