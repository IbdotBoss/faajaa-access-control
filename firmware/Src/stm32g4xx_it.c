/**
 * @file    stm32g4xx_it.c
 * @brief   Interrupt Service Routines for FAC firmware (FreeRTOS build).
 *
 * FreeRTOS owns SVC_Handler, PendSV_Handler, and SysTick_Handler
 * (provided by the CM4F port), so they are NOT defined here.
 *
 * HAL tick is driven by TIM1 (via stm32g4xx_hal_timebase_tim.c),
 * so TIM1_UP_TIM16_IRQHandler calls HAL_IncTick().
 *
 * LPUART1 ISR still pushes bytes into the uart_comm ring buffer.
 */

#include "stm32g4xx_hal.h"
#include "uart_comm.h"

/* TIM1 handle — defined in stm32g4xx_hal_timebase_tim.c */
extern TIM_HandleTypeDef htim1;

/* -----------------------------------------------------------------------
 * Cortex-M4 core exception handlers
 * --------------------------------------------------------------------- */

void NMI_Handler(void)
{
    while (1) {}
}

void HardFault_Handler(void)
{
    while (1) {}
}

void MemManage_Handler(void)
{
    while (1) {}
}

void BusFault_Handler(void)
{
    while (1) {}
}

void UsageFault_Handler(void)
{
    while (1) {}
}

void DebugMon_Handler(void)
{
}

/* NOTE: SVC_Handler, PendSV_Handler, SysTick_Handler are provided
 * by FreeRTOS portable/GCC/ARM_CM4F/port.c — do NOT define them here. */

/* -----------------------------------------------------------------------
 * TIM1 Update interrupt — HAL timebase (replaces SysTick for HAL)
 * --------------------------------------------------------------------- */

void TIM1_UP_TIM16_IRQHandler(void)
{
    HAL_TIM_IRQHandler(&htim1);
}

/* -----------------------------------------------------------------------
 * LPUART global interrupt  (startup file uses LPUART_IRQHandler, not
 * LPUART1_IRQHandler — the "1" is dropped in the vector table name)
 * --------------------------------------------------------------------- */

void LPUART_IRQHandler(void)
{
    uart_comm_irq_handler();
}
