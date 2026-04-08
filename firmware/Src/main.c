/**
 * @file    main.c
 * @brief   FAC firmware entry point — HAL init + FreeRTOS/CSP launch.
 *
 * After HAL and peripheral init, this file initialises the RTOS kernel,
 * launches the four CSP processes (UartRx, Button, FSM, UartTx) via
 * fac_start_processes(), and starts the scheduler.  The super-loop is
 * replaced entirely by FreeRTOS tasks communicating over CSP channels.
 */

/* ------------------------------------------------------------------ */
/*  Includes                                                           */
/* ------------------------------------------------------------------ */
#include "stm32g4xx_hal.h"
#include "cmsis_os2.h"
#include "app_config.h"
#include "uart_comm.h"
#include "security.h"
#include "fac_processes.h"

/* ------------------------------------------------------------------ */
/*  HAL handles  (defined by CubeMX, externed in uart_comm.c)          */
/* ------------------------------------------------------------------ */
UART_HandleTypeDef hlpuart1;

/* ------------------------------------------------------------------ */
/*  CubeMX-style peripheral init prototypes                            */
/* ------------------------------------------------------------------ */
static void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_LPUART1_UART_Init(void);
static void MX_RNG_Init(void);

/* ================================================================== */
/*  main                                                               */
/* ================================================================== */
int main(void)
{
    /* --- HAL and clock --- */
    HAL_Init();
    SystemClock_Config();

    /* --- Peripheral init --- */
    MX_GPIO_Init();
    MX_LPUART1_UART_Init();
    MX_RNG_Init();

    /* --- Boot diagnostic: prove UART TX works --- */
    {
        const uint8_t banner[] = "FAC_BOOT\r\n";
        HAL_UART_Transmit(&hlpuart1, (uint8_t *)banner, sizeof(banner) - 1, 500);
    }

    /* --- Application init (modules kept from bare-metal) --- */
    security_init();
    uart_comm_init();   /* enables LPUART1 RXNE interrupt + NVIC */

    /* --- RTOS + CSP process network --- */
    osKernelInitialize();
    fac_start_processes();   /* creates 4 CSP tasks + 3 channels */
    osKernelStart();

    /* Should never reach here */
    while (1) {}
}

/* ================================================================== */
/*  Clock configuration                                                */
/*                                                                     */
/*  SYSCLK stays on HSI16 (16 MHz) — no flash latency changes.        */
/*  PLL is enabled solely to provide a 48 MHz clock for the RNG        */
/*  peripheral via PLL_Q output.                                       */
/*                                                                     */
/*  PLL config: HSI16 / PLLM=1 * PLLN=12 / PLLQ=4 = 48 MHz (PLL_Q)   */
/* ================================================================== */
static void SystemClock_Config(void)
{
    /* Enable HSI16 and configure PLL for 48 MHz on PLL_Q */
    RCC_OscInitTypeDef osc = {0};
    osc.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
    osc.HSIState            = RCC_HSI_ON;
    osc.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    osc.PLL.PLLState        = RCC_PLL_ON;
    osc.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
    osc.PLL.PLLM            = RCC_PLLM_DIV1;
    osc.PLL.PLLN            = 12;
    osc.PLL.PLLQ            = RCC_PLLQ_DIV4;   /* 16 * 12 / 4 = 48 MHz */
    osc.PLL.PLLR            = RCC_PLLR_DIV2;   /* not used but must be valid */
    osc.PLL.PLLP            = RCC_PLLP_DIV2;   /* not used but must be valid */
    HAL_RCC_OscConfig(&osc);

    /* Enable PLL_Q output */
    __HAL_RCC_PLLCLKOUT_ENABLE(RCC_PLL_48M1CLK);

    /* SYSCLK remains HSI16 — no PLL on system bus */
    RCC_ClkInitTypeDef clk = {0};
    clk.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                        | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_HSI;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_0);

    /* Select PLL_Q (48 MHz) as RNG clock source */
    __HAL_RCC_RNG_CONFIG(RCC_RNGCLKSOURCE_PLL);
}

/* ================================================================== */
/*  RNG init  (direct register access — no HAL RNG driver needed)      */
/* ================================================================== */
static void MX_RNG_Init(void)
{
    __HAL_RCC_RNG_CLK_ENABLE();
    RNG->CR |= RNG_CR_RNGEN;
}

/* ================================================================== */
/*  GPIO init  (LED and button — clocks only; pin config done in       */
/*  ButtonProcess)                                                     */
/* ================================================================== */
static void MX_GPIO_Init(void)
{
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
}

/* ================================================================== */
/*  LPUART1 init                                                       */
/*                                                                     */
/*  TODO: replace with CubeMX-generated MX_LPUART1_UART_Init().       */
/*  This stub configures 115200-8N1 on LPUART1.                       */
/* ================================================================== */
static void MX_LPUART1_UART_Init(void)
{
    __HAL_RCC_LPUART1_CLK_ENABLE();

    /* Configure PA2 (TX) and PA3 (RX) as alternate function */
    __HAL_RCC_GPIOA_CLK_ENABLE();
    GPIO_InitTypeDef gpio = {0};
    gpio.Pin       = GPIO_PIN_2 | GPIO_PIN_3;
    gpio.Mode      = GPIO_MODE_AF_PP;
    gpio.Pull      = GPIO_NOPULL;
    gpio.Speed     = GPIO_SPEED_FREQ_LOW;
    gpio.Alternate = GPIO_AF12_LPUART1;
    HAL_GPIO_Init(GPIOA, &gpio);

    hlpuart1.Instance               = LPUART1;
    hlpuart1.Init.BaudRate          = FAC_UART_BAUD;
    hlpuart1.Init.WordLength        = UART_WORDLENGTH_8B;
    hlpuart1.Init.StopBits          = UART_STOPBITS_1;
    hlpuart1.Init.Parity            = UART_PARITY_NONE;
    hlpuart1.Init.Mode              = UART_MODE_TX_RX;
    hlpuart1.Init.HwFlowCtl         = UART_HWCONTROL_NONE;
    hlpuart1.Init.OneBitSampling    = UART_ONE_BIT_SAMPLE_DISABLE;
    hlpuart1.Init.ClockPrescaler    = UART_PRESCALER_DIV1;
    hlpuart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    HAL_UART_Init(&hlpuart1);
}

/* ================================================================== */
/*  HAL TIM callback — drives HAL_GetTick() via TIM1                   */
/*                                                                     */
/*  Without this, HAL_GetTick() is stuck at 0 and every HAL timeout    */
/*  (including HAL_UART_Transmit) plus FsmProcess timeouts break.      */
/* ================================================================== */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
    if (htim->Instance == TIM1) {
        HAL_IncTick();
    }
}

/* ================================================================== */
/*  Error handler  (required by HAL)                                   */
/* ================================================================== */
void Error_Handler(void)
{
    __disable_irq();
    while (1) {
    }
}
