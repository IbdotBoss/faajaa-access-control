/**
 * @file    fac_processes.h
 * @brief   CSP process network launcher for the FAC firmware.
 *
 * Declares fac_start_processes() with C linkage so it can be called
 * from main.c (compiled as C) while the implementation in
 * fac_processes.cpp uses the C++ CSP4CMSIS library.
 */
#ifndef FAC_PROCESSES_H
#define FAC_PROCESSES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create all CSP channels and launch the four FAC processes
 * (UartRx, Button, Fsm, UartTx) as FreeRTOS tasks via
 * csp::Run(InParallel(...), ExecutionMode::StaticNetwork).
 *
 * Call after osKernelInitialize() but before osKernelStart().
 */
void fac_start_processes(void);

#ifdef __cplusplus
}
#endif

#endif /* FAC_PROCESSES_H */
