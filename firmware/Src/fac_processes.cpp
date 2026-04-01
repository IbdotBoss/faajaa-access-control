/**
 * @file    fac_processes.cpp
 * @brief   CSP process network for the FAC access-control firmware.
 *
 * Four concurrent processes connected by three rendezvous channels:
 *
 *   LPUART1 ISR -> [ring buf] -> UartRxProcess --packetChan--> FsmProcess
 *   PC13 button ----------------> ButtonProcess --buttonChan--> FsmProcess
 *   FsmProcess --txChan--> UartTxProcess -> HAL_UART_Transmit
 *
 * The FsmProcess uses an ALT (selective wait) on packetChan, buttonChan,
 * and a RelTimeoutGuard to handle all FSM state transitions and timeouts
 * without polling.
 */

#include "csp/csp4cmsis.h"

extern "C" {
#include "app_config.h"
#include "packet_codec.h"
#include "uart_comm.h"
#include "security.h"
#include "stm32g4xx_hal.h"
#include "fac_processes.h"
}

#include <cstring>

/* ================================================================== */
/*  FSM state enum (mirrors the old state_machine.h)                   */
/* ================================================================== */
enum class FsmState {
    LOCKED_IDLE,
    VALIDATING_LOCAL,
    PENDING_ADMIN,
    UNLOCKED,
    DENIED,
    LOCKOUT,
    SYSTEM_FAULT
};

/* ================================================================== */
/*  Button event (trivial type for channel)                            */
/* ================================================================== */
struct ButtonEvent {
    bool pressed;
};

/* ================================================================== */
/*  Static channels                                                    */
/* ================================================================== */
static csp::One2OneChannel<fac_packet_t> packetChan;
static csp::One2OneChannel<ButtonEvent>  buttonChan;
static csp::One2OneChannel<fac_packet_t> txChan;

/* ================================================================== */
/*  UartRxProcess                                                      */
/*  Drains ISR ring buffer -> parser -> writes complete packets to     */
/*  packetChan.  Polls with a 1ms osDelay when buffer is empty.        */
/* ================================================================== */
class UartRxProcess : public csp::CSProcess {
public:
    const char* name() const override { return "UartRx"; }

public:
    void run() override {
        packet_parser_t parser;
        parser_init(&parser);

        auto out = packetChan.writer();

        while (true) {
            int byte = uart_comm_read_byte();
            if (byte < 0) {
                vTaskDelay(pdMS_TO_TICKS(1));
                continue;
            }

            if (parser_feed_byte(&parser, (uint8_t)byte)) {
                /* Complete valid packet — send to FSM */
                out << parser.pkt;
            }
        }
    }
};

/* ================================================================== */
/*  ButtonProcess                                                      */
/*  Polls PC13 (active-low) with 20ms debounce via osDelay.            */
/*  On falling edge, writes to buttonChan.                             */
/* ================================================================== */
class ButtonProcess : public csp::CSProcess {
public:
    const char* name() const override { return "Button"; }

public:
    void run() override {
        /* GPIO init: PA5 output (LED), PC13 input (button) */
        __HAL_RCC_GPIOA_CLK_ENABLE();
        __HAL_RCC_GPIOC_CLK_ENABLE();

        GPIO_InitTypeDef gpio = {};
        gpio.Pin   = LED_LOCK_PIN;
        gpio.Mode  = GPIO_MODE_OUTPUT_PP;
        gpio.Pull  = GPIO_NOPULL;
        gpio.Speed = GPIO_SPEED_FREQ_LOW;
        HAL_GPIO_Init(LED_LOCK_PORT, &gpio);

        gpio.Pin  = BTN_USER_PIN;
        gpio.Mode = GPIO_MODE_INPUT;
        gpio.Pull = GPIO_NOPULL;
        HAL_GPIO_Init(BTN_USER_PORT, &gpio);

        auto out = buttonChan.writer();

        bool last_stable = true;  /* PC13 is active-low; idle = HIGH */
        uint32_t last_change = HAL_GetTick();

        while (true) {
            vTaskDelay(pdMS_TO_TICKS(10));

            bool raw = (HAL_GPIO_ReadPin(BTN_USER_PORT, BTN_USER_PIN) == GPIO_PIN_SET);
            uint32_t now = HAL_GetTick();

            if (raw != last_stable && (now - last_change) >= DEBOUNCE_MS) {
                last_stable = raw;
                last_change = now;

                if (!last_stable) {
                    /* Falling edge = button pressed (active-low) */
                    ButtonEvent evt{true};
                    out << evt;
                }
            }
        }
    }
};

/* ================================================================== */
/*  UartTxProcess                                                      */
/*  Reads packets from txChan, encodes, and transmits via HAL.         */
/* ================================================================== */
class UartTxProcess : public csp::CSProcess {
public:
    const char* name() const override { return "UartTx"; }

public:
    void run() override {
        extern UART_HandleTypeDef hlpuart1;
        auto in = txChan.reader();
        uint8_t buf[PACKET_MAX_SIZE];

        while (true) {
            fac_packet_t pkt;
            in >> pkt;

            uint16_t len = packet_encode(&pkt, buf, sizeof(buf));
            if (len > 0) {
                HAL_UART_Transmit(&hlpuart1, buf, len, 100);
            }
        }
    }
};

/* ================================================================== */
/*  FsmProcess                                                         */
/*  Core FSM using ALT on packetChan, buttonChan, and timeout guard.   */
/* ================================================================== */
class FsmProcess : public csp::CSProcess {
public:
    const char* name() const override { return "FSM"; }

public:
    void run() override {
        auto pktIn = packetChan.reader();
        auto btnIn = buttonChan.reader();
        auto txOut = txChan.writer();

        FsmState state       = FsmState::LOCKED_IDLE;
        uint8_t  fail_count  = 0;
        uint16_t cur_req_id  = 0;
        uint8_t  nonce[NONCE_SIZE] = {};
        bool     nonce_valid = false;

        /* LED off initially */
        HAL_GPIO_WritePin(LED_LOCK_PORT, LED_LOCK_PIN, GPIO_PIN_RESET);

        /* Send initial status */
        send_status(txOut, STATE_CODE_LOCKED_IDLE, 0);

        /* Timeout for ALT — initially "infinite" (max wait) */
        uint32_t timeout_ms = 0;  /* 0 = no active timeout */
        uint32_t timeout_started = 0;

        while (true) {
            /* ---- Build ALT ---- */
            fac_packet_t pkt = {};
            ButtonEvent  btn = {};

            uint32_t alt_timeout_ms = remaining_ms(timeout_ms, timeout_started);

            if (alt_timeout_ms > 0) {
                csp::RelTimeoutGuard timer(csp::Milliseconds(alt_timeout_ms));
                csp::Alternative alt(pktIn | pkt, btnIn | btn, timer);

                int idx = alt.fairSelect();
                if (idx == 0) {
                    handle_packet(pkt, state, fail_count, cur_req_id,
                                  nonce, nonce_valid, timeout_ms,
                                  timeout_started, txOut);
                } else if (idx == 1) {
                    handle_button(state, cur_req_id, nonce, nonce_valid,
                                  timeout_ms, timeout_started, txOut);
                } else {
                    /* Timeout fired */
                    handle_timeout(state, fail_count, cur_req_id,
                                   nonce_valid, timeout_ms,
                                   timeout_started, txOut);
                }
            } else {
                /* No timeout active — wait on channels only */
                csp::RelTimeoutGuard timer(csp::Seconds(3600));
                csp::Alternative alt(pktIn | pkt, btnIn | btn, timer);

                int idx = alt.fairSelect();
                if (idx == 0) {
                    handle_packet(pkt, state, fail_count, cur_req_id,
                                  nonce, nonce_valid, timeout_ms,
                                  timeout_started, txOut);
                } else if (idx == 1) {
                    handle_button(state, cur_req_id, nonce, nonce_valid,
                                  timeout_ms, timeout_started, txOut);
                }
                /* idx == 2 is the 1-hour fallback timeout — just loop */
            }
        }
    }

private:
    /* -------------------------------------------------------------- */
    /*  Timeout helpers                                                 */
    /* -------------------------------------------------------------- */
    static uint32_t remaining_ms(uint32_t timeout_ms, uint32_t started) {
        if (timeout_ms == 0) return 0;
        uint32_t elapsed = HAL_GetTick() - started;
        if (elapsed >= timeout_ms) return 1;  /* fire immediately */
        return timeout_ms - elapsed;
    }

    static void start_timeout(uint32_t &timeout_ms, uint32_t &started, uint32_t duration) {
        timeout_ms = duration;
        started = HAL_GetTick();
    }

    static void stop_timeout(uint32_t &timeout_ms, uint32_t &started) {
        timeout_ms = 0;
        started = 0;
    }

    /* -------------------------------------------------------------- */
    /*  Packet builders (write to txChan)                               */
    /* -------------------------------------------------------------- */
    static void send_status(csp::Chanout<fac_packet_t> &tx,
                            uint8_t state_code, uint16_t req_id) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_STATUS_UPDATE;
        p.request_id  = req_id;
        p.payload_len = 1;
        p.payload[0]  = state_code;
        tx << p;
    }

    static void send_pass_result(csp::Chanout<fac_packet_t> &tx,
                                 uint8_t result, uint16_t req_id) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_PASS_RESULT;
        p.request_id  = req_id;
        p.payload_len = 1;
        p.payload[0]  = result;
        tx << p;
    }

    static void send_error(csp::Chanout<fac_packet_t> &tx,
                           uint8_t err, uint16_t req_id) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_ERROR;
        p.request_id  = req_id;
        p.payload_len = 1;
        p.payload[0]  = err;
        tx << p;
    }

    static void send_nonce(csp::Chanout<fac_packet_t> &tx,
                           uint16_t req_id, const uint8_t *nonce_data) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_NONCE_ISSUED;
        p.request_id  = req_id;
        p.payload_len = NONCE_SIZE;
        std::memcpy(p.payload, nonce_data, NONCE_SIZE);
        tx << p;
    }

    static void send_pong(csp::Chanout<fac_packet_t> &tx, uint16_t req_id) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_PONG;
        p.request_id  = req_id;
        p.payload_len = 0;
        tx << p;
    }

    static void send_lockout_notice(csp::Chanout<fac_packet_t> &tx,
                                    uint16_t req_id,
                                    uint32_t timeout_ms, uint32_t started) {
        fac_packet_t p = {};
        p.version     = PROTO_VERSION;
        p.msg_type    = MSG_LOCKOUT_NOTICE;
        p.request_id  = req_id;
        p.payload_len = 1;
        uint32_t remaining = 0;
        if (timeout_ms > 0) {
            uint32_t elapsed = HAL_GetTick() - started;
            if (elapsed < timeout_ms) {
                remaining = (timeout_ms - elapsed) / 1000;
            }
        }
        p.payload[0] = (remaining > 255) ? 255 : (uint8_t)remaining;
        tx << p;
    }

    /* -------------------------------------------------------------- */
    /*  Passkey validation (used by LOCKED_IDLE and PENDING_ADMIN)      */
    /* -------------------------------------------------------------- */
    static void do_passkey(const fac_packet_t &pkt,
                           FsmState &state, uint8_t &fail_count,
                           uint16_t &cur_req_id, bool &nonce_valid,
                           uint32_t &timeout_ms, uint32_t &timeout_started,
                           csp::Chanout<fac_packet_t> &tx) {
        cur_req_id = pkt.request_id;

        state = FsmState::VALIDATING_LOCAL;
        send_status(tx, STATE_CODE_VALIDATING, cur_req_id);

        if (security_validate_passkey(pkt.payload, pkt.payload_len)) {
            fail_count = 0;
            nonce_valid = false;
            stop_timeout(timeout_ms, timeout_started);

            HAL_GPIO_WritePin(LED_LOCK_PORT, LED_LOCK_PIN, GPIO_PIN_SET);
            send_pass_result(tx, RESULT_GRANTED, pkt.request_id);
            send_status(tx, STATE_CODE_UNLOCKED, cur_req_id);
            start_timeout(timeout_ms, timeout_started, UNLOCK_DURATION_MS);
            state = FsmState::UNLOCKED;
        } else {
            fail_count++;
            if (fail_count >= MAX_FAIL_ATTEMPTS) {
                send_pass_result(tx, RESULT_LOCKOUT_ACTIVE, pkt.request_id);
                send_lockout_notice(tx, pkt.request_id, 0, 0);
                send_status(tx, STATE_CODE_LOCKOUT, cur_req_id);
                start_timeout(timeout_ms, timeout_started, LOCKOUT_DURATION_MS);
                state = FsmState::LOCKOUT;
            } else {
                send_pass_result(tx, RESULT_DENIED, pkt.request_id);
                send_status(tx, STATE_CODE_DENIED, cur_req_id);
                start_timeout(timeout_ms, timeout_started, DENIED_DISPLAY_MS);
                state = FsmState::DENIED;
            }
        }
    }

    /* -------------------------------------------------------------- */
    /*  Admin request initiation                                        */
    /* -------------------------------------------------------------- */
    static void do_admin_request(uint16_t req_id,
                                 FsmState &state, uint16_t &cur_req_id,
                                 uint8_t *nonce, bool &nonce_valid,
                                 uint32_t &timeout_ms, uint32_t &timeout_started,
                                 csp::Chanout<fac_packet_t> &tx) {
        cur_req_id = req_id;
        nonce_valid = true;
        security_generate_nonce(nonce);

        send_status(tx, STATE_CODE_PENDING_ADMIN, cur_req_id);
        send_nonce(tx, req_id, nonce);
        start_timeout(timeout_ms, timeout_started, ADMIN_NONCE_TIMEOUT_MS);
        state = FsmState::PENDING_ADMIN;
    }

    /* -------------------------------------------------------------- */
    /*  Handle incoming packet                                          */
    /* -------------------------------------------------------------- */
    static void handle_packet(const fac_packet_t &pkt,
                              FsmState &state, uint8_t &fail_count,
                              uint16_t &cur_req_id,
                              uint8_t *nonce, bool &nonce_valid,
                              uint32_t &timeout_ms, uint32_t &timeout_started,
                              csp::Chanout<fac_packet_t> &tx) {
        switch (state) {

        case FsmState::LOCKED_IDLE:
        case FsmState::VALIDATING_LOCAL:
            switch (pkt.msg_type) {
            case MSG_PASS_TRY:
                do_passkey(pkt, state, fail_count, cur_req_id,
                           nonce_valid, timeout_ms, timeout_started, tx);
                break;
            case MSG_REQUEST_ADMIN:
                do_admin_request(pkt.request_id, state, cur_req_id,
                                 nonce, nonce_valid, timeout_ms,
                                 timeout_started, tx);
                break;
            case MSG_PING:
                send_pong(tx, pkt.request_id);
                break;
            default:
                send_error(tx, ERR_INVALID_TRANSITION, pkt.request_id);
                break;
            }
            break;

        case FsmState::PENDING_ADMIN:
            switch (pkt.msg_type) {
            case MSG_ADMIN_APPROVE:
                if (!nonce_valid) {
                    send_error(tx, ERR_NONCE_INVALID, pkt.request_id);
                    break;
                }
                if (security_verify_admin_token(pkt.payload, pkt.payload_len, nonce)) {
                    nonce_valid = false;
                    stop_timeout(timeout_ms, timeout_started);
                    HAL_GPIO_WritePin(LED_LOCK_PORT, LED_LOCK_PIN, GPIO_PIN_SET);
                    send_status(tx, STATE_CODE_UNLOCKED, cur_req_id);
                    start_timeout(timeout_ms, timeout_started, UNLOCK_DURATION_MS);
                    state = FsmState::UNLOCKED;
                } else {
                    send_error(tx, ERR_ADMIN_TOKEN_INVALID, pkt.request_id);
                }
                break;
            case MSG_ADMIN_DENY:
                nonce_valid = false;
                stop_timeout(timeout_ms, timeout_started);
                send_status(tx, STATE_CODE_LOCKED_IDLE, cur_req_id);
                state = FsmState::LOCKED_IDLE;
                break;
            case MSG_PASS_TRY:
                do_passkey(pkt, state, fail_count, cur_req_id,
                           nonce_valid, timeout_ms, timeout_started, tx);
                break;
            case MSG_PING:
                send_pong(tx, pkt.request_id);
                break;
            default:
                send_error(tx, ERR_INVALID_TRANSITION, pkt.request_id);
                break;
            }
            break;

        case FsmState::UNLOCKED:
            if (pkt.msg_type == MSG_PING) {
                send_pong(tx, pkt.request_id);
            }
            break;

        case FsmState::DENIED:
            /* Ignore packets during brief denial display */
            break;

        case FsmState::LOCKOUT:
            switch (pkt.msg_type) {
            case MSG_PASS_TRY:
                send_pass_result(tx, RESULT_LOCKOUT_ACTIVE, pkt.request_id);
                send_lockout_notice(tx, pkt.request_id, timeout_ms, timeout_started);
                break;
            case MSG_PING:
                send_pong(tx, pkt.request_id);
                break;
            default:
                send_error(tx, ERR_INVALID_TRANSITION, pkt.request_id);
                break;
            }
            break;

        case FsmState::SYSTEM_FAULT:
            /* No recovery — manual reset required */
            break;
        }
    }

    /* -------------------------------------------------------------- */
    /*  Handle button press                                             */
    /* -------------------------------------------------------------- */
    static void handle_button(FsmState &state, uint16_t &cur_req_id,
                              uint8_t *nonce, bool &nonce_valid,
                              uint32_t &timeout_ms, uint32_t &timeout_started,
                              csp::Chanout<fac_packet_t> &tx) {
        if (state == FsmState::LOCKED_IDLE) {
            do_admin_request(0, state, cur_req_id, nonce, nonce_valid,
                             timeout_ms, timeout_started, tx);
        }
        /* Button ignored in all other states */
    }

    /* -------------------------------------------------------------- */
    /*  Handle timeout expiry                                           */
    /* -------------------------------------------------------------- */
    static void handle_timeout(FsmState &state, uint8_t &fail_count,
                               uint16_t &cur_req_id, bool &nonce_valid,
                               uint32_t &timeout_ms, uint32_t &timeout_started,
                               csp::Chanout<fac_packet_t> &tx) {
        switch (state) {

        case FsmState::UNLOCKED:
            stop_timeout(timeout_ms, timeout_started);
            HAL_GPIO_WritePin(LED_LOCK_PORT, LED_LOCK_PIN, GPIO_PIN_RESET);
            send_status(tx, STATE_CODE_LOCKED_IDLE, cur_req_id);
            state = FsmState::LOCKED_IDLE;
            break;

        case FsmState::DENIED:
            stop_timeout(timeout_ms, timeout_started);
            send_status(tx, STATE_CODE_LOCKED_IDLE, cur_req_id);
            state = FsmState::LOCKED_IDLE;
            break;

        case FsmState::PENDING_ADMIN:
            stop_timeout(timeout_ms, timeout_started);
            nonce_valid = false;
            send_error(tx, ERR_NONCE_EXPIRED, cur_req_id);
            send_status(tx, STATE_CODE_LOCKED_IDLE, cur_req_id);
            state = FsmState::LOCKED_IDLE;
            break;

        case FsmState::LOCKOUT:
            stop_timeout(timeout_ms, timeout_started);
            fail_count = 0;
            send_status(tx, STATE_CODE_LOCKED_IDLE, cur_req_id);
            state = FsmState::LOCKED_IDLE;
            break;

        default:
            /* No timeout expected in other states */
            break;
        }
    }
};

/* ================================================================== */
/*  Static process instances                                           */
/* ================================================================== */
static UartRxProcess uartRxProc;
static ButtonProcess buttonProc;
static FsmProcess    fsmProc;
static UartTxProcess uartTxProc;

/* ================================================================== */
/*  CSP network task (runs inside a FreeRTOS task, not from main)      */
/*                                                                     */
/*  csp::Run(StaticNetwork) runs process[0] on the CURRENT thread      */
/*  and spawns the rest.  If called from main(), osKernelStart() is    */
/*  never reached because process[0].run() is an infinite loop.        */
/*  Wrapping in a task matches the reference project pattern            */
/*  (application.cpp → MainApp_Task → csp::Run).                      */
/* ================================================================== */
static void csp_network_task(void* params)
{
    (void)params;
    csp::Run(
        csp::InParallel(fsmProc, uartRxProc, buttonProc, uartTxProc),
        csp::ExecutionMode::StaticNetwork
    );
}

/* ================================================================== */
/*  Launcher (called from main.c via extern "C")                       */
/* ================================================================== */
extern "C" void fac_start_processes(void)
{
    /*
     * Create a dedicated FreeRTOS task for the CSP process network.
     * fsmProc runs on this task's stack (2048 words = 8KB).
     * The other 3 processes are spawned as separate tasks by csp::Run.
     * main() then proceeds to osKernelStart() to begin scheduling.
     */
    xTaskCreate(csp_network_task, "CSPNet", 2048, NULL,
                tskIDLE_PRIORITY + 2, NULL);
}
