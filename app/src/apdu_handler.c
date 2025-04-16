/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *   (c) 2016 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "secret.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"
#include "parser_utils.h"

static bool tx_initialized = false;
static bool tx_bufferFull = false;
static uint32_t wasm_counter = 0;
streaming_state_e streaming_state = StreamingStateNoStreaming;

static void write_error_msg(const char *error_msg, volatile uint32_t *tx);

static void extractHDPath(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

static bool process_wasm_chunk(volatile uint32_t *tx, uint32_t rx) {
    UNUSED(tx);
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            tx_bufferFull = false;
            wasm_counter = 0;
            return false;

        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (!tx_bufferFull && (added != rx - OFFSET_DATA)) {
                if (tx_parse_wasm() != zxerr_ok) {
                    tx_initialized = false;
                    THROW(APDU_CODE_EXECUTION_ERROR);
                }
                tx_bufferFull = true;
            }
            return false;

        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (!tx_bufferFull && (added != rx - OFFSET_DATA)) {
                if (tx_parse_wasm() != zxerr_ok) {
                    tx_initialized = false;
                    THROW(APDU_CODE_EXECUTION_ERROR);
                }
                tx_bufferFull = true;
            }
            return true;
    }

    tx_initialized = false;
    THROW(APDU_CODE_INVALIDP1P2);
}

static bool process_chunk(volatile uint32_t *tx, uint32_t rx) {
    UNUSED(tx);
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            streaming_state = StreamingStateNoStreaming;
            return false;

        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_EXECUTION_ERROR);
            }
            if (tx_get_buffer_length() >= (tx_get_flash_buffer_size() - IO_APDU_BUFFER_SIZE)) {
                if (streaming_state == StreamingStateNoStreaming) {
                    streaming_state = StreamingStateInit;
                } 

                if (streaming_state == StreamingStateInit) {
                    const char *error_msg = tx_parse();

                    if (strcmp(error_msg, WASM_TOO_LARGE_ERROR_MSG) != 0) {
                        // Expected WASM too large error
                        write_error_msg(error_msg, tx);
                        THROW(APDU_CODE_EXECUTION_ERROR);
                    }

                    tx_incrementally_hash_txnV1(hash_start);
                    tx_reset();
                    streaming_state = StreamingStateInProgress;
                } else if (streaming_state == StreamingStateInProgress) {
                    tx_incrementally_hash_txnV1(hash_update);
                    tx_reset();
                } else {
                    // Something went wrong, this should never be reached
                    THROW(APDU_CODE_EXECUTION_ERROR);
                }
            }
            return false;

        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_EXECUTION_ERROR);
            }

            if (streaming_state == StreamingStateInProgress) {
                // Hash the last bytes of the transaction
                tx_incrementally_hash_txnV1(hash_finish);
                streaming_state = StreamingStateFinal;
            }

            if (streaming_state != StreamingStateFinal && streaming_state != StreamingStateNoStreaming) {
                // Something went wrong, this should never be reached
                THROW(APDU_CODE_EXECUTION_ERROR);
            }

            return true;

        default:
            THROW(APDU_CODE_INVALIDP1P2);
    }

    tx_initialized = false;
    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handleSignWasmDeploy(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    wasm_counter++;
    if (!process_wasm_chunk(tx, rx)) {
        char message[50] = {0};
        snprintf(message, sizeof(message), "Chunk %d\n", wasm_counter);
        // Don't refresh too fast
        if ((wasm_counter % 5) == 0) {
            view_message_show("Raw Wasm", message);
#if !(defined(TARGET_STAX) || defined(TARGET_FLEX))
            UX_WAIT_DISPLAYED();
#endif
        }
        THROW(APDU_CODE_OK);
    }
    tx_initialized = false;

    view_idle_show(0, NULL);
    // If not done before, parse transaction
    if (!tx_bufferFull && (tx_parse_wasm() != zxerr_ok)) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    if (tx_validate_wasm() != zxerr_ok) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getWasmItem, tx_getWasmNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSign(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    tx_initialized = false;

    CHECK_APP_CANARY()

    // If the transaction didn't require streaming, we can parse the transaction here.
    // Otherwise, tx_parse is called in process_chunk
    if (streaming_state == StreamingStateNoStreaming) {
        const char *error_msg = tx_parse();
        CHECK_APP_CANARY()
        if (error_msg != NULL) {
            write_error_msg(error_msg, tx);
            THROW(APDU_CODE_DATA_INVALID);
        }
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handle_getversion(volatile uint32_t *flags, volatile uint32_t *tx) {
    UNUSED(flags);
#ifdef DEBUG
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;
    G_io_apdu_buffer[4] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

    *tx += 9;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = app_fill_address();
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignMessage(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()

    const char *error_msg = tx_parse_message();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        const size_t error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getMessageItem, tx_getMessageNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }

                case INS_GET_ADDR: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx);
                    break;
                }

                case INS_SIGN: {
                    CHECK_PIN_VALIDATED()
                    handleSign(flags, tx, rx);
                    break;
                }

                case INS_SIGN_MSG: {
                    CHECK_PIN_VALIDATED()
                    handleSignMessage(flags, tx, rx);
                    break;
                }

                case INS_SIGN_WASM_DEPLOY: {
                    CHECK_PIN_VALIDATED()
                    handleSignWasmDeploy(flags, tx, rx);
                    break;
                }

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {}
    }
    END_TRY;
}

static void write_error_msg(const char *error_msg, volatile uint32_t *tx) {
    int error_msg_length = strlen(error_msg);
    MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
    *tx += (error_msg_length);
}

