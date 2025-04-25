/*******************************************************************************
 *  (c) 2019 Zondax GmbH
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "parser_txdef.h"
#include "crypto.h"

#define CHECK_PARSER_ERR(__CALL)              \
    {                                         \
        parser_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                    \
        if (__err != parser_ok) return __err; \
    }

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data = 1,
    parser_init_context_empty = 2,
    parser_display_idx_out_of_range = 3,
    parser_display_page_out_of_range = 4,
    parser_unexpected_error = 5,
    // Cbor
    parser_cbor_unexpected = 6,
    parser_cbor_unexpected_EOF = 7,
    parser_cbor_not_canonical = 8,
    // Coin specific
    parser_unexpected_tx_version = 9,
    parser_unexpected_type = 10,
    parser_unexpected_method = 11,
    parser_unexpected_buffer_end = 12,
    parser_unexpected_value = 13,
    parser_unexpected_number_items = 14,
    parser_unexpected_number_fields = 15,
    parser_unexpected_characters = 16,
    parser_unexpected_field = 17,
    parser_unexpected_field_offset = 18,
    parser_value_out_of_range = 19,
    parser_invalid_address = 20,
    // Context related errors
    parser_context_mismatch = 21,
    parser_context_unexpected_size = 22,
    parser_context_invalid_chars = 23,
    parser_context_unknown_prefix = 24,
    // Required fields
    parser_required_nonce = 25,
    parser_required_method = 26,
    // Casper specific
    parser_runtimearg_notfound = 27,
    parser_invalid_stored_contract = 28,
    parser_wasm_too_large = 29,
} parser_error_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t bufferSize;
    uint16_t offset;
    void *tx_obj;  // Can be either parser_tx_deploy_t or parser_tx_txnV1_t
    transaction_content_e tx_content;
    uint8_t txnV1_hash[BLAKE2B_256_SIZE];
    bool isStreaming;
} parser_context_t;

#ifdef __cplusplus
}
#endif
