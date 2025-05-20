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

#include "tx.h"

#include <string.h>

#include "apdu_codes.h"
#include "app_mode.h"
#include "buffering.h"
#include "parser.h"
#include "parser_txdef.h"
#include "zxmacros.h"

#if defined(TARGET_NANOS)
#define RAM_BUFFER_SIZE 384
#define FLASH_BUFFER_SIZE 8192
#else
#define RAM_BUFFER_SIZE 8192
#define FLASH_BUFFER_SIZE 16384
#endif
// Ram
uint8_t ram_buffer[RAM_BUFFER_SIZE];

// Flash
typedef struct {
    uint8_t buffer[FLASH_BUFFER_SIZE];
} storage_t;

#if defined(LEDGER_SPECIFIC)
storage_t NV_CONST N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(NV_VOLATILE storage_t *)PIC(&N_appdata_impl))
#endif

parser_context_t ctx_parsed_tx;
uint32_t bytes_hashed = 0;

static void tx_incremental_hash_reset() {
    MEMZERO(ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE);
    ctx_parsed_tx.isStreaming = false;
    bytes_hashed = 0;
}

uint8_t *tx_get_incremental_hash() {
    return ctx_parsed_tx.txnV1_hash;
}

bool tx_isStreaming() {
    return ctx_parsed_tx.isStreaming;
}

transaction_content_e tx_get_content_type() { return ctx_parsed_tx.tx_content; }
#if defined(LEDGER_SPECIFIC)

void tx_initialize() { 
    buffering_init(ram_buffer, sizeof(ram_buffer), (uint8_t *)N_appdata.buffer, FLASH_BUFFER_SIZE);
    tx_incremental_hash_reset();
}

void tx_reset() { 
    buffering_reset(); 
}

uint32_t tx_append(unsigned char *buffer, uint32_t length) { return buffering_append(buffer, length); }

uint32_t tx_get_buffer_length() { return buffering_get_buffer()->pos; }

uint32_t tx_get_flash_buffer_size() { return buffering_get_flash_buffer()->size; }

uint8_t *tx_get_buffer() { return buffering_get_buffer()->data; }

zxerr_t tx_incrementally_hash_txnV1(hash_chunk_operation_e operation) {
    parser_tx_txnV1_t *txnV1_parser_obj = (parser_tx_txnV1_t *)ctx_parsed_tx.tx_obj;

    if (ctx_parsed_tx.tx_content != TransactionV1) {
        return zxerr_unknown;
    }

    ctx_parsed_tx.isStreaming = true;

    const uint32_t total_bytes_to_hash = txnV1_parser_obj->payload_metadata.metadata_size + txnV1_parser_obj->payload_metadata.fields_size;

    if (operation == hash_start) {
        const uint8_t *pPayload = ctx_parsed_tx.buffer + txnV1_parser_obj->metadata.metadata_size + txnV1_parser_obj->metadata.field_offsets[PAYLOAD_FIELD_POS];
        uint32_t in_len = (uint32_t)(ctx_parsed_tx.buffer + ctx_parsed_tx.bufferLen) - (uint32_t)pPayload;

        // init blake2b context
        zxerr_t err = crypto_hashChunk(NULL, 0, NULL, 0, hash_start);

        if (err != zxerr_ok) {
            return err;
        }

        bytes_hashed += in_len;

        // All the bytes to hash are inside the current buffer
        if (in_len >= total_bytes_to_hash) {
            in_len = total_bytes_to_hash;

            err = crypto_hashChunk(pPayload, in_len, ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE, hash_update);

            if (err != zxerr_ok) {
                return err;
            }

            return crypto_hashChunk(NULL, 0, ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE, hash_finish);
        } else {
            // We will need to keep hashing the next buffer (streaming)
            return crypto_hashChunk(pPayload, in_len, ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE, hash_update);
        }
    } else if (operation == hash_update) {
        if (bytes_hashed == total_bytes_to_hash) {
            return zxerr_ok;
        }

        uint32_t in_len = 0;

        if (bytes_hashed < total_bytes_to_hash) {
            uint32_t remaining_bytes_to_hash = total_bytes_to_hash - bytes_hashed;
            if (remaining_bytes_to_hash > tx_get_buffer_length()) {
                in_len = tx_get_buffer_length();
            } else {
                in_len = remaining_bytes_to_hash;
            }
        }

        bytes_hashed += in_len;
        return crypto_hashChunk(tx_get_buffer(), in_len, ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE, hash_update);
    }

    return crypto_hashChunk(NULL, 0, ctx_parsed_tx.txnV1_hash, BLAKE2B_256_SIZE, hash_finish);
}

const char *tx_parse() {
    uint8_t err = parser_parse(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length(), tx_get_flash_buffer_size());

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    err = parser_validate(&ctx_parsed_tx);

    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    return NULL;
}

const char *tx_validate_incremental_hash() {
    if (!app_mode_blindsign()) {
        return parser_getErrorDescription(parser_blind_sign_required);
    }
    parser_error_t err = parser_validate(&ctx_parsed_tx);
    return (err == parser_ok) ? NULL : parser_getErrorDescription(err);
}

const char *tx_parse_message() {
    const uint8_t err = parser_parse_message(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length());

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    return NULL;
}

zxerr_t tx_getNumItems(uint8_t *num_items) {
    const parser_error_t err = parser_getNumItems(&ctx_parsed_tx, num_items);

    if (err != parser_ok) {
        return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t tx_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                   uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;
    CHECK_ZXERR(tx_getNumItems(&numItems))

    if (displayIdx < 0 || displayIdx > numItems) {
        return zxerr_no_data;
    }

    parser_error_t err =
        parser_getItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range)
        return zxerr_no_data;

    if (err != parser_ok) return zxerr_unknown;

    return zxerr_ok;
}

zxerr_t tx_getMessageNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    const parser_error_t err = parser_getMessageNumItems(num_items);
    if (err != parser_ok) {
        return zxerr_no_data;
    }
    return zxerr_ok;
}

zxerr_t tx_getMessageItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                          uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;
    CHECK_ZXERR(tx_getMessageNumItems(&numItems))

    const parser_error_t err =
        parser_getMessageItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t tx_parse_wasm() {
    const parser_error_t err = parser_parse_wasm(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length(), tx_get_flash_buffer_size());
    return (err == parser_ok) ? zxerr_ok : zxerr_unknown;
}

zxerr_t tx_validate_wasm() {
    const parser_error_t err = parser_validate_wasm(&ctx_parsed_tx, ctx_parsed_tx.tx_obj);
    return (err == parser_ok) ? zxerr_ok : zxerr_unknown;
}

zxerr_t tx_getWasmNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    const parser_error_t err = parser_getWasmNumItems(num_items);
    if (err != parser_ok) {
        return zxerr_no_data;
    }
    return zxerr_ok;
}

zxerr_t tx_getWasmItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                       uint8_t pageIdx, uint8_t *pageCount) {
    const parser_error_t err =
        parser_getWasmItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}
#endif