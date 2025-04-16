/*******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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
#include "parser_message.h"

#include "app_mode.h"
#include "common/parser.h"
#include "parser_impl_deploy.h"
#include "parser_utils.h"
#include "zxformat.h"

static const char messagePrefix[] = "Casper Message:\n";
#define NEW_LINE_CHAR 0x0a

parser_error_t parser_parse_message(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen, dataLen))

    memset(&parser_tx_obj_deploy, 0, sizeof(parser_tx_obj_deploy));
    ctx->tx_obj = &parser_tx_obj_deploy;

    const uint8_t messagePrefixLen = strlen(messagePrefix);
    if (dataLen < messagePrefixLen) {
        return parser_unexpected_buffer_end;
    }

    // Message prefix must match
    if (memcmp(messagePrefix, data, messagePrefixLen)) {
        return parser_context_unknown_prefix;
    }

    parser_tx_deploy_t *tx_obj = (parser_tx_deploy_t *)ctx->tx_obj;
    tx_obj->type = Message;
    return parser_ok;
}

parser_error_t parser_getMessageNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return parser_unexpected_error;
    }
    *num_items = 1;
    return parser_ok;
}

parser_error_t parser_getMessageItem(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                     char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    if (displayIdx != 0) {
        return parser_display_idx_out_of_range;
    }

    snprintf(outKey, outKeyLen, "Msg hash");

    uint8_t buff[40] = {0};
    if (blake2b_hash((const unsigned char *)ctx->buffer, ctx->bufferLen, buff) != zxerr_ok) {
        return parser_unexpected_error;
    }
    pageStringHex(outVal, outValLen, (const char *)buff, HASH_LENGTH, pageIdx, pageCount);

    return parser_ok;
}
