/*******************************************************************************
 *   (c) 2019 Zondax GmbH
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

#include "common/parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>

#include "app_mode.h"
#include "bignum.h"
#include "coin.h"
#include "crypto.h"
#include "parser_common.h"
#include "parser_impl_deploy.h"
#include "parser_impl_transactionV1.h"
#include "parser_special.h"
#include "parser_utils.h"
#include "runtime_arg.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
// For some reason NanoX requires this function
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    UNUSED(assertion);
    UNUSED(file);
    UNUSED(line);
    UNUSED(function);
    while (1) {
    };
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, size_t bufferSize) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen, bufferSize))

    uint8_t tx_content = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tx_content));
    ctx->tx_content = tx_content;

    // Dirty hack to avoid rewriting deploy's parser
    // We read the first byte, which indicates Deploy or TransactionV1
    // and then we reset the offset to 0 and set the buffer to the rest of the
    // data
    ctx->buffer = ctx->buffer + ctx->offset;
    ctx->bufferLen = ctx->bufferLen - ctx->offset;
    ctx->offset = 0;

    if (ctx->buffer == NULL || ctx->bufferLen == 0) {
        return parser_unexpected_buffer_end;
    }

    if (ctx->tx_content == Deploy) {
        memset(&parser_tx_obj_deploy, 0, sizeof(parser_tx_obj_deploy));
        ctx->tx_obj = &parser_tx_obj_deploy;
        return parser_read_deploy(ctx, (parser_tx_deploy_t *)ctx->tx_obj);
    } else if (ctx->tx_content == TransactionV1) {
        memset(&parser_tx_obj_txnV1, 0, sizeof(parser_tx_obj_txnV1));
        ctx->tx_obj = &parser_tx_obj_txnV1;
        return parser_read_transactionV1(ctx, (parser_tx_txnV1_t *)ctx->tx_obj);
    } else {
        return parser_context_unknown_prefix;
    }
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    if (ctx->tx_content == Deploy) {
        CHECK_PARSER_ERR(_validateTxDeploy(ctx, (parser_tx_deploy_t *)ctx->tx_obj))
    } else if (ctx->tx_content == TransactionV1) {
        CHECK_PARSER_ERR(_validateTxV1(ctx, (parser_tx_txnV1_t *)ctx->tx_obj))
    } else {
        return parser_context_unknown_prefix;
    }

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(
            parser_getItem((parser_context_t *)ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (ctx->tx_content == Deploy) {
        *num_items = _getNumItemsDeploy(ctx, (parser_tx_deploy_t *)ctx->tx_obj);
    } else if (ctx->tx_content == TransactionV1) {
        *num_items = _getNumItemsTxV1(ctx, (parser_tx_txnV1_t *)ctx->tx_obj);
    } else {
        return parser_context_unknown_prefix;
    }
    return parser_ok;
}

parser_error_t find_end_of_number(char *buffer, uint16_t bufferSize, uint16_t *output) {
    uint16_t index = 0;
    *output = 0;
    while (index < bufferSize) {
        if (buffer[index] == 0 && index != 0) {
            *output = index;
            return parser_ok;
        }
        index++;
    }
    return parser_unexpected_buffer_end;
}

parser_error_t inplace_insert_char(char *s, uint16_t sMaxLen, uint16_t pos, char separator) {
    const size_t len = strlen(s);
    if (len >= sMaxLen) {
        return parser_unexpected_buffer_end;
    }

    if (pos > len) {
        return parser_value_out_of_range;
    }

    MEMMOVE(s + pos + 1, s + pos,
            len - pos + 1);  // len-pos+1 because we copy zero terminator
    s[pos] = separator;

    return parser_ok;
}

parser_error_t add_thousands_separators(char *buffer, uint16_t bufferSize, uint16_t *numsize) {
    uint16_t new_size = *numsize;
    uint16_t index = *numsize - 1;
    uint16_t step = 1;
    if (*numsize >= bufferSize) {
        return parser_unexpected_buffer_end;
    }
    MEMZERO(buffer + *numsize, bufferSize - *numsize);
    while (index > 0) {
        if (step % 3 == 0) {
            CHECK_PARSER_ERR(inplace_insert_char(buffer, bufferSize, index, ' '))
            step = 1;
            new_size++;
        } else {
            step++;
        }
        index--;
    }
    *numsize = new_size;
    return parser_ok;
}

__attribute__((noinline)) parser_error_t display_runtimearg_amount_bignum(parser_context_t *ctx, char *buffer, uint16_t bufferSize, uint32_t len, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount)
{                                                                                             
    uint8_t bcdOut[128];                                                                      
    MEMZERO(bcdOut, sizeof(bcdOut));                                                          
    uint16_t bcdOutLen = sizeof(bcdOut);                                                      
    bignumLittleEndian_to_bcd(bcdOut, bcdOutLen, (ctx)->buffer + (ctx)->offset + 1, len-1); 
    MEMZERO(buffer, bufferSize);                                                          
    bool ok = bignumLittleEndian_bcdprint(buffer, bufferSize, bcdOut, bcdOutLen);         
    if (!ok) {                                                                                
        return parser_unexpected_error;                                                       
    }                                                                                         
    uint16_t numsize = 0;                                                                     
    CHECK_PARSER_ERR(find_end_of_number(buffer, bufferSize, &numsize))                    
    CHECK_PARSER_ERR(add_thousands_separators(buffer, bufferSize, &numsize))              
    if (numsize + 6 >= bufferSize) {
        return parser_unexpected_buffer_end;
    }                                                                                        
    MEMCPY(buffer + numsize, (char *)" motes", 6);
    pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
    return parser_ok;                                                                        
}

#define DISPLAY_RUNTIMEARG_AMOUNT_BIGNUM(CTX, LEN)                                                \
    {                                                                                             \
        uint8_t bcdOut[128];                                                                      \
        MEMZERO(bcdOut, sizeof(bcdOut));                                                          \
        uint16_t bcdOutLen = sizeof(bcdOut);                                                      \
        bignumLittleEndian_to_bcd(bcdOut, bcdOutLen, (CTX)->buffer + (CTX)->offset + 1, (LEN)-1); \
        MEMZERO(buffer, sizeof(buffer));                                                          \
        bool ok = bignumLittleEndian_bcdprint(buffer, sizeof(buffer), bcdOut, bcdOutLen);         \
        if (!ok) {                                                                                \
            return parser_unexpected_error;                                                       \
        }                                                                                         \
        uint16_t numsize = 0;                                                                     \
        CHECK_PARSER_ERR(find_end_of_number(buffer, sizeof(buffer), &numsize))                    \
        CHECK_PARSER_ERR(add_thousands_separators(buffer, sizeof(buffer), &numsize))              \
        if (numsize + 6 >= sizeof(buffer)) {                                                      \
            return parser_unexpected_buffer_end;                                                  \
        }                                                                                         \
        MEMCPY(buffer + numsize, (char *)" motes", 6);                                            \
        pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);                        \
        return parser_ok;                                                                         \
    }

// render alternative amounts of type u64, u32
#define DISPLAY_RUNTIMEARG_AMOUNT_INT(VALUE)                                         \
    {                                                                                \
        fpuint64_to_str(buffer, sizeof(buffer), (uint64_t)(VALUE), 0);               \
        uint16_t numsize = 0;                                                        \
        CHECK_PARSER_ERR(find_end_of_number(buffer, sizeof(buffer), &numsize))       \
        CHECK_PARSER_ERR(add_thousands_separators(buffer, sizeof(buffer), &numsize)) \
        if (numsize + 6 >= sizeof(buffer)) {                                         \
            return parser_unexpected_buffer_end;                                     \
        }                                                                            \
        MEMCPY(buffer + numsize, (char *)" motes", 6);                               \
        pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);           \
        return parser_ok;                                                            \
    }

// helper function to render integers with the motes suffix at the end.
parser_error_t parser_display_runtimeArgMotes(uint8_t type, uint32_t dataLen, parser_context_t *ctx, char *outVal,
                                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[300] = {0};
    uint64_t value = 0;
    if (ctx->offset + dataLen >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }
    if (dataLen == 0) {
        return parser_unexpected_error;
    }
    switch (type) {
        case TAG_U32: {
            CHECK_PARSER_ERR(readU32(ctx, (uint32_t *)(&value)));
            DISPLAY_RUNTIMEARG_AMOUNT_INT(value);
        }
        case TAG_U64: {
            CHECK_PARSER_ERR(readU64(ctx, &value));
            DISPLAY_RUNTIMEARG_AMOUNT_INT(value);
        }
        case TAG_U512: {
            return display_runtimearg_amount_bignum(ctx, buffer, sizeof(buffer), dataLen, outVal, outValLen, pageIdx, pageCount);
        }

        default: {
            return parser_unexpected_type;
        }
    }
}

parser_error_t parser_display_runtimeArg(uint8_t type, uint32_t dataLen, parser_context_t *ctx, char *outVal,
                                         uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[300] = {0};
    if (ctx->offset + dataLen >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }
    if (dataLen == 0) {
        return parser_unexpected_error;
    }
    switch (type) {
        case TAG_U8: {
            return display_runtimearg_u8(ctx, outVal, outValLen, pageIdx, pageCount);
        }
        case TAG_U32: {
            return display_runtimearg_u32(ctx, outVal, outValLen, pageIdx, pageCount);
        }
        case TAG_U64: {
            return display_runtimearg_u64(ctx, outVal, outValLen, pageIdx, pageCount);
        }
        case TAG_U512: {
            return display_runtimearg_amount_bignum(ctx, buffer, sizeof(buffer), dataLen, outVal, outValLen, pageIdx, pageCount);
        }

        case TAG_KEY: {
            ctx->offset++;  // skip internal type for key
            return display_runtimearg_bytes(ctx, dataLen - 1, outVal, outValLen, pageIdx, pageCount);
        }

        case TAG_UREF: {
            return display_runtimearg_bytes(ctx, dataLen - 1, outVal, outValLen, pageIdx, pageCount);
        }

        case TAG_OPTION: {
            uint8_t optiontype = 0;
            CHECK_PARSER_ERR(readU8(ctx, &optiontype));
            if (optiontype == 0x00) {
                snprintf(outVal, outValLen, "Null");
                return parser_ok;
            } else {
                type = *(ctx->buffer + ctx->offset + dataLen);
                if (type == TAG_U64) {
                    return display_runtimearg_u64(ctx, outVal, outValLen, pageIdx, pageCount);
                } else if (type == TAG_U32) {
                    return display_runtimearg_u32(ctx, outVal, outValLen, pageIdx, pageCount);
                } else if (type == TAG_UREF) {
                    if (dataLen < 2) return parser_unexpected_value;
                    return display_runtimearg_bytes(ctx, dataLen - 2, outVal, outValLen, pageIdx, pageCount);
                } else {
                    return parser_unexpected_error;
                }
            }
        }

        case TAG_BYTE_ARRAY: {
            return display_runtimearg_bytes(ctx, dataLen, outVal, outValLen, pageIdx, pageCount);
        }

        case TAG_PUBLIC_KEY: {
            uint8_t pubkeyType = *(ctx->buffer + ctx->offset);
            uint16_t pubkeyLen = pubkeyType == 0x01 ? 32 : 33;
            return display_runtimearg_address(ctx, 1 + pubkeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        default: {
            return parser_unexpected_type;
        }
    }
}

parser_error_t parser_runtimeargs_getData(const char *keystr, uint32_t *length, uint8_t *runtype, uint32_t num_items,
                                          parser_context_t *ctx) {
    char buffer[300];
    // loop to the correct index
    uint32_t dataLen = 0;
    uint8_t dummyType = 0;
    uint8_t dummyInternal = 0;

    for (uint32_t index = 0; index < num_items; index++) {
        CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
        if (strcmp(buffer, keystr) == 0) {
            // read value length
            CHECK_PARSER_ERR(readU32(ctx, &dataLen));
            if (dataLen > ctx->bufferLen - ctx->offset) {
                return parser_unexpected_buffer_end;
            }

            // remember start of data
            uint16_t start_data = ctx->offset;
            // write length of data
            *length = dataLen;
            ctx->offset += dataLen;
            // write data type
            CHECK_PARSER_ERR(get_type(ctx, runtype, &dummyInternal));
            // write offset back to start of data
            ctx->offset = start_data;
            return parser_ok;
        }

        CHECK_PARSER_ERR(parse_item(ctx));

        CHECK_PARSER_ERR(get_type(ctx, &dummyType, &dummyInternal));
    }

    return parser_no_data;
}

parser_error_t parser_getItem_Transfer(ExecutableDeployItem item, parser_context_t *ctx, uint8_t displayIdx,
                                       char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                       uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t num_items = 0;
    CHECK_PARSER_ERR(readU32(ctx, &num_items));

    if (item.UI_runtime_items > num_items) {
        return parser_unexpected_number_items;
    }

    uint8_t new_displayIdx = displayIdx - item.UI_fixed_items;

    if (new_displayIdx > item.UI_runtime_items || displayIdx < item.UI_fixed_items) {
        return parser_no_data;
    }
    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (!app_mode_expert()) {
        if (new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Target");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        if (new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        return parser_no_data;
    } else {
        if (new_displayIdx == 0 && item.hasSource) {
            snprintf(outKey, outKeyLen, "From");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("source", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        } else {
            new_displayIdx += 1;
        }

        if (new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Target");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        if (new_displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        if (new_displayIdx == 3 && item.hasId) {
            snprintf(outKey, outKeyLen, "ID");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("id", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        return parser_no_data;
    }
}

parser_error_t parser_getItem_ModuleBytes(ExecutableDeployItem item, parser_context_t *ctx, uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (dataLen > ctx->bufferLen - ctx->offset) {
        return parser_unexpected_buffer_end;
    }
    ctx->offset += dataLen;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));

    uint8_t new_displayIdx = displayIdx - item.UI_fixed_items;
    if (new_displayIdx > item.UI_runtime_items || displayIdx < item.UI_fixed_items) {
        return parser_no_data;
    }
    uint32_t dataLength = 0;
    uint8_t datatype = 255;
    if (new_displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Fee");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, item.UI_runtime_items, ctx))
        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}

parser_error_t parser_getItemDeploy(ExecutableDeployItem item, parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                    uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                    uint8_t *pageCount) {
    ctx->offset++;
    switch (item.type) {
        case ModuleBytes: {
            return parser_getItem_ModuleBytes(item, ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                              pageCount);
        }

        case StoredVersionedContractByHash:
        case StoredContractByHash: {
            return parser_ok;
        }

        case StoredVersionedContractByName:
        case StoredContractByName: {
            return parser_unexpected_method;
        }
        case Transfer: {
            return parser_getItem_Transfer(item, ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                           pageCount);
        }
        default: {
            return parser_context_mismatch;
        }
    }
}

parser_error_t parse_TTL(uint64_t value, char *buffer, uint16_t bufferSize) {
    MEMZERO(buffer, bufferSize);
    if (bufferSize < 23) {  // size needed for: "28days 23hours 59m 59s\0"
        return parser_unexpected_buffer_end;
    }
    uint16_t index = 0;
    uint64_t days = value / (60 * 60 * 24);
    if (days > 28) {
        return parser_unexpected_value;
    };
    if (days == 1) {
        MEMCPY(buffer + index, (char *)"1day", 4);
        index += 4;
    } else if (days > 1) {
        index += fpuint64_to_str(buffer, bufferSize, days, 0);
        MEMCPY(buffer + index, (char *)"days", 4);
        index += 4;
    }
    value %= (60 * 60 * 24);

    uint64_t hours = value / (60 * 60);
    value %= (60 * 60);
    uint64_t minutes = value / (60);
    value %= 60;
    uint64_t seconds = value;
    if (hours > 0) {
        // add space if index > 0
        if (index > 0) {
            MEMCPY(buffer + index, (char *)" ", 1);
            index += 1;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, hours, 0);
        MEMCPY(buffer + index, (char *)"h", 1);
        index += 1;
    }
    if (minutes > 0) {
        // add space if index > 0
        if (index > 0) {
            MEMCPY(buffer + index, (char *)" ", 1);
            index += 1;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, minutes, 0);
        MEMCPY(buffer + index, (char *)"m", 1);
        index += 1;
    }
    if (seconds > 0) {
        // add space if index > 0
        if (index > 0) {
            MEMCPY(buffer + index, (char *)" ", 1);
            index += 1;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, seconds, 0);
        MEMCPY(buffer + index, (char *)"s", 1);
        index += 1;
    }
    buffer[index] = 0;
    return parser_ok;
}

parser_error_t parser_getItem(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (ctx->tx_content == Deploy) {
        return _getItemDeploy(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    } else if (ctx->tx_content == TransactionV1) {
        return _getItemTxV1(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    } else {
        return parser_context_unknown_prefix;
    }
}
