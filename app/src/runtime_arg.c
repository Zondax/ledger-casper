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

#include "runtime_arg.h"
#include "parser_impl.h"
#include "parser_common.h"
#include "parser_txdef.h"
#include "parser.h"
#include "crypto.h"
#include "zxformat.h"

#define MAX_ARGNAME_LEN 100
parser_error_t parseRuntimeArgs(parser_context_t *ctx, uint32_t deploy_argLen) {
    uint8_t dummy_type = 0;
    uint8_t dummy_internal = 0;
    for (uint32_t i = 0; i < deploy_argLen; i++) {
        //key
        CHECK_PARSER_ERR(parse_item(ctx));

        //value
        CHECK_PARSER_ERR(parse_item(ctx));
        //type
        CHECK_PARSER_ERR(get_type(ctx, &dummy_type, &dummy_internal));

    }
    return parser_ok;
}


parser_error_t searchRuntimeArgs(const char *argstr, uint8_t *type, uint8_t *internal_type, uint32_t deploy_argLen, parser_context_t *ctx) {
    uint16_t start = ctx->offset;
    char buffer[300] = {0};
    uint8_t dummy_type = 0;
    uint8_t dummy_internal = 0;

    for (uint32_t i = 0; i < deploy_argLen; ++i) {
        //key
        CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
        if (strcmp(buffer, argstr) == 0) {
              //value
            CHECK_PARSER_ERR(parse_item(ctx));

            CHECK_PARSER_ERR(get_type(ctx, type, internal_type));

            ctx->offset = start;
            return parser_ok;
        }
        //value
        CHECK_PARSER_ERR(parse_item(ctx));

        CHECK_PARSER_ERR(get_type(ctx, &dummy_type, &dummy_internal));
    }

    // runtimarg_notfound is an expected error, so we should
    // set the offset to its original value back for further processing
    ctx->offset = start;
    return parser_runtimearg_notfound;
}

parser_error_t showRuntimeArgsHash(__Z_UNUSED ExecutableDeployItem item, parser_context_t *ctx,
                                          uint32_t bytes_len, const char *name, uint8_t name_len,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {

    uint8_t hash[BLAKE2B_256_SIZE] = {0};
    if (blake2b_hash(ctx->buffer + ctx->offset, bytes_len, hash) != zxerr_ok){
        return parser_unexepected_error;
    };

    snprintf(outKey, outKeyLen, "Args hash");
    MEMZERO(outVal, outValLen);

    // name-hash
    // name + '-' + hex-hash + 'null-terminator'
    uint8_t output[MAX_ARGNAME_LEN] = {0};
    if (name_len >= (MAX_ARGNAME_LEN - 2 * BLAKE2B_256_SIZE - 1)) {
        return parser_value_out_of_range;
    }

    char hex_hash[BLAKE2B_256_SIZE * 2] = {0};
    if (encode_hex((char *)hash, BLAKE2B_256_SIZE, hex_hash, sizeof(hex_hash)) != zxerr_ok) {
        return parser_unexepected_error;
    }

    MEMCPY(output, name, name_len);
    output[name_len] = '-';
    MEMCPY((output + name_len + 1), hex_hash, BLAKE2B_256_SIZE * 2);

    pageString(outVal, outValLen, (char *)output, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t showRuntimeArgByIndex(uint16_t index, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
        uint16_t pageIdx, uint8_t *pageCount, uint32_t num_items, parser_context_t *ctx) {

    uint32_t start = ctx->offset;

    char buffer[300] = {0};

    uint32_t dataLength = 0;
    uint8_t dataType = 0;
    uint8_t dataInternal = 0;

    for (uint32_t i = 0; i < num_items; i++) {
        MEMZERO(buffer, 300);
        CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));

        if (i == index) {
            uint32_t key_len = strlen(buffer);
            if (strcmp(buffer, "id") == 0){
                snprintf(outKey, outKeyLen, "ID");
            } else {
                MEMCPY(outKey, buffer, key_len);
                // convert first character to upper case
                if(is_alphabetic(outKey[0])) {
                    to_uppercase((uint8_t*) &outKey[0]);
                }
            }

            ctx->offset = start;
            CHECK_PARSER_ERR(parser_runtimeargs_getData(buffer, &dataLength, &dataType, num_items, ctx));


            return parser_display_runtimeArg(dataType, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

        CHECK_PARSER_ERR(parse_item(ctx));

        CHECK_PARSER_ERR(get_type(ctx, &dataType, &dataInternal));
    }

    return parser_no_data;
}


