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

#include "parser_special.h"
#include "parser_impl.h"
#include "parser_common.h"
#include "parser_txdef.h"

#include "app_mode.h"

parser_error_t searchRuntimeArgs(char *argstr, uint8_t *type, uint8_t *internal_type, uint32_t deploy_argLen, parser_context_t *ctx) {
    uint16_t start = ctx->offset;
    char buffer[300];
    uint8_t dummy_type = 0;
    uint8_t dummy_internal = 0;
    for (uint32_t i = 0; i < deploy_argLen; i++) {
        //key
        CHECK_PARSER_ERR(copy_key_into_buffer(ctx, buffer, sizeof(buffer)));
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
    return parser_runtimearg_notfound;
}

#define CHECK_RUNTIME_ARGTYPE(CTX, NUM_ITEMS, STR, CONDITION) { \
    type = 255;                     \
    internal_type = 255;                                           \
    CHECK_PARSER_ERR(searchRuntimeArgs((STR), &type, &internal_type, (NUM_ITEMS), (CTX)));          \
    PARSER_ASSERT_OR_ERROR((CONDITION), parser_unexpected_type);                                      \
}

parser_error_t parseNativeTransfer(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items) {
    PARSER_ASSERT_OR_ERROR(3 <= num_items && num_items <= 4, parser_unexpected_number_items);
    uint8_t type = 0;
    uint8_t internal_type = 0;
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "amount", type == 8);
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "id", type == 13 && internal_type == 5);
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "target", type == 11 || type == 12 || type == 15);
    if(num_items == 4){
        CHECK_RUNTIME_ARGTYPE(ctx, num_items, "source", type == 13 && internal_type == 12);
    }
    if(app_mode_expert()){
        item->UI_runtime_items += num_items;
    }else{
        item->UI_runtime_items += 2; //amount and target only
    }
    return parser_ok;
}

parser_error_t parseSystemPayment(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items){

    PARSER_ASSERT_OR_ERROR(num_items == 1, parser_unexpected_number_items);

    uint8_t type = 0;
    uint8_t internal_type = 0;
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "amount", type == 8);
    item->UI_runtime_items += 1; //amount only
    return parser_ok;
}