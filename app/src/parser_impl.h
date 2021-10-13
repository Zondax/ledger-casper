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

#include "parser_common.h"
#include "parser_txdef.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

extern parser_tx_t parser_tx_obj;

typedef enum {
    tag_bool = 0,
    tag_i32 = 1,
    tag_i64 = 2,
    tag_u8 = 3,
    tag_u32 = 4,
    tag_u64 = 5,
    tag_u128 = 6,
    tag_u256 = 7,
    tag_u512 = 8,
    tag_unit = 9,
    tag_string = 10,
    tag_key = 11,
    tag_uref = 12,
    tag_option = 13,
    tag_list = 14,
    tag_byte_array = 15,
    tag_result = 16,
    tag_map = 17,
    tag_tuple1 = 18,
    tag_tuple2 = 19,
    tag_tuple3 = 20,
    tag_any = 21,
    tag_public_key = 22,
    tag_unknown = 255,
} runtime_type_e;

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize);

parser_error_t _read(parser_context_t *c, parser_tx_t *v);

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v);

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v);

parser_error_t index_headerpart(parser_header_t head, header_part_e part, uint16_t *index);

uint16_t headerLength(parser_header_t header);

parser_error_t readU32(parser_context_t *ctx, uint32_t *result);

parser_error_t readU64(parser_context_t *ctx, uint64_t *result);

parser_error_t readU8(parser_context_t *ctx, uint8_t *result);

parser_error_t parse_item(parser_context_t *ctx);

parser_error_t get_type(parser_context_t *ctx, runtime_type_e *runtime_type, runtime_type_e *option_type);

parser_error_t check_fixed_items(deploy_type_e type, char *buffer, bool *result);

parser_error_t copy_item_into_charbuffer(parser_context_t *ctx, char *buffer, uint16_t bufferLen);

parser_error_t parse_version(parser_context_t *ctx, uint32_t *version);

#ifdef __cplusplus
}
#endif
