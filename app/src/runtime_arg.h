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

#include <stdbool.h>
#include "parser_common.h"
#include "parser_txdef.h"

// defines for the runtime_arg types
#define TAG_BOOL 0
#define TAG_I32 1
#define TAG_I64 2
#define TAG_U8 3
#define TAG_U32 4
#define TAG_U64 5
#define TAG_U128 6
#define TAG_U256 7
#define TAG_U512 8
#define TAG_UNIT 9
#define TAG_STRING 10
#define TAG_KEY 11
#define TAG_UREF 12
#define TAG_OPTION 13
#define TAG_LIST 14
#define TAG_BYTE_ARRAY 15
#define TAG_RESULT 16
#define TAG_MAP 17
#define TAG_TUPLE1 18
#define TAG_TUPLE2 19
#define TAG_TUPLE3 20
#define TAG_ANY 21
#define TAG_PUBLIC_KEY 22

parser_error_t parseRuntimeArgs(parser_context_t *ctx, uint32_t deploy_argLen);

parser_error_t searchRuntimeArgs(const char *argstr, uint8_t *type, uint8_t *internal_type, uint32_t deploy_argLen, parser_context_t *ctx);

parser_error_t showRuntimeArgsHash(ExecutableDeployItem item, parser_context_t *ctx,
                                          uint32_t bytes_len, const char *name, uint8_t name_len,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount);

parser_error_t showRuntimeArgByIndex(uint16_t index, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
        uint16_t pageIdx, uint8_t *pageCount, uint32_t num_items, parser_context_t *ctx);


