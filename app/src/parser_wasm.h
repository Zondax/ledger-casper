/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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

#include "parser_common.h"

parser_error_t parser_parse_wasm(parser_context_t *ctx, const uint8_t *data, size_t dataLen, size_t bufferSize);
parser_error_t parser_validate_wasm(const parser_context_t *ctx, const parser_tx_deploy_t *v);

parser_error_t parser_getWasmNumItems(uint8_t *num_items);
parser_error_t parser_getWasmItem(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
