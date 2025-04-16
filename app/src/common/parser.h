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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "parser_impl_deploy.h"
#include "parser_message.h"
#include "parser_wasm.h"

const char *parser_getErrorDescription(parser_error_t err);

//// parses a tx buffer
parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, size_t bufferSize);

//// verifies tx fields
parser_error_t parser_validate(const parser_context_t *ctx);

//// returns the number of items in the current parsing context
parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items);

// retrieves a readable output for each field / page
parser_error_t parser_getItem(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parse_TTL(uint64_t value, char *buffer, uint16_t bufferSize);

parser_error_t parser_runtimeargs_getData(const char *keystr, uint32_t *length, uint8_t *runtype, uint32_t num_items,
                                          parser_context_t *ctx);

parser_error_t parser_display_runtimeArg(uint8_t type, uint32_t dataLen, parser_context_t *ctx, char *outVal,
                                         uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parser_display_runtimeArgMotes(uint8_t type, uint32_t dataLen, parser_context_t *ctx, char *outVal,
                                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parser_printBytes(const uint8_t *bytes, uint16_t byteLength, char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parser_printU64(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

// as amount and fee can be now of type u64, u32 and u512,
// lets generalize it here, we have a render function for u512,
parser_error_t parser_display_motesQuantity(uint8_t type, uint32_t dataLen, parser_context_t *ctx, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
