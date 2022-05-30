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

parser_error_t parseRuntimeArgs(parser_context_t *ctx, uint32_t deploy_argLen);

parser_error_t searchRuntimeArgs(char *argstr, uint8_t *type, uint8_t *internal_type, uint32_t deploy_argLen, parser_context_t *ctx);

parser_error_t showRuntimeArgsHash(ExecutableDeployItem item, parser_context_t *ctx,
                                          uint32_t bytes_len, char *name, uint8_t name_len,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount);

parser_error_t showRuntimeArgByIndex(uint16_t index, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
        uint16_t pageIdx, uint8_t *pageCount, uint32_t num_items, parser_context_t *ctx);

