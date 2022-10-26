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

// offset to the entrypoint for retrival during the getItem stage
extern uint16_t entry_point_offset;

parser_error_t parseSystemPayment(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items);

parser_error_t parseNativeTransfer(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items);

parser_error_t parseDelegation(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items, bool redelegation);

parser_error_t parser_getItem_SystemPayment(ExecutableDeployItem item, parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parser_getItem_NativeTransfer(ExecutableDeployItem item, parser_context_t *ctx,
                                             uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parser_getItem_Delegation(ExecutableDeployItem *item, parser_context_t *ctx,
                                         uint8_t displayIdx,
                                         char *outKey, uint16_t outKeyLen,
                                         char *outVal, uint16_t outValLen,
                                         uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parseAuction(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items);
