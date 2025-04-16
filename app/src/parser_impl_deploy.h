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

#include "crypto.h"
#include "parser_common.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

extern parser_tx_deploy_t parser_tx_obj_deploy;

parser_error_t parser_read_deploy(parser_context_t *ctx, parser_tx_deploy_t *v);

parser_error_t _validateTxDeploy(const parser_context_t *c, const parser_tx_deploy_t *v);

uint8_t _getNumItemsDeploy(const parser_context_t *c, const parser_tx_deploy_t *v);

parser_error_t index_headerpart_deploy(parser_header_deploy_t head, header_part_e part, parser_context_t *ctx);

uint16_t header_length_deploy(parser_header_deploy_t header);

parser_error_t readU32(parser_context_t *ctx, uint32_t *result);

parser_error_t readU64(parser_context_t *ctx, uint64_t *result);

parser_error_t readU8(parser_context_t *ctx, uint8_t *result);

parser_error_t parse_item(parser_context_t *ctx);

parser_error_t get_type(parser_context_t *ctx, uint8_t *runtime_type, uint8_t *option_type);

parser_error_t check_fixed_items(deploy_type_e type, char *buffer, bool *result);

parser_error_t copy_item_into_charbuffer(parser_context_t *ctx, char *buffer, uint16_t bufferLen);

parser_error_t parse_version(parser_context_t *ctx, uint32_t *version);

parser_error_t parseDeployType(uint8_t type, deploy_type_e *deploytype);

parser_error_t parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item);

parser_error_t _getItemDeploy(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
