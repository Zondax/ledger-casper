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

#include "parser.h"
#include "parser_txdef.h"
#include "parser_utils.h"

extern parser_tx_txnV1_t parser_tx_obj_txnV1;

uint16_t header_length_txnV1(parser_header_txnV1_t header);
parser_error_t index_headerpart_txnV1(parser_header_txnV1_t head,
                                      header_part_e part, uint16_t *index);
parser_error_t parser_read_transactionV1(parser_context_t *ctx,
                                         parser_tx_txnV1_t *v);
parser_error_t _validateTxV1(const parser_context_t *c,
                             const parser_tx_txnV1_t *v);
uint8_t _getNumItemsTxV1(__Z_UNUSED const parser_context_t *c,
                         const parser_tx_txnV1_t *v);
parser_error_t _getItemTxV1(parser_context_t *ctx, uint8_t displayIdx,
                            char *outKey, uint16_t outKeyLen, char *outVal,
                            uint16_t outValLen, uint8_t pageIdx,
                            uint8_t *pageCount);

parser_error_t readU8(parser_context_t *ctx, uint8_t *result);
parser_error_t readU16(parser_context_t *ctx, uint16_t *result);
parser_error_t readU32(parser_context_t *ctx, uint32_t *result);
parser_error_t readU64(parser_context_t *ctx, uint64_t *result);