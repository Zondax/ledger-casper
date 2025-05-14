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

#include "common/parser.h"
#include "parser_txdef.h"
#include "parser_utils.h"

/**
 * Global object that holds the parsed TransactionV1 data.
 * This is a common reference used by various functions for accessing transaction data.
 */
extern parser_tx_txnV1_t parser_tx_obj_txnV1;

/**
 * Indexes to a specific part of the transaction header for direct access.
 * 
 * @param[in] head The transaction header
 * @param[in] part Specific header part to index
 * @param[out] ctx Context with offset set to the specified header part
 * @return Error code indicating success or type of failure
 */
parser_error_t index_headerpart_txnV1(parser_header_txnV1_t head, header_part_e part, parser_context_t *ctx);

/**
 * Parses a Casper transaction (TransactionV1) from binary data.
 * 
 * @param[in] ctx Parser context containing binary data buffer
 * @param[out] v Pointer to structure that will hold the parsed transaction
 * @return Error code indicating success or type of failure
 */
parser_error_t parser_read_transactionV1(parser_context_t *ctx, parser_tx_txnV1_t *v);

/**
 * Validates a parsed transaction for correctness and consistency.
 * 
 * @param[in] c Context that was used to parse the transaction
 * @param[in] v Parsed transaction to validate
 * @return Error code indicating success or validation failure
 */
parser_error_t _validateTxV1(const parser_context_t *c, const parser_tx_txnV1_t *v);

/**
 * Returns the number of UI items to display for this transaction.
 * 
 * @param[in] c Context that was used to parse the transaction
 * @param[in] v Parsed transaction to count items for
 * @return Number of UI display items
 */
uint8_t _getNumItemsTxV1(__Z_UNUSED const parser_context_t *c, const parser_tx_txnV1_t *v);

/**
 * Gets a specific display item from the transaction for UI rendering.
 * 
 * @param[in] ctx Context that was used to parse the transaction
 * @param[in] displayIdx Index of the item to retrieve
 * @param[out] outKey Buffer to receive the item's key
 * @param[in] outKeyLen Maximum length of the key buffer
 * @param[out] outVal Buffer to receive the item's value
 * @param[in] outValLen Maximum length of the value buffer
 * @param[in] pageIdx For paginated output, the page index to retrieve
 * @param[out] pageCount Total number of pages for this item
 * @return Error code indicating success or failure
 */
parser_error_t _getItemTxV1(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                            uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

/**
 * Reads an 8-bit unsigned integer from the binary buffer.
 * 
 * @param[in,out] ctx Parser context with buffer and current offset
 * @param[out] result The read 8-bit value
 * @return Error code indicating success or failure
 */
parser_error_t readU8(parser_context_t *ctx, uint8_t *result);

/**
 * Reads a 16-bit unsigned integer from the binary buffer.
 * 
 * @param[in,out] ctx Parser context with buffer and current offset
 * @param[out] result The read 16-bit value
 * @return Error code indicating success or failure
 */
parser_error_t readU16(parser_context_t *ctx, uint16_t *result);

/**
 * Reads a 32-bit unsigned integer from the binary buffer.
 * 
 * @param[in,out] ctx Parser context with buffer and current offset
 * @param[out] result The read 32-bit value
 * @return Error code indicating success or failure
 */
parser_error_t readU32(parser_context_t *ctx, uint32_t *result);

/**
 * Reads a 64-bit unsigned integer from the binary buffer.
 * 
 * @param[in,out] ctx Parser context with buffer and current offset
 * @param[out] result The read 64-bit value
 * @return Error code indicating success or failure
 */
parser_error_t readU64(parser_context_t *ctx, uint64_t *result);