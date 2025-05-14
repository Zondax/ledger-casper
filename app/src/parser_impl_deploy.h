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

/**
 * Global instance of the deploy being processed
 */
extern parser_tx_deploy_t parser_tx_obj_deploy;

/**
 * Parses a Casper deploy from the provided context
 * @param[in] ctx Parser context that contains the transaction buffer
 * @param[out] v Pointer to the transaction data structure to be filled
 * @return Error code indicating parsing success or failure
 */
parser_error_t parser_read_deploy(parser_context_t *ctx, parser_tx_deploy_t *v);

/**
 * Validates the correctness of a parsed deploy transaction
 * @param[in] c Parser context containing the transaction buffer
 * @param[in] v Pointer to the parsed transaction data
 * @return Error code indicating validation success or failure
 */
parser_error_t _validateTxDeploy(const parser_context_t *c, const parser_tx_deploy_t *v);

/**
 * Returns the number of items to display for a deploy transaction
 * @param[in] c Parser context containing the transaction buffer
 * @param[in] v Pointer to the parsed transaction data
 * @return Number of items to display
 */
uint8_t _getNumItemsDeploy(const parser_context_t *c, const parser_tx_deploy_t *v);

/**
 * Updates the context offset to point to a specific part of the deploy header
 * @param[in] head Deploy header data structure
 * @param[in] part Specific part of the header to index
 * @param[out] ctx Parser context to update
 * @return Error code indicating success or failure
 */
parser_error_t index_headerpart_deploy(parser_header_deploy_t head, header_part_e part, parser_context_t *ctx);

/**
 * Calculates the total length of a deploy header
 * @param[in] header Deploy header data structure
 * @return Length of the deploy header in bytes
 */
uint16_t header_length_deploy(parser_header_deploy_t header);

/**
 * Reads a 32-bit unsigned integer from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] result Pointer to store the read value
 * @return Error code indicating success or failure
 */
parser_error_t readU32(parser_context_t *ctx, uint32_t *result);

/**
 * Reads a 64-bit unsigned integer from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] result Pointer to store the read value
 * @return Error code indicating success or failure
 */
parser_error_t readU64(parser_context_t *ctx, uint64_t *result);

/**
 * Reads an 8-bit unsigned integer from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] result Pointer to store the read value
 * @return Error code indicating success or failure
 */
parser_error_t readU8(parser_context_t *ctx, uint8_t *result);

/**
 * Parses an item from the parser context, skipping its contents
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @return Error code indicating success or failure
 */
parser_error_t parse_item(parser_context_t *ctx);

/**
 * Extracts runtime and option types from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] runtime_type Type of the runtime argument
 * @param[out] option_type Type contained within an option (if applicable)
 * @return Error code indicating success or failure
 */
parser_error_t get_type(parser_context_t *ctx, uint8_t *runtime_type, uint8_t *option_type);

/**
 * Checks if deploy type has fixed display items
 * @param[in] type Deploy type to check
 * @param[out] buffer Buffer to use for temporary storage
 * @param[out] result Set to true if deploy type has fixed items
 * @return Error code indicating success or failure
 */
parser_error_t check_fixed_items(deploy_type_e type, char *buffer, bool *result);

/**
 * Copies an item from the parser context into a character buffer
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] buffer Buffer to copy the item into
 * @param[in] bufferLen Maximum length of the buffer
 * @return Error code indicating success or failure
 */
parser_error_t copy_item_into_charbuffer(parser_context_t *ctx, char *buffer, uint16_t bufferLen);

/**
 * Parses a version field from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] version Pointer to store the parsed version
 * @return Error code indicating success or failure
 */
parser_error_t parse_version(parser_context_t *ctx, uint32_t *version);

/**
 * Parses deploy type from a byte value
 * @param[in] type Byte value representing deploy type
 * @param[out] deploytype Enum value of the deploy type
 * @return Error code indicating success or failure
 */
parser_error_t parseDeployType(uint8_t type, deploy_type_e *deploytype);

/**
 * Parses a deploy item from the parser context
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[out] item Pointer to store the parsed deploy item
 * @return Error code indicating success or failure
 */
parser_error_t parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item);

/**
 * Gets a specific display item from a deploy transaction
 * @param[in,out] ctx Parser context containing buffer and current offset
 * @param[in] displayIdx Index of the item to display
 * @param[out] outKey Buffer to store the item's key
 * @param[in] outKeyLen Maximum length of the key buffer
 * @param[out] outVal Buffer to store the item's value
 * @param[in] outValLen Maximum length of the value buffer
 * @param[in] pageIdx Index of the page to display (for multi-page values)
 * @param[out] pageCount Pointer to store the total number of pages
 * @return Error code indicating success or failure
 */
parser_error_t _getItemDeploy(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
