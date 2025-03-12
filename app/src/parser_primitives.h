/*******************************************************************************
 *  (c) 2018-2025 Zondax GmbH
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

#define SERIALIZED_FIELD_INDEX_SIZE 2

parser_error_t read_metadata(parser_context_t *ctx, parser_metadata_txnV1_t *metadata);
parser_error_t read_string(parser_context_t *ctx, uint32_t *outLen);
parser_error_t read_bytes(parser_context_t *ctx, uint32_t *outLen);
parser_error_t read_bool(parser_context_t *ctx, uint8_t *result);
parser_error_t read_entity_version(parser_context_t *ctx, uint32_t *entity_version);
parser_error_t read_runtime(parser_context_t *ctx);
parser_error_t read_entity_address(parser_context_t *ctx);
parser_error_t read_clvalue(parser_context_t *ctx);
parser_error_t read_public_key(parser_context_t *ctx);
parser_error_t read_signature(parser_context_t *ctx);
parser_error_t read_hash(parser_context_t *ctx);