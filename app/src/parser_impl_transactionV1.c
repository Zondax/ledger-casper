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

#include "parser_impl_transactionV1.h"

#include <zxmacros.h>

#include "app_mode.h"
#include "tx.h"
#include "parser_primitives.h"

#define TAG_SIZE 1

#define INITIATOR_ADDRESS_NUM_FIELDS 2

#define TAG_PRICING_MODE_LIMITED 0x00
#define TAG_PRICING_MODE_FIXED 0x01
#define TAG_PRICING_MODE_PREPAID 0x02

#define TAG_ENUM_IS_PUBLIC_KEY 0x00
#define TAG_ENUM_IS_HASH 0x01

#define TAG_TARGET_NATIVE 0x00
#define TAG_TARGET_STORED 0x01
#define TAG_TARGET_SESSION 0x02

#define TAG_STORED_INVOCABLE_ENTITY 0x00
#define TAG_STORED_INVOCABLE_ENTITY_ALIAS 0x01
#define TAG_STORED_PACKAGE 0x02
#define TAG_STORED_PACKAGE_ALIAS 0x03

#define TAG_SCHEDULING_STANDARD 0x00

#define TAG_RUNTIME_ARGS 0x00
#define TAG_BYTES_REPR 0x01

#define TIMESTAMP_SIZE 8
#define TTL_SIZE 8
#define CHAIN_NAME_LEN_SIZE 4
#define PAYMENT_SIZE 8
#define GAS_PRICE_SIZE 8

#define PRICING_MODE_FIELD_POS 4
#define BODY_FIELD_POS 5

#define NUM_FIELDS_TXV1_BODY 4

#define HASH_FIELD_POS 0
#define PAYLOAD_FIELD_POS 1
#define VALIDATORS_FIELD_POS 2

#define HEADER_FIELD_POS 0

#define PAYLOAD_FIRST_FIELD_OFFSET                                                                                \
    (parser_tx_obj_txnV1.metadata.metadata_size + parser_tx_obj_txnV1.metadata.field_offsets[PAYLOAD_FIELD_POS] + \
     parser_tx_obj_txnV1.payload_metadata.metadata_size)

#define MINIMUM_RUNTIME_ARGS_NATIVE_TRANSFER 2

#define INCR_NUM_ITEMS(v, only_in_expert_mode) \
    {                                          \
        if (only_in_expert_mode) {             \
            if (app_mode_expert()) {           \
                v->numItems++;                 \
            }                                  \
        } else {                               \
            v->numItems++;                     \
        }                                      \
    }

#define INCR_NUM_ITEMS_BY(v, only_in_expert_mode, num) \
    {                                                  \
        if (only_in_expert_mode) {                     \
            if (app_mode_expert()) {                   \
                v->numItems += num;                    \
            }                                          \
        } else {                                       \
            v->numItems += num;                        \
        }                                              \
    }

parser_tx_txnV1_t parser_tx_obj_txnV1;

#define PRICING_MODE_TAG_FIELD_POS 0
#define PRICING_MODE_PAYMENT_FIELD_POS 1
#define PRICING_MODE_GAS_PRICE_FIELD_POS 2
#define PRICING_MODE_ADDITIONAL_FACTOR_FIELD_POS 3

#define TARGET_TAG_FIELD_POS 0
#define TARGET_DATA_FIELD_POS 1

#define ENTRY_POINT_TAG_FIELD_POS 0
#define ENTRY_POINT_DATA_FIELD_POS 1

#define SCHEDULING_TAG_FIELD_POS 0
#define SCHEDULING_DATA_FIELD_POS 1

#define BODY_ARGS_KEY_POS 0
#define BODY_TARGET_KEY_POS 1
#define BODY_ENTRY_POINT_KEY_POS 2
#define BODY_SCHEDULING_KEY_POS 3

#define HEADER_INITIATOR_ADDR_FIELD_POS 0
#define HEADER_TIMESTAMP_FIELD_POS 1
#define HEADER_TTL_FIELD_POS 2
#define HEADER_CHAINNAME_FIELD_POS 3
#define HEADER_PRICING_MODE_FIELD_POS 4

#define FIELD_TAG_POS 0
#define FIELD_DATA_POS 1

static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body_fields(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_initiator_address(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_chain_name(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_pricing_mode(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_args(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_field_key(parser_context_t *ctx, uint16_t expected_key);
static parser_error_t read_target(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_entry_point(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_scheduling(parser_context_t *ctx);
static void entry_point_to_str(entry_point_type_e entry_point_type, char *outVal, uint16_t outValLen);
static parser_error_t parser_getItem_txV1_Custom(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                 uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                 uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_Transfer(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                   uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_pricing_mode(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                  uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                  uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_AddBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                 uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                 uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_WithdrawBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                      uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_Delegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                   uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_Undelegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                     uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_Redelegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                     uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_ActivateBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                      uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_ChangePublicKey(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                          uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                          uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_AddReservations(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                          uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                          uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_CancelReservations(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                             uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                             uint8_t pageIdx, uint8_t *pageCount);
static parser_error_t parser_getItem_txV1_Burn(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount);

static parser_error_t check_sanity_native_transfer(parser_context_t *ctx, parser_tx_txnV1_t *v);

parser_error_t index_headerpart_txnV1(parser_header_txnV1_t header, header_part_e part, parser_context_t *ctx) {
    uint16_t *offset = &ctx->offset;
    uint16_t initial_offset = parser_tx_obj_txnV1.metadata.metadata_size;
    parser_metadata_txnV1_t *txnV1_metadata = &parser_tx_obj_txnV1.metadata;
    parser_metadata_txnV1_t *payload_metadata = &parser_tx_obj_txnV1.payload_metadata;

    initial_offset += txnV1_metadata->field_offsets[PAYLOAD_FIELD_POS];
    initial_offset += payload_metadata->metadata_size;
    initial_offset += header.initiator_address_metadata_size;
    initial_offset += sizeof(uint8_t);  // Tag for initiator_address

    switch (part) {
        case header_initiator_addr:
            *offset = initial_offset;
            break;
        case header_timestamp:
            *offset = initial_offset + header.initiator_address_len;
            break;
        case header_ttl:
            *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE;
            break;
        case header_chainname:
            *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE + TTL_SIZE + CHAIN_NAME_LEN_SIZE;
            break;
        case header_payment:
            *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE + TTL_SIZE + CHAIN_NAME_LEN_SIZE +
                      header.chain_name_len + header.pricing_mode_metadata_size + TAG_SIZE;
            break;
        case header_gasprice:
            *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE + TTL_SIZE + CHAIN_NAME_LEN_SIZE +
                      header.chain_name_len + header.pricing_mode_metadata_size + TAG_SIZE;
            if (header.pricing_mode == PricingModeClassic) {
                *offset += PAYMENT_SIZE;
            }
            break;
        case header_receipt:
            *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE + TTL_SIZE + CHAIN_NAME_LEN_SIZE +
                      header.chain_name_len + header.pricing_mode_metadata_size + TAG_SIZE;
            break;
        default:
            return parser_unexpected_value;
    }

    if (*offset > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    return parser_ok;
}

parser_error_t parser_read_transactionV1(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    if (ctx->buffer == NULL || ctx->bufferLen == 0 || v == NULL) {
        return parser_unexpected_value;
    }

    parser_metadata_txnV1_t *metadata = &v->metadata;
    CHECK_PARSER_ERR(read_metadata(ctx, metadata));

    uint32_t initial_field_offset = metadata->metadata_size;
    uint32_t field_offset = initial_field_offset + metadata->field_offsets[HASH_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_txV1_hash(ctx, v));

    field_offset = initial_field_offset + metadata->field_offsets[PAYLOAD_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_txV1_payload(ctx, v));

    field_offset = initial_field_offset + metadata->field_offsets[VALIDATORS_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_txV1_approvals(ctx, v));

    field_offset = initial_field_offset + metadata->fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    return parser_ok;
}

static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    MEMCPY(v->txnHash, ctx->buffer + ctx->offset, HASH_LENGTH);
    ctx->offset += HASH_LENGTH;

    INCR_NUM_ITEMS(v, false);

    return parser_ok;
}

static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t *metadata = &v->payload_metadata;

    CHECK_PARSER_ERR(read_metadata(ctx, metadata));

    uint32_t initial_field_offset = PAYLOAD_FIRST_FIELD_OFFSET;
    uint32_t field_offset = initial_field_offset + metadata->field_offsets[HEADER_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_txV1_header(ctx, v));

    field_offset = initial_field_offset + metadata->field_offsets[BODY_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_txV1_body(ctx, v));
    field_offset = initial_field_offset + metadata->fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);
    return parser_ok;
}

static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t num_fields = 0;
    CHECK_PARSER_ERR(readU32(ctx, &num_fields));

    v->num_approvals = num_fields;

    for (uint32_t i = 0; i < num_fields; i++) {
        CHECK_PARSER_ERR(read_public_key(ctx));
        CHECK_PARSER_ERR(read_signature(ctx));
    }

    INCR_NUM_ITEMS(v, true);

    return parser_ok;
}

static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t metadata = v->payload_metadata;

    uint32_t initial_field_offset = PAYLOAD_FIRST_FIELD_OFFSET;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[HEADER_INITIATOR_ADDR_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_initiator_address(ctx, v));
    INCR_NUM_ITEMS(v, false);  // Account

    field_offset = initial_field_offset + metadata.field_offsets[HEADER_TIMESTAMP_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint64_t timestamp;
    CHECK_PARSER_ERR(readU64(ctx, &timestamp));
    INCR_NUM_ITEMS(v, true);  // Timestamp

    field_offset = initial_field_offset + metadata.field_offsets[HEADER_TTL_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint64_t ttl;
    CHECK_PARSER_ERR(readU64(ctx, &ttl));
    INCR_NUM_ITEMS(v, true);  // TTL

    field_offset = initial_field_offset + metadata.field_offsets[HEADER_CHAINNAME_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_chain_name(ctx, v));
    INCR_NUM_ITEMS(v, false);  // Chain ID

    field_offset = initial_field_offset + metadata.field_offsets[HEADER_PRICING_MODE_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    CHECK_PARSER_ERR(read_pricing_mode(ctx, v));
    field_offset = initial_field_offset + metadata.field_offsets[BODY_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    INCR_NUM_ITEMS(v, true);  // Payment
    INCR_NUM_ITEMS(v, true);  // Max gs prce

    return parser_ok;
}

static parser_error_t read_initiator_address(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t metadata = {0};
    CHECK_PARSER_ERR(read_metadata(ctx, &metadata));

    uint32_t initial_field_offset = PAYLOAD_FIRST_FIELD_OFFSET + metadata.metadata_size;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[HEADER_INITIATOR_ADDR_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(metadata.num_fields == INITIATOR_ADDRESS_NUM_FIELDS, parser_unexpected_number_fields);

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    v->header.initiator_address_metadata_size = metadata.metadata_size;

    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));
    PARSER_ASSERT_OR_ERROR(tag == TAG_ENUM_IS_PUBLIC_KEY || tag == TAG_ENUM_IS_HASH, parser_unexpected_value);

    field_offset = initial_field_offset + metadata.field_offsets[FIELD_DATA_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint32_t initial_offset = ctx->offset;
    if (tag == TAG_ENUM_IS_PUBLIC_KEY) {
        CHECK_PARSER_ERR(read_public_key(ctx));
    } else if (tag == TAG_ENUM_IS_HASH) {
        CHECK_PARSER_ERR(read_hash(ctx));
    }

    field_offset = initial_field_offset + metadata.fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    v->header.initiator_address_len = ctx->offset - initial_offset;

    return parser_ok;
}

static parser_error_t read_chain_name(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t len = 0;
    CHECK_PARSER_ERR(read_string(ctx, &len));
    v->header.chain_name_len = len;
    return parser_ok;
}

static parser_error_t read_pricing_mode(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t metadata = {0};
    CHECK_PARSER_ERR(read_metadata(ctx, &metadata));

    uint32_t initial_field_offset =
        PAYLOAD_FIRST_FIELD_OFFSET + v->payload_metadata.field_offsets[PRICING_MODE_FIELD_POS] + metadata.metadata_size;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[PRICING_MODE_TAG_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    v->header.pricing_mode_metadata_size = metadata.metadata_size;
    v->header.pricing_mode_items = 2;

    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));

    field_offset = initial_field_offset + metadata.field_offsets[PRICING_MODE_PAYMENT_FIELD_POS];
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint8_t gas_price = 0;

    if (tag == TAG_PRICING_MODE_LIMITED) {
        uint64_t payment_amount;
        CHECK_PARSER_ERR(readU64(ctx, &payment_amount));
        field_offset = initial_field_offset + metadata.field_offsets[PRICING_MODE_GAS_PRICE_FIELD_POS];
        PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

        CHECK_PARSER_ERR(readU8(ctx, &gas_price));
        field_offset = initial_field_offset + metadata.field_offsets[PRICING_MODE_ADDITIONAL_FACTOR_FIELD_POS];
        PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

        uint8_t standard_payment;
        CHECK_PARSER_ERR(readU8(ctx, &standard_payment));
    } else if (tag == TAG_PRICING_MODE_FIXED) {
        CHECK_PARSER_ERR(readU8(ctx, &gas_price));
        field_offset = initial_field_offset + metadata.field_offsets[PRICING_MODE_GAS_PRICE_FIELD_POS];
        PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

        uint8_t additional_computation_factor;
        CHECK_PARSER_ERR(readU8(ctx, &additional_computation_factor));
    } else if (tag == TAG_PRICING_MODE_PREPAID) {
        CHECK_PARSER_ERR(read_hash(ctx));
    } else {
        return parser_unexpected_value;
    }

    field_offset = initial_field_offset + metadata.fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    v->header.pricing_mode = tag;

    return parser_ok;
}

static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    CHECK_PARSER_ERR(read_txV1_body_fields(ctx, v));
    return parser_ok;
}

static parser_error_t read_txV1_body_fields(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t num_fields = 0;
    CHECK_PARSER_ERR(readU32(ctx, &num_fields));

    if (num_fields != NUM_FIELDS_TXV1_BODY) {
        return parser_unexpected_value;
    }

    CHECK_PARSER_ERR(read_field_key(ctx, BODY_ARGS_KEY_POS));
    CHECK_PARSER_ERR(read_args(ctx, v));

    CHECK_PARSER_ERR(read_field_key(ctx, BODY_TARGET_KEY_POS));
    CHECK_PARSER_ERR(read_target(ctx, v));

    CHECK_PARSER_ERR(read_field_key(ctx, BODY_ENTRY_POINT_KEY_POS));
    CHECK_PARSER_ERR(read_entry_point(ctx, v));

    CHECK_PARSER_ERR(read_field_key(ctx, BODY_SCHEDULING_KEY_POS));
    CHECK_PARSER_ERR(read_scheduling(ctx));

    return parser_ok;
}

static parser_error_t read_args(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t vec_len = 0;
    CHECK_PARSER_ERR(readU32(ctx, &vec_len));

    v->runtime_args_len = vec_len;

    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));

    if (tag == TAG_RUNTIME_ARGS) {
        v->args_type = RuntimeArgs;
        CHECK_PARSER_ERR(readU32(ctx, &v->num_runtime_args));

        v->runtime_args_offset = ctx->offset;

        for (uint32_t i = 0; i < v->num_runtime_args; i++) {
            uint32_t name_len = 0;
            CHECK_PARSER_ERR(read_string(ctx, &name_len));
            CHECK_PARSER_ERR(read_clvalue(ctx));
        }
    } else if (tag == TAG_BYTES_REPR) {
        v->args_type = BytesRepr;
        v->runtime_args_offset = ctx->offset + sizeof(uint32_t);
        uint32_t len = 0;
        CHECK_PARSER_ERR(read_bytes(ctx, &len));
        v->runtime_args_len = len;
    } else {
        return parser_unexpected_value;
    }

    return parser_ok;
}

static parser_error_t read_field_key(parser_context_t *ctx, uint16_t expected_key) {
    uint16_t key = 0;
    CHECK_PARSER_ERR(readU16(ctx, &key));
    if (key != expected_key) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

static parser_error_t read_target(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t bytes_len = 0;
    CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

    parser_metadata_txnV1_t metadata = {0};
    CHECK_PARSER_ERR(read_metadata(ctx, &metadata));

    uint32_t initial_field_offset = ctx->offset;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[TARGET_TAG_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint8_t tag_target = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag_target));

    uint32_t len = 0;

    switch (tag_target) {
        case TAG_TARGET_NATIVE:
            field_offset = initial_field_offset + metadata.fields_size;
            PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);
            v->target.type = TargetNative;
            break;
        case TAG_TARGET_STORED:
            field_offset = initial_field_offset + metadata.field_offsets[TARGET_DATA_FIELD_POS];
            PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

            parser_metadata_txnV1_t target_stored_metadata = {0};
            CHECK_PARSER_ERR(read_metadata(ctx, &target_stored_metadata));

            uint8_t tag_stored = 0;
            CHECK_PARSER_ERR(readU8(ctx, &tag_stored));

            INCR_NUM_ITEMS(v, false);  // Execution
            INCR_NUM_ITEMS(v, false);  // Entry-point

            switch (tag_stored) {
                case TAG_STORED_INVOCABLE_ENTITY:
                    v->target.type = TargetStoredByHash;
                    v->target.hash = ctx->buffer + ctx->offset;
                    CHECK_PARSER_ERR(read_entity_address(ctx));
                    INCR_NUM_ITEMS(v, false);  // Address
                    break;
                case TAG_STORED_INVOCABLE_ENTITY_ALIAS:
                    v->target.type = TargetStoredByName;
                    v->target.name = ctx->buffer + ctx->offset + sizeof(uint32_t);
                    CHECK_PARSER_ERR(read_string(ctx, &len));
                    v->target.name_len = len;
                    INCR_NUM_ITEMS(v, false);  // Name
                    break;
                case TAG_STORED_PACKAGE:
                    v->target.type = TargetStoredByPackageHash;
                    v->target.hash = ctx->buffer + ctx->offset;
                    CHECK_PARSER_ERR(read_entity_address(ctx));
                    CHECK_PARSER_ERR(read_entity_version(ctx, &v->target.entity_version));
                    INCR_NUM_ITEMS(v, false);  // Address
                    if (v->target.entity_version != NO_ENTITY_VERSION_PRESENT) {
                        INCR_NUM_ITEMS(v, true);  // Version
                    }
                    break;
                case TAG_STORED_PACKAGE_ALIAS:
                    v->target.type = TargetStoredByPackageName;
                    v->target.name = ctx->buffer + ctx->offset + sizeof(uint32_t);
                    CHECK_PARSER_ERR(read_string(ctx, &len));
                    v->target.name_len = len;
                    CHECK_PARSER_ERR(read_entity_version(ctx, &v->target.entity_version));
                    INCR_NUM_ITEMS(v, false);  // Name
                    if (v->target.entity_version != NO_ENTITY_VERSION_PRESENT) {
                        INCR_NUM_ITEMS(v, true);  // Version
                    }
                    break;
                default:
                    return parser_unexpected_value;
            }

            // Parse runtime
            CHECK_PARSER_ERR(read_runtime(ctx));

            break;
        case TAG_TARGET_SESSION:
            field_offset = initial_field_offset + metadata.field_offsets[TARGET_DATA_FIELD_POS];
            PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

            v->target.type = TargetSession;
            uint8_t is_install_upgrade = 0;
            CHECK_PARSER_ERR(read_bool(ctx, &is_install_upgrade));
            CHECK_PARSER_ERR(read_runtime(ctx));

            uint32_t wasm_len = 0;
            CHECK_PARSER_ERR(readU32(ctx, &wasm_len));
            v->module_bytes_len = wasm_len;

            if (ctx->offset + wasm_len > ctx->bufferSize) {
                // Streaming, we will only show hash
                v->numItems = 1;
                return parser_wasm_too_large;
            }

            ctx->offset += wasm_len;
            return parser_ok;
        default:
            return parser_unexpected_value;
    }

    return parser_ok;
}

static parser_error_t read_entry_point(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t bytes_len = 0;
    CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

    parser_metadata_txnV1_t metadata = {0};
    CHECK_PARSER_ERR(read_metadata(ctx, &metadata));

    uint32_t initial_field_offset = ctx->offset;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[ENTRY_POINT_TAG_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));

    if (tag > (uint8_t)EntryPointBurn) {
        return parser_unexpected_value;
    }

    if (tag == (uint8_t)EntryPointCustom) {
        field_offset = initial_field_offset + metadata.field_offsets[ENTRY_POINT_DATA_FIELD_POS];
        PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

        v->custom_entry_point = ctx->buffer + ctx->offset + sizeof(uint32_t);
        uint32_t len = 0;
        CHECK_PARSER_ERR(read_bytes(ctx, &len));
        v->custom_entry_point_len = len;
    }

    field_offset = initial_field_offset + metadata.fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    v->entry_point_type = tag;

    INCR_NUM_ITEMS(v, false);  // Type

    switch (tag) {
        case EntryPointTransfer:
            if (app_mode_expert()) {
                INCR_NUM_ITEMS_BY(v, true, v->num_runtime_args);
            } else {
                INCR_NUM_ITEMS(v, false);  // Target
                INCR_NUM_ITEMS(v, false);  // Amount
            }
            break;
        case EntryPointAddBid:
            INCR_NUM_ITEMS_BY(v, false, v->num_runtime_args);
            break;
        case EntryPointCustom:
            INCR_NUM_ITEMS(v, false);  // Args hash
            break;
        case EntryPointWithdrawBid:
        case EntryPointDelegate:
        case EntryPointUndelegate:
        case EntryPointRedelegate:
        case EntryPointActivateBid:
        case EntryPointChangePublicKey:
        case EntryPointBurn:
            INCR_NUM_ITEMS_BY(v, false, v->num_runtime_args);
            break;
        case EntryPointAddReservations:
            INCR_NUM_ITEMS(v, false);  // Rsrv len
            INCR_NUM_ITEMS(v, false);  // Rsrv hash
            break;
        case EntryPointCancelReservations:
            INCR_NUM_ITEMS(v, false);  // Validator
            INCR_NUM_ITEMS(v, false);  // Dlgtrs len
            INCR_NUM_ITEMS(v, false);  // Dlgtrs hash
            break;
        default:
            break;
    }

    parser_context_t to_check_ctx = *ctx;
    to_check_ctx.buffer = ctx->buffer;
    to_check_ctx.offset = v->runtime_args_offset;
    CHECK_PARSER_ERR(check_sanity_native_transfer(&to_check_ctx, v));

    return parser_ok;
}

static parser_error_t read_scheduling(parser_context_t *ctx) {
    uint32_t bytes_len = 0;
    CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

    parser_metadata_txnV1_t metadata = {0};
    CHECK_PARSER_ERR(read_metadata(ctx, &metadata));

    uint32_t initial_field_offset = ctx->offset;
    uint32_t field_offset = initial_field_offset + metadata.field_offsets[SCHEDULING_TAG_FIELD_POS];

    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));

    switch (tag) {
        case TAG_SCHEDULING_STANDARD:
            break;
        default:
            return parser_unexpected_value;
    }

    field_offset = initial_field_offset + metadata.fields_size;
    PARSER_ASSERT_OR_ERROR(ctx->offset == field_offset, parser_unexpected_field_offset);

    return parser_ok;
}

parser_error_t _validateTxV1(const parser_context_t *ctx, const parser_tx_txnV1_t *v) {
    uint8_t txnHash[BLAKE2B_256_SIZE] = {0};
    if (tx_isStreaming()) {
        MEMCPY(txnHash, tx_get_incremental_hash(), BLAKE2B_256_SIZE);
    } else {
        const uint8_t *pPayload = ctx->buffer + v->metadata.metadata_size + v->metadata.field_offsets[PAYLOAD_FIELD_POS];
        uint32_t payload_size = v->payload_metadata.metadata_size + v->payload_metadata.fields_size;

        if (blake2b_hash(pPayload, payload_size, txnHash) != zxerr_ok) {
            return parser_unexpected_error;
        }
    }
    PARSER_ASSERT_OR_ERROR(MEMCMP(txnHash, v->txnHash, BLAKE2B_256_SIZE) == 0, parser_context_mismatch);

    return parser_ok;
}

uint8_t _getNumItemsTxV1(__Z_UNUSED const parser_context_t *c, const parser_tx_txnV1_t *v) { return v->numItems; }

static void entry_point_to_str(entry_point_type_e entry_point_type, char *outVal, uint16_t outValLen) {
    switch (entry_point_type) {
        case EntryPointCall:
            snprintf(outVal, outValLen, "Call");
            break;
        case EntryPointCustom:
            snprintf(outVal, outValLen, "Contract Execution");
            break;
        case EntryPointTransfer:
            snprintf(outVal, outValLen, "Transfer");
            break;
        case EntryPointAddBid:
            snprintf(outVal, outValLen, "Add Bid");
            break;
        case EntryPointWithdrawBid:
            snprintf(outVal, outValLen, "Withdraw Bid");
            break;
        case EntryPointDelegate:
            snprintf(outVal, outValLen, "Delegate");
            break;
        case EntryPointUndelegate:
            snprintf(outVal, outValLen, "Undelegate");
            break;
        case EntryPointRedelegate:
            snprintf(outVal, outValLen, "Redelegate");
            break;
        case EntryPointActivateBid:
            snprintf(outVal, outValLen, "Activate Bid");
            break;
        case EntryPointChangePublicKey:
            snprintf(outVal, outValLen, "Change Bid PK");
            break;
        case EntryPointAddReservations:
            snprintf(outVal, outValLen, "Add Reservations");
            break;
        case EntryPointCancelReservations:
            snprintf(outVal, outValLen, "Cancel Reservations");
            break;
        case EntryPointBurn:
            snprintf(outVal, outValLen, "Burn");
            break;
        default:
            snprintf(outVal, outValLen, "Unknown");
    }
}

parser_error_t _getItemTxV1(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                            uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx >= numItems) {
        return parser_no_data;
    }

    parser_tx_txnV1_t parser_tx_obj = *(parser_tx_txnV1_t *)ctx->tx_obj;

    uint16_t runtime_args_to_show;

    if (app_mode_expert()) {
        runtime_args_to_show = numItems - 9;
    } else {
        runtime_args_to_show = numItems - (2 + parser_tx_obj.header.pricing_mode_items);
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Txn hash");
        ctx->offset = parser_tx_obj.metadata.metadata_size + parser_tx_obj.metadata.field_offsets[HASH_FIELD_POS];
        return parser_printBytes((const uint8_t *)(ctx->buffer + ctx->offset), HASH_LENGTH, outVal, outValLen, pageIdx,
                                 pageCount);
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Type");
        char tmpBuf[50] = {0};
        entry_point_to_str(parser_tx_obj.entry_point_type, tmpBuf, sizeof(tmpBuf));
        snprintf(outVal, outValLen, "%s", tmpBuf);
        return parser_ok;
    }

    if (displayIdx == 2) {
        CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_chainname, ctx));
        DISPLAY_STRING("Chain ID", ctx->buffer + ctx->offset, parser_tx_obj.header.chain_name_len)
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Account");
        CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_initiator_addr, ctx));
        return parser_printBytes((const uint8_t *)(ctx->buffer + ctx->offset),
                                 parser_tx_obj.header.initiator_address_len, outVal, outValLen, pageIdx, pageCount);
    }

    if (app_mode_expert()) {
        if (displayIdx == 4) {
            DISPLAY_HEADER_TIMESTAMP("Timestamp", header_timestamp, txnV1)
            return parser_ok;
        }

        if (displayIdx == 5) {
            snprintf(outKey, outKeyLen, "Ttl");
            CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_ttl, ctx));
            uint64_t value = 0;
            CHECK_PARSER_ERR(readU64(ctx, &value));
            value /= 1000;
            char buffer[100] = {0};
            CHECK_PARSER_ERR(parse_TTL(value, buffer, sizeof(buffer)));
            pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx < (6 + parser_tx_obj.header.pricing_mode_items)) {
            parser_getItem_pricing_mode(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            return parser_ok;
        }
    } else {
        displayIdx += 2 + parser_tx_obj.header.pricing_mode_items;
    }

    if ((displayIdx >= 8) && (displayIdx < (8 + runtime_args_to_show))) {
        ctx->offset = parser_tx_obj.runtime_args_offset;
        switch (parser_tx_obj.entry_point_type) {
            case EntryPointCall:
                break;
            case EntryPointCustom:
                return parser_getItem_txV1_Custom(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                  pageCount);
            case EntryPointTransfer:
                return parser_getItem_txV1_Transfer(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                    pageCount);
            case EntryPointAddBid:
                return parser_getItem_txV1_AddBid(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                  pageCount);
            case EntryPointWithdrawBid:
                return parser_getItem_txV1_WithdrawBid(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                       pageCount);
            case EntryPointDelegate:
                return parser_getItem_txV1_Delegate(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                    pageCount);
            case EntryPointUndelegate:
                return parser_getItem_txV1_Undelegate(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                      pageCount);
            case EntryPointRedelegate:
                return parser_getItem_txV1_Redelegate(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                      pageCount);
            case EntryPointActivateBid:
                return parser_getItem_txV1_ActivateBid(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                       pageCount);
            case EntryPointChangePublicKey:
                return parser_getItem_txV1_ChangePublicKey(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                                                           pageIdx, pageCount);
            case EntryPointAddReservations:
                return parser_getItem_txV1_AddReservations(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                                                           pageIdx, pageCount);
            case EntryPointCancelReservations:
                return parser_getItem_txV1_CancelReservations(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                                                              pageIdx, pageCount);
            case EntryPointBurn:
                return parser_getItem_txV1_Burn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                pageCount);
            default:
                break;
        }
    }

    if ((displayIdx >= 8 + runtime_args_to_show) && app_mode_expert()) {
        snprintf(outKey, outKeyLen, "Approvals #");
        snprintf(outVal, outValLen, "%d", parser_tx_obj.num_approvals);
        return parser_ok;
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_Custom(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                 uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                 uint8_t *pageCount) {
    uint32_t custom_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.numItems;
    num_items -= app_mode_expert() ? 9 : 4;

    if (custom_display_idx >= num_items) {
        return parser_no_data;
    }

    switch (parser_tx_obj_txnV1.target.type) {
        case TargetNative:
        case TargetSession:
            break;
        case TargetStoredByHash:
            if (custom_display_idx == 0) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-hash");
                return parser_ok;
            } else if (custom_display_idx == 1) {
                snprintf(outKey, outKeyLen, "Address");
                return parser_printByHashAddress(parser_tx_obj_txnV1.target.hash, HASH_LENGTH, outVal, outValLen,
                                                 pageIdx, pageCount);
            } else if (custom_display_idx == 2) {
                snprintf(outKey, outKeyLen, "Entry-point");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.custom_entry_point_len,
                         parser_tx_obj_txnV1.custom_entry_point);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            }
            break;
        case TargetStoredByName:
            if (custom_display_idx == 0) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-name");
                return parser_ok;
            } else if (custom_display_idx == 1) {
                snprintf(outKey, outKeyLen, "Name");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.target.name_len,
                         parser_tx_obj_txnV1.target.name);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            } else if (custom_display_idx == 2) {
                snprintf(outKey, outKeyLen, "Entry-point");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.custom_entry_point_len,
                         parser_tx_obj_txnV1.custom_entry_point);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            }
            break;
        case TargetStoredByPackageHash:
            if (custom_display_idx == 0) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-hash-versioned");
                return parser_ok;
            } else if (custom_display_idx == 1) {
                snprintf(outKey, outKeyLen, "Address");
                return parser_printByHashAddress(parser_tx_obj_txnV1.target.hash, HASH_LENGTH, outVal, outValLen,
                                                 pageIdx, pageCount);
            }

            if (app_mode_expert()) {
                if (custom_display_idx == 2) {
                    if (parser_tx_obj_txnV1.target.entity_version != NO_ENTITY_VERSION_PRESENT) {
                        snprintf(outKey, outKeyLen, "Version");
                        parser_printU32(parser_tx_obj_txnV1.target.entity_version, outVal, outValLen, pageIdx,
                                        pageCount);
                    }
                    return parser_ok;
                }
            } else {
                custom_display_idx += 1;
            }

            if (custom_display_idx == 3) {
                snprintf(outKey, outKeyLen, "Entry-point");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.custom_entry_point_len,
                         parser_tx_obj_txnV1.custom_entry_point);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            }
            break;
        case TargetStoredByPackageName:
            if (custom_display_idx == 0) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-name-versioned");
                return parser_ok;
            } else if (custom_display_idx == 1) {
                snprintf(outKey, outKeyLen, "Name");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.target.name_len,
                         parser_tx_obj_txnV1.target.name);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            }

            if (app_mode_expert()) {
                if (custom_display_idx == 2) {
                    if (parser_tx_obj_txnV1.target.entity_version != NO_ENTITY_VERSION_PRESENT) {
                        snprintf(outKey, outKeyLen, "Version");
                        parser_printU32(parser_tx_obj_txnV1.target.entity_version, outVal, outValLen, pageIdx,
                                        pageCount);
                    }
                    return parser_ok;
                }
            } else {
                custom_display_idx += 1;
            }

            if (custom_display_idx == 3) {
                snprintf(outKey, outKeyLen, "Entry-point");
                char tmpBuf[100] = {0};
                snprintf(tmpBuf, sizeof(tmpBuf), "%.*s", parser_tx_obj_txnV1.custom_entry_point_len,
                         parser_tx_obj_txnV1.custom_entry_point);
                pageString(outVal, outValLen, tmpBuf, pageIdx, pageCount);
                return parser_ok;
            }
            break;
    }

    uint8_t args_hash[32] = {0};
    if (parser_tx_obj_txnV1.args_type == RuntimeArgs) {
        blake2b_hash(ctx->buffer + parser_tx_obj_txnV1.runtime_args_offset - 4,
                     parser_tx_obj_txnV1.runtime_args_len - 1, args_hash);
    } else {
        blake2b_hash(ctx->buffer + parser_tx_obj_txnV1.runtime_args_offset, parser_tx_obj_txnV1.runtime_args_len,
                     args_hash);
    }

    snprintf(outKey, outKeyLen, "Args hash");
    return parser_printBytes(args_hash, sizeof(args_hash), outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t parser_getItem_txV1_Transfer(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                   uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t transfer_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;
    parser_context_t initial_ctx = *ctx;

    if (transfer_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (app_mode_expert()) {
        parser_error_t err = parser_runtimeargs_getData("source", &dataLength, &datatype, num_items, ctx);

        if (err == parser_ok && transfer_display_idx == 0) {
            snprintf(outKey, outKeyLen, "From");
            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }

        if (err == parser_no_data) {
            transfer_display_idx += 1;
        }

        *ctx = initial_ctx;

        if (err != parser_ok && err != parser_no_data) {
            return err;
        }
    } else {
        transfer_display_idx += 1;
    }

    if (transfer_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Target");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    } else if (transfer_display_idx == 2) {
        snprintf(outKey, outKeyLen, "Amount");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (app_mode_expert()) {
        if (transfer_display_idx == 3) {
            snprintf(outKey, outKeyLen, "ID");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("id", &dataLength, &datatype, num_items, ctx))

            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_ok;
}

static parser_error_t parser_getItem_pricing_mode(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                  uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                  uint8_t *pageCount) {
    uint8_t pm_display_idx = displayIdx - 6;

    if (pm_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Payment");
        switch (parser_tx_obj_txnV1.header.pricing_mode) {
            case PricingModeClassic:
                CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj_txnV1.header, header_payment, ctx));
                uint64_t value = 0;
                CHECK_PARSER_ERR(readU64(ctx, &value));
                char buffer[20] = {0};
                uint64_to_str(buffer, sizeof(buffer), value);
                char formattedPayment[30] = {0};
                add_thousand_separators(formattedPayment, sizeof(formattedPayment), buffer);
                pageString(outVal, outValLen, formattedPayment, pageIdx, pageCount);
                break;
            case PricingModeFixed:
                snprintf(outVal, outValLen, "Fixed");
                break;
            case PricingModePrepaid:
                snprintf(outVal, outValLen, "Prepaid");
                break;
            default:
                return parser_unexpected_value;
        }
    }

    if (pm_display_idx == 1) {
        switch (parser_tx_obj_txnV1.header.pricing_mode) {
            case PricingModeClassic:
            case PricingModeFixed:
                snprintf(outKey, outKeyLen, "Max gs prce");
                CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj_txnV1.header, header_gasprice, ctx));
                uint64_t value = 0;
                CHECK_PARSER_ERR(readU8(ctx, (uint8_t *)&value));
                char buffer[8] = {0};
                uint64_to_str(buffer, sizeof(buffer), value);
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
                break;
            case PricingModePrepaid:
                snprintf(outKey, outKeyLen, "Receipt");
                CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj_txnV1.header, header_receipt, ctx));
                return parser_printBytes((const uint8_t *)(ctx->buffer + ctx->offset), HASH_LENGTH, outVal, outValLen,
                                         pageIdx, pageCount);
        }
    }

    return parser_ok;
}

parser_error_t parser_getItem_txV1_AddBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t addbid_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

    if (addbid_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (addbid_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Pk");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (addbid_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Deleg. rate");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("delegation_rate", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (addbid_display_idx == 2) {
        snprintf(outKey, outKeyLen, "Amount");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (addbid_display_idx == 3) {
        snprintf(outKey, outKeyLen, "Min. amount");
        CHECK_PARSER_ERR(
            parser_runtimeargs_getData("minimum_delegation_amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (addbid_display_idx == 4) {
        snprintf(outKey, outKeyLen, "Max. amount");
        CHECK_PARSER_ERR(
            parser_runtimeargs_getData("maximum_delegation_amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (addbid_display_idx == 5) {
        snprintf(outKey, outKeyLen, "Rsrvd slots");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("reserved_slots", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

parser_error_t parser_getItem_txV1_WithdrawBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                               uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                               uint8_t *pageCount) {
    uint32_t withdrawbid_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

    if (withdrawbid_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (withdrawbid_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Pk");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (withdrawbid_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Amount");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_Delegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                   uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t delegate_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

    if (delegate_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (delegate_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Delegator");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("delegator", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (delegate_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Validator");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (delegate_display_idx == 2) {
        snprintf(outKey, outKeyLen, "Amount");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_Undelegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                     uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount) {
    return parser_getItem_txV1_Delegate(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t parser_getItem_txV1_Redelegate(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                     uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t redelegate_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;
    parser_context_t initial_ctx = *ctx;

    if (redelegate_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    uint8_t existsDelegator = 0;
    parser_error_t err = parser_runtimeargs_getData("delegator", &dataLength, &datatype, num_items, ctx);
    if (err == parser_ok) {
        existsDelegator = 1;
    } else if (err != parser_no_data) {
        return err;
    }

    *ctx = initial_ctx;

    uint8_t existsOldValidator = 0;
    err = parser_runtimeargs_getData("validator", &dataLength, &datatype, num_items, ctx);
    if (err == parser_ok) {
        existsOldValidator = 1;
    } else if (err != parser_no_data) {
        return err;
    }

    *ctx = initial_ctx;

    uint8_t existsAmount = 0;
    err = parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx);
    if (err == parser_ok) {
        existsAmount = 1;
    } else if (err != parser_no_data) {
        return err;
    }

    *ctx = initial_ctx;

    if (existsDelegator) {
        if (redelegate_display_idx == 0) {
            snprintf(outKey, outKeyLen, "Delegator");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("delegator", &dataLength, &datatype, num_items, ctx))

            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }
    } else {
        redelegate_display_idx += 1;
    }

    if (existsOldValidator) {
        if (redelegate_display_idx == 1) {
            snprintf(outKey, outKeyLen, "Old");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, num_items, ctx))

            return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }
    } else {
        redelegate_display_idx += 1;
    }

    if (redelegate_display_idx == 2) {
        snprintf(outKey, outKeyLen, "New");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("new_validator", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (existsAmount) {
        if (redelegate_display_idx == 3) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))

            return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_ActivateBid(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                      uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t activatebid_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

    if (activatebid_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (activatebid_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Validtr pk");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("validator_public_key", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_ChangePublicKey(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                          uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t chgpk_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

    if (chgpk_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (chgpk_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Pk");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    if (chgpk_display_idx == 1) {
        snprintf(outKey, outKeyLen, "New pk");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("new_public_key", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_AddReservations(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                          uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t addrsv_display_idx = displayIdx - 8;
    uint32_t num_items = 2;

    if (addrsv_display_idx >= num_items) {
        return parser_no_data;
    }
    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    CHECK_PARSER_ERR(parser_runtimeargs_getData("reservations", &dataLength, &datatype, num_items, ctx))

    if (addrsv_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Rsrv len");

        parser_printU32((uint32_t) * (ctx->buffer + ctx->offset), outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    if (addrsv_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Rsrv hash");
        uint8_t rsrv_hash[HASH_LENGTH];
        blake2b_hash(ctx->buffer + ctx->offset, dataLength, rsrv_hash);
        parser_printBytes(rsrv_hash, HASH_LENGTH, outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_CancelReservations(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                             uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                             uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t cancelrsv_display_idx = displayIdx - 8;
    uint32_t num_items = 3;

    if (cancelrsv_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (cancelrsv_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Validator");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, num_items, ctx))

        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }
    if (cancelrsv_display_idx == 1) {
        snprintf(outKey, outKeyLen, "Dlgtrs len");

        CHECK_PARSER_ERR(parser_runtimeargs_getData("delegators", &dataLength, &datatype, num_items, ctx))

        parser_printU32((uint32_t) * (ctx->buffer + ctx->offset), outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    if (cancelrsv_display_idx == 2) {
        snprintf(outKey, outKeyLen, "Dlgtrs hash");

        CHECK_PARSER_ERR(parser_runtimeargs_getData("delegators", &dataLength, &datatype, num_items, ctx))
        uint8_t dlgtrs_hash[HASH_LENGTH];
        blake2b_hash(ctx->buffer + ctx->offset, dataLength, dlgtrs_hash);
        parser_printBytes(dlgtrs_hash, HASH_LENGTH, outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_ok;
}

static parser_error_t parser_getItem_txV1_Burn(parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount) {
    uint32_t burn_display_idx = displayIdx - 8;
    uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;
    parser_context_t initial_ctx = *ctx;

    if (burn_display_idx >= num_items) {
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    parser_error_t err = parser_runtimeargs_getData("source", &dataLength, &datatype, num_items, ctx);

    if (err == parser_ok && burn_display_idx == 0) {
        snprintf(outKey, outKeyLen, "Source");
        return parser_display_runtimeArg(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
    }

    *ctx = initial_ctx;


    snprintf(outKey, outKeyLen, "Amount");
    CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, num_items, ctx))
    return parser_display_runtimeArgMotes(datatype, dataLength, ctx, outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t check_sanity_native_transfer(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (v->entry_point_type != EntryPointCustom) {
        if (v->target.type != TargetNative && v->target.type != TargetSession) {
            return parser_invalid_stored_contract;
        }
    }

    parser_context_t initial_ctx = *ctx;

    switch (v->entry_point_type) {
        case EntryPointTransfer:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, v->num_runtime_args, ctx));
            PARSER_ASSERT_OR_ERROR(datatype == TAG_U512, parser_unexpected_value);
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, v->num_runtime_args, ctx));
            break;
        case EntryPointAddBid:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(
                parser_runtimeargs_getData("delegation_rate", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, v->num_runtime_args, ctx))
            PARSER_ASSERT_OR_ERROR(datatype == TAG_U512, parser_unexpected_value);
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("minimum_delegation_amount", &dataLength, &datatype,
                                                        v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("maximum_delegation_amount", &dataLength, &datatype,
                                                        v->num_runtime_args, ctx))
            break;
        case EntryPointWithdrawBid:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, v->num_runtime_args, ctx))
            PARSER_ASSERT_OR_ERROR(datatype == TAG_U512, parser_unexpected_value);
            break;
        case EntryPointDelegate:
        case EntryPointUndelegate:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("delegator", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, v->num_runtime_args, ctx))
            PARSER_ASSERT_OR_ERROR(datatype == TAG_U512, parser_unexpected_value);
            break;
        case EntryPointRedelegate:
            CHECK_PARSER_ERR(
                parser_runtimeargs_getData("new_validator", &dataLength, &datatype, v->num_runtime_args, ctx))
            break;
        case EntryPointActivateBid:
            CHECK_PARSER_ERR(
                parser_runtimeargs_getData("validator_public_key", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            break;
        case EntryPointChangePublicKey:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("public_key", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(
                parser_runtimeargs_getData("new_public_key", &dataLength, &datatype, v->num_runtime_args, ctx))
            break;
        case EntryPointAddReservations:
            CHECK_PARSER_ERR(
                parser_runtimeargs_getData("reservations", &dataLength, &datatype, v->num_runtime_args, ctx))
            break;
        case EntryPointCancelReservations:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("delegators", &dataLength, &datatype, v->num_runtime_args, ctx))
            break;
        case EntryPointBurn:
            CHECK_PARSER_ERR(parser_runtimeargs_getData("source", &dataLength, &datatype, v->num_runtime_args, ctx))
            *ctx = initial_ctx;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, v->num_runtime_args, ctx))
            PARSER_ASSERT_OR_ERROR(datatype == TAG_U512, parser_unexpected_value);
            break;
        default:
            break;
    }

    return parser_ok;
}
