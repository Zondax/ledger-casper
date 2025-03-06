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

#include "parser_primitives.h"
#include "parser_impl_transactionV1.h"
#include "app_mode.h"
#include <zxmacros.h>

#define INITIATOR_ADDRESS_NUM_FIELDS 2

#define TAG_PRICING_MODE_CLASSIC 0x00
#define TAG_PRICING_MODE_FIXED 0x01

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
#define TAG_SCHEDULING_FUTURE_ERA 0x01
#define TAG_SCHEDULING_FUTURE_TIMESTAMP 0x02

#define TAG_RUNTIME_ARGS 0x00
#define TAG_BYTES_REPR 0x01

// TODO: Check if these should be dynamic
#define INITIATOR_ADDRESS_METADATA_SIZE 20
#define PAYLOAD_METADATA_SIZE 44
#define PRICING_MODE_METADATA_SIZE 33

#define TIMESTAMP_SIZE 8
#define TTL_SIZE 8
#define CHAIN_NAME_LEN_SIZE 4
#define PAYMENT_SIZE 8
#define GAS_PRICE_SIZE 8

#define NUM_FIELDS_TXV1_BODY 4

#define INCR_NUM_ITEMS(v, only_in_expert_mode) { \
  if (only_in_expert_mode) { \
    if (app_mode_expert()) { \
      v->numItems++; \
    } \
  } else { \
    v->numItems++; \
  } \
}

#define INCR_NUM_ITEMS_BY(v, only_in_expert_mode, num) { \
  if (only_in_expert_mode) { \
    if (app_mode_expert()) { \
      v->numItems += num; \
    } \
  } else { \
    v->numItems += num; \
  } \
}

// TODO: Remove, debug purpose only
#define PRINT_BUFFER(ctx)                                                      \
  for (int i = 0; i < 60; i++) {                                               \
    printf("%02x ", ctx->buffer[ctx->offset + i]);                             \
  }                                                                            \
  printf("\n");

parser_tx_txnV1_t parser_tx_obj_txnV1;

static parser_error_t read_txV1_hash(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v);
static parser_error_t read_metadata(parser_context_t *ctx,
                                    parser_metadata_txnV1_t *metadata);
static parser_error_t read_txV1_payload_metadata(parser_context_t *ctx,
                                                 parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v);
static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_header(parser_context_t *ctx,
                                       parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body_fields(parser_context_t *ctx,
                                            parser_tx_txnV1_t *v);
static parser_error_t read_initiator_address(parser_context_t *ctx,
                                             parser_tx_txnV1_t *v);
static parser_error_t read_chain_name(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v);
static parser_error_t read_pricing_mode(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v);
static parser_error_t read_args(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_field_key(parser_context_t *ctx, uint32_t num_fields, uint16_t expected_key);
static parser_error_t read_target(parser_context_t *ctx);
static parser_error_t read_entry_point(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_scheduling(parser_context_t *ctx);
static void entry_point_to_str(entry_point_type_e entry_point_type, char *outVal, uint16_t outValLen);
static parser_error_t parser_getItem_txV1_Transfer(parser_context_t *ctx, uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx,
                                            uint8_t *pageCount);

uint16_t header_length_txnV1(parser_header_txnV1_t header) {
  // TODO
  return 0;
}

parser_error_t index_headerpart_txnV1(parser_header_txnV1_t header,
                                      header_part_e part, uint16_t *offset) {
  uint16_t initial_offset = parser_tx_obj_txnV1.metadata.metadata_size;
  parser_metadata_txnV1_t *metadata = &parser_tx_obj_txnV1.metadata;

  initial_offset += metadata->field_offsets[PAYLOAD_FIELD_POS];
  initial_offset += PAYLOAD_METADATA_SIZE;
  initial_offset += INITIATOR_ADDRESS_METADATA_SIZE;
  initial_offset += sizeof(uint8_t); // Tag for initiator_address

  switch (part) {
  case header_initiator_addr:
    *offset = initial_offset;
    return parser_ok;
  case header_timestamp:
    *offset = initial_offset + header.initiator_address_len;
    return parser_ok;
  case header_ttl:
    *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE;
    return parser_ok;
  case header_chainname:
    *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE +
              TTL_SIZE + CHAIN_NAME_LEN_SIZE;
    return parser_ok;
  case header_payment:
    *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE +
              TTL_SIZE + CHAIN_NAME_LEN_SIZE + header.chain_name_len + PRICING_MODE_METADATA_SIZE;
    return parser_ok;
  case header_gasprice:
    *offset = initial_offset + header.initiator_address_len + TIMESTAMP_SIZE +
              TTL_SIZE + CHAIN_NAME_LEN_SIZE + header.chain_name_len + PRICING_MODE_METADATA_SIZE + PAYMENT_SIZE;
    return parser_ok;
  }
  return parser_ok;
}

parser_error_t parser_read_transactionV1(parser_context_t *ctx,
                                         parser_tx_txnV1_t *v) {
  // TODO: Sanity check

  read_metadata(ctx, &v->metadata);
  read_txV1_hash(ctx, v);
  read_txV1_payload_metadata(ctx, v);
  read_txV1_payload(ctx, v);
  read_txV1_approvals(ctx, v);
  return parser_ok;
}

static parser_error_t read_metadata(parser_context_t *ctx,
                                    parser_metadata_txnV1_t *metadata) {
  uint32_t initial_ctx_offset = ctx->offset;
  readU32(ctx, (uint32_t *)&metadata->num_fields);

  PARSER_ASSERT_OR_ERROR(metadata->num_fields > 0,
                         parser_unexpected_number_fields);

  for (uint8_t i = 0; i < metadata->num_fields; i++) {
    uint16_t index = 0;

    readU16(ctx, &index);
    PARSER_ASSERT_OR_ERROR(index == i, parser_unexpected_field_offset);

    readU32(ctx, &metadata->field_offsets[i]);
  }

  readU32(ctx, (uint32_t *)&metadata->fields_size);

  metadata->metadata_size = ctx->offset - initial_ctx_offset;

  return parser_ok;
}

static parser_error_t read_txV1_hash(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = v->metadata;

  PARSER_ASSERT_OR_ERROR(0 == metadata.field_offsets[0],
                         parser_unexpected_field_offset);

  ctx->offset += HASH_LENGTH;

  INCR_NUM_ITEMS(v, false);

  return parser_ok;
}

// TODO: consider merging with read_metadata
static parser_error_t read_txV1_payload_metadata(parser_context_t *ctx,
                                                 parser_tx_txnV1_t *v) {
  parser_payload_metadata_txnV1_t *metadata = &v->payload_metadata;

  readU32(ctx, (uint32_t *)&metadata->num_fields);

  // All fields must be present : Initiator Address, Timestamp, TTL, Chain Name,
  // Pricing Mode, Fields
  PARSER_ASSERT_OR_ERROR(metadata->num_fields == PAYLOAD_METADATA_FIELDS,
                         parser_unexpected_number_fields);

  for (uint8_t i = 0; i < metadata->num_fields; i++) {
    // Skip Index
    ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
    readU32(ctx, &metadata->field_offsets[i]);
  }

  readU32(ctx, (uint32_t *)&metadata->fields_size);

  return parser_ok;
}

static parser_error_t read_txV1_payload(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = v->metadata;

  PARSER_ASSERT_OR_ERROR(HASH_LENGTH == metadata.field_offsets[1],
                         parser_unexpected_field_offset);

  read_txV1_header(ctx, v);

  read_txV1_body(ctx, v);
  return parser_ok;
}

static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v) {
  uint32_t num_fields = 0;
  readU32(ctx, &num_fields);

  v->num_approvals = num_fields;

  for (uint32_t i = 0; i < num_fields; i++) {
    read_public_key(ctx);
    read_signature(ctx);
  }

  INCR_NUM_ITEMS(v, true);

  return parser_ok;
}

static parser_error_t read_txV1_header(parser_context_t *ctx,
                                       parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = v->metadata;

  // TODO: Assert ctx->offset matches with metadata.field_offsets

  read_initiator_address(ctx, v);
  INCR_NUM_ITEMS(v, false);

  uint64_t timestamp;
  readU64(ctx, &timestamp);
  INCR_NUM_ITEMS(v, true);

  uint64_t ttl;
  readU64(ctx, &ttl);
  INCR_NUM_ITEMS(v, true);

  read_chain_name(ctx, v);
  INCR_NUM_ITEMS(v, false);

  read_pricing_mode(ctx, v);
  INCR_NUM_ITEMS(v, true);
  INCR_NUM_ITEMS(v, true);

  return parser_ok;
}

static parser_error_t read_initiator_address(parser_context_t *ctx,
                                             parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = {0};
  read_metadata(ctx, &metadata);

  PARSER_ASSERT_OR_ERROR(metadata.num_fields == INITIATOR_ADDRESS_NUM_FIELDS,
                         parser_unexpected_number_fields);

  PARSER_ASSERT_OR_ERROR(metadata.field_offsets[0] == 0, parser_unexpected_field_offset);
  PARSER_ASSERT_OR_ERROR(metadata.field_offsets[1] == 1, parser_unexpected_field_offset);

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));
  PARSER_ASSERT_OR_ERROR(tag == TAG_ENUM_IS_PUBLIC_KEY || tag == TAG_ENUM_IS_HASH, parser_unexpected_value);

  uint32_t initial_offset = ctx->offset;
  if (tag == TAG_ENUM_IS_PUBLIC_KEY) {
    CHECK_PARSER_ERR(read_public_key(ctx));
  } else if (tag == TAG_ENUM_IS_HASH) {
    CHECK_PARSER_ERR(read_hash(ctx));
  }

  v->header.initiator_address_len = ctx->offset - initial_offset;

  return parser_ok;
}

static parser_error_t read_chain_name(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v) {
  uint32_t len = 0;
  CHECK_PARSER_ERR(read_string(ctx, &len));
  v->header.chain_name_len = len;
  return parser_ok;
}

static parser_error_t read_pricing_mode(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v) {
  // READ METADATA
  parser_metadata_txnV1_t metadata = {0};
  read_metadata(ctx, &metadata);

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));

  if (tag == TAG_PRICING_MODE_CLASSIC) {
    uint64_t payment_amount;
    readU64(ctx, &payment_amount);
    uint8_t gas_price;
    readU8(ctx, &gas_price);
    uint8_t standard_payment;
    readU8(ctx, &standard_payment);
  } else if (tag == TAG_PRICING_MODE_FIXED) {
    uint8_t gas_price_tolerance;
    readU8(ctx, &gas_price_tolerance);
  } else {
    return parser_unexpected_value;
  }

  v->header.pricing_mode = tag;

  return parser_ok;
}

static parser_error_t read_txV1_body(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v) {
  read_txV1_body_fields(ctx, v);
  return parser_ok;
}

static parser_error_t read_txV1_body_fields(parser_context_t *ctx, 
                                            parser_tx_txnV1_t *v) {
  uint32_t num_fields = 0;
  CHECK_PARSER_ERR(readU32(ctx, &num_fields));

  if (num_fields != NUM_FIELDS_TXV1_BODY) {
    return parser_unexpected_value;
  }

  uint16_t key = 0;
  CHECK_PARSER_ERR(read_field_key(ctx, num_fields, key));
  CHECK_PARSER_ERR(read_args(ctx, v));
  key++;

  CHECK_PARSER_ERR(read_field_key(ctx, num_fields, key));
  CHECK_PARSER_ERR(read_target(ctx));
  key++;

  CHECK_PARSER_ERR(read_field_key(ctx, num_fields, key));
  CHECK_PARSER_ERR(read_entry_point(ctx, v));
  key++;

  CHECK_PARSER_ERR(read_field_key(ctx, num_fields, key));
  CHECK_PARSER_ERR(read_scheduling(ctx));
  key++;

  return parser_ok;
}

static parser_error_t read_args(parser_context_t *ctx, parser_tx_txnV1_t *v) {
  uint32_t vec_len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &vec_len));

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));

  if (tag == TAG_RUNTIME_ARGS) {
    CHECK_PARSER_ERR(readU32(ctx, &v->num_runtime_args));

    v->runtime_args = ctx->buffer + ctx->offset;
    v->runtime_args_len = vec_len;

    for (uint32_t i = 0; i < v->num_runtime_args; i++) {
      uint32_t name_len = 0;
      CHECK_PARSER_ERR(read_string(ctx, &name_len));
      CHECK_PARSER_ERR(read_clvalue(ctx));
    }
  } else if (tag == TAG_BYTES_REPR) {
    uint32_t len = 0;
    CHECK_PARSER_ERR(read_bytes(ctx, &len));
  } else {
    return parser_unexpected_value;
  }

  return parser_ok;
}

static parser_error_t read_field_key(parser_context_t *ctx, uint32_t num_fields, uint16_t expected_key) {
  uint16_t key = 0;
  CHECK_PARSER_ERR(readU16(ctx, &key));
  if (key != expected_key) {
    return parser_unexpected_value;
  }
  return parser_ok;
}

// u8 type + data
// https://docs.casper.network/concepts/serialization/structures#transactiontarget
static parser_error_t read_target(parser_context_t *ctx) {
  uint32_t bytes_len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

  parser_metadata_txnV1_t metadata = {0};
  read_metadata(ctx, &metadata);

  uint8_t tag_target = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag_target));

  uint32_t len = 0;

  switch (tag_target) {
    case TAG_TARGET_NATIVE:
      break;
    case TAG_TARGET_STORED:
      // Parse ID
      uint8_t tag_stored = 0;
      CHECK_PARSER_ERR(readU8(ctx, &tag_stored));

      switch (tag_stored) {
        case TAG_STORED_INVOCABLE_ENTITY:
          CHECK_PARSER_ERR(read_entity_address(ctx));
          break;
        case TAG_STORED_INVOCABLE_ENTITY_ALIAS:
          CHECK_PARSER_ERR(read_string(ctx, &len));
          break;
        case TAG_STORED_PACKAGE:
          CHECK_PARSER_ERR(read_bytes(ctx, &len));
          CHECK_PARSER_ERR(read_entity_version(ctx));
          break;
        case TAG_STORED_PACKAGE_ALIAS:
          CHECK_PARSER_ERR(read_string(ctx, &len));
          CHECK_PARSER_ERR(read_entity_version(ctx));
          break;
        default:
          return parser_unexpected_value;
      }

      // Parse runtime
      CHECK_PARSER_ERR(read_runtime(ctx));

      break;
    case TAG_TARGET_SESSION:
      uint8_t is_install_upgrade = 0;
      CHECK_PARSER_ERR(read_bool(ctx, &is_install_upgrade));
      CHECK_PARSER_ERR(read_bytes(ctx, &len));
      CHECK_PARSER_ERR(read_runtime(ctx));
      break;
    default:
      return parser_unexpected_value;
  }

  return parser_ok;
}

// u8
// https://docs.casper.network/concepts/serialization/structures#transactionentrypoint
static parser_error_t read_entry_point(parser_context_t *ctx, parser_tx_txnV1_t *v) {
  uint32_t bytes_len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

  parser_metadata_txnV1_t metadata = {0};
  read_metadata(ctx, &metadata);

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));

  if (tag > (uint8_t) EntryPointCancelReservations) {
    return parser_unexpected_value;
  }

  if (tag == (uint8_t) EntryPointCustom) {
    uint32_t len = 0;
    CHECK_PARSER_ERR(read_bytes(ctx, &len));
  }

  v->entry_point_type = tag;

  INCR_NUM_ITEMS(v, false); // Type

  if (tag == EntryPointTransfer) {
    if (app_mode_expert()) {
      INCR_NUM_ITEMS_BY(v, true, v->num_runtime_args);
    } else {
      INCR_NUM_ITEMS(v, false); // Target
      INCR_NUM_ITEMS(v, false); // Amount
    }
  }

  return parser_ok;
}

// u8 type + data
// https://docs.casper.network/concepts/serialization/structures#transactionscheduling
static parser_error_t read_scheduling(parser_context_t *ctx) {
  uint32_t bytes_len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &bytes_len));

  parser_metadata_txnV1_t metadata = {0};
  read_metadata(ctx, &metadata);

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));

  switch (tag) {
    case TAG_SCHEDULING_STANDARD:
      break;
    case TAG_SCHEDULING_FUTURE_ERA:
      uint64_t future_era_id;
      CHECK_PARSER_ERR(readU64(ctx, &future_era_id));
      break;
    case TAG_SCHEDULING_FUTURE_TIMESTAMP:
      uint64_t future_timestamp;
      CHECK_PARSER_ERR(readU64(ctx, &future_timestamp));
      break;
    default:
      return parser_unexpected_value;
  }
  
  return parser_ok;
}

parser_error_t _validateTxV1(const parser_context_t *c,
                             const parser_tx_txnV1_t *v) {
  // TODO
  return parser_ok;
}

uint8_t _getNumItemsTxV1(__Z_UNUSED const parser_context_t *c,
                         const parser_tx_txnV1_t *v) {
  return v->numItems;
}

static void entry_point_to_str(entry_point_type_e entry_point_type, char *outVal, uint16_t outValLen) {
  switch (entry_point_type) {
    case EntryPointCall:
      snprintf(outVal, outValLen, "Call");
      break;
    case EntryPointCustom:
      snprintf(outVal, outValLen, "Custom");
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
      snprintf(outVal, outValLen, "Change Public Key");
      break;
    case EntryPointAddReservations:
      snprintf(outVal, outValLen, "Add Reservations");
      break;
    case EntryPointCancelReservations:
      snprintf(outVal, outValLen, "Cancel Reservations");
      break;
    default:
      snprintf(outVal, outValLen, "Unknown");
  }
}

parser_error_t _getItemTxV1(parser_context_t *ctx, uint8_t displayIdx,
                            char *outKey, uint16_t outKeyLen, char *outVal,
                            uint16_t outValLen, uint8_t pageIdx,
                            uint8_t *pageCount) {
  MEMZERO(outKey, outKeyLen);
  MEMZERO(outVal, outValLen);
  snprintf(outKey, outKeyLen, "?");
  snprintf(outVal, outValLen, "?");
  *pageCount = 1;

  uint8_t numItems = 0;
  CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
  CHECK_APP_CANARY()

  if (displayIdx < 0 || displayIdx >= numItems) {
    return parser_no_data;
  }

  parser_tx_txnV1_t parser_tx_obj = *(parser_tx_txnV1_t *)ctx->tx_obj;

  if (displayIdx == 0) {
    snprintf(outKey, outKeyLen, "Txn hash");
    ctx->offset = parser_tx_obj.metadata.metadata_size +
                  parser_tx_obj.metadata.field_offsets[HASH_FIELD_POS];
    return parser_printBytes((const uint8_t *)(ctx->buffer + ctx->offset),
                             HASH_LENGTH, outVal, outValLen, pageIdx,
                             pageCount);
  }

  if (displayIdx == 1) {
    snprintf(outKey, outKeyLen, "Type");
    char tmpBuf[50];
    entry_point_to_str(parser_tx_obj.entry_point_type, tmpBuf, sizeof(tmpBuf));
    snprintf(outVal, outValLen, "%s", tmpBuf);
    return parser_ok;
  }

  if (displayIdx == 2) {
    CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header,
                                            header_chainname, &ctx->offset));
    DISPLAY_STRING("Chain ID", ctx->buffer + ctx->offset,
                   parser_tx_obj.header.chain_name_len)
  }

  if (displayIdx == 3) {
    snprintf(outKey, outKeyLen, "Account");
    CHECK_PARSER_ERR(index_headerpart_txnV1(
        parser_tx_obj.header, header_initiator_addr, &ctx->offset));
    return parser_printAddress((const uint8_t *)(ctx->buffer + ctx->offset),
                               parser_tx_obj.header.initiator_address_len,
                               outVal, outValLen, pageIdx, pageCount);
  }

  if (app_mode_expert()) {
    if (displayIdx == 4) {
      DISPLAY_HEADER_TIMESTAMP("Timestamp", header_timestamp, txnV1)
    }

    if (displayIdx == 5) {
      snprintf(outKey, outKeyLen, "Ttl");
      CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_ttl,
                                              &ctx->offset));
      uint64_t value = 0;
      CHECK_PARSER_ERR(readU64(ctx, &value));
      value /= 1000;
      char buffer[100];
      CHECK_PARSER_ERR(parse_TTL(value, buffer, sizeof(buffer)));
      pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
    }

    if (displayIdx == 6) {
      snprintf(outKey, outKeyLen, "Payment");
      if (parser_tx_obj.header.pricing_mode == PricingModeClassic) {
        CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_payment,
                                                &ctx->offset));
        uint64_t value = 0;
      CHECK_PARSER_ERR(readU64(ctx, &value));
      char buffer[20];
        uint64_to_str(buffer, sizeof(buffer), value);
        char formattedPayment[30];
        add_thousand_separators(formattedPayment, sizeof(formattedPayment), buffer);
        pageString(outVal, outValLen, formattedPayment, pageIdx, pageCount);
      } else {
        snprintf(outVal, outValLen, "Fixed");
      }
    }

    if (displayIdx == 7) {
      snprintf(outKey, outKeyLen, "Max gs prce");
      CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_gasprice,
                                              &ctx->offset));
      uint64_t value = 0;
      CHECK_PARSER_ERR(readU8(ctx, (uint8_t *)&value));
      char buffer[8];
      uint64_to_str(buffer, sizeof(buffer), value);
      pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    }
  } else {
    displayIdx += 4;
  }

  if (displayIdx >= 8) {
    switch (parser_tx_obj.entry_point_type) {
      case EntryPointCall:
        break;
      case EntryPointCustom:
        break;
      case EntryPointTransfer:
        ctx->buffer = parser_tx_obj.runtime_args;
        ctx->offset = 0;
        parser_getItem_txV1_Transfer(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        break;
      case EntryPointAddBid:
        break;
      case EntryPointWithdrawBid:
        break;
      case EntryPointDelegate:
        break;
      case EntryPointUndelegate:
        break;
      case EntryPointRedelegate:
        break;
      case EntryPointActivateBid:
        break;
      case EntryPointChangePublicKey:
        break;
      case EntryPointAddReservations:
        break;
      case EntryPointCancelReservations:
        break;
      default:
        break;
    }

    if ((displayIdx >= 8 + parser_tx_obj.num_runtime_args) && app_mode_expert()) {
      snprintf(outKey, outKeyLen, "Approvals #");
      snprintf(outVal, outValLen, "%d", parser_tx_obj.num_approvals);
      return parser_ok;
    }
  }

  return parser_ok;
}

parser_error_t parser_getItem_txV1_Transfer(parser_context_t *ctx, uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx,
                                            uint8_t *pageCount) {
  uint32_t transfer_display_idx = displayIdx - 8;
  uint32_t num_items = parser_tx_obj_txnV1.num_runtime_args;

  if (transfer_display_idx >= num_items) {
    return parser_no_data;
  }

  uint32_t dataLength = 0;
  uint8_t datatype = 255;

  if (app_mode_expert()) {
    if (transfer_display_idx == 0) {
      snprintf(outKey, outKeyLen, "From");
      CHECK_PARSER_ERR(parser_runtimeargs_getData("source", &dataLength,
                                                  &datatype, num_items, ctx))

      return parser_display_runtimeArg(datatype, dataLength, ctx, outVal,
                                       outValLen, pageIdx, pageCount);
    }
  } else {
    transfer_display_idx += 1;
  }

  if (transfer_display_idx == 1) {
      snprintf(outKey, outKeyLen, "Target");
      CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength,
                                                  &datatype, num_items, ctx))

      return parser_display_runtimeArg(datatype, dataLength, ctx, outVal,
                                       outValLen, pageIdx, pageCount);
  } else if (transfer_display_idx == 2) {
    snprintf(outKey, outKeyLen, "Amount");
    CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength,
                                                &datatype, num_items, ctx))

    return parser_display_runtimeArg(datatype, dataLength, ctx, outVal,
                                       outValLen, pageIdx, pageCount);
  }

  if (app_mode_expert()) {
    if (transfer_display_idx == 3) {
      snprintf(outKey, outKeyLen, "ID");
      CHECK_PARSER_ERR(parser_runtimeargs_getData("id", &dataLength,
                                                  &datatype, num_items, ctx))

      return parser_display_runtimeArg(datatype, dataLength, ctx, outVal,
                                       outValLen, pageIdx, pageCount);
    }
  }

  return parser_ok;
}
