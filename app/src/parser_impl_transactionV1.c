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

/*
Metadata Format : Number of fields (u32) + fields info (u16, u32) + fields size (u32);

Example of Header Metadata:
0300000000000000000001002000000002009f01000006020000

03000000 - u32 number of fields (3)
Then for each field:
Field 1: 0000 (index) 00000000 (offset)
Field 2: 0100 (index) 20000000 (offset = 32)
Field 3: 0200 (index) 9f010000 (offset = 415)
All fields size (u32) = 06020000 (518 bytes)

Example of Body Metadata:
0600000000000000000001003700000002003f00000003004700000004005200000005007d00000050010000

06000000 - u32 number of fields (6)
Then for each field:
Field 1: 0000 (index) 00000000 (offset)
Field 2: 0100 (index) 37000000 (offset = 55)
Field 3: 0200 (index) 3f000000 (offset = 63)
Field 4: 0300 (index) 47000000 (offset = 71)
Field 5: 0400 (index) 52000000 (offset = 82)
Field 6: 0500 (index) 7d000000 (offset = 125)
All fields size (u32) = 50010000 (80 bytes)

Note : Type serialization info @
https://docs.casper.network/concepts/serialization/types

TransactionV1Hash ([u8; 32])

TransactionV1Payload (HEADER + BODY)
├── initiator_addr: enum
│   ├── PublicKey: enum
│   │   ├── System
│   │   ├── Ed25519(Ed25519PublicKey)
│   │   └── Secp256k1(Secp256k1PublicKey)
│   └── AccountHash([u8; 32])
├── timestamp: u64
├── ttl: u64
├── chain_name: String
├── pricing_mode: u8 (enum)
│   ├── Standard = 0
│   └── Fixed = 1
└── fields: BTreeMap<u16, Vec<u8>>
    ├── 0 (ARGS_MAP_KEY) -> TransactionArgs
    │   ├── Named(Vec<(String, CLValue)>)
    │   └── Bytesrepr(Vec<u8>)
    ├── 1 (TARGET_MAP_KEY) -> TransactionTarget
    │   ├── Native
    │   ├── Stored {
    │   │   ├── id: TransactionInvocationTarget
    │   │   │   ├── ByHash([u8; 32])
    │   │   │   ├── ByName(String)
    │   │   │   ├── ByPackageHash {
    │   │   │   │   ├── addr: [u8; 32]
    │   │   │   │   └── version: Option<u32>
    │   │   │   │}
    │   │   │   └── ByPackageName {
    │   │   │       ├── name: String
    │   │   │       └── version: Option<u32>
    │   │   │   }
    │   │   └── runtime: TransactionRuntimeParams
    │   │       ├── VmCasperV1
    │   │       └── VmCasperV2 {
    │   │           ├── transferred_value: u64
    │   │           └── seed: Option<[u8; 32]>
    │   │       }
    │   │}
    │   └── Session {
    │       ├── is_install_upgrade: bool
    │       ├── module_bytes: Vec<u8>
    │       └── runtime: TransactionRuntimeParams
    │           ├── VmCasperV1
    │           └── VmCasperV2 {
    │               ├── transferred_value: u64
    │               └── seed: Option<[u8; 32]>
    │           }
    │   }
    ├── 2 (ENTRY_POINT_MAP_KEY) -> TransactionEntryPoint
    │   ├── Call
    │   ├── Custom(String)
    │   ├── Transfer
    │   ├── AddBid
    │   ├── WithdrawBid
    │   ├── Delegate
    │   ├── Undelegate
    │   ├── Redelegate
    │   ├── ActivateBid
    │   ├── ChangeBidPublicKey
    │   ├── AddReservations
    │   └── CancelReservations
    └── 3 (SCHEDULING_MAP_KEY) -> TransactionScheduling
        ├── Standard: ()
        ├── FutureEra: u64
        └── FutureTimestamp: u65

approvals:
└── BtreeSet: BTreeSet<Approval>
    └── Approval: (
        ├── PublicKey: enum
        │   ├── System
        │   ├── Ed25519(Ed25519PublicKey)
        │   └── Secp256k1(Secp256k1PublicKey)
        └── Signature: enum
            ├── System
            ├── Ed25519(Ed25519Signature)
            └── Secp256k1(Secp256k1Signature)
*/

#include "parser_impl_transactionV1.h"
#include "app_mode.h"
#include <zxmacros.h>

#define SERIALIZED_FIELD_INDEX_SIZE 2

#define INITIATOR_ADDRESS_NUM_FIELDS 2

#define TAG_ENUM_IS_PUBLIC_KEY 0x00
#define TAG_ENUM_IS_HASH 0x01

// Pubkey serialization tags
#define TAG_SYSTEM 0x00
#define TAG_ED25519 0x01
#define TAG_SECP256K1 0x02

#define INIT_ADDR_PUBLIC_KEY_LENGTH 33
#define INIT_ADDR_HASH_LENGTH 32

// TODO: Check if these should be dynamic
#define INITIATOR_ADDRESS_METADATA_SIZE 20
#define PAYLOAD_METADATA_SIZE 44
#define PRICING_MODE_METADATA_SIZE 33

#define TIMESTAMP_SIZE 8
#define TTL_SIZE 8
#define CHAIN_NAME_LEN_SIZE 4
#define PAYMENT_SIZE 8
#define GAS_PRICE_SIZE 8

#define INCR_NUM_ITEMS(v) (v->numItems++)

#define PRINT_BUFFER(ctx)                                                      \
  for (int i = 0; i < 60; i++) {                                               \
    printf("%02x ", ctx->buffer[ctx->offset + i]);                             \
  }                                                                            \
  printf("\n");

parser_tx_txnV1_t parser_tx_obj_txnV1;

static parser_error_t read_txV1_hash(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v);
static parser_error_t read_txV1_metadata(parser_context_t *ctx,
                                         parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload_metadata(parser_context_t *ctx,
                                                 parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v);
static parser_error_t read_txV1_approvals(parser_context_t *ctx,
                                          parser_tx_txnV1_t *v);
static parser_error_t read_txV1_header(parser_context_t *ctx,
                                       parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v);
static parser_error_t read_initiator_address(parser_context_t *ctx,
                                             parser_tx_txnV1_t *v);
static parser_error_t read_chain_name(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v);
static parser_error_t read_pricing_mode(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v);
static parser_error_t read_args(parser_context_t *ctx,
                                parser_tx_txnV1_t *v);
static parser_error_t read_target(parser_context_t *ctx,
                                parser_tx_txnV1_t *v);
static parser_error_t read_entry_point(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v);
static parser_error_t read_scheduling(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v);

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

  read_txV1_metadata(ctx, v);
  read_txV1_hash(ctx, v);
  read_txV1_payload_metadata(ctx, v);
  read_txV1_payload(ctx, v);
  read_txV1_approvals(ctx, v);
  return parser_ok;
}

static parser_error_t read_txV1_metadata(parser_context_t *ctx,
                                         parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t *metadata = &v->metadata;

  readU32(ctx, (uint32_t *)&metadata->num_fields);

  PARSER_ASSERT_OR_ERROR(metadata->num_fields > 0,
                         parser_unexpected_number_fields);
  PARSER_ASSERT_OR_ERROR(metadata->num_fields <= 3,
                         parser_unexpected_number_fields);

  for (uint8_t i = 0; i < metadata->num_fields; i++) {
    // Skip Index Info
    ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
    readU32(ctx, &metadata->field_offsets[i]);
  }

  readU32(ctx, (uint32_t *)&metadata->fields_size);

  metadata->metadata_size = ctx->offset;

  return parser_ok;
}

static parser_error_t read_txV1_hash(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = v->metadata;

  PARSER_ASSERT_OR_ERROR(0 == metadata.field_offsets[0],
                         parser_unexpected_field_offset);

  ctx->offset += HASH_LENGTH;

  INCR_NUM_ITEMS(v);

  return parser_ok;
}

// TODO: consider merging with read_txV1_metadata
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

static parser_error_t read_txV1_approvals(parser_context_t *ctx,
                                          parser_tx_txnV1_t *v) {
  // TODO
  return parser_ok;
}

// Initiator Address: u8 tag + 33 or 32 bytes
// Timestamp: uint64
// TTL: uint64
// Chain Name: String
// Pricing Mode: u8 TAG followed by : Classic (0) or Fixed (1)
//    - Classic PricingMode serializes as the u64 payment_amount followed by the
//    u64 value of the gas_price.
//    - Fixed PricingMode serializes as the u64 gas_price_tolerance.
// 0300000000000000000001002000000002009f01000006020000 -> read_txV1_metadata
// a4b7296ad9b1ea0a038d0d385fb867b772f4c73c0dcd36149c50ee4598183aec -> read_txV1_hash
// 0600000000000000000001003700000002003f00000003004700000004005200000005007d00000053010000 -> payload metadata
// 0200000000000000000001000100000023000000 -> initiator address metadata
// 000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 -> initiator address
// a087c0377901000080ee360000000000070000006d61696e6e65740400000000000000000001000100000002000900000003000a0000000b00000000102700000000000064000400000000008d000000000400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75010c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000001000f00000001000000000000000000010000000002000f00000001000000000000000000010000000203000f000000010000000000000000000100000000010000000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33702ddfc1e0e8956b79d90d3ebb66fd8f0b3422917460257c76ed575d588793178c475922403678efd343f082aef0e7e28e88953ed85250b0b2de19faeb838a13d3b
static parser_error_t read_txV1_header(parser_context_t *ctx,
                                       parser_tx_txnV1_t *v) {
  parser_metadata_txnV1_t metadata = v->metadata;

  // TODO: Assert ctx->offset matches with metadata.field_offsets

  read_initiator_address(ctx, v);
  INCR_NUM_ITEMS(v);

  uint64_t timestamp;
  readU64(ctx, &timestamp);
  INCR_NUM_ITEMS(v);

  uint64_t ttl;
  readU64(ctx, &ttl);
  INCR_NUM_ITEMS(v);

  read_chain_name(ctx, v);
  INCR_NUM_ITEMS(v);

  read_pricing_mode(ctx, v);
  INCR_NUM_ITEMS(v);
  INCR_NUM_ITEMS(v);

  return parser_ok;
}

static parser_error_t read_initiator_address(parser_context_t *ctx,
                                             parser_tx_txnV1_t *v) {
  // READ METADATA
  uint32_t num_fields = 0;
  readU32(ctx, &num_fields);

  PARSER_ASSERT_OR_ERROR(num_fields == INITIATOR_ADDRESS_NUM_FIELDS,
                         parser_unexpected_number_fields);

  ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
  uint32_t first_field_offset = 0;
  readU32(ctx, &first_field_offset);

  PARSER_ASSERT_OR_ERROR(first_field_offset == 0, parser_unexpected_field_offset);

  ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
  uint32_t addr_offset = 0;
  readU32(ctx, &addr_offset);

  PARSER_ASSERT_OR_ERROR(addr_offset == 1, parser_unexpected_field_offset);

  uint32_t fields_size = 0;
  readU32(ctx, &fields_size);

  // READ DATA
  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));
  PARSER_ASSERT_OR_ERROR(tag == TAG_ENUM_IS_PUBLIC_KEY || tag == TAG_ENUM_IS_HASH, parser_unexpected_value);

  uint8_t len = 0;
  if (tag == TAG_ENUM_IS_PUBLIC_KEY) {
    // Check validity of pubKey tag
    uint8_t pubkey_tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &pubkey_tag));
    PARSER_ASSERT_OR_ERROR(pubkey_tag == TAG_SYSTEM || pubkey_tag == TAG_ED25519 ||
                               pubkey_tag == TAG_SECP256K1,
                           parser_unexpected_value);
    v->header.initiator_address_len = 1;
    len = INIT_ADDR_PUBLIC_KEY_LENGTH;
  } else if (tag == TAG_ENUM_IS_HASH) {
    len = INIT_ADDR_HASH_LENGTH;
  }

  ctx->offset += len;
  v->header.initiator_address_len += len;

  return parser_ok;
}

static parser_error_t read_chain_name(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v) {
  readU32(ctx, (uint32_t *)&v->header.chain_name_len);
  ctx->offset += v->header.chain_name_len;
  return parser_ok;
}

// Classic PricingMode: u8 tag (0x00) + u64 payment_amount + u64 gas_price
// Fixed PricingMode: u8 tag (0x01) + u64 gas_price_tolerance
// Vec<(String, CLValue)>
// https://docs.casper.network/concepts/serialization/types#runtimeargs
// 01
// 0300000000000000000001002000000002009f01000006020000
// a4b7296ad9b1ea0a038d0d385fb867b772f4c73c0dcd36149c50ee4598183aec
// 0600000000000000000001003700000002003f00000003004700000004005200000005007d00000053010000 -> payload metadata
// 0200000000000000000001000100000023000000 -> initiator address metadata
// 000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 -> initiator address
// a087c03779010000 -> timestamp
// 80ee360000000000 -> ttl
// 07000000 -> chain_id length
// 6d61696e6e6574 -> chain_id
// 04000000 0000 00000000 0100 01000000 0200 09000000 03000 a000000 0b000000 -> pricing mode metadata
// 00 -> pricing mode tag 
// 1027000000000000 -> payment amount
// 6400 -> gas price
// 040000000000
// 8d000000000400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75010c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000001000f00000001000000000000000000010000000002000f00000001000000000000000000010000000203000f000000010000000000000000000100000000010000000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33702ddfc1e0e8956b79d90d3ebb66fd8f0b3422917460257c76ed575d588793178c475922403678efd343f082aef0e7e28e88953ed85250b0b2de19faeb838a13d3b
static parser_error_t read_pricing_mode(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v) {
  // READ METADATA
  uint32_t num_fields = 0;
  readU32(ctx, &num_fields);

  for (uint32_t i = 0; i < num_fields; i++) {
    ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
    uint32_t field_offset = 0;
    readU32(ctx, &field_offset);
  }

  uint32_t fields_size = 0;
  readU32(ctx, &fields_size);

  uint8_t tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &tag));
  PARSER_ASSERT_OR_ERROR(tag == 0x00 || tag == 0x01, parser_unexpected_value);

  if (tag == 0x00) {
    // Classic PricingMode
    uint64_t payment_amount;
    readU64(ctx, &payment_amount);
    uint64_t gas_price;
    readU8(ctx, &gas_price);
  } else {
    // Fixed PricingMode
    uint64_t gas_price_tolerance;
    readU8(ctx, &gas_price_tolerance);
  }

  return parser_ok;
}

static parser_error_t read_txV1_body(parser_context_t *ctx,
                                     parser_tx_txnV1_t *v) {
  // TODO
  read_args(ctx, v);
  read_target(ctx, v);
  INCR_NUM_ITEMS(v);
  read_entry_point(ctx, v);
  read_scheduling(ctx, v);
  return parser_ok;
}

// Vec<(String, CLValue)>
// https://docs.casper.network/concepts/serialization/types#runtimeargs
// 01
// 0300000000000000000001002000000002009f01000006020000
// a4b7296ad9b1ea0a038d0d385fb867b772f4c73c0dcd36149c50ee4598183aec
// 0600000000000000000001003700000002003f00000003004700000004005200000005007d00000053010000 -> payload metadata
// 0200000000000000000001000100000023000000 -> initiator address metadata
// 000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 -> initiator address
// a087c03779010000 -> timestamp
// 80ee360000000000 -> ttl
// 07000000 -> chain_id length
// 6d61696e6e6574 -> chain_id
// 04000000 -> number of args
// 00000000 000001000100000002000900000003000a0000000b00000000102700000000000064000400000000008d000000000400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75010c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000001000f00000001000000000000000000010000000002000f00000001000000000000000000010000000203000f000000010000000000000000000100000000010000000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33702ddfc1e0e8956b79d90d3ebb66fd8f0b3422917460257c76ed575d588793178c475922403678efd343f082aef0e7e28e88953ed85250b0b2de19faeb838a13d3b
static parser_error_t read_args(parser_context_t *ctx,
                                parser_tx_txnV1_t *v) {
  // TODO
  return parser_ok;
}

// u8 type + data
// https://docs.casper.network/concepts/serialization/structures#transactiontarget
// - 0x00: Native => Just that byte
// - 0x01: Stored => id (TransactionInvocationTarget) + runtime (0x00: VmCasperV1)
//                    -> - InvocableEntity (u8 tag (0x00) + entity address)
//                    -> - InvocableEntityAlias (u8 tag (0x01) + alias(string))
//                    -> - Package (u8 tag (0x02) + package hash + [optional entity_version])
//                    -> - PackageAlias (u8 tag (0x03) + alias(string) + [optional entity_version])
// - 0x02: Session => kind + module_bytes + runtime (0x00: VmCasperV1)
static parser_error_t read_target(parser_context_t *ctx,
                                parser_tx_txnV1_t *v) {
  // TODO
  return parser_ok;
}

// u8
// https://docs.casper.network/concepts/serialization/structures#transactionentrypoint
static parser_error_t read_entry_point(parser_context_t *ctx,
                                        parser_tx_txnV1_t *v) {
  // TODO
  return parser_ok;
}

// u8 type + data
// https://docs.casper.network/concepts/serialization/structures#transactionscheduling
static parser_error_t read_scheduling(parser_context_t *ctx,
                                      parser_tx_txnV1_t *v) {
  // TODO
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

/*
"0202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337
a087c03779010000
80ee360000000000
070000006d61696e6e6574
*/
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
    snprintf(outVal, outValLen, "TODO");
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

  /*
      4 | timestamp : 1970-01-01t00:00:00z
      5 | ttl : unexpected value
  */
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
      CHECK_PARSER_ERR(index_headerpart_txnV1(parser_tx_obj.header, header_payment,
                                              &ctx->offset));
      uint64_t value = 0;
      CHECK_PARSER_ERR(readU64(ctx, &value));
      char buffer[8];
      uint64_to_str(buffer, sizeof(buffer), value);
      pageString(outVal, outValLen, buffer, pageIdx, pageCount);
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
  }

  return parser_ok;
}
