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
Metadata Format : Number of fields (u32) + fields info (u32, u32) + fields size (u32); 
where fields info is (index (u16), offset (u32))

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

Note : Type serialization info @ https://docs.casper.network/concepts/serialization/types

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

#include <zxmacros.h>
#include "parser_impl_transactionV1.h"

#define FIELD_INDEX_SIZE 2

#define INCR_NUM_ITEMS(v) (v->numItems++)

parser_tx_txnV1_t parser_tx_obj_txnV1;

static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_initiator_address(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_chain_name(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_pricing_mode(parser_context_t *ctx, parser_tx_txnV1_t *v);

uint16_t header_length_txnV1(parser_header_txnV1_t header) {
    // TODO
    return 0;
}

parser_error_t index_headerpart_txnV1(parser_header_txnV1_t head, header_part_e part, uint16_t *index) {
    // TODO
    return parser_ok;
}

parser_error_t parser_read_transactionV1(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO: Sanity check
    read_txV1_metadata(ctx, v);
    read_txV1_hash(ctx, v);
    read_txV1_payload_metadata(ctx, v);
    read_txV1_payload(ctx, v);
    read_txV1_approvals(ctx, v);
    return parser_ok;
}

static parser_error_t read_txV1_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t* metadata = &v->metadata;

    readU32(ctx, (uint32_t *) &metadata->num_fields);

    PARSER_ASSERT_OR_ERROR(metadata->num_fields > 0, parser_unexpected_number_fields);
    PARSER_ASSERT_OR_ERROR(metadata->num_fields <= 3, parser_unexpected_number_fields);

    for (uint8_t i = 0; i < metadata->num_fields; i++) {
        // Skip Index Info
        ctx->offset += FIELD_INDEX_SIZE;
        readU32(ctx, &metadata->field_offsets[i]);
    }

    readU32(ctx, (uint32_t *) &metadata->fields_size);

    metadata->metadata_size = ctx->offset;

    return parser_ok;
}

static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t metadata = v->metadata;

    PARSER_ASSERT_OR_ERROR(0 == metadata.field_offsets[0], parser_unexpected_field_offset);

    ctx->offset += HASH_LENGTH;

    INCR_NUM_ITEMS(v);

    return parser_ok;
}

// TODO: consider merging with read_txV1_metadata
static parser_error_t read_txV1_payload_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_payload_metadata_txnV1_t* metadata = &v->payload_metadata;

    readU32(ctx, (uint32_t *) &metadata->num_fields);

    // All fields must be present : Initiator Address, Timestamp, TTL, Chain Name, Pricing Mode, Fields
    PARSER_ASSERT_OR_ERROR(metadata->num_fields == PAYLOAD_METADATA_FIELDS, parser_unexpected_number_fields);

    for (uint8_t i = 0; i < metadata->num_fields; i++) {
        // Skip Index
        ctx->offset += FIELD_INDEX_SIZE;
        readU32(ctx, &metadata->field_offsets[i]);
    }

    readU32(ctx, (uint32_t *) &metadata->fields_size);

    return parser_ok;
}

static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    parser_metadata_txnV1_t metadata = v->metadata;

    PARSER_ASSERT_OR_ERROR(HASH_LENGTH == metadata.field_offsets[1], parser_unexpected_field_offset);

    read_txV1_header(ctx, v);

    read_txV1_body(ctx, v);
    return parser_ok;
}

static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

// Initiator Address: u8 tag + 33 or 32 bytes
// Timestamp: uint64
// TTL: uint64
// Chain Name: String
// Pricing Mode: u8 TAG followed by : Classic (0) or Fixed (1)
//    - Classic PricingMode serializes as the u64 payment_amount followed by the u64 value of the gas_price.
//    - Fixed PricingMode serializes as the u64 gas_price_tolerance.
static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v) {
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

    return parser_ok;
}

static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_initiator_address(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));
    PARSER_ASSERT_OR_ERROR(tag == 0x00 || tag == 0x01, parser_unexpected_value);

    v->header.initiator_address = ctx->buffer + ctx->offset;

    if (tag == 0x00) {
        // Check validity of pubKey tag
        uint8_t pubkey_tag = 0;
        CHECK_PARSER_ERR(readU8(ctx, &pubkey_tag));
        PARSER_ASSERT_OR_ERROR(pubkey_tag == 0x00 || pubkey_tag == 0x01 || pubkey_tag == 0x02, parser_unexpected_value);
        v->header.initiator_address_len = 1;
    }

    // Either 32 bytes of hash or 32 bytes of PublicKey (Tag already read)
    uint8_t len = 32;
    ctx->offset += len;
    v->header.initiator_address_len += len;

    return parser_ok;
}

static parser_error_t read_chain_name(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    readU32(ctx, (uint32_t *) &v->header.chain_name_len);
    v->header.chain_name = ctx->buffer + ctx->offset;
    ctx->offset += v->header.chain_name_len;
    return parser_ok;
}

static parser_error_t read_pricing_mode(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    uint8_t tag = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tag));
    PARSER_ASSERT_OR_ERROR(tag == 0x00 || tag == 0x01, parser_unexpected_value);

    if (tag == 0x00) {
        // Classic PricingMode
        uint64_t payment_amount;
        readU64(ctx, &payment_amount);
        uint64_t gas_price;
        readU64(ctx, &gas_price);
    } else {
        // Fixed PricingMode
        uint64_t gas_price_tolerance;
        readU64(ctx, &gas_price_tolerance);
    }

    return parser_ok;
}

parser_error_t _validateTxV1(const parser_context_t *c, const parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

uint8_t _getNumItemsTxV1(__Z_UNUSED const parser_context_t *c, const parser_tx_txnV1_t *v) {
    return v->numItems;
}

parser_error_t _getItemTxV1(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
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

    parser_tx_txnV1_t parser_tx_obj = *(parser_tx_txnV1_t*) ctx->tx_obj;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Txn hash");
        ctx->offset = parser_tx_obj.metadata.metadata_size + parser_tx_obj.metadata.field_offsets[HASH_FIELD];
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), HASH_LENGTH, outVal, outValLen,
                                 pageIdx, pageCount);
    }
    return parser_ok;
}
