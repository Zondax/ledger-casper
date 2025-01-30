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

#include <zxmacros.h>
#include "parser_impl_transactionV1.h"

parser_tx_txnV1_t parser_tx_obj_txnV1;

static parser_error_t read_txV1_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v);
static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v);

// Initiator Address: 32 bytes
// Timestamp: uint64
// TTL: uint64
// Chain Name: String
// Pricing Mode: u8 TAG followed by : Classic (0) or Fixed (1)
//    - Classic PricingMode serializes as the u64 payment_amount followed by the u64 value of the gas_price.
//    - Fixed PricingMode serializes as the u64 gas_price_tolerance.
uint16_t header_length_txnV1(parser_header_txnV1_t header) {
    // TODO
    return 0;
}

parser_error_t index_headerpart_txnV1(parser_header_txnV1_t head, header_part_e part, uint16_t *index) {
    // TODO
    return parser_ok;
}

/*
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
parser_error_t parser_read_transactionV1(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    read_txV1_metadata(ctx, v);
    read_txV1_hash(ctx, v);
    read_txV1_payload(ctx, v);
    read_txV1_approvals(ctx, v);
    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const parser_tx_txnV1_t *v) {
    // TODO
    return 0;
}

/*
Metadata Format : Number of fields (u32) + fields info (u32, u32) + fields size (u32); 
where fields info is (index (u16), offset (u32))

Example:
0300000000000000000001002000000002009f01000006020000

03000000 - u32 number of fields (3)
Then for each field:
Field 1: 0000 (index) 00000000 (offset)
Field 2: 0100 (index) 20000000 (offset = 32)
Field 3: 0200 (index) 9f010000 (offset = 415)
All fields size (u32) = 06020000 (518 bytes)

Note : Type serialization info @ https://docs.casper.network/concepts/serialization/types
*/
static parser_error_t read_txV1_metadata(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_txV1_hash(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_txV1_payload(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    read_txV1_header(ctx, v);
    read_txV1_body(ctx, v);
    return parser_ok;
}

static parser_error_t read_txV1_approvals(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_txV1_header(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_txV1_body(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}

static parser_error_t read_PricingMode(parser_context_t *ctx, parser_tx_txnV1_t *v) {
    // TODO
    return parser_ok;
}
