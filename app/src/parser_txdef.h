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

#include <coin.h>
#include <zxerror.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DELEGATE_STR "delegate"
#define UNDELEGATE_STR "undelegate"
#define REDELEGATE_STR "redelegate"

#define MAX_METADATA_FIELDS 10
#define PAYLOAD_METADATA_FIELDS 6

#define HASH_FIELD_POS 0
#define PAYLOAD_FIELD_POS 1
#define VALIDATORS_FIELD_POS 2

typedef struct {
    uint8_t pubkeytype;
    uint32_t lenDependencies;
    uint32_t lenChainName;
} parser_header_deploy_t;

#define NUM_RUNTIME_TYPES 22

#define NUM_DEPLOY_TYPES 6
typedef enum {
    ModuleBytes = 0,
    StoredContractByHash = 1,
    StoredContractByName = 2,
    StoredVersionedContractByHash = 3,
    StoredVersionedContractByName = 4,
    Transfer = 5,
} deploy_type_e;

// These are either Generic or special deploys that need specific handling
typedef enum {
    Generic = 0,  // Not special: no support yet
    SystemPayment = 1,
    NativeTransfer = 2,
    Delegate = 3,
    UnDelegate = 4,
    ReDelegate = 5,
} special_deploy_e;

typedef enum {
    Payment = 0,
    Session = 1,
} phase_type_e;

typedef enum {
    Transaction = 0,
    Message = 1,
    WasmDeploy = 2,
} transaction_type_e;

typedef struct {
    phase_type_e phase;
    deploy_type_e type;
    special_deploy_e special_type;
    uint8_t with_generic_args;
    uint32_t num_runtime_args;
    uint32_t UI_fixed_items;
    uint32_t UI_runtime_items;
    uint32_t totalLength;
    uint32_t itemOffset;
    bool hasAmount;
} ExecutableDeployItem;

typedef struct {
    parser_header_deploy_t header;
    ExecutableDeployItem payment;
    ExecutableDeployItem session;
    transaction_type_e type;
    uint8_t *wasmHash;
} parser_tx_deploy_t;

typedef enum {
    PricingModeClassic = 0,
    PricingModeFixed = 1,
    PricingModePrepaid = 2,
} pricing_mode_e;

typedef struct {
    uint16_t initiator_address_metadata_size;
    uint8_t initiator_address_len;
    uint8_t chain_name_len;
    pricing_mode_e pricing_mode;
    uint16_t pricing_mode_metadata_size;
    uint8_t pricing_mode_items;
} parser_header_txnV1_t;

typedef struct {
    uint8_t num_fields;
    uint16_t metadata_size;
    uint32_t field_offsets[MAX_METADATA_FIELDS];
    uint16_t fields_size;
} parser_metadata_txnV1_t;

typedef enum {
    EntryPointCall = 0,
    EntryPointCustom = 1,
    EntryPointTransfer = 2,
    EntryPointAddBid = 3,
    EntryPointWithdrawBid = 4,
    EntryPointDelegate = 5,
    EntryPointUndelegate = 6,
    EntryPointRedelegate = 7,
    EntryPointActivateBid = 8,
    EntryPointChangePublicKey = 9,
    EntryPointAddReservations = 10,
    EntryPointCancelReservations = 11,
    EntryPointBurn = 12,
} entry_point_type_e;

typedef enum {
    TargetNative = 0,
    TargetStoredByHash = 1,
    TargetStoredByName = 2,
    TargetStoredByPackageHash = 3,
    TargetStoredByPackageName = 4,
    TargetSession = 5,
} target_type_e;

typedef struct {
    target_type_e type;
    union {
        const uint8_t *hash;
        const uint8_t *name;
    };
    uint32_t name_len;
    uint32_t entity_version;
} target_t;

typedef enum {
    RuntimeArgs = 0,
    BytesRepr = 1,
} args_type_e;

typedef struct {
    parser_metadata_txnV1_t metadata;
    parser_header_txnV1_t header;
    parser_metadata_txnV1_t payload_metadata;
    entry_point_type_e entry_point_type;
    const uint8_t *custom_entry_point;
    uint32_t custom_entry_point_len;
    target_t target;
    uint8_t runtime_args_offset;
    args_type_e args_type;
    uint32_t runtime_args_len;
    uint32_t num_runtime_args;
    uint32_t module_bytes_len;
    uint8_t numItems;
    uint8_t num_approvals;
} parser_tx_txnV1_t;

typedef enum {
    Deploy = 0,
    TransactionV1 = 1,
} transaction_content_e;

typedef enum {
    StreamingStateNoStreaming = 0,
    StreamingStateInit = 1,
    StreamingStateInProgress = 2,
    StreamingStateFinal = 3,
} streaming_state_e;

#ifdef __cplusplus
}
#endif
