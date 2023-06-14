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
#include <zxtypes.h>
#include <zxerror.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DELEGATE_STR    "delegate"
#define UNDELEGATE_STR  "undelegate"
#define REDELEGATE_STR  "redelegate"

typedef struct {
    uint8_t pubkeytype;
    uint32_t lenDependencies;
    uint32_t lenChainName;
} parser_header_t;

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

//These are either Generic or special deploys that need specific handling
typedef enum {
    Generic = 0, //Not special: no support yet
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
    parser_header_t header;
    ExecutableDeployItem payment;
    ExecutableDeployItem session;
    transaction_type_e type;
    uint8_t *wasmHash;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
