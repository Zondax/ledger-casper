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

typedef struct {
    uint8_t pubkeytype;
    uint32_t lenDependencies;
    uint32_t lenChainName;
} parser_header_t;

typedef struct {
    uint8_t paymenttype;
    uint32_t lenName;
    uint32_t lenEntry;
    uint32_t totalLength;
} parser_payment_t;

typedef struct {
    uint8_t sessiontype;
    uint32_t totalLength;
} parser_session_t;


typedef struct {
    parser_header_t header;
    parser_payment_t payment;
    parser_session_t session;
} parser_tx_t;

//let payment_args = runtime_args! {
//"quantity" => 1000
//};
//let payment = ExecutableDeployItem::StoredContractByName {
//        name: String::from("casper-example"),
//        entry_point: String::from("example-entry-point"),
//        args: payment_args,
//};
#ifdef __cplusplus
}
#endif
