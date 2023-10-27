/*******************************************************************************
*  (c) 2018-2021 Zondax GmbH
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

#ifdef __cplusplus
extern "C" {
#endif

#define CLA                             0x11

#include <stdint.h>
#include <stddef.h>

#define HDPATH_LEN_DEFAULT   5

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x1fau)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_0_TESTNET     (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET     (0x80000000u | 0x1fau)

#define SIG_RS_LEN                  64u
#define SECP256K1_PK_LEN            33u
#define ED25519_PK_LEN              32u
#define HASH_LENGTH                 32u

typedef enum {
    addr_secp256k1 = 0,
} address_kind_e;

typedef enum {
    header_pubkey = 0,
    header_timestamp = 1,
    header_ttl = 2,
    header_gasprice = 3,
    header_bodyhash = 4,
    header_deps = 5,
    header_chainname = 6,
} header_part_e;

#define INS_SIGN_MSG                        0x03
#define INS_SIGN_WASM                       0x04

#define CBOR_PARSER_MAX_RECURSIONS          4
#define COIN_SECRET_REQUIRED_CLICKS         0
#define COIN_AMOUNT_DECIMAL_PLACES          0                              // FIXME: Adjust this

#define VIEW_ADDRESS_OFFSET_SECP256K1       (SECP256K1_PK_LEN )
#define COIN_SUPPORTED_TX_VERSION           0

#define MENU_MAIN_APP_LINE1                 "Casper"
#define MENU_MAIN_APP_LINE2                 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET          "???"
#define APPVERSION_LINE1                    "Version"
#define APPVERSION_LINE2                    "v" APPVERSION

#ifdef __cplusplus
}
#endif
