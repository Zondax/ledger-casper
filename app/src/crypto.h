/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include <zxerror.h>

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

#define ADDRESS_PROTOCOL_LEN        1

#define BLAKE2B_256_SIZE            32

typedef enum {
    hash_start = 0,
    hash_update = 1,
    hash_finish = 2,
} hash_chunk_operation_e;

uint16_t formatProtocol(const uint8_t *addressBytes, uint16_t addressSize,
                        uint8_t *formattedAddress,
                        uint16_t formattedAddressSize);

bool isTestnet();

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);

zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize);

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen,
                     unsigned char *out);

zxerr_t pubkey_to_hash(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *out);

zxerr_t encode(char* address, const uint8_t addressLen, char* encodedAddr);
zxerr_t encode_addr(char* address, const uint8_t addressLen, char* encodedAddr);
zxerr_t encode_hex(char* bytes, const uint8_t bytesLen, char* output, uint16_t outputLen);

void bytes_to_nibbles(uint8_t* bytes,uint8_t bytesLen, uint8_t* nibbles);

bool is_alphabetic(const char byte);

zxerr_t crypto_hashChunk(const uint8_t *buffer, uint32_t bufferLen, uint8_t *output, uint16_t outputLen,
                         hash_chunk_operation_e operation);

#ifdef __cplusplus
}
#endif
