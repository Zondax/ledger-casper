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

#include "crypto.h"

#include "coin.h"
#include "parser_impl_deploy.h"
#include "parser_impl_transactionV1.h"
#include "parser_txdef.h"
#include "tx.h"
#include "zxformat.h"
#include "zxmacros.h"

#define MAX_NIBBLE_LEN 100
uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() { return hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET; }

const char HEX_CHARS[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static bool get_next_hash_bit(char *hash_input, uint8_t *index, uint8_t *offset);

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || \
    defined(TARGET_FLEX)
#include "cx.h"
#include "cx_blake2b.h"
static cx_blake2b_t body_hash_ctx;

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen, unsigned char *out) {
    cx_blake2b_t ctx;
    if (cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, CX_LAST, in, inLen, out, 32) != CX_OK) {
        return zxerr_invalid_crypto_settings;
    }

    return zxerr_ok;
}

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    if (pubKey == NULL || pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_public_key_t cx_publicKey = {0};
    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[64] = {0};

    zxerr_t error = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, path, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02;  // "Compress" public key in place
    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

    return error;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                    uint16_t *sigSize, transaction_content_e tx_content) {
    if (signature == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_unknown;
    }
    MEMZERO(signature, signatureMaxlen);

    uint8_t hash[CX_SHA256_SIZE] = {0};
    if (tx_content == Deploy) {
        switch (parser_tx_obj_deploy.type) {
            case WasmDeploy:
            case Transaction: {
            const uint8_t *message_digest = message + header_length_deploy(parser_tx_obj_deploy.header);
            cx_hash_sha256(message_digest, CX_SHA256_SIZE, hash, CX_SHA256_SIZE);
            break;
        }
        case Message:
            cx_hash_sha256(message, messageLen, hash, CX_SHA256_SIZE);
            break;

        default:
                return zxerr_unknown;
        }
    } else {
        const uint8_t *message_digest = parser_tx_obj_txnV1.txnHash;
        cx_hash_sha256(message_digest, CX_SHA256_SIZE, hash, CX_SHA256_SIZE);
    }

    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[64] = {0};
    size_t signatureLength = sizeof_field(signature_t, der_signature);
    uint32_t tmpInfo = 0;
    *sigSize = 0;

    signature_t *const signature_object = (signature_t *)signature;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, hash, CX_SHA256_SIZE,
                                         signature_object->der_signature, &signatureLength, &tmpInfo));

    const err_convert_e err_c = convertDERtoRSV(signature_object->der_signature, tmpInfo, signature_object->r,
                                                signature_object->s, &signature_object->v);
    if (err_c == no_error) {
        *sigSize = sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) +
                   signatureLength;
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(signature, signatureMaxlen);
    }

    return error;
}

zxerr_t crypto_hashChunk(const uint8_t *buffer, uint32_t bufferLen, uint8_t *output, uint16_t outputLen,
                         hash_chunk_operation_e operation) {
    if ((operation == hash_update && buffer == NULL) ||
        (operation == hash_finish && (output == NULL || outputLen < CX_SHA256_SIZE))) {
        return zxerr_no_data;
    }

    switch (operation) {
        case hash_start:
            CHECK_CX_OK(cx_blake2b_init2_no_throw(&body_hash_ctx, 256, NULL, 0, NULL, 0));
            break;

        case hash_update:
            CHECK_CX_OK(cx_blake2b_update(&body_hash_ctx, buffer, bufferLen));
            break;

        case hash_finish:
            CHECK_CX_OK(cx_blake2b_final(&body_hash_ctx, output));
            break;
    }

    return zxerr_ok;
}

#else

#include "blake2.h"
#include "hexutils.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen, unsigned char *out) {
    int result = blake2(out, 32, in, inLen, NULL, 0);
    if (result != 0) {
        return zxerr_unknown;
    } else {
        return zxerr_ok;
    }
}

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    const char *tmp =
        "7f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75"
        "ce5537a087c03779";
    parseHexString(pubKey, pubKeyLen, tmp);

    return zxerr_ok;
}

#endif

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t address[68];

} __attribute__((packed)) answer_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    MEMZERO(buffer, buffer_len);

    if (buffer_len < sizeof(answer_t)) {
        return zxerr_buffer_too_small;
    }

    answer_t *const answer = (answer_t *)buffer;

    zxerr_t err = crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey));
    if (err != zxerr_ok) {
        return err;
    }

    uint8_t addr_plus_prefix[1 + SECP256K1_PK_LEN];
    MEMCPY(addr_plus_prefix + 1, answer->publicKey, SECP256K1_PK_LEN);
    addr_plus_prefix[0] = 02;

    err = encode_addr((char *)addr_plus_prefix, SECP256K1_PK_LEN + 1, (char *)answer->address);

    if (err != zxerr_ok) {
        return err;
    }

    *addrLen = sizeof_field(answer_t, address) + sizeof_field(answer_t, publicKey);
    return zxerr_ok;
}

zxerr_t encode_addr(char *address, const uint8_t addressLen, char *encodedAddr) {
    // Address Prefix must not be encoded
    bytes_to_nibbles((uint8_t *)address, 1, (uint8_t *)encodedAddr);
    encodedAddr[0] += '0';
    encodedAddr[1] += '0';

    return encode(address + 1, addressLen - 1, encodedAddr + 2);
}

zxerr_t encode(char *address, const uint8_t addressLen, char *encodedAddr) {
    const uint8_t nibblesLen = 2 * addressLen;
    if (nibblesLen > MAX_NIBBLE_LEN) {
        return zxerr_encoding_failed;
    }
    uint8_t input_nibbles[MAX_NIBBLE_LEN] = {0};
    uint8_t hash_input[BLAKE2B_256_SIZE] = {0};

    bytes_to_nibbles((uint8_t *)address, addressLen, input_nibbles);
    blake2b_hash((uint8_t *)address, addressLen, hash_input);

    uint8_t offset = 0x00;
    uint8_t index = 0x00;

    for (int i = 0; i < nibblesLen; i++) {
        const uint8_t char_index = input_nibbles[i];
        if (char_index >= sizeof(HEX_CHARS)) {
            return zxerr_out_of_bounds;
        }
        char c = HEX_CHARS[char_index];
        if (is_alphabetic(c)) {
            get_next_hash_bit((char *)hash_input, &index, &offset) ? to_uppercase((uint8_t *)&c)
                                                                   : to_lowercase((uint8_t *)&c);
        }
        encodedAddr[i] = c;
    }
    return zxerr_ok;
}

zxerr_t encode_hex(char *bytes, const uint8_t bytesLen, char *output, uint16_t outputLen) {
    const uint8_t nibblesLen = 2 * bytesLen;
    if (bytesLen > BLAKE2B_256_SIZE || outputLen < 2 * bytesLen) {
        return zxerr_encoding_failed;
    }
    uint8_t input_nibbles[2 * BLAKE2B_256_SIZE] = {0};

    bytes_to_nibbles((uint8_t *)bytes, bytesLen, input_nibbles);

    uint8_t offset = 0x00;
    uint8_t index = 0x00;

    for (int i = 0; i < nibblesLen; i++) {
        const uint8_t char_index = input_nibbles[i];
        if (char_index >= sizeof(HEX_CHARS)) {
            return zxerr_out_of_bounds;
        }
        char c = HEX_CHARS[char_index];
        if (is_alphabetic(c)) {
            get_next_hash_bit(bytes, &index, &offset) ? to_uppercase((uint8_t *)&c) : to_lowercase((uint8_t *)&c);
        }
        output[i] = c;
    }
    return zxerr_ok;
}

bool get_next_hash_bit(char *hash_input, uint8_t *index, uint8_t *offset) {
    // Return true if following bit is 1
    bool ret = ((hash_input[*index] >> *offset) & 0x01) == 0x01;
    (*offset)++;
    if (*offset >= 0x08) {
        *offset = 0x00;
        (*index)++;
    }
    return ret;
}

bool is_alphabetic(const char byte) { return (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x41 && byte <= 0x5A); }

void bytes_to_nibbles(uint8_t *bytes, uint8_t bytesLen, uint8_t *nibbles) {
    for (uint8_t i = 0; i < bytesLen; i++) {
        nibbles[2 * i] = bytes[i] >> 4;
        nibbles[2 * i + 1] = bytes[i] & 0x0F;
    }
}
