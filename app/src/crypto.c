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
#include "zxmacros.h"
#include "parser_impl.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

const char HEX_CHARS[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
'a', 'b', 'c', 'd', 'e', 'f'};

static bool is_alphabetic(const char byte);
static void to_uppercase(char* letter);
static void to_lowercase(char* letter);
static bool get_next_hash_bit(uint8_t* hash_input, uint8_t* index, uint8_t* offset);

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out) {
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, NULL, 0);
    cx_hash(&ctx.header, CX_LAST, in, inLen, out, 32);
    return zxerr_ok;
}

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    return zxerr_ok;
}

zxerr_t pubkey_to_hash(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *out){
    uint8_t preimage[100];
    uint16_t preimageLen = 0;
    MEMZERO(preimage, sizeof(preimage));
    uint8_t type = pubkey[0];
    switch(type){
        case 0x00 :{
            MEMCPY(preimage, (uint8_t *)"system", 6);
            preimageLen+=6;
            break;
        }
        case 0x01 : {
            MEMCPY(preimage, (uint8_t *)"ed25519", 7);
            preimageLen += 7;
            break;
        }
        case 0x02 : {
            MEMCPY(preimage, (uint8_t *)"secp256k1", 9);
            preimageLen += 9;
            break;
        }
        default : {
            return zxerr_unknown;
        }
    }

    preimage[preimageLen++] = 0;
    MEMCPY(preimage + preimageLen, pubkey+1, pubkeyLen-1);
    preimageLen += pubkeyLen-1;
    blake2b_hash(preimage, preimageLen,
                 out);
    return zxerr_ok;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;


zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize) {
    UNUSED(messageLen);

    MEMZERO(signature, signatureMaxlen);

    const uint8_t *message_digest = message + headerLength(parser_tx_obj.header);

    uint8_t hash[CX_SHA256_SIZE];
    MEMCPY(hash, message_digest, CX_SHA256_SIZE);
    cx_hash_sha256(message_digest, CX_SHA256_SIZE, hash, CX_SHA256_SIZE);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    unsigned int info = 0;

    signature_t *const signature_object = (signature_t *) signature;
    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                                      hdPath,
                                                      HDPATH_LEN_DEFAULT,
                                                      privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            hash,
                                            CX_SHA256_SIZE,
                                            signature_object->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);

            err_convert_e err_c = convertDERtoRSV(signature_object->der_signature, info,  signature_object->r, signature_object->s, &signature_object->v);
            if (err_c != no_error) {
                // Error while converting so return length 0
                MEMZERO(signature, signatureMaxlen);
                err = zxerr_unknown;
            }else{
                *sigSize = SIG_RS_LEN;
            }
        }
        CATCH_ALL {
            MEMZERO(signature, signatureMaxlen);
            err = zxerr_unknown;
        };
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

#else

#include "blake2.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen,
                     unsigned char *out){
    int result = blake2(out, 32, in, inLen, NULL, 0);
    if (result != 0) {
        return zxerr_unknown;
    } else {
        return zxerr_ok;
    }
}

#endif

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];

} __attribute__((packed)) answer_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    MEMZERO(buffer, buffer_len);

    if (buffer_len < sizeof(answer_t)) {
        zemu_log_stack("crypto_fillAddress: zxerr_buffer_too_small");
        return zxerr_buffer_too_small;
    }

    answer_t *const answer = (answer_t *) buffer;

    zxerr_t err = crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey));
    if (err != zxerr_ok) {
        return err;
    }

    *addrLen = sizeof_field(answer_t, publicKey);
    return zxerr_ok;
}

zxerr_t encode_addr(char* address, const uint8_t addressLen, char* encodedAddr) {
    //Address Prefix must not be encoded
    bytes_to_nibbles((uint8_t*)address, 1, (uint8_t*)encodedAddr);
    encodedAddr[0] += '0';
    encodedAddr[1] += '0';

    return encode(address+1, addressLen-1, encodedAddr+2);
}

zxerr_t encode(char* address, const uint8_t addressLen, char* encodedAddr) {
    const uint8_t nibblesLen = 2 * addressLen;
    uint8_t input_nibbles[nibblesLen];
    uint8_t hash_input[BLAKE2B_256_SIZE];

    bytes_to_nibbles((uint8_t*)address, addressLen, input_nibbles);
    blake2b_hash((uint8_t*)address, addressLen, hash_input);

    uint8_t offset = 0x00;
    uint8_t index = 0x00;

    for(int i = 0; i < nibblesLen; i++) {
        char c = HEX_CHARS[input_nibbles[i]];
        if(is_alphabetic(c)) {
            get_next_hash_bit(hash_input, &index, &offset) ? to_uppercase(&c) : to_lowercase(&c);
        }
        encodedAddr[i] = c;
    }
    return zxerr_ok;
}

bool get_next_hash_bit(uint8_t* hash_input, uint8_t* index, uint8_t* offset) {
    //Return true if following bit is 1
    bool ret = ((hash_input[*index] >> *offset) & 0x01) == 0x01;
    (*offset)++;
    if(*offset >= 0x08) {
        *offset = 0x00;
        (*index)++;
    }
    return ret;
}

bool is_alphabetic(const char byte) {
    return  (byte >= 0x61  && byte <= 0x7A) ||
            (byte >= 0x41  && byte <= 0x5A);
}

void to_uppercase(char* letter) {
    //Check if lowercase letter
    if(*letter >= 0x61  && *letter <= 0x7A) {
        *letter = *letter - 0x20;
    }
}

void to_lowercase(char* letter) {
    //Check if uppercase letter
    if(*letter >= 0x41  && *letter <= 0x5A) {
        *letter = *letter + 0x20;
    }
}

void bytes_to_nibbles(uint8_t* bytes,uint8_t bytesLen, uint8_t* nibbles) {
    for(uint8_t i = 0; i < bytesLen; i++){
        nibbles[2*i] = bytes[i] >> 4;
        nibbles[2*i+1] = bytes[i] & 0x0F;
    }
}
