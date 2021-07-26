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
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    err_convert_e err = convertDERtoRSV(signature_object->der_signature, info,  signature_object->r, signature_object->s, &signature_object->v);
    if (err != no_error) {
        // Error while converting so return length 0
        MEMZERO(signature, signatureMaxlen);
        return zxerr_unknown;
    }
    *sigSize = SIG_RS_LEN;

    return zxerr_ok;
}

#else

#include "blake2.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen,
                     unsigned char *out){
    int result = blake2(out, 32, in, inLen, NULL, 0);
    if(result != 0){
        return zxerr_unknown;
    }else{
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
