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
#include "parser_impl.h"
#include "parser_txdef.h"
#include "app_mode.h"
#include "crypto.h"

parser_tx_t parser_tx_obj;

#define GEN_DEC_READFIX_UNSIGNED(BITS) parser_error_t _readUInt ## BITS(parser_context_t *ctx, uint ## BITS ##_t *value) \
{                                                                                           \
    if (value == NULL)  return parser_no_data;                                              \
    *value = 0u;                                                                            \
    for(uint8_t i=0u; i < (BITS##u>>3u); i++, ctx->offset++) {                              \
        if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end;             \
        *value += (uint ## BITS ##_t) *(ctx->buffer + ctx->offset) << (8u*i);               \
    }                                                                                       \
    return parser_ok;                                                                       \
}

GEN_DEC_READFIX_UNSIGNED(8);

GEN_DEC_READFIX_UNSIGNED(16);

GEN_DEC_READFIX_UNSIGNED(32);

GEN_DEC_READFIX_UNSIGNED(64);

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

//pub account: PublicKey,             //1 + 32/33
//pub timestamp: Timestamp,           //8
//pub ttl: TimeDiff,                  //8
//pub gas_price: u64,                 //8
//pub body_hash: Digest,              //32
//pub dependencies: Vec<DeployHash>,  //4 + len*32
//pub chain_name: String,             //4+14 = 18

uint16_t headerLength(parser_header_t header) {
    uint16_t pubkeyLen = 1 + (header.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t fixedLen = 56;
    uint16_t depsLen = 4 + header.lenDependencies * 32;
    uint16_t chainNameLen = 4 + header.lenChainName;
    return pubkeyLen + fixedLen + depsLen + chainNameLen;
}

parser_error_t readU64(parser_context_t *ctx, uint64_t *result) {
    return _readUInt64(ctx, result);
}

parser_error_t readU32(parser_context_t *ctx, uint32_t *result) {
    return _readUInt32(ctx, result);
}

parser_error_t readU8(parser_context_t *ctx, uint8_t *result) {
    return _readUInt8(ctx, result);
}


parser_error_t index_headerpart(parser_header_t head, header_part_e part, uint16_t *index) {
    *index = 0;
    uint16_t pubkeyLen = 1 + (head.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t deployHashLen = 4 + head.lenDependencies * 32;
    switch (part) {
        case header_pubkey : {
            *index = 1;
            return parser_ok;
        }
        case header_timestamp : {
            *index = pubkeyLen;
            return parser_ok;
        }

        case header_ttl : {
            *index = pubkeyLen + 8;
            return parser_ok;
        }

        case header_gasprice : {
            *index = pubkeyLen + 16;
            return parser_ok;
        }

        case header_bodyhash : {
            *index = pubkeyLen + 24;
            return parser_ok;
        }

        case header_deps : {
            *index = pubkeyLen + 56;
            return parser_ok;
        }

        case header_chainname : {
            *index = pubkeyLen + 56 + deployHashLen;
            return parser_ok;
        }

        default : {
            return parser_unexepected_error;
        }
    }
}

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexepected_error:
            return "Unexepected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
        case parser_unexpected_tx_version:
            return "tx version is not supported";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        default:
            return "Unrecognized error code";
    }
}

parser_error_t parseDeployType(uint8_t type, deploy_type_e *deploytype) {
    if (type > NUM_DEPLOY_TYPES) {
        return parser_value_out_of_range;
    } else {
        *deploytype = type;
        return parser_ok;
    }
}

#define PARSE_ITEM(SKIP) {         \
    part = 0;                       \
    CHECK_PARSER_ERR(_readUInt32(ctx, &part));      \
    ctx->offset += part + (SKIP);                            \
}

parser_error_t parseTotalLength(parser_context_t *ctx, uint32_t start, uint32_t *totalLength) {
    PARSER_ASSERT_OR_ERROR(*(uint32_t *) &ctx->offset > start, parser_unexepected_error);
    *totalLength = (*(uint32_t *) &ctx->offset - start) + 1;
    return parser_ok;
}

parser_error_t parseRuntimeArgs(parser_context_t *ctx, uint32_t *num_items) {
    uint32_t part = 0;
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &deploy_argLen));
    *num_items += deploy_argLen;
    for (uint32_t i = 0; i < deploy_argLen; i++) {
        //key
        PARSE_ITEM(0);

        //value
        PARSE_ITEM(1);
    }
    return parser_ok;
}

#define PARSE_VERSION(CTX, ITEM) {         \
    uint8_t type = 0xff;                    \
    _readUInt8(CTX, &type);                 \
    if (type == 0x00) {                     \
    } else if (type == 0x01) {              \
        uint32_t p = 0;                     \
        _readUInt32(CTX, &p);               \
    } else {                                \
        return parser_context_unknown_prefix;   \
    }                                       \
    (ITEM)->num_items += 1;                 \
}                                           \

parser_error_t
parseStoredContractByHash(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    uint32_t part = 0;

    ctx->offset += HASH_LENGTH;

    if (item->type == StoredVersionedContractByHash) {
        PARSE_VERSION(ctx, item)
    }

    PARSE_ITEM(0);

    item->num_items += 2;

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, &item->num_items));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t
parseStoredContractByName(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    uint32_t part = 0;

    PARSE_ITEM(0);

    if (item->type == StoredVersionedContractByName) {
        PARSE_VERSION(ctx, item)
    }

    PARSE_ITEM(0);

    item->num_items += 2;

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, &item->num_items));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parseTransfer(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, &item->num_items));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parseModuleBytes(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    uint32_t part = 0;

    PARSE_ITEM(0);

    item->num_items += 1;
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, &item->num_items));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t
parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item) {
    item->totalLength = 0;
    item->num_items = 2;                                        //all have two fixed items: type & number of runtime args
    switch (item->type) {
        case ModuleBytes : {
            return parseModuleBytes(ctx, item);
        }

        case StoredVersionedContractByHash :
        case StoredContractByHash : {
            return parseStoredContractByHash(ctx, item);
        }

        case StoredVersionedContractByName :
        case StoredContractByName : {
            return parseStoredContractByName(ctx, item);
        }

        case Transfer : {
            return parseTransfer(ctx, item);
        }
        default : {
            return parser_context_mismatch;
        }
    }
}

parser_error_t _read(parser_context_t *ctx, parser_tx_t *v) {
    PARSER_ASSERT_OR_ERROR(ctx->buffer[0] == 0x02 || ctx->buffer[0] == 0x01, parser_context_unknown_prefix);
    v->header.pubkeytype = ctx->buffer[0];

    CHECK_PARSER_ERR(index_headerpart(v->header, header_deps, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenDependencies));

    CHECK_PARSER_ERR(index_headerpart(v->header, header_chainname, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenChainName));

    ctx->offset = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint8_t type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    CHECK_PARSER_ERR(parseDeployType(type, &v->payment.type));

    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->payment));

    type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    CHECK_PARSER_ERR(parseDeployType(type, &v->session.type));

    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->session));

    return parser_ok;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
parser_error_t _validateTx(parser_context_t *c, const parser_tx_t *v) {
    uint8_t hash[BLAKE2B_256_SIZE];

    //check headerhash
    MEMZERO(hash, sizeof(hash));
    blake2b_hash(c->buffer,headerLength(v->header),hash);
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + headerLength(v->header), BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    //check bodyhash
    MEMZERO(hash, sizeof(hash));
    uint16_t index = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint32_t size = v->payment.totalLength + v->session.totalLength;
    blake2b_hash(c->buffer + index,size,hash);

    index = 0;
    CHECK_PARSER_ERR(index_headerpart(v->header,header_bodyhash, &index));
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + index, BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    uint16_t index_signatures = headerLength(v->header) + 32 + v->payment.totalLength + v->session.totalLength;
    c->offset = index_signatures;
    uint32_t num_signatures = 0 ;
    CHECK_PARSER_ERR(_readUInt32(c, &num_signatures));
    uint8_t *digest = c->buffer + headerLength(v->header);
    for(uint16_t i = 0; i < num_signatures; i++){
        char buf[140];
        array_to_hexstr(buf, sizeof(buf), (const uint8_t *)c->buffer + c->offset, 32);
        zemu_log("offset  :"); zemu_log(buf); zemu_log("\n");
        uint8_t pubkeyType = 0;
        CHECK_PARSER_ERR(_readUInt8(c, &pubkeyType));
        uint8_t *pubkey = c->buffer + c->offset;
        c->offset += (pubkeyType == 0x01) ? 32 : 33;
        array_to_hexstr(buf, sizeof(buf), (const uint8_t *)c->buffer + c->offset, 32);
        zemu_log("offset  :"); zemu_log(buf); zemu_log("\n");
        uint8_t signType = 0;
        CHECK_PARSER_ERR(_readUInt8(c, &signType));
        PARSER_ASSERT_OR_ERROR(pubkeyType == signType, parser_context_mismatch);
        uint8_t *signature = c->buffer + c->offset;
        switch(pubkeyType) {
            case 0x01: {
                bool verify = crypto_verify_ed25519_signature(pubkey, signature, digest);
                PARSER_ASSERT_OR_ERROR(verify, parser_context_mismatch);
                break;
            }
            case 0x02: {
                bool verify = crypto_verify_secp256k1_signature(pubkey, signature, digest);
                PARSER_ASSERT_OR_ERROR(verify, parser_context_mismatch);
                break;
            }
            default : {
                return parser_no_data;
            }
        }
        c->offset += 64;
    }

    return parser_ok;
}
#else

parser_error_t _validateTx(parser_context_t *c, const parser_tx_t *v) {
    return parser_ok;
}

#endif

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    uint8_t itemCount =
            5 + v->payment.num_items + v->session.num_items; //header + payment + session v->session.num_items
    return itemCount;
}
