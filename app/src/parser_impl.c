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
            *index = 0;
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

parser_error_t check_runtime_type(uint8_t cl_type) {
    if (cl_type > NUM_RUNTIME_TYPES) {
        return parser_context_unknown_prefix;
    } else {
        return parser_ok;
    }
}

/*
 * const CL_TYPE_TAG_BOOL: u8 = 0;
const CL_TYPE_TAG_I32: u8 = 1;
const CL_TYPE_TAG_I64: u8 = 2;
const CL_TYPE_TAG_U8: u8 = 3;
const CL_TYPE_TAG_U32: u8 = 4;
const CL_TYPE_TAG_U64: u8 = 5;
const CL_TYPE_TAG_U128: u8 = 6;
const CL_TYPE_TAG_U256: u8 = 7;
const CL_TYPE_TAG_U512: u8 = 8;
const CL_TYPE_TAG_UNIT: u8 = 9;
const CL_TYPE_TAG_STRING: u8 = 10;
const CL_TYPE_TAG_KEY: u8 = 11;
const CL_TYPE_TAG_UREF: u8 = 12;
const CL_TYPE_TAG_OPTION: u8 = 13;
const CL_TYPE_TAG_LIST: u8 = 14;
const CL_TYPE_TAG_BYTE_ARRAY: u8 = 15;
const CL_TYPE_TAG_RESULT: u8 = 16;
const CL_TYPE_TAG_MAP: u8 = 17;
const CL_TYPE_TAG_TUPLE1: u8 = 18;
const CL_TYPE_TAG_TUPLE2: u8 = 19;
const CL_TYPE_TAG_TUPLE3: u8 = 20;
const CL_TYPE_TAG_ANY: u8 = 21;
const CL_TYPE_TAG_PUBLIC_KEY: u8 = 22;
 */

parser_error_t parse_additional_typebytes(parser_context_t *ctx, uint8_t type, uint8_t *option_type) {
    switch (type) {
        case 8: {
            return parser_ok;
        }

        case 10 : {
            return parser_ok;
        }

        //only account_hash for "from" supported
        case 11 : {
            return parser_ok;
        }

        case 12 : {
            return parser_ok;
        }

        //option with U64 inside for ID
        case 13: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            if(inner_type != 5 && inner_type != 12){
                return parser_unexpected_type;
            }else{
                *option_type = inner_type;
                return parser_ok;
            }
        }

        case 15: {
            uint32_t num_bytes = 0;
            return _readUInt32(ctx, &num_bytes);
        }

        default : {
            return parser_unexpected_type;
        }
    }
}

parser_error_t parse_item(parser_context_t *ctx) {
    uint32_t part = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &part));
    ctx->offset += part;
    return parser_ok;
}

parser_error_t get_type(parser_context_t *ctx, uint8_t *runtime_type, uint8_t *option_type) {
    uint8_t type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    CHECK_PARSER_ERR(check_runtime_type(type));
    CHECK_PARSER_ERR(parse_additional_typebytes(ctx, type, option_type));
    *runtime_type = type;
    return parser_ok;
}

parser_error_t parseTotalLength(parser_context_t *ctx, uint32_t start, uint32_t *totalLength) {
    PARSER_ASSERT_OR_ERROR(*(uint32_t *) &ctx->offset > start, parser_unexepected_error);
    *totalLength = (*(uint32_t *) &ctx->offset - start) + 1;
    return parser_ok;
}

parser_error_t parseRuntimeArgs(parser_context_t *ctx, uint32_t deploy_argLen) {
    uint8_t dummy_type = 0;
    uint8_t dummy_internal = 0;
    for (uint32_t i = 0; i < deploy_argLen; i++) {
        //key
        CHECK_PARSER_ERR(parse_item(ctx));

        //value
        CHECK_PARSER_ERR(parse_item(ctx));
        //type
        CHECK_PARSER_ERR(get_type(ctx, &dummy_type, &dummy_internal));

    }
    return parser_ok;
}

parser_error_t searchRuntimeArgs(char *argstr, uint8_t *type, uint8_t *internal_type, uint32_t deploy_argLen, parser_context_t *ctx) {
    uint16_t start = ctx->offset;
    char buffer[300];
    uint8_t dummy_type = 0;
    uint8_t dummy_internal = 0;
    for (uint32_t i = 0; i < deploy_argLen; i++) {
        //key
        uint32_t part = 0;
        CHECK_PARSER_ERR(readU32(ctx, &part));
        MEMZERO(buffer, sizeof(buffer));
        MEMCPY(buffer, (char *) (ctx->buffer + ctx->offset), part);
        if (strcmp(buffer, argstr) == 0) {
            ctx->offset += part;
            //value
            CHECK_PARSER_ERR(parse_item(ctx));

            CHECK_PARSER_ERR(get_type(ctx, type, internal_type));

            ctx->offset = start;
            return parser_ok;
        }
        ctx->offset += part;
        //value
        CHECK_PARSER_ERR(parse_item(ctx));

        CHECK_PARSER_ERR(get_type(ctx, &dummy_type, &dummy_internal));

    }
    return parser_runtimearg_notfound;
}

#define CHECK_RUNTIME_ARGTYPE(STR,CONDITION) { \
    type = 255;                     \
    internal_type = 255;                                           \
    CHECK_PARSER_ERR(searchRuntimeArgs((STR), &type, &internal_type, deploy_argLen, ctx));          \
    PARSER_ASSERT_OR_ERROR((CONDITION), parser_unexpected_type);                                      \
}

parser_error_t parseNativeTransfer(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    item->fixed_items += 1;               //type of transfer
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &deploy_argLen));
    PARSER_ASSERT_OR_ERROR(3 <= deploy_argLen && deploy_argLen <= 4, parser_unexpected_number_items);
    uint8_t type = 0;
    uint8_t internal_type = 0;
    CHECK_RUNTIME_ARGTYPE("amount", type == 8);
    CHECK_RUNTIME_ARGTYPE("id", type == 13 && internal_type == 5);
    CHECK_RUNTIME_ARGTYPE("target", type == 11 || type == 12 || type == 15);
    if(deploy_argLen == 4){
        CHECK_RUNTIME_ARGTYPE("source", type == 13 && internal_type == 12);
    }
    if(app_mode_expert()){
        item->runtime_items += deploy_argLen;
    }else{
        item->runtime_items += 2; //amount and target only
    }
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parseModuleBytes(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;

    uint16_t index = ctx->offset;
    CHECK_PARSER_ERR(parse_item(ctx));
    if (ctx->offset - index == 4) {                          //this means the module bytes are empty
        item->fixed_items += 1;
    } else {
        return parser_unexpected_method; //only system payments support
    }
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &deploy_argLen));
    uint8_t type = 255;
    uint8_t internal_type = 0;
    CHECK_RUNTIME_ARGTYPE("amount", type == 8);
    item->runtime_items += 1; //amount only
    PARSER_ASSERT_OR_ERROR(deploy_argLen == 1, parser_unexpected_number_items);
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t
parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item) {
    item->totalLength = 0;
    item->fixed_items = 0;
    item->runtime_items = 0;
    switch (item->type) {
        case ModuleBytes : {
            return parseModuleBytes(ctx, item);
        }

        case StoredVersionedContractByHash :
        case StoredContractByHash : {
            return parser_unexpected_method;
        }

        case StoredVersionedContractByName :
        case StoredContractByName : {
            return parser_unexpected_method;
        }

        case Transfer : {
            return parseNativeTransfer(ctx, item);
        }
        default : {
            return parser_context_mismatch;
        }
    }
}

parser_error_t _read(parser_context_t *ctx, parser_tx_t *v) {
    //PARSER_ASSERT_OR_ERROR(ctx->buffer[0] == 0x02, parser_context_unknown_prefix);
    v->header.pubkeytype = ctx->buffer[0];

    CHECK_PARSER_ERR(index_headerpart(v->header, header_deps, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenDependencies));

    CHECK_PARSER_ERR(index_headerpart(v->header, header_chainname, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenChainName));

    ctx->offset = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint8_t type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    v->payment.phase = Payment;
    CHECK_PARSER_ERR(parseDeployType(type, &v->payment.type));
    if(v->payment.type != ModuleBytes){
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->payment));

    type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    v->session.phase = Session;
    CHECK_PARSER_ERR(parseDeployType(type, &v->session.type));
    if(v->session.type != Transfer){
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->session));

    return parser_ok;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
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

    return parser_ok;
}
#else

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    return parser_ok;
}

#endif

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    UNUSED(c);
    uint8_t basicnum = app_mode_expert() ? 7 : 3;
    uint8_t itemCount = 1 +
            basicnum + v->payment.fixed_items + v->payment.runtime_items + v->session.fixed_items + v->session.runtime_items; //header + payment + session v->session.num_items
    return itemCount;
}
