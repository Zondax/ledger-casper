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
#include "parser_special.h"
#include "runtime_arg.h"

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

    ctx->tx_obj = &parser_tx_obj;
    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    entry_point_offset = 0;

    memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));

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
        case parser_runtimearg_notfound:
            return "RuntimArg not found";
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

bool is_container_type(uint8_t cl_type) {
    return cl_type == TAG_OPTION || cl_type == TAG_LIST
    || (cl_type >= TAG_RESULT && cl_type <= TAG_ANY);
}

bool is_map_type(uint8_t cl_type) {
    return cl_type == TAG_MAP;
}

parser_error_t parse_additional_typebytes(parser_context_t *ctx, uint8_t type, uint8_t *option_type) {
    switch (type) {
        case TAG_BOOL: {
            return parser_ok;
        }

        case TAG_U8:
        case TAG_U32:
        case TAG_U64:
        case TAG_U128:
        case TAG_U256:
        case TAG_I32:
        case TAG_I64:
        case TAG_U512: {
            return parser_ok;
        }

        case TAG_UNIT: {
            return parser_ok;
        }

        case TAG_STRING: {
            return parser_ok;
        }

        //only account_hash for "from" supported
        case TAG_KEY: {
            return parser_ok;
        }

        case TAG_UREF: {
            return parser_ok;
        }

        // parse any option as long as the inner type is not a container
        // to be clear, the presentation layer only support
        // OPtion<u64> and Option<uref>
        case TAG_OPTION: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            // keep commented code just to clarify that we now parse any Option
            // as long as the inner type is not a container type,
            // in the presentation layer the only valid options are
            // the one commented bellow
            /*if(inner_type != TAG_U64 && inner_type != TAG_UREF){*/
            if(is_container_type(inner_type)){
                return parser_unexpected_type;
            }else{
                *option_type = inner_type;
                uint8_t dummy_inner = 255;
                return parse_additional_typebytes(ctx, inner_type, &dummy_inner);
            }
        }

        case TAG_BYTE_ARRAY: {
            uint32_t num_bytes = 0;
            return _readUInt32(ctx, &num_bytes);
        }

        case TAG_PUBLIC_KEY: {
            return parser_ok;
        }

        // Parse any list as long as inner type is not a container
        // presentation layer do not support list though, this is intended
        // to support generic runtime-args in transactions
        // so arguments of this type are hashed
        case TAG_LIST: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            if(is_container_type(inner_type)){
                return parser_unexpected_type;
            }else{
                *option_type = inner_type;
                return parse_additional_typebytes(ctx, inner_type, &inner_type);
            }
        }

        // Parse any result as long as ok and error types are not a container
        // presentation layer do not support result though, this is intended
        // to support generic runtime-args in transactions
        // so arguments of this type are hashed
        case TAG_RESULT: {
            uint8_t ok_type = 0;
            uint8_t err_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &ok_type));
            CHECK_PARSER_ERR(_readUInt8(ctx, &err_type));
            if(is_container_type(ok_type) || is_container_type(err_type)){
                return parser_unexpected_type;
            }else{
                parser_error_t err = parse_additional_typebytes(ctx, ok_type, option_type);
                return err | parse_additional_typebytes(ctx, err_type, option_type);
            }
        }

        case TAG_TUPLE1:
        case TAG_TUPLE2:
        case TAG_TUPLE3: {
            const uint8_t elements_len = type - TAG_TUPLE1 + 1;
            uint8_t element[TAG_TUPLE3 - TAG_TUPLE1 + 1] = {0}; // 3
            uint8_t inner_type = 0;
            parser_error_t err = parser_ok;

            for(uint8_t i = 0; i < elements_len; i++) {
                CHECK_PARSER_ERR(_readUInt8(ctx, &element[i]));
                if (is_container_type(element[i])) {
                    return parser_unexpected_type;
                }
            }

            for(uint8_t i = 0; i < elements_len; i++) {
                err |= parse_additional_typebytes(ctx, element[i], &inner_type);
            }

            return err;
        }

        case TAG_MAP: {
            uint8_t key_type = 0;
            uint8_t value_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &key_type));
            CHECK_PARSER_ERR(_readUInt8(ctx, &value_type));

            // do not support nested maps
            if(is_map_type(key_type) || is_map_type(value_type)) {
                return parser_unexpected_type;
            }

            parser_error_t err = parse_additional_typebytes(ctx, key_type, option_type);
            return err | parse_additional_typebytes(ctx, value_type, option_type);
        }

        case TAG_ANY: {
            // any is an empty type
            // https://docs.rs/casper-types/4.0.1/src/casper_types/cl_type.rs.html#138
            // nothing to do here.
            return parser_ok;
        }
       default : {
            // we support now generic arguments
            // in transactions but we only support
            // the types define above
             zemu_log("type not supported\n");
            return parser_unexpected_type;
        }
    }
}

parser_error_t parse_item(parser_context_t *ctx) {
    uint32_t part = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &part));
    if(part >= ctx->bufferLen - ctx->offset){
        return parser_unexpected_buffer_end;
    }
    ctx->offset += part;
    return parser_ok;
}

parser_error_t get_type(parser_context_t *ctx, uint8_t *runtime_type, uint8_t *option_type) {
    zemu_log_stack("get_type");
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

parser_error_t copy_item_into_charbuffer(parser_context_t *ctx, char *buffer, uint16_t bufferLen){
    uint32_t part = 0;
    CHECK_PARSER_ERR(readU32(ctx, &part));
    if(part > bufferLen || part > ctx->bufferLen - ctx->offset){
        return parser_unexpected_buffer_end;
    }
    MEMZERO(buffer, bufferLen);
    MEMCPY(buffer, (char *) (ctx->buffer + ctx->offset), part);
    ctx->offset += part;
    return parser_ok;
}

parser_error_t parseModuleBytes(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;

    CHECK_PARSER_ERR(parse_item(ctx));
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &deploy_argLen));
    if(item->phase == Payment){
        CHECK_PARSER_ERR(parseSystemPayment(ctx, item, deploy_argLen)); //only support for system payment
        item->special_type = SystemPayment;
    }else{
        CHECK_PARSER_ERR(parseDelegation(ctx, item, deploy_argLen, false));
    }

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parseTransfer(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &deploy_argLen));
    //only support for native transfers now
    CHECK_PARSER_ERR(parseNativeTransfer(ctx, item, deploy_argLen));
    item->special_type = NativeTransfer;
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parse_version(parser_context_t *ctx, uint32_t *version){
    uint8_t type = 0xff;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    if (type == 0x00) {
    /*nothing to do : empty version */
    } else if (type == 0x01) {
        CHECK_PARSER_ERR(_readUInt32(ctx, version));
    } else {
        return parser_context_unknown_prefix;
    }
    return parser_ok;
}

parser_error_t check_entrypoint(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t *num_runs){
    char buffer[100] = {0};
    // set the offset for later retrival
    entry_point_offset = ctx->offset;

    CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
    item->itemOffset = ctx->offset;
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &deploy_argLen));
    bool redelegation = false;

    if (strcmp(buffer, "delegate") == 0) {
        //is delegation
        item->special_type = Delegate;
    }else if (strcmp(buffer, "undelegate") == 0) {
        item->special_type = UnDelegate;
    }else if (strcmp(buffer, "redelegate") == 0) {
        item->special_type = ReDelegate;
        redelegation = true;
    }

    // anything else is generic
    if (!redelegation && item->special_type == 255)
        item->special_type = Generic;

    zemu_log("entry_point-->: ");
    zemu_log(buffer);
    zemu_log("\n");
    CHECK_PARSER_ERR(parseDelegation(ctx, item, deploy_argLen,redelegation))
    *num_runs = deploy_argLen;

    return parser_ok;
}


parser_error_t
parseStoredContractByHash(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    ctx->offset += HASH_LENGTH;
    uint32_t dummy = 0;
    if (item->type == StoredVersionedContractByHash) {
        CHECK_PARSER_ERR(parse_version(ctx, &dummy))
        if(app_mode_expert()){
            item->UI_fixed_items++;
        }
    }
    uint32_t num_runtimeargs = 0;
    CHECK_PARSER_ERR(check_entrypoint(ctx, item, &num_runtimeargs));

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx,num_runtimeargs));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t
parseStoredContractByName(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    CHECK_PARSER_ERR(parse_item(ctx));

    uint32_t dummy = 0;
    if (item->type == StoredVersionedContractByName) {
        CHECK_PARSER_ERR(parse_version(ctx, &dummy))
        if(app_mode_expert()){
            item->UI_fixed_items++;
        }
    }

    uint32_t num_runtimeargs = 0;
    CHECK_PARSER_ERR(check_entrypoint(ctx, item, &num_runtimeargs));
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx,num_runtimeargs));

    return parseTotalLength(ctx, start, &item->totalLength);
}


parser_error_t
parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item) {
    item->totalLength = 0;
    item->UI_fixed_items = 0;
    item->UI_runtime_items = 0;
    item->num_runtime_args = 0;
    item->with_generic_args = 0;
    item->special_type = 255;
    switch (item->type) {
        case ModuleBytes : {
            return parseModuleBytes(ctx, item);
        }

        case StoredVersionedContractByHash :
        case StoredContractByHash : {
            return parseStoredContractByHash(ctx,item);
        }

        case StoredVersionedContractByName :
        case StoredContractByName : {
            return parseStoredContractByName(ctx,item);
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
    v->header.pubkeytype = ctx->buffer[0];
    PARSER_ASSERT_OR_ERROR(v->header.pubkeytype == 0x01 || v->header.pubkeytype == 0x02, parser_context_unknown_prefix);

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

    if (v->payment.special_type == SystemPayment && !v->payment.hasAmount) {
        return parser_no_data;
    }

    type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    v->session.phase = Session;
    CHECK_PARSER_ERR(parseDeployType(type, &v->session.type));
    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->session));

    v->type = Transaction;
    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    uint8_t hash[BLAKE2B_256_SIZE] = {0};

    //check headerhash
    if (blake2b_hash(c->buffer,headerLength(v->header),hash) != zxerr_ok){
        return parser_unexepected_error;
    }
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + headerLength(v->header), BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    //check bodyhash
    MEMZERO(hash, sizeof(hash));
    uint16_t index = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint32_t size = v->payment.totalLength + v->session.totalLength;
    if (blake2b_hash(c->buffer + index,size,hash) != zxerr_ok){
        return parser_unexepected_error;
    }

    index = 0;
    CHECK_PARSER_ERR(index_headerpart(v->header,header_bodyhash, &index));
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + index, BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    return parser_ok;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const parser_tx_t *v) {
    uint8_t basicnum = app_mode_expert() ? 9 : 4;
    uint8_t itemCount =
            basicnum + v->payment.UI_fixed_items + v->payment.UI_runtime_items + v->session.UI_fixed_items + v->session.UI_runtime_items; //header + payment + session v->session.num_items
    return itemCount;
}
