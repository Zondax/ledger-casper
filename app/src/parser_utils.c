#include <zxmacros.h>
#include "parser_txdef.h"
#include "parser_utils.h"
#include "parser_special.h"
#include "runtime_arg.h"

parser_error_t readU64(parser_context_t *ctx, uint64_t *result) {
    return _readUInt64(ctx, result);
}

parser_error_t readU32(parser_context_t *ctx, uint32_t *result) {
    return _readUInt32(ctx, result);
}

parser_error_t readU8(parser_context_t *ctx, uint8_t *result) {
    return _readUInt8(ctx, result);
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

    entry_point_offset = 0;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
    return parser_ok;
}

bool is_container_type(uint8_t cl_type) {
    return cl_type == TAG_OPTION || cl_type == TAG_LIST
    || (cl_type >= TAG_RESULT && cl_type <= TAG_ANY);
}

bool is_map_type(uint8_t cl_type) {
    return cl_type == TAG_MAP;
}

parser_error_t check_runtime_type(uint8_t cl_type) {
    if (cl_type > NUM_RUNTIME_TYPES) {
        return parser_context_unknown_prefix;
    } else {
        return parser_ok;
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

parser_error_t parser_printBytes(const uint8_t *bytes, uint16_t byteLength,
                                 char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    char encodedAddr[100];
    MEMZERO(encodedAddr, sizeof(encodedAddr));
    encode((char*)bytes, byteLength, encodedAddr);
    pageString(outVal, outValLen, encodedAddr, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_printAddress(const uint8_t *bytes, uint16_t byteLength,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));

    encode_addr((char*)bytes, byteLength, buffer);

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_printU32(uint32_t value, char *outVal,
                               uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {
    char tmpBuffer[30];
    fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), (uint64_t)value, 0);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}


parser_error_t parser_printU64(uint64_t value, char *outVal,
                               uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {
    char tmpBuffer[30];
    fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), value, 0);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
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
        case parser_unexpected_number_fields:
            return "Unexpected number of fields";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_unexpected_field_offset:
            return "Unexpected field offset";
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
