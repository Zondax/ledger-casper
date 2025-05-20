#pragma once

#include <zxformat.h>
#include <zxmacros.h>

#include "crypto.h"
#include "parser_special.h"
#include "parser_txdef.h"
#include "runtime_arg.h"
#include "timeutils.h"

#define NO_ENTITY_VERSION_PRESENT 0xFFFFFFFF

#define BLIND_SIGN_REQUIRED_ERROR_MSG "Blind sign required"
#define WASM_TOO_LARGE_ERROR_MSG "WASM too large"

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) \
    if (!(CALL)) return ERROR;

#define DISPLAY_STRING(KEYNAME, VALUE, VALUELEN)                           \
    {                                                                      \
        snprintf(outKey, outKeyLen, KEYNAME);                              \
        char buffer[100];                                                  \
        MEMZERO(buffer, sizeof(buffer));                                   \
        if ((VALUELEN) > sizeof(buffer)) {                                 \
            return parser_unexpected_buffer_end;                           \
        }                                                                  \
        MEMCPY(buffer, (char *)(VALUE), VALUELEN);                         \
        pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount); \
        return parser_ok;                                                  \
    }

#define DISPLAY_HEADER_U64(KEYNAME, HEADERPART, TX_CONTENT)                                              \
    {                                                                                                    \
        snprintf(outKey, outKeyLen, KEYNAME);                                                            \
        CHECK_PARSER_ERR(index_headerpart_##TX_CONTENT(parser_tx_obj.header, HEADERPART, ctx)); \
        uint64_t value = 0;                                                                              \
        CHECK_PARSER_ERR(readU64(ctx, &value));                                                          \
        return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);                            \
    }

#define DISPLAY_HEADER_TIMESTAMP(KEYNAME, HEADERPART, TX_CONTENT)                                        \
    {                                                                                                    \
        snprintf(outKey, outKeyLen, KEYNAME);                                                            \
        CHECK_PARSER_ERR(index_headerpart_##TX_CONTENT(parser_tx_obj.header, HEADERPART, ctx)); \
        uint64_t value = 0;                                                                              \
        CHECK_PARSER_ERR(readU64(ctx, &value));                                                          \
        value /= 1000;                                                                                   \
        char buffer[300];                                                                                \
        MEMZERO(buffer, sizeof(buffer));                                                                 \
        PARSER_ASSERT_OR_ERROR(printTimeSpecialFormat(buffer, sizeof(buffer), value) == zxerr_ok,        \
                               parser_unexpected_error);                                                 \
        pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);                               \
        return parser_ok;                                                                                \
    }

#define GEN_DEC_READFIX_UNSIGNED(BITS)                                                           \
    static inline parser_error_t _readUInt##BITS(parser_context_t *ctx, uint##BITS##_t *value) { \
        if (value == NULL) return parser_no_data;                                                \
        *value = 0u;                                                                             \
        for (uint8_t i = 0u; i < (BITS##u >> 3u); i++, ctx->offset++) {                          \
            if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end;              \
            *value += (uint##BITS##_t) * (ctx->buffer + ctx->offset) << (8u * i);                \
        }                                                                                        \
        return parser_ok;                                                                        \
    }

GEN_DEC_READFIX_UNSIGNED(8);
GEN_DEC_READFIX_UNSIGNED(16);
GEN_DEC_READFIX_UNSIGNED(32);
GEN_DEC_READFIX_UNSIGNED(64);

parser_error_t readU64(parser_context_t *ctx, uint64_t *result);
parser_error_t readU32(parser_context_t *ctx, uint32_t *result);
parser_error_t readU16(parser_context_t *ctx, uint16_t *result);
parser_error_t readU8(parser_context_t *ctx, uint8_t *result);
parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferLen, uint16_t bufferSize);
parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferLen, uint16_t bufferSize);
bool is_container_type(uint8_t cl_type);
bool is_map_type(uint8_t cl_type);
parser_error_t check_runtime_type(uint8_t cl_type);
parser_error_t parse_item(parser_context_t *ctx);
parser_error_t get_type(parser_context_t *ctx, uint8_t *runtime_type, uint8_t *option_type);
parser_error_t parseTotalLength(parser_context_t *ctx, uint32_t start, uint32_t *totalLength);
parser_error_t parse_additional_typebytes(parser_context_t *ctx, uint8_t type, uint8_t *option_type);
parser_error_t parser_printByHashAddress(const uint8_t *bytes, uint16_t byteLength, char *outVal, uint16_t outValLen,
                                         uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printBytes(const uint8_t *bytes, uint16_t byteLength, char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printAddress(const uint8_t *bytes, uint16_t byteLength, char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printU8(uint8_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printU32(uint32_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printU64(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
const char *parser_getErrorDescription(parser_error_t err);
parser_error_t add_thousand_separators(char *out, uint16_t outLen, const char *number);

__attribute__((noinline)) parser_error_t display_runtimearg_u64(parser_context_t *ctx, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
__attribute__((noinline)) parser_error_t display_runtimearg_u32(parser_context_t *ctx, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);    
__attribute__((noinline)) parser_error_t display_runtimearg_u8(parser_context_t *ctx, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
__attribute__((noinline)) parser_error_t display_runtimearg_bytes(parser_context_t *ctx, uint32_t len, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
__attribute__((noinline)) parser_error_t display_runtimearg_address(parser_context_t *ctx, uint32_t len, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
