#include "parser_primitives.h"
#include "common/parser.h"

#define TAG_RUNTIME_VM_CASPER_V1 0x00

#define TAG_OPTION_ABSENT 0x00
#define TAG_OPTION_PRESENT 0x01

#define ENTITY_ADDRESS_SIZE 34

// read_string
parser_error_t read_string(parser_context_t *ctx, uint32_t *outLen) {
  uint32_t len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &len));

  if (len > ctx->bufferLen - ctx->offset) {
    return parser_unexpected_value;
  }

  ctx->offset += len;
  *outLen = len;
  return parser_ok;
}

// read_bytes
parser_error_t read_bytes(parser_context_t *ctx, uint32_t *outLen) {
  uint32_t len = 0;
  CHECK_PARSER_ERR(readU32(ctx, &len));

  if (len > ctx->bufferLen - ctx->offset) {
    return parser_unexpected_value;
  }

  ctx->offset += len;
  *outLen = len;
  return parser_ok;
}
// read_bool
parser_error_t read_bool(parser_context_t *ctx, uint8_t *result) {
  CHECK_PARSER_ERR(readU8(ctx, result));

  if (*result != 0 && *result != 1) {
    return parser_unexpected_value;
  }

  return parser_ok;
}

// read_entity_version
parser_error_t read_entity_version(parser_context_t *ctx) {
  uint8_t tag = 0;
  uint32_t protocol_version = 0;
  uint32_t entity_version = 0;

  CHECK_PARSER_ERR(read_bool(ctx, &tag));

  if (tag == TAG_OPTION_PRESENT) {
    CHECK_PARSER_ERR(readU32(ctx, &protocol_version));
    CHECK_PARSER_ERR(readU32(ctx, &entity_version));
  } else if (tag == TAG_OPTION_ABSENT) {
    return parser_ok;
  } else {
    return parser_unexpected_value;
  }

  return parser_ok;
}

// read_runtime
parser_error_t read_runtime(parser_context_t *ctx) {
  uint8_t runtime = 0;
  CHECK_PARSER_ERR(readU8(ctx, &runtime));

  if (runtime != TAG_RUNTIME_VM_CASPER_V1) {
    return parser_unexpected_value;
  }

  return parser_ok;
}

//read_entity_address
parser_error_t read_entity_address(parser_context_t *ctx) {
  ctx->offset += SERIALIZED_FIELD_INDEX_SIZE;
  ctx->offset += ENTITY_ADDRESS_SIZE;
  return parser_ok;
}
