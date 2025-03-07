#include "parser_primitives.h"
#include "common/parser.h"
#include "parser_utils.h"

#define TAG_RUNTIME_VM_CASPER_V1 0x00

#define TAG_OPTION_ABSENT 0x00
#define TAG_OPTION_PRESENT 0x01

#define TAG_SYSTEM 0x00
#define TAG_ED25519 0x01
#define TAG_SECP256K1 0x02

#define SERIALIZED_PUBLIC_KEY_LENGTH_ED25519 32
#define SERIALIZED_PUBLIC_KEY_LENGTH_SECP256K1 33
#define SERIALIZED_HASH_LENGTH 32

#define SERIALIZED_SIGNATURE_KEY_LENGTH 64

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

  printf("read_runtime - runtime: %d\n", runtime);

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

parser_error_t read_clvalue(parser_context_t *ctx) {
  uint32_t len = 0;
  CHECK_PARSER_ERR(read_bytes(ctx, &len));

  uint8_t dummy_type = 0;
  uint8_t dummy_type_internal = 0;
  CHECK_PARSER_ERR(get_type(ctx, &dummy_type, &dummy_type_internal));

  return parser_ok;
}

parser_error_t read_public_key(parser_context_t *ctx) {
  uint8_t pubkey_tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &pubkey_tag));
  PARSER_ASSERT_OR_ERROR(pubkey_tag == TAG_SYSTEM || pubkey_tag == TAG_ED25519 ||
                              pubkey_tag == TAG_SECP256K1,
                          parser_unexpected_value);
  
  if (pubkey_tag == TAG_ED25519) {
    ctx->offset += SERIALIZED_PUBLIC_KEY_LENGTH_ED25519;
  } else if (pubkey_tag == TAG_SECP256K1) {
    ctx->offset += SERIALIZED_PUBLIC_KEY_LENGTH_SECP256K1;
  }

  return parser_ok;
}

parser_error_t read_signature(parser_context_t *ctx) {
  uint8_t signature_tag = 0;
  CHECK_PARSER_ERR(readU8(ctx, &signature_tag));
  PARSER_ASSERT_OR_ERROR(signature_tag == TAG_ED25519 || signature_tag == TAG_SECP256K1,
                          parser_unexpected_value);

  ctx->offset += SERIALIZED_SIGNATURE_KEY_LENGTH;

  return parser_ok;
}

parser_error_t read_hash(parser_context_t *ctx) {
  ctx->offset += SERIALIZED_HASH_LENGTH;
  return parser_ok;
}
