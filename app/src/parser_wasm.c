/*******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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
#include "app_mode.h"
#include "common/parser.h"
#include "crypto.h"
#include "parser_impl_deploy.h"
#include "parser_message.h"
#include "parser_utils.h"
#include "zxformat.h"

static parser_error_t readHeader(parser_context_t *ctx, parser_tx_deploy_t *txObj) {
    txObj->header.pubkeytype = ctx->buffer[0];
    PARSER_ASSERT_OR_ERROR(txObj->header.pubkeytype == 0x01 || txObj->header.pubkeytype == 0x02,
                           parser_context_unknown_prefix);

    CHECK_PARSER_ERR(index_headerpart_deploy(txObj->header, header_deps, ctx));
    CHECK_PARSER_ERR(readU32(ctx, &txObj->header.lenDependencies));

    CHECK_PARSER_ERR(index_headerpart_deploy(txObj->header, header_chainname, ctx));
    CHECK_PARSER_ERR(readU32(ctx, &txObj->header.lenChainName));

    if (ctx->bufferLen - ctx->offset < BLAKE2B_256_SIZE) {
        return parser_unexpected_buffer_end;
    }
    ctx->offset = header_length_deploy(txObj->header) + BLAKE2B_256_SIZE;
    uint8_t type = 0;
    CHECK_PARSER_ERR(readU8(ctx, &type));
    txObj->payment.phase = Payment;
    CHECK_PARSER_ERR(parseDeployType(type, &txObj->payment.type));
    if (txObj->payment.type != ModuleBytes) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(parseDeployItem(ctx, &txObj->payment));

    if (txObj->payment.special_type == SystemPayment && !txObj->payment.hasAmount) {
        return parser_no_data;
    }

    type = 0;
    CHECK_PARSER_ERR(readU8(ctx, &type));
    txObj->session.phase = Session;
    CHECK_PARSER_ERR(parseDeployType(type, &txObj->session.type));
    const parser_error_t err = parseDeployItem(ctx, &txObj->session);
    // WasmDeploy type must be ModuleBytes and
    // parseDeployItem won't return parser_ok for these kind of blobs.
    // We expect blobs from some kBs up to 1MB. In such cases, the device is not
    // able to store the transaction and parsing it. If parseDeployItem returns
    // parser_ok, then we are not processing a WasmDeploy and therefore, we
    // consider that case as an error. We expect that the parser moves until
    // parser_runtimeargs_getData method and get here one of these errors:
    // parser_unexpected_buffer_end (cannot store all the param within input
    // buffer) or parser_no_data (parameter not found)
    if (txObj->session.type == ModuleBytes && (err == parser_no_data || err == parser_unexpected_buffer_end)) {
        return parser_ok;
    }

    return parser_unexpected_error;
}

parser_error_t parser_parse_wasm(parser_context_t *ctx, const uint8_t *data, size_t dataLen, size_t bufferSize) {
    if (ctx == NULL || data == NULL || dataLen == 0 || bufferSize == 0) {
        return parser_unexpected_error;
    }

    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen, bufferSize))

    uint8_t tx_content = 0;
    CHECK_PARSER_ERR(readU8(ctx, &tx_content));
    ctx->tx_content = tx_content;

    // handleSignWasm only handles Deploys
    PARSER_ASSERT_OR_ERROR(tx_content == Deploy, parser_unexpected_type);

    // Reset ctx pointers to ignore prefix
    ctx->buffer = ctx->buffer + ctx->offset;
    ctx->bufferLen = ctx->bufferLen - ctx->offset;
    ctx->offset = 0;

    memset(&parser_tx_obj_deploy, 0, sizeof(parser_tx_obj_deploy));
    ctx->tx_obj = &parser_tx_obj_deploy;

    ((parser_tx_deploy_t *)ctx->tx_obj)->type = WasmDeploy;
    return readHeader(ctx, ctx->tx_obj);
}

parser_error_t parser_validate_wasm(const parser_context_t *ctx, const parser_tx_deploy_t *v) {
    uint8_t hash[BLAKE2B_256_SIZE] = {0};

    // check headerhash
    if (blake2b_hash(ctx->buffer, header_length_deploy(v->header), hash) != zxerr_ok) {
        return parser_unexpected_error;
    }
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash, ctx->buffer + header_length_deploy(v->header), BLAKE2B_256_SIZE) == 0,
                           parser_context_mismatch);

    return parser_ok;
}

parser_error_t parser_getWasmNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return parser_unexpected_error;
    }
    *num_items = 2;
    return parser_ok;
}

parser_error_t parser_getWasmItem(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "DeployHash");
            pageStringHex(outVal, outValLen,
                          (const char *)ctx->buffer + header_length_deploy(((parser_tx_deploy_t *)ctx->tx_obj)->header),
                          HASH_LENGTH, pageIdx, pageCount);
            return parser_ok;

        case 1:
            snprintf(outKey, outKeyLen, "BodyHash");
            CHECK_PARSER_ERR(index_headerpart_deploy(((parser_tx_deploy_t *)ctx->tx_obj)->header, header_bodyhash,
                                                    ctx));
            pageStringHex(outVal, outValLen, (const char *)ctx->buffer + ctx->offset, HASH_LENGTH, pageIdx, pageCount);
            return parser_ok;

        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
