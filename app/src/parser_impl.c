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

parser_tx_t parser_tx_obj;

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

//pub account: PublicKey,             //1 + 32/33
//pub timestamp: Timestamp,           //8
//pub ttl: TimeDiff,                  //8
//pub gas_price: u64,                 //8
//pub body_hash: Digest,              //32
//pub dependencies: Vec<DeployHash>,  //4 + len*32
//pub chain_name: String,             //4+14 = 18

uint16_t headerLength(parser_header_t header){
    uint16_t pubkeyLen = 1 + (header.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t depsLen = 4 +  header.lenDependencies * 32;
    uint16_t chainNameLen = 4 + header.lenChainName;
    return pubkeyLen + depsLen + chainNameLen;
}

zxerr_t index_headerpart(parser_header_t head, header_part_e part, uint16_t *index){
    *index = 0;
    uint16_t pubkeyLen = 1 + (head.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t deployHashLen = 4 + head.lenDependencies * 32;
    switch (part){
        case header_pubkey : {
            *index = 0;
            return zxerr_ok;
        }
        case header_timestamp : {
            *index = pubkeyLen;
            return zxerr_ok;
        }

        case header_ttl : {
            *index = pubkeyLen + 8;
            return zxerr_ok;
        }

        case header_gasprice : {
            *index = pubkeyLen + 16;
            return zxerr_ok;
        }

        case header_bodyhash : {
            *index = pubkeyLen + 24;
            return zxerr_ok;
        }

        case header_deps : {
            *index = pubkeyLen + 56;
            return zxerr_ok;
        }

        case header_chainname : {
            *index = pubkeyLen + deployHashLen;
            return zxerr_ok;
        }

        default : {
            return zxerr_unknown;
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

parser_error_t _read(parser_context_t *c, parser_tx_t *v) {
    uint8_t type = c->buffer[0];
    PARSER_ASSERT_OR_ERROR(type == 0x02, parser_context_unknown_prefix);
    MEMCPY(&v->header.pubkeytype, &type, 1);

    CHECK_ZXERR(index_headerpart(v->header, header_deps, &c->offset));
    CHECK_PARSER_ERR(_readUInt32(&c, &v->header.lenDependencies));

    CHECK_ZXERR(index_headerpart(v->header, header_chainname, &c->offset));
    CHECK_PARSER_ERR(_readUInt32(&c, &v->header.lenChainName));

    PARSER_ASSERT_OR_ERROR(v->header.lenDependencies == 1, parser_context_unknown_prefix);

    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    // Note: This is place holder for transaction level checks that the project may require before accepting
    // the parsed values. the parser already validates input
    // This function is called by parser_validate, where additional checks are made (formatting, UI/UX, etc.(
    return parser_ok;
}

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    uint8_t itemCount = 9;

    return itemCount;
}
