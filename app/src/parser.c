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

#include <stdio.h>
#include <zxmacros.h>
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    parser_error_t err =  _read(ctx, &parser_tx_obj);
    return err;
}

parser_error_t parser_printBytes(uint8_t *bytes, uint16_t byteLength,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount){
    char buffer[300];
    MEMZERO(buffer, sizeof(buffer));
    array_to_hexstr(buffer, sizeof(buffer), bytes, byteLength);
    pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_printU64(uint64_t value, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx,
                                            uint8_t *pageCount){
    char tmpBuffer[100];
    fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), value, 0);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}


parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    return parser_ok;
}

parser_error_t parser_getItem(parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Account");
        uint16_t index = 0;
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_pubkey, &index));
        return parser_printBytes(ctx->buffer + index, SECP256K1_PK_LEN, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Timestamp");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_timestamp, &ctx->offset));
        uint64_t value = 0;
        CHECK_PARSER_ERR(readU64(ctx,&value));
        return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "TTL");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_ttl, &ctx->offset));
        uint64_t value = 0;
        CHECK_PARSER_ERR(readU64(ctx,&value));
        return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Gas price");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_gasprice, &ctx->offset));
        uint64_t value = 0;
        CHECK_PARSER_ERR(readU64(ctx,&value));
        return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Chain name");
        snprintf(outVal, outValLen, "Casper Example");
        //FIXME: grab the network name from the bytes?
//        uint16_t index = 0 ;
//        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_chainname, &index));
//        char buffer[100];
//        MEMZERO(buffer, sizeof(buffer));
//        MEMCPY(buffer, (char *)(ctx->buffer + index), parser_tx_obj.header.lenChainName);
//        asciify_ext(buffer,buffer);
//        pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
        return parser_ok;
    }



    //pub account: PublicKey,             //1 + 32/33
//pub timestamp: Timestamp,           //8
//pub ttl: TimeDiff,                  //8
//pub gas_price: u64,                 //8
//pub body_hash: Digest,              //32
//pub dependencies: Vec<DeployHash>,  //4 + len*32
//pub chain_name: String,             //4+14 = 18

    return parser_ok;
}
