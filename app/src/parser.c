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
#include "app_mode.h"
#include "bignum.h"
#include "crypto.h"
#include "timeutils.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    parser_error_t err = _read(ctx, &parser_tx_obj);
    return err;
}

parser_error_t parser_printBytes(const uint8_t *bytes, uint16_t byteLength,
                                 char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[300];
    MEMZERO(buffer, sizeof(buffer));
    array_to_hexstr(buffer, sizeof(buffer), bytes, byteLength);
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_printU64(uint64_t value, char *outVal,
                               uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {
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
        CHECK_PARSER_ERR(
                parser_getItem((parser_context_t *) ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0,
                               &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    return parser_ok;
}

#define DISPLAY_TYPE(KEYNAME, TYPE) { \
    snprintf(outKey, outKeyLen, "%s Type", KEYNAME);     \
    snprintf(outVal, outValLen, TYPE);                \
    return parser_ok;                                       \
}

#define DISPLAY_U32(KEYNAME, VALUE) {         \
    snprintf(outKey, outKeyLen, KEYNAME);     \
    uint64_t number = 0;                      \
    MEMCPY(&number, &VALUE, 4);  \
    return parser_printU64(number, outVal, outValLen, pageIdx, pageCount); \
}

#define DISPLAY_STRING(KEYNAME, VALUE, VALUELEN) {         \
    snprintf(outKey, outKeyLen, KEYNAME);            \
    char buffer[100];                               \
    MEMZERO(buffer, sizeof(buffer));              \
    MEMCPY(buffer, (char *)(VALUE),VALUELEN);         \
    pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount); \
    return parser_ok;   \
}

#define DISPLAY_RUNTIMEARG_U64(CTX){                                        \
    uint64_t value = 0;                                                     \
    readU64(CTX, &value);                                                   \
    return parser_printU64(value, outVal, outValLen, pageIdx, pageCount); \
}

#define DISPLAY_RUNTIMEARG_BYTES(CTX, LEN){                                        \
    return parser_printBytes((const uint8_t *) ((CTX)->buffer + (CTX)->offset), LEN, outVal, outValLen, pageIdx,        \
    pageCount);                                                                                                         \
}

#define DISPLAY_RUNTIMEARG_STRING(CTX, LEN){                                        \
    MEMZERO(buffer, sizeof(buffer));                                                \
    uint8_t *str = (CTX)->buffer + (CTX)->offset;                                       \
    MEMCPY(buffer, (char *) (str), LEN);                                           \
    snprintf(outVal, outValLen, "%s", buffer);                                          \
    return parser_ok;                                                                     \
}

#define DISPLAY_RUNTIMEARG_U512(CTX, LEN){                                        \
    uint8_t bcdOut[64];                                                     \
    MEMZERO(bcdOut, sizeof(bcdOut));                                         \
    uint16_t bcdOutLen = sizeof(bcdOut);                                      \
    bignumLittleEndian_to_bcd(bcdOut, bcdOutLen, (CTX)->buffer + (CTX)->offset + 1, (LEN) - 1); \
    MEMZERO(buffer, sizeof(buffer));    \
    bool ok = bignumLittleEndian_bcdprint(buffer, sizeof(buffer), bcdOut, bcdOutLen);   \
    if(!ok) {           \
        return parser_unexepected_error;        \
    }       \
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);         \
    return parser_ok;                                                       \
}

parser_error_t parser_runtimeargs_tokentransfer(char *keystr, uint8_t num_items, parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t dataLen = 0;
    char buffer[300];
    //loop to the correct index
    for (uint8_t index = 0; index < num_items; index++) {
        uint32_t part = 0;
        CHECK_PARSER_ERR(readU32(ctx, &part));
        MEMZERO(buffer, sizeof(buffer));
        MEMCPY(buffer, (char *) (ctx->buffer + ctx->offset), part);
        if (strcmp(buffer, keystr) == 0) {
            //value
            ctx->offset += part;
            CHECK_PARSER_ERR(readU32(ctx, &dataLen));
            uint8_t type = *(ctx->buffer + ctx->offset + dataLen);
            switch(type) {
                case 8 : {
                    DISPLAY_RUNTIMEARG_U512(ctx, dataLen);
                }

                case 15 : {
                    DISPLAY_RUNTIMEARG_BYTES(ctx, dataLen)
                }

                default : {
                    return parser_unexpected_type;
                }
            }

        }
        ctx->offset += part;

        parse_item(ctx);

        parse_type(ctx);
    }

    return parser_no_data;
}


parser_error_t parser_getItem_RuntimeArgs(parser_context_t *ctx,
                                          uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t dataLen = 0;

    //loop to the correct index
    for (uint8_t index = 0; index < displayIdx; index++) {
        parse_item(ctx);

        parse_item(ctx);

        parse_type(ctx);
    }
    //key
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    char buffer[300];
    MEMZERO(buffer, sizeof(buffer));
    uint8_t *data = (uint8_t *) ctx->buffer + ctx->offset;
    MEMCPY(buffer, (char *) (data), dataLen);
    snprintf(outKey, outKeyLen, "%s", buffer);
    ctx->offset += dataLen;

    //value
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    uint8_t type = *(ctx->buffer + ctx->offset + dataLen);
    displayRuntimeArgs:
    switch (type) {
        case 5: {
            DISPLAY_RUNTIMEARG_U64(ctx)
        }

        case 8: {
            DISPLAY_RUNTIMEARG_U512(ctx, dataLen)
        }

        case 10 : {
            uint32_t stringLen = 0;
            CHECK_PARSER_ERR(readU32(ctx, &stringLen))
            DISPLAY_RUNTIMEARG_STRING(ctx, stringLen)
        }

        case 13 : {
            uint8_t optiontype = 0;
            CHECK_PARSER_ERR(readU8(ctx, &optiontype));
            if (optiontype == 0x00) {
                snprintf(outVal, outValLen, "None");
                return parser_ok;
            } else {
                type = *(ctx->buffer + ctx->offset + dataLen);
                dataLen -= 1;
                goto displayRuntimeArgs;
            }
        }

        case 15 : {
            DISPLAY_RUNTIMEARG_BYTES(ctx, dataLen)
        }

        default : {
            //TYPE NOT SUPPORTED
            return parser_unexpected_type;
        }
    }
}

parser_error_t parser_getItem_Transfer(ExecutableDeployItem item, parser_context_t *ctx,
                                       uint8_t displayIdx,
                                       char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen,
                                       uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        snprintf(outVal, outValLen, "%s", "native transfer");
        return parser_ok;
    }
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));

    uint8_t new_displayIdx = displayIdx - 1;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - 1) {
        return parser_no_data;
    }
    if (!app_mode_expert()) {
        if(new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Target");
            return parser_runtimeargs_tokentransfer("target", dataLen, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                                    outValLen, pageIdx,
                                                    pageCount);
        }

        if(new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Amount");
            return parser_runtimeargs_tokentransfer("amount", dataLen, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                                    outValLen, pageIdx,
                                                    pageCount);
        }

    } else {
        return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                          pageCount);
    }
}

parser_error_t parser_getItem_ModuleBytes(ExecutableDeployItem item, parser_context_t *ctx,
                                          uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (displayIdx == 0) {
        if (item.phase == Payment && dataLen == 0) {
            snprintf(outVal, outValLen, "system");
        } else {
            snprintf(outVal, outValLen, "contract");
        }
        return parser_ok;
    }
    if (displayIdx == 1 && dataLen != 0) {
        snprintf(outKey, outKeyLen, "Cntrct hash");
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), dataLen, outVal, outValLen, pageIdx,
                                 pageCount);
    }
    uint8_t skip_items = dataLen != 0 ? 2 : 1;
    ctx->offset += dataLen;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));

    uint8_t new_displayIdx = displayIdx - skip_items;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - skip_items) {
        return parser_no_data;
    }
    if (!app_mode_expert()) {
        snprintf(outKey, outKeyLen, "Amount");
        return parser_runtimeargs_tokentransfer("amount", dataLen, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                                outValLen, pageIdx,
                                                pageCount);
    } else {
        return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                          pageCount);
    }
}

#define DISPLAY_HEADER_U64(KEYNAME, HEADERPART) {         \
    snprintf(outKey, outKeyLen, KEYNAME);                                                             \
    CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, HEADERPART, &ctx->offset));     \
    uint64_t value = 0;                                                                         \
    CHECK_PARSER_ERR(readU64(ctx,&value));                                             \
    return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);                   \
}

#define DISPLAY_HEADER_TIMESTAMP(KEYNAME, HEADERPART) {         \
    snprintf(outKey, outKeyLen, KEYNAME);                                                             \
    CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, HEADERPART, &ctx->offset));     \
    uint64_t value = 0;                                                                         \
    CHECK_PARSER_ERR(readU64(ctx,&value));                      \
    value /= 1000;                                                            \
    char buffer[300];                                           \
    MEMZERO(buffer,sizeof(buffer));                             \
    zxerr_t err = printTime(buffer, sizeof(buffer), value);     \
    if(err != zxerr_ok){                                        \
        return parser_unexepected_error;                                   \
    }                                                            \
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);         \
    return parser_ok;                                                                \
}

parser_error_t parser_getItemDeploy(ExecutableDeployItem item, parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        char *deployPhase = item.phase == Payment ? "Payment" : "Execution";
        snprintf(outKey, outKeyLen, "%s", deployPhase);
    }
    ctx->offset++;
    switch (item.type) {
        case ModuleBytes : {
            return parser_getItem_ModuleBytes(item, ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                                              pageIdx, pageCount);
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
            return parser_getItem_Transfer(item, ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                                           pageIdx, pageCount);
        }
        default : {
            return parser_context_mismatch;
        }
    }
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
        snprintf(outKey, outKeyLen, "Type");
        if (parser_tx_obj.session.type == Transfer) {
            snprintf(outVal, outValLen, "Transfer");
        } else {
            snprintf(outVal, outValLen, "Contract");
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_chainname, &ctx->offset));
        DISPLAY_STRING("Chain ID", ctx->buffer + 4 + ctx->offset, parser_tx_obj.header.lenChainName)
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "From");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_pubkey, &ctx->offset));
        uint8_t hash[32];
        zxerr_t err = pubkey_to_hash((const uint8_t *) (ctx->buffer + ctx->offset),  1 + (parser_tx_obj.header.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN), hash);
        if(err != zxerr_ok){
            return parser_unexepected_error;
        }
        return parser_printBytes((const uint8_t *) hash, 32, outVal, outValLen,
                                 pageIdx, pageCount);
    }

    if (app_mode_expert()) {
        if (displayIdx == 3) {
            DISPLAY_HEADER_TIMESTAMP("Timestamp", header_timestamp)
        }

        if (displayIdx == 4) {
            snprintf(outKey, outKeyLen, "Ttl");
            CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_ttl, &ctx->offset));
            uint64_t value = 0;
            CHECK_PARSER_ERR(readU64(ctx,&value));
            value /= 60000;
            char tmpBuffer[100];
            fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), value, 0);
            snprintf(outVal, outValLen, "%sm", tmpBuffer);
            return parser_ok;
        }

        if (displayIdx == 5) {
            DISPLAY_HEADER_U64("Gas price", header_gasprice)
        }

        if (displayIdx == 6) {
            CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_deps, &ctx->offset));
            uint32_t numdeps = 0;
            CHECK_PARSER_ERR(readU32(ctx, &numdeps));
            snprintf(outKey, outKeyLen, "Txn deps");

            char buffer[400];
            MEMZERO(buffer, sizeof(buffer));
            MEMCPY(buffer,(char *)"[", 1);
            uint8_t num_deps = numdeps <= 5 ? numdeps : 5;
            uint16_t write = 1;
            uint8_t index = 0;
            while(index < num_deps - 1){
                array_to_hexstr(buffer + write, sizeof(buffer) - write, (ctx->buffer + ctx->offset + index * 32), 32);
                write += 64;
                MEMCPY(buffer + write, (char *)",",1);
                write += 1;
                index += 1;
            }
            array_to_hexstr(buffer + write, sizeof(buffer) - write, (ctx->buffer + ctx->offset + index * 32), 32);
            write += 64;
            MEMCPY(buffer + write,(char *)"]", 1);
            pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
            return parser_ok;
        }
    }
    uint8_t new_displayIdx = displayIdx - 3;
    if (app_mode_expert()) {
        new_displayIdx -= 4;
    }
    ctx->offset = headerLength(parser_tx_obj.header) + 32;

    if (new_displayIdx < parser_tx_obj.payment.num_items) {
        return parser_getItemDeploy(parser_tx_obj.payment, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                    outValLen, pageIdx, pageCount);
    }

    new_displayIdx -= parser_tx_obj.payment.num_items;
    ctx->offset += parser_tx_obj.payment.totalLength;

    if (new_displayIdx < parser_tx_obj.session.num_items) {
        return parser_getItemDeploy(parser_tx_obj.session, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                    outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}
