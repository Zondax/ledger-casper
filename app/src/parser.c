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

parser_error_t parser_getItem_RuntimeArgs(parser_context_t *ctx,
                                          uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t dataLen = 0;

    //loop to the correct index
    for (uint8_t index = 0; index < displayIdx; index++) {
        CHECK_PARSER_ERR(readU32(ctx, &dataLen));
        ctx->offset += dataLen;
        CHECK_PARSER_ERR(readU32(ctx, &dataLen));
        ctx->offset += dataLen + 1; //data + type
    }
    //key
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    uint8_t *data = (uint8_t *)ctx->buffer + ctx->offset;
    MEMCPY(buffer, (char *) (data), dataLen);
    snprintf(outKey, outKeyLen, "%s", buffer);
    ctx->offset += dataLen;

    //value
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    uint8_t type = *(ctx->buffer + ctx->offset + dataLen);
    if (type == 0x01) {
        CHECK_PARSER_ERR(readU32(ctx, &dataLen));
        uint64_t number = 0;
        MEMCPY(&number, &dataLen, 4);
        return parser_printU64(number, outVal, outValLen, pageIdx, pageCount);
    } else {
        //FIXME: support other types
        snprintf(outVal, outValLen, "Type not supported");
        return parser_ok;
    }
}

parser_error_t parser_getItem_Transfer(ExecutableDeployItem item, parser_context_t *ctx,
                                       uint8_t displayIdx,
                                       char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen,
                                       uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        char *deployType = item.phase == Payment ? "Payment" : "Session";
        DISPLAY_TYPE(deployType, "Transfer")
    }
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (dataLen != item.num_items - 2) {
        return parser_unexepected_error;
    }
    if (displayIdx == 1) {
        DISPLAY_U32("RuntimeArgs", dataLen)
    }

    uint8_t new_displayIdx = displayIdx - 2;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - 2) {
        return parser_no_data;
    }
    return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
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
            return parser_ok;
        } else {
            snprintf(outVal, outValLen, "contract");
            return parser_ok;
        }
    }
    if (displayIdx == 1 && dataLen != 0) {
        snprintf(outKey, outKeyLen, "Cntrct hash");
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), dataLen, outVal, outValLen, pageIdx,
                                 pageCount);
    }
    uint8_t skip_items = dataLen != 0 ? 1 : 0;
    skip_items++;
    ctx->offset += dataLen;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));


    if (dataLen != item.num_items - skip_items) {
        return parser_unexepected_error;
    }

    uint8_t new_displayIdx = displayIdx - skip_items;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - skip_items) {
        return parser_no_data;
    }
    if(!app_mode_expert()) {

    }else {
        return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                          pageCount);
    }
}

#define HANDLE_VERSION(CTX) {         \
    uint8_t type = 0xff;                        \
    CHECK_PARSER_ERR(readU8(CTX, &type));       \
    if (type == 0x00) {                          \
        if (displayIdx == 2) {                      \
            snprintf(outKey, outKeyLen, "Version"); \
            snprintf(outVal, outValLen, "Not set"); \
            return parser_ok;                       \
        }                                            \
    } else if (type == 0x01) {                       \
            uint32_t p = 0;                         \
            CHECK_PARSER_ERR(readU32(CTX, &p));     \
            if (displayIdx == 2) {                  \
                DISPLAY_U32("Version", p);  \
            }                                       \
    } else {                                        \
        return parser_context_unknown_prefix;       \
    }                                               \
}

parser_error_t parser_getItem_StoredContractByHash(ExecutableDeployItem item, parser_context_t *ctx,
                                                   uint8_t displayIdx,
                                                   char *outKey, uint16_t outKeyLen,
                                                   char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        char *deployType = item.phase == Payment ? "Payment" : "Session";
        if (item.type == StoredVersionedContractByHash) {
            DISPLAY_TYPE(deployType, "StoredVersionedContractByHash")
        } else {
            DISPLAY_TYPE(deployType, "StoredContractByHash")
        }
    }
    uint32_t dataLen = HASH_LENGTH;
    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Hash");
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), dataLen, outVal, outValLen,
                                 pageIdx, pageCount);
    }
    ctx->offset += dataLen;

    if (item.type == StoredVersionedContractByHash) {
        HANDLE_VERSION(ctx)
    }

    uint8_t skip = (item.type == StoredVersionedContractByHash) ? 1 : 0;

    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (displayIdx == 2 + skip) {
        DISPLAY_STRING("Entrypoint", ctx->buffer + ctx->offset, dataLen);
    }
    ctx->offset += dataLen;

    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (dataLen != item.num_items - 4 - skip) {
        return parser_unexepected_error;
    }

    if (displayIdx == 3 + skip) {
        DISPLAY_U32("RuntimeArgs", dataLen)
    }

    uint8_t new_displayIdx = displayIdx - 4 - skip;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - 4 - skip) {
        return parser_unexepected_error;
    }
    return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_getItem_StoredContractByName(ExecutableDeployItem item, parser_context_t *ctx,
                                                   uint8_t displayIdx,
                                                   char *outKey, uint16_t outKeyLen,
                                                   char *outVal, uint16_t outValLen,
                                                   uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        char *deployType = item.phase == Payment ? "Payment" : "Session";
        if (item.type == StoredVersionedContractByName) {
            DISPLAY_TYPE(deployType, "StoredVersionedContractByName")
        } else {
            DISPLAY_TYPE(deployType, "StoredContractByName")
        }
    }
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (displayIdx == 1) {
        DISPLAY_STRING("Name", ctx->buffer + ctx->offset, dataLen)
    }
    ctx->offset += dataLen;

    if (item.type == StoredVersionedContractByName) {
        HANDLE_VERSION(ctx)
    }

    uint8_t skip = (item.type == StoredVersionedContractByName) ? 1 : 0;

    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (displayIdx == 2 + skip) {
        DISPLAY_STRING("Entrypoint", ctx->buffer + ctx->offset, dataLen);
    }
    ctx->offset += dataLen;

    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if (dataLen != item.num_items - 4 - skip) {
        return parser_unexepected_error;
    }

    if (displayIdx == 3 + skip) {
        DISPLAY_U32("RuntimeArgs", dataLen)
    }

    uint8_t new_displayIdx = displayIdx - 4 - skip;
    if (new_displayIdx < 0 || new_displayIdx > item.num_items - 4 - skip) {
        return skip;
    }
    return parser_getItem_RuntimeArgs(ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

#define DISPLAY_HEADER_U64(KEYNAME, HEADERPART) {         \
    snprintf(outKey, outKeyLen, KEYNAME);                                                             \
    CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, HEADERPART, &ctx->offset));     \
    uint64_t value = 0;                                                                         \
    CHECK_PARSER_ERR(readU64(ctx,&value));                                             \
    return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);                   \
}

parser_error_t parser_getItemDeploy(ExecutableDeployItem item, parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        char *deployPhase = item.phase == Payment ? "Payment" : "Session";
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
            return parser_getItem_StoredContractByHash(item, ctx, displayIdx, outKey, outKeyLen, outVal,
                                                       outValLen, pageIdx, pageCount);
        }

        case StoredVersionedContractByName :
        case StoredContractByName : {
            return parser_getItem_StoredContractByName(item, ctx, displayIdx, outKey, outKeyLen, outVal,
                                                       outValLen, pageIdx, pageCount);
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
        if(parser_tx_obj.session.type == Transfer){
            snprintf(outVal, outValLen, "Transfer");
        }else{
            snprintf(outVal, outValLen, "Contract");
        }
    }

    if (displayIdx == 1) {
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_chainname, &ctx->offset));
        DISPLAY_STRING("Chain ID", ctx->buffer + 4 + ctx->offset, parser_tx_obj.header.lenChainName)
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "From");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_pubkey, &ctx->offset));
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), SECP256K1_PK_LEN, outVal, outValLen,
                                 pageIdx, pageCount);
    }

    if (app_mode_expert()) {
        if (displayIdx == 3) {
            DISPLAY_HEADER_U64("Timestamp", header_timestamp)
        }

        if (displayIdx == 4) {
            DISPLAY_HEADER_U64("TTL", header_ttl)
        }

        if (displayIdx == 5) {
            DISPLAY_HEADER_U64("Gas price", header_gasprice)
        }

        if (displayIdx == 6) {
            CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_deps, &ctx->offset));
            uint32_t numdeps = 0;
            CHECK_PARSER_ERR(readU32(ctx, &numdeps));
            snprintf(outKey, outKeyLen, "Txn deps");
            return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), 32, outVal, outValLen,
                                     pageIdx, pageCount);
        }
    }
    uint8_t new_displayIdx = displayIdx - 3;
    new_displayIdx -= app_mode_expert() ? 4 : 0;
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
