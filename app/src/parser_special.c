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

#include "parser_special.h"
#include "parser_impl.h"
#include "parser_common.h"
#include "parser_txdef.h"
#include "parser.h"
#include "crypto.h"
#include "zxformat.h"
#include "app_mode.h"
#include "runtime_arg.h"

uint16_t entry_point_offset;

#define CHECK_RUNTIME_ARGTYPE(CTX, NUM_ITEMS, STR, CONDITION) { \
    type = 255;                     \
    internal_type = 255;                                           \
    CHECK_PARSER_ERR(searchRuntimeArgs((STR), &type, &internal_type, (NUM_ITEMS), (CTX)));          \
    PARSER_ASSERT_OR_ERROR((CONDITION), parser_unexpected_type);                                      \
}


parser_error_t render_fixed_delegation_items(ExecutableDeployItem *item, parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t render_entry_point(parser_context_t *ctx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount);


parser_error_t parser_getItem_NativeTransfer(ExecutableDeployItem item, parser_context_t *ctx,
                                       uint8_t displayIdx,
                                       char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen,
                                       uint8_t pageIdx, uint8_t *pageCount) {
    ctx->offset++;
    uint32_t start = ctx->offset;
    uint32_t num_items = 0;
    CHECK_PARSER_ERR(readU32(ctx, &num_items));

    if(item.UI_runtime_items > num_items){
        return parser_unexpected_number_items;
    }

    uint8_t new_displayIdx = displayIdx - item.UI_fixed_items;

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    if (new_displayIdx >= item.UI_runtime_items || displayIdx < item.UI_fixed_items) {
        return parser_unexpected_number_items;
    }

    // generic
    if (item.with_generic_args > 0){
        if (new_displayIdx == 0) {
            char *name = "native-transfer";
            uint32_t name_len = strlen(name);
            // move offset to the end of args
            CHECK_PARSER_ERR(parseRuntimeArgs(ctx, item.UI_runtime_items));
            uint32_t end = ctx->offset;
            uint32_t len = ctx->offset - start;
            // blake2b of runtime args
            ctx->offset = start;
            CHECK_PARSER_ERR(showRuntimeArgsHash(item, ctx, len, name, name_len, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount));

            ctx->offset = end;
            return parser_ok;
        }
        return parser_no_data;
    }

    bool expected_items = num_items == 3 || num_items == 4;

    // generic no hash there is less args than expected but they are valid
    if (!expected_items) {
        return showRuntimeArgByIndex(new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount, item.UI_runtime_items, ctx);
    }

    // no generic, normal transactions
    if(!app_mode_expert()) {
        if(new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Target");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);

        }

        if(new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype,num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

        return parser_no_data;
    }else{
        if(new_displayIdx == 0 && item.UI_runtime_items == 4) {
            snprintf(outKey, outKeyLen, "From");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("source", &dataLength, &datatype,num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

        if(item.UI_runtime_items == 4){
            new_displayIdx -= 1;
        }

        if(new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Target");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("target", &dataLength, &datatype, num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);

        }

        if(new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype,num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

        if(new_displayIdx == 2) {
            snprintf(outKey, outKeyLen, "ID");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("id", &dataLength, &datatype,num_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }
    }

    return parser_no_data;
}


parser_error_t checkNativeTransferArgs(parser_context_t *ctx, __Z_UNUSED ExecutableDeployItem *item, uint32_t num_items, uint32_t *fitems) {

    uint8_t type = 0;
    uint8_t internal_type = 0;
    *fitems = 0;
    parser_error_t err = searchRuntimeArgs("amount", &type, &internal_type, num_items, ctx);

    if (err == parser_ok && (type == 8 || type == 4 || type == 5) ) {
        *fitems += 1;
    } else if (err != parser_runtimearg_notfound && err != parser_unexpected_type)
        return err;

    err = searchRuntimeArgs("id", &type, &internal_type, num_items, ctx);
    if (err == parser_ok && ((type == 13 && internal_type == 5) || type == 5) ) {
        *fitems += 1;
    } else if (err != parser_runtimearg_notfound && err != parser_unexpected_type)
        return err;

    err = searchRuntimeArgs("target", &type, &internal_type, num_items, ctx);
    if (err == parser_ok && (type == 11 || type == 12 || type == 15 || type == 22) ) {
        *fitems += 1;
    } else if (err != parser_runtimearg_notfound && err != parser_unexpected_type)
        return err;

    if(num_items == 4){
        err = searchRuntimeArgs("source", &type, &internal_type, num_items, ctx);
        if (err == parser_ok && (type == 11 || type == 12 || type == 15 || type == 22) ) {
            *fitems += 1;
        } else if (err != parser_runtimearg_notfound && err != parser_unexpected_type)
            return err;
    }

    return parser_ok;
}

parser_error_t parseNativeTransfer(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items) {
    parser_error_t ret = parser_ok;
    uint32_t found_items = 0;

    ret = checkNativeTransferArgs(ctx, item, num_items, &found_items);

    if (ret != parser_ok)
        return ret;

    uint32_t uitems = num_items - found_items;

    bool expected_items = found_items == 3 || found_items == 4;

    // normal tx, target, id, source(optional) and amount
    if (uitems == 0 && expected_items) {
        if(app_mode_expert()){
            item->UI_runtime_items += num_items;
        }else{
            item->UI_runtime_items += 2; //amount and target only
        }
        item->with_generic_args = 0;
        return parser_ok;
    }

    // generic no hash
    if (uitems == 0 && !expected_items) {
        item->UI_runtime_items += found_items;
        item->with_generic_args = 0;
        return parser_ok;
    }
    // generic with hash
    if (uitems > 0) {
        item->with_generic_args = 1;
        item->UI_runtime_items += 1;
        return parser_ok;
    }

    return parser_unexepected_error;
}

parser_error_t checkForSystemPaymentArgs(parser_context_t *ctx, __Z_UNUSED ExecutableDeployItem *item, uint32_t num_items){

    uint8_t type = 0;
    uint8_t internal_type = 0;

    PARSER_ASSERT_OR_ERROR(num_items == 1, parser_unexpected_number_items);
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "amount", type == 8 || type == 5  ); // also type 5

    return parser_ok;
}

parser_error_t parseSystemPayment(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items){

    if (num_items == 0 )
        return parser_unexpected_number_items;

    parser_error_t ret = parser_ok;
    ret = checkForSystemPaymentArgs(ctx, item, num_items);

    if (ret == parser_ok) {
        item->with_generic_args = 0;
        item->UI_runtime_items += 1;// Amount arg
        return ret;
    } else if (ret != parser_unexpected_number_items && ret != parser_runtimearg_notfound && ret != parser_unexpected_type ) {
        return ret;
    }

    // generic SystemPayment with one or more generic args
    item->with_generic_args = 1;
    item->UI_runtime_items += 1;

    return parser_ok;
}

parser_error_t parser_getItem_SystemPayment(ExecutableDeployItem item, parser_context_t *ctx,
                                          uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    ctx->offset++;
    uint32_t start = ctx->offset;
    uint32_t dataLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));
    if(dataLen > ctx->bufferLen - ctx->offset){
        return parser_unexpected_buffer_end;
    }
    ctx->offset += dataLen;
    CHECK_PARSER_ERR(readU32(ctx, &dataLen));

    uint8_t new_displayIdx = displayIdx - item.UI_fixed_items;
    if (new_displayIdx > item.UI_runtime_items || displayIdx < item.UI_fixed_items) {
        return parser_no_data;
    }
    uint32_t dataLength = 0;
    uint8_t datatype = 255;
    if(new_displayIdx == 0) {
        if (item.with_generic_args == 0) {
            snprintf(outKey, outKeyLen, "Fee");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, item.UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                    outVal, outValLen,
                    pageIdx, pageCount);
        } else {
            char *name = "payment";
            uint32_t name_len = strlen(name);
            // move offset to the end of args
            CHECK_PARSER_ERR(parseRuntimeArgs(ctx, item.UI_runtime_items));
            uint32_t end = ctx->offset;
            uint32_t len = ctx->offset - start;
            // blake2b of runtime args
            ctx->offset = start;
            CHECK_PARSER_ERR(showRuntimeArgsHash(item, ctx, len, name, name_len, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount));

            ctx->offset = end;
            return parser_ok;
        }
    }
    return parser_no_data;
}

parser_error_t render_entry_point(parser_context_t *ctx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    uint16_t prev_offset = ctx->offset;

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));

    ctx->offset = entry_point_offset;

    CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
    ctx->offset = prev_offset;

    snprintf(outKey, outKeyLen, "Entry-point");
    pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t render_fixed_delegation_items(ExecutableDeployItem *item, parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {

    // this are not generic args and are part of valid contract transactions
    switch (item->type){
        case ModuleBytes : {
            if(displayIdx == 0 ) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "contract");
                return parser_ok;
            }
            if(displayIdx == 1 ){
                snprintf(outKey, outKeyLen, "Cntrct hash");
                uint32_t dataLength = 0;
                CHECK_PARSER_ERR(readU32(ctx, &dataLength))
                uint64_t value = 0;
                MEMCPY(&value, &dataLength, 4);
                uint8_t hash[32];
                MEMZERO(hash, sizeof(hash));
                MEMCPY(hash, (ctx->buffer + ctx->offset), dataLength);
                if (blake2b_hash(ctx->buffer + ctx->offset,dataLength,hash) != zxerr_ok){
                    return parser_unexepected_error;
                };
                return parser_printBytes(hash, 32, outVal, outValLen,
                                         pageIdx, pageCount);
            }
            CHECK_PARSER_ERR(parse_item(ctx));
            break;
        }

        case StoredContractByHash: {
            if(displayIdx == 0 ) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-hash");
                return parser_ok;
            }
            if(displayIdx == 1 ) {
                snprintf(outKey, outKeyLen, "Address");
                return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), HASH_LENGTH, outVal, outValLen,
                                         pageIdx, pageCount);
            }
            ctx->offset += HASH_LENGTH;
            CHECK_PARSER_ERR(parse_item(ctx))

            if(displayIdx == 2 && app_mode_expert()) {
                return render_entry_point(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            }
            break;
        }
        case StoredVersionedContractByHash: {
            if(displayIdx == 0 ) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-hash-versioned");
                return parser_ok;
            }
            if(displayIdx == 1 ) {
                snprintf(outKey, outKeyLen, "Address");
                return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), HASH_LENGTH, outVal, outValLen,
                                         pageIdx, pageCount);
            }

            ctx->offset += HASH_LENGTH;
            uint32_t version = 0;
            CHECK_PARSER_ERR(parse_version(ctx, &version))

            if(displayIdx == 2 && app_mode_expert()) {
                uint64_t value = 0;
                MEMCPY(&value, &version, 4);
                snprintf(outKey, outKeyLen, "Version");
                return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
            }
            CHECK_PARSER_ERR(parse_item(ctx))

            if(displayIdx == 3 && app_mode_expert()) {
                return render_entry_point(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            }

            break;
        }

        case StoredContractByName: {
            if(displayIdx == 0 ) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-name");
                return parser_ok;
            }

            if (displayIdx == 1 ) {
                char buffer[300];
                CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
                snprintf(outKey, outKeyLen, "Name");
                pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
                return parser_ok;
            }
            CHECK_PARSER_ERR(parse_item(ctx));
            CHECK_PARSER_ERR(parse_item(ctx))

            if(displayIdx == 2 && app_mode_expert()) {
                return render_entry_point(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            }

            break;
        }

        case StoredVersionedContractByName: {
            if(displayIdx == 0 ) {
                snprintf(outKey, outKeyLen, "Execution");
                snprintf(outVal, outValLen, "by-name-versioned");
                return parser_ok;
            }

            if (displayIdx == 1 ) {
                char buffer[300];
                CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
                snprintf(outKey, outKeyLen, "Name");
                pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
                return parser_ok;
            }

            CHECK_PARSER_ERR(parse_item(ctx));
            uint32_t version = 0;
            CHECK_PARSER_ERR(parse_version(ctx, &version))

            if(displayIdx == 2 && app_mode_expert()) {
                uint64_t value = 0;
                MEMCPY(&value, &version, 4);
                snprintf(outKey, outKeyLen, "Version");
                return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
            }
            CHECK_PARSER_ERR(parse_item(ctx))

            if(displayIdx == 3 && app_mode_expert()) {
                return render_entry_point(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            }

            break;
        }
        default :{
            return parser_unexpected_type;
        }
    }
    return parser_ok;
}

parser_error_t parser_getItem_Delegation(ExecutableDeployItem *item, parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    ctx->offset++;

    // call fixed items rendering and move offset if items
    // have been already rendered
    CHECK_PARSER_ERR(render_fixed_delegation_items(item, ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount));
    if (displayIdx < item->UI_fixed_items)
        return parser_ok;

    uint32_t dataLen = 0;
    uint32_t start = ctx->offset;

    CHECK_PARSER_ERR(readU32(ctx, &dataLen));

    uint8_t new_displayIdx = displayIdx - item->UI_fixed_items;

    if (new_displayIdx > item->UI_runtime_items || displayIdx < item->UI_fixed_items) {
        return parser_no_data;
    }

    // get hash and show it
    if (item->with_generic_args) {
        // two cases
        // 1. special_type == Generic -> amount(if present) + hash
        // 2. special_type != Generic -> only hash

        // case amount.
        if ( (new_displayIdx == 0) && (item->UI_runtime_items == 2)) {
            snprintf(outKey, outKeyLen, "Amount");

            uint32_t dlen = 0;
            uint8_t dtyp = 255;
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dlen, &dtyp, dataLen, ctx))
            return parser_display_runtimeArg(dtyp, dlen, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

        if ((new_displayIdx == 1) && (item->UI_runtime_items == 2)) {
            new_displayIdx -= 1;
        }

        if (new_displayIdx == 0) {
            char *name = "execution";
            uint32_t name_len = strlen(name);
            // move offset to the end of args
            CHECK_PARSER_ERR(parseRuntimeArgs(ctx, dataLen));
            uint32_t end = ctx->offset;
            uint32_t len = ctx->offset - start;
            // blake2b of runtime args
            ctx->offset = start;
            CHECK_PARSER_ERR(showRuntimeArgsHash( *item, ctx, len, name, name_len, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount));

            ctx->offset = end;
            return parser_ok;
        }
        return parser_no_data;
    }

    uint32_t dataLength = 0;
    uint8_t datatype = 255;

    // Normal transaction
    if(new_displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Delegator");
        CHECK_PARSER_ERR(parser_runtimeargs_getData("delegator", &dataLength, &datatype, item->UI_runtime_items, ctx))
        return parser_display_runtimeArg(datatype, dataLength, ctx,
                                         outVal, outValLen,
                                         pageIdx, pageCount);

    }
    if(item->special_type == ReDelegate){
        if(new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Old");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, item->UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);

        }
        if(new_displayIdx == 2) {
            snprintf(outKey, outKeyLen, "New");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("new_validator", &dataLength, &datatype, item->UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }
        if(new_displayIdx == 3) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, item->UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);
        }

    }
    else{
        if(new_displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("validator", &dataLength, &datatype, item->UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);

        }

        if(new_displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_PARSER_ERR(parser_runtimeargs_getData("amount", &dataLength, &datatype, item->UI_runtime_items, ctx))
            return parser_display_runtimeArg(datatype, dataLength, ctx,
                                             outVal, outValLen,
                                             pageIdx, pageCount);

        }
    }

    return parser_no_data;
}

parser_error_t checkForDelegationItems(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items) {
    uint8_t type = 0;
    uint8_t internal_type = 0;

    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "delegator", type == 22  );
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "validator", type == 22  );
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "amount", type == 8 || type == 4 || type == 5  );

    if (item->special_type == Generic) {
        item->UI_runtime_items += 2; // amount and hash
        item->with_generic_args = 1;
        return parser_ok;
    }

    if (item->type == ReDelegate) {
        CHECK_RUNTIME_ARGTYPE(ctx, num_items, "new_validator", type == 22); // also type 5
        item->UI_runtime_items += 4;
    } else {
        item->UI_runtime_items += 3;
    }

    return parser_ok;
}

parser_error_t parseDelegation(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items, bool redelegation){

    uint8_t type = 0;
    uint8_t internal_type = 0;

    // for calls coming from parseModuleBytes, we need to check again
    uint16_t start = ctx->offset;
    parser_error_t err = searchRuntimeArgs(("new_validator"), &type, &internal_type, (num_items), (ctx));
    if(err == parser_ok){
        redelegation = true;
    }
    ctx->offset = start;

    if(item->type == ModuleBytes){
        start = ctx->offset;

        uint32_t dataLength = 0;
        // this should be present in any transaction of this type
        CHECK_PARSER_ERR(parser_runtimeargs_getData("auction", &dataLength, &type, num_items, ctx));

        char buffer[100];
        MEMZERO(buffer,sizeof(buffer));
        PARSER_ASSERT_OR_ERROR(dataLength < sizeof(buffer) && ctx->bufferLen > ctx->offset + dataLength, parser_unexpected_buffer_end);
        PARSER_ASSERT_OR_ERROR(type == 10, parser_unexpected_type);
        uint32_t stringLength = 0;
        CHECK_PARSER_ERR(readU32(ctx, &stringLength))
        MEMCPY(buffer, ctx->buffer + ctx->offset, stringLength);

        if (strcmp(buffer, "delegate") == 0){
            item->special_type = Delegate;
        }else if (strcmp(buffer, "undelegate") == 0){
            item->special_type = UnDelegate;
        }else if (strcmp(buffer, "redelegate") == 0){
            item->special_type = ReDelegate;
        }else {
            item->special_type = Generic;
        }
        ctx->offset = start;
    }

    // lets track the number of expected items we found
    err = checkForDelegationItems(ctx, item, num_items);

    if (err == parser_runtimearg_notfound || err == parser_unexpected_type) {
        bool add_amount = 0;

        if (item->special_type == Generic) {
            // we should show amount(if present) and the runtime args hash
            parser_error_t err = searchRuntimeArgs("amount", &type, &internal_type, num_items, ctx);
            if(err == parser_ok){
                add_amount += 1;
            }
        }
        item->UI_runtime_items += 1 + add_amount;
        item->with_generic_args = 1;
    } else if (err != parser_ok)
        return err;

    // if the entry-point is invalid or generic,
    // we should show only the hash of the runtime args
    // the special case is the amount arg is present
    // showing it along the hash
    if (item->special_type == Generic) {
        item->with_generic_args = 1;
    }

    // always render the execution type
    // and the value for example, the hash if the execution
    // is of the type, by-hash
    item->UI_fixed_items = 2;

    // render the contract-hash or name
    // of the execution
    if(app_mode_expert()){
        uint8_t has_version = item->type == StoredVersionedContractByHash ||  item->type == StoredVersionedContractByName ? 1 : 0;
        item->UI_fixed_items += has_version + 1; // entry-point
    }

    return parser_ok;
}
