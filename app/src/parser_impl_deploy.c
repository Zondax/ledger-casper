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
#include "parser_impl_deploy.h"
#include "parser_txdef.h"
#include "parser.h"
#include "parser_utils.h"
#include "app_mode.h"
#include "crypto.h"
#include "parser_special.h"
#include "runtime_arg.h"

parser_tx_deploy_t parser_tx_obj_deploy;

//pub account: PublicKey,             //1 + 32/33
//pub timestamp: Timestamp,           //8
//pub ttl: TimeDiff,                  //8
//pub gas_price: u64,                 //8
//pub body_hash: Digest,              //32
//pub dependencies: Vec<DeployHash>,  //4 + len*32
//pub chain_name: String,             //4+14 = 18

uint16_t headerLength(parser_header_deploy_t header) {
    uint16_t pubkeyLen = 1 + (header.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t fixedLen = 56;
    uint16_t depsLen = 4 + header.lenDependencies * 32;
    uint16_t chainNameLen = 4 + header.lenChainName;
    return pubkeyLen + fixedLen + depsLen + chainNameLen;
}

parser_error_t index_headerpart(parser_header_deploy_t head, header_part_e part, uint16_t *index) {
    *index = 0;
    uint16_t pubkeyLen = 1 + (head.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
    uint16_t deployHashLen = 4 + head.lenDependencies * 32;
    switch (part) {
        case header_pubkey : {
            *index = 0;
            return parser_ok;
        }
        case header_timestamp : {
            *index = pubkeyLen;
            return parser_ok;
        }

        case header_ttl : {
            *index = pubkeyLen + 8;
            return parser_ok;
        }

        case header_gasprice : {
            *index = pubkeyLen + 16;
            return parser_ok;
        }

        case header_bodyhash : {
            *index = pubkeyLen + 24;
            return parser_ok;
        }

        case header_deps : {
            *index = pubkeyLen + 56;
            return parser_ok;
        }

        case header_chainname : {
            *index = pubkeyLen + 56 + deployHashLen;
            return parser_ok;
        }

        default : {
            return parser_unexepected_error;
        }
    }
}

parser_error_t parseDeployType(uint8_t type, deploy_type_e *deploytype) {
    if (type > NUM_DEPLOY_TYPES) {
        return parser_value_out_of_range;
    } else {
        *deploytype = type;
        return parser_ok;
    }
}

parser_error_t copy_item_into_charbuffer(parser_context_t *ctx, char *buffer, uint16_t bufferLen){
    uint32_t part = 0;
    CHECK_PARSER_ERR(readU32(ctx, &part));
    if(part > bufferLen || part > ctx->bufferLen - ctx->offset){
        return parser_unexpected_buffer_end;
    }
    MEMZERO(buffer, bufferLen);
    MEMCPY(buffer, (char *) (ctx->buffer + ctx->offset), part);
    ctx->offset += part;
    return parser_ok;
}

parser_error_t parseModuleBytes(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;

    CHECK_PARSER_ERR(parse_item(ctx));
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &deploy_argLen));
    if(item->phase == Payment){
        CHECK_PARSER_ERR(parseSystemPayment(ctx, item, deploy_argLen)); //only support for system payment
        item->special_type = SystemPayment;
    }else{
        CHECK_PARSER_ERR(parseDelegation(ctx, item, deploy_argLen, false));
    }

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parseTransfer(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &deploy_argLen));
    //only support for native transfers now
    CHECK_PARSER_ERR(parseNativeTransfer(ctx, item, deploy_argLen));
    item->special_type = NativeTransfer;
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx, deploy_argLen));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t parse_version(parser_context_t *ctx, uint32_t *version){
    uint8_t type = 0xff;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    if (type == 0x00) {
    /*nothing to do : empty version */
    } else if (type == 0x01) {
        CHECK_PARSER_ERR(_readUInt32(ctx, version));
    } else {
        return parser_context_unknown_prefix;
    }
    return parser_ok;
}

parser_error_t check_entrypoint(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t *num_runs){
    char buffer[100] = {0};
    // set the offset for later retrival
    entry_point_offset = ctx->offset;

    CHECK_PARSER_ERR(copy_item_into_charbuffer(ctx, buffer, sizeof(buffer)));
    item->itemOffset = ctx->offset;
    uint32_t deploy_argLen = 0;
    CHECK_PARSER_ERR(readU32(ctx, &deploy_argLen));
    bool redelegation = false;

    if (strcmp(buffer, "delegate") == 0) {
        //is delegation
        item->special_type = Delegate;
    }else if (strcmp(buffer, "undelegate") == 0) {
        item->special_type = UnDelegate;
    }else if (strcmp(buffer, "redelegate") == 0) {
        item->special_type = ReDelegate;
        redelegation = true;
    }

    // anything else is generic
    if (!redelegation && item->special_type == 255)
        item->special_type = Generic;

    zemu_log("entry_point-->: ");
    zemu_log(buffer);
    zemu_log("\n");
    CHECK_PARSER_ERR(parseDelegation(ctx, item, deploy_argLen,redelegation))
    *num_runs = deploy_argLen;

    return parser_ok;
}


parser_error_t
parseStoredContractByHash(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    ctx->offset += HASH_LENGTH;
    uint32_t dummy = 0;
    if (item->type == StoredVersionedContractByHash) {
        CHECK_PARSER_ERR(parse_version(ctx, &dummy))
        if(app_mode_expert()){
            item->UI_fixed_items++;
        }
    }
    uint32_t num_runtimeargs = 0;
    CHECK_PARSER_ERR(check_entrypoint(ctx, item, &num_runtimeargs));

    CHECK_PARSER_ERR(parseRuntimeArgs(ctx,num_runtimeargs));
    return parseTotalLength(ctx, start, &item->totalLength);
}

parser_error_t
parseStoredContractByName(parser_context_t *ctx, ExecutableDeployItem *item) {
    uint32_t start = *(uint32_t *) &ctx->offset;
    CHECK_PARSER_ERR(parse_item(ctx));

    uint32_t dummy = 0;
    if (item->type == StoredVersionedContractByName) {
        CHECK_PARSER_ERR(parse_version(ctx, &dummy))
        if(app_mode_expert()){
            item->UI_fixed_items++;
        }
    }

    uint32_t num_runtimeargs = 0;
    CHECK_PARSER_ERR(check_entrypoint(ctx, item, &num_runtimeargs));
    CHECK_PARSER_ERR(parseRuntimeArgs(ctx,num_runtimeargs));

    return parseTotalLength(ctx, start, &item->totalLength);
}


parser_error_t
parseDeployItem(parser_context_t *ctx, ExecutableDeployItem *item) {
    item->totalLength = 0;
    item->UI_fixed_items = 0;
    item->UI_runtime_items = 0;
    item->num_runtime_args = 0;
    item->with_generic_args = 0;
    item->special_type = 255;
    switch (item->type) {
        case ModuleBytes : {
            return parseModuleBytes(ctx, item);
        }

        case StoredVersionedContractByHash :
        case StoredContractByHash : {
            return parseStoredContractByHash(ctx,item);
        }

        case StoredVersionedContractByName :
        case StoredContractByName : {
            return parseStoredContractByName(ctx,item);
        }

        case Transfer : {
            return parseTransfer(ctx, item);
        }
        default : {
            return parser_context_mismatch;
        }
    }
}

parser_error_t parser_read_deploy(parser_context_t *ctx, parser_tx_deploy_t *v) {
    v->header.pubkeytype = ctx->buffer[0];
    PARSER_ASSERT_OR_ERROR(v->header.pubkeytype == 0x01 || v->header.pubkeytype == 0x02, parser_context_unknown_prefix);

    CHECK_PARSER_ERR(index_headerpart(v->header, header_deps, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenDependencies));

    CHECK_PARSER_ERR(index_headerpart(v->header, header_chainname, &ctx->offset));
    CHECK_PARSER_ERR(_readUInt32(ctx, &v->header.lenChainName));

    ctx->offset = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint8_t type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    v->payment.phase = Payment;
    CHECK_PARSER_ERR(parseDeployType(type, &v->payment.type));
    if(v->payment.type != ModuleBytes){
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->payment));

    if (v->payment.special_type == SystemPayment && !v->payment.hasAmount) {
        return parser_no_data;
    }

    type = 0;
    CHECK_PARSER_ERR(_readUInt8(ctx, &type));
    v->session.phase = Session;
    CHECK_PARSER_ERR(parseDeployType(type, &v->session.type));
    CHECK_PARSER_ERR(parseDeployItem(ctx, &v->session));

    v->type = Transaction;
    return parser_ok;
}

parser_error_t _validateTxDeploy(const parser_context_t *c, const parser_tx_deploy_t *v) {
    uint8_t hash[BLAKE2B_256_SIZE] = {0};

    //check headerhash
    if (blake2b_hash(c->buffer,headerLength(v->header),hash) != zxerr_ok){
        return parser_unexepected_error;
    }
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + headerLength(v->header), BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    //check bodyhash
    MEMZERO(hash, sizeof(hash));
    uint16_t index = headerLength(v->header) + BLAKE2B_256_SIZE;
    uint32_t size = v->payment.totalLength + v->session.totalLength;
    if (blake2b_hash(c->buffer + index,size,hash) != zxerr_ok){
        return parser_unexepected_error;
    }

    index = 0;
    CHECK_PARSER_ERR(index_headerpart(v->header,header_bodyhash, &index));
    PARSER_ASSERT_OR_ERROR(MEMCMP(hash,c->buffer + index, BLAKE2B_256_SIZE) == 0,parser_context_mismatch);

    return parser_ok;
}

uint8_t _getNumItemsDeploy(__Z_UNUSED const parser_context_t *c, const parser_tx_deploy_t *v) {
    uint8_t basicnum = app_mode_expert() ? 9 : 4;
    uint8_t itemCount =
            basicnum + v->payment.UI_fixed_items + v->payment.UI_runtime_items + v->session.UI_fixed_items + v->session.UI_runtime_items; //header + payment + session v->session.num_items
    return itemCount;
}

parser_error_t _getItemDeploy(parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
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

    parser_tx_deploy_t parser_tx_obj = *(parser_tx_deploy_t*) ctx->tx_obj;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Txn hash");
        ctx->offset = headerLength(parser_tx_obj.header);
        return parser_printBytes((const uint8_t *) (ctx->buffer + ctx->offset), 32, outVal, outValLen,
                                 pageIdx, pageCount);
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Type");
        if (parser_tx_obj.payment.special_type == SystemPayment && parser_tx_obj.session.type == Transfer) {
            snprintf(outVal, outValLen, "Token transfer");
        } else if (parser_tx_obj.session.special_type == Delegate && parser_tx_obj.session.with_generic_args == 0 ){
            snprintf(outVal, outValLen, "Delegate");
        }else if (parser_tx_obj.session.special_type == UnDelegate && parser_tx_obj.session.with_generic_args == 0) {
            snprintf(outVal, outValLen, "Undelegate");
        }else if (parser_tx_obj.session.special_type == ReDelegate && parser_tx_obj.session.with_generic_args == 0) {
            snprintf(outVal, outValLen, "Redelegate");
        }else {
            snprintf(outVal, outValLen, "Contract execution");
        }
        return parser_ok;
    }

    if (displayIdx == 2) {
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_chainname, &ctx->offset));
        DISPLAY_STRING("Chain ID", ctx->buffer + 4 + ctx->offset, parser_tx_obj.header.lenChainName)
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Account");
        CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_pubkey, &ctx->offset));
        uint16_t pubkeyLen = 1 + (parser_tx_obj.header.pubkeytype == 0x02 ? SECP256K1_PK_LEN : ED25519_PK_LEN);
        return parser_printAddress((const uint8_t *) (ctx->buffer + ctx->offset), pubkeyLen, outVal, outValLen,
                                 pageIdx, pageCount);
    }

    if (app_mode_expert()) {
        if (displayIdx == 4) {
            DISPLAY_HEADER_TIMESTAMP("Timestamp", header_timestamp)
        }

        if (displayIdx == 5) {
            snprintf(outKey, outKeyLen, "Ttl");
            CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_ttl, &ctx->offset));
            uint64_t value = 0;
            CHECK_PARSER_ERR(readU64(ctx,&value));
            value /= 1000;
            char buffer[100];
            CHECK_PARSER_ERR(parse_TTL(value, buffer, sizeof(buffer)));
            pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx == 6) {
            DISPLAY_HEADER_U64("Gas price", header_gasprice)
        }

        if (displayIdx == 7) {
            CHECK_PARSER_ERR(index_headerpart(parser_tx_obj.header, header_deps, &ctx->offset));
            uint32_t numdeps = 0;
            CHECK_PARSER_ERR(readU32(ctx, &numdeps));
            snprintf(outKey, outKeyLen, "Deps #");
            uint64_t value = 0;
            MEMCPY(&value, &numdeps, 4);
            return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);

        }
    }
    uint8_t new_displayIdx = displayIdx - 4;
    if (app_mode_expert()) {
        new_displayIdx -= 4;
    }
    ctx->offset = headerLength(parser_tx_obj.header) + 32;

    uint16_t total_payment_items = parser_tx_obj.payment.UI_fixed_items + parser_tx_obj.payment.UI_runtime_items;
    if (new_displayIdx < total_payment_items) {
        if(parser_tx_obj.payment.special_type == SystemPayment){
            return parser_getItem_SystemPayment(parser_tx_obj.payment, ctx, new_displayIdx, outKey, outKeyLen, outVal,
                                                outValLen, pageIdx, pageCount);
        }else{
            return parser_unexpected_type; //only support for system payments now
        }
    }

    new_displayIdx -= total_payment_items;
    ctx->offset += parser_tx_obj.payment.totalLength;

    uint16_t total_session_items = parser_tx_obj.session.UI_fixed_items + parser_tx_obj.session.UI_runtime_items;

    if (new_displayIdx < total_session_items) {
        special_deploy_e special_type = parser_tx_obj.session.special_type;
        if(special_type == NativeTransfer){
            return parser_getItem_NativeTransfer(parser_tx_obj.session, ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }else if(special_type == Delegate || special_type == UnDelegate || special_type == ReDelegate || special_type == Generic){
            return parser_getItem_Delegation(&parser_tx_obj.session, ctx, new_displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }else{
            return parser_unexpected_type;
        }
    }

    ctx->offset += parser_tx_obj.session.totalLength;

    if (displayIdx == numItems - 1 && app_mode_expert()) {
        snprintf(outKey, outKeyLen, "Approvals #");
        uint32_t num_approvs = 0;
        CHECK_PARSER_ERR(readU32(ctx, &num_approvs));
        uint64_t value = 0;
        MEMCPY(&value, &num_approvs, 4);
        return parser_printU64(value, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}