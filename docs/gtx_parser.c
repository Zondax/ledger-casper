
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

#define DISPLAY_RUNTIMEARG_BOOLEAN(CTX){                                        \
    uint8_t value = 0;                                                     \
    readU8(ctx, &value);                                                   \
    if (value == 0x00) {                                             \
        snprintf(outVal, outValLen, "True");                        \
    }else{                                                           \
        snprintf(outVal, outValLen, "False");                      \
    }                                                               \
    return parser_ok;                                                \
}


#define DISPLAY_RUNTIMEARG_I32(CTX){                                        \
    uint32_t value = 0;                                                     \
    readU32(CTX, &value);                                                   \
    uint64_t bigvalue = 0;                                                  \
    MEMCPY(&bigvalue, &value , 4);                                         \
    int64_t signedvalue = *(int64_t *)&bigvalue;                            \
    if ( (value >> 31) > 0 ){                          \
        signedvalue ^= 0xffffffff00000000;                              \
    }                                                                   \
    char tmpBuffer[100];                                                \
    int64_to_str(tmpBuffer, sizeof(tmpBuffer), signedvalue);            \
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);       \
    return parser_ok;                                                   \
}

#define DISPLAY_RUNTIMEARG_I64(CTX){                                        \
    uint64_t value = 0;                                                     \
    readU64(CTX, &value);                                                   \
    int64_t signedvalue = *(int64_t *)&value;                              \
    char tmpBuffer[100];                                                \
    int64_to_str(tmpBuffer, sizeof(tmpBuffer), signedvalue);            \
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);       \
    return parser_ok;                                                   \
}

#define DISPLAY_RUNTIMEARG_U8(CTX){                                        \
    uint8_t value = 0;                                                     \
    readU8(CTX, &value);                                                   \
    uint64_t number = 0;                                                    \
    MEMCPY(&number, &value, 1);                                             \
    return parser_printU64(number, outVal, outValLen, pageIdx, pageCount); \
}

#define DISPLAY_RUNTIMEARG_U32(CTX){                                        \
    uint32_t value = 0;                                                     \
    readU32(CTX, &value);                                                   \
    uint64_t number = 0;                                                    \
    MEMCPY(&number, &value, 4);                                             \
    return parser_printU64(number, outVal, outValLen, pageIdx, pageCount); \
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

#define DISPLAY_RUNTIMEARG_KEY(CTX, TYPE, TYPELEN, LEN){     \
    char buffer[300];                                       \
    MEMZERO(buffer, sizeof(buffer));                         \
    MEMCPY(buffer, (TYPE), TYPELEN);                                                         \
    array_to_hexstr(buffer + (TYPELEN), sizeof(buffer)- (TYPELEN), (CTX)->buffer + (CTX)->offset + 1, LEN); \
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount); \
    return parser_ok;                              \
}

#define DISPLAY_RUNTIMEARG_UREF(CTX, LEN){     \
    char buffer[300];                                       \
    MEMZERO(buffer, sizeof(buffer));                         \
    MEMCPY(buffer, (char *)"uref-", 5);                                                         \
    array_to_hexstr(buffer + 5, sizeof(buffer)-5, (CTX)->buffer + (CTX)->offset, (LEN)-1);      \
    MEMCPY(buffer + 4 + (LEN), (char *)"-0", 2);            \
    array_to_hexstr(buffer + 6 + (LEN), sizeof(buffer)-(6 + (LEN)), (CTX)->buffer + (CTX)->offset + (LEN), 1);      \
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount); \
    return parser_ok;                              \
}

#define DISPLAY_RUNTIMEARG_MAP_METADATA(LEN, KEYTYPE, VALUETYPE){     \
    char buffer[300];                                       \
    MEMZERO(buffer, sizeof(buffer));                         \
    MEMCPY(buffer, (char *)"uref-", 5);                                                         \
    array_to_hexstr(buffer + 5, sizeof(buffer)-5, (CTX)->buffer + (CTX)->offset, (LEN)-1);      \
    MEMCPY(buffer + 4 + (LEN), (char *)"-0", 2);            \
    array_to_hexstr(buffer + 6 + (LEN), sizeof(buffer)-(6 + (LEN)), (CTX)->buffer + (CTX)->offset + (LEN), 1);      \
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount); \
    return parser_ok;                              \
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
        case 0: {
            DISPLAY_RUNTIMEARG_BOOLEAN(ctx)
        }
        case 1: {
            DISPLAY_RUNTIMEARG_I32(ctx)
        }
        case 2: {
            DISPLAY_RUNTIMEARG_I64(ctx)
        }
        case 3: {
            DISPLAY_RUNTIMEARG_U8(ctx)
        }
        case 4: {
            DISPLAY_RUNTIMEARG_U32(ctx)
        }
        case 5: {
            DISPLAY_RUNTIMEARG_U64(ctx)
        }

        case 6:
        case 7:
        case 8: {
            DISPLAY_RUNTIMEARG_U512(ctx, dataLen)
        }

        case 9: {
            DISPLAY_RUNTIMEARG_BYTES(ctx, dataLen)
        }

        case 10 : {
            uint32_t stringLen = 0;
            CHECK_PARSER_ERR(readU32(ctx, &stringLen))
            DISPLAY_RUNTIMEARG_STRING(ctx, stringLen)
        }

        case 11 : {
            uint8_t keytype = 0;
            CHECK_PARSER_ERR(readU8(ctx, &keytype));
            switch (keytype) {
                case 0x00 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "account-hash-", 13, dataLen - 1);
                }
                case 0x01 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "hash-", 5, dataLen - 1);
                }
                case 0x02 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "uref-", 5, dataLen - 1);
                }
                case 0x03 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "transfer-", 9, dataLen - 1);
                }
                case 0x04 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "deploy-", 7, dataLen - 1);
                }
                case 0x05 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "era-", 4, dataLen - 1);
                }
                case 0x06 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "balance-", 8, dataLen - 1);
                }
                case 0x07 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "bid-", 4, dataLen - 1);
                }
                case 0x08 : {
                    DISPLAY_RUNTIMEARG_KEY(ctx, "withdraw-", 9, dataLen - 1);
                }
                default : {
                    return parser_unexepected_error;
                }
            }
        }

        case 12 : {
            DISPLAY_RUNTIMEARG_UREF(ctx, dataLen);
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

        case 16 : {
            uint8_t optiontype = 0;
            CHECK_PARSER_ERR(readU8(ctx, &optiontype));
            type = *(ctx->buffer + ctx->offset + dataLen + (1 - optiontype));
            dataLen -= 1;
            goto displayRuntimeArgs;
        }

        case 22 : {
            uint8_t pubkeyType = *(ctx->buffer + ctx->offset);
            uint32_t pubkeyLen = pubkeyType == 0x01 ? 32 : 33;
            DISPLAY_RUNTIMEARG_BYTES(ctx, pubkeyLen)
        }

        default : {
            //FIXME: support other types
            snprintf(outVal, outValLen, "Type not supported");
            return parser_ok;
        }
    }
}

