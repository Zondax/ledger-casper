parser_error_t parse_additional_typebytes(parser_context_t *ctx, uint8_t type) {
    switch (type) {
        case 13 :
        case 14 : {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            return parse_additional_typebytes(ctx, inner_type);
        }

        case 15 : {
            uint32_t num_bytes = 0;
            return _readUInt32(ctx, &num_bytes);
        }
        case 16:
        case 17 : {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            return _readUInt8(ctx, &inner_type);
        }

        case 18: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            return parse_additional_typebytes(ctx, inner_type);
        }

        case 19: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            CHECK_PARSER_ERR(parse_additional_typebytes(ctx, inner_type));
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            CHECK_PARSER_ERR(parse_additional_typebytes(ctx, inner_type));
            return parser_ok;
        }

        case 20: {
            uint8_t inner_type = 0;
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            CHECK_PARSER_ERR(parse_additional_typebytes(ctx, inner_type));
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            CHECK_PARSER_ERR(parse_additional_typebytes(ctx, inner_type));
            CHECK_PARSER_ERR(_readUInt8(ctx, &inner_type));
            CHECK_PARSER_ERR(parse_additional_typebytes(ctx, inner_type));
            return parser_ok;
        }

        default : {
            return parser_ok;
        }
    }
}

