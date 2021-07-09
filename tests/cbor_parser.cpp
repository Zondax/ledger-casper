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

#include "gtest/gtest.h"
#include <string>
#include <cbor.h>
#include <hexutils.h>
#include <zxmacros.h>
#include "parser.h"

// Basic CBOR test cases generated with http://cbor.me/

namespace {
    TEST(DeployUI, TTL) {
        uint64_t minute = 60;
        uint64_t hour = 60 * minute;
        uint64_t day = 24 * hour;
        uint64_t week = 7*day;

        char buffer[100];
        auto err = parse_TTL(minute, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "1m");

        err = parse_TTL(minute + 20, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "1m 20s");

        err = parse_TTL(hour + minute + 20, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "1h 1m 20s");

        err = parse_TTL(day, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "1day");

        err = parse_TTL(day + hour + minute + 20, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "1day 1h 1m 20s");

        err = parse_TTL(week + day + hour + minute + 20, buffer, sizeof(buffer));
        EXPECT_EQ(err, parser_ok);
        EXPECT_STREQ(buffer, "8days 1h 1m 20s");

    }

    TEST(DeployGen, tokentransfer) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000006bcc398e392003d4b8f76c522d2c348a802b0833f0a730ae25ecba7277f88097020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65741ecf7adc0c92e68526e190bc2e678ee4d0a594acdffe16b3f845d44b1013b12a00000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f7572636522000000010202020202020202020202020202020202020202020202020202020202020202010d0c06000000746172676574210000002121212121212121212121212121212121212121212121212121212121212121070c01000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537019dd5966a72ede22e2e28a4b6c500ee12e561961a5a9ba7c8debd1d20d9c54ef7c74203a614aeafaa35ed0ac0eba737ddeae24cd26ee3fbf16e4d09c705fed308";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, delegate_byhashpayment) {
        uint8_t inBuffer[1000];
        const char *tmp = "02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fa087c0377901000080ee3600000000000200000000000000a214f01a236e5793eef21efe8bdb0f9ec7b95f20d0d4c149e9fc8a58d21647c303000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e65741014d6a144218d679dd2509953f567ad2d0d6952713a9226fd3a6499a9d6167e00000000000100000006000000616d6f756e74050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e740100000000080300000002031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02611d93753628c649c117c1ed9672666aa63ed063ee44579da2e6ff58a8a82f6e24c3fce56b91097aba9e1600d8ee61064a3362ae3a0a32ccd3d6acba0339f0cc013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290150ea6e6a305a3ca68001ccecb8637bbbb6e4ffaae2fb52abcb86c09ec6e3044e23d3c7ff11b076ba6a69a46b9d7b53d435db3e3b872c8541b10b6ac5f790f208018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394015f3e4c89498e6f00cfe847b6cfe4ee96038aeb3b66f212afe548fe62a0820eaf3e9e0709fbf44a4f3686538ce40c418f474bdcdd707cb8c1829c71336f872506";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(CBORParserTest, MinimalListTest) {
        // [1,2,3]
        uint8_t inBuffer[100];
        const char *tmp = "83010203";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        CborParser parser;
        CborValue it;
        CborError err;

        err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);
        size_t arrLen;
        err = cbor_value_get_array_length(&it, &arrLen);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(arrLen, 3);

        // Manually iterate
        EXPECT_FALSE(cbor_value_at_end(&it));

        CborType type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborArrayType);
        EXPECT_TRUE(cbor_value_is_container(&it));

        /// Enter container and iterate along items
        CborValue contents;
        err = cbor_value_enter_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);

        int64_t val;
        // item = 1
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 1);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // item = 2
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 2);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // item = 3
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 3);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // Close container
        err = cbor_value_leave_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);
    }

    TEST(CBORParserTest, MinimalDictTest) {
        // { "x" : 1, "y" : 2, "z" : "test" }
        uint8_t inBuffer[100];
        const char *tmp = "A3617801617902617A6474657374";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        CborParser parser;
        CborValue it;
        CborError err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);

        // Manually iterate
        EXPECT_FALSE(cbor_value_at_end(&it));

        CborType type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborMapType);
        EXPECT_TRUE(cbor_value_is_container(&it));
        size_t mapLen;
        err = cbor_value_get_map_length(&it, &mapLen);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(mapLen, 3);

        /// Enter container and iterate along items
        CborValue contents;
        err = cbor_value_enter_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);

        size_t key_len;
        uint64_t val;
        char buffer[100];
        MEMZERO(buffer, 100);

        // "x":1  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "x");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "x":1  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_uint64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 1);
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "y":2  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "y");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "y":2  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_uint64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 2);
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "z":"test"  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "z");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "z":"test"  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 4);
        EXPECT_EQ(strlen((const char *) buffer), 4);
        EXPECT_STREQ(buffer, "test");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // Close container
        err = cbor_value_leave_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);
    }
}
