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

    TEST(DeployGen, Case0) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000f2e0782bba4a0a9663cafc7d707fd4a74421bc5bfef4e368b7e8f38dfab87db8020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e6574d7a68bbe656a883d04bba9f26aa340dbe3f8ec99b2adb63b628f2bc92043199800000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e740600000005005550b40508060000007461726765742000000001010101010101010101010101010101010101010101010101010101010101010f200000000200000069640900000001e7030000000000000d050f0000006164646974696f6e616c5f696e666f140000001000000074686973206973207472616e736665720a01000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370195a68b1a05731b7014e580b4c67a506e0339a7fffeaded9f24eb2e7f78b96bdd900b9be8ca33e4552a9a619dc4fc5e4e3a9f74a4b0537c14a5a8007d62a5dc06";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case1) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000009bdb14ca4d83ff840565406ccad54176ee690a7cbdb1423d765dc9905c759364020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65748378f11139a6d65575cf839691fce97bc37c4f6c5d65e0be12b3d41a0815344700000000000100000006000000616d6f756e74050000000400ca9a3b080103030303030303030303030303030303030303030303030303030303030303030e000000706c656173655f63616c6c5f6d650900000008000000626f6f6c5f617267010000000100070000006933325f61726704000000ffffffff01070000006936345f61726708000000feffffffffffffff020600000075385f617267010000000403070000007533325f617267040000000500000004070000007536345f61726704000000060000000408000000753132385f6172670200000001070608000000753235365f6172670200000001080608000000753531325f6172670200000001090601000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce553701ef2d191d0635e05b1ed704f286e5d0de626e744180289493c6742ba768034e8edca20c95126876541812a9d941237d891cb6cb72ce11284829c1e0af8afa0506";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case2) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000855973990b9fc55432f1d889a96efb688df506b659a1e78d2641868e84e97176020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65747f1353d9a0ec2b4113a789dc61598a36845b4aec40c51f79105c2e432b91c22700000000000100000006000000616d6f756e74050000000400ca9a3b080216000000646563656e7472616c697a65645f65786368616e676508000000747261736e666572060000000a0000006172675f737472696e670a00000006000000616c6c5f696e0a0e0000006172675f7075626c69635f6b6579210000000166be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a160f0000006172675f6f7074696f6e5f6e6f6e6501000000000d0a100000006172675f6f7074696f6e5f666972737405000000010a0000000d04110000006172675f6f7074696f6e5f7365636f6e642100000001147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0d0f20000000100000006172675f6163636f756e745f6861736820000000147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0f2000000001000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370186660813374d3a8092a116ff0db0600a193517dbc0b2b1ca0b892ba16d44731cdb37caa7c7109686ba5827d89d791bf1ba21a95463fb484a800d2601ddbf6900";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case3) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000009bd53cb2ae84eb661cfdd32008e34edc3abd0a3aa054f7aea910690fd973b860020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65742f043befbe920560fe3987f2bf4ad73bdaa73213d7bea55c799ca0446c3eca4c00000000000100000006000000616d6f756e74050000000400ca9a3b08030303030303030303030303030303030303030303030303030303030303030303010c0000000b000000766573745f746f6b656e73080000000d0000006172675f726573756c745f6f6b05000000017b00000010040a0e0000006172675f726573756c745f65727211000000000c000000686172642070726f626c656d10040a070000006172675f6d617064000000020000000b0000006163636f756e745f6f6e650166be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a0b0000006163636f756e745f74776f010b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d110a160d0000006172675f656d7074795f6d617004000000000000001104020a0000006172675f7475706c6531040000000a00000012040a0000006172675f7475706c65320e0000000b000000060000007365636f6e6413040a0a0000006172675f7475706c6533100000000c000000060000007365636f6e641e0114040a130300080000006172675f756e6974000000000901000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537011557487c1fd82c5cc91e7170c94025c1438ef88670494b418f7b2f29dfb115447b7a4e91453d10f31ef94e7fa2f401153f2968dc7a045178d9557321de6a5404";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case4) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000b8546a64df5f4f24ee3f901860951f22ee18a1f739b5ef5eddc55485d328aa46020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e6574f1e7ddc274257b69d387a3f195a25a45aa0fb39c40d91de37d4351bff85aa78700000000000100000006000000616d6f756e74050000000400ca9a3b08030303030303030303030303030303030303030303030303030303030303030303000b000000766573745f746f6b656e73030000000c0000006172675f6c6973745f6f6e6514000000040000000a0000000b0000000c0000000d0000000e040c0000006172675f6c6973745f74776f4400000002000000147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcfaecb045411527ca0eeb648bb6c531ea74b317c1f2d0a698b1cc48850ea3872d60e0f20000000080000006172675f75726566210000001616161616161616161616161616161616161616161616161616161616161616010c01000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370162b517cd3f15d0dedd0228d8aa1295183635a0f2c6c6f9107d311412d1ecc6d2be14df3d9228c0a54f3dc4fa432b4a56fc5c7302ebb15901485536a7e3cf2607";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case5) {
        uint8_t inBuffer[1000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000be445d5b0bc65a6226f424435f9be214ff9e6fd0205141c7d3c6b6c9ab1c12cd020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e6574b74450d4d82c7fd4557925cf84c5e92ea443367b1a4cc6a73a5686603a49299a00000000000100000006000000616d6f756e74050000000400ca9a3b08040a000000626c61636b5f686f6c6500070000006578706c6f6465090000000f0000006172675f6b65795f6163636f756e742100000000147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0b0c0000006172675f6b65795f6861736821000000012a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0b0c0000006172675f6b65795f7572656622000000021717171717171717171717171717171717171717171717171717171717171717060b100000006172675f6b65795f7472616e7366657221000000037c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c0b0e0000006172675f6b65795f6465706c6f7921000000042d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0b0e0000006172675f6b65795f6572615f696409000000050f000000000000000b0f0000006172675f6b65795f62616c616e63652100000006fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe0b0b0000006172675f6b65795f6269642100000007147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0b100000006172675f6b65795f77697468647261772100000008147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0b01000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce553701206ac32bac4713d9e0122e4364367fd5485a28e219b8be15ef7afb78d37f6c7a5ec4784fdb317fb4a524d2cf698ca4961e4b5eb3b873054ba170f9d517147903";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployGen, Case6) {
        uint8_t inBuffer[5000];
        const char *tmp = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000004827ee40728af724a74532718c0cfc690bc64617d03376d8d5d8c47b53d74d5f020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e6574704f8e3347f7ee2bf7d233daf349f803381818dd80324fc599ced4c64405faa500000000000100000006000000616d6f756e74050000000400ca9a3b0800e9030000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd0000000001000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370162da98abb00161b501aed25cfe42eb19b3ba0883f496a58b92ac6189a8c57486db68f13bc682b96679d1a3b6aba03d4c48c12a72e0824be8a312afa40cfe880c";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployParserTest, MinimalListTest) {
        uint8_t inBuffer[1000];
        const char *tmp = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000004811966d37fe5674a8af4001884ea0d9042d1c06668da0c963769c3a01ebd08f0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c657725c391ccf5053bbe48b6a99843ceef4b342e72cc1daf195d1bcfa8d805f0d8020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(CLTypeTests, Array) {
        uint8_t inBuffer[1000];
        const char *tmp = "01d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900ca856a4d37501000080ee36000000000001000000000000009ee5ec4efe8d2d1eceb5ddb16711dc8be6d1a371c3b62119b868d8b2e8c5cf500100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c65043b7a3e19791d4315b514c068111ad021bdee997b11228914d5650b87b228ba020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000004000000746573740a0000000a0a0a0a0a0a0a0a0a0a0f0a00000000000000";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);
    }


    TEST(DeployParserTest, ContractByHash) {
        uint8_t inBuffer[1000];
        const char *tmp = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000005ecf9b7c916e59d106dc0f205fe8ade59c26bd321c5e90b44c970fd30402a2930100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c655dd440a64c305581ecf8f4dfaee0ed538817a0bdf2857a4ed6a6f4530ef14488010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployParserTest, ContractVersionedByHash) {
        uint8_t inBuffer[1000];
        const char *tmp = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee3600000000000100000000000000e159c9ed050bdc2600b070d7a29e436ee53e62896ef830473cf1a669bc8b16440100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c65141722ad47b6c586e2e03825e4e0e2190f107321e9cca3d8bd692b5f8f11a984020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001030f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0190340000070000006578616d706c650100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployParserTest, ContractVersionedByName) {
        uint8_t inBuffer[1000];
        const char *tmp = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000001cd0229f526223ed6cf64b2559962f65fad578bbf81d1ecbb38d74dc03f9701e0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c652be8ca5bfe306b6f83b519dc8671b11cb71fa5cc7b6f09c4eac1be41bbf5e7e9020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001040e0000006361737065722d6578616d706c650190340000070000006578616d706c650100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08";

        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);

    }

    TEST(DeployParserTest, ContractVersionedByHash_versionNone) {
        uint8_t inBuffer[1000];
        const char *tmp = "01d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900ca856a4d37501000080ee3600000000000100000000000000407c289687246eba34843a500603178764ac0e18247d7a11ff1770b00174663c0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c6533f21d563daac1ebe6fccd3b1a96d3460495e54fb7ba470eb51d8606c6d5a6ce020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e740400000018fcffff010200000001d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c01b47e4b8ccc377c300909ac2f6ab286371de4ac62325d92643af82292692ccb994e3c726d020d4179aaaef59fec3eb7d4b59fcf6c9540d8cb529ceac823534c0902026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb302494565e2e1e38eca1fb56fbc29fc32bb9ee30c0a7b1d9bb5004df4ce9fa715ac6c498c07cfbcf535f03f6837f2e5e4d2075d32ebefb7bc0dba214c2162e486c2";

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
