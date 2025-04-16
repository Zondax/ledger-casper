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

#include "gmock/gmock.h"
#include <algorithm>

#include <iostream>
#include <fstream>
#include <json/json.h>
#include <hexutils.h>
#include <app_mode.h>
#include "parser.h"
#include "common.h"

zxerr_t pubkey_to_hash(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *out){
    const char *tmp = "24749ecb377e548d114538c2d5504d77645257e21b2b8ee430170c74ab3ddc6d";
    parseHexString(out, 32, tmp);

    return zxerr_ok;
}

using ::testing::TestWithParam;
class JsonTests : public JsonTests_Base {};
class JsonTestsSignMessage : public JsonTests_Base {};

std::vector<testcase_t> GetJsonTestCases(const std::string &jsonFile) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    Json::Value obj;

    std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (auto &i : obj) {

        auto outputs = std::vector<std::string>();
        for (const auto &s : i["output"]) {
            outputs.push_back(s.asString());
        }

        auto outputs_expert = std::vector<std::string>();
        for (const auto &s : i["output_expert"]) {
            outputs_expert.push_back(s.asString());
        }

        answer.push_back(testcase_t{
                i["index"].asUInt64(),
                i["name"].asString(),
                i["blob"].asString(),
                i["valid_regular"].asBool(),
                i["valid_expert"].asBool(),
                outputs,
                outputs_expert
        });
    }

    return answer;
}

void check_testcase(const testcase_t &tc, bool expert_mode, transaction_type_e type) {
    app_mode_set_expert(expert_mode);

    parser_context_t ctx;
    parser_error_t err;

    uint8_t buffer[10000] = {0};
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    switch (type)
    {
    case Transaction:
        err = parser_parse(&ctx, buffer, bufferLen, sizeof(buffer));
        break;
    case Message:
        err = parser_parse_message(&ctx, buffer, bufferLen);
        break;
    default:
        return;
    }

    if (tc.valid_regular && tc.valid_expert) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

    if (type == Transaction) {
        err = parser_validate(&ctx);
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    }

    auto output = dumpUI(&ctx, 40, 35, type);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() ? tc.expected_expert : tc.expected;
    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            auto estr = expected[i];
            if (type == Transaction) {
                std::for_each(estr.begin(), estr.end(), [](char & c){
                        c = ::tolower(c);
                });
            }

            EXPECT_THAT(output[i], testing::Eq(estr));
        }
    }
}

INSTANTIATE_TEST_SUITE_P (
        JsonTestCasesCurrentTxVer,
        JsonTests,
        ::testing::ValuesIn(GetJsonTestCases("manual.json")),
        JsonTests::PrintToStringParamName()
);

// Parametric test using current runtime:
TEST_P(JsonTests, CheckUIOutput_CurrentTX_Normal) { check_testcase(GetParam(), false, Transaction); }

TEST_P(JsonTests, CheckUIOutput_CurrentTX_Expert) { check_testcase(GetParam(), true, Transaction); }

INSTANTIATE_TEST_SUITE_P (
        JsonTestCasesSignMessage,
        JsonTestsSignMessage,
        ::testing::ValuesIn(GetJsonTestCases("sign_message.json")),
        JsonTestsSignMessage::PrintToStringParamName()
);

// Parametric test using current runtime:
TEST_P(JsonTestsSignMessage, CheckUIOutput_CurrentTX_Normal) { check_testcase(GetParam(), false, Message); }

TEST_P(JsonTestsSignMessage, CheckUIOutput_CurrentTX_Expert) { check_testcase(GetParam(), true, Message); }
