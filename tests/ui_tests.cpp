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

#include <iostream>
#include <fstream>
#include <json/json.h>
#include <hexutils.h>
#include <app_mode.h>
#include "parser.h"
#include "common.h"

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    const char *tmp = "7f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c03779";
    parseHexString(pubKey, pubKeyLen, tmp);

    return zxerr_ok;
}

zxerr_t pubkey_to_hash(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *out){
    const char *tmp = "24749ecb377e548d114538c2d5504d77645257e21b2b8ee430170c74ab3ddc6d";
    parseHexString(out, 32, tmp);

    return zxerr_ok;
}



using ::testing::TestWithParam;

typedef struct {
    uint64_t index;
    std::string name;
    std::string blob;
    bool valid_regular;
    bool valid_expert;
    std::vector<std::string> expected;
    std::vector<std::string> expected_expert;
} testcase_t;

class JsonTests : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

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

void check_testcase(const testcase_t &tc, bool expert_mode) {
    app_mode_set_expert(expert_mode);

    parser_context_t ctx;
    parser_error_t err;

    uint8_t buffer[10000];
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    err = parser_parse(&ctx, buffer, bufferLen);

    if (tc.valid_regular && tc.valid_expert) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

    auto output = dumpUI(&ctx, 40, 35);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() ? tc.expected_expert : tc.expected;
    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(expected[i]));
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
TEST_P(JsonTests, CheckUIOutput_CurrentTX_Normal) { check_testcase(GetParam(), false); }

TEST_P(JsonTests, CheckUIOutput_CurrentTX_Expert) { check_testcase(GetParam(), true); }
