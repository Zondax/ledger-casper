/*******************************************************************************
*   (c) 2019-2021 Zondax GmbH
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
#include <algorithm>
#include <parser.h>
#include <sstream>
#include <string>
#include "common.h"

std::vector<std::string> dumpUI(parser_context_t *ctx,
                                uint16_t maxKeyLen,
                                uint16_t maxValueLen,
                                transaction_type_e type) {
    auto answer = std::vector<std::string>();

    uint8_t numItems;
    parser_error_t err;
    switch (type) {
        case Transaction:
            err = parser_getNumItems(ctx, &numItems);
            break;
        case Message:
            err = parser_getMessageNumItems(&numItems);
            break;

        default:
            err = parser_unexepected_error;
    }

    if (err != parser_ok) {
        return answer;
    }

    for (uint16_t idx = 0; idx < numItems; idx++) {
        char keyBuffer[1000] = {0};
        char valueBuffer[1000] = {0};
        uint8_t pageIdx = 0;
        uint8_t pageCount = 1;

        while (pageIdx < pageCount) {
            std::stringstream ss;

            switch (type) {
            case Transaction:
                err = parser_getItem(ctx,
                        idx,
                        keyBuffer, maxKeyLen,
                        valueBuffer, maxValueLen,
                        pageIdx, &pageCount);
                break;
            case Message:
                err = parser_getMessageItem(ctx,
                            idx,
                            keyBuffer, maxKeyLen,
                            valueBuffer, maxValueLen,
                            pageIdx, &pageCount);
                break;

            default:
                break;
            }


            ss << idx << " | " << keyBuffer;
            if (pageCount > 1) {
                ss << " [" << (int) pageIdx + 1 << "/" << (int) pageCount << "]";
            }
            ss << " : ";

            if (err == parser_ok) {
                ss << valueBuffer;
            } else {
                ss << parser_getErrorDescription(err);
            }
            auto str = ss.str();
            if (type == Transaction) {
                std::for_each(str.begin(), str.end(), [](char & c){
                    c = ::tolower(c);
                });
            }
            answer.push_back(str);

            pageIdx++;
        }
    }

    return answer;
}
