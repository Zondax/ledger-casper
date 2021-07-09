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

parser_error_t parseSystemPayment(parser_context_t *ctx, ExecutableDeployItem *item, uint32_t num_items){

    PARSER_ASSERT_OR_ERROR(num_items == 1, parser_unexpected_number_items);

    uint8_t type = 0;
    uint8_t internal_type = 0;
    CHECK_RUNTIME_ARGTYPE(ctx, num_items, "amount", type == 8);
    item->UI_runtime_items += 1; //amount only
    return parser_ok;
}