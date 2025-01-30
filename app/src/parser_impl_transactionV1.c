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
#include "parser_impl_transactionV1.h"
#include "parser_txdef.h"

uint16_t headerLength(parser_header_transactionV1_t header) {
    // TODO
}

parser_error_t index_headerpart(parser_header_transactionV1_t head, header_part_e part, uint16_t *index) {
    // TODO
}

parser_error_t parser_read_transactionV1(parser_context_t *ctx, parser_tx_transactionV1_t *v) {
    // TODO
    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_transactionV1_t *v) {
    // TODO
    return parser_ok;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const parser_tx_transactionV1_t *v) {
    // TODO
    return 0;
}
