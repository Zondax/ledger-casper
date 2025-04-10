/*******************************************************************************
 *   (c) 2020 Zondax GmbH
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

#include <stdio.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

zxerr_t addr_getNumItems(uint8_t *num_items) {
    *num_items = 1;
    if (app_mode_expert()) {
        *num_items = 2;
    }
    return zxerr_ok;
}

zxerr_t addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                     uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    uint8_t addr_plus_prefix[1 + SECP256K1_PK_LEN];
    MEMCPY(addr_plus_prefix + 1, G_io_apdu_buffer, SECP256K1_PK_LEN);
    addr_plus_prefix[0] = 02;

    encode_addr((char *)addr_plus_prefix, SECP256K1_PK_LEN + 1, buffer);

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address");
            pageString(outVal, outValLen, (char *)buffer, pageIdx, pageCount);
            return zxerr_ok;
        case 1: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            snprintf(outKey, outKeyLen, "Path");
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }
}
