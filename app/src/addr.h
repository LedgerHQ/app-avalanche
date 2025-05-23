/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


zxerr_t fill_address(
    uint32_t *flags,
    uint32_t *tx,
    uint32_t rx,
    uint8_t *buffer,
    uint16_t buffer_len,
    uint8_t curve_type
);

// Return the number of items in the address view
zxerr_t addr_getNumItems(uint8_t *num_items);

// Gets an specific item from the address view (including paging)
zxerr_t addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outValue, uint16_t outValueLen,
                     uint8_t pageIdx, uint8_t *pageCount);

zxerr_t addr_getNumItemsEd25519(uint8_t *num_items);

zxerr_t addr_getItemEd25519(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
