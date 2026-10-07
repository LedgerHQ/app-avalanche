/*******************************************************************************
 *   (c) 2016 Ledger
 *   (c) 2018-2023 Zondax AG
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

#if defined(FEATURE_ETH)
#include "handler.h"

// Explicit path: avalanche has its own app/src/common/parser.h which would
// otherwise shadow the SDK header defining command_t. It has to precede
// apdu_constants.h, which uses that type, and the style merges include blocks
// before sorting, so ordering is pinned explicitly here.
// clang-format off
#include "lib_standard_app/parser.h"
// clang-format on

#include "apdu_constants.h"
#include "common_ui.h"
#include "common_utils.h"
#include "cx_errors.h"
#include "eip712_v1_commands.h"
#include "eip712_v1_context.h"
#include "glyphs.h"
#include "handle_check_address.h"
#include "lib_standard_app/crypto_helpers.h"
#include "manage_asset_info.h"
#include "mem_utils.h"
#include "shared_context.h"
#include "status_words.h"
#include "ui_utils.h"

uint32_t set_result_get_publicKey(void);
void finalizeParsing(bool);

// Variables bellow are used by app-ethereum app
// to handle/manage stages during parsing and signing
tmpCtx_t tmpCtx;
txContext_t txContext;
tmpContent_t tmpContent;
dataContext_t dataContext;
strings_t strings;
cx_sha3_t global_sha3;

uint8_t appState;
uint16_t apdu_response_code;
volatile bool G_called_from_swap;
volatile bool G_swap_response_ready;
pluginType_t pluginType;

#ifdef HAVE_ETH2
uint32_t eth2WithdrawalIndex;
#endif

#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

const internalStorage_t N_storage_real;

#ifdef HAVE_NBGL
caller_app_t *caller_app = NULL;
#endif

const chain_config_t *g_chain_config = NULL;
chain_config_t config;

// This function is only present in master branch
// was moved/removed in develop branch.
// to keep in mind when develop gets merged into master
// later.
void format_signature_out(const uint8_t *signature) {
    memset(G_io_apdu_buffer + 1, 0x00, 64);
    uint8_t offset = 1;
    uint8_t xoffset = 4;  // point to r value
    // copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
    offset += 32;
    xoffset += xlength + 2;  // move over rvalue and TagLEn
    // copy s value
    xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
}

void reset_app_context() {
    // Upstream moved the EIP-712 teardown into reset_app_context(): the
    // approve/reject callbacks, the error paths and eip712_v1_context_init()
    // all rely on it to free the typed-data context and the review buffers.
    // Without it the context stays allocated after the first message, so every
    // later EIP-712 request is refused until the app is restarted, and the
    // heap leaks. All three are no-ops when nothing is allocated.
    eip712_v1_context_deinit();
    forget_known_assets();
    ui_all_cleanup();

    appState = APP_STATE_IDLE;
    G_called_from_swap = false;
    G_swap_response_ready = false;
    pluginType = PLUGIN_TYPE_OLD_INTERNAL;
#ifdef HAVE_ETH2
    eth2WithdrawalIndex = 0;
#endif
    memset((uint8_t *)&tmpCtx, 0, sizeof(tmpCtx));
    memset((uint8_t *)&txContext, 0, sizeof(txContext));
    memset((uint8_t *)&tmpContent, 0, sizeof(tmpContent));
}

uint16_t io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, __Z_UNUSED bool idle) {
    G_io_apdu_buffer[tx] = ((sw >> 8) & 0xff);
    G_io_apdu_buffer[tx + 1] = (sw & 0xff);
    if (reset) {
        reset_app_context();
    }
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx + 2);
    return sw;
}

// clang-format on

const uint8_t *parseBip32(const uint8_t *dataBuffer, uint8_t *dataLength, bip32_path_t *bip32) {
    if (*dataLength < 1) {
        PRINTF("Invalid data\n");
        return NULL;
    }

    bip32->length = *dataBuffer;

    if (bip32->length < 0x1 || bip32->length > MAX_BIP32_PATH) {
        PRINTF("Invalid bip32\n");
        return NULL;
    }

    dataBuffer++;
    (*dataLength)--;

    if (*dataLength < sizeof(uint32_t) * (bip32->length)) {
        PRINTF("Invalid data\n");
        return NULL;
    }

    for (uint8_t i = 0; i < bip32->length; i++) {
        bip32->path[i] = U4BE(dataBuffer, 0);
        dataBuffer += sizeof(uint32_t);
        *dataLength -= sizeof(uint32_t);
    }

    return dataBuffer;
}

/**
 * Initialise app-ethereum's NVRAM settings.
 *
 * Upstream does this in its own main.c, which avalanche replaces, so without
 * it every field reads as zero. That matters since the upstream bump: the
 * EIP-712 entry points now refuse to run unless N_storage.dataAllowed is set,
 * where previously they had no such gate. Avalanche exposes no app-ethereum
 * settings screen to turn it on, so enable it here to keep the pre-bump
 * behaviour of these APDUs.
 */
static void eth_storage_init(void) {
    internalStorage_t storage;

    if (N_storage.initialized) {
        return;
    }
    explicit_bzero(&storage, sizeof(storage));
    storage.dataAllowed = true;
    storage.initialized = true;
    nvm_write((void *)&N_storage, (void *)&storage, sizeof(internalStorage_t));
}

void init_coin_config(chain_config_t *coin_config) {
    memset(coin_config, 0, sizeof(chain_config_t));
    strlcpy(coin_config->ticker, CHAINID_COINNAME, sizeof(coin_config->ticker));
    coin_config->chain_id = CHAIN_ID;
    coin_config->coin_type = BIP44_COIN_TYPE_3;
}

/**
 * Handles incoming APDU commands for Ethereum operations.
 *
 * This function processes a variety of Ethereum-related operations including key management,
 * signing transactions, and token information provisioning. It is designed to respond to a set
 * of predefined APDU instructions and manage their execution securely within a hardware wallet or similar environment.
 *
 * @param flags A pointer to the volatile uint32_t flags used to manage APDU response behaviors.
 * @param tx A pointer to the volatile uint32_t transaction context, indicating the length of the response.
 * @param rx The length of the received APDU data.
 * @param buffer A pointer to the data buffer containing the APDU commands.
 * @param bufferLen The total length of the data buffer.
 *
 * @note This function sets the blockchain configuration on the first call and logs each operation.
 *       It includes extensive error handling to gracefully manage exceptions and reset the context as needed.
 */
void handle_eth_apdu(uint32_t *flags, uint32_t *tx, uint32_t rx, uint8_t *buffer, __Z_UNUSED uint16_t bufferLen) {
    uint16_t sw;

    // This is the best place to put this,
    // and by checking to NULL we ensure that it is set once,
    // after the first call to this function
    if (g_chain_config == NULL) {
        init_coin_config(&config);
        g_chain_config = &config;

        // app-ethereum sets its dynamic allocator up in main.c, which
        // avalanche replaces. The EIP-712 review allocates its tag/value pairs
        // from that heap, so without this the first review runs against an
        // uninitialised buffer. app_mem_init() resets the heap, so it must run
        // exactly once - hence its place alongside the one-shot config setup.
        if (!app_mem_init()) {
            PRINTF("app-ethereum memory init failed\n");
        }
    }
    eth_storage_init();

    if (buffer[OFFSET_CLA] != CLA) {
        sw = SWO_INVALID_CLA;
    } else if ((rx < OFFSET_CDATA) || ((rx - OFFSET_CDATA) != buffer[OFFSET_LC])) {
        // The handlers trust lc, so it must match what was received; otherwise
        // they read stale bytes from an earlier APDU. Upstream's apdu_parser()
        // performs the same check in the main.c that avalanche replaces.
        sw = SWO_WRONG_DATA_LENGTH;
    } else {
        const command_t cmd = {
            .cla = buffer[OFFSET_CLA],
            .ins = buffer[OFFSET_INS],
            .p1 = buffer[OFFSET_P1],
            .p2 = buffer[OFFSET_P2],
            .lc = buffer[OFFSET_LC],
            .data = buffer + OFFSET_CDATA,
        };

        switch (cmd.ins) {
            case INS_SIGN_EIP_712_MESSAGE:
                switch (cmd.p2) {
                    case P2_EIP712_V0_IMPLEM:
                        forget_known_assets();
                        sw = handle_sign_eip712_message_v0(cmd.p1, cmd.data, cmd.lc);
                        break;
#ifdef HAVE_EIP712_FULL_SUPPORT
                    case P2_EIP712_V1_IMPLEM:
                        sw = handle_eip712_v1_sign(cmd.data, cmd.lc);
                        break;
#endif  // HAVE_EIP712_FULL_SUPPORT
                    default:
                        sw = SWO_WRONG_P1_P2;
                        break;
                }
                break;

#ifdef HAVE_EIP712_FULL_SUPPORT
            case INS_EIP712_STRUCT_DEF:
                sw = handle_eip712_v1_struct_def(cmd.p2, cmd.data, cmd.lc);
                break;

            case INS_EIP712_STRUCT_IMPL:
                sw = handle_eip712_v1_struct_impl(cmd.p1, cmd.p2, cmd.data, cmd.lc);
                break;

            case INS_EIP712_FILTERING:
                sw = handle_eip712_v1_filtering(cmd.p1, cmd.p2, cmd.data, cmd.lc);
                // app-ethereum reports a refused filter, one not signed by
                // Ledger's CAL key among them, as SWO_PARAMETER_ERROR_NO_INFO
                // (0x6a00). Before the bump this app answered a filter whose
                // signature does not verify with 0x6a80, which hosts already
                // handle, so keep reporting that.
                if (sw == SWO_PARAMETER_ERROR_NO_INFO) {
                    sw = SWO_INCORRECT_DATA;
                }
                break;
#endif  // HAVE_EIP712_FULL_SUPPORT

            default:
                sw = SWO_INVALID_INS;
                break;
        }
    }

    // The handler has taken over the screen; the reply is sent once the user
    // answers, so nothing is appended here.
    if (sw == SWO_NO_RESPONSE) {
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    if (sw != SWO_SUCCESS) {
        // Upstream's dispatcher dismisses a review that is on screen before
        // the reset frees the pairs it displays.
        if (appState == APP_STATE_SIGNING_EIP712) {
            ui_idle();
        }
        // Wipe the transaction context on any error, as the pre-bump
        // CATCH_OTHER handler did.
        reset_app_context();
    }

    buffer[*tx] = sw >> 8;
    buffer[*tx + 1] = sw;
    *tx += 2;
}

#endif
