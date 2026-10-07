#include "os_pic.h"
#include "os_utils.h"

// Replace functions from ethereum app to skip icon generation and UI idle menu
#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)
#include "caller_app.h"
#include "glyphs.h"
#include "nbgl_types.h"
#include "ui_nbgl.h"
#include "view.h"

nbgl_page_t *pageContext;

const nbgl_icon_details_t *get_app_icon(bool caller_icon) {
    UNUSED(caller_icon);
    const nbgl_icon_details_t *icon = NULL;

    icon = &ICONGLYPH;
    if (icon == NULL) {
        PRINTF("%s(%s) returned NULL!\n", __func__, (caller_icon ? "true" : "false"));
    }
    return icon;
}

const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id) {
    UNUSED(chain_id);
    return get_app_icon(false);
}

// Lives in app-ethereum's src/nbgl/ui_home.c, which is excluded because
// avalanche supplies its own home screen. The review screens still reference
// it, so it is defined here.
nbgl_warning_t warning;

const nbgl_icon_details_t *get_home_icon(void) { return get_app_icon(false); }

// Avalanche is never launched as a plugin caller or a clone, so every review
// screen shows the app icon rather than a per-network one.
const nbgl_icon_details_t *get_tx_icon(bool fromPlugin) {
    UNUSED(fromPlugin);
    return get_app_icon(false);
}

const nbgl_icon_details_t *get_clone_network_icon(const caller_app_t *caller_app) {
    UNUSED(caller_app);
    return NULL;
}
#endif  // NBGL targets

#if !defined(TARGET_STAX) && !defined(TARGET_FLEX) && !defined(TARGET_APEX_P)
#include "view.h"
#endif

// Both UI stacks hand control back to the app's home screen once a review
// ends, so these are defined for every target rather than the NBGL ones only.

// Redirect ui_idle from eth app to ours UI
void ui_idle(void) { view_idle_show(0, NULL); }

// eth's warning screens offer a jump to settings. Avalanche's settings belong
// to its own UI, so send the user back to the home screen.
void ui_settings(void) { view_idle_show(0, NULL); }
