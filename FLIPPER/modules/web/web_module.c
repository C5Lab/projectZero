#include "../../module_api.h"
#include "web_lists.h"
#include "web_karma.h"
#include "web_module.h"
#include "web_overlay.h"
#include "web_protocol.h"
#include "web_qr.h"
#include "web_status.h"

#include <furi/core/memmgr.h>
#include <flipper_application/flipper_application.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../qrcodegen.h"

#define WEB_HEAP_FREE_RESERVE 1024u
#define WEB_HEAP_BLOCK_MARGIN 128u

/* Web owns its mode state and UI; the host owns UART, GUI and module lifetime. */
typedef enum {
    WebScreenPortalMenu,
    WebScreenSsidPopup,
    WebScreenHtmlPopup,
    WebScreenPasswordsSelect,
    WebScreenPasswordsText,
    WebScreenEvilPassList,
    WebScreenEvilPassQr,
    WebScreenKarmaDuration,
    WebScreenKarmaProbePopup,
} WebScreen;

typedef struct {
    C5WebLaunchContext launch;
    C5WebSessionPrefs prefs;
    WebScreen screen;
    size_t menu_index;
    char ssid[33];
    uint8_t selected_html_id;
    char selected_html_name[32];
    C5WebList list;
    C5WebSsidEntry* ssids;
    size_t ssid_count;
    C5WebHtmlEntry* htmls;
    size_t html_count;
    C5WebTextLine* password_lines;
    size_t password_line_count;
    size_t password_scroll;
    size_t password_scroll_x;
    bool password_source_evil;
    C5WebPassEntry* passes;
    size_t pass_count;
    size_t pass_index;
    C5WebProbeEntry* probes;
    size_t probe_count;
    uint8_t selected_probe_id;
    char selected_probe_name[48];
    C5WebKarma karma;
    uint32_t last_tick;
    size_t popup_index;
    size_t popup_offset;
    bool ssid_missing;
    bool text_input_pending;
    C5WebQr qr;
    C5WebStatus status;
    bool running;
    bool serial_visible;
    char overlay_title[64];
    size_t overlay_scroll_offset;
    int8_t overlay_scroll_direction;
    uint8_t overlay_scroll_hold;
    uint32_t overlay_scroll_tick;
} WebState;

static bool web_heap_can_allocate(size_t block_bytes, size_t peak_bytes) {
    size_t free_bytes = memmgr_get_free_heap();
    size_t max_block = memmgr_heap_get_max_free_block();
    return block_bytes <= max_block && max_block - block_bytes >= WEB_HEAP_BLOCK_MARGIN &&
           peak_bytes <= free_bytes && free_bytes - peak_bytes >= WEB_HEAP_FREE_RESERVE;
}

static void* web_calloc(size_t count, size_t size) {
    if(!count || !size || count > SIZE_MAX / size) return NULL;
    size_t bytes = count * size;
    if(!web_heap_can_allocate(bytes, bytes)) return NULL;
    return calloc(count, size);
}

static void web_redraw(const C5HostApiV3* host) {
    if(host->request_redraw) host->request_redraw(host->ctx);
}

static bool web_send(const C5HostApiV3* host, const char* command) {
    if(!host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(!length || length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[64];
    if(length + 1 > sizeof(batch)) return false;
    memcpy(batch, command, length);
    batch[length] = '\n';
    return host->send_raw_lines(host->ctx, batch, length + 1);
}

static bool web_send_two(
    const C5HostApiV3* host,
    const char* first,
    const char* second) {
    char batch[C5_MODULE_RAW_TX_MAX];
    size_t length = 0;
    if(!c5_web_batch_two(
           batch, sizeof(batch), first, strlen(first), second, strlen(second), &length)) {
        return false;
    }
    return host->send_raw_lines(host->ctx, batch, length);
}

static bool web_send_three(
    const C5HostApiV3* host,
    const char* first,
    const char* second,
    const char* third) {
    char batch[C5_MODULE_RAW_TX_MAX];
    size_t length = 0;
    size_t third_length = strlen(third);
    if(!c5_web_batch_two(
           batch, sizeof(batch), first, strlen(first), second, strlen(second), &length) ||
       !third_length || length + third_length + 1 > sizeof(batch)) {
        return false;
    }
    memcpy(batch + length, third, third_length);
    batch[length + third_length] = '\n';
    return host->send_raw_lines(host->ctx, batch, length + third_length + 1);
}

static void web_status(const C5HostApiV3* host, const char* text, uint32_t ms) {
    if(host->show_status) host->show_status(host->ctx, text, ms, ms != 0);
}

static void* web_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !host->request_text_input) return NULL;
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    if(params || params_size) {
        if(!params || params_size != sizeof(launch)) return NULL;
        memcpy(&launch, params, sizeof(launch));
        if(launch.version != C5_WEB_LAUNCH_VERSION || launch.size != sizeof(launch) ||
           launch.mode > C5WebModeKarma ||
           !memchr(launch.first_selected_ssid, '\0', sizeof(launch.first_selected_ssid)) ||
           !memchr(launch.select_networks, '\0', sizeof(launch.select_networks)) ||
           !memchr(launch.prefs.portal_ssid, '\0', sizeof(launch.prefs.portal_ssid)) ||
           !memchr(launch.prefs.selected_html_name, '\0', sizeof(launch.prefs.selected_html_name)) ||
           !memchr(launch.prefs.evil_html_name, '\0', sizeof(launch.prefs.evil_html_name)) ||
           !memchr(launch.prefs.selected_probe_name, '\0', sizeof(launch.prefs.selected_probe_name)) ||
           launch.prefs.portal_menu_index >= 4 ||
           launch.prefs.evil_menu_index >= 5 ||
           launch.prefs.karma_menu_index >= 5 ||
           (launch.prefs.selected_html_id == 0) !=
               (launch.prefs.selected_html_name[0] == '\0') ||
           (launch.prefs.evil_html_id == 0) !=
               (launch.prefs.evil_html_name[0] == '\0') ||
           (launch.prefs.selected_probe_id == 0) !=
               (launch.prefs.selected_probe_name[0] == '\0') ||
           (launch.selected_count &&
            strncmp(launch.select_networks, "select_networks ", 16) != 0) ||
           (launch.mode == C5WebModeKarma &&
            (!launch.ticks_per_second || !launch.probe_refresh_delay_ticks))) {
            return NULL;
        }
        for(size_t i = 0; launch.select_networks[i]; i++) {
            char ch = launch.select_networks[i];
            if((ch < '0' || ch > '9') && ch != ' ' && ch != '_' &&
               (ch < 'a' || ch > 'z')) return NULL;
        }
    }
    if(!launch.ticks_per_second) launch.ticks_per_second = 1000;
    WebState* web = web_calloc(1, sizeof(WebState));
    if(!web) return NULL;
    web->launch = launch;
    web->prefs = launch.prefs;
    snprintf(web->ssid, sizeof(web->ssid), "%s", launch.prefs.portal_ssid);
    web->selected_html_id = launch.mode == C5WebModeEvilTwin ?
                                launch.prefs.evil_html_id : launch.prefs.selected_html_id;
    snprintf(web->selected_html_name, sizeof(web->selected_html_name), "%s",
             launch.mode == C5WebModeEvilTwin ?
                 launch.prefs.evil_html_name : launch.prefs.selected_html_name);
    web->selected_probe_id = launch.prefs.selected_probe_id;
    snprintf(web->selected_probe_name, sizeof(web->selected_probe_name), "%s",
             launch.prefs.selected_probe_name);
    web->menu_index = launch.mode == C5WebModeEvilTwin ? launch.prefs.evil_menu_index :
                      (launch.mode == C5WebModeKarma ? launch.prefs.karma_menu_index :
                                                       launch.prefs.portal_menu_index);
    if(web->menu_index >= (launch.mode == C5WebModePortal ? 4u : 5u)) web->menu_index = 0;
    c5_web_karma_init(&web->karma);
    if(params) c5_web_karma_set_duration(&web->karma, launch.karma_duration_sec);
    c5_web_status_reset(&web->status,
                        launch.mode == C5WebModeEvilTwin ? C5WebStatusEvilTwin : C5WebStatusPortal);
    return web;
}

static void web_leave(void* state, const C5HostApiV3* host) {
    WebState* web = state;
    if(!web) return;
    if(host && (web->running || web->serial_visible || web->karma.collecting)) {
        web_send(host, "stop");
        c5_web_karma_cancel(&web->karma);
    }
    snprintf(web->prefs.portal_ssid, sizeof(web->prefs.portal_ssid), "%s", web->ssid);
    web->prefs.selected_html_id = web->selected_html_id;
    snprintf(web->prefs.selected_html_name, sizeof(web->prefs.selected_html_name), "%s",
             web->selected_html_name);
    web->prefs.evil_html_id = web->selected_html_id;
    snprintf(web->prefs.evil_html_name, sizeof(web->prefs.evil_html_name), "%s",
             web->selected_html_name);
    web->prefs.selected_probe_id = web->selected_probe_id;
    snprintf(web->prefs.selected_probe_name, sizeof(web->prefs.selected_probe_name), "%s",
             web->selected_probe_name);
    if(web->launch.mode == C5WebModePortal) web->prefs.portal_menu_index = (uint8_t)web->menu_index;
    else if(web->launch.mode == C5WebModeEvilTwin) web->prefs.evil_menu_index = (uint8_t)web->menu_index;
    else web->prefs.karma_menu_index = (uint8_t)web->menu_index;
    if(host && host->save_session) {
        host->save_session(host->ctx, &web->prefs, sizeof(web->prefs));
    }
    c5_web_qr_clear(&web->qr);
    free(web->ssids);
    free(web->htmls);
    free(web->password_lines);
    free(web->passes);
    free(web->probes);
    free(state);
}

static void web_release_collections(WebState* web) {
    if(!web) return;
    c5_web_list_end(&web->list);
    free(web->ssids);
    web->ssids = NULL;
    web->ssid_count = 0;
    free(web->htmls);
    web->htmls = NULL;
    web->html_count = 0;
    free(web->probes);
    web->probes = NULL;
    web->probe_count = 0;
    free(web->password_lines);
    web->password_lines = NULL;
    web->password_line_count = 0;
    free(web->passes);
    web->passes = NULL;
    web->pass_count = 0;
    c5_web_qr_clear(&web->qr);
}

static bool web_request_ssid_input(WebState* web, const C5HostApiV3* host) {
    if(web->text_input_pending) return false;
    C5TextInputRequest request = {
        .header = "Portal SSID",
        .capacity = sizeof(web->ssid),
        .minimum_length = 1,
    };
    memcpy(request.initial, web->ssid, sizeof(web->ssid));
    if(!host->request_text_input(host->ctx, &request)) {
        web_status(host, "Text input unavailable", 1500);
        return false;
    }
    web->text_input_pending = true;
    return true;
}

static void web_finish_ssid_listing(WebState* web, const C5HostApiV3* host) {
    web->ssid_count = web->list.count;
    web->ssid_missing = web->list.missing || !web->ssid_count;
    bool show_result = web->screen == WebScreenPortalMenu && !web->serial_visible;
    if(show_result) web_status(host, "", 0);
    if(web->ssid_count) {
        if(show_result) {
            web->screen = WebScreenSsidPopup;
            web->popup_index = 0; /* Manual entry is first. */
            for(size_t i = 0; i < web->ssid_count; i++) {
                if(strcmp(web->ssids[i].ssid, web->ssid) == 0) web->popup_index = i + 1;
            }
        }
    } else {
        free(web->ssids);
        web->ssids = NULL;
        if(show_result) {
            web_status(host, "SSID presets\nnot available", 1500);
            web_request_ssid_input(web, host);
        }
    }
    web_redraw(host);
}

static void web_finish_html_listing(WebState* web, const C5HostApiV3* host) {
    web->html_count = web->list.count;
    bool show_result = web->screen == WebScreenPortalMenu && !web->serial_visible;
    if(show_result) web_status(host, "", 0);
    if(web->html_count) {
        if(show_result) {
            web->screen = WebScreenHtmlPopup;
            web->popup_index = 0;
            for(size_t i = 0; i < web->html_count; i++) {
                if(web->htmls[i].id == web->selected_html_id) web->popup_index = i;
            }
        }
    } else {
        free(web->htmls);
        web->htmls = NULL;
        if(show_result) web_status(host, "No HTML files\nfound on SD", 1500);
    }
    web_redraw(host);
}

static void web_finish_probe_listing(WebState* web, const C5HostApiV3* host) {
    web->probe_count = web->list.count;
    bool show_result = web->screen == WebScreenPortalMenu && !web->serial_visible;
    if(show_result) web_status(host, "", 0);
    if(web->probe_count && web->launch.mode == C5WebModeKarma && show_result) {
        web->popup_index = 0;
        for(size_t i = 0; i < web->probe_count; i++) {
            if(web->probes[i].id == web->selected_probe_id) web->popup_index = i;
        }
        web->menu_index = 2;
        web->screen = WebScreenKarmaProbePopup;
    } else if(!web->probe_count) {
        free(web->probes);
        web->probes = NULL;
        if(show_result) web_status(host, "No probes found", 1500);
    }
    web_redraw(host);
}

typedef struct {
    const C5HostApiV3* host;
} WebStatusCallbackContext;

static void web_status_event(void* context, C5WebStatusEvent event) {
    const WebStatusCallbackContext* callback = context;
    if(!callback || !callback->host) return;
    web_status(callback->host,
               event == C5WebStatusBadPassword ? "Bad Password\nEvil ongoing" :
                                                     "Password OK\nClosing Evil",
               2000);
}

static void web_on_bytes(
    void* state,
    const C5HostApiV3* host,
    const uint8_t* bytes,
    size_t length) {
    WebState* web = state;
    if(!web || !host || !bytes) return;
    if(!web->list.active) {
        if(web->running) {
            WebStatusCallbackContext callback = {.host = host};
            c5_web_status_feed(&web->status, bytes, length, web_status_event, &callback);
            web_redraw(host);
        }
        return;
    }
    C5WebListKind kind = web->list.kind;
    uint32_t events = c5_web_list_feed(&web->list, bytes, length);
    if(events & C5WebListEventDone) {
        if(kind == C5WebListPortalSsids) web_finish_ssid_listing(web, host);
        else if(kind == C5WebListHtml) web_finish_html_listing(web, host);
        else if(kind == C5WebListKarmaProbes) web_finish_probe_listing(web, host);
        else if(kind == C5WebListPasswordsText) web->password_line_count = web->list.count;
        else if(kind == C5WebListEvilPasswords) web->pass_count = web->list.count;
        web_redraw(host);
    } else if(events & C5WebListEventEntries) {
        if(kind == C5WebListPasswordsText) web->password_line_count = web->list.count;
        if(kind == C5WebListEvilPasswords) web->pass_count = web->list.count;
        web_redraw(host);
    }
}

static void web_on_text_input(
    void* state,
    const C5HostApiV3* host,
    bool accepted,
    const char* text) {
    WebState* web = state;
    if(!web || !host || !web->text_input_pending) return;
    web->text_input_pending = false;
    if(accepted && text) {
        size_t length = strlen(text);
        if(length > 0 && length < sizeof(web->ssid)) {
            size_t written = 0;
            for(size_t i = 0; i < length && written + 1 < sizeof(web->ssid); i++) {
                unsigned char ch = (unsigned char)text[i];
                if(ch >= 32) web->ssid[written++] = ch == '"' ? '\'' : (char)ch;
            }
            web->ssid[written] = '\0';
            size_t first = 0;
            while(first < written && isspace((unsigned char)web->ssid[first])) first++;
            while(written > first && isspace((unsigned char)web->ssid[written - 1])) written--;
            memmove(web->ssid, web->ssid + first, written - first);
            web->ssid[written - first] = '\0';
            if(web->ssid[0]) {
                web->menu_index = 1;
                web_status(host, "SSID updated", 1000);
            } else {
                web_status(host, "SSID cleared", 1000);
            }
        }
    }
    web_redraw(host);
}

static void web_request_ssid_list(WebState* web, const C5HostApiV3* host) {
    web_release_collections(web);
    web->ssids = web_calloc(C5_WEB_SSID_MAX, sizeof(C5WebSsidEntry));
    web->ssid_count = 0;
    web->ssid_missing = false;
    if(!web->ssids) {
        web_status(host, "OOM: SSID list", 2000);
        return;
    }
    if(!c5_web_list_begin(&web->list, C5WebListPortalSsids, web->ssids, C5_WEB_SSID_MAX) ||
       !web_send(host, "list_ssid")) {
        c5_web_list_end(&web->list);
        web_status(host, "SSID list unavailable", 1500);
        return;
    }
    web_status(host, "Listing SSID...", 0);
}

static void web_request_html_list(WebState* web, const C5HostApiV3* host) {
    web_release_collections(web);
    web->htmls = web_calloc(C5_WEB_HTML_MAX, sizeof(C5WebHtmlEntry));
    web->html_count = 0;
    if(!web->htmls) {
        web_status(host, "OOM: HTML list", 2000);
        return;
    }
    if(!c5_web_list_begin(&web->list, C5WebListHtml, web->htmls, C5_WEB_HTML_MAX) ||
       !web_send(host, "list_sd")) {
        c5_web_list_end(&web->list);
        web_status(host, "HTML list unavailable", 1500);
        return;
    }
    web_status(host, "Listing HTML...", 0);
}

static void web_request_passwords(WebState* web, const C5HostApiV3* host) {
    web_release_collections(web);
    web->password_lines = web_calloc(C5_WEB_TEXT_MAX, sizeof(C5WebTextLine));
    web->password_line_count = 0;
    web->password_scroll = 0;
    web->password_scroll_x = 0;
    if(!web->password_lines) {
        web_status(host, "OOM: passwords", 1500);
        return;
    }
    const char* command = web->password_source_evil ? "show_pass evil" : "show_pass portal";
    if(!c5_web_list_begin(&web->list, C5WebListPasswordsText, web->password_lines,
                          C5_WEB_TEXT_MAX) || !web_send(host, command)) {
        c5_web_list_end(&web->list);
        web_status(host, "Passwords unavailable", 1500);
        return;
    }
    web->screen = WebScreenPasswordsText;
}

static void web_request_evil_passes(WebState* web, const C5HostApiV3* host) {
    web_release_collections(web);
    web->passes = web_calloc(C5_WEB_PASS_MAX, sizeof(C5WebPassEntry));
    web->pass_count = 0;
    web->pass_index = 0;
    c5_web_qr_clear(&web->qr);
    if(!web->passes) {
        web_status(host, "OOM: WiFi list", 2000);
        return;
    }
    if(!c5_web_list_begin(&web->list, C5WebListEvilPasswords, web->passes,
                          C5_WEB_PASS_MAX) || !web_send(host, "show_pass evil")) {
        c5_web_list_end(&web->list);
        web_status(host, "WiFi list unavailable", 1500);
        return;
    }
    web->screen = WebScreenEvilPassList;
}

static void web_request_probe_list(WebState* web, const C5HostApiV3* host) {
    web_release_collections(web);
    web->probes = web_calloc(C5_WEB_PROBE_MAX, sizeof(C5WebProbeEntry));
    web->probe_count = 0;
    if(!web->probes) {
        web_status(host, "OOM: probe list", 2000);
        return;
    }
    if(!c5_web_list_begin(&web->list, C5WebListKarmaProbes, web->probes,
                          C5_WEB_PROBE_MAX) || !web_send(host, "list_probes")) {
        c5_web_list_end(&web->list);
        web_status(host, "Probe list unavailable", 1500);
        return;
    }
    web_status(host, "Listing probes...", 0);
}

static C5InputResult web_popup_input(
    WebState* web,
    const C5HostApiV3* host,
    const InputEvent* event) {
    WebScreen popup_type = web->screen;
    size_t total = web->screen == WebScreenSsidPopup ? web->ssid_count + 1 :
                   (web->screen == WebScreenKarmaProbePopup ? web->probe_count : web->html_count);
    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        web->screen = WebScreenPortalMenu;
    } else if(event->key == InputKeyUp && total) {
        if(web->popup_index) web->popup_index--;
    } else if(event->key == InputKeyDown && total) {
        if(web->popup_index + 1 < total) web->popup_index++;
    } else if(event->type == InputTypeShort && event->key == InputKeyOk && total) {
        if(web->screen == WebScreenSsidPopup) {
            if(web->popup_index == 0) {
                web->screen = WebScreenPortalMenu;
                web_request_ssid_input(web, host);
            } else {
                const C5WebSsidEntry* selected = &web->ssids[web->popup_index - 1];
                snprintf(web->ssid, sizeof(web->ssid), "%s", selected->ssid);
                web->menu_index = 1;
                web->screen = WebScreenPortalMenu;
            }
        } else if(web->screen == WebScreenKarmaProbePopup) {
            const C5WebProbeEntry* selected = &web->probes[web->popup_index];
            web->selected_probe_id = selected->id;
            snprintf(web->selected_probe_name, sizeof(web->selected_probe_name), "%s", selected->name);
            web->screen = WebScreenPortalMenu;
            char status[64];
            snprintf(status, sizeof(status), "Probe selected:\n%s", selected->name);
            web_status(host, status, 1500);
        } else {
            const C5WebHtmlEntry* selected = &web->htmls[web->popup_index];
            web->selected_html_id = selected->id;
            snprintf(web->selected_html_name, sizeof(web->selected_html_name), "%s", selected->name);
            char command[48];
            snprintf(command, sizeof(command), "select_html %u", (unsigned)selected->id);
            web_send(host, command);
            web->menu_index = web->launch.mode == C5WebModeKarma ? 4 : 2;
            web->screen = WebScreenPortalMenu;
            char status[64];
            snprintf(status, sizeof(status), "HTML set:\n%s", selected->name);
            web_status(host, status, 1500);
        }
    } else {
        return C5InputIgnored;
    }
    if(web->screen == WebScreenPortalMenu) {
        if(popup_type == WebScreenSsidPopup) {
            free(web->ssids);
            web->ssids = NULL;
            web->ssid_count = 0;
        } else if(popup_type == WebScreenHtmlPopup) {
            free(web->htmls);
            web->htmls = NULL;
            web->html_count = 0;
        } else if(popup_type == WebScreenKarmaProbePopup) {
            free(web->probes);
            web->probes = NULL;
            web->probe_count = 0;
        }
    }
    web_redraw(host);
    return C5InputConsumed;
}

static C5InputResult web_passwords_input(
    WebState* web,
    const C5HostApiV3* host,
    const InputEvent* event) {
    if(web->screen == WebScreenPasswordsSelect) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            web->screen = WebScreenPortalMenu;
        } else if(event->key == InputKeyUp || event->key == InputKeyDown) {
            web->password_source_evil = !web->password_source_evil;
        } else if(event->type == InputTypeShort && event->key == InputKeyOk) {
            web_request_passwords(web, host);
        } else {
            return C5InputIgnored;
        }
    } else if(web->screen == WebScreenPasswordsText) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            c5_web_list_end(&web->list);
            free(web->password_lines);
            web->password_lines = NULL;
            web->password_line_count = 0;
            web->screen = WebScreenPortalMenu;
        } else if(event->key == InputKeyUp && web->password_scroll) {
            web->password_scroll--;
        } else if(event->key == InputKeyDown &&
                  web->password_scroll + 4 < web->password_line_count) {
            web->password_scroll++;
        } else if(event->key == InputKeyLeft && web->password_scroll_x) {
            web->password_scroll_x--;
        } else if(event->key == InputKeyRight && web->password_scroll_x < 70) {
            web->password_scroll_x++;
        } else {
            return C5InputIgnored;
        }
    } else {
        return C5InputIgnored;
    }
    web_redraw(host);
    return C5InputConsumed;
}

static C5InputResult web_evil_qr_input(
    WebState* web,
    const C5HostApiV3* host,
    const InputEvent* event) {
    if(web->screen == WebScreenEvilPassQr) {
        if(event->type != InputTypeShort ||
           (event->key != InputKeyBack && event->key != InputKeyLeft &&
            event->key != InputKeyOk)) return C5InputIgnored;
        c5_web_qr_clear(&web->qr);
        web->screen = WebScreenEvilPassList;
    } else if(web->screen == WebScreenEvilPassList) {
        if(event->type == InputTypeShort &&
           (event->key == InputKeyBack || event->key == InputKeyLeft)) {
            c5_web_list_end(&web->list);
            free(web->passes);
            web->passes = NULL;
            web->pass_count = 0;
            web->screen = WebScreenPortalMenu;
        } else if(event->key == InputKeyUp && web->pass_count) {
            web->pass_index = web->pass_index ? web->pass_index - 1 : web->pass_count - 1;
        } else if(event->key == InputKeyDown && web->pass_count) {
            web->pass_index = (web->pass_index + 1) % web->pass_count;
        } else if(event->type == InputTypeShort && event->key == InputKeyOk) {
            if(web->list.active) web_status(host, "Wait for list\ncompletion", 1200);
            else if(web->pass_count && web->pass_index < web->pass_count) {
                const C5WebPassEntry* entry = &web->passes[web->pass_index];
                size_t qr_bytes = qrcodegen_BUFFER_LEN_FOR_VERSION(10);
                if(web_heap_can_allocate(qr_bytes * 2, qr_bytes * 2)) {
                    c5_web_qr_build(&web->qr, entry->ssid, entry->pass);
                } else {
                    c5_web_qr_clear(&web->qr);
                    snprintf(web->qr.error, sizeof(web->qr.error), "QR OOM");
                }
                web->screen = WebScreenEvilPassQr;
            }
        } else {
            return C5InputIgnored;
        }
    } else {
        return C5InputIgnored;
    }
    web_redraw(host);
    return C5InputConsumed;
}

static C5InputResult web_karma_ok(WebState* web, const C5HostApiV3* host) {
    switch(web->menu_index) {
    case 0: {
        uint32_t actions = c5_web_karma_start_collect(
            &web->karma, web->last_tick, web->launch.ticks_per_second,
            web->launch.probe_refresh_delay_ticks, web->list.active);
        if(actions & C5WebKarmaActionStop) {
            web_send(host, "stop");
            c5_web_list_end(&web->list);
        }
        if(actions & C5WebKarmaActionStart) {
            if(web_send(host, "start_sniffer")) {
                web_status(host, "Collecting probes...", 0);
            } else {
                c5_web_karma_cancel(&web->karma);
                web_status(host, "Sniffer command failed", 1500);
            }
        }
        break;
    }
    case 1:
        web->screen = WebScreenKarmaDuration;
        web_status(host, "", 0);
        break;
    case 2:
        if(web->karma.collecting) web_status(host, "Sniffer running\nwait for idle", 1500);
        else if(web->list.active) web_status(host, "Wait for list\ncompletion", 1500);
        else if(!web->probe_count) web_request_probe_list(web, host);
        else {
            web->popup_index = 0;
            web->screen = WebScreenKarmaProbePopup;
        }
        break;
    case 3:
        if(web->list.active) web_status(host, "Wait for list\ncompletion", 1500);
        else if(!web->html_count) web_request_html_list(web, host);
        else {
            web->popup_index = 0;
            web->screen = WebScreenHtmlPopup;
        }
        break;
    case 4:
        if(web->karma.collecting) web_status(host, "Sniffer running\nwait for idle", 1500);
        else if(web->list.active) web_status(host, "Wait for list\ncompletion", 1500);
        else if(!web->selected_probe_id) web_status(host, "Select probe\nbefore starting", 1500);
        else if(!web->selected_html_id) web_status(host, "Select HTML file\nbefore starting", 1500);
        else {
            char select[48];
            char start[48];
            snprintf(select, sizeof(select), "select_html %u", (unsigned)web->selected_html_id);
            snprintf(start, sizeof(start), "start_karma %u", (unsigned)web->selected_probe_id);
            if(web_send_two(host, select, start)) {
                web->serial_visible = true;
                web_redraw(host);
                return C5InputSwitchTerminal;
            }
            web_status(host, "Karma command failed", 1500);
        }
        break;
    }
    web_redraw(host);
    return C5InputConsumed;
}

static C5InputResult web_karma_duration_input(
    WebState* web,
    const C5HostApiV3* host,
    const InputEvent* event) {
    if(event->type == InputTypeShort &&
       (event->key == InputKeyBack || event->key == InputKeyOk)) {
        web->screen = WebScreenPortalMenu;
    } else {
        int32_t delta = 0;
        if(event->key == InputKeyUp) delta = C5_WEB_KARMA_DURATION_STEP_SEC;
        else if(event->key == InputKeyDown) delta = -C5_WEB_KARMA_DURATION_STEP_SEC;
        else if(event->key == InputKeyRight) delta = 1;
        else if(event->key == InputKeyLeft) delta = -1;
        if(!delta) return C5InputIgnored;
        if(c5_web_karma_adjust_duration(&web->karma, delta) && host->set_setting) {
            host->set_setting(host->ctx, C5SettingKarmaDurationSec,
                              (int32_t)web->karma.duration_sec);
        }
    }
    web_redraw(host);
    return C5InputConsumed;
}

static C5InputResult web_on_input(
    void* state,
    const C5HostApiV3* host,
    const InputEvent* event) {
    WebState* web = state;
    if(!web || !host || !event) return C5InputIgnored;
    if(web->serial_visible) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            if(web->running || web->launch.mode == C5WebModeKarma) {
                if(!web_send(host, "stop")) {
                    web_status(host, "Stop command failed", 1500);
                    return C5InputConsumed;
                }
                web->running = false;
            }
            web->serial_visible = false;
            web_redraw(host);
            return C5InputSwitchModule;
        }
        if(event->type == InputTypeLong && event->key == InputKeyOk) {
            return C5InputToggleConsole;
        }
        return C5InputIgnored;
    }
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return C5InputIgnored;
    if(web->screen == WebScreenPasswordsSelect || web->screen == WebScreenPasswordsText) {
        return web_passwords_input(web, host, event);
    }
    if(web->screen == WebScreenEvilPassList || web->screen == WebScreenEvilPassQr) {
        return web_evil_qr_input(web, host, event);
    }
    if(web->screen == WebScreenKarmaDuration) {
        return web_karma_duration_input(web, host, event);
    }
    if(web->screen != WebScreenPortalMenu) return web_popup_input(web, host, event);
    if(event->type == InputTypeShort &&
       (event->key == InputKeyBack || event->key == InputKeyLeft)) {
        return C5InputIgnored; /* Host owns exit from the Web section. */
    }
    size_t option_count = web->launch.mode == C5WebModePortal ? 4 : 5;
    if(event->key == InputKeyUp) {
        web->menu_index = web->menu_index == 0 ? option_count - 1 : web->menu_index - 1;
    } else if(event->key == InputKeyDown) {
        web->menu_index = (web->menu_index + 1) % option_count;
    } else if(event->type == InputTypeShort && event->key == InputKeyOk) {
        if(web->launch.mode == C5WebModeKarma) return web_karma_ok(web, host);
        if(web->launch.mode == C5WebModeEvilTwin && web->menu_index == 0) {
            if(!web->launch.selected_count) web_status(host, "Select in Scanner", 1200);
        } else if(web->launch.mode == C5WebModePortal && web->menu_index == 0) {
            if(web->list.active) {
                web_status(host, "Listing already\nin progress", 1200);
            } else if(web->ssid_count) {
                web->popup_index = 0;
                web->screen = WebScreenSsidPopup;
            } else if(web->ssid_missing) {
                web_request_ssid_input(web, host);
            } else {
                web_request_ssid_list(web, host);
            }
        } else if(web->menu_index == 1) {
            if(web->list.active) {
                web_status(host, "Listing already\nin progress", 1200);
            } else if(web->html_count) {
                web->popup_index = 0;
                web->screen = WebScreenHtmlPopup;
            } else {
                web_request_html_list(web, host);
            }
        } else if(web->menu_index == 2) {
            if(web->list.active) web_status(host, "Wait for list\ncompletion", 1500);
            else if(web->launch.mode == C5WebModePortal && !web->ssid[0]) {
                web_status(host, "Set SSID first", 1200);
            } else if(web->launch.mode == C5WebModeEvilTwin && !web->launch.selected_count) {
                web_status(host, "Please select\nnetwork first", 1500);
            }
            else if(!web->selected_html_id) web_status(host, "Select HTML file\nbefore starting", 1500);
            else {
                char select[48];
                snprintf(select, sizeof(select), "select_html %u", (unsigned)web->selected_html_id);
                bool sent;
                if(web->launch.mode == C5WebModeEvilTwin) {
                    sent = web_send_three(host, select, web->launch.select_networks,
                                          "start_evil_twin");
                } else {
                    char start[96];
                    snprintf(start, sizeof(start), "start_portal \"%s\"", web->ssid);
                    sent = web_send_two(host, select, start);
                }
                if(!sent) web_status(host, "Web command failed", 1500);
                else {
                    web->running = true;
                    web->serial_visible = true;
                    c5_web_status_reset(&web->status,
                                        web->launch.mode == C5WebModeEvilTwin ?
                                            C5WebStatusEvilTwin : C5WebStatusPortal);
                    web_redraw(host);
                    return C5InputSwitchTerminal;
                }
            }
        } else if((web->launch.mode == C5WebModePortal && web->menu_index == 3) ||
                  (web->launch.mode == C5WebModeEvilTwin && web->menu_index == 4)) {
            web->password_source_evil = web->launch.mode == C5WebModeEvilTwin;
            web->screen = WebScreenPasswordsSelect;
        } else if(web->launch.mode == C5WebModeEvilTwin && web->menu_index == 3) {
            web_request_evil_passes(web, host);
        }
    } else {
        return C5InputIgnored;
    }
    web_redraw(host);
    return C5InputConsumed;
}

static void web_draw(void* state, const C5HostApiV3* host, Canvas* canvas) {
    const WebState* web = state;
    (void)host;
    if(!web || !canvas) return;
    if(web->serial_visible) {
        if(web->launch.mode == C5WebModeKarma) return;
        C5WebOverlayView view = {
            .status = &web->status,
            .fallback_ssid = web->launch.mode == C5WebModeEvilTwin ?
                                 web->launch.first_selected_ssid : web->ssid,
            .scroll_title = web->overlay_title,
            .scroll_offset = web->overlay_scroll_offset,
        };
        if(web->launch.mode == C5WebModeEvilTwin) c5_web_overlay_draw_evil_twin(canvas, &view);
        else c5_web_overlay_draw_portal(canvas, &view);
        return;
    }
    if(web->screen == WebScreenPasswordsSelect) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 4, 14, "Show Passwords");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, web->password_source_evil ? 44 : 34, ">");
        canvas_draw_str(canvas, 14, 34, "Portal (portals.txt)");
        canvas_draw_str(canvas, 14, 44, "Evil Twin (eviltwin.txt)");
        canvas_draw_str(canvas, 2, 62, "OK select, Back");
        return;
    }
    if(web->screen == WebScreenPasswordsText) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 4, 12,
                        web->password_source_evil ? "Evil Twin Pass" : "Portal Pass");
        if(web->list.active && web->password_line_count == 0) {
            canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "Loading...");
        } else if(web->password_line_count == 0) {
            canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "No passwords");
        } else {
            for(size_t i = 0; i < 4; i++) {
                size_t index = web->password_scroll + i;
                if(index >= web->password_line_count) break;
                const char* source = web->password_lines[index];
                size_t length = strlen(source);
                size_t offset = web->password_scroll_x < length ? web->password_scroll_x : length;
                char line[27];
                size_t count = length - offset;
                if(count > 26) count = 26;
                memcpy(line, source + offset, count);
                line[count] = '\0';
                canvas_draw_str(canvas, 2, 26 + (int)i * 12, line);
            }
        }
        return;
    }
    if(web->screen == WebScreenEvilPassList) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 12, "Evil Twin QR");
        canvas_set_font(canvas, FontSecondary);
        if(web->list.active && web->pass_count == 0) {
            canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignCenter, "Loading...");
        } else if(web->pass_count == 0) {
            canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignCenter, "No entries");
        } else {
            size_t offset = web->pass_index >= 4 ? web->pass_index - 3 : 0;
            for(size_t i = 0; i < 4 && offset + i < web->pass_count; i++) {
                const C5WebPassEntry* entry = &web->passes[offset + i];
                char line[48];
                snprintf(line, sizeof(line), "%u %s", (unsigned)entry->id, entry->ssid);
                if(offset + i == web->pass_index) canvas_draw_str(canvas, 2, 22 + (int)i * 12, ">");
                canvas_draw_str(canvas, 12, 22 + (int)i * 12, line);
            }
        }
        return;
    }
    if(web->screen == WebScreenEvilPassQr) {
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, 0, 8, 32, 32);
        canvas_set_color(canvas, ColorBlack);
        int size = c5_web_qr_size(&web->qr);
        if(web->qr.valid && size > 0 && size <= 32) {
            int scale = 32 / size;
            int offset = (32 - size * scale) / 2;
            for(int y = 0; y < size; y++) {
                for(int x = 0; x < size; x++) {
                    if(c5_web_qr_get_module(&web->qr, x, y)) {
                        canvas_draw_box(canvas, offset + x * scale,
                                        8 + offset + y * scale, scale, scale);
                    }
                }
            }
        } else {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str_aligned(canvas, 16, 28, AlignCenter, AlignCenter, "QR error");
            canvas_draw_str_aligned(canvas, 16, 40, AlignCenter, AlignCenter,
                                    web->qr.error[0] ? web->qr.error : "QR too big");
        }
        canvas_set_font(canvas, FontSecondary);
        char ssid_first[19] = {0};
        char ssid_second[20] = {0};
        char pass_first[19] = {0};
        char pass_second[20] = {0};
        size_t ssid_length = strlen(web->qr.ssid);
        size_t pass_length = strlen(web->qr.pass);
        size_t first_length = ssid_length < 18 ? ssid_length : 18;
        memcpy(ssid_first, web->qr.ssid, first_length);
        if(ssid_length > 18) {
            size_t tail = ssid_length - 18;
            if(tail > 19) tail = 19;
            memcpy(ssid_second, web->qr.ssid + 18, tail);
        }
        first_length = pass_length < 18 ? pass_length : 18;
        memcpy(pass_first, web->qr.pass, first_length);
        if(pass_length > 18) {
            size_t tail = pass_length - 18;
            if(tail > 19) tail = 19;
            memcpy(pass_second, web->qr.pass + 18, tail);
        }
        canvas_draw_str(canvas, 36, 10, "SSID");
        canvas_draw_str(canvas, 36, 20, ssid_first);
        if(ssid_second[0]) canvas_draw_str(canvas, 36, 30, ssid_second);
        canvas_draw_str(canvas, 36, 42, "PASS");
        canvas_draw_str(canvas, 36, 52, pass_first);
        if(pass_second[0]) canvas_draw_str(canvas, 36, 62, pass_second);
        return;
    }
    if(web->screen == WebScreenKarmaDuration) {
        char line[32];
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 4, 14, "Karma Duration");
        canvas_set_font(canvas, FontSecondary);
        snprintf(line, sizeof(line), "Duration: %lus",
                 (unsigned long)web->karma.duration_sec);
        canvas_draw_str(canvas, 4, 34, line);
        canvas_draw_str(canvas, 2, 48, "Up/Down: 5s");
        canvas_draw_str(canvas, 2, 60, "Left/Right: 1s");
        return;
    }
    static const char* portal_options[] = {"SSID", "Select HTML", "Start Portal", "Show Passwords"};
    static const char* evil_options[] = {"Target", "Select HTML", "Start Evil Twin", "WiFi QR", "Show Passwords"};
    static const char* karma_options[] = {"Collect Probes", "Duration", "Select Probe", "Select HTML", "Start Karma"};
    const char* const* options = web->launch.mode == C5WebModePortal ? portal_options :
                                 (web->launch.mode == C5WebModeEvilTwin ? evil_options : karma_options);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 14, web->launch.mode == C5WebModePortal ? "Portal" :
                                   (web->launch.mode == C5WebModeEvilTwin ? "Evil Twin" : "Karma"));
    canvas_set_font(canvas, FontSecondary);
    for(size_t i = 0; i < 2; i++) {
        size_t idx = web->menu_index < 2 ? i : web->menu_index - 1 + i;
        int y = 30 + (int)(i * 20);
        if(idx == web->menu_index) canvas_draw_str(canvas, 2, y, ">");
        canvas_draw_str(canvas, 14, y, options[idx]);
        if(idx == 0 && web->launch.mode == C5WebModePortal) {
            canvas_draw_str(canvas, 14, y + 10, web->ssid[0] ? web->ssid : "<none>");
        }
        if(idx == 0 && web->launch.mode == C5WebModeEvilTwin) {
            canvas_draw_str(canvas, 14, y + 10,
                            web->launch.selected_count ? web->launch.first_selected_ssid : "Select in Scanner");
        }
        if(idx == 1 && web->launch.mode != C5WebModeKarma) canvas_draw_str(canvas, 14, y + 10,
                                     web->selected_html_name[0] ? web->selected_html_name : "<none>");
        if(web->launch.mode == C5WebModeKarma) {
            char detail[48];
            detail[0] = '\0';
            if(idx == 0) {
                snprintf(detail, sizeof(detail), "%s",
                         web->karma.collecting ? "running" :
                         (web->karma.pending_probe_refresh ? "updating" : "idle"));
            } else if(idx == 1) {
                snprintf(detail, sizeof(detail), "%lus",
                         (unsigned long)web->karma.duration_sec);
            } else if(idx == 2) {
                snprintf(detail, sizeof(detail), "%s",
                         web->selected_probe_name[0] ? web->selected_probe_name : "<none>");
            } else if(idx == 3) {
                snprintf(detail, sizeof(detail), "%s",
                         web->selected_html_name[0] ? web->selected_html_name : "<none>");
            } else if(!web->selected_probe_id) {
                snprintf(detail, sizeof(detail), "need probe");
            } else if(!web->selected_html_id) {
                snprintf(detail, sizeof(detail), "need HTML");
            }
            if(detail[0]) canvas_draw_str(canvas, 14, y + 10, detail);
        }
    }
    if(web->screen != WebScreenPortalMenu) {
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_rbox(canvas, 4, 4, 120, 56, 9);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_rframe(canvas, 4, 4, 120, 56, 9);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 12, 20, web->screen == WebScreenSsidPopup ? "Select SSID" :
                                        (web->screen == WebScreenKarmaProbePopup ?
                                             "Select Probe" : "Select HTML"));
        canvas_set_font(canvas, FontSecondary);
        size_t total = web->screen == WebScreenSsidPopup ? web->ssid_count + 1 :
                       (web->screen == WebScreenKarmaProbePopup ? web->probe_count : web->html_count);
        size_t start = web->popup_index >= 3 ? web->popup_index - 2 : 0;
        for(size_t i = 0; i < 3 && start + i < total; i++) {
            size_t index = start + i;
            if(index == web->popup_index) canvas_draw_str(canvas, 8, 32 + (int)i * 12, ">");
            const char* label = web->screen == WebScreenSsidPopup ?
                                    (index == 0 ? "Manual entry" : web->ssids[index - 1].ssid) :
                                (web->screen == WebScreenKarmaProbePopup ?
                                     web->probes[index].name : web->htmls[index].name);
            canvas_draw_str(canvas, 12, 32 + (int)i * 12, label);
        }
    }
}

static void web_tick(void* state, const C5HostApiV3* host, uint32_t ticks) {
    WebState* web = state;
    if(!web || !host) return;
    web->last_tick = ticks;
    if(web->serial_visible && web->running && web->launch.mode != C5WebModeKarma) {
        const char* title = web->status.ssid[0] ? web->status.ssid :
                            (web->launch.mode == C5WebModeEvilTwin ?
                                 web->launch.first_selected_ssid : web->ssid);
        if(!title[0]) title = "--";
        if(strcmp(web->overlay_title, title) != 0) {
            snprintf(web->overlay_title, sizeof(web->overlay_title), "%s", title);
            web->overlay_scroll_offset = 0;
            web->overlay_scroll_direction = 1;
            web->overlay_scroll_hold = 3;
            web->overlay_scroll_tick = ticks;
            web_redraw(host);
        } else {
            size_t title_length = strlen(web->overlay_title);
            if(title_length > 22) {
                uint32_t interval = web->launch.ticks_per_second / 5;
                if(!interval) interval = 1;
                if((uint32_t)(ticks - web->overlay_scroll_tick) >= interval) {
                    web->overlay_scroll_tick = ticks;
                    if(web->overlay_scroll_hold) web->overlay_scroll_hold--;
                    else {
                        size_t maximum = title_length - 22;
                        if(web->overlay_scroll_direction > 0) {
                            if(web->overlay_scroll_offset < maximum) web->overlay_scroll_offset++;
                            if(web->overlay_scroll_offset == maximum) {
                                web->overlay_scroll_direction = -1;
                                web->overlay_scroll_hold = 3;
                            }
                        } else {
                            if(web->overlay_scroll_offset) web->overlay_scroll_offset--;
                            if(!web->overlay_scroll_offset) {
                                web->overlay_scroll_direction = 1;
                                web->overlay_scroll_hold = 3;
                            }
                        }
                        web_redraw(host);
                    }
                }
            }
        }
    }
    if(web->launch.mode != C5WebModeKarma) return;
    uint32_t actions = c5_web_karma_tick(
        &web->karma, ticks,
        web->list.active || web->screen != WebScreenPortalMenu || web->serial_visible);
    if(actions & C5WebKarmaActionStop) {
        if(web_send(host, "stop")) {
            web_status(host, "Sniffer stopped", 1000);
        } else {
            web->karma.collecting = true;
            web->karma.pending_probe_refresh = false;
            web->karma.stop_tick = ticks + web->karma.refresh_delay_ticks;
            web_status(host, "Stop command failed", 1500);
        }
    }
    if(actions & C5WebKarmaActionListProbes) web_request_probe_list(web, host);
}

static const C5ModuleV3 c5_web_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = web_enter,
    .leave = web_leave,
    .on_bytes = web_on_bytes,
    .on_input = web_on_input,
    .on_text_input = web_on_text_input,
    .draw = web_draw,
    .tick = web_tick,
};

static const FlipperAppPluginDescriptor c5_web_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_web_module,
};

const FlipperAppPluginDescriptor* lab_c5_web_plugin_ep(void) {
    return &c5_web_descriptor;
}
