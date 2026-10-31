#include "../module_api.h"
#include "../modules/connect/connect_module.h"
#include <flipper_application/flipper_application.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_connect_plugin_ep(void);
typedef struct { char tx[2][96]; size_t count; bool fail; } Fake;
static bool send_raw(void* ctx, const char* bytes, size_t n) {
    Fake* f = ctx;
    assert(n && n < sizeof(f->tx[0]) && bytes[n-1] == '\n' && !memchr(bytes, 0, n));
    if(f->fail) return false;
    assert(f->count < 2);
    memcpy(f->tx[f->count], bytes, n);
    f->tx[f->count++][n] = 0;
    return true;
}
static void redraw(void* ctx) { (void)ctx; }
void canvas_set_color(Canvas* c, Color v) { (void)c; (void)v; }
void canvas_set_font(Canvas* c, Font v) { (void)c; (void)v; }
void canvas_draw_str(Canvas* c, int x, int y, const char* s) {
    (void)x; (void)y;
    assert(c->line_count < 16);
    snprintf(c->lines[c->line_count++], sizeof(c->lines[0]), "%s", s);
}
void canvas_draw_str_aligned(Canvas* c, int x, int y, Align h, Align v, const char* s) {
    (void)h; (void)v; canvas_draw_str(c, x, y, s);
}
void canvas_draw_box(Canvas* c, int x, int y, int w, int h) {
    (void)c; (void)x; (void)y; (void)w; (void)h;
}
void canvas_draw_rbox(Canvas* c, int x, int y, int w, int h, int r) {
    (void)c; (void)x; (void)y; (void)w; (void)h; (void)r;
}
void canvas_draw_rframe(Canvas* c, int x, int y, int w, int h, int r) {
    (void)c; (void)x; (void)y; (void)w; (void)h; (void)r;
}
static bool has(Canvas* c, const char* s) {
    for(size_t i=0; i<c->line_count; i++) if(!strcmp(c->lines[i], s)) return true;
    return false;
}
static C5HostApiV3 api(Fake* f) {
    C5HostApiV3 h = {.version=C5_MODULE_API_VERSION, .size=sizeof(C5HostApiV3),
                     .ctx=f, .send_raw_lines=send_raw, .request_redraw=redraw};
    return h;
}
static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* d=lab_c5_connect_plugin_ep();
    assert(d && d->ep_api_version==C5_MODULE_API_VERSION);
    const C5ModuleV3* m=d->entry_point;
    assert(m && m->version==C5_MODULE_API_VERSION && m->size==sizeof(*m));
    return m;
}
static C5ConnectLaunchContext launch_data(const char* ssid) {
    C5ConnectLaunchContext p={.version=C5_CONNECT_LAUNCH_VERSION,
                              .size=sizeof(C5ConnectLaunchContext), .ticks_per_second=1000};
    snprintf(p.ssid,sizeof(p.ssid),"%s",ssid);
    return p;
}
static void* enter(const C5ModuleV3* m, C5HostApiV3* h, const char* ssid) {
    C5ConnectLaunchContext p=launch_data(ssid);
    return m->enter(h,&p,sizeof(p));
}
static void feed(const C5ModuleV3* m, void* s, C5HostApiV3* h, const char* transcript) {
    m->on_bytes(s,h,(const uint8_t*)transcript,strlen(transcript));
}
static void fragmented(const C5ModuleV3* m, void* s, C5HostApiV3* h, const char* t) {
    for(size_t i=0;t[i];i++) m->on_bytes(s,h,(const uint8_t*)t+i,1);
}
static Canvas draw(const C5ModuleV3* m, void* s, C5HostApiV3* h) {
    Canvas c={0}; m->draw(s,h,&c); return c;
}
static C5InputResult back(const C5ModuleV3* m, void* s, C5HostApiV3* h) {
    InputEvent e={.type=InputTypeShort,.key=InputKeyBack}; return m->on_input(s,h,&e);
}
static void start(const C5ModuleV3* m, void* s, C5HostApiV3* h) { m->tick(s,h,1234); }

static void test_command_escaping_and_no_stop_while_pending(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Cafe \"North\"\\Wing"); assert(s && !f.count);
    start(m,s,&h);
    assert(f.count==1 && !strcmp(f.tx[0],"wifi_connect \"Cafe \\\"North\\\"\\\\Wing\" --saved\n"));
    m->tick(s,&h,2345); assert(f.count==1);
    assert(back(m,s,&h)==C5InputConsumed);
    Canvas c=draw(m,s,&h); assert(has(&c,"Connecting...") && has(&c,"Back: wait"));
    m->leave(s,&h); assert(f.count==1);
}
static void test_saved_success_ip_and_prompt(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    fragmented(m,s,&h,"I (101) projectZero: wifi_connect: using saved password from home.txt for 'Home'\r\n"
                      "wifi_connect: password source=saved\nSUCCESS: Connected to 'Home'\n");
    Canvas c=draw(m,s,&h); assert(has(&c,"WiFi joined") && !has(&c,"Connected + IP"));
    fragmented(m,s,&h,"DHCP IP: 192.168.1.42, Netmask: 255.255.255.0, GW: 192.168.1.1\r\n");
    c=draw(m,s,&h); assert(has(&c,"Saved key used") && has(&c,"Connected + IP") &&
                           has(&c,"192.168.1.42"));
    assert(back(m,s,&h)==C5InputConsumed);
    fragmented(m,s,&h,"> "); assert(back(m,s,&h)==C5InputSwitchModule);
    m->leave(s,&h); assert(f.count==1);
}
static void test_missing_key_fallback_failure_and_open_success(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Cafe"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: no saved password found for 'Cafe'\n"
                "wifi_connect: saved password requested but missing, trying open network\n"
                "FAILED: Connection to 'Cafe' failed (reason=201). Check SSID/password and signal.\n>");
    Canvas c=draw(m,s,&h); assert(has(&c,"No saved key") && has(&c,"Connect failed") &&
                           has(&c,"Reason 201") && !has(&c,"Saved key used"));
    assert(back(m,s,&h)==C5InputSwitchModule); m->leave(s,&h);
    memset(&f,0,sizeof(f)); s=enter(m,&h,"Guest"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: no saved password found for 'Guest'\n"
                "wifi_connect: saved password requested but missing, trying open network\n"
                "SUCCESS: Connected to 'Guest'\n"
                "Static IP: 10.1.0.7, Netmask: 255.255.255.0, GW: 10.1.0.1\n> ");
    c=draw(m,s,&h); assert(has(&c,"Open network") && has(&c,"Connected + IP") &&
                        has(&c,"10.1.0.7") && !has(&c,"Saved key used"));
    m->leave(s,&h);
}
static void test_missing_key_already_connected_is_distinct(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: no saved password found for 'Home'\n"
                "Wi-Fi: already connected to SSID='Home'\n"
                "SUCCESS: Connected to 'Home'\n"
                "DHCP IP: 192.168.0.2, Netmask: 255.255.255.0, GW: 192.168.0.1\n>");
    Canvas c=draw(m,s,&h); assert(has(&c,"Already connected") && !has(&c,"Open network") &&
                           !has(&c,"Saved key used"));
    m->leave(s,&h);
}
static void test_wrong_ssid_success_does_not_claim_ip(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Selected"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: password source=saved\nSUCCESS: Connected to 'Other'\n"
                "DHCP IP: 192.168.0.2, Netmask: 255.255.255.0, GW: 192.168.0.1\n>");
    Canvas c=draw(m,s,&h); assert(has(&c,"SSID mismatch") && !has(&c,"Connected + IP"));
    m->leave(s,&h);
}
static void test_incomplete_ip_line_does_not_claim_ip(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"SUCCESS: Connected to 'Home'\n"
                "DHCP IP: 10.0.0.5, Netmask: bad\n>");
    Canvas c=draw(m,s,&h);
    assert(has(&c,"WiFi joined") && has(&c,"IP unconfirmed") && !has(&c,"Connected + IP"));
    m->leave(s,&h);
}
static void test_stale_prompt_before_reply_is_ignored(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    fragmented(m,s,&h,"> ");
    assert(back(m,s,&h)==C5InputConsumed);
    feed(m,s,&h,"\nwifi_connect: password source=saved\n"
                "SUCCESS: Connected to 'Home'\n"
                "No IP assigned yet. Wait for DHCP.\n>");
    Canvas c=draw(m,s,&h);
    assert(has(&c,"WiFi joined") && has(&c,"No IP yet"));
    assert(back(m,s,&h)==C5InputSwitchModule);
    m->leave(s,&h);
}
static void test_lost_prompt_allows_uncertain_exit_after_timeout(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: password source=saved\n"
                "SUCCESS: Connected to 'Home'\n"
                "No IP assigned yet. Wait for DHCP.\n");
    m->tick(s,&h,31233);
    assert(back(m,s,&h)==C5InputConsumed);
    m->tick(s,&h,31234);
    Canvas c=draw(m,s,&h);
    assert(has(&c,"Result unconfirmed") && has(&c,"JanOS may be busy") &&
           !has(&c,"Connected + IP"));
    assert(back(m,s,&h)==C5InputSwitchModule);
    m->leave(s,&h); assert(f.count==1);
}
static void test_no_ip_prompt_and_timeout(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"wifi_connect: password source=saved\nSUCCESS: Connected to 'Home'\n"
                "No IP assigned yet. Wait for DHCP.\n>");
    Canvas c=draw(m,s,&h); assert(has(&c,"WiFi joined") && has(&c,"No IP yet") &&
                           !has(&c,"Connected + IP")); m->leave(s,&h);
    memset(&f,0,sizeof(f)); s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"Waiting for connection result...\n>"); c=draw(m,s,&h);
    assert(has(&c,"Result unconfirmed") && back(m,s,&h)==C5InputSwitchModule); m->leave(s,&h);
    memset(&f,0,sizeof(f)); s=enter(m,&h,"Home"); start(m,s,&h);
    feed(m,s,&h,"TIMEOUT: Connection to 'Home' timed out\n>"); c=draw(m,s,&h);
    assert(has(&c,"Connection timeout")); m->leave(s,&h);
}
static void test_refusal_and_immediate_errors(void) {
    const char* t[]={"Capture Gateway is active. Use 'capture_gateway stop' or 'stop' first.\n>",
                     "Failed to reinitialize WiFi\n>","STA interface not found\n>"};
    const char* want[]={"Gateway active","WiFi init failed","STA unavailable"};
    const C5ModuleV3* m=module();
    for(size_t i=0;i<3;i++) {
        Fake f={0}; C5HostApiV3 h=api(&f); void* s=enter(m,&h,"Home"); start(m,s,&h);
        fragmented(m,s,&h,t[i]); Canvas c=draw(m,s,&h);
        assert(has(&c,want[i]) && back(m,s,&h)==C5InputSwitchModule);
        m->leave(s,&h); assert(f.count==1);
    }
}
static void test_hidden_invalid_launch_and_tx_failure(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Hidden"); assert(s); start(m,s,&h);
    Canvas c=draw(m,s,&h); assert(has(&c,"Hidden SSID unavailable") && f.count==0 &&
                           back(m,s,&h)==C5InputSwitchModule); m->leave(s,&h);
    C5ConnectLaunchContext p=launch_data("Home");
    assert(!m->enter(&h,NULL,sizeof(p)) && !m->enter(&h,&p,sizeof(p)-1));
    p.version++; assert(!m->enter(&h,&p,sizeof(p)));
    p=launch_data("Home"); p.size--; assert(!m->enter(&h,&p,sizeof(p)));
    p=launch_data("Home"); p.ticks_per_second=0; assert(!m->enter(&h,&p,sizeof(p)));
    p=launch_data(""); assert(!m->enter(&h,&p,sizeof(p)));
    p=launch_data("12345678901234567890123456789012"); assert(!m->enter(&h,&p,sizeof(p)));
    const char* bad[]={"Bad\nSSID","Bad\rSSID","Bad\tSSID"};
    for(size_t i=0;i<3;i++) { p=launch_data(bad[i]); assert(!m->enter(&h,&p,sizeof(p))); }
    p=launch_data("Home"); memset(p.ssid,'A',sizeof(p.ssid)); assert(!m->enter(&h,&p,sizeof(p)));
    p=launch_data("Home"); h.send_raw_lines=NULL; assert(!m->enter(&h,&p,sizeof(p)));
    h=api(&f); f.fail=true; s=enter(m,&h,"Home"); assert(s); start(m,s,&h);
    c=draw(m,s,&h); assert(has(&c,"Send failed") && back(m,s,&h)==C5InputSwitchModule);
    m->leave(s,&h); assert(f.count==0);
}
static void test_overlong_line_discarded(void) {
    Fake f={0}; C5HostApiV3 h=api(&f); const C5ModuleV3* m=module();
    void* s=enter(m,&h,"Home"); start(m,s,&h);
    char junk[301]; memset(junk,'X',300); junk[300]=0; fragmented(m,s,&h,junk);
    feed(m,s,&h,"\nSUCCESS: Connected to 'Home'\nNo IP assigned yet. Wait for DHCP.\n>");
    Canvas c=draw(m,s,&h); assert(has(&c,"WiFi joined") && has(&c,"No IP yet"));
    m->leave(s,&h);
}
int main(void) {
    test_command_escaping_and_no_stop_while_pending();
    test_saved_success_ip_and_prompt();
    test_missing_key_fallback_failure_and_open_success();
    test_missing_key_already_connected_is_distinct();
    test_wrong_ssid_success_does_not_claim_ip();
    test_incomplete_ip_line_does_not_claim_ip();
    test_lost_prompt_allows_uncertain_exit_after_timeout();
    test_stale_prompt_before_reply_is_ignored();
    test_no_ip_prompt_and_timeout();
    test_refusal_and_immediate_errors();
    test_hidden_invalid_launch_and_tx_failure();
    test_overlong_line_discarded();
    puts("PASS: connect_module"); return 0;
}
