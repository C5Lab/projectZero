#include "wifi_shield_wire.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static char out[WIFI_SHIELD_LINE_MAX + 32];
static char before[sizeof(out)];

void *__wrap_malloc(size_t n) { (void)n; assert(0); return NULL; }
void *__wrap_calloc(size_t n, size_t size) { (void)n; (void)size; assert(0); return NULL; }
void *__wrap_realloc(void *p, size_t n) { (void)p; (void)n; assert(0); return NULL; }
void __wrap_free(void *p) { (void)p; assert(0); }

static wifi_shield_status_t status_fixture(void)
{
    wifi_shield_status_t s = {0};
    s.running = true; s.target_count = 2; s.channel_count = 2;
    s.channels[0] = 4; s.channels[1] = 11; s.current_channel = 4;
    s.source_events[0] = 12; s.source_events[1] = 3;
    s.source_events[3] = 1; s.alerts = 4;
    return s;
}

static wifi_shield_event_t event_fixture(void)
{
    wifi_shield_event_t e = {
        .source = WIFI_SHIELD_SOURCE_WPS, .type = WIFI_SHIELD_EVENT_WPS_ACTIVITY,
        .severity = WIFI_SHIELD_SEVERITY_INFO,
        .bssid = {0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        .station = {2,3,4,5,6,7}, .channel = 4, .count = 1,
        .window_ms = 10000, .wps_message = WIFI_SHIELD_WPS_UNKNOWN
    };
    return e;
}

static wifi_shield_target_t target_fixture(void)
{
    wifi_shield_target_t target = {
        .bssid = {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90},
        .channel = 4,
        .ssid = "TP-Link_0E90",
        .wpa2_psk_ccmp = true
    };
    return target;
}

static void exact(int result, const char *expected)
{
    size_t n = strlen(expected);
    if (result != (int)n || memcmp(out, expected, n + 1) != 0)
        fprintf(stderr, "expected: %.511sactual: %.511s", expected, out);
    assert(result == (int)n && n < WIFI_SHIELD_LINE_MAX);
    assert(memcmp(out, expected, n + 1) == 0);
    assert(n >= 2 && out[n-2] == '\r' && out[n-1] == '\n');
    assert(memchr(out, '\n', n-1) == NULL);
}

#define REJECT(call) do { memset(out, 0xa5, sizeof(out)); \
    memcpy(before, out, sizeof(out)); assert((call) < 0); \
    assert(memcmp(out, before, sizeof(out)) == 0); } while (0)

static void records(void)
{
    wifi_shield_status_t s = status_fixture();
    wifi_shield_event_t e = event_fixture();
    wifi_shield_target_t target = target_fixture();
    exact(wifi_shield_format_armed(out, sizeof(out), &s),
          "[SHIELD/1] ARMED MODE=passive TARGETS=2 CHANNELS=4,11 COVERAGE=sampled\r\n");
    exact(wifi_shield_format_target(out, sizeof(out), &target, 1U, 1U),
          "[SHIELD/1] TARGET N=1/1 SSID=\"TP-Link_0E90\" BSSID=b0:be:76:70:0e:90 CH=4\r\n");
    exact(wifi_shield_format_event(out, sizeof(out), &e),
          "[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=info COUNT=1 WINDOW_MS=10000 MESSAGE=unknown\r\n");
    e.type = WIFI_SHIELD_EVENT_WPS_RETRY_BURST;
    e.severity = WIFI_SHIELD_SEVERITY_WARN; e.count = 8;
    exact(wifi_shield_format_event(out, sizeof(out), &e),
          "[SHIELD/1] ALERT SOURCE=wps TYPE=retry_burst BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=warn COUNT=8 WINDOW_MS=10000 MESSAGE=unknown\r\n");
    exact(wifi_shield_format_status(out, sizeof(out), &s),
          "[SHIELD/1] STATUS RUNNING=1 MODE=passive TARGETS=2 CURRENT_CH=4 COVERAGE=sampled DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
    exact(wifi_shield_format_terminal(out, sizeof(out), &s, "stopped"),
          "[SHIELD/1] TERMINAL OUTCOME=stopped RUNNING=1 MODE=passive TARGETS=2 CURRENT_CH=4 COVERAGE=sampled DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
    s.target_count = s.channel_count = 1;
    exact(wifi_shield_format_armed(out, sizeof(out), &s),
          "[SHIELD/1] ARMED MODE=passive TARGETS=1 CHANNELS=4 COVERAGE=continuous\r\n");
    s.active_defence = true; s.pmkid_decoy = true;
    exact(wifi_shield_format_armed(out, sizeof(out), &s),
          "[SHIELD/1] ARMED MODE=active TARGETS=1 CHANNELS=4 COVERAGE=continuous\r\n");
    exact(wifi_shield_format_status(out, sizeof(out), &s),
          "[SHIELD/1] STATUS RUNNING=1 MODE=active TARGETS=1 CURRENT_CH=4 COVERAGE=continuous DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
    exact(wifi_shield_format_terminal(out, sizeof(out), &s, "stopped"),
          "[SHIELD/1] TERMINAL OUTCOME=stopped RUNNING=1 MODE=active TARGETS=1 CURRENT_CH=4 COVERAGE=continuous DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
    s.multi_vector = true; s.protect_all = true;
    exact(wifi_shield_format_armed(out, sizeof(out), &s),
          "[SHIELD/1] ARMED MODE=protect-all TARGETS=1 CHANNELS=4 COVERAGE=continuous ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust\r\n");
    exact(wifi_shield_format_status(out, sizeof(out), &s),
          "[SHIELD/1] STATUS RUNNING=1 MODE=protect-all ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust TARGETS=1 CURRENT_CH=4 COVERAGE=continuous DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
    exact(wifi_shield_format_terminal(out, sizeof(out), &s, "stopped"),
          "[SHIELD/1] TERMINAL OUTCOME=stopped RUNNING=1 MODE=protect-all ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust TARGETS=1 CURRENT_CH=4 COVERAGE=continuous DEAUTH=12 WPS=3 SAE=0 TRUST=1 ALERTS=4 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n");
}

static void target_records_escape_untrusted_ssid(void)
{
    wifi_shield_target_t target = target_fixture();
    static const char unsafe[] = {'L', 'a', 'b', '"', '\\', '\r', '\n', '\0'};
    memcpy(target.ssid, unsafe, sizeof(unsafe));
    exact(wifi_shield_format_target(out, sizeof(out), &target, 1U, 2U),
          "[SHIELD/1] TARGET N=1/2 SSID=\"Lab\\\"\\\\\\x0d\\x0a\" BSSID=b0:be:76:70:0e:90 CH=4\r\n");

    target.ssid[0] = '\0';
    exact(wifi_shield_format_target(out, sizeof(out), &target, 2U, 2U),
          "[SHIELD/1] TARGET N=2/2 SSID=\"<hidden>\" BSSID=b0:be:76:70:0e:90 CH=4\r\n");
}

static void outcomes_and_messages(void)
{
#define TERMINAL(value) "[SHIELD/1] TERMINAL OUTCOME=" value " RUNNING=0 MODE=passive TARGETS=0 CURRENT_CH=0 COVERAGE=none DEAUTH=0 WPS=0 SAE=0 TRUST=0 ALERTS=0 RX_DROPS=0 EVENT_DROPS=0 OUTPUT_FAILURES=0\r\n"
    const struct { const char *outcome; const char *expected; } outcomes[] = {
        {"stopped",TERMINAL("stopped")}, {"busy",TERMINAL("busy")},
        {"invalid",TERMINAL("invalid")}, {"timeout",TERMINAL("timeout")},
        {"queue_overflow",TERMINAL("queue_overflow")},
        {"restore_failed",TERMINAL("restore_failed")},
        {"output_failed",TERMINAL("output_failed")}, {"no_mem",TERMINAL("no_mem")}
    };
#undef TERMINAL
#define MESSAGE(value) "[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=info COUNT=1 WINDOW_MS=10000 MESSAGE=" value "\r\n"
    const char *messages[] = { MESSAGE("unknown"), MESSAGE("M1"), MESSAGE("M2"),
        MESSAGE("M3"), MESSAGE("M4"), MESSAGE("M5"), MESSAGE("M6"), MESSAGE("M7"),
        MESSAGE("M8"), MESSAGE("ACK"), MESSAGE("NACK"), MESSAGE("DONE") };
#undef MESSAGE
    wifi_shield_status_t s = {0};
    for (size_t i = 0; i < sizeof(outcomes)/sizeof(*outcomes); ++i) {
        exact(wifi_shield_format_terminal(out, sizeof(out), &s, outcomes[i].outcome), outcomes[i].expected);
    }
    wifi_shield_event_t e = event_fixture();
    for (size_t i = 0; i < sizeof(messages)/sizeof(*messages); ++i) {
        e.wps_message = (wifi_shield_wps_message_t)i;
        exact(wifi_shield_format_event(out, sizeof(out), &e), messages[i]);
    }
}

static void validation(void)
{
    wifi_shield_status_t s = status_fixture();
    wifi_shield_event_t e = event_fixture(), bad;
    wifi_shield_target_t target = target_fixture(), bad_target;
    assert(wifi_shield_format_event(NULL, 512, &e) < 0);
    assert(wifi_shield_format_status(NULL, 512, &s) < 0);
    assert(wifi_shield_format_armed(NULL, 512, &s) < 0);
    assert(wifi_shield_format_target(NULL, 512, &target, 1U, 1U) < 0);
    assert(wifi_shield_format_terminal(NULL, 512, &s, "busy") < 0);
    REJECT(wifi_shield_format_event(out, sizeof(out), NULL));
    REJECT(wifi_shield_format_status(out, sizeof(out), NULL));
    REJECT(wifi_shield_format_armed(out, sizeof(out), NULL));
    REJECT(wifi_shield_format_target(out, sizeof(out), NULL, 1U, 1U));
    REJECT(wifi_shield_format_target(out, sizeof(out), &target, 0U, 1U));
    REJECT(wifi_shield_format_target(out, sizeof(out), &target, 2U, 1U));
    REJECT(wifi_shield_format_target(out, sizeof(out), &target, 1U, 0U));
    REJECT(wifi_shield_format_target(out, sizeof(out), &target, 1U,
                                     WIFI_SHIELD_TARGET_MAX + 1U));
    bad_target = target; memset(bad_target.bssid, 0, sizeof(bad_target.bssid));
    REJECT(wifi_shield_format_target(out, sizeof(out), &bad_target, 1U, 1U));
    bad_target = target; bad_target.bssid[0] |= 1U;
    REJECT(wifi_shield_format_target(out, sizeof(out), &bad_target, 1U, 1U));
    bad_target = target; bad_target.channel = 0U;
    REJECT(wifi_shield_format_target(out, sizeof(out), &bad_target, 1U, 1U));
    bad_target = target; memset(bad_target.ssid, 'x', sizeof(bad_target.ssid));
    REJECT(wifi_shield_format_target(out, sizeof(out), &bad_target, 1U, 1U));
    REJECT(wifi_shield_format_terminal(out, sizeof(out), NULL, "busy"));
    const char *unsafe[] = {NULL, "", "ok", "stopped\r\n", "busy x", "busy=1", "BUSY", "queue_overflowx"};
    for (size_t i = 0; i < sizeof(unsafe)/sizeof(*unsafe); ++i)
        REJECT(wifi_shield_format_terminal(out, sizeof(out), &s, unsafe[i]));
    char unterminated[15]; memset(unterminated, 'x', sizeof(unterminated));
    REJECT(wifi_shield_format_terminal(out, sizeof(out), &s, unterminated));
    for (int i = -1; i <= 20; ++i) {
        bad = e; bad.source = (wifi_shield_source_t)i;
        if (i != WIFI_SHIELD_SOURCE_WPS) REJECT(wifi_shield_format_event(out, sizeof(out), &bad));
        bad = e; bad.type = (wifi_shield_event_type_t)i;
        if (i != WIFI_SHIELD_EVENT_WPS_ACTIVITY) REJECT(wifi_shield_format_event(out, sizeof(out), &bad));
        bad = e; bad.severity = (wifi_shield_severity_t)i;
        if (i != WIFI_SHIELD_SEVERITY_INFO) REJECT(wifi_shield_format_event(out, sizeof(out), &bad));
    }
    bad=e; bad.wps_message=(wifi_shield_wps_message_t)-1;
    REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; bad.wps_message=(wifi_shield_wps_message_t)12;
    REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    const unsigned channels[] = {0};
    for(size_t i=0;i<sizeof(channels)/sizeof(*channels);++i) {
        bad=e; bad.channel=(uint8_t)channels[i];
        REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    }
    bad=e; bad.count=0; REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; memset(bad.bssid,0,6); REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; bad.bssid[0]|=1; REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; memset(bad.station,0,6); REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; memset(bad.station,255,6); REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    bad=e; memcpy(bad.station,bad.bssid,6); REJECT(wifi_shield_format_event(out,sizeof(out),&bad));
    s.channel_count=65; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.target_count=65; REJECT(wifi_shield_format_armed(out,sizeof(out),&s));
    s=status_fixture(); s.channels[1]=4; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.current_channel=6; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.pmkid_decoy=true; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.protect_all=true; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.active_defence=true; s.pmkid_decoy=true;
    s.protect_all=true; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.running=false; REJECT(wifi_shield_format_armed(out,sizeof(out),&s));
    s=status_fixture(); s.stopping=true; REJECT(wifi_shield_format_armed(out,sizeof(out),&s));
    s=status_fixture(); s.channels[0]=0; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.channel_count=0; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
    s=status_fixture(); s.target_count=0; REJECT(wifi_shield_format_status(out,sizeof(out),&s));
}

static void bounds(void)
{
    wifi_shield_status_t s=status_fixture(); wifi_shield_event_t e=event_fixture();
    wifi_shield_target_t target=target_fixture();
    int target_n=wifi_shield_format_target(out,sizeof(out),&target,1U,1U);
    assert(target_n>0&&target_n<512);
    REJECT(wifi_shield_format_target(out,(size_t)target_n,&target,1U,1U));
    assert(wifi_shield_format_target(out,(size_t)target_n+1U,&target,1U,1U)==target_n);
    int n=wifi_shield_format_armed(out,sizeof(out),&s);
    REJECT(wifi_shield_format_armed(out,(size_t)n,&s));
    assert(wifi_shield_format_armed(out,(size_t)n+1,&s)==n);
    n=wifi_shield_format_status(out,sizeof(out),&s);
    REJECT(wifi_shield_format_status(out,(size_t)n,&s));
    assert(wifi_shield_format_status(out,(size_t)n+1,&s)==n);
    n=wifi_shield_format_terminal(out,sizeof(out),&s,"queue_overflow");
    REJECT(wifi_shield_format_terminal(out,(size_t)n,&s,"queue_overflow"));
    assert(wifi_shield_format_terminal(out,(size_t)n+1,&s,"queue_overflow")==n);
    e.count=e.window_ms=UINT32_MAX; e.timestamp_us=UINT64_MAX;
    n=wifi_shield_format_event(out,sizeof(out),&e); assert(n>0 && n<512);
    REJECT(wifi_shield_format_event(out,(size_t)n,&e));
    assert(wifi_shield_format_event(out,(size_t)n+1,&e)==n);
    REJECT(wifi_shield_format_event(out,0,&e));
    memset(&s,0,sizeof(s));
    for(size_t i=0;i<5;++i) s.source_events[i]=UINT32_MAX;
    s.alerts=s.rx_drops=s.event_drops=s.output_failures=UINT32_MAX;
    n=wifi_shield_format_terminal(out,sizeof(out),&s,"restore_failed"); assert(n>0&&n<512);
    s.running=true; s.target_count=s.channel_count=WIFI_SHIELD_TARGET_MAX;
    s.current_channel=1;
    for(size_t i=0;i<WIFI_SHIELD_TARGET_MAX;++i) s.channels[i]=(uint8_t)(i+1);
    n=wifi_shield_format_armed(out,sizeof(out),&s); assert(n>0&&n<512);
    REJECT(wifi_shield_format_armed(out,(size_t)n,&s));
    assert(wifi_shield_format_armed(out,(size_t)n+1,&s)==n);
    s.channels[63]=255; s.current_channel=255;
    n=wifi_shield_format_status(out,sizeof(out),&s); assert(n>0&&n<512);
}

static void all_event_types(void)
{
    static const struct { wifi_shield_source_t source; wifi_shield_severity_t severity;
        const char *expected; } fixtures[] = {
        {WIFI_SHIELD_SOURCE_DEAUTH,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=deauth TYPE=deauth BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_DEAUTH,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=deauth TYPE=disassoc BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_DEAUTH,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=deauth TYPE=csa BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_WPS,WIFI_SHIELD_SEVERITY_INFO,"[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=info COUNT=1 WINDOW_MS=10000 MESSAGE=unknown\r\n"},
        {WIFI_SHIELD_SOURCE_WPS,WIFI_SHIELD_SEVERITY_WARN,"[SHIELD/1] ALERT SOURCE=wps TYPE=retry_burst BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=warn COUNT=1 WINDOW_MS=10000 MESSAGE=unknown\r\n"},
        {WIFI_SHIELD_SOURCE_WPS,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=wps TYPE=protocol_anomaly BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000 MESSAGE=unknown\r\n"},
        {WIFI_SHIELD_SOURCE_SAE,WIFI_SHIELD_SEVERITY_INFO,"[SHIELD/1] EVENT SOURCE=sae TYPE=authentication_activity BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=info COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_SAE,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=sae TYPE=protocol_anomaly BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_TRUST,WIFI_SHIELD_SEVERITY_ALERT,"[SHIELD/1] ALERT SOURCE=trust TYPE=security_drift BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=alert COUNT=1 WINDOW_MS=10000\r\n"},
        {WIFI_SHIELD_SOURCE_PMKID,WIFI_SHIELD_SEVERITY_INFO,"[SHIELD/1] EVENT SOURCE=pmkid TYPE=sequence BSSID=aa:bb:cc:dd:ee:ff CH=4 SEVERITY=info COUNT=1 WINDOW_MS=10000\r\n"}
    };
    for(size_t i=0;i<sizeof(fixtures)/sizeof(*fixtures);++i) {
        wifi_shield_event_t e=event_fixture(); e.type=(wifi_shield_event_type_t)i;
        e.source=fixtures[i].source; e.severity=fixtures[i].severity;
        exact(wifi_shield_format_event(out,sizeof(out),&e),fixtures[i].expected);
        for(int source=-1;source<=5;++source) {
            e.source=(wifi_shield_source_t)source;
            if(e.source!=fixtures[i].source) REJECT(wifi_shield_format_event(out,sizeof(out),&e));
        }
        e.source=fixtures[i].source;
        for(int severity=-1;severity<=3;++severity) {
            e.severity=(wifi_shield_severity_t)severity;
            if(e.severity!=fixtures[i].severity) REJECT(wifi_shield_format_event(out,sizeof(out),&e));
        }
        e.severity=fixtures[i].severity;
        if(e.source==WIFI_SHIELD_SOURCE_DEAUTH||e.source==WIFI_SHIELD_SOURCE_TRUST) {
            memset(e.station,255,6);
            exact(wifi_shield_format_event(out,sizeof(out),&e),fixtures[i].expected);
        }
    }
}


static void v2_records(void)
{
    _Static_assert(WIFI_SHIELD_V2_LINE_MAX == WIFI_SHIELD_LINE_MAX,
                   "public V2 UART bound must match the actual publisher");
    memset(out,0,sizeof(out));
    wifi_shield_campaign_snapshot_t c={.id=4,.bssid={0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        .first_us=100,.last_us=200,.sources=3,.threat=WIFI_SHIELD_THREAT_CRITICAL,
        .session_peak=WIFI_SHIELD_THREAT_CRITICAL,.completed_campaigns=2,
        .confidence=WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED,.active=true,
        .last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR,
        .rx_drops=2,.event_drops=1,.output_failures=3,.sampled=true};
    exact(wifi_shield_format_campaign_report(out,sizeof(out),&c),
        "[SHIELD/2] CAMPAIGN ID=4 BSSID=aa:bb:cc:dd:ee:ff ACTIVE=1 THREAT=critical SESSION_PEAK=critical COMPLETED=2 REASON=cross_vector SOURCES=3 FIRST_US=100 LAST_US=200 CONFIDENCE=limited SAMPLED=1 RX_DROPS=2 EVENT_DROPS=1 OUTPUT_FAILURES=3 JOURNAL_DROPS=0\r\n");
    wifi_shield_ap_health_snapshot_t a={.beacons=2,.sequence_gaps=1,
        .epoch_changes=1,.channel_changes=0,.csa_events=2,
        .rssi_average=-60,.rssi_min=-70,.rssi_max=-50,.jitter_average_us=5,.jitter_max_us=10,
        .continuity_confidence=WIFI_SHIELD_AP_CONFIDENCE_OBSERVED,
        .timing_confidence=WIFI_SHIELD_AP_CONFIDENCE_LIMITED,
        .recommendations=WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF|WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
        .recommendation_count=2,
        .recommendation_details={{WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
            WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,WIFI_SHIELD_AP_CONFIDENCE_OBSERVED},
            {WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF,
            WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,WIFI_SHIELD_AP_CONFIDENCE_OBSERVED}}};
    exact(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a),
        "[SHIELD/2] AP_HEALTH BSSID=aa:bb:cc:dd:ee:ff BEACONS=2 SEQ_GAPS=1 EPOCH_CHANGES=1 CHANNEL_CHANGES=0 CSA_EVENTS=2 RSSI_AVG=-60 RSSI_MIN=-70 RSSI_MAX=-50 JITTER_AVG_US=5 JITTER_MAX_US=10 CONTINUITY=observed TIMING=limited SAMPLED=0 RX_DROPS=0 EVENT_DROPS=0 JOURNAL_DROPS=0 RECOMMENDATIONS=2\r\n");
    exact(wifi_shield_format_recommendation(out,sizeof(out),c.bssid,
          &a.recommendation_details[0]),
        "[SHIELD/2] RECOMMENDATION BSSID=aa:bb:cc:dd:ee:ff ACTION=disable_wps EVIDENCE=wps_advertised CONFIDENCE=observed\r\n");
    exact(wifi_shield_format_recommendation(out,sizeof(out),c.bssid,
          &a.recommendation_details[1]),
        "[SHIELD/2] RECOMMENDATION BSSID=aa:bb:cc:dd:ee:ff ACTION=require_pmf EVIDENCE=pmf_not_required CONFIDENCE=observed\r\n");
    wifi_shield_journal_status_t j={.state=WIFI_SHIELD_JOURNAL_ACTIVE,
        .bytes_written=123,.records_written=2,.queue_high_water=3,
        .time_sources=WIFI_SHIELD_JOURNAL_TIME_MONOTONIC|
            WIFI_SHIELD_JOURNAL_TIME_AP_TSF,
        .path="/sdcard/lab/shield/shield-b89abcdef-s3.jsonl.part"};
    exact(wifi_shield_format_log_status(out,sizeof(out),&j),
        "[SHIELD/2] LOG STATE=active PATH=/sdcard/lab/shield/shield-b89abcdef-s3.jsonl.part BYTES=123 RECORDS=2 QUEUE_HIGH=3 DROPS=0 FAILURES=0 ADMISSION_DROPS=0 ENCODING_FAILURES=0 WRITE_FAILURES=0 SYNC_FAILURES=0 FINALIZATION_FAILURES=0 TIME=monotonic+ap_tsf\r\n");
    j.state=WIFI_SHIELD_JOURNAL_DEGRADED; j.failures=1; j.degraded_notice_pending=true;
    j.write_failures=1;
    exact(wifi_shield_format_storage_degraded(out,sizeof(out),&j),
        "[SHIELD/2] STORAGE STATE=degraded PATH=/sdcard/lab/shield/shield-b89abcdef-s3.jsonl.part BYTES=123 RECORDS=2 QUEUE_HIGH=3 DROPS=0 FAILURES=1 ADMISSION_DROPS=0 ENCODING_FAILURES=0 WRITE_FAILURES=1 SYNC_FAILURES=0 FINALIZATION_FAILURES=0 TIME=monotonic+ap_tsf\r\n");
    /* Formatter is pure. The owning worker acknowledges the one-shot notice. */
    j.degraded_notice_pending=false;
    memset(out,0xa5,sizeof(out)); memcpy(before,out,sizeof(out));
    assert(wifi_shield_format_storage_degraded(out,sizeof(out),&j)==0);
    assert(memcmp(out,before,sizeof(out))==0);
}
static void v2_validation_and_bounds(void)
{
    wifi_shield_campaign_snapshot_t c={.id=1,.bssid={2,3,4,5,6,7},
        .first_us=1,.last_us=2,.sources=1,.threat=WIFI_SHIELD_THREAT_WATCH,
        .session_peak=WIFI_SHIELD_THREAT_WATCH,
        .last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY};
    wifi_shield_ap_health_snapshot_t a={0};
    wifi_shield_journal_status_t j={.state=WIFI_SHIELD_JOURNAL_DEGRADED,
        .time_sources=WIFI_SHIELD_JOURNAL_TIME_MONOTONIC,
        .degraded_notice_pending=true};
    int n=wifi_shield_format_campaign_report(out,sizeof(out),&c); assert(n>0);
    REJECT(wifi_shield_format_campaign_report(out,(size_t)n,&c));
    assert(wifi_shield_format_campaign_report(out,(size_t)n+1,&c)==n);
    n=wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a); assert(n>0);
    REJECT(wifi_shield_format_ap_health(out,(size_t)n,c.bssid,&a));
    assert(wifi_shield_format_ap_health(out,(size_t)n+1,c.bssid,&a)==n);
    n=wifi_shield_format_log_status(out,sizeof(out),&j); assert(n>0);
    REJECT(wifi_shield_format_log_status(out,(size_t)n,&j));
    assert(wifi_shield_format_log_status(out,(size_t)n+1,&j)==n);
    n=wifi_shield_format_storage_degraded(out,sizeof(out),&j); assert(n>0);
    REJECT(wifi_shield_format_storage_degraded(out,(size_t)n,&j));
    assert(wifi_shield_format_storage_degraded(out,(size_t)n+1,&j)==n);
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),NULL));
    REJECT(wifi_shield_format_ap_health(out,sizeof(out),NULL,&a));
    REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,NULL));
    REJECT(wifi_shield_format_log_status(out,sizeof(out),NULL));
    REJECT(wifi_shield_format_storage_degraded(out,sizeof(out),NULL));
    assert(wifi_shield_format_campaign_report(NULL,512,&c)<0);
    assert(wifi_shield_format_ap_health(NULL,512,c.bssid,&a)<0);
    assert(wifi_shield_format_log_status(NULL,512,&j)<0);
    assert(wifi_shield_format_storage_degraded(NULL,512,&j)<0);
    c.id=0; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c)); c.id=1;
    c.bssid[0]=1; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a)); c.bssid[0]=2;
    c.threat=(wifi_shield_threat_t)4; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c)); c.threat=WIFI_SHIELD_THREAT_WATCH;
    c.last_transition_reason=(wifi_shield_campaign_reason_t)99;
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    c.last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY;
    c.threat=WIFI_SHIELD_THREAT_ATTACK;
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    c.last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT;
    c.session_peak=WIFI_SHIELD_THREAT_ATTACK;
    assert(wifi_shield_format_campaign_report(out,sizeof(out),&c)>0);
    c.threat=WIFI_SHIELD_THREAT_CRITICAL;
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    c.last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR;
    c.session_peak=WIFI_SHIELD_THREAT_CRITICAL;
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    c.sources=3U;
    assert(wifi_shield_format_campaign_report(out,sizeof(out),&c)>0);
    c.session_peak=(wifi_shield_threat_t)4;
    REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c));
    c.session_peak=WIFI_SHIELD_THREAT_CRITICAL;
    c.threat=WIFI_SHIELD_THREAT_WATCH;
    c.last_transition_reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY;
    c.sources=1U;
    c.confidence=(wifi_shield_campaign_confidence_t)-1; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c)); c.confidence=WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL;
    c.sources=32; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c)); c.sources=1;
    c.first_us=3; REJECT(wifi_shield_format_campaign_report(out,sizeof(out),&c)); c.first_us=1;
    a.continuity_confidence=(wifi_shield_ap_confidence_t)3;
    REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a)); a.continuity_confidence=WIFI_SHIELD_AP_CONFIDENCE_NONE;
    a.recommendations=1024; REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a)); a.recommendations=0;
    a.recommendation_count=1U;
    a.recommendation_details[0]=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
        WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a));
    memset(&a.recommendation_details,0,sizeof(a.recommendation_details));
    a.recommendation_count=0U;
    wifi_shield_ap_recommendation_detail_t d={WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
        WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    assert(wifi_shield_format_recommendation(out,sizeof(out),c.bssid,&d)>0);
    d.action |= WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF;
    REJECT(wifi_shield_format_recommendation(out,sizeof(out),c.bssid,&d));
    a.rssi_min=1; REJECT(wifi_shield_format_ap_health(out,sizeof(out),c.bssid,&a)); a.rssi_min=0;
    j.state=(wifi_shield_journal_state_t)6; REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    j.state=WIFI_SHIELD_JOURNAL_ACTIVE; j.time_sources=UINT32_C(0x80);
    REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    j.time_sources=0U;
    j.state=WIFI_SHIELD_JOURNAL_ACTIVE; strcpy(j.path,"-");
    REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    strcpy(j.path,"/sdcard/lab/shield/x.part");
    REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    j.time_sources=WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    assert(wifi_shield_format_log_status(out,sizeof(out),&j)>0);
    j.state=WIFI_SHIELD_JOURNAL_ACTIVE; REJECT(wifi_shield_format_storage_degraded(out,sizeof(out),&j));
    strcpy(j.path,"x\r\ny"); REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    strcpy(j.path,"x y"); REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    memset(j.path,'x',sizeof(j.path)); REJECT(wifi_shield_format_log_status(out,sizeof(out),&j));
    memset(j.path,'x',sizeof(j.path)-1); j.path[sizeof(j.path)-1]=0;
    j.bytes_written=UINT64_MAX;
    j.records_written=j.failures=j.dropped=j.queue_high_water=
        j.admission_drops=j.encoding_failures=j.write_failures=
        j.sync_failures=j.finalization_failures=UINT32_MAX;
    j.time_sources=WIFI_SHIELD_JOURNAL_TIME_MASK;
    n=wifi_shield_format_log_status(out,sizeof(out),&j);
    assert(n>0 && n<(int)WIFI_SHIELD_LINE_MAX);
    char maximum[WIFI_SHIELD_V2_LINE_MAX];
    a.beacons=a.sequence_gaps=a.rx_drops=a.event_drops=a.journal_drops=UINT32_MAX;
    a.jitter_average_us=a.jitter_max_us=UINT64_MAX;
    n=wifi_shield_format_ap_health(maximum,sizeof(maximum),c.bssid,&a); assert(n>0);
    assert(n < (int)WIFI_SHIELD_LINE_MAX);
    char uart_line[WIFI_SHIELD_LINE_MAX];
    assert(wifi_shield_format_ap_health(uart_line,sizeof(uart_line),c.bssid,&a)==n);
    assert(strstr(maximum,"RECOMMENDATIONS=0\r\n")!=NULL);
    assert(memchr(maximum,'\n',(size_t)n-1)==NULL);
}

int main(void)
{
    records(); target_records_escape_untrusted_ssid();
    outcomes_and_messages(); validation(); bounds(); all_event_types();
    v2_records(); v2_validation_and_bounds();
    puts("wifi shield wire: PASS"); return 0;
}
