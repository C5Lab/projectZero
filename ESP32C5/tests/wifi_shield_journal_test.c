#include "wifi_shield_journal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static char line[WIFI_SHIELD_JOURNAL_LINE_MAX + 16], saved[sizeof(line)];
void *__wrap_malloc(size_t n) { (void)n; assert(0); return NULL; }
void *__wrap_calloc(size_t n, size_t s) { (void)n; (void)s; assert(0); return NULL; }
void *__wrap_realloc(void *p, size_t n) { (void)p; (void)n; assert(0); return NULL; }
void __wrap_free(void *p) { (void)p; assert(0); }
#define BASE(type) "{\"schema\":1,\"type\":\"" type "\",\"boot_id\":\"89abcdef\",\"session_id\":3,\"sequence\":9,\"boot_us\":1200"
#define REJECT(call) do { memset(line, 0xa5, sizeof(line)); memcpy(saved,line,sizeof(line)); \
    assert((call)<0); assert(memcmp(line,saved,sizeof(line))==0); } while(0)

static wifi_shield_journal_record_t record(void)
{
    wifi_shield_journal_record_t r = {0};
    r.type=WIFI_SHIELD_JOURNAL_EVENT; r.boot_id=UINT32_C(0x89abcdef);
    r.session_id=3; r.sequence=9; r.time.boot_us=1200;
    r.event_source=WIFI_SHIELD_SOURCE_WPS; r.event_type=WIFI_SHIELD_EVENT_WPS_ACTIVITY;
    return r;
}
static void no_secrets(void)
{
    const char *keys[]={"\"password\":","\"pin\":","\"pmk\":","\"nonce\":","\"mic_key\":","\"raw_frame\":"};
    for(size_t i=0;i<sizeof(keys)/sizeof(*keys);++i) assert(strstr(line,keys[i])==NULL);
}
static void literal(wifi_shield_journal_record_t *r, const char *expected)
{
    int n=wifi_shield_journal_encode(line,sizeof(line),r);
    if(n<0 || strcmp(line,expected)) fprintf(stderr,"expected: %sactual: %s",expected,n<0?"REJECTED\n":line);
    assert(n==(int)strlen(expected)); assert(strcmp(line,expected)==0);
    assert(line[n-1]=='\n' && memchr(line,'\n',(size_t)n-1)==NULL);
    assert(n<(int)WIFI_SHIELD_JOURNAL_LINE_MAX); no_secrets();
    REJECT(wifi_shield_journal_encode(line,(size_t)n,r));
    assert(wifi_shield_journal_encode(line,(size_t)n+1,r)==n);
    assert(strcmp(line,expected)==0);
}
static void event_and_time(void)
{
    wifi_shield_journal_record_t r=record();
    literal(&r,BASE("event") ",\"source\":\"wps\",\"event\":\"enrollment_activity\"}\n");
    assert(strstr(line,"epoch_ms")==NULL && strstr(line,"ap_tsf_us")==NULL);
    r.epoch_ms=1793798400000ULL; /* Untrusted tuples are invalid, not omitted piecemeal. */
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
    r.epoch_ms=0; r.time_uncertainty_ms=1000U;
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
    r.epoch_ms=1793798400000ULL;
    r.gps_time_trusted=true;
    literal(&r,BASE("event") ",\"epoch_ms\":1793798400000,\"time_source\":\"gps\",\"time_uncertainty_ms\":1000,\"source\":\"wps\",\"event\":\"enrollment_activity\"}\n");
    r.gps_time_trusted=false; r.epoch_ms=0U; r.time_uncertainty_ms=0U;
    r.has_bssid=true;
    const uint8_t b[]={0xaa,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(r.bssid,b,6);
    r.time.quality=WIFI_SHIELD_TIME_EXACT; r.time.ap_epoch=1;
    literal(&r,BASE("event") ",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ap_tsf_us\":0,\"ap_epoch\":1,\"ap_tsf_quality\":\"exact\",\"ap_tsf_uncertainty_us\":0,\"source\":\"wps\",\"event\":\"enrollment_activity\"}\n");
    r.time.quality=WIFI_SHIELD_TIME_ESTIMATED; r.time.ap_tsf_us=500; r.time.uncertainty_us=25;
    literal(&r,BASE("event") ",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ap_tsf_us\":500,\"ap_epoch\":1,\"ap_tsf_quality\":\"estimated\",\"ap_tsf_uncertainty_us\":25,\"source\":\"wps\",\"event\":\"enrollment_activity\"}\n");
}
static void record_types(void)
{
    wifi_shield_journal_record_t r=record();
    r.type=WIFI_SHIELD_JOURNAL_SESSION_START; r.target_count=2;
    literal(&r,BASE("session_start") ",\"targets\":2}\n");
    r.type=WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION; r.has_bssid=true;
    const uint8_t b[]={0xaa,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(r.bssid,b,6);
    r.campaign.id=4; memcpy(r.campaign.bssid,b,6);
    r.campaign.from=WIFI_SHIELD_THREAT_NONE; r.campaign.to=WIFI_SHIELD_THREAT_ATTACK;
    r.campaign.sources=3; r.campaign.confidence=WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
    r.campaign.reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT;
    literal(&r,BASE("campaign_transition") ",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"campaign_id\":4,\"from\":\"quiet\",\"to\":\"attack\",\"reason\":\"isolated_alert\",\"sources\":3,\"confidence\":\"limited\"}\n");
    r.type=WIFI_SHIELD_JOURNAL_AP_HEALTH;
    literal(&r,BASE("ap_health") ",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"beacons\":0,\"sequence_gaps\":0,\"interval_pairs\":0,\"rssi_average\":0,\"rssi_min\":0,\"rssi_max\":0,\"jitter_avg_us\":0,\"jitter_max_us\":0,\"epoch_changes\":0,\"channel_changes\":0,\"csa_events\":0,\"retry_beacons\":0,\"retry_events\":0,\"deauth_events\":0,\"disassoc_events\":0,\"rx_drops\":0,\"event_drops\":0,\"journal_drops\":0,\"sampled\":false,\"same_neighbors\":0,\"overlap_neighbors\":0,\"continuity_conf\":\"none\",\"timing_conf\":\"none\",\"rec_rev\":0,\"recommendation_count\":0}\n");
    r.type=WIFI_SHIELD_JOURNAL_RECOMMENDATION;
    r.recommendation_set_revision=1U;
    r.recommendation_set_index=0U;
    r.recommendation_set_count=1U;
    r.recommendation=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF,
        WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    literal(&r,BASE("recommendation") ",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"rec_rev\":1,\"rec_index\":0,\"rec_count\":1,\"action\":\"require_pmf\",\"evidence\":\"pmf_not_required\",\"confidence\":\"observed\"}\n");
    r.type=WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED; r.has_bssid=false;
    r.storage.state=WIFI_SHIELD_JOURNAL_DEGRADED; r.storage.failures=1;
    r.storage.write_failures=1;
    strcpy(r.storage.path,"/sdcard/lab/shield/test.jsonl.part");
    literal(&r,BASE("storage_degraded") ",\"state\":\"degraded\",\"path\":\"/sdcard/lab/shield/test.jsonl.part\",\"bytes_written\":0,\"records_written\":0,\"failures\":1,\"dropped\":0}\n");
    r.type=WIFI_SHIELD_JOURNAL_SESSION_TERMINAL; r.outcome=WIFI_SHIELD_JOURNAL_STOPPED;
    literal(&r,BASE("session_terminal") ",\"outcome\":\"stopped\"}\n");
    r.type=WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN; r.outcome=WIFI_SHIELD_JOURNAL_RESTORE_FAILED;
    literal(&r,BASE("session_uncertain") ",\"outcome\":\"restore_failed\"}\n");
}
static void escaping_and_limits(void)
{
    wifi_shield_journal_record_t r=record(); r.type=WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED;
    r.storage.state=WIFI_SHIELD_JOURNAL_DEGRADED;
    strcpy(r.storage.path,"a\"b\\c\n\r\t\b\f\001\177");
    literal(&r,BASE("storage_degraded") ",\"state\":\"degraded\",\"path\":\"a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\\u007f\",\"bytes_written\":0,\"records_written\":0,\"failures\":0,\"dropped\":0}\n");
    strcpy(r.storage.path,"{\"password\":\"x\"}");
    literal(&r,BASE("storage_degraded") ",\"state\":\"degraded\",\"path\":\"{\\\"password\\\":\\\"x\\\"}\",\"bytes_written\":0,\"records_written\":0,\"failures\":0,\"dropped\":0}\n");
    memset(r.storage.path,'x',sizeof(r.storage.path)-1); r.storage.path[sizeof(r.storage.path)-1]=0;
    assert(wifi_shield_journal_encode(line,sizeof(line),&r)>0); no_secrets();
    memset(r.storage.path,1,sizeof(r.storage.path)-1);
    assert(wifi_shield_journal_encode(line,sizeof(line),&r)>0); no_secrets();
    memset(r.storage.path,'x',sizeof(r.storage.path));
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
    r=record(); r.has_bssid=true; memset(r.bssid,255,6); r.bssid[0]=254;
    r.type=WIFI_SHIELD_JOURNAL_RECOMMENDATION;
    r.recommendation_set_revision=1U;
    r.recommendation_set_count=1U;
    r.recommendation=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL,
        WIFI_SHIELD_AP_EVIDENCE_RSSI_OBSERVATIONS,
        WIFI_SHIELD_AP_CONFIDENCE_LIMITED};
    assert(wifi_shield_journal_encode(line,sizeof(line),&r)>0); no_secrets();
    assert(strstr(line,"\"action\":\"weak_or_unstable_signal\",\"evidence\":\"rssi_observations\",\"confidence\":\"limited\"")!=NULL);
    r=record(); r.time.boot_us=UINT64_MAX; r.sequence=UINT64_MAX; r.session_id=UINT32_MAX;
    int n=wifi_shield_journal_encode(line,sizeof(line),&r); assert(n>0);
    REJECT(wifi_shield_journal_encode(line,(size_t)n,&r));
    assert(wifi_shield_journal_encode(line,(size_t)n+1,&r)==n);
    REJECT(wifi_shield_journal_encode(line,0,&r));
    assert(wifi_shield_journal_encode(NULL,1024,&r)<0);
    REJECT(wifi_shield_journal_encode(line,sizeof(line),NULL));
}
static void invalid_states(void)
{
    wifi_shield_journal_record_t r=record(), b;
#define BAD(field,value) do { b=r; b.field=(value); REJECT(wifi_shield_journal_encode(line,sizeof(line),&b)); } while(0)
    BAD(type,(wifi_shield_journal_type_t)-1); BAD(type,(wifi_shield_journal_type_t)8);
    BAD(boot_id,0); BAD(session_id,0); BAD(sequence,0);
    BAD(event_source,(wifi_shield_source_t)-1); BAD(event_type,(wifi_shield_event_type_t)10);
    BAD(event_source,WIFI_SHIELD_SOURCE_SAE); BAD(time.quality,(wifi_shield_time_quality_t)3);
    BAD(time.ap_epoch,1); BAD(time.ap_tsf_us,1); BAD(time.uncertainty_us,1);
    r.time.quality=WIFI_SHIELD_TIME_EXACT; BAD(time.ap_epoch,0);
    r.time.ap_epoch=1; BAD(time.uncertainty_us,1);
    r=record(); BAD(epoch_ms,1); BAD(time_uncertainty_ms,1);
    r.gps_time_trusted=true; r.time_uncertainty_ms=1000U; BAD(epoch_ms,0);
    r=record(); r.has_bssid=true; BAD(bssid[0],1); BAD(bssid[0],0);
    r.type=WIFI_SHIELD_JOURNAL_AP_HEALTH;
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
    r.bssid[0]=2; BAD(ap_health.continuity_confidence,(wifi_shield_ap_confidence_t)3);
    BAD(ap_health.timing_confidence,(wifi_shield_ap_confidence_t)-1);
    BAD(ap_health.recommendations,1024); BAD(ap_health.rssi_min,1);
    r.type=WIFI_SHIELD_JOURNAL_RECOMMENDATION;
    r.recommendation_set_revision=1U;
    r.recommendation_set_count=1U;
    r.recommendation=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
        WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    BAD(recommendation.action,0); BAD(recommendation.action,3);
    BAD(recommendation.evidence,WIFI_SHIELD_AP_EVIDENCE_NONE);
    BAD(recommendation.confidence,WIFI_SHIELD_AP_CONFIDENCE_NONE);
    BAD(recommendation_set_revision,0U);
    BAD(recommendation_set_count,0U);
    BAD(recommendation_set_count,WIFI_SHIELD_AP_RECOMMENDATION_MAX + 1U);
    BAD(recommendation_set_index,1U);
    r.type=WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION; BAD(campaign.id,0);
    r.campaign.id=1; memcpy(r.campaign.bssid,r.bssid,6);
    r.campaign.to=WIFI_SHIELD_THREAT_WATCH;
    r.campaign.sources=1;
    r.campaign.reason=WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY;
    BAD(campaign.to,(wifi_shield_threat_t)4); BAD(campaign.from,WIFI_SHIELD_THREAT_ATTACK);
    BAD(campaign.sources,32); BAD(campaign.sources,0); BAD(campaign.bssid[0],4);
    BAD(campaign.confidence,(wifi_shield_campaign_confidence_t)-1);
    BAD(campaign.reason,WIFI_SHIELD_CAMPAIGN_REASON_NONE);
    r.campaign.reason=WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR;
    BAD(campaign.sources,1U);
    r.campaign.sources=3U;
    BAD(campaign.to,WIFI_SHIELD_THREAT_ATTACK);
    r=record(); r.type=WIFI_SHIELD_JOURNAL_SESSION_START; BAD(target_count,0); BAD(target_count,65);
    r.type=WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED; BAD(storage.state,WIFI_SHIELD_JOURNAL_ACTIVE);
    BAD(storage.state,(wifi_shield_journal_state_t)6);
    r.storage.state=WIFI_SHIELD_JOURNAL_DEGRADED; BAD(storage.path[0],(char)0xff);
    r.type=WIFI_SHIELD_JOURNAL_SESSION_TERMINAL; BAD(outcome,(wifi_shield_journal_outcome_t)8);
    r=record(); r.event_source=WIFI_SHIELD_SOURCE_DEAUTH;
    r.event_type=WIFI_SHIELD_EVENT_DEAUTH; r.event_count=2U;
    r.has_bssid=true; r.bssid[0]=2U;
    r.event_first_boot_us=100U;
    r.event_last_boot_us=UINT64_C(1000100);
    r.time.boot_us=r.event_last_boot_us;
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
#undef BAD
}

static void nonzero_health_and_scratch_overflow(void)
{
    wifi_shield_journal_record_t r=record(); r.type=WIFI_SHIELD_JOURNAL_AP_HEALTH;
    r.has_bssid=true; r.bssid[0]=2;
    r.ap_health=(wifi_shield_ap_health_snapshot_t){.beacons=8,.sequence_gaps=3,.interval_pairs=2,
        .rssi_average=-65,.rssi_min=-80,.rssi_max=-50,.jitter_average_us=5,.jitter_max_us=9,
        .epoch_changes=1,.channel_changes=2,.csa_events=3,.retry_beacons=4,.retry_events=5,
        .deauth_events=6,.disassoc_events=7,.rx_drops=8,.event_drops=9,.journal_drops=10,
        .sampled=true,.same_channel_neighbors=11,.overlapping_channel_neighbors=12,
        .continuity_confidence=WIFI_SHIELD_AP_CONFIDENCE_LIMITED,
        .timing_confidence=WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    literal(&r,BASE("ap_health") ",\"bssid\":\"02:00:00:00:00:00\",\"beacons\":8,\"sequence_gaps\":3,\"interval_pairs\":2,\"rssi_average\":-65,\"rssi_min\":-80,\"rssi_max\":-50,\"jitter_avg_us\":5,\"jitter_max_us\":9,\"epoch_changes\":1,\"channel_changes\":2,\"csa_events\":3,\"retry_beacons\":4,\"retry_events\":5,\"deauth_events\":6,\"disassoc_events\":7,\"rx_drops\":8,\"event_drops\":9,\"journal_drops\":10,\"sampled\":true,\"same_neighbors\":11,\"overlap_neighbors\":12,\"continuity_conf\":\"limited\",\"timing_conf\":\"observed\",\"rec_rev\":0,\"recommendation_count\":0}\n");
    r.boot_id=r.session_id=UINT32_MAX; r.sequence=r.time.boot_us=UINT64_MAX;
    r.time.ap_tsf_us=r.time.uncertainty_us=UINT64_MAX; r.time.ap_epoch=UINT32_MAX;
    r.time.quality=WIFI_SHIELD_TIME_ESTIMATED; r.gps_time_trusted=true; r.epoch_ms=UINT64_MAX;
    r.time_uncertainty_ms=UINT32_MAX;
    wifi_shield_ap_health_snapshot_t *a=&r.ap_health;
    a->beacons=a->sequence_gaps=a->interval_pairs=UINT32_MAX;
    a->jitter_average_us=a->jitter_max_us=UINT64_MAX;
    a->epoch_changes=a->channel_changes=a->csa_events=UINT32_MAX;
    a->retry_beacons=a->retry_events=a->deauth_events=a->disassoc_events=UINT32_MAX;
    a->rx_drops=a->event_drops=a->journal_drops=UINT32_MAX;
    a->same_channel_neighbors=a->overlapping_channel_neighbors=UINT32_MAX;
    static const wifi_shield_ap_recommendation_evidence_t evidence[] = {
        WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
        WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,
        WIFI_SHIELD_AP_EVIDENCE_WPA3_NOT_ONLY,
        WIFI_SHIELD_AP_EVIDENCE_TRANSITION_MODE,
        WIFI_SHIELD_AP_EVIDENCE_LEGACY_CIPHER,
        WIFI_SHIELD_AP_EVIDENCE_CHANNEL_CHANGES,
        WIFI_SHIELD_AP_EVIDENCE_OBSERVED_NEIGHBORS,
        WIFI_SHIELD_AP_EVIDENCE_RSSI_OBSERVATIONS,
        WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE,
        WIFI_SHIELD_AP_EVIDENCE_VALIDATED_CATALOG_MATCH,
    };
    a->recommendations = WIFI_SHIELD_JOURNAL_RECOMMENDATION_MASK;
    a->recommendation_count = WIFI_SHIELD_AP_RECOMMENDATION_MAX;
    for (uint8_t i = 0U; i < WIFI_SHIELD_AP_RECOMMENDATION_MAX; ++i) {
        a->recommendation_details[i] =
            (wifi_shield_ap_recommendation_detail_t){
                UINT32_C(1) << i, evidence[i],
                WIFI_SHIELD_AP_CONFIDENCE_LIMITED};
    }
    r.recommendation_set_revision=UINT32_MAX;
    r.recommendation_set_count=WIFI_SHIELD_AP_RECOMMENDATION_MAX;
    int maximum_length=wifi_shield_journal_encode(line,sizeof(line),&r);
    assert(maximum_length==1018 && maximum_length<=1023); no_secrets();
    REJECT(wifi_shield_journal_encode(line,(size_t)maximum_length,&r));
    assert(wifi_shield_journal_encode(line,(size_t)maximum_length+1U,&r)==maximum_length);
    /* All AP scalar maxima still fit. Escaped maximum path + optional clocks
     * actually exceed scratch, independently of caller buffer capacity. */
    r.type=WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED;
    r.storage.state=WIFI_SHIELD_JOURNAL_DEGRADED;
    memset(r.storage.path,1,sizeof(r.storage.path)-1);
    r.storage.path[sizeof(r.storage.path)-1]=0;
    r.storage.bytes_written=UINT64_MAX;
    r.storage.records_written=r.storage.failures=r.storage.dropped=UINT32_MAX;
    REJECT(wifi_shield_journal_encode(line,sizeof(line),&r));
}
static void all_event_names(void)
{
    static const struct {wifi_shield_source_t source; const char *suffix;} cases[]={
        {WIFI_SHIELD_SOURCE_DEAUTH,",\"source\":\"deauth\",\"event\":\"deauth\"}\n"},
        {WIFI_SHIELD_SOURCE_DEAUTH,",\"source\":\"deauth\",\"event\":\"disassoc\"}\n"},
        {WIFI_SHIELD_SOURCE_DEAUTH,",\"source\":\"deauth\",\"event\":\"csa\"}\n"},
        {WIFI_SHIELD_SOURCE_WPS,",\"source\":\"wps\",\"event\":\"enrollment_activity\"}\n"},
        {WIFI_SHIELD_SOURCE_WPS,",\"source\":\"wps\",\"event\":\"retry_burst\"}\n"},
        {WIFI_SHIELD_SOURCE_WPS,",\"source\":\"wps\",\"event\":\"protocol_anomaly\"}\n"},
        {WIFI_SHIELD_SOURCE_SAE,",\"source\":\"sae\",\"event\":\"authentication_activity\"}\n"},
        {WIFI_SHIELD_SOURCE_SAE,",\"source\":\"sae\",\"event\":\"protocol_anomaly\"}\n"},
        {WIFI_SHIELD_SOURCE_TRUST,",\"source\":\"trust\",\"event\":\"security_drift\"}\n"},
        {WIFI_SHIELD_SOURCE_PMKID,",\"source\":\"pmkid\",\"event\":\"sequence\"}\n"}
    };
    for(size_t i=0;i<sizeof(cases)/sizeof(*cases);++i) {
        wifi_shield_journal_record_t r=record(); r.event_type=(wifi_shield_event_type_t)i;
        r.event_source=cases[i].source;
        char expected[256]; int n=snprintf(expected,sizeof(expected),"%s%s",BASE("event"),cases[i].suffix);
        assert(n>0 && (size_t)n<sizeof(expected)); literal(&r,expected);
    }
}

int main(void)
{
    assert(WIFI_SHIELD_JOURNAL_LINE_MAX<=1024);
    event_and_time(); record_types(); escaping_and_limits(); invalid_states();
    nonzero_health_and_scratch_overflow(); all_event_names();
    puts("wifi shield journal: PASS"); return 0;
}
