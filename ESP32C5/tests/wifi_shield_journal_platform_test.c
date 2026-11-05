#include "wifi_shield_journal_platform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* No allocator is available to the portable platform or the real store. */
void *__wrap_malloc(size_t n) { (void)n; assert(!"heap forbidden"); return NULL; }
void *__wrap_calloc(size_t n, size_t s) { (void)n; (void)s; assert(!"heap forbidden"); return NULL; }
void *__wrap_realloc(void *p, size_t n) { (void)p; (void)n; assert(!"heap forbidden"); return NULL; }
void __wrap_free(void *p) { (void)p; assert(!"heap forbidden"); }

typedef struct {
    wifi_shield_journal_platform_t platform;
    wifi_shield_journal_record_t queue[2];
    unsigned head, count, locks, sends, mounts, writes, flushes, file_syncs;
    unsigned sd_syncs, closes, joins;
    unsigned stack[4096];
    bool writer, task, fail_task, fail_mount, fail_write, fail_close, fail_join;
    bool fail_summary_write, fail_latest_rename;
    bool json_renamed, summary_renamed, latest_renamed;
    bool gps_valid;
    uint64_t gps_epoch;
    uint32_t gps_uncertainty;
    void (*entry)(void *);
    void *argument;
    char bytes[8192];
    size_t length;
    char opened_paths[4][WIFI_SHIELD_JOURNAL_PATH_MAX];
    unsigned opened_count;
} fixture_t;
static void lock(void *v) { fixture_t *f=v; assert(f->locks++==0); }
static void unlock(void *v) { fixture_t *f=v; assert(f->locks--==1); }
static bool send_record(void *v, const wifi_shield_journal_record_t *r) {
    fixture_t *f=v; assert(f->locks==1); ++f->sends;
    if(f->count==2) return false;
    f->queue[(f->head+f->count++)%2]=*r; return true;
}
static bool receive_record(void *v, wifi_shield_journal_record_t *r) {
    fixture_t *f=v; assert(f->writer);
    if(!f->count) return false;
    *r=f->queue[f->head]; f->head=(f->head+1)%2; --f->count; return true;
}
static bool task_start(void *v, void (*entry)(void *), void *arg, void *stack, size_t bytes) {
    fixture_t *f=v; assert(stack==f->stack && bytes==sizeof(f->stack));
    f->entry=entry; f->argument=arg; f->task=!f->fail_task; return f->task;
}
static void wake(void *v) { (void)v; }
static void wait_writer(void *v) { fixture_t *f=v; assert(f->writer); }
static bool join(void *v, uint32_t timeout) {
    fixture_t *f=v; assert(timeout==99); ++f->joins;
    if(f->fail_join) return false;
    f->writer=true; f->entry(f->argument); f->writer=false; f->task=false; return true;
}
static bool gps(void *v, uint64_t *epoch, uint32_t *uncertainty) {
    fixture_t *f=v; *epoch=f->gps_epoch; *uncertainty=f->gps_uncertainty;
    return f->gps_valid;
}
static void io_context(fixture_t *f) { assert(f->writer && f->locks==0); }
static bool mount_fs(void *v) { fixture_t *f=v; io_context(f); ++f->mounts; return !f->fail_mount; }
static bool mkdir_fs(void *v,const char *p) { fixture_t *f=v; io_context(f); assert(strstr(p,"/shield")); return true; }
static void *open_fs(void *v,const char *p) {
    fixture_t *f=v; io_context(f); assert(strstr(p,".part"));
    assert(f->opened_count < 4U && strlen(p) < sizeof(f->opened_paths[0]));
    strcpy(f->opened_paths[f->opened_count++], p); return f;
}
static size_t write_fs(void *v,void *h,const char *b,size_t n) {
    fixture_t *f=v; io_context(f); assert(h==f); ++f->writes;
    const char *path=f->opened_count ? f->opened_paths[f->opened_count-1U] : "";
    if(f->fail_write || (f->fail_summary_write && strstr(path,"-summary.txt.part")))
        return 0;
    assert(f->length+n<sizeof(f->bytes)); memcpy(f->bytes+f->length,b,n); f->length+=n; return n;
}
static bool flush_fs(void *v,void *h) { fixture_t *f=v; io_context(f); assert(h==f); ++f->flushes; return true; }
static bool file_sync_fs(void *v,void *h) { fixture_t *f=v; io_context(f); assert(h==f); ++f->file_syncs; return true; }
static bool close_fs(void *v,void *h) { fixture_t *f=v; io_context(f); assert(h==f); ++f->closes; return !f->fail_close; }
static bool sync_fs(void *v) { fixture_t *f=v; io_context(f); ++f->sd_syncs; return true; }
static bool rename_fs(void *v,const char *a,const char *b) {
    fixture_t *f=v; io_context(f); assert(strstr(a,".part") &&
        (strstr(b,".jsonl") || strstr(b,"-summary.txt")));
    if(strstr(b,".jsonl")) f->json_renamed=true;
    if(strstr(b,"-summary.txt")) f->summary_renamed=true;
    return true;
}
static void *open_replace_fs(void *v,const char *p) { return open_fs(v,p); }
static bool rename_replace_fs(void *v,const char *a,const char *b) {
    fixture_t *f=v; io_context(f); assert(strstr(a,"00-LATEST.txt.part") &&
                          strstr(b,"00-LATEST.txt"));
    if(f->fail_latest_rename) return false;
    f->latest_renamed=true; return true;
}
static bool start_metadata(fixture_t *f,
                           const wifi_shield_summary_metadata_t *metadata) {
    wifi_shield_journal_platform_hooks_t h={f,lock,unlock,send_record,receive_record,
        task_start,wake,wait_writer,join,gps};
    wifi_shield_journal_store_hooks_t s={f,mount_fs,mkdir_fs,open_fs,write_fs,
        flush_fs,file_sync_fs,close_fs,sync_fs,rename_fs,open_replace_fs,
        rename_replace_fs};
    return wifi_shield_journal_platform_start(&f->platform,&h,&s,metadata,
        1,42,8192,
        f->queue,2,f->stack,sizeof(f->stack));
}
static bool start(fixture_t *f) { return start_metadata(f,NULL); }
static bool opened(const fixture_t *f, const char *path) {
    for (unsigned i=0U; i<f->opened_count; ++i)
        if(strcmp(f->opened_paths[i],path)==0) return true;
    return false;
}
static wifi_shield_journal_record_t record(wifi_shield_journal_type_t type) {
    wifi_shield_journal_record_t r={0}; r.type=type; r.target_count=1;
    r.event_source=WIFI_SHIELD_SOURCE_DEAUTH; r.event_type=WIFI_SHIELD_EVENT_DEAUTH;
    r.boot_id=999; r.session_id=999; r.sequence=999;
    r.gps_time_trusted=true; r.epoch_ms=111; r.time_uncertainty_ms=222; return r;
}
static void poll_writer(fixture_t *f) {
    assert(f->task); f->writer=true;
    assert(wifi_shield_journal_platform_writer_poll(&f->platform)); f->writer=false;
}
static void copied_nonblocking_fifo(void) {
    fixture_t f={0}; assert(start(&f)); assert(f.mounts==0);
    f.gps_valid=true; f.gps_epoch=0U; f.gps_uncertainty=99U;
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(!f.queue[0].gps_time_trusted && f.queue[0].epoch_ms==0 &&
           f.queue[0].time_uncertainty_ms==0);
    memset(&r,0xff,sizeof(r));
    r=record(WIFI_SHIELD_JOURNAL_EVENT); f.gps_valid=true; f.gps_epoch=123456;
    f.gps_uncertainty=37U;
    r.time.quality=WIFI_SHIELD_TIME_EXACT; r.time.ap_epoch=1U;
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    wifi_shield_journal_record_t aggregate=r;
    aggregate.event_count=17U; aggregate.has_bssid=true;
    aggregate.bssid[0]=2U; aggregate.event_first_boot_us=100U;
    aggregate.event_last_boot_us=200U; aggregate.time.boot_us=200U;
    assert(!wifi_shield_journal_platform_submit(&f.platform,&aggregate));
    assert(f.writes==0 && f.mounts==0 && f.joins==0 && f.sends==3);
    wifi_shield_journal_status_t status =
        wifi_shield_journal_platform_status(&f.platform);
    assert(status.dropped==17 && status.admission_drops==17 &&
           status.queue_high_water==2 &&
           status.time_sources==(WIFI_SHIELD_JOURNAL_TIME_MONOTONIC|
                                WIFI_SHIELD_JOURNAL_TIME_AP_TSF|
                                WIFI_SHIELD_JOURNAL_TIME_GPS));
    assert(!wifi_shield_journal_platform_drain(&f.platform));
    poll_writer(&f); poll_writer(&f);
    assert(wifi_shield_journal_platform_drain(&f.platform));
    assert(strstr(f.bytes,"\"boot_id\":\"00000001\",\"session_id\":42,\"sequence\":1"));
    char *event=strstr(f.bytes,"\"sequence\":2"); assert(event);
    assert(strstr(event,"\"epoch_ms\":123456,\"time_source\":\"gps\","));
    assert(strstr(event,"\"time_uncertainty_ms\":37"));
    assert(!strstr(f.bytes,"111") && !strstr(f.bytes,"222"));
    r=record(WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_finish(&f.platform,true,99));
    assert(!f.task && f.closes==1 && f.count==0);
    assert(strstr(f.bytes,"\"sequence\":3"));
    assert(!wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_status(&f.platform).state==WIFI_SHIELD_JOURNAL_FINALIZED);
    assert(wifi_shield_journal_platform_finish(&f.platform,true,99)); assert(f.joins==1);
}
static void safe_failures(void) {
    fixture_t f={0}; wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(!wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_drain(&f.platform));
    assert(wifi_shield_journal_platform_finish(&f.platform,false,99));
    assert(wifi_shield_journal_platform_status(&f.platform).state==WIFI_SHIELD_JOURNAL_UNAVAILABLE);
    f.fail_task=true; assert(!start(&f));
    assert(!wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_finish(&f.platform,false,99)); assert(f.mounts==0);
    memset(&f,0,sizeof(f)); f.fail_mount=true; assert(start(&f));
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_finish(&f.platform,true,99));
    assert(f.mounts==1 && f.writes==0 && !f.task);
    assert(wifi_shield_journal_platform_status(&f.platform).dropped==1);
}
static void degraded_and_join_retention(void) {
    fixture_t f={0}; assert(start(&f));
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    f.fail_write=true; r=record(WIFI_SHIELD_JOURNAL_EVENT);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    wifi_shield_journal_status_t s=wifi_shield_journal_platform_status(&f.platform);
    assert(s.state==WIFI_SHIELD_JOURNAL_DEGRADED && s.degraded_notice_pending &&
           s.failures==1 && s.write_failures==1);
    wifi_shield_journal_platform_acknowledge_degraded(&f.platform);
    assert(!wifi_shield_journal_platform_status(&f.platform).degraded_notice_pending);
    assert(!wifi_shield_journal_platform_submit(&f.platform,&r));
    f.fail_close=true; f.fail_join=true;
    assert(!wifi_shield_journal_platform_finish(&f.platform,true,99));
    assert(f.task && f.closes==0);
    assert(!wifi_shield_journal_platform_submit(&f.platform,&r));
    f.fail_join=false; assert(wifi_shield_journal_platform_finish(&f.platform,true,99));
    s=wifi_shield_journal_platform_status(&f.platform);
    assert(!f.task && f.closes==1 && f.mounts==1 && s.failures==2 && s.dropped==3);
    assert(!s.degraded_notice_pending);
    assert(!start(&f)); /* Same accepted session must never retry the store. */
    assert(f.mounts==1);
}
static void encoding_failure_is_distinct_and_fail_open(void) {
    fixture_t f={0}; assert(start(&f));
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    r=record(WIFI_SHIELD_JOURNAL_EVENT);
    r.event_source=WIFI_SHIELD_SOURCE_WPS; /* Invalid for DEAUTH event. */
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    wifi_shield_journal_status_t s=wifi_shield_journal_platform_status(&f.platform);
    assert(s.state==WIFI_SHIELD_JOURNAL_ACTIVE && s.encoding_failures==1U &&
           s.dropped==1U && s.failures==1U && s.write_failures==0U);
}
static void uncertainty_checkpoint_precedes_drain(void) {
    fixture_t f={0}; assert(start(&f));
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    r=record(WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN);
    r.outcome=WIFI_SHIELD_JOURNAL_RESTORE_FAILED;
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(!wifi_shield_journal_platform_drain(&f.platform));
    poll_writer(&f);
    assert(wifi_shield_journal_platform_drain(&f.platform));
    assert(f.flushes==1 && f.file_syncs==1 && f.sd_syncs==1 && f.closes==0);
    r=record(WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_finish(&f.platform,true,99));
    assert(f.flushes==2 && f.file_syncs==2 && f.sd_syncs==3 && f.closes==1);
    assert(wifi_shield_journal_platform_status(&f.platform).state==
           WIFI_SHIELD_JOURNAL_FINALIZED);
}
static void clean_finish_writes_human_summary_and_latest_pointer(void) {
    fixture_t f={0};
    wifi_shield_summary_metadata_t metadata={0};
    metadata.target_count=1U; metadata.primary_target_valid=true;
    memcpy(metadata.primary_bssid,"\xb0\xbe\x76\x70\x0e\x90",6U);
    metadata.primary_channel=4U;
    strcpy(metadata.primary_ssid,"TP-Link_0E90");
    metadata.protect_all=true; metadata.active_defence=true;
    metadata.pmkid_decoy=true; metadata.multi_vector=true;
    assert(start_metadata(&f,&metadata));
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    r.time.boot_us=UINT64_C(1000000);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    r=record(WIFI_SHIELD_JOURNAL_EVENT);
    r.time.boot_us=UINT64_C(1900000);
    r.has_bssid=true;
    memcpy(r.bssid,"\xb0\xbe\x76\x70\x0e\x90",6U);
    r.event_count=304U;
    r.event_first_boot_us=UINT64_C(1000000);
    r.event_last_boot_us=UINT64_C(1900000);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r)); poll_writer(&f);
    r=record(WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    r.time.boot_us=UINT64_C(7000000);
    assert(wifi_shield_journal_platform_submit(&f.platform,&r));
    assert(wifi_shield_journal_platform_finish(&f.platform,true,99));

    assert(opened(&f,"/sdcard/lab/shield/shield-b00000001-s42-summary.txt.part"));
    assert(opened(&f,"/sdcard/lab/shield/00-LATEST.txt.part"));
    assert(strstr(f.bytes,"JanOS Wi-Fi Shield - Session Summary\n")!=NULL);
    assert(strstr(f.bytes,"Deauth: 304\n")!=NULL);
    assert(strstr(f.bytes,"shield-b00000001-s42-summary.txt")!=NULL);
}

static void summary_uses_only_primary_target_health(void) {
    wifi_shield_summary_metadata_t metadata={0};
    metadata.target_count=2U; metadata.primary_target_valid=true;
    memcpy(metadata.primary_bssid,"\x02\x11\x22\x33\x44\x55",6U);
    metadata.primary_channel=4U; strcpy(metadata.primary_ssid,"primary");
    wifi_shield_summary_t summary;
    assert(wifi_shield_summary_init(&summary,&metadata,1U,42U));
    wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
    r.boot_id=1U; r.session_id=42U; r.time.boot_us=1U;
    wifi_shield_summary_observe(&summary,&r);
    r=record(WIFI_SHIELD_JOURNAL_AP_HEALTH); r.boot_id=1U; r.session_id=42U;
    r.has_bssid=true; memcpy(r.bssid,metadata.primary_bssid,6U);
    r.ap_health.recommendations=WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS;
    r.ap_health.recommendation_count=1U;
    r.ap_health.recommendation_details[0]=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
        WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    wifi_shield_summary_observe(&summary,&r);
    const uint8_t other[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    memcpy(r.bssid,other,6U);
    r.ap_health.recommendations=WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF;
    r.ap_health.recommendation_details[0]=(wifi_shield_ap_recommendation_detail_t){
        WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF,
        WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED};
    wifi_shield_summary_observe(&summary,&r);
    r=record(WIFI_SHIELD_JOURNAL_SESSION_TERMINAL); r.boot_id=1U;
    r.session_id=42U; r.time.boot_us=2U;
    wifi_shield_summary_observe(&summary,&r);
    wifi_shield_journal_status_t status={.state=WIFI_SHIELD_JOURNAL_FINALIZED};
    char text[WIFI_SHIELD_SUMMARY_TEXT_MAX];
    assert(wifi_shield_summary_format(text,sizeof(text),&summary,&status,
                                     "/sdcard/lab/shield/test.jsonl")>0);
    assert(strstr(text,"disable_wps")!=NULL);
    assert(strstr(text,"require_pmf")==NULL);
}

static void sidecar_failures_keep_jsonl_finalized(void) {
    wifi_shield_summary_metadata_t metadata={0};
    metadata.target_count=1U; metadata.primary_target_valid=true;
    metadata.primary_bssid[0]=2U;
    for(unsigned latest=0U; latest<2U; ++latest) {
        fixture_t f={0};
        f.fail_summary_write=latest==0U;
        f.fail_latest_rename=latest!=0U;
        assert(start_metadata(&f,&metadata));
        wifi_shield_journal_record_t r=record(WIFI_SHIELD_JOURNAL_SESSION_START);
        r.time.boot_us=1U;
        assert(wifi_shield_journal_platform_submit(&f.platform,&r));
        poll_writer(&f);
        r=record(WIFI_SHIELD_JOURNAL_SESSION_TERMINAL); r.time.boot_us=2U;
        assert(wifi_shield_journal_platform_submit(&f.platform,&r));
        assert(wifi_shield_journal_platform_finish(&f.platform,true,99));
        wifi_shield_journal_status_t status=
            wifi_shield_journal_platform_status(&f.platform);
        assert(status.state==WIFI_SHIELD_JOURNAL_FINALIZED && f.json_renamed);
        if(latest==0U) {
            assert(status.summary_failures==1U && status.latest_failures==0U);
            assert(!f.summary_renamed && !f.latest_renamed);
        } else {
            assert(status.summary_failures==0U && status.latest_failures==1U);
            assert(f.summary_renamed && !f.latest_renamed);
        }
        assert(status.failures==1U);
    }
}
int main(void) {
    copied_nonblocking_fifo(); safe_failures(); degraded_and_join_retention();
    encoding_failure_is_distinct_and_fail_open();
    uncertainty_checkpoint_precedes_drain();
    clean_finish_writes_human_summary_and_latest_pointer();
    summary_uses_only_primary_target_health();
    sidecar_failures_keep_jsonl_finalized();
    puts("wifi shield journal platform: PASS"); return 0;
}
