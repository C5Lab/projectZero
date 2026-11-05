#include "wifi_shield_journal_store.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The fake is a real byte/path store. Faults affect the corresponding operation,
 * never synthesize the core's resulting status or file contents. */
enum fault { NONE, MOUNT, MKDIR, OPEN, WRITE_FAIL, WRITE_SHORT, FLUSH, FILE_SYNC,
             CLOSE, SD_SYNC_FIRST, RENAME, SD_SYNC_FINAL };
typedef struct {
    char path[WIFI_SHIELD_JOURNAL_PATH_MAX];
    char bytes[8192];
    size_t length;
    bool exists, open;
} file_t;
typedef struct {
    file_t files[4];
    char trace[2048];
    enum fault fault;
    unsigned mount_calls, open_calls, write_calls, sync_calls;
    bool mounted, directory;
} filesystem_t;

static const char part[] = "/sdcard/lab/shield/shield-b1234abcd-s42.jsonl.part";
static const char final[] = "/sdcard/lab/shield/shield-b1234abcd-s42.jsonl";
static const char start_line[] = "{\"schema\":1,\"type\":\"session_start\",\"boot_id\":\"1234abcd\",\"session_id\":42,\"sequence\":1,\"boot_us\":0,\"targets\":1}\n";
static const char event_line[] = "{\"schema\":1,\"type\":\"event\",\"boot_id\":\"1234abcd\",\"session_id\":42,\"sequence\":2,\"boot_us\":0,\"source\":\"deauth\",\"event\":\"deauth\"}\n";
static const char terminal_line[] = "{\"schema\":1,\"type\":\"session_terminal\",\"boot_id\":\"1234abcd\",\"session_id\":42,\"sequence\":3,\"boot_us\":0,\"outcome\":\"stopped\"}\n";
static const char uncertain_line[] = "{\"schema\":1,\"type\":\"session_uncertain\",\"boot_id\":\"1234abcd\",\"session_id\":42,\"sequence\":2,\"boot_us\":0,\"outcome\":\"restore_failed\"}\n";

void *__wrap_malloc(size_t n) { (void)n; assert(!"heap forbidden"); return NULL; }
void *__wrap_calloc(size_t n, size_t size) { (void)n; (void)size; assert(!"heap forbidden"); return NULL; }
void *__wrap_realloc(void *p, size_t n) { (void)p; (void)n; assert(!"heap forbidden"); return NULL; }
void __wrap_free(void *p) { (void)p; assert(!"heap forbidden"); }

static void trace(filesystem_t *fs, const char *operation)
{
    assert(strlen(fs->trace) + strlen(operation) + 2 < sizeof(fs->trace));
    if (fs->trace[0]) strcat(fs->trace, ">");
    strcat(fs->trace, operation);
}
static file_t *find(filesystem_t *fs, const char *path)
{
    for (size_t i=0; i<4; ++i)
        if (fs->files[i].exists && strcmp(fs->files[i].path, path)==0) return &fs->files[i];
    return NULL;
}
static bool mount_fs(void *ctx)
{
    filesystem_t *fs=ctx; trace(fs,"mount"); ++fs->mount_calls;
    fs->mounted=fs->fault!=MOUNT; return fs->mounted;
}
static bool mkdir_fs(void *ctx, const char *path)
{
    filesystem_t *fs=ctx; trace(fs,"mkdir");
    assert(fs->mounted && strcmp(path,"/sdcard/lab/shield")==0);
    fs->directory=fs->fault!=MKDIR; return fs->directory;
}
static void *open_fs(void *ctx, const char *path)
{
    filesystem_t *fs=ctx; trace(fs,"open"); ++fs->open_calls;
    assert(fs->directory);
    if (fs->fault==OPEN || find(fs,path)) return NULL;
    for (size_t i=0; i<4; ++i) if (!fs->files[i].exists) {
        file_t *f=&fs->files[i]; f->exists=true; f->open=true;
        assert(strlen(path)<sizeof(f->path)); strcpy(f->path,path); return f;
    }
    return NULL;
}
static size_t write_fs(void *ctx, void *handle, const char *bytes, size_t n)
{
    filesystem_t *fs=ctx; file_t *f=handle; trace(fs,"write"); ++fs->write_calls;
    assert(f->exists && f->open);
    size_t count=fs->fault==WRITE_FAIL ? 0 : (fs->fault==WRITE_SHORT ? n-1 : n);
    assert(f->length+count<sizeof(f->bytes));
    memcpy(f->bytes+f->length,bytes,count); f->length+=count; return count;
}
static bool flush_fs(void *ctx, void *handle)
{
    filesystem_t *fs=ctx; file_t *f=handle; assert(f->open); trace(fs,"flush");
    return fs->fault!=FLUSH;
}
static bool file_sync_fs(void *ctx, void *handle)
{
    filesystem_t *fs=ctx; file_t *f=handle; assert(f->open); trace(fs,"fsync_file");
    return fs->fault!=FILE_SYNC;
}
static bool close_fs(void *ctx, void *handle)
{
    filesystem_t *fs=ctx; file_t *f=handle; assert(f->open); trace(fs,"close");
    f->open=false; return fs->fault!=CLOSE;
}
static bool sync_fs(void *ctx)
{
    filesystem_t *fs=ctx; trace(fs,"sync_sd"); ++fs->sync_calls;
    return !((fs->fault==SD_SYNC_FIRST && fs->sync_calls==1) ||
             (fs->fault==SD_SYNC_FINAL && fs->sync_calls==2));
}
static bool rename_fs(void *ctx, const char *from, const char *to)
{
    filesystem_t *fs=ctx; trace(fs,"rename"); file_t *f=find(fs,from);
    assert(f && !f->open);
    if (fs->fault==RENAME || find(fs,to)) return false;
    assert(strlen(to)<sizeof(f->path)); strcpy(f->path,to); return true;
}
static wifi_shield_journal_store_hooks_t hooks(filesystem_t *fs)
{
    wifi_shield_journal_store_hooks_t h={fs,mount_fs,mkdir_fs,open_fs,write_fs,
        flush_fs,file_sync_fs,close_fs,sync_fs,rename_fs,NULL,NULL}; return h;
}
static void encode_and_append(wifi_shield_journal_store_t *s,
                              wifi_shield_journal_type_t type, uint64_t sequence,
                              const char *expected)
{
    wifi_shield_journal_record_t r={0}; char encoded[WIFI_SHIELD_JOURNAL_LINE_MAX];
    r.type=type; r.boot_id=UINT32_C(0x1234abcd); r.session_id=42; r.sequence=sequence;
    r.target_count=1; r.event_source=WIFI_SHIELD_SOURCE_DEAUTH;
    r.event_type=WIFI_SHIELD_EVENT_DEAUTH;
    int n=wifi_shield_journal_encode(encoded,sizeof(encoded),&r);
    assert(n>0 && (size_t)n==strlen(expected) && strcmp(encoded,expected)==0);
    assert(wifi_shield_journal_store_append(s,type,encoded,(size_t)n));
}
static void started(filesystem_t *fs, wifi_shield_journal_store_t *s, uint64_t quota)
{
    wifi_shield_journal_store_hooks_t h=hooks(fs);
    assert(wifi_shield_journal_store_start(s,&h,UINT32_C(0x1234abcd),42,quota));
    encode_and_append(s,WIFI_SHIELD_JOURNAL_SESSION_START,1,start_line);
}
static void terminal(wifi_shield_journal_store_t *s)
{ encode_and_append(s,WIFI_SHIELD_JOURNAL_SESSION_TERMINAL,3,terminal_line); }
static void assert_file(filesystem_t *fs, const char *path, const char *a,
                        const char *b, const char *c);
static void uncertainty_then_recovery(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
    wifi_shield_journal_record_t r={0}; char encoded[WIFI_SHIELD_JOURNAL_LINE_MAX];
    r.type=WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN;
    r.boot_id=UINT32_C(0x1234abcd); r.session_id=42; r.sequence=2;
    r.outcome=WIFI_SHIELD_JOURNAL_RESTORE_FAILED;
    int n=wifi_shield_journal_encode(encoded,sizeof(encoded),&r);
    assert(n>0 && strcmp(encoded,uncertain_line)==0);
    assert(wifi_shield_journal_store_append(&s,r.type,encoded,(size_t)n));
    /* A provisional restore failure must be durable before Stop returns, while
     * the same .part remains open so a later radio-recovery terminal can be
     * appended without manufacturing a second session. */
    assert(strcmp(fs.trace,
        "mount>mkdir>open>write>write>flush>fsync_file>sync_sd")==0);
    file_t *part_file=find(&fs,part);
    assert(part_file && part_file->open);
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_ACTIVE);
    terminal(&s);
    wifi_shield_journal_store_finish(&s,true);
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_FINALIZED);
    assert_file(&fs,final,start_line,uncertain_line,terminal_line);
}
static void uncertainty_checkpoint_failures(void)
{
    const enum fault faults[]={FLUSH,FILE_SYNC,SD_SYNC_FIRST};
    for (size_t i=0; i<sizeof(faults)/sizeof(faults[0]); ++i) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
        fs.fault=faults[i];
        assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN,
            uncertain_line,strlen(uncertain_line)));
        wifi_shield_journal_status_t st=wifi_shield_journal_store_status(&s);
        assert(st.state==WIFI_SHIELD_JOURNAL_DEGRADED);
        assert(st.failures==1 && st.dropped==1 && st.records_written==2 &&
               st.sync_failures==1 && st.write_failures==0 &&
               st.finalization_failures==0);
        file_t *part_file=find(&fs,part);
        assert(part_file && part_file->open);
        fs.fault=NONE;
        wifi_shield_journal_store_finish(&s,false);
        assert(!part_file->open && find(&fs,part));
    }
}
static void bounded_periodic_and_transition_checkpoints(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
    assert(wifi_shield_journal_store_append(
        &s,WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION,event_line,strlen(event_line)));
    assert(strcmp(fs.trace,
        "mount>mkdir>open>write>write>flush>fsync_file>sync_sd")==0);
    assert(s.records_since_checkpoint==0U && fs.sync_calls==1U);
    wifi_shield_journal_store_finish(&s,false);

    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0}; started(&fs,&s,8192);
    for (unsigned i=1U; i<WIFI_SHIELD_JOURNAL_CHECKPOINT_RECORDS; ++i)
        assert(wifi_shield_journal_store_append(
            &s,WIFI_SHIELD_JOURNAL_EVENT,event_line,strlen(event_line)));
    assert(s.records_since_checkpoint==0U && fs.sync_calls==1U);
    assert(strstr(fs.trace,"flush>fsync_file>sync_sd")!=NULL);
    wifi_shield_journal_store_finish(&s,false);

    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0}; started(&fs,&s,8192);
    fs.fault=FLUSH;
    assert(!wifi_shield_journal_store_append(
        &s,WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION,event_line,strlen(event_line)));
    assert(s.status.state==WIFI_SHIELD_JOURNAL_DEGRADED &&
           s.status.records_written==2U && s.status.dropped==1U);
    fs.fault=NONE;
    wifi_shield_journal_store_finish(&s,false);
}
static void assert_file(filesystem_t *fs, const char *path, const char *a,
                        const char *b, const char *c)
{
    file_t *f=find(fs,path); assert(f);
    size_t an=strlen(a),bn=strlen(b),cn=strlen(c);
    assert(f->length==an+bn+cn);
    assert(memcmp(f->bytes,a,an)==0 && memcmp(f->bytes+an,b,bn)==0 &&
           memcmp(f->bytes+an+bn,c,cn)==0);
}
static void no_more_io(wifi_shield_journal_store_t *s, filesystem_t *fs)
{
    char before[2048]; strcpy(before,fs->trace);
    assert(!wifi_shield_journal_store_append(s,WIFI_SHIELD_JOURNAL_EVENT,event_line,strlen(event_line)));
    wifi_shield_journal_store_hooks_t h=hooks(fs);
    assert(!wifi_shield_journal_store_start(s,&h,1,1,8192));
    assert(strcmp(before,fs->trace)==0);
}
static void healthy(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
    encode_and_append(&s,WIFI_SHIELD_JOURNAL_EVENT,2,event_line); terminal(&s);
    wifi_shield_journal_store_finish(&s,true);
    wifi_shield_journal_status_t st=wifi_shield_journal_store_status(&s);
    assert(st.state==WIFI_SHIELD_JOURNAL_FINALIZED && strcmp(st.path,final)==0);
    assert(st.records_written==3 && st.failures==0 && st.dropped==0);
    assert(st.time_sources==WIFI_SHIELD_JOURNAL_TIME_MONOTONIC &&
           st.admission_drops==0 && st.encoding_failures==0 &&
           st.write_failures==0 && st.sync_failures==0 &&
           st.finalization_failures==0);
    assert(st.bytes_written==strlen(start_line)+strlen(event_line)+strlen(terminal_line));
    assert(!find(&fs,part)); assert_file(&fs,final,start_line,event_line,terminal_line);
    assert(strcmp(fs.trace,"mount>mkdir>open>write>write>write>flush>fsync_file>close>sync_sd>rename>sync_sd")==0);
    no_more_io(&s,&fs); char before[2048]; strcpy(before,fs.trace);
    wifi_shield_journal_store_finish(&s,true); assert(strcmp(before,fs.trace)==0);
}
static void startup_failures(void)
{
    const enum fault faults[]={MOUNT,MKDIR,OPEN};
    for (size_t i=0;i<3;++i) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; fs.fault=faults[i];
        wifi_shield_journal_store_hooks_t h=hooks(&fs);
        assert(!wifi_shield_journal_store_start(&s,&h,UINT32_C(0x1234abcd),42,8192));
        wifi_shield_journal_status_t st=wifi_shield_journal_store_status(&s);
        assert(st.state==(faults[i]==MOUNT ? WIFI_SHIELD_JOURNAL_UNAVAILABLE : WIFI_SHIELD_JOURNAL_DEGRADED));
        assert(st.failures==1 && st.write_failures==1 &&
               st.bytes_written==0 && !find(&fs,part));
        no_more_io(&s,&fs); wifi_shield_journal_store_finish(&s,true);
        assert(!find(&fs,final) && fs.mount_calls==1 && fs.open_calls<=1);
    }
}
static void writes_fail_open(void)
{
    const enum fault faults[]={WRITE_FAIL,WRITE_SHORT};
    for(size_t i=0;i<2;++i) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
        fs.fault=faults[i];
        assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_EVENT,event_line,strlen(event_line)));
        wifi_shield_journal_status_t st=wifi_shield_journal_store_status(&s);
        assert(st.state==WIFI_SHIELD_JOURNAL_DEGRADED && st.failures==1 &&
               st.write_failures==1 && st.dropped==1 &&
               st.degraded_notice_pending);
        file_t *f=find(&fs,part); assert(f && st.bytes_written==f->length && st.records_written==1);
        assert(f->length==strlen(start_line)+(faults[i]==WRITE_SHORT ? strlen(event_line)-1 : 0));
        no_more_io(&s,&fs); wifi_shield_journal_store_finish(&s,true);
        assert(!find(&fs,final) && !f->open && fs.write_calls==2);
    }
}
static void quota_boundaries(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0};
    started(&fs,&s,strlen(start_line)+strlen(terminal_line)); terminal(&s);
    wifi_shield_journal_store_finish(&s,true);
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_FINALIZED);
    assert_file(&fs,final,start_line,"",terminal_line);
    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0};
    started(&fs,&s,strlen(start_line)+strlen(event_line)-1);
    assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_EVENT,event_line,strlen(event_line)));
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_QUOTA_REACHED);
    no_more_io(&s,&fs); wifi_shield_journal_store_finish(&s,true);
    assert_file(&fs,part,start_line,"",""); assert(!find(&fs,final) && !find(&fs,part)->open);
    assert(strcmp(fs.trace,"mount>mkdir>open>write>flush>fsync_file>close>sync_sd")==0);
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_QUOTA_REACHED);
}
static void finalization_failures(void)
{
    const enum fault faults[]={FLUSH,FILE_SYNC,CLOSE,SD_SYNC_FIRST,RENAME,SD_SYNC_FINAL};
    for(size_t i=0;i<sizeof(faults)/sizeof(faults[0]);++i) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192); terminal(&s);
        fs.fault=faults[i]; wifi_shield_journal_store_finish(&s,true);
        wifi_shield_journal_status_t st=wifi_shield_journal_store_status(&s);
        assert(st.state==WIFI_SHIELD_JOURNAL_DEGRADED && st.failures==1 &&
               st.finalization_failures==1 && st.degraded_notice_pending);
        const char *actual=faults[i]==SD_SYNC_FINAL ? final : part;
        assert(strcmp(st.path,actual)==0); assert_file(&fs,actual,start_line,"",terminal_line);
        assert(!find(&fs,actual)->open);
        if(faults[i]!=SD_SYNC_FINAL) assert(!find(&fs,final));
        no_more_io(&s,&fs); char before[2048]; strcpy(before,fs.trace);
        wifi_shield_journal_store_finish(&s,true); assert(strcmp(before,fs.trace)==0);
    }
}
static void incomplete_retains_evidence(void)
{
    for(unsigned clean=0;clean<2;++clean) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
        if(!clean) terminal(&s);
        wifi_shield_journal_store_finish(&s,clean!=0);
        assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_INCOMPLETE);
        assert_file(&fs,part,start_line,"",clean ? "" : terminal_line);
        assert(!find(&fs,final) && !find(&fs,part)->open);
    }
}
static void never_overwrite_old_evidence(void)
{
    for(unsigned collision=0;collision<2;++collision) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; file_t *old=&fs.files[0];
        old->exists=true; strcpy(old->path,collision ? final : part);
        memcpy(old->bytes,"OLD EVIDENCE",12); old->length=12;
        wifi_shield_journal_store_hooks_t h=hooks(&fs);
        bool ok=wifi_shield_journal_store_start(&s,&h,UINT32_C(0x1234abcd),42,8192);
        if(collision) {
            assert(ok); encode_and_append(&s,WIFI_SHIELD_JOURNAL_SESSION_START,1,start_line); terminal(&s);
            wifi_shield_journal_store_finish(&s,true); assert_file(&fs,part,start_line,"",terminal_line);
        } else assert(!ok);
        assert(old->length==12 && memcmp(old->bytes,"OLD EVIDENCE",12)==0);
        assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_DEGRADED);
    }
}
static void generated_path_extremes(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; wifi_shield_journal_store_hooks_t h=hooks(&fs);
    assert(wifi_shield_journal_store_start(&s,&h,UINT32_MAX,UINT32_MAX,8192));
    assert(strcmp(wifi_shield_journal_store_status(&s).path,
        "/sdcard/lab/shield/shield-bffffffff-s4294967295.jsonl.part")==0);
    wifi_shield_journal_store_finish(&s,false);
}
static void malformed_input_and_saturation(void)
{
    filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
    assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_EVENT,"bad",3));
    assert(wifi_shield_journal_store_status(&s).state==WIFI_SHIELD_JOURNAL_DEGRADED);
    assert_file(&fs,part,start_line,"","");
    s.status.dropped=UINT32_MAX; s.status.failures=UINT32_MAX;
    no_more_io(&s,&fs); assert(s.status.dropped==UINT32_MAX && s.status.failures==UINT32_MAX);
    s.status.degraded_notice_pending=false; fs.fault=FLUSH;
    wifi_shield_journal_store_finish(&s,false);
    assert(s.status.failures==UINT32_MAX && !s.status.degraded_notice_pending);
    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0}; started(&fs,&s,UINT64_MAX);
    s.status.bytes_written=UINT64_MAX-1;
    assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_EVENT,event_line,strlen(event_line)));
    assert(s.status.state==WIFI_SHIELD_JOURNAL_QUOTA_REACHED && s.status.bytes_written==UINT64_MAX-1);
    wifi_shield_journal_store_finish(&s,false);
    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0}; started(&fs,&s,8192);
    s.status.records_written=UINT32_MAX;
    encode_and_append(&s,WIFI_SHIELD_JOURNAL_EVENT,2,event_line);
    assert(s.status.records_written==UINT32_MAX); wifi_shield_journal_store_finish(&s,false);
    fs=(filesystem_t){0}; s=(wifi_shield_journal_store_t){0}; started(&fs,&s,UINT64_MAX);
    s.status.bytes_written=UINT64_MAX-strlen(event_line);
    encode_and_append(&s,WIFI_SHIELD_JOURNAL_EVENT,2,event_line);
    assert(s.status.bytes_written==UINT64_MAX);
    assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_SESSION_TERMINAL,terminal_line,strlen(terminal_line)));
    assert(s.status.bytes_written==UINT64_MAX && s.status.state==WIFI_SHIELD_JOURNAL_QUOTA_REACHED);
    wifi_shield_journal_store_finish(&s,true); assert(!find(&fs,final));
}
static void terminal_failure_and_record_order(void)
{
    for(unsigned first=0;first<2;++first) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0};
        wifi_shield_journal_store_hooks_t h=hooks(&fs);
        assert(wifi_shield_journal_store_start(&s,&h,UINT32_C(0x1234abcd),42,8192));
        if(!first) encode_and_append(&s,WIFI_SHIELD_JOURNAL_SESSION_START,1,start_line);
        fs.fault=WRITE_SHORT;
        const char *line=first ? start_line : terminal_line;
        wifi_shield_journal_type_t type=first ? WIFI_SHIELD_JOURNAL_SESSION_START : WIFI_SHIELD_JOURNAL_SESSION_TERMINAL;
        assert(!wifi_shield_journal_store_append(&s,type,line,strlen(line)));
        wifi_shield_journal_store_finish(&s,true);
        assert(s.status.state==WIFI_SHIELD_JOURNAL_DEGRADED && !find(&fs,final));
        file_t *f=find(&fs,part); assert(f && !f->open);
        assert(f->length==(first ? strlen(start_line)-1 : strlen(start_line)+strlen(terminal_line)-1));
    }
    for(unsigned order=0;order<3;++order) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0};
        wifi_shield_journal_store_hooks_t h=hooks(&fs);
        assert(wifi_shield_journal_store_start(&s,&h,UINT32_C(0x1234abcd),42,8192));
        if(order) encode_and_append(&s,WIFI_SHIELD_JOURNAL_SESSION_START,1,start_line);
        if(order==2) terminal(&s);
        const char *line=order==1 ? start_line : event_line;
        wifi_shield_journal_type_t type=order==1 ? WIFI_SHIELD_JOURNAL_SESSION_START : WIFI_SHIELD_JOURNAL_EVENT;
        assert(!wifi_shield_journal_store_append(&s,type,line,strlen(line)));
        wifi_shield_journal_store_finish(&s,true);
        assert(s.status.state==WIFI_SHIELD_JOURNAL_DEGRADED && !find(&fs,final));
        assert_file(&fs,part,order ? start_line : "","",order==2 ? terminal_line : "");
    }
}
static void invalid_start_and_input_are_bounded(void)
{
    assert(!wifi_shield_journal_store_start(NULL,NULL,1,1,1));
    assert(!wifi_shield_journal_store_append(NULL,WIFI_SHIELD_JOURNAL_EVENT,NULL,0));
    wifi_shield_journal_store_finish(NULL,true);
    assert(wifi_shield_journal_store_status(NULL).state==WIFI_SHIELD_JOURNAL_UNAVAILABLE);
    for(unsigned invalid=0;invalid<5;++invalid) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; wifi_shield_journal_store_hooks_t h=hooks(&fs);
        if(invalid==0) h.mount=NULL;
        if(invalid==1) h.write=NULL;
        assert(!wifi_shield_journal_store_start(&s,&h,invalid==2 ? 0 : 1,invalid==3 ? 0 : 1,invalid==4 ? 0 : 8192));
        assert(s.status.state==WIFI_SHIELD_JOURNAL_UNAVAILABLE && s.status.failures==1 && !fs.trace[0]);
        no_more_io(&s,&fs); wifi_shield_journal_store_finish(&s,true);
    }
    const char *bad[]={NULL,"", "{}\n{}\n", "{}\r\n", "{}\0x\n", "x"};
    const size_t lengths[]={0,0,6,4,6,WIFI_SHIELD_JOURNAL_LINE_MAX};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        filesystem_t fs={0}; wifi_shield_journal_store_t s={0}; started(&fs,&s,8192);
        assert(!wifi_shield_journal_store_append(&s,WIFI_SHIELD_JOURNAL_EVENT,bad[i],lengths[i]));
        assert(s.status.state==WIFI_SHIELD_JOURNAL_DEGRADED);
        assert_file(&fs,part,start_line,"",""); wifi_shield_journal_store_finish(&s,false);
    }
}
int main(void)
{
    healthy(); startup_failures(); writes_fail_open(); quota_boundaries();
    finalization_failures(); incomplete_retains_evidence(); never_overwrite_old_evidence();
    generated_path_extremes(); malformed_input_and_saturation();
    uncertainty_then_recovery(); uncertainty_checkpoint_failures();
    bounded_periodic_and_transition_checkpoints();
    terminal_failure_and_record_order(); invalid_start_and_input_are_bounded();
    puts("wifi shield journal store: PASS"); return 0;
}
