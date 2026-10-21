#include "wps_transport_core.h"

#include <assert.h>
#include <string.h>

typedef struct {
    unsigned call;
    unsigned fail_call;
    char fail_cleanup;
    char trace[256];
    size_t length;
} mock_t;

static int event(mock_t *mock, char code)
{
    mock->trace[mock->length++] = code;
    mock->trace[mock->length] = '\0';
    mock->call++;
    return mock->call == mock->fail_call || code == mock->fail_cleanup ? -1 : 0;
}

static int init(void *c) { return event(c, 'I'); }
static int start(void *c) { return event(c, 'S'); }
static int stop(void *c) { return event(c, 's'); }
static int deinit(void *c) { return event(c, 'i'); }
static int set_mac(void *c, const uint8_t mac[6]) { return event(c, mac[0] == 0x02 ? 'M' : 'm'); }
static int callbacks(void *c, bool enabled) { return event(c, enabled ? 'C' : 'c'); }
static int appie(void *c, bool enabled) { return event(c, enabled ? 'A' : 'a'); }
static int wps(void *c, bool enabled) { return event(c, enabled ? 'W' : 'w'); }
static int disconnect(void *c) { return event(c, 'D'); }

static const wps_transport_ops_t ops = {
    init, start, stop, deinit, set_mac, callbacks, appie, wps, disconnect,
};

static void clean_cycle(void)
{
    mock_t mock = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &ops, &mock);
    const uint8_t session[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t original[6] = {0x3c, 1, 2, 3, 4, 5};
    assert(wps_transport_begin(&transport, session, original));
    assert(strcmp(mock.trace, "IMSCAW") == 0);
    assert(wps_transport_active(&transport));
    assert(!wps_transport_begin(&transport, session, original));
    assert(wps_transport_cancel(&transport));
    assert(strcmp(mock.trace, "IMSCAWwDacsmi") == 0);
    assert(!wps_transport_active(&transport));
    size_t calls = mock.call;
    assert(!wps_transport_cleanup_pending(&transport));
    assert(wps_transport_cancel(&transport));
    assert(mock.call == calls);
}

static void failure_unwinds_every_prefix(void)
{
    const uint8_t session[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t original[6] = {0x3c, 1, 2, 3, 4, 5};
    const char *traces[] = {
        "Ii", "IMi", "IMSmi", "IMSCDsmi", "IMSCADcsmi", "IMSCAWwDacsmi",
    };
    for (unsigned failure = 1; failure <= 6; failure++) {
        mock_t mock = {.fail_call = failure};
        wps_transport_t transport;
        wps_transport_init(&transport, &ops, &mock);
        assert(!wps_transport_begin(&transport, session, original));
        assert(!wps_transport_active(&transport));
        assert(strcmp(mock.trace, traces[failure - 1]) == 0);
        assert(!transport.initialized);
        size_t calls = mock.call;
        assert(wps_transport_cancel(&transport));
        assert(mock.call == calls);
    }
}

/* A failed release must retain ownership and stop dependent cleanup. */
static void cleanup_failure_can_be_retried(void)
{
    const uint8_t session[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t original[6] = {0x3c, 1, 2, 3, 4, 5};
    const char failures[] = "wDacsmi";
    const char *failed_traces[] = {
        "IMSCAWw", "IMSCAWwD", "IMSCAWwDa", "IMSCAWwDac",
        "IMSCAWwDacs", "IMSCAWwDacsm", "IMSCAWwDacsmi",
    };
    const char *retried_traces[] = {
        "IMSCAWwwDacsmi", "IMSCAWwDDacsmi", "IMSCAWwDaacsmi",
        "IMSCAWwDaccsmi", "IMSCAWwDacssmi", "IMSCAWwDacsmmi",
        "IMSCAWwDacsmii",
    };
    for (size_t index = 0; index < sizeof(failures) - 1; index++) {
        mock_t mock = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &ops, &mock);
        assert(wps_transport_begin(&transport, session, original));
        mock.fail_cleanup = failures[index];
        assert(!wps_transport_cancel(&transport));
        assert(transport.initialized);
        assert(wps_transport_cleanup_pending(&transport));
        assert(!wps_transport_active(&transport));
        assert(strcmp(mock.trace, failed_traces[index]) == 0);
        size_t calls = mock.call;
        assert(!wps_transport_begin(&transport, session, original));
        assert(mock.call == calls);
        mock.fail_cleanup = 0;
        assert(wps_transport_cancel(&transport));
        assert(!transport.initialized);
        assert(!wps_transport_cleanup_pending(&transport));
        assert(strcmp(mock.trace, retried_traces[index]) == 0);
        assert(wps_transport_begin(&transport, session, original));
        assert(wps_transport_cancel(&transport));
    }
}

static void setup_failure_preserves_failed_rollback(void)
{
    const uint8_t session[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t original[6] = {0x3c, 1, 2, 3, 4, 5};
    mock_t mock = {.fail_call = 5, .fail_cleanup = 'c'};
    wps_transport_t transport;
    wps_transport_init(&transport, &ops, &mock);
    assert(!wps_transport_begin(&transport, session, original));
    assert(transport.initialized && transport.callbacks_set);
    assert(strcmp(mock.trace, "IMSCADc") == 0);
    mock.fail_cleanup = 0;
    assert(wps_transport_cancel(&transport));
    assert(!transport.initialized);
    assert(strcmp(mock.trace, "IMSCADccsmi") == 0);
}

int main(void)
{
    assert(!wps_transport_cancel(NULL));
    assert(!wps_transport_cleanup_pending(NULL));
    clean_cycle();
    cleanup_failure_can_be_retried();
    failure_unwinds_every_prefix();
    setup_failure_preserves_failed_rollback();
    return 0;
}
