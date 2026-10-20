"""Execute the MITM PCAP helpers from main.c on a local C host.

Run with: python3 -m unittest discover -s tests -p test_mitm_pcap_host.py -v
The generated harnesses use only memory; no radio, network, or firmware runs.
"""

from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main" / "main.c"


def _function(source: str, name: str) -> str:
    """Copy one complete C definition, leaving its production body intact."""
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.S,
    )
    match = re.search(
        r"(?m)^[ \t]*static[^\n;{}]*\b" + re.escape(name)
        + r"\s*\([^;{}]*\)\s*\{",
        masked,
    )
    if match is None:
        raise AssertionError(f"definition missing from main.c: {name}")
    begin = source.rfind("\n", 0, match.start()) + 1
    depth, end = 1, match.end()
    while depth:
        if end >= len(masked):
            raise AssertionError(f"unclosed definition in main.c: {name}")
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[begin:end]


GATEWAY_HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

typedef enum {
    PCAP_MODE_NONE = 0, PCAP_MODE_RADIO, PCAP_MODE_NET, PCAP_MODE_GATEWAY
} pcap_capture_mode_t;
static pcap_capture_mode_t pcap_capture_mode = PCAP_MODE_GATEWAY;

FUNCTION

int main(void) {
    /* Ethernet + minimal IPv4 header; offsets follow the wire format. */
    uint8_t frame[38] = {0};
    frame[12] = 0x08; frame[13] = 0x00;
    frame[14] = 0x45;
    frame[26] = 10; frame[27] = 42; frame[28] = 0; frame[29] = 7;
    frame[30] = 8; frame[31] = 8; frame[32] = 8; frame[33] = 8;
    assert(pcap_gateway_should_record(frame, 34));

    /* Destination in 10.42.0.0/24 is sufficient for inbound traffic. */
    frame[26] = 8; frame[27] = 8; frame[28] = 4; frame[29] = 4;
    frame[30] = 10; frame[31] = 42; frame[32] = 0; frame[33] = 254;
    assert(pcap_gateway_should_record(frame, 34));

    /* Adjacent subnets and unrelated IPv4 traffic stay out of the capture. */
    frame[32] = 1;
    assert(!pcap_gateway_should_record(frame, 34));
    frame[30] = 1; frame[31] = 1; frame[32] = 1; frame[33] = 1;
    assert(!pcap_gateway_should_record(frame, 34));

    /* Tagged IPv4 uses the inner EtherType and shifted IP addresses. */
    uint8_t vlan[38] = {0};
    vlan[12] = 0x81; vlan[13] = 0x00;
    vlan[16] = 0x08; vlan[17] = 0x00;
    vlan[18] = 0x45;
    vlan[30] = 10; vlan[31] = 42; vlan[32] = 0; vlan[33] = 1;
    vlan[34] = 9; vlan[35] = 9; vlan[36] = 9; vlan[37] = 9;
    assert(pcap_gateway_should_record(vlan, sizeof(vlan)));
    vlan[31] = 43;
    assert(!pcap_gateway_should_record(vlan, sizeof(vlan)));

    frame[12] = 0x08; frame[13] = 0x06; /* ARP */
    assert(!pcap_gateway_should_record(frame, sizeof(frame)));
    frame[12] = 0x86; frame[13] = 0xdd; /* IPv6 */
    assert(!pcap_gateway_should_record(frame, sizeof(frame)));
    frame[12] = 0x08; frame[13] = 0x00;
    frame[26] = 10; frame[27] = 42; frame[28] = 0; frame[29] = 7;
    assert(!pcap_gateway_should_record(NULL, 34));
    assert(!pcap_gateway_should_record(frame, 13));
    assert(!pcap_gateway_should_record(frame, 33));
    assert(!pcap_gateway_should_record(vlan, 17));
    assert(!pcap_gateway_should_record(vlan, 37));

    /* The legacy net/radio recorders intentionally do not apply this gate. */
    pcap_capture_mode = PCAP_MODE_NET;
    assert(pcap_gateway_should_record(NULL, 0));
    pcap_capture_mode = PCAP_MODE_RADIO;
    assert(pcap_gateway_should_record(frame, 13));
    return 0;
}
'''


GATEWAY_ENQUEUE_HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef enum {
    PCAP_MODE_NONE = 0, PCAP_MODE_RADIO, PCAP_MODE_NET, PCAP_MODE_GATEWAY
} pcap_capture_mode_t;
typedef struct {
    uint16_t len;
    int64_t timestamp_us;
    uint8_t data[];
} pcap_queued_frame_t;
typedef struct {
    pcap_queued_frame_t *frame;
    unsigned depth;
} host_queue_t;
typedef host_queue_t *QueueHandle_t;

#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define pdTRUE 1
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))

static pcap_capture_mode_t pcap_capture_mode = PCAP_MODE_GATEWAY;
static bool pcap_capture_active = true;
static host_queue_t queue;
static QueueHandle_t pcap_packet_queue = &queue;
static int pcap_stats_lock;
static uint32_t pcap_gateway_filtered_frame_count;
static uint32_t pcap_capture_drop_count;
static uint32_t pcap_capture_drop_alloc_count;
static uint32_t pcap_capture_drop_queue_count;
static uint32_t pcap_capture_queue_high_water;
static bool fail_allocation;
static unsigned allocation_attempts;

static void *heap_caps_malloc(size_t size, int caps) {
    (void)caps;
    allocation_attempts++;
    return fail_allocation ? NULL : malloc(size);
}
static void heap_caps_free(void *pointer) { free(pointer); }
static int xQueueSend(QueueHandle_t target, const void *item, int ticks) {
    (void)ticks;
    if (target->depth == 1) return 0;
    memcpy(&target->frame, item, sizeof(target->frame));
    target->depth = 1;
    return pdTRUE;
}
static unsigned uxQueueMessagesWaiting(QueueHandle_t target) {
    return target->depth;
}

FUNCTION

int main(void) {
    uint8_t frame[34] = {0};
    frame[12] = 0x08; frame[13] = 0x00; frame[14] = 0x45;
    frame[26] = 9; frame[27] = 9; frame[28] = 9; frame[29] = 9;
    frame[30] = 8; frame[31] = 8; frame[32] = 8; frame[33] = 8;
    pcap_enqueue_frame_at(frame, sizeof(frame), 1234567);
    assert(pcap_gateway_filtered_frame_count == 1);
    assert(pcap_capture_drop_count == 0);
    assert(allocation_attempts == 0);
    assert(queue.depth == 0);

    frame[26] = 10; frame[27] = 42; frame[28] = 0; frame[29] = 7;
    fail_allocation = true;
    pcap_enqueue_frame_at(frame, sizeof(frame), 1234567);
    assert(allocation_attempts == 2); /* SPIRAM and 8-bit fallback */
    assert(pcap_capture_drop_count == 1);
    assert(pcap_capture_drop_alloc_count == 1);
    assert(pcap_capture_drop_queue_count == 0);
    assert(pcap_gateway_filtered_frame_count == 1);
    assert(queue.depth == 0);

    fail_allocation = false;
    pcap_enqueue_frame_at(frame, sizeof(frame), 1234567);
    assert(queue.depth == 1);
    assert(queue.frame != NULL);
    assert(queue.frame->len == sizeof(frame));
    assert(queue.frame->timestamp_us == 1234567);
    assert(memcmp(queue.frame->data, frame, sizeof(frame)) == 0);
    assert(pcap_capture_queue_high_water == 1);
    assert(pcap_capture_drop_count == 1);
    assert(pcap_gateway_filtered_frame_count == 1);

    pcap_enqueue_frame_at(frame, sizeof(frame), 7654321); /* one-slot queue full */
    assert(queue.depth == 1);
    assert(queue.frame->timestamp_us == 1234567);
    assert(memcmp(queue.frame->data, frame, sizeof(frame)) == 0);
    assert(pcap_capture_drop_count == 2);
    assert(pcap_capture_drop_alloc_count == 1);
    assert(pcap_capture_drop_queue_count == 1);
    assert(pcap_gateway_filtered_frame_count == 1);
    assert(pcap_capture_queue_high_water == 1);
    heap_caps_free(queue.frame);
    return 0;
}
'''


BASENAME_HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#define PCAP_BASENAME_MAX_LEN 95

/* ESP-IDF supplies these BSD string helpers; glibc may not. */
static size_t host_strlcpy(char *dst, const char *src, size_t size) {
    size_t len = strlen(src);
    if (size) {
        size_t copied = len < size - 1 ? len : size - 1;
        memcpy(dst, src, copied);
        dst[copied] = '\0';
    }
    return len;
}
static size_t host_strlcat(char *dst, const char *src, size_t size) {
    size_t used = strnlen(dst, size);
    if (used == size) return size + strlen(src);
    return used + host_strlcpy(dst + used, src, size - used);
}
#define strlcpy host_strlcpy
#define strlcat host_strlcat

FUNCTION

int main(void) {
    char name[96] = {0};
    assert(pcap_normalize_basename("rogue_01", name, sizeof(name)));
    assert(strcmp(name, "rogue_01.pcap") == 0);
    assert(pcap_normalize_basename("session.PCAP", name, sizeof(name)));
    assert(strcmp(name, "session.PCAP") == 0);
    assert(pcap_normalize_basename("x-y.z", name, sizeof(name)));
    assert(strcmp(name, "x-y.z.pcap") == 0);

    assert(!pcap_normalize_basename("", name, sizeof(name)));
    assert(!pcap_normalize_basename(".hidden", name, sizeof(name)));
    assert(!pcap_normalize_basename("../escape", name, sizeof(name)));
    assert(!pcap_normalize_basename("dir/name", name, sizeof(name)));
    assert(!pcap_normalize_basename("dir\\name", name, sizeof(name)));
    assert(!pcap_normalize_basename("bad name", name, sizeof(name)));
    assert(!pcap_normalize_basename(NULL, name, sizeof(name)));
    assert(!pcap_normalize_basename("ok", NULL, sizeof(name)));
    assert(!pcap_normalize_basename("ok", name, 5));
    assert(!pcap_normalize_basename("ok", name, 7)); /* needs 8 bytes */

    char ninety[91];
    memset(ninety, 'a', 90); ninety[90] = '\0';
    assert(pcap_normalize_basename(ninety, name, sizeof(name)));
    assert(strlen(name) == 95);
    char ninety_one[92];
    memset(ninety_one, 'a', 91); ninety_one[91] = '\0';
    assert(!pcap_normalize_basename(ninety_one, name, sizeof(name)));
    return 0;
}
'''


ARP_HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARP_PACKET_SIZE 42
#define ETH_TYPE_ARP 0x0806
#define ARP_HWTYPE_ETH 1
#define ARP_PROTO_IP 0x0800
#define ARP_OP_REPLY 2
#define PBUF_RAW 0
#define PBUF_RAM 0

struct pbuf { void *payload; };
struct netif { int (*linkoutput)(struct netif *, struct pbuf *); };
static uint8_t transmitted[ARP_PACKET_SIZE];
static unsigned transmissions;
static struct pbuf *pbuf_alloc(int layer, size_t size, int type) {
    (void)layer; (void)type;
    struct pbuf *p = malloc(sizeof(*p));
    if (p) p->payload = malloc(size);
    if (p && !p->payload) { free(p); return NULL; }
    return p;
}
static void pbuf_free(struct pbuf *p) { free(p->payload); free(p); }
static int capture_frame(struct netif *netif, struct pbuf *p) {
    (void)netif;
    memcpy(transmitted, p->payload, sizeof(transmitted));
    transmissions++;
    return 0;
}

FUNCTION

int main(void) {
    struct netif netif = {.linkoutput = capture_frame};
    const uint8_t victim[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    const uint8_t own[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint32_t gateway_ip, victim_ip;
    const uint8_t gateway_bytes[4] = {192, 168, 1, 1};
    const uint8_t victim_bytes[4] = {192, 168, 1, 77};
    memcpy(&gateway_ip, gateway_bytes, 4);
    memcpy(&victim_ip, victim_bytes, 4);
    send_arp_reply(&netif, victim, own, own, gateway_ip, victim, victim_ip);
    const uint8_t expected[42] = {
        0x10,0x20,0x30,0x40,0x50,0x60, 0x02,0xaa,0xbb,0xcc,0xdd,0xee,
        0x08,0x06, 0x00,0x01, 0x08,0x00, 0x06,0x04, 0x00,0x02,
        0x02,0xaa,0xbb,0xcc,0xdd,0xee, 192,168,1,1,
        0x10,0x20,0x30,0x40,0x50,0x60, 192,168,1,77
    };
    assert(transmissions == 1);
    assert(memcmp(transmitted, expected, sizeof(expected)) == 0);
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run in Linux/WSL")
class MitmPcapHostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MAIN.read_text(encoding="utf-8")

    def _run(self, names, harness: str):
        if isinstance(names, str):
            names = (names,)
        functions = "\n\n".join(_function(self.source, name) for name in names)
        code = harness.replace("FUNCTION", functions)
        with tempfile.TemporaryDirectory(prefix="janos-mitm-pcap-") as temporary:
            generated = Path(temporary) / "test.c"
            executable = Path(temporary) / "test"
            generated.write_text(code, encoding="utf-8")
            compiled = subprocess.run(
                [os.environ.get("CC", "gcc"), "-std=gnu11", "-Wall", "-Wextra",
                 "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 str(generated), "-o", str(executable)],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(
                [str(executable)], cwd=ROOT, capture_output=True, text=True,
                timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_gateway_ipv4_subnet_and_vlan_filter(self):
        self._run("pcap_gateway_should_record", GATEWAY_HARNESS)

    def test_gateway_enqueue_copies_frames_and_counts_distinct_drops(self):
        self._run(("pcap_gateway_should_record", "pcap_enqueue_frame_at"),
                  GATEWAY_ENQUEUE_HARNESS)

    def test_capture_basename_normalization_and_path_rejection(self):
        self._run("pcap_normalize_basename", BASENAME_HARNESS)

    def test_legacy_arp_reply_wire_bytes(self):
        self._run("send_arp_reply", ARP_HARNESS)


if __name__ == "__main__":
    unittest.main()
