#include "wsc_fragment.h"

#include <assert.h>
#include <string.h>

static size_t frame(uint8_t *out, size_t cap, uint8_t id, uint8_t flags,
                    uint16_t total, const uint8_t *payload, size_t payload_len)
{
    size_t header = (flags & WSC_FLAG_LENGTH_FIELD) ? 20U : 18U;
    size_t length = header + payload_len;
    assert(cap >= length);
    memset(out, 0, length);
    out[0] = 1; out[2] = (uint8_t)((length - 4U) >> 8); out[3] = (uint8_t)(length - 4U);
    out[4] = 1; out[5] = id; out[6] = out[2]; out[7] = out[3]; out[8] = 254;
    out[10] = 0x37; out[11] = 0x2a; out[15] = 1; out[16] = 4; out[17] = flags;
    if (flags & WSC_FLAG_LENGTH_FIELD) { out[18] = (uint8_t)(total >> 8); out[19] = (uint8_t)total; }
    memcpy(out + header, payload, payload_len);
    return length;
}

int main(void)
{
    uint8_t storage[32], packet[64], ack[18], complete[64];
    wsc_reassembly_t state;
    wsc_reassembly_init(&state, storage, sizeof(storage), 1000U);
    const uint8_t first[] = {1, 2, 3};
    const uint8_t second[] = {4, 5};
    size_t length = frame(packet, sizeof(packet), 10, 3, 5, first, sizeof(first));
    wsc_fragment_view_t view;
    assert(wsc_reassembly_accept(&state, packet, length, 100, &view) == WSC_FRAGMENT_NEED_ACK);
    assert(view.eap_id == 10 && view.length == 0);
    assert(wsc_build_fragment_ack(10, ack, sizeof(ack)) == sizeof(ack));
    assert(ack[4] == 2 && ack[5] == 10 && ack[16] == 6 && ack[17] == 0);

    /* Exact retransmission requests another ACK without appending twice. */
    assert(wsc_reassembly_accept(&state, packet, length, 200, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 37, 0, 0, second, sizeof(second));
    assert(wsc_reassembly_accept(&state, packet, length, 300, &view) == WSC_FRAGMENT_COMPLETE);
    const uint8_t expected[] = {1, 2, 3, 4, 5};
    assert(view.first_eap_id == 10 && view.eap_id == 37);
    assert(view.length == sizeof(expected) && memcmp(view.payload, expected, sizeof(expected)) == 0);
    assert(wsc_materialize_message(&view, complete, sizeof(complete)) == 23U);
    assert(complete[3] == 19U && complete[7] == 19U && complete[5] == 37U);
    assert(complete[16] == 4U && complete[17] == 0U);
    assert(memcmp(complete + 18U, expected, sizeof(expected)) == 0);
    assert(wsc_materialize_message(&view, complete, 22U) == 0U);

    /* A retransmitted final fragment reproduces the whole completed message. */
    assert(wsc_reassembly_accept(&state, packet, length, 301, &view) == WSC_FRAGMENT_COMPLETE);
    assert(view.first_eap_id == 10 && view.eap_id == 37);
    assert(view.length == sizeof(expected) && memcmp(view.payload, expected, sizeof(expected)) == 0);

    /* Complete unfragmented messages follow the same bounded copy path. */
    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 7, 0, 0, expected, sizeof(expected));
    assert(wsc_reassembly_accept(&state, packet, length, 0, &view) == WSC_FRAGMENT_COMPLETE);
    wsc_reassembly_reset(&state);
    for (size_t index = 0; index < sizeof(expected); index++) assert(storage[index] == 0U);

    /* Same id with different payload and wrong opcode fail closed. */
    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 20, 3, 5, first, sizeof(first));
    assert(wsc_reassembly_accept(&state, packet, length, 0, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 20, 0, 0, second, sizeof(second));
    assert(wsc_reassembly_accept(&state, packet, length, 1, &view) == WSC_FRAGMENT_INVALID);
    packet[16] = 3;
    assert(wsc_reassembly_accept(&state, packet, length, 2, &view) == WSC_FRAGMENT_OTHER);

    /* Oversize, inconsistent total, missing final fragment and cancellation. */
    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 1, 3, 33, first, sizeof(first));
    assert(wsc_reassembly_accept(&state, packet, length, 0, &view) == WSC_FRAGMENT_OVERSIZE);
    length = frame(packet, sizeof(packet), 1, 3, 4, first, sizeof(first));
    assert(wsc_reassembly_accept(&state, packet, length, 10, &view) == WSC_FRAGMENT_NEED_ACK);
    assert(wsc_reassembly_expire(&state, 1009) == false);
    assert(wsc_reassembly_expire(&state, 1011) == true);
    assert(!wsc_reassembly_active(&state));
    wsc_reassembly_reset(&state);
    assert(!wsc_reassembly_active(&state));

    /* Three fragments support EAP-ID wrap and timeout is checked on input. */
    const uint8_t one[] = {1}, two[] = {2}, three[] = {3};
    length = frame(packet, sizeof(packet), 255, 3, 3, one, sizeof(one));
    assert(wsc_reassembly_accept(&state, packet, length, 2000, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 42, 1, 0, two, sizeof(two));
    assert(wsc_reassembly_accept(&state, packet, length, 2100, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 1, 0, 0, three, sizeof(three));
    assert(wsc_reassembly_accept(&state, packet, length, 2200, &view) == WSC_FRAGMENT_COMPLETE);
    assert(view.first_eap_id == 255 && view.eap_id == 1 && view.length == 3U);

    /* Fragments carrying MORE must make progress. */
    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 5, 3, 2, one, 0);
    assert(wsc_reassembly_accept(&state, packet, length, 2300, &view) == WSC_FRAGMENT_INVALID);
    length = frame(packet, sizeof(packet), 5, 3, 2, one, sizeof(one));
    assert(wsc_reassembly_accept(&state, packet, length, 2301, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 9, 1, 0, two, 0);
    assert(wsc_reassembly_accept(&state, packet, length, 2302, &view) == WSC_FRAGMENT_INVALID);

    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 30, 3, 3, one, sizeof(one));
    assert(wsc_reassembly_accept(&state, packet, length, 3000, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 31, 1, 0, two, sizeof(two));
    assert(wsc_reassembly_accept(&state, packet, length, 4001, &view) == WSC_FRAGMENT_TIMEOUT);
    assert(!wsc_reassembly_active(&state));

    wsc_reassembly_reset(&state);
    length = frame(packet, sizeof(packet), 40, 3, 2, one, sizeof(one));
    assert(wsc_reassembly_accept(&state, packet, length, 5000, &view) == WSC_FRAGMENT_NEED_ACK);
    length = frame(packet, sizeof(packet), 41, 0, 0, two, sizeof(two));
    assert(wsc_reassembly_accept(&state, packet, length, 6001, &view) == WSC_FRAGMENT_TIMEOUT);
    assert(!wsc_reassembly_active(&state));
    return 0;
}
