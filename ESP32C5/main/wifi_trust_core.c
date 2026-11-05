#include "wifi_trust_core.h"

#include <limits.h>
#include <string.h>

static bool valid_status(sx_status_t status)
{
    return status >= SX_UNKNOWN && status <= SX_INVALID;
}

static bool valid_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i) any |= bssid[i];
    return any != 0 && (bssid[0] & 1U) == 0;
}

static bool bytes_zero(const void *memory, size_t size)
{
    const uint8_t *bytes = memory;
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] != 0U) return false;
    return true;
}

static bool text_valid(const sx_text_t *text)
{
    if (text->truncated || text->len > SX_TEXT_BYTES) return false;
    if (!text->present)
        return text->len == 0U &&
               bytes_zero(text->bytes, sizeof(text->bytes));
    return bytes_zero(text->bytes + text->len,
                      sizeof(text->bytes) - text->len);
}

static bool security_malformed(const sx_security_t *security, bool rsn)
{
    if (!valid_status(security->status) || security->status == SX_INVALID)
        return true;
    if (security->status != SX_VALID)
        return security->group_present || security->management_present ||
               security->pairwise_known || security->akm_known ||
               security->capabilities_present || security->truncated ||
               security->pairwise_count != 0U ||
               security->akm_count != 0U || security->pmf_capable ||
               security->pmf_required ||
               !bytes_zero(security->group, sizeof(security->group)) ||
               !bytes_zero(security->management,
                           sizeof(security->management)) ||
               !bytes_zero(security->pairwise,
                           sizeof(security->pairwise)) ||
               !bytes_zero(security->akm, sizeof(security->akm));
    if (security->truncated || (!rsn && security->capabilities_present) ||
        (security->capabilities_present && security->pmf_required &&
         !security->pmf_capable))
        return true;
    if (!security->group_present &&
        !bytes_zero(security->group, sizeof(security->group))) return true;
    if (!security->management_present &&
        !bytes_zero(security->management,
                    sizeof(security->management))) return true;
    if (!security->pairwise_known) {
        if (security->pairwise_count != 0U ||
            !bytes_zero(security->pairwise, sizeof(security->pairwise)))
            return true;
    } else if (security->pairwise_count == 0U ||
               security->pairwise_count > SX_SELECTORS ||
               !bytes_zero(security->pairwise + security->pairwise_count,
                           (SX_SELECTORS - security->pairwise_count) *
                           sizeof(security->pairwise[0]))) {
        return true;
    }
    if (!security->akm_known) {
        if (security->akm_count != 0U ||
            !bytes_zero(security->akm, sizeof(security->akm))) return true;
    } else if (security->akm_count == 0U ||
               security->akm_count > SX_SELECTORS ||
               !bytes_zero(security->akm + security->akm_count,
                           (SX_SELECTORS - security->akm_count) *
                           sizeof(security->akm[0]))) {
        return true;
    }
    return !security->capabilities_present &&
           (security->pmf_capable || security->pmf_required);
}

static bool wps_malformed(const sx_wps_t *wps)
{
    if (!valid_status(wps->status) || wps->status == SX_INVALID) return true;
    if (wps->status != SX_VALID)
        return wps->present || wps->truncated || wps->state != -1 ||
               wps->config_methods != -1 || wps->setup_locked != -1 ||
               wps->selected_registrar != -1 ||
               !text_valid(&wps->manufacturer) ||
               !text_valid(&wps->model_name) ||
               !text_valid(&wps->model_number) ||
               !text_valid(&wps->device_name);
    return !wps->present || wps->truncated ||
           (wps->state != -1 && wps->state != 1 && wps->state != 2) ||
           wps->config_methods < -1 ||
           wps->config_methods > UINT16_MAX ||
           wps->setup_locked < -1 || wps->setup_locked > 1 ||
           wps->selected_registrar < -1 || wps->selected_registrar > 1 ||
           !text_valid(&wps->manufacturer) ||
           !text_valid(&wps->model_name) || !text_valid(&wps->model_number) ||
           !text_valid(&wps->device_name);
}

static bool rsnxe_malformed(const sx_rsnxe_t *rsnxe)
{
    if (!valid_status(rsnxe->status) || rsnxe->status == SX_INVALID)
        return true;
    if (rsnxe->status != SX_VALID)
        return rsnxe->present || rsnxe->truncated || rsnxe->len != 0U ||
               !bytes_zero(rsnxe->bytes, sizeof(rsnxe->bytes));
    return !rsnxe->present || rsnxe->truncated || rsnxe->len == 0U ||
           rsnxe->len > SX_RSNXE_BYTES ||
           !bytes_zero(rsnxe->bytes + rsnxe->len,
                       sizeof(rsnxe->bytes) - rsnxe->len);
}

static bool country_malformed(const sx_country_t *country)
{
    if (!valid_status(country->status) || country->status == SX_INVALID)
        return true;
    if (country->status != SX_VALID)
        return !bytes_zero(country->code, sizeof(country->code));
    return country->code[0] < 'A' || country->code[0] > 'Z' ||
           country->code[1] < 'A' || country->code[1] > 'Z' ||
           (country->code[2] != ' ' && country->code[2] != 'I' &&
            country->code[2] != 'O');
}

static bool observation_malformed(const sx_observation_t *observation)
{
    if (observation == NULL || !observation->complete ||
        (observation->source != SX_BEACON &&
         observation->source != SX_PROBE_RESP) ||
        !valid_bssid(observation->bssid) || observation->ssid_len > 32U ||
        (!observation->ssid_present &&
         (observation->ssid_len != 0U ||
          !bytes_zero(observation->ssid, sizeof(observation->ssid)))) ||
        (observation->ssid_present &&
         !bytes_zero(observation->ssid + observation->ssid_len,
                     sizeof(observation->ssid) - observation->ssid_len)) ||
        observation->privacy < -1 || observation->privacy > 1 ||
        security_malformed(&observation->rsn, true) ||
        security_malformed(&observation->wpa, false) ||
        wps_malformed(&observation->wps) ||
        rsnxe_malformed(&observation->rsnxe) ||
        country_malformed(&observation->country))
        return true;
    return false;
}

static void copy_text(sx_text_t *out, const sx_text_t *in)
{
    memset(out, 0, sizeof(*out));
    out->present = in->present;
    out->truncated = in->truncated;
    out->len = in->present ? in->len : 0U;
    if (out->len != 0U) memcpy(out->bytes, in->bytes, out->len);
}

static void copy_security(sx_security_t *out, const sx_security_t *in)
{
    memset(out, 0, sizeof(*out));
    out->status = in->status;
    if (in->status != SX_VALID) return;
    out->group_present = in->group_present;
    if (in->group_present) memcpy(out->group, in->group, 4);
    out->management_present = in->management_present;
    if (in->management_present) memcpy(out->management, in->management, 4);
    out->pairwise_known = in->pairwise_known;
    out->pairwise_count = in->pairwise_known ? in->pairwise_count : 0U;
    if (out->pairwise_count != 0U)
        memcpy(out->pairwise, in->pairwise,
               (size_t)out->pairwise_count * sizeof(out->pairwise[0]));
    out->akm_known = in->akm_known;
    out->akm_count = in->akm_known ? in->akm_count : 0U;
    if (out->akm_count != 0U)
        memcpy(out->akm, in->akm,
               (size_t)out->akm_count * sizeof(out->akm[0]));
    out->capabilities_present = in->capabilities_present;
    if (in->capabilities_present) {
        out->pmf_capable = in->pmf_capable;
        out->pmf_required = in->pmf_required;
    }
}

static void copy_wps(sx_wps_t *out, const sx_wps_t *in)
{
    memset(out, 0, sizeof(*out));
    out->state = out->config_methods = out->setup_locked =
        out->selected_registrar = -1;
    out->status = in->status;
    if (in->status != SX_VALID) return;
    out->present = in->present;
    out->truncated = in->truncated;
    out->state = in->state;
    out->config_methods = in->config_methods;
    out->setup_locked = in->setup_locked;
    out->selected_registrar = in->selected_registrar;
    copy_text(&out->manufacturer, &in->manufacturer);
    copy_text(&out->model_name, &in->model_name);
    copy_text(&out->model_number, &in->model_number);
    copy_text(&out->device_name, &in->device_name);
}

static void copy_rsnxe(sx_rsnxe_t *out, const sx_rsnxe_t *in)
{
    memset(out, 0, sizeof(*out));
    out->status = in->status;
    if (in->status != SX_VALID) return;
    out->present = in->present;
    out->truncated = in->truncated;
    out->len = in->len;
    if (out->len != 0U) memcpy(out->bytes, in->bytes, out->len);
}

static void copy_country(sx_country_t *out, const sx_country_t *in)
{
    memset(out, 0, sizeof(*out));
    out->status = in->status;
    if (in->status == SX_VALID) memcpy(out->code, in->code, 3);
}

bool wifi_trust_profile_from_observation(const sx_observation_t *observation,
                                         uint8_t channel,
                                         uint64_t observed_us,
                                         wifi_trust_profile_t *out)
{
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (observation_malformed(observation) || channel > 233U) return false;
    memcpy(out->bssid, observation->bssid, 6);
    out->ssid_status = observation->ssid_present ? SX_VALID : SX_ABSENT;
    out->ssid_len = observation->ssid_present ? observation->ssid_len : 0U;
    if (out->ssid_len != 0U)
        memcpy(out->ssid, observation->ssid, out->ssid_len);
    out->source = observation->source;
    out->privacy = observation->privacy;
    copy_security(&out->rsn, &observation->rsn);
    copy_security(&out->wpa, &observation->wpa);
    copy_rsnxe(&out->rsnxe, &observation->rsnxe);
    copy_wps(&out->wps, &observation->wps);
    copy_country(&out->country, &observation->country);
    out->channel = channel;
    out->observed_us = observed_us;
    return true;
}

static void merge_security(sx_security_t *out, const sx_security_t *in)
{
    if (in->status == SX_UNKNOWN) return;
    if (in->status != SX_VALID || out->status != SX_VALID) {
        *out = *in;
        return;
    }
    sx_security_t merged = *in;
    if (!in->group_present && out->group_present) {
        memcpy(merged.group, out->group, 4);
        merged.group_present = true;
    }
    if (!in->management_present && out->management_present) {
        memcpy(merged.management, out->management, 4);
        merged.management_present = true;
    }
    if (!in->pairwise_known && out->pairwise_known) {
        memcpy(merged.pairwise, out->pairwise, sizeof(merged.pairwise));
        merged.pairwise_count = out->pairwise_count;
        merged.pairwise_known = true;
    }
    if (!in->akm_known && out->akm_known) {
        memcpy(merged.akm, out->akm, sizeof(merged.akm));
        merged.akm_count = out->akm_count;
        merged.akm_known = true;
    }
    if (!in->capabilities_present && out->capabilities_present) {
        merged.capabilities_present = true;
        merged.pmf_capable = out->pmf_capable;
        merged.pmf_required = out->pmf_required;
    }
    *out = merged;
}

static void merge_wps(sx_wps_t *out, const sx_wps_t *in)
{
    if (in->status == SX_UNKNOWN) return;
    if (in->status != SX_VALID || out->status != SX_VALID) {
        *out = *in;
        return;
    }
    sx_wps_t merged = *in;
    if (in->state < 0) merged.state = out->state;
    if (in->config_methods < 0) merged.config_methods = out->config_methods;
    if (in->setup_locked < 0) merged.setup_locked = out->setup_locked;
    if (in->selected_registrar < 0)
        merged.selected_registrar = out->selected_registrar;
    if (!in->manufacturer.present && out->manufacturer.present)
        merged.manufacturer = out->manufacturer;
    if (!in->model_name.present && out->model_name.present)
        merged.model_name = out->model_name;
    if (!in->model_number.present && out->model_number.present)
        merged.model_number = out->model_number;
    if (!in->device_name.present && out->device_name.present)
        merged.device_name = out->device_name;
    *out = merged;
}

static void merge_profile(wifi_trust_profile_t *out,
                          const wifi_trust_profile_t *in)
{
    if (in->ssid_status != SX_UNKNOWN) {
        out->ssid_status = in->ssid_status;
        out->ssid_len = in->ssid_status == SX_VALID ? in->ssid_len : 0U;
        memset(out->ssid, 0, sizeof(out->ssid));
        if (out->ssid_len != 0U) memcpy(out->ssid, in->ssid, out->ssid_len);
    }
    if (in->privacy >= 0) out->privacy = in->privacy;
    merge_security(&out->rsn, &in->rsn);
    merge_security(&out->wpa, &in->wpa);
    if (in->rsnxe.status != SX_UNKNOWN) out->rsnxe = in->rsnxe;
    merge_wps(&out->wps, &in->wps);
    if (in->country.status != SX_UNKNOWN) out->country = in->country;
    if (in->channel != 0U) out->channel = in->channel;
    out->observed_us = in->observed_us;
}

static bool selector_multiset_equal(const uint8_t left[SX_SELECTORS][4],
                                    uint8_t left_count,
                                    const uint8_t right[SX_SELECTORS][4],
                                    uint8_t right_count)
{
    if (left_count != right_count) return false;
    bool used[SX_SELECTORS] = {0};
    for (size_t i = 0; i < left_count; ++i) {
        bool found = false;
        for (size_t j = 0; j < right_count; ++j) {
            if (!used[j] && memcmp(left[i], right[j], 4) == 0) {
                used[j] = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

static bool status_conflict(sx_status_t left, sx_status_t right)
{
    return left != SX_UNKNOWN && right != SX_UNKNOWN && left != right;
}

static bool ssid_conflict(const wifi_trust_profile_t *left,
                          const wifi_trust_profile_t *right)
{
    if (status_conflict(left->ssid_status, right->ssid_status)) return true;
    return left->ssid_status == SX_VALID && right->ssid_status == SX_VALID &&
           (left->ssid_len != right->ssid_len ||
            memcmp(left->ssid, right->ssid, left->ssid_len) != 0);
}

static bool security_akm_conflict(const sx_security_t *left,
                                  const sx_security_t *right)
{
    if (status_conflict(left->status, right->status)) return true;
    if (left->status != SX_VALID || right->status != SX_VALID ||
        !left->akm_known || !right->akm_known) return false;
    return !selector_multiset_equal(left->akm, left->akm_count,
                                    right->akm, right->akm_count);
}

static bool security_cipher_conflict(const sx_security_t *left,
                                     const sx_security_t *right)
{
    if (status_conflict(left->status, right->status)) return true;
    if (left->status != SX_VALID || right->status != SX_VALID) return false;
    if (left->group_present && right->group_present &&
        memcmp(left->group, right->group, 4) != 0) return true;
    if (left->management_present && right->management_present &&
        memcmp(left->management, right->management, 4) != 0) return true;
    return left->pairwise_known && right->pairwise_known &&
           !selector_multiset_equal(left->pairwise, left->pairwise_count,
                                    right->pairwise, right->pairwise_count);
}

static int32_t pmf_mode(const sx_security_t *security)
{
    return security->pmf_required ? 2 : security->pmf_capable ? 1 : 0;
}

static bool pmf_conflict(const wifi_trust_profile_t *left,
                         const wifi_trust_profile_t *right)
{
    if (left->rsn.status == SX_UNKNOWN || right->rsn.status == SX_UNKNOWN)
        return false;
    if ((left->rsn.status == SX_VALID &&
         !left->rsn.capabilities_present) ||
        (right->rsn.status == SX_VALID &&
         !right->rsn.capabilities_present))
        return false;
    int32_t left_mode = left->rsn.status == SX_VALID ?
        pmf_mode(&left->rsn) : 0;
    int32_t right_mode = right->rsn.status == SX_VALID ?
        pmf_mode(&right->rsn) : 0;
    return left_mode != right_mode;
}

static bool rsnxe_conflict(const sx_rsnxe_t *left,
                           const sx_rsnxe_t *right)
{
    if (status_conflict(left->status, right->status)) return true;
    return left->status == SX_VALID && right->status == SX_VALID &&
           (left->len != right->len ||
            memcmp(left->bytes, right->bytes, left->len) != 0);
}

static bool wps_enabled(const sx_wps_t *wps)
{
    return wps->status == SX_VALID && wps->present;
}

static bool wps_conflict(const sx_wps_t *left, const sx_wps_t *right)
{
    if (status_conflict(left->status, right->status)) return true;
    return left->status == SX_VALID && right->status == SX_VALID &&
           wps_enabled(left) != wps_enabled(right);
}

static bool wps_lock_conflict(const sx_wps_t *left, const sx_wps_t *right)
{
    return left->status == SX_VALID && right->status == SX_VALID &&
           left->setup_locked >= 0 && right->setup_locked >= 0 &&
           left->setup_locked != right->setup_locked;
}

static bool wps_number_conflict(const sx_wps_t *left, int left_value,
                                const sx_wps_t *right, int right_value)
{
    return left->status == SX_VALID && right->status == SX_VALID &&
           left_value >= 0 && right_value >= 0 && left_value != right_value;
}

static bool wps_text_conflict(const sx_wps_t *left,
                              const sx_text_t *left_text,
                              const sx_wps_t *right,
                              const sx_text_t *right_text)
{
    return left->status == SX_VALID && right->status == SX_VALID &&
           left_text->present && right_text->present &&
           (left_text->len != right_text->len ||
            memcmp(left_text->bytes, right_text->bytes,
                   left_text->len) != 0);
}

static bool country_conflict(const sx_country_t *left,
                             const sx_country_t *right)
{
    if (status_conflict(left->status, right->status)) return true;
    return left->status == SX_VALID && right->status == SX_VALID &&
           memcmp(left->code, right->code, 3) != 0;
}

static wifi_trust_field_mask_t conflict_mask(
    const wifi_trust_profile_t *beacon, const wifi_trust_profile_t *probe)
{
    wifi_trust_field_mask_t mask = 0;
    if (ssid_conflict(beacon, probe))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_SSID);
    if (beacon->privacy >= 0 && probe->privacy >= 0 &&
        beacon->privacy != probe->privacy)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_PRIVACY);
    if (security_akm_conflict(&beacon->rsn, &probe->rsn) ||
        security_akm_conflict(&beacon->wpa, &probe->wpa))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_AKM);
    if (security_cipher_conflict(&beacon->rsn, &probe->rsn) ||
        security_cipher_conflict(&beacon->wpa, &probe->wpa))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_CIPHER);
    if (pmf_conflict(beacon, probe))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_PMF);
    if (rsnxe_conflict(&beacon->rsnxe, &probe->rsnxe))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_RSNXE);
    if (wps_conflict(&beacon->wps, &probe->wps))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS);
    if (wps_number_conflict(&beacon->wps, beacon->wps.state,
                            &probe->wps, probe->wps.state))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_STATE);
    if (wps_number_conflict(&beacon->wps, beacon->wps.config_methods,
                            &probe->wps, probe->wps.config_methods))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_CONFIG_METHODS);
    if (wps_lock_conflict(&beacon->wps, &probe->wps))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_LOCK);
    if (wps_number_conflict(&beacon->wps, beacon->wps.selected_registrar,
                            &probe->wps, probe->wps.selected_registrar))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR);
    if (wps_text_conflict(&beacon->wps, &beacon->wps.manufacturer,
                          &probe->wps, &probe->wps.manufacturer))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_MANUFACTURER);
    if (wps_text_conflict(&beacon->wps, &beacon->wps.model_name,
                          &probe->wps, &probe->wps.model_name))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_MODEL_NAME);
    if (wps_text_conflict(&beacon->wps, &beacon->wps.model_number,
                          &probe->wps, &probe->wps.model_number))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_MODEL_NUMBER);
    if (wps_text_conflict(&beacon->wps, &beacon->wps.device_name,
                          &probe->wps, &probe->wps.device_name))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_DEVICE_NAME);
    if (country_conflict(&beacon->country, &probe->country))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_COUNTRY);
    if (beacon->channel != 0U && probe->channel != 0U &&
        beacon->channel != probe->channel)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_CHANNEL);
    return mask;
}

void wifi_trust_table_init(wifi_trust_table_t *table)
{
    if (table != NULL) memset(table, 0, sizeof(*table));
}

static wifi_trust_ingest_result_t builder_observe_profile(
    wifi_trust_builder_t *builder, const wifi_trust_profile_t *incoming,
    wifi_trust_field_mask_t *new_conflicts,
    wifi_trust_builder_t *updated)
{
    if (builder == NULL || incoming == NULL || updated == NULL)
        return WIFI_TRUST_INGEST_MALFORMED;
    if (builder->used && memcmp(builder->bssid, incoming->bssid, 6) != 0)
        return WIFI_TRUST_INGEST_UNRELATED;
    wifi_trust_profile_t *slot = incoming->source == SX_BEACON ?
        &builder->beacon : &builder->probe;
    bool *have = incoming->source == SX_BEACON ?
        &builder->have_beacon : &builder->have_probe;
    if (builder->used && *have && incoming->observed_us < slot->observed_us)
        return WIFI_TRUST_INGEST_UNRELATED;

    *updated = *builder;
    if (!updated->used) {
        memset(updated, 0, sizeof(*updated));
        updated->used = true;
        memcpy(updated->bssid, incoming->bssid, 6);
    }
    slot = incoming->source == SX_BEACON ? &updated->beacon : &updated->probe;
    have = incoming->source == SX_BEACON ?
        &updated->have_beacon : &updated->have_probe;
    if (*have) merge_profile(slot, incoming);
    else {
        *slot = *incoming;
        *have = true;
    }
    wifi_trust_field_mask_t previous = updated->conflict_mask;
    updated->conflict_mask = updated->have_beacon && updated->have_probe ?
        conflict_mask(&updated->beacon, &updated->probe) : 0;
    *builder = *updated;
    if (new_conflicts != NULL)
        *new_conflicts = updated->conflict_mask & ~previous;
    return updated->conflict_mask != 0 ? WIFI_TRUST_INGEST_CONFLICT :
                                        WIFI_TRUST_INGEST_ACCEPTED;
}

wifi_trust_ingest_result_t wifi_trust_builder_observe(
    wifi_trust_builder_t *builder,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_field_mask_t *new_conflicts)
{
    if (new_conflicts != NULL) *new_conflicts = 0;
    if (builder == NULL || observation == NULL)
        return WIFI_TRUST_INGEST_MALFORMED;
    wifi_trust_observe_workspace_t workspace;
    if (!wifi_trust_profile_from_observation(
            observation, channel, observed_us, &workspace.incoming))
        return WIFI_TRUST_INGEST_MALFORMED;
    return builder_observe_profile(builder, &workspace.incoming,
                                   new_conflicts, &workspace.updated);
}

wifi_trust_ingest_result_t wifi_trust_table_observe_with_workspace(
    wifi_trust_table_t *table,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_builder_t **builder,
    wifi_trust_field_mask_t *new_conflicts,
    wifi_trust_observe_workspace_t *workspace)
{
    if (builder != NULL) *builder = NULL;
    if (new_conflicts != NULL) *new_conflicts = 0;
    if (table == NULL || observation == NULL || workspace == NULL)
        return WIFI_TRUST_INGEST_MALFORMED;
    if (!wifi_trust_profile_from_observation(observation, channel,
                                             observed_us,
                                             &workspace->incoming))
        return WIFI_TRUST_INGEST_MALFORMED;
    wifi_trust_builder_t *available = NULL;
    wifi_trust_builder_t *match = NULL;
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i) {
        if (!table->entries[i].used) {
            if (available == NULL) available = &table->entries[i];
        } else if (memcmp(table->entries[i].bssid,
                          workspace->incoming.bssid, 6) == 0) {
            match = &table->entries[i];
            break;
        }
    }
    if (match == NULL && available == NULL) {
        if (table->capacity_drops != UINT32_MAX) ++table->capacity_drops;
        return WIFI_TRUST_INGEST_CAPACITY;
    }
    match = match != NULL ? match : available;
    bool was_used = match->used;
    wifi_trust_ingest_result_t result = builder_observe_profile(
        match, &workspace->incoming, new_conflicts, &workspace->updated);
    if (!was_used && match->used &&
        (result == WIFI_TRUST_INGEST_ACCEPTED ||
         result == WIFI_TRUST_INGEST_CONFLICT))
        ++table->active;
    if (builder != NULL && match->used) *builder = match;
    return result;
}

wifi_trust_ingest_result_t wifi_trust_table_observe(
    wifi_trust_table_t *table,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_builder_t **builder,
    wifi_trust_field_mask_t *new_conflicts)
{
    wifi_trust_observe_workspace_t workspace;
    return wifi_trust_table_observe_with_workspace(
        table, observation, channel, observed_us, builder, new_conflicts,
        &workspace);
}

static void fill_unknown_from(wifi_trust_profile_t *out,
                              const wifi_trust_profile_t *other)
{
    if (out->ssid_status == SX_UNKNOWN && other->ssid_status != SX_UNKNOWN) {
        out->ssid_status = other->ssid_status;
        out->ssid_len = other->ssid_len;
        memcpy(out->ssid, other->ssid, sizeof(out->ssid));
    }
    if (out->privacy < 0 && other->privacy >= 0) out->privacy = other->privacy;
    if (out->rsn.status == SX_UNKNOWN) out->rsn = other->rsn;
    else if (out->rsn.status == SX_VALID && other->rsn.status == SX_VALID)
        merge_security(&out->rsn, &other->rsn);
    if (out->wpa.status == SX_UNKNOWN) out->wpa = other->wpa;
    else if (out->wpa.status == SX_VALID && other->wpa.status == SX_VALID)
        merge_security(&out->wpa, &other->wpa);
    if (out->rsnxe.status == SX_UNKNOWN) out->rsnxe = other->rsnxe;
    if (out->wps.status == SX_UNKNOWN) out->wps = other->wps;
    else if (out->wps.status == SX_VALID && other->wps.status == SX_VALID)
        merge_wps(&out->wps, &other->wps);
    if (out->country.status == SX_UNKNOWN) out->country = other->country;
    if (out->channel == 0U) out->channel = other->channel;
}

bool wifi_trust_builder_snapshot(const wifi_trust_builder_t *builder,
                                 wifi_trust_profile_t *out)
{
    if (builder == NULL || out == NULL || !builder->used ||
        (!builder->have_beacon && !builder->have_probe) ||
        builder->conflict_mask != 0)
        return false;
    if (builder->have_beacon && !builder->have_probe) {
        *out = builder->beacon;
        return true;
    }
    if (!builder->have_beacon) {
        *out = builder->probe;
        return true;
    }
    const wifi_trust_profile_t *chosen =
        builder->probe.observed_us > builder->beacon.observed_us ?
        &builder->probe : &builder->beacon;
    const wifi_trust_profile_t *other = chosen == &builder->probe ?
        &builder->beacon : &builder->probe;
    *out = *chosen;
    fill_unknown_from(out, other);
    return true;
}

static void value_clear(wifi_trust_event_value_t *value, sx_status_t status)
{
    memset(value, 0, sizeof(*value));
    value->status = status;
}

static void value_append(wifi_trust_event_value_t *value,
                         const void *bytes, size_t length)
{
    if (length > WIFI_TRUST_EVENT_VALUE_BYTES - value->len) return;
    memcpy(value->bytes + value->len, bytes, length);
    value->len = (uint8_t)(value->len + length);
}

static void value_security_akm(wifi_trust_event_value_t *value,
                               const wifi_trust_profile_t *profile)
{
    value_clear(value, SX_VALID);
    const sx_security_t *items[] = {&profile->rsn, &profile->wpa};
    for (size_t i = 0; i < 2; ++i) {
        bool known = items[i]->status == SX_VALID && items[i]->akm_known;
        uint8_t header[3] = {(uint8_t)items[i]->status,
                             known ? 1U : 0U,
                             known ? items[i]->akm_count : 0U};
        value_append(value, header, sizeof(header));
        if (known)
            value_append(value, items[i]->akm,
                         (size_t)items[i]->akm_count * 4U);
    }
}

static void value_security_cipher(wifi_trust_event_value_t *value,
                                  const wifi_trust_profile_t *profile)
{
    value_clear(value, SX_VALID);
    const sx_security_t *items[] = {&profile->rsn, &profile->wpa};
    for (size_t i = 0; i < 2; ++i) {
        bool valid = items[i]->status == SX_VALID;
        bool group = valid && items[i]->group_present;
        bool pairwise = valid && items[i]->pairwise_known;
        uint8_t header[3] = {(uint8_t)items[i]->status,
                             group ? 1U : 0U,
                             pairwise ?
                                items[i]->pairwise_count : 0U};
        value_append(value, header, sizeof(header));
        if (group) value_append(value, items[i]->group, 4);
        if (pairwise)
            value_append(value, items[i]->pairwise,
                         (size_t)items[i]->pairwise_count * 4U);
        uint8_t management = valid && items[i]->management_present ? 1U : 0U;
        value_append(value, &management, 1);
        if (items[i]->management_present)
            value_append(value, items[i]->management, 4);
    }
}

static void value_for_field(wifi_trust_event_value_t *value,
                            const wifi_trust_profile_t *profile,
                            wifi_trust_field_t field)
{
    value_clear(value, SX_UNKNOWN);
    if (profile == NULL) return;
    switch (field) {
    case WIFI_TRUST_FIELD_NONE:
    case WIFI_TRUST_FIELD_ADVERTISEMENT:
        break;
    case WIFI_TRUST_FIELD_SSID:
        value->status = profile->ssid_status;
        if (profile->ssid_status == SX_VALID) {
            value->len = profile->ssid_len;
            memcpy(value->bytes, profile->ssid, value->len);
        }
        break;
    case WIFI_TRUST_FIELD_PRIVACY:
        value->status = profile->privacy < 0 ? SX_UNKNOWN : SX_VALID;
        value->number = profile->privacy;
        break;
    case WIFI_TRUST_FIELD_AKM:
        value_security_akm(value, profile);
        break;
    case WIFI_TRUST_FIELD_CIPHER:
        value_security_cipher(value, profile);
        break;
    case WIFI_TRUST_FIELD_PMF:
        value->status = profile->rsn.status == SX_VALID &&
                        !profile->rsn.capabilities_present ?
                        SX_UNKNOWN : profile->rsn.status;
        if (value->status == SX_VALID)
            value->number = pmf_mode(&profile->rsn);
        break;
    case WIFI_TRUST_FIELD_RSNXE:
        value->status = profile->rsnxe.status;
        if (profile->rsnxe.status == SX_VALID) {
            value->len = profile->rsnxe.len;
            memcpy(value->bytes, profile->rsnxe.bytes, value->len);
        }
        break;
    case WIFI_TRUST_FIELD_WPS:
        value->status = profile->wps.status;
        value->number = wps_enabled(&profile->wps) ? 1 : 0;
        break;
    case WIFI_TRUST_FIELD_WPS_STATE:
        value->status = profile->wps.status == SX_VALID &&
                        profile->wps.state >= 0 ? SX_VALID : SX_UNKNOWN;
        value->number = profile->wps.state;
        break;
    case WIFI_TRUST_FIELD_WPS_CONFIG_METHODS:
        value->status = profile->wps.status == SX_VALID &&
                        profile->wps.config_methods >= 0 ? SX_VALID : SX_UNKNOWN;
        value->number = profile->wps.config_methods;
        break;
    case WIFI_TRUST_FIELD_WPS_LOCK:
        value->status = profile->wps.status == SX_VALID &&
                        profile->wps.setup_locked >= 0 ? SX_VALID : SX_UNKNOWN;
        value->number = profile->wps.setup_locked;
        break;
    case WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR:
        value->status = profile->wps.status == SX_VALID &&
                        profile->wps.selected_registrar >= 0 ?
                        SX_VALID : SX_UNKNOWN;
        value->number = profile->wps.selected_registrar;
        break;
    case WIFI_TRUST_FIELD_WPS_MANUFACTURER:
    case WIFI_TRUST_FIELD_WPS_MODEL_NAME:
    case WIFI_TRUST_FIELD_WPS_MODEL_NUMBER:
    case WIFI_TRUST_FIELD_WPS_DEVICE_NAME: {
        const sx_text_t *text = field == WIFI_TRUST_FIELD_WPS_MANUFACTURER ?
            &profile->wps.manufacturer :
            field == WIFI_TRUST_FIELD_WPS_MODEL_NAME ?
            &profile->wps.model_name :
            field == WIFI_TRUST_FIELD_WPS_MODEL_NUMBER ?
            &profile->wps.model_number : &profile->wps.device_name;
        value->status = profile->wps.status == SX_VALID && text->present ?
                        SX_VALID : SX_UNKNOWN;
        if (value->status == SX_VALID) {
            value->len = text->len;
            memcpy(value->bytes, text->bytes, value->len);
        }
        break;
    }
    case WIFI_TRUST_FIELD_COUNTRY:
        value->status = profile->country.status;
        if (profile->country.status == SX_VALID) {
            value->len = 3;
            memcpy(value->bytes, profile->country.code, 3);
        }
        break;
    case WIFI_TRUST_FIELD_CHANNEL:
        value->status = profile->channel == 0U ? SX_UNKNOWN : SX_VALID;
        value->number = profile->channel;
        break;
    default:
        break;
    }
}

static void event_identity_from_profile(wifi_trust_event_t *event,
                                        const wifi_trust_profile_t *profile)
{
    if (profile == NULL) return;
    memcpy(event->bssid, profile->bssid, sizeof(event->bssid));
    event->source = profile->source == SX_BEACON ||
                    profile->source == SX_PROBE_RESP ?
                    profile->source : SX_NONE;
    event->channel = profile->channel <= 233U ? profile->channel : 0U;
    event->timestamp_us = profile->observed_us;

    bool canonical = valid_status(profile->ssid_status) &&
                     profile->ssid_status != SX_INVALID &&
                     profile->ssid_len <= sizeof(profile->ssid);
    if (canonical && profile->ssid_status == SX_VALID)
        canonical = bytes_zero(profile->ssid + profile->ssid_len,
                               sizeof(profile->ssid) - profile->ssid_len);
    else if (canonical)
        canonical = profile->ssid_len == 0U &&
                    bytes_zero(profile->ssid, sizeof(profile->ssid));
    if (!canonical) {
        event->ssid_status = SX_INVALID;
        return;
    }
    event->ssid_status = profile->ssid_status;
    event->ssid_len = profile->ssid_len;
    memcpy(event->ssid, profile->ssid, sizeof(event->ssid));
}

static void fill_event(wifi_trust_event_t *event,
                       wifi_trust_reason_t reason,
                       wifi_trust_field_t field,
                       const wifi_trust_profile_t *baseline,
                       const wifi_trust_profile_t *current)
{
    memset(event, 0, sizeof(*event));
    event->reason = reason;
    event->field = field;
    const wifi_trust_profile_t *identity = current != NULL ? current : baseline;
    event_identity_from_profile(event, identity);
    value_clear(&event->baseline, SX_UNKNOWN);
    value_clear(&event->current, SX_UNKNOWN);
    if (baseline != NULL)
        (void)wifi_trust_value_from_profile(baseline, field,
                                            &event->baseline);
    if (current != NULL)
        (void)wifi_trust_value_from_profile(current, field,
                                            &event->current);
}

static bool security_akm_changed(const sx_security_t *baseline,
                                 const sx_security_t *current)
{
    if (current->status == SX_UNKNOWN) return false;
    if (baseline->status == SX_UNKNOWN) return false;
    if (baseline->status != current->status) return true;
    if (current->status != SX_VALID || !current->akm_known ||
        !baseline->akm_known) return false;
    return !selector_multiset_equal(baseline->akm, baseline->akm_count,
                                    current->akm, current->akm_count);
}

static bool security_cipher_changed(const sx_security_t *baseline,
                                    const sx_security_t *current)
{
    if (current->status == SX_UNKNOWN || baseline->status == SX_UNKNOWN)
        return false;
    if (baseline->status != current->status) return true;
    if (current->status != SX_VALID) return false;
    if (current->group_present && baseline->group_present &&
        memcmp(current->group, baseline->group, 4) != 0) return true;
    if (current->management_present && baseline->management_present &&
        memcmp(current->management, baseline->management, 4) != 0) return true;
    return current->pairwise_known && baseline->pairwise_known &&
           !selector_multiset_equal(baseline->pairwise,
                                    baseline->pairwise_count,
                                    current->pairwise,
                                    current->pairwise_count);
}

static bool status_bytes_changed(sx_status_t baseline_status,
                                 const uint8_t *baseline, size_t baseline_len,
                                 sx_status_t current_status,
                                 const uint8_t *current, size_t current_len)
{
    if (current_status == SX_UNKNOWN || baseline_status == SX_UNKNOWN)
        return false;
    if (baseline_status != current_status) return true;
    return current_status == SX_VALID &&
           (baseline_len != current_len ||
            memcmp(baseline, current, baseline_len) != 0);
}

static bool profile_invalid(const wifi_trust_profile_t *profile)
{
    return profile == NULL || !valid_bssid(profile->bssid) ||
           (profile->source != SX_BEACON &&
            profile->source != SX_PROBE_RESP) || profile->channel > 233U ||
           profile->privacy < -1 || profile->privacy > 1 ||
           !valid_status(profile->ssid_status) ||
           profile->ssid_status == SX_INVALID || profile->ssid_len > 32U ||
           (profile->ssid_status != SX_VALID &&
            (profile->ssid_len != 0U ||
             !bytes_zero(profile->ssid, sizeof(profile->ssid)))) ||
           (profile->ssid_status == SX_VALID &&
            !bytes_zero(profile->ssid + profile->ssid_len,
                        sizeof(profile->ssid) - profile->ssid_len)) ||
           security_malformed(&profile->rsn, true) ||
           security_malformed(&profile->wpa, false) ||
           wps_malformed(&profile->wps) ||
           rsnxe_malformed(&profile->rsnxe) ||
           country_malformed(&profile->country);
}

bool wifi_trust_profile_valid(const wifi_trust_profile_t *profile)
{
    return !profile_invalid(profile);
}

bool wifi_trust_value_from_profile(const wifi_trust_profile_t *profile,
                                   wifi_trust_field_t field,
                                   wifi_trust_event_value_t *out)
{
    if (out == NULL || !wifi_trust_profile_valid(profile) ||
        (int)field < (int)WIFI_TRUST_FIELD_NONE ||
        field >= WIFI_TRUST_FIELD_COUNT)
        return false;
    wifi_trust_event_value_t value;
    value_for_field(&value, profile, field);
    *out = value;
    return true;
}

static const wifi_trust_field_t diff_field_order[] = {
    WIFI_TRUST_FIELD_SSID,
    WIFI_TRUST_FIELD_AKM,
    WIFI_TRUST_FIELD_PRIVACY,
    WIFI_TRUST_FIELD_CIPHER,
    WIFI_TRUST_FIELD_PMF,
    WIFI_TRUST_FIELD_RSNXE,
    WIFI_TRUST_FIELD_WPS,
    WIFI_TRUST_FIELD_WPS_LOCK,
    WIFI_TRUST_FIELD_COUNTRY,
    WIFI_TRUST_FIELD_CHANNEL,
};

static size_t field_mask_count(wifi_trust_field_mask_t mask)
{
    size_t count = 0U;
    while (mask != 0U) {
        count += mask & 1U;
        mask >>= 1U;
    }
    return count;
}

static wifi_trust_field_mask_t diff_field_mask(
    const wifi_trust_profile_t *baseline,
    const wifi_trust_profile_t *current)
{
    wifi_trust_field_mask_t mask = 0U;
    if (ssid_conflict(baseline, current))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_SSID);
    if (security_akm_changed(&baseline->rsn, &current->rsn) ||
        security_akm_changed(&baseline->wpa, &current->wpa))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_AKM);
    if (baseline->privacy >= 0 && current->privacy >= 0 &&
        baseline->privacy != current->privacy)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_PRIVACY);
    if (security_cipher_changed(&baseline->rsn, &current->rsn) ||
        security_cipher_changed(&baseline->wpa, &current->wpa))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_CIPHER);
    bool pmf_downgrade = false;
    if (baseline->rsn.status == SX_VALID &&
        baseline->rsn.capabilities_present &&
        (baseline->rsn.pmf_capable || baseline->rsn.pmf_required) &&
        current->rsn.status != SX_UNKNOWN) {
        if (current->rsn.status != SX_VALID) pmf_downgrade = true;
        else if (!current->rsn.capabilities_present)
            pmf_downgrade = false;
        else if (baseline->rsn.pmf_required)
            pmf_downgrade = !current->rsn.pmf_required;
        else
            pmf_downgrade = !current->rsn.pmf_capable;
    }
    if (pmf_downgrade)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_PMF);
    if (status_bytes_changed(baseline->rsnxe.status, baseline->rsnxe.bytes,
                             baseline->rsnxe.len, current->rsnxe.status,
                             current->rsnxe.bytes, current->rsnxe.len))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_RSNXE);
    if (baseline->wps.status == SX_ABSENT && wps_enabled(&current->wps))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS);
    if (baseline->wps.status == SX_VALID &&
        current->wps.status == SX_VALID &&
        baseline->wps.setup_locked >= 0 &&
        current->wps.setup_locked >= 0 &&
        baseline->wps.setup_locked != current->wps.setup_locked)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_WPS_LOCK);
    if (status_bytes_changed(baseline->country.status,
                             baseline->country.code, 3,
                             current->country.status,
                             current->country.code, 3))
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_COUNTRY);
    if (baseline->channel != 0U && current->channel != 0U &&
        baseline->channel != current->channel)
        mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_CHANNEL);
    return mask;
}

static wifi_trust_reason_t diff_reason(wifi_trust_field_t field)
{
    switch (field) {
    case WIFI_TRUST_FIELD_SSID: return WIFI_TRUST_SSID_CHANGED;
    case WIFI_TRUST_FIELD_AKM: return WIFI_TRUST_AKM_CHANGED;
    case WIFI_TRUST_FIELD_PRIVACY:
    case WIFI_TRUST_FIELD_CIPHER: return WIFI_TRUST_CIPHER_CHANGED;
    case WIFI_TRUST_FIELD_PMF: return WIFI_TRUST_PMF_DOWNGRADE;
    case WIFI_TRUST_FIELD_RSNXE: return WIFI_TRUST_RSNXE_CHANGED;
    case WIFI_TRUST_FIELD_WPS: return WIFI_TRUST_WPS_ENABLED;
    case WIFI_TRUST_FIELD_WPS_LOCK: return WIFI_TRUST_WPS_LOCK_CHANGED;
    case WIFI_TRUST_FIELD_COUNTRY: return WIFI_TRUST_COUNTRY_CHANGED;
    case WIFI_TRUST_FIELD_CHANNEL: return WIFI_TRUST_CHANNEL_CHANGED;
    default: return WIFI_TRUST_NO_CHANGE;
    }
}

size_t wifi_trust_diff(const wifi_trust_profile_t *baseline,
                       const wifi_trust_profile_t *current,
                       wifi_trust_event_t *events, size_t capacity)
{
    if (current == NULL) return 0U;
    bool current_invalid = profile_invalid(current);
    bool baseline_invalid = baseline != NULL && profile_invalid(baseline);
    if (current_invalid || baseline_invalid) {
        if (events == NULL || capacity < 1U) return 1U;
        fill_event(events, WIFI_TRUST_MALFORMED_OBSERVATION,
                   WIFI_TRUST_FIELD_ADVERTISEMENT, baseline, current);
        events[0].baseline.status = baseline == NULL ? SX_UNKNOWN :
                                    baseline_invalid ? SX_INVALID : SX_VALID;
        events[0].current.status = current_invalid ? SX_INVALID : SX_VALID;
        return 1U;
    }
    if (baseline == NULL || memcmp(baseline->bssid, current->bssid, 6) != 0) {
        if (events == NULL || capacity < 1U) return 1U;
        fill_event(events, WIFI_TRUST_NEW_BSSID, WIFI_TRUST_FIELD_NONE,
                   baseline, current);
        return 1U;
    }
    wifi_trust_field_mask_t changes = diff_field_mask(baseline, current);
    size_t count = field_mask_count(changes);
    if (count == 0U || events == NULL || capacity < count) return count;
    size_t written = 0U;
    for (size_t i = 0U;
         i < sizeof(diff_field_order) / sizeof(diff_field_order[0]); ++i) {
        wifi_trust_field_t field = diff_field_order[i];
        if ((changes & WIFI_TRUST_FIELD_MASK(field)) == 0U) continue;
        fill_event(&events[written++], diff_reason(field), field,
                   baseline, current);
    }
    return count;
}

size_t wifi_trust_builder_conflict_events(
    const wifi_trust_builder_t *builder,
    wifi_trust_event_t *events, size_t capacity)
{
    if (builder == NULL || !builder->used || !builder->have_beacon ||
        !builder->have_probe || builder->conflict_mask == 0)
        return 0;
    if (!wifi_trust_profile_valid(&builder->beacon) ||
        !wifi_trust_profile_valid(&builder->probe) ||
        builder->beacon.source != SX_BEACON ||
        builder->probe.source != SX_PROBE_RESP ||
        memcmp(builder->bssid, builder->beacon.bssid,
               sizeof(builder->bssid)) != 0 ||
        memcmp(builder->bssid, builder->probe.bssid,
               sizeof(builder->bssid)) != 0)
        return 0;
    size_t count = 0U;
    for (wifi_trust_field_t field = WIFI_TRUST_FIELD_SSID;
         field < WIFI_TRUST_FIELD_COUNT; ++field)
        if ((builder->conflict_mask & WIFI_TRUST_FIELD_MASK(field)) != 0U)
            ++count;
    if (events == NULL || capacity < count) return count;
    size_t written = 0U;
    for (wifi_trust_field_t field = WIFI_TRUST_FIELD_SSID;
         field < WIFI_TRUST_FIELD_COUNT; ++field) {
        if ((builder->conflict_mask & WIFI_TRUST_FIELD_MASK(field)) == 0)
            continue;
        fill_event(&events[written++], WIFI_TRUST_ADVERTISEMENT_CONFLICT,
                   field, &builder->beacon, &builder->probe);
    }
    return count;
}

size_t wifi_trust_malformed_events(const sx_observation_t *observation,
                                   uint8_t channel, uint64_t observed_us,
                                   wifi_trust_event_t *events,
                                   size_t capacity)
{
    if (observation == NULL) return 0;
    if (!observation_malformed(observation) && channel <= 233U) return 0;
    if (events == NULL || capacity < 1U) return 1;
    memset(events, 0, sizeof(*events));
    events->reason = WIFI_TRUST_MALFORMED_OBSERVATION;
    events->field = WIFI_TRUST_FIELD_ADVERTISEMENT;
    memcpy(events->bssid, observation->bssid, sizeof(events->bssid));
    events->source = observation->source == SX_BEACON ||
                     observation->source == SX_PROBE_RESP ?
                     observation->source : SX_NONE;
    events->channel = channel <= 233U ? channel : 0U;
    bool ssid_canonical = observation->ssid_len <=
                          sizeof(observation->ssid);
    if (ssid_canonical && observation->ssid_present)
        ssid_canonical = bytes_zero(
            observation->ssid + observation->ssid_len,
            sizeof(observation->ssid) - observation->ssid_len);
    else if (ssid_canonical)
        ssid_canonical = observation->ssid_len == 0U &&
                         bytes_zero(observation->ssid,
                                    sizeof(observation->ssid));
    if (ssid_canonical) {
        events->ssid_status = observation->ssid_present ?
                              SX_VALID : SX_ABSENT;
        events->ssid_len = observation->ssid_len;
        memcpy(events->ssid, observation->ssid, sizeof(events->ssid));
    } else {
        events->ssid_status = SX_INVALID;
    }
    events->current.status = SX_INVALID;
    events->current.number = events->channel;
    events->timestamp_us = observed_us;
    return 1;
}
