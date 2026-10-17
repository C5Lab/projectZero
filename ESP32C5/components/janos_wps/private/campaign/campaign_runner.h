#pragma once

#include "campaign_policy.h"

typedef wps_session_result_t (*campaign_attempt_fn)(unsigned index, void *context);

typedef struct {
    campaign_decision_t decision;
    unsigned attempt_count;
    /* WPS_SESSION_FATAL is a sentinel when attempt_count == 0. */
    wps_session_result_t last_result;
    unsigned resume_index;
} campaign_run_result_t;

/* Count must be 1..3. Only PIN_REJECTED advances resume_index; all other
 * session results terminate at the current candidate (including success).
 * Exhaustion is distinct from invalid arguments. Neither invokes a callback
 * beyond the clipped budget, and invalid arguments invoke no callbacks. */
campaign_run_result_t campaign_run(unsigned start_index, unsigned requested_count,
                                   unsigned total_candidates,
                                   campaign_attempt_fn attempt, void *context);
