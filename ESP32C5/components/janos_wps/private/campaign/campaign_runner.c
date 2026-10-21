#include "campaign_runner.h"

campaign_run_result_t campaign_run(unsigned start_index, unsigned requested_count,
                                   unsigned total_candidates,
                                   campaign_attempt_fn attempt, void *context) {
    campaign_run_result_t result = {
        CAMPAIGN_DECISION_INVALID, 0, WPS_SESSION_FATAL, start_index
    };
    if (!attempt || requested_count < 1U || requested_count > 3U ||
        start_index >= total_candidates) return result;

    unsigned budget = total_candidates - start_index;
    if (budget > requested_count) budget = requested_count;
    for (unsigned i = 0; i < budget; ++i) {
        result.last_result = attempt(result.resume_index, context);
        ++result.attempt_count;
        result.decision = campaign_decide(result.last_result);
        if (result.decision != CAMPAIGN_DECISION_ADVANCE) return result;
        ++result.resume_index;
    }
    result.decision = CAMPAIGN_DECISION_EXHAUSTED;
    return result;
}
