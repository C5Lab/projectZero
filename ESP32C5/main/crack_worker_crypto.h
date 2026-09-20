#ifndef CRACK_WORKER_CRYPTO_H
#define CRACK_WORKER_CRYPTO_H

#include "crack_worker_core.h"

typedef bool (*crack_worker_checkpoint_fn)(void *context);

/* Returns a matching record index, -1 for no match, -2 on a crypto/input
 * error, and -3 when the checkpoint requests cancellation. */
int crack_worker_verify_candidate(const char *password,
                                  const crack_worker_hccapx_t *records,
                                  size_t record_count,
                                  crack_worker_checkpoint_fn checkpoint,
                                  void *checkpoint_context);

#endif
