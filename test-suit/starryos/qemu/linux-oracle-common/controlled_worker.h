#ifndef STARRY_LINUX_ORACLE_CONTROLLED_WORKER_H
#define STARRY_LINUX_ORACLE_CONTROLLED_WORKER_H

#include <pthread.h>
#include <stdatomic.h>

enum controlled_worker_phase {
    CONTROLLED_WORKER_IDLE,
    CONTROLLED_WORKER_ENTERED,
    CONTROLLED_WORKER_COMPLETED,
};

enum controlled_worker_status {
    CONTROLLED_WORKER_OK,
    CONTROLLED_WORKER_COMPLETED_EARLY,
    CONTROLLED_WORKER_COMPLETION_TIMEOUT,
    CONTROLLED_WORKER_PTHREAD_ERROR,
    CONTROLLED_WORKER_CLOCK_ERROR,
    CONTROLLED_WORKER_SLEEP_ERROR,
};

struct controlled_worker {
    pthread_t thread;
    atomic_int phase;
};

void controlled_worker_initialize(struct controlled_worker *worker);
enum controlled_worker_status
controlled_worker_start(struct controlled_worker *worker,
                        void *(*entry)(void *), void *argument);
void controlled_worker_publish_entered(struct controlled_worker *worker);
void controlled_worker_publish_completed(struct controlled_worker *worker);
enum controlled_worker_status
controlled_worker_observe_pending(struct controlled_worker *worker);
enum controlled_worker_status
controlled_worker_wait_for_completion(struct controlled_worker *worker);
enum controlled_worker_status
controlled_worker_join(struct controlled_worker *worker);

#endif
