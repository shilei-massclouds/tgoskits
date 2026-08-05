#ifndef STARRY_LINUX_ORACLE_CONTROLLED_WORKER_H
#define STARRY_LINUX_ORACLE_CONTROLLED_WORKER_H

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/types.h>

#define CONTROLLED_WORKER_COUNT 2

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
    CONTROLLED_WORKER_SIGNAL_ERROR,
    CONTROLLED_WORKER_CLEANUP_ERROR,
};

struct controlled_worker {
    pthread_t thread;
    atomic_int phase;
    atomic_int tid;
    atomic_uint completion_ordinal;
    atomic_uint *completion_counter;
    int started;
};

struct controlled_workers {
    struct controlled_worker slots[CONTROLLED_WORKER_COUNT];
    atomic_uint next_completion_ordinal;
};

typedef int (*controlled_worker_cleanup_fn)(void *argument);

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
pid_t controlled_worker_tid(const struct controlled_worker *worker);
unsigned int
controlled_worker_completion_ordinal(const struct controlled_worker *worker);
enum controlled_worker_status
controlled_worker_send_signal(struct controlled_worker *worker, int signal_number);

void controlled_workers_initialize(struct controlled_workers *workers);
struct controlled_worker *
controlled_workers_actor(struct controlled_workers *workers, int actor);
enum controlled_worker_status
controlled_workers_observe_all_pending(struct controlled_workers *workers);
enum controlled_worker_status
controlled_workers_wait_for_all(struct controlled_workers *workers);
enum controlled_worker_status
controlled_workers_wait_for_next(struct controlled_workers *workers,
                                 unsigned int completed_actor_mask,
                                 int *completed_actor);
enum controlled_worker_status
controlled_workers_join_all(struct controlled_workers *workers);
enum controlled_worker_status
controlled_workers_cleanup(struct controlled_workers *workers,
                           controlled_worker_cleanup_fn cleanup,
                           void *argument);

#endif
