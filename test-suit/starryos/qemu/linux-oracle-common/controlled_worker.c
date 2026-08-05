#include "controlled_worker.h"

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PENDING_GUARD_NANOSECONDS UINT64_C(50000000)
#define COMPLETION_TIMEOUT_NANOSECONDS UINT64_C(5000000000)
#define WAIT_POLL_NANOSECONDS 1000000L

static enum controlled_worker_status monotonic_nanoseconds(uint64_t *value)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
        now.tv_nsec < 0)
        return CONTROLLED_WORKER_CLOCK_ERROR;
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
             (uint64_t)now.tv_nsec;
    return CONTROLLED_WORKER_OK;
}

static enum controlled_worker_status sleep_wait_interval(void)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = WAIT_POLL_NANOSECONDS};

    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR)
            return CONTROLLED_WORKER_SLEEP_ERROR;
    }
    return CONTROLLED_WORKER_OK;
}

static enum controlled_worker_status
wait_for_phase(struct controlled_worker *worker,
               enum controlled_worker_phase target,
               uint64_t timeout_nanoseconds)
{
    enum controlled_worker_status status;
    uint64_t started;

    status = monotonic_nanoseconds(&started);
    if (status != CONTROLLED_WORKER_OK)
        return status;
    for (;;) {
        uint64_t now;

        if (atomic_load_explicit(&worker->phase, memory_order_acquire) >=
            (int)target)
            return CONTROLLED_WORKER_OK;
        status = monotonic_nanoseconds(&now);
        if (status != CONTROLLED_WORKER_OK)
            return status;
        if (now - started >= timeout_nanoseconds)
            return CONTROLLED_WORKER_COMPLETION_TIMEOUT;
        status = sleep_wait_interval();
        if (status != CONTROLLED_WORKER_OK)
            return status;
    }
}

void controlled_worker_initialize(struct controlled_worker *worker)
{
    atomic_init(&worker->phase, CONTROLLED_WORKER_IDLE);
    atomic_init(&worker->tid, 0);
    atomic_init(&worker->completion_ordinal, 0U);
    worker->completion_counter = NULL;
    worker->started = 0;
}

enum controlled_worker_status
controlled_worker_start(struct controlled_worker *worker,
                        void *(*entry)(void *), void *argument)
{
    if (worker->started)
        return CONTROLLED_WORKER_PTHREAD_ERROR;
    atomic_store_explicit(&worker->phase, CONTROLLED_WORKER_IDLE,
                          memory_order_relaxed);
    atomic_store_explicit(&worker->tid, 0, memory_order_relaxed);
    atomic_store_explicit(&worker->completion_ordinal, 0U,
                          memory_order_relaxed);
    if (pthread_create(&worker->thread, NULL, entry, argument) != 0)
        return CONTROLLED_WORKER_PTHREAD_ERROR;
    worker->started = 1;
    return CONTROLLED_WORKER_OK;
}

void controlled_worker_publish_entered(struct controlled_worker *worker)
{
    atomic_store_explicit(&worker->tid, (int)syscall(SYS_gettid),
                          memory_order_release);
    atomic_store_explicit(&worker->phase, CONTROLLED_WORKER_ENTERED,
                          memory_order_release);
}

void controlled_worker_publish_completed(struct controlled_worker *worker)
{
    unsigned int ordinal = 1U;

    if (worker->completion_counter != NULL)
        ordinal = atomic_fetch_add_explicit(worker->completion_counter, 1U,
                                            memory_order_acq_rel) +
                  1U;
    atomic_store_explicit(&worker->completion_ordinal, ordinal,
                          memory_order_release);
    atomic_store_explicit(&worker->phase, CONTROLLED_WORKER_COMPLETED,
                          memory_order_release);
}

enum controlled_worker_status
controlled_worker_observe_pending(struct controlled_worker *worker)
{
    enum controlled_worker_status status;
    uint64_t started;

    status = wait_for_phase(worker, CONTROLLED_WORKER_ENTERED,
                            COMPLETION_TIMEOUT_NANOSECONDS);
    if (status != CONTROLLED_WORKER_OK)
        return status;
    status = monotonic_nanoseconds(&started);
    if (status != CONTROLLED_WORKER_OK)
        return status;
    for (;;) {
        uint64_t now;

        if (atomic_load_explicit(&worker->phase, memory_order_acquire) ==
            CONTROLLED_WORKER_COMPLETED)
            return CONTROLLED_WORKER_COMPLETED_EARLY;
        status = monotonic_nanoseconds(&now);
        if (status != CONTROLLED_WORKER_OK)
            return status;
        if (now - started >= PENDING_GUARD_NANOSECONDS)
            return CONTROLLED_WORKER_OK;
        status = sleep_wait_interval();
        if (status != CONTROLLED_WORKER_OK)
            return status;
    }
}

enum controlled_worker_status
controlled_worker_wait_for_completion(struct controlled_worker *worker)
{
    return wait_for_phase(worker, CONTROLLED_WORKER_COMPLETED,
                          COMPLETION_TIMEOUT_NANOSECONDS);
}

enum controlled_worker_status
controlled_worker_join(struct controlled_worker *worker)
{
    if (!worker->started || pthread_join(worker->thread, NULL) != 0)
        return CONTROLLED_WORKER_PTHREAD_ERROR;
    worker->started = 0;
    return CONTROLLED_WORKER_OK;
}

pid_t controlled_worker_tid(const struct controlled_worker *worker)
{
    return (pid_t)atomic_load_explicit(&worker->tid, memory_order_acquire);
}

unsigned int
controlled_worker_completion_ordinal(const struct controlled_worker *worker)
{
    return atomic_load_explicit(&worker->completion_ordinal,
                                memory_order_acquire);
}

enum controlled_worker_status
controlled_worker_send_signal(struct controlled_worker *worker,
                              int signal_number)
{
    pid_t tid = controlled_worker_tid(worker);

    if (!worker->started || tid <= 0 || signal_number <= 0 ||
        syscall(SYS_tgkill, getpid(), tid, signal_number) != 0)
        return CONTROLLED_WORKER_SIGNAL_ERROR;
    return CONTROLLED_WORKER_OK;
}

void controlled_workers_initialize(struct controlled_workers *workers)
{
    int index;

    atomic_init(&workers->next_completion_ordinal, 0U);
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        controlled_worker_initialize(&workers->slots[index]);
        workers->slots[index].completion_counter =
            &workers->next_completion_ordinal;
    }
}

struct controlled_worker *
controlled_workers_actor(struct controlled_workers *workers, int actor)
{
    if (actor < 1 || actor > CONTROLLED_WORKER_COUNT)
        return NULL;
    return &workers->slots[actor - 1];
}

enum controlled_worker_status
controlled_workers_observe_all_pending(struct controlled_workers *workers)
{
    int index;

    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        enum controlled_worker_status status =
            controlled_worker_observe_pending(&workers->slots[index]);

        if (status != CONTROLLED_WORKER_OK)
            return status;
    }
    return CONTROLLED_WORKER_OK;
}

enum controlled_worker_status
controlled_workers_wait_for_all(struct controlled_workers *workers)
{
    int index;

    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        enum controlled_worker_status status =
            controlled_worker_wait_for_completion(&workers->slots[index]);

        if (status != CONTROLLED_WORKER_OK)
            return status;
    }
    return CONTROLLED_WORKER_OK;
}

enum controlled_worker_status
controlled_workers_join_all(struct controlled_workers *workers)
{
    enum controlled_worker_status result = CONTROLLED_WORKER_OK;
    int index;

    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        enum controlled_worker_status status;

        if (!workers->slots[index].started)
            continue;
        status = controlled_worker_join(&workers->slots[index]);
        if (result == CONTROLLED_WORKER_OK && status != CONTROLLED_WORKER_OK)
            result = status;
    }
    return result;
}

enum controlled_worker_status
controlled_workers_cleanup(struct controlled_workers *workers,
                           controlled_worker_cleanup_fn cleanup,
                           void *argument)
{
    enum controlled_worker_status result = CONTROLLED_WORKER_OK;
    int index;

    if (cleanup != NULL && cleanup(argument) != 0)
        result = CONTROLLED_WORKER_CLEANUP_ERROR;
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        enum controlled_worker_status status;

        if (!workers->slots[index].started)
            continue;
        status = controlled_worker_wait_for_completion(&workers->slots[index]);
        if (result == CONTROLLED_WORKER_OK && status != CONTROLLED_WORKER_OK)
            result = status;
    }
    if (controlled_workers_join_all(workers) != CONTROLLED_WORKER_OK &&
        result == CONTROLLED_WORKER_OK)
        result = CONTROLLED_WORKER_CLEANUP_ERROR;
    return result;
}
