#include "controlled_worker.h"

#include <errno.h>
#include <stdint.h>
#include <time.h>

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
}

enum controlled_worker_status
controlled_worker_start(struct controlled_worker *worker,
                        void *(*entry)(void *), void *argument)
{
    atomic_store_explicit(&worker->phase, CONTROLLED_WORKER_IDLE,
                          memory_order_relaxed);
    if (pthread_create(&worker->thread, NULL, entry, argument) != 0)
        return CONTROLLED_WORKER_PTHREAD_ERROR;
    return CONTROLLED_WORKER_OK;
}

void controlled_worker_publish_entered(struct controlled_worker *worker)
{
    atomic_store_explicit(&worker->phase, CONTROLLED_WORKER_ENTERED,
                          memory_order_release);
}

void controlled_worker_publish_completed(struct controlled_worker *worker)
{
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
    if (pthread_join(worker->thread, NULL) != 0)
        return CONTROLLED_WORKER_PTHREAD_ERROR;
    return CONTROLLED_WORKER_OK;
}
