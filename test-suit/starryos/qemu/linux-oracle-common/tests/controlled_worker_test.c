#include "../controlled_worker.h"

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static int fail_pthread_create;
static int fail_pthread_join;
static int fail_clock;
static int fail_sleep;
static int use_timeout_clock;
static unsigned int timeout_clock_calls;

int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*entry)(void *), void *argument);
int __real_pthread_join(pthread_t thread, void **return_value);
int __real_clock_gettime(clockid_t clock_id, struct timespec *time);
int __real_nanosleep(const struct timespec *request, struct timespec *remaining);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*entry)(void *), void *argument)
{
    if (fail_pthread_create)
        return EAGAIN;
    return __real_pthread_create(thread, attributes, entry, argument);
}

int __wrap_pthread_join(pthread_t thread, void **return_value)
{
    if (fail_pthread_join)
        return ESRCH;
    return __real_pthread_join(thread, return_value);
}

int __wrap_clock_gettime(clockid_t clock_id, struct timespec *time)
{
    if (fail_clock) {
        errno = EIO;
        return -1;
    }
    if (use_timeout_clock) {
        time->tv_sec = timeout_clock_calls++ == 0 ? 0 : 5;
        time->tv_nsec = 0;
        return 0;
    }
    return __real_clock_gettime(clock_id, time);
}

int __wrap_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    if (fail_sleep) {
        errno = EIO;
        return -1;
    }
    return __real_nanosleep(request, remaining);
}

#define CHECK(expression)                                                       \
    do {                                                                        \
        if (!(expression)) {                                                    \
            fprintf(stderr, "check failed at line %d: %s\n", __LINE__,         \
                    #expression);                                               \
            return 1;                                                           \
        }                                                                       \
    } while (0)

struct pending_worker {
    struct controlled_worker *controller;
    atomic_int wake;
};

struct grouped_workers {
    struct controlled_workers *controllers;
    atomic_int wake[CONTROLLED_WORKER_COUNT];
};

static void reset_failures(void)
{
    fail_pthread_create = 0;
    fail_pthread_join = 0;
    fail_clock = 0;
    fail_sleep = 0;
    use_timeout_clock = 0;
    timeout_clock_calls = 0;
}

static void *run_pending_worker(void *argument)
{
    struct pending_worker *worker = argument;

    controlled_worker_publish_entered(worker->controller);
    while (atomic_load_explicit(&worker->wake, memory_order_acquire) == 0)
        sched_yield();
    controlled_worker_publish_completed(worker->controller);
    return NULL;
}

static void *run_immediate_worker(void *argument)
{
    struct controlled_worker *worker = argument;

    controlled_worker_publish_entered(worker);
    controlled_worker_publish_completed(worker);
    return NULL;
}

static void *run_grouped_worker(void *argument)
{
    struct pending_worker *worker = argument;

    controlled_worker_publish_entered(worker->controller);
    while (atomic_load_explicit(&worker->wake, memory_order_acquire) == 0)
        sched_yield();
    controlled_worker_publish_completed(worker->controller);
    return NULL;
}

static int wake_group(void *argument)
{
    struct grouped_workers *workers = argument;
    int index;

    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++)
        atomic_store_explicit(&workers->wake[index], 1, memory_order_release);
    return 0;
}

static int test_pending_wake_join(void)
{
    struct controlled_worker controller;
    struct pending_worker worker = {.controller = &controller};

    reset_failures();
    controlled_worker_initialize(&controller);
    atomic_init(&worker.wake, 0);
    CHECK(controlled_worker_start(&controller, run_pending_worker, &worker) ==
          CONTROLLED_WORKER_OK);
    CHECK(controlled_worker_observe_pending(&controller) ==
          CONTROLLED_WORKER_OK);
    atomic_store_explicit(&worker.wake, 1, memory_order_release);
    CHECK(controlled_worker_wait_for_completion(&controller) ==
          CONTROLLED_WORKER_OK);
    CHECK(controlled_worker_join(&controller) == CONTROLLED_WORKER_OK);
    return 0;
}

static int test_immediate_completion(void)
{
    struct controlled_worker controller;

    reset_failures();
    controlled_worker_initialize(&controller);
    CHECK(controlled_worker_start(&controller, run_immediate_worker,
                                  &controller) == CONTROLLED_WORKER_OK);
    CHECK(controlled_worker_observe_pending(&controller) ==
          CONTROLLED_WORKER_COMPLETED_EARLY);
    CHECK(controlled_worker_join(&controller) == CONTROLLED_WORKER_OK);
    return 0;
}

static int test_completion_timeout(void)
{
    struct controlled_worker controller;

    reset_failures();
    controlled_worker_initialize(&controller);
    use_timeout_clock = 1;
    CHECK(controlled_worker_wait_for_completion(&controller) ==
          CONTROLLED_WORKER_COMPLETION_TIMEOUT);
    return 0;
}

static int test_platform_failures(void)
{
    struct controlled_worker controller;

    reset_failures();
    controlled_worker_initialize(&controller);
    fail_pthread_create = 1;
    CHECK(controlled_worker_start(&controller, run_immediate_worker,
                                  &controller) ==
          CONTROLLED_WORKER_PTHREAD_ERROR);

    reset_failures();
    controlled_worker_initialize(&controller);
    fail_clock = 1;
    CHECK(controlled_worker_wait_for_completion(&controller) ==
          CONTROLLED_WORKER_CLOCK_ERROR);

    reset_failures();
    controlled_worker_initialize(&controller);
    controlled_worker_publish_entered(&controller);
    fail_sleep = 1;
    CHECK(controlled_worker_observe_pending(&controller) ==
          CONTROLLED_WORKER_SLEEP_ERROR);

    reset_failures();
    controlled_worker_initialize(&controller);
    fail_pthread_join = 1;
    CHECK(controlled_worker_join(&controller) ==
          CONTROLLED_WORKER_PTHREAD_ERROR);
    return 0;
}

static int test_two_worker_group(void)
{
    struct controlled_workers controllers;
    struct grouped_workers group = {.controllers = &controllers};
    struct pending_worker arguments[CONTROLLED_WORKER_COUNT];
    struct controlled_worker *actor1;
    struct controlled_worker *actor2;
    int completed_actor;
    int index;

    reset_failures();
    controlled_workers_initialize(&controllers);
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        arguments[index].controller = &controllers.slots[index];
        atomic_init(&arguments[index].wake, 0);
        atomic_init(&group.wake[index], 0);
        CHECK(controlled_worker_start(&controllers.slots[index],
                                      run_grouped_worker,
                                      &arguments[index]) == CONTROLLED_WORKER_OK);
    }
    actor1 = controlled_workers_actor(&controllers, 1);
    actor2 = controlled_workers_actor(&controllers, 2);
    CHECK(actor1 == &controllers.slots[0]);
    CHECK(actor2 == &controllers.slots[1]);
    CHECK(controlled_workers_actor(&controllers, 0) == NULL);
    CHECK(controlled_workers_observe_all_pending(&controllers) ==
          CONTROLLED_WORKER_OK);
    CHECK(controlled_worker_tid(actor1) > 0);
    CHECK(controlled_worker_tid(actor2) > 0);

    atomic_store_explicit(&arguments[1].wake, 1, memory_order_release);
    CHECK(controlled_workers_wait_for_next(&controllers, 0, &completed_actor) ==
          CONTROLLED_WORKER_OK);
    CHECK(completed_actor == 2);
    atomic_store_explicit(&arguments[0].wake, 1, memory_order_release);
    CHECK(controlled_workers_wait_for_next(&controllers, 1U << 1,
                                           &completed_actor) ==
          CONTROLLED_WORKER_OK);
    CHECK(completed_actor == 1);
    CHECK(controlled_workers_wait_for_all(&controllers) == CONTROLLED_WORKER_OK);
    CHECK(controlled_worker_completion_ordinal(actor2) == 1U);
    CHECK(controlled_worker_completion_ordinal(actor1) == 2U);
    CHECK(controlled_workers_join_all(&controllers) == CONTROLLED_WORKER_OK);
    return 0;
}

static int test_group_cleanup_joins_started_workers(void)
{
    struct controlled_workers controllers;
    struct grouped_workers group = {.controllers = &controllers};
    struct pending_worker arguments[CONTROLLED_WORKER_COUNT];
    int index;

    reset_failures();
    controlled_workers_initialize(&controllers);
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++) {
        arguments[index].controller = &controllers.slots[index];
        atomic_init(&arguments[index].wake, 0);
        atomic_init(&group.wake[index], 0);
        CHECK(controlled_worker_start(&controllers.slots[index],
                                      run_grouped_worker,
                                      &arguments[index]) == CONTROLLED_WORKER_OK);
    }
    CHECK(controlled_workers_observe_all_pending(&controllers) ==
          CONTROLLED_WORKER_OK);
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++)
        atomic_store_explicit(&arguments[index].wake, 1, memory_order_release);
    CHECK(controlled_workers_cleanup(&controllers, wake_group, &group) ==
          CONTROLLED_WORKER_OK);
    CHECK(controllers.slots[0].started == 0);
    CHECK(controllers.slots[1].started == 0);
    return 0;
}

int main(void)
{
    if (test_pending_wake_join() != 0 || test_immediate_completion() != 0 ||
        test_completion_timeout() != 0 || test_platform_failures() != 0 ||
        test_two_worker_group() != 0 ||
        test_group_cleanup_joins_started_workers() != 0)
        return 1;
    return 0;
}
