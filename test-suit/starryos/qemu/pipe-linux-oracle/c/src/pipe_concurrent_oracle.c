#define _GNU_SOURCE

#include "pipe_concurrent_oracle.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "concurrent_trace.h"
#include "controlled_worker.h"

#define CORPUS_VERSION 7L
#define MAX_SLOTS 16
#define MAX_LINE_BYTES 512
#define MAX_IO_BYTES 8192
#define PIPE_BUF_BYTES 4096L
#define O_NONBLOCK_FLAG 2048L
#define O_CLOEXEC_FLAG 524288L
#define READ_SENTINEL 0xa5U
#define POLL_REVENTS_SENTINEL ((short)0x5a5a)
#define SIGUSR1_NUMBER 10L
#define SA_RESTART_FLAG 268435456L
#define MAX_TIMEOUT_NS UINT64_C(1000000000)
#define KERNEL_SIGSET_SIZE 8U
#define SIGUSR1_MASK (UINT64_C(1) << (SIGUSR1 - 1))
#define MAX_EPOLL_OBJECTS 8
#define MAX_EPOLL_REGISTRATIONS 16
#define MAX_EPOLL_EVENTS 4
#define EPOLL_EVENT_RESULT_BYTES 12U
#define ENDPOINT_NONE 0
#define ENDPOINT_READER 1
#define ENDPOINT_WRITER 2

static const unsigned char raw_magic[8] = {
    'P', 'I', 'P', 'E', 'R', 'U', 'N', '7',
};
static const unsigned char allowed_magic[8] = {
    'P', 'I', 'P', 'E', 'O', 'R', 'C', '1',
};

enum operation_kind {
    OP_PIPE2 = 1,
    OP_READ,
    OP_READ_NULL,
    OP_WRITE,
    OP_WRITE_NULL,
    OP_DUP,
    OP_CLOSE,
    OP_POLL,
    OP_SET_SIZE,
    OP_GET_SIZE,
    OP_FIONREAD,
    OP_GET_STATUS_FLAGS,
    OP_SET_STATUS_FLAGS,
    OP_GET_FD_FLAGS,
    OP_SET_FD_FLAGS,
    OP_DUP2,
    OP_DUP3,
    OP_READV,
    OP_WRITEV,
    OP_POLL_MANY,
    OP_START_READ,
    OP_START_WRITE,
    OP_ASSERT_PENDING,
    OP_JOIN,
    OP_START_POLL,
    OP_ASSERT_ALL_PENDING,
    OP_JOIN_SET,
    OP_SIGNAL_CONFIG,
    OP_SEND_SIGNAL,
    OP_ASSERT_SIGNAL_HANDLED,
    OP_START_PPOLL,
    OP_EPOLL_CREATE,
    OP_EPOLL_CTL,
    OP_START_EPOLL_WAIT,
    OP_START_EPOLL_PWAIT,
    OP_START_EPOLL_PWAIT2,
};

enum worker_kind {
    WORKER_READ,
    WORKER_WRITE,
    WORKER_POLL,
    WORKER_PPOLL,
    WORKER_EPOLL_WAIT,
    WORKER_EPOLL_PWAIT,
    WORKER_EPOLL_PWAIT2,
};

struct epoll_registration {
    int active;
    int target_slot;
    uint32_t events;
    uint64_t data;
};

struct epoll_object {
    int fd;
    struct epoll_registration registrations[MAX_EPOLL_REGISTRATIONS];
};

struct concurrent_worker_state {
    struct controlled_worker *controller;
    enum worker_kind kind;
    struct concurrent_operation_result syscall_result;
    uint32_t start_result_index;
    int active;
    int pending_confirmed;
    int accounted;
    int slot;
    int fd;
    int peer_fd;
    size_t length;
    unsigned char byte_value;
    struct pollfd poll_fd;
    struct epoll_event epoll_events[MAX_EPOLL_EVENTS];
    int epoll_object;
    int maxevents;
    int timeout_ms;
    int64_t timeout_ns;
    int block_sigusr1;
    atomic_uint *handler_count;
    int clock_failed;
    int mask_failed;
    int timeout_too_early;
    int partial_progress_expected;
    long start_delay_nanoseconds;
};

struct concurrent_context {
    int record_mode;
    struct concurrent_raw_writer raw_writer;
    struct concurrent_allowed_reader allowed_reader;
    struct controlled_workers controllers;
    struct concurrent_worker_state workers[CONTROLLED_WORKER_COUNT];
    struct concurrent_operation_result results[CONCURRENT_MAX_OPERATIONS];
    int slots[MAX_SLOTS];
    int slot_peer_fds[MAX_SLOTS];
    int slot_epolls[MAX_SLOTS];
    int slot_endpoints[MAX_SLOTS];
    struct epoll_object epolls[MAX_EPOLL_OBJECTS];
    int epoll_count;
    uint32_t scenario_index;
    uint32_t operation_index;
    uint32_t total_operations;
    unsigned int accounted_actor_mask;
    int preferred_actor;
    atomic_uint signal_counts[CONTROLLED_WORKER_COUNT];
    long signal_flags;
    int signal_configured;
};

static _Thread_local atomic_uint *current_handler_count;

static int fail(const char *message)
{
    fprintf(stderr, "STARRY_PIPE_LINUX_ORACLE_FAILED: %s\n", message);
    return 1;
}

static int fail_line(unsigned int line_number, const char *line,
                     const char *message)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_FAILED: line=%u operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static int fail_harness(unsigned int line_number, const char *line,
                        const char *message)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_HARNESS_ERROR: line=%u "
            "operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static int fail_schedule_timeout(unsigned int line_number, const char *line)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=%u "
            "operation=\"%s\"\n",
            line_number, line);
    return 1;
}

static int fail_syscall_timeout(unsigned int line_number, const char *line)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_SYSCALL_TIMEOUT: line=%u "
            "operation=\"%s\"\n",
            line_number, line);
    return 1;
}

static char *trim(char *text)
{
    char *end;

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
        text++;
    end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
            end[-1] == '\n'))
        *--end = '\0';
    return text;
}

static int parse_long_value(const char *text, long minimum, long maximum,
                            long *value)
{
    char *end;
    long parsed;

    if (text == NULL || *text == '\0')
        return -1;
    errno = 0;
    parsed = strtol(text, &end, 0);
    if (errno != 0 || *end != '\0' || parsed < minimum || parsed > maximum)
        return -1;
    *value = parsed;
    return 0;
}

static int parse_u64_value(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long parsed;

    if (text == NULL || *text == '\0' || *text == '-')
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || *end != '\0')
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_slot(const char *text, int *slot)
{
    long parsed;

    if (parse_long_value(text, 0, MAX_SLOTS - 1, &parsed) != 0)
        return -1;
    *slot = (int)parsed;
    return 0;
}

static int parse_actor(const char *text, int *actor)
{
    long parsed;

    if (parse_long_value(text, 1, CONTROLLED_WORKER_COUNT, &parsed) != 0)
        return -1;
    *actor = (int)parsed;
    return 0;
}

static int parse_timeout_ns(const char *text, int64_t *timeout_ns)
{
    char *end;
    unsigned long long parsed;

    if (text != NULL && strcmp(text, "null") == 0) {
        *timeout_ns = -1;
        return 0;
    }
    if (text == NULL || *text == '\0' || *text == '-')
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || *end != '\0' || parsed > MAX_TIMEOUT_NS)
        return -1;
    *timeout_ns = (int64_t)parsed;
    return 0;
}

static void finish_syscall_result(struct concurrent_operation_result *result,
                                  long syscall_result)
{
    result->result = syscall_result;
    result->error_number = syscall_result < 0 ? errno : 0;
}

static void count_signal_handler(int signal_number)
{
    (void)signal_number;
    if (current_handler_count != NULL)
        atomic_fetch_add_explicit(current_handler_count, 1U,
                                  memory_order_relaxed);
}

static int configure_count_signal_handler(int signal_number, long flags,
                                          struct sigaction *previous_action)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = count_signal_handler;
    action.sa_flags = (int)flags;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    return sigaction(signal_number, &action, previous_action);
}

static int cleanup_workers(void *argument)
{
    struct concurrent_context *context = argument;
    int actor;
    int status = 0;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];
        unsigned char buffer[MAX_IO_BYTES] = {1};
        long syscall_result;

        if (!worker->active || !worker->controller->started)
            continue;
        if (worker->kind == WORKER_EPOLL_WAIT ||
            worker->kind == WORKER_EPOLL_PWAIT ||
            worker->kind == WORKER_EPOLL_PWAIT2) {
            struct epoll_object *epoll = &context->epolls[worker->epoll_object];
            int registration_index;
            int triggered = 0;

            if (!worker->block_sigusr1) {
                if (controlled_worker_send_signal(worker->controller, SIGUSR1) !=
                    CONTROLLED_WORKER_OK)
                    status = -1;
                continue;
            }
            for (registration_index = 0;
                 registration_index < MAX_EPOLL_REGISTRATIONS;
                 registration_index++) {
                struct epoll_registration *registration =
                    &epoll->registrations[registration_index];
                int target_slot;

                if (!registration->active)
                    continue;
                target_slot = registration->target_slot;
                if ((registration->events & EPOLLIN) != 0 &&
                    context->slot_endpoints[target_slot] == ENDPOINT_READER) {
                    int queued = 0;

                    if (syscall(SYS_ioctl, context->slots[target_slot], FIONREAD,
                                &queued) != 0) {
                        status = -1;
                        break;
                    }
                    if (queued > 0) {
                        size_t length = queued > (int)sizeof(buffer) ?
                                            sizeof(buffer) :
                                            (size_t)queued;

                        syscall_result = syscall(SYS_read,
                                                 context->slots[target_slot],
                                                 buffer, length);
                        if (syscall_result <= 0)
                            status = -1;
                    }
                    syscall_result = syscall(SYS_write,
                                             context->slot_peer_fds[target_slot],
                                             buffer, 1U);
                    if (syscall_result != 1)
                        status = -1;
                    triggered = 1;
                    break;
                }
                if ((registration->events & EPOLLOUT) != 0 &&
                    context->slot_endpoints[target_slot] == ENDPOINT_WRITER) {
                    syscall_result = syscall(SYS_read,
                                             context->slot_peer_fds[target_slot],
                                             buffer, sizeof(buffer));
                    if (syscall_result <= 0)
                        status = -1;
                    triggered = 1;
                    break;
                }
            }
            if (!triggered)
                status = -1;
            continue;
        }
        errno = 0;
        if (worker->kind == WORKER_WRITE ||
            ((worker->kind == WORKER_POLL || worker->kind == WORKER_PPOLL) &&
             worker->poll_fd.events == POLLOUT)) {
            syscall_result = syscall(SYS_read, worker->peer_fd, buffer,
                                     sizeof(buffer));
        } else {
            syscall_result = syscall(SYS_write, worker->peer_fd, buffer, 1U);
        }
        if (syscall_result < 0 && errno != EPIPE && errno != EBADF)
            status = -1;
        if (worker->kind == WORKER_WRITE &&
            worker->length > PIPE_BUF_BYTES && syscall_result > 0 &&
            atomic_load_explicit(&worker->controller->phase,
                                 memory_order_acquire) !=
                CONTROLLED_WORKER_COMPLETED) {
            struct pollfd descriptor = {
                .fd = worker->peer_fd,
                .events = POLLIN,
                .revents = 0,
            };

            do {
                errno = 0;
                syscall_result = syscall(SYS_poll, &descriptor, 1U, 1000);
            } while (syscall_result < 0 && errno == EINTR);
            if (syscall_result <= 0 || descriptor.revents == 0 ||
                controlled_worker_send_signal(worker->controller, SIGUSR1) !=
                    CONTROLLED_WORKER_OK)
                status = -1;
        }
    }
    return status;
}

static void initialize_scenario(struct concurrent_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        context->slots[index] = -1;
        context->slot_peer_fds[index] = -1;
        context->slot_epolls[index] = -1;
        context->slot_endpoints[index] = ENDPOINT_NONE;
    }
    memset(context->epolls, 0, sizeof(context->epolls));
    context->epoll_count = 0;
    context->operation_index = 0;
    context->accounted_actor_mask = 0;
    memset(context->results, 0, sizeof(context->results));
    memset(context->workers, 0, sizeof(context->workers));
    controlled_workers_initialize(&context->controllers);
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++)
        context->workers[index].controller = &context->controllers.slots[index];
    for (index = 0; index < CONTROLLED_WORKER_COUNT; index++)
        atomic_init(&context->signal_counts[index], 0U);
    context->signal_flags = 0;
    context->signal_configured = 0;
}

static int cleanup_scenario(struct concurrent_context *context)
{
    int status = 0;
    int index;

    if (context->controllers.slots[0].started ||
        context->controllers.slots[1].started) {
        if (controlled_workers_cleanup(&context->controllers, cleanup_workers,
                                       context) != CONTROLLED_WORKER_OK)
            status = -1;
    }
    for (index = 0; index < MAX_SLOTS; index++) {
        if (context->slots[index] >= 0) {
            if (syscall(SYS_close, context->slots[index]) != 0)
                status = -1;
            context->slots[index] = -1;
            context->slot_peer_fds[index] = -1;
            context->slot_epolls[index] = -1;
            context->slot_endpoints[index] = ENDPOINT_NONE;
        }
    }
    if (configure_count_signal_handler(SIGUSR1, 0, NULL) != 0)
        status = -1;
    return status;
}

static uint64_t timespec_nanoseconds(const struct timespec *value)
{
    return (uint64_t)value->tv_sec * UINT64_C(1000000000) +
           (uint64_t)value->tv_nsec;
}

static int wait_for_handler_count(atomic_uint *count, unsigned int target)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};
    unsigned int attempt;

    for (attempt = 0; attempt < 5000U; attempt++) {
        if (atomic_load_explicit(count, memory_order_acquire) >= target)
            return 0;
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR)
                return -2;
            delay.tv_sec = 0;
            delay.tv_nsec = 1000000L;
        }
        delay.tv_sec = 0;
        delay.tv_nsec = 1000000L;
    }
    return -4;
}

static void record_poll_revents(struct concurrent_worker_state *worker)
{
    uint16_t revents = (uint16_t)worker->poll_fd.revents;

    worker->syscall_result.data_length = sizeof(revents);
    worker->syscall_result.data[0] = (unsigned char)revents;
    worker->syscall_result.data[1] = (unsigned char)(revents >> 8);
}

static void run_ppoll_worker(struct concurrent_worker_state *worker)
{
    struct timespec timeout;
    struct timespec started;
    struct timespec completed;
    const struct timespec *timeout_pointer = NULL;
    uint64_t empty_mask = 0;
    uint64_t original_mask = 0;
    uint64_t restored_mask = 0;
    uint64_t temporary_mask = worker->block_sigusr1 ? SIGUSR1_MASK : 0;
    long syscall_result;

    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &empty_mask, &original_mask,
                KERNEL_SIGSET_SIZE) != 0)
        worker->mask_failed = 1;
    if (worker->timeout_ns >= 0) {
        timeout.tv_sec = (time_t)((uint64_t)worker->timeout_ns / MAX_TIMEOUT_NS);
        timeout.tv_nsec = (long)((uint64_t)worker->timeout_ns % MAX_TIMEOUT_NS);
        timeout_pointer = &timeout;
    }
    controlled_worker_publish_entered(worker->controller);
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        worker->clock_failed = 1;
    errno = 0;
    syscall_result = syscall(SYS_ppoll, &worker->poll_fd, 1U, timeout_pointer,
                             &temporary_mask, KERNEL_SIGSET_SIZE);
    finish_syscall_result(&worker->syscall_result, syscall_result);
    if (clock_gettime(CLOCK_MONOTONIC, &completed) != 0) {
        worker->clock_failed = 1;
    } else if (!worker->clock_failed && syscall_result == 0 &&
               worker->timeout_ns > 0 &&
               timespec_nanoseconds(&completed) + UINT64_C(10000000) <
                   timespec_nanoseconds(&started) +
                       (uint64_t)worker->timeout_ns) {
        worker->timeout_too_early = 1;
    }
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &restored_mask,
                KERNEL_SIGSET_SIZE) != 0)
        worker->mask_failed = 1;
    worker->syscall_result.value =
        (temporary_mask & SIGUSR1_MASK ? UINT64_C(1) : UINT64_C(0)) |
        (restored_mask & SIGUSR1_MASK ? UINT64_C(2) : UINT64_C(0));
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &original_mask, NULL,
                KERNEL_SIGSET_SIZE) != 0)
        worker->mask_failed = 1;
    record_poll_revents(worker);
}

static void record_epoll_events(struct concurrent_worker_state *worker)
{
    long count = worker->syscall_result.result;
    long index;

    if (count <= 0)
        return;
    if (count > worker->maxevents)
        count = worker->maxevents;
    worker->syscall_result.data_length =
        (uint32_t)count * EPOLL_EVENT_RESULT_BYTES;
    for (index = 0; index < count; index++) {
        size_t offset = (size_t)index * EPOLL_EVENT_RESULT_BYTES;
        uint32_t events = worker->epoll_events[index].events;
        uint64_t data = worker->epoll_events[index].data.u64;

        memcpy(worker->syscall_result.data + offset, &events, sizeof(events));
        memcpy(worker->syscall_result.data + offset + sizeof(events), &data,
               sizeof(data));
    }
}

static void run_epoll_worker(struct concurrent_worker_state *worker)
{
    struct timespec timeout;
    struct timespec started;
    struct timespec completed;
    const struct timespec *timeout_pointer = NULL;
    uint64_t empty_mask = 0;
    uint64_t original_mask = 0;
    uint64_t restored_mask = 0;
    uint64_t temporary_mask = worker->block_sigusr1 ? SIGUSR1_MASK : 0;
    int uses_mask = worker->kind != WORKER_EPOLL_WAIT;
    int64_t requested_timeout_ns = -1;
    long syscall_result;

    if (uses_mask &&
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &empty_mask, &original_mask,
                KERNEL_SIGSET_SIZE) != 0)
        worker->mask_failed = 1;
    if (worker->kind == WORKER_EPOLL_PWAIT2 && worker->timeout_ns >= 0) {
        timeout.tv_sec = (time_t)((uint64_t)worker->timeout_ns / MAX_TIMEOUT_NS);
        timeout.tv_nsec = (long)((uint64_t)worker->timeout_ns % MAX_TIMEOUT_NS);
        timeout_pointer = &timeout;
        requested_timeout_ns = worker->timeout_ns;
    } else if (worker->kind != WORKER_EPOLL_PWAIT2 && worker->timeout_ms >= 0) {
        requested_timeout_ns =
            (int64_t)worker->timeout_ms * INT64_C(1000000);
    }
    memset(worker->epoll_events, 0xa5, sizeof(worker->epoll_events));
    controlled_worker_publish_entered(worker->controller);
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        worker->clock_failed = 1;
    errno = 0;
    if (worker->kind == WORKER_EPOLL_WAIT) {
        syscall_result = syscall(SYS_epoll_wait, worker->fd,
                                 worker->epoll_events, worker->maxevents,
                                 worker->timeout_ms);
    } else if (worker->kind == WORKER_EPOLL_PWAIT) {
        syscall_result = syscall(SYS_epoll_pwait, worker->fd,
                                 worker->epoll_events, worker->maxevents,
                                 worker->timeout_ms, &temporary_mask,
                                 KERNEL_SIGSET_SIZE);
    } else {
        syscall_result = syscall(SYS_epoll_pwait2, worker->fd,
                                 worker->epoll_events, worker->maxevents,
                                 timeout_pointer, &temporary_mask,
                                 KERNEL_SIGSET_SIZE);
    }
    finish_syscall_result(&worker->syscall_result, syscall_result);
    if (clock_gettime(CLOCK_MONOTONIC, &completed) != 0) {
        worker->clock_failed = 1;
    } else if (!worker->clock_failed && syscall_result == 0 &&
               requested_timeout_ns > 0 &&
               timespec_nanoseconds(&completed) + UINT64_C(10000000) <
                   timespec_nanoseconds(&started) +
                       (uint64_t)requested_timeout_ns) {
        worker->timeout_too_early = 1;
    }
    if (uses_mask) {
        if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &restored_mask,
                    KERNEL_SIGSET_SIZE) != 0)
            worker->mask_failed = 1;
        worker->syscall_result.value =
            (temporary_mask & SIGUSR1_MASK ? UINT64_C(1) : UINT64_C(0)) |
            (restored_mask & SIGUSR1_MASK ? UINT64_C(2) : UINT64_C(0));
        if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &original_mask, NULL,
                    KERNEL_SIGSET_SIZE) != 0)
            worker->mask_failed = 1;
    }
    record_epoll_events(worker);
}

static void *run_worker(void *argument)
{
    struct concurrent_worker_state *worker = argument;
    long syscall_result;

    current_handler_count = worker->handler_count;

    if (worker->start_delay_nanoseconds > 0) {
        struct timespec delay = {
            .tv_sec = 0,
            .tv_nsec = worker->start_delay_nanoseconds,
        };

        while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
            ;
    }
    if (worker->kind == WORKER_READ) {
        unsigned char buffer[MAX_IO_BYTES];
        size_t copy_length;

        memset(buffer, READ_SENTINEL, sizeof(buffer));
        controlled_worker_publish_entered(worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_read, worker->fd, buffer, worker->length);
        finish_syscall_result(&worker->syscall_result, syscall_result);
        copy_length = syscall_result > 0 ? (size_t)syscall_result : 0U;
        if (copy_length > CONCURRENT_RESULT_DATA_MAX)
            copy_length = CONCURRENT_RESULT_DATA_MAX;
        worker->syscall_result.data_length = (uint32_t)copy_length;
        memcpy(worker->syscall_result.data, buffer, copy_length);
    } else if (worker->kind == WORKER_WRITE) {
        unsigned char buffer[MAX_IO_BYTES];

        memset(buffer, worker->byte_value, sizeof(buffer));
        controlled_worker_publish_entered(worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_write, worker->fd, buffer, worker->length);
        finish_syscall_result(&worker->syscall_result, syscall_result);
        worker->syscall_result.value = worker->byte_value;
    } else if (worker->kind == WORKER_POLL) {
        struct timespec started;
        struct timespec completed;

        controlled_worker_publish_entered(worker->controller);
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
            worker->clock_failed = 1;
        errno = 0;
        syscall_result = syscall(SYS_poll, &worker->poll_fd, 1U,
                                 worker->timeout_ms);
        finish_syscall_result(&worker->syscall_result, syscall_result);
        if (clock_gettime(CLOCK_MONOTONIC, &completed) != 0) {
            worker->clock_failed = 1;
        } else if (!worker->clock_failed && syscall_result == 0 &&
                   worker->timeout_ms > 0 &&
                   timespec_nanoseconds(&completed) + UINT64_C(10000000) <
                       timespec_nanoseconds(&started) +
                           (uint64_t)worker->timeout_ms * UINT64_C(1000000)) {
            worker->timeout_too_early = 1;
        }
        record_poll_revents(worker);
    } else if (worker->kind == WORKER_PPOLL) {
        run_ppoll_worker(worker);
    } else {
        run_epoll_worker(worker);
    }
    worker->syscall_result.handler_count =
        atomic_load_explicit(worker->handler_count, memory_order_acquire);
    controlled_worker_publish_completed(worker->controller);
    current_handler_count = NULL;
    return NULL;
}

static void account_worker(struct concurrent_context *context, int actor)
{
    struct concurrent_worker_state *worker = &context->workers[actor - 1];

    if (!worker->active || worker->accounted ||
        atomic_load_explicit(&worker->controller->phase,
                             memory_order_acquire) != CONTROLLED_WORKER_COMPLETED)
        return;
    worker->accounted = 1;
    context->accounted_actor_mask |= 1U << (actor - 1);
}

static int worker_is_ready(struct concurrent_worker_state *worker)
{
    struct pollfd descriptor;
    long syscall_result;

    if (!worker->active || worker->accounted)
        return 0;
    if (atomic_load_explicit(&worker->controller->phase,
                             memory_order_acquire) == CONTROLLED_WORKER_COMPLETED)
        return 1;
    descriptor.fd = worker->fd;
    descriptor.events =
        worker->kind == WORKER_READ ? POLLIN :
        worker->kind == WORKER_WRITE ? POLLOUT :
        worker->kind == WORKER_POLL || worker->kind == WORKER_PPOLL ?
            worker->poll_fd.events :
            POLLIN;
    descriptor.revents = 0;
    do {
        errno = 0;
        syscall_result = syscall(SYS_poll, &descriptor, 1U, 0);
    } while (syscall_result < 0 && errno == EINTR);
    return syscall_result > 0 && descriptor.revents != 0;
}

static int has_unaccounted_worker(struct concurrent_context *context,
                                  enum worker_kind kind, short poll_events)
{
    int actor;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];

        if (!worker->active || worker->accounted)
            continue;
        if (worker->kind == kind ||
            ((worker->kind == WORKER_POLL || worker->kind == WORKER_PPOLL) &&
             (worker->poll_fd.events & poll_events) != 0))
            return 1;
    }
    return 0;
}

static int has_ready_epoll_worker(struct concurrent_context *context)
{
    int actor;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];

        if ((worker->kind == WORKER_EPOLL_WAIT ||
             worker->kind == WORKER_EPOLL_PWAIT ||
             worker->kind == WORKER_EPOLL_PWAIT2) &&
            worker_is_ready(worker))
            return 1;
    }
    return 0;
}

static int has_unaccounted_large_writer(struct concurrent_context *context)
{
    int actor;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];

        if (worker->active && !worker->accounted &&
            worker->kind == WORKER_WRITE && worker->length > PIPE_BUF_BYTES)
            return 1;
    }
    return 0;
}

static void mark_large_writer_progress_expected(struct concurrent_context *context)
{
    int actor;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];

        if (worker->active && !worker->accounted &&
            worker->kind == WORKER_WRITE && worker->length > PIPE_BUF_BYTES)
            worker->partial_progress_expected = 1;
    }
}

static int wait_for_partial_write_progress(struct concurrent_worker_state *worker)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};
    unsigned int attempt;

    if (!worker->partial_progress_expected)
        return 0;
    for (attempt = 0; attempt < 5000U; attempt++) {
        int queued = 0;

        if (syscall(SYS_ioctl, worker->peer_fd, FIONREAD, &queued) != 0)
            return -2;
        if (queued > 0)
            return 0;
        if (atomic_load_explicit(&worker->controller->phase,
                                 memory_order_acquire) ==
            CONTROLLED_WORKER_COMPLETED)
            return -3;
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR)
                return -2;
            delay.tv_sec = 0;
            delay.tv_nsec = 1000000L;
        }
        delay.tv_sec = 0;
        delay.tv_nsec = 1000000L;
    }
    return -4;
}

static int has_any_unaccounted_worker(struct concurrent_context *context)
{
    int actor;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];

        if (worker->active && !worker->accounted)
            return 1;
    }
    return 0;
}

static int wait_for_trigger_progress(struct concurrent_context *context,
                                     int progress_required)
{
    unsigned int ready_mask = 0;
    int actor;
    enum controlled_worker_status status;

    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        if (worker_is_ready(&context->workers[actor - 1]))
            ready_mask |= 1U << (actor - 1);
    }
    if (ready_mask == 0 && !progress_required)
        return 0;
    status = controlled_workers_wait_for_next(
        &context->controllers, context->accounted_actor_mask, &actor);
    if (status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
        return -4;
    if (status != CONTROLLED_WORKER_OK)
        return -2;
    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++)
        account_worker(context, actor);
    return 0;
}

static int execute_pipe2(struct concurrent_context *context, char *save,
                         struct concurrent_operation_result *result)
{
    char *read_slot_text = strtok_r(NULL, " \t", &save);
    char *write_slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = strtok_r(NULL, " \t", &save);
    int descriptors[2];
    int read_slot;
    int write_slot;
    long flags;
    long syscall_result;

    if (parse_slot(read_slot_text, &read_slot) != 0 ||
        parse_slot(write_slot_text, &write_slot) != 0 ||
        parse_long_value(flags_text, 0, O_NONBLOCK_FLAG | O_CLOEXEC_FLAG,
                         &flags) != 0 ||
        (flags & ~(O_NONBLOCK_FLAG | O_CLOEXEC_FLAG)) != 0 ||
        read_slot == write_slot || context->slots[read_slot] >= 0 ||
        context->slots[write_slot] >= 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_pipe2, descriptors, flags);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        context->slots[read_slot] = descriptors[0];
        context->slots[write_slot] = descriptors[1];
        context->slot_peer_fds[read_slot] = descriptors[1];
        context->slot_peer_fds[write_slot] = descriptors[0];
        context->slot_endpoints[read_slot] = ENDPOINT_READER;
        context->slot_endpoints[write_slot] = ENDPOINT_WRITER;
    }
    result->kind = OP_PIPE2;
    return 0;
}

static int execute_read(struct concurrent_context *context, char *save,
                        struct concurrent_operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    unsigned char buffer[MAX_IO_BYTES];
    size_t copy_length;
    int queued_before;
    int progress_required;
    long length;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        context->slots[slot] < 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    memset(buffer, READ_SENTINEL, sizeof(buffer));
    if (syscall(SYS_ioctl, context->slots[slot], FIONREAD, &queued_before) != 0)
        return -2;
    errno = 0;
    syscall_result = syscall(SYS_read, context->slots[slot], buffer,
                             (size_t)length);
    finish_syscall_result(result, syscall_result);
    copy_length = syscall_result > 0 ? (size_t)syscall_result : 0U;
    if (copy_length > CONCURRENT_RESULT_DATA_MAX)
        copy_length = CONCURRENT_RESULT_DATA_MAX;
    result->data_length = (uint32_t)copy_length;
    memcpy(result->data, buffer, copy_length);
    result->kind = OP_READ;
    if (syscall_result > 0 && syscall_result == queued_before &&
        has_unaccounted_large_writer(context)) {
        mark_large_writer_progress_expected(context);
        return 0;
    }
    progress_required =
        (syscall_result > 0 && syscall_result == queued_before &&
         has_unaccounted_worker(context, WORKER_WRITE, POLLOUT)) ||
        has_ready_epoll_worker(context);
    return wait_for_trigger_progress(context, progress_required);
}

static int execute_write(struct concurrent_context *context, char *save,
                         struct concurrent_operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    char *byte_text = strtok_r(NULL, " \t", &save);
    unsigned char buffer[MAX_IO_BYTES];
    long length;
    long byte_value;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        parse_long_value(byte_text, 0, UCHAR_MAX, &byte_value) != 0 ||
        context->slots[slot] < 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    memset(buffer, (unsigned char)byte_value, sizeof(buffer));
    errno = 0;
    syscall_result = syscall(SYS_write, context->slots[slot], buffer,
                             (size_t)length);
    finish_syscall_result(result, syscall_result);
    result->value = (uint64_t)byte_value;
    result->kind = OP_WRITE;
    return wait_for_trigger_progress(
        context,
        (syscall_result > 0 &&
         has_unaccounted_worker(context, WORKER_READ, POLLIN)) ||
            has_ready_epoll_worker(context));
}

static int execute_dup(struct concurrent_context *context, char *save,
                       struct concurrent_operation_result *result)
{
    char *source_text = strtok_r(NULL, " \t", &save);
    char *destination_text = strtok_r(NULL, " \t", &save);
    long syscall_result;
    int source;
    int destination;

    if (parse_slot(source_text, &source) != 0 ||
        parse_slot(destination_text, &destination) != 0 || source == destination ||
        context->slots[source] < 0 ||
        context->slot_endpoints[source] == ENDPOINT_NONE ||
        context->slots[destination] >= 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_dup, context->slots[source]);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0) {
        context->slots[destination] = (int)syscall_result;
        context->slot_peer_fds[destination] = context->slot_peer_fds[source];
        context->slot_endpoints[destination] = context->slot_endpoints[source];
    }
    result->kind = OP_DUP;
    return 0;
}

static int execute_close(struct concurrent_context *context, char *save,
                         struct concurrent_operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 || context->slots[slot] < 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_close, context->slots[slot]);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        context->slots[slot] = -1;
        context->slot_peer_fds[slot] = -1;
        context->slot_epolls[slot] = -1;
        context->slot_endpoints[slot] = ENDPOINT_NONE;
    }
    result->kind = OP_CLOSE;
    return wait_for_trigger_progress(context,
                                     has_any_unaccounted_worker(context));
}

static int execute_fcntl(struct concurrent_context *context, char *save,
                         struct concurrent_operation_result *result,
                         int command, uint32_t kind)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = command == F_SETFL ? strtok_r(NULL, " \t", &save) : NULL;
    long flags = 0;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 || context->slots[slot] < 0 ||
        (flags_text != NULL &&
         parse_long_value(flags_text, 0, O_NONBLOCK_FLAG, &flags) != 0) ||
        (flags_text != NULL && flags != 0 && flags != O_NONBLOCK_FLAG) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_fcntl, context->slots[slot], command, flags);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (command == F_GETFL)
        result->value = syscall_result < 0 ? UINT64_MAX :
                                            (uint64_t)(syscall_result & O_NONBLOCK_FLAG);
    result->kind = kind;
    return 0;
}

static int execute_epoll_create(struct concurrent_context *context, char *save,
                                struct concurrent_operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = strtok_r(NULL, " \t", &save);
    long flags;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(flags_text, 0, EPOLL_CLOEXEC, &flags) != 0 ||
        (flags != 0 && flags != EPOLL_CLOEXEC) ||
        strtok_r(NULL, " \t", &save) != NULL || context->slots[slot] >= 0 ||
        context->epoll_count >= MAX_EPOLL_OBJECTS)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_epoll_create1, (int)flags);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0) {
        int epoll_object = context->epoll_count++;

        context->slots[slot] = (int)syscall_result;
        context->slot_epolls[slot] = epoll_object;
        context->epolls[epoll_object].fd = (int)syscall_result;
    }
    result->kind = OP_EPOLL_CREATE;
    result->value = (uint64_t)flags;
    return 0;
}

static struct epoll_registration *find_epoll_registration(
    struct epoll_object *epoll, int target_slot)
{
    int index;

    for (index = 0; index < MAX_EPOLL_REGISTRATIONS; index++) {
        if (epoll->registrations[index].active &&
            epoll->registrations[index].target_slot == target_slot)
            return &epoll->registrations[index];
    }
    return NULL;
}

static struct epoll_registration *free_epoll_registration(
    struct epoll_object *epoll)
{
    int index;

    for (index = 0; index < MAX_EPOLL_REGISTRATIONS; index++) {
        if (!epoll->registrations[index].active)
            return &epoll->registrations[index];
    }
    return NULL;
}

static int execute_epoll_ctl(struct concurrent_context *context, char *save,
                             struct concurrent_operation_result *result)
{
    char *epoll_slot_text = strtok_r(NULL, " \t", &save);
    char *action_text = strtok_r(NULL, " \t", &save);
    char *target_slot_text = strtok_r(NULL, " \t", &save);
    char *events_text = strtok_r(NULL, " \t", &save);
    char *data_text = strtok_r(NULL, " \t", &save);
    struct epoll_registration *registration;
    struct epoll_object *epoll;
    struct epoll_event event;
    uint64_t data;
    uint64_t events;
    int command;
    int epoll_slot;
    int target_slot;
    long syscall_result;

    if (parse_slot(epoll_slot_text, &epoll_slot) != 0 || action_text == NULL ||
        parse_slot(target_slot_text, &target_slot) != 0 ||
        parse_u64_value(events_text, &events) != 0 || events > UINT32_MAX ||
        parse_u64_value(data_text, &data) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL ||
        context->slot_epolls[epoll_slot] < 0 ||
        context->slot_endpoints[target_slot] == ENDPOINT_NONE)
        return -1;
    if (strcmp(action_text, "add") == 0) {
        command = EPOLL_CTL_ADD;
    } else if (strcmp(action_text, "mod") == 0) {
        command = EPOLL_CTL_MOD;
    } else if (strcmp(action_text, "del") == 0) {
        command = EPOLL_CTL_DEL;
    } else {
        return -1;
    }
    if ((events & ~(uint64_t)(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP |
                              EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) != 0 ||
        (command == EPOLL_CTL_DEL && (events != 0 || data != 0)) ||
        (command != EPOLL_CTL_DEL &&
         (events & (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP)) == 0) ||
        ((events & EPOLLEXCLUSIVE) != 0 &&
         (command != EPOLL_CTL_ADD || (events & EPOLLONESHOT) != 0)))
        return -1;
    epoll = &context->epolls[context->slot_epolls[epoll_slot]];
    registration = find_epoll_registration(epoll, target_slot);
    if ((command == EPOLL_CTL_ADD && registration != NULL) ||
        (command != EPOLL_CTL_ADD && registration == NULL))
        return -1;
    if (command == EPOLL_CTL_ADD && free_epoll_registration(epoll) == NULL)
        return -1;
    memset(&event, 0, sizeof(event));
    event.events = (uint32_t)events;
    event.data.u64 = data;
    errno = 0;
    syscall_result = syscall(SYS_epoll_ctl, epoll->fd, command,
                             context->slots[target_slot],
                             command == EPOLL_CTL_DEL ? NULL : &event);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        if (command == EPOLL_CTL_ADD) {
            registration = free_epoll_registration(epoll);
            memset(registration, 0, sizeof(*registration));
            registration->active = 1;
            registration->target_slot = target_slot;
        }
        if (command == EPOLL_CTL_DEL) {
            memset(registration, 0, sizeof(*registration));
        } else {
            registration->events = (uint32_t)events;
            registration->data = data;
        }
    }
    result->kind = OP_EPOLL_CTL;
    result->value = data;
    return wait_for_trigger_progress(context, has_ready_epoll_worker(context));
}

static int execute_set_size(struct concurrent_context *context, char *save,
                            struct concurrent_operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *size_text = strtok_r(NULL, " \t", &save);
    long requested_size;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(size_text, PIPE_BUF_BYTES, MAX_IO_BYTES,
                         &requested_size) != 0 ||
        context->slots[slot] < 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_fcntl, context->slots[slot], F_SETPIPE_SZ,
                             requested_size);
    finish_syscall_result(result, syscall_result);
    result->kind = OP_SET_SIZE;
    return 0;
}

static int execute_start_worker(struct concurrent_context *context, char *save,
                                struct concurrent_operation_result *result,
                                enum worker_kind kind)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *argument_text = strtok_r(NULL, " \t", &save);
    char *timeout_text =
        kind == WORKER_POLL || kind == WORKER_PPOLL ?
            strtok_r(NULL, " \t", &save) :
            NULL;
    char *sigmask_text =
        kind == WORKER_PPOLL ? strtok_r(NULL, " \t", &save) : NULL;
    struct concurrent_worker_state *worker;
    long argument;
    long timeout = -1;
    int64_t timeout_ns = -1;
    int block_sigusr1 = 0;
    int actor;
    int slot;

    if (parse_actor(actor_text, &actor) != 0 ||
        parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(argument_text, 1,
                         MAX_IO_BYTES,
                         &argument) != 0 ||
        (kind == WORKER_POLL &&
         parse_long_value(timeout_text, -1, 1000, &timeout) != 0) ||
        (kind == WORKER_PPOLL && parse_timeout_ns(timeout_text, &timeout_ns) != 0) ||
        (kind == WORKER_PPOLL &&
         (sigmask_text == NULL ||
          (strcmp(sigmask_text, "empty") != 0 &&
           strcmp(sigmask_text, "usr1") != 0))) ||
        strtok_r(NULL, " \t", &save) != NULL || context->slots[slot] < 0 ||
        context->slot_peer_fds[slot] < 0)
        return -1;
    if ((kind == WORKER_POLL || kind == WORKER_PPOLL) &&
        ((argument != POLLIN && argument != POLLOUT) ||
         (kind == WORKER_POLL && timeout >= 0 && timeout < 100) ||
         (kind == WORKER_PPOLL && timeout_ns >= 0 &&
          timeout_ns < INT64_C(100000000))))
        return -1;
    if (kind == WORKER_PPOLL)
        block_sigusr1 = strcmp(sigmask_text, "usr1") == 0;
    worker = &context->workers[actor - 1];
    if (worker->active)
        return -1;
    {
        struct controlled_worker *controller = worker->controller;

        memset(worker, 0, sizeof(*worker));
        worker->controller = controller;
        worker->handler_count = &context->signal_counts[actor - 1];
    }
    context->accounted_actor_mask &= ~(1U << (actor - 1));
    worker->kind = kind;
    worker->active = 1;
    worker->slot = slot;
    worker->fd = context->slots[slot];
    worker->peer_fd = context->slot_peer_fds[slot];
    worker->epoll_object = -1;
    worker->start_result_index = context->operation_index;
    worker->length = (size_t)argument;
    worker->byte_value = (unsigned char)(64 + actor);
    worker->timeout_ms = (int)timeout;
    worker->timeout_ns = timeout_ns;
    worker->block_sigusr1 = block_sigusr1;
    worker->start_delay_nanoseconds =
        context->preferred_actor != 0 && context->preferred_actor != actor ?
            10000000L :
            0L;
    worker->poll_fd.fd = worker->fd;
    worker->poll_fd.events = (short)argument;
    worker->poll_fd.revents = POLL_REVENTS_SENTINEL;
    if (controlled_worker_start(worker->controller, run_worker, worker) !=
        CONTROLLED_WORKER_OK) {
        worker->active = 0;
        return -2;
    }
    result->kind = kind == WORKER_READ ? OP_START_READ :
                   kind == WORKER_WRITE ? OP_START_WRITE :
                   kind == WORKER_POLL ? OP_START_POLL : OP_START_PPOLL;
    result->actor = (uint32_t)actor;
    result->value = (uint64_t)argument;
    return 0;
}

static int epoll_has_registration(const struct epoll_object *epoll)
{
    int index;

    for (index = 0; index < MAX_EPOLL_REGISTRATIONS; index++) {
        if (epoll->registrations[index].active)
            return 1;
    }
    return 0;
}

static int execute_start_epoll_worker(
    struct concurrent_context *context, char *save,
    struct concurrent_operation_result *result, enum worker_kind kind)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *maxevents_text = strtok_r(NULL, " \t", &save);
    char *timeout_text = strtok_r(NULL, " \t", &save);
    char *sigmask_text = kind == WORKER_EPOLL_WAIT ?
                             NULL :
                             strtok_r(NULL, " \t", &save);
    struct concurrent_worker_state *worker;
    struct epoll_object *epoll;
    long maxevents;
    long timeout_ms = -1;
    int64_t timeout_ns = -1;
    int block_sigusr1 = 0;
    int actor;
    int slot;

    if (parse_actor(actor_text, &actor) != 0 || parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(maxevents_text, 1, MAX_EPOLL_EVENTS, &maxevents) != 0 ||
        (kind != WORKER_EPOLL_PWAIT2 &&
         parse_long_value(timeout_text, -1, 1000, &timeout_ms) != 0) ||
        (kind == WORKER_EPOLL_PWAIT2 &&
         parse_timeout_ns(timeout_text, &timeout_ns) != 0) ||
        (kind != WORKER_EPOLL_WAIT &&
         (sigmask_text == NULL ||
          (strcmp(sigmask_text, "empty") != 0 &&
           strcmp(sigmask_text, "usr1") != 0))) ||
        strtok_r(NULL, " \t", &save) != NULL ||
        context->slot_epolls[slot] < 0 ||
        (kind != WORKER_EPOLL_PWAIT2 && timeout_ms >= 0 && timeout_ms < 100) ||
        (kind == WORKER_EPOLL_PWAIT2 && timeout_ns >= 0 &&
         timeout_ns < INT64_C(100000000)))
        return -1;
    if (kind != WORKER_EPOLL_WAIT)
        block_sigusr1 = strcmp(sigmask_text, "usr1") == 0;
    epoll = &context->epolls[context->slot_epolls[slot]];
    if (block_sigusr1 &&
        ((kind == WORKER_EPOLL_PWAIT && timeout_ms < 0) ||
         (kind == WORKER_EPOLL_PWAIT2 && timeout_ns < 0)) &&
        !epoll_has_registration(epoll))
        return -1;
    worker = &context->workers[actor - 1];
    if (worker->active)
        return -1;
    {
        struct controlled_worker *controller = worker->controller;

        memset(worker, 0, sizeof(*worker));
        worker->controller = controller;
        worker->handler_count = &context->signal_counts[actor - 1];
    }
    context->accounted_actor_mask &= ~(1U << (actor - 1));
    worker->kind = kind;
    worker->active = 1;
    worker->slot = slot;
    worker->fd = context->slots[slot];
    worker->peer_fd = -1;
    worker->epoll_object = context->slot_epolls[slot];
    worker->start_result_index = context->operation_index;
    worker->maxevents = (int)maxevents;
    worker->timeout_ms = (int)timeout_ms;
    worker->timeout_ns = timeout_ns;
    worker->block_sigusr1 = block_sigusr1;
    if (controlled_worker_start(worker->controller, run_worker, worker) !=
        CONTROLLED_WORKER_OK) {
        worker->active = 0;
        return -2;
    }
    result->kind = kind == WORKER_EPOLL_WAIT ? OP_START_EPOLL_WAIT :
                   kind == WORKER_EPOLL_PWAIT ? OP_START_EPOLL_PWAIT :
                                                OP_START_EPOLL_PWAIT2;
    result->actor = (uint32_t)actor;
    result->value = (uint64_t)maxevents;
    return 0;
}

static int execute_assert_pending(struct concurrent_context *context, char *save,
                                  struct concurrent_operation_result *result,
                                  int all)
{
    int first = 1;
    int last = CONTROLLED_WORKER_COUNT;
    int actor;

    if (!all) {
        char *actor_text = strtok_r(NULL, " \t", &save);

        if (parse_actor(actor_text, &first) != 0)
            return -1;
        last = first;
    }
    if (strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    for (actor = first; actor <= last; actor++) {
        struct concurrent_worker_state *worker = &context->workers[actor - 1];
        enum controlled_worker_status status;
        int progress_status;

        if (!worker->active)
            return -1;
        progress_status = wait_for_partial_write_progress(worker);
        if (progress_status != 0)
            return progress_status;
        status = controlled_worker_observe_pending(worker->controller);
        if (status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
            return -4;
        if (status == CONTROLLED_WORKER_COMPLETED_EARLY)
            return -3;
        if (status != CONTROLLED_WORKER_OK)
            return -2;
        worker->pending_confirmed = 1;
    }
    result->kind = all ? OP_ASSERT_ALL_PENDING : OP_ASSERT_PENDING;
    result->actor = all ? 0U : (uint32_t)first;
    return 0;
}

static int copy_completed_worker(struct concurrent_context *context, int actor)
{
    struct concurrent_worker_state *worker = &context->workers[actor - 1];
    struct concurrent_operation_result *start;
    enum controlled_worker_status status;

    if (!worker->active || !worker->pending_confirmed)
        return -1;
    status = controlled_worker_wait_for_completion(worker->controller);
    if (status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
        return -4;
    if (status != CONTROLLED_WORKER_OK)
        return -2;
    if (worker->clock_failed || worker->mask_failed)
        return -2;
    if (worker->timeout_too_early)
        return -5;
    account_worker(context, actor);
    start = &context->results[worker->start_result_index];
    start->result = worker->syscall_result.result;
    start->error_number = worker->syscall_result.error_number;
    start->value = worker->syscall_result.value;
    start->data_length = worker->syscall_result.data_length;
    start->handler_count = worker->syscall_result.handler_count;
    start->completion_ordinal =
        controlled_worker_completion_ordinal(worker->controller);
    memcpy(start->data, worker->syscall_result.data, sizeof(start->data));
    return 0;
}

static int execute_join(struct concurrent_context *context, char *save,
                        struct concurrent_operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    struct concurrent_worker_state *worker;
    int actor;
    int status;

    if (parse_actor(actor_text, &actor) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    status = copy_completed_worker(context, actor);
    if (status != 0)
        return status;
    worker = &context->workers[actor - 1];
    if (controlled_worker_join(worker->controller) != CONTROLLED_WORKER_OK)
        return -2;
    worker->active = 0;
    result->kind = OP_JOIN;
    result->actor = (uint32_t)actor;
    return 0;
}

static int execute_join_set(struct concurrent_context *context, char *save,
                            struct concurrent_operation_result *result)
{
    char *first_text = strtok_r(NULL, " \t", &save);
    char *second_text = strtok_r(NULL, " \t", &save);
    long first;
    long second;
    int actor;
    int status;

    if (parse_long_value(first_text, 1, 1, &first) != 0 ||
        parse_long_value(second_text, 2, 2, &second) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    for (actor = 1; actor <= CONTROLLED_WORKER_COUNT; actor++) {
        status = copy_completed_worker(context, actor);
        if (status != 0)
            return status;
    }
    if (controlled_workers_join_all(&context->controllers) != CONTROLLED_WORKER_OK)
        return -2;
    for (actor = 0; actor < CONTROLLED_WORKER_COUNT; actor++)
        context->workers[actor].active = 0;
    result->kind = OP_JOIN_SET;
    result->value = 3;
    return 0;
}

static int execute_signal_config(struct concurrent_context *context, char *save,
                                 struct concurrent_operation_result *result)
{
    char *signo_text = strtok_r(NULL, " \t", &save);
    char *flags_text = strtok_r(NULL, " \t", &save);
    long signo;
    long flags;

    if (parse_long_value(signo_text, SIGUSR1_NUMBER, SIGUSR1_NUMBER, &signo) != 0 ||
        parse_long_value(flags_text, 0, SA_RESTART_FLAG, &flags) != 0 ||
        (flags != 0 && flags != SA_RESTART_FLAG) ||
        strtok_r(NULL, " \t", &save) != NULL || context->workers[0].active ||
        context->workers[1].active)
        return -1;
    if (configure_count_signal_handler((int)signo, flags, NULL) != 0)
        return -2;
    context->signal_flags = flags;
    context->signal_configured = 1;
    result->kind = OP_SIGNAL_CONFIG;
    result->value = (uint64_t)flags;
    return 0;
}

static int execute_send_signal(struct concurrent_context *context, char *save,
                               struct concurrent_operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *signo_text = strtok_r(NULL, " \t", &save);
    struct concurrent_worker_state *worker;
    enum controlled_worker_status worker_status;
    unsigned int target_count;
    long signo;
    int actor;
    int status;

    if (parse_actor(actor_text, &actor) != 0 ||
        parse_long_value(signo_text, SIGUSR1_NUMBER, SIGUSR1_NUMBER, &signo) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL || !context->signal_configured)
        return -1;
    worker = &context->workers[actor - 1];
    if (!worker->active || !worker->pending_confirmed || worker->accounted)
        return -1;
    target_count =
        atomic_load_explicit(worker->handler_count, memory_order_acquire) + 1U;
    if (controlled_worker_send_signal(worker->controller, (int)signo) !=
        CONTROLLED_WORKER_OK)
        return -2;
    if ((worker->kind == WORKER_PPOLL ||
         worker->kind == WORKER_EPOLL_PWAIT ||
         worker->kind == WORKER_EPOLL_PWAIT2) &&
        worker->block_sigusr1) {
        status = 0;
    } else {
        status = wait_for_handler_count(worker->handler_count, target_count);
        if (status != 0)
            return status;
    }
    if ((worker->kind == WORKER_POLL || worker->kind == WORKER_PPOLL ||
         worker->kind == WORKER_EPOLL_WAIT ||
         worker->kind == WORKER_EPOLL_PWAIT ||
         worker->kind == WORKER_EPOLL_PWAIT2 || context->signal_flags == 0 ||
         worker->partial_progress_expected) &&
        !((worker->kind == WORKER_PPOLL ||
           worker->kind == WORKER_EPOLL_PWAIT ||
           worker->kind == WORKER_EPOLL_PWAIT2) &&
          worker->block_sigusr1)) {
        worker_status =
            controlled_worker_wait_for_completion(worker->controller);
        if (worker_status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
            return -4;
        if (worker_status != CONTROLLED_WORKER_OK)
            return -2;
        account_worker(context, actor);
    }
    result->kind = OP_SEND_SIGNAL;
    result->actor = (uint32_t)actor;
    result->value = (uint64_t)signo;
    result->handler_count = atomic_load_explicit(worker->handler_count,
                                                  memory_order_acquire);
    return 0;
}

static int execute_assert_signal_handled(
    struct concurrent_context *context, char *save,
    struct concurrent_operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *count_text = strtok_r(NULL, " \t", &save);
    unsigned int actual;
    long count;
    int actor;

    if (parse_actor(actor_text, &actor) != 0 ||
        parse_long_value(count_text, 0, CONCURRENT_MAX_OPERATIONS, &count) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    actual = atomic_load_explicit(&context->signal_counts[actor - 1],
                                  memory_order_acquire);
    if (actual != (unsigned int)count)
        return -1;
    result->kind = OP_ASSERT_SIGNAL_HANDLED;
    result->actor = (uint32_t)actor;
    result->handler_count = actual;
    return 0;
}

static int execute_operation(struct concurrent_context *context, char *line,
                             struct concurrent_operation_result *result)
{
    char *save = NULL;
    char *operation = strtok_r(line, " \t", &save);

    if (strcmp(operation, "pipe2") == 0)
        return execute_pipe2(context, save, result);
    if (strcmp(operation, "read") == 0)
        return execute_read(context, save, result);
    if (strcmp(operation, "write") == 0)
        return execute_write(context, save, result);
    if (strcmp(operation, "dup") == 0)
        return execute_dup(context, save, result);
    if (strcmp(operation, "close") == 0)
        return execute_close(context, save, result);
    if (strcmp(operation, "get-status-flags") == 0)
        return execute_fcntl(context, save, result, F_GETFL,
                             OP_GET_STATUS_FLAGS);
    if (strcmp(operation, "set-status-flags") == 0)
        return execute_fcntl(context, save, result, F_SETFL,
                             OP_SET_STATUS_FLAGS);
    if (strcmp(operation, "epoll-create") == 0)
        return execute_epoll_create(context, save, result);
    if (strcmp(operation, "epoll-ctl") == 0)
        return execute_epoll_ctl(context, save, result);
    if (strcmp(operation, "set-size") == 0)
        return execute_set_size(context, save, result);
    if (strcmp(operation, "start-read") == 0)
        return execute_start_worker(context, save, result, WORKER_READ);
    if (strcmp(operation, "start-write") == 0)
        return execute_start_worker(context, save, result, WORKER_WRITE);
    if (strcmp(operation, "start-poll") == 0)
        return execute_start_worker(context, save, result, WORKER_POLL);
    if (strcmp(operation, "start-ppoll") == 0)
        return execute_start_worker(context, save, result, WORKER_PPOLL);
    if (strcmp(operation, "start-epoll-wait") == 0)
        return execute_start_epoll_worker(context, save, result,
                                          WORKER_EPOLL_WAIT);
    if (strcmp(operation, "start-epoll-pwait") == 0)
        return execute_start_epoll_worker(context, save, result,
                                          WORKER_EPOLL_PWAIT);
    if (strcmp(operation, "start-epoll-pwait2") == 0)
        return execute_start_epoll_worker(context, save, result,
                                          WORKER_EPOLL_PWAIT2);
    if (strcmp(operation, "assert-pending") == 0)
        return execute_assert_pending(context, save, result, 0);
    if (strcmp(operation, "assert-all-pending") == 0)
        return execute_assert_pending(context, save, result, 1);
    if (strcmp(operation, "join") == 0)
        return execute_join(context, save, result);
    if (strcmp(operation, "join-set") == 0)
        return execute_join_set(context, save, result);
    if (strcmp(operation, "signal-config") == 0)
        return execute_signal_config(context, save, result);
    if (strcmp(operation, "send-signal") == 0)
        return execute_send_signal(context, save, result);
    if (strcmp(operation, "assert-signal-handled") == 0)
        return execute_assert_signal_handled(context, save, result);
    return -1;
}

static int process_operation(struct concurrent_context *context,
                             char *parse_line, const char *display_line,
                             unsigned int line_number)
{
    struct concurrent_operation_result *result;
    int status;

    if (context->operation_index >= CONCURRENT_MAX_OPERATIONS)
        return fail_line(line_number, display_line,
                         "scenario has too many operations");
    result = &context->results[context->operation_index];
    memset(result, 0, sizeof(*result));
    result->scenario_index = context->scenario_index;
    result->operation_index = context->operation_index;
    status = execute_operation(context, parse_line, result);
    if (status == -2)
        return fail_harness(line_number, display_line,
                            "thread, clock, sleep, or join operation failed");
    if (status == -3)
        return fail_line(line_number, display_line,
                         "worker completed before pending guard");
    if (status == -4)
        return fail_schedule_timeout(line_number, display_line);
    if (status == -5)
        return fail_syscall_timeout(line_number, display_line);
    if (status != 0)
        return fail_line(line_number, display_line, "invalid operation");
    context->operation_index++;
    context->total_operations++;
    return 0;
}

static void print_digest(const unsigned char digest[32])
{
    size_t index;

    for (index = 0; index < 32; index++)
        fprintf(stderr, "%02x", digest[index]);
}

static void print_vector(const unsigned char *payload, uint32_t payload_length)
{
    uint32_t index;

    for (index = 0; index < payload_length; index++)
        fprintf(stderr, "%02x", payload[index]);
}

static int finish_scenario(struct concurrent_context *context)
{
    unsigned char payload[CONCURRENT_MAX_OPERATIONS * CONCURRENT_RESULT_SIZE];
    uint32_t index;

    if (context->controllers.slots[0].started ||
        context->controllers.slots[1].started)
        return fail("scenario ends with active workers");
    for (index = 0; index < context->operation_index; index++) {
        if (concurrent_encode_result(&context->results[index],
                                     payload + index * CONCURRENT_RESULT_SIZE) != 0)
            return fail("cannot encode concurrent result");
    }
    if (context->record_mode) {
        if (concurrent_raw_write_scenario(
                &context->raw_writer, context->scenario_index,
                context->operation_index, payload,
                context->operation_index * CONCURRENT_RESULT_SIZE) != 0)
            return fail("cannot write concurrent raw scenario");
    } else {
        struct concurrent_mismatch mismatch;
        int comparison = concurrent_allowed_compare(
            &context->allowed_reader, context->scenario_index,
            context->operation_index, payload,
            context->operation_index * CONCURRENT_RESULT_SIZE, &mismatch);

        if (comparison < 0)
            return fail("invalid concurrent allowed trace");
        if (comparison > 0) {
            fprintf(stderr,
                    "STARRY_PIPE_CONCURRENT_MISMATCH: scenario=%" PRIu32
                    " alternative=%" PRIu32 " byte_offset=%" PRIu32
                    " expected_length=%" PRIu32 " actual_length=%" PRIu32
                    " expected_byte=%u actual_byte=%u set_digest=",
                    context->scenario_index, mismatch.alternative_index,
                    mismatch.byte_offset, mismatch.expected_length,
                    mismatch.actual_length, mismatch.expected_byte,
                    mismatch.actual_byte);
            print_digest(mismatch.allowed_set_digest);
            fprintf(stderr, " actual_digest=");
            print_digest(mismatch.actual_digest);
            fprintf(stderr, " actual_vector=");
            print_vector(payload,
                         context->operation_index * CONCURRENT_RESULT_SIZE);
            fputc('\n', stderr);
            return 1;
        }
    }
    return 0;
}

static int process_corpus(struct concurrent_context *context,
                          const char *corpus_path)
{
    FILE *corpus = fopen(corpus_path, "r");
    char raw_line[MAX_LINE_BYTES];
    unsigned int line_number = 0;
    int saw_version = 0;
    int saw_scenario = 0;
    int status = 0;

    if (corpus == NULL)
        return fail("cannot open operation corpus");
    while (fgets(raw_line, sizeof(raw_line), corpus) != NULL) {
        char parse_line[MAX_LINE_BYTES];
        char display_line[MAX_LINE_BYTES];
        char *comment;
        char *line;

        line_number++;
        if (strchr(raw_line, '\n') == NULL && !feof(corpus)) {
            status = fail_line(line_number, "<overlong>",
                               "corpus line is too long");
            break;
        }
        comment = strchr(raw_line, '#');
        if (comment != NULL)
            *comment = '\0';
        line = trim(raw_line);
        if (*line == '\0')
            continue;
        snprintf(parse_line, sizeof(parse_line), "%s", line);
        snprintf(display_line, sizeof(display_line), "%s", line);
        if (strncmp(line, "version ", 8) == 0) {
            long version;

            if (saw_version || saw_scenario ||
                parse_long_value(trim(line + 8), CORPUS_VERSION,
                                 CORPUS_VERSION, &version) != 0) {
                status = fail_line(line_number, display_line,
                                   "invalid corpus version");
                break;
            }
            saw_version = 1;
            continue;
        }
        if (strncmp(line, "scenario ", 9) == 0) {
            char *name = trim(line + 9);

            if (!saw_version || *name == '\0' || strchr(name, ' ') != NULL ||
                strchr(name, '\t') != NULL) {
                status = fail_line(line_number, display_line,
                                   "invalid scenario");
                break;
            }
            if (saw_scenario) {
                status = finish_scenario(context);
                if (status != 0)
                    break;
                if (cleanup_scenario(context) != 0) {
                    status = fail_harness(line_number, display_line,
                                          "scenario cleanup failed");
                    break;
                }
                context->scenario_index++;
                initialize_scenario(context);
            }
            saw_scenario = 1;
            continue;
        }
        if (!saw_scenario) {
            status = fail_line(line_number, display_line,
                               "operation appears before first scenario");
            break;
        }
        status = process_operation(context, parse_line, display_line, line_number);
        if (status != 0)
            break;
    }
    if (ferror(corpus) != 0 && status == 0)
        status = fail("cannot read operation corpus");
    if ((!saw_version || !saw_scenario || context->operation_index == 0) &&
        status == 0)
        status = fail("operation corpus is incomplete");
    if (status == 0)
        status = finish_scenario(context);
    if (cleanup_scenario(context) != 0 && status == 0)
        status = fail("cannot clean up concurrent scenario");
    if (fclose(corpus) != 0 && status == 0)
        status = fail("cannot close operation corpus");
    return status;
}

int pipe_concurrent_run(int record_mode, const char *corpus_path,
                        const char *trace_path, uint64_t corpus_digest)
{
    struct concurrent_context context;
    struct sigaction previous_action;
    int status;

    memset(&context, 0, sizeof(context));
    context.record_mode = record_mode;
    if (record_mode) {
        const char *bias = getenv("STARRY_PIPE_CONCURRENT_START_BIAS");

        if (bias != NULL) {
            long actor;

            if (parse_long_value(bias, 1, CONTROLLED_WORKER_COUNT, &actor) != 0)
                return fail("invalid concurrent start bias");
            context.preferred_actor = (int)actor;
        }
    }
    initialize_scenario(&context);
    if (!atomic_is_lock_free(&context.signal_counts[0]) ||
        !atomic_is_lock_free(&context.signal_counts[1]))
        return fail("signal handler counter is not lock-free");
    if (configure_count_signal_handler(SIGUSR1, 0, &previous_action) != 0)
        return fail("cannot install concurrent cleanup signal handler");
    if (record_mode) {
        if (concurrent_raw_open(&context.raw_writer, trace_path, raw_magic,
                                CORPUS_VERSION, corpus_digest) != 0) {
            (void)sigaction(SIGUSR1, &previous_action, NULL);
            return fail("cannot create concurrent raw trace");
        }
    } else if (concurrent_allowed_open(&context.allowed_reader, trace_path,
                                       allowed_magic, CORPUS_VERSION,
                                       corpus_digest) != 0) {
        (void)sigaction(SIGUSR1, &previous_action, NULL);
        return fail("invalid concurrent allowed trace header");
    }
    status = process_corpus(&context, corpus_path);
    if (status == 0) {
        int close_status = record_mode ? concurrent_raw_close(&context.raw_writer) :
                                         concurrent_allowed_close(&context.allowed_reader);

        if (close_status != 0)
            status = fail("cannot finalize concurrent trace");
    } else if (record_mode && context.raw_writer.file != NULL) {
        (void)fclose(context.raw_writer.file);
    } else if (!record_mode && context.allowed_reader.encoded != NULL) {
        free(context.allowed_reader.encoded);
    }
    if (sigaction(SIGUSR1, &previous_action, NULL) != 0 && status == 0)
        status = fail("cannot restore concurrent cleanup signal handler");
    if (status == 0) {
        printf("STARRY_PIPE_LINUX_ORACLE_PASSED: operations=%" PRIu32
               " scenarios=%" PRIu32 "\n",
               context.total_operations, context.scenario_index + 1U);
    }
    return status;
}
