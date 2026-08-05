#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "controlled_worker.h"
#include "eventfd_concurrent_oracle.h"

#define SIMPLE_CORPUS_VERSION 1L
#define BLOCKING_CORPUS_VERSION 2L
#define POLL_CORPUS_VERSION 3L
#define CONCURRENT_CORPUS_VERSION 4L
#define MAX_SLOTS 16
#define MAX_OBJECTS 32
#define MAX_IO_BYTES 16
#define MAX_POLL_FDS 4
#define MAX_LINE_BYTES 512
#define DUP_TARGET_FD_BASE 64
#define TRACE_RELEASE_BYTES 64
#define TRACE_MACHINE_BYTES 32
#define EFD_SEMAPHORE_FLAG 1L
#define UNKNOWN_FLAG 0x40000000L
#define READ_SENTINEL 0xa5U
#define POLL_REVENTS_SENTINEL ((short)0x5a5a)
#define WORKER_ACTOR 1L

static const unsigned char trace_magic_v1[8] = {'E', 'V', 'F', 'D', 'O', 'R', 'C', '1'};
static const unsigned char trace_magic_v2[8] = {'E', 'V', 'F', 'D', 'O', 'R', 'C', '2'};
static const unsigned char trace_magic_v3[8] = {'E', 'V', 'F', 'D', 'O', 'R', 'C', '3'};

enum operation_kind {
    OP_EVENTFD = 1,
    OP_EVENTFD2,
    OP_READ,
    OP_WRITE,
    OP_DUP,
    OP_DUP2,
    OP_DUP3,
    OP_CLOSE,
    OP_GET_STATUS_FLAGS,
    OP_SET_STATUS_FLAGS,
    OP_GET_FD_FLAGS,
    OP_SET_FD_FLAGS,
    OP_POLL_MANY,
    OP_START_READ,
    OP_START_WRITE,
    OP_ASSERT_PENDING,
    OP_JOIN,
    OP_START_POLL,
};

enum operation_difference {
    DIFF_SCENARIO = 1U << 0,
    DIFF_OPERATION = 1U << 1,
    DIFF_KIND = 1U << 2,
    DIFF_RESULT = 1U << 3,
    DIFF_ERRNO = 1U << 4,
    DIFF_VALUE = 1U << 5,
    DIFF_DATA_LEN = 1U << 6,
    DIFF_DATA = 1U << 7,
};

struct trace_header {
    unsigned char magic[8];
    uint32_t version;
    uint32_t record_count;
    uint64_t corpus_digest;
    uint32_t page_size;
    char release[TRACE_RELEASE_BYTES];
    char machine[TRACE_MACHINE_BYTES];
};

struct operation_result {
    uint32_t scenario_index;
    uint32_t operation_index;
    uint32_t kind;
    uint32_t data_len;
    int64_t result;
    uint64_t value;
    int32_t error;
    unsigned char data[MAX_IO_BYTES];
};

struct event_object {
    uint64_t count;
    int semaphore;
    int nonblocking;
};

enum run_mode {
    MODE_RECORD,
    MODE_COMPARE,
};

enum worker_kind {
    WORKER_READ,
    WORKER_WRITE,
    WORKER_POLL,
};

struct worker_state {
    struct controlled_worker controller;
    enum worker_kind kind;
    struct operation_result result;
    int active;
    int pending_confirmed;
    int completable;
    int slot;
    int fd;
    int object;
    uint64_t value;
    struct pollfd poll_fd;
};

struct run_context {
    enum run_mode mode;
    FILE *trace;
    struct trace_header header;
    int slots[MAX_SLOTS];
    int slot_objects[MAX_SLOTS];
    struct event_object objects[MAX_OBJECTS];
    int object_count;
    long corpus_version;
    struct worker_state worker;
    uint32_t scenario_index;
    uint32_t operation_index;
};

static int fail(const char *message)
{
    fprintf(stderr, "STARRY_EVENTFD_LINUX_ORACLE_FAILED: %s\n", message);
    return 1;
}

static int fail_line(unsigned int line_number, const char *line, const char *message)
{
    fprintf(stderr,
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: line=%u operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static int fail_schedule_timeout(unsigned int line_number, const char *line)
{
    fprintf(stderr,
            "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=%u operation=\"%s\"\n",
            line_number, line);
    return 1;
}

static int fail_harness(unsigned int line_number, const char *line,
                        const char *message)
{
    fprintf(stderr,
            "STARRY_EVENTFD_LINUX_ORACLE_HARNESS_ERROR: line=%u operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static void initialize_scenario(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        context->slots[index] = -1;
        context->slot_objects[index] = -1;
    }
    memset(context->objects, 0, sizeof(context->objects));
    context->object_count = 0;
    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
}

static void close_scenario(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        if (context->slots[index] >= 0) {
            (void)syscall(SYS_close, context->slots[index]);
            context->slots[index] = -1;
            context->slot_objects[index] = -1;
        }
    }
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

static int supported_eventfd_flags(long flags)
{
    long allowed = EFD_SEMAPHORE_FLAG | O_NONBLOCK | O_CLOEXEC;

    return (flags & ~allowed) == 0 || flags == UNKNOWN_FLAG;
}

static int supported_dup3_flags(long flags)
{
    return flags == 0 || flags == O_CLOEXEC || flags == O_NONBLOCK ||
           flags == (O_CLOEXEC | O_NONBLOCK) || flags == UNKNOWN_FLAG;
}

static int supported_poll_literal(long fd)
{
    return fd == -2 || fd == -1 || fd == INT_MAX;
}

static int controlled_corpus_version(long version)
{
    return version == BLOCKING_CORPUS_VERSION || version == POLL_CORPUS_VERSION;
}

static const unsigned char *trace_magic_for_version(long version)
{
    if (version == SIMPLE_CORPUS_VERSION)
        return trace_magic_v1;
    if (version == BLOCKING_CORPUS_VERSION)
        return trace_magic_v2;
    if (version == POLL_CORPUS_VERSION)
        return trace_magic_v3;
    return NULL;
}

static int destination_fd(const struct run_context *context, int slot)
{
    return context->slots[slot] >= 0 ? context->slots[slot]
                                     : DUP_TARGET_FD_BASE + slot;
}

static void finish_syscall_result(struct operation_result *result, long syscall_result)
{
    result->result = syscall_result;
    result->error = syscall_result < 0 ? errno : 0;
}

static void *run_worker(void *argument)
{
    struct worker_state *worker = argument;
    long syscall_result;

    if (worker->kind == WORKER_READ) {
        unsigned char buffer[MAX_IO_BYTES];
        uint64_t decoded;

        memset(buffer, READ_SENTINEL, sizeof(buffer));
        controlled_worker_publish_entered(&worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_read, worker->fd, buffer, 8U);
        finish_syscall_result(&worker->result, syscall_result);
        memcpy(&decoded, buffer, sizeof(decoded));
        worker->result.value = decoded;
        worker->result.data_len = sizeof(buffer);
        memcpy(worker->result.data, buffer, sizeof(buffer));
    } else if (worker->kind == WORKER_WRITE) {
        controlled_worker_publish_entered(&worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_write, worker->fd, &worker->value, 8U);
        finish_syscall_result(&worker->result, syscall_result);
    } else {
        uint16_t revents;

        controlled_worker_publish_entered(&worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_poll, &worker->poll_fd, 1U, -1L);
        finish_syscall_result(&worker->result, syscall_result);
        revents = (uint16_t)worker->poll_fd.revents;
        worker->result.data_len = sizeof(revents);
        worker->result.data[0] = (unsigned char)(revents & 0xffU);
        worker->result.data[1] = (unsigned char)(revents >> 8);
    }
    controlled_worker_publish_completed(&worker->controller);
    return NULL;
}

static struct event_object *object_for_slot(struct run_context *context, int slot)
{
    int object = context->slot_objects[slot];

    return object >= 0 ? &context->objects[object] : NULL;
}

static int valid_controller_trigger(const struct run_context *context, int slot,
                                    long length, long pointer_mode,
                                    int is_write, uint64_t value)
{
    if (!context->worker.active)
        return 1;
    if (!context->worker.pending_confirmed || context->worker.completable ||
        context->slots[slot] < 0 || context->slot_objects[slot] < 0 ||
        context->slot_objects[slot] != context->worker.object || length != 8 ||
        pointer_mode != 0)
        return 0;
    return !is_write || value != UINT64_MAX;
}

static void update_worker_completable(struct run_context *context)
{
    struct event_object *object;

    if (!context->worker.active)
        return;
    object = &context->objects[context->worker.object];
    if (context->worker.kind == WORKER_READ)
        context->worker.completable = object->count > 0;
    else if (context->worker.kind == WORKER_WRITE)
        context->worker.completable =
            UINT64_MAX - object->count > context->worker.value;
    else if (context->worker.poll_fd.events == POLLIN)
        context->worker.completable = object->count > 0;
    else
        context->worker.completable = UINT64_MAX - 1U > object->count;
}

static int create_object(struct run_context *context, int slot, uint64_t initval,
                         long flags, int fd)
{
    struct event_object *object;

    if (context->object_count >= MAX_OBJECTS || context->slots[slot] >= 0)
        return -1;
    object = &context->objects[context->object_count];
    object->count = initval;
    object->semaphore = (flags & EFD_SEMAPHORE_FLAG) != 0;
    object->nonblocking = (flags & O_NONBLOCK) != 0;
    context->slots[slot] = fd;
    context->slot_objects[slot] = context->object_count++;
    return 0;
}

static int execute_eventfd(struct run_context *context, char *save,
                           struct operation_result *result, int with_flags)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *initval_text = strtok_r(NULL, " \t", &save);
    char *flags_text = with_flags ? strtok_r(NULL, " \t", &save) : NULL;
    int slot;
    uint64_t initval;
    long flags = 0;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_u64_value(initval_text, &initval) != 0 || initval > UINT32_MAX ||
        (with_flags && parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        (with_flags && !supported_eventfd_flags(flags)) ||
        strtok_r(NULL, " \t", &save) != NULL ||
        (((flags & ~(EFD_SEMAPHORE_FLAG | O_NONBLOCK | O_CLOEXEC)) == 0) &&
         context->slots[slot] >= 0))
        return -1;

    errno = 0;
    syscall_result = with_flags
                         ? syscall(SYS_eventfd2, (unsigned int)initval, (int)flags)
                         : syscall(SYS_eventfd, (unsigned int)initval);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0 &&
        create_object(context, slot, initval, flags, (int)syscall_result) != 0) {
        (void)syscall(SYS_close, syscall_result);
        return -1;
    }
    result->kind = with_flags ? OP_EVENTFD2 : OP_EVENTFD;
    return 0;
}

static int read_cannot_block(const struct run_context *context, int slot, long length)
{
    int object = context->slot_objects[slot];

    if (context->slots[slot] < 0 || length < 8 || object < 0)
        return 1;
    return context->objects[object].count > 0 ||
           context->objects[object].nonblocking;
}

static int execute_read(struct run_context *context, char *save,
                        struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    char *pointer_text = strtok_r(NULL, " \t", &save);
    unsigned char buffer[MAX_IO_BYTES];
    uint64_t decoded;
    struct event_object *object;
    long length;
    long pointer_mode;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        parse_long_value(pointer_text, 0, 1, &pointer_mode) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL ||
        !read_cannot_block(context, slot, length) ||
        (context->worker.active &&
         !valid_controller_trigger(context, slot, length, pointer_mode, 0, 0)))
        return -1;

    memset(buffer, READ_SENTINEL, sizeof(buffer));
    errno = 0;
    syscall_result = syscall(SYS_read, context->slots[slot],
                             pointer_mode == 0 ? buffer : (void *)(uintptr_t)1,
                             (size_t)length);
    finish_syscall_result(result, syscall_result);
    memcpy(&decoded, buffer, sizeof(decoded));
    result->value = decoded;
    result->data_len = sizeof(buffer);
    memcpy(result->data, buffer, sizeof(buffer));
    object = object_for_slot(context, slot);
    if (object != NULL && length >= 8 && object->count > 0) {
        uint64_t consumed = object->semaphore ? 1 : object->count;

        object->count -= consumed;
    }
    update_worker_completable(context);
    result->kind = OP_READ;
    return 0;
}

static int write_cannot_block(const struct run_context *context, int slot, long length,
                              long pointer_mode, uint64_t value)
{
    int object = context->slot_objects[slot];

    if (context->slots[slot] < 0 || length < 8 || pointer_mode != 0 ||
        value == UINT64_MAX || object < 0)
        return 1;
    return UINT64_MAX - context->objects[object].count > value ||
           context->objects[object].nonblocking;
}

static int execute_write(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    char *pointer_text = strtok_r(NULL, " \t", &save);
    char *value_text = strtok_r(NULL, " \t", &save);
    struct event_object *object;
    uint64_t value;
    long length;
    long pointer_mode;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        parse_long_value(pointer_text, 0, 1, &pointer_mode) != 0 ||
        parse_u64_value(value_text, &value) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL ||
        !write_cannot_block(context, slot, length, pointer_mode, value) ||
        (context->worker.active &&
         !valid_controller_trigger(context, slot, length, pointer_mode, 1,
                                   value)))
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_write, context->slots[slot],
                             pointer_mode == 0 ? &value : (void *)(uintptr_t)1,
                             (size_t)length);
    finish_syscall_result(result, syscall_result);
    object = object_for_slot(context, slot);
    if (object != NULL && length >= 8 && pointer_mode == 0 &&
        value != UINT64_MAX && UINT64_MAX - object->count > value)
        object->count += value;
    update_worker_completable(context);
    result->kind = OP_WRITE;
    return 0;
}

static int execute_dup(struct run_context *context, char *save,
                       struct operation_result *result)
{
    char *source_text = strtok_r(NULL, " \t", &save);
    char *destination_text = strtok_r(NULL, " \t", &save);
    int source;
    int destination;
    long syscall_result;

    if (parse_slot(source_text, &source) != 0 ||
        parse_slot(destination_text, &destination) != 0 || source == destination ||
        context->slots[destination] >= 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_dup, context->slots[source]);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0) {
        context->slots[destination] = (int)syscall_result;
        context->slot_objects[destination] = context->slot_objects[source];
    }
    result->kind = OP_DUP;
    return 0;
}

static int execute_dup_to(struct run_context *context, char *save,
                          struct operation_result *result, int use_dup3)
{
    char *source_text = strtok_r(NULL, " \t", &save);
    char *destination_text = strtok_r(NULL, " \t", &save);
    char *flags_text = use_dup3 ? strtok_r(NULL, " \t", &save) : NULL;
    long flags = 0;
    long syscall_result;
    int source;
    int destination;
    int target_fd;

    if (parse_slot(source_text, &source) != 0 ||
        parse_slot(destination_text, &destination) != 0 ||
        (use_dup3 && parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        (use_dup3 && !supported_dup3_flags(flags)) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    target_fd = destination_fd(context, destination);
    errno = 0;
    syscall_result = use_dup3
                         ? syscall(SYS_dup3, context->slots[source], target_fd,
                                   (int)flags)
                         : syscall(SYS_dup2, context->slots[source], target_fd);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0) {
        context->slots[destination] = (int)syscall_result;
        context->slot_objects[destination] = context->slot_objects[source];
    }
    result->kind = use_dup3 ? OP_DUP3 : OP_DUP2;
    return 0;
}

static int execute_close(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    int slot;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_close, context->slots[slot]);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        context->slots[slot] = -1;
        context->slot_objects[slot] = -1;
    }
    result->kind = OP_CLOSE;
    return 0;
}

static int execute_fcntl(struct run_context *context, char *save,
                         struct operation_result *result, int command,
                         uint32_t kind, int normalized_mask)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = (command == F_SETFL || command == F_SETFD)
                           ? strtok_r(NULL, " \t", &save)
                           : NULL;
    struct event_object *object;
    long flags = 0;
    long syscall_result;
    int slot;

    if (parse_slot(slot_text, &slot) != 0 ||
        (flags_text != NULL && parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        ((command == F_SETFL) && flags != 0 && flags != O_NONBLOCK) ||
        ((command == F_SETFD) && flags != 0 && flags != FD_CLOEXEC) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_fcntl, context->slots[slot], command, flags);
    if (command == F_GETFL || command == F_GETFD) {
        finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
        result->value = syscall_result < 0
                            ? UINT64_MAX
                            : (uint64_t)(syscall_result & normalized_mask);
    } else {
        finish_syscall_result(result, syscall_result);
    }
    object = object_for_slot(context, slot);
    if (command == F_SETFL && syscall_result == 0 && object != NULL)
        object->nonblocking = (flags & O_NONBLOCK) != 0;
    result->kind = kind;
    return 0;
}

static int execute_poll_many(struct run_context *context, char *save,
                             struct operation_result *result)
{
    char *count_text = strtok_r(NULL, " \t", &save);
    struct pollfd poll_fds[MAX_POLL_FDS];
    long count;
    long entry_index;
    long syscall_result;

    if (parse_long_value(count_text, 0, MAX_POLL_FDS, &count) != 0)
        return -1;
    memset(poll_fds, 0, sizeof(poll_fds));
    for (entry_index = 0; entry_index < count; entry_index++) {
        char *mode_text = strtok_r(NULL, " \t", &save);
        char *fd_text = strtok_r(NULL, " \t", &save);
        char *events_text = strtok_r(NULL, " \t", &save);
        long mode;
        long fd_arg;
        long events;

        if (parse_long_value(mode_text, 0, 1, &mode) != 0 ||
            parse_long_value(fd_text, INT_MIN, INT_MAX, &fd_arg) != 0 ||
            parse_long_value(events_text, 0, SHRT_MAX, &events) != 0 ||
            (mode == 0 && (fd_arg < 0 || fd_arg >= MAX_SLOTS)) ||
            (mode == 1 && !supported_poll_literal(fd_arg)))
            return -1;
        poll_fds[entry_index].fd =
            mode == 0 ? context->slots[fd_arg] : (int)fd_arg;
        poll_fds[entry_index].events = (short)events;
        poll_fds[entry_index].revents = POLL_REVENTS_SENTINEL;
    }
    if (strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    errno = 0;
    syscall_result = syscall(SYS_poll, poll_fds, (nfds_t)count, 0L);
    finish_syscall_result(result, syscall_result);
    result->value = (uint64_t)count;
    result->data_len = (uint32_t)count * 2U;
    for (entry_index = 0; entry_index < count; entry_index++) {
        uint16_t revents = (uint16_t)poll_fds[entry_index].revents;

        result->data[entry_index * 2] = (unsigned char)(revents & 0xffU);
        result->data[entry_index * 2 + 1] = (unsigned char)(revents >> 8);
    }
    result->kind = OP_POLL_MANY;
    return 0;
}

static int execute_start_worker(struct run_context *context, char *save,
                                struct operation_result *result, int is_write)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *value_text = is_write ? strtok_r(NULL, " \t", &save) : NULL;
    struct event_object *object;
    uint64_t value = 0;
    long actor;
    int slot;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION ||
        parse_long_value(actor_text, WORKER_ACTOR, WORKER_ACTOR, &actor) != 0 ||
        parse_slot(slot_text, &slot) != 0 ||
        (is_write && parse_u64_value(value_text, &value) != 0) ||
        strtok_r(NULL, " \t", &save) != NULL || context->worker.active ||
        context->slots[slot] < 0 || context->slot_objects[slot] < 0)
        return -1;
    object = object_for_slot(context, slot);
    if (object == NULL || object->nonblocking ||
        (!is_write && object->count != 0) ||
        (is_write &&
         (value == UINT64_MAX || UINT64_MAX - object->count > value)))
        return -1;

    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
    context->worker.kind = is_write ? WORKER_WRITE : WORKER_READ;
    context->worker.active = 1;
    context->worker.slot = slot;
    context->worker.fd = context->slots[slot];
    context->worker.object = context->slot_objects[slot];
    context->worker.value = value;
    if (controlled_worker_start(&context->worker.controller, run_worker,
                                &context->worker) != CONTROLLED_WORKER_OK) {
        context->worker.active = 0;
        return -2;
    }
    result->kind = is_write ? OP_START_WRITE : OP_START_READ;
    result->value = value;
    return 0;
}

static int execute_start_poll(struct run_context *context, char *save,
                              struct operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *events_text = strtok_r(NULL, " \t", &save);
    struct event_object *object;
    long actor;
    long events;
    int slot;

    if (context->corpus_version != POLL_CORPUS_VERSION ||
        parse_long_value(actor_text, WORKER_ACTOR, WORKER_ACTOR, &actor) != 0 ||
        parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(events_text, POLLIN, POLLOUT, &events) != 0 ||
        (events != POLLIN && events != POLLOUT) ||
        strtok_r(NULL, " \t", &save) != NULL || context->worker.active ||
        context->slots[slot] < 0 || context->slot_objects[slot] < 0)
        return -1;
    object = object_for_slot(context, slot);
    if (object == NULL || (events == POLLIN && object->count != 0) ||
        (events == POLLOUT && object->count != UINT64_MAX - 1U))
        return -1;

    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
    context->worker.kind = WORKER_POLL;
    context->worker.active = 1;
    context->worker.slot = slot;
    context->worker.fd = context->slots[slot];
    context->worker.object = context->slot_objects[slot];
    context->worker.poll_fd.fd = context->slots[slot];
    context->worker.poll_fd.events = (short)events;
    context->worker.poll_fd.revents = POLL_REVENTS_SENTINEL;
    if (controlled_worker_start(&context->worker.controller, run_worker,
                                &context->worker) != CONTROLLED_WORKER_OK) {
        context->worker.active = 0;
        return -2;
    }
    result->kind = OP_START_POLL;
    result->value = (uint64_t)events;
    return 0;
}

static int execute_assert_pending(struct run_context *context, char *save,
                                  struct operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    long actor;
    enum controlled_worker_status pending_status;

    if (!controlled_corpus_version(context->corpus_version) ||
        parse_long_value(actor_text, WORKER_ACTOR, WORKER_ACTOR, &actor) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL || !context->worker.active ||
        context->worker.completable)
        return -1;
    pending_status =
        controlled_worker_observe_pending(&context->worker.controller);
    if (pending_status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
        return -4;
    if (pending_status != CONTROLLED_WORKER_OK &&
        pending_status != CONTROLLED_WORKER_COMPLETED_EARLY)
        return -2;
    result->kind = OP_ASSERT_PENDING;
    result->result =
        pending_status == CONTROLLED_WORKER_COMPLETED_EARLY ? 1 : 0;
    if (pending_status == CONTROLLED_WORKER_COMPLETED_EARLY)
        return context->mode == MODE_RECORD ? -3 : 0;
    context->worker.pending_confirmed = 1;
    return 0;
}

static int execute_join(struct run_context *context, char *save,
                        struct operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    struct event_object *object;
    long actor;
    enum controlled_worker_status wait_status;

    if (!controlled_corpus_version(context->corpus_version) ||
        parse_long_value(actor_text, WORKER_ACTOR, WORKER_ACTOR, &actor) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL || !context->worker.active ||
        !context->worker.pending_confirmed || !context->worker.completable)
        return -1;
    wait_status =
        controlled_worker_wait_for_completion(&context->worker.controller);
    if (wait_status == CONTROLLED_WORKER_COMPLETION_TIMEOUT)
        return -4;
    if (wait_status != CONTROLLED_WORKER_OK)
        return -2;
    if (controlled_worker_join(&context->worker.controller) !=
        CONTROLLED_WORKER_OK)
        return -2;

    result->kind = OP_JOIN;
    result->result = context->worker.result.result;
    result->error = context->worker.result.error;
    result->value = context->worker.result.value;
    result->data_len = context->worker.result.data_len;
    memcpy(result->data, context->worker.result.data, sizeof(result->data));

    object = &context->objects[context->worker.object];
    if (context->worker.kind == WORKER_READ) {
        uint64_t consumed = object->semaphore ? 1 : object->count;

        object->count -= consumed;
    } else if (context->worker.kind == WORKER_WRITE) {
        object->count += context->worker.value;
    }
    context->worker.active = 0;
    return 0;
}

static int execute_operation(struct run_context *context, char *line,
                             struct operation_result *result)
{
    char *save = NULL;
    char *operation = strtok_r(line, " \t", &save);

    if (context->worker.active && strcmp(operation, "read") != 0 &&
        strcmp(operation, "write") != 0 &&
        strcmp(operation, "assert-pending") != 0 &&
        strcmp(operation, "join") != 0)
        return -1;

    if (strcmp(operation, "eventfd") == 0)
        return execute_eventfd(context, save, result, 0);
    if (strcmp(operation, "eventfd2") == 0)
        return execute_eventfd(context, save, result, 1);
    if (strcmp(operation, "read") == 0)
        return execute_read(context, save, result);
    if (strcmp(operation, "write") == 0)
        return execute_write(context, save, result);
    if (strcmp(operation, "dup") == 0)
        return execute_dup(context, save, result);
    if (strcmp(operation, "dup2") == 0)
        return execute_dup_to(context, save, result, 0);
    if (strcmp(operation, "dup3") == 0)
        return execute_dup_to(context, save, result, 1);
    if (strcmp(operation, "close") == 0)
        return execute_close(context, save, result);
    if (strcmp(operation, "get-status-flags") == 0)
        return execute_fcntl(context, save, result, F_GETFL,
                             OP_GET_STATUS_FLAGS, O_NONBLOCK);
    if (strcmp(operation, "set-status-flags") == 0)
        return execute_fcntl(context, save, result, F_SETFL,
                             OP_SET_STATUS_FLAGS, 0);
    if (strcmp(operation, "get-fd-flags") == 0)
        return execute_fcntl(context, save, result, F_GETFD,
                             OP_GET_FD_FLAGS, FD_CLOEXEC);
    if (strcmp(operation, "set-fd-flags") == 0)
        return execute_fcntl(context, save, result, F_SETFD,
                             OP_SET_FD_FLAGS, 0);
    if (strcmp(operation, "poll-many") == 0)
        return execute_poll_many(context, save, result);
    if (strcmp(operation, "start-read") == 0)
        return execute_start_worker(context, save, result, 0);
    if (strcmp(operation, "start-write") == 0)
        return execute_start_worker(context, save, result, 1);
    if (strcmp(operation, "start-poll") == 0)
        return execute_start_poll(context, save, result);
    if (strcmp(operation, "assert-pending") == 0)
        return execute_assert_pending(context, save, result);
    if (strcmp(operation, "join") == 0)
        return execute_join(context, save, result);
    return -1;
}

static int compare_operation(const struct run_context *context,
                             const struct operation_result *actual,
                             unsigned int line_number, const char *line)
{
    struct operation_result expected;
    uint32_t difference_mask = 0;
    uint32_t compared_data;

    if (fread(&expected, sizeof(expected), 1, context->trace) != 1)
        return fail_line(line_number, line, "expected trace is truncated");
    if (expected.data_len > MAX_IO_BYTES)
        return fail_line(line_number, line, "expected trace data length is invalid");
    if (expected.scenario_index != actual->scenario_index)
        difference_mask |= DIFF_SCENARIO;
    if (expected.operation_index != actual->operation_index)
        difference_mask |= DIFF_OPERATION;
    if (expected.kind != actual->kind)
        difference_mask |= DIFF_KIND;
    if (expected.result != actual->result)
        difference_mask |= DIFF_RESULT;
    if (expected.error != actual->error)
        difference_mask |= DIFF_ERRNO;
    if (expected.value != actual->value)
        difference_mask |= DIFF_VALUE;
    if (expected.data_len != actual->data_len)
        difference_mask |= DIFF_DATA_LEN;
    compared_data = expected.data_len > actual->data_len ? expected.data_len
                                                         : actual->data_len;
    if (memcmp(expected.data, actual->data, compared_data) != 0)
        difference_mask |= DIFF_DATA;
    if (difference_mask != 0) {
        fprintf(stderr,
                "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=%s/%s line=%u "
                "scenario=%" PRIu32 " operation=%" PRIu32
                " text=\"%s\" difference_mask=0x%08" PRIx32
                " expected={kind=%" PRIu32 ",result=%" PRId64
                ",errno=%" PRId32 ",value=%" PRIu64 ",data_len=%" PRIu32
                "} actual={kind=%" PRIu32 ",result=%" PRId64
                ",errno=%" PRId32 ",value=%" PRIu64 ",data_len=%" PRIu32 "}\n",
                context->header.release, context->header.machine, line_number,
                actual->scenario_index, actual->operation_index, line,
                difference_mask, expected.kind, expected.result, expected.error,
                expected.value, expected.data_len, actual->kind, actual->result,
                actual->error, actual->value, actual->data_len);
        return 1;
    }
    return 0;
}

static int process_operation(struct run_context *context, char *parse_line,
                             const char *display_line, unsigned int line_number)
{
    struct operation_result result;
    int execution_status;

    memset(&result, 0, sizeof(result));
    result.scenario_index = context->scenario_index;
    result.operation_index = context->operation_index;
    execution_status = execute_operation(context, parse_line, &result);
    if (execution_status == -2)
        return fail_harness(line_number, display_line,
                            "thread or monotonic-clock operation failed");
    if (execution_status == -3)
        return fail_line(line_number, display_line,
                         "worker completed before pending guard");
    if (execution_status == -4)
        return fail_schedule_timeout(line_number, display_line);
    if (execution_status != 0)
        return fail_line(line_number, display_line, "invalid operation");
    if (context->mode == MODE_RECORD) {
        if (fwrite(&result, sizeof(result), 1, context->trace) != 1)
            return fail_line(line_number, display_line, "cannot write trace record");
    } else if (compare_operation(context, &result, line_number, display_line) != 0) {
        return 1;
    }
    context->operation_index++;
    return 0;
}

static int process_corpus(struct run_context *context, const char *corpus_path)
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
            status = fail_line(line_number, "<overlong>", "corpus line is too long");
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
                parse_long_value(trim(line + 8), context->corpus_version,
                                 context->corpus_version, &version) != 0) {
                status = fail_line(line_number, display_line, "invalid corpus version");
                break;
            }
            saw_version = 1;
            continue;
        }
        if (strncmp(line, "scenario ", 9) == 0) {
            char *name = trim(line + 9);

            if (!saw_version || *name == '\0' || strchr(name, ' ') != NULL ||
                strchr(name, '\t') != NULL ||
                (saw_scenario && context->worker.active)) {
                status = fail_line(line_number, display_line, "invalid scenario");
                break;
            }
            close_scenario(context);
            initialize_scenario(context);
            context->scenario_index = saw_scenario ? context->scenario_index + 1U : 0U;
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
    if ((!saw_version || !saw_scenario || context->operation_index == 0U) && status == 0)
        status = fail("operation corpus is incomplete");
    if (context->worker.active && status == 0)
        status = fail("operation corpus ends with an active worker");
    close_scenario(context);
    if (fclose(corpus) != 0 && status == 0)
        status = fail("cannot close operation corpus");
    return status;
}

static int digest_file(const char *path, uint64_t *digest)
{
    FILE *file = fopen(path, "rb");
    unsigned char buffer[4096];
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t count;

    if (file == NULL)
        return -1;
    while ((count = fread(buffer, 1, sizeof(buffer), file)) > 0U) {
        size_t index;

        for (index = 0; index < count; index++) {
            hash ^= buffer[index];
            hash *= UINT64_C(1099511628211);
        }
    }
    if (ferror(file) != 0 || fclose(file) != 0)
        return -1;
    *digest = hash;
    return 0;
}

static int read_corpus_version(const char *path, long *version)
{
    FILE *corpus = fopen(path, "r");
    char raw_line[MAX_LINE_BYTES];
    int status = -1;

    if (corpus == NULL)
        return -1;
    while (fgets(raw_line, sizeof(raw_line), corpus) != NULL) {
        char *comment = strchr(raw_line, '#');
        char *line;

        if (comment != NULL)
            *comment = '\0';
        line = trim(raw_line);
        if (*line == '\0')
            continue;
        if (strncmp(line, "version ", 8) == 0 &&
            parse_long_value(trim(line + 8), SIMPLE_CORPUS_VERSION,
                             CONCURRENT_CORPUS_VERSION, version) == 0)
            status = 0;
        break;
    }
    if (ferror(corpus) != 0)
        status = -1;
    if (fclose(corpus) != 0)
        status = -1;
    return status;
}

static void copy_metadata(char *destination, size_t capacity, const char *source)
{
    size_t length = strnlen(source, capacity - 1U);

    memcpy(destination, source, length);
    destination[length] = '\0';
}

static int initialize_record_header(struct trace_header *header,
                                    uint64_t corpus_digest, long corpus_version)
{
    const unsigned char *magic = trace_magic_for_version(corpus_version);
    struct utsname system_name;
    long page_size;

    if (magic == NULL)
        return -1;
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, magic, sizeof(header->magic));
    header->version = (uint32_t)corpus_version;
    header->corpus_digest = corpus_digest;
    if (uname(&system_name) != 0)
        return -1;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || page_size > UINT32_MAX)
        return -1;
    header->page_size = (uint32_t)page_size;
    copy_metadata(header->release, sizeof(header->release), system_name.release);
    copy_metadata(header->machine, sizeof(header->machine), system_name.machine);
    return 0;
}

static int record_trace(const char *corpus_path, const char *trace_path,
                        uint64_t corpus_digest, long corpus_version)
{
    struct run_context context;
    int status;

    memset(&context, 0, sizeof(context));
    context.mode = MODE_RECORD;
    context.corpus_version = corpus_version;
    initialize_scenario(&context);
    if (initialize_record_header(&context.header, corpus_digest, corpus_version) != 0)
        return fail("cannot read host Linux metadata");
    context.trace = fopen(trace_path, "wb+");
    if (context.trace == NULL)
        return fail("cannot create expected trace");
    if (fwrite(&context.header, sizeof(context.header), 1, context.trace) != 1) {
        fclose(context.trace);
        return fail("cannot write expected trace header");
    }
    status = process_corpus(&context, corpus_path);
    context.header.record_count = context.operation_index;
    if (status == 0 &&
        (fseek(context.trace, 0L, SEEK_SET) != 0 ||
         fwrite(&context.header, sizeof(context.header), 1, context.trace) != 1 ||
         fflush(context.trace) != 0))
        status = fail("cannot finalize expected trace");
    if (fclose(context.trace) != 0 && status == 0)
        status = fail("cannot close expected trace");
    if (status == 0) {
        printf("EVENTFD_LINUX_ORACLE_RECORDED: release=%s machine=%s page_size=%" PRIu32
               " operations=%" PRIu32 "\n",
               context.header.release, context.header.machine, context.header.page_size,
               context.header.record_count);
    }
    return status;
}

static int compare_trace(const char *corpus_path, const char *trace_path,
                         uint64_t corpus_digest, long corpus_version)
{
    struct run_context context;
    const unsigned char *magic = trace_magic_for_version(corpus_version);
    unsigned char trailing_byte;
    int status;

    if (magic == NULL)
        return fail("invalid corpus version");
    memset(&context, 0, sizeof(context));
    context.mode = MODE_COMPARE;
    context.corpus_version = corpus_version;
    initialize_scenario(&context);
    context.trace = fopen(trace_path, "rb");
    if (context.trace == NULL)
        return fail("cannot open expected trace");
    if (fread(&context.header, sizeof(context.header), 1, context.trace) != 1 ||
        memcmp(context.header.magic, magic, sizeof(context.header.magic)) != 0 ||
        context.header.version != (uint32_t)corpus_version ||
        context.header.corpus_digest != corpus_digest) {
        fclose(context.trace);
        return fail("invalid expected trace header or corpus digest");
    }
    printf("EVENTFD_LINUX_ORACLE_REFERENCE: release=%s machine=%s page_size=%" PRIu32
           " operations=%" PRIu32 "\n",
           context.header.release, context.header.machine, context.header.page_size,
           context.header.record_count);
    status = process_corpus(&context, corpus_path);
    if (status == 0 && context.operation_index != context.header.record_count)
        status = fail("expected trace operation count does not match corpus");
    if (status == 0 && fread(&trailing_byte, 1, 1, context.trace) != 0U)
        status = fail("expected trace has trailing records");
    if (ferror(context.trace) != 0 && status == 0)
        status = fail("cannot read expected trace");
    if (fclose(context.trace) != 0 && status == 0)
        status = fail("cannot close expected trace");
    if (status == 0) {
        printf("\nSTARRY_EVENTFD_LINUX_ORACLE_PASSED: operations=%" PRIu32
               " host_linux=%s/%s\n",
               context.operation_index, context.header.release, context.header.machine);
    }
    return status;
}

int main(int argc, char **argv)
{
    enum run_mode mode;
    uint64_t corpus_digest;
    long corpus_version;

    if (argc != 4)
        return fail("usage: eventfd-linux-oracle --record|--compare CORPUS TRACE");
    if (strcmp(argv[1], "--record") == 0)
        mode = MODE_RECORD;
    else if (strcmp(argv[1], "--compare") == 0)
        mode = MODE_COMPARE;
    else
        return fail("unknown mode");
    if (digest_file(argv[2], &corpus_digest) != 0)
        return fail("cannot digest operation corpus");
    if (read_corpus_version(argv[2], &corpus_version) != 0)
        return fail("invalid corpus version");
    if (corpus_version == CONCURRENT_CORPUS_VERSION)
        return eventfd_concurrent_run(mode == MODE_RECORD, argv[2], argv[3],
                                      corpus_digest);
    if (mode == MODE_RECORD)
        return record_trace(argv[2], argv[3], corpus_digest, corpus_version);
    return compare_trace(argv[2], argv[3], corpus_digest, corpus_version);
}
