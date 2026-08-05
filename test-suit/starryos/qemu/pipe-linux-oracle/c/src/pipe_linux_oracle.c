#define _GNU_SOURCE

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
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "controlled_worker.h"

#define LEGACY_TRACE_VERSION 1U
#define FD_TRACE_VERSION 2U
#define VECTOR_TRACE_VERSION 3U
#define TRACE_VERSION 4U
#define BLOCKING_TRACE_VERSION 5U
#define LEGACY_CORPUS_VERSION 1L
#define FD_CORPUS_VERSION 2L
#define VECTOR_CORPUS_VERSION 3L
#define CORPUS_VERSION 4L
#define BLOCKING_CORPUS_VERSION 5L
#define MAX_SLOTS 16
#define MAX_PIPE_OBJECTS 16
#define DUP_TARGET_FD_BASE 64
#define MAX_IO_BYTES 8192
#define MAX_IOV_SEGMENTS 4
#define MAX_POLL_FDS 4
#define MAX_LINE_BYTES 256
#define TRACE_RELEASE_BYTES 64
#define TRACE_MACHINE_BYTES 32
#define UNKNOWN_FLAG 0x40000000L
#define READV_SENTINEL 0xa5U
#define POLL_REVENTS_SENTINEL ((short)0x5a5a)
#define WORKER_ACTOR 1L
#define PIPE_BUFFER_BYTES 4096L

static const unsigned char trace_magic[8] = {'P', 'I', 'P', 'E', 'O', 'R', 'C', '1'};

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
    int64_t value;
    int32_t error;
    unsigned char data[MAX_IO_BYTES];
};

enum run_mode {
    MODE_RECORD,
    MODE_COMPARE,
};

enum endpoint_kind {
    ENDPOINT_NONE,
    ENDPOINT_READER,
    ENDPOINT_WRITER,
};

enum worker_kind {
    WORKER_READ,
    WORKER_WRITE,
};

struct pipe_object {
    int readers;
    int writers;
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
    int pipe_object;
    long length;
    long byte_value;
    long write_release_remaining;
};

struct run_context {
    enum run_mode mode;
    FILE *trace;
    struct trace_header header;
    int slots[MAX_SLOTS];
    int slot_pipe_objects[MAX_SLOTS];
    enum endpoint_kind slot_endpoints[MAX_SLOTS];
    struct pipe_object pipe_objects[MAX_PIPE_OBJECTS];
    int pipe_object_count;
    long corpus_version;
    struct worker_state worker;
    uint32_t scenario_index;
    uint32_t operation_index;
};

static int fail(const char *message)
{
    fprintf(stderr, "STARRY_PIPE_LINUX_ORACLE_FAILED: %s\n", message);
    return 1;
}

static int fail_line(unsigned int line_number, const char *line, const char *message)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_FAILED: line=%u operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static int fail_schedule_timeout(unsigned int line_number, const char *line)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=%u operation=\"%s\"\n",
            line_number, line);
    return 1;
}

static int fail_harness(unsigned int line_number, const char *line,
                        const char *message)
{
    fprintf(stderr,
            "STARRY_PIPE_LINUX_ORACLE_HARNESS_ERROR: line=%u operation=\"%s\" %s\n",
            line_number, line, message);
    return 1;
}

static void close_slots(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        if (context->slots[index] >= 0) {
            (void)syscall(SYS_close, context->slots[index]);
            context->slots[index] = -1;
            context->slot_pipe_objects[index] = -1;
            context->slot_endpoints[index] = ENDPOINT_NONE;
        }
    }
    memset(context->pipe_objects, 0, sizeof(context->pipe_objects));
    context->pipe_object_count = 0;
    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
}

static void initialize_slots(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        context->slots[index] = -1;
        context->slot_pipe_objects[index] = -1;
        context->slot_endpoints[index] = ENDPOINT_NONE;
    }
    memset(context->pipe_objects, 0, sizeof(context->pipe_objects));
    context->pipe_object_count = 0;
    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
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

static int parse_decimal_long_value(const char *text, long minimum,
                                    long maximum, long *value)
{
    const char *cursor = text;
    char *end;
    long parsed;

    if (cursor == NULL || *cursor == '\0')
        return -1;
    if (*cursor == '+' || *cursor == '-')
        cursor++;
    if (*cursor == '\0')
        return -1;
    for (; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return -1;
    }

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed < minimum || parsed > maximum)
        return -1;
    *value = parsed;
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

static int is_supported_pipe2_flags(long flags)
{
    return flags == 0 || flags == O_NONBLOCK || flags == O_CLOEXEC ||
           flags == (O_NONBLOCK | O_CLOEXEC) || flags == UNKNOWN_FLAG;
}

static int is_supported_dup3_flags(long flags)
{
    return flags == 0 || flags == O_CLOEXEC || flags == O_NONBLOCK ||
           flags == (O_CLOEXEC | O_NONBLOCK) || flags == UNKNOWN_FLAG;
}

static int is_supported_iovcnt(long iovcnt)
{
    return iovcnt == -1 || (iovcnt >= 0 && iovcnt <= MAX_IOV_SEGMENTS) ||
           iovcnt == 1025;
}

static int is_supported_poll_literal_fd(long fd)
{
    return fd == -2 || fd == -1 || fd == INT_MAX;
}

static void finish_syscall_result(struct operation_result *result, long syscall_result)
{
    result->result = syscall_result;
    result->error = syscall_result < 0 ? errno : 0;
}

static void *run_worker(void *argument)
{
    struct worker_state *worker = argument;
    unsigned char buffer[MAX_IO_BYTES];
    long syscall_result;

    if (worker->kind == WORKER_READ) {
        memset(buffer, 0, sizeof(buffer));
        controlled_worker_publish_entered(&worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_read, worker->fd, buffer,
                                 (size_t)worker->length);
        finish_syscall_result(&worker->result, syscall_result);
        if (syscall_result > 0) {
            worker->result.data_len = (uint32_t)syscall_result;
            memcpy(worker->result.data, buffer, (size_t)syscall_result);
        }
    } else {
        memset(buffer, (unsigned char)worker->byte_value,
               (size_t)worker->length);
        controlled_worker_publish_entered(&worker->controller);
        errno = 0;
        syscall_result = syscall(SYS_write, worker->fd, buffer,
                                 (size_t)worker->length);
        finish_syscall_result(&worker->result, syscall_result);
    }
    controlled_worker_publish_completed(&worker->controller);
    return NULL;
}

static int destination_fd(const struct run_context *context, int slot)
{
    if (context->slots[slot] >= 0)
        return context->slots[slot];
    return DUP_TARGET_FD_BASE + slot;
}

static void release_slot_metadata(struct run_context *context, int slot)
{
    int object_index = context->slot_pipe_objects[slot];

    if (object_index >= 0) {
        struct pipe_object *object = &context->pipe_objects[object_index];

        if (context->slot_endpoints[slot] == ENDPOINT_READER)
            object->readers--;
        else if (context->slot_endpoints[slot] == ENDPOINT_WRITER)
            object->writers--;
    }
    context->slot_pipe_objects[slot] = -1;
    context->slot_endpoints[slot] = ENDPOINT_NONE;
}

static void duplicate_slot_metadata(struct run_context *context, int source,
                                    int destination)
{
    int object_index = context->slot_pipe_objects[source];

    context->slot_pipe_objects[destination] = object_index;
    context->slot_endpoints[destination] = context->slot_endpoints[source];
    if (object_index >= 0) {
        struct pipe_object *object = &context->pipe_objects[object_index];

        if (context->slot_endpoints[source] == ENDPOINT_READER)
            object->readers++;
        else if (context->slot_endpoints[source] == ENDPOINT_WRITER)
            object->writers++;
    }
}

static int pipe_queued_bytes(int fd, long *queued)
{
    int value = -1;

    errno = 0;
    if (syscall(SYS_ioctl, fd, FIONREAD, &value) != 0 || value < 0)
        return -1;
    *queued = value;
    return 0;
}

static int pipe_capacity(int fd, long *capacity)
{
    long value;

    errno = 0;
    value = syscall(SYS_fcntl, fd, F_GETPIPE_SZ, 0);
    if (value <= 0)
        return -1;
    *capacity = value;
    return 0;
}

static int positive_io_is_nonblocking(const struct run_context *context, int slot,
                                      long length)
{
    long flags;

    if (length == 0 || context->slots[slot] < 0)
        return 1;
    errno = 0;
    flags = syscall(SYS_fcntl, context->slots[slot], F_GETFL, 0);
    return flags < 0 || (flags & O_NONBLOCK) != 0;
}

static int blocking_read_is_ready(const struct run_context *context, int slot,
                                  long length)
{
    int object_index = context->slot_pipe_objects[slot];
    long queued;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION || length <= 0 ||
        object_index < 0 || context->slot_endpoints[slot] != ENDPOINT_READER ||
        pipe_queued_bytes(context->slots[slot], &queued) != 0)
        return 0;
    return queued > 0 || context->pipe_objects[object_index].writers == 0;
}

static int blocking_write_is_ready(const struct run_context *context, int slot,
                                   long length)
{
    int object_index = context->slot_pipe_objects[slot];
    long queued;
    long capacity;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION || length <= 0 ||
        length > PIPE_BUFFER_BYTES || object_index < 0 ||
        context->slot_endpoints[slot] != ENDPOINT_WRITER ||
        context->pipe_objects[object_index].readers == 0 ||
        pipe_queued_bytes(context->slots[slot], &queued) != 0 ||
        pipe_capacity(context->slots[slot], &capacity) != 0)
        return 0;
    /* v5 setup writes deliberately start from an empty pipe.  Keeping that
     * invariant here avoids admitting fragmented raw corpora that the model
     * cannot prove have an immediately available pipe-buffer record. */
    return queued == 0 && length <= capacity;
}

static int valid_controller_read(const struct run_context *context, int slot,
                                 long length)
{
    return context->worker.active && context->worker.pending_confirmed &&
           !context->worker.completable &&
           context->worker.kind == WORKER_WRITE && length > 0 &&
           context->slots[slot] >= 0 &&
           context->slot_pipe_objects[slot] == context->worker.pipe_object &&
           context->slot_endpoints[slot] == ENDPOINT_READER;
}

static int valid_controller_write(const struct run_context *context, int slot,
                                  long length)
{
    return context->worker.active && context->worker.pending_confirmed &&
           !context->worker.completable &&
           context->worker.kind == WORKER_READ && length >= 0 &&
           length <= PIPE_BUFFER_BYTES && context->slots[slot] >= 0 &&
           context->slot_pipe_objects[slot] == context->worker.pipe_object &&
           context->slot_endpoints[slot] == ENDPOINT_WRITER;
}

static int positive_vector_io_is_nonblocking(const struct run_context *context,
                                             int slot, long iov_mode,
                                             long iovcnt, size_t total_length,
                                             int write_side)
{
    long flags;
    long access_mode;

    if (iov_mode != 0 || iovcnt <= 0 || iovcnt > MAX_IOV_SEGMENTS ||
        total_length == 0U || context->slots[slot] < 0)
        return 1;
    errno = 0;
    flags = syscall(SYS_fcntl, context->slots[slot], F_GETFL, 0);
    if (flags < 0)
        return 1;
    access_mode = flags & O_ACCMODE;
    if ((write_side && access_mode == O_RDONLY) ||
        (!write_side && access_mode == O_WRONLY))
        return 1;
    return (flags & O_NONBLOCK) != 0;
}

static int execute_pipe2(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *read_slot_text = strtok_r(NULL, " \t", &save);
    char *write_slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = context->corpus_version >= FD_CORPUS_VERSION
                           ? strtok_r(NULL, " \t", &save)
                           : NULL;
    int read_slot;
    int write_slot;
    long flags = O_NONBLOCK | O_CLOEXEC;
    int pipe_fds[2] = {-1, -1};
    long syscall_result;

    if (parse_slot(read_slot_text, &read_slot) != 0 ||
        parse_slot(write_slot_text, &write_slot) != 0 ||
        (context->corpus_version >= FD_CORPUS_VERSION &&
         parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        (context->corpus_version >= FD_CORPUS_VERSION &&
         !is_supported_pipe2_flags(flags)) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    if ((flags & ~(O_NONBLOCK | O_CLOEXEC)) == 0 &&
        (read_slot == write_slot || context->slots[read_slot] >= 0 ||
         context->slots[write_slot] >= 0))
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_pipe2, pipe_fds, (int)flags);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        if (read_slot == write_slot || context->slots[read_slot] >= 0 ||
            context->slots[write_slot] >= 0) {
            (void)syscall(SYS_close, pipe_fds[0]);
            (void)syscall(SYS_close, pipe_fds[1]);
            return -1;
        }
        context->slots[read_slot] = pipe_fds[0];
        context->slots[write_slot] = pipe_fds[1];
        if (context->pipe_object_count >= MAX_PIPE_OBJECTS) {
            (void)syscall(SYS_close, pipe_fds[0]);
            (void)syscall(SYS_close, pipe_fds[1]);
            context->slots[read_slot] = -1;
            context->slots[write_slot] = -1;
            return -1;
        }
        context->slot_pipe_objects[read_slot] = context->pipe_object_count;
        context->slot_pipe_objects[write_slot] = context->pipe_object_count;
        context->slot_endpoints[read_slot] = ENDPOINT_READER;
        context->slot_endpoints[write_slot] = ENDPOINT_WRITER;
        context->pipe_objects[context->pipe_object_count].readers = 1;
        context->pipe_objects[context->pipe_object_count].writers = 1;
        context->pipe_object_count++;
    }
    result->kind = OP_PIPE2;
    return 0;
}

static int execute_read(struct run_context *context, char *save,
                        struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    long length;
    int slot;
    unsigned char buffer[MAX_IO_BYTES];
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL ||
        !(context->worker.active
              ? valid_controller_read(context, slot, length)
              : (positive_io_is_nonblocking(context, slot, length) ||
                 blocking_read_is_ready(context, slot, length))))
        return -1;

    memset(buffer, 0, sizeof(buffer));
    errno = 0;
    syscall_result = syscall(SYS_read, context->slots[slot], buffer, (size_t)length);
    finish_syscall_result(result, syscall_result);
    if (syscall_result > 0) {
        result->data_len = (uint32_t)syscall_result;
        memcpy(result->data, buffer, (size_t)syscall_result);
        if (context->worker.active) {
            context->worker.write_release_remaining -= syscall_result;
            if (context->worker.write_release_remaining <= 0)
                context->worker.completable = 1;
        }
    }
    result->kind = OP_READ;
    return 0;
}

static int execute_null_io(struct run_context *context, char *save,
                           struct operation_result *result, int write_side)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    int slot;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    errno = 0;
    syscall_result = syscall(write_side ? SYS_write : SYS_read, context->slots[slot],
                             (void *)(uintptr_t)1, 0U);
    finish_syscall_result(result, syscall_result);
    result->kind = write_side ? OP_WRITE_NULL : OP_READ_NULL;
    return 0;
}

static int execute_write(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    char *byte_text = strtok_r(NULL, " \t", &save);
    long length;
    long byte_value;
    int slot;
    unsigned char buffer[MAX_IO_BYTES];
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
        parse_long_value(byte_text, 0, UCHAR_MAX, &byte_value) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL ||
        !(context->worker.active
              ? valid_controller_write(context, slot, length)
              : (positive_io_is_nonblocking(context, slot, length) ||
                 blocking_write_is_ready(context, slot, length))))
        return -1;

    memset(buffer, (unsigned char)byte_value, (size_t)length);
    errno = 0;
    syscall_result = syscall(SYS_write, context->slots[slot], buffer, (size_t)length);
    finish_syscall_result(result, syscall_result);
    if (context->worker.active && syscall_result > 0)
        context->worker.completable = 1;
    result->kind = OP_WRITE;
    return 0;
}

static int execute_vector_io(struct run_context *context, char *save,
                             struct operation_result *result, int write_side)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *iov_mode_text = strtok_r(NULL, " \t", &save);
    char *iovcnt_text = strtok_r(NULL, " \t", &save);
    char *segment_count_text = strtok_r(NULL, " \t", &save);
    struct iovec iov[MAX_IOV_SEGMENTS];
    unsigned char storage[MAX_IO_BYTES];
    size_t storage_offset = 0U;
    size_t total_length = 0U;
    long iov_mode;
    long iovcnt;
    long segment_count;
    long expected_segment_count;
    long syscall_result;
    int slot;
    long segment_index;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(iov_mode_text, 0, 1, &iov_mode) != 0 ||
        parse_long_value(iovcnt_text, -1, 1025, &iovcnt) != 0 ||
        !is_supported_iovcnt(iovcnt) ||
        parse_long_value(segment_count_text, 0, MAX_IOV_SEGMENTS,
                         &segment_count) != 0)
        return -1;
    expected_segment_count =
        iov_mode == 0 && iovcnt >= 0 && iovcnt <= MAX_IOV_SEGMENTS ? iovcnt : 0;
    if (segment_count != expected_segment_count)
        return -1;

    memset(iov, 0, sizeof(iov));
    memset(storage, READV_SENTINEL, sizeof(storage));
    for (segment_index = 0; segment_index < segment_count; segment_index++) {
        char *base_mode_text = strtok_r(NULL, " \t", &save);
        char *length_text = strtok_r(NULL, " \t", &save);
        char *byte_text = write_side ? strtok_r(NULL, " \t", &save) : NULL;
        long base_mode;
        long length;
        long byte_value = 0;

        if (parse_long_value(base_mode_text, 0, 1, &base_mode) != 0 ||
            parse_long_value(length_text, 0, MAX_IO_BYTES, &length) != 0 ||
            (write_side &&
             parse_long_value(byte_text, 0, UCHAR_MAX, &byte_value) != 0) ||
            (size_t)length > MAX_IO_BYTES - total_length)
            return -1;
        total_length += (size_t)length;
        iov[segment_index].iov_len = (size_t)length;
        if (base_mode == 0) {
            iov[segment_index].iov_base = storage + storage_offset;
            if (write_side)
                memset(storage + storage_offset, (unsigned char)byte_value,
                       (size_t)length);
            storage_offset += (size_t)length;
        } else {
            iov[segment_index].iov_base = (void *)(uintptr_t)1;
        }
    }
    if (strtok_r(NULL, " \t", &save) != NULL ||
        !positive_vector_io_is_nonblocking(context, slot, iov_mode, iovcnt,
                                           total_length, write_side))
        return -1;

    errno = 0;
    syscall_result = syscall(write_side ? SYS_writev : SYS_readv,
                             context->slots[slot],
                             iov_mode == 0 ? iov : (void *)(uintptr_t)1,
                             iovcnt);
    finish_syscall_result(result, syscall_result);
    if (!write_side) {
        result->data_len = (uint32_t)storage_offset;
        memcpy(result->data, storage, storage_offset);
    }
    result->kind = write_side ? OP_WRITEV : OP_READV;
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
        strtok_r(NULL, " \t", &save) != NULL || context->slots[destination] >= 0)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_dup, context->slots[source]);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0) {
        context->slots[destination] = (int)syscall_result;
        duplicate_slot_metadata(context, source, destination);
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
    int source;
    int destination;
    int target_fd;
    long flags = 0;
    long syscall_result;

    if (parse_slot(source_text, &source) != 0 ||
        parse_slot(destination_text, &destination) != 0 ||
        (use_dup3 && parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        (use_dup3 && !is_supported_dup3_flags(flags)) ||
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
        if (source != destination) {
            release_slot_metadata(context, destination);
            duplicate_slot_metadata(context, source, destination);
        }
        context->slots[destination] = (int)syscall_result;
    }
    result->kind = use_dup3 ? OP_DUP3 : OP_DUP2;
    return 0;
}

static int execute_close(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    int slot;
    long queued = 0;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;
    if (context->worker.active) {
        if (!context->worker.pending_confirmed || context->worker.completable ||
            context->worker.kind != WORKER_READ ||
            context->slot_pipe_objects[slot] != context->worker.pipe_object ||
            context->slot_endpoints[slot] != ENDPOINT_WRITER ||
            context->pipe_objects[context->worker.pipe_object].writers != 1 ||
            pipe_queued_bytes(context->slots[slot], &queued) != 0 || queued != 0)
            return -1;
    }

    errno = 0;
    syscall_result = syscall(SYS_close, context->slots[slot]);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        release_slot_metadata(context, slot);
        context->slots[slot] = -1;
        if (context->worker.active)
            context->worker.completable = 1;
    }
    result->kind = OP_CLOSE;
    return 0;
}

static int execute_poll(struct run_context *context, char *save,
                        struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *events_text = strtok_r(NULL, " \t", &save);
    long events;
    int slot;
    struct pollfd poll_fd;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(events_text, 0, SHRT_MAX, &events) != 0 ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    memset(&poll_fd, 0, sizeof(poll_fd));
    poll_fd.fd = context->slots[slot];
    poll_fd.events = (short)events;
    errno = 0;
    syscall_result = syscall(SYS_poll, &poll_fd, 1UL, 0L);
    finish_syscall_result(result, syscall_result);
    result->value = poll_fd.revents;
    result->kind = OP_POLL;
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

    if (parse_decimal_long_value(count_text, 0, MAX_POLL_FDS, &count) != 0)
        return -1;

    memset(poll_fds, 0, sizeof(poll_fds));
    for (entry_index = 0; entry_index < count; entry_index++) {
        char *mode_text = strtok_r(NULL, " \t", &save);
        char *fd_arg_text = strtok_r(NULL, " \t", &save);
        char *events_text = strtok_r(NULL, " \t", &save);
        long mode;
        long fd_arg;
        long events;

        if (parse_decimal_long_value(mode_text, 0, 1, &mode) != 0 ||
            parse_decimal_long_value(fd_arg_text, INT_MIN, INT_MAX,
                                     &fd_arg) != 0 ||
            parse_decimal_long_value(events_text, 0, SHRT_MAX, &events) != 0 ||
            (mode == 0 && (fd_arg < 0 || fd_arg >= MAX_SLOTS)) ||
            (mode == 1 && !is_supported_poll_literal_fd(fd_arg)))
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
    result->value = count;
    result->data_len = (uint32_t)count * 2U;
    for (entry_index = 0; entry_index < count; entry_index++) {
        uint16_t revents = (uint16_t)poll_fds[entry_index].revents;

        result->data[entry_index * 2] = (unsigned char)(revents & 0xffU);
        result->data[entry_index * 2 + 1] = (unsigned char)(revents >> 8);
    }
    result->kind = OP_POLL_MANY;
    return 0;
}

static int execute_fcntl(struct run_context *context, char *save,
                         struct operation_result *result, int set_size)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *size_text = set_size ? strtok_r(NULL, " \t", &save) : NULL;
    long size = 0;
    int slot;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        (set_size && parse_long_value(size_text, 0, INT_MAX, &size) != 0) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_fcntl, context->slots[slot],
                             set_size ? F_SETPIPE_SZ : F_GETPIPE_SZ, size);
    finish_syscall_result(result, syscall_result);
    result->kind = set_size ? OP_SET_SIZE : OP_GET_SIZE;
    return 0;
}

static int execute_flag_fcntl(struct run_context *context, char *save,
                              struct operation_result *result, int command,
                              uint32_t kind, int normalized_mask)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *flags_text = (command == F_SETFL || command == F_SETFD)
                           ? strtok_r(NULL, " \t", &save)
                           : NULL;
    int slot;
    long flags = 0;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 ||
        (flags_text != NULL &&
         parse_long_value(flags_text, 0, INT_MAX, &flags) != 0) ||
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_fcntl, context->slots[slot], command, flags);
    if (command == F_GETFL || command == F_GETFD) {
        finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
        result->value = syscall_result < 0 ? -1 : syscall_result & normalized_mask;
    } else {
        finish_syscall_result(result, syscall_result);
    }
    result->kind = kind;
    return 0;
}

static int execute_fionread(struct run_context *context, char *save,
                            struct operation_result *result)
{
    char *slot_text = strtok_r(NULL, " \t", &save);
    int slot;
    int queued = -1;
    long syscall_result;

    if (parse_slot(slot_text, &slot) != 0 || strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_ioctl, context->slots[slot], FIONREAD, &queued);
    finish_syscall_result(result, syscall_result);
    result->value = syscall_result == 0 ? queued : -1;
    result->kind = OP_FIONREAD;
    return 0;
}

static int execute_start_worker(struct run_context *context, char *save,
                                struct operation_result *result, int is_write)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    char *slot_text = strtok_r(NULL, " \t", &save);
    char *length_text = strtok_r(NULL, " \t", &save);
    char *byte_text = is_write ? strtok_r(NULL, " \t", &save) : NULL;
    int object_index;
    int slot;
    long actor;
    long byte_value = 0;
    long capacity = 0;
    long flags;
    long length;
    long queued;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION ||
        parse_long_value(actor_text, WORKER_ACTOR, WORKER_ACTOR, &actor) != 0 ||
        parse_slot(slot_text, &slot) != 0 ||
        parse_long_value(length_text, 1,
                         is_write ? PIPE_BUFFER_BYTES : MAX_IO_BYTES,
                         &length) != 0 ||
        (is_write &&
         parse_long_value(byte_text, 0, UCHAR_MAX, &byte_value) != 0) ||
        strtok_r(NULL, " \t", &save) != NULL || context->worker.active ||
        context->slots[slot] < 0 || context->slot_pipe_objects[slot] < 0)
        return -1;
    object_index = context->slot_pipe_objects[slot];
    errno = 0;
    flags = syscall(SYS_fcntl, context->slots[slot], F_GETFL, 0);
    if (flags < 0 || (flags & O_NONBLOCK) != 0 ||
        pipe_queued_bytes(context->slots[slot], &queued) != 0)
        return -1;
    if ((!is_write &&
         (context->slot_endpoints[slot] != ENDPOINT_READER || queued != 0 ||
          context->pipe_objects[object_index].writers == 0)) ||
        (is_write &&
         (context->slot_endpoints[slot] != ENDPOINT_WRITER ||
          context->pipe_objects[object_index].readers == 0 ||
          pipe_capacity(context->slots[slot], &capacity) != 0 ||
          capacity != PIPE_BUFFER_BYTES || queued != capacity)))
        return -1;

    memset(&context->worker, 0, sizeof(context->worker));
    controlled_worker_initialize(&context->worker.controller);
    context->worker.kind = is_write ? WORKER_WRITE : WORKER_READ;
    context->worker.active = 1;
    context->worker.slot = slot;
    context->worker.fd = context->slots[slot];
    context->worker.pipe_object = object_index;
    context->worker.length = length;
    context->worker.byte_value = byte_value;
    context->worker.write_release_remaining = queued;
    if (controlled_worker_start(&context->worker.controller, run_worker,
                                &context->worker) != CONTROLLED_WORKER_OK) {
        context->worker.active = 0;
        return -2;
    }
    result->kind = is_write ? OP_START_WRITE : OP_START_READ;
    result->value = length;
    if (is_write) {
        result->data_len = 1;
        result->data[0] = (unsigned char)byte_value;
    }
    return 0;
}

static int execute_assert_pending(struct run_context *context, char *save,
                                  struct operation_result *result)
{
    char *actor_text = strtok_r(NULL, " \t", &save);
    long actor;
    enum controlled_worker_status pending_status;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION ||
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
    long actor;
    enum controlled_worker_status wait_status;

    if (context->corpus_version != BLOCKING_CORPUS_VERSION ||
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
    context->worker.active = 0;
    return 0;
}

static int execute_operation(struct run_context *context, char *line,
                             struct operation_result *result)
{
    char *save = NULL;
    char *operation = strtok_r(line, " \t", &save);

    if (context->corpus_version == BLOCKING_CORPUS_VERSION &&
        strcmp(operation, "pipe2") != 0 && strcmp(operation, "read") != 0 &&
        strcmp(operation, "write") != 0 && strcmp(operation, "dup") != 0 &&
        strcmp(operation, "close") != 0 &&
        strcmp(operation, "set-size") != 0 &&
        strcmp(operation, "get-size") != 0 &&
        strcmp(operation, "fionread") != 0 &&
        strcmp(operation, "get-status-flags") != 0 &&
        strcmp(operation, "set-status-flags") != 0 &&
        strcmp(operation, "get-fd-flags") != 0 &&
        strcmp(operation, "set-fd-flags") != 0 &&
        strcmp(operation, "start-read") != 0 &&
        strcmp(operation, "start-write") != 0 &&
        strcmp(operation, "assert-pending") != 0 &&
        strcmp(operation, "join") != 0)
        return -1;

    if (context->worker.active && strcmp(operation, "read") != 0 &&
        strcmp(operation, "write") != 0 && strcmp(operation, "close") != 0 &&
        strcmp(operation, "assert-pending") != 0 &&
        strcmp(operation, "join") != 0)
        return -1;

    if (strcmp(operation, "start-read") == 0)
        return execute_start_worker(context, save, result, 0);
    if (strcmp(operation, "start-write") == 0)
        return execute_start_worker(context, save, result, 1);
    if (strcmp(operation, "assert-pending") == 0)
        return execute_assert_pending(context, save, result);
    if (strcmp(operation, "join") == 0)
        return execute_join(context, save, result);

    if (strcmp(operation, "pipe2") == 0)
        return execute_pipe2(context, save, result);
    if (strcmp(operation, "read") == 0)
        return execute_read(context, save, result);
    if (strcmp(operation, "read-null") == 0)
        return execute_null_io(context, save, result, 0);
    if (strcmp(operation, "write") == 0)
        return execute_write(context, save, result);
    if (strcmp(operation, "write-null") == 0)
        return execute_null_io(context, save, result, 1);
    if (context->corpus_version >= VECTOR_CORPUS_VERSION &&
        strcmp(operation, "readv") == 0)
        return execute_vector_io(context, save, result, 0);
    if (context->corpus_version >= VECTOR_CORPUS_VERSION &&
        strcmp(operation, "writev") == 0)
        return execute_vector_io(context, save, result, 1);
    if (context->corpus_version == CORPUS_VERSION &&
        strcmp(operation, "poll-many") == 0)
        return execute_poll_many(context, save, result);
    if (strcmp(operation, "dup") == 0)
        return execute_dup(context, save, result);
    if (strcmp(operation, "close") == 0)
        return execute_close(context, save, result);
    if (strcmp(operation, "poll") == 0)
        return execute_poll(context, save, result);
    if (strcmp(operation, "set-size") == 0)
        return execute_fcntl(context, save, result, 1);
    if (strcmp(operation, "get-size") == 0)
        return execute_fcntl(context, save, result, 0);
    if (strcmp(operation, "fionread") == 0)
        return execute_fionread(context, save, result);
    if (context->corpus_version < FD_CORPUS_VERSION)
        return -1;
    if (strcmp(operation, "get-status-flags") == 0)
        return execute_flag_fcntl(context, save, result, F_GETFL,
                                  OP_GET_STATUS_FLAGS, O_NONBLOCK);
    if (strcmp(operation, "set-status-flags") == 0)
        return execute_flag_fcntl(context, save, result, F_SETFL,
                                  OP_SET_STATUS_FLAGS, 0);
    if (strcmp(operation, "get-fd-flags") == 0)
        return execute_flag_fcntl(context, save, result, F_GETFD,
                                  OP_GET_FD_FLAGS, FD_CLOEXEC);
    if (strcmp(operation, "set-fd-flags") == 0)
        return execute_flag_fcntl(context, save, result, F_SETFD,
                                  OP_SET_FD_FLAGS, 0);
    if (strcmp(operation, "dup2") == 0)
        return execute_dup_to(context, save, result, 0);
    if (strcmp(operation, "dup3") == 0)
        return execute_dup_to(context, save, result, 1);
    return -1;
}

static int compare_operation(const struct run_context *context,
                             const struct operation_result *actual,
                             unsigned int line_number, const char *line)
{
    struct operation_result expected;
    uint32_t difference_mask = 0;

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
    if (memcmp(expected.data, actual->data,
               expected.data_len > actual->data_len ? expected.data_len
                                                    : actual->data_len) != 0)
        difference_mask |= DIFF_DATA;
    if (difference_mask != 0) {
        fprintf(stderr,
                "STARRY_PIPE_LINUX_ORACLE_FAILED: host=%s/%s line=%u scenario=%" PRIu32
                " operation=%" PRIu32 " text=\"%s\" difference_mask=0x%08" PRIx32
                " expected={kind=%" PRIu32
                ",result=%" PRId64 ",errno=%" PRId32 ",value=%" PRId64
                ",data_len=%" PRIu32 "} actual={kind=%" PRIu32 ",result=%" PRId64
                ",errno=%" PRId32 ",value=%" PRId64 ",data_len=%" PRIu32 "}\n",
                context->header.release, context->header.machine, line_number,
                actual->scenario_index, actual->operation_index, line, difference_mask,
                expected.kind,
                expected.result, expected.error, expected.value, expected.data_len,
                actual->kind, actual->result, actual->error, actual->value,
                actual->data_len);
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
                parse_long_value(trim(line + 8), LEGACY_CORPUS_VERSION,
                                 BLOCKING_CORPUS_VERSION,
                                 &version) != 0) {
                status = fail_line(line_number, display_line, "invalid corpus version");
                break;
            }
            context->corpus_version = version;
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
            close_slots(context);
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
        status = fail("scenario ends with an unfinished worker");
    close_slots(context);
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

static void copy_metadata(char *destination, size_t capacity, const char *source)
{
    size_t length = strnlen(source, capacity - 1U);

    memcpy(destination, source, length);
    destination[length] = '\0';
}

static int initialize_record_header(struct trace_header *header, uint64_t corpus_digest)
{
    struct utsname system_name;
    long page_size;

    memset(header, 0, sizeof(*header));
    memcpy(header->magic, trace_magic, sizeof(trace_magic));
    header->version = TRACE_VERSION;
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
                        uint64_t corpus_digest)
{
    struct run_context context;
    int status;

    memset(&context, 0, sizeof(context));
    context.mode = MODE_RECORD;
    initialize_slots(&context);
    if (initialize_record_header(&context.header, corpus_digest) != 0)
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
    context.header.version = context.corpus_version == BLOCKING_CORPUS_VERSION
                                 ? BLOCKING_TRACE_VERSION
                                 : TRACE_VERSION;
    if (status == 0 &&
        (fseek(context.trace, 0L, SEEK_SET) != 0 ||
         fwrite(&context.header, sizeof(context.header), 1, context.trace) != 1 ||
         fflush(context.trace) != 0))
        status = fail("cannot finalize expected trace");
    if (fclose(context.trace) != 0 && status == 0)
        status = fail("cannot close expected trace");
    if (status == 0) {
        printf("PIPE_LINUX_ORACLE_RECORDED: release=%s machine=%s page_size=%" PRIu32
               " operations=%" PRIu32 "\n",
               context.header.release, context.header.machine, context.header.page_size,
               context.header.record_count);
    }
    return status;
}

static int compare_trace(const char *corpus_path, const char *trace_path,
                         uint64_t corpus_digest)
{
    struct run_context context;
    unsigned char trailing_byte;
    int status;

    memset(&context, 0, sizeof(context));
    context.mode = MODE_COMPARE;
    initialize_slots(&context);
    context.trace = fopen(trace_path, "rb");
    if (context.trace == NULL)
        return fail("cannot open expected trace");
    if (fread(&context.header, sizeof(context.header), 1, context.trace) != 1 ||
        memcmp(context.header.magic, trace_magic, sizeof(trace_magic)) != 0 ||
        (context.header.version != LEGACY_TRACE_VERSION &&
         context.header.version != FD_TRACE_VERSION &&
         context.header.version != VECTOR_TRACE_VERSION &&
         context.header.version != TRACE_VERSION &&
         context.header.version != BLOCKING_TRACE_VERSION) ||
        context.header.corpus_digest != corpus_digest) {
        fclose(context.trace);
        return fail("invalid expected trace header or corpus digest");
    }

    printf("PIPE_LINUX_ORACLE_REFERENCE: release=%s machine=%s page_size=%" PRIu32
           " operations=%" PRIu32 "\n",
           context.header.release, context.header.machine, context.header.page_size,
           context.header.record_count);
    status = process_corpus(&context, corpus_path);
    if (status == 0 && context.corpus_version == FD_CORPUS_VERSION &&
        context.header.version < FD_TRACE_VERSION)
        status = fail("version-2 corpus requires a version-2 or newer trace");
    if (status == 0 && context.corpus_version == VECTOR_CORPUS_VERSION &&
        context.header.version < VECTOR_TRACE_VERSION)
        status = fail("version-3 corpus requires a version-3 or newer trace");
    if (status == 0 && context.corpus_version == CORPUS_VERSION &&
        context.header.version != TRACE_VERSION)
        status = fail("version-4 corpus requires a version-4 trace");
    if (status == 0 && context.corpus_version == BLOCKING_CORPUS_VERSION &&
        context.header.version != BLOCKING_TRACE_VERSION)
        status = fail("version-5 corpus requires a version-5 trace");
    if (status == 0 && context.operation_index != context.header.record_count)
        status = fail("expected trace operation count does not match corpus");
    if (status == 0 && fread(&trailing_byte, 1, 1, context.trace) != 0U)
        status = fail("expected trace has trailing records");
    if (ferror(context.trace) != 0 && status == 0)
        status = fail("cannot read expected trace");
    if (fclose(context.trace) != 0 && status == 0)
        status = fail("cannot close expected trace");
    if (status == 0) {
        printf("\nSTARRY_PIPE_LINUX_ORACLE_PASSED: operations=%" PRIu32
               " host_linux=%s/%s\n",
               context.operation_index, context.header.release, context.header.machine);
    }
    return status;
}

int main(int argc, char **argv)
{
    enum run_mode mode;
    uint64_t corpus_digest;

    if (argc != 4)
        return fail("usage: pipe-linux-oracle --record|--compare CORPUS TRACE");
    if (strcmp(argv[1], "--record") == 0)
        mode = MODE_RECORD;
    else if (strcmp(argv[1], "--compare") == 0)
        mode = MODE_COMPARE;
    else
        return fail("unknown mode");
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return fail("cannot ignore SIGPIPE");
    if (digest_file(argv[2], &corpus_digest) != 0)
        return fail("cannot digest operation corpus");

    if (mode == MODE_RECORD)
        return record_trace(argv[2], argv[3], corpus_digest);
    return compare_trace(argv[2], argv[3], corpus_digest);
}
