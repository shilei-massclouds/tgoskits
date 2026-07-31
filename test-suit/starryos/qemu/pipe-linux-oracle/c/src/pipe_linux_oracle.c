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
#include <sys/utsname.h>
#include <unistd.h>

#define TRACE_VERSION 1U
#define CORPUS_VERSION 1L
#define MAX_SLOTS 16
#define MAX_IO_BYTES 8192
#define MAX_LINE_BYTES 256
#define TRACE_RELEASE_BYTES 64
#define TRACE_MACHINE_BYTES 32

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

struct run_context {
    enum run_mode mode;
    FILE *trace;
    struct trace_header header;
    int slots[MAX_SLOTS];
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

static void close_slots(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++) {
        if (context->slots[index] >= 0) {
            (void)syscall(SYS_close, context->slots[index]);
            context->slots[index] = -1;
        }
    }
}

static void initialize_slots(struct run_context *context)
{
    int index;

    for (index = 0; index < MAX_SLOTS; index++)
        context->slots[index] = -1;
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

static int parse_slot(const char *text, int *slot)
{
    long parsed;

    if (parse_long_value(text, 0, MAX_SLOTS - 1, &parsed) != 0)
        return -1;
    *slot = (int)parsed;
    return 0;
}

static void finish_syscall_result(struct operation_result *result, long syscall_result)
{
    result->result = syscall_result;
    result->error = syscall_result < 0 ? errno : 0;
}

static int execute_pipe2(struct run_context *context, char *save,
                         struct operation_result *result)
{
    char *read_slot_text = strtok_r(NULL, " \t", &save);
    char *write_slot_text = strtok_r(NULL, " \t", &save);
    int read_slot;
    int write_slot;
    int pipe_fds[2] = {-1, -1};
    long syscall_result;

    if (parse_slot(read_slot_text, &read_slot) != 0 ||
        parse_slot(write_slot_text, &write_slot) != 0 || read_slot == write_slot ||
        strtok_r(NULL, " \t", &save) != NULL || context->slots[read_slot] >= 0 ||
        context->slots[write_slot] >= 0)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_pipe2, pipe_fds, O_NONBLOCK | O_CLOEXEC);
    finish_syscall_result(result, syscall_result);
    if (syscall_result == 0) {
        context->slots[read_slot] = pipe_fds[0];
        context->slots[write_slot] = pipe_fds[1];
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
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    memset(buffer, 0, sizeof(buffer));
    errno = 0;
    syscall_result = syscall(SYS_read, context->slots[slot], buffer, (size_t)length);
    finish_syscall_result(result, syscall_result);
    if (syscall_result > 0) {
        result->data_len = (uint32_t)syscall_result;
        memcpy(result->data, buffer, (size_t)syscall_result);
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
        strtok_r(NULL, " \t", &save) != NULL)
        return -1;

    memset(buffer, (unsigned char)byte_value, (size_t)length);
    errno = 0;
    syscall_result = syscall(SYS_write, context->slots[slot], buffer, (size_t)length);
    finish_syscall_result(result, syscall_result);
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
        strtok_r(NULL, " \t", &save) != NULL || context->slots[destination] >= 0)
        return -1;

    errno = 0;
    syscall_result = syscall(SYS_dup, context->slots[source]);
    finish_syscall_result(result, syscall_result < 0 ? syscall_result : 0);
    if (syscall_result >= 0)
        context->slots[destination] = (int)syscall_result;
    result->kind = OP_DUP;
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
    if (syscall_result == 0)
        context->slots[slot] = -1;
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

static int execute_operation(struct run_context *context, char *line,
                             struct operation_result *result)
{
    char *save = NULL;
    char *operation = strtok_r(line, " \t", &save);

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

    memset(&result, 0, sizeof(result));
    result.scenario_index = context->scenario_index;
    result.operation_index = context->operation_index;
    if (execute_operation(context, parse_line, &result) != 0)
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
                parse_long_value(trim(line + 8), CORPUS_VERSION, CORPUS_VERSION,
                                 &version) != 0) {
                status = fail_line(line_number, display_line, "invalid corpus version");
                break;
            }
            saw_version = 1;
            continue;
        }

        if (strncmp(line, "scenario ", 9) == 0) {
            char *name = trim(line + 9);

            if (!saw_version || *name == '\0' || strchr(name, ' ') != NULL ||
                strchr(name, '\t') != NULL) {
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
        context.header.version != TRACE_VERSION ||
        context.header.corpus_digest != corpus_digest) {
        fclose(context.trace);
        return fail("invalid expected trace header or corpus digest");
    }

    printf("PIPE_LINUX_ORACLE_REFERENCE: release=%s machine=%s page_size=%" PRIu32
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
        printf("STARRY_PIPE_LINUX_ORACLE_PASSED: operations=%" PRIu32
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
