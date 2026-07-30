#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TEST_PIPE_CAPACITY 4096
#define FRAGMENTED_PIPE_CAPACITY (2 * TEST_PIPE_CAPACITY)
#define INITIAL_WRITE_SIZE 4000
#define ATOMIC_WRITE_SIZE 200
#define FRAGMENTED_WRITE_SIZE 5000
#define FRAGMENTED_READ_SIZE 1000

static int failures;

#define CHECK(condition, message)                                               \
    do {                                                                        \
        if (condition) {                                                        \
            printf("PASS: %s\n", message);                                    \
        } else {                                                                \
            printf("FAIL: %s (%s:%d, errno=%d %s)\n", message, __FILE__,     \
                   __LINE__, errno, strerror(errno));                           \
            failures++;                                                        \
        }                                                                       \
    } while (0)

static int create_nonblocking_pipe(int pipefd[2])
{
    return pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
}

static void check_null_io(void)
{
    int pipefd[2];
    if (create_nonblocking_pipe(pipefd) != 0) {
        CHECK(0, "create pipe for null read");
        return;
    }
    CHECK(1, "create pipe for null read");

    errno = 0;
    CHECK(syscall(SYS_read, pipefd[0], (void *)1, 0) == 0 && errno == 0,
          "null read succeeds while empty pipe has writer");

    close(pipefd[0]);
    errno = 0;
    CHECK(syscall(SYS_write, pipefd[1], (void *)1, 0) == 0 && errno == 0,
          "null write succeeds after last reader closes");
    close(pipefd[1]);
}

static void check_atomic_small_write(void)
{
    int pipefd[2];
    char initial[INITIAL_WRITE_SIZE];
    char atomic[ATOMIC_WRITE_SIZE];
    int queued = -1;

    memset(initial, 'a', sizeof(initial));
    memset(atomic, 'b', sizeof(atomic));
    if (create_nonblocking_pipe(pipefd) != 0) {
        CHECK(0, "create pipe for atomic nonblocking write");
        return;
    }
    CHECK(1, "create pipe for atomic nonblocking write");

    CHECK(fcntl(pipefd[1], F_SETPIPE_SZ, TEST_PIPE_CAPACITY) ==
              TEST_PIPE_CAPACITY,
          "set pipe capacity to one PIPE_BUF page");
    CHECK(write(pipefd[1], initial, sizeof(initial)) == (ssize_t)sizeof(initial),
          "fill all but 96 bytes of pipe");

    errno = 0;
    CHECK(write(pipefd[1], atomic, sizeof(atomic)) == -1 && errno == EAGAIN,
          "small nonblocking write is all-or-EAGAIN");
    CHECK(ioctl(pipefd[0], FIONREAD, &queued) == 0 &&
              queued == INITIAL_WRITE_SIZE,
          "failed atomic write leaves pipe contents unchanged");

    close(pipefd[0]);
    close(pipefd[1]);
}

static void check_writer_poll_events(void)
{
    int pipefd[2];
    char initial[INITIAL_WRITE_SIZE];
    struct pollfd pfd;

    if (create_nonblocking_pipe(pipefd) != 0) {
        CHECK(0, "create pipe for closed-reader poll");
        return;
    }
    CHECK(1, "create pipe for closed-reader poll");
    close(pipefd[0]);

    pfd.fd = pipefd[1];
    pfd.events = POLLOUT;
    pfd.revents = 0;
    CHECK(poll(&pfd, 1, 0) == 1, "closed-reader writer poll returns event");
    CHECK((pfd.revents & (POLLOUT | POLLERR)) == (POLLOUT | POLLERR),
          "closed-reader writer reports POLLOUT and POLLERR");
    close(pipefd[1]);

    memset(initial, 'a', sizeof(initial));
    if (create_nonblocking_pipe(pipefd) != 0) {
        CHECK(0, "create pipe for near-full poll");
        return;
    }
    CHECK(1, "create pipe for near-full poll");
    CHECK(fcntl(pipefd[1], F_SETPIPE_SZ, TEST_PIPE_CAPACITY) ==
              TEST_PIPE_CAPACITY,
          "set near-full poll pipe capacity");
    CHECK(write(pipefd[1], initial, sizeof(initial)) == (ssize_t)sizeof(initial),
          "prepare near-full pipe");

    pfd.fd = pipefd[1];
    pfd.events = POLLOUT;
    pfd.revents = 0;
    CHECK(poll(&pfd, 1, 0) == 0,
          "writer is not POLLOUT with less than PIPE_BUF space");

    close(pipefd[0]);
    close(pipefd[1]);
}

static void check_page_slot_fragmentation(void)
{
    int pipefd[2];
    char initial[FRAGMENTED_WRITE_SIZE];
    char consumed[FRAGMENTED_READ_SIZE];
    char atomic[INITIAL_WRITE_SIZE];
    int queued = -1;
    struct pollfd pfd;

    memset(initial, 'e', sizeof(initial));
    memset(atomic, 'f', sizeof(atomic));
    if (create_nonblocking_pipe(pipefd) != 0) {
        CHECK(0, "create pipe for page-slot fragmentation");
        return;
    }
    CHECK(1, "create pipe for page-slot fragmentation");

    CHECK(fcntl(pipefd[1], F_SETPIPE_SZ, FRAGMENTED_PIPE_CAPACITY) ==
              FRAGMENTED_PIPE_CAPACITY,
          "set fragmented pipe capacity to two pages");
    CHECK(write(pipefd[1], initial, sizeof(initial)) == (ssize_t)sizeof(initial),
          "occupy both pipe page slots");
    CHECK(read(pipefd[0], consumed, sizeof(consumed)) == (ssize_t)sizeof(consumed),
          "leave vacant bytes without freeing a pipe page slot");
    CHECK(ioctl(pipefd[0], FIONREAD, &queued) == 0 && queued == 4000,
          "fragmented pipe keeps the expected byte count");

    pfd.fd = pipefd[1];
    pfd.events = POLLOUT;
    pfd.revents = 0;
    CHECK(poll(&pfd, 1, 0) == 0,
          "writer is not POLLOUT while every pipe page slot is occupied");

    errno = 0;
    CHECK(fcntl(pipefd[1], F_SETPIPE_SZ, TEST_PIPE_CAPACITY) == -1 &&
              errno == EBUSY,
          "shrinking below the occupied page-slot count returns EBUSY");
    errno = 0;
    CHECK(write(pipefd[1], atomic, sizeof(atomic)) == -1 && errno == EAGAIN,
          "fragmented small write is all-or-EAGAIN");

    close(pipefd[0]);
    close(pipefd[1]);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    check_null_io();
    check_atomic_small_write();
    check_writer_poll_events();
    check_page_slot_fragmentation();

    if (failures != 0) {
        printf("STARRY_GROUPED_TEST_FAILED: bug-pipe-linux-semantics "
               "failures=%d\n",
               failures);
        return 1;
    }
    printf("STARRY_GROUPED_TEST_PASSED: bug-pipe-linux-semantics\n");
    return 0;
}
