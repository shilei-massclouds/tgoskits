#include "test_framework.h"

#include <poll.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define REVENTS_SENTINEL ((short)0x5a5a)

static long raw_ppoll_zero(struct pollfd *fds, nfds_t nfds)
{
    const struct timespec timeout = {0, 0};

    return syscall(SYS_ppoll, fds, nfds, &timeout, NULL, 0UL);
}

int run_poll_multi_entry_semantics(void)
{
    MODULE_START("poll_multi_entry_semantics");

    struct pollfd negative = {
        .fd = -2,
        .events = POLLIN,
        .revents = REVENTS_SENTINEL,
    };
    errno = 0;
    long ret = syscall(SYS_poll, &negative, 1UL, 0L);
    CHECK(ret == 0 && errno == 0, "poll ignores fd=-2");
    CHECK(negative.revents == 0, "poll clears fd=-2 revents");

    negative.revents = REVENTS_SENTINEL;
    errno = 0;
    ret = raw_ppoll_zero(&negative, 1);
    CHECK(ret == 0 && errno == 0, "ppoll ignores fd=-2");
    CHECK(negative.revents == 0, "ppoll clears fd=-2 revents");

    int pipe_fds[2];
    CHECK_RET(pipe(pipe_fds), 0, "ready pipe created");
    CHECK_RET(write(pipe_fds[1], "R", 1), 1, "ready pipe populated");
    int closed_fd = dup(pipe_fds[0]);
    CHECK(closed_fd >= 0, "positive fd duplicated for invalid entry");
    CHECK_RET(close(closed_fd), 0, "positive fd closed before poll");

    struct pollfd mixed[2] = {
        {
            .fd = closed_fd,
            .events = POLLIN,
            .revents = REVENTS_SENTINEL,
        },
        {
            .fd = pipe_fds[0],
            .events = POLLIN,
            .revents = REVENTS_SENTINEL,
        },
    };
    errno = 0;
    ret = syscall(SYS_poll, mixed, 2UL, 0L);
    CHECK(ret == 2 && errno == 0,
          "poll counts invalid and ready entries before returning");
    CHECK((mixed[0].revents & POLLNVAL) != 0,
          "poll reports POLLNVAL for a closed positive fd");
    CHECK((mixed[1].revents & POLLIN) != 0,
          "poll still reports POLLIN after an invalid entry");

    mixed[0].revents = REVENTS_SENTINEL;
    mixed[1].revents = REVENTS_SENTINEL;
    errno = 0;
    ret = raw_ppoll_zero(mixed, 2);
    CHECK(ret == 2 && errno == 0,
          "ppoll counts invalid and ready entries before returning");
    CHECK((mixed[0].revents & POLLNVAL) != 0,
          "ppoll reports POLLNVAL for a closed positive fd");
    CHECK((mixed[1].revents & POLLIN) != 0,
          "ppoll still reports POLLIN after an invalid entry");

    CHECK_RET(close(pipe_fds[0]), 0, "ready pipe reader closed");
    CHECK_RET(close(pipe_fds[1]), 0, "ready pipe writer closed");

    MODULE_SUMMARY("poll_multi_entry_semantics");
    MODULE_RETURN();
}
