// SPDX-License-Identifier: Apache-2.0
// Focused regression: verify that poll/epoll correctly detects a pipe close
// when the write end is dropped (child process exits).
//
// Mimics the Nix build monitoring pattern: Nix creates a pipe, forks a
// builder, and monitors the read end via epoll.  When the builder exits,
// epoll must return EPOLLIN|EPOLLHUP so Nix can detect completion.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int tests_pass;
static int tests_fail;

enum {
    SAME_FD_DIAGNOSTIC_ITERATIONS = 100,
    SAME_FD_POLL_TIMEOUT_MS = 250,
};

struct same_fd_poll_worker {
    int fd;
    atomic_int entered;
    atomic_int completed;
    int result;
    int error;
    short revents;
};

struct same_fd_poll_distribution {
    int close_completed;
    int peer_completed;
    int final_completed;
    int cleanup_timeouts;
    int trigger_writes;
    int trigger_epipe;
    int result_zero;
    int result_one;
    int result_error;
    int error_eintr;
    int revents_in;
    int revents_hup;
    int revents_nval;
    int revents_other;
};

#define TEST(cond, msg)                                                        \
    do {                                                                      \
        if (cond) {                                                           \
            tests_pass++;                                                     \
            printf("  PASS: %s\n", msg);                                      \
        } else {                                                              \
            tests_fail++;                                                     \
            printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
        }                                                                     \
    } while (0)

static void diagnostic_signal_handler(int signo) {
    (void)signo;
}

static void sleep_one_millisecond(void) {
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
    (void)nanosleep(&delay, NULL);
}

static int wait_for_flag(atomic_int *flag, int timeout_ms) {
    for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms++) {
        if (atomic_load_explicit(flag, memory_order_acquire) != 0) {
            return 1;
        }
        sleep_one_millisecond();
    }
    return atomic_load_explicit(flag, memory_order_acquire) != 0;
}

static void *same_fd_poll_worker_main(void *argument) {
    struct same_fd_poll_worker *worker = argument;
    struct pollfd pfd = {.fd = worker->fd, .events = POLLIN};

    atomic_store_explicit(&worker->entered, 1, memory_order_release);
    errno = 0;
    worker->result = poll(&pfd, 1, SAME_FD_POLL_TIMEOUT_MS);
    worker->error = worker->result < 0 ? errno : 0;
    worker->revents = pfd.revents;
    atomic_store_explicit(&worker->completed, 1, memory_order_release);
    return NULL;
}

static void record_same_fd_poll_result(
    const struct same_fd_poll_worker *worker,
    struct same_fd_poll_distribution *distribution) {
    if (worker->result == 0) {
        distribution->result_zero++;
    } else if (worker->result == 1) {
        distribution->result_one++;
    } else {
        distribution->result_error++;
        if (worker->error == EINTR) {
            distribution->error_eintr++;
        }
    }

    if ((worker->revents & POLLIN) != 0) {
        distribution->revents_in++;
    }
    if ((worker->revents & POLLHUP) != 0) {
        distribution->revents_hup++;
    }
    if ((worker->revents & POLLNVAL) != 0) {
        distribution->revents_nval++;
    }
    if ((worker->revents & ~(POLLIN | POLLHUP | POLLNVAL)) != 0) {
        distribution->revents_other++;
    }
}


// ─── Test 1: poll detects pipe close (HUP) ──────────────────────────────
static void test_poll_pipe_close(void) {
    printf("Test 1: poll detects pipe close when write end drops\n");
    int pipefd[2];
    TEST(pipe(pipefd) == 0, "pipe created");

    pid_t child = fork();
    TEST(child >= 0, "fork succeeded");

    if (child == 0) {
        // Child: close read end, write, then exit
        close(pipefd[0]);
        const char *msg = "hello";
        (void)!write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);
        _exit(0);
    }

    // Parent: close write end, wait for child to finish writing
    close(pipefd[1]);

    // Ensure child has written before polling, avoiding arch-dependent
    // scheduler race where poll(200ms) fires before the child is scheduled.
    waitpid(child, NULL, 0);

    // First read the data the child wrote
    char buf[64] = {0};
    struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
    int ret = poll(&pfd, 1, 200);
    TEST(ret == 1, "poll returned 1 after child wrote data");
    TEST(pfd.revents & POLLIN, "POLLIN set after child writes");

    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    TEST(n == 5, "read got 5 bytes from pipe");
    TEST(strcmp(buf, "hello") == 0, "read correct data");

    // Now poll again — pipe should show POLLHUP since write end is closed
    // and no data remains
    pfd.revents = 0;
    ret = poll(&pfd, 1, 200);
    TEST(ret == 1, "poll returned 1 after pipe close");
    TEST((pfd.revents & (POLLIN | POLLHUP)) != 0,
         "POLLIN or POLLHUP set after pipe close (Linux: both)");
    TEST(pfd.revents & POLLHUP, "POLLHUP set after pipe close");

    // Per Linux behaviour, a closed empty pipe should also set POLLIN
    // because read() would return 0 (EOF) without blocking.
    fprintf(stderr, "  INFO: revents=0x%x (POLLIN=0x%x POLLHUP=0x%x)\n",
            pfd.revents, POLLIN, POLLHUP);

    // Verify EOF
    n = read(pipefd[0], buf, sizeof(buf));
    TEST(n == 0, "read returns 0 (EOF) after pipe close");

    close(pipefd[0]);
    waitpid(child, NULL, 0);
}

// ─── Test 2: epoll detects pipe close ───────────────────────────────────
static void test_epoll_pipe_close(void) {
    printf("Test 2: epoll detects pipe close when write end drops\n");
    int pipefd[2];
    TEST(pipe(pipefd) == 0, "pipe created");

    int epfd = epoll_create1(0);
    TEST(epfd >= 0, "epoll_create1 succeeded");

    pid_t child = fork();
    TEST(child >= 0, "fork succeeded");

    if (child == 0) {
        // Child: close read end, write, then exit
        close(pipefd[0]);
        const char *msg = "world";
        (void)!write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);
        _exit(0);
    }

    // Parent: close write end, add read end to epoll
    close(pipefd[1]);

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
    TEST(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0,
         "epoll_ctl ADD succeeded");

    // Wait for first event: data available
    struct epoll_event events[4];
    int nfds = epoll_wait(epfd, events, 4, 200);
    TEST(nfds == 1, "epoll_wait returned 1 event when data is ready");
    TEST(events[0].data.fd == pipefd[0], "event is for pipe fd");
    TEST(events[0].events & EPOLLIN, "EPOLLIN set after child writes data");

    // Read data
    char buf[64] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    TEST(n == 5, "read 5 bytes via epoll wake");
    TEST(strcmp(buf, "world") == 0, "correct data via epoll");

    // Now wait for close event — after draining data and child exited,
    // epoll should report EPOLLHUP
    nfds = epoll_wait(epfd, events, 4, 200);
    TEST(nfds == 1, "epoll_wait returned event after pipe close");
    TEST(events[0].data.fd == pipefd[0], "close event is for pipe fd");
    fprintf(stderr, "  INFO: epoll events=0x%x (EPOLLIN=0x%x EPOLLHUP=0x%x)\n",
            events[0].events, EPOLLIN, EPOLLHUP);

    // Linux: EPOLLHUP is set; EPOLLIN may or may not be set depending on
    // kernel version.  epoll_wait returning at all for the close is the
    // essential behaviour.
    TEST((events[0].events & (EPOLLIN | EPOLLHUP)) != 0,
         "EPOLLIN or EPOLLHUP set after pipe close");
    TEST(events[0].events & EPOLLHUP, "EPOLLHUP set after pipe close");

    // Verify EOF
    n = read(pipefd[0], buf, sizeof(buf));
    TEST(n == 0, "read returns 0 (EOF) after pipe close");

    close(pipefd[0]);
    close(epfd);
    waitpid(child, NULL, 0);
}

// ─── Test 3: epoll EPOLLIN-only interest still receives close event ─────
static void test_epoll_in_only_detects_close(void) {
    printf("Test 3: epoll EPOLLIN-only detects pipe close (Nix pattern)\n");
    int pipefd[2];
    TEST(pipe(pipefd) == 0, "pipe created");

    int epfd = epoll_create1(0);
    TEST(epfd >= 0, "epoll_create1 succeeded");


    pid_t child = fork();
    TEST(child >= 0, "fork succeeded");

    if (child == 0) {
        // Child: close read end, write marker, exit
        close(pipefd[0]);
        (void)!write(pipefd[1], "x", 1);
        (void)!fsync(pipefd[1]);
        close(pipefd[1]);
        _exit(0);
    }

    // Parent: close write end, monitor read end with EPOLLIN only
    close(pipefd[1]);

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
    TEST(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0,
         "epoll_ctl ADD with EPOLLIN only");

    // First event: data
    struct epoll_event events[4];
    int nfds = epoll_wait(epfd, events, 4, 200);
    TEST(nfds == 1, "EPOLLIN-only: first epoll_wait got data event");
    TEST(events[0].events & EPOLLIN, "EPOLLIN-only: EPOLLIN set for data");

    // Drain data
    char c;
    TEST(read(pipefd[0], &c, 1) == 1, "EPOLLIN-only: read 1 byte");

    // Now the child has exited and closed its write end.
    // We monitor with EPOLLIN only — this is exactly what Nix does.
    // The epoll must wake us up even though we only asked for EPOLLIN.
    // Verify the child has exited
    int status;
    waitpid(child, &status, 0);

    nfds = epoll_wait(epfd, events, 4, 200);
    // We must get at least 1 event — the pipe close.
    TEST(nfds >= 1, "EPOLLIN-only: epoll_wait returned after pipe close");
    if (nfds >= 1) {
        fprintf(stderr,
                "  INFO: EPOLLIN-only close events=0x%x (EPOLLIN=0x%x "
                "EPOLLHUP=0x%x)\n",
                events[0].events, EPOLLIN, EPOLLHUP);
        TEST((events[0].events & (EPOLLIN | EPOLLHUP)) != 0,
             "EPOLLIN-only: got EPOLLIN or EPOLLHUP on close");
    }

    close(pipefd[0]);
    close(epfd);
}

// ─── Test 4: poll_smoke — 2-fd poll where one fd closes ─────────────────
static void test_poll_two_fds_one_closes(void) {
    printf("Test 4: poll with 2 fds, one pipe closes (Nix multi-fd pattern)\n");
    int pipefd[2];
    TEST(pipe(pipefd) == 0, "pipe created");

    pid_t child = fork();
    TEST(child >= 0, "fork succeeded");

    if (child == 0) {
        close(pipefd[0]);
        (void)!write(pipefd[1], "!", 1);
        (void)!fsync(pipefd[1]);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);

    // Also open another fd (e.g. a "control" fd via pipe-to-self)
    int ctrlfd[2];
    TEST(pipe(ctrlfd) == 0, "control pipe created");

    struct pollfd pfds[2] = {
        {.fd = pipefd[0], .events = POLLIN},
        {.fd = ctrlfd[0], .events = POLLIN},
    };

    // First poll: data on pipefd
    int ret = poll(pfds, 2, 200);
    TEST(ret >= 1, "multi-fd: poll got initial event(s)");
    TEST(pfds[0].revents & POLLIN, "multi-fd: pipe fd has POLLIN");

    // Drain
    char c;
    (void)!read(pipefd[0], &c, 1);

    // Wait for child exit
    waitpid(child, NULL, 0);

    // Poll again: pipe should report HUP
    pfds[0].revents = 0;
    pfds[1].revents = 0;
    ret = poll(pfds, 2, 200);
    TEST(ret >= 1, "multi-fd: poll detected pipe close");
    TEST((pfds[0].revents & (POLLIN | POLLHUP)) != 0,
         "multi-fd: pipe fd reports POLLIN or POLLHUP after close");
    fprintf(stderr, "  INFO: multi-fd pipe revents=0x%x ctrl revents=0x%x\n",
            pfds[0].revents, pfds[1].revents);

    close(pipefd[0]);
    close(ctrlfd[0]);
    close(ctrlfd[1]);
}

// ─── Test 5: epoll LT + close without draining first ────────────────────
// Edge case: fd added to epoll, child writes and exits, parent hasn't
// drained yet.  epoll must deliver both IN (data) and HUP (close).
static void test_epoll_lt_close_with_data(void) {
    printf("Test 5: epoll LT delivers both data and close in one event\n");
    int pipefd[2];
    TEST(pipe(pipefd) == 0, "pipe created");

    int epfd = epoll_create1(0);
    TEST(epfd >= 0, "epoll_create1 succeeded");

    pid_t child = fork();
    TEST(child >= 0, "fork succeeded");

    if (child == 0) {
        close(pipefd[0]);
        (void)!write(pipefd[1], "data", 4);
        (void)!fsync(pipefd[1]);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
    TEST(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0,
         "epoll_ctl ADD succeeded");

    // Wait for child to exit
    waitpid(child, NULL, 0);

    // Now epoll should report events — both data and close
    struct epoll_event events[4];
    int nfds = epoll_wait(epfd, events, 4, 200);
    TEST(nfds == 1, "epoll_wait returned 1 event (data+close combined)");
    TEST(events[0].data.fd == pipefd[0],
         "event is for the pipe read end");
    fprintf(stderr,
            "  INFO: LT data+close events=0x%x (EPOLLIN=0x%x EPOLLHUP=0x%x)\n",
            events[0].events, EPOLLIN, EPOLLHUP);
    TEST((events[0].events & (EPOLLIN | EPOLLHUP)) != 0,
         "got EPOLLIN or EPOLLHUP for data+close");
    // EPOLLIN must be set because there is unconsumed data
    TEST(events[0].events & EPOLLIN,
         "EPOLLIN set (data present in buffer)");

    // Read data
    char buf[64] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    TEST(n == 4, "read 4 bytes");
    TEST(strcmp(buf, "data") == 0, "correct data");

    // After draining, epoll should report HUP
    nfds = epoll_wait(epfd, events, 4, 200);
    TEST(nfds == 1, "after drain: epoll_wait returned close event");
    fprintf(stderr, "  INFO: after-drain close events=0x%x\n",
            events[0].events);
    TEST((events[0].events & (EPOLLIN | EPOLLHUP)) != 0,
         "after drain: got EPOLLIN or EPOLLHUP");

    close(pipefd[0]);
    close(epfd);
}

// Linux does not define a portable result when one thread closes the same
// descriptor that another thread is polling. Keep this as a distributional
// diagnostic: only harness, crash, and bounded-cleanup failures are gates.
static void diagnose_same_fd_cross_thread_poll_close(void) {
    printf("Test 6: diagnose same-fd cross-thread poll close (100 runs)\n");

    struct sigaction handler = {0};
    struct sigaction old_usr1;
    struct sigaction ignore_pipe = {0};
    struct sigaction old_pipe;
    handler.sa_handler = diagnostic_signal_handler;
    ignore_pipe.sa_handler = SIG_IGN;
    sigemptyset(&handler.sa_mask);
    sigemptyset(&ignore_pipe.sa_mask);
    if (sigaction(SIGUSR1, &handler, &old_usr1) != 0) {
        TEST(0, "same-fd diagnostic installed signal dispositions");
        return;
    }
    if (sigaction(SIGPIPE, &ignore_pipe, &old_pipe) != 0) {
        (void)sigaction(SIGUSR1, &old_usr1, NULL);
        TEST(0, "same-fd diagnostic installed signal dispositions");
        return;
    }

    struct same_fd_poll_distribution distribution = {0};
    int harness_failed = 0;
    int completed_iterations = 0;

    for (int iteration = 0; iteration < SAME_FD_DIAGNOSTIC_ITERATIONS;
         iteration++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            harness_failed = 1;
            break;
        }

        struct same_fd_poll_worker worker = {.fd = pipefd[0]};
        atomic_init(&worker.entered, 0);
        atomic_init(&worker.completed, 0);
        pthread_t thread;
        int thread_error = pthread_create(
            &thread, NULL, same_fd_poll_worker_main, &worker);
        if (thread_error != 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            harness_failed = 1;
            break;
        }

        if (!wait_for_flag(&worker.entered, 1000)) {
            harness_failed = 1;
        }
        // Give the worker an opportunity to cross from the published entry
        // point into poll before the controller closes the numeric fd.
        sleep_one_millisecond();
        if (close(pipefd[0]) != 0) {
            harness_failed = 1;
        }

        if (wait_for_flag(&worker.completed, 5)) {
            distribution.close_completed++;
        } else {
            errno = 0;
            ssize_t written = write(pipefd[1], "x", 1);
            if (written == 1) {
                distribution.trigger_writes++;
            } else if (written < 0 && errno == EPIPE) {
                distribution.trigger_epipe++;
            } else {
                harness_failed = 1;
            }

            if (wait_for_flag(&worker.completed, 20)) {
                distribution.peer_completed++;
            } else {
                thread_error = pthread_kill(thread, SIGUSR1);
                if (thread_error != 0 && thread_error != ESRCH) {
                    harness_failed = 1;
                }
                if (wait_for_flag(&worker.completed, 500)) {
                    distribution.final_completed++;
                } else {
                    distribution.cleanup_timeouts++;
                    harness_failed = 1;
                }
            }
        }

        close(pipefd[1]);
        if (atomic_load_explicit(&worker.completed, memory_order_acquire) == 0) {
            // Exiting the process is the only safe fallback after reporting
            // an uncleanable worker; never block the grouped suite in join.
            break;
        }
        thread_error = pthread_join(thread, NULL);
        if (thread_error != 0) {
            harness_failed = 1;
            break;
        }
        record_same_fd_poll_result(&worker, &distribution);
        completed_iterations++;
    }

    struct utsname system_name;
    const char *release = "unknown";
    if (uname(&system_name) == 0) {
        release = system_name.release;
    }
    printf("SAME_FD_POLL_CLOSE_DIAGNOSTIC: release=%s iterations=%d "
           "completed=%d "
           "close_completed=%d peer_completed=%d final_completed=%d "
           "cleanup_timeouts=%d trigger_writes=%d trigger_epipe=%d "
           "result_zero=%d result_one=%d result_error=%d eintr=%d "
           "pollin=%d pollhup=%d pollnval=%d other=%d\n",
           release, SAME_FD_DIAGNOSTIC_ITERATIONS, completed_iterations,
           distribution.close_completed, distribution.peer_completed,
           distribution.final_completed, distribution.cleanup_timeouts,
           distribution.trigger_writes, distribution.trigger_epipe,
           distribution.result_zero, distribution.result_one,
           distribution.result_error, distribution.error_eintr,
           distribution.revents_in, distribution.revents_hup,
           distribution.revents_nval, distribution.revents_other);

    if (sigaction(SIGUSR1, &old_usr1, NULL) != 0 ||
        sigaction(SIGPIPE, &old_pipe, NULL) != 0) {
        harness_failed = 1;
    }
    TEST(!harness_failed,
         "same-fd diagnostic completed and cleaned all 100 workers");
}

int main(void) {
    printf("=== pipe-poll-close regression ===\n");

    test_poll_pipe_close();
    test_epoll_pipe_close();
    test_epoll_in_only_detects_close();
    test_poll_two_fds_one_closes();
    test_epoll_lt_close_with_data();
    diagnose_same_fd_cross_thread_poll_close();

    printf("\n=== Results: %d pass, %d fail ===\n", tests_pass, tests_fail);
    if (tests_fail == 0) {
        printf("TEST PASSED\n");
    } else {
        printf("TEST FAILED\n");
    }
    return tests_fail > 0 ? 1 : 0;
}
