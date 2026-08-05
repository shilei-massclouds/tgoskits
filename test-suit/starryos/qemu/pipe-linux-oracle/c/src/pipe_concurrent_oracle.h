#ifndef STARRY_PIPE_CONCURRENT_ORACLE_H
#define STARRY_PIPE_CONCURRENT_ORACLE_H

#include <stdint.h>

int pipe_concurrent_run(int record_mode, const char *corpus_path,
                        const char *trace_path, uint64_t corpus_digest);

#endif
