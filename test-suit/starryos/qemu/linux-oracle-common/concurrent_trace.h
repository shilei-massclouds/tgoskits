#ifndef STARRY_LINUX_ORACLE_CONCURRENT_TRACE_H
#define STARRY_LINUX_ORACLE_CONCURRENT_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* The default campaign combines 32 entries with at most 8 scenarios each. */
#define CONCURRENT_MAX_SCENARIOS 256U
#define CONCURRENT_MAX_OPERATIONS 64U
#define CONCURRENT_MAX_ALTERNATIVES 4U
#define CONCURRENT_RESULT_DATA_MAX 64U
#define CONCURRENT_RESULT_SIZE 112U

struct concurrent_operation_result {
    uint32_t scenario_index;
    uint32_t operation_index;
    uint32_t kind;
    uint32_t actor;
    int64_t result;
    int32_t error_number;
    uint32_t data_length;
    uint64_t value;
    uint32_t handler_count;
    uint32_t completion_ordinal;
    unsigned char data[CONCURRENT_RESULT_DATA_MAX];
};

struct concurrent_raw_writer {
    FILE *file;
    uint32_t scenario_count;
    int failed;
};

struct concurrent_allowed_reader {
    unsigned char *encoded;
    size_t length;
    size_t offset;
    uint32_t scenario_count;
    uint32_t next_scenario;
};

struct concurrent_mismatch {
    unsigned char allowed_set_digest[32];
    unsigned char actual_digest[32];
    uint32_t alternative_index;
    uint32_t byte_offset;
    uint32_t expected_length;
    uint32_t actual_length;
    unsigned char expected_byte;
    unsigned char actual_byte;
};

int concurrent_encode_result(const struct concurrent_operation_result *result,
                             unsigned char encoded[CONCURRENT_RESULT_SIZE]);
void concurrent_sha256(const unsigned char *input, size_t length,
                       unsigned char digest[32]);

int concurrent_raw_open(struct concurrent_raw_writer *writer, const char *path,
                        const unsigned char magic[8], uint32_t version,
                        uint64_t corpus_digest);
int concurrent_raw_write_scenario(struct concurrent_raw_writer *writer,
                                  uint32_t scenario_index,
                                  uint32_t operation_count,
                                  const unsigned char *payload,
                                  uint32_t payload_length);
int concurrent_raw_close(struct concurrent_raw_writer *writer);

int concurrent_allowed_open(struct concurrent_allowed_reader *reader,
                            const char *path,
                            const unsigned char expected_magic[8],
                            uint32_t expected_version,
                            uint64_t expected_corpus_digest);
/* Returns zero for a match, one for a well-formed mismatch, and -1 on error. */
int concurrent_allowed_compare(struct concurrent_allowed_reader *reader,
                               uint32_t scenario_index,
                               uint32_t operation_count,
                               const unsigned char *payload,
                               uint32_t payload_length,
                               struct concurrent_mismatch *mismatch);
int concurrent_allowed_close(struct concurrent_allowed_reader *reader);

#endif
