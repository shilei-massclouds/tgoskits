#include "../concurrent_trace.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_result_encoding(void)
{
    struct concurrent_operation_result result = {
        .scenario_index = 1,
        .operation_index = 2,
        .kind = 3,
        .actor = 1,
        .result = -1,
        .error_number = EINTR,
        .data_length = 3,
        .value = UINT64_C(0x0102030405060708),
        .handler_count = 4,
        .completion_ordinal = 2,
        .data = {0xaa, 0xbb, 0xcc},
    };
    unsigned char encoded[CONCURRENT_RESULT_SIZE];

    assert(concurrent_encode_result(&result, encoded) == 0);
    assert(encoded[0] == 1 && encoded[4] == 2 && encoded[8] == 3);
    assert(encoded[16] == 0xff && encoded[23] == 0xff);
    assert(encoded[24] == EINTR && encoded[28] == 3);
    assert(encoded[32] == 0x08 && encoded[39] == 0x01);
    assert(encoded[48] == 0xaa && encoded[50] == 0xcc);

    result.data_length = CONCURRENT_RESULT_DATA_MAX + 1;
    assert(concurrent_encode_result(&result, encoded) == -1);
}

static void test_raw_trace_writer(void)
{
    const unsigned char magic[8] = {'E', 'V', 'F', 'D', 'R', 'U', 'N', '4'};
    const unsigned char first[] = {1, 2, 3};
    const unsigned char second[] = {4, 5};
    struct concurrent_raw_writer writer;
    unsigned char encoded[64];
    char path[] = "/tmp/concurrent-trace-test-XXXXXX";
    FILE *file;
    int descriptor;
    size_t length;

    descriptor = mkstemp(path);
    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    assert(concurrent_raw_open(&writer, path, magic, 4, UINT64_C(17)) == 0);
    assert(concurrent_raw_write_scenario(&writer, 0, 2, first,
                                         sizeof(first)) == 0);
    assert(concurrent_raw_write_scenario(&writer, 1, 3, second,
                                         sizeof(second)) == 0);
    assert(concurrent_raw_close(&writer) == 0);

    file = fopen(path, "rb");
    assert(file != NULL);
    length = fread(encoded, 1, sizeof(encoded), file);
    assert(fclose(file) == 0);
    assert(unlink(path) == 0);
    assert(length == 53);
    assert(memcmp(encoded, magic, sizeof(magic)) == 0);
    assert(encoded[8] == 4 && encoded[12] == 2 && encoded[16] == 17);
    assert(encoded[24] == 0 && encoded[28] == 2 && encoded[32] == 3);
    assert(memcmp(&encoded[36], first, sizeof(first)) == 0);
    assert(encoded[39] == 1 && encoded[43] == 3 && encoded[47] == 2);
    assert(memcmp(&encoded[51], second, sizeof(second)) == 0);
}

static void test_raw_trace_writer_accepts_default_campaign_batch(void)
{
    static const unsigned char magic[8] = {
        'E', 'V', 'F', 'D', 'R', 'U', 'N', '4',
    };
    static const uint32_t expected_scenarios = 32U * 8U;
    const unsigned char payload[] = {0x5a};
    struct concurrent_raw_writer writer;
    char path[] = "/tmp/concurrent-trace-batch-test-XXXXXX";
    int descriptor;
    uint32_t index;

    descriptor = mkstemp(path);
    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    assert(concurrent_raw_open(&writer, path, magic, 4, UINT64_C(19)) == 0);
    for (index = 0; index < expected_scenarios; index++) {
        assert(concurrent_raw_write_scenario(&writer, index, 1, payload,
                                             sizeof(payload)) == 0);
    }
    assert(concurrent_raw_write_scenario(&writer, expected_scenarios, 1,
                                         payload, sizeof(payload)) == -1);
    assert(concurrent_raw_close(&writer) == 0);
    assert(unlink(path) == 0);
}

static void test_sha256(void)
{
    static const unsigned char expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    unsigned char actual[32];

    concurrent_sha256((const unsigned char *)"abc", 3, actual);
    assert(memcmp(actual, expected, sizeof(expected)) == 0);
}

static void write_fixture(const char *path, const unsigned char *fixture,
                          size_t length)
{
    FILE *file = fopen(path, "wb");

    assert(file != NULL);
    assert(fwrite(fixture, 1, length, file) == length);
    assert(fclose(file) == 0);
}

static void test_python_allowed_trace_fixture(void)
{
    static const unsigned char fixture[] = {
        0x45, 0x56, 0x46, 0x44, 0x4f, 0x52, 0x43, 0x34, 0x04, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xa9, 0x03, 0x93, 0xda, 0xc1, 0x04,
        0xbf, 0x99, 0x6d, 0x1b, 0xdf, 0x12, 0xe8, 0xaa, 0xd3, 0xbe,
        0xe6, 0x39, 0x37, 0x81, 0x30, 0xf7, 0x5e, 0xf2, 0x81, 0x49,
        0x6b, 0x71, 0xf2, 0xfc, 0xf2, 0x94, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x96, 0xf6,
        0x73, 0x44, 0x83, 0x69, 0x15, 0x64, 0xe1, 0x2a, 0x1f, 0xd5,
        0xd7, 0x3d, 0xde, 0x4c, 0x13, 0xba, 0xf4, 0x18, 0x5c, 0xec,
        0x82, 0x4b, 0xd1, 0x03, 0xee, 0x4c, 0xe2, 0x1e, 0x2e, 0xd2,
        0x03, 0x00, 0x00, 0x00, 0x61, 0x61, 0x61, 0x03, 0x00, 0x00,
        0x00, 0x62, 0x62, 0x62,
    };
    static const unsigned char magic[8] = {
        'E', 'V', 'F', 'D', 'O', 'R', 'C', '4',
    };
    struct concurrent_allowed_reader reader;
    struct concurrent_mismatch mismatch;
    char path[] = "/tmp/concurrent-allowed-test-XXXXXX";
    int descriptor = mkstemp(path);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    write_fixture(path, fixture, sizeof(fixture));
    assert(concurrent_allowed_open(&reader, path, magic, 4, 17) == 0);
    assert(concurrent_allowed_compare(&reader, 0, 1,
                                      (const unsigned char *)"bbb", 3,
                                      &mismatch) == 0);
    assert(concurrent_allowed_close(&reader) == 0);

    assert(concurrent_allowed_open(&reader, path, magic, 4, 17) == 0);
    assert(concurrent_allowed_compare(&reader, 0, 1,
                                      (const unsigned char *)"abc", 3,
                                      &mismatch) == 1);
    assert(mismatch.alternative_index == 1);
    assert(mismatch.byte_offset == 0);
    assert(mismatch.expected_byte == 'b' && mismatch.actual_byte == 'a');
    assert(concurrent_allowed_close(&reader) == 0);

    assert(concurrent_allowed_open(&reader, path, magic, 5, 17) == -1);
    assert(unlink(path) == 0);
}

int main(void)
{
    test_result_encoding();
    test_raw_trace_writer();
    test_raw_trace_writer_accepts_default_campaign_batch();
    test_sha256();
    test_python_allowed_trace_fixture();
    puts("concurrent trace tests passed");
    return 0;
}
