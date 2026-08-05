#include "concurrent_trace.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define RAW_HEADER_SIZE 24U
#define RAW_SCENARIO_HEADER_SIZE 12U
#define ALLOWED_HEADER_SIZE 56U
#define ALLOWED_SCENARIO_HEADER_SIZE 44U

struct sha256_context {
    uint32_t state[8];
    uint64_t bit_length;
    unsigned char block[64];
    size_t block_length;
};

static uint32_t rotate_right(uint32_t value, unsigned int shift)
{
    return (value >> shift) | (value << (32U - shift));
}

static uint32_t load_le32(const unsigned char *input)
{
    return (uint32_t)input[0] | (uint32_t)input[1] << 8 |
           (uint32_t)input[2] << 16 | (uint32_t)input[3] << 24;
}

static uint64_t load_le64(const unsigned char *input)
{
    return (uint64_t)load_le32(input) |
           (uint64_t)load_le32(input + 4) << 32;
}

static void store_le32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)value;
    output[1] = (unsigned char)(value >> 8);
    output[2] = (unsigned char)(value >> 16);
    output[3] = (unsigned char)(value >> 24);
}

static void store_le64(unsigned char *output, uint64_t value)
{
    store_le32(output, (uint32_t)value);
    store_le32(output + 4, (uint32_t)(value >> 32));
}

static uint32_t load_be32(const unsigned char *input)
{
    return (uint32_t)input[0] << 24 | (uint32_t)input[1] << 16 |
           (uint32_t)input[2] << 8 | (uint32_t)input[3];
}

static void store_be32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static void sha256_transform(struct sha256_context *context,
                             const unsigned char block[64])
{
    static const uint32_t constants[64] = {
        UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
        UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
        UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
        UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
        UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
        UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
        UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
        UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
        UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
        UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
        UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
        UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
        UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
        UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
        UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
        UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
        UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
        UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
        UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
        UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
        UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
        UINT32_C(0xc67178f2),
    };
    uint32_t schedule[64];
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    uint32_t f = context->state[5];
    uint32_t g = context->state[6];
    uint32_t h = context->state[7];
    unsigned int index;

    for (index = 0; index < 16; index++)
        schedule[index] = load_be32(block + index * 4U);
    for (; index < 64; index++) {
        uint32_t first = rotate_right(schedule[index - 15], 7) ^
                         rotate_right(schedule[index - 15], 18) ^
                         (schedule[index - 15] >> 3);
        uint32_t second = rotate_right(schedule[index - 2], 17) ^
                          rotate_right(schedule[index - 2], 19) ^
                          (schedule[index - 2] >> 10);

        schedule[index] = schedule[index - 16] + first +
                          schedule[index - 7] + second;
    }
    for (index = 0; index < 64; index++) {
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                          rotate_right(a, 22);
        uint32_t sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                          rotate_right(e, 25);
        uint32_t first = h + sigma1 + choose + constants[index] +
                         schedule[index];
        uint32_t second = sigma0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_initialize(struct sha256_context *context)
{
    static const uint32_t initial[8] = {
        UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85),
        UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f), UINT32_C(0x9b05688c),
        UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19),
    };

    memcpy(context->state, initial, sizeof(initial));
    context->bit_length = 0;
    context->block_length = 0;
}

static void sha256_update(struct sha256_context *context,
                          const unsigned char *input, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++) {
        context->block[context->block_length++] = input[index];
        if (context->block_length == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->bit_length += UINT64_C(512);
            context->block_length = 0;
        }
    }
}

static void sha256_finish(struct sha256_context *context,
                          unsigned char digest[32])
{
    uint64_t total_bits = context->bit_length +
                          (uint64_t)context->block_length * UINT64_C(8);
    size_t index = context->block_length;

    context->block[index++] = 0x80;
    if (index > 56) {
        memset(context->block + index, 0, 64 - index);
        sha256_transform(context, context->block);
        index = 0;
    }
    memset(context->block + index, 0, 56 - index);
    for (index = 0; index < 8; index++)
        context->block[63 - index] = (unsigned char)(total_bits >> (index * 8));
    sha256_transform(context, context->block);
    for (index = 0; index < 8; index++)
        store_be32(digest + index * 4, context->state[index]);
}

void concurrent_sha256(const unsigned char *input, size_t length,
                       unsigned char digest[32])
{
    struct sha256_context context;

    sha256_initialize(&context);
    sha256_update(&context, input, length);
    sha256_finish(&context, digest);
}

int concurrent_encode_result(const struct concurrent_operation_result *result,
                             unsigned char encoded[CONCURRENT_RESULT_SIZE])
{
    if (result == NULL || encoded == NULL ||
        result->data_length > CONCURRENT_RESULT_DATA_MAX)
        return -1;
    memset(encoded, 0, CONCURRENT_RESULT_SIZE);
    store_le32(encoded, result->scenario_index);
    store_le32(encoded + 4, result->operation_index);
    store_le32(encoded + 8, result->kind);
    store_le32(encoded + 12, result->actor);
    store_le64(encoded + 16, (uint64_t)result->result);
    store_le32(encoded + 24, (uint32_t)result->error_number);
    store_le32(encoded + 28, result->data_length);
    store_le64(encoded + 32, result->value);
    store_le32(encoded + 40, result->handler_count);
    store_le32(encoded + 44, result->completion_ordinal);
    memcpy(encoded + 48, result->data, result->data_length);
    return 0;
}

static int write_bytes(FILE *file, const unsigned char *bytes, size_t length)
{
    return fwrite(bytes, 1, length, file) == length ? 0 : -1;
}

int concurrent_raw_open(struct concurrent_raw_writer *writer, const char *path,
                        const unsigned char magic[8], uint32_t version,
                        uint64_t corpus_digest)
{
    unsigned char header[RAW_HEADER_SIZE] = {0};

    if (writer == NULL || path == NULL || magic == NULL || version == 0)
        return -1;
    memset(writer, 0, sizeof(*writer));
    writer->file = fopen(path, "wb+");
    if (writer->file == NULL)
        return -1;
    memcpy(header, magic, 8);
    store_le32(header + 8, version);
    store_le64(header + 16, corpus_digest);
    if (write_bytes(writer->file, header, sizeof(header)) != 0) {
        fclose(writer->file);
        writer->file = NULL;
        return -1;
    }
    return 0;
}

int concurrent_raw_write_scenario(struct concurrent_raw_writer *writer,
                                  uint32_t scenario_index,
                                  uint32_t operation_count,
                                  const unsigned char *payload,
                                  uint32_t payload_length)
{
    unsigned char header[RAW_SCENARIO_HEADER_SIZE];

    if (writer == NULL || writer->file == NULL || writer->failed ||
        scenario_index != writer->scenario_count ||
        scenario_index >= CONCURRENT_MAX_SCENARIOS || operation_count == 0 ||
        operation_count > CONCURRENT_MAX_OPERATIONS || payload == NULL ||
        payload_length == 0)
        return -1;
    store_le32(header, scenario_index);
    store_le32(header + 4, operation_count);
    store_le32(header + 8, payload_length);
    if (write_bytes(writer->file, header, sizeof(header)) != 0 ||
        write_bytes(writer->file, payload, payload_length) != 0) {
        writer->failed = 1;
        return -1;
    }
    writer->scenario_count++;
    return 0;
}

int concurrent_raw_close(struct concurrent_raw_writer *writer)
{
    unsigned char count[4];
    int status = 0;

    if (writer == NULL || writer->file == NULL)
        return -1;
    if (writer->failed || writer->scenario_count == 0 ||
        fseek(writer->file, 12, SEEK_SET) != 0) {
        status = -1;
    } else {
        store_le32(count, writer->scenario_count);
        if (write_bytes(writer->file, count, sizeof(count)) != 0 ||
            fflush(writer->file) != 0)
            status = -1;
    }
    if (fclose(writer->file) != 0)
        status = -1;
    writer->file = NULL;
    return status;
}

static int read_entire_file(const char *path, unsigned char **encoded,
                            size_t *length)
{
    FILE *file = fopen(path, "rb");
    long end;
    unsigned char *buffer;

    if (file == NULL || fseek(file, 0, SEEK_END) != 0 ||
        (end = ftell(file)) < 0 || (unsigned long)end > SIZE_MAX ||
        fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL)
            fclose(file);
        return -1;
    }
    buffer = malloc(end == 0 ? 1U : (size_t)end);
    if (buffer == NULL || fread(buffer, 1, (size_t)end, file) != (size_t)end ||
        fclose(file) != 0) {
        free(buffer);
        return -1;
    }
    *encoded = buffer;
    *length = (size_t)end;
    return 0;
}

int concurrent_allowed_open(struct concurrent_allowed_reader *reader,
                            const char *path,
                            const unsigned char expected_magic[8],
                            uint32_t expected_version,
                            uint64_t expected_corpus_digest)
{
    unsigned char digest[32];

    if (reader == NULL || path == NULL || expected_magic == NULL ||
        expected_version == 0)
        return -1;
    memset(reader, 0, sizeof(*reader));
    if (read_entire_file(path, &reader->encoded, &reader->length) != 0)
        return -1;
    if (reader->length < ALLOWED_HEADER_SIZE ||
        memcmp(reader->encoded, expected_magic, 8) != 0 ||
        load_le32(reader->encoded + 8) != expected_version ||
        load_le64(reader->encoded + 16) != expected_corpus_digest) {
        free(reader->encoded);
        memset(reader, 0, sizeof(*reader));
        return -1;
    }
    reader->scenario_count = load_le32(reader->encoded + 12);
    concurrent_sha256(reader->encoded + ALLOWED_HEADER_SIZE,
                      reader->length - ALLOWED_HEADER_SIZE, digest);
    if (reader->scenario_count == 0 ||
        reader->scenario_count > CONCURRENT_MAX_SCENARIOS ||
        memcmp(digest, reader->encoded + 24, sizeof(digest)) != 0) {
        free(reader->encoded);
        memset(reader, 0, sizeof(*reader));
        return -1;
    }
    reader->offset = ALLOWED_HEADER_SIZE;
    return 0;
}

static int compare_payloads(const unsigned char *left, uint32_t left_length,
                            const unsigned char *right, uint32_t right_length)
{
    uint32_t common = left_length < right_length ? left_length : right_length;
    int comparison = memcmp(left, right, common);

    if (comparison != 0)
        return comparison;
    return left_length < right_length ? -1 : left_length > right_length;
}

static uint32_t first_difference(const unsigned char *expected,
                                 uint32_t expected_length,
                                 const unsigned char *actual,
                                 uint32_t actual_length)
{
    uint32_t common = expected_length < actual_length ? expected_length :
                                                      actual_length;
    uint32_t offset;

    for (offset = 0; offset < common; offset++) {
        if (expected[offset] != actual[offset])
            return offset;
    }
    return common;
}

int concurrent_allowed_compare(struct concurrent_allowed_reader *reader,
                               uint32_t scenario_index,
                               uint32_t operation_count,
                               const unsigned char *payload,
                               uint32_t payload_length,
                               struct concurrent_mismatch *mismatch)
{
    const unsigned char *scenario;
    const unsigned char *previous = NULL;
    uint32_t previous_length = 0;
    uint32_t alternative_count;
    uint32_t alternative_index;
    size_t alternative_offset;
    size_t alternatives_end;
    uint32_t best_difference = UINT32_MAX;
    unsigned char calculated_set_digest[32];
    struct sha256_context set_context;
    int matched = 0;

    if (reader == NULL || reader->encoded == NULL || payload == NULL ||
        payload_length == 0 || mismatch == NULL ||
        reader->next_scenario >= reader->scenario_count ||
        reader->offset + ALLOWED_SCENARIO_HEADER_SIZE > reader->length)
        return -1;
    scenario = reader->encoded + reader->offset;
    alternative_count = load_le32(scenario + 8);
    if (scenario_index != reader->next_scenario ||
        load_le32(scenario) != scenario_index ||
        load_le32(scenario + 4) != operation_count || operation_count == 0 ||
        operation_count > CONCURRENT_MAX_OPERATIONS ||
        alternative_count == 0 ||
        alternative_count > CONCURRENT_MAX_ALTERNATIVES)
        return -1;
    memset(mismatch, 0, sizeof(*mismatch));
    memcpy(mismatch->allowed_set_digest, scenario + 12, 32);
    concurrent_sha256(payload, payload_length, mismatch->actual_digest);
    alternative_offset = reader->offset + ALLOWED_SCENARIO_HEADER_SIZE;
    alternatives_end = alternative_offset;
    for (alternative_index = 0; alternative_index < alternative_count;
         alternative_index++) {
        const unsigned char *alternative;
        uint32_t alternative_length;
        uint32_t difference;

        if (alternatives_end + 4 > reader->length)
            return -1;
        alternative_length = load_le32(reader->encoded + alternatives_end);
        alternatives_end += 4;
        if (alternative_length == 0 ||
            alternatives_end + alternative_length > reader->length)
            return -1;
        alternative = reader->encoded + alternatives_end;
        if (previous != NULL &&
            compare_payloads(previous, previous_length, alternative,
                             alternative_length) >= 0)
            return -1;
        if (alternative_length == payload_length &&
            memcmp(alternative, payload, payload_length) == 0)
            matched = 1;
        difference = first_difference(alternative, alternative_length,
                                      payload, payload_length);
        if (difference < best_difference) {
            best_difference = difference;
            mismatch->alternative_index = alternative_index;
            mismatch->byte_offset = difference;
            mismatch->expected_length = alternative_length;
            mismatch->actual_length = payload_length;
            mismatch->expected_byte = difference < alternative_length ?
                                          alternative[difference] : 0;
            mismatch->actual_byte = difference < payload_length ?
                                        payload[difference] : 0;
        }
        previous = alternative;
        previous_length = alternative_length;
        alternatives_end += alternative_length;
    }
    sha256_initialize(&set_context);
    sha256_update(&set_context, scenario, 8);
    sha256_update(&set_context, reader->encoded + alternative_offset,
                  alternatives_end - alternative_offset);
    sha256_finish(&set_context, calculated_set_digest);
    if (memcmp(calculated_set_digest, scenario + 12, 32) != 0)
        return -1;
    reader->offset = alternatives_end;
    reader->next_scenario++;
    return matched ? 0 : 1;
}

int concurrent_allowed_close(struct concurrent_allowed_reader *reader)
{
    int status;

    if (reader == NULL || reader->encoded == NULL)
        return -1;
    status = reader->next_scenario == reader->scenario_count &&
                     reader->offset == reader->length ?
                 0 :
                 -1;
    free(reader->encoded);
    memset(reader, 0, sizeof(*reader));
    return status;
}
