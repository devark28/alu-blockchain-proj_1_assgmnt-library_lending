#include "blockchain.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define GENESIS_PREVIOUS_HASH "0000000000000000000000000000000000000000000000000000000000000000"
#define PAYLOAD_SIZE 512
#define SIGNATURE_HEX_SIZE (MAX_SIGNATURE_SIZE * 2 + 1)
#define CHAIN_LINE_SIZE 1024
#define BLOCK_FIELD_COUNT 10

/*
 * The fields covered by the signature, joined with '|'. The separator keeps
 * the encoding unambiguous: without it, the fields "AB" + "C" and "A" + "BC"
 * would produce the same bytes and therefore the same hash and signature.
 */
static void build_signing_payload(const Block *block, char *payload, size_t size)
{
    snprintf(payload, size, "%d|%lld|%s|%s|%s|%s|%s|%s",
             block->index, (long long)block->timestamp,
             block->book_id, block->book_title,
             block->member_id, block->member_name,
             block->action, block->previous_hash);
}

void compute_block_hash(const Block *block, char output[HASH_HEX_SIZE])
{
    char payload[PAYLOAD_SIZE];
    char signature_hex[SIGNATURE_HEX_SIZE];
    char hash_input[PAYLOAD_SIZE + SIGNATURE_HEX_SIZE + 1];

    build_signing_payload(block, payload, sizeof(payload));
    bytes_to_hex(block->signature, block->signature_len, signature_hex);
    snprintf(hash_input, sizeof(hash_input), "%s|%s", payload, signature_hex);
    sha256_hex(hash_input, output);
}

bool block_signature_is_valid(const Block *block, EVP_PKEY *public_key)
{
    char payload[PAYLOAD_SIZE];
    build_signing_payload(block, payload, sizeof(payload));
    return verify_signature(public_key, payload, block->signature, block->signature_len);
}

/* Sign first, then hash, so the block hash also commits to the signature. */
static bool seal_block(Block *block, EVP_PKEY *private_key)
{
    char payload[PAYLOAD_SIZE];
    build_signing_payload(block, payload, sizeof(payload));

    if (!sign_data(private_key, payload, block->signature, &block->signature_len)) {
        fprintf(stderr, "ERROR: could not sign block %d\n", block->index);
        return false;
    }
    compute_block_hash(block, block->hash);
    return true;
}

bool create_genesis_block(Block *genesis, EVP_PKEY *private_key)
{
    memset(genesis, 0, sizeof(*genesis));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->action, ACTION_GENESIS);
    strcpy(genesis->previous_hash, GENESIS_PREVIOUS_HASH);
    return seal_block(genesis, private_key);
}

bool create_block(const Blockchain *chain, const Book *book, const Member *member,
                  const char *action, EVP_PKEY *private_key, Block *new_block)
{
    if (chain->count == 0) {
        fprintf(stderr, "ERROR: the chain has no genesis block\n");
        return false;
    }
    const Block *last_block = &chain->blocks[chain->count - 1];

    memset(new_block, 0, sizeof(*new_block));
    new_block->index = chain->count;
    new_block->timestamp = time(NULL);
    strcpy(new_block->book_id, book->book_id);
    strcpy(new_block->book_title, book->title);
    strcpy(new_block->member_id, member->member_id);
    strcpy(new_block->member_name, member->full_name);
    if (!copy_field(new_block->action, sizeof(new_block->action), action)) {
        fprintf(stderr, "ERROR: action \"%s\" is too long\n", action);
        return false;
    }
    strcpy(new_block->previous_hash, last_block->hash);
    return seal_block(new_block, private_key);
}

/*
 * The block is written to disk before it is added to memory, so a failed
 * write never leaves the program holding a block that was not saved.
 */
bool append_block(Blockchain *chain, const Block *block, const char *path)
{
    if (chain->count == MAX_BLOCKS) {
        fprintf(stderr, "ERROR: the chain is full (%d blocks)\n", MAX_BLOCKS);
        return false;
    }

    FILE *file = fopen(path, "a");
    if (file == NULL) {
        fprintf(stderr, "ERROR: cannot open %s for writing (%s)\n", path, strerror(errno));
        return false;
    }

    char signature_hex[SIGNATURE_HEX_SIZE];
    bytes_to_hex(block->signature, block->signature_len, signature_hex);

    int written = fprintf(file, "%d|%lld|%s|%s|%s|%s|%s|%s|%s|%s\n",
                          block->index, (long long)block->timestamp,
                          block->book_id, block->book_title,
                          block->member_id, block->member_name,
                          block->action, block->previous_hash,
                          signature_hex, block->hash);
    bool closed = fclose(file) == 0;
    if (written < 0 || !closed) {
        fprintf(stderr, "ERROR: could not save block %d to %s\n", block->index, path);
        return false;
    }

    chain->blocks[chain->count++] = *block;
    return true;
}

static bool parse_block_line(char *line, Block *block)
{
    char *fields[BLOCK_FIELD_COUNT];
    if (split_line(line, '|', fields, BLOCK_FIELD_COUNT) != BLOCK_FIELD_COUNT) {
        return false;
    }

    memset(block, 0, sizeof(*block));
    long long timestamp;
    int signature_len = hex_to_bytes(fields[8], block->signature, MAX_SIGNATURE_SIZE);

    if (sscanf(fields[0], "%d", &block->index) != 1
        || sscanf(fields[1], "%lld", &timestamp) != 1
        || !copy_field(block->book_id, sizeof(block->book_id), fields[2])
        || !copy_field(block->book_title, sizeof(block->book_title), fields[3])
        || !copy_field(block->member_id, sizeof(block->member_id), fields[4])
        || !copy_field(block->member_name, sizeof(block->member_name), fields[5])
        || !copy_field(block->action, sizeof(block->action), fields[6])
        || !copy_field(block->previous_hash, sizeof(block->previous_hash), fields[7])
        || signature_len < 0
        || !copy_field(block->hash, sizeof(block->hash), fields[9])) {
        return false;
    }

    block->timestamp = (time_t)timestamp;
    block->signature_len = (unsigned int)signature_len;
    return true;
}

/* A missing file is not an error: it means this is the first run. */
bool load_chain(Blockchain *chain, const char *path)
{
    chain->count = 0;

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        if (errno == ENOENT) {
            return true;
        }
        fprintf(stderr, "ERROR: cannot open %s (%s)\n", path, strerror(errno));
        return false;
    }

    char line[CHAIN_LINE_SIZE];
    int line_number = 0;
    bool loaded = true;

    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        if (chain->count == MAX_BLOCKS) {
            fprintf(stderr, "ERROR: %s has more than %d blocks\n", path, MAX_BLOCKS);
            loaded = false;
            break;
        }
        if (!parse_block_line(line, &chain->blocks[chain->count])) {
            fprintf(stderr, "ERROR: %s line %d is not a valid block record\n", path, line_number);
            loaded = false;
            break;
        }
        chain->count++;
    }
    fclose(file);
    return loaded;
}

static const char *check_result(bool passed)
{
    return passed ? "OK" : "FAIL";
}

bool validate_chain(const Blockchain *chain, EVP_PKEY *public_key, bool print_report)
{
    int first_bad_block = -1;

    for (int i = 0; i < chain->count; i++) {
        const Block *block = &chain->blocks[i];
        const char *expected_previous = (i == 0) ? GENESIS_PREVIOUS_HASH : chain->blocks[i - 1].hash;
        char recomputed_hash[HASH_HEX_SIZE];
        compute_block_hash(block, recomputed_hash);

        bool index_ok = block->index == i;
        bool hash_ok = strcmp(block->hash, recomputed_hash) == 0;
        bool link_ok = strcmp(block->previous_hash, expected_previous) == 0;
        bool signature_ok = block_signature_is_valid(block, public_key);
        bool block_ok = index_ok && hash_ok && link_ok && signature_ok;

        if (!block_ok && first_bad_block == -1) {
            first_bad_block = i;
        }

        if (print_report) {
            printf("Block %-3d  index %-4s  hash %-4s  link %-4s  signature %-4s%s\n",
                   i, check_result(index_ok), check_result(hash_ok),
                   check_result(link_ok), check_result(signature_ok),
                   block_ok ? "" : "  <-- TAMPERED");
            if (!hash_ok) {
                printf("           stored hash     %s\n", block->hash);
                printf("           recomputed hash %s\n", recomputed_hash);
            }
            if (!link_ok) {
                printf("           previous_hash   %s\n", block->previous_hash);
                printf("           expected        %s\n", expected_previous);
            }
        }
    }

    if (print_report) {
        if (first_bad_block == -1) {
            printf("\nRESULT: chain is VALID (%d blocks, all hashes, links and signatures verified)\n", chain->count);
        } else {
            printf("\nRESULT: chain is INVALID, first tampered block is %d\n", first_bad_block);
        }
    }
    return first_bad_block == -1;
}

/*
 * A book's state is not stored anywhere; it is derived from its latest
 * block. The book is on loan when that block is BORROWED or OVERDUE.
 */
const Block *find_open_loan(const Blockchain *chain, const char *book_id)
{
    for (int i = chain->count - 1; i > 0; i--) {
        const Block *block = &chain->blocks[i];
        if (strcmp(block->book_id, book_id) != 0) {
            continue;
        }
        if (strcmp(block->action, ACTION_BORROWED) == 0 || strcmp(block->action, ACTION_OVERDUE) == 0) {
            return block;
        }
        return NULL;
    }
    return NULL;
}

void format_timestamp(time_t timestamp, char *buffer, size_t size)
{
    struct tm *local = localtime(&timestamp);
    if (local == NULL || strftime(buffer, size, "%Y-%m-%d %H:%M:%S", local) == 0) {
        snprintf(buffer, size, "%lld", (long long)timestamp);
    }
}

void print_block(const Block *block, EVP_PKEY *public_key)
{
    char time_text[32];
    format_timestamp(block->timestamp, time_text, sizeof(time_text));
    bool signature_ok = block_signature_is_valid(block, public_key);

    printf("Block %d  [signature %s]\n", block->index, signature_ok ? "VALID" : "INVALID");
    printf("  Time       %s\n", time_text);
    printf("  Action     %s\n", block->action);
    if (block->index == 0) {
        printf("  Record     genesis block, no lending data\n");
    } else {
        printf("  Book       %s  %s\n", block->book_id, block->book_title);
        printf("  Member     %s  %s\n", block->member_id, block->member_name);
    }
    printf("  Prev hash  %s\n", block->previous_hash);
    printf("  Hash       %s\n\n", block->hash);
}
