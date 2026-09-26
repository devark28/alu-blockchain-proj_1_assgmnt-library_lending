#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "crypto.h"
#include "registry.h"

#include <stdbool.h>
#include <time.h>

#define MAX_BLOCKS 1000
#define ACTION_SIZE 10

#define ACTION_GENESIS "GENESIS"
#define ACTION_BORROWED "BORROWED"
#define ACTION_RETURNED "RETURNED"
#define ACTION_OVERDUE "OVERDUE"

typedef struct {
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_SIZE];
    char previous_hash[HASH_HEX_SIZE];
    unsigned char signature[MAX_SIGNATURE_SIZE];
    unsigned int signature_len;
    char hash[HASH_HEX_SIZE];
} Block;

typedef struct {
    Block blocks[MAX_BLOCKS];
    int count;
} Blockchain;

bool create_genesis_block(Block *genesis, EVP_PKEY *private_key);
bool create_block(const Blockchain *chain, const Book *book, const Member *member,
                  const char *action, EVP_PKEY *private_key, Block *new_block);
bool append_block(Blockchain *chain, const Block *block, const char *path);
bool load_chain(Blockchain *chain, const char *path);

void compute_block_hash(const Block *block, char output[HASH_HEX_SIZE]);
bool block_signature_is_valid(const Block *block, EVP_PKEY *public_key);
bool validate_chain(const Blockchain *chain, EVP_PKEY *public_key, bool print_report);

const Block *find_open_loan(const Blockchain *chain, const char *book_id);
void format_timestamp(time_t timestamp, char *buffer, size_t size);
void print_block(const Block *block, EVP_PKEY *public_key);

#endif
