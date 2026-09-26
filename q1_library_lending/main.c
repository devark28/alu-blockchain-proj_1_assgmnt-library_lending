#include "blockchain.h"
#include "crypto.h"
#include "registry.h"
#include "utils.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define BOOKS_FILE "books.txt"
#define MEMBERS_FILE "members.txt"
#define CHAIN_FILE "chain.txt"
#define KEYS_DIR "keys"
#define PRIVATE_KEY_FILE KEYS_DIR "/librarian_private.pem"
#define PUBLIC_KEY_FILE KEYS_DIR "/librarian_public.pem"

#define INPUT_SIZE 64
#define PASSPHRASE_SIZE 128
#define MIN_PASSPHRASE_LENGTH 8
#define MAX_LOGIN_ATTEMPTS 3

#ifndef LOAN_PERIOD_SECONDS
#define LOAN_PERIOD_SECONDS (14 * 24 * 60 * 60)
#endif

typedef struct {
    Registry registry;
    Blockchain chain;
    EVP_PKEY *public_key;
    EVP_PKEY *private_key;
} LibrarySystem;

static bool read_line(char *buffer, size_t size)
{
    if (fgets(buffer, (int)size, stdin) == NULL) {
        buffer[0] = '\0';
        return false;
    }

    size_t length = strcspn(buffer, "\n");
    if (buffer[length] != '\n') {
        int extra;
        while ((extra = getchar()) != '\n' && extra != EOF) {
        }
    }
    buffer[length] = '\0';
    trim_whitespace(buffer);
    return true;
}

static void prompt(const char *label, char *buffer, size_t size)
{
    printf("%s", label);
    fflush(stdout);
    read_line(buffer, size);
}

/* Turns terminal echo off while the passphrase is typed. */
static void prompt_passphrase(const char *label, char *buffer, size_t size)
{
    struct termios original_settings;
    bool is_terminal = tcgetattr(STDIN_FILENO, &original_settings) == 0;

    if (is_terminal) {
        struct termios hidden_settings = original_settings;
        hidden_settings.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &hidden_settings);
    }

    prompt(label, buffer, size);

    if (is_terminal) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_settings);
        printf("\n");
    }
}

static bool choose_new_passphrase(char *passphrase, size_t size)
{
    char confirmation[PASSPHRASE_SIZE];

    for (;;) {
        prompt_passphrase("New librarian passphrase: ", passphrase, size);
        if (strlen(passphrase) < MIN_PASSPHRASE_LENGTH) {
            printf("The passphrase must be at least %d characters.\n", MIN_PASSPHRASE_LENGTH);
            if (feof(stdin)) {
                return false;
            }
            continue;
        }
        prompt_passphrase("Confirm passphrase: ", confirmation, sizeof(confirmation));
        bool matches = strcmp(passphrase, confirmation) == 0;
        OPENSSL_cleanse(confirmation, sizeof(confirmation));
        if (matches) {
            return true;
        }
        printf("The passphrases do not match, try again.\n");
        if (feof(stdin)) {
            return false;
        }
    }
}

/*
 * First run: create the librarian's key pair. The new private key stays
 * loaded, so the librarian is logged in and can sign the genesis block.
 */
static bool create_librarian_keys(LibrarySystem *library)
{
    printf("No librarian keys found. Creating a new %s key pair.\n", SIGNATURE_CURVE);

    if (mkdir(KEYS_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "ERROR: cannot create %s/ (%s)\n", KEYS_DIR, strerror(errno));
        return false;
    }

    char passphrase[PASSPHRASE_SIZE];
    if (!choose_new_passphrase(passphrase, sizeof(passphrase))) {
        fprintf(stderr, "ERROR: no passphrase was set\n");
        return false;
    }

    EVP_PKEY *key = generate_key_pair();
    bool saved = key != NULL && save_key_pair(key, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, passphrase);
    OPENSSL_cleanse(passphrase, sizeof(passphrase));
    if (!saved) {
        EVP_PKEY_free(key);
        return false;
    }

    library->private_key = key;
    library->public_key = load_public_key(PUBLIC_KEY_FILE);
    if (library->public_key == NULL) {
        return false;
    }
    printf("Keys saved to %s/. The private key is encrypted with your passphrase.\n", KEYS_DIR);
    return true;
}

static bool setup_keys(LibrarySystem *library)
{
    if (access(PUBLIC_KEY_FILE, F_OK) != 0) {
        return create_librarian_keys(library);
    }
    library->public_key = load_public_key(PUBLIC_KEY_FILE);
    return library->public_key != NULL;
}

/*
 * Read-only actions need only the public key. Actions that add a block need
 * the private key, and the only way to get it is to decrypt it with the
 * librarian's passphrase.
 */
static bool require_login(LibrarySystem *library)
{
    if (library->private_key != NULL) {
        return true;
    }
    printf("This action adds a signed block and requires librarian login.\n");

    for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
        char passphrase[PASSPHRASE_SIZE];
        prompt_passphrase("Librarian passphrase: ", passphrase, sizeof(passphrase));
        EVP_PKEY *key = load_private_key(PRIVATE_KEY_FILE, passphrase);
        OPENSSL_cleanse(passphrase, sizeof(passphrase));

        if (key != NULL && EVP_PKEY_eq(key, library->public_key) == 1) {
            library->private_key = key;
            printf("Login successful.\n");
            return true;
        }
        if (key != NULL) {
            EVP_PKEY_free(key);
            printf("ERROR: %s does not match %s\n", PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
            return false;
        }
        printf("Wrong passphrase (attempt %d of %d).\n", attempt, MAX_LOGIN_ATTEMPTS);
        if (feof(stdin)) {
            break;
        }
    }
    printf("ERROR: login failed, action cancelled.\n");
    return false;
}

static void logout(LibrarySystem *library)
{
    if (library->private_key == NULL) {
        printf("You are not logged in.\n");
        return;
    }
    EVP_PKEY_free(library->private_key);
    library->private_key = NULL;
    printf("Logged out. The private key has been removed from memory.\n");
}

static bool create_chain_if_missing(LibrarySystem *library)
{
    if (library->chain.count > 0) {
        return true;
    }
    printf("No chain found in %s, creating the genesis block.\n", CHAIN_FILE);
    if (!require_login(library)) {
        return false;
    }

    Block genesis;
    return create_genesis_block(&genesis, library->private_key)
        && append_block(&library->chain, &genesis, CHAIN_FILE);
}

static void record_action(LibrarySystem *library, const Book *book, const Member *member, const char *action)
{
    if (!validate_chain(&library->chain, library->public_key, false)) {
        printf("ERROR: the chain failed validation, new records are blocked until it is restored.\n");
        return;
    }

    Block new_block;
    if (!create_block(&library->chain, book, member, action, library->private_key, &new_block)
        || !append_block(&library->chain, &new_block, CHAIN_FILE)) {
        printf("ERROR: the record was not saved.\n");
        return;
    }
    printf("Block %d added: %s %s (%s) by %s (%s)\n", new_block.index, action,
           book->book_id, book->title, member->member_id, member->full_name);
    printf("Hash %s\n", new_block.hash);
}

static bool lookup_book_and_member(const LibrarySystem *library, const Book **book, const Member **member)
{
    char book_id[INPUT_SIZE];
    char member_id[INPUT_SIZE];
    prompt("Book ID: ", book_id, sizeof(book_id));
    prompt("Member ID: ", member_id, sizeof(member_id));

    *book = find_book(&library->registry, book_id);
    *member = find_member(&library->registry, member_id);
    if (*book == NULL || *member == NULL) {
        printf("ERROR: Book or Member not found\n");
        return false;
    }
    return true;
}

static void borrow_book(LibrarySystem *library)
{
    const Book *book;
    const Member *member;
    if (!require_login(library) || !lookup_book_and_member(library, &book, &member)) {
        return;
    }

    const Block *open_loan = find_open_loan(&library->chain, book->book_id);
    if (open_loan != NULL) {
        printf("ERROR: %s is already on loan to %s (%s) since block %d\n",
               book->book_id, open_loan->member_id, open_loan->member_name, open_loan->index);
        return;
    }
    record_action(library, book, member, ACTION_BORROWED);
}

static void return_book(LibrarySystem *library)
{
    const Book *book;
    const Member *member;
    if (!require_login(library) || !lookup_book_and_member(library, &book, &member)) {
        return;
    }

    const Block *open_loan = find_open_loan(&library->chain, book->book_id);
    if (open_loan == NULL) {
        printf("ERROR: %s has no open BORROWED record (never borrowed or already returned)\n", book->book_id);
        return;
    }
    if (strcmp(open_loan->member_id, member->member_id) != 0) {
        printf("ERROR: %s is on loan to %s (%s), not %s\n",
               book->book_id, open_loan->member_id, open_loan->member_name, member->member_id);
        return;
    }
    record_action(library, book, member, ACTION_RETURNED);
}

static void mark_overdue(LibrarySystem *library)
{
    if (!require_login(library)) {
        return;
    }

    char book_id[INPUT_SIZE];
    prompt("Book ID: ", book_id, sizeof(book_id));
    const Book *book = find_book(&library->registry, book_id);
    if (book == NULL) {
        printf("ERROR: Book or Member not found\n");
        return;
    }

    const Block *open_loan = find_open_loan(&library->chain, book->book_id);
    if (open_loan == NULL) {
        printf("ERROR: %s is not on loan\n", book->book_id);
        return;
    }
    if (strcmp(open_loan->action, ACTION_OVERDUE) == 0) {
        printf("ERROR: %s is already marked overdue in block %d\n", book->book_id, open_loan->index);
        return;
    }

    time_t due_time = open_loan->timestamp + LOAN_PERIOD_SECONDS;
    if (time(NULL) < due_time) {
        char due_text[32];
        format_timestamp(due_time, due_text, sizeof(due_text));
        printf("ERROR: %s is not overdue yet, it is due on %s\n", book->book_id, due_text);
        return;
    }

    const Member *member = find_member(&library->registry, open_loan->member_id);
    if (member == NULL) {
        printf("ERROR: Book or Member not found\n");
        return;
    }
    record_action(library, book, member, ACTION_OVERDUE);
}

static void view_registries(const LibrarySystem *library)
{
    const Registry *registry = &library->registry;

    printf("\nBooks (%d)\n", registry->book_count);
    for (int i = 0; i < registry->book_count; i++) {
        const Book *book = &registry->books[i];
        const Block *open_loan = find_open_loan(&library->chain, book->book_id);
        printf("  %-8s %-28s %-26s ", book->book_id, book->title, book->author);
        if (open_loan == NULL) {
            printf("available\n");
        } else {
            printf("%s by %s\n", open_loan->action, open_loan->member_id);
        }
    }

    printf("\nMembers (%d)\n", registry->member_count);
    for (int i = 0; i < registry->member_count; i++) {
        const Member *member = &registry->members[i];
        printf("  %-8s %-28s %s\n", member->member_id, member->full_name, member->course_code);
    }
}

static void view_records(const LibrarySystem *library)
{
    printf("\n");
    for (int i = 0; i < library->chain.count; i++) {
        print_block(&library->chain.blocks[i], library->public_key);
    }
    printf("%d blocks in the chain.\n", library->chain.count);
}

/*
 * Works on a copy of the chain, so chain.txt and the real chain are never
 * touched. Step 1 edits a block the naive way. Step 2 repeats what a smarter
 * attacker would do: recompute every hash from the edited block onwards so
 * the links line up again. Only the signature check can catch step 2.
 */
static void run_tamper_demo(const LibrarySystem *library)
{
    static Blockchain copy;
    const Blockchain *chain = &library->chain;

    if (chain->count < 2) {
        printf("Record at least one borrow first, the genesis block has no lending data to tamper with.\n");
        return;
    }

    char input[INPUT_SIZE];
    int target;
    printf("This demo edits a copy of the chain in memory, %s is not modified.\n", CHAIN_FILE);
    printf("Block to tamper with (1-%d): ", chain->count - 1);
    fflush(stdout);
    read_line(input, sizeof(input));
    if (sscanf(input, "%d", &target) != 1 || target < 1 || target >= chain->count) {
        printf("ERROR: invalid block number\n");
        return;
    }

    copy = *chain;
    Block *block = &copy.blocks[target];
    const char *forged_action = strcmp(block->action, ACTION_RETURNED) == 0 ? ACTION_BORROWED : ACTION_RETURNED;

    printf("\nStep 1: change block %d action from %s to %s, leaving its hash and signature as they were.\n\n",
           target, block->action, forged_action);
    strcpy(block->action, forged_action);
    validate_chain(&copy, library->public_key, true);

    printf("\nStep 2: recompute the hash of block %d and every block after it, relinking the chain.\n\n", target);
    for (int i = target; i < copy.count; i++) {
        strcpy(copy.blocks[i].previous_hash, copy.blocks[i - 1].hash);
        compute_block_hash(&copy.blocks[i], copy.blocks[i].hash);
    }
    validate_chain(&copy, library->public_key, true);

    printf("\nHashes and links are consistent again, but block %d still fails its signature check.\n", target);
    printf("Re-signing it would need the librarian's private key, which the attacker does not have.\n");
}

static void print_menu(const LibrarySystem *library)
{
    printf("\n===== Library Lending Tracker =====\n");
    printf("Books %d | Members %d | Blocks %d | Librarian %s\n",
           library->registry.book_count, library->registry.member_count, library->chain.count,
           library->private_key != NULL ? "logged in" : "logged out");
    printf("  1. View registries\n");
    printf("  2. Borrow a book\n");
    printf("  3. Return a book\n");
    printf("  4. Mark a book overdue\n");
    printf("  5. View lending records\n");
    printf("  6. Validate chain\n");
    printf("  7. Tamper detection demo\n");
    printf("  8. Log out\n");
    printf("  0. Exit\n");
    printf("Choice: ");
    fflush(stdout);
}

static void run_menu(LibrarySystem *library)
{
    char choice[INPUT_SIZE];

    for (;;) {
        print_menu(library);
        if (!read_line(choice, sizeof(choice))) {
            printf("\n");
            return;
        }
        if (strlen(choice) != 1) {
            printf("Invalid choice.\n");
            continue;
        }

        switch (choice[0]) {
        case '1': view_registries(library); break;
        case '2': borrow_book(library); break;
        case '3': return_book(library); break;
        case '4': mark_overdue(library); break;
        case '5': view_records(library); break;
        case '6': validate_chain(&library->chain, library->public_key, true); break;
        case '7': run_tamper_demo(library); break;
        case '8': logout(library); break;
        case '0': return;
        default: printf("Invalid choice.\n");
        }
    }
}

int main(void)
{
    static LibrarySystem library;

    if (!load_registry(&library.registry, BOOKS_FILE, MEMBERS_FILE)) {
        return EXIT_FAILURE;
    }
    printf("Loaded %d books from %s and %d members from %s.\n",
           library.registry.book_count, BOOKS_FILE, library.registry.member_count, MEMBERS_FILE);

    bool ready = setup_keys(&library)
        && load_chain(&library.chain, CHAIN_FILE)
        && create_chain_if_missing(&library);

    if (ready) {
        printf("Chain loaded from %s, blocks: %d\n", CHAIN_FILE, library.chain.count);
        if (!validate_chain(&library.chain, library.public_key, false)) {
            printf("WARNING: %s failed validation. Use option 6 for details. New records are blocked.\n", CHAIN_FILE);
        }
        run_menu(&library);
    }

    EVP_PKEY_free(library.private_key);
    EVP_PKEY_free(library.public_key);
    return ready ? EXIT_SUCCESS : EXIT_FAILURE;
}
