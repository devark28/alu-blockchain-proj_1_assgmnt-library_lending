#include "registry.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define LINE_SIZE 256
#define FIELDS_PER_RECORD 3

/*
 * A record is valid when it has exactly three non-empty fields. The '|'
 * character is refused because it is the field separator in chain.txt.
 */
static bool parse_record(char *line, char *fields[FIELDS_PER_RECORD])
{
    if (strchr(line, '|') != NULL) {
        return false;
    }
    if (split_line(line, ',', fields, FIELDS_PER_RECORD) != FIELDS_PER_RECORD) {
        return false;
    }
    for (int i = 0; i < FIELDS_PER_RECORD; i++) {
        trim_whitespace(fields[i]);
        if (fields[i][0] == '\0') {
            return false;
        }
    }
    return true;
}

static FILE *open_registry_file(const char *path)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: cannot open %s (%s)\n", path, strerror(errno));
    }
    return file;
}

static bool load_books(Registry *registry, const char *path)
{
    FILE *file = open_registry_file(path);
    if (file == NULL) {
        return false;
    }

    char line[LINE_SIZE];
    int line_number = 0;
    registry->book_count = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        if (registry->book_count == MAX_BOOKS) {
            fprintf(stderr, "WARNING: %s has more than %d books, the rest are ignored\n", path, MAX_BOOKS);
            break;
        }

        char *fields[FIELDS_PER_RECORD];
        Book book;
        if (!parse_record(line, fields)
            || !copy_field(book.book_id, sizeof(book.book_id), fields[0])
            || !copy_field(book.title, sizeof(book.title), fields[1])
            || !copy_field(book.author, sizeof(book.author), fields[2])) {
            fprintf(stderr, "WARNING: %s line %d is malformed or too long, skipped\n", path, line_number);
            continue;
        }
        if (find_book(registry, book.book_id) != NULL) {
            fprintf(stderr, "WARNING: %s line %d repeats book ID %s, skipped\n", path, line_number, book.book_id);
            continue;
        }
        registry->books[registry->book_count++] = book;
    }
    fclose(file);

    if (registry->book_count == 0) {
        fprintf(stderr, "ERROR: %s is empty or has no valid book records\n", path);
        return false;
    }
    return true;
}

static bool load_members(Registry *registry, const char *path)
{
    FILE *file = open_registry_file(path);
    if (file == NULL) {
        return false;
    }

    char line[LINE_SIZE];
    int line_number = 0;
    registry->member_count = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        if (registry->member_count == MAX_MEMBERS) {
            fprintf(stderr, "WARNING: %s has more than %d members, the rest are ignored\n", path, MAX_MEMBERS);
            break;
        }

        char *fields[FIELDS_PER_RECORD];
        Member member;
        if (!parse_record(line, fields)
            || !copy_field(member.member_id, sizeof(member.member_id), fields[0])
            || !copy_field(member.full_name, sizeof(member.full_name), fields[1])
            || !copy_field(member.course_code, sizeof(member.course_code), fields[2])) {
            fprintf(stderr, "WARNING: %s line %d is malformed or too long, skipped\n", path, line_number);
            continue;
        }
        if (find_member(registry, member.member_id) != NULL) {
            fprintf(stderr, "WARNING: %s line %d repeats member ID %s, skipped\n", path, line_number, member.member_id);
            continue;
        }
        registry->members[registry->member_count++] = member;
    }
    fclose(file);

    if (registry->member_count == 0) {
        fprintf(stderr, "ERROR: %s is empty or has no valid member records\n", path);
        return false;
    }
    return true;
}

bool load_registry(Registry *registry, const char *books_path, const char *members_path)
{
    bool books_loaded = load_books(registry, books_path);
    bool members_loaded = load_members(registry, members_path);
    return books_loaded && members_loaded;
}

const Book *find_book(const Registry *registry, const char *book_id)
{
    for (int i = 0; i < registry->book_count; i++) {
        if (strcmp(registry->books[i].book_id, book_id) == 0) {
            return &registry->books[i];
        }
    }
    return NULL;
}

const Member *find_member(const Registry *registry, const char *member_id)
{
    for (int i = 0; i < registry->member_count; i++) {
        if (strcmp(registry->members[i].member_id, member_id) == 0) {
            return &registry->members[i];
        }
    }
    return NULL;
}
