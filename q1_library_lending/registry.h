#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdbool.h>

#define MAX_BOOKS 200
#define MAX_MEMBERS 200

typedef struct {
    char book_id[20];
    char title[80];
    char author[50];
} Book;

typedef struct {
    char member_id[20];
    char full_name[50];
    char course_code[10];
} Member;

typedef struct {
    Book books[MAX_BOOKS];
    int book_count;
    Member members[MAX_MEMBERS];
    int member_count;
} Registry;

bool load_registry(Registry *registry, const char *books_path, const char *members_path);
const Book *find_book(const Registry *registry, const char *book_id);
const Member *find_member(const Registry *registry, const char *member_id);

#endif
