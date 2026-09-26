#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>

int split_line(char *line, char delimiter, char *fields[], int max_fields);
bool copy_field(char *dest, size_t dest_size, const char *src);
void trim_whitespace(char *text);

#endif
