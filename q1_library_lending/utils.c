#include "utils.h"

#include <ctype.h>
#include <string.h>

/*
 * Splits line in place on delimiter and returns how many fields were found.
 * The last field keeps any remaining delimiters, so a line with too many
 * fields is caught by the caller's length checks instead of being dropped.
 */
int split_line(char *line, char delimiter, char *fields[], int max_fields)
{
    int count = 1;
    fields[0] = line;

    while (count < max_fields) {
        char *separator = strchr(fields[count - 1], delimiter);
        if (separator == NULL) {
            break;
        }
        *separator = '\0';
        fields[count] = separator + 1;
        count++;
    }
    return count;
}

bool copy_field(char *dest, size_t dest_size, const char *src)
{
    size_t length = strlen(src);
    if (length >= dest_size) {
        return false;
    }
    memcpy(dest, src, length + 1);
    return true;
}

void trim_whitespace(char *text)
{
    size_t start = 0;
    while (isspace((unsigned char)text[start])) {
        start++;
    }

    size_t end = strlen(text);
    while (end > start && isspace((unsigned char)text[end - 1])) {
        end--;
    }

    memmove(text, text + start, end - start);
    text[end - start] = '\0';
}
