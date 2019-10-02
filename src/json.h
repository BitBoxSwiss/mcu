#include <stddef.h>
#include <stdint.h>

#ifndef _JSON_H_
#define _JSON_H_

/**
 * Appends a "key"="value" and the closing bracket '}' where value will be correctly quoted.
 */
int json_append_kv_pair_quoted(char *out, size_t len, const char *key,
                               const char *val);

/**
 * Appends a "key"=value string where value should not be quoted, like if value
 * is a number or already a correctly quoted string, and the closing bracket '}'.
 */
int json_append_kv_pair_unquoted(char *out, size_t len, const char *key,
                                 const char *val);

/**
 * Writes a complete valid json object for errors.
 */
int json_format_error(char *out, size_t len, const char *cmd, const char *msg,
                      int flag);

/**
 * Writes a complete valid json object. Will quote value[i] if type[i] ==
 * DBB_JSON_STRING.
 */
int json_format_object(char *out, size_t len, const char **key,
                       const char **value, int *type);

#endif
