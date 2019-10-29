#include "json.h"
#include <yajl/src/api/yajl_gen.h>
#include "flags.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define GEN_CHECK(func, g)               \
    do {                                 \
        yajl_gen_status res = func;      \
        if (res != yajl_gen_status_ok) { \
            yajl_gen_free(g);            \
            return DBB_ERROR;            \
        }                                \
    } while (0)

int json_append_kv_pair_quoted(char *out, size_t len, const char *key, const char *val)
{
    yajl_gen g = yajl_gen_alloc(NULL);
    if (!g) {
        return DBB_ERROR;
    }
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    GEN_CHECK(yajl_gen_map_open(g), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)key, strlens(key)), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)val, strlens(val)), g);
    GEN_CHECK(yajl_gen_map_close(g), g);
    const uint8_t *buf;
    size_t json_len;
    yajl_gen_get_buf(g, &buf, &json_len);
    size_t l = snprintf(out, len, "%.*s", (int)json_len - 1,
                        &buf[1]); // Ignore opening bracket '{'
    yajl_gen_free(g);
    if (l >= len) {
        return DBB_ERROR;
    }
    return DBB_OK;
}


int json_append_kv_pair_unquoted(char *out, size_t len, const char *key, const char *val)
{
    yajl_gen g = yajl_gen_alloc(NULL);
    if (!g) {
        return DBB_ERROR;
    }
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    GEN_CHECK(yajl_gen_map_open(g), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)key, strlens(key)), g);
    // gen_number allows you to write unescaped bytes to the json document
    GEN_CHECK(yajl_gen_number(g, val, strlens(val)), g);
    GEN_CHECK(yajl_gen_map_close(g), g);
    const uint8_t *buf;
    size_t json_len;
    yajl_gen_get_buf(g, &buf, &json_len);
    size_t l = snprintf(out, len, "%.*s", (int)json_len - 1,
                        &buf[1]); // Ignore opening bracket '{'
    yajl_gen_free(g);
    if (l >= len) {
        return DBB_ERROR;
    }
    return DBB_OK;
}

int json_format_error(char *out, size_t len, const char *cmd, const char *msg, int flag)
{
    yajl_gen g = yajl_gen_alloc(NULL);
    if (!g) {
        return DBB_ERROR;
    }
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    if (strlens(msg) == 0) {
        msg = flag_msg(flag);
    }
    GEN_CHECK(yajl_gen_map_open(g), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)attr_str(ATTR_error),
                              strlens(attr_str(ATTR_error))), g);
    GEN_CHECK(yajl_gen_map_open(g), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)"message", sizeof("message") - 1), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)msg, strlens(msg)), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)"code", sizeof("code") - 1), g);
    GEN_CHECK(yajl_gen_number(g, flag_code(flag), strlens(flag_code(flag))),
              g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)"command", sizeof("command") - 1), g);
    GEN_CHECK(yajl_gen_string(g, (const uint8_t *)cmd, strlens(cmd)), g);
    GEN_CHECK(yajl_gen_map_close(g), g);
    GEN_CHECK(yajl_gen_map_close(g), g);
    const uint8_t *buf;
    size_t json_len;
    yajl_gen_get_buf(g, &buf, &json_len);
    size_t l = snprintf(out, len, "%.*s", (int)json_len, buf);
    yajl_gen_free(g);
    if (l >= len) {
        return DBB_ERROR;
    }
    return DBB_OK;
}

int json_format_object(char *out, size_t len, const char **key, const char **value,
                       int *type)
{
    yajl_gen g = yajl_gen_alloc(NULL);
    if (!g) {
        return DBB_ERROR;
    }
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    GEN_CHECK(yajl_gen_map_open(g), g);
    while (*key && *value) {
        GEN_CHECK(yajl_gen_string(g, (const uint8_t *)*key, strlens(*key)), g);
        if (*type == DBB_JSON_STRING) {
            GEN_CHECK(yajl_gen_string(g, (const uint8_t *)*value, strlens(*value)), g);
        } else {
            GEN_CHECK(yajl_gen_number(g, *value, strlens(*value)), g);
        }
        key++;
        value++;
        type++;
    }
    GEN_CHECK(yajl_gen_map_close(g), g);
    const uint8_t *buf;
    size_t json_len;
    yajl_gen_get_buf(g, &buf, &json_len);
    size_t l = snprintf(out, len, "%.*s", (int)json_len, buf);
    yajl_gen_free(g);
    if (l >= len) {
        return DBB_ERROR;
    }
    return DBB_OK;
}
