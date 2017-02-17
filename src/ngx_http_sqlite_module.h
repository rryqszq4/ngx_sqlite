/**
 *    Copyright(c) 2017 rryqszq4
 *
 *
 */

#ifndef NGX_HTTP_SQLITE_MODULE_H
#define NGX_HTTP_SQLITE_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>
#include <nginx.h>

#include <sqlite3.h>

#define NGX_HTTP_SQLITE_MODULE_NAME "ngx_sqlite"
#define NGX_HTTP_SQLITE_MODULE_VERSION "0.0.1"

extern ngx_module_t ngx_http_sqlite_module;
ngx_http_request_t *ngx_sqlite_request;

typedef struct {
    char *sql;
} ngx_http_sqlite_query_t;

typedef struct {
    unsigned enabled_content_handler:1;

    ngx_str_t sqlite_database;
} ngx_http_sqlite_main_conf_t;

typedef struct {
    ngx_http_sqlite_query_t *sqlite_query;

    ngx_int_t (*content_handler)(ngx_http_request_t *r);
} ngx_http_sqlite_loc_conf_t;

typedef struct {
    ngx_chain_t **last;
    ngx_chain_t *out;
} ngx_http_sqlite_rputs_chain_list_t;

typedef struct {
    ngx_http_sqlite_rputs_chain_list_t *rputs_chain;

    unsigned request_body_more:1;
} ngx_http_sqlite_ctx_t;

#endif