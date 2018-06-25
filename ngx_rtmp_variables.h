
#ifndef _NGX_RTMP_VARIABLES_H_INCLUDED_
#define _NGX_RTMP_VARIABLES_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_variable_value_t  ngx_rtmp_variable_value_t;


#include "ngx_rtmp.h"
#include "ngx_role.h"


#define ngx_rtmp_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

#define NGX_RTMP_VAR_CHANGEABLE   1
#define NGX_RTMP_VAR_NOCACHEABLE  2
#define NGX_RTMP_VAR_INDEXED      4
#define NGX_RTMP_VAR_NOHASH       8

#define ngx_rtmp_variables_var(vstr, val)           \
    if ((vstr)->data == NULL || (vstr)->len == 0)  {\
        val->len = 0;                               \
        val->data = NULL;                           \
        return NGX_OK;                              \
    }                                               \
    val->data = (vstr)->data;                       \
    val->len = (vstr)->len;                         \
    val->valid = 1;                                 \
    val->no_cacheable = 0;                          \
    val->not_found = 0;

typedef struct ngx_rtmp_variable_s  ngx_rtmp_variable_t;

typedef void (*ngx_rtmp_set_variable_pt) (ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_rtmp_get_variable_pt) (ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);


struct ngx_rtmp_variable_s {
    ngx_str_t                     name;   /* must be first to build the hash */
    ngx_rtmp_set_variable_pt      set_handler;
    ngx_rtmp_get_variable_pt      get_handler;
    uintptr_t                     data;
    ngx_uint_t                    flags;
    ngx_uint_t                    index;
};


ngx_rtmp_variable_t *ngx_rtmp_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_rtmp_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_int_t ngx_rtmp_get_http_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_rtmp_variable_value_t *ngx_rtmp_get_indexed_variable(ngx_rtmp_session_t *s,
    ngx_uint_t index);
ngx_rtmp_variable_value_t *ngx_rtmp_get_flushed_variable(ngx_rtmp_session_t *s,
    ngx_uint_t index);

ngx_rtmp_variable_value_t *ngx_rtmp_get_variable(ngx_rtmp_session_t *s,
    ngx_str_t *name, ngx_uint_t key);


ngx_int_t ngx_rtmp_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_rtmp_variables_init_vars(ngx_conf_t *cf);


extern ngx_rtmp_variable_value_t  ngx_rtmp_variable_null_value;
extern ngx_rtmp_variable_value_t  ngx_rtmp_variable_true_value;


#endif /* _NGX_RTMP_VARIABLES_H_INCLUDED_ */
