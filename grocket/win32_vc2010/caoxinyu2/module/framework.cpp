// This file generate by:
// grtool create_module -name caoxinyu -dir ./caoxinyu2 -tcp_port 8000

/*
 * Copyright (C) 2013-now da_ming at hotmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


////////////////////////////////////////////////////////////////////////
//
// The more time YOU DON'T NEED TO CHANGE THIS FILE !!!!!!!!!
// Your code should appear in the application.h and application.cpp.
//

#include "application.h"
#include "tcp_conn.h"

extern "C"
{

int gr_init(
    gr_init_param_t *   param
)
{
    if ( GR_PROCESS_PARENT == param->proc_type )
    {
        application_t * global = (application_t *)framework_t::create_instance( param->server );
        if ( global )
        {
            return global->init_server();
        }
        else
        {
            printf("framework_t::create_instance(%p) failed\n", param->server);
            return -1;
        }
        return 0;
    }
    else if ( param->proc_type >= GR_PROCESS_WORKER_1 )
    {
        application_t * global = (application_t *)param->server->user_global;
        if ( global )
        {
            return global->init_worker(param->proc_type - GR_PROCESS_WORKER_1);
        }
        else
        {
            printf("global is NULL\n");
            return -1;
        }
        return 0;
    }
    return 0;
}

void gr_term(
    gr_term_param_t *   param
)
{
    application_t * global = (application_t *)param->server->user_global;
    assert(global);

    if ( param->proc_type >= GR_PROCESS_WORKER_1 )
    {
        global->destroy_worker(param->proc_type - GR_PROCESS_WORKER_1);
    }
    else if ( GR_PROCESS_PARENT == param->proc_type )
    {
        global->destroy_framework_inner();
    }
}

void gr_tcp_accept(
    gr_tcp_accept_param_t * param,
    bool *                  need_disconnect
)
{
    application_t *    global  = (application_t *)param->server->user_global;
    tcp_conn_t *       conn    = (tcp_conn_t *)param->conn_buddy->ptr;
    tcp_accept_ctxt_t  ctxt;
    ctxt.worker_id             = param->worker_id;
    ctxt.fd                    = param->fd;
    ctxt.port                  = param->port_info->port;
    ctxt.conn                  = &conn;
    if ( global->tcp_accept(ctxt) )
    {
        if ( conn ) {
            param->conn_buddy->ptr = conn;
        }
        return;
    }
    * need_disconnect = true;
}

void gr_tcp_close(
    gr_tcp_close_param_t *  param
)
{
    application_t *    global = (application_t *)param->server->user_global;
    tcp_close_ctxt_t   ctxt;
    assert(global);
    ctxt.worker_id            = param->worker_id;
    ctxt.fd                   = param->fd;
    ctxt.port                 = param->port_info->port;
    ctxt.conn                 = (tcp_conn_t *)param->conn_buddy->ptr;
    global->tcp_close(ctxt);
    param->conn_buddy->ptr = NULL;
}

void gr_proc_binary(
    gr_proc_param_t *   param,
    int *               processed_len
)
{
    application_t *     global = (application_t *)param->server->user_global;
    proc_binary_ctxt_t  ctxt;

    assert(global);

    ctxt._framework     = param;
    ctxt.port           = param->port;
    ctxt.fd             = param->fd;
    ctxt.worker_id      = param->worker_id;
    ctxt.data           = param->data;
    ctxt.data_len       = param->len;
    ctxt.peer           = param->peer;
    ctxt.conn           = param->conn_buddy ? (tcp_conn_t *)param->conn_buddy->ptr : NULL;
    global->proc_binary(ctxt, * processed_len);
}

bool gr_proc_http(
    gr_http_ctxt_t *    param
)
{
    application_t * global = (application_t *)param->server->user_global;
    assert(global);
    return global->proc_http(param);
}

bool gr_hotfix_export(
    gr_server_t *       server,
    const char *        file_path
)
{
    FILE * fp;
    fp = fopen( file_path, "wb" );
    if ( unlikely( NULL == fp ) ) {
        return false;
    }
    fclose( fp );
    return true;
}

bool gr_hotfix_import(
    gr_server_t *       server,
    const char *        file_path
)
{
    int r;
    gr_init_param_t param;
    param.server = server;
    param.proc_type = GR_PROCESS_PARENT;
    r = gr_init( & param );
    if ( unlikely( 0 != r ) ) {
        return false;
    }
    return true;
}

bool gr_hotfix_cleanup(
    gr_server_t *       server
)
{
    gr_term_param_t param;
    param.server = server;
    param.proc_type = GR_PROCESS_PARENT;
    gr_term( & param );
    return true;
}

void gr_version(
    gr_version_param_t *    param
)
{
    application_t::before_bind_port( param->server );

    // interface compatible check
    param->gr_version           = GR_SERVER_VERSION;
    param->user_global_bytes    = (int)sizeof( application_t );

    // user functions:
    param->init                 = gr_init;
    param->term                 = gr_term;
    param->tcp_accept           = gr_tcp_accept;
    param->tcp_close            = gr_tcp_close;
    param->proc_binary          = gr_proc_binary;
    param->proc_http            = gr_proc_http;

    param->module_version       = MODULE_VERSION;
    param->hotfix_import        = gr_hotfix_import;
    param->hotfix_export        = gr_hotfix_export;
    param->hotfix_cleanup       = gr_hotfix_cleanup;
}

} // extern "C"

///////////////////////////////////////////////////////////////////////
//
// framework_t
//

struct framework_t::framework_inner_t
{
    gr_server_t *      _framework;
    gr_i_server_t *    _server;
    gr_i_gcom_t *      _gcom;
    gr_i_str_t *       _string;
    gr_i_network_t *   _network;
    gr_i_parallel_t *  _parallel;
    gr_i_tool_t *      _tool;

    framework_inner_t()
        : _framework(NULL)
        , _server(NULL)
        , _gcom(NULL)
       , _string(NULL)
       , _network(NULL)
       , _parallel(NULL)
       , _tool(NULL)
    {
    }
};

framework_t::framework_t()
    : _framework(0)
{}

framework_t * framework_t::create_instance(void * framework)
{
    application_t * global = (application_t *)((gr_server_t *)framework)->user_global;

    assert(global);
    if (global->_framework)
    {
        return global;
    }

    new (global) application_t();
    if ( global->init_framework_inner( framework ) )
    {
        return global;
    }

    global->destroy_server();
    return NULL;
}

bool framework_t::init_framework_inner(void * framework)
{
    assert(framework);

    if ( NULL == _framework )
    {
        try {
            _framework = new framework_inner_t();
        } catch ( ... ) {
            printf( "new framework_inner_t exception! maybe std::bad_alloc" );
            return false;
        }
    }

    _framework->_framework = (gr_server_t *)framework;
    _framework->_server    = _framework->_framework->library->buildin;
    _framework->_gcom      = _framework->_framework->library->gcom;
    _framework->_string     = _framework->_framework->library->string;
    _framework->_network    = _framework->_framework->library->network;
    _framework->_parallel   = _framework->_framework->library->parallel;
    _framework->_tool       = _framework->_framework->library->tool;

    return true;
}

void framework_t::destroy_framework_inner()
{
    assert(_framework);

    application_t * global = (application_t *)this;
    global->destroy_server();
    global->~application_t();

    delete _framework;
    _framework = NULL;
}

framework_t::~framework_t()
{
}

void * framework_t::debug_alloc( const char * file, int line, const char * func, size_t bytes )
{
    return _framework->_server->debug_alloc(file, line, func, bytes);
}
void * framework_t::debug_calloc( const char * file, int line, const char * func, size_t bytes )
{
    return _framework->_server->debug_calloc(file, line, func, bytes);
}
void framework_t::debug_free( const char * file, int line, const char * func, void * p )
{
    return _framework->_server->debug_free(file, line, func, p);
}
bool framework_t::get_port(
    int         port_index,
    int *       port,
    bool *      is_tcp,
    bool *      is_local,
    int *       fd,
    in_addr *   ip
)
{
    gr_server_t *       server;
    gr_port_item_t *    pi;
    server = get_interface();
    if ( NULL == server || port_index < 0 || port_index >= server->ports_count ) {
        if ( port ) * port = 0;
        if ( is_tcp ) * is_tcp = false;
        if ( is_local ) * is_local = false;
        if ( ip ) ip->s_addr = 0;
        if ( fd ) * fd = -1;
        return false;
    }
    pi = & server->ports[ port_index ];
    if ( port ) * port = pi->port;
    if ( is_tcp ) * is_tcp = pi->is_tcp;
    if ( is_local ) * is_local = pi->is_local;
    if ( fd ) * fd = pi->fd;
    if ( ip ) {
        if ( pi->addr_len == (socklen_t)sizeof( sockaddr_in ) ) {
            ip->s_addr = pi->addr4.sin_addr.s_addr;
        } else {
            ip->s_addr = 0;
        }
    }
    return true;
}

gr_server_t * framework_t::get_interface()
{
    return _framework->_framework;
}

bool framework_t::worker_is_process() const
{
    return _framework->_framework->is_process_worker;
}

int framework_t::worker_count() const
{
    return _framework->_framework->worker_count;
}

void * framework_t::alloc_response(proc_binary_ctxt_t & ctxt, int bytes)
{
    assert(bytes > 0);
    gr_proc_ctxt_t * pc = (gr_proc_ctxt_t *)ctxt._framework;
    void* p = _framework->_server->set_max_response(pc, bytes);
    if (NULL != p)
    {
        pc->result_buf_len = bytes;
    }
    return p;
}
void framework_t::gr_need_exit()
{
    return _framework->_server->gr_need_exit();
}
int framework_t::get_worker_count() const
{
    return _framework->_framework->worker_count;
}
bool framework_t::config_get_bool(const char * section, const char * name, bool default_value)
{
    return _framework->_server->config_get_bool(section, name, default_value);
}
int framework_t::config_get_int(const char * section, const char * name, int default_value)
{
    return _framework->_server->config_get_int(section, name, default_value);
}
const char * framework_t::config_get_string(const char * section, const char * name, const char * default_value)
{
    return _framework->_server->config_get_string(section, name, default_value);
}
bool framework_t::config_get_addr(const char * section, const char * name, sockaddr_in & addr)
{
    const char * s = config_get_string(section, name, NULL);
    if ( unlikely( NULL == s || '\0' == * s ) ) {
        memset( & addr, 0, sizeof( sockaddr_in ) );
        return false;
    }
    if ( unlikely( ! socket_str_2_addr_v4( s, & addr ) ) ) {
        memset( & addr, 0, sizeof( sockaddr_in ) );
        return false;
    }
    return true;
}
void framework_t::log_va_list(const char * file, int line, const char * func, gr_log_level_t level, va_list valist, const char **  fmt )
{
    _framework->_server->log_va_list(file, line, func, level, valist, fmt );
}
void framework_t::log_error_inner(const char * file, int line, const char * func, const char * fmt, ... )
{
    va_list va;
    va_start( va, fmt );
    _framework->_server->log_va_list(file, line, func, GR_LOG_ERROR, va, & fmt );
    va_end ( va );
}
void framework_t::log_info_inner(const char * file, int line, const char * func, const char * fmt, ... )
{
    va_list va;
    va_start( va, fmt );
    _framework->_server->log_va_list(file, line, func, GR_LOG_INFO, va, & fmt );
    va_end ( va );
}
void framework_t::log_debug_inner(const char * file, int line, const char * func, const char * fmt, ... )
{
    va_list va;
    va_start( va, fmt );
    _framework->_server->log_va_list(file, line, func, GR_LOG_DEBUG, va, & fmt );
    va_end ( va );
}
bool framework_t::start_listen_tcp()
{
    return _framework->_server->start_listen_tcp();
}
bool framework_t::kick_tcp(int fd)
{
    return _framework->_server->kick_tcp(fd);
}
http_pair_t * framework_t::http_get_query_string(gr_http_ctxt_t * http, size_t & count)
{
    count = http->params_count;
    return (http_pair_t *)http->params;
}
http_pair_t * framework_t::http_get_form(gr_http_ctxt_t * http, size_t & count)
{
    count = http->form_count;
    return (http_pair_t *)http->form;
}
const char * framework_t::http_get_body(gr_http_ctxt_t * http, size_t & body_len)
{
    body_len = http->body_len;
    return http->body;
}
int framework_t::http_get_worker_id( gr_http_ctxt_t * http ) const
{
    return http->hc_worker_id;
}
void * framework_t::http_set_max_response(gr_http_ctxt_t *http, size_t bytes)
{
    return _framework->_server->http_set_max_response(http, bytes);
}
const char * framework_t::http_get_req(gr_http_ctxt_t * http, const char * name, size_t * value_len)
{
    return _framework->_server->http_get_req(http, name, value_len);
}
int framework_t::http_get_req_int(gr_http_ctxt_t * http, const char * name, int default_value)
{
    return _framework->_server->http_get_req_int(http, name, default_value);
}
long long framework_t::http_get_req_int64(gr_http_ctxt_t * http, const char * name, long long default_value)
{
    return _framework->_server->http_get_req_int64(http, name, default_value);
}
bool framework_t::http_get_req_bool(gr_http_ctxt_t * http, const char * name, bool default_value)
{
    return _framework->_server->http_get_req_bool(http, name, default_value);
}
const char * framework_t::http_get_header(gr_http_ctxt_t * http, const char * name)
{
    return _framework->_server->http_get_header(http, name);
}
bool framework_t::http_append(gr_http_ctxt_t * http, const void * data, size_t len)
{
    return _framework->_server->http_append(http, data, len);
}
bool framework_t::http_send( gr_http_ctxt_t * http, const void * data, size_t len, const char * content_type)
{
    return _framework->_server->http_send(http, data, len, content_type);
}
bool framework_t::http_send_gzip( gr_http_ctxt_t * http, const void * data, size_t len, const char * content_type)
{
    return _framework->_server->http_send_gzip(http, data, len, content_type);
}
bool framework_t::http_send_header(gr_http_ctxt_t * http, size_t content_length, const char * content_type)
{
    return _framework->_server->http_send_header(http, content_length, content_type);
}
bool framework_t::http_send_header2(gr_http_ctxt_t * http, size_t content_length, const char * content_type, const char * connection, const char * status, const char * additional_headers)
{
    return _framework->_server->http_send_header2(http, content_length, content_type, connection, status, additional_headers);
}
bool framework_t::http_send_auth_failed( gr_http_ctxt_t * http, const char * tip, size_t tip_len )
{
    return _framework->_server->http_send_auth_failed(http, tip, tip_len);
}
bool framework_t::http_auth( gr_http_ctxt_t * http,
                             bool ( * auth_func )( void * param, const char * user, const char * passwd ),
                             void *           auth_func_param )
{
    return _framework->_server->http_auth(http, auth_func, auth_func_param);
}
int framework_t::getpeername( gr_proc_ctxt_t * ctxt, struct sockaddr * addr, socklen_t * addr_len )
{
    return _framework->_server->getpeername(ctxt, addr, addr_len);
}
int framework_t::getpeername( gr_proc_ctxt_t * ctxt, struct sockaddr_in & addr )
{
    socklen_t addr_len = (socklen_t)sizeof( sockaddr_in );
    int r = _framework->_server->getpeername(ctxt, (sockaddr *)& addr, & addr_len);
    if ( 0 != r || addr_len != (socklen_t)sizeof( sockaddr_in ) ) {
        memset( & addr, 0, sizeof( sockaddr_in ) );
        if ( 0 == r ) { r = - EINVAL; }
    }
    return r;
}
int framework_t::http_getpeername( gr_http_ctxt_t * http, struct sockaddr * addr, socklen_t * addr_len )
{
    return _framework->_server->http_getpeername(http, addr, addr_len);
}
int framework_t::http_getpeername( gr_http_ctxt_t * http, struct sockaddr_in & addr )
{
    socklen_t addr_len = (socklen_t)sizeof( sockaddr_in );
    int r = _framework->_server->http_getpeername(http, (sockaddr *)& addr, & addr_len);
    if ( 0 != r || addr_len != (socklen_t)sizeof( sockaddr_in ) ) {
        memset( & addr, 0, sizeof( sockaddr_in ) );
        if ( 0 == r ) { r = - EINVAL; }
    }
    return r;
}
bool framework_t::is_server_stopping() const
{
    return _framework->_framework->is_server_stopping;
}
int framework_t::get_errno()
{
    return _framework->_server->get_errno();
}
size_t framework_t::get_exe_path(
    char * path,
    size_t  path_len
)
{
    return _framework->_server->get_exe_path( path, path_len );
}
size_t framework_t::get_exe_dir(
    char *  dir,
    size_t  dir_len,
    bool    add_sep
)
{
    return _framework->_server->get_exe_dir( dir, dir_len, add_sep );
}
void framework_t::path_to_os(
    char * path
)
{
    return _framework->_server->path_to_os(path);
}
bool framework_t::path_to_os( const char * path, std::string & result )
{
    result.resize( 0 );
    if ( unlikely( NULL == path || '\0' == * path ) ) {
        return false;
    }
    size_t path_len = strlen( path );
    if ( unlikely( path_len >= MAX_PATH ) ) {
        // path too long
        return false;
    }
    try {
        result.resize( path_len );
    } catch ( ... ) {
        return false;
    }
    memcpy( (char *)result.c_str(), path, path_len );
    path_to_os( (char *)result.c_str() );
    return true;
}
void framework_t::sleep_ms(
    uint32_t ms
)
{
    return _framework->_server->sleep_ms(ms);
}
bool framework_t::is_dir(
    const char * path
)
{
    return _framework->_server->is_dir(path);
}
bool framework_t::is_file(
    const char * path
)
{
    return _framework->_server->is_file(path);
}
unsigned long framework_t::get_tick_count()
{
    return _framework->_server->get_tick_count();
}
bool framework_t::make_dir(const char * dir)
{
    return _framework->_server->make_dir(dir);
}
atomic_t framework_t::atomic_fetch_add( int v, atomic_t * dst )
{
    return _framework->_server->atomic_fetch_add(v, dst);
}
dll_t framework_t::dll_open( const char * path )
{
    return _framework->_server->dll_open(path);
}
dll_t framework_t::dll_open_absolute( const char * path )
{
    return _framework->_server->dll_open_absolute(path);
}
/**
    * @brief close a dynamic library
    * @param[in] dll_t: dynamic library handle
    */
void framework_t::dll_close( dll_t h )
{
    return _framework->_server->dll_close(h);
}
/**
  * @brief query a function, that export function
  * @param[in] dll_t: dynamic library handle
  * @param[in] const char * func_name: function name 
  */
void * framework_t::dll_symbol( dll_t h, const char * func_name )
{
    return _framework->_server->dll_symbol(h, func_name);
}
bool framework_t::event_create( event_t * o )
{
    return _framework->_server->event_create(o);
}
void framework_t::event_destroy( event_t * o )
{
    return _framework->_server->event_destroy(o);
}
bool framework_t::event_alarm( event_t * o )
{
    return _framework->_server->event_alarm(o);
}
/**
    * @brief block current thread, wait for a event
    * @param[in] event_t * o point to event object instance
    * @param[in] unsigned int ms wait timeout by ms.
    *            ms>0, then wait max ms
    *            ms is INFINITE, then always wait if no event alarm
    * @return int 1: event alarm;
    *             0: timeout
    *             -1: error
    *             -2: EINTR
    */
int framework_t::event_wait( event_t * o, unsigned int ms )
{
    return _framework->_server->event_wait(o, ms);
}
bool framework_t::get_user_name( char * user_name, int * user_name_len )
{
    return _framework->_server->get_user_name(user_name, user_name_len);
}
void framework_t::md5_init( MD5_CTX * ctx )
{
    return _framework->_server->md5_init(ctx);
}
void framework_t::md5_update( MD5_CTX * ctx, const unsigned char * buf, unsigned int len )
{
    return _framework->_server->md5_update(ctx, buf, len);
}
void framework_t::md5_final( MD5_CTX * ctx, unsigned char * digest )
{
    return _framework->_server->md5_final(ctx, digest);
}
int framework_t::processor_count()
{
    return _framework->_server->processor_count();
}
bool framework_t::process_kill( proc_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->process_kill( self );
}
bool framework_t::process_kill_tree(
    pid_t       pid,
    int *       kill_count,
    int *       fail_count,
    int         max_sub_process
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->process_kill_tree( pid, kill_count, fail_count, max_sub_process );
}
bool framework_t::pipe_create(
    int             fds[ 2 ]
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->pipe_create( fds );
}
void framework_t::pipe_destroy(
    int             fds[ 2 ]
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_parallel->pipe_destroy( fds );
}
int framework_t::pipe_read(
    int             fds[ 2 ],
    void *          buf,
    int             len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->pipe_read( fds, buf, len );
}
int framework_t::pipe_write(
    int             fds[ 2 ],
    const void *    data,
    int             len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->pipe_write( fds, data, len );
}
int framework_t::pipe_read_fd(
    int             fds[ 2 ],
    int *           fd,
    void *          buf,
    int             len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_parallel->pipe_read_fd( fds, fd, buf, len );
}
int framework_t::pipe_write_fd(
    int             fds[ 2 ],
    int             fd,
    const void *    data,
    int             len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_parallel->pipe_write_fd( fds, fd, data, len );
}
int framework_t::pipe_wait_for_read(
    int             fds[ 2 ],
    unsigned int    ms
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_parallel->pipe_wait_for_read( fds, ms );
}
int framework_t::write_http_to_pipe(
    int                 fds[ 2 ],
    gr_http_ctxt_t *    http
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->write_http_to_pipe( fds, http );
}
int framework_t::read_http_from_pipe(
    int                 fds[ 2 ],
    pipe_http_t **      result
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->read_http_from_pipe( fds, result );
}
pid_t framework_t::process_get_pid( proc_t * proc )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->process_get_pid( proc );
}
bool framework_t::process_is_running( proc_t * proc )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->process_is_running( proc );
}
bool framework_t::process_fork(
    proc_t *       process,
    void *         (*start_routine)(void*),
    void *         arg
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->process_fork( process, start_routine, arg );
}
bool framework_t::process_exec( proc_t * self, const char * cmdline, bool is_hide )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->process_exec( self, cmdline, is_hide );
}
bool framework_t::cgi_process_exec(
    proc_t *        process,
    const char *    cmdline,
    bool            is_hide
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->cgi_process_exec( process, cmdline, is_hide );
}
bool framework_t::cgi_process_fork(
    proc_t *       process,
    void *         (*start_routine)(void*),
    void *         arg,
    bool           redirect_stdout
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->cgi_process_fork( process, start_routine, arg, redirect_stdout );
}
fast_poll_t *
framework_t::fast_poll_create(
    int                     concurrent
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_parallel->fast_poll_create( concurrent );
}
void
framework_t::fast_poll_destroy(
    fast_poll_t *               poll
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_parallel->fast_poll_destroy( poll );
}
bool
framework_t::fast_poll_set(
    fast_poll_t *               poll,
    int                         fd,
    const fast_poll_event_t *   data
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->fast_poll_set( poll, fd, data );
}
bool
framework_t::fast_poll_del(
    fast_poll_t *               poll,
    int                         fd
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->fast_poll_del( poll, fd );
}
int
framework_t::fast_poll_wait(
    fast_poll_t *               poll,
    fast_poll_event_t *         events,
    int                         event_count,
    int                         timeout_ms
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->fast_poll_wait( poll, events, event_count, timeout_ms );
}
int
framework_t::fast_poll_connect(
    fast_poll_t *               poll,
    int                         fd,
    const fast_poll_event_t *   data,
    const struct sockaddr *     addr,
    socklen_t                   addr_len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->fast_poll_connect( poll, fd, data, addr, addr_len );
}
void framework_t::os_thread_init( os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_parallel->os_thread_init( self );
}
bool framework_t::os_thread_is_started( const os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->os_thread_is_started( self );
}
bool framework_t::os_thread_is_need_exit( const os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return true;
    }
    return _framework->_parallel->os_thread_is_need_exit( self );
}
bool framework_t::os_thread_is_exited( const os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return true;
    }
    return _framework->_parallel->os_thread_is_exited( self );
}
int framework_t::os_thread_tid( const os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_parallel->os_thread_tid( self );
}
bool framework_t::os_thread_start(
    os_thread_t *  self,
    void *      (*start_routine)(void*),
    void *      param
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_parallel->os_thread_start( self, start_routine, param );
}
void framework_t::os_thread_stop( os_thread_t * self )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_parallel->os_thread_stop( self );
}
void framework_t::process_init( proc_t * proc )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_parallel->process_init( proc );
}
tcp_connector_t * framework_t::tcp_connector_create(
    const tcp_connector_param_t * param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->tcp_connector_create( param );
}
void framework_t::tcp_connector_destroy(
    tcp_connector_t *   self
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_network->tcp_connector_destroy( self );
}
bool framework_t::tcp_connector_add(
    tcp_connector_t *       self,
    int                     fd,
    const struct sockaddr * addr,
    int                     addr_len,
    int                     timeout_ms,
    tcp_connector_result_t  callback,
    void *                  callback_param1,
    void *                  callback_param2
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->tcp_connector_add( self, fd, addr, addr_len, timeout_ms, callback, callback_param1, callback_param2 );
}
bool framework_t::tcp_connector_del(
    tcp_connector_t *       self,
    int                     fd
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->tcp_connector_del( self, fd );
}
tcp_sender_t * framework_t::tcp_sender_create(
    const tcp_sender_param_t * param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->tcp_sender_create( param );
}
void framework_t::tcp_sender_destroy(
    tcp_sender_t *      self
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_network->tcp_sender_destroy( self );
}
int framework_t::tcp_sender_send(
    tcp_sender_t *      self,
    int                 fd,
    void *              data,
    int                 data_len,
    void *              user_pointer
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_network->tcp_sender_send( self, fd, data, data_len, user_pointer );
}
int framework_t::tcp_sender_send_http_rsp(
    tcp_sender_t *              self,
    int                         fd,
    void *                      data,
    int                         data_len,
    void *                      user_data,
    const tcp_sender_http_t *   param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    return _framework->_network->tcp_sender_send_http_rsp( self, fd, data, data_len, user_data, param );
}
void framework_t::tcp_sender_del(
    tcp_sender_t *      self,
    int                 fd
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_network->tcp_sender_del( self, fd );
}
int  framework_t::socket_create_tcp_v4()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_create_tcp_v4();
}
int  framework_t::socket_create_udp_v4()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_create_udp_v4();
}
int  framework_t::socket_close(
    int sock
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_close( sock );
}
bool framework_t::socket_get_tcp_no_delay(
    int sock,
    bool * isNoDelay
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_get_tcp_no_delay( sock, isNoDelay );
}
bool framework_t::socket_set_tcp_no_delay(
    int sock,
    bool isNoDelay
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_tcp_no_delay( sock, isNoDelay );
}
bool framework_t::socket_set_keep_alive(
    int sock,
    bool isKeepAlive
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_keep_alive( sock, isKeepAlive );
}
bool framework_t::socket_get_send_buf(
    int sock,
    int * bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_get_send_buf( sock, bytes );
}
bool framework_t::socket_set_send_buf(
    int sock,
    int bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_send_buf( sock, bytes );
}
bool framework_t::socket_get_recv_buf(
    int sock,
    int * bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_get_recv_buf( sock, bytes );
}
bool framework_t::socket_set_recv_buf(
    int sock,
    int bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_recv_buf( sock, bytes );
}
bool framework_t::socket_set_ttl(
    int sock,
    int ttl
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_ttl( sock, ttl );
}
bool framework_t::socket_set_loopback(
    int sock,
    bool enable
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_loopback( sock, enable );
}
bool framework_t::socket_get_linger(
    int sock,
    uint16_t * lv
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_get_linger( sock, lv );
}
bool framework_t::socket_set_linger(
    int sock,
    uint16_t linger
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_linger( sock, linger );
}
bool framework_t::socket_is_pending()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_is_pending();
}
int  framework_t::socket_recv(
    int sock,
    void * buf,
    int bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_recv( sock, buf, bytes );
}
int  framework_t::socket_send(
    int sock,
    const void * buf,
    int bytes
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_send( sock, buf, bytes );
}
bool framework_t::socket_recv_fill(
    int sock,
    void * buf,
    int bytes,
    size_t timeout_ms,
    bool * is_timeout
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_recv_fill( sock, buf, bytes, timeout_ms, is_timeout );
}
bool framework_t::socket_send_all(
    int sock,
    const void * buf,
    int bytes,
    bool is_async_socket,
    size_t timeout_ms
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_send_all( sock, buf, bytes, is_async_socket, timeout_ms );
}
bool framework_t::socket_addr_v4(
    const char * host,
    int port,
    struct sockaddr_in * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_addr_v4( host, port, addr );
}
bool framework_t::socket_str_2_addr_v4(
    const char * str,
    struct sockaddr_in * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_str_2_addr_v4( str, addr );
}
int  framework_t::socket_addr_cmp(
    const struct sockaddr * left,
    const struct sockaddr * right,
    int len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_addr_cmp( left, right, len );
}
int  framework_t::socket_addr_cmp_ip(
    const struct sockaddr * left,
    const struct sockaddr * right,
    int len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_addr_cmp_ip( left, right, len );
}
bool framework_t::socket_in_progress()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_in_progress();
}
bool framework_t::socket_would_block()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_would_block();
}
bool framework_t::socket_set_block( int fd, bool is_block )
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->socket_set_block( fd, is_block );
}
int framework_t::get_ip_type( struct in_addr ip )
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return IPTYPE_BAD;
    }
    errno = 0;
    return _framework->_network->get_ip_type( ip );
}
bool framework_t::socket_get_all_ip( struct in_addr * addrs, size_t * count )
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( count ) { * count = 0; }
        return false;
    }
    errno = 0;
    return _framework->_network->socket_get_all_ip( addrs, count );
}
int framework_t::socketpair(int d, int type, int protocol, int fds[2])
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_network->socketpair( d, type, protocol, fds );
}

bool framework_t::to_array(
    char *          src,
    const char *    sep,
    char **         result,
    int *           result_count
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->to_array( src, sep, result, result_count );
}
bool framework_t::to_const_array(
    const char *    src,
    int             src_len,
    const char *    sep,
    int             sep_len,
    const_str_t *   result,
    int *           result_count
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->to_const_array( src, src_len, sep, sep_len, result, result_count );
}
bool framework_t::to_pair_array(
    const char *    src,
    int             src_len,
    const char *    row_sep,
    int             row_sep_len,
    const char *    col_sep,
    int             col_sep_len,
    const_pair *    result,
    int *           result_count
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->to_pair_array( src, src_len, row_sep, row_sep_len, col_sep, col_sep_len, result, result_count );
}
bool framework_t::del_dir( const char * dir )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->del_dir( dir );
}
bool framework_t::del_file( const char * path )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->del_file( path );
}
DIR * framework_t::opendir( const char* filespec )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->opendir( filespec );
}
struct dirent * framework_t::readdir( DIR* dir )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->readdir( dir );
}
int framework_t::closedir( DIR* dir )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->closedir( dir );
}
int64_t framework_t::get_file_size( const char * path )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (int64_t)-1;
    }
    return _framework->_tool->get_file_size( path );
}
int framework_t::place_id_to_city_code( int place_id, int * result, size_t result_max )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_tool->place_id_to_city_code( place_id, result, result_max );
}
int framework_t::get_mobile_provider( const char * str, size_t str_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->get_mobile_provider( str, str_len );
}
int framework_t::get_mobile_provider2( const char * str, size_t str_len, int * small_id )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( small_id ) * small_id = 0;
        return 0;
    }
    return _framework->_tool->get_mobile_provider2( str, str_len, small_id );
}
int framework_t::get_mobile_place(
    const char *                str,
    size_t                      str_len,
    int *                       provider,
    cn_place_name_item_t **     place,
    int                         place_max
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->get_mobile_place( str, str_len, provider, place, place_max );
}
bool framework_t::load_file( const char * path, std::string & result )
{
    return ::load_file( path, result );
}
bool framework_t::to_vector(
    const std::string & src,
    const std::string & sep,
    std::vector< std::string > & result
)
{
    return ::to_vector( src, sep, result );
}
int framework_t::stdstr_replace( std::string & s, const char * lpszOld, const char * lpszNew )
{
    return ::stdstr_replace( s, lpszOld, lpszNew );
}
bool framework_t::http_is_peer_local( gr_http_ctxt_t * http )
{
    sockaddr_in addr;
    int         r;
    socklen_t   addr_len = (socklen_t)sizeof( sockaddr_in );
    r = http_getpeername( http, (sockaddr *)&addr, & addr_len );
    if ( 0 != r || addr_len != (socklen_t)sizeof( addr ) ) {
        return false;
    }
    uint32_t ipv4 = addr.sin_addr.s_addr;
    byte_t * p = (byte_t *)& ipv4;
    if ( 127 == p[ 0 ] && 0 == p[ 1 ] && 0 == p[ 2 ] && 1 == p[ 3 ] ) {
        return true;
    }
    return false;
}
static size_t http_stdstr_cb(
    const void *        data,
    size_t              always_1,
    size_t              data_bytes,
    void *              param
)
{
    std::string & s = * ((std::string *)param);
    s.append( (const char *)data, ((const char *)data) + data_bytes );
    return data_bytes;
}
bool framework_t::http_stdstr(
    const char *        url,
    const char *        refer,
    int                 connect_timeout_second,
    int                 recv_timeout_second,
    unsigned int        flags,
    const char *        http_method,
    std::string &       result,
    int *               http_code
)
{
    http_t *    http = NULL;
    bool        b = false;
    result.resize( 0 );
    if ( http_code ) {
        * http_code = 0;
    }
    do {
        http = http_create();
        if ( NULL == http ) {
            log_error( "http_create failed" );
            break;
        }
        if ( connect_timeout_second > 0 && recv_timeout_second > 0 ) {
            if ( ! http_set_timeout( http, connect_timeout_second, recv_timeout_second ) ) {
                log_error( "http_set_timeout failed" );
                break;
            }
        }
        if ( ! http_set_url( http, url, refer ) ) {
            log_error( "http_set_url failed" );
            break;
        }
        if ( ! http_set_callback( http, http_stdstr_cb, & result, NULL, NULL ) ) {
            log_error( "http_set_callback failed" );
            break;
        }
        if ( ! http_perform( http, flags, http_method, http_code ) ) {
            log_error( "http_perform failed" );
            break;
        }
        b = true;
    } while ( 0 );
    if ( http ) {
        http_destroy( http );
    }
    if ( ! b ) {
        result.resize( 0 );
    }
    return b;
}
http_t * framework_t::http_create()
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->http_create();
}
bool framework_t::http_set_timeout(
    http_t *            http,
    int                 connect_timeout_second,
    int                 recv_timeout_second
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_set_timeout(http, connect_timeout_second, recv_timeout_second);
}
bool framework_t::http_set_callback(
    http_t *                http,
    http_data_callback_t    content_callback,
    void *                  content_callback_param,
    http_data_callback_t    header_callback,
    void *                  header_callback_param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_set_callback(http, content_callback, content_callback_param, header_callback, header_callback_param);
}
bool framework_t::http_set_base_security(
    http_t *            http,
    const char *        user,
    const char *        passwd
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_set_base_security(http, user, passwd);
}
bool framework_t::http_set_url(
    http_t *            http,
    const char *        url,
    const char *        refer
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_set_url(http, url, refer);
}
bool framework_t::http_set_postfields(
    http_t *            http,
    const char *        fields,
    size_t              fields_bytes,
    const char *        content_type
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_set_postfields(http, fields, fields_bytes, content_type);
}
bool framework_t::http_add_multi_post(
    http_t *            http,
    const char *        name,
    const char *        file
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_add_multi_post(http, name, file);
}
void framework_t::http_reset_request(
    http_t *    http
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_network->http_reset_request(http);
}
bool framework_t::http_perform(
    http_t *            http,
    unsigned int        flags,
    const char *        http_method,
    int *               http_code
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_perform(http, flags, http_method, http_code);
}
void framework_t::http_destroy(
    http_t *            http
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_network->http_destroy(http);
}
gr_package_type_t framework_t::http_check_type(
    const void *    p,
    int             len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return GR_PACKAGE_ERROR;
    }
    return _framework->_network->http_check_type(p, len);
}
bool framework_t::http_check_full(
    const char *    buf,
    int             len,
    bool            is_http_reply,
    bool *          is_error,
    int *           header_offset,
    int *           body_offset,
    int64_t *       content_length
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->http_check_full(buf, len, is_http_reply, is_error, header_offset, body_offset, content_length);
}
gr_http_ctxt_t * framework_t::http_build_req(
    int                 rsp_fd,
    const char *        buf,
    int                 len,
    bool                is_http_reply,
    http_parse_ctxt_t * parse_ctxt,
    int                 header_offset,
    int                 body_offset,
    int64_t             content_length
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->http_build_req(rsp_fd, buf, len, is_http_reply, parse_ctxt, header_offset, body_offset, content_length);
}
int framework_t::url_decode(
    char *          s,
    int             s_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->url_decode(s, s_len);
}
bool framework_t::url_encode(
    const char *    src,
    int             src_len,
    char *          dst,
    int *           dst_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->url_encode(src, src_len, dst, dst_len);
}
bool framework_t::url_encode_all(
    const char *    src,
    int             src_len,
    char *          dst,
    int *           dst_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->url_encode_all(src, src_len, dst, dst_len);
}
bool framework_t::url_encode(
    const char *    src,
    int             src_len,
    std::string &   dst
)
{
    dst.resize( 0 );
    if ( NULL == src || src_len <= 0 ) {
        return true;
    }
    int dst_len = src_len * 3 + 1;
    try {
        dst.resize( dst_len );
    } catch ( ... ) {
        dst.resize( 0 );
        return false;
    }
    if ( ! url_encode( src, src_len, & dst[ 0 ], & dst_len ) ) {
        dst.resize( 0 );
        return false;
    }
    dst.resize( dst_len );
    return true;
}
bool framework_t::url_encode_all(
    const char *    src,
    int             src_len,
    std::string &   dst
)
{
    dst.resize( 0 );
    if ( NULL == src || src_len <= 0 ) {
        return true;
    }
    int dst_len = src_len * 3 + 1;
    try {
        dst.resize( dst_len );
    } catch ( ... ) {
        dst.resize( 0 );
        return false;
    }
    if ( ! url_encode_all( src, src_len, & dst[ 0 ], & dst_len ) ) {
        dst.resize( 0 );
        return false;
    }
    dst.resize( dst_len );
    return true;
}
bool framework_t::parse_url(
    const char *        url,
    int                 url_len,
    url_infomation_t *  url_info,
    int                 url_info_bytes,
    int *               query_string_count
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->parse_url(url, url_len, url_info, url_info_bytes, query_string_count);
}
int framework_t::url_normalize(
    const char *    url,
    int             url_len,
    char *          dest,
    int             dest_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->url_normalize(url, url_len, dest, dest_len);
}
bool framework_t::is_url_valid(
    const char *    url,
    int             url_len,
    bool            english_domain_only
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->is_url_valid(url, url_len, english_domain_only);
}
bool framework_t::is_part_url_valid(
    const char *    url,
    int             url_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->is_part_url_valid(url, url_len);
}
bool framework_t::format_url(
    const char *    url,
    int             url_len,
    const char *    base_url,
    int             base_url_len,
    char *          dest,
    int *           dest_len,
    bool            delete_anchor
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->format_url2(url, url_len, base_url, base_url_len, dest, dest_len, delete_anchor);
}
void framework_t::cookie_parse(
    const char *        cookie,
    int                 cookie_len,
    url_pair_t *        result,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_string->cookie_parse(cookie, cookie_len, result, result_len);
}
int framework_t::parse_base_url(
    const char *        page_html,
    int                 page_html_len,
    char *              base_url,
    int                 base_url_max
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parse_base_url(page_html, page_html_len, base_url, base_url_max);
}
int framework_t::parse_urls(
    const char *                page_html,
    int                         page_html_len,
    char *                      base_url,
    int                         base_url_max,
    int *                       pbase_url_len,
    parse_urls_callback_t       callback,
    void *                      callback_param
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_string->parse_urls(page_html, page_html_len, base_url, base_url_max, pbase_url_len, callback, callback_param);
}
snappy_status_t framework_t::snappy_compress(
    const void *        input,
    size_t              input_length,
    void *              compressed,
    size_t *            compressed_length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return SNAPPY_INVALID_INPUT;
    }
    return _framework->_string->snappy_compress(input, input_length, compressed, compressed_length);
}
snappy_status_t framework_t::snappy_uncompress(
    const void *    compressed,
    size_t          compressed_length,
    void *          uncompressed,
    size_t *        uncompressed_length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return SNAPPY_INVALID_INPUT;
    }
    return _framework->_string->snappy_uncompress(compressed, compressed_length, uncompressed, uncompressed_length);
}
size_t framework_t::snappy_max_compressed_length(
    size_t          source_length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->snappy_max_compressed_length(source_length);
}
snappy_status_t framework_t::snappy_uncompressed_length(
    const void *    compressed,
    size_t          compressed_length,
    size_t *        result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return SNAPPY_INVALID_INPUT;
    }
    return _framework->_string->snappy_uncompressed_length(compressed, compressed_length, result);
}
snappy_status_t framework_t::snappy_validate_compressed_buffer(
    const void *    compressed,
    size_t          compressed_length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return SNAPPY_INVALID_INPUT;
    }
    return _framework->_string->snappy_validate_compressed_buffer(compressed, compressed_length);
}
int framework_t::zlib_compress(
    void *          dest,
    size_t *        dest_len,
    const void *    source,
    size_t          source_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return Z_ERRNO;
    }
    return _framework->_string->zlib_compress(dest, dest_len, source, source_len);
}
int framework_t::zlib_compress2(
    void *          dest,
    size_t *        destLen,
    const void *    source,
    size_t          source_len,
    int             level
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return Z_ERRNO;
    }
    return _framework->_string->zlib_compress2(dest, destLen, source, source_len, level);
}
size_t framework_t::zlib_compress_bound(
    size_t          source_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return Z_ERRNO;
    }
    return _framework->_string->zlib_compress_bound(source_len);
}
int framework_t::zlib_uncompress(
    void *          dest,
    size_t *        dest_len,
    const void *    source,
    size_t          source_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return Z_ERRNO;
    }
    return _framework->_string->zlib_uncompress(dest, dest_len, source, source_len);
}
unsigned long framework_t::crc32(
    unsigned long  crc,
    const void *   buf,
    size_t         len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->crc32(crc, buf, len);
}
int framework_t::html_extract_content(
    const char *                    html,
    int                             html_len,
    const html_extract_param_t *    param
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->html_extract_content(html, html_len, param);
}
const char * framework_t::charset_id2str(
    int             charset_id
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return "";
    }
    return _framework->_string->charset_id2str(charset_id);
}
int framework_t::charset_str2id(
    const char *   charset
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return CHARSET_UNKNOWN;
    }
    return _framework->_string->charset_str2id(charset);
}
int framework_t::charset_check(
    const void *    str,
    int             str_bytes
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return CHARSET_UNKNOWN;
    }
    return _framework->_string->charset_check(str, str_bytes);
}
int framework_t::charset_utf8_bytes(
    const char      c
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->charset_utf8_bytes(c);
}
int framework_t::charset_convert(
    int             src_type,
    const void *    src,
    int             src_bytes,
    int             dst_type,
    void *          dst,
    int *           dst_bytes
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->charset_convert(src_type, src, src_bytes, dst_type, dst, dst_bytes);
}
int framework_t::charset_convert(
    int                 src_type,
    const void *        src,
    int                 src_bytes,
    int                 dst_type,
    std::string &       dst
)
{
    dst.resize( 0 );
    try {
        dst.resize( src_bytes * 3 + 1 );
    } catch ( ... ) {
        dst.resize( 0 );
        return - ENOMEM;
    }
    int dst_bytes = (int)dst.size();
    int r = charset_convert( src_type, src, (int)src_bytes, dst_type, (char *)dst.c_str(), & dst_bytes );
    dst.resize( dst_bytes );
    return r;
}
int framework_t::charset_convert(
    int                 src_type,
    const std::string & src,
    int                 dst_type,
    std::string &       dst
)
{
    dst.resize( 0 );
    try {
        dst.resize( src.size() * 3 + 1 );
    } catch ( ... ) {
        dst.resize( 0 );
        return - ENOMEM;
    }
    int dst_bytes = (int)dst.size();
    int r = charset_convert( src_type, src.c_str(), (int)src.size(), dst_type, (char *)dst.c_str(), & dst_bytes );
    dst.resize( dst_bytes );
    return r;
}
fingerprint_t * framework_t::fingerprint_open(
    const char *            path
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_string->fingerprint_open(path);
}
void framework_t::fingerprint_close(
    fingerprint_t *         self
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_string->fingerprint_close(self);
}
int framework_t::fingerprint_html(
    fingerprint_t *         self,
    const char *            html,
    int                     html_len,
    int                     to_charset,
    int                     debug_level,
    fingerdata_t *          result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->fingerprint_html(self, html, html_len, to_charset, debug_level, result);
}
int framework_t::fingerprint_html_file(
    fingerprint_t *         self,
    const char *            html_path,
    int                     to_charset,
    int                     debug_level,
    fingerdata_t *          result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->fingerprint_html_file(self, html_path, to_charset, debug_level, result);
}
int framework_t::fingerprint_similar_percent(
    fingerprint_t *         self,
    int                     charset,
    const fingerdata_t *    left,
    const fingerdata_t *    right
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->fingerprint_similar_percent(self, charset, left, right);
}
int framework_t::fingerprint_keywords(
    fingerprint_t *                 self,
    int                             charset,
    const fingerdata_t *            finger,
    fingerprint_keywords_callback_t callback,
    void *                          callback_param
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->fingerprint_keywords(self, charset, finger, callback, callback_param);
}
const void * framework_t::memrchr( const void *s, int c, size_t n )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_string->memrchr(s, c, n);
}
const char * framework_t::memistr( const void * s, int s_len, const void * find, int find_len )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_string->memistr(s, s_len, find, find_len);
}
const char * framework_t::memstr( const void * s, int s_len, const void * find, int find_len )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_string->memstr(s, s_len, find, find_len);
}
int framework_t::merge_multi_space(
    char *  str,
    int     str_len,
    bool    add_0
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->merge_multi_space(str, str_len, add_0);
}
int framework_t::merge_multi_chars(
    char *          str,
    int             str_len,
    const char *    from_chars,
    int             from_chars_len,
    char            to_char,
    bool            add_0
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->merge_multi_chars(str, str_len, from_chars, from_chars_len, to_char, add_0);
}
int framework_t::regex_match(
    const char *                text,
    int                         text_len,
    const char *                regex,
    int                         regex_len,
    regex_match_item_t *        result,
    int                         result_max
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_string->regex_match(text, text_len, regex, regex_len, result, result_max);
}
int framework_t::regex_match_all(
    const char *                text,
    int                         text_len,
    const char *                regex,
    int                         regex_len,
    regex_match_item_t *        result,
    int                         result_max
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->regex_match_all(text, text_len, regex, regex_len, result, result_max);
}
bool framework_t::base64_encode(
    const void *    input,
    int             input_len,
    int             crlf_len,
    char *          output,
    int *           output_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->base64_encode(input, input_len, crlf_len, output, output_len);
}
bool framework_t::base64_decode(
    const char *    input,
    int             input_len,
    void *          output,
    int *           output_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->base64_decode(input, input_len, output, output_len);
}
bool framework_t::base64_encode( const void * input, int input_len, int crlf_len, std::string & output )
{
    int len = 0;
    if ( ! base64_encode( input, input_len, crlf_len, NULL, & len ) ) {
        output.resize( 0 );
        return false;
    }
    output.resize( 0 );
    try {
        output.resize( len );
    } catch ( ... ) {
        output.resize( 0 );
        return false;
    }
    if ( ! base64_encode( input, input_len, crlf_len, (char *)output.c_str(), & len ) ) {
        output.resize( 0 );
        return false;
    }
    output.resize( len );
    return true;
}
bool framework_t::base64_decode( const char * input, int input_len, std::string & output )
{
    int len = 0;
    if ( ! base64_decode( input, input_len, NULL, & len ) ) {
        output.resize( 0 );
        return false;
    }
    output.resize( 0 );
    try {
        output.resize( len );
    } catch ( ... ) {
        output.resize( 0 );
        return false;
    }
    if ( ! base64_decode( input, input_len, (char *)output.c_str(), & len ) ) {
        output.resize( 0 );
        return false;
    }
    output.resize( len );
    return true;
}
bool framework_t::bytes_to_hex(
    const void *    bytes,
    size_t          length,
    char *          result,
    size_t          result_length,
    bool            write_end_char
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->bytes_to_hex(bytes, length, result, result_length, write_end_char);
}
bool framework_t::hex_to_bytes(
    const char *    hex,
    size_t          length,
    void *          result,
    size_t          result_length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->hex_to_bytes(hex, length, result, result_length);
}
bool framework_t::hex_to_bytes(
    const char *    hex,
    size_t          length,
    char *          result,
    size_t          result_length,
    bool            write_end_char
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->hex_to_string(hex, length, result, result_length, write_end_char);
}
bool framework_t::hex_to_bytes( const char * hex, size_t length, std::string & result )
{
    result.resize( 0 );
    if ( unlikely( NULL == hex || 0 == length ) ) {
        return true;
    }
    size_t dest_size = length / 2;
    try {
        result.resize( dest_size );
    } catch ( ... ) {
        result.resize( 0 );
        return false;
    }
    if ( unlikely( ! hex_to_bytes( hex, length, & result[ 0 ], dest_size + 1, false ) ) ) {
        result.resize( 0 );
        return false;
    }
    return true;
}
bool framework_t::bytes_to_hex( const void * bytes, size_t length, std::string & result )
{
    result.resize( 0 );
    if ( NULL == bytes || 0 == length ) {
        return true;
    }
    size_t dest_size = length * 2;
    try {
        result.resize( dest_size );
    } catch ( ... ) {
        result.resize( 0 );
        return false;
    }
    if ( unlikely( ! bytes_to_hex( bytes, length, & result[ 0 ], dest_size + 1, false ) ) ) {
        result.resize( 0 );
        return false;
    }
    return true;
}
bool framework_t::uuid_create(
    char result[ 16 ]
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->uuid_create(result);
}
struct trie_t* framework_t::trie_create(void)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_create();
}
struct trie_t* framework_t::trie_init(const void* p, const size_t size)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_init(p, size);
}
void framework_t::trie_destroy(struct trie_t* two)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->trie_destroy(two);
}
int framework_t::trie_insert(struct trie_t* two, const char* str, const size_t len, const int value, const int overwrite)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_insert(two, str, len, value, overwrite);
}
int framework_t::trie_match(struct trie_t* two, const char* str, const size_t len, int* val)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_match(two, str, len, val);
}
int framework_t::trie_matchall(struct trie_t* two, const char* str, const size_t len,  trie_mi* minfo, const size_t mlen)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_matchall(two, str, len, minfo, mlen);
}
size_t framework_t::trie_allsize(struct trie_t* two)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_allsize(two);
}
void * framework_t::trie_write(struct trie_t* two, void* p)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_write(two, p);
}
int framework_t::trie_isgood(struct trie_t* two)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_isgood(two);
}
void framework_t::trie_walk(struct trie_t* two, void *arg, two_cb cb)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->trie_walk(two, arg, cb);
}
void framework_t::trie_walk_dump(struct trie_t* two)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->trie_walk_dump(two);
}
int framework_t::trie_feture(struct trie_t* two,
                const char* str, const size_t len,
                const char * out_buf_sep, int out_buf_sep_len,
                char * out_buf, int max_out_buf_len, int * out_buf_len,
                int max_item_count, int * item_count,
                trie_fi * items )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_feture(two, str, len, out_buf_sep, out_buf_sep_len,
        out_buf, max_out_buf_len, out_buf_len, max_item_count, item_count, items);
}
int framework_t::trie_has_feture(struct trie_t* two, const char* str, const size_t len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_has_feture(two, str, len);
}
bool framework_t::trie_write_file(
    trie_t *        two,
    FILE *          fp
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->trie_write_file(two, fp);
}
bool framework_t::trie_db_build( const char * src_file, const char * dest_dir, const trie_db_build_params_t * params )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->trie_db_build(src_file, dest_dir, params);
}
bool framework_t::trie_db_valid(
    const char *            dir
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->trie_db_valid(dir);
}
trie_db_t * framework_t::trie_db_open(
    const char *    dir
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_db_open(dir);
}
void framework_t::trie_db_close( trie_db_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->trie_db_close(db);
}
void * framework_t::trie_db_find( trie_db_t * db, const void * key, int key_len, int * val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_db_find(db, key, key_len, val_len);
}
uint32_t framework_t::trie_db_get_count( trie_db_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->trie_db_get_count(db);
}
void * framework_t::trie_db_get_val( trie_db_t * db, int offset, int * val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_db_get_val(db, offset, val_len);
}
struct trie_t * framework_t::trie_db_get_index( trie_db_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_db_get_index(db);
}
void * framework_t::trie_db_get_key( trie_db_t * db, int offset, int * key_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->trie_db_get_key(db, offset, key_len);
}
bdb_t * framework_t::bdb_open( const char * dir )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->bdb_open(dir);
}
bdb_t * framework_t::bdb_open_advanced(
    const char *    path,
    bool            auto_create,
    const char *    type,
    bool            dup,
    int             page_size,
    int             cache_gb,
    int             cache_k,
    int             cache_n,
    bool            read_only,
    int             record_size,
    int             queue_extent_size
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->bdb_open_advanced(path, auto_create, type, dup, page_size, cache_gb, cache_k, cache_n, read_only, record_size, queue_extent_size);
}
void framework_t::bdb_close( bdb_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->bdb_close(db);
}
int framework_t::bdb_get( bdb_t * db, const void * key, int key_len, void * val, int * val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_get(db, key, key_len, val, val_len);
}
int framework_t::bdb_set( bdb_t * db, const void * key, int key_len, const void * val, int val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_set(db, key, key_len, val, val_len);
}
int framework_t::bdb_del( bdb_t * db, const void * key, int key_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_del(db, key, key_len);
}
int framework_t::bdb_flush( bdb_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_flush(db);
}
bdb_cursor_t * framework_t::bdb_cursor_open( bdb_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->bdb_cursor_open(db);
}
void framework_t::bdb_cursor_close( bdb_cursor_t * self )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->bdb_cursor_close(self);
}
int framework_t::bdb_cursor_next(
    bdb_cursor_t *  self,
    void *          key,
    int *           key_len,
    void *          val,
    int  *          val_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_cursor_next(self, key, key_len, val, val_len);
}
int framework_t::bdb_cursor_find_next(
    bdb_cursor_t *  self,
    const void *    key,
    int             key_len,
    void *          val,
    int *           val_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_cursor_find_next(self, key, key_len, val, val_len);
}
int framework_t::bdb_cursor_del( bdb_cursor_t * self )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->bdb_cursor_del(self);
}
void framework_t::fmap_init(
    fmap_t *    o
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->fmap_init(o);
}
bool framework_t::fmap_open(
    fmap_t *        o,
    const char *    path,
    size_t          offset,
    size_t          len,
    bool            read_write
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->fmap_open(o, path, offset, len, read_write);
}
bool framework_t::fmap_flush(
    fmap_t *        o
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->fmap_flush(o);
}
void framework_t::fmap_close(
    fmap_t * o
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->fmap_close(o);
}
pair_db_t * framework_t::pair_db_open( const char * dir )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->pair_db_open(dir);
}
void framework_t::pair_db_close( pair_db_t * db )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_tool->pair_db_close(db);
}
int framework_t::pair_db_get( pair_db_t * db, const void * key, int key_len, void * val, int * val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->pair_db_get(db, key, key_len, val, val_len);
}
int framework_t::pair_db_set( pair_db_t * db, const void * key, int key_len, const void * val, int val_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->pair_db_set(db, key, key_len, val, val_len);
}
int framework_t::pair_db_del( pair_db_t * db, const void * key, int key_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->pair_db_del(db, key, key_len);
}
int framework_t::keyset_generate(
    const char * src_path,
    const char * src_sep,
    const char * dst_path
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->keyset_generate(src_path, src_sep, dst_path);
}
keyset_t * framework_t::keyset_open( const char * path )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->keyset_open(path);
}
keyset_t * framework_t::keyset_open_memory( const void * data, int data_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->keyset_open_memory(data, data_len);
}
void framework_t::keyset_close( keyset_t * self )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->keyset_close(self);
}
int framework_t::keyset_find(
    keyset_t *      self,
    const void *    key,
    int             key_len,
    keyset_item_t * result,
    int             result_max
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->keyset_find(self, key, key_len, result, result_max);
}
int framework_t::cn_people_name_generate(
    const char *    src_surname_path,
    const char *    src_sname_path,
    const char *    src_dname1_path,
    const char *    src_dname2_path,
    const char *    src_stop_path,
    const char *    src_sep,
    const char *    dst_surname_path,
    const char *    dst_sname_path,
    const char *    dst_dname1_path,
    const char *    dst_dname2_path,
    const char *    dst_stop_path
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->cn_people_name_generate(
        src_surname_path,src_sname_path,src_dname1_path,src_dname2_path,src_stop_path,src_sep,
        dst_surname_path,dst_sname_path,dst_dname1_path,dst_dname2_path,dst_stop_path );
}
cn_people_name_t * framework_t::cn_people_name_open( int charset )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_people_name_open( charset );
}
void framework_t::cn_people_name_close( cn_people_name_t *  self )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->cn_people_name_close(self);
}
int framework_t::cn_people_name_find(
    cn_people_name_t *         self,
    const char *               str,
    int                        str_len,
    int *                      charset,
    cn_people_name_item_t *    result,
    int                        result_max
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->cn_people_name_find(self, str, str_len, charset, result, result_max );
}
int framework_t::cn_people_name_get_sample(
    cn_people_name_t *         self,
    const char *               str,
    int                        str_len,
    int *                      charset,
    cn_people_name_item_t *    result,
    int                        result_max
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - errno;
    }
    return _framework->_tool->cn_people_name_get_sample(self, str, str_len, charset, result, result_max );
}
int framework_t::cn_people_name_surname(
    cn_people_name_t *      self,
    const char *            str,
    int                     str_len,
    int *                   charset,
    const char **           suname
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( suname ) * suname = NULL;
        return - errno;
    }
    return _framework->_tool->cn_people_name_surname(self, str, str_len, charset, suname );
}
cn_place_name_item_t * framework_t::fixed_tel_get_city_code(
    const char *    fixed_tel,
    size_t          fixed_tel_len,
    int *           city_code_len,
    int *           place_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( city_code_len ) * city_code_len = 0;
        if ( place_id ) * place_id = 0;
        return NULL;
    }
    return _framework->_tool->fixed_tel_get_city_code(fixed_tel, fixed_tel_len, city_code_len, place_id );
}
int framework_t::analyse_places(
    const char *                gbk_text,
    int                         gbk_text_bytes,
    cn_place_name_item_t **     result,
    int                         max_count
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_tool->analyse_places( gbk_text, gbk_text_bytes, result, max_count );
}
bool framework_t::analyse_places_tels(
    const char *                gbk_text,
    int                         gbk_text_bytes,
    cn_place_name_item_t **     places,
    int *                       places_count,
    const_str *                 tels,
    int *                       tels_count
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( places_count ) * places_count = 0;
        if ( tels_count ) * tels_count = 0;
        return false;
    }
    return _framework->_tool->analyse_places_tels( gbk_text, gbk_text_bytes, places, places_count, tels, tels_count );
}
cn_place_name_item_t * framework_t::t2260_2013_to_place( const char * str, size_t str_len )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->t2260_2013_to_place( str, str_len );
}
int framework_t::cn_place_name_id_compare(
    int                     left,
    int                     right
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - 1;
    }
    return _framework->_tool->cn_place_name_id_compare(left, right);
}
cn_place_name_item_t * framework_t::cn_place_name_parent(
    cn_place_name_item_t *  child
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_place_name_parent(child);
}
cn_place_name_item_t * framework_t::cn_place_name_top_parent(
    cn_place_name_item_t *  child
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_place_name_top_parent(child);
}
bool framework_t::cn_place_name_check_elder(
    int                     elder_id,
    int                     child_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->cn_place_name_check_elder(elder_id, child_id);
}
int framework_t::cn_place_name_child_count(
    cn_place_name_item_t *  parent
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->cn_place_name_child_count(parent);
}
cn_place_name_item_t * framework_t::cn_place_name_child(
    cn_place_name_item_t *  parent,
    int                     index
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_place_name_child(parent, index);
}
cn_place_name_item_t * framework_t::cn_place_name_find_by_id(
    int                     node_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_place_name_find_by_id(node_id);
}
cn_place_name_item_t * framework_t::cn_place_name_find_by_name(
    const char *            gbk_name,
    size_t                  gbk_name_len,
    int *                   next_node_id,
    int                     priority_elder_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( next_node_id ) { * next_node_id = 0; }
        return NULL;
    }
    return _framework->_tool->cn_place_name_find_by_name(gbk_name, gbk_name_len, next_node_id, priority_elder_id);
}
size_t framework_t::cn_place_name_match_all_by_name(
    const char *            gbk_name,
    size_t                  gbk_name_len,
    int *                   id_list,
    size_t                  id_list_max,
    int                     priority_elder_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->cn_place_name_match_all_by_name(gbk_name, gbk_name_len, id_list, id_list_max, priority_elder_id);
}
size_t framework_t::cn_place_name_match_part_by_name(
    const char *            gbk_name,
    size_t                  gbk_name_len,
    int *                   id_list,
    size_t                  id_list_max,
    int                     priority_elder_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_tool->cn_place_name_match_part_by_name(gbk_name, gbk_name_len, id_list, id_list_max, priority_elder_id);
}
highway_info_t * framework_t::cn_highway_info(
    int G_id
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_tool->cn_highway_info(G_id);
}
highway_station_t * framework_t::cn_highway_by_place_id(
    int &                   place_id,
    int *                   result_count
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_count ) * result_count = 0;
        return NULL;
    }
    return _framework->_tool->cn_highway_by_place_id(&place_id, result_count);
}
fanout2_t * framework_t::fanout2_create(
    fanout2_param_t *       param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->fanout2_create(param);
}
void framework_t::fanout2_destroy(
    fanout2_t *             fanout
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_network->fanout2_destroy(fanout);
}
fanout2_task_t * framework_t::fanout2_task_create(
    fanout2_t *             fanout,
    fanout2_callback_t      callback,
    void *                  callback_param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->fanout2_task_create(fanout, callback, callback_param);
}
void * framework_t::fanout2_task_param(
    fanout2_task_t *        task
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->fanout2_task_param(task);
}
bool framework_t::fanout2_add_pending_http(
    fanout2_task_t *        task,
    const char *            url,
    int                     url_len,
    const char *            refer,
    int                     refer_len,
    int                     connect_timeout_ms,
    int                     total_timeout_ms,
    fanout2_http_param_t *  param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->fanout2_add_pending_http(task, url, url_len, refer, refer_len, connect_timeout_ms, total_timeout_ms, param);
}
void framework_t::fanout2_task_destroy(
    fanout2_task_t *        task
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    return _framework->_network->fanout2_task_destroy(task);
}
bool framework_t::fanout2_task_start(
    fanout2_task_t *        task
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_network->fanout2_task_start(task);
}
size_t framework_t::fanout2_task_request_size(
    fanout2_task_t *        task
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_network->fanout2_task_request_size(task);
}
int framework_t::fanout2_task_get_error_code(
    fanout2_task_t *        task,
    size_t                  index
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -999;
    }
    return _framework->_network->fanout2_task_get_error_code(task, index);
}
const char * framework_t::fanout2_task_get_url(
    fanout2_task_t *        task,
    size_t                  index,
    size_t *                url_len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( url_len ) * url_len = 0;
        return NULL;
    }
    return _framework->_network->fanout2_task_get_url(task, index, url_len);
}
const char * framework_t::fanout2_task_get_rsp(
    fanout2_task_t *        task,
    size_t                  index,
    size_t *                rsp_len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( rsp_len ) * rsp_len = 0;
        return NULL;
    }
    return _framework->_network->fanout2_task_get_rsp(task, index, rsp_len);
}
const struct sockaddr_in * framework_t::fanout2_task_get_addr(
    fanout2_task_t *        task,
    size_t                  index
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->fanout2_task_get_addr(task, index);
}
const char * framework_t::fanout2_task_get_req(
    fanout2_task_t *        task,
    size_t                  index,
    size_t *                req_len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( req_len ) * req_len = 0;
        return NULL;
    }
    return _framework->_network->fanout2_task_get_req(task, index, req_len);
}
gr_http_ctxt_t * framework_t::fanout2_task_get_http_rsp(
    fanout2_task_t *        task,
    size_t                  index
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->fanout2_task_get_http_rsp(task, index);
}
tcp_channel_t * framework_t::tcp_channel_create(
    int                     thread_count,
    int                     up_buf_bytes,
    int                     down_buf_bytes,
    int                     concurrent,
    int                     max_conn,
    int                     poll_wait_ms,
    tcp_channel_cb_t        callback
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    return _framework->_network->tcp_channel_create(thread_count, up_buf_bytes, down_buf_bytes, concurrent, max_conn, poll_wait_ms, callback);
}
void framework_t::tcp_channel_destroy(
    tcp_channel_t * self
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_network->tcp_channel_destroy(self);
}
int framework_t::tcp_channel_connect(
    tcp_channel_t *         self,
    int                     fd,
    const struct sockaddr * addr,
    socklen_t               addr_len,
    void *                  param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_network->tcp_channel_connect(self, fd, addr, addr_len, param);
}
int framework_t::tcp_channel_async_connect(
    tcp_channel_t *         self,
    int                     fd,
    const struct sockaddr * addr,
    socklen_t               addr_len,
    void *                  param
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_network->tcp_channel_async_connect(self, fd, addr, addr_len, param);
}
int framework_t::tcp_channel_send(
    tcp_channel_t *         self,
    int                     fd,
    const void *            data,
    int                     data_len,
    uint32_t                wait_ms
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_network->tcp_channel_send(self, fd, data, data_len, wait_ms);
}
int framework_t::tcp_channel_pop_recved(
    tcp_channel_t *         self,
    int                     fd,
    int                     len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_network->tcp_channel_pop_recved(self, fd, len);
}
int framework_t::tcp_channel_del(
    tcp_channel_t *         self,
    int                     fd,
    bool                    close_fd
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    return _framework->_network->tcp_channel_del(self, fd, close_fd);
}
int framework_t::gzcompress(
    const void *    data,
    int             data_len,
    void *          zdata,
    int *           zdata_len
)
{
    return _framework->_server->gzcompress(data, data_len, zdata, zdata_len);
}
int framework_t::gzdecompress(
    const void *    zdata,
    int             zdata_len,
    void *          data,
    int *           data_len
)
{
    return _framework->_server->gzdecompress(zdata, zdata_len, data, data_len);
}
bool framework_t::set_additional_read_fd(
    int         worker_id,
    int         fd,
    void *      param,
    void        ( * callback )( int fd, void * param )
)
{
    return _framework->_server->set_additional_read_fd(worker_id, fd, param, callback);
}
bool framework_t::find_argv(
    const char *    key,
    const char **   value,
    size_t *        value_len
)
{
    int             argc = get_interface()->argc;
    char **         argv = get_interface()->argv;
    return _framework->_server->find_argv(argc, argv, key, value, value_len);
}
bool framework_t::find_argv_int(
    const char *    key,
    int *           value
)
{
    int             argc = get_interface()->argc;
    char **         argv = get_interface()->argv;
    return _framework->_server->find_argv_int(argc, argv, key, value);
}
void framework_t::datetime_now( uint64_t * result )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_tool->datetime_now(result);
}
bool framework_t::datetime_make(
    uint64_t *  result,
    int         year,
    int         month,
    int         day,
    int         hour,
    int         minute,
    int         second,
    int         ms
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result ) * result = 0;
        return false;
    }
    return _framework->_tool->datetime_make(result, year, month, day, hour, minute, second, ms);
}
bool framework_t::datetime_info(
    uint64_t    ticks,
    int *       year,
    int *       month,
    int *       day,
    int *       hour,
    int *       minute,
    int *       second,
    int *       ms
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( year )     * year = 0;
        if ( month )    * month = 0;
        if ( day )      * day = 0;
        if ( hour )     * hour = 0;
        if ( minute )   * minute = 0;
        if ( second )   * second = 0;
        if ( ms )       * ms = 0;
        return false;
    }
    return _framework->_tool->datetime_info(ticks, year, month, day, hour, minute, second, ms);
}
bool framework_t::time_info(
    time_t      v,
    int *       year,
    int *       month,
    int *       day,
    int *       hour,
    int *       minute,
    int *       second
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( year )     * year = 0;
        if ( month )    * month = 0;
        if ( day )      * day = 0;
        if ( hour )     * hour = 0;
        if ( minute )   * minute = 0;
        if ( second )   * second = 0;
        return false;
    }
    return _framework->_tool->time_info(v, year, month, day, hour, minute, second);
}
bool framework_t::get_current_time(
    int *       year,
    int *       month,
    int *       day,
    int *       hour,
    int *       minute,
    int *       second,
    int *       ms
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( year )     * year = 0;
        if ( month )    * month = 0;
        if ( day )      * day = 0;
        if ( hour )     * hour = 0;
        if ( minute )   * minute = 0;
        if ( second )   * second = 0;
        if ( ms )       * ms = 0;
        return false;
    }
    return _framework->_tool->get_current_time(year, month, day, hour, minute, second, ms);
}
time_t framework_t::time_from_str(
    const char *    str,
    int             str_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (time_t)0;
    }
    return _framework->_tool->time_from_str(str, str_len);
}
bool framework_t::time_to_str(
    time_t      v,
    char *      str,
    int *       str_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_tool->time_to_str(v, str, str_len);
}
bool framework_t::time_to_str(
    time_t          v,
    std::string &   str
)
{
    str.resize( 0 );
    try {
        str.resize( 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1 );
    } catch ( ... ) {
        str.resize( 0 );
        return false;
    }
    int str_len = (int)str.size();
    if ( ! time_to_str( v, & str[ 0 ], & str_len ) ) {
        str.resize( 0 );
        return false;
    }
    str.resize( str_len );
    return true;
}
void framework_t::md5( const void * data, size_t data_len, char * digest )
{
    return _framework->_server->md5(data, data_len, digest);
}
bool framework_t::parser_open_charset(
    parser_t *      parser,
    const void *    ptr,
    int             len,
    int             charset
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->parser_open_charset(parser, ptr, len, charset);
}
bool framework_t::parser_end(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    return _framework->_string->parser_end(parser);
}
char framework_t::parser_peek(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (char)0;
    }
    return _framework->_string->parser_peek(parser);
}
char framework_t::parser_read(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (char)0;
    }
    return _framework->_string->parser_read(parser);
}
int framework_t::parser_read_charset(
    parser_t *      parser,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_charset(parser, result, result_len);
}
const char * framework_t::parser_read_charset_ptr(
    parser_t *      parser,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_charset_ptr(parser, result_len);
}
void framework_t::parser_back(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_string->parser_back(parser);
}
void framework_t::parser_back_bytes(
    parser_t *      parser,
    size_t          bytes
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    _framework->_string->parser_back_bytes(parser, bytes);
}
int framework_t::parser_ignore_spaces(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_ignore_spaces(parser);
}
int framework_t::parser_ignore_spaces_tail(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_ignore_spaces_tail(parser);
}
int framework_t::parser_ignore_to(
    parser_t *          parser,
    const char *        stop_chars
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_ignore_to(parser, stop_chars);
}
int framework_t::parser_escape_char(
    parser_t *      parser,
    char *          result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_escape_char(parser, result);
}
int framework_t::parser_read_string(
    parser_t *      parser,
    bool            translate_escape_char,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_read_string(parser, translate_escape_char, result, result_len);
}
int framework_t::parser_read_whole_string(
    parser_t *      parser,
    bool            translate_escape_char,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    return _framework->_string->parser_read_whole_string(parser, translate_escape_char, result, result_len);
}
const char * framework_t::parser_read_string_ptr(
    parser_t *      parser,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_string_ptr(parser, result_len);
}
int framework_t::parser_html_escape_char(
    parser_t *      parser,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_html_escape_char(parser, result, result_len);
}
int framework_t::parser_read_html_string(
    parser_t *      parser,
    bool            entity_decode,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_html_string(parser, entity_decode, result, result_len);
}
int framework_t::parser_read_whole_html_string(
    parser_t *      parser,
    bool            entity_decode,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_whole_html_string(parser, entity_decode, result, result_len);
}
const char * framework_t::parser_read_html_string_ptr(
    parser_t *      parser,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_html_string_ptr(parser, result_len);
}
int framework_t::parser_read_to(
    parser_t *          parser,
    const char *        stop_chars,
    bool                enable_escape,
    char *              result,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_to(parser, stop_chars, enable_escape, result, result_len);
}
const char * framework_t::parser_read_ptr_to(
    parser_t *          parser,
    const char *        stop_chars,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_ptr_to(parser, stop_chars, result_len);
}
int framework_t::parser_read_word(
    parser_t *          parser,
    bool                enable_escape,
    char *              result,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_word(parser, enable_escape, result, result_len);
}
const char *
framework_t::parser_read_word_ptr(
    parser_t *          parser,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_word_ptr(parser, result_len);
}
bool framework_t::parser_read_last_word(
    parser_t *          parser,
    bool                enable_escape,
    char *              result,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return false;
    }
    return _framework->_string->parser_read_last_word(parser, enable_escape, result, result_len);
}
int framework_t::parser_read_alpha(
    parser_t *          parser,
    bool                enable_escape,
    char *              result,
    int *               result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_alpha(parser, enable_escape, result, result_len);
}
int framework_t::parser_read_int(
    parser_t *      parser,
    int *           result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result ) { * result = 0; }
        return 0;
    }
    return _framework->_string->parser_read_int(parser, result);
}
int framework_t::parser_read_number(
    parser_t *      parser,
    char *          result,
    int *           result_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return 0;
    }
    return _framework->_string->parser_read_number(parser, result, result_len);
}
time_t framework_t::parser_read_datetime_rfc867(
    parser_t *      parser
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (time_t)0;
    }
    return _framework->_string->parser_read_datetime_rfc867(parser);
}
const const_str *
framework_t::get_sentence_sep_list(
    int             charset,
    int *           count
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( count ) { * count = 0; }
        return NULL;
    }
    return _framework->_string->get_sentence_sep_list(charset, count);
}
const char *
framework_t::parser_read_sentence_ptr(
    parser_t *      parser,
    int *           result_len,
    const char **   sep
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( result_len ) { * result_len = 0; }
        return NULL;
    }
    return _framework->_string->parser_read_sentence_ptr(parser, result_len, sep);
}
void framework_t::simple_encrypt( void *buf, int buf_len, uint32_t passwd )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    return _framework->_string->simple_encrypt( buf, buf_len, passwd );
}
void framework_t::simple_decrypt( void *buf, int buf_len, uint32_t passwd )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    return _framework->_string->simple_decrypt( buf, buf_len, passwd );
}
void framework_t::binary_set_bit( void * src, size_t witch_bit, bool v )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    return _framework->_string->binary_set_bit( (unsigned char *)src, witch_bit, v );
}
bool framework_t::binary_get_bit( const void * src, size_t witch_bit )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->binary_get_bit( (const unsigned char *)src, witch_bit );
}
const unsigned char * framework_t::binary_find_non_zero_byte( const void * src, size_t src_bytes )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_string->binary_find_non_zero_byte( (const unsigned char *)src, src_bytes );
}
size_t framework_t::binary_find_non_zero_bit( const void * src, size_t src_bytes )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return (size_t)-1;
    }
    errno = 0;
    return _framework->_string->binary_find_non_zero_bit( (const unsigned char *)src, src_bytes );
}
unsigned char framework_t::byte_set_bit( unsigned char src, unsigned char witch_bit, bool v )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing, exception raised" );
        errno = EINVAL;
        // we must throw exception here
        throw std::exception();
        return src;
    }
    errno = 0;
    return _framework->_string->byte_set_bit( src, witch_bit, v );
}
bool framework_t::byte_get_bit( unsigned char src, unsigned char witch_bit )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing, exception raised" );
        errno = EINVAL;
        // we must throw exception here
        throw std::exception();
        return false;
    }
    errno = 0;
    return _framework->_string->byte_get_bit( src, witch_bit );
}
bool framework_t::cluster_get_dirty()
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_get_dirty();
}
void framework_t::cluster_set_dirty( bool v )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_parallel->cluster_set_dirty( v );
}
bool framework_t::cluster_save( const char * path, uint32_t * version )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_save( path, version );
}
bool framework_t::cluster_load( const char * path, uint32_t * version )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_load( path, version );
}
bool framework_t::cluster_update( const char * path, const char * mem, int mem_bytes, uint32_t * version )
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_update( path, mem, mem_bytes, version );
}
uint32_t framework_t::cluster_version()
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_parallel->cluster_version();
}
cluster_group_t * framework_t::cluster_find_group(
    const char *    path,
    bool            auto_create
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_find_group( path, auto_create );
}
bool framework_t::cluster_del_group(
    const char *    path
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_del_group( path );
}
bool framework_t::cluster_del_peer(
    cluster_peer_t * peer
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_del_peer( peer );
}
cluster_peer_t * framework_t::cluster_find_peer(
    const char * addr
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_find_peer( addr );
}
cluster_peer_t * framework_t::cluster_group_find_peer_by_index(
    cluster_group_t *   group,
    int                 index
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_find_peer_by_index( group, index );
}
cluster_peer_t * framework_t::cluster_group_find_peer(
    cluster_group_t *   group,
    const char *        addr,
    bool                auto_create
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_find_peer( group, addr, auto_create );
}
const char * framework_t::cluster_group_get_name(
    cluster_group_t *   group
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_get_name( group );
}
cluster_group_t * framework_t::cluster_group_get_parent(
    cluster_group_t *   group
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_get_parent( group );
}
bool framework_t::cluster_group_get_enable(
    cluster_group_t *   group
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_get_enable( group );
}
void framework_t::cluster_group_set_enable(
    cluster_group_t *   group,
    bool                b
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_set_enable( group, b );
}
const void * framework_t::cluster_group_get_property(
    cluster_group_t *   group,
    const char *        name,
    int *               property_len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( property_len ) { * property_len = 0; }
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_get_property( group, name, property_len );
}
bool framework_t::cluster_group_set_property(
    cluster_group_t *   group,
    const char *        name,
    const void *        property,
    int                 property_len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_set_property( group, name, property, property_len );
}
int framework_t::cluster_group_child_groups(
    cluster_group_t *   group,
    cluster_group_t **  result,
    int                 result_max
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_child_groups( group, result, result_max );
}
int framework_t::cluster_group_child_peers(
    cluster_group_t *   group,
    cluster_peer_t **   result,
    int                 result_max
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_parallel->cluster_group_child_peers( group, result, result_max );
}
const char * framework_t::cluster_peer_get_addr(
    cluster_peer_t *    peer
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_get_addr( peer );
}
const struct sockaddr_in * framework_t::cluster_peer_get_sock_addr(
    cluster_peer_t *    peer
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_get_sock_addr( peer );
}
cluster_group_t * framework_t::cluster_peer_get_parent(
    cluster_peer_t *    peer
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_get_parent( peer );
}
bool framework_t::cluster_peer_get_enable(
    cluster_peer_t *    peer
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_get_enable( peer );
}
void framework_t::cluster_peer_set_enable(
    cluster_peer_t *    peer,
    bool                b
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_parallel->cluster_peer_set_enable( peer, b );
}
const void * framework_t::cluster_peer_get_property(
    cluster_peer_t *    peer,
    const char *        name,
    int *               property_len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( property_len ) { * property_len = 0; }
        return (const void *)NULL;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_get_property( peer, name, property_len );
}
bool framework_t::cluster_peer_set_property(
    cluster_peer_t *    peer,
    const char *        name,
    const void *        property,
    int                 property_len
)
{
    if ( unlikely( NULL == _framework->_parallel ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_parallel->cluster_peer_set_property( peer, name, property, property_len );
}
ini_t * framework_t::ini_create(
    const char * path
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_tool->ini_create( path );
}
ini_t * framework_t::ini_create_memory(
    const char * content,
    size_t content_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_tool->ini_create_memory( content, content_len );
}
void framework_t::ini_destroy(
    ini_t * This
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_tool->ini_destroy( This );
}
size_t framework_t::ini_get_sections_count(
    ini_t * ini
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_tool->ini_get_sections_count( ini );
}
bool framework_t::ini_get_sections(
   ini_t * ini,
   const char ** sections,
   size_t * sections_count
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_tool->ini_get_sections( ini, sections, sections_count );
}
bool framework_t::ini_get_bool(
    ini_t * ini,
    const char * section,
    const char * name,
    bool def
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_tool->ini_get_bool( ini, section, name, def );
}
int framework_t::ini_get_int(
    ini_t * ini,
    const char * section,
    const char * name,
    int def
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return def;
    }
    errno = 0;
    return _framework->_tool->ini_get_int( ini, section, name, def );
}
long long framework_t::ini_get_int64(
    ini_t * ini,
    const char * section,
    const char * name,
    long long def
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return def;
    }
    errno = 0;
    return _framework->_tool->ini_get_int64( ini, section, name, def );
}
const char * framework_t::ini_get_string(
    ini_t * This,
    const char * section,
    const char * name,
    const char * def
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return def;
    }
    errno = 0;
    return _framework->_tool->ini_get_string( This, section, name, def );
}
bool framework_t::ini_get_addr(
    ini_t * This,
    const char * section,
    const char * name,
    sockaddr_in & addr
)
{
    const char * s = ini_get_string( This, section, name, NULL );
    if ( NULL == s || '\0' == * s ) {
        memset( & addr, 0, sizeof( sockaddr_in ) );
        return false;
    }
    return socket_str_2_addr_v4( s, & addr );
}
agile_t * framework_t::agile_create(
    const char *    addr_list,
    const char *    addr_list_sep,
    int             connect_timeout_s,
    int             recv_timeout_s,
    const char *    user,
    const char *    passwd
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_tool->agile_create(addr_list, addr_list_sep, connect_timeout_s, recv_timeout_s, user, passwd);
}
void framework_t::agile_destroy(
    agile_t *       self
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_tool->agile_destroy(self);
}
int framework_t::agile_get(
    agile_t *       self,
    const void *    key,
    size_t          key_len,
    uint32_t *      version,
    void *          rsp,
    size_t *        rsp_len
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    errno = 0;
    return _framework->_tool->agile_get(self, key, key_len, version, rsp, rsp_len);
}
int framework_t::agile_put(
    agile_t *       self,
    const void *    key,
    size_t          key_len,
    const void *    value,
    size_t          value_len,
    uint32_t *      version
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    errno = 0;
    return _framework->_tool->agile_put(self, key, key_len, value, value_len, version);
}
int framework_t::agile_del(
    agile_t *       self,
    const void *    key,
    size_t          key_len,
    uint32_t *      version
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    errno = 0;
    return _framework->_tool->agile_del(self, key, key_len, version);
}
int framework_t::agile_exist(
    agile_t *       self,
    const void *    key,
    size_t          key_len,
    uint32_t *      version
)
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return - EINVAL;
    }
    errno = 0;
    return _framework->_tool->agile_exist(self, key, key_len, version);
}
const char * framework_t::str_trim_const(
    const char *    s,
    int *           len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( len ) * len = 0;
        return NULL;
    }
    errno = 0;
    return _framework->_string->str_trim_const(s, len);
}
void framework_t::str_trim( std::string & s )
{
    int             len = (int)s.size();
    const char *    dst;
    dst = str_trim_const( s.c_str(), & len );
    if ( dst != s.c_str() ) {
        memcpy( (char *)s.c_str(), dst, len );
    }
    s.resize( len );
}
char * framework_t::str_trim( char * s, int * len )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( len ) * len = 0;
        return NULL;
    }
    errno = 0;
    return _framework->_string->str_trim(s, len);
}
void * framework_t::tcp_find_conn(int fd)
{
    return _framework->_server->tcp_find_conn(fd);
}
bool framework_t::compress(
    const void *    data,
    size_t          data_len,
    std::string &   compred_data
)
{
    compred_data.resize( 0 );
    try {
        compred_data.resize( 4 + data_len );
    } catch ( ... ) {
        log_error( "bad_alloc" );
        return false;
    }
    size_t ignore = 4;
    size_t compred_len = compred_data.size() - ignore;
    int r = zlib_compress(
        (unsigned char *)& compred_data[ ignore ],
        & compred_len,
        (const unsigned char*)data,
        (unsigned int)data_len
    );
    unsigned int * plen = (unsigned int *)& compred_data[ 0 ];
    if ( 0 != r ) {
        if ( Z_BUF_ERROR != r ) {
            log_error( "compress return %d, use orig data", r );
        }
        * plen = (unsigned int)data_len;
        memcpy( & compred_data[ ignore ], data, data_len );
        return true;
    }
    if ( compred_len == compred_data.size() - ignore ) {
        * plen = (unsigned int)data_len;
        memcpy( & compred_data[ ignore ], data, data_len );
        return true;
    }
    * plen = (unsigned int)data_len;
    compred_data.resize( compred_len + ignore );
    return true;
}
bool framework_t::uncompress(
    const void *    data,
    size_t          data_len,
    std::string &   uncompr_data
)
{
    uncompr_data.resize( 0 );
    if ( unlikely( NULL == data || data_len <= 4 ) ) {
        return false;
    }
    const unsigned int * plen = (const unsigned int *)data;
    data = (plen + 1);
    data_len -= sizeof( int );
    if ( unlikely( data_len > * plen ) ) {
        return false;
    }
    if ( data_len == (size_t)* plen ) {
        // no compressed
        try {
            uncompr_data.resize( * plen );
        } catch ( ... ) {
            log_error( "bad_alloc" );
            return false;
        }
        memcpy( & uncompr_data[ 0 ], data, data_len );
        return true;
    }
    //TODO: performance
    try {
        uncompr_data.resize( * plen );
    } catch ( ... ) {
        log_error( "bad_alloc" );
        return false;
    }
    size_t uncompr_len = uncompr_data.size();
    int r = zlib_uncompress(
        (unsigned char *)& uncompr_data[ 0 ],
        & uncompr_len,
        (const unsigned char*)data,
        (unsigned int)data_len
    );
    if ( 0 != r ) {
        log_error( "uncompress return %d", r );
        uncompr_data.resize( 0 );
        return false;
    }
    if ( uncompr_len != * plen ) {
        log_error( "invalid uncompressed len" );
        uncompr_data.resize( 0 );
        return false;
    }
    uncompr_data.resize( uncompr_len );
    return true;
}
MiniDbConnection * framework_t::db_connect( const char * uri, const char * user, const char * passwd )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_tool->db_connect(uri, user, passwd);
}
void framework_t::db_conn_release( MiniDbConnection * conn )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_tool->db_conn_release(conn);
}
bool framework_t::db_conn_execute_non_query( MiniDbConnection * conn, const char * sql, int64_t * affected )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_tool->db_conn_execute_non_query(conn, sql, affected);
}
MiniDataReader * framework_t::db_conn_execute_reader( MiniDbConnection * conn, const char * sql, int32_t page_size, int64_t cur_page )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_tool->db_conn_execute_reader(conn, sql, page_size, cur_page);
}
void framework_t::db_reader_release( MiniDataReader * reader )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return;
    }
    errno = 0;
    _framework->_tool->db_reader_release(reader);
}
int framework_t::db_reader_get_column_count( MiniDataReader * reader )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_column_count(reader);
}
int framework_t::db_reader_get_column_index( MiniDataReader * reader, const char * name )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_column_index(reader, name);
}
bool framework_t::db_reader_read( MiniDataReader * reader, bool read_page )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_tool->db_reader_read(reader, read_page);
}
int framework_t::db_reader_get_int( MiniDataReader * reader, int index, int def )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return def;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_int(reader, index, def);
}
int64_t framework_t::db_reader_get_int64( MiniDataReader * reader, int index, int64_t def )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return def;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_int64(reader, index, def);
}
double framework_t::db_reader_get_float( MiniDataReader * reader, int index )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0.0f;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_float(reader, index);
}
int64_t framework_t::db_reader_get_datetime( MiniDataReader * reader, int index )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_tool->db_reader_get_datetime(reader, index);
}
bool framework_t::db_reader_get_string( MiniDataReader * reader, int index, std::string & result )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        result.resize( 0 );
        return false;
    }
    errno = 0;
    size_t len = 0;
    const char * s = _framework->_tool->db_reader_get_string(reader, index, & len);
    if ( NULL == s ) {
        result.resize( 0 );
        return false;
    }
    result.assign( s, len );
    return true;
}
bool framework_t::db_reader_get_binary( MiniDataReader * reader, int index, std::string & result )
{
    if ( unlikely( NULL == _framework->_tool ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        result.resize( 0 );
        return false;
    }
    errno = 0;
    size_t len = 0;
    const char * s = (const char *)_framework->_tool->db_reader_get_binary(reader, index, & len);
    if ( NULL == s ) {
        result.resize( 0 );
        return false;
    }
    result.assign( s, len );
    return true;
}
size_t framework_t::zrpc_package_length( ZRpcHeader * header )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->zrpc_package_length( header );
}
int framework_t::zrpc_reader_open( ZRpcReader * This, ZRpcHeader * package )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_open( This, package );
}
int framework_t::zrpc_reader_open_raw(
    ZRpcReader * This,
    const void * data,
    size_t       len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_open_raw( This, data, len );
}
bool framework_t::zrpc_reader_is_raw(
    ZRpcReader *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_is_raw( This );
}
size_t framework_t::zrpc_reader_get_length(
    ZRpcReader *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_get_length( This );
}
void * framework_t::zrpc_reader_get_package(
    ZRpcReader *    This,
    size_t *        length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( length ) { * length = 0; }
        return NULL;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_get_package( This, length );
}
int framework_t::zrpc_reader_read(
    ZRpcReader * This,
    void * ret,
    size_t len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read( This, ret, len );
}
int framework_t::zrpc_reader_ignore(
    ZRpcReader * This,
    size_t len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_ignore( This, len );
}
int framework_t::zrpc_reader_get_header_size(
    ZRpcReader * This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_get_header_size( This );
}
bool framework_t::zrpc_reader_is_big_endian(
    ZRpcReader *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_is_big_endian( This );
}
void * framework_t::zrpc_reader_get_curr(
    ZRpcReader *    This,
    size_t *        len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( len ) { * len = 0; }
        return NULL;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_get_curr( This, len );
}
int framework_t::zrpc_reader_move_pos(
    ZRpcReader *    This,
    long            pos
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_move_pos( This, pos );
}
int framework_t::zrpc_reader_set_pos(
    ZRpcReader *    This,
    long            pos
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_set_pos( This, pos );
}
int framework_t::zrpc_reader_read_byte(
    ZRpcReader * This,
    byte_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_byte( This, ret );
}
int framework_t::zrpc_reader_read_uint16(
    ZRpcReader * This,
    uint16_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_uint16( This, ret );
}
int framework_t::zrpc_reader_read_uint32(
    ZRpcReader * This,
    uint32_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_uint32( This, ret );
}
int framework_t::zrpc_reader_read_uint64(
    ZRpcReader * This,
    uint64_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_uint64( This, ret );
}
int framework_t::zrpc_reader_read_int32v(
    ZRpcReader * This,
    int32_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_int32v( This, ret );
}
int framework_t::zrpc_reader_read_uint32v(
    ZRpcReader * This,
    uint32_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_uint32v( This, ret );
}
int framework_t::zrpc_reader_read_uint64v(
    ZRpcReader * This,
    uint64_t * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_uint64v( This, ret );
}
int framework_t::zrpc_reader_read_float(
    ZRpcReader * This,
    float * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_float( This, ret );
}
int framework_t::zrpc_reader_read_double(
    ZRpcReader * This,
    double * ret
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_double( This, ret );
}
int framework_t::zrpc_reader_read_bytes(
    ZRpcReader * This,
    const char ** s,
    size_t * l
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_reader_read_bytes( This, s, l );
}
int framework_t::zrpc_writer_open_raw(
    ZRpcWriter *    This,
    byte_t *        buff,
    size_t          capacity,
    size_t *        length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_open_raw( This, buff, capacity, length );
}
int framework_t::zrpc_writer_open_expandable_raw(
    ZRpcWriter *    This,
    size_t *        length
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_open_expandable_raw( This, length );
}
int framework_t::zrpc_writer_close_expandable(
    ZRpcWriter *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_close_expandable( This );
}
bool framework_t::zrpc_writer_is_raw(
    ZRpcWriter *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_is_raw( This );
}
int framework_t::zrpc_writer_set_udp_info(
    struct ZRpcWriter *         writer,
    uint16_t                    reply_port
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_set_udp_info( writer, reply_port );
}
int framework_t::zrpc_writer_set_error(
    struct ZRpcWriter *         writer,
    uint32_t                    e
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_set_error( writer, e );
}
bool framework_t::zrpc_writer_is_big_endian(
    ZRpcWriter *    This
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_is_big_endian( This );
}
void * framework_t::zrpc_writer_get_curr(
    ZRpcWriter *    This,
    size_t *        len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return NULL;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_get_curr( This, len );
}
int framework_t::zrpc_writer_add_length(
    ZRpcWriter *    This,
    int             len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_add_length( This, len );
}
int framework_t::zrpc_writer_write(
    ZRpcWriter * This,
    const void * p,
    size_t l
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write( This, p, l );
}
int framework_t::zrpc_writer_write_byte(
    ZRpcWriter * This,
    byte_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_byte( This, p );
}
int framework_t::zrpc_writer_write_uint16(
    ZRpcWriter * This,
    uint16_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_uint16( This, p );
}
int framework_t::zrpc_writer_write_int32v(
    ZRpcWriter * This,
    int32_t      p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_int32v( This, p );
}
int framework_t::zrpc_writer_write_uint32(
    ZRpcWriter * This,
    uint32_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_uint32( This, p );
}
int framework_t::zrpc_writer_write_uint64(
    ZRpcWriter * This,
    uint64_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_uint64( This, p );
}
int framework_t::zrpc_writer_write_uint32v(
    ZRpcWriter * This,
    uint32_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_uint32v( This, p );
}
int framework_t::zrpc_writer_write_uint64v(
    ZRpcWriter * This,
    uint64_t p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_uint64v( This, p );
}
int framework_t::zrpc_writer_write_float(
    ZRpcWriter * This,
    float p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_float( This, p );
}
int framework_t::zrpc_writer_write_double(
    ZRpcWriter * This,
    double p
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_double( This, p );
}
int framework_t::zrpc_writer_write_bytes(
    ZRpcWriter * This,
    const void * s,
    size_t l
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_bytes( This, s, l );
}
int framework_t::zrpc_writer_write_reader(
    ZRpcWriter * This,
    ZRpcReader * reader
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_write_reader( This, reader );
}
int framework_t::zrpc_writer_set_reader(
    ZRpcWriter * This,
    ZRpcReader * reader
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return errno;
    }
    errno = 0;
    return _framework->_string->zrpc_writer_set_reader( This, reader );
}
uint16_t framework_t::zrpc_calc_crc16(
    const char *            data,
    size_t                  data_len
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->zrpc_calc_crc16( data, data_len );
}
uint32_t framework_t::zrpc_calc_crc32(
    const char *            p,
    size_t                  pl
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->zrpc_calc_crc32( p, pl );
}
bool framework_t::str_find_scope(
    const char *    s,
    int             s_len,
    const char *    begin,
    int             begin_len,
    const char *    end,
    int             end_len,
    bool            include_border,
    const_str *     result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        result->ptr = NULL;
        result->len = 0;
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->str_find_scope( s, s_len, begin, begin_len, end, end_len, NULL, 0, include_border, result );
}
bool framework_t::check_mobile( const char * phone, size_t phone_len )
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_string->check_mobile( phone, phone_len );
}
bool framework_t::str_find_scope(
    const char *    s,
    int             s_len,
    const char *    begin,
    int             begin_len,
    const char *    end,
    int             end_len,
    const char *    stop,
    int             stop_len,
    bool            include_border,
    const_str *     result
)
{
    if ( unlikely( NULL == _framework->_string ) ) {
        log_error( "fclass missing" );
        result->ptr = NULL;
        result->len = 0;
        errno = EINVAL;
        return 0;
    }
    errno = 0;
    return _framework->_string->str_find_scope( s, s_len, begin, begin_len, end, end_len, stop, stop_len, include_border, result );
}
bool framework_t::socket_addr(
    const char * host,
    int port,
    bool is_ipv6,
    socket_address_t * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( addr ) {
            memset( addr, 0, sizeof(socket_address_t) );
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr( host, port, is_ipv6, addr );
}
bool framework_t::socket_addr2(
     const struct sockaddr * a,
     int a_len,
     socket_address_t * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( addr ) {
            memset( addr, 0, sizeof(socket_address_t) );
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr2( a, a_len, addr );
}
bool framework_t::socket_addr_from_str(
    const char * str,
    bool is_ipv6,
    socket_address_t * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( addr ) {
            memset( addr, 0, sizeof(socket_address_t) );
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr_from_str( str, is_ipv6, addr );
}
bool framework_t::socket_addr_to_str(
     const struct sockaddr * a,
     int a_len,
     char * buf,
     size_t buf_max
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( buf ) {
            * buf = '\0';
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr_to_str( a, a_len, buf, buf_max );
}
struct sockaddr * framework_t::socket_addr_get(
    socket_address_t * addr,
    int * len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        if ( len ) * len = 0;
        return NULL;
    }
    errno = 0;
    return _framework->_network->socket_addr_get( addr, len );
}
bool framework_t::socket_addr_is_valid(
    socket_address_t * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr_is_valid( addr );
}
bool framework_t::socket_addr_is_ipv6(
    socket_address_t * addr
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_addr_is_ipv6( addr );
}
// buf_len same with sizeof(INET6_ADDRSTRLEN或INET_ADDRSTRLEN)
bool framework_t::socket_ntoa(
    const void * sin_addr_or_sin6_addr,
    bool is_ipv6,
    char * buf,
    size_t buf_len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( buf ) {
            * buf = '\0';
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_ntoa( sin_addr_or_sin6_addr, is_ipv6, buf, buf_len );
}
bool framework_t::socket_aton(
    const char * ip,
    bool is_ipv6,
    void * sin_addr_or_sin6_addr,
    size_t sin_addr_or_sin6_addr_len
)
{
    if ( unlikely( NULL == _framework->_network ) ) {
        log_error( "fclass missing" );
        if ( sin_addr_or_sin6_addr ) {
            memset( sin_addr_or_sin6_addr, 0, sin_addr_or_sin6_addr_len );
        }
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return _framework->_network->socket_aton( ip, is_ipv6, sin_addr_or_sin6_addr, sin_addr_or_sin6_addr_len );
}
void framework_t::analyse_tel_read( parser_t & parser, const_str & word )
{
    memset( & word, 0, sizeof( const_str ) );
    bool is_num = false;
    const_str c;
    while ( true ) {
        c.ptr = parser_read_charset_ptr( & parser, & c.len );
        if ( 0 == c.len ) {
            break;
        }
        if ( 1 == c.len ) {
            if ( c.ptr[ 0 ] > 0 && isdigit( c.ptr[ 0 ] ) ) {
                // number
                if ( 0 == word.len ) {
                    // a new number
                    is_num = true;
                    word = c;
                } else {
                    if ( is_num ) {
                        // a continue number
                        if ( ! analyse_tel_add_to_word( word, c ) ) {
                            break;
                        }
                    } else {
                        // stop
                        parser_back_bytes( & parser, c.len );
                        break;
                    }
                }
            } else if ( '.' == c.ptr[ 0 ] || '-' == c.ptr[ 0 ] ) {
                if ( is_num ) {
                    char c2 = parser_peek( & parser );
                    if ( c2 > 0 && isdigit( c2 ) ) {
                        // decimal
                        // maybe sep by area_id, or 18-24
                        if ( ! analyse_tel_add_to_word( word, c ) ) {
                            break;
                        }
                    } else {
                        // stop
                        parser_back_bytes( & parser, c.len );
                        break;
                    }
                } else {
                    // alone .
                    if ( ! analyse_tel_add_to_word( word, c ) ) {
                        break;
                    }
                    break;
                }
            } else {
                if ( is_num ) {
                    // stop
                    parser_back_bytes( & parser, c.len );
                    break;
                }
                if ( ! analyse_tel_add_to_word( word, c ) ) {
                    break;
                }
                break;
            }
        } else {
            if ( is_num ) {
                // stop
                parser_back_bytes( & parser, c.len );
                break;
            }
            if ( ! analyse_tel_add_to_word( word, c ) ) {
                break;
            }
            break;
        }
    }
    if ( word.len > 7 && word.ptr[ 0 ] > 0 && isdigit( word.ptr[ 0 ] ) ) {
        do {
            const char * p = (const char *)memchr( word.ptr, '-', word.len );
            if ( NULL == p ) {
                break;
            }
            const char * p2 = (const char *)memchr( p + 1, '-', word.ptr + word.len - (p + 1) );
            if ( NULL == p2 ) {
                break;
            }
            ++ p2;
            if ( '1' != * p2 || 11 != ( word.ptr + word.len - p2 ) ) {
                break;
            }
            word.len = (int)(p2 - word.ptr) - 1;
            parser.cur = p2 - 1;
        } while ( 0 );
    }
}
bool framework_t::analyse_tel_add_to_word( const_str & word, const const_str & c )
{
    if ( 0 == word.len ) {
        word = c;
        return true;
    }
    if ( c.ptr != & word.ptr[ word.len ] ) {
        log_error( "!!!!!!!!!!!!!!!!!!!!!!" );
        return false;
    }
    word.len += c.len;
    return true;
}
bool framework_t::analyse_tels( int src_charset, const char * src, size_t src_bytes, std::vector< std::string > & result )
{
    time_t tt;
    result.resize( 0 );
    if ( result.capacity() < 3 ) {
        try {
            result.reserve( 3 );
        } catch ( ... ) {
            log_error( "bad_alloc" );
            return false;
        }
    }
    parser_t parser;
    if ( ! parser_open_charset( & parser, src, (int)src_bytes, src_charset ) ) {
        log_error( "parser_open_charset failed" );
        return false;
    }
    const_str wi;
    wi.ptr = NULL;
    wi.len = 0;
    bool is_tel;
    std::string t;
    while ( true ) {
        analyse_tel_read( parser, wi );
        if ( wi.len <= 0 ) {
            break;
        }
        is_tel = false;
        ///////////////////////////////////////////////////////////////
        do {
            if ( wi.ptr[ 0 ] <= 0 || ! isdigit( wi.ptr[ 0 ] ) ) {
                // not number
                break;
            }
            if ( memchr( wi.ptr, '.', wi.len ) ) {
                // dot 
                break;
            }
            // number, by no dot
            const char * h = (const char *)memchr( wi.ptr, '-', wi.len );
            if ( h ) {
                const char * e = wi.ptr + wi.len;
                const char * h2 = (const char *)memchr( h + 1, '-', e - (h + 1) );
                if ( NULL != h2 ) {
                    // double -
                    break;
                }
            }
            const char *    ptr;
            size_t          len;
            if ( NULL == h ) {
                ptr = wi.ptr;
                len = wi.len;
            } else {
                if ( h - wi.ptr < 3 || wi.ptr[ 0 ] != '0' ) {
                    // area number length < 3, or not leadding by 0
                    break;
                }
                ptr = h + 1;
                len = wi.ptr + wi.len - ptr;
            }
            if ( '1' == ptr[ 0 ] ) {
                // maybe 119, but we ignore 119
                if ( 11 != len ) {
                    // leadding by 1, length not 11
                    break;
                }
                if ( NULL != h ) {
                    // mobile, not area_id
                    wi.ptr = ptr;
                    wi.len = len;
                    h = NULL;
                }
                is_tel = true;
            } else if ( '0' != ptr[ 0 ] ) {
                // maybe 400, 95588... but ignore
                if ( len != 7 && len != 8 ) {
                    // not leadding by 0, china phone number length is 7 or 8
                    break;
                }
                tt = time_from_str( ptr, len );
                if ( 0 == tt ) {
                    // no time
                    is_tel = true;
                }
            } else {
                if ( NULL != h ) {
                    // leadding by 0, must no -
                    break;
                }
                if ( len < 3 + 7 ) {
                    // number leadding by 0, if it's telephone number, 0101234567
                    break;
                }
                is_tel = true;
            }
        } while ( 0 );
        ///////////////////////////////////////////////////////////////
        if ( is_tel ) {
            try {
                t.assign( wi.ptr, wi.ptr + wi.len );
                if ( '1' == t[ 0 ] ) {
                    if ( ! check_mobile( t.c_str(), t.size() ) ) {
                        continue;
                    }
                } else {
                    do {
                        int city_code_len;
                        cn_place_name_item_t * p = fixed_tel_get_city_code( t.c_str(), t.size(), & city_code_len, NULL );
                        if ( NULL == p ) {
                            if ( '0' == t[ 0 ] && '1' == t[ 1 ] && check_mobile( & t[ 1 ], t.size() - 1 ) ) {
                                // 013933445566 -> 13933445566
                                t = t.substr( 1 );
                            } else {
                                // 023456787
                                t.resize( 0 );
                            }
                            break;
                        }
                        std::string tt;
                        tt = t.substr( 0, city_code_len );
                        std::string t2 = & t[ city_code_len ];
                        stdstr_replace( t2, "-", "" );
                        str_trim( t2 );
                        if ( t2.size() <= 6 ) {
                            t = "";
                            break;
                        }
                        tt += "-";
                        tt += t2;
                        t = tt;
                    } while ( 0 );
                    if ( t.empty() ) {
                        continue;
                    }
                }
                // check repeat
                size_t j;
                for ( j = 0; j < result.size(); ++ j ) {
                    if ( t == result[ j ] ) {
                        break;
                    }
                }
                if ( j >= result.size() ) {
                    result.push_back( t );
                }
            } catch ( ... ) {
                log_error( "bad_alloc" );
                result.resize( 0 );
                return false;
            }
        }
    }
    return true;
}

