// This file generate by:
// ./grtool create_module -name abc -tcp_port 10000 -dir ./abc

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

// YOU DON'T NEED TO CHANGE THIS FILE !!!!!!!!!

#ifndef _framework_h_
#define _framework_h_

////////////////////////////////////////////////////////////////////////
//
// The more time you needn't to change this file !
// Your code should appear in the framework.cpp.
//

#include "gr_stdinc.h"
#include "grlib.h"
#include "compiler_switch.h"
#include <stddef.h>    // for size_t
#if defined( WIN32 ) || defined( WIN64 )
typedef int socklen_t;
#else
#include <unistd.h>     // for socklen_t on non windows
#endif

struct gr_http_ctxt_t;
struct gr_proc_ctxt_t;
class tcp_conn_t;

struct proc_binary_ctxt_t
{
    /// framework special data
    gr_proc_ctxt_t *    _framework;
    /// listen port
    int                 port;
    /// socket fd
    int                 fd;
    /// worker id, [0, framework_t::worker_count())
    /// We can set worker count in abc_svr.ini file:
    /// [server]tcp.in.worker_count
    int                 worker_id;

    /// request buffer length, NOT including '\0' charactor
    int                 data_len;
    /// request buffer
    const char *        data;

    ///
    struct sockaddr *   peer;
    /// if in TCP, this is user specific conn, NULL otherwise.
    tcp_conn_t *        conn;
};

struct tcp_accept_ctxt_t
{
    /// listen port
    int                 port;
    /// socket fd
    int                 fd;
    /// worker id, [0, framework_t::worker_count())
    /// We can set worker count in abc_svr.ini file:
    /// [server]tcp.in.worker_count
    int                 worker_id;

    /// user can alloc a tcp_conn_t object binding to a TCP connection
    tcp_conn_t **       conn;
};

struct tcp_close_ctxt_t
{
    /// listen port
    int                 port;
    /// socket fd
    int                 fd;
    /// worker id, [0, framework_t::worker_count())
    /// We can set worker count in abc_svr.ini file:
    /// [server]tcp.in.worker_count
    int                 worker_id;

    /// user tcp_conn_t object
    tcp_conn_t *        conn;
};

struct http_pair_t
{
    // parameter name
    char *              name;
    // parameter value
    char *              value;
};

#ifndef log_error
    #define log_error( fmt, ... ) log_error_inner(__FILE__, __LINE__, __FUNCTION__, (fmt), ##__VA_ARGS__ )
#endif
#ifndef log_info
    #define log_info( fmt, ... )  log_info_inner (__FILE__, __LINE__, __FUNCTION__, (fmt), ##__VA_ARGS__ )
#endif
#ifndef log_debug
    #define log_debug( fmt, ... ) log_debug_inner(__FILE__, __LINE__, __FUNCTION__, (fmt), ##__VA_ARGS__ )
#endif

class framework_t
{
public:

    /*
     * @brief Worker is process or thread
     * @return bool: true: worker is process
     *               false:worker is thread
     */
    bool worker_is_process() const;
    /*
     * @brief Worker Count. We can set this in abc_svr.ini file:
     *        [server]tcp.in.worker_count
     * @return int: must > 0
     */
    int worker_count() const;

    bool http_is_peer_local( gr_http_ctxt_t * http );

private:

    ///////////////////////////////////////////////////////////////////
    //
    // Begin framework special code
    //
public:
    void * debug_alloc( const char * file, int line, const char * func, size_t bytes );
    void * debug_calloc( const char * file, int line, const char * func, size_t bytes );
    void   debug_free( const char * file, int line, const char * func, void * p );
    gr_server_t * get_interface();
    void gr_need_exit();
    int get_port_count() { return get_interface()->ports_count; }
    bool get_port(
        int         port_index,
        int *       port    = NULL,
        bool *      is_tcp  = NULL,
        bool *      is_local= NULL,
        int *       fd      = NULL,
        in_addr *   ip      = NULL
    );
    /*
     * @brief alloc buffer for response package
     * @param[in/out]ctxt : process context
     * @param[in]    bytes: allocate bytes
     * @return void *     : response package buffer,
     *                      NULL if alloc failed
     */
    void * alloc_response(proc_binary_ctxt_t & ctxt, int bytes);
    /*
     * @brief get server worker count
     * @return int : server worker count
     */
    int get_worker_count() const;
    bool is_server_stopping() const;
    bool config_get_bool(const char * section, const char * name, bool default_value);
    int config_get_int(const char * section, const char * name, int default_value);
    const char * config_get_string(const char * section, const char * name, const char * default_value);
    bool config_get_addr(const char * section, const char * name, sockaddr_in & addr);
    /*
     * @function log_error
     * @brief output error log
     * @param[in] fmt : long format string
     * @param[in] ... : parameters
     */
    void log_error_inner(const char * file, int line, const char * func, const char * fmt, ... );
    /*
     * @function log_info
     * @brief output info log
     * @param[in] fmt : long format string
     * @param[in] ... : parameters
     */
    void log_info_inner(const char * file, int line, const char * func, const char * fmt, ... );
    /*
     * @function log_debug
     * @brief output debug log
     * @param[in] fmt : long format string
     * @param[in] ... : parameters
     */
    void log_debug_inner(const char * file, int line, const char * func, const char * fmt, ... );
    void log_va_list(const char * file, int line, const char * func, gr_log_level_t level, va_list valist, const char **  fmt );
    bool start_listen_tcp();
    bool kick_tcp(int fd);
    void * tcp_find_conn(int fd);
    /*
     * @brief get query string field name and value
     * @param[in]  http : http object
     * @param[out] count : query string field count
     * @return http_pair_t * : array of field name & value pair
     */
    http_pair_t * http_get_query_string(gr_http_ctxt_t * http, size_t & count);
    /*
     * @brief get form field name and value
     * @param[in]  http : http object
     * @param[out] count : form field count
     * @param count : form field count
     * @return http_pair_t * : array of field name & value pair
     */
    http_pair_t * http_get_form(gr_http_ctxt_t * http, size_t & count);
    /*
     * @brief get current worker id from http request object
     * @return int : worker id [ 0, get_worker_count )
     */
    int http_get_worker_id(gr_http_ctxt_t * http) const;
    void * http_set_max_response(gr_http_ctxt_t *http, size_t bytes);
    const char * http_get_body(gr_http_ctxt_t * http, size_t & body_len);
    const char * http_get_req(gr_http_ctxt_t * http, const char * name, size_t * value_len = NULL);
    int http_get_req_int(gr_http_ctxt_t * http, const char * name, int default_value);
    long long http_get_req_int64(gr_http_ctxt_t * http, const char * name, long long default_value);
    bool http_get_req_bool(gr_http_ctxt_t * http, const char * name, bool default_value);
    const char * http_get_header(gr_http_ctxt_t * http, const char * name);
    bool http_append(gr_http_ctxt_t * http, const void * data, size_t len);
    bool http_send( gr_http_ctxt_t * http, const void * data, size_t len, const char * content_type);
    bool http_send_gzip( gr_http_ctxt_t * http, const void * data, size_t len, const char * content_type);
    bool http_send_header(gr_http_ctxt_t * http, size_t content_length, const char * content_type);
    bool http_send_header2(gr_http_ctxt_t * http, size_t content_length, const char * content_type, const char * connection, const char * status, const char * additional_headers);
    bool http_send_auth_failed( gr_http_ctxt_t * http, const char * tip, size_t tip_len );
    bool http_auth( gr_http_ctxt_t * http,
                    bool ( * auth_func )( void * param, const char * user, const char * passwd ),
                    void *           auth_func_param );
    int  getpeername( gr_proc_ctxt_t * ctxt, struct sockaddr * addr, socklen_t * addr_len );
    int  getpeername( gr_proc_ctxt_t * ctxt, struct sockaddr_in & addr );
    int  http_getpeername( gr_http_ctxt_t * http, struct sockaddr * addr, socklen_t * addr_len );
    int  http_getpeername( gr_http_ctxt_t * http, struct sockaddr_in & addr );

    int get_errno();
    /**
    * @brief get current exe file path
    * @param [out] char * path: path buffer
    * @param [in] size_t path_len: path buffer capacity, including '\0'
    * @return real path bytes, not including '\0'
    */
    size_t get_exe_path(
        char * path,
        size_t  path_len
    );
    size_t get_exe_dir(
        char *  dir,
        size_t  dir_len,
        bool    add_sep
    );
    /**
     * @brief transform / or \ separate path to current OS separate path
     * @param[in, out] car * path: path
     * @code
           char path[ 256 ] = "./log/today.log";
           gr_path_to_os( path );
     * @endcode
     */
    void path_to_os(char * path);
    bool path_to_os(const char * path, std::string & result);
    void sleep_ms(
        uint32_t ms
    );
    bool is_dir(
        const char * path
    );
    bool is_file(
        const char * path
    );
    unsigned long get_tick_count();
    bool make_dir( const char * dir );
    bool del_dir( const char * dir );
    bool del_file( const char * path );
    atomic_t atomic_fetch_add( int v, atomic_t * dst );
    dll_t dll_open( const char * path );
    dll_t dll_open_absolute( const char * path );
    /**
     * @brief close a dynamic library
     * @param[in] dll_t: dynamic library handle
     */
    void dll_close( dll_t h );
    /**
     * @brief query a function, that export function
     * @param[in] dll_t: dynamic library handle
     * @param[in] const char * func_name: function name 
     */
    void * dll_symbol( dll_t h, const char * func_name );
    /**
     * @brief get user name
     * @param[out]    char * user_name  : user name result buffer, must reserve space for \0
     * @param[in/out] int user_name_len : input user_name buffer len, output real user_name length.
     * @return bool : is it successed.
     */
    bool get_user_name( char * user_name, int * user_name_len );
    /**
     * @brief create event object
     * @param[in] event_t * o event
     * @return bool return true if successed, return false otherwise.
     */
    bool event_create( event_t * o );
    /**
     * @brief destroy event object
     * @param[in] event_t * o event
     */
    void event_destroy( event_t * o );
    /**
     * @brief fire event
     * @param[in] event_t * o event
     * @return bool is it successed
     */
    bool event_alarm( event_t * o );
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
    int event_wait( event_t * o, unsigned int ms );
    void md5_init( MD5_CTX * ctx );
    void md5_update( MD5_CTX * ctx, const unsigned char * buf, unsigned int len );
    void md5_final( MD5_CTX * ctx, unsigned char * digest );
    void md5( const void * data, size_t data_len, char * digest );
    /**
     * @brief get CPU processor core count
     * @return int >= 1
     */
    int processor_count();

    void process_init( proc_t * proc );
    pid_t process_get_pid( proc_t * proc );
    bool process_is_running( proc_t * proc );
    /**
     * @brief fork a new process
     * @param[in] start_routine process rountine
     * @param[in] arg process rountine parameter
     * @return bool return true if successed; otherwise return error code
     */
    bool process_fork(
        proc_t *       process,
        void *         (*start_routine)(void*),
        void *         arg
    );
    /**
     * @brief fork a new process
     * @param process[ out ] : pid
     * @param pipefds[ out ] : pipe
     * @param[in] start_routine process rountine
     * @param[in] arg process rountine parameter
     * @param[in] redirect_stdout
     * @return bool return true if successed; otherwise return error code
     */
    bool cgi_process_fork(
        proc_t *       process,
        void *         (*start_routine)(void*),
        void *         arg,
        bool           redirect_stdout
    );
    /*
     * @brief create a new process[need libbase.so]
     * @param self[ out ] : pid
     * @param cmdline[in] : command line
     * @param is_hide[in] : is application has windows
     * @return bool : is it ok
     */
    bool process_exec( proc_t * self, const char * cmdline, bool is_hide );
    /*
     * @brief create a new CGI process[need libbase.so]
     * @param process[ out ] : pid
     * @param pipe[ out ]    : pipe
     * @param cmdline[in] : command line
     * @param is_hide[in] : is application has windows
     * @return bool : is it ok
     */
    bool cgi_process_exec(
        proc_t *        process,
        const char *    cmdline,
        bool            is_hide
    );
    /*
     * @brief kill a process[need libbase.so]
     * @param process[ in ] : process that will be kill
     * @return bool : is it ok
     */
    bool process_kill( proc_t * self );
    bool process_kill_tree(
        pid_t       pid,
        int *       kill_count,
        int *       fail_count,
        int         max_sub_process
    );
    /**
     * @brief create a pipe object[need libbase.so]
     * @param[out] int fds[ 2 ] : pipe
     * @return bool: is it ok
     */
    bool pipe_create(
        int             fds[ 2 ]
    );
    /**
     * @brief destroy a pipe object[need libbase.so]
     * @param[in/out] int fds[ 2 ] : pipe
     */
    void pipe_destroy(
        int             fds[ 2 ]
    );
    /**
     * @brief read from pipe[need libbase.so]
     * @param[in] int fds[ 2 ] : pipe
     * @param[out] void * buf  : read buffer
     * @param[in]  int    len  : read max len
     * @return readded bytes
     */
    int pipe_read(
        int             fds[ 2 ],
        void *          buf,
        int             len
    );
    /**
     * @brief write to pipe[need libbase.so]
     * @param[in] int fds[ 2 ] : pipe
     * @param[in] void * buf  : buffer to write
     * @param[in]  int    len  : write len
     * @return written bytes
     */
    int pipe_write(
        int             fds[ 2 ],
        const void *    data,
        int             len
    );
    int pipe_read_fd(
        int             fds[ 2 ],
        int *           fd,
        void *          buf,
        int             len
    );
    int pipe_write_fd(
        int             fds[ 2 ],
        int             fd,
        const void *    data,
        int             len
    );
    /**
     * @brief wait for read
     * @param[in] int fds[ 2 ] : pipe
     * @param[in] unsigned int ms wait timeout by ms.
     * @return int  1: have data to read
     *              0: timeout
     *             -1: error
     *             -2: EINTR
     */
    int pipe_wait_for_read(
        int             fds[ 2 ],
        unsigned int    ms
    );
    int write_http_to_pipe(
        int                 fds[ 2 ],
        gr_http_ctxt_t *    http
    );
    int read_http_from_pipe(
        int                 fds[ 2 ],
        pipe_http_t **      result
    );
    /**
     * @brief create fast_pool object
     * @param process[ in ] : concurrent
     * @return fast_poll_t * non NULL if successed
     */
    fast_poll_t *
    fast_poll_create(
        int                     concurrent
    );
    /**
     * @brief destroy fast_pool object
     * @param process[ in ] : concurrent
     */
    void
    fast_poll_destroy(
        fast_poll_t *               poll
    );
    /**
     * @brief set a fd event
     * @param poll[ in ] : fast_poll object
     * @param fd  [ in ] : fd
     * @param data[ in ] : pointer to event info
     */
    bool
    fast_poll_set(
        fast_poll_t *               poll,
        int                         fd,
        const fast_poll_event_t *   data
    );
    /**
     * @brief del a fd event
     * @param poll[ in ] : fast_poll object
     * @param fd  [ in ] : fd
     */
    bool
    fast_poll_del(
        fast_poll_t *               poll,
        int                         fd
    );
    /**
     * @brief same with epoll_wait
     * @param poll[ in ]        : fast_poll object
     * @param events[out]       : result event list buffer
     * @param event_count[ in ] : events parameter max count
     * @param timeout_ms[ in ]  : wait max time
     * @return int : result count of events
     */
    int
    fast_poll_wait(
        fast_poll_t *               poll,
        fast_poll_event_t *         events,
        int                         event_count,
        int                         timeout_ms
    );
    /**
    * @brief add fd for connect
    * @param poll[ in ] : fast_poll object
    * @param fd  [ in ] : fd
    * @param data[ in ] : event info
    * @param addr[ in ] : connect addr
    * @param addr_len[in]:addr bytes
    * @return int : errcode, 0 = successed; < 0 = error; > 0: connected
    */
    int fast_poll_connect(
        fast_poll_t *               poll,
        int                         fd,
        const fast_poll_event_t *   data,
        const struct sockaddr *     addr,
        socklen_t                   addr_len
    );
    void os_thread_init( os_thread_t * self );
    bool os_thread_is_started( const os_thread_t * self );
    bool os_thread_is_need_exit( const os_thread_t * self );
    bool os_thread_is_exited( const os_thread_t * self );
    int os_thread_tid( const os_thread_t * self );
    bool os_thread_start(
        os_thread_t *  self,
        void *      (*start_routine)(void*),
        void *      param
    );
    void os_thread_stop( os_thread_t * self );

    tcp_connector_t *
    tcp_connector_create(
        const tcp_connector_param_t * param
    );
    void
    tcp_connector_destroy(
        tcp_connector_t *   self
    );
    bool
    tcp_connector_add(
        tcp_connector_t *       self,
        int                     fd,
        const struct sockaddr * addr,
        int                     addr_len,
        int                     timeout_ms,
        tcp_connector_result_t  callback,
        void *                  callback_param1,
        void *                  callback_param2
    );
    bool
    tcp_connector_del(
        tcp_connector_t *       self,
        int                     fd
    );
    tcp_sender_t *          tcp_sender_create(
        const tcp_sender_param_t * param
    );
    void                    tcp_sender_destroy(
        tcp_sender_t *      self
    );
    int                     tcp_sender_send(
        tcp_sender_t *      self,
        int                 fd,
        void *              data,
        int                 data_len,
        void *              user_pointer
    );
    int                     tcp_sender_send_http_rsp(
        tcp_sender_t *              self,
        int                         fd,
        void *                      data,
        int                         data_len,
        void *                      user_data,
        const tcp_sender_http_t *   param
    );
    void                    tcp_sender_del(
        tcp_sender_t *      self,
        int                 fd
    );
    int                     socket_create_tcp_v4();
    int                     socket_create_udp_v4();
    /**
     * @brief close socket
     * @param[in] SOCKET sock: socket fd that will be close
     */
    int                     socket_close(
        int sock
    );
    /**
     * @brief Is TCP use delay algorithem?
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isNoDelay: is it no delay? if true,
     *                            single send call will be fire a real send.
     * @return bool: is OK?
     */
    bool                    socket_get_tcp_no_delay(
        int sock,
        bool * isNoDelay
    );
    bool                    socket_set_tcp_no_delay(
        int sock,
        bool isNoDelay
    );
    /**
     * @brief Is TCP use KeepAlive?
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isKeepAlive: is it KeepAlive
     * @return bool: is OK?
     */
    bool                    socket_set_keep_alive(
        int sock,
        bool isKeepAlive
    );
    /**
     * @brief set send buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: send buffer bytes
     * @return bool: is OK?
     */
    bool                    socket_get_send_buf(
        int sock,
        int * bytes
    );
    bool                    socket_set_send_buf(
        int sock,
        int bytes
    );
    /**
     * @brief set recv buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: recv buffer bytes
     * @return bool: is OK?
     */
    bool                    socket_get_recv_buf(
        int sock,
        int * bytes
    );
    bool                    socket_set_recv_buf(
        int sock,
        int bytes
    );
    /**
     * @brief set TTL
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int ttl: TTL
     * @return bool: is OK?
     */
    bool                    socket_set_ttl(
        int sock,
        int ttl
    );
    bool                    socket_set_loopback(
        int sock,
        bool enable
    );
    bool                    socket_get_linger(
        int sock,
        uint16_t * lv
    );
    bool                    socket_set_linger(
        int sock,
        uint16_t linger
    );
    /**
     * @brief if last socket call failed, is it because E_INPROGRESS or E_WOULDBLOCK
     * @param[in] SOCKET sock: SOCKET fd
     * @return bool: yes or no
     */
    bool                    socket_is_pending();
    /**
     * @brief same as socket recv function
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] void * buf: recv buffer
     * @param[in] int bytes: recv buffer bytes
     * @return int: readed bytes, < 0 if failed
     */
    int                     socket_recv(
        int sock,
        void * buf,
        int bytes
    );
    /**
     * @brief same as socket send function
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] void * buf: data pointer that will be send
     * @param[in] int bytes: data bytes
     * @return int: sent bytes
     */
    int                     socket_send(
        int sock,
        const void * buf,
        int bytes
    );
    bool                    socket_recv_fill(
        int sock,
        void * buf,
        int bytes,
        size_t timeout_ms,
        bool * is_timeout
    );
    /**
     * @brief send all data
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] void * buf: data pointer that will be send
     * @param[in] int bytes: data bytes
     * @return bool: is all sent
     */
    bool                    socket_send_all(
        int sock,
        const void * buf,
        int bytes,
        bool is_async_socket,
        size_t timeout_ms
    );
    /**
     * @brief construct a IPV4 address
     * @param[in] const char * host: host
     * @param[in] int port: port
     * @param[out] sockaddr_in * addr: result
     * @return bool: is it OK
     */
    bool                    socket_addr_v4(
        const char * host,
        int port,
        struct sockaddr_in * addr
    );
    bool                    socket_str_2_addr_v4(
        const char * str,
        struct sockaddr_in * addr
    );
    int                     socket_addr_cmp(
        const struct sockaddr * left,
        const struct sockaddr * right,
        int len
    );
    int                     socket_addr_cmp_ip(
        const struct sockaddr * left,
        const struct sockaddr * right,
        int len
    );
    bool                    socket_in_progress();
    bool                    socket_would_block();
    bool                    socket_set_block( int fd, bool is_block );
    int get_ip_type( struct in_addr ip );
    bool socket_get_all_ip( struct in_addr * addrs, size_t * count );
    /**
     * @brief create an unnamed pair of connected socket.\n
     *     The  socketpair()  call creates an unnamed pair of connected sockets
     *     in the specified domain d, of the specified type, and using the
     *     optionally specified protocol.\n
     *     The descriptors used in  referencing  the  new  sockets  are
     *     returned in sv[0] and sv[1].  The two sockets are indistinguishable.
     * @param[in] int d        : domain, AF_INET, AF_LOCAL...
     * @param[in] int type     : SOCK_STREAM, SOCK_DGRAM...
     * @param[in] int protocol : IPPROTO_TCP...
     * @param[out] int fds[2]  : result fds
     */
    int socketpair(int d, int type, int protocol, int fds[2]);
    bool socket_addr(
        const char * host,
        int port,
        bool is_ipv6,
        socket_address_t * addr
    );
    bool socket_addr2(
         const struct sockaddr * a,
         int a_len,
         socket_address_t * addr
    );
    bool socket_addr_from_str(
        const char * str,
        bool is_ipv6,
        socket_address_t * addr
    );
    bool socket_addr_to_str(
         const struct sockaddr * a,
         int a_len,
         char * buf,
         size_t buf_max
    );
    struct sockaddr * socket_addr_get(
        socket_address_t * addr,
        int * len
    );
    bool socket_addr_is_valid(
        socket_address_t * addr
    );
    bool socket_addr_is_ipv6(
        socket_address_t * addr
    );
    // buf_len same with sizeof(INET6_ADDRSTRLEN或INET_ADDRSTRLEN)
    bool socket_ntoa(
        const void * sin_addr_or_sin6_addr,
        bool is_ipv6,
        char * buf,
        size_t buf_len
    );
    bool socket_aton(
        const char * ip,
        bool is_ipv6,
        void * sin_addr_or_sin6_addr,
        size_t sin_addr_or_sin6_addr_len
    );
    bool set_additional_read_fd(
        int         worker_id,
        int         fd,
        void *      param,
        void        ( * callback )( int fd, void * param )
    );
    bool find_argv(
        const char *    key,
        const char **   value,
        size_t *        value_len
    );
    bool find_argv_int(
        const char *    key,
        int *           value
    );

    bool to_array(
        char *          src,
        const char *    sep,
        char **         result,
        int *           result_count
    );
    bool to_const_array(
        const char *    src,
        int             src_len,
        const char *    sep,
        int             sep_len,
        const_str_t *   result,
        int *           result_count
    );
    bool to_pair_array(
        const char *    src,
        int             src_len,
        const char *    row_sep,
        int             row_sep_len,
        const char *    col_sep,
        int             col_sep_len,
        const_pair *    result,
        int *           result_count
    );
    bool str_find_scope(
        const char *    s,
        int             s_len,
        const char *    begin,
        int             begin_len,
        const char *    end,
        int             end_len,
        bool            include_border,
        const_str *     result
    );
    bool str_find_scope(
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
    );
    bool check_mobile( const char * phone, size_t phone_len );
    bool analyse_tels( int src_charset, const char * src, size_t src_bytes, std::vector< std::string > & result );
    // Returns a pointer to a DIR structure appropriately filled in to begin
    // searching a directory.
    DIR* opendir( const char* filespec );
    // Return a pointer to a dirent structure filled with the information on the
    // next entry in the directory.
    struct dirent*	readdir( DIR* dir );
    // Frees up resources allocated by opendir.
    int	closedir( DIR* dir );
    bool load_file( const char * path, std::string & result );
    // return (int64_t)-1 if failed
    int64_t get_file_size( const char * path );
    int place_id_to_city_code( int place_id, int * result, size_t result_max );
    // NetCom              = 1
    // China TeleCom       = 2
    // China UniCom        = 3
    int get_mobile_provider( const char * str, size_t str_len );
    int get_mobile_provider2( const char * str, size_t str_len, int * small_id );
    int get_mobile_place(
        const char *                str,
        size_t                      str_len,
        int *                       provider,
        cn_place_name_item_t **     place,
        int                         place_max
    );
    bool to_vector(
        const std::string & src,
        const std::string & sep,
        std::vector< std::string > & result
    );
    int stdstr_replace( std::string & s, const char * lpszOld, const char * lpszNew );
    bool http_stdstr(
        const char *        url,
        const char *        refer,
        int                 connect_timeout_second,
        int                 recv_timeout_second,
        unsigned int        flags,
        const char *        http_method,
        std::string &       result,
        int *               http_code
    );
    http_t * http_create();
    bool http_set_timeout(
        http_t *            http,
        int                 connect_timeout_second,
        int                 recv_timeout_second
    );
    bool http_set_callback(
        http_t *                http,
        http_data_callback_t    content_callback,
        void *                  content_callback_param,
        http_data_callback_t    header_callback,
        void *                  header_callback_param
    );
    // this info will be lost after http_perform called
    bool http_set_base_security(
        http_t *            http,
        const char *        user,
        const char *        passwd
    );
    // this info will be lost after http_perform called
    bool http_set_url(
        http_t *            http,
        const char *        url,
        const char *        refer
    );
    // this info will be lost after http_perform called
    bool http_set_postfields(
        http_t *            http,
        const char *        fields,
        size_t              fields_bytes = (size_t)-1,
        const char *        content_type = NULL
    );
    // this info will be lost after http_perform called
    bool http_add_multi_post(
        http_t *            http,
        const char *        name,
        const char *        file
    );
    // lost belows data;
    //    http_set_base_security
    //    http_set_url
    //    http_set_postfields
    //    http_add_multi_post
    void http_reset_request(
        http_t *    http
    );
    bool http_perform(
        http_t *            http,
        unsigned int        flags,
        const char *        http_method,
        int *               http_code
    );
    void http_destroy(
        http_t *            http
    );
    gr_package_type_t http_check_type(
        const void *    p,
        int             len
    );
    bool http_check_full(
        const char *    buf,
        int             len,
        bool            is_http_reply,
        bool *          is_error,
        int *           header_offset,
        int *           body_offset,
        int64_t *       content_length
    );
    gr_http_ctxt_t * http_build_req(
        int                 rsp_fd,
        const char *        buf,
        int                 len,
        bool                is_http_reply,
        http_parse_ctxt_t * parse_ctxt     = NULL,
        int                 header_offset  = 0,
        int                 body_offset    = 0,
        int64_t             content_length = 0
    );
    const void * memrchr( const void *s, int c, size_t n );
    const char * memistr( const void * s, int s_len, const void * find, int find_len );
    const char * memstr( const void * s, int s_len, const void * find, int find_len );
    int merge_multi_space(
        char *  str,
        int     str_len,
        bool    add_0
    );
    int merge_multi_chars(
        char *          str,
        int             str_len,
        const char *    from_chars,
        int             from_chars_len,
        char            to_char,
        bool            add_0
    );
    int regex_match(
        const char *                text,
        int                         text_len,
        const char *                regex,
        int                         regex_len,
        regex_match_item_t *        result,
        int                         result_max
    );
    int regex_match_all(
        const char *                text,
        int                         text_len,
        const char *                regex,
        int                         regex_len,
        regex_match_item_t *        result,
        int                         result_max
    );
    void str_trim( std::string & s );
    char * str_trim( char * s, int * len );
    const char * str_trim_const( const char * s, int * len );
    bool base64_encode(
        const void *    input,
        int             input_len,
        int             crlf_len,
        char *          output,
        int *           output_len
    );
    bool base64_decode(
        const char *    input,
        int             input_len,
        void *          output,
        int *           output_len
    );
    bool base64_encode( const void * input, int input_len, int crlf_len, std::string & output );
    bool base64_decode( const char * input, int input_len, std::string & output );
    bool bytes_to_hex(
        const void *    bytes,
        size_t          length,
        char *          result,
        size_t          result_length,
        bool            write_end_char
    );
    bool hex_to_bytes(
        const char *    hex,
        size_t          length,
        void *          result,
        size_t          result_length
    );
    bool hex_to_bytes(
        const char *    hex,
        size_t          length,
        char *          result,
        size_t          result_length,
        bool            write_end_char
    );
    bool hex_to_bytes( const char * hex, size_t length, std::string & result );
    bool bytes_to_hex( const void * bytes, size_t length, std::string & result );
    int url_decode(
        char *          s,
        int             s_len
    );
    bool url_encode(
        const char *    src,
        int             src_len,
        char *          dst,
        int *           dst_len
    );
    bool url_encode_all(
        const char *    src,
        int             src_len,
        char *          dst,
        int *           dst_len
    );
    bool url_encode(
        const char *    src,
        int             src_len,
        std::string &   dst
    );
    bool url_encode_all(
        const char *    src,
        int             src_len,
        std::string &   dst
    );
    bool parse_url(
        const char *        url,
        int                 url_len,
        url_infomation_t *  url_info,
        int                 url_info_bytes,
        int *               query_string_count
    );
    int url_normalize(
        const char *    url,
        int             url_len,
        char *          dest,
        int             dest_len
    );
    bool is_url_valid(
        const char *    url,
        int             url_len,
        bool            english_domain_only
    );
    bool is_part_url_valid(
        const char *    url,
        int             url_len
    );
    bool format_url(
        const char *    url,
        int             url_len,
        const char *    base_url,
        int             base_url_len,
        char *          dest,
        int *           dest_len,
        bool            delete_anchor = true
    );
    void cookie_parse(
        const char *        cookie,
        int                 cookie_len,
        url_pair_t *        result,
        int *               result_len
    );
    int parse_base_url(
        const char *        page_html,
        int                 page_html_len,
        char *              base_url,
        int                 base_url_max
    );
    int parse_urls(
        const char *                page_html,
        int                         page_html_len,
        char *                      base_url,
        int                         base_url_max,
        int *                       pbase_url_len,
        parse_urls_callback_t       callback,
        void *                      callback_param
    );
    snappy_status_t snappy_compress(
        const void *        input,
        size_t              input_length,
        void *              compressed,
        size_t *            compressed_length
    );
    /**
     @brief Given data in "compressed[0..compressed_length-1]" generated by
     * calling the snappy_compress routine, this routine stores
     * the uncompressed data to\n
     *   uncompressed[0..uncompressed_length-1].\n
     @return Returns failure (a value not equal to SNAPPY_OK) if the message
     * is corrupted and could not be decrypted.
     *
     @param[out] uncompressed_length: signals the space available in "uncompressed".
     * If it is not at least equal to the value returned by
     * snappy_uncompressed_length for this stream, SNAPPY_BUFFER_TOO_SMALL
     * is returned. After successful decompression, <uncompressed_length>
     * contains the true length of the decompressed output.
     * Example:\n
     @code
        size_t output_length;
        if (snappy_uncompressed_length(input, input_length, &output_length)
            != SNAPPY_OK) {
          ... fail ...
        }
        char* output = (char*)malloc(output_length);
        if (snappy_uncompress(input, input_length, output, &output_length)
            == SNAPPY_OK) {
          ... Process(output, output_length) ...
        }
        free(output);
     @endcode
     */
    snappy_status_t snappy_uncompress(
        const void *    compressed,
        size_t          compressed_length,
        void *          uncompressed,
        size_t *        uncompressed_length
    );
    /*
     * Returns the maximal size of the compressed representation of
     * input data that is "source_length" bytes in length.
     */
    size_t snappy_max_compressed_length(
        size_t          source_length
    );
    /*
     * REQUIRES: "compressed[]" was produced by snappy_compress()
     * Returns SNAPPY_OK and stores the length of the uncompressed data in
     * *result normally. Returns SNAPPY_INVALID_INPUT on parsing error.
     * This operation takes O(1) time.
     */
    snappy_status_t snappy_uncompressed_length(
        const void *    compressed,
        size_t          compressed_length,
        size_t *        result
    );
    /*
     * Check if the contents of "compressed[]" can be uncompressed successfully.
     * Does not return the uncompressed data; if so, returns SNAPPY_OK,
     * or if not, returns SNAPPY_INVALID_INPUT.
     * Takes time proportional to compressed_length, but is usually at least a
     * factor of four faster than actual decompression.
     */
    snappy_status_t snappy_validate_compressed_buffer(
        const void *    compressed,
        size_t          compressed_length
    );
    /*
         The following utility functions are implemented on top of the
       basic stream-oriented functions. To simplify the interface, some
       default options are assumed (compression level and memory usage,
       standard memory allocation functions). The source code of these
       utility functions can easily be modified if you need special options.
    */
    int zlib_compress(
        void *          dest,
        size_t *        dest_len,
        const void *    source,
        size_t          source_len
    );
    /*
       Compresses the source buffer into the destination buffer.  sourceLen is
       the byte length of the source buffer. Upon entry, destLen is the total
       size of the destination buffer, which must be at least the value returned
       by compressBound(sourceLen). Upon exit, destLen is the actual size of the
       compressed buffer.
         This function can be used to compress a whole file at once if the
       input file is mmap'ed.
         compress returns Z_OK if success, Z_MEM_ERROR if there was not
       enough memory, Z_BUF_ERROR if there was not enough room in the output
       buffer.
    */
    int zlib_compress2(
        void *          dest,
        size_t *        destLen,
        const void *    source,
        size_t          source_len,
        int             level
    );
    /*
       Compresses the source buffer into the destination buffer. The level
       parameter has the same meaning as in deflateInit.  sourceLen is the byte
       length of the source buffer. Upon entry, destLen is the total size of the
       destination buffer, which must be at least the value returned by
       compressBound(sourceLen). Upon exit, destLen is the actual size of the
       compressed buffer.
         compress2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
       memory, Z_BUF_ERROR if there was not enough room in the output buffer,
       Z_STREAM_ERROR if the level parameter is invalid.
    */
    size_t zlib_compress_bound(
        size_t          source_len
    );
    /*
       compressBound() returns an upper bound on the compressed size after
       compress() or compress2() on sourceLen bytes.  It would be used before
       a compress() or compress2() call to allocate the destination buffer.
    */
    int zlib_uncompress(
        void *          dest,
        size_t *        dest_len,
        const void *    source,
        size_t          source_len
    );
    bool compress(
        const void *    data,
        size_t          data_len,
        std::string &   compred_data
    );
    bool uncompress(
        const void *    data,
        size_t          data_len,
        std::string &   uncompr_data
    );
    /*
         Combine two Adler-32 checksums into one.  For two sequences of bytes, seq1
       and seq2 with lengths len1 and len2, Adler-32 checksums were calculated for
       each, adler1 and adler2.  adler32_combine() returns the Adler-32 checksum of
       seq1 and seq2 concatenated, requiring only adler1, adler2, and len2.
    */
    unsigned long crc32(
        unsigned long  crc,
        const void *   buf,
        size_t         len
    );
    int html_extract_content(
        const char *                    html,
        int                             html_len,
        const html_extract_param_t *    param
    );
    const char * charset_id2str(
        int             charset_id
    );
    int charset_str2id(
        const char *   charset
    );
    int charset_check(
        const void *    str,
        int             str_bytes
    );
    int charset_utf8_bytes(
        const char      c
    );
    int charset_convert(
        int             src_type,
        const void *    src,
        int             src_bytes,
        int             dst_type,
        void *          dst,
        int *           dst_bytes
    );
    int charset_convert(
        int                 src_type,
        const void *        src,
        int                 src_bytes,
        int                 dst_type,
        std::string &       dst
    );
    int charset_convert(
        int                 src_type,
        const std::string & src,
        int                 dst_type,
        std::string &       dst
    );
    fingerprint_t * fingerprint_open(
        const char *            path
    );
    void fingerprint_close(
        fingerprint_t *         self
    );
    int fingerprint_html(
        fingerprint_t *         self,
        const char *            html,
        int                     html_len,
        int                     to_charset,
        int                     debug_level,
        fingerdata_t *          result
    );
    int fingerprint_html_file(
        fingerprint_t *         self,
        const char *            html_path,
        int                     to_charset,
        int                     debug_level,
        fingerdata_t *          result
    );
    int fingerprint_similar_percent(
        fingerprint_t *         self,
        int                     charset,
        const fingerdata_t *    left,
        const fingerdata_t *    right
    );
    int fingerprint_keywords(
        fingerprint_t *                 self,
        int                             charset,
        const fingerdata_t *            finger,
        fingerprint_keywords_callback_t callback,
        void *                          callback_param
    );
    /**
     * @brief 16 bytes random ID
     * @param[out] UUID * result data
     * @return bool is it successed
     */
    bool uuid_create(
        char result[ 16 ]
    );
    struct trie_t* trie_create(void);
    struct trie_t* trie_init(const void* p, const size_t size);
    void trie_destroy(struct trie_t* two);
    int trie_insert(struct trie_t* two, const char* str, const size_t len, const int value, const int overwrite);
    int trie_match(struct trie_t* two, const char* str, const size_t len, int* val);
    int trie_matchall(struct trie_t* two, const char* str, const size_t len,  trie_mi* minfo, const size_t mlen);
    size_t trie_allsize(struct trie_t* two);
    void * trie_write(struct trie_t* two, void* p);
    int trie_isgood(struct trie_t* two);
    void trie_walk(struct trie_t* two, void *arg, two_cb cb);
    void trie_walk_dump(struct trie_t* two);
    int trie_feture(struct trie_t* two,
                   const char* str, const size_t len,
                   const char * out_buf_sep, int out_buf_sep_len,
                   char * out_buf, int max_out_buf_len, int * out_buf_len,
                   int max_item_count, int * item_count,
                   trie_fi * items );
    int trie_has_feture(struct trie_t* two, const char* str, const size_t len );
    bool trie_write_file(
        trie_t *        two,
        FILE *          fp
    );
    bool trie_db_build( const char * src_file, const char * dest_dir, const trie_db_build_params_t * params );
    bool trie_db_valid(
        const char *            dir
    );
    trie_db_t * trie_db_open(
        const char *    dir
    );
    void trie_db_close( trie_db_t * db );
    void * trie_db_find( trie_db_t * db, const void * key, int key_len, int * val_len );
    uint32_t trie_db_get_count( trie_db_t * db );
    void * trie_db_get_val( trie_db_t * db, int offset, int * val_len );
    struct trie_t * trie_db_get_index( trie_db_t * db );
    void * trie_db_get_key( trie_db_t * db, int offset, int * key_len );
    bdb_t *         bdb_open( const char * dir );
    bdb_t *         bdb_open_advanced(
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
                    );
    void            bdb_close( bdb_t * db );
    int             bdb_get( bdb_t * db, const void * key, int key_len, void * val, int * val_len );
    int             bdb_set( bdb_t * db, const void * key, int key_len, const void * val, int val_len );
    int             bdb_del( bdb_t * db, const void * key, int key_len );
    int             bdb_flush( bdb_t * db );
    bdb_cursor_t *  bdb_cursor_open( bdb_t * db );
    void            bdb_cursor_close( bdb_cursor_t * self );
    int             bdb_cursor_next(
        bdb_cursor_t *  self,
        void *          key,
        int *           key_len,
        void *          val,
        int  *          val_len
    );
    int             bdb_cursor_find_next(
        bdb_cursor_t *  self,
        const void *    key,
        int             key_len,
        void *          val,
        int *           val_len
    );
    int             bdb_cursor_del( bdb_cursor_t * self );
    void fmap_init(
        fmap_t *    o
    );
    bool fmap_open(
        fmap_t *        o,
        const char *    path,
        size_t          offset,
        size_t          len,
        bool            read_write
    );
    bool fmap_flush(
        fmap_t *        o
    );
    void fmap_close(
        fmap_t * o
    );
    pair_db_t * pair_db_open( const char * dir );
    void pair_db_close( pair_db_t * db );
    int pair_db_get( pair_db_t * db, const void * key, int key_len, void * val, int * val_len );
    int pair_db_set( pair_db_t * db, const void * key, int key_len, const void * val, int val_len );
    int pair_db_del( pair_db_t * db, const void * key, int key_len );
    int keyset_generate(
        const char * src_path,
        const char * src_sep,
        const char * dst_path
    );
    keyset_t * keyset_open( const char * path );
    keyset_t * keyset_open_memory( const void * data, int data_len );
    void keyset_close( keyset_t * self );
    /**
     * @brief find key
     * @param[in] keyset_t * self : open by keyset_open_memory or keyset_open
     * @param[in] const void * key: key ptr
     * @param[in] int key_len     : key bytes
     * @return int: return match key bytes, < 0 if error.
     */
    int keyset_find(
        keyset_t *      self,
        const void *    key,
        int             key_len,
        keyset_item_t * result,
        int             result_max
    );
    int cn_people_name_generate(
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
    );
    cn_people_name_t * cn_people_name_open(int charset);
    void cn_people_name_close(
        cn_people_name_t *  self
    );
    int cn_people_name_find(
        cn_people_name_t *         self,
        const char *               str,
        int                        str_len,
        int *                      charset,
        cn_people_name_item_t *    result,
        int                        result_max
    );
    int cn_people_name_get_sample(
        cn_people_name_t *         self,
        const char *               str,
        int                        str_len,
        int *                      charset,
        cn_people_name_item_t *    result,
        int                        result_max
    );
    int cn_people_name_surname(
        cn_people_name_t *      self,
        const char *            str,
        int                     str_len,
        int *                   charset,
        const char **           suname
    );
    cn_place_name_item_t * fixed_tel_get_city_code(
        const char *    fixed_tel,
        size_t          fixed_tel_len,
        int *           city_code_len,
        int *           place_id
    );
    int analyse_places(
        const char *                gbk_text,
        int                         gbk_text_bytes,
        cn_place_name_item_t **     result,
        int                         max_count
    );
    bool analyse_places_tels(
        const char *                gbk_text,
        int                         gbk_text_bytes,
        cn_place_name_item_t **     places,
        int *                       places_count,
        const_str *                 tels,
        int *                       tels_count
    );
    cn_place_name_item_t * t2260_2013_to_place( const char * str, size_t str_len );
    int cn_place_name_id_compare(
        int                     left,
        int                     right
    );
    cn_place_name_item_t * cn_place_name_parent(
        cn_place_name_item_t *  child
    );
    cn_place_name_item_t * cn_place_name_top_parent(
        cn_place_name_item_t *  child
    );
    bool cn_place_name_check_elder(
        int                     elder_id,
        int                     child_id
    );
    int cn_place_name_child_count(
        cn_place_name_item_t *  parent
    );
    cn_place_name_item_t * cn_place_name_child(
        cn_place_name_item_t *  parent,
        int                     index
    );
    cn_place_name_item_t * cn_place_name_find_by_id(
        int                     node_id
    );
    cn_place_name_item_t * cn_place_name_find_by_name(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   next_node_id,
        int                     priority_elder_id
    );
    size_t cn_place_name_match_all_by_name(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   id_list,
        size_t                  id_list_max,
        int                     priority_elder_id
    );
    size_t cn_place_name_match_part_by_name(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   id_list,
        size_t                  id_list_max,
        int                     priority_elder_id
    );
    highway_info_t * cn_highway_info(
        int G_id
    );
    highway_station_t * cn_highway_by_place_id(
        int &                   place_id,
        int *                   result_count
    );
    fanout2_t * fanout2_create(
        fanout2_param_t *       param
    );
    void fanout2_destroy(
        fanout2_t *             fanout
    );
    fanout2_task_t * fanout2_task_create(
        fanout2_t *             fanout,
        fanout2_callback_t      callback,
        void *                  callback_param
    );
    void * fanout2_task_param(
        fanout2_task_t *        task
    );
    bool fanout2_add_pending_http(
        fanout2_task_t *        task,
        const char *            url,
        int                     url_len,
        const char *            refer,
        int                     refer_len,
        int                     connect_timeout_ms,
        int                     total_timeout_ms,
        fanout2_http_param_t *  param
    );
    void fanout2_task_destroy(
        fanout2_task_t *        task
    );
    bool fanout2_task_start(
        fanout2_task_t *        task
    );
    size_t fanout2_task_request_size(
        fanout2_task_t *        task
    );
    int fanout2_task_get_error_code(
        fanout2_task_t *        task,
        size_t                  index
    );
    const char * fanout2_task_get_url(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                url_len
    );
    const char * fanout2_task_get_rsp(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                rsp_len
    );
    const struct sockaddr_in *
    fanout2_task_get_addr(
        fanout2_task_t *        task,
        size_t                  index
    );
    const char * fanout2_task_get_req(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                req_len
    );
    gr_http_ctxt_t * fanout2_task_get_http_rsp(
        fanout2_task_t *        task,
        size_t                  index
    );
    tcp_channel_t * tcp_channel_create(
        int                     thread_count,
        int                     up_buf_bytes,
        int                     down_buf_bytes,
        int                     concurrent,
        int                     max_conn,
        int                     poll_wait_ms,
        tcp_channel_cb_t        callback
    );
    void tcp_channel_destroy(
        tcp_channel_t * self
    );
    int tcp_channel_connect(
        tcp_channel_t *         self,
        int                     fd,
        const struct sockaddr * addr,
        socklen_t               addr_len,
        void *                  param
    );
    // return value:
    //       0:           connected
    //       <0:          failed
    //       EINPROGRESS: in connecting
    int tcp_channel_async_connect(
        tcp_channel_t *         self,
        int                     fd,
        const struct sockaddr * addr,
        socklen_t               addr_len,
        void *                  param
    );
    int tcp_channel_send(
        tcp_channel_t *         self,
        int                     fd,
        const void *            data,
        int                     data_len,
        uint32_t                wait_ms
    );
    int tcp_channel_pop_recved(
        tcp_channel_t *         self,
        int                     fd,
        int                     len
    );
    int tcp_channel_del(
        tcp_channel_t *         self,
        int                     fd,
        bool                    close_fd
    );
    int gzcompress(
        const void *    data,
        int             data_len,
        void *          zdata,
        int *           zdata_len
    );
    int gzdecompress(
        const void *    zdata,
        int             zdata_len,
        void *          data,
        int *           data_len
    );
    void datetime_now( uint64_t * result );
    bool datetime_make(
        uint64_t *  ticks,
        int         year,
        int         month,
        int         day,
        int         hour,
        int         minute,
        int         second,
        int         ms
    );
    bool datetime_info(
        uint64_t    ticks,
        int *       year,
        int *       month,
        int *       day,
        int *       hour,
        int *       minute,
        int *       second,
        int *       ms
    );
    bool time_info(
        time_t      v,
        int *       year,
        int *       month,
        int *       day,
        int *       hour,
        int *       minute,
        int *       second
    );
    bool get_current_time(
        int *       year,
        int *       month,
        int *       day,
        int *       hour,
        int *       minute,
        int *       second,
        int *       ms
    );
    time_t time_from_str(
        const char *    str,
        int             str_len
    );
    bool time_to_str(
        time_t      v,
        char *      str,
        int *       str_len
    );
    bool time_to_str(
        time_t          v,
        std::string &   str
    );
    bool parser_open_charset(
        parser_t *      parser,
        const void *    ptr,
        int             len,
        int             charset
    );
    bool parser_end(
        parser_t *      parser
    );
    char parser_peek(
        parser_t *      parser
    );
    char parser_read(
        parser_t *      parser
    );
    int parser_read_charset(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    const char * parser_read_charset_ptr(
        parser_t *      parser,
        int *           result_len
    );
    void parser_back(
        parser_t *      parser
    );
    void parser_back_bytes(
        parser_t *      parser,
        size_t          bytes
    );
    int parser_ignore_spaces(
        parser_t *      parser
    );
    int parser_ignore_spaces_tail(
        parser_t *      parser
    );
    int parser_ignore_to(
        parser_t *          parser,
        const char *        stop_chars
    );
    int parser_escape_char(
        parser_t *      parser,
        char *          result
    );
    int parser_read_string(
        parser_t *      parser,
        bool            translate_escape_char,
        char *          result,
        int *           result_len
    );
    int parser_read_whole_string(
        parser_t *      parser,
        bool            translate_escape_char,
        char *          result,
        int *           result_len
    );
    const char * parser_read_string_ptr(
        parser_t *      parser,
        int *           result_len
    );
    int parser_html_escape_char(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    int parser_read_html_string(
        parser_t *      parser,
        bool            entity_decode,
        char *          result,
        int *           result_len
    );
    int parser_read_whole_html_string(
        parser_t *      parser,
        bool            entity_decode,
        char *          result,
        int *           result_len
    );
    const char * parser_read_html_string_ptr(
        parser_t *      parser,
        int *           result_len
    );
    int parser_read_to(
        parser_t *          parser,
        const char *        stop_chars,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    const char * parser_read_ptr_to(
        parser_t *          parser,
        const char *        stop_chars,
        int *               result_len
    );
    int parser_read_word(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    const char *
    parser_read_word_ptr(
        parser_t *          parser,
        int *               result_len
    );
    bool parser_read_last_word(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    int parser_read_alpha(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    int parser_read_int(
        parser_t *      parser,
        int *           result
    );
    int parser_read_number(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    time_t parser_read_datetime_rfc867(
        parser_t *      parser
    );
    const const_str *
    get_sentence_sep_list(
        int             charset,
        int *           count
    );
    const char *
    parser_read_sentence_ptr(
        parser_t *      parser,
        int *           result_len,
        const char **   sep
    );
    void simple_encrypt( void *buf, int buf_len, uint32_t passwd );
    void simple_decrypt( void *buf, int buf_len, uint32_t passwd );
    void binary_set_bit( void * src, size_t witch_bit, bool v );
    bool binary_get_bit( const void * src, size_t witch_bit );
    const unsigned char * binary_find_non_zero_byte( const void * src, size_t src_bytes );
    size_t binary_find_non_zero_bit( const void * src, size_t src_bytes );
    unsigned char byte_set_bit( unsigned char src, unsigned char witch_bit, bool v );
    bool byte_get_bit( unsigned char src, unsigned char witch_bit );
    bool cluster_get_dirty();
    void cluster_set_dirty( bool v );
    bool cluster_save( const char * path, uint32_t * version );
    bool cluster_load( const char * path, uint32_t * version );
    bool cluster_update( const char * path, const char * mem, int mem_bytes, uint32_t * version );
    uint32_t cluster_version();
    cluster_group_t * cluster_find_group(
        const char *    path,
        bool            auto_create
    );
    bool cluster_del_group(
        const char *    path
    );
    bool cluster_del_peer(
        cluster_peer_t * peer
    );
    cluster_peer_t * cluster_find_peer(
        const char * addr
    );
    cluster_peer_t * cluster_group_find_peer(
        cluster_group_t *   group,
        const char *        addr,
        bool                auto_create
    );
    cluster_peer_t * cluster_group_find_peer_by_index(
        cluster_group_t *   group,
        int                 index
    );
    const char * cluster_group_get_name(
        cluster_group_t *   group
    );
    cluster_group_t * cluster_group_get_parent(
        cluster_group_t *   group
    );
    bool cluster_group_get_enable(
        cluster_group_t *   group
    );
    void cluster_group_set_enable(
        cluster_group_t *   group,
        bool                b
    );
    const void * cluster_group_get_property(
        cluster_group_t *   group,
        const char *        name,
        int *               property_len
    );
    bool cluster_group_set_property(
        cluster_group_t *   group,
        const char *        name,
        const void *        property,
        int                 property_len
    );
    int cluster_group_child_groups(
        cluster_group_t *   group,
        cluster_group_t **  result,
        int                 result_max
    );
    int cluster_group_child_peers(
        cluster_group_t *   group,
        cluster_peer_t **   result,
        int                 result_max
    );
    const char * cluster_peer_get_addr(
        cluster_peer_t *    peer
    );
    const struct sockaddr_in * cluster_peer_get_sock_addr(
        cluster_peer_t *    peer
    );
    cluster_group_t * cluster_peer_get_parent(
        cluster_peer_t *    peer
    );
    bool cluster_peer_get_enable(
        cluster_peer_t *    peer
    );
    void cluster_peer_set_enable(
        cluster_peer_t *    peer,
        bool                b
    );
    const void * cluster_peer_get_property(
        cluster_peer_t *    peer,
        const char *        name,
        int *               property_len
    );
    bool cluster_peer_set_property(
        cluster_peer_t *    peer,
        const char *        name,
        const void *        property,
        int                 property_len
    );
    ini_t * ini_create(
        const char * path
    );
    ini_t * ini_create_memory(
        const char * content,
        size_t content_len
    );
    void ini_destroy(
        ini_t * This
    );
    void ini_close(
        ini_t * This
    );
    size_t ini_get_sections_count(
        ini_t * ini
    );
    bool ini_get_sections(
       ini_t * ini,
       const char ** sections,
       size_t * sections_count
    );
    bool ini_get_bool(
        ini_t * ini,
        const char * section,
        const char * name,
        bool def
    );
    int ini_get_int(
        ini_t * ini,
        const char * section,
        const char * name,
        int def
    );
    long long ini_get_int64(
        ini_t * ini,
        const char * section,
        const char * name,
        long long def
    );
    const char * ini_get_string(
        ini_t * This,
        const char * section,
        const char * name,
        const char * def
    );
    bool ini_get_addr(
        ini_t * This,
        const char * section,
        const char * name,
        sockaddr_in & addr
    );
    agile_t * agile_create(
        const char *    addr_list,
        const char *    addr_list_sep,
        int             connect_timeout_s,
        int             recv_timeout_s,
        const char *    user,
        const char *    passwd
    );
    void agile_destroy(
        agile_t *       self
    );
    int agile_get(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version,
        void *          rsp,
        size_t *        rsp_len
    );
    int agile_put(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        const void *    value,
        size_t          value_len,
        uint32_t *      version
    );
    int agile_del(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version
    );
    int agile_exist(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version
    );

    MiniDbConnection * db_connect( const char * uri, const char * user, const char * passwd );
    void db_conn_release( MiniDbConnection * conn );
    bool db_conn_execute_non_query( MiniDbConnection * conn, const char * sql, int64_t * affected );
    MiniDataReader * db_conn_execute_reader( MiniDbConnection * conn, const char * sql, int32_t page_size, int64_t cur_page );
    void db_reader_release( MiniDataReader * reader );
    int db_reader_get_column_count( MiniDataReader * reader );
    int db_reader_get_column_index( MiniDataReader * reader, const char * name );
    bool db_reader_read( MiniDataReader * reader, bool read_page );
    int db_reader_get_int( MiniDataReader * reader, int index, int def );
    int64_t db_reader_get_int64( MiniDataReader * reader, int index, int64_t def );
    double db_reader_get_float( MiniDataReader * reader, int index );
    int64_t db_reader_get_datetime( MiniDataReader * reader, int index );
    bool db_reader_get_string( MiniDataReader * reader, int index, std::string & result );
    bool db_reader_get_binary( MiniDataReader * reader, int index, std::string & result );

    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_package_length  
    //  
    // 说明：  
    //     取得一个数据包的完整长度字节数。  
    //  
    // 参数：  
    //      header - 数据包头指针。  
    // 返回值：  
    //      字节数  
    size_t  
    zrpc_package_length(  
        ZRpcHeader * header  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_open  
    //  
    // 说明：  
    //     打开一个数据包读入器对象  
    //  
    // 参数：  
    //      This        - 调用方管理，可以是未初始化的内存。  
    //      package     - 完整的数据包，必须已经调用过 zrpc_header_in  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_reader_open(  
        ZRpcReader * This,  
        ZRpcHeader * package  
    );  
    int  
    zrpc_reader_open_raw(  
        ZRpcReader * This,  
        const void * data,  
        size_t       len  
    );  
    bool  
    zrpc_reader_is_raw(  
        ZRpcReader *    This  
    );  
    size_t  
    zrpc_reader_get_length(  
        ZRpcReader *    This  
    );  
    void *  
    zrpc_reader_get_package(  
        ZRpcReader *    This,  
        size_t *        length  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_read  
    //  
    // 说明：  
    //     从数据包中拷贝指定长度的数据到调用方管理的缓存，然后向后移动  
    // 数据指针。  
    //     这是一个底层函数，用该函数读的是裸数据包，给熟悉协议的同志使用！  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_reader_open  
    //      ret         - 读出的二进制数据，调用方管理内存  
    //      len         - 需要读出数据长度。  
    // 返回值：  
    //      错误代码。0       表示成功。  
    //               ENODATA 表示没有数据可读  
    //  
    int  
    zrpc_reader_read(  
        ZRpcReader * This,  
        void * ret,  
        size_t len  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_ignore  
    //  
    // 说明：  
    //     从数据包中当前位置开始忽略指定字节的数据，向后移动数据指针。  
    //     这是一个底层函数，用该函数读的是裸数据包，给熟悉协议的同志使用！  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_reader_open  
    //      len         - 需要忽略的数据长度。  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_reader_ignore(  
        ZRpcReader * This,  
        size_t len  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_get_header_size  
    //  
    // 说明：  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_reader_open  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_reader_get_header_size(  
        ZRpcReader * This  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_is_big_endian  
    //  
    // 说明：  
    //     数据是否为网络字节序。  
    //  
    // 参数：  
    // 返回值：  
    //      是否网络字节序  
    //  
    bool  
    zrpc_reader_is_big_endian(  
        ZRpcReader *    This  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_get_curr  
    //  
    // 说明：  
    //     取得读取器中当前数据指针与数据区的剩余数据长度。  
    //     这是一个比 zrpc_reader_read 还底层的函数，它连数据指针都不移动，  
    // 调用方修改数据后需要自己移动数据指针。  
    //     用该函数取的是裸数据包数据指针，给熟悉协议的同志使用！  
    //  
    // 参数：  
    //      This - 当前对象，必须有效。  
    //      len  - 当前还有多少字节数据，调用方管理内存  
    // 返回值：  
    //      当前数据。  
    //  
    void *  
    zrpc_reader_get_curr(  
        ZRpcReader *    This,  
        size_t *        len  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_move_pos  
    //  
    // 说明：  
    //     本函数用于移动指针。  
    //     这是一个直接操作原始数据包的函数，调用方必须要  
    // 知道自己在做什么。  
    //  
    // 参数：  
    //      This - 当前对象，必须有效  
    //      pos  - 要移动的字节数，正数向数据尾端移动指针，负数则向数据开头移动指针。  
    //             本函数不检查调用方传入 pos 参数的正确性。  
    // 返回值：  
    //      成功与否  
    //  
    int  
    zrpc_reader_move_pos(  
        ZRpcReader *    This,  
        long            pos  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_set_pos  
    //  
    // 说明：  
    //     本函数用于设置数据指针的绝对位置。  
    //     这是一个直接操作原始数据包的函数，调用方必须要  
    // 知道自己在做什么。  
    //  
    // 参数：  
    //      This - 当前对象，必须有效  
    //      pos  - 数据指针的位置，不允许小于 sizeof( ZRpcHeader )。  
    // 返回值：  
    //      成功与否  
    //  
    int  
    zrpc_reader_set_pos(  
        ZRpcReader *    This,  
        long            pos  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_reader_read_byte  
    // zrpc_reader_read_uint16  
    // zrpc_reader_read_uint32  
    // zrpc_reader_read_uint32v  
    // zrpc_reader_read_uint64  
    // zrpc_reader_read_uint64v  
    // zrpc_reader_read_float  
    // zrpc_reader_read_double  
    // zrpc_reader_read_time32  
    // zrpc_reader_read_bytes  
    //  
    // 特别注意：zrpc_reader_read_bytes 函数在二进制数据前加了四字节的长度。  
    //  
    // 说明：  
    //     从数据包中读入数据，然后向后移动数据指针到下一个字段的开始处  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_reader_open  
    //      ret         - 读出的整型数据  
    //      s           - 读出的二进制数据指针，调用方无需管理内存，但在  
    //                    下一次操作 reader 之前，需要将数据拷贝出去做以后用。  
    //                    允许为空。  
    //      l           - 二进制数据长度，调用方管理内存。允许为空。  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_reader_read_byte(  
        ZRpcReader * This,  
        byte_t * ret  
    );  
    int  
    zrpc_reader_read_uint16(  
        ZRpcReader * This,  
        uint16_t * ret  
    );  
    int  
    zrpc_reader_read_uint32(  
        ZRpcReader * This,  
        uint32_t * ret  
    );  
    int  
    zrpc_reader_read_uint64(  
        ZRpcReader * This,  
        uint64_t * ret  
    );  
    int  
    zrpc_reader_read_int32v(  
        ZRpcReader * This,  
        int32_t * ret  
    );  
    int  
    zrpc_reader_read_uint32v(  
        ZRpcReader * This,  
        uint32_t * ret  
    );  
    int  
    zrpc_reader_read_uint64v(  
        ZRpcReader * This,  
        uint64_t * ret  
    );  
    int  
    zrpc_reader_read_float(  
        ZRpcReader * This,  
        float * ret  
    );  
    int  
    zrpc_reader_read_double(  
        ZRpcReader * This,  
        double * ret  
    );  
    int  
    zrpc_reader_read_bytes(  
        ZRpcReader * This,  
        const char ** s,  
        size_t * l  
    );  
    int  
    zrpc_writer_open_raw(  
        ZRpcWriter *    This,  
        byte_t *        buff,  
        size_t          capacity,  
        size_t *        length  
    );  
    int  
    zrpc_writer_open_expandable_raw(  
        ZRpcWriter *    This,  
        size_t *        length  
    );  
    int zrpc_writer_close_expandable(  
        ZRpcWriter *    This  
    );  
    bool  
    zrpc_writer_is_raw(  
        ZRpcWriter *    This  
    );  
    int  
    zrpc_writer_set_udp_info(  
        struct ZRpcWriter *         writer,  
        uint16_t                    reply_port  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_set_error  
    //  
    // 说明：  
    //     修改当前数据包为错误数据包。  
    // 该函数专为服务器端功能响应函数设计。  
    //  
    // 参数：  
    // 返回值：  
    //      错误码  
    //  
    int  
    zrpc_writer_set_error(  
        struct ZRpcWriter *         writer,  
        uint32_t                    e  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_is_big_endian  
    //  
    // 说明：  
    //     数据是否为网络字节序。  
    //  
    // 参数：  
    // 返回值：  
    //      是否网络字节序  
    //  
    bool  
    zrpc_writer_is_big_endian(  
        ZRpcWriter *    This  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_get_curr  
    //  
    // 说明：  
    //     取得写入器的当前数据指针与剩余空间。留给熟悉协议细节的高级用户  
    // 使用，便于提高处理速度。  
    //  
    // 参数：  
    // 返回值：  
    //      剩余空间开始位置指针。  
    //  
    void *  
    zrpc_writer_get_curr(  
        ZRpcWriter *    This,  
        size_t *        len  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_add_length  
    //  
    // 说明：  
    //     在使用 zrpc_writer_get_curr 修改数据后，调用  
    // 本函数增减数据包长度。  
    //     这是一个直接操作原始数据包的函数，调用方必须要  
    // 知道自己在做什么。  
    //  
    // 参数：  
    //      This - 当前对象，必须有效  
    //      len  - 要增加的指针，正数向数据尾端移动指针，负数则向数据开头移动指针。  
    //             本函数不检查调用方传入 len 参数的正确性。  
    // 返回值：  
    //      成功与否  
    //  
    int  
    zrpc_writer_add_length(  
        ZRpcWriter *    This,  
        int             len  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_write  
    //  
    // 说明：  
    //     向数据包中拷贝调用方指定的数据，然后向后移动数据指针。  
    //     这是一个底层函数，用该函数写的是裸数据包，给熟悉协议的同志使用！  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_writer_open  
    //      p           - 待写的二进制数据，调用方管理内存  
    //      l           - 待写的二进制数据长度。  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_writer_write(  
        ZRpcWriter * This,  
        const void * p,  
        size_t l  
    );  
    ///////////////////////////////////////////////////////////////////////  
    //  
    // zrpc_writer_write_byte  
    // zrpc_writer_write_uint16  
    // zrpc_writer_write_uint32  
    // zrpc_writer_write_uint64  
    // zrpc_writer_write_uint32v  
    // zrpc_writer_write_uint64v  
    // zrpc_writer_write_float  
    // zrpc_writer_write_double  
    // zrpc_writer_write_time32  
    // zrpc_writer_write_bytes  
    // zrpc_writer_write_reader  
    //  
    // 特别注意：zrpc_writer_write_bytes 函数在二进制数据前加了四字节的长度。  
    //  
    // 说明：  
    //     向数据包中写入数据，然后向后移动数据指针到下一个写入位置的开始处  
    //  
    // 参数：  
    //      This        - 调用方管理，已经调用过 zrpc_writer_open。  
    //      ret         - 待写入的整型数据  
    //      s           - 待写入的二进制数据指针，调用方管理内存。  
    //      l           - s 的长度。  
    // 返回值：  
    //      错误代码。0 表示成功。  
    //  
    int  
    zrpc_writer_write_byte(  
        ZRpcWriter * This,  
        byte_t p  
    );  
    int  
    zrpc_writer_write_uint16(  
        ZRpcWriter * This,  
        uint16_t p  
    );  
    int  
    zrpc_writer_write_int32v(  
        ZRpcWriter * This,  
        int32_t      p  
    );  
    int  
    zrpc_writer_write_uint32(  
        ZRpcWriter * This,  
        uint32_t p  
    );  
    int  
    zrpc_writer_write_uint64(  
        ZRpcWriter * This,  
        uint64_t p  
    );  
    int  
    zrpc_writer_write_uint32v(  
        ZRpcWriter * This,  
        uint32_t p  
    );  
    int  
    zrpc_writer_write_uint64v(  
        ZRpcWriter * This,  
        uint64_t p  
    );  
    int  
    zrpc_writer_write_float(  
        ZRpcWriter * This,  
        float p  
    );  
    int  
    zrpc_writer_write_double(  
        ZRpcWriter * This,  
        double p  
    );  
    int  
    zrpc_writer_write_bytes(  
        ZRpcWriter * This,  
        const void * s,  
        size_t l  
    );  
    int  
    zrpc_writer_write_reader(  
        ZRpcWriter * This,  
        ZRpcReader * reader  
    );  
    int  
    zrpc_writer_set_reader(  
        ZRpcWriter * This,  
        ZRpcReader * reader  
    );  
    uint16_t  
    zrpc_calc_crc16(  
        const char *            data,  
        size_t                  data_len  
    );  
    uint32_t  
    zrpc_calc_crc32(  
        const char *            p,  
        size_t                  pl  
    );  

private:
    void analyse_tel_read( parser_t & parser, const_str & word );
    bool analyse_tel_add_to_word( const_str & word, const const_str & c );
public:
    static framework_t * create_instance(void * framework);
    void destroy_framework_inner();
private:
    friend class application_t;
    framework_t();
    virtual ~framework_t();
    bool init_framework_inner( void * framework );
    struct framework_inner_t;
    framework_inner_t * _framework;
    //
    // End framework special code
    //
    ///////////////////////////////////////////////////////////////////

private:
    // disable copy
    framework_t(const framework_t &);
    const framework_t & operator = (const framework_t &);
};

#endif // #ifndef _framework_h_
