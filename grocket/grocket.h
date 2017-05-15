// YOU DON'T NEED TO CHANGE THIS FILE !!!!!!!!!

/**
 * @file include/grocket.h
 * @author zouyueming(da_ming at hotmail.com)
 * @date 2013/09/24
 * @version $Revision$
 * @brief   server frame header. caller just need this one header file
 * @warning before including this header file, below type must ready:
 *          uint16_t, uint32_t, int64_t, socklen_t, bool, size_t,
 *          sockaddr_in, sockaddr_in6, sockaddr_un.
 *          if C language, must define bool as one byte.
 * Revision History
 *
 * @if  ID       Author       Date          Major Change       @endif
 *  ---------+------------+------------+------------------------------+\n
 *       1     zouyueming   2013-09-24    Created.\n
 *       2     zouyueming   2013-10-25    add is_server_stopping member
 *                                        to gr_server_t\n
 *       3     zouyueming   2013-12-02    delete gr_check function\n
 *       4     zouyueming   2013-12-05    add gr_i_gcom_t,
 *                                        support dynamic C function call\n
 **/
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

#ifndef _GROCKET_INCLUDE_GROCKET_H_
#define _GROCKET_INCLUDE_GROCKET_H_

#if ! defined( WIN32 ) && ! defined( WIN64 )
    #include <sys/un.h>
    #include <netinet/in.h>
    #if defined( __linux )
        #include <semaphore.h>
    #elif defined( __APPLE__ )
        #include <mach/semaphore.h>
        //#include <mach/task.h>    // conflict with thread_create
        #include <mach/mach.h>
    #endif // #if defined( __linux )
#endif // #if ! defined( WIN32 ) && ! defined( WIN64 )
#include <stdarg.h>
#ifdef __cplusplus
    #include <string>
    #include <vector>
#endif // #ifdef __cplusplus

/// GRocket server framework current version
#define GR_SERVER_VERSION       8
/// GRocket server framework support user module lowest version
#define GR_SERVER_LOW_VERSION   8

/// listen port count limit
#define GR_PORT_MAX             16

#ifdef __cplusplus
extern "C" {
#endif

// forward declare
        struct gr_server_t;
typedef struct gr_server_t              gr_server_t;
        struct gr_port_item_t;
typedef struct gr_port_item_t           gr_port_item_t;
        struct gr_proc_ctxt_t;
typedef struct gr_proc_ctxt_t           gr_proc_ctxt_t;
        struct gr_http_pair_t;
typedef struct gr_http_pair_t           gr_http_pair_t;
        struct gr_init_param_t;
typedef struct gr_init_param_t          gr_init_param_t;
        struct gr_term_param_t;
typedef struct gr_term_param_t          gr_term_param_t;
        struct gr_tcp_accept_param_t;
typedef struct gr_tcp_accept_param_t    gr_tcp_accept_param_t;
        struct gr_tcp_close_param_t;
typedef struct gr_tcp_close_param_t     gr_tcp_close_param_t;
        struct gr_version_param_t;
typedef struct gr_version_param_t       gr_version_param_t;
        struct gr_object_t;
typedef struct gr_object_t              gr_object_t;
        struct gr_class_t;
typedef struct gr_class_t               gr_class_t;
        struct gr_library_t;
typedef struct gr_library_t             gr_library_t;
        struct gr_i_server_t;
typedef struct gr_i_server_t            gr_i_server_t;
        struct gr_i_gcom_t;
typedef struct gr_i_gcom_t              gr_i_gcom_t;
        struct gr_i_str_t;
typedef struct gr_i_str_t               gr_i_str_t;
        struct gr_i_network_t;
typedef struct gr_i_network_t           gr_i_network_t;
        struct gr_i_parallel_t;
typedef struct gr_i_parallel_t          gr_i_parallel_t;
        struct gr_i_tool_t;
typedef struct gr_i_tool_t              gr_i_tool_t;
        struct gcom_method_t;
typedef struct gcom_method_t            gcom_method_t;
        struct gcom_method_declare_t;
typedef struct gcom_method_declare_t    gcom_method_declare_t;
        struct gcom_module_t;
typedef struct gcom_module_t            gcom_module_t;
        struct gr_http_ctxt_t;
typedef struct gr_http_ctxt_t           gr_http_ctxt_t;
    
/**
 * @brief log level enumeration
 * @author zouyueming
 * @date 2013/09/24
 */
typedef enum
{
    /// enable all log
    GR_LOG_ALL          = 0,
    /// enable debug or higher log
    GR_LOG_DEBUG        = 1,
    /// enable info or higher log
    GR_LOG_INFO         = 2,
    /// enable warning or higher log
    GR_LOG_WARNING      = 3,
    /// enable error or higher log
    GR_LOG_ERROR        = 4,
    /// enable fatal or higher log
    GR_LOG_FATAL        = 5,
    /// disable log
    GR_LOG_NONE         = 6,

    GR_LOG_LEVEL_COUNT  = 7
} gr_log_level_t;

/**
 * @brief GRocket process type
 * @author zouyueming
 * @date 2013/09/24
 */
typedef enum
{
    /// parent process.
    GR_PROCESS_PARENT   = 1,
    
    /// worker. worker maybe thread, maybe process,
    /// config in [server]tcp.in.worker_type.\n
    /// first worker is GR_PROCESS_WORKER_1, 
    /// second worker is GR_PROCESS_WORKER_1 + 1
    /// ...
    GR_PROCESS_WORKER_1 = 2

} gr_process_type_t;

/**
 * @brief GRocket allow connection use a gr_conn_buddy_t to
 *        store a user data.
 * @author zouyueming
 * @date 2013/09/24
 */
typedef struct gr_conn_buddy_t
{
    union
    {
        int         n;
        long        ln;
        int64_t     n64;
        uint64_t    u64;
        int32_t     n32;
        uint32_t    u32;
        void *      ptr;
    };
    
} gr_conn_buddy_t;

/**
 * @brief GRocket listen port infomation
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_port_item_t
{
    /// listen address
    union
    {
        struct sockaddr         addr;
        struct sockaddr_in      addr4;
        struct sockaddr_in6     addr6;
#if ! defined( WIN32 ) && ! defined( WIN32 )
        struct sockaddr_un      addr_local;
#endif
    };
    /// bytes of addr
    socklen_t                   addr_len;
    
    /// listen socket fd
    int                         fd;
    /// listen port, in host endian
    uint16_t                    port;
    
    /// is it TCP(stream) or UDP(datagram)
    bool                        is_tcp;

    /// is it AF_UNIX socket
    bool                        is_local;
    
} __attribute__ ((aligned (64)));

/**
 * @brief GRocket package type
 * @author zouyueming
 * @date 2013/09/24
 */
typedef enum
{
    /// invalid package
    GR_PACKAGE_ERROR            = 0,
    
    /// HTTP request
    GR_PACKAGE_HTTP_REQ         = 1,
    
    /// HTTP reply
    GR_PACKAGE_HTTP_REPLY       = 2,

    /// GCOM protocol, GCOM is a GRocket private protocol.
    GR_PACKAGE_GCOM             = 3,

    /// user private package, implementation in user module
    /// 好像这个已经不用了  
    GR_PACKAGE_PRIVATE          = 4,

    GR_PACKAGE_TYPE_MAX         = 7

} gr_package_type_t;

/**
 * @brief GRocket package processor context, gr_proc_t and gr_proc_http_t
 *        use this structure.\n
 *        this structure is 64 bytes.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_proc_ctxt_t
{
    /// socket fd:\n
    /// if TCP: connection fd;\n
    /// if UDP: listen fd
    int                         fd;

    /// worker thread/process ID, [0, count - 1]
    short                       worker_id;

    /// listen port, copy from gr_port_item_t, in host endian
    unsigned short              port;


    /// is TCP or UDP
    unsigned char               is_tcp          : 1;

    /// is it AF_UNIX
    unsigned char               is_local        : 1;

    /// package type, see gr_package_type_t
    unsigned char               package_type    : 3;

    /// need disconnect
    unsigned char               need_disconnect : 1;

    unsigned char               _reserved_bits  : 2;

    /// result buffer data start offset
    unsigned char               result_buf_offset;

    char                        _reserved_1[ 2 ];

    /// result buffer capacity
    int                         result_buf_max;


    /// result buffer
    char *                      result_buf;
#if ! S_64
    char                        _no_use_1[ 4 ];
#endif
    /// result buffer data length
    int                         result_buf_len;

    /// request data bytes
    int                         len;
    /// request data
    const char *                data;
#if ! S_64
    char                        _no_use_2[ 4 ];
#endif

    /// pointer to server interface
    gr_server_t *               server;
#if ! S_64
    char                        _no_use_3[ 4 ];
#endif

    /// user data
    gr_conn_buddy_t *           conn_buddy;
#if ! S_64
    char                        _no_use_4[ 4 ];
#endif

    // 56 bytes

    /// pointer to peer addr, if NULL, then user need call getpeername by self.
    struct sockaddr *           peer;
#if ! S_64
    char                        _no_use_5[ 4 ];
#endif

    // 64 bytes

} __attribute__ ((aligned (64)));

/**
 * @brief KV pair, used in HTTP form, header, query_string.\n
 *        this structure is 64 bytes.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_http_pair_t
{
    /// key name
    char *                      name;
    /// value
    char *                      value;

    /// key name bytes, not including end of string charactor
    int                         name_len;
    /// value bytes, not including end of string charactor
    int                         value_len;
};

/**
 * @brief GRocket HTTP package processor context,
 *        gr_proc_http_t use this structure.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_http_ctxt_t
{
    // uint16_t                 hc_is_tcp
    // uint16_t                 hc_is_local
    // uint16_t                 hc_package_type
    // int                      hc_port
    // int                      hc_fd
    // int                      hc_worker_id
    // char *                   hc_result_buf
    // int                      hc_result_buf_max
    // int *                    hc_result_buf_len
    // byte_t                   hc_result_buf_offset
    // bool                     hc_keep_alive
    // bool                     hc_accept_encoding_gzip
    //char *                    method;
    //char *                    version;
    //char *                    directory;
    //char *                    object;
    //char *                    content_type;
    //char *                    user_agent;
    //gr_http_pair_t *          params;
    //size_t                    params_count;
    //gr_http_pair_t *          header;
    //size_t                    header_count;
    //gr_http_pair_t *          form;
    //size_t                    form_count;
    //char *                    body;
    //size_t                    body_len;
    //int                       http_reply_code;

#define hc_is_tcp               base->is_tcp
#define hc_is_local             base->is_local
#define hc_package_type         base->package_type
#define hc_port                 base->port
#define hc_fd                   base->fd
#define hc_worker_id            base->worker_id
#define hc_result_buf           base->result_buf
#define hc_result_buf_max       base->result_buf_max
#define hc_result_buf_len       base->result_buf_len
#define hc_result_buf_offset    base->result_buf_offset
#define hc_keep_alive           keep_alive
#define hc_accept_encoding_gzip accept_encoding_gzip
#define hc_method               method
#define hc_version              version
#define hc_directory            directory
#define hc_object               object
#define hc_content_type         content_type
#define hc_user_agent           user_agent
#define hc_params               params
#define hc_params_count         params_count
#define hc_header               header
#define hc_header_count         header_count
#define hc_form                 form
#define hc_form_count           form_count
#define hc_body                 body
#define hc_body_len             body_len
#define hc_reply_code           http_reply_code
    
    ///////////////////////////////////////////////////////////////////
    // Inner field
    
    gr_proc_ctxt_t *            base;

    //TODO: bit field store in little endian.

    // is need Connection: Keep-Alive, default true
    unsigned char               keep_alive              : 1;

    // HTTP Accept-Encoding : gzip
    unsigned char               accept_encoding_gzip    : 1;

    // is RAW HTTP package, body, body_len
    unsigned char               is_raw_http             : 1;

    unsigned char               _reserved_bits          : 5;

    char                        _reserved_bytes[ 1 ];

    // HTTP code, only use to HTTP reply
    short                       http_reply_code;
    
    // HTTP
    

    // '\0' indicate this is HTTP reply
    char *                      method;

    // HTTP/1.1, HTTP/1.0, HTTP/0.9
    char *                      version;

    // in HTTP reply, directory and object field is empty
    char *                      directory;
    // foo in http://a/foo?a=b
    char *                      object;
    int                         directory_len;
    int                         object_len;

    // Content-Type header value:
    // auto parse content these type:
    //     multipart/form-data
    //     application/x-www-form-urlencoded
    char *                      content_type;
    // User-Agent header value
    char *                      user_agent;

    // query strings
    gr_http_pair_t *            params;
    size_t                      params_count;

    // HTTP headers
    gr_http_pair_t *            header;
    size_t                      header_count;

    // HTTP form fields
    gr_http_pair_t *            form;
    size_t                      form_count;

    // if not application/x-www-form-urlencoded,
    // these two member store raw HTTP body data
    char *                      body;
    size_t                      body_len;

    // server interface
    gr_server_t *               server;
    // user data
    gr_conn_buddy_t *           conn_buddy;

};

///////////////////////////////////////////////////////////////////////
//
// gr_init_t   :   initialize the module
//

/**
 * @brief gr_init_t function parameter data type.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_init_param_t
{
    /// process/thread type,
    gr_process_type_t   proc_type;
    /// GRocket server interface
    gr_server_t *       server;
};

/**
 * @brief init the GRocket module, this is a OPTIONAL function.
 * @param[in] gr_init_param_t * param : init parameter
 * @return int, initialize OK? 0 if successed, failed otherwise.
 * @author zouyueming
 * @date 2013/09/24
 */
typedef int ( * gr_init_t )(
    gr_init_param_t *   param
);

///////////////////////////////////////////////////////////////////////
//
// gr_term_t   :   terminate the module
//

/**
 * @brief gr_term_t function parameter data type.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_term_param_t
{
    /// process/thread type,
    gr_process_type_t   proc_type;
    /// GRocket server interface
    gr_server_t *       server;

};

/**
 * @brief terminate the GRocket module, this is a OPTIONAL function.
 * @param[in] gr_term_param_t * param : terminate parameter
 * @author zouyueming
 * @date 2013/09/24
 */
typedef void ( * gr_term_t )(
    gr_term_param_t *   param
);

///////////////////////////////////////////////////////////////////////
//
// gr_tcp_accept  : after TCP accept, this function will call
//

/**
 * @brief gr_tcp_accept_t function parameter data type.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_tcp_accept_param_t
{
    /// GRocket server interface
    gr_server_t *       server;
    /// listen port info
    gr_port_item_t *    port_info;
    /// per conn user data, NULL if UDP
    gr_conn_buddy_t *   conn_buddy;
    /// worker thread/process id [0, count - 1)
    int                 worker_id;
    /// socket fd
    int                 fd;
};

/**
 * @brief after accept a TCP connection, this function will be call, is a OPTIONAL function.
 * @param[in]  gr_tcp_accept_param_t * param : parameter
 * @param[out] bool * need_disconnect        : if * need_disconnect set to true,
 *                                             GRocket will close the socket.\n
 *                                             default value is FALSE.
 * @author zouyueming
 * @date 2013/09/24
 */
typedef void ( * gr_tcp_accept_t )(
    gr_tcp_accept_param_t * param,
    bool *                  need_disconnect
);

///////////////////////////////////////////////////////////////////////
//
// gr_tcp_close   :   called before close the TCP socket
//

/**
 * @brief gr_tcp_close_t function parameter data type.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_tcp_close_param_t
{
    /// GRocket server interface
    gr_server_t *       server;
    /// listen port info
    gr_port_item_t *    port_info;
    /// per conn user data
    gr_conn_buddy_t *   conn_buddy;
    /// worker thread/process id [0, count - 1)
    int                 worker_id;
    /// socket fd
    int                 fd;
};

/**
 * @brief called before close the TCP socket, is a OPTIONAL function.
 * @param[in]  gr_tcp_close_param_t * param : parameter
 * @author zouyueming
 * @date 2013/09/24
 */
typedef void ( * gr_tcp_close_t )(
    gr_tcp_close_param_t *  param
);
    
///////////////////////////////////////////////////////////////////////
//
// gr_proc_t
//

typedef gr_proc_ctxt_t  gr_proc_param_t;
    
/**
 * @brief called when process a full binary package
 *        ( call by worker process/thread ),\n
 *        is a OPTIONAL function.
 * @param[in]  gr_proc_param_t * param : parameter
 * @param[out] int * processed_len     :
 *             * processed_len < 0: need disconnect connection\n
 *             * processed_len = 0: do nothing, package not full, just recv again\n
 *             * processed_len > 0: data ok, return processed request bytes
 * @author zouyueming
 * @date 2013/09/24
 */
typedef void ( * gr_proc_t )(
    gr_proc_param_t *   param,
    int *               processed_len
);

///////////////////////////////////////////////////////////////////////
//
// gr_poc_http_t
//

typedef gr_http_ctxt_t  gr_http_param_t;

/**
 * @brief called when process a full HTTP package
 *        ( call by worker process/thread ),\n
 *        is a OPTIONAL function.
 * @param[in]  gr_http_ctxt_t * http : HTTP parameter
 * @return bool : is it OK? return false if we want to close connection. 
 * @author zouyueming
 * @date 2013/09/24
 */
typedef bool ( * gr_proc_http_t )(
    gr_http_param_t *   http
);

///////////////////////////////////////////////////////////////////////
//
// gr_config_t
//

/**
 * @brief use this function to avoid the config file\n
 *        is a OPTIONAL function.
 * @param[out] char * buf : config buffer, caller allocated.
 * @param[in]  int buf_max : buffer capacity.
 * @param[out] int buf_len : buffer length.
 * @return bool : is it OK? 
 * @author zouyueming
 * @date 2013/09/24
 */
typedef bool ( * gr_config_t )(
    char * buf,
    int    buf_max,
    int *  buf_len

);
#define GR_CONFIG_FUNC_NAME     "gr_config"

///////////////////////////////////////////////////////////////////////
//

// gr_hotfix_export_t
typedef bool ( * gr_hotfix_export_t )(
    gr_server_t *       server,
    const char *        file_path
);
#define GR_HOTFIX_EXPORT_FUNC_NAME  "gr_hotfix_export"

// gr_hotfix_import_t
typedef bool ( * gr_hotfix_import_t )(
    gr_server_t *       server,
    const char *        file_path
);
#define GR_HOTFIX_IMPORT_FUNC_NAME  "gr_hotfix_import"

// gr_hotfix_cleanup_t
typedef bool ( * gr_hotfix_cleanup_t )(
    gr_server_t *       server
);
#define GR_HOTFIX_CLEANUP_FUNC_NAME "gr_hotfix_cleanup"

///////////////////////////////////////////////////////////////////////
//
// gr_version_t : version negotiation
//

/**
 * @brief gr_version_t function parameter data type.
 * @author zouyueming
 * @date 2013/09/24
 */
struct gr_version_param_t
{
    /// GRocket server interface
    gr_server_t *       server;

    /// user module fill GR_SERVER_VERSION
    int                 gr_version;
    
    /// module give a user global data length,
    /// GRocket framework alloc and put share memory to
    /// user_global member in gr_server_t
    int                 user_global_bytes;
    
    // user module fill these function pointer

    /// initialize the user module, optional.
    gr_init_t           init;
    /// terminate the user module, optional.
    gr_term_t           term;
    /// accept TCP connection callback, optional.
    gr_tcp_accept_t     tcp_accept;
    /// close TCP connection callback, optional.
    gr_tcp_close_t      tcp_close;
    /// process binary package, optional.
    gr_proc_t           proc_binary;
    /// process HTTP package(HTTP request or response), optional.
    gr_proc_http_t      proc_http;

    /// user module version
    int                 module_version;
    gr_hotfix_export_t  hotfix_export;  // optional
    gr_hotfix_import_t  hotfix_import;  // optional
    gr_hotfix_cleanup_t hotfix_cleanup; // optional
    
};

/**
 * @brief GRocket server framework user module interface function. 
 * @param[in/out] gr_version_param_t * param : parameter.
 * @author zouyueming
 * @date 2013/09/24
 */
typedef void ( * gr_version_t )(
    gr_version_param_t *    param
);
#define GR_VERSION_NAME     "gr_version"

///////////////////////////////////////////////////////////////////////
//
// gr_class_t
// gr_object_t
// gr_class_t and gr_object_t didn't have anything to do with GCOM
//

struct gr_object_t
{
    // class object's class
    gr_class_t *    klass;
};

struct gr_class_t
{
    gr_object_t     base;
    
    // if I'm a singleton, then this is singleton instance,
    // NULL if otherwise.
    gr_object_t *   singleton;
    
    // delete the class
    void            ( * destroy_class )( gr_class_t *    self );
    
    // create the class's instance
    gr_object_t *   ( * create_object )( gr_class_t *    self );
    
    // delete the class's instance
    void            ( * destroy_object )( gr_object_t *  object );
};

#define     GR_CLASS_DECLARE_BEGIN( name, interface_type )      \
    struct name##_class_t;                                      \
    typedef struct name##_class_t name##_class_t;               \
    struct name##_object_t;                                     \
    typedef struct name##_object_t name##_object_t;             \
                                                                \
    struct name##_class_t                                       \
    {                                                           \
        union {                                                 \
            gr_class_t      base;                               \
            interface_type  face;                               \
        };

#define     GR_CLASS_DECLARE_OBJECT( name )                     \
    };                                                          \
                                                                \
    struct name##_object_t                                      \
    {                                                           \
    gr_object_t     base;

#define     GR_CLASS_DECLARE_END( name )                        \
    };

#define     GR_CLASS_DECLARE_SINGLETON( name )                  \
    name##_class_t      name##_class_singleton;

#define GR_CLASS_INSTALL_SINGLETON( library, parent, name, id ) \
do {                                                            \
    bool cls_ok = name##_class_construct(                       \
                      & (parent)->name##_class_singleton );     \
    (parent)->name##_class_singleton.base.base.klass            \
        = & (parent)->name##_class_singleton.base;              \
    (parent)->name##_class_singleton.base.singleton             \
        = & (parent)->name##_class_singleton.base.base;         \
    (parent)->name##_class_singleton.base.destroy_class = NULL; \
    (parent)->name##_class_singleton.base.create_object = NULL; \
    (parent)->name##_class_singleton.base.destroy_object= NULL; \
    if ( cls_ok ) {                                             \
        (library)->classes[ (id) ]                              \
            = & (parent)->name##_class_singleton.base;          \
    } else {                                                    \
        (library)->classes[ (id) ] = NULL;                      \
    }                                                           \
} while( false );

///////////////////////////////////////////////////////////////////////
//
// gr_i_server_t
//

#ifndef _fclass_base_atomic_h_
    #if defined( WIN32 ) || defined( WIN64 )
        typedef long volatile               atomic_t;
    #else
        typedef volatile int                atomic_t;
    #endif
    #define ATOMIC_T_LEN                    sizeof( atomic_t )
#endif // #ifndef _fclass_base_atomic_h_
#ifndef _fclass_base_dll_h_
    #if defined(WIN32) || defined(WIN64)
	    typedef	HINSTANCE	                dll_t;
    #else
	    typedef void *		                dll_t;
    #endif
#endif // #ifndef _fclass_base_dll_h_
#ifndef _fclass_base_event_h_
    typedef struct event_t
    {
    #if defined( WIN32 ) || defined( WIN64 )
        HANDLE          cond;
    #elif defined( __APPLE__ ) || defined( __FreeBSD__ )
        semaphore_t     cond;
    #else
        sem_t           cond;
    #endif
        // is event_create called?
        bool            is_inited;
    } event_t;

    #if defined( __APPLE__ ) || defined( __FreeBSD__ )
        #define INFINITE    0xFFFFFFFF  // Infinite timeout
    #elif ! defined( WIN32 ) && ! defined( WIN64 )
        #define INFINITE    0xFFFFFFFF  // Infinite timeout
    #endif
#endif // #ifndef _fclass_base_event_h_
#ifndef _fclass_base_md5_h_
    typedef unsigned int UINT4;
    typedef struct {
      UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
      UINT4 buf[4];                                    /* scratch buffer */
      unsigned char in[64];                              /* input buffer */
    } MD5_CTX;
#endif // #ifndef _fclass_base_md5_h_
#ifndef _fclass_base_thread_h_
    #if defined( WIN32 ) || defined( WIN64 )
        typedef HANDLE      pthread_t;
    #endif
#endif // #ifndef _fclass_base_thread_h_

struct gr_i_server_t
{
    gr_class_t      base;

    const char *( * author )();

    void *      ( * memory_alloc )( size_t bytes );
    void *      ( * memory_calloc )( size_t bytes );    
    void        ( * memory_free )( void * p );

    void *      ( * debug_alloc )( const char * file, int line, const char * func, size_t bytes );
    void *      ( * debug_calloc )( const char * file, int line, const char * func, size_t bytes );    
    void        ( * debug_free )( const char * file, int line, const char * func, void * p );

    // get config item as bool
    bool        ( * config_get_bool )(  const char * section,
                                        const char * name,
                                        bool         default_value );
    
    // get config item as int
    int         ( * config_get_int )(   const char * section,
                                        const char * name,
                                        int          default_value );
    
    // get config item as string
    const char *( * config_get_string )(const char * section,
                                        const char * name,
                                        const char * default_value );
    
    // set max responpse package bytes
    void *      ( * set_max_response )( gr_proc_ctxt_t * ctxt,
                                        size_t           bytes );
    
    // log output
    void        ( * log )(  const char *    file,
                            int             line,
                            const char *    func,
                            gr_log_level_t  level,
                            const char *    fmt,
                            ... );

    void        ( * log_va_list )(
                            const char *    file,
                            int             line,
                            const char *    func,
                            gr_log_level_t  level,
                            va_list         valist,
                            const char **   fmt );

    // manual listen tcp
    bool        ( * start_listen_tcp )();

    // kick tcp
    bool        ( * kick_tcp )( int fd );

    int         ( * getpeername )(          gr_proc_ctxt_t *    ctxt,
                                            struct sockaddr *   addr,
                                            socklen_t *         addr_len );

    int         ( * http_getpeername )(     gr_http_ctxt_t *    http,
                                            struct sockaddr *   addr,
                                            socklen_t *         addr_len );

    void *      ( * tcp_find_conn )( int fd );

    void *      reserved[ 7 ];
    
    void *      ( * http_set_max_response)( gr_http_ctxt_t *http,
                                            size_t          bytes );
    
    const char *( * http_get_req )(     gr_http_ctxt_t *    http,
                                        const char *        name,
                                        size_t *            value_len
                                  );
    
    int         ( * http_get_req_int )( gr_http_ctxt_t *    http,
                                        const char *        name,
                                        int                 default_value );
    
    int64_t     ( * http_get_req_int64)(gr_http_ctxt_t *    http,
                                        const char *        name,
                                        int64_t             default_value );
    
    bool        ( * http_get_req_bool)( gr_http_ctxt_t *    http,
                                        const char *        name,
                                        bool                default_value );
    
    const char *( * http_get_header )(  gr_http_ctxt_t *    http,
                                        const char *        name );
    
    bool        ( * http_append )(  gr_http_ctxt_t *        http,
                                    const void *            data,
                                    size_t                  len );
    
    bool        ( * http_send )(    gr_http_ctxt_t *        http,
                                    const void *            data,
                                    size_t                  len,
                                    const char *            content_type );
    
    bool        ( * http_send_gzip )(   gr_http_ctxt_t *    http,
                                        const void *        data,
                                        size_t              len,
                                        const char *        content_type );

    bool        ( * http_send_header )( gr_http_ctxt_t *    http,
                                        size_t              content_length,
                                        const char *        content_type );
    
    bool        ( * http_send_header2)( gr_http_ctxt_t *    http,
                                        size_t              content_length,
                                        const char *        content_type,
                                        const char *        connection,
                                        const char *        status,
                                        const char *        additional_headers );

    bool        ( * http_send_auth_failed )( gr_http_ctxt_t * http, const char * tip, size_t tip_len );
    
    bool        ( * http_auth )( gr_http_ctxt_t *    http,
                                 bool ( * auth_func )( void * param, const char * user, const char * passwd ),
                                 void *              auth_func_param );

    int         ( * get_errno )();

    /**
    * @brief get current exe file path
    * @param [out] char * path: path buffer
    * @param [in] size_t path_len: path buffer capacity, including '\0'
    * @return real path bytes, not including '\0'
    */
    size_t      ( * get_exe_path )(
        char * path,
        size_t  path_len
    );

    size_t      ( * get_exe_dir )(
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
    void        ( * path_to_os )(
        char * path
    );

    void        ( * sleep_ms )(
        uint32_t ms
    );

    bool        ( * is_dir )(
        const char * path
    );

    bool        ( * is_file )(
        const char * path
    );

    unsigned long   ( * get_tick_count )();

    bool        ( * make_dir )(
        const char * dir
    );

    atomic_t ( * atomic_fetch_add )( int v, atomic_t * dst );

    dll_t       ( * dll_open )( const char * path );

    dll_t       ( * dll_open_absolute )( const char * path );

    /**
     * @brief close a dynamic library
     * @param[in] dll_t: dynamic library handle
     */
    void        ( * dll_close )( dll_t h );

    /**
     * @brief query a function, that export function
     * @param[in] dll_t: dynamic library handle
     * @param[in] const char * func_name: function name 
     */
    void *      ( * dll_symbol )( dll_t h, const char * func_name );
    /**
     * @brief create event object
     * @param[in] event_t * o event
     * @return bool return true if successed, return false otherwise.
     */
    bool        ( * event_create )( event_t * o );
    /**
     * @brief destroy event object
     * @param[in] event_t * o event
     */
    void        ( * event_destroy )( event_t * o );
    /**
     * @brief fire event
     * @param[in] event_t * o event
     * @return bool is it successed
     */
    bool        ( * event_alarm )( event_t * o );
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
    int         ( * event_wait )( event_t * o, unsigned int ms );

    void        ( * md5_init )( MD5_CTX * ctx );
    void        ( * md5_update )( MD5_CTX * ctx, const unsigned char * buf, unsigned int len );
    void        ( * md5_final )( MD5_CTX * ctx, unsigned char * digest );
    void        ( * md5 )( const void * data, size_t data_len, char * digest );

    int         ( * processor_count )();
    /**
     * @brief create a new thread
     * @param[out] thread thread create successed, then write thread_id to thread param.
     * @param[in] start_routine thread rountine
     * @param[in] arg thread rountine parameter
     * @return int return 0 if successed; otherwise return error code
     */
    int         ( * thread_create )(
        pthread_t * thread,
        void *(*start_routine)(void*),
        void * arg
    );

    /**
     * @function thread_join
     * @brief wait for thread stop
     */
    void        ( * thread_join )(
        pthread_t * thread
    );

    int         ( * socket_tcp_v4 )();

    int         ( * socket_udp_v4 )();

    /**
     * @brief close socket
     * @param[in] SOCKET sock: socket fd that will be close
     */
    int         ( * socket_close )(
	    int sock
    );

    /**
     * @brief Is TCP use delay algorithem? 
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isNoDelay: is it no delay? if true,
     *                            single send call will be fire a real send.
     * @return bool: is OK?
     */
    bool        ( * socket_get_tcp_no_delay )(
	    int sock,
	    bool * isNoDelay
    );

    bool        ( * socket_set_tcp_no_delay )(
	    int sock,
	    bool isNoDelay
    );

    /**
     * @brief Is TCP use KeepAlive?
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isKeepAlive: is it KeepAlive
     * @return bool: is OK?
     */
    bool        ( * socket_set_keep_alive )(
	    int sock,
	    bool isKeepAlive
    );

    /**
     * @brief set send buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: send buffer bytes
     * @return bool: is OK?
     */
    bool        ( * socket_get_send_buf )(
	    int sock,
	    int * bytes
    );

    bool        ( * socket_set_send_buf )(
	    int sock,
	    int bytes
    );

    /**
     * @brief set recv buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: recv buffer bytes
     * @return bool: is OK?
     */
    bool        ( * socket_get_recv_buf )(
	    int sock,
	    int * bytes
    );

    bool        ( * socket_set_recv_buf )(
	    int sock,
	    int bytes
    );

    /**
     * @brief set TTL
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int ttl: TTL
     * @return bool: is OK?
     */
    bool        ( * socket_set_ttl )(
	    int sock,
	    int ttl
    );

    bool        ( * socket_set_loopback )(
        int sock,
        bool enable
    );

    /**
     * @brief set sync or async SOCKET
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool is_block: is_block
     * @return bool: is OK?
     */
    bool        ( * socket_set_block )(
	    int sock,
	    bool is_block
    );

    bool        ( * socket_get_linger )(
        int sock,
        uint16_t * lv
    );

    bool        ( * socket_set_linger )(
        int sock,
        uint16_t linger
    );

    /**
     * @brief if last socket call failed, is it because E_INPROGRESS?
     * @param[in] SOCKET sock: SOCKET fd
     * @return bool: yes or no
     */
    bool        ( * socket_in_progress )();

    /**
     * @brief same as socket recv function
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] void * buf: recv buffer
     * @param[in] int bytes: recv buffer bytes
     * @return int: readed bytes, < 0 if failed
     */
    int         ( * socket_recv )(
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
    int         ( * socket_send )(
	    int sock,
	    const void * buf,
	    int bytes
    );

    bool        ( * socket_recv_fill )(
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
    bool        ( * socket_send_all )(
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
    bool        ( * socket_addr_v4 )(
        const char * host,
        int port,
        struct sockaddr_in * addr
    );
    bool ( * find_argv )(
        int             argc,
        char **         argv,
        const char *    key,
        const char **   value,
        size_t *        value_len
    );

    bool ( * find_argv_int )(
        int             argc,
        char **         argv,
        const char *    key,
        int *           value
    );

    /**
     * @brief get user name
     * @param[out]    char * user_name  : user name result buffer, must reserve space for \0
     * @param[in/out] int user_name_len : input user_name buffer len, output real user_name length.
     * @return bool : is it successed.
     */
    bool ( * get_user_name )( char * user_name, int * user_name_len );

    int ( * gzcompress )(
        const void *    data,
        int             data_len,
        void *          zdata,
        int *           zdata_len
    );

    int ( * gzdecompress )(
        const void *    zdata,
        int             zdata_len,
        void *          data,
        int *           data_len
    );

    bool ( * set_additional_read_fd )(
        int             worker_id,
        int             fd,
        void *          param,
        void            ( * callback )( int fd, void * param )
    );

    // tell server: u should exit
    void ( * gr_need_exit )();
};

///////////////////////////////////////////////////////////////////////
//
// GCOM buildin support
//

struct gr_i_gcom_t
{
    gr_class_t      base;

    // alloc a method object
    gcom_method_t * ( * method_alloc )(const char *    str,
                                       void *          func_addr );

    // invoke a method
    bool            ( * method_call )( gcom_method_t * method,
                                       void *          ret,
                                       ... );

    // free a method
    void            ( * method_free )( gcom_method_t * method );

    // get real function pointer
    void *          ( * method_func_addr )( gcom_method_t * method );

    // find declare object by name
    gcom_method_declare_t *
                    ( * find_declare )( const char * name, int name_len, int * declare_bytes );

    // get declare object
    gcom_method_declare_t *
                    ( * method_declare )( gcom_method_t * method );

    // get method object
    gcom_method_t * ( * declare_method )( gcom_method_declare_t * method );

    // declare object bytes
    int             ( * declare_bytes )( gcom_method_declare_t * declare );

    // get method name
    const char *    ( * declare_name )( gcom_method_declare_t * declare );

    // get method owner module name
    const char *    ( * declare_module )( gcom_method_declare_t * declare );

    // get function name in owner module
    const char *    ( * declare_symbol )( gcom_method_declare_t * declare );

    // get return value data type
    const char *    ( * declare_ret )( gcom_method_declare_t * declare );

    // get parameter count
    int             ( * declare_param_count )( gcom_method_declare_t * declare );

    // get parameter data type
    const char *    ( * declare_param )( gcom_method_declare_t *    declare,
                                         int                        param_id
    );

    // build invoke GCOM request package
    bool            ( * build_call_req )(
                        gcom_method_declare_t * declare,
                        const char *            key,
                        uint32_t                user_data,
                        char *                  req,
                        int *                   req_len,
                        ...
    );

    // build query GCOM function name list request package
    bool            ( * build_query_names_req )(
                        const char *            key,
                        uint32_t                user_data,
                        char *                  req,
                        int *                   req_len
    );

    // parse query GCOM function name list response package
    bool            ( * parse_query_names_rsp )(
                        char *                  rsp,
                        int                     rsp_len,
                        uint32_t *              user_data,
                        char **                 names,
                        int *                   names_count
    );

    // build fetch GCOM function declaretion request package
    bool            ( * build_query_declare_req )(
                        const char *            key,
                        uint32_t                user_data,
                        char *                  req,
                        int *                   req_len
    );

    // parse GCOM function declaretion response package
    gcom_method_declare_t *
                    ( * parse_query_declare_rsp )(
                        char *                  rsp,
                        int                     rsp_len,
                        uint32_t *              user_data
    );

    // check the buffer, return true if it a GCOM package
    // is_full is true, if it is a full package
    bool            ( * check_protocol )(
                        const char *            data,
                        int                     data_len,
                        int *                   full_len,
                        bool *                  is_full
    );

    // server side process a GCOM package
    bool            ( * proc_protocol )(
                        const char *            req,
                        int                     req_len,
                        char *                  rsp,
                        int *                   rsp_len
    );

    // server side find method name list
    bool            ( * find_names )(
                        const char *            name,
                        int                     name_len,
                        char *                  rsp,
                        int *                   rsp_bytes
    );

};

///////////////////////////////////////////////////////////////////////
//
// gr_library_t
//

#define GR_LIBRARY_MAGIC        "GL"
#define GR_LIBRARY_VERSION      1
#define GR_LIBRARY_LOW_VERSION  1

struct gr_library_t
{
    // signature. GR_LIBRARY_MAGIC
    char                magic[ 2 ];
    
    // interface version. GR_LIBRARY_VERSION
    unsigned char       grlib_high_version;
    
    // compatible lowest version. GR_LIBRARY_LOW_VERSION
    unsigned char       grlib_low_version;
    
    // classes count capacity
    uint32_t            class_max;
    
    // buildin server object. same with:
    // classes[ GR_CLASS_SERVER ]->singleton
    // just easy to use
    gr_i_server_t *     buildin;
    
    // buildin gcom object. same with:
    // classes[ GR_CLASS_GCOM ]->singleton
    // just easy to use
    gr_i_gcom_t *       gcom;

    // string object. same with:
    // classes[ GR_CLASS_STRING ]->singleton
    // just easy to use
    gr_i_str_t *        string;

    // network object. same with:
    // classes[ GR_CLASS_NETWORK ]->singleton
    // just easy to use
    gr_i_network_t *    network;

    // parallel object. same with:
    // classes[ GR_CLASS_PARALLEL ]->singleton
    // just easy to use
    gr_i_parallel_t *   parallel;

    // tool object. same with:
    // class[ GR_CLASS_TOOL ]->singleton
    // just easy to use
    gr_i_tool_t *       tool;

    // reserve for feature
    unsigned char       reserved[ 124 * sizeof(void*) ];
    
    // classes
    gr_class_t *        classes[ 1 ];
    
};

typedef enum
{
    // server preinside class's ID
    GR_CLASS_SERVER     = 0,
    // GCOM preinside class's ID
    GR_CLASS_GCOM       = 1,
    // string class's id
    GR_CLASS_STRING     = 2,
    // network class's id
    GR_CLASS_NETWORK    = 3,
    // parallel class's id
    GR_CLASS_PARALLEL   = 4,
    // tool class's id
    GR_CLASS_TOOL       = 5,
} gr_class_id_t;

///////////////////////////////////////////////////////////////////////
//
// gr_library_init
//
// parameters:
//     http       : http context
// remark:
//     option functions
//
typedef int ( * gr_library_init_t )(
    gr_library_t *  library
);
#define GR_LIBRARY_INIT_NAME    "gr_library_init"

///////////////////////////////////////////////////////////////////////
//
// gr_server_t
//

#define GR_SERVER_MAGIC         "GS"

struct gr_server_t
{
    // signature. GR_SERVER_MAGIC
    char                magic[ 2 ];
    
    // interface version. GR_SERVER_VERSION
    unsigned char       gr_high_version;
    
    // compatible lowest version. GR_SERVER_LOW_VERSION
    unsigned char       gr_low_version;

    // module's GR_SERVER_VERSION
    unsigned char       gr_user_version;

    // server stopping signature
    volatile bool       is_server_stopping;

    // true if tcp listening
    bool                is_tcp_listening;
    
    // is it running at debug mode
    bool                is_debug;

    // user module version
    int                 module_version;

    // worker process/thread count
    int                 worker_count;
    
    // you can not touch module_inner member
    //TODO: faint, fixed it later!
    void *              module_inner;

    // connection count, size same with atomic_t
#if defined( WIN32 ) || defined( WIN64 )
    volatile long       conn_count;
#else
    volatile int        conn_count;
#endif

    // program parameters
    char **             argv;
    int                 argc;
    
    // listen port info
    int                 ports_count;
    gr_port_item_t      ports[ GR_PORT_MAX ];
    
    // server function library
    gr_library_t *      library;


    // module global data
    size_t              user_global_bytes;
    void *              user_global;

    // server start time
    time_t              start_time;
    
    // current log level. small this level will not output
    gr_log_level_t      log_level;

    // is it Worker is Process ?
    // if this value is false, then Worker is thread
    bool                is_process_worker;

    char                _reserved_3b[ 3 ];

    // reserved must be zero fill
    char                _reserved[ 255 ];
};

#ifdef __cplusplus
}
#endif

#endif // #ifndef _GROCKET_INCLUDE_GROCKET_H_
