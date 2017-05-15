// YOU DON'T NEED TO CHANGE THIS FILE !!!!!!!!!

/**
 * @file include/grlib.h
 * @author zouyueming(da_ming at hotmail.com)
 * @date 2013/06/05
 * @version $Revision$
 * @brief   server library header. caller just need this one header file
 * @warning before including this header file, below type must ready:
 *          uint16_t, uint32_t, int64_t, socklen_t, bool, size_t,
 *          sockaddr_in, sockaddr_in6.
 *          if C language, must define bool as one byte.
 * Revision History
 *
 * @if  ID       Author       Date          Major Change       @endif
 *  ---------+------------+------------+------------------------------+\n
 *       1     zouyueming   2013-06-05    Created.
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

#ifndef _GROCKET_INCLUDE_GRLIB_H_
#define _GROCKET_INCLUDE_GRLIB_H_

#include "grocket.h"
#if defined( WIN32 ) || defined( WIN64 )
    #ifdef _WIN32_WCE
        #include <Ws2tcpip.h>
        #pragma comment( lib, "ws2.lib" )
    #else
        #include <Iphlpapi.h>   // GetAdapterInfo
        #include <Sensapi.h>
        #pragma comment( lib, "Iphlpapi.lib" )
        #pragma comment( lib, "Sensapi.lib" )
        #pragma comment( lib, "ws2_32.lib" )
    #endif
#else
	#include <unistd.h>
	#include <fcntl.h>
	#include <sys/socket.h>
	#include <sys/poll.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <netdb.h>
    #include <sys/types.h>
    #include <dirent.h>

	#if defined(__linux) || defined(__APPLE__) || defined(__FreeBSD__)
        #if ! defined( __ANDROID__ )
		    #include <ifaddrs.h>
        #endif
        #if defined( __linux )
            #include <sys/epoll.h>
        #endif
	#else
		#include <sys/ioctl.h>
		#include <net/if.h>
		#ifdef __sun
			#include <sys/sockio.h>
		#endif
	#endif
#endif
#ifdef __cplusplus
#include <list>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _fclass_base_string_h_
    
    typedef struct const_str
    {
        const char *    ptr;
        int             len;
    } const_str;

    #ifdef __cplusplus
    } // extern "C" {
    static inline bool operator < ( const const_str & left, const const_str & right )
    {
        int len;
        if ( left.len < right.len ) {
            len = left.len;
        } else {
            len = right.len;
        }

        int r = memcmp( left.ptr, right.ptr, len );
        if ( r < 0 ) {
            return true;
        } else if ( r > 0 ) {
            return false;
        }
        return left.len < right.len;
    }
    static inline bool operator == (const const_str & lhd,const const_str & rhd )
    {
        return lhd.len == rhd.len
            && ( lhd.ptr == rhd.ptr || 0 == memcmp( lhd.ptr, rhd.ptr, lhd.len ) );
    }
    extern "C" {
    #endif // #ifdef __cplusplus

    typedef struct const_pair
    {
        const_str   name;
        const_str   value;
    } const_pair;

    typedef struct const_three
    {
        const_str   one;
        const_str   two;
        const_str   three;
    } const_three;

#endif // #ifndef _fclass_base_string_h_

typedef const_str   const_str_t;
typedef const_pair  const_pair_t;

typedef struct regex_match_item_t
{
    int begin;
    int end;
} regex_match_item_t;

typedef const_str_t     url_value_t;
typedef const_pair_t    url_pair_t;

#ifndef ZLIB_H
    #define Z_OK            0
    #define Z_STREAM_END    1
    #define Z_NEED_DICT     2
    #define Z_ERRNO        (-1)
    #define Z_STREAM_ERROR (-2)
    #define Z_DATA_ERROR   (-3)
    #define Z_MEM_ERROR    (-4)
    #define Z_BUF_ERROR    (-5)
    #define Z_VERSION_ERROR (-6)
    /* Return codes for the compression/decompression functions. Negative values
     * are errors, positive values are used for special but normal events.
     */

    #define Z_NO_COMPRESSION         0
    #define Z_BEST_SPEED             1
    #define Z_BEST_COMPRESSION       9
    #define Z_DEFAULT_COMPRESSION  (-1)
    /* compression levels */

#endif // #ifndef ZLIB_H

#ifndef _fclass_base_circle_buf_h_

    typedef struct circle_buf_t
    {
        // capacity = 10

        // 0123456789
        // |        |
        // first   last
        // 0        9

        //   last
        //    3
        //    |
        // 6789012345
        //     |
        //    first
        //     4

        unsigned char * buffer;
        unsigned int    capacity;
        unsigned int    first;
        unsigned int    last;

    } circle_buf_t;

#endif // #ifndef _fclass_base_circle_buf_h_

#ifndef _fclass_base_process_h_
    #if defined( WIN32 ) || defined( WIN64 )
        typedef struct proc_t
        {
            HANDLE              h;
            // true if process, false if thread
            bool                is_process;
        } proc_t;
    #else
        typedef struct proc_t
        {
            pid_t               pid;
            int                 pipe_fds[ 2 ];
        } proc_t;
    #endif

    #if defined( __linux )
        #define MAX_PID_STR_LEN     16
    #else
        #define MAX_PID_STR_LEN     256
    #endif

    typedef enum process_state_t
    {
        PS_UNKNOWN      = 0,
        PS_RUNNING      = 1,
        PS_SLEEP        = 2,
        PS_DISK_SLEEP   = 3,
        PS_STOPPED      = 4,
        PS_ZOMBIE       = 5,
        PS_DEAD         = 6
    } process_state_t;

    typedef struct proc_info_t
    {
        char            cmdline[ 1024 ];
        char            name[ MAX_PID_STR_LEN ];
        int             cmdline_len;
        int             parent_pid;
        process_state_t state;
    } proc_info_t;
#endif // #ifndef _fclass_base_process_h_

#ifndef _fclass_base_proc_monitor_h_
            struct proc_monitor_t;
    typedef struct proc_monitor_t proc_monitor_t;
#endif // #ifndef _fclass_base_proc_monitor_h_

#ifndef _fclass_base_tls_h_
    #if defined( WIN32 ) || defined( WIN64 )
        typedef DWORD           tls_key_t;
        #define TLS_INIT_KEY    TLS_OUT_OF_INDEXES
    #else
        typedef pthread_key_t   tls_key_t;
        #define TLS_INIT_KEY    INT_MAX
    #endif
#endif // #ifndef _fclass_base_tls_h_

#ifndef _fclass_base_thread_h_
    #if defined( WIN32 ) || defined( WIN64 )
        typedef HANDLE      pthread_t;
    #else
        //typedef pthread_t   thread_t;
    #endif
#endif // #ifndef _fclass_base_thread_h_

typedef struct os_thread_t
{
    pthread_t       thread;
    volatile bool   is_started;
    volatile bool   is_exited;
    volatile bool   is_need_exit;
    void *          ( * user_routine )( void * p );
    void *          user_routine_param;
    event_t         start_event;
    int             thread_id;
    bool            start_event_inited;
} os_thread_t;

typedef struct url_infomation_t
{
    url_value_t    scheme;
    url_value_t    host;
    url_value_t    user;
    url_value_t    passwd;
    url_value_t    path;
    url_value_t    query;
    url_value_t    fragment;
    int            port;
    int            query_string_max;
    int            url_len;
    url_pair_t     query_string[ 100 ];
} url_infomation_t;

typedef bool ( * parse_urls_callback_t )(
    void *              callback_param,
    const char *        tag,
    int                 tag_len,
    const char *        url,
    int                 url_len
);

typedef enum
{
    SNAPPY_OK = 0,
    SNAPPY_INVALID_INPUT = 1,
    SNAPPY_BUFFER_TOO_SMALL = 2
} snappy_status_t;

#ifndef _fclass_base_http_h_
            struct http_t;
    typedef struct http_t http_t;
            struct http_parse_buf_t;
    typedef struct http_parse_buf_t http_parse_buf_t;
            struct http_parse_ctxt_t;
    typedef struct http_parse_ctxt_t http_parse_ctxt_t;

    typedef enum
    {
        // use Connection: KeepAlive request header
        HTTP_KEEP_ALIVE     = 0x00000001,
        // include header in response HTTP packet.
        HTTP_RESP_HEADER    = 0x00000002

    } http_flags_t;

    typedef size_t ( * http_data_callback_t )(
        const void *        data,
        size_t              always_1,
        size_t              data_bytes,
        void *              param
    );

    struct http_parse_buf_t
    {
        gr_http_pair_t *    header;
        int                 header_max;

        gr_http_pair_t *    query;
        int                 query_max;

        gr_http_pair_t *    form;
        int                 form_max;

    }  __attribute__ ((aligned (64)));

    struct http_parse_ctxt_t
    {
        http_parse_buf_t    parse_buf;

        gr_proc_ctxt_t      base;
        gr_http_ctxt_t      http;

        int                 header_offset;
        int                 body_offset;
        size_t              http_body_length;

    }  __attribute__ ((aligned (64)));

#endif // #ifndef _fclass_base_http_h_

#ifndef _fclass_base_html_h_

    typedef enum html_extract_mode_t
    {
        HTML_EXTRACT_FOOL   = 1,
        HTML_EXTRACT_SMART  = 2
    } html_extract_mode_t;

    typedef enum html_extract_algorithm_t
    {
        HTML_EXTRACT_CONTENT    = 1,
        HTML_EXTRACT_LIST       = 2
    } html_extract_algorithm_t;

    // if tag is "" and tag_len is 0, 
    // then this is a message for developer
    // maybe you should write text to log
    typedef bool ( * html_extract_callback_t )(
        void *          param,
        int             charset,
        const char *    tag,
        int             tag_len,
        const char *    text,
        int             text_len
    );

    typedef bool ( * fingerprint_keywords_callback_t )(
        void *          param,
        const char *    keyword,
        int             keyword_len
    );

    typedef struct html_extract_param_t
    {
        // CHARSET_UNKNOWN then check myself
        int                         html_from_charset;
        int                         html_to_charset;

        // see html_extract_mode_t
        html_extract_mode_t         mode;

        // see html_extract_algorithm_t
        html_extract_algorithm_t    algorithm;

        // line callback;
        html_extract_callback_t     line_callback;
        void *                      line_param;

        // tag callback
        html_extract_callback_t     tag_callback;
        void *                      tag_param;

        // 0: no debug
        // 1: output extract detail info to log
        // 2: output all detail info to log
        int                         debug_level;

    } html_extract_param_t;

    typedef struct fingerdata_t
    {
        unsigned char   data[ 64 ];
    } fingerdata_t;

            struct fingerprint_t;
    typedef struct fingerprint_t fingerprint_t;

#endif // #ifndef _fclass_base_html_h_

#ifndef _fclass_base_string_h_

    #define CHARSET_UNKNOWN     0
    #define CHARSET_GBK         1
    #define CHARSET_UTF8        2
    #define CHARSET_UCS2LE      3
    #define CHARSET_UCS2BE      4
    #define CHARSET_BIG5        5
    #define CHARSET_EUCJP       6
    #define CHARSET_SJIS        7
    #define CHARSET_EUCKR       8
    #define CHARSET_ISO1        9
    #define CHARSET_WIN1        10
    #define CHARSET_WIN2        11

#endif // #ifndef _fclass_base_string_h_

#ifndef _fclass_base_fast_poll_h_

    #if defined( __linux )
        #if defined( __ANDROID__ )
            #define EPOLLONESHOT    0x40000000
        #endif
    #else
        // yes, linux has real mama, other OS no mama...
        #define EPOLLIN         0x001
        #define EPOLLOUT        0x004
        #define EPOLLERR        0x008
        #define EPOLLONESHOT    0x40000000
    #endif

            struct fast_poll_t;
    typedef struct fast_poll_t fast_poll_t;

            struct fast_poll_event_t;
    typedef struct fast_poll_event_t fast_poll_event_t;

    // this enum's value must same with epoll
    typedef enum
    {
        FAST_POLLIN         = EPOLLIN,
        FAST_POLLOUT        = EPOLLOUT,
        FAST_POLLERR        = EPOLLERR,
        FAST_POLLONESHOT    = EPOLLONESHOT
    } FAST_POLL_EVENT;

    // in Linux, this struct must same with epoll_data
    typedef union
    {
        void *                  ptr;
        int                     fd;
        uint32_t                u32;
        uint64_t                u64;
    } fast_poll_data_t;

    // in Linux, this struct must same with epoll_event
    struct fast_poll_event_t
    {
        uint32_t                events;
        fast_poll_data_t        data;
    #if defined( _OPENWRT )
    };
    #else
    } __attribute__ ((__packed__));
    #endif

#endif // #ifndef _fclass_base_fast_poll_h_

#ifndef _fclass_base_tcp_channel_h_

            struct tcp_channel_t;
    typedef struct tcp_channel_t tcp_channel_t;

    typedef enum tcp_channel_action_t
    {
        TCP_CHANNEL_ERROR       = 0,
        TCP_CHANNEL_RECVED      = 1,
        TCP_CHANNEL_CONNECTED   = 2
    } tcp_channel_action_t;

    typedef int ( * tcp_channel_cb_t )(
        void *                  param,
        int                     fd,
        const char *            data,
        int                     data_len,
        tcp_channel_action_t    action
    );

#endif // #ifndef _fclass_base_tcp_channel_h_

#ifndef _fclass_base_tcp_socket_h_

    #if defined( WIN32 ) || defined( WIN64 )
        #define AF_LOCAL AF_UNIX
    #endif

    #ifdef __sun
	    #define INADDR_NONE (in_addr_t)0xFFFFFFFF
    #endif

    #define IPTYPE_BAD      0
    #define IPTYPE_LAN      1
    #define IPTYPE_PUBLIC   2

    typedef struct socket_address_t
    {
        union
        {
            struct sockaddr_in     addr_v4;
            struct sockaddr_in6    addr_v6;
        };

        bool                is_valid;
        bool                is_v6;

    } socket_address_t;

    #ifdef __cplusplus
        static inline int
        socket_addr_cmp_inline(
            const struct sockaddr * left,
            const struct sockaddr * right,
            int len
        )
        {
            if ( (NULL == left && NULL == right) || 0 == len ) {
                return 0;
            } else if ( NULL == left && right ) {
                return -1;
            } else if ( left && NULL == right ) {
                return 1;
            }

            assert( left && right && len );
            assert( len == (int)sizeof( struct sockaddr_in ) || len == (int)sizeof( struct sockaddr_in6 ) );

            if ( len == (int)sizeof( struct sockaddr_in ) ) {

                struct sockaddr_in * l = (struct sockaddr_in *)left;
                struct sockaddr_in * r = (struct sockaddr_in *)right;

                if ( l->sin_family == r->sin_family ) {
                    if ( l->sin_port == r->sin_port ) {
                        if ( l->sin_addr.s_addr == r->sin_addr.s_addr ) {
                            return 0;
                        } else if ( l->sin_addr.s_addr < r->sin_addr.s_addr ) {
                            return -1;
                        } else {
                            return 1;
                        }
                    } else if ( l->sin_port < r->sin_port ) {
                        return -1;
                    } else {
                        return 1;
                    }
                } else if ( l->sin_family < r->sin_family ) {
                    return -1;
                } else {
                    return 1;
                }

            } else if ( len == (int)sizeof( struct sockaddr_in6 ) ){

                struct sockaddr_in6 * l = (struct sockaddr_in6 *)left;
                struct sockaddr_in6 * r = (struct sockaddr_in6 *)right;

                if ( l->sin6_family == r->sin6_family ) {
                    if ( l->sin6_port == r->sin6_port ) {
                        return memcmp( & l->sin6_addr, & r->sin6_addr, sizeof( l->sin6_addr ) );
                    } else if ( l->sin6_port < r->sin6_port ) {
                        return -1;
                    } else {
                        return 1;
                    }
                } else if ( l->sin6_family < r->sin6_family ) {
                    return -1;
                } else {
                    return 1;
                }
            }

            return 0;
        }

// Fuck VC 2010 !
// 1>grlib.h(552): error C2733: second C linkage of overloaded function 'operator ==' not allowed
// 1>          grlib.h(551) : see declaration of 'operator =='

        } // extern "C"

        static inline bool operator == ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return 0 == socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            );
        }
        static inline bool operator != ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return 0 != socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            );
        }

        static inline bool operator > ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            ) > 0;
        }

        static inline bool operator >= ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            ) >= 0;
        }

        static inline bool operator < ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            ) < 0;
        }

        static inline bool operator <= ( const sockaddr_in & lhd, const sockaddr_in & rhd )
        {
            return socket_addr_cmp_inline(
                (const sockaddr *)& lhd,
                (const sockaddr *)& rhd,
                (int)sizeof( sockaddr_in )
            ) <= 0;
        }

        extern "C" {
    #endif // #ifdef __cplusplus
#endif // #ifndef _fclass_base_tcp_socket_h_

#ifndef _fclass_base_tcp_sender_h_

            struct tcp_sender_t;
    typedef struct tcp_sender_t tcp_sender_t;

            struct tcp_sender_param_t;
    typedef struct tcp_sender_param_t tcp_sender_param_t;

            struct tcp_sender_http_t;
    typedef struct tcp_sender_http_t tcp_sender_http_t;

    // send OK
    #define TCP_SENDER_OK       0
    // send failed
    #define TCP_SENDER_FAILED   2

    typedef void ( * tcp_sender_result_t )(
        void *              param,
        int                 fd,
        char *              data,
        int                 data_len,
        int                 error_code
    );

    struct tcp_sender_param_t
    {
        int                 thread_count;
        int                 concurrent;
        int                 max_conn;
        int                 poll_wait_ms;
        int                 thread_max_waitting_item_count;
        tcp_sender_result_t callback;
        void *              ( * alloc_func )( size_t bytes );
        void                ( * free_func )( void * p );

        bool                enable_fastpoll_in;
        bool                disable_async_send;
        bool                disable_sync_send;
    };

    struct tcp_sender_http_t
    {
        // text/plain ...
        const char *        content_type;
        // close
        const char *        connection;
        // Apache 2.2
        const char *        server;
        bool                enable_gzip;
    };

#endif // #ifndef _fclass_base_tcp_sender_h_

#if ( defined( WIN32 ) || defined( WIN64 ) ) && ! defined( _fclass_base_dir_h_ )

    #if _MSC_VER <= 1200
        typedef long intptr_t;
    #endif

    // dirent structure - used by the dirent.h directory iteration functions
    struct dirent
    {
	    unsigned short	    d_namlen;	// Length of name in d_name.
        #define d_reclen    d_namlen
	    char *              d_name;		// File name.
        unsigned char       d_type;     // 4->directory; 8->file
    };

    // DIR structure - used by the dirent.h directory iteration functions
    typedef struct DIR
    {
	    // disk transfer area for this dir
        WIN32_FIND_DATAA    dd_dta;
	    // dirent struct to return from dir (NOTE: this makes this thread
	    // safe as long as only one thread uses a particular DIR struct at
	    // a time)
	    struct dirent       dd_dir;
	    // _findnext handle
	    HANDLE              dd_handle;
	    //
        //   * Status of search:
	    //   0 = not started yet (next entry to read is first entry)
	    //  -1 = off the end
	    //   positive = 0 based index of next entry
	    //
	    int             dd_stat;
	    // given path for dir with search pattern (struct is extended)
	    char            dd_name[ MAX_PATH ];
    } DIR;

#endif // #if ( defined( WIN32 ) || defined( WIN64 ) ) && ! defined( _fclass_base_dir_h_ )

#ifndef _fclass_base_tcp_connector_h_

            struct tcp_connector_t;
    typedef struct tcp_connector_t tcp_connector_t;
            struct tcp_connector_param_t;
    typedef struct tcp_connector_param_t tcp_connector_param_t;

    // connect OK
    #define TCP_CONNECTOR_OK        0
    // connect timeout
    #define TCP_CONNECTOR_TIMEOUT   1
    // connect failed
    #define TCP_CONNECTOR_FAILED    2

    typedef void ( * tcp_connector_result_t )(
        tcp_connector_t *   self,
        int                 fd,
        void *              param,
        int                 error_code
    );

    struct tcp_connector_param_t
    {
        int     thread_count;
        int     concurrent;
        int     max_conn;
        int     poll_wait_ms;
    };

#endif // #ifndef _fclass_base_tcp_connector_h_

#ifndef _fclass_base_pipe_h_

    typedef struct pipe_http_t
    {
        // socket fd
        int                         fd;

        // worker ID, [0, count - 1]
        short                       worker_id;

        // bind port
        unsigned short              port;

        // is need Connection: Keep-Alive, default true
        bool                        keep_alive;

        // is TCP or UDP
        bool                        is_tcp;

        // AF_UNIX
        bool                        is_local;

        // package type, see gr_package_type_t
        unsigned char               package_type;

        // request data len
        int                         http_len;
    
        // HTTP

        // HTTP code, only use to HTTP reply
        int                         http_reply_code;
    
        // "" indicate this is HTTP reply
        const char *                method;
        int                         method_len;

        // HTTP/1.1, HTTP/1.0, "" indicate this is HTTP/0.9
        const char *                version;
        int                         version_len;

        // in HTTP reply, directory and object field is empty
        const char *                directory;
        int                         directory_len;

        const char *                object;
        int                         object_len;

        // query string
        gr_http_pair_t *            query_string;
        int                         query_string_count;

        // headers
        gr_http_pair_t *            header;
        int                         header_count;

        // form
        gr_http_pair_t *            form;
        int                         form_count;

        const char *                body;
        int                         body_len;

    } pipe_http_t;

#endif // #ifndef _fclass_base_pipe_h_

#ifndef cJSON__h
    /* cJSON Types: */
    #define cJSON_False 0
    #define cJSON_True 1
    #define cJSON_NULL 2
    #define cJSON_Number 3
    #define cJSON_String 4
    #define cJSON_Array 5
    #define cJSON_Object 6
	
    #define cJSON_IsReference 256

    /* The cJSON structure: */
    typedef struct cJSON {
	    struct cJSON *next,*prev;	/* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
	    struct cJSON *child;		/* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */

	    int type;					/* The type of the item, as above. */

	    char *valuestring;			/* The item's string, if type==cJSON_String */
	    int valueint;				/* The item's number, if type==cJSON_Number */
	    double valuedouble;			/* The item's number, if type==cJSON_Number */

	    char *string;				/* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
    } cJSON;

    typedef struct cJSON_Hooks {
          void *(*malloc_fn)(size_t sz);
          void (*free_fn)(void *ptr);
    } cJSON_Hooks;
#endif // #ifndef cJSON__h

#ifndef	_fclass_base_trie_h_

            struct trie_t;
    typedef struct trie_t trie_t;

    typedef struct trie_mi
    {
	    int	pos;
	    int value;
    } trie_mi;

    #define	TWO_TRIE 1

    typedef int (*two_cb) (void *arg, const char *key, const size_t klen, const void *value, const size_t vlen);

    typedef struct trie_fi
    {
        const char *    key;
        int             len;
        int             value;
    } trie_fi;

#endif // #ifndef	_fclass_base_trie_h_

#ifndef _fclass_base_cn_place_name_h_

            struct cn_place_name_item_t;
    typedef struct cn_place_name_item_t cn_place_name_item_t;
            struct highway_info_t;
    typedef struct highway_info_t       highway_info_t;
            struct highway_station_t;
    typedef struct highway_station_t    highway_station_t;

    typedef enum cn_place_type_t
    {  
        PLACE_TYPE_DIRECT   = 1
    } cn_place_type_t;

    struct cn_place_name_item_t
    {
        int                     id;
        uint32_t                type;
        const char *            name;
        size_t                  name_len;
        cn_place_name_item_t *  childs;
        size_t                  child_count;
    };

    struct highway_info_t
    {
        const char *    name;
        int *           stations;
        size_t          stations_count;

    #ifdef __cplusplus
        highway_info_t(const char * _name, int * _stations, size_t _stations_count)
            : name( _name )
            , stations( _stations )
            , stations_count( _stations_count )
        {}

        highway_info_t()
            : stations( NULL )
            , stations_count( 0 )
            , name( NULL )
        {}
    #endif
    };

    struct highway_station_t
    {
        int G_id;
        int station_id;

    #ifdef __cplusplus
        highway_station_t() : G_id( 0 ), station_id( 0 ) {}
        highway_station_t( int id, int _station_id ) : G_id( id ), station_id( _station_id ) {}
    #endif
    };

#endif // #ifndef _fclass_base_cn_place_name_h_

#ifndef	_GROCKET_INDEX_INDEX_H_

            struct trie_t;
            struct trie_db_t;
    typedef struct trie_db_t trie_db_t;
            struct bdb_t;
    typedef struct bdb_t bdb_t;
            struct bdb_cursor_t;
    typedef struct bdb_cursor_t bdb_cursor_t;
            struct pair_db_t;
    typedef struct pair_db_t pair_db_t;
            struct keyset_t;
    typedef struct keyset_t keyset_t;
            struct keyset_item_t;
    typedef struct keyset_item_t keyset_item_t;
            struct trie_db_build_params_t;
    typedef struct trie_db_build_params_t trie_db_build_params_t;

    struct trie_db_build_params_t
    {
        const char *    fields_sep;
    };

    struct keyset_item_t
    {
        const char *    ptr;
        int             len;
        int             value;
    };


#endif // #ifndef _GROCKET_INCLUDE_GRLIB_H_

#ifndef _fclass_base_timers_h_

    #if defined( WIN32 ) || defined( WIN64 )
        // in windows, I see the vast majority of cases the error is less than 1 ms,
        // but the maximum error is 16 ms
        #define TIMERS_ERROR_SCOPE  16
    #else

    #endif

    struct timers;
    typedef struct timers   timers;

    struct timer_node;
    typedef struct timer_node timer_node;

    typedef timers *        timers_t;

    /// timer callback function
    /// @return > 0: auto add next timer
    typedef int ( * timers_callback )( void * param1, void * param2 );

    /// delete timer function
    typedef void ( * timers_free_node_obj )( void * param1 );

    // memory allocation function
    typedef void * ( * timers_malloc )( size_t len );
    typedef void ( * timers_free )( void * p );

#endif // #ifndef _fclass_base_timers_h_

#ifndef _fclass_base_fmap_h_

    typedef struct fmap_t
    {
    #if defined( WIN32 ) || defined( WIN64 )
        HANDLE          fd;
        HANDLE          mfd;
    #endif
    
        unsigned char * ptr;
        size_t          ptr_len;
    
    } fmap_t;

#endif // #ifndef _fclass_base_fmap_h_

#ifndef _fclass_base_fanout2_fanout2_h_

            struct fanout2_t;
    typedef struct fanout2_t fanout2_t;
            struct fanout2_param_t;
    typedef struct fanout2_param_t fanout2_param_t;
            struct fanout2_task_t;
    typedef struct fanout2_task_t fanout2_task_t;
            struct fanout2_http_param_t;
    typedef struct fanout2_http_param_t fanout2_http_param_t;

    struct fanout2_param_t
    {
        int     worker_thread;
        int     max_pending;
    };

    typedef void ( * fanout2_callback_t )(
        fanout2_task_t *        task
    );

    struct fanout2_http_param_t
    {
        const char *            http_body;
        int                     http_body_len;
        const char *            http_additional_header;
        int                     http_additional_header_len;
        bool                    http_need_response_header;
    };

#endif // #ifndef _fclass_base_fanout2_fanout2_h_

#ifndef _fclass_base_cn_people_name_h_

            struct cn_people_name_t;
    typedef struct cn_people_name_t cn_people_name_t;
            struct cn_people_name_item_t;
    typedef struct cn_people_name_item_t cn_people_name_item_t;
            struct cn_people_name_char_item_t;
    typedef struct cn_people_name_char_item_t cn_people_name_char_item_t;

    #define CPN_TYPE_NONE       0
    #define CPN_TYPE_SURNAME    1
    #define CPN_TYPE_SNAME      2
    #define CPN_TYPE_DNAME1     3
    #define CPN_TYPE_DNAME2     4
    #define CPN_TYPE_IMPORTANT  5

    #define CN_PEOPLE_NAME_CHAR_LEN_SHIFT   4
    #define CN_PEOPLE_NAME_CHAR_MAX         15 // ( 1 << CN_PEOPLE_NAME_CHAR_LEN_SHIFT - 1 )

    #pragma pack( push, 1 )
    struct cn_people_name_char_item_t
    {
        unsigned char               len         : CN_PEOPLE_NAME_CHAR_LEN_SHIFT;

        unsigned char               type        : 3;

        unsigned char               _reserved   : 1;
    };
    #pragma pack( pop )

    struct cn_people_name_item_t
    {
        const char *                ptr;
        int                         len;
        int                         value;
        unsigned char               char_count;
        cn_people_name_char_item_t  char_items[ CN_PEOPLE_NAME_CHAR_MAX ];
    };

#endif // #ifndef _fclass_base_cn_people_name_h_

#ifndef _fclass_base_parser_h_

    typedef struct parser_t
    {
        const char *    begin;
        const char *    end;
        const char *    cur;
        int             charset;

    } parser_t;

#endif // #ifndef _fclass_base_parser_h_

#ifndef _fclass_base_cluster_h_

            struct cluster_group_t;
    typedef struct cluster_group_t cluster_group_t;
            struct cluster_peer_t;
    typedef struct cluster_peer_t cluster_peer_t;

#endif // #ifndef _fclass_base_cluster_h_

#ifndef _fclass_base_ini_h_

            struct ini_t;
    typedef struct ini_t ini_t;

#endif // #ifndef _fclass_base_ini_h_

#ifndef _fclass_base_agile_h_

            struct agile_t;
    typedef struct agile_t agile_t;

#endif // #ifndef _fclass_base_agile_h_

        struct MiniDbConnection;
typedef struct MiniDbConnection MiniDbConnection;
        struct MiniDataReader;
typedef struct MiniDataReader MiniDataReader;

#ifndef _fclass_rpc_zrpc_h_

    ///////////////////////////////////////////////////////////////////////
    //
    // Forward declares
    //

    struct ZRpcHeader;
    typedef struct ZRpcHeader           ZRpcHeader;

    struct ZRpcCallHeader;
    typedef struct ZRpcCallHeader       ZRpcCallHeader;

    struct ZRpcReplyHeader;
    typedef struct ZRpcReplyHeader      ZRpcReplyHeader;

    struct ZRpcReader;
    typedef struct ZRpcReader           ZRpcReader;

    struct ZRpcWriter;
    typedef struct ZRpcWriter           ZRpcWriter;

    ///////////////////////////////////////////////////////////////////////
    //
    // Macro declares
    //

    // ZRpcHeader 中 magic 字段的值  
    #define ZRPC_MAGIC                  "ZR"
    #define ZRPC_MAGIC_LEN              2

    // ZRpcHeader 中 version 字段的值  
    #define ZRPC_VERSION                3

    // ZRpc 最大数据部分长度（不包括 ZRpcHeader）  
    #define ZRPC_MAX_DATA_LENGTH        0xFFFF

    // ZRpc 最大包长度，包括 ZRpcHeader
    #define ZRPC_MAX_LENGTH             ( sizeof( ZRpcHeader ) + ZRPC_MAX_DATA_LENGTH )


    // ZRpc 错误状态数据包数据区长度  
    #define ZRPC_ERROR_PKG_DATA_LENGTH  4

    // ZRpc 错误状态数据包完整长度  
    #define ZRPC_ERROR_PKG_LENGTH       ( sizeof( ZRpcHeader ) + ZRPC_ERROR_PKG_DATA_LENGTH )


    ///////////////////////////////////////////////////////////////////////
    //
    // ZRpcHeader
    //
    //     所有数据包的包头  
    //
    // 定义：  
    //
    //     [数据区] - 数据包中 ZRpcHeader 以外的部分叫数据区。数据压缩与加密都  
    //                只在数据区中操作。  
    //                比如：data_length 字段为数据区长度。也就是从 ZRpcHeader
    //                后第一个字节到当前数据包结束之间的长度做为 data_length 值。  
    //
    // TODO：  
    //     *     为了方便使用，数据包中用位域来声明不到 1 字节的数据，对于不同  
    //       的编译器可能需要调整这些字段的顺序才能保证协议在某些编译器上的一致性，  
    //       但这不会影响任何以前的程序。  
    //
    //     *     目前没提供对 ZRpcHeader 的数据有效性检验机制。  
    //
    // 提示：  
    //         目前 ZRpcHeader 声明中，与字节序相关的只有 data_length 字段。  
    //     也就是说，如果接收方发现数据包的字节序与本机不同，ZRpcHeader 中只有  
    //     data_length 需要转换字节序。  
    //

    typedef enum ZRPC_HEADER_FLAG
    {
        // 是否为异步调用  
        //ZRPC_ASYNC          = 0x1,

        // 当前数据包是否必须使用网络字节序。如果为否则使用发送方的字节序，由接收方转换。  
        ZRPC_BIG_ENDIAN     = 0x2,

        // 是否 One Way 调用  
        ZRPC_ONE_WAY        = 0x4,

        // 当前数据包是否是一个拒绝包  
        ZRPC_REJECT         = 0x8,

        // 当前数据包是否是一个返回数据包  
        ZRPC_REPLY          = 0x10,

        // 设置此位，则启动CRC校验  
        ZRPC_ENABLE_CRC     = 0x20,

        // 当前数据包是否还有下一个返回数据包  
        // 只有返回数据包会带有此标志  
        // 暂时该标志未实现  
        //ZRPC_HAS_NEXT_REPLY = 0x40

    } ZRPC_HEADER_FLAG;

    // 以下 mask 为直接分析数据包的程序使用  

    // 数据包是否为 big endian。 数据接收方必须先  
    // 判断本字段之后才能存取包头的多字节数据及数据区内容。  
    #define ZRPC_IS_BIG_ENDIAN_MASK         0x01

    // 数据区压缩否（目前不支持压缩，必须置0）  
    #define ZRPC_IS_COMPRESS_MASK           0x02

    // 数据区加密否（目前不支持加密，必须置0）  
    #define ZRPC_IS_ENCRYPT_MASK            0x04

    // 当前消息是否为应答。有两种消息：请求( 0 )和应答( 1 )。  
    // 客户端和服务器端都可能发送请求。  
    //     对于请求，对应数据包的格式为 ZRpcCallHeader；对于应答，  
    // 数据包格式为 ZRpcReplyHeader。  
    #define ZRPC_IS_REPLY_MASK              0x08

    // 如果操作成功，则此位置0，否则此位置1。  
    // 这是最简单的判断操作成功与失败的方法。  
    #define ZRPC_IS_REJECT_MASK             0x10

    // 数据包头是否需要做 CRC 校验（目前不支持，必须置0）  
    #define ZRPC_IS_CRC_HEADER_MASK         0x20

    // 当前调用是否为 OneWay 调用。如果此字段被置位，  
    // 则客户端不会等待服务器端对当前命令的返回数据包，  
    // 服务器也绝不会有数据包返回，无论模块的实现是否  
    // 有数据返回  
    #define ZRPC_IS_ONE_WAY_MASK            0x40

    //     数据包头是否强制为网络字节序。强烈建议此位置0。  
    #define ZRPC_IS_HEADER_BIG_ENDIAN_MASK  0x80

    struct ZRpcHeader
    {
        // 数据包标识，必须是 ZRPC_MAGIC
        // 2 字节  
        byte_t                  magic[ ZRPC_MAGIC_LEN ];

        // 数据包版本号，必须是 ZRPC_VERSION
        // 1 字节  
        byte_t                  version;

        // 一些开关属性  
        // 1 字节  

        //     数据包是否为 big endian。 数据接收方必须先判断本字段之后才能  
        // 存取数据区内容。  
        byte_t                  is_big_endian       : 1;

        // 数据区压缩否  
        byte_t                  is_compress         : 1;

        // 数据区加密否  
        byte_t                  is_encrypt          : 1;

        // 当前消息是否为应答。有两种消息：请求( 0 )和应答( 1 )。  
        // 客户端和服务器端都可能发送请求。  
        //     对于请求，对应数据包的格式为 ZRpcCallHeader；对于应答，  
        // 数据包格式为 ZRpcReplyHeader。
        byte_t                  is_reply            : 1;

        // 如果操作成功，则此值为0，否则此值为1。  
        // 这是最简单的判断操作成功与失败的方法。  
        byte_t                  is_reject           : 1;

        // 数据包头是否需要做 CRC 校验  
        byte_t                  is_crc_header       : 1;

        // 当前调用是否为 OneWay 调用。如果此字段被置位，则客户端不会等待服务器  
        // 端对当前命令的返回数据包，服务器也绝不会有数据包返回，无论模块的实现  
        // 是否有数据返回  
        byte_t                  is_one_way          : 1;

        byte_t                  is_header_big_endian: 1;

        // 数据区长度  
        // 4 字节  
        uint32_t                data_length;

        // 会话ID。  
        // 4 字节  
        //     该字段由服务器生成，调用方并不处理其内容，所以该  
        // 字段无需做字节序转换。  
        uint32_t                session;

        // 事务码。  
        // 2 字节。  
        // 调用方填该字段的值，接收方会把该值填回返回数据包 transaction
        // 字段，便于通信双方在处理异步调用时对返回数据包的处理。  
        // 接收方并不处理该字段的内容，所以该字段无需做字节序转换。  
        uint16_t                transaction;

        // CRC16 校验码（如果 is_crc_header 值为1）  
        // 2 字节  
        // 校验范围：本结构（crc_header字段以0填充）  
        uint16_t                crc_header;
    };

    ///////////////////////////////////////////////////////////////////////
    //
    // ZRpcCallHeader
    //
    //     所有请求的包头  
    //
    struct ZRpcCallHeader
    {
        // 协议包头  
        // 16 字节  
        struct ZRpcHeader       base;

        // 被调用功能的编号  
        // 功能编号分 3 部分，用 3 级来表示一个全局唯一的模块方法编号。  
        // 3 字节  
        byte_t                  function_id[ 3 ];

        // 调用方功能的编号  
        // 功能编号分 3 部分，用 3 级来表示一个全局唯一的模块方法编号。  
        // 3 字节
        byte_t                  caller_function_id[ 3 ];

        // 返回的 UDP 端口号，如果为0，则使用发送方的端口号  
        uint16_t                reply_udp_port;
    };

    ///////////////////////////////////////////////////////////////////////
    //
    // ZRpcReplyHeader
    //
    //     所有回复的包头  
    //

    struct ZRpcReplyHeader
    {
        // 协议包头  
        // 16 字节  
        struct ZRpcHeader       base;

        // 调用方功能的编号。该参数为调用方提供某些保存状态的机制  
        // 3 字节  
        byte_t                  function_id[ 3 ];

        // 是否还有下一个数据包  
        byte_t                  has_next    : 1;

        // 保留  
        byte_t                  reserved    : 7;

        // CRC32
        uint32_t                crc;
    };

    ///////////////////////////////////////////////////////////////////////
    //
    // ZRpcReader
    //
    //     包数据读入器。数据是 ZRpcCallHeader 及 ZRpcReplyHeader 以外的数据。  
    //
    // 注意：  
    //      请不要试图为本结构增加 length 字段，因为在数据包头的 data_length
    //  能完成 length 的功能。使用 zrpc_package_length 宏也可以取得整个数据包  
    //  长度。  
    struct ZRpcReader
    {
        // 数据包缓冲区指针  
        byte_t *                buffer;

        // 当前缓冲区读指针位置  
        size_t                  pos;

        // 该成员只为读取用户自定义缓冲区而使用，当读取 ZRpc 数据包时，该成员为0
        // 所以判断当前是否读取用户自定义缓冲区的办法就是判断该值是否不为0
        size_t                  length;
    };

    ///////////////////////////////////////////////////////////////////////
    //
    // ZRpcWriter
    //
    //     包数据写入器。  
    //
    struct ZRpcWriter
    {
        // 数据包缓冲区指针  
        byte_t *                buffer;

        // 当前缓冲区写指针位置，即当前数据包大小  
        size_t *                length;

        // 当前缓冲区字节上限  
        size_t                  capacity;

        // 
        byte_t                  _reserved;

        // 是否原始写入器，原始写入器没有 ZRpcHeader
        bool                    is_raw;

        // 是否自动扩展内存  
        bool                    is_expandable;
    };

#endif // #ifndef _fclass_rpc_zrpc_h_

///////////////////////////////////////////////////////////////////////
//
// gr_i_str_t
//

struct gr_i_str_t
{
    gr_class_t      base;

    bool ( * is_space )( char c );

    char * ( * trim )(
        char *          s,
        int *           len
    );

    const char * ( * trim_const )(
        const char *    s,
        int *           len
    );

    void * _unused_1;
    void * _unused_2;

    bool ( * to_array )(
        char *          src,
        const char *    sep,
        char **         result,
        int *           result_count
    );

    bool ( * to_const_array )(
        const char *    src,
        int             src_len,
        const char *    sep,
        int             sep_len,
        const_str_t *   result,
        int *           result_count
    );

    bool ( * to_pair_array )(
        const char *    src,
        int             src_len,
        const char *    row_sep,
        int             row_sep_len,
        const char *    col_sep,
        int             col_sep_len,
        const_pair *    result,
        int *           result_count
    );

    const void * ( * memrchr )( const void *s, int c, size_t n );
    const char * ( * memistr )( const void * s, int s_len, const void * find, int find_len );
    const char * ( * memstr )( const void * s, int s_len, const void * find, int find_len );

    int ( * merge_multi_space )(
        char *  str,
        int     str_len,
        bool    add_0
    );

    int ( * merge_multi_chars )(
        char *          str,
        int             str_len,
        const char *    from_chars,
        int             from_chars_len,
        char            to_char,
        bool            add_0
    );

    int ( * regex_match )(
        const char *                text,
        int                         text_len,
        const char *                regex,
        int                         regex_len,
        regex_match_item_t *        result,
        int                         result_max
    );

    int ( * regex_match_all )(
        const char *                text,
        int                         text_len,
        const char *                regex,
        int                         regex_len,
        regex_match_item_t *        result,
        int                         result_max
    );

    bool ( * base64_encode )(
        const void *    input,
        int             input_len,
        int             crlf_len,
        char *          output,
        int *           output_len
    );

    bool ( * base64_decode )(
        const char *    input,
        int             input_len,
        void *          output,
        int *           output_len
    );

    const char * ( * str_trim_const )( const char * s, int * len );
    char * ( * str_trim )( char * s, int * len );

    bool ( * bytes_to_hex )(
        const void *    bytes,
        size_t          length,
        char *          result,
        size_t          result_length,
        bool            write_end_char
    );

    bool ( * hex_to_bytes )(
        const char *    hex,
        size_t          length,
        void *          result,
        size_t          result_length
    );

    bool ( * hex_to_string )(
        const char *    hex,
        size_t          length,
        char *          result,
        size_t          result_length,
        bool            write_end_char
    );

#ifdef __cplusplus
    bool ( * hex_to_std_string )( const char * hex, size_t length, std::string & result );
    bool ( * bytes_to_hex_std_string )( const void * bytes, size_t length, std::string & result );
#else
    void * _hex_to_std_string_only_cpp;
    void * _bytes_to_hex_std_string;
#endif

    int ( * url_decode )(
        char *          s,
        int             s_len
    );

    bool ( * url_encode )(
        const char *    src,
        int             src_len,
        char *          dst,
        int *           dst_len
    );

    bool ( * url_encode_all )(
        const char *    src,
        int             src_len,
        char *          dst,
        int *           dst_len
    );

    bool ( * parse_url )(
        const char *        url,
        int                 url_len,
        url_infomation_t *  url_info,
        int                 url_info_bytes,
        int *               query_string_count
    );

    int ( * url_normalize )(
        const char *    url,
        int             url_len,
        char *          dest,
        int             dest_len
    );

    bool ( * is_url_valid )(
        const char *    url,
        int             url_len,
        bool            english_domain_only
    );

    bool ( * is_part_url_valid )(
        const char *    url,
        int             url_len
    );

    bool ( * format_url )(
        const char *    url,
        int             url_len,
        const char *    base_url,
        int             base_url_len,
        char *          dest,
        int *           dest_len
    );

    bool ( * format_url2 )(
        const char *    url,
        int             url_len,
        const char *    base_url,
        int             base_url_len,
        char *          dest,
        int *           dest_len,
        bool            delete_anchor
    );

    void ( * cookie_parse )(
        const char *        cookie,
        int                 cookie_len,
        url_pair_t *        result,
        int *               result_len
    );

    int ( * parse_base_url )(
        const char *        page_html,
        int                 page_html_len,
        char *              base_url,
        int                 base_url_max
    );

    int ( * parse_urls )(
        const char *                page_html,
        int                         page_html_len,
        char *                      base_url,
        int                         base_url_max,
        int *                       pbase_url_len,
        parse_urls_callback_t       callback,
        void *                      callback_param
    );

    snappy_status_t ( * snappy_compress )(
        const void *        input,
        size_t              input_length,
        void *              compressed,
        size_t *            compressed_length
    );

    /*
     * Given data in "compressed[0..compressed_length-1]" generated by
     * calling the snappy_compress routine, this routine stores
     * the uncompressed data to
     *   uncompressed[0..uncompressed_length-1].
     * Returns failure (a value not equal to SNAPPY_OK) if the message
     * is corrupted and could not be decrypted.
     *
     * <uncompressed_length> signals the space available in "uncompressed".
     * If it is not at least equal to the value returned by
     * snappy_uncompressed_length for this stream, SNAPPY_BUFFER_TOO_SMALL
     * is returned. After successful decompression, <uncompressed_length>
     * contains the true length of the decompressed output.
     *
     * Example:
     *   size_t output_length;
     *   if (snappy_uncompressed_length(input, input_length, &output_length)
     *       != SNAPPY_OK) {
     *     ... fail ...
     *   }
     *   char* output = (char*)malloc(output_length);
     *   if (snappy_uncompress(input, input_length, output, &output_length)
     *       == SNAPPY_OK) {
     *     ... Process(output, output_length) ...
     *   }
     *   free(output);
     */
    snappy_status_t ( * snappy_uncompress )(
        const void *    compressed,
        size_t          compressed_length,
        void *          uncompressed,
        size_t *        uncompressed_length
    );

    /*
     * Returns the maximal size of the compressed representation of
     * input data that is "source_length" bytes in length.
     */
    size_t ( * snappy_max_compressed_length )(
        size_t          source_length
    );

    /*
     * REQUIRES: "compressed[]" was produced by snappy_compress()
     * Returns SNAPPY_OK and stores the length of the uncompressed data in
     * *result normally. Returns SNAPPY_INVALID_INPUT on parsing error.
     * This operation takes O(1) time.
     */
    snappy_status_t ( * snappy_uncompressed_length )(
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
    snappy_status_t ( * snappy_validate_compressed_buffer )(
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
    int ( * zlib_compress )(
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
    int ( * zlib_compress2 )(
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
    size_t ( * zlib_compress_bound )(
        size_t          source_len
    );

    /*
       compressBound() returns an upper bound on the compressed size after
       compress() or compress2() on sourceLen bytes.  It would be used before
       a compress() or compress2() call to allocate the destination buffer.
    */
    int ( * zlib_uncompress )(
        void *          dest,
        size_t *        dest_len,
        const void *    source,
        size_t          source_len
    );

    /*
         Combine two Adler-32 checksums into one.  For two sequences of bytes, seq1
       and seq2 with lengths len1 and len2, Adler-32 checksums were calculated for
       each, adler1 and adler2.  adler32_combine() returns the Adler-32 checksum of
       seq1 and seq2 concatenated, requiring only adler1, adler2, and len2.
    */
    unsigned long ( * crc32 )(
        unsigned long  crc,
        const void *   buf,
        size_t         len
    );

    int ( * html_extract_content )(
        const char *                    html,
        int                             html_len,
        const html_extract_param_t *    param
    );

    const char * ( * charset_id2str )(
        int             charset_id
    );

    int ( * charset_str2id )(
        const char *   charset
    );

    int ( * charset_check )(
        const void *    str,
        int             str_bytes
    );

    int ( * charset_utf8_bytes )(
        const char      c
    );

    /**
     * @brief charset convert
     * @return int: 0 if successed, < 0, error code
     */
    int ( * charset_convert )(
        int             src_type,
        const void *    src,
        int             src_bytes,
        int             dst_type,
        void *          dst,
        int *           dst_bytes
    );

    fingerprint_t * ( * fingerprint_open )(
        const char *            path
    );

    void ( * fingerprint_close )(
        fingerprint_t *         self
    );

    int ( * fingerprint_html )(
        fingerprint_t *         self,
        const char *            html,
        int                     html_len,
        int                     to_charset,
        int                     debug_level,
        fingerdata_t *          result
    );

    int ( * fingerprint_html_file )(
        fingerprint_t *         self,
        const char *            html_path,
        int                     to_charset,
        int                     debug_level,
        fingerdata_t *          result
    );

    int ( * fingerprint_similar_percent )(
        fingerprint_t *         self,
        int                     charset,
        const fingerdata_t *    left,
        const fingerdata_t *    right
    );

    int ( * fingerprint_keywords )(
        fingerprint_t *                 self,
        int                             charset,
        const fingerdata_t *            finger,
        fingerprint_keywords_callback_t callback,
        void *                          callback_param
    );

    /* Supply malloc, realloc and free functions to cJSON */
    void ( * cJSON_InitHooks )(cJSON_Hooks* hooks);

    /* Supply a block of JSON, and this returns a cJSON object you can interrogate. Call cJSON_Delete when finished. */
    cJSON * ( * cJSON_Parse )(const char *value);
    /* Render a cJSON entity to text for transfer/storage. Free the char* when finished. */
    char  * ( *cJSON_Print )(cJSON *item);
    /* Render a cJSON entity to text for transfer/storage without any formatting. Free the char* when finished. */
    char  * ( *cJSON_PrintUnformatted )(cJSON *item);
    /* Delete a cJSON entity and all subentities. */
    void    ( *cJSON_Delete )(cJSON *c);

    /* Returns the number of items in an array (or object). */
    int	   ( *cJSON_GetArraySize )(cJSON *array);
    /* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
    cJSON * ( * cJSON_GetArrayItem )(cJSON *array,int item);
    /* Get item "string" from object. Case insensitive. */
    cJSON * ( * cJSON_GetObjectItem )(cJSON *object,const char *string);

    /* For analysing failed parses. This returns a pointer to the parse error. You'll probably need to look a few chars back to make sense of it. Defined when cJSON_Parse() returns 0. 0 when cJSON_Parse() succeeds. */
    const char * ( * cJSON_GetErrorPtr )(void);
	
    /* These calls create a cJSON item of the appropriate type. */
    cJSON * ( * cJSON_CreateNull )(void);
    cJSON * ( * cJSON_CreateTrue )(void);
    cJSON * ( * cJSON_CreateFalse )(void);
    cJSON * ( * cJSON_CreateBool )(int b);
    cJSON * ( * cJSON_CreateNumber )(double num);
    cJSON * ( * cJSON_CreateString )(const char *string);
    cJSON * ( * cJSON_CreateArray )(void);
    cJSON * ( * cJSON_CreateObject )(void);

    /* These utilities create an Array of count items. */
    cJSON * ( * cJSON_CreateIntArray )(const int *numbers,int count);
    cJSON * ( * cJSON_CreateFloatArray )(const float *numbers,int count);
    cJSON * ( * cJSON_CreateDoubleArray )(const double *numbers,int count);
    cJSON * ( * cJSON_CreateStringArray )(const char **strings,int count);

    /* Append item to the specified array/object. */
    void  ( * cJSON_AddItemToArray )(cJSON *array, cJSON *item);
    void	 ( * cJSON_AddItemToObject )(cJSON *object,const char *string,cJSON *item);
    /* Append reference to item to the specified array/object. Use this when you want to add an existing cJSON to a new cJSON, but don't want to corrupt your existing cJSON. */
    void  ( * cJSON_AddItemReferenceToArray )(cJSON *array, cJSON *item);
    void	 ( * cJSON_AddItemReferenceToObject )(cJSON *object,const char *string,cJSON *item);

    /* Remove/Detatch items from Arrays/Objects. */
    cJSON * ( * cJSON_DetachItemFromArray )(cJSON *array,int which);
    void    ( * cJSON_DeleteItemFromArray )(cJSON *array,int which);
    cJSON * ( * cJSON_DetachItemFromObject )(cJSON *object,const char *string);
    void    ( * cJSON_DeleteItemFromObject )(cJSON *object,const char *string);
	
    /* Update array items. */
    void  ( * cJSON_ReplaceItemInArray )(cJSON *array,int which,cJSON *newitem);
    void  ( * cJSON_ReplaceItemInObject )(cJSON *object,const char *string,cJSON *newitem);

    /* Duplicate a cJSON item */
    cJSON * ( * cJSON_Duplicate )(cJSON *item,int recurse);
    /* Duplicate will create a new, identical cJSON item to the one you pass, in new memory that will
    need to be released. With recurse!=0, it will duplicate any children connected to the item.
    The item->next and ->prev pointers are always zero on return from Duplicate. */

    /* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
    cJSON * ( * cJSON_ParseWithOpts )(const char *value,const char **return_parse_end,int require_null_terminated);

    void  ( * cJSON_Minify )(char *json);
    bool ( * parser_open_charset )(
        parser_t *      parser,
        const void *    ptr,
        int             len,
        int             charset
    );
    bool ( * parser_end )(
        parser_t *      parser
    );
    char ( * parser_peek )(
        parser_t *      parser
    );
    char ( * parser_read )(
        parser_t *      parser
    );
    int ( * parser_read_charset )(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    const char * ( * parser_read_charset_ptr )(
        parser_t *      parser,
        int *           result_len
    );
    void ( * parser_back )(
        parser_t *      parser
    );
    int ( * parser_ignore_spaces )(
        parser_t *      parser
    );
    int ( * parser_ignore_spaces_tail )(
        parser_t *      parser
    );
    int ( * parser_ignore_to )(
        parser_t *          parser,
        const char *        stop_chars
    );
    int ( * parser_escape_char )(
        parser_t *      parser,
        char *          result
    );
    int ( * parser_read_string )(
        parser_t *      parser,
        bool            translate_escape_char,
        char *          result,
        int *           result_len
    );
    int ( * parser_read_whole_string )(
        parser_t *      parser,
        bool            translate_escape_char,
        char *          result,
        int *           result_len
    );
    const char * ( * parser_read_string_ptr )(
        parser_t *      parser,
        int *           result_len
    );
    int ( * parser_html_escape_char )(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    int ( * parser_read_html_string )(
        parser_t *      parser,
        bool            entity_decode,
        char *          result,
        int *           result_len
    );
    int ( * parser_read_whole_html_string )(
        parser_t *      parser,
        bool            entity_decode,
        char *          result,
        int *           result_len
    );
    const char * ( * parser_read_html_string_ptr )(
        parser_t *      parser,
        int *           result_len
    );
    int ( * parser_read_to )(
        parser_t *          parser,
        const char *        stop_chars,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    const char * ( * parser_read_ptr_to )(
        parser_t *          parser,
        const char *        stop_chars,
        int *               result_len
    );
    int ( * parser_read_word )(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    const char * ( * parser_read_word_ptr )(
        parser_t *          parser,
        int *               result_len
    );
    bool ( * parser_read_last_word )(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    int ( * parser_read_alpha )(
        parser_t *          parser,
        bool                enable_escape,
        char *              result,
        int *               result_len
    );
    int ( * parser_read_int )(
        parser_t *      parser,
        int *           result
    );
    int ( * parser_read_number )(
        parser_t *      parser,
        char *          result,
        int *           result_len
    );
    time_t ( * parser_read_datetime_rfc867 )(
        parser_t *      parser
    );
    const const_str * ( * get_sentence_sep_list )(
        int             charset,
        int *           count
    );
    const char * ( * parser_read_sentence_ptr )(
        parser_t *      parser,
        int *           result_len,
        const char **   sep
    );

    void ( * simple_encrypt )( void *buf, int buf_len, uint32_t passwd );
    void ( * simple_decrypt )( void *buf, int buf_len, uint32_t passwd );

    void ( * binary_set_bit )( unsigned char * src, size_t witch_bit, bool v );
    bool ( * binary_get_bit )( const unsigned char * src, size_t witch_bit );
    const unsigned char * ( * binary_find_non_zero_byte )( const unsigned char * src, size_t src_bytes );
    size_t ( * binary_find_non_zero_bit )( const unsigned char * src, size_t src_bytes );
    unsigned char ( * byte_set_bit )( unsigned char src, unsigned char witch_bit, bool v );
    bool ( * byte_get_bit )( unsigned char src, unsigned char witch_bit );

    void ( * parser_back_bytes )( parser_t * parser, size_t bytes );

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
    ( * zrpc_package_length )(
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
    ( * zrpc_reader_open )(
        ZRpcReader * This,
        ZRpcHeader * package
    );

    int
    ( * zrpc_reader_open_raw )(
        ZRpcReader * This,
        const void * data,
        size_t       len
    );

    bool
    ( * zrpc_reader_is_raw )(
        ZRpcReader *    This
    );

    size_t
    ( * zrpc_reader_get_length )(
        ZRpcReader *    This
    );

    void *
    ( * zrpc_reader_get_package )(
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
    ( * zrpc_reader_read )(
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
    ( * zrpc_reader_ignore )(
        ZRpcReader * This,
        size_t len
    );

    ///////////////////////////////////////////////////////////////////////
    //
    // zrpc_reader_get_header_size
    //
    // 说明：
    //     
    //
    // 参数：
    //      This        - 调用方管理，已经调用过 zrpc_reader_open
    // 返回值：
    //      错误代码。0 表示成功。
    //
    int
    ( * zrpc_reader_get_header_size )(
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
    ( * zrpc_reader_is_big_endian )(
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
    ( * zrpc_reader_get_curr )(
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
    ( * zrpc_reader_move_pos )(
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
    ( * zrpc_reader_set_pos )(
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
    ( * zrpc_reader_read_byte )(
        ZRpcReader * This,
        byte_t * ret
    );

    int
    ( * zrpc_reader_read_uint16 )(
        ZRpcReader * This,
        uint16_t * ret
    );

    int
    ( * zrpc_reader_read_uint32 )(
        ZRpcReader * This,
        uint32_t * ret
    );

    int
    ( * zrpc_reader_read_uint64 )(
        ZRpcReader * This,
        uint64_t * ret
    );

    int
    ( * zrpc_reader_read_int32v )(
        ZRpcReader * This,
        int32_t * ret
    );

    int
    ( * zrpc_reader_read_uint32v )(
        ZRpcReader * This,
        uint32_t * ret
    );

    int
    ( * zrpc_reader_read_uint64v )(
        ZRpcReader * This,
        uint64_t * ret
    );

    int
    ( * zrpc_reader_read_float )(
        ZRpcReader * This,
        float * ret
    );

    int
    ( * zrpc_reader_read_double )(
        ZRpcReader * This,
        double * ret
    );

    int
    ( * zrpc_reader_read_bytes )(
        ZRpcReader * This,
        const char ** s,
        size_t * l
    );


    int
    ( * zrpc_writer_open_raw )(
        ZRpcWriter *    This,
        byte_t *        buff,
        size_t          capacity,
        size_t *        length
    );

    int
    ( * zrpc_writer_open_expandable_raw )(
        ZRpcWriter *    This,
        size_t *        length
    );

    int ( * zrpc_writer_close_expandable )(
        ZRpcWriter *    This
    );

    bool
    ( * zrpc_writer_is_raw )(
        ZRpcWriter *    This
    );

    int
    ( * zrpc_writer_set_udp_info )(
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
    ( * zrpc_writer_set_error )(
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
    ( * zrpc_writer_is_big_endian )(
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
    ( * zrpc_writer_get_curr )(
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
    ( * zrpc_writer_add_length )(
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
    ( * zrpc_writer_write )(
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
    ( * zrpc_writer_write_byte )(
        ZRpcWriter * This,
        byte_t p
    );

    int
    ( * zrpc_writer_write_uint16 )(
        ZRpcWriter * This,
        uint16_t p
    );

    int
    ( * zrpc_writer_write_int32v )(
        ZRpcWriter * This,
        int32_t      p
    );

    int
    ( * zrpc_writer_write_uint32 )(
        ZRpcWriter * This,
        uint32_t p
    );

    int
    ( * zrpc_writer_write_uint64 )(
        ZRpcWriter * This,
        uint64_t p
    );

    int
    ( * zrpc_writer_write_uint32v )(
        ZRpcWriter * This,
        uint32_t p
    );

    int
    ( * zrpc_writer_write_uint64v )(
        ZRpcWriter * This,
        uint64_t p
    );

    int
    ( * zrpc_writer_write_float )(
        ZRpcWriter * This,
        float p
    );

    int
    ( * zrpc_writer_write_double )(
        ZRpcWriter * This,
        double p
    );

    int
    ( * zrpc_writer_write_bytes )(
        ZRpcWriter * This,
        const void * s,
        size_t l
    );

    int
    ( * zrpc_writer_write_reader )(
        ZRpcWriter * This,
        ZRpcReader * reader
    );

    int
    ( * zrpc_writer_set_reader )(
        ZRpcWriter * This,
        ZRpcReader * reader
    );

    uint16_t
    ( * zrpc_calc_crc16 )(
        const char *            data,
        size_t                  data_len
    );

    uint32_t
    ( * zrpc_calc_crc32 )(
        const char *            p,
        size_t                  pl
    );

    bool ( * str_find_scope )(
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
    bool ( * check_mobile )( const char * phone, size_t phone_len );

};

///////////////////////////////////////////////////////////////////////
//
// gr_i_network_t
//

struct gr_i_network_t
{
    gr_class_t      base;

    tcp_connector_t *       ( * tcp_connector_create )(
        const tcp_connector_param_t * param
    );

    void                    ( * tcp_connector_destroy )(
        tcp_connector_t *   self
    );

    bool                    ( * tcp_connector_add )(
        tcp_connector_t *       self,
        int                     fd,
        const struct sockaddr * addr,
        int                     addr_len,
        int                     timeout_ms,
        tcp_connector_result_t  callback,
        void *                  callback_param1,
        void *                  callback_param2
    );

    bool                    ( * tcp_connector_del )(
        tcp_connector_t *       self,
        int                     fd
    );

#ifdef __cplusplus
    bool                    ( * http_stdstr )(
        const char *        url,
        const char *        refer,
        int                 connect_timeout_second,
        int                 recv_timeout_second,
        unsigned int        flags,
        const char *        http_method,
        std::string &       result,
        int *               http_code
    );
#else
    void *                  http_stdstr_for_cpp;
#endif

    http_t *                ( * http_create )();

    // auto member
    bool                    ( * http_set_timeout )(
        http_t *            http,
        int                 connect_timeout_second,
        int                 recv_timeout_second
    );

    // auto member
    bool                    ( * http_set_callback )(
        http_t *                http,
        http_data_callback_t    content_callback,
        void *                  content_callback_param,
        http_data_callback_t    header_callback,
        void *                  header_callback_param
    );

    // this info will be lost after http_perform called
    bool                    ( * http_set_base_security )(
        http_t *            http,
        const char *        user,
        const char *        passwd
    );

    // this info will be lost after http_perform called
    bool                    ( * http_set_url )(
        http_t *            http,
        const char *        url,
        const char *        refer
    );

    // this info will be lost after http_perform called
    bool                    ( * http_set_postfields )(
        http_t *            http,
        const char *        fields,
        size_t              fields_bytes,
        const char *        content_type
    );

    // this info will be lost after http_perform called
    bool                    ( * http_add_multi_post )(
        http_t *            http,
        const char *        name,
        const char *        file
    );

    // lost belows data;
    //    http_set_base_security
    //    http_set_url
    //    http_set_postfields
    //    http_add_multi_post
    void                    ( * http_reset_request )(
        http_t *    http
    );

    bool                    ( * http_perform )(
        http_t *            http,
        unsigned int        flags,
        const char *        http_method,
        int *               http_code
    );

    void                    ( * http_destroy )(
        http_t *            http
    );

    int                     ( * socket_create_tcp_v4 )();

    int                     ( * socket_create_udp_v4 )();

    /**
     * @brief close socket
     * @param[in] SOCKET sock: socket fd that will be close
     */
    int                     ( * socket_close )(
	    int sock
    );

    /**
     * @brief Is TCP use delay algorithem? 
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isNoDelay: is it no delay? if true,
     *                            single send call will be fire a real send.
     * @return bool: is OK?
     */
    bool                    ( * socket_get_tcp_no_delay )(
	    int sock,
	    bool * isNoDelay
    );

    bool                    ( * socket_set_tcp_no_delay )(
	    int sock,
	    bool isNoDelay
    );

    /**
     * @brief Is TCP use KeepAlive?
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] bool isKeepAlive: is it KeepAlive
     * @return bool: is OK?
     */
    bool                    ( * socket_set_keep_alive )(
	    int sock,
	    bool isKeepAlive
    );

    /**
     * @brief set send buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: send buffer bytes
     * @return bool: is OK?
     */
    bool                    ( * socket_get_send_buf )(
	    int sock,
	    int * bytes
    );

    bool                    ( * socket_set_send_buf )(
	    int sock,
	    int bytes
    );

    /**
     * @brief set recv buffer
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int bytes: recv buffer bytes
     * @return bool: is OK?
     */
    bool                    ( * socket_get_recv_buf )(
	    int sock,
	    int * bytes
    );

    bool                    ( * socket_set_recv_buf )(
	    int sock,
	    int bytes
    );

    /**
     * @brief set TTL
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] int ttl: TTL
     * @return bool: is OK?
     */
    bool                    ( * socket_set_ttl )(
	    int sock,
	    int ttl
    );

    bool                    ( * socket_set_loopback )(
        int sock,
        bool enable
    );


    bool                    ( * socket_get_linger )(
        int sock,
        uint16_t * lv
    );

    bool                    ( * socket_set_linger )(
        int sock,
        uint16_t linger
    );

    /**
     * @brief if last socket call failed, is it because E_INPROGRESS or E_WOULDBLOCK
     * @param[in] SOCKET sock: SOCKET fd
     * @return bool: yes or no
     */
    bool                    ( * socket_is_pending )();


    /**
     * @brief same as socket recv function
     * @param[in] SOCKET sock: SOCKET fd
     * @param[in] void * buf: recv buffer
     * @param[in] int bytes: recv buffer bytes
     * @return int: readed bytes, < 0 if failed
     */
    int                     ( * socket_recv )(
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
    int                     ( * socket_send )(
	    int sock,
	    const void * buf,
	    int bytes
    );

    bool                    ( * socket_recv_fill )(
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
    bool                    ( * socket_send_all )(
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
    bool                    ( * socket_addr_v4 )(
        const char * host,
        int port,
        struct sockaddr_in * addr
    );

    bool                    ( * socket_str_2_addr_v4 )(
        const char * str,
        struct sockaddr_in * addr
    );

    int                     ( * socket_addr_cmp )(
        const struct sockaddr * left,
        const struct sockaddr * right,
        int len
    );

    int                     ( * socket_addr_cmp_ip )(
        const struct sockaddr * left,
        const struct sockaddr * right,
        int len
    );

    bool                    ( * socket_in_progress )();

    bool                    ( * socket_would_block )();

    bool                    ( * socket_set_block )( int fd, bool is_block );

    int ( * get_ip_type )( struct in_addr ip );

    bool ( * socket_get_all_ip )( struct in_addr * addrs, size_t * count );

    tcp_sender_t *          ( * tcp_sender_create )(
        const tcp_sender_param_t * param
    );

    void                    ( * tcp_sender_destroy )(
        tcp_sender_t *      self
    );

    int                     ( * tcp_sender_send )(
        tcp_sender_t *      self,
        int                 fd,
        void *              data,
        int                 data_len,
        void *              user_data
    );

    void                    ( * tcp_sender_del )(
        tcp_sender_t *      self,
        int                 fd
    );

    int                     ( * tcp_sender_send_http_rsp )(
        tcp_sender_t *              self,
        int                         fd,
        void *                      data,
        int                         data_len,
        void *                      user_data,
        const tcp_sender_http_t *   param
    );

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
    int ( * socketpair )(int d, int type, int protocol, int fds[2]);

    gr_package_type_t ( * http_check_type )(
        const void *    p,
        int             len
    );

    bool ( * http_check_full )(
        const char *    buf,
        int             len,
        bool            is_http_reply,
        bool *          is_error,
        int *           header_offset,
        int *           body_offset,
        int64_t *       content_length
    );

    gr_http_ctxt_t * ( * http_build_req )(
        int                 rsp_fd,
        const char *        buf,
        int                 len,
        bool                is_http_reply,
        http_parse_ctxt_t * parse_ctxt,
        int                 header_offset,
        int                 body_offset,
        int64_t             content_length
    );

    fanout2_t * ( * fanout2_create )(
        fanout2_param_t *       param
    );

    void ( * fanout2_destroy )(
        fanout2_t *             fanout
    );

    fanout2_task_t * ( * fanout2_task_create )(
        fanout2_t *             fanout,
        fanout2_callback_t      callback,
        void *                  callback_param
    );

    void * ( * fanout2_task_param )(
        fanout2_task_t *        task
    );

    bool ( * fanout2_add_pending_http )(
        fanout2_task_t *        task,
        const char *            url,
        int                     url_len,
        const char *            refer,
        int                     refer_len,
        int                     connect_timeout_ms,
        int                     total_timeout_ms,
        fanout2_http_param_t *  param
    );

    void ( * fanout2_task_destroy )(
        fanout2_task_t *        task
    );

    bool ( * fanout2_task_start )(
        fanout2_task_t *        task
    );

    size_t ( * fanout2_task_request_size )(
        fanout2_task_t *        task
    );

    int ( * fanout2_task_get_error_code )(
        fanout2_task_t *        task,
        size_t                  index
    );

    const char * ( * fanout2_task_get_url )(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                url_len
    );

    const char * ( * fanout2_task_get_rsp )(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                rsp_len
    );

    const struct sockaddr_in * ( * fanout2_task_get_addr )(
        fanout2_task_t *        task,
        size_t                  index
    );

    gr_http_ctxt_t * ( * fanout2_task_get_http_rsp )(
        fanout2_task_t *        task,
        size_t                  index
    );

    const char * ( * fanout2_task_get_req )(
        fanout2_task_t *        task,
        size_t                  index,
        size_t *                req_len
    );

    tcp_channel_t *         ( * tcp_channel_create )(
        int                     thread_count,
        int                     up_buf_bytes,
        int                     down_buf_bytes,
        int                     concurrent,
        int                     max_conn,
        int                     poll_wait_ms,
        tcp_channel_cb_t        callback
    );

    void                    ( * tcp_channel_destroy )(
        tcp_channel_t * self
    );

    int                     ( * tcp_channel_connect )(
        tcp_channel_t *         self,
        int                     fd,
        const struct sockaddr * addr,
        socklen_t               addr_len,
        void *                  param
    );

    int                     ( * tcp_channel_async_connect )(
        tcp_channel_t *         self,
        int                     fd,
        const struct sockaddr * addr,
        socklen_t               addr_len,
        void *                  param
    );

    int                     ( * tcp_channel_send )(
        tcp_channel_t *         self,
        int                     fd,
        const void *            data,
        int                     data_len,
        uint32_t                wait_ms
    );

    int                     ( * tcp_channel_pop_recved )(
        tcp_channel_t *         self,
        int                     fd,
        int                     len
    );

    int                     ( * tcp_channel_del )(
        tcp_channel_t *         self,
        int                     fd,
        bool                    close_fd
    );

    bool ( * socket_addr )(
        const char * host,
        int port,
        bool is_ipv6,
        socket_address_t * addr
    );

    bool ( * socket_addr2 )(
         const struct sockaddr * a,
         int a_len,
         socket_address_t * addr
    );

    bool ( * socket_addr_from_str )(
        const char * str,
        bool is_ipv6,
        socket_address_t * addr
    );

    bool ( * socket_addr_to_str )(
         const struct sockaddr * a,
         int a_len,
         char * buf,
         size_t buf_max
    );

    struct sockaddr * ( * socket_addr_get )(
        socket_address_t * addr,
        int * len
    );

    bool ( * socket_addr_is_valid )(
        socket_address_t * addr
    );

    bool ( * socket_addr_is_ipv6 )(
        socket_address_t * addr
    );

    // buf_len same with sizeof(INET6_ADDRSTRLEN或INET_ADDRSTRLEN)
    bool ( * socket_ntoa )(
        const void * sin_addr_or_sin6_addr,
        bool is_ipv6,
        char * buf,
        size_t buf_len
    );

    bool ( * socket_aton )(
        const char * ip,
        bool is_ipv6,
        void * sin_addr_or_sin6_addr,
        size_t sin_addr_or_sin6_addr_len
    );
};

///////////////////////////////////////////////////////////////////////
//
// gr_i_parallel_t
//

struct gr_i_parallel_t
{
    gr_class_t      base;

    bool ( * tls_open )( tls_key_t * tls, void ( * free_func )( void * ) );
    void ( * tls_close )( tls_key_t * tls );
    bool ( * tls_is_open )( tls_key_t * tls );
    void * ( * tls_get )( tls_key_t * tls );
    bool ( * tls_set )( tls_key_t * tls, void * v );

    void ( * os_thread_init )( os_thread_t * self );
    bool ( * os_thread_is_started )( const os_thread_t * self );
    bool ( * os_thread_is_need_exit )( const os_thread_t * self );
    bool ( * os_thread_is_exited )( const os_thread_t * self );
    int ( * os_thread_tid )( const os_thread_t * self );
    bool ( * os_thread_start )(
        os_thread_t *  self,
        void *      (*start_routine)(void*),
        void *      param
    );
    void ( * os_thread_stop )( os_thread_t * self );

    void ( * process_init )(
        proc_t *       process
    );

    /**
     * @brief fork a new process
     * @param[in] start_routine process rountine
     * @param[in] arg process rountine parameter
     * @return bool return true if successed; otherwise return error code
     */
    bool ( * process_fork )(
        proc_t *       process,
        void *         (*start_routine)(void*),
        void *         arg
    );

    /*
     * @brief create a new process[need libbase.so]
     * @param self[ out ] : pid
     * @param cmdline[in] : command line
     * @param is_hide[in] : is application has windows
     * @return bool : is it ok
     */
    bool ( * process_exec )(
        proc_t *        process,
        const char *    cmdline,
        bool            is_hide
    );

    /**
     * @brief fork a new process
     * @param process[ out ] : pid
     * @param[in] start_routine process rountine
     * @param[in] arg process rountine parameter
     * @param[in] redirect_stdout
     * @return bool return true if successed; otherwise return error code
     */
    bool ( * cgi_process_fork )(
        proc_t *        process,
        void *          (*start_routine)(void*),
        void *          arg,
        bool            redirect_stdout
    );

    /*
     * @brief create a new CGI process[need libbase.so]
     * @param process[ out ] : pid
     * @param cmdline[in] : command line
     * @param is_hide[in] : is application has windows
     * @return bool : is it ok
     */
    bool ( * cgi_process_exec )(
        proc_t *        process,
        const char *    cmdline,
        bool            is_hide
    );

    /**
     * @function process_join[need libbase.so]
     * @brief wait for process stop
     */
    void ( * process_join )(
        proc_t *        process );

    bool ( * process_is_running )(
        proc_t *        process );

    /*
     * @brief kill a process[need libbase.so]
     * @param process[ in ] : process that will be kill
     * @return bool : is it ok
     */
    bool ( * process_kill )(
        proc_t *        process );

    bool ( * process_get_info )(
        pid_t           pid,
        proc_info_t *   info
    );

    pid_t ( * process_get_pid )(
        proc_t *        process );

    bool ( * process_kill_zombies )(
        const char *    name_lead,
        unsigned int    kill_timeout_ms,
        bool ( *        can_kill )( void * param, pid_t pid ),
        void *          can_kill_param,
        int *           kill_count,
        int *           fail_count
    );
    
    bool ( * process_walk )(
        bool            ( * callback )( void * param, pid_t pid ),
        void *          callback_param
    );

    bool ( * process_find )(
        const char *    name,
        pid_t *         pids,
        int *           pids_count
    );

    bool ( * process_get_children )(
        pid_t       pid,
        pid_t *     children,
        int *       children_count
    );

    bool ( * process_kill_tree )(
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
    bool ( * pipe_create )(
        int             fds[ 2 ]
    );

    /**
     * @brief destroy a pipe object[need libbase.so]
     * @param[in/out] int fds[ 2 ] : pipe
     */
    void ( * pipe_destroy )(
        int             fds[ 2 ]
    );

    /**
     * @brief read from pipe[need libbase.so]
     * @param[in] int fds[ 2 ] : pipe
     * @param[out] void * buf  : read buffer
     * @param[in]  int    len  : read max len
     * @return readded bytes
     */
    int ( * pipe_read )(
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
    int ( * pipe_write )(
        int             fds[ 2 ],
        const void *    data,
        int             len
    );

    int ( * pipe_read_fd )(
        int             fds[ 2 ],
        int *           fd,
        void *          buf,
        int             len
    );

    int ( * pipe_write_fd )(
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
    int ( * pipe_wait_for_read )(
        int             fds[ 2 ],
        unsigned int    ms
    );

    int ( * write_http_to_pipe )(
        int                 fds[ 2 ],
        gr_http_ctxt_t *    http
    );

    int ( * read_http_from_pipe )(
        int                 fds[ 2 ],
        pipe_http_t **      result
    );

    /**
     * @brief create fast_pool object
     * @param process[ in ] : concurrent
     * @return fast_poll_t * non NULL if successed
     */
    fast_poll_t * ( * fast_poll_create )(
        int                     concurrent
    );
    /**
     * @brief destroy fast_pool object
     * @param process[ in ] : concurrent
     */
    void ( * fast_poll_destroy )(
        fast_poll_t *               poll
    );
    /**
     * @brief set a fd event
     * @param poll[ in ] : fast_poll object
     * @param fd  [ in ] : fd
     * @param data[ in ] : pointer to event info
     */
    bool ( * fast_poll_set )(
        fast_poll_t *               poll,
        int                         fd,
        const fast_poll_event_t *   data
    );
    /**
     * @brief del a fd event
     * @param poll[ in ] : fast_poll object
     * @param fd  [ in ] : fd
     */
    bool ( * fast_poll_del )(
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
    int ( * fast_poll_wait )(
        fast_poll_t *               poll,
        fast_poll_event_t *         events,
        int                         event_count,
        int                         timeout_ms
    );
    /**
    * @brief add fd for connect
    * @param poll[ in ]        : fast_poll object
    * @param fd  [ in ] : fd
    * @param data[ in ] : event info
    * @param addr[ in ] : connect addr
    * @param addr_len[in]:addr bytes
    * @return int : errcode, 0 = successed; < 0 = error; > 0: connected
    */
    int ( * fast_poll_connect )(
        fast_poll_t *               poll,
        int                         fd,
        const fast_poll_event_t *   data,
        const struct sockaddr *     addr,
        socklen_t                   addr_len
    );

    bool ( * cluster_get_dirty )();
    void ( * cluster_set_dirty )( bool v );
    bool ( * cluster_save )( const char * path, uint32_t * version );
    bool ( * cluster_load )( const char * path, uint32_t * version );
    bool ( * cluster_update )( const char * path, const char * mem, int mem_bytes, uint32_t * version );
    uint32_t ( * cluster_version )();
    cluster_group_t * ( * cluster_find_group )(
        const char *    path,
        bool            auto_create
    );
    bool ( * cluster_del_group )(
        const char *    path
    );
    bool ( * cluster_del_peer )(
        cluster_peer_t * peer
    );
    cluster_peer_t * ( * cluster_find_peer )(
        const char * addr
    );
    cluster_peer_t * ( * cluster_group_find_peer )(
        cluster_group_t *   group,
        const char *        addr,
        bool                auto_create
    );
    cluster_peer_t * ( * cluster_group_find_peer_by_index )(
        cluster_group_t *   group,
        int                 index
    );
    const char * ( * cluster_group_get_name )(
        cluster_group_t *   group
    );
    cluster_group_t * ( * cluster_group_get_parent )(
        cluster_group_t *   group
    );
    bool ( * cluster_group_get_enable )(
        cluster_group_t *   group
    );
    void ( * cluster_group_set_enable )(
        cluster_group_t *   group,
        bool                b
    );
    const void * ( * cluster_group_get_property )(
        cluster_group_t *   group,
        const char *        name,
        int *               property_len
    );
    bool ( * cluster_group_set_property )(
        cluster_group_t *   group,
        const char *        name,
        const void *        property,
        int                 property_len
    );
    int ( * cluster_group_child_groups )(
        cluster_group_t *   group,
        cluster_group_t **  result,
        int                 result_max
    );
    int ( * cluster_group_child_peers )(
        cluster_group_t *   group,
        cluster_peer_t **   result,
        int                 result_max
    );
    const char * ( * cluster_peer_get_addr )(
        cluster_peer_t *    peer
    );
    const struct sockaddr_in * ( * cluster_peer_get_sock_addr )(
        cluster_peer_t *    peer
    );
    cluster_group_t * ( * cluster_peer_get_parent )(
        cluster_peer_t *    peer
    );
    bool ( * cluster_peer_get_enable )(
        cluster_peer_t *    peer
    );
    void ( * cluster_peer_set_enable )(
        cluster_peer_t *    peer,
        bool                b
    );
    const void * ( * cluster_peer_get_property )(
        cluster_peer_t *    peer,
        const char *        name,
        int *               property_len
    );
    bool ( * cluster_peer_set_property )(
        cluster_peer_t *    peer,
        const char *        name,
        const void *        property,
        int                 property_len
    );

};

///////////////////////////////////////////////////////////////////////
//
// gr_i_tool_t
//

struct gr_i_tool_t
{
    gr_class_t      base;

    int ( * circle_buf_create )(
        circle_buf_t *  self,
        size_t          size
    );

    void ( * circle_buf_destroy )(
        circle_buf_t *  self
    );

    size_t ( * circle_buf_capacity )(
        circle_buf_t * self
    );

    bool ( * circle_buf_is_empty )(
        circle_buf_t *  self
    );

    bool ( * circle_buf_is_full )(
        circle_buf_t *  self
    );

    bool ( * circle_buf_reset )(
        circle_buf_t *  self,
        size_t          capacity
    );

    size_t ( * circle_buf_size )(
        circle_buf_t *  self
    );

    size_t ( * circle_buf_push )(
        circle_buf_t *  self,
        const void *    data,
        size_t          data_len
    );

    size_t ( * circle_buf_pop )(
        circle_buf_t *  self,
        void *          data,
        size_t          data_len
    );

    const void * ( * circle_buf_get_part )(
        circle_buf_t *  self,
        size_t *        len
    );

    //
    // Returns a pointer to a DIR structure appropriately filled in to begin
    // searching a directory.
    //
    DIR * ( * opendir )( const char * filespec );

    //
    // Return a pointer to a dirent structure filled with the information on the
    // next entry in the directory.
    //
    struct dirent* ( * readdir )( DIR* dir );

    //
    // Frees up resources allocated by opendir.
    //
    int	( * closedir )( DIR * dir );

    void ( * datetime_now )( uint64_t * result );
    bool ( * datetime_make )(
        uint64_t *  ticks,
        int         year,
        int         month,
        int         day,
        int         hour,
        int         minute,
        int         second,
        int         ms
    );
    bool ( * datetime_info )(
        uint64_t    ticks,
        int *       year,
        int *       month,
        int *       day,
        int *       hour,
        int *       minute,
        int *       second,
        int *       ms
    );

    bool ( * get_current_time )(
        int *   year,
        int *   month,
        int *   day,
        int *   hour,
        int *   minute,
        int *   second,
        int *   ms
    );

    bool ( * time_info )(
        time_t      v,
        int *       year,
        int *       month,
        int *       day,
        int *       hour,
        int *       minute,
        int *       second
    );

    time_t ( * time_from_str )(
        const char *    str,
        int             str_len
    );

    bool ( * time_to_str )(
        time_t      v,
        char *      str,
        int *       str_len
    );

    /**
     * @brief 16 bytes random ID
     * @param[out] UUID * result data
     * @return bool is it successed
     */
    bool ( * uuid_create )(
        char result[ 16 ]
    );

    struct trie_t* ( * trie_create )(void);
    struct trie_t* ( * trie_init )(const void* p, const size_t size);
    void ( * trie_destroy )(struct trie_t* two);
    int ( * trie_insert )(struct trie_t* two, const char* str, const size_t len, const int value, const int overwrite);
    int ( * trie_match )(struct trie_t* two, const char* str, const size_t len, int* val);
    int ( * trie_matchall )(struct trie_t* two, const char* str, const size_t len,  trie_mi* minfo, const size_t mlen);
    size_t ( * trie_allsize )(struct trie_t* two);
    void * ( * trie_write )(struct trie_t* two, void* p);
    int ( * trie_isgood )(struct trie_t* two);
    void ( * trie_walk )(struct trie_t* two, void *arg, two_cb cb);
    void ( * trie_walk_dump )(struct trie_t* two);
    int ( * trie_feture )(struct trie_t* two,
                   const char* str, const size_t len,
                   const char * out_buf_sep, int out_buf_sep_len,
                   char * out_buf, int max_out_buf_len, int * out_buf_len,
                   int max_item_count, int * item_count,
                   trie_fi * items );

    int ( * trie_has_feture )(struct trie_t* two, const char* str, const size_t len );
    bool ( * trie_write_file )(
        trie_t *        two,
        FILE *          fp
    );

    bool            ( * trie_db_build )( const char * src_file, const char * dest_dir, const trie_db_build_params_t * params );
    bool            ( * trie_db_valid )( const char * dir );
    trie_db_t *     ( * trie_db_open )( const char * dir );
    void            ( * trie_db_close )( trie_db_t * db );
    void *          ( * trie_db_find )( trie_db_t * db, const void * key, int key_len, int * val_len );
    uint32_t        ( * trie_db_get_count )( trie_db_t * db );
    void *          ( * trie_db_get_val )( trie_db_t * db, int offset, int * val_len );
    struct trie_t * ( * trie_db_get_index )( trie_db_t * db );
    void *          ( * trie_db_get_key )( trie_db_t * db, int offset, int * key_len );
    bdb_t *         ( * bdb_open )( const char * dir );
    bdb_t *         ( * bdb_open_advanced )(
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
    void            ( * bdb_close )( bdb_t * db );
    int             ( * bdb_get )( bdb_t * db, const void * key, int key_len, void * val, int * val_len );
    int             ( * bdb_set )( bdb_t * db, const void * key, int key_len, const void * val, int val_len );
    int             ( * bdb_del )( bdb_t * db, const void * key, int key_len );
    int             ( * bdb_flush )( bdb_t * db );
    bdb_cursor_t *  ( * bdb_cursor_open )( bdb_t * db );
    void            ( * bdb_cursor_close )( bdb_cursor_t * self );
    int             ( * bdb_cursor_next )(
        bdb_cursor_t *  self,
        void *          key,
        int *           key_len,
        void *          val,
        int  *          val_len
    );
    int             ( * bdb_cursor_find_next )(
        bdb_cursor_t *  self,
        const void *    key,
        int             key_len,
        void *          val,
        int *           val_len
    );
    int             ( * bdb_cursor_del )( bdb_cursor_t * self );
    pair_db_t *     ( * pair_db_open )( const char * dir );
    void            ( * pair_db_close )( pair_db_t * db );
    int             ( * pair_db_get )( pair_db_t * db, const void * key, int key_len, void * val, int * val_len );
    int             ( * pair_db_set )( pair_db_t * db, const void * key, int key_len, const void * val, int val_len );
    int             ( * pair_db_del )( pair_db_t * db, const void * key, int key_len );
    int ( * keyset_generate )(
        const char * src_path,
        const char * src_sep,
        const char * dst_path
    );
    keyset_t * ( * keyset_open )( const char * path );
    keyset_t * ( * keyset_open_memory )( const void * data, int data_len );
    void ( * keyset_close )( keyset_t * self );
    /**
     * @brief find key
     * @param[in] keyset_t * self : open by keyset_open_memory or keyset_open
     * @param[in] const void * key: key ptr
     * @param[in] int key_len     : key bytes
     * @return int: result count. < 0 error.
     */
    int ( * keyset_find )(
        keyset_t *      self,
        const void *    key,
        int             key_len,
        keyset_item_t * result,
        int             result_max
    );
    int ( * cn_people_name_generate )(
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
    cn_people_name_t * ( * cn_people_name_open )( int charset );
    void ( * cn_people_name_close )( cn_people_name_t *  self );
    int ( * cn_people_name_find )(
        cn_people_name_t *      self,
        const char *            str,
        int                     str_len,
        int *                   charset,
        cn_people_name_item_t * result,
        int                     result_max
    );
    int ( * cn_people_name_get_sample )(
        cn_people_name_t *      self,
        const char *            str,
        int                     str_len,
        int *                   charset,
        cn_people_name_item_t * result,
        int                     result_max
    );
    /** 
     * @brief create a timers
     *   @param timers_malloc * m: [optional] memory alloc function
     *   @param timers_free * f:   [optional] memory free function
     * @return timers_t timers
     */
    timers_t ( * timers_create )(
        timers_malloc   m,
        timers_free     f
    );
    /**
     * @brief destroy timers
     * @param[in] this timers
     */
    void ( * timers_destroy )(
        timers_t This
    );
    /**
     * @brief start timer
     * @param[in] this timers
     */
    bool ( * timers_start )(
        timers_t This
    );
    /**
     * @brief stop timers
     * @param[in] this timers
     */
    void ( * timers_stop )(
        timers_t This
    );
    /** 
     * @brief add a timer
     * @param[in] this timers 
     * @param[in] interval_ms time out ms, this is a relative time.
     * @param[in] callback timer callback function
     * @param[in] free_obj delete timer function
     * @param[in] param1 callback function param 1
     * @param[in] param2 callback function param 2
     * @return timer_node * non NULL: successed; NULL: failed
     */
    timer_node * ( * timers_add_timer )(
        timers_t This,
        int interval_ms,
        timers_callback callback,
	    timers_free_node_obj free_obj,
        void * param1,
        void * param2,
        bool is_sync
    );
    /** 
     * @brief delete a timer
     * @param[in] this timers object
     * @param[in] timer_node * p: return by timers_add_timer function
     */
    bool ( * timers_del_timer )(
        timers_t This,
        timer_node * p,
        bool is_sync
    );
    /** 
     * @brief timer thread call this function
     */
    void ( * timers_thread_loop )(
        timers_t This
    );
    void ( * fmap_init )(
        fmap_t *    o
    );
    bool ( * fmap_open )(
        fmap_t *        o,
        const char *    path,
        size_t          offset,
        size_t          len,
        bool            read_write
    );
    bool ( * fmap_flush )(
        fmap_t *        o
    );
    void ( * fmap_close )(
        fmap_t * o
    );

    ini_t * ( * ini_create )(
        const char * path
    );

    ini_t * ( * ini_create_memory )(
        const char * content,
        size_t content_len
    );

    void ( * ini_destroy )(
        ini_t * This
    );

    size_t ( * ini_get_sections_count )(
        ini_t * ini
    );

    bool ( * ini_get_sections )(
       ini_t * ini,
       const char ** sections,
       size_t * sections_count
    );

    bool ( * ini_get_bool )(
        ini_t * ini,
        const char * section,
        const char * name,
        bool def
    );

    int ( * ini_get_int )(
        ini_t * ini,
        const char * section,
        const char * name,
        int def
    );

    long long ( * ini_get_int64 )(
        ini_t * ini,
        const char * section,
        const char * name,
        long long def
    );

    const char * ( * ini_get_string )(
        ini_t * This,
        const char * section,
        const char * name,
        const char * def
    );

    bool ( * del_dir )( const char * path );
    bool ( * del_file )( const char * path );

    agile_t * ( * agile_create )(
        const char *    addr_list,
        const char *    addr_list_sep,
        int             connect_timeout_s,
        int             recv_timeout_s,
        const char *    user,
        const char *    passwd
    );
    void ( * agile_destroy )(
        agile_t *       self
    );

    int ( * agile_get )(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version,
        void *          rsp,
        size_t *        rsp_len
    );
    int ( * agile_put )(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        const void *    value,
        size_t          value_len,
        uint32_t *      version
    );
    int ( * agile_del )(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version
    );
    int ( * agile_exist )(
        agile_t *       self,
        const void *    key,
        size_t          key_len,
        uint32_t *      version
    );
    cn_place_name_item_t * ( * cn_place_name_parent )(
        cn_place_name_item_t *  child
    );
    int ( * cn_place_name_child_count )(
        cn_place_name_item_t *  parent
    );
    cn_place_name_item_t * ( * cn_place_name_child )(
        cn_place_name_item_t *  parent,
        int                     index
    );
    cn_place_name_item_t * ( * cn_place_name_find_by_id )(
        int                     node_id
    );
    cn_place_name_item_t * ( * cn_place_name_find_by_name )(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   next_node_id,
        int                     priority_elder_id
    );
    size_t ( * cn_place_name_match_all_by_name )(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   id_list,
        size_t                  id_list_max,
        int                     priority_elder_id
    );
    size_t ( * cn_place_name_match_part_by_name )(
        const char *            gbk_name,
        size_t                  gbk_name_len,
        int *                   id_list,
        size_t                  id_list_max,
        int                     priority_elder_id
    );
    int ( * cn_place_name_id_compare )(
        int                     left,
        int                     right
    );
    bool ( * cn_place_name_check_elder )(
        int                     elder_id,
        int                     child_id
    );
    cn_place_name_item_t * ( * cn_place_name_top_parent )(
        cn_place_name_item_t *  child
    );
    highway_info_t * ( * cn_highway_info )(
        int G_id
    );
    highway_station_t * ( * cn_highway_by_place_id )(
        int *                   place_id,
        int *                   result_count
    );

    MiniDbConnection * ( * db_connect )( const char * uri, const char * user, const char * passwd );
    void ( * db_conn_release )( MiniDbConnection * conn );
    bool ( * db_conn_execute_non_query )( MiniDbConnection * conn, const char * sql, int64_t * affected );
    MiniDataReader * ( * db_conn_execute_reader )( MiniDbConnection * conn, const char * sql, int32_t page_size, int64_t cur_page );
    void ( * db_reader_release )( MiniDataReader * reader );
    int ( * db_reader_get_column_count )( MiniDataReader * reader );
    int ( * db_reader_get_column_index )( MiniDataReader * reader, const char * name );
    bool ( * db_reader_read )( MiniDataReader * reader, bool read_page );
    int ( * db_reader_get_int )( MiniDataReader * reader, int index, int def );
    int64_t ( * db_reader_get_int64 )( MiniDataReader * reader, int index, int64_t def );
    double ( * db_reader_get_float )( MiniDataReader * reader, int index );
    int64_t ( * db_reader_get_datetime )( MiniDataReader * reader, int index );
    const char * ( * db_reader_get_string )( MiniDataReader * reader, int index, size_t * len );
    const void * ( * db_reader_get_binary )( MiniDataReader * reader, int index, size_t * len );
    int ( * cn_people_name_surname )(
        cn_people_name_t *      self,
        const char *            str,
        int                     str_len,
        int *                   charset,
        const char **           suname
    );
    cn_place_name_item_t * ( * fixed_tel_get_city_code )(
        const char *    fixed_tel,
        size_t          fixed_tel_len,
        int *           city_code_len,
        int *           place_id
    );
    int ( * analyse_places )(
        const char *                gbk_text,
        int                         gbk_text_bytes,
        cn_place_name_item_t **     result,
        int                         max_count
    );
    bool ( * analyse_places_tels )(
        const char *                gbk_text,
        int                         gbk_text_bytes,
        cn_place_name_item_t **     places,
        int *                       places_count,
        const_str *                 tels,
        int *                       tels_count
    );

    cn_place_name_item_t * ( * t2260_2013_to_place )( const char * str, size_t str_len );
    int64_t ( * get_file_size )( const char * path );
    int ( * place_id_to_city_code )( int place_id, int * result, size_t result_max );

    // NetCom
    // MOBILE_PROVIDER_NC = 1,
    // China TeleCom  
    // MOBILE_PROVIDER_CT  = 2,
    // China UniCom  
    // MOBILE_PROVIDER_UC  = 3
    int ( * get_mobile_provider )( const char * str, size_t str_len );
    int ( * get_mobile_provider2 )( const char * str, size_t str_len, int * small_id );

    int ( * get_mobile_place )(
        const char *                str,
        size_t                      str_len,
        int *                       provider,
        cn_place_name_item_t **     place,
        int                         place_max
    );

};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#ifndef _fclass_base_thread_h_

    #if ! defined( __APPLE__ )
        #define THREAD_T    thread2_t
        class thread2_t;
        typedef thread2_t thread_t;
    #else
        // FUCK!!!!!!!!!!!!!!!!!!!!!!!!!! OS X !!!!!!!!!!!
        #define THREAD_T    thread2_t
    #endif

    class THREAD_T
    {
    public:

        THREAD_T()
            : m_server( NULL )
            , m_buildin( NULL )
            , m_funcs( NULL )
        {
        }

        virtual ~THREAD_T()
        {
            stop();
        }

        bool is_started() const
        {
            if ( unlikely( NULL == m_funcs ) ) {
                return false;
            }
            return m_funcs->os_thread_is_started( & m_thread );
        }

        bool is_need_exit() const
        {
            if ( unlikely( NULL == m_funcs ) ) {
                return true;
            }
            return m_funcs->os_thread_is_need_exit( & m_thread );
        }

        bool is_exited() const
        {
            if ( unlikely( NULL == m_funcs ) ) {
                return true;
            }
            return m_funcs->os_thread_is_exited( & m_thread );
        }

        int tid() const
        {
            if ( unlikely( NULL == m_funcs ) ) {
                return -1;
            }
            return m_funcs->os_thread_tid( & m_thread );
        }

        static void * thread_routine( void * p )
        {
            THREAD_T * t = (THREAD_T *)p;
            t->run();
            return NULL;
        }

        virtual bool start( gr_server_t * server )
        {
            if ( unlikely( NULL == server ) ) {
                fprintf( stderr, "server is NULL\n" );
                return false;
            }

            m_server    = server;
            m_buildin   = server->library->buildin;
            m_funcs     = server->library->parallel;

            m_funcs->os_thread_init( & m_thread );
            bool b = m_funcs->os_thread_start( & m_thread, thread_routine, this );
            if ( unlikely( ! b ) ) {
                m_buildin->log( __FILE__, __LINE__, __FUNCTION__, GR_LOG_ERROR,
                                "os_thread_start failed" );
                return false;
            }

            return true;
        }

        virtual void stop()
        {
            if ( m_funcs ) {
                m_funcs->os_thread_stop( & m_thread );
            }
        }

        virtual void run()
        {
            // sample code
            while ( ! is_need_exit() ) {
                m_buildin->sleep_ms( 1000 );
            }
        }

    protected:

        gr_server_t *       m_server;
        gr_i_server_t *     m_buildin;
        gr_i_parallel_t *   m_funcs;
        os_thread_t         m_thread;

    private:
        // disable
        THREAD_T(const THREAD_T &);
        const THREAD_T & operator = (const THREAD_T &);
    };

#endif // #ifndef _fclass_base_thread_h_

#endif // #ifdef __cplusplus

#ifndef _fclass_base_string_h_

#ifdef __cplusplus
extern "C" {
#endif

static inline int isspace2( char c )
{
    switch ( c )
    {
    case 0x20:
    case 0x09:
    case 0x0A:
    case 0x0D:
    case 0x00:
    case 0x0B:
        return 1;
    default:
        break;
    };

    if ( c > 0 ) {
        return isspace( c );
    }

    return 0;
}

static inline char * str_trim(
    char *      s,
    int *       len
)
{
    char *  t;
    int     n;
    char *  orig_s;
    char *  orig_e;
        
    assert( s );
    if ( len && * len >= 0 ) {
        n = * len;
    } else {
        n = (int)strlen( s );
    }
    orig_s = s;
    orig_e = s + n;

    // de pre space
    while ( n > 0 && isspace2( * s ) ) {
        ++ s;
        -- n;
    };
        
    // de tail space
    if ( n > 0 ) {
        t = s + n;
        while( n > 0 && isspace2( * ( t - 1 ) ) ) {
            -- t;
            -- n;
        };
        if ( t < orig_e ) {
            * t = '\0';
        }
    }
        
    if ( len ) {
        * len = n;
    }
    return s;
}

#ifndef _GROCKET_SERVER_LIBGROCKET_GR_TOOLS_H_

// fast_mem?cmp
#if (S_LITTLE_ENDIAN)
    #define fast_mem2cmp(m, c0, c1)                                                \
        ( *(uint16_t *)(m) == (c1 << 8 | c0) )
    #define fast_mem3cmp(m, c0, c1, c2)                                            \
        ( fast_mem2cmp((m), c0, c1 ) && ( (m)[2] == c2 ) )
    #define fast_mem4cmp(m, c0, c1, c2, c3)                                        \
        ( *(uint32_t *)(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) )
    #define fast_mem5cmp(m, c0, c1, c2, c3, c4)                                    \
        ( *(uint32_t *)(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)       \
        && (m)[4] == c4 )
    #define fast_mem6cmp(m, c0, c1, c2, c3, c4, c5)                                \
        ( *(uint32_t *)(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)       \
        && (((uint32_t *)(m))[1] & 0xffff) == ((c5 << 8) | c4) )
    #define fast_mem7cmp(m, c0, c1, c2, c3, c4, c5, c6)                            \
        ( *(uint32_t *)(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)       \
        && (((uint32_t *)(m))[1] & 0xffffff) == ( (c6 << 16) | (c5 << 8) | c4) )
    #define fast_mem8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
        ( *(uint32_t *)(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)       \
        && ((uint32_t *)(m))[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4) )
    #define fast_mem9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
                    ( fast_mem8cmp((m), c0, c1, c2, c3, c4, c5, c6, c7) && (m)[8] == c8 )
#else
    #define fast_mem2cmp(m, c0, c1)                                                \
        ( (m)[0] == c0 && (m)[1] == c1 )
    #define fast_mem3cmp(m, c0, c1, c2)                                            \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 )
    #define fast_mem4cmp(m, c0, c1, c2, c3)                                        \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3 )
    #define fast_mem5cmp(m, c0, c1, c2, c3, c4)                                    \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3 && (m)[4] == c4 )
    #define fast_mem6cmp(m, c0, c1, c2, c3, c4, c5)                                \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3                \
        && (m)[4] == c4 && (m)[5] == c5 )
    #define fast_mem7cmp(m, c0, c1, c2, c3, c4, c5, c6)                            \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3                \
        && (m)[4] == c4 && (m)[5] == c5 && (m)[6] == c6 )
    #define fast_mem8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3                \
        && (m)[4] == c4 && (m)[5] == c5 && (m)[6] == c6 && (m)[7] == c7 )
    #define fast_mem9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
        ( (m)[0] == c0 && (m)[1] == c1 && (m)[2] == c2 && (m)[3] == c3                \
        && (m)[4] == c4 && (m)[5] == c5 && (m)[6] == c6 && (m)[7] == c7 && (m)[8] == c8 )
#endif

// fast_mem?cpy
#if (S_LITTLE_ENDIAN)
    #define fast_mem2cpy(m, c0, c1)                                                \
        ( *(uint16_t *)(m) = (c1 << 8 | c0) )
    #define fast_mem3cpy(m, c0, c1, c2)                                            \
        ( fast_mem2cpy((m), c0, c1 ), ( (m)[2] = c2 ) )
    #define fast_mem4cpy(m, c0, c1, c2, c3)                                        \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) )
    #define fast_mem5cpy(m, c0, c1, c2, c3, c4)                                    \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
        , (m)[4] = c4 )
    #define fast_mem6cpy(m, c0, c1, c2, c3, c4, c5)                                \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
        , (m)[4] = c4, (m)[5] = c5 )
    #define fast_mem7cpy(m, c0, c1, c2, c3, c4, c5, c6)                            \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
        , (m)[4] = c4, (m)[5] = c5, (m)[6] = c6 )
    #define fast_mem8cpy(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
        , ((uint32_t *)(m))[1] = ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4) )
    #define fast_mem9cpy(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
        ( *(uint32_t *)(m) = ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
        , ((uint32_t *)(m))[1] = ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)    \
        , (m)[8] = c8 )
#else
    #define fast_mem2cpy(m, c0, c1)                                                \
        ( (m)[0] = c0, (m)[1] = c1 )
    #define fast_mem3cpy(m, c0, c1, c2)                                            \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2 )
    #define fast_mem4cpy(m, c0, c1, c2, c3)                                        \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] == c3 )
    #define fast_mem5cpy(m, c0, c1, c2, c3, c4)                                    \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] = c3, (m)[4] == c4 )
    #define fast_mem6cpy(m, c0, c1, c2, c3, c4, c5)                                \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] == c3                         \
        , (m)[4] = c4, (m)[5] = c5 )
    #define fast_mem7cpy(m, c0, c1, c2, c3, c4, c5, c6)                            \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] = c3                          \
        , (m)[4] = c4, (m)[5] = c5, (m)[6] = c6 )
    #define fast_mem8cpy(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] = c3                          \
        , (m)[4] = c4, (m)[5] = c5, (m)[6] = c6, (m)[7] = c7 )
    #define fast_mem9cpy(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
        ( (m)[0] = c0, (m)[1] = c1, (m)[2] = c2, (m)[3] = c3                          \
        , (m)[4] = c4, (m)[5] = c5, (m)[6] = c6, (m)[7] = c7, (m)[8] = c8 )
#endif

static inline
void fast_memcpy(
    void *          dest,
    const void *    src,
    size_t          len
)
{
    switch ( len )
    {
    case 0:
        break;
    case 1:
        ((unsigned char *)dest)[0] = ((const unsigned char *)src)[0];
        break;
    case 2:
        fast_mem2cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1]
        );
        break;
    case 3:
        fast_mem3cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2]
        );
        break;
    case 4:
        fast_mem4cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3]
        );
        break;
    case 5:
        fast_mem5cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3],
                      ((const unsigned char *)src)[4]
        );
        break;
    case 6:
        fast_mem6cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3],
                      ((const unsigned char *)src)[4],
                      ((const unsigned char *)src)[5]
        );
        break;
    case 7:
        fast_mem7cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3],
                      ((const unsigned char *)src)[4],
                      ((const unsigned char *)src)[5],
                      ((const unsigned char *)src)[6]
        );
        break;
    case 8:
        fast_mem8cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3],
                      ((const unsigned char *)src)[4],
                      ((const unsigned char *)src)[5],
                      ((const unsigned char *)src)[6],
                      ((const unsigned char *)src)[7]
        );
        break;
    case 9:
        fast_mem9cpy( (unsigned char *)dest,
                      ((const unsigned char *)src)[0],
                      ((const unsigned char *)src)[1],
                      ((const unsigned char *)src)[2],
                      ((const unsigned char *)src)[3],
                      ((const unsigned char *)src)[4],
                      ((const unsigned char *)src)[5],
                      ((const unsigned char *)src)[6],
                      ((const unsigned char *)src)[7],
                      ((const unsigned char *)src)[8]
        );
        break;
    default:
        memcpy( dest, src, len );
        break;
    }
}

static inline
bool mem_equal(
    const void *    lhd,
    const void *    rhd,
    size_t          len
)
{
    switch ( len )
    {
    case 0:
        return true;
    case 1:
        return ((const unsigned char *)lhd)[0] == ((const unsigned char *)rhd)[0];
    case 2:
        return fast_mem2cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1]
        );
    case 3:
        return fast_mem3cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2]
        );
    case 4:
        return fast_mem4cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3]
        );
    case 5:
        return fast_mem5cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3],
                      ((const unsigned char *)rhd)[4]
        );
    case 6:
        return fast_mem6cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3],
                      ((const unsigned char *)rhd)[4],
                      ((const unsigned char *)rhd)[5]
        );
    case 7:
        return fast_mem7cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3],
                      ((const unsigned char *)rhd)[4],
                      ((const unsigned char *)rhd)[5],
                      ((const unsigned char *)rhd)[6]
        );
    case 8:
        return fast_mem8cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3],
                      ((const unsigned char *)rhd)[4],
                      ((const unsigned char *)rhd)[5],
                      ((const unsigned char *)rhd)[6],
                      ((const unsigned char *)rhd)[7]
        );
    case 9:
        return fast_mem9cmp( (const unsigned char *)lhd,
                      ((const unsigned char *)rhd)[0],
                      ((const unsigned char *)rhd)[1],
                      ((const unsigned char *)rhd)[2],
                      ((const unsigned char *)rhd)[3],
                      ((const unsigned char *)rhd)[4],
                      ((const unsigned char *)rhd)[5],
                      ((const unsigned char *)rhd)[6],
                      ((const unsigned char *)rhd)[7],
                      ((const unsigned char *)rhd)[8]
        );
    default:
        return 0 == memcmp( lhd, rhd, len );
    }
}

#endif // #ifndef _GROCKET_SERVER_LIBGROCKET_GR_TOOLS_H_

#ifdef __cplusplus
}
#endif

#endif // #ifndef _fclass_base_string_h_

#ifndef _fclass_base_lock_h_
#define _fclass_base_lock_h_

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////
//
// InitializeCriticalSection, DeleteCriticalSection,
// EnterCriticalSection, LeaveCriticalSection
// for Non Windows OS
//
// pthread_mutex_init, pthread_mutex_destroy,
// pthread_mutex_lock, pthread_mutex_unlock
// for Windows OS
//
// Lockable, ScopeLock for C++
//

#if defined( WIN32 ) || defined( WIN64 )

    // Windows

    typedef struct pthread_mutex_t
    {
        CRITICAL_SECTION    lock;

        unsigned char       is_init;

    } pthread_mutex_t;

    /**
     * @function pthread_mutex_init
     * @brief 
     * @param[in] pthread_mutex_t * p:
     * @param[in] void * zero: not used, must be zero
     */
    static inline
    int pthread_mutex_init( pthread_mutex_t * p, void * zero )
    {
        InitializeCriticalSection( & p->lock );
        p->is_init = 1;
        return 0;
    }

    /**
     * @function pthread_mutex_destroy
     * @brief 
     * @param[in] pthread_mutex_t * p: 
     */
    static inline
    void pthread_mutex_destroy( pthread_mutex_t * p )
    {
        DeleteCriticalSection( & p->lock );
        p->is_init = 0;
    }

    /**
     * @function pthread_mutex_lock
     * @brief 
     * @param[in] pthread_mutex_t * p: 
     */
    static inline
    void pthread_mutex_lock( pthread_mutex_t * p )
    {
        if ( ! p->is_init ) {
            pthread_mutex_init( p, NULL );
        }

        EnterCriticalSection( & p->lock );
    }

    /**
     * @function pthread_mutex_unlock
     * @brief 
     * @param[in] pthread_mutex_t * p: 
     */
    static inline
    void pthread_mutex_unlock( pthread_mutex_t * p )
    {
        LeaveCriticalSection( & p->lock );
    }

#else

    // Non Windows

    typedef pthread_mutex_t CRITICAL_SECTION;

    /**
     * @function InitializeCriticalSection
     * @brief 
     * @param[out] CRITICAL_SECTION * p: 
     */
    static inline
    void InitializeCriticalSection( CRITICAL_SECTION * p )
    {
        pthread_mutex_init( p, NULL );
    }

    /**
     * @function DeleteCriticalSection
     * @brief 
     * @param[in] CRITICAL_SECTION * p: 
     */
    static inline
    void DeleteCriticalSection( CRITICAL_SECTION * p )
    {
        pthread_mutex_destroy( p );
    }

    /**
     * @function EnterCriticalSection
     * @brief 
     * @param[in] CRITICAL_SECTION * p: 
     */
    static inline
    void EnterCriticalSection( CRITICAL_SECTION * p )
    {
        pthread_mutex_lock( p );
    }

    /**
     * @function LeaveCriticalSection
     * @brief 
     * @param[in] CRITICAL_SECTION * p: 
     */
    static inline
    void LeaveCriticalSection( CRITICAL_SECTION * p )
    {
        pthread_mutex_unlock( p );
    }

#endif

#ifdef __cplusplus
}

#define DEBUG_LOCK  0

/**
 * @class lockable_t
 * @brief 
 */
struct lockable_t
{
public:
    lockable_t()
#if DEBUG_LOCK
        : m_file( NULL ), m_line( 0 )
#endif
    {
#if defined( WIN32 ) || defined( WIN64 )
        pthread_mutex_init( & m_lock, NULL );
#elif defined(__FreeBSD__) || defined(__APPLE__)
        pthread_mutex_init( & m_lock, NULL );
#else
        pthread_mutexattr_t attr;
        pthread_mutexattr_init( & attr );
        pthread_mutexattr_settype( & attr, PTHREAD_MUTEX_RECURSIVE_NP );
        pthread_mutex_init( & m_lock, & attr );
        pthread_mutexattr_destroy( & attr );
#endif
    }

    ~lockable_t() { pthread_mutex_destroy( & m_lock ); }

    pthread_mutex_t * get() { return & m_lock; }

    void lock() { pthread_mutex_lock( & m_lock ); }

    void unlock()
    {
#if DEBUG_LOCK
        if ( NULL != m_file || 0 != m_line ) {
            //printf( "%s:%d leave\n",
            //    m_file, m_line );
            m_file = NULL;
            m_line = 0;
        } else {
            printf( "double leave\n" );
        }
#endif
        pthread_mutex_unlock( & m_lock );
    }

#if DEBUG_LOCK
    void lock( const char * file, int line )
    {
        if ( NULL != m_file || 0 != m_line ) {
            printf( "%s:%d coming, but %s:%d already lock\n",
                file, line, m_file, m_line );
        } else {
            //printf( "%s:%d coming\n", file, line );
            m_file = file;
            m_line = line;
        }

        pthread_mutex_lock( & m_lock );
    }
#else
    void lock( const char *, int ) { pthread_mutex_lock( & m_lock ); }
#endif

private:
    pthread_mutex_t m_lock;
#if DEBUG_LOCK
    const char *    m_file;
    int             m_line;
#endif

private:
    // disable
    lockable_t(const lockable_t &);
    const lockable_t & operator = (const lockable_t &);
};

/**
 * @class scope_lock_t
 * @brief 
 */
struct scope_lock_t
{
public:
    explicit scope_lock_t( lockable_t & lock ) : m_lock( lock ) { m_lock.lock(); }
    ~scope_lock_t() { m_lock.unlock(); }

#if DEBUG_LOCK
    explicit scope_lock_t( lockable_t & lock, const char * file, int line )
        : m_lock( lock )
    { m_lock.lock( file, line ); }
#else
    explicit scope_lock_t( lockable_t & lock, const char *, int ) : m_lock( lock ) { m_lock.lock(); }
#endif

private:
    lockable_t & m_lock;

private:
    // disable
    scope_lock_t();
    scope_lock_t(const scope_lock_t &);
    const scope_lock_t & operator = (const scope_lock_t &);
};

#endif // #ifdef __cplusplus

///////////////////////////////////////////////////////////////////////
//
// rwlockable_t, scope_rlock_t, scope_wlock_t
//

#ifdef __cplusplus

#if defined( WIN32 ) || defined( WIN64 )

struct rwlockable_t
{
public:
    rwlockable_t() : m_nReaders(0), m_nWriters(0)
    {
        m_hDataEvent = CreateEvent(
            NULL,    // no security attributes
            FALSE,   // Auto reset event
            FALSE,   // initially set to non signaled state
            NULL);   // un named event
        InitializeCriticalSection( & m_WriteLock );
    }

    ~rwlockable_t()
    {
        DeleteCriticalSection( & m_WriteLock );
        CloseHandle( m_hDataEvent );
    }

    void rlock() const
    {
        // 有写入线程,等  
        while( m_nReaders > 0 ) {
            WaitForSingleObject( m_hDataEvent, 50 );
        }

        InterlockedIncrement( & m_nReaders );
    }

    void runlock() const
    {
        long n = InterlockedDecrement( & m_nReaders );
        if ( 0 == n ) {
            SetEvent( m_hDataEvent );
        }
    }

    void wlock() const
    {
        // 有读或写线程,等  
        while ( m_nReaders > 0 || m_nWriters > 0 ) {
            WaitForSingleObject( m_hDataEvent, 50 );
        }

        InterlockedIncrement( & m_nWriters );

        EnterCriticalSection( & m_WriteLock );
    }

    void wunlock() const
    {
        LeaveCriticalSection( & m_WriteLock );

        long n = InterlockedDecrement( & m_nWriters );

        if ( 0 == n ) {
            SetEvent( m_hDataEvent );
        }
    }

private:
    mutable volatile long       m_nReaders;
    mutable volatile long       m_nWriters;
    mutable CRITICAL_SECTION    m_WriteLock;
    mutable HANDLE              m_hDataEvent;

private:
    // disable
    rwlockable_t(const rwlockable_t &);
    const rwlockable_t & operator = (const rwlockable_t &);
};

#elif defined( __ANDROID__ )

struct rwlockable_t
{
public:
    rwlockable_t() { pthread_mutex_init( & m_lock, NULL ); }
    ~rwlockable_t() { pthread_mutex_destroy( & m_lock ); }

    void rlock() const { pthread_mutex_lock( & m_lock ); }
    void runlock() const { pthread_mutex_unlock( & m_lock ); }

    void wlock() const { pthread_mutex_lock( & m_lock ); }
    void wunlock() const { pthread_mutex_unlock( & m_lock ); }

private:
    mutable pthread_mutex_t m_lock;

private:
    // disable
    rwlockable_t(const rwlockable_t &);
    const rwlockable_t & operator = (const rwlockable_t &);
};

#else

struct rwlockable_t
{
public:
    rwlockable_t() { pthread_rwlock_init( & m_lock, NULL ); }
    ~rwlockable_t() { pthread_rwlock_destroy( & m_lock ); }

    void rlock() const { pthread_rwlock_rdlock( & m_lock ); }
    void runlock() const { pthread_rwlock_unlock( & m_lock ); }

    void wlock() const { pthread_rwlock_wrlock( & m_lock ); }
    void wunlock() const { pthread_rwlock_unlock( & m_lock ); }

private:
    mutable pthread_rwlock_t m_lock;

private:
    // disable
    rwlockable_t(const rwlockable_t &);
    const rwlockable_t & operator = (const rwlockable_t &);
};

#endif

struct scope_rlock_t
{
public:
    explicit scope_rlock_t( rwlockable_t & lock ) : m_lock( lock ) {
        m_lock.rlock();
    }

    ~scope_rlock_t() {
        m_lock.runlock();
    }

private:
    rwlockable_t & m_lock;

private:
    // disable
    scope_rlock_t();
    scope_rlock_t(const scope_rlock_t &);
    const scope_rlock_t & operator = (const scope_rlock_t &);
};

struct scope_wlock_t
{
public:
    explicit scope_wlock_t( rwlockable_t & lock ) : m_lock( lock ) {
        m_lock.wlock();
    }

    ~scope_wlock_t() {
        m_lock.wunlock();
    }

private:
    rwlockable_t & m_lock;

private:
    // disable
    scope_wlock_t();
    scope_wlock_t(const scope_wlock_t &);
    const scope_wlock_t & operator = (const scope_wlock_t &);
};

#endif // #ifdef __cplusplus

//
// rwlockable_t, scope_rlock_t, scope_wlock_t
//
///////////////////////////////////////////////////////////////////////

#endif // #ifndef _fclass_base_lock_h_


#ifndef _fclass_base_tool_h_
#ifdef __cplusplus

static inline
bool
load_file(
    const char * path,
    std::string & result
)
{
    FILE * h = NULL;
    long sz = 0;
    bool r = false;
    char ph[ MAX_PATH ];

    if ( NULL == path || '\0' == * path ) {
        result.resize( 0 );
        return false;
    }

    strncpy( ph, path, sizeof( ph ) );
    ph[ sizeof( ph ) - 1 ] = '\0';
    if ( ph[ 0 ] ) {
        char * path = ph;
        while ( * path ) {
            if ( '/' == * path || '\\' == * path )
                * path = S_PATH_SEP_C;
            ++ path;
        }
    }

    h = fopen( ph, "rb" );
    if ( NULL == h ) {
        result.resize( 0 );
        return false;
    }

    do {

        if ( 0 != fseek( h, 0, SEEK_END ) ) {
            break;
        }

        sz = ftell( h );
        if ( -1L == sz ) {
            break;
        }

        if ( 0 != fseek( h, 0, SEEK_SET ) ) {
            break;
        }

        result.resize( 0 );
        try {
            result.resize( (size_t)sz );
        } catch( ... ) {
            break;
        }

        if ( sz > 0 ) {
            size_t readed = 0;
            bool ok = true;
            while ( sz > 0 ) {

                size_t item = sz;
                if ( item > 1 * 1024 * 1024 ) {
                    item = 1 * 1024 * 1024;
                }

                size_t ret = fread( & result[ readed ], 1, item, h );
                if ( item != ret ) {
                    result.resize( 0 );
                    ok = false;
                    break;
                }

                readed += ret;
                sz -= (long)ret;
            }
            if ( ! ok ) {
                break;
            }
        }

        r = true;

    } while( 0 );

    fclose( h );

    return r;
}
#endif // #ifdef __cplusplus
#endif // #ifndef _fclass_base_tool_h_

#ifndef _fclass_base_string_h_
#ifdef __cplusplus

static inline
bool to_vector( const std::string & src, const std::string & sep, std::vector< std::string > & result )
{
    result.resize( 0 );
        
    if ( sep.empty() ) {
        return false;
    }

    bool sep_has_space = false;
    for ( size_t i = 0; i < sep.size(); ++ i ) {
        if ( sep[ i ] > 0 && isspace( sep[ i ] ) ) {
            sep_has_space = true;
            break;
        }
    }

    int count = 1;
    size_t pos = 0;
        
    while( pos < src.size() ) {
            
        pos = src.find( sep.c_str(), pos );
        if ( pos == std::string::npos ) {
            break;
        }
            
        ++ count;
            
        pos += sep.size();
    }
        
    if ( result.capacity() < (size_t)count ) {
        try {
            result.reserve( count );
        } catch ( ... ) {
            return false;
        }
    }
        
    std::string t;
    const char * p;
        
    pos = 0;
    size_t pos2 = 0;
    while ( pos < src.size() ) {
            
        pos2 = src.find( sep.c_str(), pos );
        if ( std::string::npos == pos2 ) {
            try {
                t = src.substr( pos );
                if ( sep_has_space ) {
                    result.push_back( t );
                } else {
                    p = str_trim( (char *)t.c_str(), NULL );
                    result.push_back( p ? p : "" );
                }
            } catch ( ... ) {
                result.resize( 0 );
                return false;
            }
            break;
        } else {
            try {
                t = src.substr( pos, pos2 - pos );
                if ( sep_has_space ) {
                    result.push_back( t );
                } else {
                    p = str_trim( (char *)t.c_str(), NULL );
                    result.push_back( p ? p : "" );
                }
            } catch ( ... ) {
                result.resize( 0 );
                return false;
            }
        }
            
        pos = pos2 + sep.size();
    }
        
    if ( result.size() < (size_t)count ) {
        // we must confirm element count is right
        result.resize( (size_t)count );
    }

    return true;
}

static inline
int stdstr_replace( std::string & s, const char * lpszOld, const char * lpszNew )
{
    if ( s.empty() )
        return 0;
    if ( NULL == lpszOld || '\0' == * lpszOld )
        return 0;
        
    int count = 0;
        
    if ( NULL == lpszNew )
        lpszNew = "";
        
    std::string src = lpszOld;
    std::string dest = lpszNew;
        
    size_t srclen = src.size();
    size_t dstlen = dest.size();
        
    if ( srclen == dstlen ) {
        // from begin to end
        size_t pos = 0;
        while( ( pos = s.find( src, pos ) ) != std::string::npos ) {
            fast_memcpy( & s[ pos ], dest.c_str(), dstlen );
            ++ count;
            pos += srclen;
        }
    } else {
        // from tail to begin
        size_t pos = std::string::npos;
        while( ( pos = s.rfind( src, pos ) ) != std::string::npos ) {
            s.replace( pos, srclen, dest );
                
            ++ count;
                
            if ( 0 == pos )
                break;
                
            -- pos;
        }
    }
        
    return count;
}
#endif // #ifdef __cplusplus
#endif // #ifndef _fclass_base_string_h_

#ifndef _fclass_base_fifo_thread_h_
#ifdef __cplusplus

template< class T >
class fifo_thread_t : public THREAD_T
{
protected:

    typedef std::list< T * >  tasks_t;

    gr_server_t *   m_server;
    tasks_t         m_tasks;
    lockable_t      m_lock;
    size_t          m_size;
    event_t         m_event;
    unsigned int    m_event_wait_ms;

public:
    fifo_thread_t()
        : THREAD_T()
        , m_server( NULL )
        , m_tasks()
        , m_lock()
        , m_size( 0 )
        , m_event_wait_ms( 5 )
    {
        memset( & m_event, 0, sizeof( m_event ) );
    }

    ~fifo_thread_t()
    {
        stop();
    }

    virtual bool start( gr_server_t * server )
    {
        m_server = server;
        if ( unlikely( NULL == m_server ) ) {
            return false;
        }

        if ( ! m_server->library->buildin->event_create( & m_event ) ) {
            m_server->library->buildin->log(
                __FILE__, __LINE__, __FUNCTION__, GR_LOG_ERROR,
                "event_create failed" );
            return false;
        }

        if ( ! THREAD_T::start( m_server ) ) {
            m_server->library->buildin->log(
                __FILE__, __LINE__, __FUNCTION__, GR_LOG_ERROR,
                "thread_t::start failed" );
            return false;
        }

        return true;
    }

    virtual void stop()
    {
        if ( NULL == m_server ) {
            return;
        }

        m_server->library->buildin->event_alarm( & m_event );

        THREAD_T::stop();

        scope_lock_t lock( m_lock );

        if ( ! m_tasks.empty() ) {
            for ( typename tasks_t::iterator i = m_tasks.begin(); i != m_tasks.end(); ++ i ) {
                T * p = (*i);
                if ( p ) {
                    p->release();
                }
            }
            m_tasks.clear();
        }

        m_size = 0;    
    }

    bool set_event_wait_ms( unsigned int ms )
    {
        if ( 0 == ms ) {
            return false;
        }

        m_event_wait_ms = ms;
        return true;
    }

    // call by push thread
    bool push( T * task )
    {
        if ( NULL == m_server ) {
            if ( task ) {
                task->release();
            }
            return false;
        }

        if ( unlikely( NULL == task ) ) {
            m_server->library->buildin->log(
                __FILE__, __LINE__, __FUNCTION__, GR_LOG_ERROR,
                "task is NULL" );
            return false;
        }

        scope_lock_t lock( m_lock );
        try {
            m_tasks.push_back( task );
            ++ m_size;
            return m_server->library->buildin->event_alarm( & m_event );
        } catch ( ... ) {
            m_server->library->buildin->log(
                __FILE__, __LINE__, __FUNCTION__, GR_LOG_ERROR,
                "bad_alloc" );
        }

        return false;
    }

    size_t size()
    {
        return m_size;
    }

    bool empty()
    {
        return 0 == m_size;
    }

    virtual void run()
    {
        if ( NULL == m_server ) {
            return;
        }

        while ( ! is_need_exit() ) {
            int r;

            r = m_server->library->buildin->event_wait( & m_event, m_event_wait_ms );
            if ( 1 != r ) {
                continue;
            }

            while ( 1 ) {
                T * p = NULL;

                {
                    scope_lock_t lock( m_lock );
                    if ( m_tasks.empty() ) {
                        break;
                    }

                    p = m_tasks.front();
                    m_tasks.pop_front();
                    -- m_size;
                }

                if ( p ) {
                    p->process();
                    //p->release();
                }
            }
        }
    }

private:
    // disable
    fifo_thread_t(const fifo_thread_t &);
    const fifo_thread_t & operator = (const fifo_thread_t &);
};

#endif // #ifdef __cplusplus
#endif // #ifndef _fclass_base_fifo_thread_h_

#ifndef _fclass_base_timers_h_
#ifdef __cplusplus

namespace base
{

//class CB
//{
//public:
    /** 
	 * @brief timer callback function
	 * @param[in] param user parameter
	 * @return int return next timer timeout ms, if <= 0, then timer will be delete
	 */
//    int on_timer( void * param );

//    void release();
//};

/** 
 * @brief timers_t
 */
template< class CB >
class timers_t
{
public:

    timers_t() : m_svr( NULL ), m_timers( NULL ), m_lock(), m_tool( NULL ) {}
    ~timers_t() { destroy(); }

    /** 
     * @brief create timers
     */
    inline bool create(
        gr_server_t *   server,
        timers_malloc   m,
        timers_free     f
    )
    {
        if ( NULL == server ) {
            return false;
        }
        m_svr = server;
        m_tool = m_svr->library->tool;

        scope_lock_t lock( m_lock );

        if ( NULL == m_timers && m_tool ) {
            m_timers = m_tool->timers_create( m, f );
            if ( NULL == m_timers ) {
                return false;
            }
            return true;
        } else {
            return false;
        }
    }

    inline bool start()
    {
        if ( m_timers && m_tool ) {
            return m_tool->timers_start( m_timers );
        } else {
            return false;
        }
    }

    inline void stop()
    {
        if ( m_timers && m_tool ) {
            m_tool->timers_stop( m_timers );
        }
    }

    inline void destroy()
    {
        scope_lock_t lock( m_lock );

        if ( m_timers && m_tool ) {
            ::timers_t t = m_timers;
            m_timers = NULL;
            m_tool->timers_destroy( t );
        }
    }

    /** 
     * @brief add timer
     * @param[in] interval_ms timeout relable time
     * @param[in] callback callback function
     * @param[in] param parameter
     * @return timer_node* non NULL: successed; NULL: failed
     */
    timer_node * add(
        int interval_ms,
        CB * callback,
        void * param,
        bool is_sync = true
    )
    {
        if ( m_timers && m_tool ) {
            return m_tool->timers_add_timer(
                m_timers, interval_ms, timers_cpp_callback, timers_cpp_release, callback, param, is_sync );
        } else {
            return NULL;
        }
    }

    /** 
     * @brief delete time
     * @param[in] tmr timer node
     */
    bool del(
        timer_node * tmr,
        bool is_sync = true
    )
    {
        if ( m_timers && m_tool ) {
            return m_tool->timers_del_timer( m_timers, tmr, is_sync );
        } else {
            return false;
        }
    }

    ::timers_t get_timers() { return m_timers; }

private:

    static int timers_cpp_callback( void * param1, void * param2 )
    {
        assert( param1 );
        CB * callback = (CB *)param1;
        return callback->on_timer( param2 );
    }

    static void timers_cpp_release( void * param1 )
    {
        assert( param1 );
        CB * obj = (CB *)param1;
        obj->release();
    }

private:

    gr_server_t *   m_svr;
    gr_i_tool_t *   m_tool;

    /// timers instance
    ::timers_t      m_timers;
    /// 
    lockable_t      m_lock;

private:
    // disable
    timers_t(const timers_t &);
    const timers_t & operator = (const timers_t &);
};

} // namespace base
#endif // #ifdef __cplusplus
#endif // #ifndef _fclass_base_timers_h_

#endif // #ifndef _GROCKET_INCLUDE_GRLIB_H_
