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

#include "application.h"
#include "tcp_conn.h"
#include <sstream>

application_t * application_t::g_instance = NULL;

application_t & application_t::instance()
{
    assert( g_instance );
    return * g_instance;
}

void application_t::before_bind_port( gr_server_t * server )
{
    // you should NOT use application_t::instance()!!!!!!!!
    printf("%s called\n", __FUNCTION__);
}

application_t::application_t()
    : framework_t()
{
    g_instance = this;
    printf("%s called\n", __FUNCTION__);
}

application_t::~application_t()
{
    printf("%s called\n", __FUNCTION__);
}

void application_t::destroy_server()
{
    assert(_framework);
 
    //TODO: the server will destroy. add your code here
    printf("%s called\n", __FUNCTION__);
}

int application_t::init_server()
{
    //TODO: add your initialize code here.
    printf("%s called\n", __FUNCTION__);
    return 0;
}

int application_t::init_worker(int worker_id)
{
    //TODO: after fork() in process mode. add your per-worker initialize code here.
    printf("%s( %d ) called\n", __FUNCTION__, worker_id);
    return 0;
}

void application_t::destroy_worker(int worker_id)
{
    //TODO: after fork() in process mode. add your per-worker destroy code here.
    printf("%s( %d ) called\n", __FUNCTION__, worker_id);
}

bool application_t::tcp_accept(tcp_accept_ctxt_t & ctxt)
{
    //TODO: when accept a TCP socket, this function will be called.
    //      return false will reject this connection.
    //      if you want to "bind" a object to this TCP connection, just do it:
    // * ctxt.conn = new tcp_conn_t( ctxt.fd );
    //WARNING: in thread mode, accept and recv in difference thread
    //         in process mode, accept and recv in difference process
    //         [server]tcp.in.worker_type in config file can set this.
    //         We can call application_t::worker_is_process() to get this.
    //         Windows does not support process mode now.
    printf("%s called\n", __FUNCTION__);
    return true;
}

void application_t::tcp_close(tcp_close_ctxt_t & ctxt)
{
    //TODO: called before close a TCP socket.
    //      if you "bind" a object to this TCP connection, you need destroy it:
    // if ( ctxt.conn ) { delete (tcp_conn_t *)ctxt.conn; }
    printf("%s called\n", __FUNCTION__);
}

void application_t::proc_binary(proc_binary_ctxt_t & ctxt, int & processed_len)
{
    assert(processed_len == ctxt.data_len);
    assert(ctxt.data && ctxt.data_len > 0 && '\0' == ctxt.data[ ctxt.data_len ]);

    //TODO: add you process binary protocol code here.
    //     processed_len  : < 0, need disconnect connection
    //                      = 0, do nothing, package not full, just recv again
    //                      > 0, data ok, return processed request bytes
    printf("%s called\n", __FUNCTION__);

    // sample protocol parse: \n separated
    char * crlf = (char *)strchr(ctxt.data, '\n');
    if (NULL == crlf)
    {
        // the package is not full, no error, we need recv again.
        processed_len = 0;
        return;
    }

    // member we process bytes in the request
    processed_len = (int)(crlf - ctxt.data + 1);

    // yes. we can change request data
    *crlf = '\0';

    if (crlf > ctxt.data && '\r' == *(crlf - 1))
    {
        // windows's CRLF is \r\n
        *(crlf - 1) = '\0';
    }

    if (0 == strcmp("author", ctxt.data))
    {
        const char * author = "you@server.com";
        size_t author_len = strlen(author) + 1;

        char* rsp = (char*)alloc_response(ctxt, (int)author_len);
        if (rsp)
        {
            strcpy(rsp, author);
        }
        else
        {
            printf("allocate response failed\n");
            // < 0, server will close this connection for TCP.
            processed_len = -1;
            return;
        }
        // response write OK
    }
    else
    {
        printf("invalid data, %d bytes\n", ctxt.data_len);

        // < 0, server will close this connection for TCP.
        processed_len = -1;
    }
}

bool application_t::proc_http_sample_hello_world( gr_http_ctxt_t * http )
{
    //TODO: add you process http protocol code here.
    //     return false : disconnection
    printf("%s called\n", __FUNCTION__);

    // sample : parse http request
    std::stringstream ss;
    size_t i;
   
    ss << "fd = " << http->hc_fd << "\n";
    ss << "worker_id = " << (int)http->hc_worker_id << "\n";
    ss << "port = " << (int)http->hc_port << "\n";
    ss << "keep_alive = " << (int)http->keep_alive << "\n";
    ss << "is_tcp = " << (int)http->hc_is_tcp << "\n";
    ss << "is_local = " << (int)http->hc_is_local << "\n";
    ss << "package_type = " << (int)http->hc_package_type << "\n";
    ss << "http_reply_code = " << http->http_reply_code << "\n";
    ss << "http_method = " << http->method << "\n";
    ss << "http_version = " << http->version << "\n";
    ss << "directory = " << http->directory << "\n";
    ss << "object = " << http->object << "\n";
    ss << "content_type = " << http->content_type << "\n";
    ss << "user_agent = " << http->user_agent << "\n";
    ss << "query_string_count = " << (int)http->params_count << "\n";
    for ( i = 0; i < http->params_count; ++ i ) {
        gr_http_pair_t * item = & http->params[ i ];
        ss << "    " << item->name << "(len:" << item->name_len << ") = " << item->value << "(len:" << item->value_len << ")\n";
    }
    ss << "header_count = " << (int)http->header_count << "\n";
    for ( i = 0; i < http->header_count; ++ i ) {
        gr_http_pair_t * item = & http->header[ i ];
        ss << "    " << item->name << "(len:" << item->name_len << ") = " << item->value << "(len:" << item->value_len << ")\n";
    }
    ss << "form_count = " << (int)http->form_count << "\n";
    for ( i = 0; i < http->form_count; ++ i ) {
        gr_http_pair_t * item = & http->form[ i ];
        ss << "    " << item->name << "(len:" << item->name_len << ") = " << item->value << "(len:" << item->value_len << ")\n";
    }
    ss << "body_len = " << http->body_len << "\n";
    ss << "body = ";
    if ( http->body_len > 0 ) {
        ss.write( http->body, (std::streamsize)http->body_len );
    }

    std::string rsp = ss.str();

    return http_send( http, rsp.c_str(), rsp.size(), "text/plain" );
}

bool application_t::proc_http(gr_http_ctxt_t * http)
{
    if ( unlikely( '/' != * http->directory ) ) {
        return false;
    }

    if ( 0 == strcmp( "/test", http->directory ) ) {
        if ( 0 == strcmp( "hello", http->object ) ) {
            return http_send( http, "hello!", (int)sizeof( "hello!" ) - 1, "text/plain" );
        }
    }

    return proc_http_sample_hello_world( http );
}

