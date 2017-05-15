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

#ifndef _tcp_conn_h_
#define _tcp_conn_h_

#include "compiler_switch.h"
#if defined( WIN32 ) || defined( WIN64 )
    #include <winsock2.h>
#else
    #include <netinet/in.h>
    #include <string.h>         // for memcpy
#endif

////////////////////////////////////////////////////////////////////////
//
// If you want to known the usage of tcp_conn_t, see the framework.cpp file
// in the framework_t::tcp_accept and framework_t::tcp_close function comments
//

class tcp_conn_t
{
public:
    tcp_conn_t( int fd );
    // add your implementation here
private:
    int    m_fd;

private:
    // disable copy
    tcp_conn_t();
    tcp_conn_t(const tcp_conn_t &);
    const tcp_conn_t & operator = (const tcp_conn_t &);
};

#endif // #ifndef _tcp_conn_h_
