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

#ifndef _application_h_
#define _application_h_

#include "framework.h"

#define g_app application_t::instance()

class application_t : public framework_t
{
public:

    static application_t & instance();

    static void before_bind_port( gr_server_t * server );

    /*
     * @brief init in parent process
     * @return int: return 0 if successed, otherwise server will exit
     */
    int init_server();
    /*
     * @brief init in worker process(or thread)
     * @param[in] worker_id : [0, worker_count())
     *                        We can set worker count in spider_svr.ini file:
     *                        [server]tcp.in.worker_count
     * @return int: return 0 if successed, otherwise server will exit
     */
    int init_worker(int worker_id);
    /*
     * @brief destroy worker process(or thread)
     * @param[in] worker_id : worker process(or thread)id
     *                        We can set worker count in spider_svr.ini file:
     *                        [server]tcp.in.worker_count
     */
    void destroy_worker(int worker_id);
    /*
     * @brief destroy server
     */
    void destroy_server();

    /*
     * @brief called after accept a TCP connection
     * @param[in] ctxt : connection info
     * @return bool: return true if successed,
     *               otherwise server will disconnect the connection
     */
    bool tcp_accept(tcp_accept_ctxt_t & ctxt);
    /*
     * @brief called before close a TCP connection
     * @param[in] ctxt : connection info
     */
    void tcp_close(tcp_close_ctxt_t & ctxt);

    /*
     * @brief process a user package
     * @param[in]  ctxt          : process context
     * @param[out] processed_len : return bytes processed, by default,
     *                             this value same with ctxt.data_len.
     *                             < 0: need disconnect connection
     *                             = 0: do nothing, package not full, just recv again
     *                             > 0: data ok, return processed request bytes
     */
    void proc_binary(proc_binary_ctxt_t & ctxt, int & processed_len);
    /*
     * @brief process a HTTP package(support HTTP request and HTTP response)
     * @param[in]  ctxt : process context
     * @return     bool : return true indicate successed;
     *                    return false indicate failed, will disconnect connection
     */
    bool proc_http(gr_http_ctxt_t * http);

private:

    //TODO: add your private function here
    bool proc_http_sample_hello_world( gr_http_ctxt_t * http );

private:

    //TODO: add your private member variable here

public:
    application_t();
    virtual ~application_t();
private:
    static application_t * g_instance;
private:
    // disable
    application_t(const application_t &);
    const application_t & operator = (const application_t &);
};

#endif // #ifndef _application_h_

