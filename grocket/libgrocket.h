// YOU DON'T NEED TO CHANGE THIS FILE !!!!!!!!!

/**
 * @file include/libgrocket.h
 * @author zouyueming(da_ming at hotmail.com)
 * @date 2013/09/24
 * @version $Revision$
 * @brief GRocket server framework static linkage version interface
 *
 * Revision History
 *
 * @if  ID       Author       Date          Major Change       @endif
 *  ---------+------------+------------+------------------------------+\n
 *       1     zouyueming   2013-09-24    Created.
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

#ifndef _GROCKET_INCLUDE_LIBGROCKET_H_
#define _GROCKET_INCLUDE_LIBGROCKET_H_

#include "grocket.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * @brief start a GRocket server instance.\n
 *        same process just allow to start a single server at same time.\n
 *        this function will block current thread util the server exited.
 * @param[in] int argc             : argc
 * @param[in] char ** argv         : argv
 * @param[in] const char * ini     : INI config content
 * @param[in] size_t ini_len       : ini bytes
 * @param[in] gr_version_t version : GRocket module interface function
 * @return int: server return code. 0 if successed, error otherwise.
 * @author zouyueming
 * @date 2013/09/24
 * @code

    static
    bool proc_http( gr_http_ctxt_t * param )
    {
        const char rsp[] = "Hello World!";
        return param->server->library->buildin->http_send(
                    param,
                    rsp,
                    sizeof( rsp ) - 1,
                    "text/plain"
        );
    }

    static
    void gr_version( gr_version_param_t * param )
    {
        param->gr_version   = GR_SERVER_VERSION;
        param->proc_http    = proc_http;
    }

    int main( int argc, char ** argv )
    {
        const char ini[] =
            "[server]\n"
            "log.level = info\n"
            "[listen]\n"
            "0 = tcp://0.0.0.0:10000\n"
            "1 = udp://0.0.0.0:10000\n"
        ;
        return gr_main( argc, argv, ini, sizeof( ini ) - 1, gr_version );
    }

 * @endcode
 */
int
gr_main(
    int                 argc,
    char **             argv,
    const char *        ini,
    size_t              ini_len,
    gr_version_t        version
);

int
gr_main2(
    int                 argc,
    char **             argv,
    const char *        ini,
    size_t              ini_len,
    gr_version_t        version,
    gr_library_init_t   library,
    const char *        log_dir,
    const char *        log_name
);

/**
 * @brief if you call gr_main function in another thread,
 *        you can call this function to tell the gr_main return.
 * @author zouyueming
 * @date 2013/09/24
 */
void gr_need_exit();

#ifdef __cplusplus
}
#endif

#endif // #ifndef _GROCKET_INCLUDE_LIBGROCKET_H_
