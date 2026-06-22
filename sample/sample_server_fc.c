/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_server" implements
 * the server components of the sample application. 
 *
 * Developing the server requires two main components:
 *  - the server "callback" that implements the server side of the
 *    application protocol, managing a server side application context
 *    for each connection.
 *  - the server loop, that reads messages on the socket, submits them
 *    to the Quic context, let the server prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Server uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". . When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".server.qlog".
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picohash.h"
#include "picoquic_sample.h"
#include "picoquic_packet_loop.h"
#include "picoquic_bbr.h"
#include "picoquic_internal.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

uint64_t c = 0;

char *debian[17] = {
"        _,met$$$$$gg.      \n",
"     ,g$$$$$$$$$$$$$$$P.   \n",
"   ,g$$P\"\"       \"\"\"Y$$.\". \n",
"  ,$$P'              `$$$. \n",
"',$$P       ,ggs.     `$$b:\n",
"`d$$'     ,$P\"'   .    $$$ \n",
" $$P      d$'     ,    $$P \n",
" $$:      $$.   -    ,d$$' \n",
" $$;      Y$b._   _,d$P'   \n",
" Y$$.    `.`\"Y$$$$P\"'      \n",
" `$$b      \"-.             \n",
"  `Y$$b                    \n",
"   `Y$$.                   \n",
"     `$$b.                 \n",
"       `Y$$b.              \n",
"         `\"Y$b.            \n",
"             `\"\"\"\"         \n"
};

char *empty = "                           \n";

/* Server context and callback management:
 *
 * The server side application context is created for each new connection,
 * and is freed when the connection is closed. It contains a list of
 * server side stream contexts, one for each stream open on the
 * connection. Each stream context includes:
 *  - description of the stream state:
 *      name_read or not, FILE open or not, stream reset or not,
 *      stream finished or not.
 *  - the number of file name bytes already read.
 *  - the name of the file requested by the client.
 *  - the FILE pointer for reading the data.
 * Server side stream context is created when the client starts the
 * stream. It is closed when the file transmission
 * is finished, or when the stream is abandoned.
 *
 * The server side callback is a large switch statement, with one entry
 * for each of the call back events.
 */

int sample_server_fc_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */

    if (ret == 0) {
        switch (fin_or_event) {
        //case picoquic_callback_almost_ready:
        //case picoquic_callback_ready:
        case picoquic_callback_app_wakeup:
            picoquic_mark_datagram_ready(cnx, 1);
            picoquic_set_app_wake_time(cnx, stream_id + 100000);
            break;
        case picoquic_callback_prepare_datagram:
            if (length < 28*17+1) {
                picoquic_provide_datagram_buffer_ex(bytes, 0, picoquic_datagram_active_any_path);
            }
            else {
                uint8_t *buf = picoquic_provide_datagram_buffer_ex(bytes, 28*17+1, picoquic_datagram_not_active);
                for (int i = 0; i < 17; i++) {
                    if (i == c%19) {
                        memcpy(buf, empty, 28);
                    }
                    else {
                        memcpy(buf, debian[i], 28);
                    }
                    buf += 28;
                }
                *buf = '\0';
            }
            ++c;
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* Server loop setup:
 * - Create the QUIC context.
 * - Open the sockets
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the socket return an error. 
 */

int picoquic_sample_server_fc(int server_port, const char* server_cert, const char* server_key, const char* default_dir, const char* fc_src_ip)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    char const* qlog_dir = default_dir;
    uint64_t current_time = 0;

    printf("Starting Picoquic Sample server on port %d\n", server_port);
    printf("Serving files from %s\n", default_dir);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        NULL, NULL, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        picoquic_set_qlog(quic, qlog_dir);

        picoquic_set_log_level(quic, 1);

        picoquic_set_key_log_file_from_env(quic);

        picoquic_set_default_multipath_option(quic, 1);
        picoquic_set_default_flexicast_option(quic, 1);
        picoquic_enable_sslkeylog(quic, 1);
        picoquic_set_key_log_file_from_env(quic);
        picoquic_set_default_lossbit_policy(quic, 0);
    }

    /* Wait for packets using the wait loop provided in the library.
     * On Linux, the default is to use UDP GSO when the system version is
     * recent enough to provide it, because this provides much better
     * performance. This may cause packet loss if a faulty driver fails
     * to provide UDP GSO and also does not return an error code when
     * doing so. In that case, the fourth zero below should be
     * changed to 1, i.e. passing "do_not_use_gso = 1". Or, better
     * still, get the faulty driver fixed.
     */
    if (ret == 0) {
        struct sockaddr_in flexicast_address, src_addr;
        memset(&flexicast_address, 0, sizeof(struct sockaddr_in));
        memset(&src_addr, 0, sizeof(struct sockaddr_in));
        flexicast_address.sin_family = AF_INET;
        flexicast_address.sin_port = htons(4444);
        inet_pton(AF_INET, "239.239.239.35", &flexicast_address.sin_addr);
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, fc_src_ip, &src_addr.sin_addr);
        picoquic_cnx_t *cnx = picoquic_create_datagram_fc_server(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&flexicast_address, (struct sockaddr*)&src_addr, current_time, 0, sample_server_fc_callback);

            printf("pt %p\n", &cnx->flows[0]->flow_id);

        ret = picoquic_packet_loop(quic, server_port, 0, 0, 0, 0, NULL, NULL);
    }

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* The "sample" project builds a simple file transfer program that can be 
 * instantiated in client or server mode. The programe can be instantiated
 * as either:
 *    picoquic_sample client server_name port folder *queried_file
 * or:
 *    picoquic_sample server port cert_file private_key_file folder
 *
 * The client opens a quic connection to the server, and then fetches 
 * the listed files. The client opens one bidir client stream for each
 * file, writes the requested file name in the stream data, and then
 * marks the stream as finished. The server reads the file name, and
 * if the named file is present in the server's folder, sends the file
 * content on the same stream, marking the fin of the stream when all
 * bytes are sent. If the file is not available, the server resets the
 * stream. If the client receives the file, it writes its content in the
 * client's folder.
 *
 * Server or client close the connection if it remains inactive for
 * more than 10 seconds.
 */


static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s port cert_file private_key_file folder fc_source_ip\n", sample_name);
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int main(int argc, char** argv)
{
    int exit_code = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc == 6) {
        int server_port = get_port(argv[0], argv[1]);
        exit_code = picoquic_sample_server_fc(server_port, argv[2], argv[3], argv[4], argv[5]);
    }
    else {
        usage(argv[0]);
    }

    exit(exit_code);
}
