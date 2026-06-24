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
 * instantiated in client or server mode. The "sample_client" implements
 * the client components of the sample application.
 *
 * Developing the client requires two main components:
 *  - the client "callback" that implements the client side of the
 *    application protocol, managing the client side application context
 *    for the connection.
 *  - the client loop, that reads messages on the socket, submits them
 *    to the Quic context, let the client prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Client uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".client.qlog".
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_packet_loop.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_internal.h"
#include "picoquic_sample_fc.h"
#include "picoquic_bbr.h"

 /* Client context and callback management:
  *
  * The client application context is created before the connection
  * is created. It contains the list of files that will be required
  * from the server.
  * On initial start, the client creates all the stream contexts 
  * that will be needed for the requested files, and marks all
  * these contexts as active.
  * Each stream context includes:
  *  - description of the stream state:
  *      name sent or not, FILE open or not, stream reset or not,
  *      stream finished or not.
  *  - index of the file in the list.
  *  - number of file name bytes sent.
  *  - stream ID.
  *  - the FILE pointer for reading the data.
  * Server side stream context is created when the client starts the
  * stream. It is closed when the file transmission
  * is finished, or when the stream is abandoned.
  *
  * The server side callback is a large switch statement, with one entry
  * for each of the call back events.
  */

typedef struct st_sample_client_ctx_t {
    int is_disconnected;
} sample_client_ctx_t;

int sample_client_callback_fc(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_client_ctx_t* client_ctx = (sample_client_ctx_t*)callback_ctx;

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_datagram:
            printf("\033[2J\033[H%.*s", (int)length, bytes);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            fprintf(stdout, "Connection closed.\n");
            /* Mark the connection as completed */
            client_ctx->is_disconnected = 1;
            /* Remove the application callback */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        default:
            break;
        }
    }

    return ret;
}

/* Sample client,  loop call back management.
 * The function "picoquic_packet_loop" will call back the application when it is ready to
 * receive or send packets, after receiving a packet, and after sending a packet.
 * We implement here a minimal callback that instruct  "picoquic_packet_loop" to exit
 * when the connection is complete.
 */

static int sample_client_loop_cb(picoquic_quic_t* UNUSED(quic), picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* UNUSED(callback_arg))
{
    int ret = 0;
    sample_client_ctx_t* cb_ctx = (sample_client_ctx_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            if (cb_ctx->is_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Prepare the context used by the simple client:
 * - Create the QUIC context.
 * - Open the sockets
 * - Find the server's address
 * - Initialize the client context and create a client connection.
 */
static int sample_client_init(char const* server_name, int server_port, char const* default_dir,
    char const* ticket_store_filename, char const* token_store_filename,
    struct sockaddr_storage * server_address, picoquic_quic_t** quic, picoquic_cnx_t** cnx, sample_client_ctx_t *client_ctx,
    int flexicast_option)
{
    int ret = 0;
    char const* sni = PICOQUIC_SAMPLE_SNI;
    char const* qlog_dir = default_dir;
    uint64_t current_time = picoquic_current_time();

    *quic = NULL;
    *cnx = NULL;

    /* Get the server's address */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, server_address, &is_name);
        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        }
        else if (is_name) {
            sni = server_name;
        }
    }

    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection.
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0) {
        *quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL,
            NULL, NULL, NULL, current_time, NULL,
            ticket_store_filename, NULL, 0);

        if (*quic == NULL) {
            fprintf(stderr, "Could not create quic context\n");
            ret = -1;
        }
        else {
            if (picoquic_load_retry_tokens(*quic, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(*quic, picoquic_bbr_algorithm);

            picoquic_set_key_log_file_from_env(*quic);
            picoquic_set_qlog(*quic, qlog_dir);
            picoquic_set_log_level(*quic, 1);
            picoquic_set_default_multipath_option(*quic, 1);
            picoquic_set_default_flexicast_option(*quic, flexicast_option);
            picoquic_enable_sslkeylog(*quic, 1);
            picoquic_set_key_log_file_from_env(*quic);
        }
    }
    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */

    if (ret == 0) {
        printf("Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        *cnx = picoquic_create_cnx(*quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);

        if (*cnx == NULL) {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        }
        else {
            /* Document connection in client's context */
            /* Set the client callback context */
            picoquic_set_callback(*cnx, sample_client_callback_fc, client_ctx);
            /* Client connection parameters could be set here, before starting the connection. */
            (*cnx)->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
            ret = picoquic_start_client_cnx(*cnx);
            if (ret < 0) {
                fprintf(stderr, "Could not activate connection\n");
            }
            else {
                /* Printing out the initial CID, which is used to identify log files */
                picoquic_connection_id_t icid = picoquic_get_initial_cnxid(*cnx);
                printf("Initial connection ID: ");
                for (uint8_t i = 0; i < icid.id_len; i++) {
                    printf("%02x", icid.id[i]);
                }
                printf("\n");
            }
        }
    }

    return ret;
}

/* Client:
 * - Call the init function to:
 *    - Create the QUIC context.
 *    - Open the sockets
 *    - Find the server's address
 *    - Create a client context and a client connection.
 * - Initialize the list of required files based on the CLI parameters.
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the client connection is finished.
 */

int picoquic_sample_client_fc(char const * server_name, int server_port, char const * default_dir, li_to_skip_t *li_to_skip)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    sample_client_ctx_t client_ctx = { 0 };
    char const* ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const* token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;

    ret = sample_client_init(server_name, server_port, default_dir,
        ticket_store_filename, token_store_filename,
        &server_address, &quic, &cnx, &client_ctx, 1);

    cnx->li_to_skip = li_to_skip;

    /* Wait for packets */
    ret = picoquic_packet_loop(quic, 0, server_address.ss_family, 0, 0, 0, sample_client_loop_cb, &client_ctx);

    /* Save tickets and tokens, and free the QUIC context */
    if (quic != NULL) {
        if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }
        if (picoquic_save_retry_tokens(quic, token_store_filename) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }
        picoquic_free(quic);
    }

    return ret;
}

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s server_name port folder\n", sample_name);
    exit(1);
}

int get_port_fc(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

void parse_packet_to_forget(char * arg, li_to_skip_t *li)
{
    char *end = NULL;
    size_t nb = 0;
    for (size_t c = 0; arg[c]; c++) {
        nb += (arg[c] == ',');
    }

    if ((li->li = calloc(nb + 1, sizeof(uint32_t))) == NULL)
        exit(1);

    for (uint32_t pn = strtoul(arg, &end, 10);;
        pn = strtoul(arg, &end, 10)) {
        if (arg != end) {
            li->li[li->len++] = pn;
            if (*end == ',') {
                arg = end + 1;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
        
    }
}

int main(int argc, char** argv)
{
    int exit_code = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    li_to_skip_t li = {0, NULL};
    int server_port;

    if (argc == 4) {
        server_port = get_port_fc(argv[0], argv[2]);

        exit_code = picoquic_sample_client_fc(argv[1], server_port, argv[3], &li);
    }
    else if (argc == 5) {
        server_port = get_port_fc(argv[0], argv[2]);

        parse_packet_to_forget(argv[5], &li);

        printf("nb %ld :", li.len);
        for (int i = 0; i<li.len; i++) {
            printf(" %u", li.li[i]);
        }
        printf("\n");

        exit_code = picoquic_sample_client_fc(argv[1], server_port, argv[3], &li);
    }
    else {
        usage(argv[0]);
    }

    if (li.li) {
        free(li.li);
    }

    exit(exit_code);
}
