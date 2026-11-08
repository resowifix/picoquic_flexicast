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

#include <errno.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_packet_loop.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "picohash.h"
#include "picoquic_internal.h"
#include "picoquic_sample_fc.h"
#include "picoquic_bbr.h"

#include <sys/un.h>

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

int file_rcv = 0;

typedef struct st_sample_client_stream_ctx_t {
    struct st_sample_client_stream_ctx_t *next_stream;
    struct st_sample_client_stream_ctx_t *previous_stream;
    size_t file_rank;
    uint64_t stream_id;
    size_t name_length;
    size_t name_sent_length;
    FILE *F;
    size_t bytes_received;
    uint64_t remote_error;
    unsigned int is_file_open       :1;
    unsigned int is_stream_reset    :1;
    unsigned int is_stream_finished :1;
    char file_name[PATH_MAX];
} sample_client_stream_ctx_t;

typedef struct st_sample_sf_client_loc_serv_ctx_t {
    int fd;
    struct sockaddr_un svaddr;
} sample_sf_client_loc_serv_ctx_t;

typedef struct st_sample_client_ctx_t {
    picoquic_cnx_t *cnx;
    char const *default_dir;
    sample_client_stream_ctx_t *first_stream;
    sample_client_stream_ctx_t *last_stream;
    sample_sf_client_loc_serv_ctx_t *sf_ctx;
    int nb_file_max;
    int next_file_id;
    int nb_files_received;
    int nb_files_failed;
    int is_disconnected;
} sample_client_ctx_t;

static void sample_client_report(sample_client_ctx_t *client_ctx)
{
    sample_client_stream_ctx_t *stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL) {
        char const *status;
        if (stream_ctx->is_stream_finished) {
            status = "complete";
        } else if (stream_ctx->is_stream_reset) {
            status = "reset";
        } else {
            status = "unknown status";
        }
        printf("file%lu: %s, received %zu bytes", stream_ctx->file_rank, status,
                stream_ctx->bytes_received);
        if (stream_ctx->is_stream_reset && stream_ctx->remote_error != PICOQUIC_SAMPLE_NO_ERROR) {
            printf(", error 0x%" PRIx64 "(%s)", stream_ctx->remote_error,
                    picoquic_error_name(stream_ctx->remote_error));
        }
        printf("\n");
        stream_ctx = stream_ctx->next_stream;
    }
}

static void sample_client_free_context(sample_client_ctx_t *client_ctx)
{
    sample_client_stream_ctx_t *stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL) {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->F != NULL) {
            (void)picoquic_file_close(stream_ctx->F);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}

sample_client_stream_ctx_t *sample_client_create_stream_context(sample_client_ctx_t *client_ctx,
        uint64_t stream_id)
{
    sample_client_stream_ctx_t *stream_ctx =
            (sample_client_stream_ctx_t *)malloc(sizeof(sample_client_stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(sample_client_stream_ctx_t));

        if (client_ctx->last_stream == NULL) {
            client_ctx->last_stream = stream_ctx;
            client_ctx->first_stream = stream_ctx;
        } else {
            stream_ctx->previous_stream = client_ctx->last_stream;
            client_ctx->last_stream->next_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int sample_client_callback_fc(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes,
        size_t length, picoquic_call_back_event_t fin_or_event, void *callback_ctx,
        void *v_stream_ctx)
{
    int ret = 0;
    sample_client_ctx_t *client_ctx = (sample_client_ctx_t *)callback_ctx;
    sample_client_stream_ctx_t *stream_ctx = (sample_client_stream_ctx_t *)v_stream_ctx;

    if (client_ctx == NULL) {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client connection. */
        return -1;
    }

    if (ret == 0) {
        switch (fin_or_event) {
            case picoquic_callback_stream_data:
            case picoquic_callback_stream_fin:
                /* Data arrival on stream #x, maybe with fin mark */
                if (stream_ctx == NULL) {
                    stream_ctx = sample_client_create_stream_context(client_ctx, stream_id);
                    if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                        /* Internal error */
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                        return (-1);
                    }
                }
                if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished) {
                    /* Unexpected: receive after fin */
                    return -1;
                } else {
                    if (stream_ctx->F == NULL) {
                        /* Open the file to receive the data. This is done at the last possible
                         * moment, to minimize the number of files open simultaneously. When
                         * formatting the file_path, verify that the directory name is zero-length,
                         * or terminated by a proper file separator.
                         */
                        char file_name[100];
                        memset(file_name, 0, 100);
                        sprintf(file_name, "file%d", file_rcv++);
                        memset(stream_ctx->file_name, 0, PATH_MAX);

                        if (client_ctx->default_dir[0] == '/'
                                || client_ctx->default_dir[0] == '~') {
                            strncpy(stream_ctx->file_name, client_ctx->default_dir, PATH_MAX - 1);
                        } else if (getcwd(stream_ctx->file_name, sizeof(stream_ctx->file_name))) {
                            if (stream_ctx->file_name[strnlen(stream_ctx->file_name, PATH_MAX) - 1]
                                    != '/') {
                                strncat(stream_ctx->file_name, "/",
                                        PATH_MAX - strnlen(stream_ctx->file_name, PATH_MAX));
                            }
                            strncat(stream_ctx->file_name, client_ctx->default_dir,
                                    PATH_MAX - strnlen(stream_ctx->file_name, PATH_MAX));
                            if (stream_ctx->file_name[strnlen(stream_ctx->file_name, PATH_MAX) - 1]
                                    != '/') {
                                strncat(stream_ctx->file_name, "/",
                                        PATH_MAX - strnlen(stream_ctx->file_name, PATH_MAX));
                            }
                            strncat(stream_ctx->file_name, file_name,
                                    PATH_MAX - strnlen(stream_ctx->file_name, PATH_MAX));
                        } else {
                            fprintf(stderr, "Could not format the file path.\n");
                            ret = -1;
                        }

                        if (ret != -1) {
                            stream_ctx->F = picoquic_file_open(stream_ctx->file_name, "wb");

                            if (stream_ctx->F == NULL) {
                                /* Could not open the file */
                                fprintf(stderr, "Could not open the file: %s : %s\n",
                                        stream_ctx->file_name, strerror(errno));
                                ret = -1;
                            }
                        }
                    }
                }

                if (ret == 0 && length > 0) {
                    /* write the received bytes to the file */
                    if (fwrite(bytes, length, 1, stream_ctx->F) != 1) {
                        /* Could not write file to disk */
                        fprintf(stderr, "Could not write data to disk.\n");
                        ret = -1;
                    } else {
                        stream_ctx->bytes_received += length;
                    }
                }

                if (ret == 0 && fin_or_event == picoquic_callback_stream_fin) {
                    fprintf(stderr, "%s received, %lu byte(s) received\n", stream_ctx->file_name,
                            stream_ctx->bytes_received);
                    stream_ctx->F = picoquic_file_close(stream_ctx->F);
                    stream_ctx->is_stream_finished = 1;
                    client_ctx->nb_files_received++;
                    if (sendto(client_ctx->sf_ctx->fd, stream_ctx->file_name,
                                strnlen(stream_ctx->file_name, 1024), 0,
                                (struct sockaddr *)&(client_ctx->sf_ctx->svaddr),
                                sizeof(struct sockaddr_un))
                            != strnlen(stream_ctx->file_name, 1024)) {}

                    if ((client_ctx->nb_files_received + client_ctx->nb_files_failed)
                                    >= client_ctx->nb_file_max
                            && client_ctx->nb_file_max > 0) {
                        /* everything is done, close the connection */
                        ret = picoquic_close(cnx, 0);
                    }
                }
                break;
            case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
                /* Mark stream as abandoned, close the file, etc. */
                picoquic_reset_stream(cnx, stream_id, 0);
                /* Fall through */
            case picoquic_callback_stream_reset: /* Server reset stream #x */
                if (stream_ctx == NULL) {
                    /* This is unexpected, as all contexts were declared when initializing the
                     * connection. */
                    return -1;
                } else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished) {
                    /* Unexpected: receive after fin */
                    return -1;
                } else {
                    stream_ctx->remote_error = picoquic_get_remote_stream_error(cnx, stream_id);
                    stream_ctx->is_stream_reset = 1;
                    client_ctx->nb_files_failed++;

                    if ((client_ctx->nb_files_received + client_ctx->nb_files_failed)
                            >= client_ctx->nb_file_max) {
                        /* everything is done, close the connection */
                        fprintf(stdout, "All done, closing the connection.\n");
                        ret = picoquic_close(cnx, 0);
                    }
                }
                break;
            case picoquic_callback_stateless_reset:
            case picoquic_callback_close:             /* Received connection close */
            case picoquic_callback_application_close: /* Received application close */
                fprintf(stdout, "Connection closed.\n");
                /* Mark the connection as completed */
                client_ctx->is_disconnected = 1;
                /* Remove the application callback */
                picoquic_set_callback(cnx, NULL, NULL);
                break;
            case picoquic_callback_version_negotiation:
                /* The client did not get the right version.
                 * TODO: some form of negotiation?
                 */
                fprintf(stdout, "Received a version negotiation request:");
                for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4) {
                    uint32_t vn = 0;
                    for (int i = 0; i < 4; i++) {
                        vn <<= 8;
                        vn += bytes[byte_index + i];
                    }
                    fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
                }
                fprintf(stdout, "\n");
                break;
            case picoquic_callback_stream_gap:
                /* This callback is never used. */
                break;
            case picoquic_callback_prepare_to_send:
                break;
            case picoquic_callback_almost_ready:
                fprintf(stdout, "Connection to the server completed, almost ready.\n");
                break;
            case picoquic_callback_ready:
                /* TODO: Check that the transport parameters are what the sample expects */
                fprintf(stdout, "Connection to the server confirmed.\n");
                break;
            default:
                /* unexpected -- just ignore. */
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

static int sample_client_loop_cb(picoquic_quic_t *UNUSED(quic),
        picoquic_packet_loop_cb_enum cb_mode, void *callback_ctx, void *UNUSED(callback_arg))
{
    int ret = 0;
    sample_client_ctx_t *cb_ctx = (sample_client_ctx_t *)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    } else {
        switch (cb_mode) {
            case picoquic_packet_loop_ready:
                fprintf(stdout, "Waiting for packets.\n");
                break;
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
static int sample_client_init(char const *server_name, int server_port, char const *default_dir,
        char const *ticket_store_filename, char const *token_store_filename,
        struct sockaddr_storage *server_address, picoquic_quic_t **quic, picoquic_cnx_t **cnx,
        sample_client_ctx_t *client_ctx, int flexicast_option)
{
    int ret = 0;
    char const *sni = PICOQUIC_SAMPLE_SNI;
    char const *qlog_dir = PICOQUIC_SAMPLE_CLIENT_QLOG_DIR;
    uint64_t current_time = picoquic_current_time();

    *quic = NULL;
    *cnx = NULL;

    /* Get the server's address */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, server_address, &is_name);
        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name,
                    server_port);
        } else if (is_name) {
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
        *quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL, NULL, NULL,
                NULL, current_time, NULL, ticket_store_filename, NULL, 0);

        if (*quic == NULL) {
            fprintf(stderr, "Could not create quic context\n");
            ret = -1;
        } else {
            if (picoquic_load_retry_tokens(*quic, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n",
                        token_store_filename);
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
        client_ctx->default_dir = default_dir;

        printf("Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        *cnx = picoquic_create_cnx(*quic, picoquic_null_connection_id, picoquic_null_connection_id,
                (struct sockaddr *)server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);

        if (*cnx == NULL) {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        } else {
            /* Document connection in client's context */
            client_ctx->cnx = *cnx;
            /* Set the client callback context */
            picoquic_set_callback(*cnx, sample_client_callback_fc, client_ctx);
            /* Client connection parameters could be set here, before starting the connection. */
            ret = picoquic_start_client_cnx(*cnx);
            if (ret < 0) {
                fprintf(stderr, "Could not activate connection\n");
            } else {
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

int picoquic_sample_client_fc(char const *server_name, int server_port, char const *default_dir,
        int nb_file, int flexicast_option, picoquic_amt_quic_ctx_t *amt_ctx,
        sample_sf_client_loc_serv_ctx_t *sf_ctx)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    sample_client_ctx_t client_ctx = {0};
    char const *ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const *token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;

    client_ctx.nb_file_max = nb_file;
    client_ctx.sf_ctx = sf_ctx;

    ret = sample_client_init(server_name, server_port, default_dir, ticket_store_filename,
            token_store_filename, &server_address, &quic, &cnx, &client_ctx, flexicast_option);

    quic->amt_cxt = amt_ctx;

    /* Wait for packets */
    ret = picoquic_packet_loop(quic, 0, server_address.ss_family, 0, 0, 0, sample_client_loop_cb,
            &client_ctx);

    /* Done. At this stage, we could print out statistics, etc. */
    sample_client_report(&client_ctx);

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

    /* Free the Client context */
    sample_client_free_context(&client_ctx);

    return ret;
}

static void usage(char const *sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s server_name server_port amt_relay_name amt_relay_port folder nb_file\n",
            sample_name);
    exit(1);
}

int get_port_fc(char const *sample_name, char const *port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int get_relay_ctx(char *relay_addr, int relay_port, picoquic_amt_quic_ctx_t *amt_ctx)
{
    int is_name;
    memset((void *)amt_ctx->relay, 0, sizeof(struct sockaddr));
    int ret = picoquic_get_server_address(relay_addr, relay_port,
            (struct sockaddr_storage *)amt_ctx->relay, &is_name);
    amt_ctx->relay_len = sizeof(struct sockaddr);
    amt_ctx->retries = 10;
    amt_ctx->ssm = 1;
    amt_ctx->timeout_ms = 1000;
    return ret;
}

void prepare_sf_local_server_ctx(struct sockaddr_un *claddr,
        sample_sf_client_loc_serv_ctx_t *sf_ctx)
{
    // Create client socket; bind to unique pathname (based on PID)
    sf_ctx->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (-1 == sf_ctx->fd) {
        fprintf(stderr, "socket\n");
    }
    // Client address is made unique by including client's process ID
    memset(claddr, 0, sizeof(struct sockaddr_un));
    claddr->sun_family = AF_UNIX;
    snprintf(claddr->sun_path, sizeof(claddr->sun_path), "/tmp/ud_ucase_cl.%ld", (long)getpid());

    // Bind socket to an address, so that the server can send its reply
    if (-1 == bind(sf_ctx->fd, (struct sockaddr *)claddr, sizeof(struct sockaddr_un))) {
        fprintf(stderr, "Error while binding local socket: %s\n", strerror(errno));
    }

    // Construct address of server
    memset(&(sf_ctx->svaddr), 0, sizeof(struct sockaddr_un));
    sf_ctx->svaddr.sun_family = AF_UNIX;
    strncpy(sf_ctx->svaddr.sun_path, "/tmp/fcquic-recv.sock", sizeof(sf_ctx->svaddr.sun_path) - 1);
}

int main(int argc, char **argv)
{
    int exit_code = 0;
#ifdef _WINDOWS
    WSADATA wsaData = {0};
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc != 7) {
        usage(argv[0]);
        exit_code = 1;
    } else {
        int server_port = get_port_fc(argv[0], argv[2]);

        picoquic_amt_quic_ctx_t amt_ctx;
        struct sockaddr_storage relay;
        amt_ctx.relay = (struct sockaddr *)&relay;
        get_relay_ctx(argv[3], get_port_fc(argv[0], argv[4]), &amt_ctx);

        struct sockaddr_un claddr;
        sample_sf_client_loc_serv_ctx_t sf_ctx;

        prepare_sf_local_server_ctx(&claddr, &sf_ctx);

        exit_code = picoquic_sample_client_fc(argv[1], server_port, argv[5], atoi(argv[6]), 1,
                &amt_ctx, &sf_ctx);

        remove(claddr.sun_path);
    }

    exit(exit_code);
}
