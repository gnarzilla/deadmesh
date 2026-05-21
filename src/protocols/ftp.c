#include "ftp.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

// FTP protocol states
typedef enum {
    FTP_STATE_INIT,
    FTP_STATE_USER_SENT,
    FTP_STATE_AUTHENTICATED,
    FTP_STATE_PASSIVE_REQUESTED,
    FTP_STATE_DATA_PENDING
} FTPState;

typedef struct {
    FTPState state;
    gchar *username;
    gboolean passive_mode;
    gchar *data_host;
    guint16 data_port;
    gchar *upstream_data_host;
    guint16 upstream_data_port;
    GSocketConnection *data_connection;
    GSocketService *data_listener;  // For active mode
    guint16 proxy_data_port;        // Port we listen on for data
    GThread *data_tunnel_thread;
    // New fields for HTTP-wrapped FTP streaming
    gboolean http_wrapped;
    gboolean headers_sent;
    GString *http_response_headers;
    GSocketConnection *http_data_conn;
    GSocketConnection *http_ctrl_conn;
    gboolean data_transfer_done;
    gboolean control_waits_226;
} FTPProtocolData;

typedef struct {
    GSocketConnection *client_data_conn;
    GSocketConnection *upstream_data_conn;
} FTPDataTunnelArgs;

// Forward declarations
static gsize ftp_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error);
static void ftp_cleanup(DeadlightConnection *conn);
static gboolean ftp_tunnel_with_inspection(DeadlightConnection *conn, GError **error);
static gboolean parse_pasv_response(const gchar *response, gchar **host, guint16 *port);
static gchar* rewrite_pasv_response(const gchar *original, const gchar *proxy_ip, guint16 proxy_port);
static gboolean handle_data_connection(DeadlightConnection *conn, const gchar *cmd);
static gboolean parse_ftp_target(DeadlightConnection *conn, gchar **host, guint16 *port);
static gboolean on_data_connection_incoming(GSocketService *service, GSocketConnection *client_conn,
                                           GObject *source_object, gpointer user_data);
static DeadlightHandlerResult handle_http_wrapped_ftp_streaming(DeadlightConnection *conn, GError **error);
static gboolean parse_ftp_uri(const gchar *uri, gchar **host, guint16 *port, 
                              gchar **user, gchar **pass, gchar **path);
static int ftp_send_command(GSocketConnection *conn, const char *cmd, char *response_buf, size_t buf_size);
static gchar* ftp_read_response_line(GInputStream *in, GError **error);

static const DeadlightProtocolHandler ftp_protocol_handler = {
    .name = "FTP",
    .protocol_id = DEADLIGHT_PROTOCOL_FTP,
    .detect = ftp_detect,
    .handle = ftp_handle,
    .cleanup = ftp_cleanup
};

void deadlight_register_ftp_handler(void) {
    deadlight_protocol_register(&ftp_protocol_handler);
}

static gsize ftp_detect(const guint8 *data, gsize len) {
    if (len < 4) return 0;
    
    // Check if it's an HTTP request for FTP URL (curl uses this)
    if (len >= 4 && memcmp(data, "GET ", 4) == 0) {
        gchar *request = g_strndup((const gchar*)data, MIN(len, 100));
        gboolean is_ftp_url = strstr(request, "ftp://") != NULL;
        g_free(request);
        if (is_ftp_url) return 15; // Higher than HTTP's 8 - take priority
    }
    
    // FTP commands are case-insensitive
    gchar *str = g_strndup((const gchar*)data, MIN(len, 10));
    gchar *upper = g_ascii_strup(str, -1);
    
    // Check for common FTP commands
    gboolean is_ftp = FALSE;
    if (g_str_has_prefix(upper, "USER ") ||
        g_str_has_prefix(upper, "PASS ") ||
        g_str_has_prefix(upper, "LIST") ||
        g_str_has_prefix(upper, "RETR ") ||
        g_str_has_prefix(upper, "STOR ") ||
        g_str_has_prefix(upper, "QUIT") ||
        g_str_has_prefix(upper, "PASV") ||
        g_str_has_prefix(upper, "PORT ") ||
        g_str_has_prefix(upper, "TYPE ") ||
        g_str_has_prefix(upper, "CWD ") ||
        g_str_has_prefix(upper, "PWD") ||
        g_str_has_prefix(upper, "MKD ") ||
        g_str_has_prefix(upper, "DELE ") ||
        g_str_has_prefix(upper, "FEAT") ||
        g_str_has_prefix(upper, "SYST")) {
        is_ftp = TRUE;
    }
    
    // Also check for FTP server responses (3 digit codes)
    if (!is_ftp && len >= 4 && 
        g_ascii_isdigit(data[0]) && 
        g_ascii_isdigit(data[1]) && 
        g_ascii_isdigit(data[2]) &&
        (data[3] == ' ' || data[3] == '-')) {
        // Common FTP response codes
        if (memcmp(data, "220", 3) == 0 ||  // Service ready
            memcmp(data, "331", 3) == 0 ||  // User OK, need password
            memcmp(data, "230", 3) == 0 ||  // User logged in
            memcmp(data, "227", 3) == 0 ||  // Entering passive mode
            memcmp(data, "150", 3) == 0 ||  // File status OK
            memcmp(data, "226", 3) == 0 ||  // Transfer complete
            memcmp(data, "250", 3) == 0 ||  // Requested file action okay
            memcmp(data, "257", 3) == 0) {  // Pathname created
            is_ftp = TRUE;
        }
    }
    
    g_free(str);
    g_free(upper);
    
    return is_ftp ? 5 : 0;  // Medium priority
}

// Helper to read a single line from an input stream
static gchar* ftp_read_response_line(GInputStream *in, GError **error) {
    GByteArray *line = g_byte_array_new();
    guint8 ch;
    gssize n;
    
    while (1) {
        n = g_input_stream_read(in, &ch, 1, NULL, error);
        if (n != 1) {
            g_byte_array_free(line, TRUE);
            return NULL;
        }
        if (ch == '\n') {
            // Remove trailing \r if present
            if (line->len > 0 && line->data[line->len-1] == '\r')
                g_byte_array_set_size(line, line->len - 1);
            g_byte_array_append(line, (guint8*)"", 1); // null terminate
            gchar *result = g_strdup((gchar*)line->data);
            g_byte_array_free(line, TRUE);
            return result;
        }
        g_byte_array_append(line, &ch, 1);
    }
}
static int ftp_send_command(GSocketConnection *conn, const char *cmd, char *response_buf, size_t buf_size) {
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(conn));
    gchar *cmd_with_crlf = g_strdup_printf("%s\r\n", cmd);
    GError *error = NULL;
    
    if (!g_output_stream_write_all(out, cmd_with_crlf, strlen(cmd_with_crlf), NULL, NULL, &error)) {
        g_free(cmd_with_crlf);
        return -1;
    }
    g_free(cmd_with_crlf);
    
    // Read response - handle multi-line (indicated by dash after code)
    GByteArray *full_response = g_byte_array_new();
    int final_code = 0;
    
    while (1) {
        // Read one line
        GByteArray *line_buf = g_byte_array_new();
        guint8 ch;
        gssize n;
        
        while (1) {
            n = g_input_stream_read(in, &ch, 1, NULL, &error);
            if (n != 1) {
                g_byte_array_free(line_buf, TRUE);
                g_byte_array_free(full_response, TRUE);
                return -1;
            }
            if (ch == '\n') {
                // Remove trailing \r if present
                if (line_buf->len > 0 && line_buf->data[line_buf->len-1] == '\r')
                    g_byte_array_set_size(line_buf, line_buf->len - 1);
                g_byte_array_append(line_buf, (guint8*)"", 1);
                break;
            }
            g_byte_array_append(line_buf, &ch, 1);
        }
        
        // Append to full response (for logging)
        if (full_response->len > 0)
            g_byte_array_append(full_response, (guint8*)"\n", 1);
        g_byte_array_append(full_response, line_buf->data, line_buf->len);
        
        // Parse code from this line
        char *line = (char*)line_buf->data;
        int line_code = atoi(line);
        
        // Store the first valid code we see
        if (final_code == 0 && line_code > 0)
            final_code = line_code;
        
        // Check if this is the final line (no dash after the code)
        // Format: "XXX " (space) indicates last line, "XXX-" indicates continuation
        gboolean is_last_line = (line[3] == ' ');
        
        g_byte_array_free(line_buf, TRUE);
        
        if (is_last_line)
            break;
    }
    
    // Copy full response to output buffer (for error messages)
    if (response_buf && buf_size > 0) {
        g_strlcpy(response_buf, (gchar*)full_response->data, buf_size);
    }
    
    g_byte_array_free(full_response, TRUE);
    return final_code;
}

static gboolean parse_ftp_target(DeadlightConnection *conn, gchar **host, guint16 *port) {
    DeadlightContext *ctx = conn->context;
    
    // Check if we have target info from a previous CONNECT or similar
    if (conn->target_host) {
        *host = g_strdup(conn->target_host);
        *port = conn->target_port ? conn->target_port : 21;
        return TRUE;
    }
    
    // Otherwise use configured upstream
    const gchar *upstream_host = deadlight_config_get_string(ctx, "ftp", "upstream_host", NULL);
    if (upstream_host && strlen(upstream_host) > 0) {
        *host = g_strdup(upstream_host);
        *port = deadlight_config_get_int(ctx, "ftp", "upstream_port", 21);
        return TRUE;
    }
    
    return FALSE;
}

// Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
static gboolean parse_pasv_response(const gchar *response, gchar **host, guint16 *port) {
    gint h1, h2, h3, h4, p1, p2;
    if (sscanf(response, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", 
               &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
        *host = g_strdup_printf("%d.%d.%d.%d", h1, h2, h3, h4);
        *port = (p1 << 8) | p2;
        return TRUE;
    }
    return FALSE;
}

// Rewrite PASV response to point to our proxy
static gchar* rewrite_pasv_response(const gchar *original, const gchar *proxy_ip, guint16 proxy_port) {
    (void)original; // Suppress unused parameter warning
    
    // Convert IP to h1,h2,h3,h4 format
    gint h1, h2, h3, h4;
    sscanf(proxy_ip, "%d.%d.%d.%d", &h1, &h2, &h3, &h4);
    
    gint p1 = (proxy_port >> 8) & 0xFF;
    gint p2 = proxy_port & 0xFF;
    
    return g_strdup_printf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
                          h1, h2, h3, h4, p1, p2);
}

static gboolean handle_data_connection(DeadlightConnection *conn, const gchar *cmd) {
    (void)conn;
    g_debug("FTP data command: %s", cmd);
    return TRUE;
}

// This function will be run in a new thread to handle the data transfer.
static gpointer ftp_data_tunnel_thread(gpointer data) {
    FTPDataTunnelArgs *args = (FTPDataTunnelArgs *)data;
    
    deadlight_network_tunnel_socket_connections(args->client_data_conn, args->upstream_data_conn);

    // Cleanup after tunnel finishes
    g_io_stream_close(G_IO_STREAM(args->client_data_conn), NULL, NULL);
    g_io_stream_close(G_IO_STREAM(args->upstream_data_conn), NULL, NULL);
    g_object_unref(args->client_data_conn);
    g_object_unref(args->upstream_data_conn);
    g_free(args);

    g_debug("FTP data tunnel thread finished.");
    return NULL;
}

// FTP-aware tunneling that inspects commands
static gboolean ftp_tunnel_with_inspection(DeadlightConnection *conn, GError **error) {
    FTPProtocolData *ftp_data = (FTPProtocolData*)conn->protocol_data;
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    GInputStream *upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    
    gchar buffer[4096];
    gboolean running = TRUE;
    
    // Set up polling
    GPollFD fds[2];
    GSocket *client_socket = g_socket_connection_get_socket(conn->client_connection);
    GSocket *upstream_socket = g_socket_connection_get_socket(conn->upstream_connection);
    
    fds[0].fd = g_socket_get_fd(client_socket);
    fds[1].fd = g_socket_get_fd(upstream_socket);
    
    while (running) {
        fds[0].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
        fds[1].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
        
        gint ready = g_poll(fds, 2, -1);
        if (ready < 0) {
            running = FALSE;
            continue;
        }
        
        // Client -> Upstream (inspect commands)
        if (fds[0].revents & G_IO_IN) {
            gssize bytes = g_input_stream_read(client_is, buffer, sizeof(buffer) - 1, NULL, error);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                
                // Check for FTP commands
                gchar *cmd_upper = g_ascii_strup(buffer, 4);
                
                if (g_str_has_prefix(cmd_upper, "USER")) {
                    ftp_data->state = FTP_STATE_USER_SENT;
                    g_free(ftp_data->username);
                    // Extract username
                    gchar *user_line = g_strndup(buffer, strcspn(buffer, "\r\n"));
                    gchar **parts = g_strsplit(user_line, " ", 2);
                    if (parts[1]) {
                        ftp_data->username = g_strdup(parts[1]);
                        g_info("Connection %lu: FTP USER %s", conn->id, ftp_data->username);
                    }
                    g_strfreev(parts);
                    g_free(user_line);
                } else if (g_str_has_prefix(cmd_upper, "PASV")) {
                    ftp_data->state = FTP_STATE_PASSIVE_REQUESTED;
                    g_info("Connection %lu: FTP PASV command detected", conn->id);
                } else if (g_str_has_prefix(cmd_upper, "LIST") || 
                          g_str_has_prefix(cmd_upper, "RETR") ||
                          g_str_has_prefix(cmd_upper, "STOR")) {
                    // Data transfer commands
                    handle_data_connection(conn, buffer);
                }
                
                g_free(cmd_upper);
                
                // Forward to upstream
                if (!g_output_stream_write_all(upstream_os, buffer, bytes, NULL, NULL, error)) {
                    running = FALSE;
                }
                conn->bytes_client_to_upstream += bytes;
            } else {
                running = FALSE;
            }
        }

        // Upstream -> Client (inspect responses)
        if (fds[1].revents & G_IO_IN) {
            gssize bytes = g_input_stream_read(upstream_is, buffer, sizeof(buffer) - 1, NULL, error);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                gboolean forward_original = TRUE;

                // Check for PASV response
                if (ftp_data->state == FTP_STATE_PASSIVE_REQUESTED && g_str_has_prefix(buffer, "227 ")) {
                    g_info("Connection %lu: FTP PASV response detected, attempting to rewrite.", conn->id);
                    forward_original = FALSE; // We will handle the response from here.

                    // 1. Parse the server's response to get the real destination
                    if (parse_pasv_response(buffer, &ftp_data->upstream_data_host, &ftp_data->upstream_data_port)) {
                        g_info("Connection %lu: Upstream wants data connection to %s:%d", conn->id, ftp_data->upstream_data_host, ftp_data->upstream_data_port);

                        // 2. Manually create and bind a socket to get a free port from the OS.
                        GSocket *listen_socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, error);
                        if (listen_socket) {
                            GInetAddress *proxy_addr = g_inet_address_new_from_string("0.0.0.0");
                            GSocketAddress *bind_addr = g_inet_socket_address_new(proxy_addr, 0); // Port 0 asks for a free port
                            
                            // Bind the socket
                            if (g_socket_bind(listen_socket, bind_addr, TRUE, error)) {
                                // Now that it's bound, get the address to see what port we got
                                GSocketAddress *effective_addr = g_socket_get_local_address(listen_socket, error);
                                if (effective_addr) {
                                    GInetAddress *proxy_inet_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(effective_addr));
                                    gchar *proxy_ip_str = g_inet_address_to_string(proxy_inet_addr);
                                    guint16 proxy_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(effective_addr));

                                    // 3. Use our function to rewrite the PASV response string
                                    gchar *rewritten_response = rewrite_pasv_response(buffer, "127.0.0.1", proxy_port);
                                    
                                    g_info("Connection %lu: Rewriting PASV response to point to %s:%d", conn->id, "127.0.0.1", proxy_port);

                                    // 4. Create the service and add our *already bound* socket to it
                                    ftp_data->data_listener = g_socket_service_new();
                                    g_socket_listener_add_socket(G_SOCKET_LISTENER(ftp_data->data_listener), listen_socket, NULL, error);
                                    g_signal_connect(ftp_data->data_listener, "incoming", G_CALLBACK(on_data_connection_incoming), conn);
                                    g_socket_service_start(ftp_data->data_listener);

                                    // 5. Send the rewritten response to the client
                                    if (!g_output_stream_write_all(client_os, rewritten_response, strlen(rewritten_response), NULL, NULL, error)) {
                                        running = FALSE;
                                    }

                                    // Cleanup from this block
                                    g_free(rewritten_response);
                                    g_free(proxy_ip_str);
                                    g_object_unref(proxy_inet_addr);
                                    g_object_unref(effective_addr);
                                }
                            }
                            g_object_unref(bind_addr);
                            g_object_unref(proxy_addr);
                            g_object_unref(listen_socket);
                        }

                        if (*error) {
                            g_warning("Connection %lu: Failed during PASV rewrite setup: %s", conn->id, (*error)->message);
                            forward_original = TRUE; // Fallback to forwarding the original broken response
                        }
                    }
                    ftp_data->state = FTP_STATE_DATA_PENDING;
                }
                
                // Check for successful login
                if (g_str_has_prefix(buffer, "230 ")) {
                    ftp_data->state = FTP_STATE_AUTHENTICATED;
                    g_info("Connection %lu: FTP authentication successful", conn->id);
                }
                
                // Forward to client if we haven't already sent a rewritten response
                if (forward_original) {
                    if (!g_output_stream_write_all(client_os, buffer, bytes, NULL, NULL, error)) {
                        running = FALSE;
                    }
                }
                conn->bytes_upstream_to_client += bytes;
            } else {
                running = FALSE;
            }
        }
        
        // Check for socket errors
        if ((fds[0].revents | fds[1].revents) & (G_IO_HUP | G_IO_ERR)) {
            running = FALSE;
        }
    }
    
    g_info("Connection %lu: FTP tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);
    
    return TRUE;
}

static gboolean on_data_connection_incoming(GSocketService *service, GSocketConnection *client_conn,
                                           GObject *source_object, gpointer user_data) {
    (void)source_object;
    DeadlightConnection *conn = (DeadlightConnection *)user_data;
    FTPProtocolData *ftp_data = (FTPProtocolData *)conn->protocol_data;
    GError *error = NULL;

    g_info("Connection %lu: Accepted incoming FTP data connection from client.", conn->id);
    
    // We have the client's data connection. Now, connect to the upstream server's data port.
    GSocketConnection *upstream_conn = deadlight_network_connect_tcp(
        conn->context,
        ftp_data->upstream_data_host,
        ftp_data->upstream_data_port,
        &error
    );

    if (!upstream_conn) {
        g_warning("Connection %lu: Failed to connect to upstream FTP data port %s:%d: %s", 
                  conn->id, ftp_data->upstream_data_host, ftp_data->upstream_data_port, error->message);
        g_io_stream_close(G_IO_STREAM(client_conn), NULL, NULL); // Close the client side
        g_error_free(error);
        return TRUE; // Stop further processing for this connection
    }

    g_info("Connection %lu: Connected to upstream FTP data port. Starting tunnel.", conn->id);

    // Prepare arguments for the tunnel thread
    FTPDataTunnelArgs *args = g_new0(FTPDataTunnelArgs, 1);
    args->client_data_conn = g_object_ref(client_conn);
    args->upstream_data_conn = upstream_conn; // no ref needed, we own it

    // Launch the tunnel in a new thread
    ftp_data->data_tunnel_thread = g_thread_new("ftp-data-tunnel", ftp_data_tunnel_thread, args);

    // Stop listening, we only need one data connection for this command.
    g_socket_service_stop(service);
    g_object_unref(ftp_data->data_listener);
    ftp_data->data_listener = NULL;

    return TRUE;
}

static gboolean parse_ftp_uri(const gchar *uri, gchar **host, guint16 *port, 
                              gchar **user, gchar **pass, gchar **path) {
    gchar *at, *colon, *slash;
    
    if (!g_str_has_prefix(uri, "ftp://"))
        return FALSE;
    
    const gchar *start = uri + 6; // after "ftp://"
    gchar *host_end = NULL;
    
    // Default values
    *host = NULL;
    *user = NULL;
    *pass = NULL;
    *path = NULL;
    
    // Check for user:pass@
    at = strchr(start, '@');
    if (at) {
        // userinfo part
        colon = strchr(start, ':');
        if (colon && colon < at) {
            *user = g_strndup(start, colon - start);
            *pass = g_strndup(colon + 1, at - colon - 1);
        } else {
            *user = g_strndup(start, at - start);
            *pass = g_strdup("");
        }
        start = at + 1;
    }
    
    // Find host part end (either ':' for port or '/' for path)
    slash = strchr(start, '/');
    colon = strchr(start, ':');
    
    if (colon && (!slash || colon < slash)) {
        // Port specified
        *host = g_strndup(start, colon - start);
        *port = (guint16)atoi(colon + 1);
        host_end = strchr(colon + 1, '/');
    } else {
        // No port, default 21
        *host = g_strndup(start, slash ? slash - start : (gssize)strlen(start));
        *port = 21;
        host_end = slash;
    }
    
    // Path (including the leading '/')
    if (host_end && *host_end == '/') {
        *path = g_strdup(host_end);
    } else {
        *path = g_strdup("/");
    }
    
    // Default user/pass if not provided
    if (!*user) *user = g_strdup("anonymous");
    if (!*pass) *pass = g_strdup("anonymous@");
    
    return TRUE;
}

static DeadlightHandlerResult handle_http_wrapped_ftp_streaming(DeadlightConnection *conn, GError **error) {
    // 1. Parse HTTP request line and extract URI
    const gchar *data = (const gchar *)conn->client_buffer->data;
    const gchar *end_of_line = strstr(data, "\r\n");
    if (!end_of_line) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Malformed HTTP request");
        return HANDLER_ERROR;
    }
    
    gchar *request_line = g_strndup(data, end_of_line - data);
    gchar **parts = g_strsplit(request_line, " ", 3);
    g_free(request_line);
    
    if (g_strv_length(parts) < 2 || g_strcmp0(parts[0], "GET") != 0) {
        g_strfreev(parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Only GET method supported for FTP URLs");
        return HANDLER_ERROR;
    }
    
    const gchar *uri = parts[1];
    
    // 2. Parse FTP URI
    gchar *ftp_host = NULL, *ftp_user = NULL, *ftp_pass = NULL, *ftp_path = NULL;
    guint16 ftp_port = 21;
    if (!parse_ftp_uri(uri, &ftp_host, &ftp_port, &ftp_user, &ftp_pass, &ftp_path)) {
        g_strfreev(parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid FTP URI");
        return HANDLER_ERROR;
    }
    g_strfreev(parts);
    
    g_info("Connection %lu: HTTP-wrapped FTP request to %s:%d, path=%s", 
           conn->id, ftp_host, ftp_port, ftp_path);
    
    // 3. Connect to FTP control port
    GSocketConnection *ctrl_conn = deadlight_network_connect_tcp(conn->context, ftp_host, ftp_port, error);
    if (!ctrl_conn) {
        // Send HTTP error response before returning
        const char *error_body = "Proxy error: Could not connect to FTP server.\n";
        char http_error[512];
        snprintf(http_error, sizeof(http_error),
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", strlen(error_body), error_body);
        
        GOutputStream *client_out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_out, http_error, strlen(http_error), NULL, NULL, NULL);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    // 4. Read welcome banner (should be 220, may be multi-line)
    GInputStream *ctrl_in = g_io_stream_get_input_stream(G_IO_STREAM(ctrl_conn));
    int welcome_code = 0;
    gchar *welcome_line = NULL;
    
    // Read until we get the final line of the banner
    while (1) {
        gchar *line = ftp_read_response_line(ctrl_in, error);
        if (!line) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to read FTP welcome banner");
            g_object_unref(ctrl_conn);
            g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
            return HANDLER_ERROR;
        }
        
        int code = atoi(line);
        if (welcome_code == 0) welcome_code = code;
        
        gboolean is_last_line = (strlen(line) > 3 && line[3] == ' ');
        
        // Accumulate but limit size to avoid memory bloat
        if (welcome_line) {
            gchar *old = welcome_line;
            welcome_line = g_strdup_printf("%s\n%.200s", old, line);
            g_free(old);
        } else {
            welcome_line = g_strdup(line);
        }
        g_free(line);
        
        if (is_last_line)
            break;
    }
    
    // 5. Authenticate
    char response[1024];  
    gchar *cmd;
    int code;
    
    cmd = g_strdup_printf("USER %s", ftp_user);
    code = ftp_send_command(ctrl_conn, cmd, response, sizeof(response));
    g_free(cmd);
    
    g_info("Connection %lu: USER response: %d - %s", conn->id, code, response);
    
    // Handle different FTP server behaviors:
    // 230 = Logged in successfully (no password needed)
    // 331 = Password required
    if (code == 230) {
        // Already authenticated (common for anonymous FTP)
        g_info("Connection %lu: FTP anonymous login accepted without password", conn->id);
    } else if (code == 331) {
        // Password required
        cmd = g_strdup_printf("PASS %s", ftp_pass);
        code = ftp_send_command(ctrl_conn, cmd, response, sizeof(response));
        g_free(cmd);
        if (code != 230) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, 
                       "FTP PASS failed (code %d): %s", code, response);
            g_object_unref(ctrl_conn);
            g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
            return HANDLER_ERROR;
        }
        g_info("Connection %lu: FTP login successful with password", conn->id);
    } else if (code == 220) {
        // Some servers send 220 for "service ready" - we already read welcome banner
        // This shouldn't happen for USER command, but just in case
        g_warning("Connection %lu: Unexpected 220 response to USER, retrying...", conn->id);
        // Small delay and retry? Or just fail.
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, 
                   "FTP USER got unexpected 220 response");
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        return HANDLER_ERROR;
    } else {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, 
                   "FTP USER failed (code %d): %s", code, response);
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        return HANDLER_ERROR;
    }
    
    // 6. Set binary mode (optional - don't fail if it doesn't work)
    code = ftp_send_command(ctrl_conn, "TYPE I", response, sizeof(response));
    if (code != 200) {
        g_warning("Connection %lu: TYPE I returned %d (continuing anyway): %s", 
                  conn->id, code, response);
        // Continue anyway - most servers default to ASCII which is fine for text
    }
    
    // 7. Determine operation: RETR or LIST
    gboolean is_dir = g_str_has_suffix(ftp_path, "/") || g_strcmp0(ftp_path, "/") == 0;
    const gchar *ftp_cmd;
    if (is_dir)
        ftp_cmd = g_strdup_printf("LIST %s", ftp_path);
    else
        ftp_cmd = g_strdup_printf("RETR %s", ftp_path);
    
    // 8. Enter passive mode
    code = ftp_send_command(ctrl_conn, "PASV", response, sizeof(response));
    if (code != 227) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "PASV failed: %s", response);
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        if (!is_dir) g_free((gchar*)ftp_cmd);
        return HANDLER_ERROR;
    }
    
    // Parse PASV response to get IP and port
    gchar *data_host = NULL;
    guint16 data_port = 0;
    if (!parse_pasv_response(response, &data_host, &data_port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to parse PASV response");
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        if (!is_dir) g_free((gchar*)ftp_cmd);
        return HANDLER_ERROR;
    }
    
    // 9. Connect to data port
    GSocketConnection *data_conn = deadlight_network_connect_tcp(conn->context, data_host, data_port, error);
    g_free(data_host);
    if (!data_conn) {
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        if (!is_dir) g_free((gchar*)ftp_cmd);
        return HANDLER_ERROR;
    }
    
    // 10. Send RETR or LIST command
    code = ftp_send_command(ctrl_conn, ftp_cmd, response, sizeof(response));
    if (code != 150 && code != 125) {
        // Build HTTP error response - use larger buffer
        char http_response[2048];  // Increased from 512
        int http_status = 404;     // Not Found
        const char *http_status_text = "Not Found";
        const char *error_body = NULL;
        char fallback_body[256];
        
        // Handle different FTP error codes
        if (code == 550) {
            http_status = 404;
            http_status_text = "Not Found";
            error_body = "FTP: File not found.\n";
        } else if (code == 553) {
            http_status = 403;
            http_status_text = "Forbidden";
            error_body = "FTP: Permission denied.\n";
        } else if (code == 530) {
            http_status = 401;
            http_status_text = "Unauthorized";
            error_body = "FTP: Authentication failed.\n";
        } else {
            // Use FTP server's message, but truncate to reasonable length
            snprintf(fallback_body, sizeof(fallback_body), "FTP error %d: %.200s\n", code, response);
            error_body = fallback_body;
        }
        
        size_t error_len = strlen(error_body);
        snprintf(http_response, sizeof(http_response),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", http_status, http_status_text, error_len, error_body);
        
        GOutputStream *client_out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_out, http_response, strlen(http_response), NULL, NULL, NULL);
        
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "FTP command %s failed: %s", ftp_cmd, response);
        g_object_unref(ctrl_conn);
        g_object_unref(data_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        if (!is_dir) g_free((gchar*)ftp_cmd);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // 11. Setup FTP protocol data for streaming
    FTPProtocolData *ftp_data = conn->protocol_data;
    if (!ftp_data) {
        ftp_data = g_new0(FTPProtocolData, 1);
        conn->protocol_data = ftp_data;
    }
    ftp_data->http_wrapped = TRUE;
    ftp_data->http_data_conn = data_conn;
    ftp_data->http_ctrl_conn = ctrl_conn;
    ftp_data->data_transfer_done = FALSE;
    ftp_data->control_waits_226 = FALSE;
    ftp_data->headers_sent = FALSE;
    
    // 12. Prepare and send chunked HTTP response headers
    GString *headers = g_string_new(NULL);
    g_string_append(headers, "HTTP/1.1 200 OK\r\n");
    g_string_append(headers, "Content-Type: application/octet-stream\r\n");
    g_string_append(headers, "Transfer-Encoding: chunked\r\n");
    g_string_append(headers, "Connection: close\r\n\r\n");
    ftp_data->http_response_headers = headers;
    
    GOutputStream *client_out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    if (!g_output_stream_write_all(client_out, headers->str, headers->len, NULL, NULL, error)) {
        g_object_unref(data_conn);
        g_object_unref(ctrl_conn);
        g_free(ftp_host); g_free(ftp_user); g_free(ftp_pass); g_free(ftp_path);
        return HANDLER_ERROR;
    }
    ftp_data->headers_sent = TRUE;
    
    // 13. Enter streaming loop
    GSocket *client_sock = g_socket_connection_get_socket(conn->client_connection);
    GSocket *ctrl_sock = g_socket_connection_get_socket(ctrl_conn);
    GSocket *data_sock = g_socket_connection_get_socket(data_conn);
    g_socket_set_blocking(client_sock, FALSE);
    g_socket_set_blocking(ctrl_sock, FALSE);
    g_socket_set_blocking(data_sock, FALSE);
    
    GPollFD fds[3];
    fds[0].fd = g_socket_get_fd(client_sock);
    fds[0].events = 0;
    fds[1].fd = g_socket_get_fd(ctrl_sock);
    fds[1].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    fds[2].fd = g_socket_get_fd(data_sock);
    fds[2].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    
    GByteArray *out_buf = g_byte_array_new();
    gboolean running = TRUE;
    guint8 data_buf[16384];
    
    while (running && !conn->context->shutdown_requested) {
        gint ready = g_poll(fds, 3, 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        // From data socket → client (chunked)
        if (fds[2].revents & G_IO_IN) {
            gssize n = g_socket_receive(data_sock, (gchar*)data_buf, sizeof(data_buf), NULL, error);
            if (n > 0) {
                // Format as HTTP chunk: "%X\r\n<data>\r\n"
                gchar chunk_header[32];
                g_snprintf(chunk_header, sizeof(chunk_header), "%X\r\n", (guint)n);
                g_byte_array_append(out_buf, (guint8*)chunk_header, strlen(chunk_header));
                g_byte_array_append(out_buf, data_buf, n);
                g_byte_array_append(out_buf, (guint8*)"\r\n", 2);
                fds[0].events = G_IO_OUT;
            } else if (n == 0) {
                // Data socket closed - transfer complete
                ftp_data->data_transfer_done = TRUE;
                fds[2].events = 0;
                // Send final zero chunk
                const gchar *end_chunk = "0\r\n\r\n";
                g_byte_array_append(out_buf, (guint8*)end_chunk, strlen(end_chunk));
                fds[0].events = G_IO_OUT;
            } else if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                running = FALSE;
            }
        }
        
        // From control socket - look for 226
        if (fds[1].revents & G_IO_IN) {
            gssize n = g_socket_receive(ctrl_sock, (gchar*)data_buf, sizeof(data_buf)-1, NULL, error);
            if (n > 0) {
                data_buf[n] = '\0';
                if (strstr((char*)data_buf, "226 ")) {
                    // Transfer complete on control channel
                    running = FALSE;
                }
            } else if (n == 0) {
                running = FALSE;
            }
        }
        
        // Write to client if writable
        if ((fds[0].revents & G_IO_OUT) && out_buf->len > 0) {
            gssize written = g_socket_send(client_sock, (const gchar*)out_buf->data, out_buf->len, NULL, error);
            if (written > 0) {
                g_byte_array_remove_range(out_buf, 0, written);
            } else if (written < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
                running = FALSE;
            }
        }
        
        // Clear write flag if buffer empty
        if (out_buf->len == 0) {
            fds[0].events = 0;
        }
        
        // Check for errors
        if ((fds[1].revents | fds[2].revents) & (G_IO_HUP | G_IO_ERR)) {
            running = FALSE;
        }
    }

    // If we didn't send any data (empty directory? no files?), send an empty chunk
    if (ftp_data->headers_sent && !ftp_data->data_transfer_done) {
        const gchar *empty_chunk = "0\r\n\r\n";
        GOutputStream *client_out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_out, empty_chunk, strlen(empty_chunk), NULL, NULL, NULL);
    }
    
    // 14. Cleanup
    g_byte_array_free(out_buf, TRUE);
    if (ftp_data->http_data_conn) {
        g_object_unref(ftp_data->http_data_conn);
        ftp_data->http_data_conn = NULL;
    }
    if (ftp_data->http_ctrl_conn) {
        g_object_unref(ftp_data->http_ctrl_conn);
        ftp_data->http_ctrl_conn = NULL;
    }
    if (ftp_data->http_response_headers) {
        g_string_free(ftp_data->http_response_headers, TRUE);
        ftp_data->http_response_headers = NULL;
    }
    
    g_free(ftp_host);
    g_free(ftp_user);
    g_free(ftp_pass);
    g_free(ftp_path);
    
    g_info("Connection %lu: HTTP-wrapped FTP streaming complete", conn->id);
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error) {
    // Check if this is an HTTP request for an FTP URL
    if (conn->client_buffer->len >= 4 && memcmp(conn->client_buffer->data, "GET ", 4) == 0) {
        gchar *sample = g_strndup((const gchar*)conn->client_buffer->data, MIN(conn->client_buffer->len, 100));
        if (strstr(sample, "ftp://")) {
            g_free(sample);
            return handle_http_wrapped_ftp_streaming(conn, error);
        }
        g_free(sample);
    }
    
    gchar *host = NULL;
    guint16 port = 21;
    
    // Try to determine the target FTP server
    if (!parse_ftp_target(conn, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                    "No FTP target server configured");
        
        const gchar *error_response = "421 No upstream FTP server configured.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: FTP connection to %s:%d", conn->id, host, port);
    
    // Allocate FTP protocol data
    FTPProtocolData *ftp_data = g_new0(FTPProtocolData, 1);
    ftp_data->state = FTP_STATE_INIT;
    conn->protocol_data = ftp_data;
    
    // Create request for plugin hooks
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("FTP");
    conn->current_request->uri = g_strdup_printf("ftp://%s:%d", host, port);
    conn->current_request->host = g_strdup(host);
    
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: FTP request blocked by plugin", conn->id);
        const gchar *error_response = "530 Access denied by proxy policy.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("Connection %lu: Failed to connect to FTP upstream %s:%d", 
                  conn->id, host, port);
        
        const gchar *error_response = "421 Service not available.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Store the upstream host for PASV rewriting
    ftp_data->data_host = host; // Take ownership
    
    // Send initial client data if any
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        GOutputStream *upstream_os = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->upstream_connection));
        
        if (!g_output_stream_write_all(upstream_os, 
                                       conn->client_buffer->data, 
                                       conn->client_buffer->len, 
                                       NULL, NULL, error)) {
            return HANDLER_ERROR;
        }
    }
    
    // Use FTP-aware tunneling
    g_info("Connection %lu: Starting FTP tunnel with command inspection", conn->id);
    if (ftp_tunnel_with_inspection(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static void ftp_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        FTPProtocolData *ftp_data = (FTPProtocolData*)conn->protocol_data;
        
        g_free(ftp_data->username);
        g_free(ftp_data->upstream_data_host);
        g_free(ftp_data->data_host);
        
        // Cleanup HTTP-wrapped FTP resources
        if (ftp_data->http_data_conn) {
            g_object_unref(ftp_data->http_data_conn);
        }
        if (ftp_data->http_ctrl_conn) {
            g_object_unref(ftp_data->http_ctrl_conn);
        }
        if (ftp_data->http_response_headers) {
            g_string_free(ftp_data->http_response_headers, TRUE);
        }
        
        // Stop the listener if it's still running
        if (ftp_data->data_listener) {
            g_socket_service_stop(ftp_data->data_listener);
            g_object_unref(ftp_data->data_listener);
        }
        
        // If a thread was created, we just let it finish.
        if (ftp_data->data_tunnel_thread) {
            g_thread_unref(ftp_data->data_tunnel_thread);
        }
        
        g_free(ftp_data);
        conn->protocol_data = NULL;
    }
    
    g_debug("FTP cleanup called for conn %lu", conn->id);
}