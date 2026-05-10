#include "smtp.h"
#include <string.h>
#include <json-glib/json-glib.h>
#include <ctype.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

// Structure to hold MX record data
typedef struct {
    gchar *hostname;
    gint priority;
} MXRecord;

static gsize smtp_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult smtp_handle(DeadlightConnection *conn, GError **error);
static void smtp_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult smtp_handle_bridge_mode(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult smtp_handle_proxy_mode(DeadlightConnection *conn, const gchar *upstream_host, gint upstream_port, GError **error);
static DeadlightHandlerResult smtp_handle_local_mode(DeadlightConnection *conn, GError **error);
static gboolean smtp_send_to_api(DeadlightConnection *conn, DeadlightSMTPData *smtp_data, const gchar *api_endpoint, GError **error);

// SMTP command constants
#define SMTP_GREETING "220 deadlight.proxy ESMTP Ready\r\n"
#define SMTP_OK "250 OK\r\n"
#define SMTP_DATA_START "354 Start mail input; end with <CRLF>.<CRLF>\r\n"
#define SMTP_BYE "221 Bye\r\n"

// The handler object
static const DeadlightProtocolHandler smtp_protocol_handler = {
    .name = "SMTP",
    .protocol_id = DEADLIGHT_PROTOCOL_SMTP,
    .detect = smtp_detect,
    .handle = smtp_handle,
    .cleanup = smtp_cleanup
};

void deadlight_register_smtp_handler(void) {
    deadlight_protocol_register(&smtp_protocol_handler);
}

// --- IMPLEMENTATION ---

static gsize smtp_detect(const guint8 *data, gsize len) {
    if (len < 4) return 0;
    
    const char *str = (const char*)data;
    
    // SMTP client commands - return priority 10 (much higher than IMAP's 1)
    if (g_str_has_prefix(str, "EHLO") ||
        g_str_has_prefix(str, "HELO") ||
        g_str_has_prefix(str, "MAIL FROM:") ||
        g_str_has_prefix(str, "RCPT TO:") ||
        g_str_has_prefix(str, "DATA") ||
        g_str_has_prefix(str, "QUIT") ||
        g_str_has_prefix(str, "RSET") ||
        g_str_has_prefix(str, "NOOP")) {
        return 10;  // Changed from 1 to 10
    }
    
    // Also check for SMTP server responses
    if (len >= 3 && str[0] >= '2' && str[0] <= '5' && 
        isdigit(str[1]) && isdigit(str[2])) {
        return 8;  // Server responses get slightly lower priority
    }
    
    return 0;
}

static DeadlightHandlerResult smtp_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("SMTP handler assigned to connection %lu", conn->id);

    // Get configuration
    gboolean bridge_mode = deadlight_config_get_bool(ctx, "smtp", "bridge_mode", FALSE);
    const gchar *upstream_host = deadlight_config_get_string(ctx, "smtp", "upstream_host", NULL);
    gint upstream_port = deadlight_config_get_int(ctx, "smtp", "upstream_port", 25);

    if (bridge_mode) {
        // API Bridge Mode - Translate SMTP to HTTP API calls
        return smtp_handle_bridge_mode(conn, error);
    } else if (upstream_host) {
        // Proxy Mode - Forward to upstream SMTP server
        return smtp_handle_proxy_mode(conn, upstream_host, upstream_port, error);
    } else {
        // Local Mode - Handle SMTP directly (for blog integration)
        return smtp_handle_local_mode(conn, error);
    }
}

// Bridge mode: Translate SMTP to HTTP API calls for Cloudflare Worker
static DeadlightHandlerResult smtp_handle_bridge_mode(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    const gchar *api_endpoint = deadlight_config_get_string(ctx, "smtp", "api_endpoint", 
                                                           "https://deadlight.boo/api/email/receive");
    
    g_info("SMTP bridge mode for conn %lu: Will translate to API calls to %s", conn->id, api_endpoint);
    
    // Initialize SMTP protocol data
    DeadlightSMTPData *smtp_data = g_new0(DeadlightSMTPData, 1);
    smtp_data->message_buffer = g_byte_array_new();
    conn->protocol_data = smtp_data;
    
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    // Send greeting
    if (!g_output_stream_write_all(client_os, SMTP_GREETING, strlen(SMTP_GREETING), NULL, NULL, error)) {
        return HANDLER_ERROR;
    }
    
    // Main SMTP command loop
    gchar buffer[1024];
    gboolean running = TRUE;
    
    while (running) {
        gssize bytes_read = g_input_stream_read(client_is, buffer, sizeof(buffer) - 1, NULL, error);
        if (bytes_read <= 0) break;
        
        buffer[bytes_read] = '\0';
        gchar **lines = g_strsplit(buffer, "\r\n", -1);
        
        for (int i = 0; lines[i] && strlen(lines[i]) > 0; i++) {
            gchar *line = g_strstrip(lines[i]);
            g_info("SMTP bridge conn %lu received: %s", conn->id, line);
            
            if (g_str_has_prefix(line, "HELO") || g_str_has_prefix(line, "EHLO")) {
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "MAIL FROM:")) {
                smtp_data->sender = g_strdup(line + 10); // Skip "MAIL FROM:"
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "RCPT TO:")) {
                smtp_data->recipient = g_strdup(line + 8); // Skip "RCPT TO:"
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "DATA")) {
                smtp_data->in_data_mode = TRUE;
                g_output_stream_write_all(client_os, SMTP_DATA_START, strlen(SMTP_DATA_START), NULL, NULL, NULL);
                
            } else if (smtp_data->in_data_mode) {
                if (g_str_equal(line, ".")) {
                    // End of message - send to API
                    if (smtp_send_to_api(conn, smtp_data, api_endpoint, error)) {
                        g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                    } else {
                        const gchar *error_msg = "550 Message processing failed\r\n";
                        g_output_stream_write_all(client_os, error_msg, strlen(error_msg), NULL, NULL, NULL);
                    }
                    smtp_data->in_data_mode = FALSE;
                    
                } else {
                    // Accumulate message data
                    g_byte_array_append(smtp_data->message_buffer, (guint8*)line, strlen(line));
                    g_byte_array_append(smtp_data->message_buffer, (guint8*)"\r\n", 2);
                }
                
            } else if (g_str_has_prefix(line, "QUIT")) {
                g_output_stream_write_all(client_os, SMTP_BYE, strlen(SMTP_BYE), NULL, NULL, NULL);
                running = FALSE;
            }
        }
        
        g_strfreev(lines);
    }
    
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

static gchar* read_auth_token(DeadlightContext *context) {
    gchar *token_file = deadlight_config_get_string(context, "api", "auth_token_file", NULL);
    if (!token_file) {
        return NULL;
    }
    
    gchar *token = NULL;
    GError *error = NULL;
    
    if (g_file_get_contents(token_file, &token, NULL, &error)) {
        // Remove any trailing newlines
        g_strstrip(token);
    } else {
        g_warning("Failed to read auth token from %s: %s", token_file, error->message);
        g_error_free(error);
    }
    
    g_free(token_file);
    return token;
}

static gint compare_mx_records(gconstpointer a, gconstpointer b) {
    const MXRecord *mx_a = (const MXRecord *)a;
    const MXRecord *mx_b = (const MXRecord *)b;
    return mx_a->priority - mx_b->priority;
}

// Query MX records for a domain and return sorted list
static GList* smtp_lookup_mx_records(const gchar *domain, GError **error) {
    GList *mx_records = NULL;
    
    // Initialize resolver
    if (res_init() != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to initialize DNS resolver");
        return NULL;
    }
    
    // Query buffer
    guchar answer[4096];
    gint answer_len = res_query(domain, ns_c_in, ns_t_mx, answer, sizeof(answer));
    
    if (answer_len < 0) {
        g_warning("SMTP: No MX records found for %s, trying A record fallback", domain);
        
        // Fallback: Use the domain itself (try A record)
        MXRecord *fallback = g_new0(MXRecord, 1);
        fallback->hostname = g_strdup(domain);
        fallback->priority = 10;
        mx_records = g_list_append(mx_records, fallback);
        
        return mx_records;
    }
    
    // Parse DNS response
    ns_msg handle;
    if (ns_initparse(answer, answer_len, &handle) < 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to parse MX DNS response for %s", domain);
        return NULL;
    }
    
    // Extract MX records
    gint mx_count = ns_msg_count(handle, ns_s_an);
    g_debug("SMTP: Found %d MX records for %s", mx_count, domain);
    
    for (int i = 0; i < mx_count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }
        
        if (ns_rr_type(rr) != ns_t_mx) {
            continue;
        }
        
        // Extract MX data
        const guchar *rdata = ns_rr_rdata(rr);
        gint priority = ns_get16(rdata);
        
        // Extract hostname
        gchar hostname[256];
        if (ns_name_uncompress(answer, answer + answer_len, rdata + 2,
                              hostname, sizeof(hostname)) < 0) {
            continue;
        }
        
        MXRecord *mx = g_new0(MXRecord, 1);
        mx->hostname = g_strdup(hostname);
        mx->priority = priority;
        mx_records = g_list_append(mx_records, mx);
        
        g_debug("SMTP: MX record: %s (priority %d)", mx->hostname, mx->priority);
    }
    
    if (!mx_records) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "No valid MX records found for %s", domain);
        return NULL;
    }
    
    // Sort by priority (lowest first)
    mx_records = g_list_sort(mx_records, compare_mx_records);
    
    return mx_records;
}

static void smtp_free_mx_records(GList *mx_records) {
    for (GList *l = mx_records; l != NULL; l = l->next) {
        MXRecord *mx = (MXRecord *)l->data;
        g_free(mx->hostname);
        g_free(mx);
    }
    g_list_free(mx_records);
}

// Enhanced SMTP to API function
static gboolean smtp_send_to_api(DeadlightConnection *conn, DeadlightSMTPData *smtp_data, 
                                       const gchar *api_endpoint, GError **error) {
    gboolean success = FALSE;
    gchar *json_str = NULL;
    gchar *auth_token = NULL;
    
    // Get endpoint from config
    gchar *endpoint = api_endpoint ? g_strdup(api_endpoint) : 
                     deadlight_config_get_string(conn->context, "smtp", "api_endpoint", 
                                                "http://localhost:8080/api/email/receive");
    
    // Parse URL
    gchar *host = NULL;
    guint16 port = 80;
    gchar *path = NULL;
    gboolean use_ssl = FALSE;
    
    if (g_str_has_prefix(endpoint, "https://")) {
        use_ssl = TRUE;
        port = 443;
        host = g_strdup(endpoint + 8);
    } else if (g_str_has_prefix(endpoint, "http://")) {
        host = g_strdup(endpoint + 7);
    } else {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Invalid API endpoint URL: %s", endpoint);
        g_free(endpoint);
        return FALSE;
    }
    
    // Extract path from host
    gchar *slash = strchr(host, '/');
    if (slash) {
        path = g_strdup(slash);
        *slash = '\0';
    } else {
        path = g_strdup("/");
    }
    
    // Extract port from host if specified
    gchar *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }
    
    g_info("SMTP bridge: Connecting to %s:%d%s", host, port, path);
    
    // Build JSON payload (simplified)
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "from");
    json_builder_add_string_value(builder, smtp_data->sender);
    json_builder_set_member_name(builder, "to");
    json_builder_add_string_value(builder, smtp_data->recipient);
    json_builder_set_member_name(builder, "body");
    json_builder_add_string_value(builder, (gchar*)smtp_data->message_buffer->data);
    json_builder_set_member_name(builder, "timestamp");
    json_builder_add_int_value(builder, g_get_real_time() / G_USEC_PER_SEC);
    json_builder_end_object(builder);
    
    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    json_str = json_generator_to_data(gen, NULL);
    
    // Read auth token
    auth_token = read_auth_token(conn->context);
    
    // Build HTTP request
    GString *request = g_string_new("");
    g_string_printf(request,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Deadlight-SMTP-Bridge/1.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n",
        path, host, strlen(json_str));
    
    if (auth_token) {
        g_string_append_printf(request, "Authorization: Bearer %s\r\n", auth_token);
    }
    
    g_string_append_printf(request, "Connection: close\r\n\r\n%s", json_str);
    
    // Connect to API
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = NULL;
    
    // With:
    if (use_ssl) {
        g_socket_client_set_tls(client, TRUE);
        // For GLib 2.72+, use the new API if available
        #if GLIB_CHECK_VERSION(2, 72, 0)
            GTlsCertificateFlags flags = G_TLS_CERTIFICATE_VALIDATE_ALL;
            g_object_set(client, "tls-validation-flags", flags, NULL);
        #else
            g_socket_client_set_tls_validation_flags(client, G_TLS_CERTIFICATE_VALIDATE_ALL);
        #endif
    }
    
    connection = g_socket_client_connect_to_host(client, host, port, NULL, error);
    
    if (connection) {
        GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(connection));
        GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
        
        // Send request
        if (g_output_stream_write_all(out, request->str, request->len, NULL, NULL, error)) {
            // Read response
            gchar buffer[4096];
            gssize bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, error);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                
                // Check for success
                if (g_strstr_len(buffer, bytes_read, "200 OK") ||
                    g_strstr_len(buffer, bytes_read, "201 Created")) {
                    g_info("SMTP bridge: Successfully posted to API");
                    success = TRUE;
                    
                    // Log response body
                    gchar *body_start = g_strstr_len(buffer, bytes_read, "\r\n\r\n");
                    if (body_start) {
                        g_debug("SMTP bridge: API response: %s", body_start + 4);
                    }
                } else {
                    g_warning("SMTP bridge: API request failed: %s", buffer);
                }
            }
        }
        
        g_object_unref(connection);
    }
    
    // Cleanup
    g_string_free(request, TRUE);
    g_object_unref(client);
    g_free(host);
    g_free(path);
    g_free(endpoint);
    g_free(auth_token);
    g_free(json_str);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return success;
}

gboolean smtp_send_message(const gchar *from, const gchar *to, 
                          const gchar *subject, const gchar *body,
                          GError **error) {
    // Extract domain from recipient email
    const gchar *at_sign = strchr(to, '@');
    if (!at_sign) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Invalid recipient email: %s", to);
        return FALSE;
    }
    const gchar *recipient_domain = at_sign + 1;
    
    // Query MX records
    GError *mx_error = NULL;
    GList *mx_records = smtp_lookup_mx_records(recipient_domain, &mx_error);
    
    if (!mx_records) {
        g_propagate_error(error, mx_error);
        return FALSE;
    }
    
    // Try each MX server in order of priority
    gboolean success = FALSE;
    GSocketClient *client = NULL;
    GSocketConnection *connection = NULL;
    
    for (GList *l = mx_records; l != NULL && !success; l = l->next) {
        MXRecord *mx = (MXRecord *)l->data;
        gint mx_port = 25;
        
        g_info("SMTP: Attempting delivery to %s via %s:%d (priority %d)", 
               to, mx->hostname, mx_port, mx->priority);
        
        // Clean up previous attempt
        if (connection) {
            g_object_unref(connection);
            connection = NULL;
        }
        if (client) {
            g_object_unref(client);
        }
        
        // Connect to MX server
        client = g_socket_client_new();
        g_socket_client_set_timeout(client, 10);
        GError *connect_error = NULL;
        connection = g_socket_client_connect_to_host(
            client, mx->hostname, mx_port, NULL, &connect_error);
        
        if (!connection) {
            g_warning("SMTP: Failed to connect to %s:%d - %s", 
                     mx->hostname, mx_port, 
                     connect_error ? connect_error->message : "unknown error");
            
            if (connect_error) {
                g_error_free(connect_error);
            }
            continue; // Try next MX server
        }
        
        // Connection successful, proceed with SMTP handshake
        GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
        GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(connection));
        
        gchar buffer[1024];
        gssize bytes_read;
        
        // Read greeting (220 ...)
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0) {
            g_warning("SMTP: No greeting from %s", mx->hostname);
            continue;
        }
        buffer[bytes_read] = '\0';
        g_debug("SMTP: Server greeting: %s", g_strstrip(buffer));
        
        // Send EHLO
        const gchar *our_domain = "deadlight.boo";
        gchar *ehlo_cmd = g_strdup_printf("EHLO %s\r\n", our_domain);
        if (!g_output_stream_write_all(out, ehlo_cmd, strlen(ehlo_cmd), NULL, NULL, NULL)) {
            g_free(ehlo_cmd);
            continue;
        }
        g_free(ehlo_cmd);
        
        // Read EHLO response (may be multi-line)
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0) continue;
        buffer[bytes_read] = '\0';
        g_debug("SMTP: EHLO response: %s", g_strstrip(buffer));
        
        // Send MAIL FROM
        gchar *mail_from = g_strdup_printf("MAIL FROM:<%s>\r\n", from);
        if (!g_output_stream_write_all(out, mail_from, strlen(mail_from), NULL, NULL, NULL)) {
            g_free(mail_from);
            continue;
        }
        g_free(mail_from);
        
        // Read response
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0 || buffer[0] != '2') continue;
        
        // Send RCPT TO
        gchar *rcpt_to = g_strdup_printf("RCPT TO:<%s>\r\n", to);
        if (!g_output_stream_write_all(out, rcpt_to, strlen(rcpt_to), NULL, NULL, NULL)) {
            g_free(rcpt_to);
            continue;
        }
        g_free(rcpt_to);
        
        // Read response
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0 || buffer[0] != '2') continue;
        
        // Send DATA
        const gchar *data_cmd = "DATA\r\n";
        if (!g_output_stream_write_all(out, data_cmd, strlen(data_cmd), NULL, NULL, NULL)) {
            continue;
        }
        
        // Read 354 response
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0 || buffer[0] != '3') continue;
        
        // Build email with proper headers
        GDateTime *now = g_date_time_new_now_local();
        gchar *date_str = g_date_time_format(now, "%a, %d %b %Y %H:%M:%S %z");

        GString *message = g_string_new("");
        g_string_printf(message,
            "From: %s\r\n"
            "To: %s\r\n"
            "Subject: %s\r\n"
            "Date: %s\r\n"
            "Message-ID: <%ld.%s>\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "\r\n"
            "%s\r\n"
            ".\r\n",
            from, to, subject,
            date_str,
            g_get_real_time(), from,
            body);

        g_free(date_str);
        g_date_time_unref(now);
        
        if (!g_output_stream_write_all(out, message->str, message->len, NULL, NULL, NULL)) {
            g_string_free(message, TRUE);
            continue;
        }
        g_string_free(message, TRUE);
        
        // Read final response
        bytes_read = g_input_stream_read(in, buffer, sizeof(buffer) - 1, NULL, NULL);
        if (bytes_read <= 0) continue;
        buffer[bytes_read] = '\0';
        g_debug("SMTP: Delivery response: %s", g_strstrip(buffer));
        
        // Check for success (250 OK)
        if (buffer[0] == '2') {
            success = TRUE;
            g_info("SMTP: Email sent successfully to %s via %s", to, mx->hostname);
        }
        
        // Send QUIT
        const gchar *quit_cmd = "QUIT\r\n";
        g_output_stream_write_all(out, quit_cmd, strlen(quit_cmd), NULL, NULL, NULL);
    }
    
    // Cleanup
    if (connection) g_object_unref(connection);
    if (client) g_object_unref(client);
    smtp_free_mx_records(mx_records);
    
    if (!success) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to deliver email to any MX server for %s", recipient_domain);
    }
    
    return success;
}

static DeadlightHandlerResult smtp_handle_proxy_mode(DeadlightConnection *conn, const gchar *upstream_host, gint upstream_port, GError **error) {
    g_info("SMTP proxy mode for conn %lu: Forwarding to %s:%d", conn->id, upstream_host, upstream_port);
    
    // Connect to upstream SMTP server
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("SMTP proxy mode for conn %lu: Failed to connect to %s:%d", conn->id, upstream_host, upstream_port);
        return HANDLER_ERROR;
    }
    
    // Send initial greeting if we have buffered client data
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
        if (!g_output_stream_write_all(upstream_os, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error)) {
            g_warning("SMTP proxy mode for conn %lu: Failed to forward initial data", conn->id);
            return HANDLER_ERROR;
        }
    }
    
    // Start tunneling
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult smtp_handle_local_mode(DeadlightConnection *conn, GError **error) {
    g_info("SMTP local mode for conn %lu: Handling locally", conn->id);
    
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    // Send a basic greeting
    const gchar *greeting = "220 deadlight.proxy ESMTP Ready (Local Mode)\r\n";
    if (!g_output_stream_write_all(client_os, greeting, strlen(greeting), NULL, NULL, error)) {
        return HANDLER_ERROR;
    }
    
    // For now, just send a basic "not implemented" message and close
    const gchar *not_impl = "502 Command not implemented in local mode\r\n";
    g_output_stream_write_all(client_os, not_impl, strlen(not_impl), NULL, NULL, NULL);
    
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Local SMTP mode not yet implemented");
    return HANDLER_ERROR;
}

static void smtp_cleanup(DeadlightConnection *conn) {
    g_debug("SMTP cleanup for connection %lu", conn->id);
    
    if (!conn->protocol_data) {
        return;
    }
    
    DeadlightSMTPData *smtp_data = (DeadlightSMTPData *)conn->protocol_data;
    
    // Free SMTP-specific data
    if (smtp_data->message_buffer) {
        g_byte_array_unref(smtp_data->message_buffer);
    }
    
    g_free(smtp_data->sender);
    g_free(smtp_data->recipient);
    g_free(smtp_data);
    
    conn->protocol_data = NULL;
}