#include "http.h"
#include "core/ssl_tunnel.h"
#include "core/deadlight.h"
#include "core/utils.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include "protocols/api.h"

static gsize http_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error);
static void http_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error);

// The handler object provided to the core
static const DeadlightProtocolHandler http_protocol_handler = {
    .name = "HTTP",
    .protocol_id = DEADLIGHT_PROTOCOL_HTTP,
    .detect = http_detect,
    .handle = http_handle,
    .cleanup = http_cleanup
};

// Public registration function
void deadlight_register_http_handler(void) {
    deadlight_protocol_register(&http_protocol_handler);
}

// --- Protocol Handler Implementation ---

static gsize http_detect(const guint8 *data, gsize len) {
    // --- Check if it's a WebSocket upgrade first ---
    gchar *request_lower = NULL;
    if (len > 20) { // A reasonable length to check headers
        gchar *request = g_strndup((const gchar*)data, len);
        request_lower = g_ascii_strdown(request, -1);
        
        // If it has WebSocket headers, it's NOT for the plain HTTP handler.
        if (strstr(request_lower, "upgrade: websocket") && strstr(request_lower, "sec-websocket-key:")) {
            g_free(request_lower);
            g_free(request);
            return 0; // Yield to the WebSocket handler
        }
    }

    // Free the temp string if we allocated it
    if (request_lower) g_free(request_lower);

    // --- ORIGINAL LOGIC: If it's not WebSocket, check for standard HTTP ---
    const gchar *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT ", "PATCH ", NULL};
    for (int i = 0; http_methods[i]; i++) {
        gsize method_len = strlen(http_methods[i]);
        if (len >= method_len && memcmp(data, http_methods[i], method_len) == 0) {
            // Return a medium priority, lower than WebSocket's 20.
            return 8; 
        }
    }
    return 0;
}

static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error) {
    if (conn->client_buffer->len > 8 && strncmp((char*)conn->client_buffer->data, "CONNECT ", 8) == 0) {
        conn->protocol = DEADLIGHT_PROTOCOL_CONNECT;
        return handle_connect(conn, error); // handle_connect also returns DeadlightHandlerResult
    }
    return handle_plain_http(conn, error); // handle_plain_http also returns DeadlightHandlerResult
}

static void http_cleanup(DeadlightConnection *conn) {
    (void)conn;
}

static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error) {
    conn->current_request = deadlight_request_new(conn);

    if (!deadlight_request_parse_headers(conn->current_request, (const gchar *)conn->client_buffer->data, conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to parse HTTP request headers");
        return HANDLER_ERROR;
    }

    // Call plugin hook early
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: HTTP request blocked by plugin", conn->id);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // Get Host header
    const gchar *host_header = deadlight_request_get_header(conn->current_request, "host");
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Host header");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 80;
    if (!deadlight_parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        return HANDLER_ERROR; 
    }

    // Check for local requests BEFORE setting target / connecting.
    // Hard rules: loopback + the proxy's own listen address.
    // Soft rule: any hostname the operator added to [proxy] local_hostnames
    // in deadmesh.conf (comma-separated). Personal machine names like
    // emilyssidepc, mulley-mooneye, or Tailscale *.ts.net addresses belong
    // there, not hardcoded in source.
    gboolean is_local = (g_strcmp0(host, "localhost") == 0 ||
                         g_strcmp0(host, "127.0.0.1") == 0 ||
                         g_strcmp0(host, "::1") == 0 ||
                         g_strcmp0(host, "deadlight") == 0 ||   /* compose svc */
                         (conn->context->listen_address &&
                          g_strcmp0(host, conn->context->listen_address) == 0));

    /* Check operator-configured local hostnames (local_hostnames in [proxy]) */
    if (!is_local && conn->context->local_hostnames) {
        for (gchar **lh = conn->context->local_hostnames; *lh && !is_local; lh++) {
            if (g_strcmp0(host, *lh) == 0 || strstr(host, *lh) != NULL)
                is_local = TRUE;
        }
    }

    if (is_local) {
        g_debug("Connection %lu: Detected local request to %s:%d → handling internally", conn->id, host, port);

        // Handle /metrics specifically
        if (g_str_equal(conn->current_request->uri, "/metrics") ||
            g_str_equal(conn->current_request->uri, "/metrics/")) {
            g_free(host);
            return api_handle_prometheus_metrics(conn, error);
        }

        // Handle root path or other local status
        if (g_strcmp0(conn->current_request->uri, "/") == 0) {
            const gchar *status_body = "DEADLIGHT PROXY: ONLINE\n";
            gchar *response = g_strdup_printf(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s", strlen(status_body), status_body);

            GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
            g_output_stream_write_all(out, response, strlen(response), NULL, NULL, NULL);
            g_free(response);
            g_free(host);
            return HANDLER_SUCCESS_CLEANUP_NOW;
        }

        // Default: 404 for other local paths
        const gchar *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(out, not_found, strlen(not_found), NULL, NULL, NULL);
        
        g_debug("Connection %lu: Local resource '%s' not found", conn->id, conn->current_request->uri);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // Only reach here if NOT local → safe to proxy
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    // Proxy loop prevention
    if (conn->target_port == conn->context->listen_port &&
        (g_strcmp0(conn->target_host, conn->context->listen_address) == 0 ||
         g_strcmp0(conn->target_host, "localhost") == 0 ||
         g_strcmp0(conn->target_host, "127.0.0.1") == 0)) {
        g_warning("Connection %lu: Detected proxy loop. Denying.", conn->id);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: Forwarding HTTP to %s:%d", conn->id, conn->target_host, conn->target_port);
    g_free(host);  // Safe now — we've used it

    // Connect upstream
    if (!deadlight_network_connect_upstream(conn, error)) {
        return HANDLER_ERROR;
    }

    // Send initial request data upstream
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    if (!g_output_stream_write_all(upstream_output, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error)) {
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: Initial request sent, starting bidirectional tunnel.", conn->id);
    
    if (deadlight_network_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error) {

    // 1. Get a pointer to the start of the buffer and find the end of the first line.
    const gchar *data = (const gchar *)conn->client_buffer->data;
    const gchar *end_of_line = strstr(data, "\r\n");

    // If we can't even find a newline, the request is malformed.
    if (!end_of_line) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Malformed CONNECT request: missing newline");
        return HANDLER_ERROR;
    }

    // 2. Copy *only* the first line, avoiding a large allocation if the buffer is big.
    gchar *request_line = g_strndup(data, end_of_line - data);
    
    // 3. Split the request line into its three expected parts.
    gchar **req_parts = g_strsplit(request_line, " ", 3);
    g_free(request_line); // The temporary line is no longer needed.

    // 4. Stricter validation: We need exactly 3 parts, and the first must be "CONNECT".
    if (g_strv_length(req_parts) < 3 || g_strcmp0(req_parts[0], "CONNECT") != 0) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid CONNECT request line format");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 443; // Default port for CONNECT
    if (!deadlight_parse_host_port(req_parts[1], &host, &port)) { // req_parts[1] is the "host:port" string
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid host:port in CONNECT request");
        return HANDLER_ERROR;
    }

    // Populate the request object for logging and plugins
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("CONNECT");
    conn->current_request->uri = g_strdup(req_parts[1]); // e.g., "example.com:443"
    conn->current_request->host = g_strdup(host); // e.g., "example.com"

    g_strfreev(req_parts); // We're done with the split parts, so free the array.

    g_debug("Connection %lu: Calling plugin hook for CONNECT to %s", conn->id, host);

    // Call plugin hook for CONNECT requests
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: CONNECT request blocked by plugin", conn->id);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Proxy loop prevention
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || g_strcmp0(host, "localhost") == 0 || g_strcmp0(host, "127.0.0.1") == 0) && port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected proxy loop to %s:%d. Denying request.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: CONNECT request to %s:%d", conn->id, host, port);
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    if (!deadlight_network_connect_upstream(conn, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host); // The host string is no longer needed after this point.

    // Send 200 to client — from here, client will begin TLS handshake
    const gchar *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    GOutputStream *client_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    if (!g_output_stream_write_all(client_output, response, strlen(response),
                                   NULL, NULL, error)) {
        return HANDLER_ERROR;
    }

    if (!conn->context->ssl_intercept_enabled) {
        g_info("Connection %lu: SSL intercept disabled — plain TCP tunnel", conn->id);
        return deadlight_network_tunnel_data(conn, error)
            ? HANDLER_SUCCESS_CLEANUP_NOW
            : HANDLER_ERROR;
    }

    // Attempt interception
    GError *intercept_error = NULL;
    if (deadlight_ssl_intercept_connection(conn, &intercept_error)) {
        // Interception succeeded — tunnel both TLS sides
        g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
        g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);

        GError *tunnel_error = NULL;
        gboolean ok = start_ssl_tunnel_blocking(conn, &tunnel_error);
        if (!ok && tunnel_error) {
            g_warning("Connection %lu: TLS tunnel error: %s",
                      conn->id, tunnel_error->message);
            g_error_free(tunnel_error);
        }
        return ok ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
    }

    // Interception declined or failed — distinguish the two cases
    if (conn->tls_passthrough) {
        // Intentional passthrough: upstream is h2 or otherwise non-interceptable.
        // We already have an upstream TLS connection established.
        // Shuttle raw bytes between the two sides.
        g_info("Connection %lu: TLS passthrough for %s (upstream h2 or non-interceptable)",
               conn->id, conn->target_host);
        g_clear_error(&intercept_error);

        // Use the raw socket connections — bypass TLS objects entirely.
        // The upstream_tls wraps upstream_connection; we need the underlying
        // TCP stream to do a raw passthrough since we're not terminating TLS.
        //
        // At this point the client has already started its own TLS handshake
        // directly to the upstream (from the client's perspective, we're just
        // a dumb pipe). We forward whatever bytes arrive, encrypted and opaque.
        deadlight_network_tunnel_socket_connections(
            conn->client_connection,
            conn->upstream_connection
        );
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // Genuine interception failure
    if (intercept_error) {
        g_warning("Connection %lu: SSL intercept failed for %s: %s",
                  conn->id, conn->target_host, intercept_error->message);
        g_propagate_error(error, intercept_error);
    }
    return HANDLER_ERROR;
}