/**
 * Deadlight Proxy v1.0 - Network ModuleS
 *
 * Socket management, connection handling, and data transfer
 * 
 */
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include "deadlight.h"
#include "utils.h"

// Network manager structure
struct _DeadlightNetworkManager {
    GSocketService *listener;
    GSocketAddress *bind_address;
    guint16 port;
    
    // Connection tracking
    guint64 next_connection_id;
    GMutex connection_mutex;
    
    // Statistics
    guint64 total_accepted;
    guint64 total_rejected;
};

// Forward declarations
static gboolean on_incoming_connection(GSocketService *service,
                                      GSocketConnection *connection,
                                      GObject *source_object,
                                      gpointer user_data);
static void connection_thread_func(gpointer data, gpointer user_data);
GSocketConnection* deadlight_network_connect_tcp(DeadlightContext *context, const gchar *host, guint16 port, GError **error);
void deadlight_network_tunnel_socket_connections(GSocketConnection *conn1, GSocketConnection *conn2);
static void cleanup_connection_internal(DeadlightConnection *conn, gboolean remove_from_table);
static void connection_pool_log_stats(ConnectionPool *pool);

static void _destroy_notify_connection (gpointer data)
{
    DeadlightConnection *conn = (DeadlightConnection*)data;
    cleanup_connection_internal(conn, FALSE);
}

gboolean deadlight_mesh_send_response(DeadlightConnection *conn,
                                       const guint8 *data, gsize len)
{
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->context != NULL, FALSE);
    g_return_val_if_fail(data != NULL && len > 0, FALSE);

    if (!conn->context->mesh_send_fn) {
        g_warning("Connection %lu (mesh): no send hook registered", conn->id);
        return FALSE;
    }

    return conn->context->mesh_send_fn(conn, data, len,
                                        conn->context->mesh_send_user_data);
}

void deadlight_network_cleanup(DeadlightContext *context) {
    if (!context || !context->network) {
        return;
    }
    // Clean up network resources
    if (context->network->listener) {
        g_socket_service_stop(context->network->listener);
        g_object_unref(context->network->listener);
    }
    if (context->network->bind_address) {
        g_object_unref(context->network->bind_address);
    }
    g_mutex_clear(&context->network->connection_mutex);
    g_free(context->network);
    context->network = NULL;
}

/**
 * Initialize network module
 */
gboolean deadlight_network_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
    
    g_info("Initializing network module...");
    
    // Create network manager
    context->network = g_new0(DeadlightNetworkManager, 1);
    g_mutex_init(&context->network->connection_mutex);
    context->network->next_connection_id = 1;
    
    // Initialize connection tracking
    context->connections = g_hash_table_new_full(
        g_int64_hash, 
        g_int64_equal,
        g_free,  // Free the guint64* key
        _destroy_notify_connection // value destroy
    );
    // Create worker thread pool
    gint worker_threads = deadlight_config_get_int(context, "core", "worker_threads", 4);
    context->worker_pool = g_thread_pool_new(connection_thread_func, context,
                                           worker_threads, FALSE, error);
    if (!context->worker_pool) {
        return FALSE;
    }

    // Initialize connection pool
    context->conn_pool = connection_pool_new(
        context->pool_max_per_host,
        context->pool_idle_timeout,
        context->pool_max_total,
        context->pool_eviction_policy,
        context->pool_health_check_interval,
        context->pool_reuse_ssl
    );
    g_info("Network module initialized with %d worker threads and connection pooling",
            worker_threads);
    return TRUE;
}

/**
 * Start network listener
 */
gboolean deadlight_network_start_listener(DeadlightContext *context, gint port, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->network != NULL, FALSE);
    g_return_val_if_fail(port > 0 && port < 65536, FALSE);
    
    // Create socket service
    context->network->listener = g_socket_service_new();
    
    // Get bind address from config
    const gchar *bind_addr = context->listen_address ? context->listen_address : "0.0.0.0";
    
    // Parse address
    GInetAddress *inet_addr = g_inet_address_new_from_string(bind_addr);
    if (!inet_addr) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Invalid bind address: %s", bind_addr);
        return FALSE;
    }
    
    // Create socket address
    GSocketAddress *sock_addr = g_inet_socket_address_new(inet_addr, port);
    g_object_unref(inet_addr);
    
    // Add address to listener
    if (!g_socket_listener_add_address(G_SOCKET_LISTENER(context->network->listener),
                                      sock_addr, G_SOCKET_TYPE_STREAM,
                                      G_SOCKET_PROTOCOL_TCP, NULL,
                                      &context->network->bind_address, error)) {
        g_object_unref(sock_addr);
        return FALSE;
    }
    g_object_unref(sock_addr);
    
    // Store port
    context->network->port = port;
    
    // Connect incoming connection signal
    g_signal_connect(context->network->listener, "incoming",
                    G_CALLBACK(on_incoming_connection), context);
    
    // Start the service
    g_socket_service_start(context->network->listener);
    
    g_info("Network listener started on %s:%d", bind_addr, port);
    return TRUE;
}

/**
 * Stop network listener
 */
void deadlight_network_stop(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    
    g_info("Stopping network module...");
    
    if (context->network) {
        // Mark shutdown state FIRST
        context->shutdown_requested = TRUE;
        
        // Stop accepting new connections
        if (context->network->listener) {
            g_socket_service_stop(context->network->listener);
            g_object_unref(context->network->listener);
            context->network->listener = NULL;
        }
        
        // Shutdown thread pool (wait for workers to finish current tasks)
        if (context->worker_pool) {
            g_thread_pool_free(context->worker_pool, TRUE, TRUE);  // immediate=TRUE, wait=TRUE
            context->worker_pool = NULL;
        }
        
        if (context->connections) {
            GHashTableIter iter;
            gpointer key, value;
            
            g_hash_table_iter_init(&iter, context->connections);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                DeadlightConnection *conn = (DeadlightConnection *)value;
                // Set a flag to interrupt tunneling loops
                conn->should_stop = TRUE;
            }
            g_mutex_lock(&context->network->connection_mutex);
            guint count = g_hash_table_size(context->connections);
            g_info("Closing %u active connections...", count);
            
            // Clear the table - this calls the destructor for each value
            g_hash_table_remove_all(context->connections);
            context->active_connections = 0;
            
            g_mutex_unlock(&context->network->connection_mutex);
            
            // Now destroy the empty table
            g_hash_table_destroy(context->connections);
            context->connections = NULL;
        }
        
        // Log and destroy connection pool
        if (context->conn_pool) {
            connection_pool_log_stats(context->conn_pool);
            connection_pool_free(context->conn_pool);
            context->conn_pool = NULL;
        }
        
        g_mutex_clear(&context->network->connection_mutex);
        g_free(context->network);
        context->network = NULL;
    }
    
    g_info("Network module stopped");
}

/**
 * Free connection object
 */
void deadlight_connection_free(DeadlightConnection *conn) {
    if (!conn) return;
    // Don't remove from table - this is called for rejected connections
    // that were never added to the table
    cleanup_connection_internal(conn, FALSE);
}

/**
 * Handle incoming connection
 */
static gboolean on_incoming_connection(GSocketService *service,
                                      GSocketConnection *connection,
                                      GObject *source_object,
                                      gpointer user_data) {
    (void)service;
    (void)source_object;

    DeadlightContext *context = (DeadlightContext *)user_data;

    if (context->shutdown_requested) {
        return FALSE;
    }

    g_mutex_lock(&context->network->connection_mutex);
    guint active_count = g_hash_table_size(context->connections);
    g_mutex_unlock(&context->network->connection_mutex);

    if (active_count >= context->max_connections) {
        g_warning("Connection limit reached (%d), rejecting new connection",
                  context->max_connections);
        context->network->total_rejected++;
        return FALSE;
    }

    g_object_ref(connection);
    context->network->total_accepted++;

    GSocketAddress *remote_addr = g_socket_connection_get_remote_address(connection, NULL);
    gchar *client_str = NULL;
    if (remote_addr) {
        if (G_IS_INET_SOCKET_ADDRESS(remote_addr)) {
            GInetSocketAddress *inet_addr = G_INET_SOCKET_ADDRESS(remote_addr);
            GInetAddress *addr = g_inet_socket_address_get_address(inet_addr);
            guint16 port = g_inet_socket_address_get_port(inet_addr);
            gchar *addr_str = g_inet_address_to_string(addr);
            client_str = g_strdup_printf("%s:%d", addr_str, port);
            g_free(addr_str);
        }
        g_object_unref(remote_addr);
    }

    g_info("New connection from %s", client_str ? client_str : "unknown");

    DeadlightConnection *conn = deadlight_connection_new(context, connection, client_str);

    detect_protocol:  

    // Call plugin hook for new connection
    if (!deadlight_plugins_call_on_connection_accept(context, conn)) {
        g_info("Connection %lu rejected by plugin", conn->id);
        deadlight_connection_free(conn);
        return FALSE;
    }

    // Add to connection table
    g_mutex_lock(&context->network->connection_mutex);
    guint64 *id_ptr = g_new(guint64, 1);
    *id_ptr = conn->id;
    g_hash_table_insert(context->connections, id_ptr, conn);
    context->active_connections++;
    context->total_connections++;
    g_mutex_unlock(&context->network->connection_mutex);

    // Queue for processing
    GError *error = NULL;
    if (!g_thread_pool_push(context->worker_pool, conn, &error)) {
        g_error("Failed to queue connection: %s", error->message);
        g_error_free(error);

        g_mutex_lock(&context->network->connection_mutex);
        g_hash_table_remove(context->connections, &conn->id);
        context->active_connections--;
        g_mutex_unlock(&context->network->connection_mutex);

        return FALSE;
    }

    return TRUE;
}

/**
 * Create new connection object
 */
DeadlightConnection *deadlight_connection_new(DeadlightContext *context,
                                            GSocketConnection *client_connection,
                                             gchar *client_address_str) {
    DeadlightConnection *conn = g_new0(DeadlightConnection, 1);

    
    // Set ID
    g_mutex_lock(&context->network->connection_mutex);
    conn->id = context->network->next_connection_id++;
    g_mutex_unlock(&context->network->connection_mutex);
    
    // Initialize connection
    conn->cleaned = FALSE;
    conn->context = context;
    conn->client_connection = client_connection ? g_object_ref(client_connection) : NULL;
    conn->state = DEADLIGHT_STATE_INIT;
    conn->client_address = client_address_str;
    conn->protocol = DEADLIGHT_PROTOCOL_UNKNOWN;
    
    
    // Create buffers
    conn->client_buffer = g_byte_array_new();
    conn->upstream_buffer = g_byte_array_new();
    
    // Plugin data storage
    conn->plugin_data = g_hash_table_new_full(g_str_hash, g_str_equal,
                                             g_free, g_free);
    
    // Start timer
    conn->connection_timer = g_timer_new();
    
    return conn;
}

/**
 * Worker thread function
 * 
 */
static void connection_thread_func(gpointer data, gpointer user_data) {
    DeadlightConnection *conn = (DeadlightConnection *)data;
    DeadlightContext *context = (DeadlightContext *)user_data;
    GError *error = NULL;

    g_debug("Worker thread processing connection %lu", conn->id);

    /* ── Mesh-origin fast path ───────────────────────────────────────
     * Mesh connections have no underlying socket — data arrives via
     * the assembly buffer injected by the Meshtastic plugin.
     * Skip all GSocket machinery and go straight to protocol detection.
     * ────────────────────────────────────────────────────────────── */
    if (conn->mesh_source_node != 0) {
        conn->state = DEADLIGHT_STATE_DETECTING;

        /* Wait for the plugin to inject data if the buffer is still empty.
         * The plugin injects synchronously before queuing, so in practice
         * this loop should not spin more than once or twice. */
        gint waited_ms = 0;
        while (conn->client_buffer->len == 0 && waited_ms < 5000) {
            g_usleep(10 * 1000);  /* 10ms */
            waited_ms += 10;
        }

        if (conn->client_buffer->len == 0) {
            g_warning("Connection %lu (mesh): no data after 5s, dropping", conn->id);
            goto cleanup;
        }

        const DeadlightProtocolHandler *handler = deadlight_protocol_detect_and_assign(
            conn, conn->client_buffer->data, conn->client_buffer->len);

        if (!handler) {
            g_warning("Connection %lu (mesh): could not detect protocol", conn->id);
            goto cleanup;
        }

        g_info("Connection %lu (mesh): detected protocol '%s'", conn->id, handler->name);
        conn->state = DEADLIGHT_STATE_CONNECTING;

        if (!deadlight_plugins_call_on_protocol_detect(context, conn)) {
            g_info("Connection %lu (mesh): blocked by plugin after protocol detection", conn->id);
            goto cleanup;
        }

        gchar *config_key = g_strdup_printf("%s_enabled", g_ascii_strdown(handler->name, -1));
        gboolean enabled = deadlight_config_get_bool(context, "protocols", config_key, TRUE);
        g_free(config_key);

        if (!enabled) {
            g_warning("Connection %lu (mesh): protocol '%s' disabled", conn->id, handler->name);
            goto cleanup;
        }

        DeadlightHandlerResult result = handler->handle(conn, &error);
        switch (result) {
            case HANDLER_SUCCESS_CLEANUP_NOW:
                g_info("Connection %lu (mesh): handler completed", conn->id);
                cleanup_connection_internal(conn, TRUE);
                return;
            case HANDLER_SUCCESS_ASYNC:
                g_debug("Connection %lu (mesh): async handler started", conn->id);
                return;
            case HANDLER_ERROR:
            default:
                g_warning("Connection %lu (mesh): handler failed: %s",
                          conn->id, error ? error->message : "unknown");
                g_clear_error(&error);
                goto cleanup;
        }
    }

    /* ── Normal socket path (unchanged below) ───────────────────── */
    detect_protocol:
    conn->state = DEADLIGHT_STATE_DETECTING;

    GSocket *socket = g_socket_connection_get_socket(conn->client_connection);
    guint8 peek_buffer[2048];
    gssize bytes_peeked = 0;
    gint timeout = deadlight_config_get_int(context, "protocols", "protocol_detection_timeout", 5);
    
    // Use blocking wait instead of busy-loop polling
    // This allows the CPU to enter deep sleep states (C3/C6) on edge devices
    g_socket_set_blocking(socket, TRUE);
    g_socket_set_timeout(socket, timeout);
    
    // Wait for data to be available (blocks efficiently)
    if (!g_socket_condition_wait(socket, G_IO_IN, NULL, &error)) {
        if (error) {
            g_warning("Connection %lu: Socket wait error: %s", conn->id, error->message);
            g_clear_error(&error);
        } else {
            g_warning("Connection %lu: Protocol detection timeout.", conn->id);
        }
        goto cleanup;
    }
    
    // Now read the data (will not block long since we know it's available)
    bytes_peeked = g_socket_receive(socket, (gchar *)peek_buffer, sizeof(peek_buffer), NULL, &error);
    
    if (bytes_peeked <= 0) {
        if (bytes_peeked == 0) {
            g_info("Connection %lu: Client closed before sending data.", conn->id);
        } else if (error) {
            g_warning("Connection %lu: Read error: %s", conn->id, error->message);
        }
        g_clear_error(&error);
        goto cleanup;
    }
    
    g_byte_array_append(conn->client_buffer, peek_buffer, bytes_peeked);

    const DeadlightProtocolHandler *handler = deadlight_protocol_detect_and_assign(conn, conn->client_buffer->data, conn->client_buffer->len);

    if (!handler) {
        g_warning("Connection %lu: Could not detect a known protocol.", conn->id);
        goto cleanup;
    }

    g_info("Connection %lu: Detected protocol '%s'", conn->id, handler->name);
    conn->state = DEADLIGHT_STATE_CONNECTING;

    // Call plugin hook for protocol detection
    if (!deadlight_plugins_call_on_protocol_detect(context, conn)) {
        g_info("Connection %lu blocked by plugin after protocol detection", conn->id);
        goto cleanup;
    }

    gchar *config_key = g_strdup_printf("%s_enabled", g_ascii_strdown(handler->name, -1));
    gboolean enabled = deadlight_config_get_bool(context, "protocols", config_key, TRUE);
    g_free(config_key);

    if (!enabled) {
        g_warning("Connection %lu: Protocol '%s' is disabled in configuration.", conn->id, handler->name);
        goto cleanup;
    }

    // ==========================================================
    // ===== PROTOCOL HANDLING LOGIC ========
    // ==========================================================

    DeadlightHandlerResult handler_result = handler->handle(conn, &error);

    switch (handler_result) {
        case HANDLER_SUCCESS_CLEANUP_NOW:
            g_info("Connection %lu: Synchronous handler for '%s' completed.", 
                conn->id, deadlight_protocol_to_string(conn->protocol));
            cleanup_connection_internal(conn, TRUE);
            return;
            
        case HANDLER_SUCCESS_ASYNC:
            g_debug("Connection %lu: Asynchronous handler for '%s' started; worker thread exiting.", 
                    conn->id, deadlight_protocol_to_string(conn->protocol));
            // Handler now owns the connection lifecycle
            break;
            
        case HANDLER_ERROR:
        {
            const gchar *msg = error ? error->message : "Unknown error";
            g_warning("Connection %lu: Handler for '%s' failed: %s",
                      conn->id, handler->name, msg);
            g_clear_error(&error);
            goto cleanup;
        }

        default:
            g_warning("Connection %lu: Unexpected handler result %d", conn->id, handler_result);
            goto cleanup;
    }
    
    return;  // Exit cleanly for ASYNC case

cleanup:
    if (conn->handler && conn->handler->cleanup) {
        conn->handler->cleanup(conn);
    }
    cleanup_connection_internal(conn, TRUE);
}

/**
 * Connect to upstream server (with pool support)
 */
gboolean deadlight_network_connect_upstream(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->target_host != NULL, FALSE);
    
    // For CONNECT tunnels to port 443, try to reuse a TLS connection first
    // since that's what gets pooled after tunnel close
    GIOStream *pooled = NULL;
    
    if (conn->protocol == DEADLIGHT_PROTOCOL_CONNECT && conn->target_port == 443) {
        pooled = connection_pool_get(
            conn->context->conn_pool,
            conn->target_host,
            conn->target_port,
            CONN_TYPE_CLIENT_TLS
        );
        
        if (pooled) {
            conn->upstream_tls = G_TLS_CONNECTION(g_object_ref(pooled));
            
            GIOStream *base = NULL;
            g_object_get(conn->upstream_tls, "base-io-stream", &base, NULL);
            if (G_IS_SOCKET_CONNECTION(base)) {
                conn->upstream_connection = G_SOCKET_CONNECTION(g_object_ref(base));
            }
            
            conn->ssl_established = TRUE;
            
            g_info("Connection %lu: Pool HIT - reusing TLS connection to %s:%d",
                   conn->id, conn->target_host, conn->target_port);
            return TRUE;
        }
    }
    
    // Original logic: try desired type
    ConnectionType desired_type = conn->will_use_ssl ? CONN_TYPE_CLIENT_TLS : CONN_TYPE_PLAIN;
    
    pooled = connection_pool_get(
        conn->context->conn_pool,
        conn->target_host,
        conn->target_port,
        desired_type
    );
    
    if (pooled) {
        if (conn->will_use_ssl) {
            conn->upstream_tls = G_TLS_CONNECTION(g_object_ref(pooled));
            
            GIOStream *base = NULL;
            g_object_get(conn->upstream_tls, "base-io-stream", &base, NULL);
            if (G_IS_SOCKET_CONNECTION(base)) {
                conn->upstream_connection = G_SOCKET_CONNECTION(g_object_ref(base));
            }
            
            conn->ssl_established = TRUE;
            
            g_info("Connection %lu: Reusing TLS connection to %s:%d from pool",
                   conn->id, conn->target_host, conn->target_port);
        } else {
            conn->upstream_connection = G_SOCKET_CONNECTION(g_object_ref(pooled));
            
            g_info("Connection %lu: Reusing plain connection to %s:%d from pool",
                   conn->id, conn->target_host, conn->target_port);
        }
        
        return TRUE;
    }
    
    // Pool miss - create new connection
    g_debug("Connection %lu: Pool MISS - creating new connection to %s:%d",
            conn->id, conn->target_host, conn->target_port);

    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_timeout(client, 30);
    
    conn->upstream_connection = g_socket_client_connect_to_host(
        client,
        conn->target_host,
        conn->target_port,
        NULL,
        error
    );
    g_object_unref(client);

    if (!conn->upstream_connection) {
        g_warning("Connection %lu: Failed to connect to %s:%d: %s",
                conn->id, conn->target_host, conn->target_port,
                error && *error ? (*error)->message : "unknown error");
        return FALSE;
    }

    if (conn->will_use_ssl) {
        GSocketConnectable *identity = g_network_address_new(conn->target_host, conn->target_port);
        
        GIOStream *tls_stream = g_tls_client_connection_new(
            G_IO_STREAM(conn->upstream_connection),
            identity,
            error
        );
        g_object_unref(identity);
        
        if (!tls_stream) {
            g_warning("Connection %lu: Failed to create TLS connection: %s",
                    conn->id, error && *error ? (*error)->message : "unknown");
            g_clear_object(&conn->upstream_connection);
            return FALSE;
        }
        
        conn->upstream_tls = G_TLS_CONNECTION(tls_stream);
        
        // Perform the handshake synchronously
        if (!g_tls_connection_handshake(conn->upstream_tls, NULL, error)) {
            g_warning("Connection %lu: TLS handshake failed: %s",
                    conn->id, error && *error ? (*error)->message : "unknown");
            g_clear_object(&conn->upstream_tls);
            g_clear_object(&conn->upstream_connection);
            return FALSE;
        }
        
        conn->ssl_established = TRUE;
        
        // Register as TLS connection
        connection_pool_register(
            conn->context->conn_pool,
            G_IO_STREAM(conn->upstream_tls),
            conn->target_host,
            conn->target_port,
            CONN_TYPE_CLIENT_TLS
        );
        
        g_info("Connection %lu: TLS established to %s:%d",
            conn->id, conn->target_host, conn->target_port);
    } else {
        // Register plain connection
        connection_pool_register(
            conn->context->conn_pool,
            G_IO_STREAM(conn->upstream_connection),
            conn->target_host,
            conn->target_port,
            CONN_TYPE_PLAIN
        );
        
        g_info("Connection %lu: Connected to %s:%d (plain)",
            conn->id, conn->target_host, conn->target_port);
    }

    return TRUE;
}

/**
 * Release connection back to pool (called instead of closing)
 */
void deadlight_network_release_to_pool(DeadlightConnection *conn, const gchar *reason) {
    if (!conn || !conn->context || !conn->context->conn_pool) return;
    
    // Determine what we're releasing
    GIOStream *stream_to_release = NULL;
    ConnectionType type = CONN_TYPE_PLAIN;
    gboolean should_pool = TRUE;
    
    if (conn->upstream_tls) {
        stream_to_release = G_IO_STREAM(conn->upstream_tls);
        type = CONN_TYPE_CLIENT_TLS;
    } else if (conn->upstream_connection) {
        stream_to_release = G_IO_STREAM(conn->upstream_connection);
        type = CONN_TYPE_PLAIN;
    }
    
    if (!stream_to_release) {
        return;  // Nothing to release
    }
    
    // Check if we should pool this connection
    if (conn->state != DEADLIGHT_STATE_CONNECTED && conn->state != DEADLIGHT_STATE_TUNNELING) {
        should_pool = FALSE;
        g_debug("Connection %lu: Not pooling: %s:%d (reason=bad state)",
                conn->id, conn->target_host, conn->target_port);
    }
    
    // For CONNECT tunnels, we can't reuse because the tunnel is bidirectional
    if (conn->protocol == DEADLIGHT_PROTOCOL_HTTP && conn->is_connect_tunnel) {
        should_pool = FALSE;
        g_debug("Connection %lu: Not pooling: %s:%d (reason=one-way protocol)",
                conn->id, conn->target_host, conn->target_port);
    }
    
    if (should_pool) {
        connection_pool_release(
            conn->context->conn_pool,
            stream_to_release,
            conn->target_host,
            conn->target_port,
            type
        );
        
        g_debug("Connection %lu: Released %s connection to %s:%d to pool",
                conn->id,
                type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                conn->target_host,
                conn->target_port);
        
        // Don't unref - pool now owns it
        conn->upstream_tls = NULL;
        conn->upstream_connection = NULL;
    } else {
        g_debug("Connection %lu: Closing %s connection to %s:%d (not pooling: %s)",
                conn->id,
                type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                conn->target_host,
                conn->target_port,
                reason ? reason : "unknown");
    }
} 

/**
 * Internal cleanup with proper NULL checks and safe object handling
 */
static void cleanup_connection_internal(DeadlightConnection *conn, gboolean remove_from_table) {
    if (!conn) return;

    /* Guard against re-entry. The hash table destructor (_destroy_notify_connection)
     * calls this with remove_from_table=FALSE. When we call g_hash_table_remove()
     * below it fires that destructor immediately for the same conn — re-entering
     * here before we've finished. cleaned must be checked, not just set.  */
    if (conn->cleaned) return;
    conn->cleaned = TRUE;

    g_debug("Cleaning up connection %lu (state=%d, remove_from_table=%d)",
            conn->id, conn->state, remove_from_table);

    // Notify plugins FIRST (while connection is still valid)
    if (conn->context) {
        deadlight_plugins_call_on_connection_close(conn->context, conn);
    }
    
    // === POOL RELEASE: Return connection if appropriate ===
    if (conn->upstream_connection && conn->target_host && conn->context && conn->context->conn_pool) {
        gboolean use_ssl = conn->upstream_tls != NULL;
        gboolean should_pool = FALSE;
        const gchar *reason = "unknown";

        /* Never pool upstream connections from mesh-origin requests —
        * mesh round-trips take 30s+, far beyond any server keep-alive
        * window. The pooled connection will always be stale by the time
        * the next mesh request arrives.                                */
        if (conn->mesh_source_node != 0) {
            reason = "mesh origin";
            goto skip_pool;
        }
        
        // Check 1: Socket health
        GSocket *socket = g_socket_connection_get_socket(conn->upstream_connection);
        gboolean socket_ok = FALSE;
        
        if (socket && G_IS_SOCKET(socket)) {
            socket_ok = (g_socket_is_connected(socket) && 
                        g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) == 0);
        }
        
        if (!socket_ok) {
            reason = "socket dead";
        }
        // Check 2: Connection state
        else if (conn->state != DEADLIGHT_STATE_CLOSING &&
                 conn->state != DEADLIGHT_STATE_CONNECTED &&
                 conn->state != DEADLIGHT_STATE_TUNNELING) {
            reason = "bad state";
        }
        // Check 3: Protocol-specific rules
        else {
            switch (conn->protocol) {
                case DEADLIGHT_PROTOCOL_HTTP:
                {
                    gboolean keep_alive = TRUE;
                    if (conn->current_request) {
                        const gchar *conn_hdr = g_hash_table_lookup(
                            conn->current_request->headers, "Connection");
                        if (conn_hdr && g_ascii_strcasecmp(conn_hdr, "close") == 0) {
                            keep_alive = FALSE;
                        }
                    }
                    
                    if (keep_alive) {
                        should_pool = TRUE;
                        reason = "HTTP keep-alive";
                    } else {
                        reason = "HTTP Connection: close";
                    }
                    break;
                }
                
                case DEADLIGHT_PROTOCOL_CONNECT:
                case DEADLIGHT_PROTOCOL_HTTPS:
                {
                    // CONNECT tunnels: the upstream TLS connection is reusable
                    // if the tunnel closed cleanly and the socket is healthy.
                    // The socket health check already passed above.
                    if (use_ssl && conn->state == DEADLIGHT_STATE_CLOSING) {
                        should_pool = TRUE;
                        reason = "CONNECT tunnel closed cleanly";
                    } else if (conn->state == DEADLIGHT_STATE_CONNECTED && use_ssl) {
                        should_pool = TRUE;
                        reason = "HTTPS clean";
                    } else {
                        reason = "HTTPS/CONNECT incomplete";
                    }
                    break;
                }
                
                case DEADLIGHT_PROTOCOL_IMAP:
                case DEADLIGHT_PROTOCOL_IMAPS:
                    if (conn->authenticated && conn->state == DEADLIGHT_STATE_CONNECTED) {
                        should_pool = TRUE;
                        reason = "IMAP auth OK";
                    } else {
                        reason = "IMAP not auth";
                    }
                    break;
                
                case DEADLIGHT_PROTOCOL_SMTP:
                    if (conn->state == DEADLIGHT_STATE_CONNECTED) {
                        should_pool = TRUE;
                        reason = "SMTP OK";
                    } else {
                        reason = "SMTP incomplete";
                    }
                    break;
                
                // Truly non-reusable protocols
                case DEADLIGHT_PROTOCOL_SOCKS:
                case DEADLIGHT_PROTOCOL_SOCKS4:
                case DEADLIGHT_PROTOCOL_SOCKS5:
                case DEADLIGHT_PROTOCOL_WEBSOCKET:
                    reason = "one-way protocol";
                    break;
                
                case DEADLIGHT_PROTOCOL_FTP:
                    reason = "FTP complex";
                    break;
                
                default:
                    reason = "unknown protocol";
                    break;
            }
        }
        skip_pool:
        if (should_pool) {
            g_info("Connection %lu: Returning to pool: %s:%d (SSL=%d, reason=%s)",
                conn->id, conn->target_host, conn->target_port, use_ssl, reason);
            
            GIOStream *stream_to_pool = use_ssl 
                ? G_IO_STREAM(conn->upstream_tls) 
                : G_IO_STREAM(conn->upstream_connection);
            
            connection_pool_release(
                conn->context->conn_pool,
                stream_to_pool,
                conn->target_host,
                conn->target_port,
                use_ssl ? CONN_TYPE_CLIENT_TLS : CONN_TYPE_PLAIN
            );
            
            // Pool now owns these — clear both so cleanup doesn't close them
            conn->upstream_tls = NULL;
            conn->upstream_connection = NULL;
        } else {
            g_debug("Connection %lu: Not pooling: %s:%d (SSL=%d, reason=%s)",
                conn->id, conn->target_host, conn->target_port, use_ssl, reason);
        }
    }
    
    // === CLOSE TLS CONNECTIONS (before underlying sockets) ===
    if (conn->client_tls) {
        if (G_IS_IO_STREAM(conn->client_tls)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->client_tls), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Client TLS close error: %s", 
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->client_tls)) {
            g_object_unref(conn->client_tls);
        }
        conn->client_tls = NULL;
    }
    
    if (conn->upstream_tls) {
        if (G_IS_IO_STREAM(conn->upstream_tls)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->upstream_tls), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Upstream TLS close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->upstream_tls)) {
            g_object_unref(conn->upstream_tls);
        }
        conn->upstream_tls = NULL;
    }

    // === CLOSE UNDERLYING SOCKET CONNECTIONS ===
    if (conn->client_connection) {
        if (G_IS_IO_STREAM(conn->client_connection)) {
            GError *close_error = NULL;

            if (!g_io_stream_close(G_IO_STREAM(conn->client_connection), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Client socket close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->client_connection)) {
            g_object_unref(conn->client_connection);
        }
        conn->client_connection = NULL;
    }
    
    if (conn->upstream_connection) {
        // Only close if not pooled (would be NULL if pooled)
        if (G_IS_IO_STREAM(conn->upstream_connection)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->upstream_connection), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Upstream socket close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->upstream_connection)) {
            g_object_unref(conn->upstream_connection);
        }
        conn->upstream_connection = NULL;
    }
    
    // === FREE OTHER RESOURCES ===
    if (conn->upstream_peer_cert && G_IS_OBJECT(conn->upstream_peer_cert)) {
        g_object_unref(conn->upstream_peer_cert);
        conn->upstream_peer_cert = NULL;
    }
    
    if (conn->client_buffer) {
        g_byte_array_free(conn->client_buffer, TRUE);
        conn->client_buffer = NULL;
    }
    
    if (conn->upstream_buffer) {
        g_byte_array_free(conn->upstream_buffer, TRUE);
        conn->upstream_buffer = NULL;
    }

    if (conn->mesh_source_node != 0) {
        g_debug("Cleaning mesh-origin conn %lu (node %08x session %08x)",
                conn->id, conn->mesh_source_node, conn->mesh_session_id);
        // Optional: remove session if needed
    }
    
    g_free(conn->client_address);
    conn->client_address = NULL;
    
    g_free(conn->target_host);
    conn->target_host = NULL;
    
    g_free(conn->username);
    conn->username = NULL;
    
    g_free(conn->session_token);
    conn->session_token = NULL;
    
    if (conn->plugin_data) {
        g_hash_table_destroy(conn->plugin_data);
        conn->plugin_data = NULL;
    }
    
    if (conn->current_request) {
        deadlight_request_free(conn->current_request);
        conn->current_request = NULL;
    }
    
    if (conn->current_response) {
        deadlight_response_free(conn->current_response);
        conn->current_response = NULL;
    }
    
    if (conn->connection_timer) {
        g_timer_destroy(conn->connection_timer);
        conn->connection_timer = NULL;
    }
    
    // === UPDATE STATS AND REMOVE FROM TABLE ===
    if (conn->context) {
        // Update stats
        g_mutex_lock(&conn->context->stats_mutex);
        conn->context->bytes_transferred += 
            conn->bytes_client_to_upstream + conn->bytes_upstream_to_client;
        g_mutex_unlock(&conn->context->stats_mutex);
        
        // Remove from connection table if requested
        if (remove_from_table && conn->context->network && conn->context->connections) {
            g_mutex_lock(&conn->context->network->connection_mutex);
            
            // Check if connection is actually in the table
            if (g_hash_table_contains(conn->context->connections, &conn->id)) {
                // Remove it - this will call the destructor
                g_hash_table_remove(conn->context->connections, &conn->id);
                conn->context->active_connections--;
                g_mutex_unlock(&conn->context->network->connection_mutex);
                
                // Return here since destructor freed the connection
                return;
            }
            
            g_mutex_unlock(&conn->context->network->connection_mutex);
        }
    }
    
    // Only free if we didn't remove from table (and thus destructor wasn't called)
    g_free(conn);
}

GSocketConnection* deadlight_network_connect_tcp(DeadlightContext *context, const gchar *host, guint16 port, GError **error) {
    (void)context;

    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = g_socket_client_connect_to_host(client, host, port, NULL, error);
    g_object_unref(client);

    return connection;
}

void deadlight_network_tunnel_socket_connections(GSocketConnection *conn1, GSocketConnection *conn2) {
    GInputStream *in1 = g_io_stream_get_input_stream(G_IO_STREAM(conn1));
    GOutputStream *out1 = g_io_stream_get_output_stream(G_IO_STREAM(conn1));
    GInputStream *in2 = g_io_stream_get_input_stream(G_IO_STREAM(conn2));
    GOutputStream *out2 = g_io_stream_get_output_stream(G_IO_STREAM(conn2));

    guchar buffer[16384];
    gboolean running = TRUE;
    
    // Create pollable sources if possible (for TLS support)
    GSource *source1 = NULL;
    GSource *source2 = NULL;
    
    if (G_IS_POLLABLE_INPUT_STREAM(in1) && g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(in1))) {
        source1 = g_pollable_input_stream_create_source(G_POLLABLE_INPUT_STREAM(in1), NULL);
    }
    if (G_IS_POLLABLE_INPUT_STREAM(in2) && g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(in2))) {
        source2 = g_pollable_input_stream_create_source(G_POLLABLE_INPUT_STREAM(in2), NULL);
    }

    while (running) {
        GError *error = NULL;
        
        // Conn1 -> Conn2
        if (G_IS_POLLABLE_INPUT_STREAM(in1) && 
            g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(in1))) {
            
            if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(in1))) {
                gssize bytes = g_pollable_input_stream_read_nonblocking(
                    G_POLLABLE_INPUT_STREAM(in1), buffer, sizeof(buffer), NULL, &error);
                if (bytes > 0) {
                    if (!g_output_stream_write_all(out2, buffer, bytes, NULL, NULL, NULL)) {
                        running = FALSE;
                    }
                } else if (bytes == 0) {
                    running = FALSE;
                } else if (error && !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    running = FALSE;
                }
                g_clear_error(&error);
            }
        } else {
            // Fallback for non-pollable streams
            gssize bytes = g_input_stream_read(in1, buffer, sizeof(buffer), NULL, &error);
            if (bytes > 0) {
                if (!g_output_stream_write_all(out2, buffer, bytes, NULL, NULL, NULL)) {
                    running = FALSE;
                }
            } else if (bytes <= 0) {
                running = FALSE;
            }
            g_clear_error(&error);
        }

        // Conn2 -> Conn1
        if (running && G_IS_POLLABLE_INPUT_STREAM(in2) && 
            g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(in2))) {
            
            if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(in2))) {
                gssize bytes = g_pollable_input_stream_read_nonblocking(
                    G_POLLABLE_INPUT_STREAM(in2), buffer, sizeof(buffer), NULL, &error);
                if (bytes > 0) {
                    if (!g_output_stream_write_all(out1, buffer, bytes, NULL, NULL, NULL)) {
                        running = FALSE;
                    }
                } else if (bytes == 0) {
                    running = FALSE;
                } else if (error && !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    running = FALSE;
                }
                g_clear_error(&error);
            }
        } else {
            // Fallback for non-pollable streams
            gssize bytes = g_input_stream_read(in2, buffer, sizeof(buffer), NULL, &error);
            if (bytes > 0) {
                if (!g_output_stream_write_all(out1, buffer, bytes, NULL, NULL, NULL)) {
                    running = FALSE;
                }
            } else if (bytes <= 0) {
                running = FALSE;
            }
            g_clear_error(&error);
        }
        
        if (G_IS_POLLABLE_INPUT_STREAM(in1)) {
            g_pollable_input_stream_create_source(G_POLLABLE_INPUT_STREAM(in1), NULL);
            // Use main loop integration instead of busy waiting
        }
    }
    
    // Cleanup sources
    if (source1) {
        g_source_destroy(source1);
        g_source_unref(source1);
    }
    if (source2) {
        g_source_destroy(source2);
        g_source_unref(source2);
    }
}

gboolean deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_connection != NULL, FALSE);

    (void)error;

    /* ── Mesh-origin path ────────────────────────────────────────────────
     * No client socket exists — drain the upstream response into a buffer
     * then fragment and send back over LoRa to the originating node.
     * ─────────────────────────────────────────────────────────────────── */
    if (conn->mesh_source_node != 0) {
        GInputStream *upstream_is;
        if (conn->upstream_tls) {
            upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
        } else {
            upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
        }

        GByteArray *response_buf = g_byte_array_new();
        guint8 buf[16384];
        GError *read_err = NULL;

        while (TRUE) {
            gssize n = g_input_stream_read(upstream_is, buf, sizeof(buf), NULL, &read_err);
            if (n > 0) {
                g_byte_array_append(response_buf, buf, (guint)n);
            } else if (n == 0) {
                break; /* EOF — upstream done */
            } else {
                if (read_err &&
                    !g_error_matches(read_err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_warning("Connection %lu (mesh): upstream read error: %s",
                              conn->id, read_err->message);
                    g_clear_error(&read_err);
                    break;
                }
                g_clear_error(&read_err);
                g_usleep(1000);
            }
        }

        g_info("Connection %lu (mesh): %u bytes from upstream → fragmenting for node %08x",
               conn->id, response_buf->len, conn->mesh_source_node);

        gboolean ok = FALSE;
        if (response_buf->len > 0) {
            ok = deadlight_mesh_send_response(conn,
                                              response_buf->data,
                                              response_buf->len);
        } else {
            g_warning("Connection %lu (mesh): upstream returned empty response", conn->id);
        }

        conn->bytes_upstream_to_client += response_buf->len;
        g_byte_array_free(response_buf, TRUE);
        conn->state = DEADLIGHT_STATE_CLOSING;

        g_info("Connection %lu (mesh): tunnel closed (upstream->mesh: %s)",
               conn->id,
               deadlight_format_bytes(conn->bytes_upstream_to_client));
        return ok;
    }

    /* ── Normal socket path ──────────────────────────────────────────────
     * Original bidirectional tunnel — unchanged.
     * ─────────────────────────────────────────────────────────────────── */
    g_return_val_if_fail(conn->client_connection != NULL, FALSE);

    // Client streams
    GInputStream *client_is;
    GOutputStream *client_os;
    if (conn->client_tls) {
        g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
        client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
        client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    } else {
        g_info("Connection %lu: Tunneling with plain-text client.", conn->id);
        client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
        client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    }

    // Upstream streams
    GInputStream *upstream_is;
    GOutputStream *upstream_os;
    if (conn->upstream_tls) {
        g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);
        upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
        upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));
    } else {
        g_info("Connection %lu: Tunneling with plain-text upstream.", conn->id);
        upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
        upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    }

    guint8 buffer[16384];
    gboolean running = TRUE;

    while (running) {
        gboolean activity = FALSE;
        GError *local_error = NULL;

        // Client to upstream
        if (G_IS_POLLABLE_INPUT_STREAM(client_is) &&
            g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(client_is))) {

            if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(client_is))) {
                gssize bytes_read = g_pollable_input_stream_read_nonblocking(
                    G_POLLABLE_INPUT_STREAM(client_is), buffer, sizeof(buffer), NULL, &local_error);
                if (bytes_read > 0) {
                    if (!g_output_stream_write_all(upstream_os, buffer, bytes_read, NULL, NULL, &local_error)) {
                        g_warning("Connection %lu: Failed to write to upstream: %s",
                                  conn->id, local_error ? local_error->message : "unknown");
                        running = FALSE;
                    } else {
                        conn->bytes_client_to_upstream += bytes_read;
                        activity = TRUE;
                    }
                } else if (bytes_read == 0) {
                    running = FALSE;
                } else if (local_error && !g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        } else {
            gssize bytes_read = g_input_stream_read(client_is, buffer, sizeof(buffer), NULL, &local_error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(upstream_os, buffer, bytes_read, NULL, NULL, &local_error)) {
                    g_warning("Connection %lu: Failed to write to upstream: %s",
                              conn->id, local_error ? local_error->message : "unknown");
                    running = FALSE;
                } else {
                    conn->bytes_client_to_upstream += bytes_read;
                    activity = TRUE;
                }
            } else if (bytes_read <= 0) {
                running = FALSE;
            }
            g_clear_error(&local_error);
        }

        // Upstream to client
        if (running && G_IS_POLLABLE_INPUT_STREAM(upstream_is) &&
            g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(upstream_is))) {

            if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(upstream_is))) {
                gssize bytes_read = g_pollable_input_stream_read_nonblocking(
                    G_POLLABLE_INPUT_STREAM(upstream_is), buffer, sizeof(buffer), NULL, &local_error);
                if (bytes_read > 0) {
                    if (!g_output_stream_write_all(client_os, buffer, bytes_read, NULL, NULL, &local_error)) {
                        g_warning("Connection %lu: Failed to write to client: %s",
                                  conn->id, local_error ? local_error->message : "unknown");
                        running = FALSE;
                    } else {
                        conn->bytes_upstream_to_client += bytes_read;
                        activity = TRUE;
                    }
                } else if (bytes_read == 0) {
                    running = FALSE;
                } else if (local_error && !g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        } else {
            gssize bytes_read = g_input_stream_read(upstream_is, buffer, sizeof(buffer), NULL, &local_error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(client_os, buffer, bytes_read, NULL, NULL, &local_error)) {
                    g_warning("Connection %lu: Failed to write to client: %s",
                              conn->id, local_error ? local_error->message : "unknown");
                    running = FALSE;
                } else {
                    conn->bytes_upstream_to_client += bytes_read;
                    activity = TRUE;
                }
            } else if (bytes_read <= 0) {
                running = FALSE;
            }
            g_clear_error(&local_error);
        }

        if (!activity) {
            g_usleep(1000);
        }
    }

    conn->state = DEADLIGHT_STATE_CLOSING;
    gchar *c2u = deadlight_format_bytes(conn->bytes_client_to_upstream);
    gchar *u2c = deadlight_format_bytes(conn->bytes_upstream_to_client);
    g_info("Connection %lu: Tunnel closed (client->upstream: %s, upstream->client: %s)",
        conn->id, c2u, u2c);
    g_free(c2u);
    g_free(u2c);

    return TRUE;
}

/**
 * Print detailed pool statistics to log
 */
static void connection_pool_log_stats(ConnectionPool *pool) {
    // Current implementation missing actual stats collection
    // Should call connection_pool_get_stats and log meaningful data
    
    guint idle, active;
    guint64 total_gets, cache_hits;
    gdouble hit_rate;
    guint64 evicted, failed;
    
    connection_pool_get_stats(pool, &idle, &active, &total_gets, 
                             &cache_hits, &hit_rate, &evicted, &failed);
    
    g_info("Pool Stats: Total=%u, Active=%u, Idle=%u, Hits=%lu, Misses=%lu, HitRate=%.1f%%",
           idle + active, active, idle, cache_hits, total_gets - cache_hits, hit_rate);
}