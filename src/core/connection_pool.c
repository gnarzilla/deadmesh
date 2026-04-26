/**
 * Deadlight Proxy v1.0 - Connection Pool Implementation
 * 
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "deadlight.h"

//==============================================================
// TYPE DEFINITIONS
//==============================================================

typedef struct _PooledConnection {
    GIOStream *stream;           // Can be GSocketConnection or GTlsConnection
    gchar *host;
    guint16 port;
    gint64 last_used;
    ConnectionType type;
    guint64 requests_served; 
} PooledConnection;

struct _ConnectionPool {
    GHashTable     *idle_by_key;      // "host:port:type" -> GQueue of PooledConnection*
    GHashTable     *active_connections; // stream -> PooledConnection*
    GMutex          mutex;

    gint            max_per_host;
    gint            max_total_idle;
    gint            idle_timeout;

    gchar          *eviction_policy;
    gint            health_check_interval;
    gboolean        reuse_ssl;

    // Statistics
    guint64 total_gets;
    guint64 cache_hits;
    guint64 cache_misses;
    guint64 connections_created;
    guint64 connections_closed;
    guint64 connections_evicted;
    guint64 health_check_failures;

    guint           cleanup_source_id;
};

//==============================================================
// FORWARD DECLARATIONS
//==============================================================

static gboolean cleanup_idle_connections(gpointer user_data);
static void pooled_connection_free(PooledConnection *pc);
static gboolean connection_is_healthy(GIOStream *stream, ConnectionType type);
static gchar* make_pool_key(const gchar *host, guint16 port, ConnectionType type);
static void evict_to_limit(ConnectionPool *pool);
void connection_pool_discard(ConnectionPool *pool, GIOStream *stream);  

//==============================================================
// HELPER FUNCTIONS
//==============================================================

/**
 * Create pool key for hash table lookup
 */
static gchar* make_pool_key(const gchar *host, guint16 port, ConnectionType type) {
    return g_strdup_printf("%s:%u:%d", host, port, type);
}

/**
 * Free a pooled connection
 */
static void pooled_connection_free(PooledConnection *pc) {
    if (!pc) return;
    
    if (pc->stream) {
        g_object_unref(pc->stream);
    }
    g_free(pc->host);
    g_free(pc);
}


/**
 * Remove a connection from the active table without returning it to idle.
 * Call this when a connection is being closed and should not be reused.
 */
void connection_pool_discard(ConnectionPool *pool, GIOStream *stream) {
    if (!pool || !stream) return;

    g_mutex_lock(&pool->mutex);

    PooledConnection *pc = g_hash_table_lookup(pool->active_connections, stream);
    if (pc) {
        g_hash_table_steal(pool->active_connections, stream);
        pooled_connection_free(pc);
        pool->connections_closed++;
    }

    g_mutex_unlock(&pool->mutex);
}

/**
 * Get the underlying socket from any stream type
 */
static GSocket* get_underlying_socket(GIOStream *stream, ConnectionType type) {
    GSocket *socket = NULL;

    if (type == CONN_TYPE_CLIENT_TLS || type == CONN_TYPE_SERVER_TLS) {
        GIOStream *base = NULL;
        g_object_get(G_TLS_CONNECTION(stream), "base-io-stream", &base, NULL);
        if (base) {
            if (G_IS_SOCKET_CONNECTION(base)) {
                socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(base));
            }
            g_object_unref(base);  // release the ref added by g_object_get
        }
    } else {
        socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream));
    }

    return socket;
}

/**
 * Check if a connection is still healthy
 */
static gboolean connection_is_healthy(GIOStream *stream, ConnectionType type) {
    if (!stream) return FALSE;

    GSocket *socket = get_underlying_socket(stream, type);
    if (!socket) return FALSE;

    if (!g_socket_is_connected(socket)) return FALSE;
    if (g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) != 0) return FALSE;

    // For TLS connections, verify the TLS session is still valid
    if (type == CONN_TYPE_CLIENT_TLS || type == CONN_TYPE_SERVER_TLS) {
        if (!G_IS_TLS_CONNECTION(stream)) return FALSE;
        GTlsConnection *tls = G_TLS_CONNECTION(stream);

        // If peer certificate is gone, session was invalidated
        GTlsCertificate *peer = g_tls_connection_get_peer_certificate(tls);
        if (!peer) {
            g_debug("Pool: TLS connection has no peer certificate - session invalid");
            return FALSE;
        }

        // Check for certificate errors
        GTlsCertificateFlags cert_errors = 
            g_tls_connection_get_peer_certificate_errors(tls);
        if (cert_errors != 0) {
            g_debug("Pool: TLS cert errors on pooled connection: 0x%x", cert_errors);
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Count idle connections for a specific host:port
 */
static guint count_host_connections(ConnectionPool *pool, const gchar *host, guint16 port) {
    guint count = 0;
    
    // Check all connection types for this host:port
    for (int type = CONN_TYPE_PLAIN; type <= CONN_TYPE_SERVER_TLS; type++) {
        gchar *key = make_pool_key(host, port, type);
        GQueue *queue = g_hash_table_lookup(pool->idle_by_key, key);
        if (queue) {
            count += g_queue_get_length(queue);
        }
        g_free(key);
    }
    
    return count;
}

/**
 * Get total number of idle connections across all queues
 */
static guint get_total_idle_count(ConnectionPool *pool) {
    guint total = 0;
    GHashTableIter iter;
    gpointer value;
    
    g_hash_table_iter_init(&iter, pool->idle_by_key);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        GQueue *queue = (GQueue *)value;
        total += g_queue_get_length(queue);
    }
    
    return total;
}

static gint compare_by_last_used(gconstpointer a, gconstpointer b) {
    const PooledConnection *pc_a = (const PooledConnection *)a;
    const PooledConnection *pc_b = (const PooledConnection *)b;
    return (pc_a->last_used > pc_b->last_used) - (pc_a->last_used < pc_b->last_used);
}
static void destroy_queue(gpointer data) {
    GQueue *queue = (GQueue *)data;
    g_queue_free_full(queue, (GDestroyNotify)pooled_connection_free);
}

/**
 * Evict oldest connections to stay under max_total_idle limit
 */
static void evict_to_limit(ConnectionPool *pool) {
    guint total_idle = get_total_idle_count(pool);

    if (total_idle <= (guint)pool->max_total_idle) {
        return;
    }

    // Build list of all idle connections with their last_used times
    GList *all_idle = NULL;
    GHashTableIter iter;
    gpointer value;

    g_hash_table_iter_init(&iter, pool->idle_by_key);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        GQueue *queue = (GQueue *)value;
        for (GList *link = queue->head; link; link = link->next) {
            PooledConnection *pc = link->data;
            all_idle = g_list_prepend(all_idle, pc);
        }
    }

    // Sort by last_used (oldest first for LRU)
    if (g_strcmp0(pool->eviction_policy, "lru") == 0) {
        all_idle = g_list_sort(all_idle, compare_by_last_used);  
    }
    // FIFO is natural queue order (oldest = head)

    // Evict oldest until under limit
    guint to_evict = total_idle - pool->max_total_idle;
    GList *link = all_idle;
    guint evicted = 0;

    while (link && evicted < to_evict) {
        PooledConnection *victim = link->data;

        // Remove from its queue
        gchar *key = make_pool_key(victim->host, victim->port, victim->type);
        GQueue *queue = g_hash_table_lookup(pool->idle_by_key, key);
        if (queue) {
            g_queue_remove(queue, victim);
            if (g_queue_is_empty(queue)) {
                g_hash_table_remove(pool->idle_by_key, key);
            }
        }
        g_free(key);

        g_debug("Pool: Evicted %s connection to %s:%d (LRU, %ld seconds idle)",
               victim->type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
               victim->host, victim->port,
               (g_get_monotonic_time() - victim->last_used) / G_TIME_SPAN_SECOND);

        pooled_connection_free(victim);
        pool->connections_closed++;
        pool->connections_evicted++;
        evicted++;

        link = link->next;
    }

    g_list_free(all_idle);

    if (evicted > 0) {
        g_info("Pool: Evicted %u connections to stay under global limit (%d)",
               evicted, pool->max_total_idle);
    }
}
//==============================================================
// PUBLIC API
//==============================================================

/**
 * Create new connection pool
 */
ConnectionPool* connection_pool_new(
    gint         max_per_host,
    gint         idle_timeout,
    gint         max_total_idle,
    const gchar *eviction_policy,
    gint         health_check_interval,
    gboolean     reuse_ssl)
{
    ConnectionPool *pool = g_new0(ConnectionPool, 1);

    pool->idle_by_key = g_hash_table_new_full(
        g_str_hash, g_str_equal,
        g_free,
        destroy_queue
    );
        
    pool->active_connections = g_hash_table_new_full(
        g_direct_hash, g_direct_equal,
        NULL, (GDestroyNotify)pooled_connection_free
    );
    
    g_mutex_init(&pool->mutex);

    pool->max_per_host           = max_per_host;
    pool->idle_timeout           = idle_timeout;
    pool->max_total_idle         = max_total_idle;
    pool->eviction_policy        = g_strdup(eviction_policy);
    pool->health_check_interval  = health_check_interval;
    pool->reuse_ssl              = reuse_ssl;

    pool->cleanup_source_id = g_timeout_add_seconds(
        pool->health_check_interval,
        cleanup_idle_connections,
        pool
    );

    g_info("Connection pool created: per_host=%d, idle_timeout=%ds, total_idle=%d, "
           "policy=%s, health_check=%ds, reuse_ssl=%d",
           max_per_host, idle_timeout, max_total_idle,
           eviction_policy, health_check_interval, reuse_ssl);

    return pool;
}

/**
 * Free connection pool
 */
void connection_pool_free(ConnectionPool *pool) {
    if (!pool) return;

    if (pool->cleanup_source_id)
        g_source_remove(pool->cleanup_source_id);

    g_hash_table_destroy(pool->idle_by_key);
    g_hash_table_destroy(pool->active_connections);
    g_free(pool->eviction_policy);

    g_mutex_clear(&pool->mutex);
    g_free(pool);
}

/**
 * Get connection from pool
 */
GIOStream* connection_pool_get(ConnectionPool *pool, 
                               const gchar *host, 
                               guint16 port,
                               ConnectionType type) {
    if (!pool || !host) return NULL;
    
    g_mutex_lock(&pool->mutex);
    pool->total_gets++;
    
    gchar *key = make_pool_key(host, port, type);
    GQueue *queue = g_hash_table_lookup(pool->idle_by_key, key);
    
    if (!queue || g_queue_is_empty(queue)) {
        pool->cache_misses++;
        g_mutex_unlock(&pool->mutex);
        
        g_debug("Pool MISS: No %s connection available for %s:%d (hit rate: %.2f%%)",
                type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                host, port,
                pool->total_gets > 0 ? (pool->cache_hits * 100.0 / pool->total_gets) : 0.0);
        
        g_free(key);
        return NULL;
    }
    
    // Pop from queue and validate
    PooledConnection *pc = NULL;
    while (!g_queue_is_empty(queue)) {
        pc = g_queue_pop_head(queue);
        
        if (connection_is_healthy(pc->stream, pc->type)) {
            break;
        }
        
        // Connection is dead
        g_debug("Pool: Removing dead %s connection to %s:%d",
                pc->type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                pc->host, pc->port);
        pooled_connection_free(pc);
        pool->connections_closed++;
        pool->health_check_failures++;
        pc = NULL;
    }
    
    // Clean up empty queue
    if (g_queue_is_empty(queue)) {
        g_hash_table_remove(pool->idle_by_key, key);
    }
    
    g_free(key);
    
    if (!pc) {
        pool->cache_misses++;
        g_mutex_unlock(&pool->mutex);
        return NULL;
    }
    
    // Move to active table
    g_hash_table_insert(pool->active_connections, pc->stream, pc);
    pool->cache_hits++;
    pc->requests_served++;
    
    g_mutex_unlock(&pool->mutex);
    
    g_info("Pool HIT: Reusing %s connection to %s:%d (served %lu requests, hit rate: %.2f%%)",
           pc->type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
           host, port, pc->requests_served,
           pool->total_gets > 0 ? (pool->cache_hits * 100.0 / pool->total_gets) : 0.0);
    
    return pc->stream;
}

/**
 * Release connection back to pool
 */
void connection_pool_release(ConnectionPool *pool,
                            GIOStream *stream,
                            const gchar *host,
                            guint16 port,
                            ConnectionType type) {
    if (!pool || !stream || !host) return;
    
    g_mutex_lock(&pool->mutex);
    
    // Lookup in active table
    PooledConnection *pc = g_hash_table_lookup(pool->active_connections, stream);
    
    if (!pc) {
        g_warning("Pool: Attempted to release %s connection to %s:%d not from pool",
                  type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                  host, port);
        g_mutex_unlock(&pool->mutex);
        return;
    }
    
    // Remove from active table (steal to avoid double-free)
    g_hash_table_steal(pool->active_connections, stream);
    
    // Validate connection is still healthy
    if (!connection_is_healthy(stream, type)) {
        g_info("Pool: %s connection to %s:%d unhealthy on release, closing",
               type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
               host, port);
        pooled_connection_free(pc);
        pool->connections_closed++;
        g_mutex_unlock(&pool->mutex);
        return;
    }
    
    // Check per-host limit
    guint host_count = count_host_connections(pool, host, port);
    if (host_count >= (guint)pool->max_per_host) {
        g_info("Pool: Per-host limit reached for %s:%d (%u/%d), closing connection",
               host, port, host_count, pool->max_per_host);
        pooled_connection_free(pc);
        pool->connections_closed++;
        g_mutex_unlock(&pool->mutex);
        return;
    }
    
    // Update timestamp
    pc->last_used = g_get_monotonic_time();
    
    // Get or create queue for this key
    gchar *key = make_pool_key(host, port, type);
    GQueue *queue = g_hash_table_lookup(pool->idle_by_key, key);
    if (!queue) {
        queue = g_queue_new();
        g_hash_table_insert(pool->idle_by_key, g_strdup(key), queue);
    }
    g_free(key);
    
    // Add to idle queue
    g_queue_push_tail(queue, pc);
    
    g_debug("Pool: Released %s connection to %s:%d (idle: %u, active: %u)",
            type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
            host, port,
            get_total_idle_count(pool),
            g_hash_table_size(pool->active_connections));
    
    // Check global limit and evict if needed
    evict_to_limit(pool);
    
    g_mutex_unlock(&pool->mutex);
}

/**
 * Register a new connection with the pool
 */
gboolean connection_pool_register(ConnectionPool *pool,
                                  GIOStream *stream,
                                  const gchar *host,
                                  guint16 port,
                                  ConnectionType type) {
    if (!pool || !stream || !host) return FALSE;
    
    g_mutex_lock(&pool->mutex);
    
    // Create new PooledConnection
    PooledConnection *pc = g_new0(PooledConnection, 1);
    pc->stream = g_object_ref(stream);
    pc->host = g_strdup(host);
    pc->port = port;
    pc->type = type;
    pc->last_used = g_get_monotonic_time();
    pc->requests_served = 0;
    
    // Add to active table
    g_hash_table_insert(pool->active_connections, stream, pc);
    pool->connections_created++;
    
    g_debug("Pool: Registered new %s connection to %s:%d",
            type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
            host, port);
    
    g_mutex_unlock(&pool->mutex);
    return TRUE;
}

/**
 * Upgrade a pooled connection from plain to TLS
 */
gboolean connection_pool_upgrade_to_tls(ConnectionPool *pool,
                                       GIOStream *plain_stream,
                                       GIOStream *tls_stream,
                                       const gchar *host,
                                       guint16 port) {
    if (!pool || !plain_stream || !tls_stream || !host) return FALSE;
    
    g_mutex_lock(&pool->mutex);
    
    // Find the plain connection in active table
    PooledConnection *pc = g_hash_table_lookup(pool->active_connections, plain_stream);
    if (!pc) {
        g_warning("Pool: Cannot upgrade - plain connection to %s:%d not found", host, port);
        g_mutex_unlock(&pool->mutex);
        return FALSE;
    }
    
    // Remove old entry
    g_hash_table_steal(pool->active_connections, plain_stream);
    
    // Update connection details
    g_object_unref(pc->stream);
    pc->stream = g_object_ref(tls_stream);
    pc->type = CONN_TYPE_CLIENT_TLS;
    
    // Re-insert with new key (tls_stream pointer)
    g_hash_table_insert(pool->active_connections, tls_stream, pc);
    
    g_info("Pool: Upgraded connection to %s:%d from plain to TLS", host, port);
    
    g_mutex_unlock(&pool->mutex);
    return TRUE;
}

/**
 * Periodic cleanup of idle connections
 */
static gboolean cleanup_idle_connections(gpointer user_data) {
    ConnectionPool *pool = (ConnectionPool *)user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout_usec = pool->idle_timeout * G_TIME_SPAN_SECOND;
    
    g_mutex_lock(&pool->mutex);
    
    guint cleaned = 0;
    GHashTableIter iter;
    gpointer key, value;
    
    g_hash_table_iter_init(&iter, pool->idle_by_key);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        GQueue *queue = (GQueue *)value;
        GList *link = queue->head;
        
        while (link) {
            PooledConnection *pc = link->data;
            GList *next = link->next;
            
            gboolean should_remove = FALSE;
            
            // Check timeout
            if (now - pc->last_used > timeout_usec) {
                g_debug("Pool: %s connection to %s:%d expired (idle for %ld seconds)",
                       pc->type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                       pc->host, pc->port,
                       (now - pc->last_used) / G_TIME_SPAN_SECOND);
                should_remove = TRUE;
            }
            // Check health
            else if (!connection_is_healthy(pc->stream, pc->type)) {
                g_debug("Pool: %s connection to %s:%d became unhealthy",
                       pc->type == CONN_TYPE_CLIENT_TLS ? "TLS" : "plain",
                       pc->host, pc->port);
                should_remove = TRUE;
                pool->health_check_failures++;
            }
            
            if (should_remove) {
                g_queue_delete_link(queue, link);
                pooled_connection_free(pc);
                pool->connections_closed++;
                cleaned++;
            }
            
            link = next;
        }
        
        // Remove empty queues
        if (g_queue_is_empty(queue)) {
            g_hash_table_iter_remove(&iter);
        }
    }
    
    if (cleaned > 0) {
        g_info("Pool: Cleaned %u idle connections (%u remaining, hit rate: %.2f%%)",
               cleaned, get_total_idle_count(pool),
               pool->total_gets > 0 ? (pool->cache_hits * 100.0 / pool->total_gets) : 0.0);
    }
    
    g_mutex_unlock(&pool->mutex);
    return G_SOURCE_CONTINUE;
}

/**
 * Get pool statistics
 */
void connection_pool_get_stats(ConnectionPool *pool,
                              guint *idle_count,
                              guint *active_count,
                              guint64 *total_gets,
                              guint64 *cache_hits,
                              gdouble *hit_rate,
                              guint64 *evicted,
                              guint64 *failed) {
    if (!pool) return;
    
    g_mutex_lock(&pool->mutex);
    
    if (idle_count) *idle_count = get_total_idle_count(pool);
    if (active_count) *active_count = g_hash_table_size(pool->active_connections);
    if (total_gets) *total_gets = pool->total_gets;
    if (cache_hits) *cache_hits = pool->cache_hits;
    if (hit_rate) {
        *hit_rate = pool->total_gets > 0 
                   ? (pool->cache_hits * 100.0 / pool->total_gets) 
                   : 0.0;
    }
    if (evicted) *evicted = pool->connections_evicted;
    if (failed) *failed = pool->health_check_failures;
    
    g_mutex_unlock(&pool->mutex);
}