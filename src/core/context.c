/**
 * Deadlight Proxy v1.0 - Context Management
 *
 * Core context creation and lifecycle management
 */

#include <glib.h>
#include <stdlib.h>
#include "deadlight.h"

/**
 * Create new Deadlight context
 */
DeadlightContext *deadlight_context_new(void) {
    DeadlightContext *ctx = g_new0(DeadlightContext, 1);
    
    // Initialize hash tables
    ctx->certificates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Initialize plugin data storage
    ctx->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    // Initialize mesh node table — keyed by node_id (uint32 as pointer),
    // values are MeshNode* allocated with g_new0 and freed with g_free.
    ctx->node_table = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, g_free);
    g_mutex_init(&ctx->node_table_mutex);

    /* Message ring buffer — zero-initialised by g_new0, just init the mutex */
    ctx->message_ring_head  = 0;
    ctx->message_ring_count = 0;
    g_mutex_init(&ctx->message_ring_mutex);

    // Initialize statistics
    ctx->total_connections = 0;
    ctx->active_connections = 0;
    ctx->bytes_transferred = 0;
    ctx->uptime_timer = g_timer_new();
    
    g_mutex_init(&ctx->stats_mutex);
    g_mutex_init(&ctx->sse_clients_mutex);

    // Set defaults
    ctx->shutdown_requested = FALSE;
    
    // VPN will be allocated when enabled
    ctx->vpn = NULL;
    
    return ctx;
}

/**
 * Free Deadlight context
 */
void deadlight_context_free(DeadlightContext *ctx) {
    if (!ctx) return;
    
    // Stop main loop if running
    if (ctx->main_loop) {
        if (g_main_loop_is_running(ctx->main_loop)) {
            g_main_loop_quit(ctx->main_loop);
        }
        g_main_loop_unref(ctx->main_loop);
    }
    
    // Clean up connections
    if (ctx->connections) {
        g_hash_table_destroy(ctx->connections);
    }
    
    // Clean up certificates
    if (ctx->certificates) {
        g_hash_table_destroy(ctx->certificates);
    }

    // Clean up plugin data
    if (ctx->plugins_data) {
        g_hash_table_destroy(ctx->plugins_data);
    }

    // Clean up mesh node table
    if (ctx->node_table) {
        g_hash_table_destroy(ctx->node_table);
        ctx->node_table = NULL;
    }
    g_mutex_clear(&ctx->node_table_mutex);

    /* Message ring — just clear the mutex, entries are stack-allocated */
    g_mutex_clear(&ctx->message_ring_mutex);

    // Stop worker pool
    if (ctx->worker_pool) {
        g_thread_pool_free(ctx->worker_pool, TRUE, TRUE);
    }
    
    // Stop uptime timer
    if (ctx->uptime_timer) {
        g_timer_destroy(ctx->uptime_timer);
    }
    if (ctx->conn_pool)
        connection_pool_free(ctx->conn_pool);

    g_free(ctx->pool_eviction_policy);

    g_mutex_clear(&ctx->sse_clients_mutex);
    g_mutex_clear(&ctx->stats_mutex);
    
    // Free cached strings
    g_free(ctx->listen_address);
    
    // Free managers (these should have their own cleanup)
    g_free(ctx->network);
    g_free(ctx->ssl);
    g_free(ctx->plugins);
    
    // Free VPN manager
    if (ctx->vpn) {
        g_free(ctx->vpn);
        ctx->vpn = NULL;
    }
    
    // Free config
    if (ctx->config) {
        if (ctx->config->file_monitor) {
            g_file_monitor_cancel(ctx->config->file_monitor);
            g_object_unref(ctx->config->file_monitor);
        }
        if (ctx->config->keyfile) {
            g_key_file_free(ctx->config->keyfile);
        }
        if (ctx->config->string_cache) {
            g_hash_table_destroy(ctx->config->string_cache);
        }
        if (ctx->config->int_cache) {
            g_hash_table_destroy(ctx->config->int_cache);
        }
        if (ctx->config->bool_cache) {
            g_hash_table_destroy(ctx->config->bool_cache);
        }
        g_free(ctx->config->config_path);
        g_free(ctx->config);
    }
    
    g_free(ctx);
}