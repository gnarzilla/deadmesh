/**
 * deadmesh - Mesh Session Routing Layer Implementation
 */

#include "mesh_session.h"
#include <string.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────────────────────
 * Key helpers
 * ───────────────────────────────────────────────────────────── */

gchar *mesh_session_make_key(uint32_t src_node_id, uint32_t session_id) {
    return g_strdup_printf("%08x:%08x", src_node_id, session_id);
}

static void mesh_session_free(gpointer data) {
    MeshSession *s = (MeshSession *)data;
    if (!s) return;
    /* conn and user_data must already be NULL before free is called —
     * caller is responsible for draining the connection first.        */
    g_assert(s->conn == NULL);
    g_free(s->key);
    g_free(s->chunk_bitmap);
    if (s->assembly_buf)
        g_byte_array_free(s->assembly_buf, TRUE);
    g_mutex_clear(&s->lock);     /* ← add */
    g_free(s);
}

void mesh_session_lock(MeshSession *session) {
    g_mutex_lock(&session->lock);
}

void mesh_session_unlock(MeshSession *session) {
    g_mutex_unlock(&session->lock);
}

/* ─────────────────────────────────────────────────────────────
 * Table lifecycle
 * ───────────────────────────────────────────────────────────── */

MeshSessionTable *mesh_session_table_new(guint session_timeout_ms) {
    MeshSessionTable *t = g_new0(MeshSessionTable, 1);
    t->table = g_hash_table_new_full(g_str_hash, g_str_equal,
                                      NULL,               /* key owned by session */
                                      mesh_session_free);
    g_mutex_init(&t->mutex);
    t->session_timeout_us = (gint64)session_timeout_ms * 1000LL;
    return t;
}

void mesh_session_table_free(MeshSessionTable *table) {
    if (!table) return;
    g_mutex_lock(&table->mutex);
    g_hash_table_destroy(table->table);
    g_mutex_unlock(&table->mutex);
    g_mutex_clear(&table->mutex);
    g_free(table);
}

/* ─────────────────────────────────────────────────────────────
 * Lookup / create
 * ───────────────────────────────────────────────────────────── */

MeshSession *mesh_session_lookup(MeshSessionTable *table,
                                  uint32_t src_node_id,
                                  uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);

    g_mutex_lock(&table->mutex);
    MeshSession *s = g_hash_table_lookup(table->table, key);
    g_mutex_unlock(&table->mutex);

    g_free(key);
    return s;
}

MeshSession *mesh_session_get_or_create(MeshSessionTable *table,
                                         uint32_t src_node_id,
                                         uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);

    g_mutex_lock(&table->mutex);

    MeshSession *s = g_hash_table_lookup(table->table, key);

    if (!s) {
        s = g_new0(MeshSession, 1);
        s->src_node_id   = src_node_id;
        s->session_id    = session_id;
        s->key           = key;
        s->state         = MESH_SESSION_OPENING;
        s->assembly_buf  = g_byte_array_new();
        s->fragment_size = 220;      /* overridden by init_reassembly caller */
        s->created_at    = g_get_monotonic_time();
        s->last_activity = s->created_at;
        g_mutex_init(&s->lock);      /* ← add */
        g_hash_table_insert(table->table, s->key, s);
        table->total_created++;
    } else {
        g_free(key);
    }

    s->last_activity = g_get_monotonic_time();

    g_mutex_unlock(&table->mutex);
    return s;
}

/* ─────────────────────────────────────────────────────────────
 * State transitions
 * ───────────────────────────────────────────────────────────── */

void mesh_session_assign_conn(MeshSessionTable *table,
                               MeshSession *session,
                               DeadlightConnection *conn) {
    (void)table; 
    g_mutex_lock(&session->lock);
    session->conn          = conn;
    session->state         = MESH_SESSION_ACTIVE;
    session->last_activity = g_get_monotonic_time();
    g_mutex_unlock(&session->lock);
}

void mesh_session_close(MeshSessionTable *table, MeshSession *session) {
    (void)table;
    g_mutex_lock(&session->lock);
    session->state = MESH_SESSION_CLOSING;
    session->conn  = NULL;   /* connection is draining, relinquish ptr */
    g_mutex_unlock(&session->lock);
}

void mesh_session_remove(MeshSessionTable *table,
                          uint32_t src_node_id,
                          uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);
    g_mutex_lock(&table->mutex);
    g_hash_table_remove(table->table, key);
    g_mutex_unlock(&table->mutex);
    g_free(key);
}

/* ─────────────────────────────────────────────────────────────
 * Expiry
 * ───────────────────────────────────────────────────────────── */

guint mesh_session_expire(MeshSessionTable *table) {
    if (table->session_timeout_us == 0) return 0;

    gint64 now     = g_get_monotonic_time();
    guint  expired = 0;

    g_mutex_lock(&table->mutex);

    GHashTableIter iter;
    gpointer key, value;
    GPtrArray *to_remove = g_ptr_array_new();

    g_hash_table_iter_init(&iter, table->table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        MeshSession *s = (MeshSession *)value;

        g_mutex_lock(&s->lock);
        gint64 idle = now - s->last_activity;
        gint64 timeout = (s->state == MESH_SESSION_ACTIVE)
            ? table->session_timeout_us * 4
            : table->session_timeout_us;
        MeshSessionState state = s->state;
        g_mutex_unlock(&s->lock);

        if (idle > timeout) {
            if (state == MESH_SESSION_ACTIVE) {
                /* Signal the connection closed before removing */
                g_mutex_lock(&s->lock);
                if (s->conn) {
                    /* Caller's responsibility to close conn cleanly;
                     * we mark CLOSING and let on_connection_close
                     * call mesh_session_remove when it drains.      */
                    s->state = MESH_SESSION_CLOSING;
                    g_mutex_unlock(&s->lock);
                    /* Don't add to to_remove — let close path do it */
                } else {
                    s->state = MESH_SESSION_CLOSED;
                    s->conn  = NULL;
                    g_mutex_unlock(&s->lock);
                    g_ptr_array_add(to_remove, s->key);
                }
            } else {
                g_ptr_array_add(to_remove, s->key);
            }
        }
    }

    for (guint i = 0; i < to_remove->len; i++) {
        g_hash_table_remove(table->table, to_remove->pdata[i]);
        expired++;
        table->total_expired++;
    }

    g_ptr_array_free(to_remove, TRUE);
    g_mutex_unlock(&table->mutex);
    return expired;
}

/* ─────────────────────────────────────────────────────────────
 * Reassembly
 * ───────────────────────────────────────────────────────────── */

bool mesh_session_init_reassembly(MeshSession *session,
                                   uint32_t total_chunks,
                                   gsize fragment_size) {
    g_mutex_lock(&session->lock);

    g_free(session->chunk_bitmap);
    session->expected_chunks = total_chunks;
    session->received_chunks = 0;
    session->fragment_size   = fragment_size > 0 ? fragment_size : 220;

    if (total_chunks == 0) {
        session->chunk_bitmap = NULL;
        session->bitmap_words = 0;
        g_mutex_unlock(&session->lock);
        return true;
    }

    session->bitmap_words = (total_chunks + 31) / 32;
    session->chunk_bitmap = g_new0(uint32_t, session->bitmap_words);
    g_byte_array_set_size(session->assembly_buf, 0);

    g_mutex_unlock(&session->lock);
    return true;
}

bool mesh_session_record_chunk(MeshSession *session, uint32_t seq_num,
                                const uint8_t *data, size_t len) {
    g_mutex_lock(&session->lock);

    if (seq_num >= session->expected_chunks || !session->chunk_bitmap) {
        g_mutex_unlock(&session->lock);
        return false;
    }

    uint32_t word = seq_num / 32;
    uint32_t bit  = seq_num % 32;

    bool already_received = (session->chunk_bitmap[word] >> bit) & 1;
    if (!already_received) {
        session->chunk_bitmap[word] |= (1u << bit);
        session->received_chunks++;
        session->bytes_in    += len;
        session->last_activity = g_get_monotonic_time();
    }

    gsize fs     = session->fragment_size > 0 ? session->fragment_size : 220;
    gsize offset = seq_num * fs;           /* ← uses stored size, not hardcoded */
    gsize required = offset + len;

    if (session->assembly_buf->len < required)
        g_byte_array_set_size(session->assembly_buf, required);

    memcpy(session->assembly_buf->data + offset, data, len);

    bool complete = (session->received_chunks >= session->expected_chunks);
    g_mutex_unlock(&session->lock);
    return complete;
}

bool mesh_session_has_chunk(const MeshSession *session, uint32_t seq_num) {
    if (seq_num >= session->expected_chunks) return false;
    if (!session->chunk_bitmap)              return false;

    uint32_t word = seq_num / 32;
    uint32_t bit  = seq_num % 32;
    return (session->chunk_bitmap[word] >> bit) & 1;
}
