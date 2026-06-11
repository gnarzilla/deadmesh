/**
 * deadmesh - Mesh Session Routing Layer
 *
 * Maps (src_node_id, session_id) tuples to DeadlightConnection instances.
 *
 * Sessions arrive on the reader thread; connections are owned by worker
 * threads. This module is the thread-safe bridge between them.
 *
 * Session lifecycle:
 *   OPENING  -> first packet seen, connection not yet assigned
 *   ACTIVE   -> connection assigned, data flowing
 *   CLOSING  -> FIN seen or timeout, draining remaining data
 *   CLOSED   -> fully cleaned up, slot can be reused
 */

#ifndef DEADMESH_SESSION_H
#define DEADMESH_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include "core/deadlight.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────
 * Session state
 * ───────────────────────────────────────────────────────────── */

typedef enum {
    MESH_SESSION_OPENING = 0,
    MESH_SESSION_ACTIVE,
    MESH_SESSION_CLOSING,
    MESH_SESSION_CLOSED
} MeshSessionState;

/* ─────────────────────────────────────────────────────────────
 * Session struct
 * ───────────────────────────────────────────────────────────── */

typedef struct _MeshSession MeshSession;

struct _MeshSession {
    /* Identity */
    uint32_t        src_node_id;    /* Meshtastic node ID of the client     */
    uint32_t        session_id;     /* Per-node monotonic session counter   */
    gchar          *key;            /* "nodeid:sessionid" — hash table key  */

    GMutex          lock;          /* protects all fields below      */

    /* Routing */
    DeadlightConnection *conn;      /* NULL until ACTIVE                    */

    /* Reassembly */
    GByteArray     *assembly_buf;   /* in-flight chunk accumulator          */
    uint32_t        expected_chunks;
    uint32_t        received_chunks;
    uint32_t       *chunk_bitmap;   /* received[i] = chunk i arrived        */
    uint32_t        bitmap_words;   /* ceil(expected_chunks / 32)           */
    gsize           fragment_size;

    /* State */
    MeshSessionState state;
    gint64           created_at;    /* g_get_monotonic_time()               */
    gint64           last_activity;
    gpointer         user_data;

    /* Stats */
    uint64_t         packets_in;
    uint64_t         packets_out;
    uint64_t         bytes_in;
    uint64_t         bytes_out;
    uint32_t         retransmits;
};

/* ─────────────────────────────────────────────────────────────
 * Session table
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    GHashTable     *table;          /* key -> MeshSession*                  */
    GMutex          mutex;
    gint64          session_timeout_us; /* microseconds before idle expiry  */
    uint64_t        total_created;
    uint64_t        total_expired;
} MeshSessionTable;

/* ─────────────────────────────────────────────────────────────
 * API
 * ───────────────────────────────────────────────────────────── */

/**
 * Allocate and initialise a session table.
 * @session_timeout_ms: idle session expiry in milliseconds (0 = no expiry)
 */
MeshSessionTable *mesh_session_table_new(guint session_timeout_ms);

/**
 * Free all sessions and the table itself.
 */
void mesh_session_table_free(MeshSessionTable *table);

/**
 * Look up a session by node + session ID.
 * Returns NULL if not found.
 * Caller must NOT free the returned pointer — table owns it.
 */
MeshSession *mesh_session_lookup(MeshSessionTable *table,
                                  uint32_t src_node_id,
                                  uint32_t session_id);

/**
 * Get or create a session for (src_node_id, session_id).
 * Returns the session in OPENING state if newly created.
 * Thread-safe.
 */
MeshSession *mesh_session_get_or_create(MeshSessionTable *table,
                                         uint32_t src_node_id,
                                         uint32_t session_id);

/**
 * Assign a DeadlightConnection to a session, moving it to ACTIVE.
 * Must be called from the worker thread that owns the connection.
 */
void mesh_session_assign_conn(MeshSessionTable *table,
                               MeshSession *session,
                               DeadlightConnection *conn);

/**
 * Mark session as closing (FIN received or error).
 * The session remains in the table until fully drained.
 */
void mesh_session_close(MeshSessionTable *table, MeshSession *session);

/**
 * Remove and free a session. Called after CLOSED state confirmed.
 */
void mesh_session_remove(MeshSessionTable *table,
                          uint32_t src_node_id,
                          uint32_t session_id);

/**
 * Expire idle sessions older than the table's timeout.
 * Returns number of sessions expired.
 * Safe to call periodically from any thread.
 */
guint mesh_session_expire(MeshSessionTable *table);

/**
 * Initialise the reassembly bitmap for a session.
 * Must be called once total_chunks is known (from first packet header).
 */
bool mesh_session_init_reassembly(MeshSession *session, uint32_t total_chunks, gsize fragment_size);

/**
 * Record arrival of chunk @seq_num.
 * Returns true if all chunks have now arrived (assembly complete).
 */
bool mesh_session_record_chunk(MeshSession *session, uint32_t seq_num,
                                const uint8_t *data, size_t len);

/**
 * Check whether a specific chunk has been received.
 */
bool mesh_session_has_chunk(const MeshSession *session, uint32_t seq_num);

/**
 * Build a formatted key string "nodeid:sessionid".
 * Caller owns the returned string (g_free it).
 */
gchar *mesh_session_make_key(uint32_t src_node_id, uint32_t session_id);
void mesh_session_lock   (MeshSession *session);
void mesh_session_unlock (MeshSession *session);

#ifdef __cplusplus
}
#endif

#endif /* DEADMESH_SESSION_H */
