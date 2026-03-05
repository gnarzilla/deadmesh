/**
 * deadmesh (meshtastic.deadlight) v1.0 - Main Header
 *
 * Internet-over-LoRa mesh gateway
 * Part of the Deadlight ecosystem: https://deadlight.boo
 *
 * Derived from proxy.deadlight — shared API surface kept intentionally
 * compatible so improvements flow between projects with minimal friction.
 */
#ifndef DEADMESH_H
#define DEADMESH_H

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !GLIB_CHECK_VERSION(2, 62, 0)
static inline GIOStream *g_tls_connection_get_base_io_stream(GTlsConnection *conn) {
    GIOStream *base_io_stream = NULL;
    g_object_get(conn, "base-io-stream", &base_io_stream, NULL);
    return base_io_stream;
}
#endif

/* ═══════════════════════════════════════════════════════════
 * Version & defaults
 * ═══════════════════════════════════════════════════════════ */

#define DEADMESH_VERSION_MAJOR  1
#define DEADMESH_VERSION_MINOR  0
#define DEADMESH_VERSION_PATCH  0
#define DEADMESH_VERSION_STRING "1.0.0"

/* Keep proxy.deadlight compat macros so shared code compiles unmodified */
#define DEADLIGHT_VERSION_MAJOR  DEADMESH_VERSION_MAJOR
#define DEADLIGHT_VERSION_MINOR  DEADMESH_VERSION_MINOR
#define DEADLIGHT_VERSION_PATCH  DEADMESH_VERSION_PATCH
#define DEADLIGHT_VERSION_STRING DEADMESH_VERSION_STRING

#define DEADLIGHT_DEFAULT_PORT            8080
#define DEADLIGHT_DEFAULT_CONFIG_FILE     "/etc/deadmesh/deadmesh.conf"
#define DEADLIGHT_DEFAULT_LOG_LEVEL       "info"
#define DEADLIGHT_DEFAULT_MAX_CONNECTIONS 5000

/* Mesh-specific defaults */
#define DEADMESH_DEFAULT_FRAGMENT_SIZE    220     /* bytes — safe Meshtastic payload */
#define DEADMESH_DEFAULT_ACK_TIMEOUT_MS   30000   /* 30 s */
#define DEADMESH_DEFAULT_MAX_RETRIES      3
#define DEADMESH_DEFAULT_HOP_LIMIT        3

/* ═══════════════════════════════════════════════════════════
 * Error domain
 * ═══════════════════════════════════════════════════════════ */

#define DEADLIGHT_ERROR deadlight_error_quark()

typedef enum {
    DEADLIGHT_ERROR_CONFIG = 1,
    DEADLIGHT_ERROR_NETWORK,
    DEADLIGHT_ERROR_SSL,
    DEADLIGHT_ERROR_PLUGIN,
    DEADLIGHT_ERROR_PROTOCOL,
    DEADLIGHT_ERROR_IO,
    DEADLIGHT_ERROR_AUTH,
    DEADLIGHT_ERROR_VPN,
    DEADLIGHT_ERROR_MESH          /* mesh transport / fragmentation errors */
} DeadlightErrorCode;

GQuark deadlight_error_quark(void);

/* ═══════════════════════════════════════════════════════════
 * Enums
 * ═══════════════════════════════════════════════════════════ */

typedef enum {
    DEADLIGHT_PROTOCOL_UNKNOWN = 0,
    DEADLIGHT_PROTOCOL_HTTP,
    DEADLIGHT_PROTOCOL_HTTPS,
    DEADLIGHT_PROTOCOL_SOCKS,
    DEADLIGHT_PROTOCOL_CONNECT,
    DEADLIGHT_PROTOCOL_WEBSOCKET,
    DEADLIGHT_PROTOCOL_IMAP,
    DEADLIGHT_PROTOCOL_IMAPS,
    DEADLIGHT_PROTOCOL_SMTP,
    DEADLIGHT_PROTOCOL_API,
    DEADLIGHT_PROTOCOL_SOCKS4,
    DEADLIGHT_PROTOCOL_SOCKS5,
    DEADLIGHT_PROTOCOL_FTP
} DeadlightProtocol;

typedef enum {
    DEADLIGHT_STATE_INIT = 0,
    DEADLIGHT_STATE_DETECTING,
    DEADLIGHT_STATE_CONNECTING,
    DEADLIGHT_STATE_CONNECTED,
    DEADLIGHT_STATE_TUNNELING,
    DEADLIGHT_STATE_CLOSING,
    DEADLIGHT_STATE_CLOSED
} DeadlightConnectionState;

typedef enum {
    CONN_TYPE_PLAIN,        /* Regular GSocketConnection          */
    CONN_TYPE_CLIENT_TLS,   /* GTlsClientConnection (upstream)    */
    CONN_TYPE_SERVER_TLS    /* GTlsServerConnection (interception) */
} ConnectionType;

typedef enum {
    DEADLIGHT_LOG_ERROR = 0,
    DEADLIGHT_LOG_WARNING,
    DEADLIGHT_LOG_INFO,
    DEADLIGHT_LOG_DEBUG
} DeadlightLogLevel;

typedef enum {
    HANDLER_ERROR            = 0, /* Handler failed — caller MUST clean up          */
    HANDLER_SUCCESS_CLEANUP_NOW = 1, /* Sync finish — caller MUST clean up          */
    HANDLER_SUCCESS_ASYNC    = 2  /* Async started — caller MUST NOT clean up       */
} DeadlightHandlerResult;

/** Meshtastic link state for a mesh session */
typedef enum {
    MESH_LINK_DISCONNECTED = 0,
    MESH_LINK_CONNECTING,
    MESH_LINK_CONNECTED,
    MESH_LINK_DEGRADED      /* connected but packet loss > threshold */
} DeadlightMeshLinkState;

/* ═══════════════════════════════════════════════════════════
 * Forward declarations
 * ═══════════════════════════════════════════════════════════ */

typedef struct _DeadlightContext        DeadlightContext;
typedef struct _DeadlightConnection     DeadlightConnection;
typedef struct _DeadlightPlugin         DeadlightPlugin;
typedef struct _DeadlightRequest        DeadlightRequest;
typedef struct _DeadlightResponse       DeadlightResponse;
typedef struct _DeadlightConfig         DeadlightConfig;
typedef struct _DeadlightNetworkManager DeadlightNetworkManager;
typedef struct _DeadlightSSLManager     DeadlightSSLManager;
typedef struct _DeadlightPluginManager  DeadlightPluginManager;
typedef struct _ConnectionPool          ConnectionPool;
typedef struct _DeadlightConnInfo       DeadlightConnInfo;
typedef struct _DeadlightVPNManager     DeadlightVPNManager;
typedef struct _DeadlightMeshManager    DeadlightMeshManager;  

/* ═══════════════════════════════════════════════════════════
 * Protocol handler vtable
 * ═══════════════════════════════════════════════════════════ */

typedef struct _DeadlightProtocolHandler {
    const gchar *name;
    DeadlightProtocol protocol_id;
    gsize (*detect)(const guint8 *initial_data, gsize len);
    DeadlightHandlerResult (*handle)(DeadlightConnection *conn, GError **error);
    void (*cleanup)(DeadlightConnection *conn);
} DeadlightProtocolHandler;

/* ═══════════════════════════════════════════════════════════
 * Struct definitions
 * ═══════════════════════════════════════════════════════════ */

struct _DeadlightConfig {
    GKeyFile     *keyfile;
    gchar        *config_path;
    GFileMonitor *file_monitor;
    GHashTable   *string_cache;
    GHashTable   *int_cache;
    GHashTable   *bool_cache;
    GMutex        cache_mutex;
};

/**
 * Meshtastic transport layer manager.
 * Owns the serial/BT/TCP link to the radio and the
 * fragmentation/reassembly state machines.
 */
struct _DeadlightMeshManager {
    DeadlightContext   *context;

    /* Radio link */
    gchar              *serial_port;       /* e.g. /dev/ttyACM0            */
    gint                baud_rate;
    gint                radio_fd;          /* -1 when not connected         */
    DeadlightMeshLinkState link_state;

    /* Node identity */
    guint32             local_node_id;
    gchar              *channel_psk;       /* base64 PSK for channel key    */

    /* Fragmentation config */
    gsize               fragment_size;     /* max payload bytes per packet  */
    guint               ack_timeout_ms;
    guint               max_retries;
    guint               hop_limit;

    /* Stats */
    guint64             packets_sent;
    guint64             packets_received;
    guint64             packets_lost;
    guint64             bytes_sent;
    guint64             bytes_received;
    guint64             sessions_total;
    guint64             sessions_active;

    /* Internal reassembly table: session_id -> GByteArray* */
    GHashTable         *reassembly_table;
    GMutex              reassembly_mutex;
};

typedef struct {
    uint32_t  node_id;                /* Meshtastic node number (hex ID)  */
    char      short_name[5];          /* e.g. "CERN" — max 4 chars + NUL  */
    char      long_name[40];          /* e.g. "Cernunnos"                 */
    int32_t   hops_away;              /* -1 = unknown                     */
    float     snr;                    /* last heard SNR (dB)              */
    double    latitude;               /* 0.0 = unknown                    */
    double    longitude;
    int32_t   altitude;
    uint8_t   battery_level;          /* 0–100, 101 = plugged in          */
    gboolean  has_position;
    gboolean  has_telemetry;
    gint64    last_heard;             /* g_get_real_time() / 1e6 (unix s) */
    gboolean  is_local;               /* TRUE for our own node            */
} MeshNode;

/*
 * ADD TO DeadlightContext struct:
 *
 *   GHashTable  *node_table;        // uint32 node_id -> MeshNode*
 *   GMutex       node_table_mutex;
 *
 * ADD TO context init (wherever other mutexes are initialised):
 *
 *   context->node_table = g_hash_table_new_full(
 *       g_direct_hash, g_direct_equal, NULL, g_free);
 *   g_mutex_init(&context->node_table_mutex);
 *
 * ADD TO context cleanup:
 *
 *   g_mutex_clear(&context->node_table_mutex);
 *   g_hash_table_destroy(context->node_table);
 */

struct _DeadlightContext {
    GMainLoop              *main_loop;
    DeadlightConfig        *config;
    DeadlightNetworkManager *network;
    DeadlightSSLManager    *ssl;
    DeadlightPluginManager *plugins;
    DeadlightVPNManager    *vpn;
    DeadlightMeshManager   *mesh;          /* NULL when mesh transport unused */
    GHashTable             *node_table;     
    GMutex                 node_table_mutex;
    GHashTable             *plugins_data;
    GHashTable             *connections;
    GHashTable             *certificates;
    GThreadPool            *worker_pool;

    /* Aggregate stats */
    guint64  total_connections;
    guint64  active_connections;
    guint64  bytes_transferred;
    GTimer  *uptime_timer;

    /* Listener config */
    gint     listen_port;
    gchar   *listen_address;
    guint    max_connections;

    DeadlightLogLevel log_level;
    gboolean ssl_intercept_enabled;

    /* Connection pool */
    ConnectionPool *conn_pool;
    gint            pool_max_per_host;
    gint            pool_idle_timeout;
    gint            pool_max_total;
    gchar          *pool_eviction_policy;
    gint            pool_health_check_interval;
    gboolean        pool_reuse_ssl;

    /* Per-protocol connection counters */
    guint64 http_connections_total;
    guint64 https_connections_total;
    guint64 socks_connections_total;
    guint64 api_connections_total;
    guint64 smtp_connections_total;
    guint64 imap_connections_total;
    guint64 ftp_connections_total;
    guint64 websocket_connections_total;

    /* Auth */
    gchar   *auth_endpoint;
    gchar   *auth_secret;

    gboolean shutdown_requested;
    GMutex   stats_mutex;

    gchar  **local_hostnames;    // NULL-terminated array of local hostnames
};

struct _DeadlightConnection {
    guint64               id;
    GSocketConnection    *client_connection;
    GSocketConnection    *upstream_connection;
    gchar                *client_address;
    gchar                *target_host;
    gint                  target_port;
    gchar                *username;
    gchar                *session_token;
    gboolean              authenticated;
    gboolean              cleaned;
    gboolean              should_stop;
    DeadlightProtocol     protocol;
    DeadlightConnectionState state;
    const DeadlightProtocolHandler *handler;
    gpointer              protocol_data;
    GTlsConnection       *client_tls;
    GTlsConnection       *upstream_tls;
    gboolean              ssl_established;
    gboolean              will_use_ssl;
    gboolean              is_connect_tunnel;
    GByteArray           *client_buffer;
    GByteArray           *upstream_buffer;
    guint64               bytes_client_to_upstream;
    guint64               bytes_upstream_to_client;
    GTimer               *connection_timer;
    GHashTable           *plugin_data;
    DeadlightRequest     *current_request;
    DeadlightResponse    *current_response;
    DeadlightContext     *context;
    GIOChannel           *client_channel;
    GIOChannel           *upstream_channel;
    GTlsCertificate      *upstream_peer_cert;
    gint                  client_fd;
    gint                  upstream_fd;

    /* Mesh session — non-NULL when this connection arrived over LoRa */
    guint32               mesh_session_id;
    guint32               mesh_source_node;
};

struct _DeadlightRequest {
    gchar      *method;
    gchar      *uri;
    gchar      *version;
    GHashTable *headers;
    GByteArray *body;
    gchar      *host;
    gint        port;
    gchar      *path;
    gchar      *query;
    DeadlightConnection *connection;
    gboolean    modified;
    gboolean    blocked;
    gchar      *block_reason;
};

struct _DeadlightResponse {
    gchar      *version;
    gint        status_code;
    gchar      *reason_phrase;
    GHashTable *headers;
    GByteArray *body;
    DeadlightConnection *connection;
    gboolean    modified;
    gboolean    blocked;
    gchar      *block_reason;
};

struct _DeadlightPlugin {
    gchar    *name;
    gchar    *version;
    gchar    *description;
    gchar    *author;
    gboolean (*init)(DeadlightContext *context);
    void     (*cleanup)(DeadlightContext *context);
    gboolean (*on_connection_accept)(DeadlightConnection *conn);
    gboolean (*on_protocol_detect)(DeadlightConnection *conn, DeadlightProtocol proto);
    gboolean (*on_request_headers)(DeadlightRequest *request);
    gboolean (*on_request_body)(DeadlightRequest *request);
    gboolean (*on_response_headers)(DeadlightResponse *response);
    gboolean (*on_response_body)(DeadlightResponse *response);
    gboolean (*on_connection_close)(DeadlightConnection *conn);
    gboolean (*on_config_change)(DeadlightContext *context, const gchar *section, const gchar *key);
    gpointer  private_data;
    gint      ref_count;
};

/* _DeadlightVPNManager is fully defined in vpn/vpn_gateway.h.
 * The forward declaration above is sufficient for DeadlightContext. */

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Context
 * ═══════════════════════════════════════════════════════════ */

DeadlightContext *deadlight_context_new(void);
void              deadlight_context_free(DeadlightContext *context);
const gchar      *deadlight_get_version(void);
const gchar      *deadlight_get_build_date(void);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Config
 * ═══════════════════════════════════════════════════════════ */

gboolean  deadlight_config_load(DeadlightContext *context, const gchar *config_file, GError **error);
gboolean  deadlight_config_save(DeadlightContext *context, GError **error);
gint      deadlight_config_get_int(DeadlightContext *context, const gchar *section, const gchar *key, gint default_value);
gchar    *deadlight_config_get_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *default_value);
gboolean  deadlight_config_get_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean default_value);
void      deadlight_config_set_int(DeadlightContext *context, const gchar *section, const gchar *key, gint value);
void      deadlight_config_set_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *value);
void      deadlight_config_set_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean value);
guint64   deadlight_config_get_size(DeadlightContext *context, const gchar *section, const gchar *key, guint64 default_value);
gboolean  deadlight_config_has_section(DeadlightContext *context, const gchar *section);
gboolean  deadlight_config_validate(DeadlightContext *context, GError **error);
void      deadlight_config_free(DeadlightContext *context);
gchar    *expand_config_path(const gchar *path);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Logging
 * ═══════════════════════════════════════════════════════════ */

void     deadlight_log_handler(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);
gboolean deadlight_logging_init(DeadlightContext *context, GError **error);
void     deadlight_logging_cleanup(DeadlightContext *context);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Network
 * ═══════════════════════════════════════════════════════════ */

gboolean            deadlight_network_init(DeadlightContext *context, GError **error);
gboolean            deadlight_network_start_listener(DeadlightContext *context, gint port, GError **error);
void                deadlight_network_stop(DeadlightContext *context);
void                deadlight_network_cleanup(DeadlightContext *context);
gboolean            deadlight_network_connect_upstream(DeadlightConnection *conn, GError **error);
void                deadlight_network_release_to_pool(DeadlightConnection *conn, const gchar *reason);
DeadlightConnection *deadlight_connection_new(DeadlightContext *context, GSocketConnection *client_connection, gchar *client_address_str);
gboolean            deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error);
gboolean            deadlight_tls_tunnel_data(DeadlightConnection *conn, GError **error);
void                deadlight_connection_free(DeadlightConnection *conn);
GSocketConnection  *deadlight_network_connect_tcp(DeadlightContext *context, const gchar *host, guint16 port, GError **error);
void                deadlight_network_tunnel_socket_connections(GSocketConnection *conn1, GSocketConnection *conn2);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Protocols
 * ═══════════════════════════════════════════════════════════ */

gboolean                     deadlight_protocol_handle_response(DeadlightConnection *connection, GError **error);
void                         deadlight_protocols_init(DeadlightContext *context);
void                         deadlight_protocol_register(const DeadlightProtocolHandler *handler);
const DeadlightProtocolHandler *deadlight_protocol_detect_and_assign(DeadlightConnection *conn, const guint8 *data, gsize length);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — SSL
 * ═══════════════════════════════════════════════════════════ */

gboolean deadlight_ssl_init(DeadlightContext *context, GError **error);
void     deadlight_ssl_cleanup(DeadlightContext *context);
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *connection, GError **error);
gboolean deadlight_ssl_tunnel_data(DeadlightConnection *conn, GError **error);
gboolean deadlight_network_establish_upstream_ssl(DeadlightConnection *conn, GError **error);
gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file, const gchar *key_file, GError **error);
gboolean deadlight_ssl_load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error);
gboolean deadlight_ssl_generate_host_certificate(DeadlightSSLManager *ssl_mgr, const gchar *hostname, X509 **out_cert, EVP_PKEY **out_key, GError **error);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Plugins
 * ═══════════════════════════════════════════════════════════ */

gboolean deadlight_plugins_init(DeadlightContext *context, GError **error);
void     deadlight_plugins_cleanup(DeadlightContext *context);
gint     deadlight_plugins_count(DeadlightContext *context);
gboolean deadlight_plugins_call_on_connection_accept(DeadlightContext *context, DeadlightConnection *conn);
gboolean deadlight_plugins_call_on_protocol_detect(DeadlightContext *context, DeadlightConnection *conn);
gboolean deadlight_plugins_call_on_request_headers(DeadlightContext *context, DeadlightRequest *request);
gboolean deadlight_plugins_call_on_request_body(DeadlightContext *context, DeadlightRequest *request);
gboolean deadlight_plugins_call_on_response_headers(DeadlightContext *context, DeadlightResponse *response);
gboolean deadlight_plugins_call_on_response_body(DeadlightContext *context, DeadlightResponse *response);
gboolean deadlight_plugins_call_on_connection_close(DeadlightContext *context, DeadlightConnection *conn);
void     deadlight_plugins_call_on_config_change(DeadlightContext *context, const gchar *section, const gchar *key);
GList   *deadlight_plugins_get_all_names(DeadlightContext *context);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Request / Response
 * ═══════════════════════════════════════════════════════════ */

DeadlightRequest  *deadlight_request_new(DeadlightConnection *connection);
void               deadlight_request_free(DeadlightRequest *request);
gboolean           deadlight_request_parse_headers(DeadlightRequest *request, const gchar *data, gsize length);
gchar             *deadlight_request_get_header(DeadlightRequest *request, const gchar *name);
void               deadlight_request_set_header(DeadlightRequest *request, const gchar *name, const gchar *value);

DeadlightResponse *deadlight_response_new(DeadlightConnection *connection);
void               deadlight_response_free(DeadlightResponse *response);
gboolean           deadlight_response_parse_headers(DeadlightResponse *response, const gchar *data, gsize length);
gchar             *deadlight_response_get_header(DeadlightResponse *response, const gchar *name);
void               deadlight_response_set_header(DeadlightResponse *response, const gchar *name, const gchar *value);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Mesh transport (deadmesh-specific)
 * ═══════════════════════════════════════════════════════════ */

gboolean deadlight_mesh_init(DeadlightContext *context, GError **error);
void     deadlight_mesh_cleanup(DeadlightContext *context);
gboolean deadlight_mesh_connect(DeadlightMeshManager *mesh, GError **error);
void     deadlight_mesh_disconnect(DeadlightMeshManager *mesh);

/* Fragmentation / reassembly */
gboolean deadlight_mesh_send(DeadlightMeshManager *mesh, guint32 dest_node, const guint8 *data, gsize len, GError **error);
gssize   deadlight_mesh_recv(DeadlightMeshManager *mesh, guint32 *out_src_node, guint8 *buf, gsize buf_len, GError **error);

/* Stats */
void     deadlight_mesh_get_stats(DeadlightMeshManager *mesh,
                                   guint64 *packets_sent, guint64 *packets_received,
                                   guint64 *packets_lost,  guint64 *sessions_active);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Connection pool
 * ═══════════════════════════════════════════════════════════ */

ConnectionPool *connection_pool_new(gint max_per_host, gint idle_timeout, gint max_total_idle,
                                    const gchar *eviction_policy, gint health_check_interval, gboolean reuse_ssl);
void            connection_pool_free(ConnectionPool *pool);
GIOStream      *connection_pool_get(ConnectionPool *pool, const gchar *host, guint16 port, ConnectionType type);
void            connection_pool_release(ConnectionPool *pool, GIOStream *stream, const gchar *host, guint16 port, ConnectionType type);
gboolean        connection_pool_register(ConnectionPool *pool, GIOStream *stream, const gchar *host, guint16 port, ConnectionType type);
gboolean        connection_pool_upgrade_to_tls(ConnectionPool *pool, GIOStream *plain_stream, GIOStream *tls_stream, const gchar *host, guint16 port);
void            connection_pool_get_stats(ConnectionPool *pool, guint *idle_count, guint *active_count,
                                          guint64 *total_gets, guint64 *cache_hits, gdouble *hit_rate,
                                          guint64 *evicted, guint64 *failed);

/* ═══════════════════════════════════════════════════════════
 * API prototypes — Testing & utilities
 * ═══════════════════════════════════════════════════════════ */

gboolean     deadlight_test_module(const gchar *module_name);
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol);
gchar       *deadlight_format_bytes(guint64 bytes);

#ifdef __cplusplus
}
#endif
#endif /* DEADMESH_H */