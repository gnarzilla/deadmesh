/**
 * deadmesh (meshtastic.deadlight) v1.0 - Configuration Management
 *
 * GKeyFile-based configuration with caching, validation,
 * and automatic file monitoring for live reload.
 *
 * Part of the Deadlight ecosystem: https://deadlight.boo
 *
 * Derived from proxy.deadlight/config.c — shared logic kept compatible.
 * Mesh-specific [meshtastic] defaults added below.
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "deadlight.h"

// Forward declarations
static void     config_file_changed(GFileMonitor *monitor, GFile *file, GFile *other_file,
                                    GFileMonitorEvent event_type, gpointer user_data);
static gboolean validate_config_section(DeadlightConfig *config, const gchar *section, GError **error);
static gboolean create_default_config_file(const gchar *config_path, GError **error);
static void     config_cache_clear(DeadlightConfig *config);
static void     config_update_context_values(DeadlightContext *context);
gchar          *expand_config_path(const gchar *path);

/* ─────────────────────────────────────────────────────────────
 * Error quark
 * Lives here rather than main.c so any translation unit that
 * includes deadlight.h and links config.o gets the definition.
 * ───────────────────────────────────────────────────────────── */

GQuark deadlight_error_quark(void) {
    return g_quark_from_static_string("deadmesh-error");
}

/* ─────────────────────────────────────────────────────────────
 * Default configuration table
 * ───────────────────────────────────────────────────────────── */

static const struct {
    const gchar *section;
    const gchar *key;
    const gchar *value;
    const gchar *description;
} default_config[] = {

    /* ── Core ─────────────────────────────────────────────── */
    {"core", "port",                "8080",        "Listen port for proxy connections"},
    {"core", "bind_address",        "0.0.0.0",     "IP address to bind to"},
    {"core", "max_connections",     "500",         "Maximum concurrent connections"},
    {"core", "connection_timeout",  "30",          "Connection timeout in seconds"},
    {"core", "buffer_size",         "65536",       "Buffer size for data transfer"},
    {"core", "log_level",           "info",        "Log level: error, warning, info, debug"},
    {"core", "log_file",            "",            "Log file path (empty for stdout)"},
    {"core", "worker_threads",      "4",           "Number of worker threads"},

    /* ── SSL/TLS ───────────────────────────────────────────── */
    {"ssl", "enabled",              "true",        "Enable SSL interception"},
    {"ssl", "ca_cert_file",         "~/.deadmesh/ca/ca.crt", "CA certificate file"},
    {"ssl", "ca_key_file",          "~/.deadmesh/ca/ca.key", "CA private key file"},
    {"ssl", "cert_cache_dir",       "/tmp/deadmesh_certs",   "Certificate cache directory"},
    {"ssl", "cert_cache_size",      "1000",        "Maximum cached certificates"},
    {"ssl", "cert_validity_days",   "30",          "Generated certificate validity period"},
    {"ssl", "cipher_suites",        "HIGH:!aNULL:!MD5", "Allowed cipher suites"},
    {"ssl", "protocols",            "TLSv1.2,TLSv1.3",  "Allowed SSL/TLS protocols"},

    /* ── Protocols ─────────────────────────────────────────── */
    {"protocols", "http_enabled",               "true",  "Enable HTTP support"},
    {"protocols", "https_enabled",              "true",  "Enable HTTPS support"},
    {"protocols", "socks4_enabled",             "true",  "Enable SOCKS4 support"},
    {"protocols", "socks5_enabled",             "true",  "Enable SOCKS5 support"},
    {"protocols", "connect_enabled",            "true",  "Enable HTTP CONNECT support"},
    {"protocols", "imap_enabled",               "true",  "Enable IMAP support"},
    {"protocols", "imaps_enabled",              "true",  "Enable IMAPS support"},
    {"protocols", "smtp_enabled",               "true",  "Enable SMTP support"},
    {"protocols", "protocol_detection_timeout", "5",     "Protocol detection timeout (seconds)"},

    /* ── Network ───────────────────────────────────────────── */
    {"network", "upstream_timeout",                     "120",  "Upstream connection timeout (mesh paths are slow)"},
    {"network", "keepalive_timeout",                    "600",  "Keep-alive timeout (hold connections longer over mesh)"},
    {"network", "dns_timeout",                          "5",    "DNS resolution timeout"},
    {"network", "dns_servers",                          "",     "Custom DNS servers (comma-separated)"},
    {"network", "ipv6_enabled",                         "true", "Enable IPv6 support"},
    {"network", "tcp_nodelay",                          "true", "Enable TCP_NODELAY"},
    {"network", "tcp_keepalive",                        "true", "Enable TCP keepalive"},
    {"network", "connection_pool_size",                 "5",    "Max connections per upstream host (conservative for mesh)"},
    {"network", "connection_pool_timeout",              "600",  "Idle connection timeout (seconds)"},
    {"network", "connection_pool_max_total",            "100",  "Total pool size across all hosts"},
    {"network", "connection_pool_eviction_policy",      "lru",  "Pool eviction policy: lru, fifo, none"},
    {"network", "connection_pool_health_check_interval","60",   "Connection health check interval (seconds)"},
    {"network", "connection_pool_reuse_ssl",            "true", "Reuse SSL connections from pool"},

    /* ── Meshtastic transport (deadmesh-specific) ──────────── */
    {"meshtastic", "enabled",        "true",          "Enable Meshtastic LoRa transport"},
    {"meshtastic", "serial_port",    "/dev/ttyACM0",  "Serial port for radio (USB) or /dev/ttyUSB0"},
    {"meshtastic", "baud_rate",      "115200",         "Serial baud rate"},
    {"meshtastic", "mesh_node_id",   "0x00000000",     "Local node ID (0 = auto-detect)"},
    {"meshtastic", "channel_psk",    "",               "Channel pre-shared key (base64, empty = default channel)"},
    {"meshtastic", "fragment_size",  "220",            "Max payload bytes per LoRa packet"},
    {"meshtastic", "ack_timeout",    "30000",          "ACK timeout in milliseconds"},
    {"meshtastic", "max_retries",    "3",              "Max packet retransmissions"},
    {"meshtastic", "hop_limit",      "3",              "Meshtastic hop limit (reduce for small networks)"},
    {"meshtastic", "gateway_mode",   "true",           "Announce as Internet gateway on mesh"},
    {"meshtastic", "announce_interval", "300",         "Gateway announcement interval (seconds)"},

    /* ── VPN gateway (optional) ────────────────────────────── */
    {"vpn", "enabled",       "false",      "Enable TUN/TAP VPN gateway"},
    {"vpn", "tun_device",    "tun0",       "TUN device name"},
    {"vpn", "subnet",        "10.8.0.0",   "VPN subnet"},
    {"vpn", "gateway_ip",    "10.8.0.1",   "Gateway IP on TUN interface"},
    {"vpn", "dns",           "1.1.1.1",    "DNS server pushed to VPN clients"},

    /* ── Plugins ───────────────────────────────────────────── */
    {"plugins", "enabled",        "true",                       "Enable plugin system"},
    {"plugins", "plugin_dir",     "/usr/lib/deadmesh/plugins",  "Plugin directory"},
    {"plugins", "autoload",       "logger,stats,compressor",    "Auto-load plugins"},
    {"plugins", "builtin_enabled","true",                        "Enable built-in plugins"},

    /* ── Compression plugin (high value over LoRa) ─────────── */
    {"plugin.compressor", "enabled",     "true",       "Enable compression (strongly recommended over mesh)"},
    {"plugin.compressor", "min_size",    "512",         "Minimum response size to compress (bytes)"},
    {"plugin.compressor", "algorithms",  "gzip,brotli", "Preferred compression algorithms"},

    /* ── Cache plugin ──────────────────────────────────────── */
    {"plugin.cache", "enabled",       "true",                  "Enable response caching (reduces mesh traffic)"},
    {"plugin.cache", "cache_dir",     "/tmp/deadmesh_cache",   "Cache directory"},
    {"plugin.cache", "max_size_mb",   "500",                    "Maximum cache size (MB)"},
    {"plugin.cache", "ttl_hours",     "24",                     "Default cache TTL (hours)"},
    {"plugin.cache", "cache_methods", "GET,HEAD",               "Cacheable HTTP methods"},

    /* ── Logger plugin ─────────────────────────────────────── */
    {"plugin.logger", "enabled",       "true",                      "Enable request logging"},
    {"plugin.logger", "log_requests",  "true",                      "Log HTTP requests"},
    {"plugin.logger", "log_responses", "false",                     "Log HTTP responses"},
    {"plugin.logger", "log_format",    "combined",                  "Log format: combined, common, json"},
    {"plugin.logger", "log_file",      "/var/log/deadmesh/access.log", "Access log file"},
    {"plugin.logger", "max_log_size",  "100MB",                     "Maximum log file size"},
    {"plugin.logger", "log_rotation",  "daily",                     "Log rotation: daily, weekly, size"},

    /* ── Stats plugin ──────────────────────────────────────── */
    {"plugin.stats", "enabled",       "true",  "Enable statistics collection"},
    {"plugin.stats", "stats_interval","60",    "Statistics update interval (seconds)"},
    {"plugin.stats", "history_size",  "1440",  "Statistics history size (minutes = 24h)"},
    {"plugin.stats", "web_interface", "true",  "Enable web statistics interface"},
    {"plugin.stats", "web_port",      "8081",  "Web interface port"},

    /* ── Rate limiter plugin ───────────────────────────────── */
    {"plugin.ratelimiter", "enabled",        "true",           "Enable bandwidth shaping"},
    {"plugin.ratelimiter", "priority_high",  "smtp,imap,dns",  "High-priority protocols"},
    {"plugin.ratelimiter", "priority_low",   "http_video,http_images", "Low-priority (defer to save airtime)"},

    /* ── Authentication plugin ─────────────────────────────── */
    {"plugin.auth", "enabled",      "false",   "Enable authentication"},
    {"plugin.auth", "auth_type",    "basic",   "Authentication type: basic, digest"},
    {"plugin.auth", "auth_file",    "/etc/deadmesh/users.txt", "Authentication file"},
    {"plugin.auth", "auth_realm",   "deadmesh", "Authentication realm"},
    {"plugin.auth", "require_auth", "false",   "Require authentication for all requests"},

    /* ── Security ──────────────────────────────────────────── */
    {"security", "enable_security_headers", "true",  "Add security headers to responses"},
    {"security", "block_private_ips",       "false", "Block requests to private IPs"},
    {"security", "allowed_domains",         "",      "Allowed domains (whitelist, empty = all)"},
    {"security", "blocked_domains",         "",      "Blocked domains (blacklist)"},
    {"security", "max_request_size",        "10MB",  "Maximum request size"},
    {"security", "max_header_size",         "8KB",   "Maximum header size"},
    {"security", "auth_secret",             "",      "API authentication secret (HMAC)"},

    {NULL, NULL, NULL, NULL}
};

/* ─────────────────────────────────────────────────────────────
 * Path utilities
 * ───────────────────────────────────────────────────────────── */

/**
 * Expand ~ to the user's home directory.
 */
gchar *expand_config_path(const gchar *path) {
    if (!path || strlen(path) == 0) {
        return g_strdup("");
    }

    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const gchar *home = g_get_home_dir();
        if (home) {
            return g_build_filename(home, path + 1, NULL);
        }
    }

    return g_strdup(path);
}

/* ─────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────── */

/**
 * Check whether a section exists in the loaded config.
 */
gboolean deadlight_config_has_section(DeadlightContext *context, const gchar *section) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->config != NULL, FALSE);
    g_return_val_if_fail(section != NULL, FALSE);

    g_mutex_lock(&context->config->cache_mutex);
    gboolean result = g_key_file_has_group(context->config->keyfile, section);
    g_mutex_unlock(&context->config->cache_mutex);

    return result;
}

/**
 * Cross-section configuration validation.
 * Called after load; also usable at runtime for sanity checks.
 */
gboolean deadlight_config_validate(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->config != NULL, FALSE);

    // Required sections
    const gchar *required_sections[] = {"core", "ssl", NULL};
    for (int i = 0; required_sections[i]; i++) {
        if (!g_key_file_has_group(context->config->keyfile, required_sections[i])) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Missing required config section: [%s]", required_sections[i]);
            return FALSE;
        }
    }

    // Port range
    gint port;
    g_mutex_lock(&context->config->cache_mutex);
    port = g_key_file_get_integer(context->config->keyfile, "core", "port", NULL);
    g_mutex_unlock(&context->config->cache_mutex);

    if (port <= 0 || port > 65535) {
        g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                    "Invalid port in [core]: %d (must be 1-65535)", port);
        return FALSE;
    }

    // SSL cert files if interception is on
    GError *local_error = NULL;
    gboolean ssl_enabled;

    g_mutex_lock(&context->config->cache_mutex);
    ssl_enabled = g_key_file_get_boolean(context->config->keyfile, "ssl", "enabled", &local_error);
    g_mutex_unlock(&context->config->cache_mutex);

    if (local_error) {
        g_error_free(local_error);
        ssl_enabled = FALSE;
    }

    if (ssl_enabled) {
        gchar *ca_cert, *ca_key;

        g_mutex_lock(&context->config->cache_mutex);
        ca_cert = g_key_file_get_string(context->config->keyfile, "ssl", "ca_cert_file", NULL);
        ca_key  = g_key_file_get_string(context->config->keyfile, "ssl", "ca_key_file",  NULL);
        g_mutex_unlock(&context->config->cache_mutex);

        gboolean missing_cert = (!ca_cert || strlen(ca_cert) == 0);
        gboolean missing_key  = (!ca_key  || strlen(ca_key)  == 0);

        if (missing_cert || missing_key) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "SSL interception enabled but missing %s%s%s",
                        missing_cert ? "ca_cert_file" : "",
                        (missing_cert && missing_key) ? " and " : "",
                        missing_key  ? "ca_key_file"  : "");
            g_free(ca_cert);
            g_free(ca_key);
            return FALSE;
        }

        gchar *expanded_cert = expand_config_path(ca_cert);
        gchar *expanded_key  = expand_config_path(ca_key);

        if (access(expanded_cert, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Cannot read CA cert file: %s", expanded_cert);
            g_free(expanded_cert); g_free(expanded_key);
            g_free(ca_cert);       g_free(ca_key);
            return FALSE;
        }

        if (access(expanded_key, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Cannot read CA key file: %s", expanded_key);
            g_free(expanded_cert); g_free(expanded_key);
            g_free(ca_cert);       g_free(ca_key);
            return FALSE;
        }

        g_free(expanded_cert); g_free(expanded_key);
        g_free(ca_cert);       g_free(ca_key);
    }

    // Mesh transport validation (if section present)
    if (deadlight_config_has_section(context, "meshtastic")) {
        gboolean mesh_enabled;
        g_mutex_lock(&context->config->cache_mutex);
        mesh_enabled = g_key_file_get_boolean(context->config->keyfile,
                                              "meshtastic", "enabled", NULL);
        g_mutex_unlock(&context->config->cache_mutex);

        if (mesh_enabled) {
            gchar *serial_port;
            g_mutex_lock(&context->config->cache_mutex);
            serial_port = g_key_file_get_string(context->config->keyfile,
                                                "meshtastic", "serial_port", NULL);
            g_mutex_unlock(&context->config->cache_mutex);

            if (!serial_port || strlen(serial_port) == 0) {
                g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                            "[meshtastic] enabled but serial_port not set");
                g_free(serial_port);
                return FALSE;
            }
            g_free(serial_port);

            gint frag_size;
            g_mutex_lock(&context->config->cache_mutex);
            frag_size = g_key_file_get_integer(context->config->keyfile,
                                               "meshtastic", "fragment_size", NULL);
            g_mutex_unlock(&context->config->cache_mutex);

            if (frag_size <= 0 || frag_size > 240) {
                g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                            "[meshtastic] fragment_size must be 1-240, got %d", frag_size);
                return FALSE;
            }
        }
    }

    // Connection pool sanity
    if (deadlight_config_has_section(context, "network")) {
        gint pool_size, idle_timeout;

        g_mutex_lock(&context->config->cache_mutex);
        pool_size    = g_key_file_get_integer(context->config->keyfile, "network",
                                              "connection_pool_size",    NULL);
        idle_timeout = g_key_file_get_integer(context->config->keyfile, "network",
                                              "connection_pool_timeout", NULL);
        g_mutex_unlock(&context->config->cache_mutex);

        if (pool_size <= 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "[network] connection_pool_size must be > 0, got %d", pool_size);
            return FALSE;
        }

        if (idle_timeout < 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "[network] connection_pool_timeout must be >= 0, got %d", idle_timeout);
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Load configuration from file.
 * Creates a default config if the file doesn't exist.
 */
gboolean deadlight_config_load(DeadlightContext *context, const gchar *config_file, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);

    // Clean up any existing config
    if (context->config) {
        deadlight_config_free(context);
    }

    // Free context strings that will be repopulated
    g_clear_pointer(&context->listen_address,      g_free);
    g_clear_pointer(&context->pool_eviction_policy, g_free);
    g_clear_pointer(&context->auth_secret,          g_free);
    g_clear_pointer(&context->auth_endpoint,        g_free);

    // Allocate new config structure
    context->config = g_new0(DeadlightConfig, 1);
    context->config->keyfile      = g_key_file_new();
    context->config->string_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    context->config->int_cache    = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    context->config->bool_cache   = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_mutex_init(&context->config->cache_mutex);

    const gchar *config_path = config_file ? config_file : DEADLIGHT_DEFAULT_CONFIG_FILE;
    context->config->config_path = g_strdup(config_path);

    // Auto-create default config if missing
    if (!g_file_test(config_path, G_FILE_TEST_EXISTS)) {
        g_info("Config file %s not found — creating default", config_path);
        if (!create_default_config_file(config_path, error)) {
            return FALSE;
        }
    }

    // Load
    g_mutex_lock(&context->config->cache_mutex);
    gboolean ok = g_key_file_load_from_file(context->config->keyfile, config_path,
                                             G_KEY_FILE_KEEP_COMMENTS |
                                             G_KEY_FILE_KEEP_TRANSLATIONS,
                                             error);
    g_mutex_unlock(&context->config->cache_mutex);

    if (!ok) {
        g_prefix_error(error, "Failed to load config %s: ", config_path);
        return FALSE;
    }

    // Per-section validation
    g_mutex_lock(&context->config->cache_mutex);
    gchar **groups = g_key_file_get_groups(context->config->keyfile, NULL);
    g_mutex_unlock(&context->config->cache_mutex);

    for (gchar **group = groups; *group; group++) {
        if (!validate_config_section(context->config, *group, error)) {
            g_strfreev(groups);
            return FALSE;
        }
    }
    g_strfreev(groups);

    // Set up live-reload file monitor
    GFile *file = g_file_new_for_path(config_path);
    context->config->file_monitor = g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, error);
    g_object_unref(file);

    if (context->config->file_monitor) {
        g_signal_connect(context->config->file_monitor, "changed",
                         G_CALLBACK(config_file_changed), context);
        g_info("Config file monitoring enabled");
    } else {
        g_warning("Config file monitoring unavailable: %s",
                  (error && *error) ? (*error)->message : "unknown");
        if (error) g_clear_error(error);
    }

    config_update_context_values(context);

    g_info("Configuration loaded from %s", config_path);
    return TRUE;
}

/**
 * Save current in-memory configuration back to disk.
 */
gboolean deadlight_config_save(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->config != NULL, FALSE);

    g_mutex_lock(&context->config->cache_mutex);
    gchar *data = g_key_file_to_data(context->config->keyfile, NULL, error);
    g_mutex_unlock(&context->config->cache_mutex);

    if (!data) return FALSE;

    gboolean result = g_file_set_contents(context->config->config_path, data, -1, error);
    g_free(data);

    if (result) g_info("Configuration saved to %s", context->config->config_path);
    return result;
}

/* ─────────────────────────────────────────────────────────────
 * Typed getters / setters
 * ───────────────────────────────────────────────────────────── */

gint deadlight_config_get_int(DeadlightContext *context, const gchar *section,
                               const gchar *key, gint default_value) {
    g_return_val_if_fail(context && context->config, default_value);

    g_mutex_lock(&context->config->cache_mutex);

    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    gpointer cached  = g_hash_table_lookup(context->config->int_cache, cache_key);

    if (cached) {
        gint val = GPOINTER_TO_INT(cached);
        g_mutex_unlock(&context->config->cache_mutex);
        g_free(cache_key);
        return val;
    }

    GError *err = NULL;
    gint val = g_key_file_get_integer(context->config->keyfile, section, key, &err);
    if (err) { g_error_free(err); val = default_value; }

    g_hash_table_insert(context->config->int_cache, cache_key, GINT_TO_POINTER(val));
    g_mutex_unlock(&context->config->cache_mutex);
    return val;
}

gchar *deadlight_config_get_string(DeadlightContext *context, const gchar *section,
                                    const gchar *key, const gchar *default_value) {
    g_return_val_if_fail(context && context->config, g_strdup(default_value));

    g_mutex_lock(&context->config->cache_mutex);

    gchar *cache_key   = g_strdup_printf("%s.%s", section, key);
    const gchar *cached = g_hash_table_lookup(context->config->string_cache, cache_key);

    if (cached) {
        gchar *result = g_strdup(cached);
        g_mutex_unlock(&context->config->cache_mutex);
        g_free(cache_key);
        return result;
    }

    GError *err  = NULL;
    gchar  *val  = g_key_file_get_string(context->config->keyfile, section, key, &err);
    if (err) { g_error_free(err); val = g_strdup(default_value); }

    g_hash_table_insert(context->config->string_cache, cache_key, g_strdup(val));
    g_mutex_unlock(&context->config->cache_mutex);
    return val;
}

gboolean deadlight_config_get_bool(DeadlightContext *context, const gchar *section,
                                    const gchar *key, gboolean default_value) {
    g_return_val_if_fail(context && context->config, default_value);

    g_mutex_lock(&context->config->cache_mutex);

    gchar   *cache_key = g_strdup_printf("%s.%s", section, key);
    gpointer cached    = g_hash_table_lookup(context->config->bool_cache, cache_key);

    if (cached) {
        gboolean val = GPOINTER_TO_INT(cached);
        g_mutex_unlock(&context->config->cache_mutex);
        g_free(cache_key);
        return val;
    }

    GError  *err = NULL;
    gboolean val = g_key_file_get_boolean(context->config->keyfile, section, key, &err);
    if (err) { g_error_free(err); val = default_value; }

    g_hash_table_insert(context->config->bool_cache, cache_key, GINT_TO_POINTER(val));
    g_mutex_unlock(&context->config->cache_mutex);
    return val;
}

void deadlight_config_set_int(DeadlightContext *context, const gchar *section,
                               const gchar *key, gint value) {
    g_return_if_fail(context && context->config);

    g_mutex_lock(&context->config->cache_mutex);
    g_key_file_set_integer(context->config->keyfile, section, key, value);
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->int_cache, cache_key, GINT_TO_POINTER(value));
    g_mutex_unlock(&context->config->cache_mutex);
}

void deadlight_config_set_string(DeadlightContext *context, const gchar *section,
                                  const gchar *key, const gchar *value) {
    g_return_if_fail(context && context->config);

    g_mutex_lock(&context->config->cache_mutex);
    g_key_file_set_string(context->config->keyfile, section, key, value);
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->string_cache, cache_key, g_strdup(value));
    g_mutex_unlock(&context->config->cache_mutex);
}

void deadlight_config_set_bool(DeadlightContext *context, const gchar *section,
                                const gchar *key, gboolean value) {
    g_return_if_fail(context && context->config);

    g_mutex_lock(&context->config->cache_mutex);
    g_key_file_set_boolean(context->config->keyfile, section, key, value);
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->bool_cache, cache_key, GINT_TO_POINTER(value));
    g_mutex_unlock(&context->config->cache_mutex);
}

/**
 * Parse human-readable size strings: "1GB", "512MB", "64KB", plain integer bytes.
 */
guint64 deadlight_config_get_size(DeadlightContext *context, const gchar *section,
                                   const gchar *key, guint64 default_value) {
    g_return_val_if_fail(context != NULL, default_value);

    gchar *value_str = deadlight_config_get_string(context, section, key, NULL);
    if (!value_str) return default_value;

    gchar  *endptr;
    guint64 size = g_ascii_strtoull(value_str, &endptr, 10);

    if (endptr && *endptr) {
        switch (g_ascii_toupper(*endptr)) {
            case 'K': size *= 1024ULL;                    break;
            case 'M': size *= 1024ULL * 1024;             break;
            case 'G': size *= 1024ULL * 1024 * 1024;      break;
            case 'T': size *= 1024ULL * 1024 * 1024 * 1024; break;
            default:
                g_warning("Unknown size suffix '%c' in [%s] %s", *endptr, section, key);
                size = default_value;
        }
    }

    g_free(value_str);
    return size;
}

/* ─────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────── */

/**
 * GFileMonitor callback — reloads config on disk change.
 */
static void config_file_changed(GFileMonitor *monitor, GFile *file, GFile *other_file,
                                 GFileMonitorEvent event_type, gpointer user_data) {
    (void)monitor; (void)file; (void)other_file;

    DeadlightContext *context = (DeadlightContext *)user_data;

    if (event_type != G_FILE_MONITOR_EVENT_CHANGED &&
        event_type != G_FILE_MONITOR_EVENT_CREATED) {
        return;
    }

    g_info("Config file changed — reloading...");

    GError *error = NULL;
    g_mutex_lock(&context->config->cache_mutex);
    gboolean ok = g_key_file_load_from_file(context->config->keyfile,
                                             context->config->config_path,
                                             G_KEY_FILE_KEEP_COMMENTS |
                                             G_KEY_FILE_KEEP_TRANSLATIONS,
                                             &error);
    g_mutex_unlock(&context->config->cache_mutex);

    if (!ok) {
        g_warning("Failed to reload config: %s", error->message);
        g_error_free(error);
    }

    // Always clear caches — forces fresh reads even on partial reload failure
    config_cache_clear(context->config);

    if (ok) {
        config_update_context_values(context);

        if (context->plugins) {
            g_info("Notifying plugins of config change");
            // deadlight_plugins_call_on_config_change() called per-key from here
            // when plugin reload support is wired in
        }

        g_info("Config reloaded successfully");
    }
}

/**
 * Per-section structural validation (called during load).
 */
static gboolean validate_config_section(DeadlightConfig *config, const gchar *section, GError **error) {
    if (!section || strlen(section) == 0) {
        g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                    "Empty section name");
        return FALSE;
    }

    if (g_strcmp0(section, "core") == 0) {
        if (!g_key_file_has_key(config->keyfile, section, "port", NULL)) {
            // Missing port — insert default silently
            g_key_file_set_integer(config->keyfile, section, "port", DEADLIGHT_DEFAULT_PORT);
        }
    }

    if (g_strcmp0(section, "network") == 0) {
        gint pool_size    = g_key_file_get_integer(config->keyfile, section, "connection_pool_size",    NULL);
        gint idle_timeout = g_key_file_get_integer(config->keyfile, section, "connection_pool_timeout", NULL);

        if (pool_size <= 0) {
            g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                        "[network] connection_pool_size must be > 0");
            return FALSE;
        }

        if (idle_timeout < 0) {
            g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                        "[network] connection_pool_timeout must be >= 0");
            return FALSE;
        }
    }

    if (g_strcmp0(section, "meshtastic") == 0) {
        gint frag = g_key_file_get_integer(config->keyfile, section, "fragment_size", NULL);
        if (frag != 0 && (frag <= 0 || frag > 240)) {
            g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                        "[meshtastic] fragment_size must be 1-240, got %d", frag);
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Create a well-commented default config file on first run.
 */
static gboolean create_default_config_file(const gchar *config_path, GError **error) {
    GKeyFile *keyfile = g_key_file_new();

    gchar *config_dir = g_path_get_dirname(config_path);
    if (g_mkdir_with_parents(config_dir, 0755) != 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Cannot create config directory %s: %s",
                    config_dir, g_strerror(errno));
        g_free(config_dir);
        g_key_file_free(keyfile);
        return FALSE;
    }
    g_free(config_dir);

    for (int i = 0; default_config[i].section; i++) {
        g_key_file_set_string(keyfile,
                              default_config[i].section,
                              default_config[i].key,
                              default_config[i].value);
        g_key_file_set_comment(keyfile,
                               default_config[i].section,
                               default_config[i].key,
                               default_config[i].description, NULL);
    }

    gchar *data = g_key_file_to_data(keyfile, NULL, error);
    if (!data) { g_key_file_free(keyfile); return FALSE; }

    gboolean result = g_file_set_contents(config_path, data, -1, error);
    g_free(data);
    g_key_file_free(keyfile);

    if (result) g_info("Default config created at %s", config_path);
    return result;
}

/**
 * Sync hot-cached values from the keyfile onto the context struct.
 * Called after initial load and on every live reload.
 */
static void config_update_context_values(DeadlightContext *context) {
    // Core
    context->listen_port    = deadlight_config_get_int(context, "core", "port", DEADLIGHT_DEFAULT_PORT);
    context->max_connections = deadlight_config_get_int(context, "core", "max_connections",
                                                        DEADLIGHT_DEFAULT_MAX_CONNECTIONS);
    g_free(context->listen_address);
    context->listen_address = deadlight_config_get_string(context, "core", "bind_address", "0.0.0.0");

    // Connection pool
    context->pool_max_per_host           = deadlight_config_get_int(context, "network", "connection_pool_size", 5);
    context->pool_idle_timeout           = deadlight_config_get_int(context, "network", "connection_pool_timeout", 600);
    context->pool_max_total              = deadlight_config_get_int(context, "network", "connection_pool_max_total", 100);
    context->pool_health_check_interval  = deadlight_config_get_int(context, "network", "connection_pool_health_check_interval", 60);
    context->pool_reuse_ssl              = deadlight_config_get_bool(context, "network", "connection_pool_reuse_ssl", TRUE);

    g_free(context->pool_eviction_policy);
    context->pool_eviction_policy = deadlight_config_get_string(context, "network",
                                                                 "connection_pool_eviction_policy", "lru");

    // Log level
    gchar *log_level = deadlight_config_get_string(context, "core", "log_level", DEADLIGHT_DEFAULT_LOG_LEVEL);
    if      (g_strcmp0(log_level, "error")   == 0) context->log_level = DEADLIGHT_LOG_ERROR;
    else if (g_strcmp0(log_level, "warning") == 0) context->log_level = DEADLIGHT_LOG_WARNING;
    else if (g_strcmp0(log_level, "debug")   == 0) context->log_level = DEADLIGHT_LOG_DEBUG;
    else                                            context->log_level = DEADLIGHT_LOG_INFO;
    g_free(log_level);

    // SSL
    context->ssl_intercept_enabled = deadlight_config_get_bool(context, "ssl", "enabled", TRUE);

    // Auth secret
    g_mutex_lock(&context->config_values_mutex);
    g_free(context->auth_secret);
    context->auth_secret = deadlight_config_get_string(context, "security", "auth_secret", NULL);
    if (context->auth_secret && strlen(context->auth_secret) > 0) {
        g_info("API auth_secret loaded (%zu chars)", strlen(context->auth_secret));
    } else {
        g_warning("No auth_secret configured in [security] — /api/outbound/email will reject all requests");
        g_free(context->auth_secret);
        context->auth_secret = NULL;
    }
    g_mutex_unlock(&context->config_values_mutex);

    // Mesh manager — update live fields if mesh is already initialised
    if (context->mesh) {
        context->mesh->fragment_size  = (gsize)deadlight_config_get_int(context, "meshtastic",
                                                                         "fragment_size",
                                                                         DEADMESH_DEFAULT_FRAGMENT_SIZE);
        context->mesh->ack_timeout_ms = (guint)deadlight_config_get_int(context, "meshtastic",
                                                                          "ack_timeout",
                                                                          DEADMESH_DEFAULT_ACK_TIMEOUT_MS);
        context->mesh->max_retries    = (guint)deadlight_config_get_int(context, "meshtastic",
                                                                          "max_retries",
                                                                          DEADMESH_DEFAULT_MAX_RETRIES);
        context->mesh->hop_limit      = (guint)deadlight_config_get_int(context, "meshtastic",
                                                                          "hop_limit",
                                                                          DEADMESH_DEFAULT_HOP_LIMIT);
    }

    g_info("Config applied: port=%d pool=%d ssl=%s mesh_frag=%zu",
           context->listen_port,
           context->pool_max_per_host,
           context->ssl_intercept_enabled ? "on" : "off",
           context->mesh ? context->mesh->fragment_size : (gsize)DEADMESH_DEFAULT_FRAGMENT_SIZE);
}

/**
 * Clear all three caches (call under external lock or within reload path).
 */
static void config_cache_clear(DeadlightConfig *config) {
    g_mutex_lock(&config->cache_mutex);
    g_hash_table_remove_all(config->string_cache);
    g_hash_table_remove_all(config->int_cache);
    g_hash_table_remove_all(config->bool_cache);
    g_mutex_unlock(&config->cache_mutex);
}

/**
 * Free all config resources. Safe to call multiple times.
 */
void deadlight_config_free(DeadlightContext *context) {
    if (!context || !context->config) return;

    DeadlightConfig *config = context->config;

    if (config->file_monitor) {
        g_file_monitor_cancel(config->file_monitor);
        g_object_unref(config->file_monitor);
        config->file_monitor = NULL;
    }

    g_mutex_lock(&config->cache_mutex);
    g_clear_pointer(&config->string_cache, g_hash_table_unref);
    g_clear_pointer(&config->int_cache,    g_hash_table_unref);
    g_clear_pointer(&config->bool_cache,   g_hash_table_unref);
    g_clear_pointer(&config->keyfile,      g_key_file_free);
    g_mutex_unlock(&config->cache_mutex);

    g_mutex_clear(&config->cache_mutex);
    g_clear_pointer(&config->config_path, g_free);
    g_free(config);
    context->config = NULL;
}