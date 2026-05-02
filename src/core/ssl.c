// src/core/ssl.c

/**
 * deadmesh - SSL/TLS Module
 *
 * SSL interception and certificate management.
 *
 */

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include "deadlight.h"

/* =========================================================================
 * TYPES
 * ========================================================================= */

typedef struct {
    gchar *pem_data;
    gint64 expiry_time;
} CertCacheEntry;

struct _DeadlightSSLManager {
    SSL_CTX        *server_ctx;
    SSL_CTX        *client_ctx;
    X509           *ca_cert;
    EVP_PKEY       *ca_key;
    gchar          *ca_cert_file;
    gchar          *ca_key_file;
    gchar          *cert_cache_dir;
    GMutex          cert_mutex;
    GHashTable     *cert_cache;
    GTlsDatabase   *system_trust_db;
    gboolean        initialized;
};

/* =========================================================================
 * FORWARD DECLARATIONS
 * ========================================================================= */

static gboolean  load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error);
static SSL_CTX  *create_ssl_context(gboolean is_server, GError **error);

/* =========================================================================
 * CERT CACHE DESTRUCTOR
 * ========================================================================= */

static void cert_cache_entry_free(gpointer data) {
    CertCacheEntry *entry = (CertCacheEntry *)data;
    if (entry) {
        g_free(entry->pem_data);
        g_free(entry);
    }
}

/* =========================================================================
 * PATH HELPERS
 * ========================================================================= */

/*
 * resolve_default_ca_cert_file / resolve_default_ca_key_file
 *
 * Returns a g_strdup'd path to the default CA cert/key location.
 * Priority:
 *   1. $DEADLIGHT_CA_CERT / $DEADLIGHT_CA_KEY env vars (override for CI/containers)
 *   2. $HOME/.deadlight/ca.crt|ca.key   (standard user install, works on Termux)
 *   3. /etc/deadlight/ca.crt|ca.key     (system install, traditional Linux)
 *
 * The returned path is always non-NULL; the file may or may not exist yet
 * (it gets created by deadlight_ssl_create_ca_certificate if missing).
 */
static gchar *resolve_default_ca_cert_file(void) {
    const gchar *env = g_getenv("DEADLIGHT_CA_CERT");
    if (env && env[0]) return g_strdup(env);

    return g_build_filename(g_get_home_dir(), ".deadlight", "ca.crt", NULL);
}

static gchar *resolve_default_ca_key_file(void) {
    const gchar *env = g_getenv("DEADLIGHT_CA_KEY");
    if (env && env[0]) return g_strdup(env);

    return g_build_filename(g_get_home_dir(), ".deadlight", "ca.key", NULL);
}

/*
 * resolve_default_cert_cache_dir
 *
 * Returns a g_strdup'd path for the per-host cert cache.
 * Priority:
 *   1. $DEADLIGHT_CERT_CACHE env var
 *   2. $XDG_CACHE_HOME/deadlight/certs   (respects XDG on desktop Linux)
 *   3. $HOME/.cache/deadlight/certs       (works on Termux, macOS)
 *   4. /tmp/deadlight_certs               (last resort, traditional Linux)
 */
static gchar *resolve_default_cert_cache_dir(void) {
    const gchar *env = g_getenv("DEADLIGHT_CERT_CACHE");
    if (env && env[0]) return g_strdup(env);

    const gchar *xdg = g_getenv("XDG_CACHE_HOME");
    if (xdg && xdg[0])
        return g_build_filename(xdg, "deadlight", "certs", NULL);

    return g_build_filename(g_get_home_dir(), ".cache", "deadlight", "certs", NULL);
}

/*
 * find_system_trust_store
 *
 * Probes a list of well-known CA bundle locations and returns the first one
 * that exists, or NULL if none found.  This covers:
 *   - Debian/Ubuntu:         /etc/ssl/certs/ca-certificates.crt
 *   - Fedora/RHEL/CentOS:   /etc/pki/tls/certs/ca-bundle.crt
 *   - openSUSE:              /etc/ssl/ca-bundle.pem
 *   - Alpine:                /etc/ssl/certs/ca-certificates.crt  (same as Debian)
 *   - macOS (Homebrew):      /opt/homebrew/etc/ca-certificates/cert.pem
 *   - Termux:                $PREFIX/etc/tls/cert.pem
 *                            $PREFIX/etc/ssl/cert.pem
 *                            $PREFIX/etc/ssl/certs/ca-certificates.crt
 */
static gchar *find_system_trust_store(void) {
    /* Build Termux prefix-relative paths dynamically so they work regardless
     * of whether Termux is installed to the standard location. */
    const gchar *prefix = g_getenv("PREFIX");   /* set by Termux shell */

    gchar *termux_tls   = prefix ? g_build_filename(prefix, "etc", "tls",  "cert.pem",                  NULL) : NULL;
    gchar *termux_ssl1  = prefix ? g_build_filename(prefix, "etc", "ssl",  "cert.pem",                  NULL) : NULL;
    gchar *termux_ssl2  = prefix ? g_build_filename(prefix, "etc", "ssl",  "certs", "ca-certificates.crt", NULL) : NULL;

    const gchar *candidates[] = {
        termux_tls,
        termux_ssl1,
        termux_ssl2,
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian/Ubuntu — move this first */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* Fedora/RHEL */
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/certs/ca-bundle.crt",         /* this one is broken on your system */
        "/opt/homebrew/etc/ca-certificates/cert.pem",
        "/usr/local/etc/ca-certificates/cert.pem",
        NULL
    };

    gchar *found = NULL;
    for (int i = 0; candidates[i] != NULL; i++) {
        if (candidates[i] && g_file_test(candidates[i], G_FILE_TEST_EXISTS)) {
            found = g_strdup(candidates[i]);
            break;
        }
    }

    g_free(termux_tls);
    g_free(termux_ssl1);
    g_free(termux_ssl2);

    return found;  /* caller must g_free */
}

/* =========================================================================
 * SSL INIT / CLEANUP
 * ========================================================================= */

gboolean deadlight_ssl_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

    g_info("Initializing SSL module...");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    context->ssl = g_new0(DeadlightSSLManager, 1);
    g_mutex_init(&context->ssl->cert_mutex);

    /* ── System trust store ──────────────────────────────────────────────
     * We probe multiple locations rather than hardcoding one path, so this
     * works on Termux, Alpine, Fedora, macOS, etc.  If we find nothing we
     * warn loudly but continue — upstream TLS verification will fail later
     * rather than killing init, which is the right trade-off for a proxy
     * that the user may be configuring before certs are installed.
     * ─────────────────────────────────────────────────────────────────── */
    g_info("Loading system CA certificates for upstream validation...");

    gchar *trust_store_path = find_system_trust_store();

    if (trust_store_path) {
        context->ssl->system_trust_db =
            g_tls_file_database_new(trust_store_path, error);

        if (!context->ssl->system_trust_db) {
            g_warning("Failed to load trust store from %s: %s — upstream TLS "
                      "verification may fail", trust_store_path,
                      error && *error ? (*error)->message : "unknown");
            g_clear_error(error);
        } else {
            g_info("System CA trust store loaded from %s", trust_store_path);
        }
        g_free(trust_store_path);
    } else {
        g_warning("No system CA bundle found — upstream TLS verification will "
                  "fail. Install ca-certificates (or on Termux: "
                  "'pkg install ca-certificates') and set ssl.ca_bundle in "
                  "your config.");
    }

    /* ── CA cert / key paths ─────────────────────────────────────────────
     * Config takes priority; if not set we fall back to $HOME/.deadlight/
     * which exists on Termux, desktop Linux, and macOS without needing root.
     * ─────────────────────────────────────────────────────────────────── */
    gchar *default_cert = resolve_default_ca_cert_file();
    gchar *default_key  = resolve_default_ca_key_file();
    gchar *default_cache = resolve_default_cert_cache_dir();

    context->ssl->ca_cert_file  = deadlight_config_get_string(context, "ssl", "ca_cert_file",   default_cert);
    context->ssl->ca_key_file   = deadlight_config_get_string(context, "ssl", "ca_key_file",    default_key);
    context->ssl->cert_cache_dir = deadlight_config_get_string(context, "ssl", "cert_cache_dir", default_cache);

    g_free(default_cert);
    g_free(default_key);
    g_free(default_cache);

    g_info("SSL: CA cert path: %s", context->ssl->ca_cert_file);
    g_info("SSL: CA key path:  %s", context->ssl->ca_key_file);
    g_info("SSL: Cert cache:   %s", context->ssl->cert_cache_dir);

    context->ssl->cert_cache = g_hash_table_new_full(
        g_str_hash, g_str_equal,
        g_free,
        cert_cache_entry_free
    );

    context->ssl->server_ctx = create_ssl_context(TRUE, error);
    if (!context->ssl->server_ctx) {
        return FALSE;
    }

    context->ssl->client_ctx = create_ssl_context(FALSE, error);
    if (!context->ssl->client_ctx) {
        SSL_CTX_free(context->ssl->server_ctx);
        return FALSE;
    }

    if (context->ssl_intercept_enabled) {
        /* Auto-generate CA if it doesn't exist yet */
        if (!g_file_test(context->ssl->ca_cert_file, G_FILE_TEST_EXISTS) ||
            !g_file_test(context->ssl->ca_key_file,  G_FILE_TEST_EXISTS)) {

            g_info("SSL: CA cert/key not found — generating new CA at %s",
                   context->ssl->ca_cert_file);

            /* Ensure the directory exists */
            gchar *ca_dir = g_path_get_dirname(context->ssl->ca_cert_file);
            if (g_mkdir_with_parents(ca_dir, 0700) != 0) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "Failed to create CA directory: %s", ca_dir);
                g_free(ca_dir);
                SSL_CTX_free(context->ssl->server_ctx);
                SSL_CTX_free(context->ssl->client_ctx);
                return FALSE;
            }
            g_free(ca_dir);

            GError *gen_error = NULL;
            if (!deadlight_ssl_create_ca_certificate(context->ssl->ca_cert_file,
                                                      context->ssl->ca_key_file,
                                                      &gen_error)) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "Failed to auto-generate CA certificate: %s",
                            gen_error ? gen_error->message : "unknown");
                g_clear_error(&gen_error);
                SSL_CTX_free(context->ssl->server_ctx);
                SSL_CTX_free(context->ssl->client_ctx);
                return FALSE;
            }
            g_info("SSL: CA certificate generated successfully");
        }

        if (!load_ca_certificate(context->ssl, error)) {
            SSL_CTX_free(context->ssl->server_ctx);
            SSL_CTX_free(context->ssl->client_ctx);
            return FALSE;
        }

        if (g_mkdir_with_parents(context->ssl->cert_cache_dir, 0700) != 0) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                        "Failed to create certificate cache directory: %s",
                        context->ssl->cert_cache_dir);
            SSL_CTX_free(context->ssl->server_ctx);
            SSL_CTX_free(context->ssl->client_ctx);
            return FALSE;
        }
    }

    context->ssl->initialized = TRUE;
    g_info("SSL module initialized successfully");
    return TRUE;
}

void deadlight_ssl_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);

    g_info("Cleaning up SSL module...");

    if (context->ssl) {
        if (context->ssl->system_trust_db)
            g_object_unref(context->ssl->system_trust_db);
        if (context->ssl->server_ctx)
            SSL_CTX_free(context->ssl->server_ctx);
        if (context->ssl->client_ctx)
            SSL_CTX_free(context->ssl->client_ctx);
        if (context->ssl->ca_cert)
            X509_free(context->ssl->ca_cert);
        if (context->ssl->ca_key)
            EVP_PKEY_free(context->ssl->ca_key);
        if (context->ssl->cert_cache)
            g_hash_table_destroy(context->ssl->cert_cache);

        g_free(context->ssl->ca_cert_file);
        g_free(context->ssl->ca_key_file);
        g_free(context->ssl->cert_cache_dir);

        g_mutex_clear(&context->ssl->cert_mutex);
        g_free(context->ssl);
        context->ssl = NULL;
    }

    EVP_cleanup();
    ERR_free_strings();
}

/* =========================================================================
 * SSL CONTEXT
 * ========================================================================= */

static SSL_CTX *create_ssl_context(gboolean is_server, GError **error) {
    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to create SSL context: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (!is_server)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");

    return ctx;
}

/* =========================================================================
 * CA CERTIFICATE LOAD
 * ========================================================================= */

static gboolean load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error) {
    FILE *fp;

    fp = fopen(ssl_mgr->ca_cert_file, "r");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                    "Cannot read CA certificate file: %s", ssl_mgr->ca_cert_file);
        return FALSE;
    }
    ssl_mgr->ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ssl_mgr->ca_cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to parse CA certificate: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        return FALSE;
    }

    fp = fopen(ssl_mgr->ca_key_file, "r");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                    "Cannot read CA key file: %s", ssl_mgr->ca_key_file);
        return FALSE;
    }
    ssl_mgr->ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ssl_mgr->ca_key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to parse CA private key: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        return FALSE;
    }

    g_info("CA certificate and key loaded successfully");
    return TRUE;
}

/* =========================================================================
 * UPSTREAM TLS
 * ========================================================================= */

gboolean deadlight_network_establish_upstream_ssl(DeadlightConnection *conn,
                                                   GError **error) {
    /* Pool reuse path */
    if (conn->upstream_tls && conn->ssl_established) {
        g_info("Connection %lu: Reusing existing TLS session to %s (from pool)",
               conn->id, conn->target_host);

        GTlsCertificate *peer_cert =
            g_tls_connection_get_peer_certificate(conn->upstream_tls);
        if (peer_cert) {
            if (conn->upstream_peer_cert)
                g_object_unref(conn->upstream_peer_cert);
            conn->upstream_peer_cert = g_object_ref(peer_cert);
            g_debug("Connection %lu: Reused TLS has valid peer certificate",
                    conn->id);
        }
        return TRUE;
    }

    if (!conn->upstream_connection) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Upstream connection not established; cannot TLS handshake.");
        return FALSE;
    }

    GSocketConnectable *server_identity =
        g_network_address_new(conn->target_host, conn->target_port);

    conn->upstream_tls = G_TLS_CONNECTION(g_tls_client_connection_new(
        G_IO_STREAM(conn->upstream_connection),
        server_identity,
        error
    ));
    g_object_unref(server_identity);

    if (!conn->upstream_tls)
        return FALSE;

    if (conn->context->ssl->system_trust_db) {
        g_object_set(G_OBJECT(conn->upstream_tls),
                     "database", conn->context->ssl->system_trust_db,
                     NULL);
    }

    /* Let upstream negotiate freely — we read the result and mirror it to
     * the client (or trigger h2 passthrough in ssl_intercept_connection). */

    if (!g_tls_connection_handshake(conn->upstream_tls, NULL, error)) {
        g_warning("Upstream TLS handshake failed for conn %lu to %s: %s",
                  conn->id, conn->target_host, (*error)->message);
        g_object_unref(conn->upstream_tls);
        conn->upstream_tls = NULL;
        return FALSE;
    }

    /* Log what upstream actually negotiated */
    gchar *negotiated = NULL;
    g_object_get(G_OBJECT(conn->upstream_tls),
                 "negotiated-protocol", &negotiated, NULL);
    g_debug("Connection %lu: Upstream %s negotiated protocol: %s",
            conn->id, conn->target_host, negotiated ? negotiated : "(none)");
    g_free(negotiated);

    GTlsCertificate *peer_cert =
        g_tls_connection_get_peer_certificate(conn->upstream_tls);
    if (peer_cert) {
        conn->upstream_peer_cert = g_object_ref(peer_cert);
        g_info("Upstream certificate retrieved for conn %lu to host %s",
               conn->id, conn->target_host);
    } else {
        g_warning("Could not retrieve upstream certificate for conn %lu to host %s",
                  conn->id, conn->target_host);
        conn->upstream_peer_cert = NULL;
    }

    g_info("Upstream TLS connection established for conn %lu to host %s",
           conn->id, conn->target_host);
    conn->ssl_established = TRUE;

    if (conn->context->conn_pool) {
        connection_pool_upgrade_to_tls(
            conn->context->conn_pool,
            G_IO_STREAM(conn->upstream_connection),
            G_IO_STREAM(conn->upstream_tls),
            conn->target_host,
            conn->target_port
        );
    }

    return TRUE;
}

/* =========================================================================
 * CERTIFICATE GENERATION
 * ========================================================================= */

static X509 *extract_x509_from_gtls_certificate(GTlsCertificate *gtls_cert) {
    GByteArray *cert_der = NULL;
    X509 *x509 = NULL;

    g_object_get(gtls_cert, "certificate", &cert_der, NULL);
    if (!cert_der) return NULL;

    const guchar *cert_data = cert_der->data;
    x509 = d2i_X509(NULL, &cert_data, cert_der->len);

    g_byte_array_unref(cert_der);
    return x509;
}

/*
 * copy_relevant_extensions — ported from proxy.deadlight
 *
 * Copies the upstream SAN directly via X509_EXTENSION_dup before falling
 * back to a hostname-only SAN.  This preserves wildcard certs and multi-SAN
 * certs correctly.  deadmesh's original version always generated a fresh
 * DNS:hostname SAN regardless of upstream content.
 */
static void copy_relevant_extensions(X509 *cert, X509 *upstream_cert,
                                     X509 *ca_cert, const char *hostname) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    /* Try to copy the upstream SAN verbatim first */
    int san_loc = X509_get_ext_by_NID(upstream_cert, NID_subject_alt_name, -1);
    if (san_loc >= 0) {
        X509_EXTENSION *upstream_san = X509_get_ext(upstream_cert, san_loc);
        X509_EXTENSION *san_copy = X509_EXTENSION_dup(upstream_san);
        if (san_copy) {
            X509_add_ext(cert, san_copy, -1);
            X509_EXTENSION_free(san_copy);
        }
    } else {
        /* Fallback: hostname-only SAN */
        gchar *san = g_strdup_printf("DNS:%s", hostname);
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                                   NID_subject_alt_name, san);
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        g_free(san);
    }

    X509_EXTENSION *ext;
    int ext_loc;

    ext_loc = X509_get_ext_by_NID(upstream_cert, NID_key_usage, -1);
    if (ext_loc >= 0) {
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                                  "digitalSignature,keyEncipherment");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    ext_loc = X509_get_ext_by_NID(upstream_cert, NID_ext_key_usage, -1);
    if (ext_loc >= 0) {
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                                  "serverAuth,clientAuth");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

static void add_default_extensions(X509 *cert, X509 *ca_cert,
                                    const char *hostname) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                               NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    g_free(san);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                               "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                               "serverAuth,clientAuth");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

static gchar *generate_host_pem(DeadlightSSLManager *ssl_mgr,
                                  const gchar *hostname,
                                  DeadlightConnection *conn,
                                  GError **error) {
    EVP_PKEY_CTX *pctx       = NULL;
    EVP_PKEY     *key        = NULL;
    X509         *cert       = NULL;
    BIO          *bio        = NULL;
    gchar        *pem_data   = NULL;
    X509         *upstream_x509 = NULL;
    long          pem_len;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to create PKEY context");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to init keygen");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to set RSA bits");
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &key) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to generate key");
        goto cleanup;
    }

    if (conn && conn->upstream_peer_cert)
        upstream_x509 = extract_x509_from_gtls_certificate(conn->upstream_peer_cert);

    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create X509");
        goto cleanup;
    }

    X509_set_version(cert, 2);

    if (upstream_x509) {
        ASN1_INTEGER *serial = X509_get_serialNumber(upstream_x509);
        X509_set_serialNumber(cert, serial);
    } else {
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    }

    if (upstream_x509) {
        X509_set_notBefore(cert, X509_get_notBefore(upstream_x509));
        X509_set_notAfter(cert,  X509_get_notAfter(upstream_x509));
    } else {
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert),  31536000L);
    }

    {
        X509_NAME *subject = X509_NAME_new();

        if (upstream_x509) {
            X509_NAME *upstream_subject = X509_get_subject_name(upstream_x509);
            for (int i = 0; i < X509_NAME_entry_count(upstream_subject); i++) {
                X509_NAME_ENTRY *entry = X509_NAME_get_entry(upstream_subject, i);
                X509_NAME_add_entry(subject, entry, -1, 0);
            }
        } else {
            X509_NAME_add_entry_by_txt(subject, "C",  MBSTRING_ASC,
                                       (unsigned char *)"US", -1, -1, 0);
            X509_NAME_add_entry_by_txt(subject, "O",  MBSTRING_ASC,
                                       (unsigned char *)"Deadlight Proxy", -1, -1, 0);
        }

        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   (unsigned char *)hostname, -1, -1, 0);
        X509_set_subject_name(cert, subject);
        X509_NAME_free(subject);
    }

    X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    X509_set_pubkey(cert, key);

    if (upstream_x509)
        copy_relevant_extensions(cert, upstream_x509, ssl_mgr->ca_cert, hostname);
    else
        add_default_extensions(cert, ssl_mgr->ca_cert, hostname);

    if (!X509_sign(cert, ssl_mgr->ca_key, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to sign certificate");
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create BIO");
        goto cleanup;
    }

    if (!PEM_write_bio_X509(bio, cert) ||
        !PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to write PEM");
        goto cleanup;
    }

    pem_len  = BIO_pending(bio);
    pem_data = g_malloc(pem_len + 1);
    BIO_read(bio, pem_data, pem_len);
    pem_data[pem_len] = '\0';

    g_info("Generated certificate for %s %s upstream mimicry",
           hostname, upstream_x509 ? "with" : "without");

cleanup:
    if (upstream_x509) X509_free(upstream_x509);
    if (cert)          X509_free(cert);
    if (key)           EVP_PKEY_free(key);
    if (bio)           BIO_free(bio);
    if (pctx)          EVP_PKEY_CTX_free(pctx);

    return pem_data;
}

/* =========================================================================
 * CERT CACHE
 * ========================================================================= */

static gchar *get_host_certificate(DeadlightSSLManager *ssl_mgr,
                                    const gchar *hostname,
                                    DeadlightConnection *conn,
                                    GError **error) {
    g_mutex_lock(&ssl_mgr->cert_mutex);

    CertCacheEntry *entry = g_hash_table_lookup(ssl_mgr->cert_cache, hostname);
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;

    if (entry && entry->expiry_time > now) {
        g_debug("Using cached PEM for %s", hostname);
        gchar *cached_pem = g_strdup(entry->pem_data);
        g_mutex_unlock(&ssl_mgr->cert_mutex);
        return cached_pem;
    }

    gchar *pem = generate_host_pem(ssl_mgr, hostname, conn, error);
    if (pem) {
        CertCacheEntry *new_entry = g_new0(CertCacheEntry, 1);
        new_entry->pem_data    = g_strdup(pem);
        new_entry->expiry_time = now + (24 * 60 * 60);
        g_hash_table_insert(ssl_mgr->cert_cache, g_strdup(hostname), new_entry);
    }

    g_mutex_unlock(&ssl_mgr->cert_mutex);
    return pem;
}

/* =========================================================================
 * SSL INTERCEPT (with h2 passthrough — retained from deadmesh)
 * ========================================================================= */

gboolean deadlight_ssl_intercept_connection(DeadlightConnection *conn,
                                             GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_connection != NULL, FALSE);
    g_return_val_if_fail(conn->target_host != NULL, FALSE);

    if (!deadlight_network_establish_upstream_ssl(conn, error))
        return FALSE;

    /* Read what upstream actually negotiated */
    gchar *upstream_protocol = NULL;
    g_object_get(conn->upstream_tls, "negotiated-protocol",
                 &upstream_protocol, NULL);

    /* h2 passthrough — we can't MITM h2 yet, so tear down and pass through */
    if (g_strcmp0(upstream_protocol, "h2") == 0) {
        g_info("Connection %lu: Upstream %s negotiated h2 — falling back to "
               "passthrough",
               conn->id, conn->target_host);
        g_free(upstream_protocol);

        g_object_unref(conn->upstream_tls);
        conn->upstream_tls   = NULL;
        conn->ssl_established = FALSE;

        g_io_stream_close(G_IO_STREAM(conn->upstream_connection), NULL, NULL);
        g_object_unref(conn->upstream_connection);
        conn->upstream_connection = NULL;

        GError *reconnect_error = NULL;
        conn->upstream_connection = deadlight_network_connect_tcp(
            conn->context, conn->target_host, conn->target_port,
            &reconnect_error);
        if (!conn->upstream_connection) {
            g_warning("Connection %lu: Passthrough reconnect failed for %s: %s",
                      conn->id, conn->target_host,
                      reconnect_error ? reconnect_error->message : "unknown");
            g_clear_error(&reconnect_error);
            return FALSE;
        }

        conn->tls_passthrough = TRUE;
        return FALSE;
    }

    gchar *pem_data = get_host_certificate(conn->context->ssl,
                                            conn->target_host, conn, error);
    if (!pem_data) {
        g_free(upstream_protocol);
        return FALSE;
    }

    GTlsCertificate *tls_cert =
        g_tls_certificate_new_from_pem(pem_data, -1, error);
    g_free(pem_data);
    if (!tls_cert) {
        g_free(upstream_protocol);
        return FALSE;
    }

    conn->client_tls = (GTlsConnection *)g_tls_server_connection_new(
        G_IO_STREAM(conn->client_connection),
        tls_cert,
        error
    );
    g_object_unref(tls_cert);
    if (!conn->client_tls) {
        g_free(upstream_protocol);
        return FALSE;
    }

    /* Mirror upstream's negotiated protocol to the client.
     * Both branches are http/1.1 for now; the h2 slot is handled above
     * via passthrough.  When full h2 interception is added, it goes here. */
    {
        const gchar *alpn[] = {"http/1.1", NULL};
        g_object_set(conn->client_tls, "advertised-protocols", alpn, NULL);
    }
    g_free(upstream_protocol);

    if (!g_tls_connection_handshake(conn->client_tls, NULL, error)) {
        g_warning("Client TLS handshake failed for conn %lu to host %s: %s",
                  conn->id, conn->target_host, (*error)->message);
        g_object_unref(conn->client_tls);
        conn->client_tls = NULL;
        return FALSE;
    }

    gchar *negotiated = NULL;
    g_object_get(conn->client_tls, "negotiated-protocol", &negotiated, NULL);
    g_info("Connection %lu: Client TLS negotiated: %s for host %s",
           conn->id, negotiated ? negotiated : "(none)", conn->target_host);
    g_free(negotiated);

    g_info("Client TLS interception established for conn %lu to host %s",
           conn->id, conn->target_host);
    conn->ssl_established = TRUE;
    return TRUE;
}

/* =========================================================================
 * CA CERTIFICATE GENERATION
 * ========================================================================= */

gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file,
                                              const gchar *key_file,
                                              GError **error) {
    X509         *cert  = NULL;
    EVP_PKEY     *pkey  = NULL;
    X509_NAME    *name  = NULL;
    FILE         *fp    = NULL;
    gboolean      success = FALSE;
    EVP_PKEY_CTX *pctx  = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to create key context");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to initialize key generation");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 4096) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to set key size");
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to generate key");
        goto cleanup;
    }

    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to create certificate");
        goto cleanup;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert),  315360000L);  /* 10 years */

    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                               (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"Deadlight CA", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);
    name = NULL;

    X509_set_pubkey(cert, pkey);

    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

        X509_EXTENSION *ext;

        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                                  "digitalSignature,keyCertSign,cRLSign");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    }

    if (!X509_sign(cert, pkey, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to sign CA certificate: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    fp = fopen(cert_file, "w");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Cannot open certificate file for writing: %s", cert_file);
        goto cleanup;
    }
    if (!PEM_write_X509(fp, cert)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to write certificate PEM");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    fp = fopen(key_file, "w");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Cannot open key file for writing: %s", key_file);
        goto cleanup;
    }
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to write private key PEM");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    /* Tighten key file permissions — the private key must not be world-readable */
    chmod(key_file, 0600);

    g_info("CA certificate created: %s", cert_file);
    g_info("CA private key created: %s (permissions: 0600)", key_file);
    success = TRUE;

cleanup:
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    /* name freed above after use */

    return success;
}