#include "deadlight.h"
#include "utils.h"
#include <gio/gio.h>
#include <string.h>

const gchar* deadlight_state_to_string(DeadlightConnectionState state) {
    switch (state) {
        case DEADLIGHT_STATE_INIT:       return "INIT";
        case DEADLIGHT_STATE_DETECTING:  return "DETECTING";
        case DEADLIGHT_STATE_CONNECTING: return "CONNECTING";
        case DEADLIGHT_STATE_CONNECTED:  return "CONNECTED";
        case DEADLIGHT_STATE_TUNNELING:  return "TUNNELING";
        case DEADLIGHT_STATE_CLOSING:    return "CLOSING";
        case DEADLIGHT_STATE_CLOSED:     return "CLOSED";
        default:                         return "UNKNOWN";
    }
}

gchar *get_external_ip(void) {
    GError *error = NULL;
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = NULL;
    gchar *result = NULL;
    
    // Try to connect to a simple IP checking service
    connection = g_socket_client_connect_to_host(client, 
                                                  "api.ipify.org", 80, 
                                                  NULL, &error);
    
    if (connection) {
        GOutputStream *output = g_io_stream_get_output_stream(G_IO_STREAM(connection));
        GInputStream *input = g_io_stream_get_input_stream(G_IO_STREAM(connection));
        
        const gchar *request = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
        
        if (g_output_stream_write_all(output, request, strlen(request), NULL, NULL, &error)) {
            gchar buffer[1024];
            gssize bytes_read = g_input_stream_read(input, buffer, sizeof(buffer) - 1, NULL, &error);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                // Find the IP address after the headers
                gchar *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4; // Skip the \r\n\r\n
                    result = g_strdup(g_strstrip(body));
                }
            }
        }
        
        g_object_unref(connection);
    }
    
    g_object_unref(client);
    
    if (error) {
        g_warning("Failed to get external IP: %s", error->message);
        g_error_free(error);
    }
    
    // Return localhost if we couldn't get external IP
    return result ? result : g_strdup("127.0.0.1");
}


gboolean deadlight_test_module(const gchar *module_name) {
    (void)module_name; // Mark as unused for now
    g_print("Testing module system...\n");
    // ... implementation ...
    return TRUE;
}

gchar *deadlight_format_bytes(guint64 bytes) {
    if (bytes < 1024) {
        return g_strdup_printf("%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        return g_strdup_printf("%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        return g_strdup_printf("%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        return g_strdup_printf("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

gchar *deadlight_format_duration(gint64 seconds) {

    if (seconds < 60) {
        return g_strdup_printf("%.1ld seconds", seconds);
    } else if (seconds < 3600) {
        return g_strdup_printf("%.1f minutes", seconds / 60.0);
    } else if (seconds < 86400) {
        return g_strdup_printf("%.1f hours", seconds / 3600.0);
    } else {
        return g_strdup_printf("%.1f days", seconds / 86400.0);
    }
}

gboolean deadlight_parse_host_port(const gchar *host_port, gchar **host, guint16 *port) {
    if (!host_port || !host || !port) return FALSE;

    *host = NULL;

    if (host_port[0] == '[') { // IPv6 address like [::1]:8080
        // 'end' is declared here, so it's only visible inside this 'if' block.
        const gchar *end = strchr(host_port, ']');
        if (!end) return FALSE; 

        *host = g_strndup(host_port + 1, end - (host_port + 1));

        // Check for a port after the ']'
        if (*(end + 1) == ':') {
            gulong p = strtoul(end + 2, NULL, 10);
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                g_free(*host);
                *host = NULL;
            }
        }

    } else {
        const gchar *colon = strrchr(host_port, ':');
        if (colon) { // A port is specified
            *host = g_strndup(host_port, colon - host_port);

            gulong p = strtoul(colon + 1, NULL, 10);
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                g_free(*host);
                *host = NULL;
            }
        } else { // No port is specified
            *host = g_strdup(host_port);
        }
    }

    return (*host != NULL && strlen(*host) > 0);
}

#include <openssl/hmac.h>
#include <openssl/evp.h>

gboolean validate_hmac_bytes(const gchar *auth_header, const guint8 *body_data, gsize body_len, const gchar *secret) {
    if (!auth_header || !secret) return FALSE;

    // Expected format: "sha256=<hex_hash>"
    if (!g_str_has_prefix(auth_header, "sha256=")) return FALSE;
    const gchar *provided_hash = auth_header + 7;

    unsigned char *digest;
    unsigned int digest_len;

    digest = HMAC(EVP_sha256(), secret, strlen(secret), body_data, body_len, NULL, &digest_len);
    
    if (!digest) return FALSE;

    // Convert to hex string
    GString *calculated_hash = g_string_new(NULL);
    for (unsigned int i = 0; i < digest_len; i++) {
        g_string_append_printf(calculated_hash, "%02x", digest[i]);
    }

    // Constant time comparison (to prevent timing attacks)
    gboolean match = (CRYPTO_memcmp(calculated_hash->str, provided_hash, digest_len * 2) == 0);

    g_string_free(calculated_hash, TRUE);
    return match;
}