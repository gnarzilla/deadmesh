/**
 * Deadlight Proxy v1.0 - Logging System
 * 
 * Centralized logging with file output, level control, and Web UI buffering.
 */
#include "core/logging.h"
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "deadlight.h"

// --- Web Buffer Config ---
#define MAX_WEB_LOG_LINES 100
static GList *web_log_buffer = NULL;
static GMutex web_log_mutex;
// -------------------------

static FILE *log_file = NULL;
static DeadlightLogLevel current_log_level = DEADLIGHT_LOG_INFO;

// Helper to escape characters for JSON (simplistic)
static void append_escaped_json(GString *str, const gchar *text) {
    const gchar *p;
    for (p = text; *p; p++) {
        if (*p == '"') g_string_append(str, "\\\"");
        else if (*p == '\\') g_string_append(str, "\\\\");
        else if (*p == '\n') g_string_append(str, " "); // Flatten newlines
        else if (*p == '\r') { /* skip */ }
        else if (*p == '\t') g_string_append(str, "    ");
        else g_string_append_c(str, *p);
    }
}

/**
 * Custom log handler
 */
void deadlight_log_handler(const gchar *log_domain, GLogLevelFlags log_level, 
                          const gchar *message, gpointer user_data) {
    (void)user_data; // Unused parameter
    
    // Check if we should log this level
    DeadlightLogLevel dl_level;
    switch (log_level & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_ERROR:    dl_level = DEADLIGHT_LOG_ERROR; break;
        case G_LOG_LEVEL_CRITICAL: dl_level = DEADLIGHT_LOG_ERROR; break;
        case G_LOG_LEVEL_WARNING:  dl_level = DEADLIGHT_LOG_WARNING; break;
        case G_LOG_LEVEL_MESSAGE:  dl_level = DEADLIGHT_LOG_INFO; break;
        case G_LOG_LEVEL_INFO:     dl_level = DEADLIGHT_LOG_INFO; break;
        case G_LOG_LEVEL_DEBUG:    dl_level = DEADLIGHT_LOG_DEBUG; break;
        default:                   dl_level = DEADLIGHT_LOG_INFO;
    }
    
    if (dl_level > current_log_level) {
        return;
    }
    
    // Format timestamp
    time_t now;
    struct tm *tm_info;
    char timestamp[26];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Determine string level
    const gchar *level_str = "INFO ";
    const gchar *color_code = "";
    const gchar *reset_code = "\033[0m";
    
    switch (dl_level) {
        case DEADLIGHT_LOG_ERROR:   level_str = "ERROR"; color_code = "\033[31m"; break; // Red
        case DEADLIGHT_LOG_WARNING: level_str = "WARN "; color_code = "\033[33m"; break; // Yellow
        case DEADLIGHT_LOG_INFO:    level_str = "INFO "; color_code = "\033[32m"; break; // Green
        case DEADLIGHT_LOG_DEBUG:   level_str = "DEBUG"; color_code = "\033[36m"; break; // Cyan
        default: break;
    }

    const gchar *domain = log_domain ? log_domain : "deadmesh";

    // 1. Construct Plain String for Web Buffer (No ANSI colors)
    // Format: YYYY-MM-DD HH:MM:SS [LEVEL] domain: message
    gchar *plain_log = g_strdup_printf("%s [%s] %s: %s", 
                                       timestamp, level_str, domain, message);

    g_mutex_lock(&web_log_mutex);
    web_log_buffer = g_list_append(web_log_buffer, plain_log);
    
    // Circular Buffer: Remove oldest if over limit
    if (g_list_length(web_log_buffer) > MAX_WEB_LOG_LINES) {
        GList *first = g_list_first(web_log_buffer);
        g_free(first->data); // Free the string string
        web_log_buffer = g_list_delete_link(web_log_buffer, first);
    }
    g_mutex_unlock(&web_log_mutex);

    // 2. Output to Console/File (With colors if TTY)
    FILE *output = log_file ? log_file : stderr;
    gboolean use_color = isatty(fileno(stderr)) && !log_file;

    if (use_color) {
        fprintf(output, "%s%s [%s] %s: %s%s\n", 
                color_code, timestamp, level_str, domain, message, reset_code);
    } else {
        // Reuse plain log + newline for file
        fprintf(output, "%s\n", plain_log); 
    }
    
    fflush(output);
}

/**
 * Export buffer as JSON array
 */
gchar *deadlight_logging_get_buffered_json(void) {
    GString *json = g_string_new("[");
    
    g_mutex_lock(&web_log_mutex);
    GList *iter;
    gboolean first = TRUE;
    
    for (iter = web_log_buffer; iter != NULL; iter = iter->next) {
        if (!first) g_string_append(json, ",");
        
        g_string_append(json, "\"");
        append_escaped_json(json, (gchar*)iter->data);
        g_string_append(json, "\"");
        
        first = FALSE;
    }
    g_mutex_unlock(&web_log_mutex);
    
    g_string_append(json, "]");
    return g_string_free(json, FALSE);
}

/**
 * Initialize logging system
 */
gboolean deadlight_logging_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    
    // Init Web Buffer Lock
    g_mutex_init(&web_log_mutex);
    
    // Get log level from config
    gchar *log_level_str = deadlight_config_get_string(context, "core", "log_level", "info");
    
    if (g_strcmp0(log_level_str, "error") == 0) {
        current_log_level = DEADLIGHT_LOG_ERROR;
    } else if (g_strcmp0(log_level_str, "warning") == 0) {
        current_log_level = DEADLIGHT_LOG_WARNING;
    } else if (g_strcmp0(log_level_str, "info") == 0) {
        current_log_level = DEADLIGHT_LOG_INFO;
    } else if (g_strcmp0(log_level_str, "debug") == 0) {
        current_log_level = DEADLIGHT_LOG_DEBUG;
    }
    g_free(log_level_str);
    
    // Get log file from config
    gchar *log_file_path = deadlight_config_get_string(context, "core", "log_file", "");
    
    if (log_file_path && strlen(log_file_path) > 0) {
        gchar *log_dir = g_path_get_dirname(log_file_path);
        if (g_mkdir_with_parents(log_dir, 0755) != 0) {
            g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                       "Failed to create log directory: %s", log_dir);
            g_free(log_dir);
            g_free(log_file_path);
            return FALSE;
        }
        g_free(log_dir);
        log_file = fopen(log_file_path, "a");
    }
    g_free(log_file_path);
    
    g_log_set_default_handler(deadlight_log_handler, context);
    g_info("Logging system initialized (level: %d)", current_log_level);
    
    return TRUE;
}

/**
 * Cleanup logging system
 */
void deadlight_logging_cleanup(DeadlightContext *context) {
    (void)context; 
    
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    
    // Cleanup Buffer
    g_mutex_lock(&web_log_mutex);
    g_list_free_full(web_log_buffer, g_free);
    web_log_buffer = NULL;
    g_mutex_unlock(&web_log_mutex);
    g_mutex_clear(&web_log_mutex);
    
    // Note: Can't easily use g_info here as handler might be invalid, 
    // but usually cleanup happens at very end.
}