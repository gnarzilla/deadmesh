/**
 * deadmesh (meshtastic.deadlight) v1.0 - Main Entry Point
 *
 * Internet-over-LoRa: Meshtastic mesh to Internet gateway
 * Part of the Deadlight ecosystem: https://deadlight.boo
 *
 * Built with GNU/GLib ecosystem for robustness and performance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <pwd.h>
#include <getopt.h>
#include <glib-unix.h>
#include <glib.h>
#include <gio/gio.h>
#include <locale.h>

#include "deadlight.h"

#ifdef ENABLE_UI
#include "ui/ui.h"
#endif

#include "vpn/vpn_gateway.h"

// Global context - managed carefully
static DeadlightContext *g_context = NULL;

// Command line options
static gboolean opt_daemon    = FALSE;
static gboolean opt_verbose   = FALSE;
static gboolean opt_test_mode = FALSE;
static gchar   *opt_config_file  = NULL;
static gchar   *opt_test_module  = NULL;
static gchar   *opt_pid_file     = NULL;
static gint     opt_port         = 0;

static GOptionEntry entries[] = {
    {"daemon",    'd', 0, G_OPTION_ARG_NONE,   &opt_daemon,
     "Run as daemon", NULL},
    {"verbose",   'v', 0, G_OPTION_ARG_NONE,   &opt_verbose,
     "Verbose output", NULL},
    {"config",    'c', 0, G_OPTION_ARG_STRING, &opt_config_file,
     "Configuration file", "FILE"},
    {"port",      'p', 0, G_OPTION_ARG_INT,    &opt_port,
     "Listen port (overrides config)", "PORT"},
    {"pid-file",   0,  0, G_OPTION_ARG_STRING, &opt_pid_file,
     "PID file for daemon mode", "FILE"},
    {"test",      't', 0, G_OPTION_ARG_STRING, &opt_test_module,
     "Test specific module", "MODULE"},
    {"test-mode",  0,  0, G_OPTION_ARG_NONE,   &opt_test_mode,
     "Enable test mode", NULL},
    {NULL}
};

#ifndef DEADMESH_VERSION
#define DEADMESH_VERSION "1.0.0"
#endif

#define VERSION DEADMESH_VERSION

static const char *BUILD_DATE = __DATE__ " " __TIME__;

// Forward declarations
static gboolean signal_handler(gpointer user_data);
static void     cleanup_resources(void);
static void     cleanup_and_exit(int exit_code);
static int      run_tests(const gchar *module);
static int      run_daemon_mode(void);
static int      run_interactive_mode(void);
static void     print_banner(void);
static void     print_test_commands(gint port, gboolean vpn_enabled);
static void     print_usage(void);
static gboolean write_pid_file_atomic(const gchar *pid_file);
static void     setup_resource_limits(void);
static void     drop_privileges(void);
static gboolean validate_configuration(DeadlightContext *ctx, GError **error);

/* ─────────────────────────────────────────────────────────────
 * Signal handling
 * ───────────────────────────────────────────────────────────── */

/**
 * Async-signal-safe graceful shutdown handler
 */
static gboolean signal_handler(gpointer user_data) {
    // Use write() for async-signal safety
    const char *msg = "Received shutdown signal, cleaning up...\n";
    ssize_t ignored = write(STDERR_FILENO, msg, strlen(msg));
    (void)ignored;

    DeadlightContext *ctx = (DeadlightContext *)user_data;
    if (ctx && ctx->main_loop) {
        g_main_loop_quit(ctx->main_loop);
    }

    return G_SOURCE_REMOVE;
}

/* ─────────────────────────────────────────────────────────────
 * Cleanup
 * ───────────────────────────────────────────────────────────── */

/**
 * Free all global resources
 */
static void cleanup_resources(void) {
    if (g_context) {
        deadlight_context_free(g_context);
        g_context = NULL;
    }

    g_clear_pointer(&opt_config_file, g_free);
    g_clear_pointer(&opt_test_module, g_free);
    g_clear_pointer(&opt_pid_file,    g_free);
}

/**
 * Cleanup and exit with code
 */
static void cleanup_and_exit(int exit_code) {
    cleanup_resources();
    exit(exit_code);
}

/* ─────────────────────────────────────────────────────────────
 * Configuration
 * ───────────────────────────────────────────────────────────── */

/**
 * Validate configuration after loading.
 * Catches bad configs before we bind ports or touch hardware.
 */
static gboolean validate_configuration(DeadlightContext *ctx, GError **error) {
    if (!ctx || !ctx->config) {
        g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                    "Configuration not loaded");
        return FALSE;
    }

    // Required sections
    const gchar *required_sections[] = {"core", "ssl", NULL};
    for (int i = 0; required_sections[i]; i++) {
        if (!deadlight_config_has_section(ctx, required_sections[i])) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Missing required config section: %s", required_sections[i]);
            return FALSE;
        }
    }

    // Validate port
    gint port = deadlight_config_get_int(ctx, "core", "port", -1);
    if (port <= 0 || port > 65535) {
        g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                    "Invalid port number: %d", port);
        return FALSE;
    }

    // Validate SSL cert/key files if SSL interception is enabled
    gboolean ssl_enabled = deadlight_config_get_bool(ctx, "ssl", "enabled", FALSE);
    if (ssl_enabled) {
        gchar *ca_cert_raw = deadlight_config_get_string(ctx, "ssl", "ca_cert_file", NULL);
        gchar *ca_key_raw  = deadlight_config_get_string(ctx, "ssl", "ca_key_file",  NULL);

        if (!ca_cert_raw || !ca_key_raw) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "SSL interception enabled but ca_cert_file/ca_key_file not set");
            g_free(ca_cert_raw);
            g_free(ca_key_raw);
            return FALSE;
        }

        gchar *ca_cert = expand_config_path(ca_cert_raw);
        gchar *ca_key  = expand_config_path(ca_key_raw);
        g_free(ca_cert_raw);
        g_free(ca_key_raw);

        if (access(ca_cert, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Cannot read CA cert file: %s", ca_cert);
            g_free(ca_cert);
            g_free(ca_key);
            return FALSE;
        }

        if (access(ca_key, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                        "Cannot read CA key file: %s", ca_key);
            g_free(ca_cert);
            g_free(ca_key);
            return FALSE;
        }

        g_free(ca_cert);
        g_free(ca_key);
    }

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * PID file
 * ───────────────────────────────────────────────────────────── */

/**
 * Atomic PID file creation with stale-lock detection.
 * Avoids TOCTOU race by using "wx" open mode (fails if file exists).
 */
static gboolean write_pid_file_atomic(const gchar *pid_file) {
    if (!pid_file) return TRUE;

    // Check for existing PID file / stale lock
    if (g_file_test(pid_file, G_FILE_TEST_EXISTS)) {
        FILE *old = fopen(pid_file, "r");
        if (old) {
            pid_t old_pid;
            if (fscanf(old, "%d", &old_pid) == 1) {
                fclose(old);
                if (kill(old_pid, 0) == 0) {
                    g_critical("Process %d is already running (PID file: %s)",
                               old_pid, pid_file);
                    return FALSE;
                } else {
                    g_warning("Removing stale PID file for dead process %d", old_pid);
                    unlink(pid_file);
                }
            } else {
                fclose(old);
            }
        }
    }

    // Atomic create: "wx" fails if the file appeared between our check and open
    FILE *fp = fopen(pid_file, "wx");
    if (!fp) {
        if (errno == EEXIST) {
            // Lost a race - retry
            return write_pid_file_atomic(pid_file);
        }
        g_critical("Failed to create PID file %s: %s", pid_file, strerror(errno));
        return FALSE;
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    g_info("PID file written: %s", pid_file);
    return TRUE;
}

/**
 * Remove PID file - registered with atexit()
 */
static void remove_pid_file(void) {
    if (opt_pid_file && g_file_test(opt_pid_file, G_FILE_TEST_EXISTS)) {
        if (unlink(opt_pid_file) == 0) {
            g_info("PID file removed");
        } else {
            g_warning("Failed to remove PID file: %s", strerror(errno));
        }
    }
}

/* ─────────────────────────────────────────────────────────────
 * System setup
 * ───────────────────────────────────────────────────────────── */

/**
 * Raise file descriptor limit and enable core dumps.
 * Mesh gateways can handle many simultaneous mesh sessions.
 */
static void setup_resource_limits(void) {
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < 4096) {
            rl.rlim_cur = 4096;
            if (rl.rlim_max < 4096) rl.rlim_max = 4096;
            if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
                g_warning("Failed to increase fd limit: %s", strerror(errno));
            } else {
                g_debug("File descriptor limit raised to %lu",
                        (unsigned long)rl.rlim_cur);
            }
        }
    }

    // Enable core dumps for debugging field deployments
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rl) < 0) {
        g_debug("Could not enable core dumps: %s", strerror(errno));
    }
}

/**
 * Drop from root to nobody/daemon after binding privileged port.
 * Critical for field deployments where the gateway runs as a service.
 */
static void drop_privileges(void) {
    if (getuid() != 0) {
        g_debug("Running as non-root, skipping privilege drop");
        return;
    }

    struct passwd *pw = getpwnam("nobody");
    if (!pw) pw = getpwnam("daemon");

    if (pw) {
        if (setgid(pw->pw_gid) != 0) {
            g_warning("setgid(%d) failed: %s", pw->pw_gid, strerror(errno));
        }
        if (setuid(pw->pw_uid) != 0) {
            g_warning("setuid(%d) failed: %s", pw->pw_uid, strerror(errno));
        }
        g_info("Dropped privileges to %s (uid=%d gid=%d)",
               pw->pw_name, pw->pw_uid, pw->pw_gid);
    } else {
        g_warning("No non-root user found; running with elevated privileges");
    }
}

/* ─────────────────────────────────────────────────────────────
 * Test mode
 * ───────────────────────────────────────────────────────────── */

static int run_tests(const gchar *module) {
    g_print("deadmesh Test Mode\n");
    g_print("Version: %s  Build: %s\n\n", VERSION, BUILD_DATE);
    g_print("Module: %s\n\n", module);

    if (g_strcmp0(module, "all") == 0) {
        g_print("Running all tests...\n");

        const gchar *modules[] = {
            "config", "logging", "network", "protocols",
            "ssl", "plugins", "meshtastic", NULL
        };

        gboolean all_passed = TRUE;
        for (int i = 0; modules[i]; i++) {
            g_print("  %-16s ", modules[i]);
            gboolean result = deadlight_test_module(modules[i]);
            g_print("%s\n", result ? "PASS" : "FAIL");
            if (!result) all_passed = FALSE;
        }

        g_print("\n%s\n", all_passed ? "All tests passed!" : "Some tests FAILED.");
        return all_passed ? 0 : 1;
    }

    g_print("  %-16s ", module);
    gboolean result = deadlight_test_module(module);
    g_print("%s\n", result ? "PASS" : "FAIL");
    return result ? 0 : 1;
}

/* ─────────────────────────────────────────────────────────────
 * Daemon mode
 * ───────────────────────────────────────────────────────────── */

static int run_daemon_mode(void) {
    g_info("Starting daemon mode...");

    pid_t pid = fork();
    if (pid < 0) {
        g_critical("fork() failed: %s", strerror(errno));
        return 1;
    }

    if (pid > 0) {
        // Parent exits cleanly
        g_info("Daemon started with PID %d", pid);
        exit(0);
    }

    // Child: become session leader
    setsid();

    if (chdir("/") < 0) {
        g_critical("chdir('/') failed: %s", strerror(errno));
        return 1;
    }

    // Detach stdio
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO) close(null_fd);
    }

    if (!write_pid_file_atomic(opt_pid_file)) return 1;
    atexit(remove_pid_file);

    drop_privileges();

    return run_interactive_mode();
}

/* ─────────────────────────────────────────────────────────────
 * Interactive / main proxy mode
 * ───────────────────────────────────────────────────────────── */

static int run_interactive_mode(void) {
    GError *error = NULL;
    int ret = 0;

    setup_resource_limits();

    // ── Context ────────────────────────────────────────────────
    g_context = deadlight_context_new();
    if (!g_context) {
        g_critical("Failed to create deadmesh context");
        return 1;
    }

    // ── Configuration ──────────────────────────────────────────
    if (!deadlight_config_load(g_context, opt_config_file, &error)) {
        g_critical("Failed to load configuration: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }

    if (!validate_configuration(g_context, &error)) {
        g_critical("Configuration validation failed: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }

    if (opt_port > 0)
        deadlight_config_set_int(g_context, "core", "port", opt_port);

    if (opt_verbose)
        deadlight_config_set_string(g_context, "core", "log_level", "debug");

    // ── Logging ────────────────────────────────────────────────
    if (!deadlight_logging_init(g_context, &error)) {
        g_critical("Failed to initialize logging: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }

    if (!opt_daemon) print_banner();

    // ── Subsystems (reverse-order cleanup via goto labels) ─────
    g_info("Initializing deadmesh systems...");

    deadlight_protocols_init(g_context);

    if (!deadlight_network_init(g_context, &error)) {
        g_critical("Network init failed: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_network;
    }

    if (!deadlight_ssl_init(g_context, &error)) {
        g_critical("SSL init failed: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_ssl;
    }

    if (!deadlight_plugins_init(g_context, &error)) {
        g_critical("Plugins init failed: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_plugins;
    }

    // ── VPN gateway (optional) ─────────────────────────────────
    {
        gboolean vpn_enabled = deadlight_config_get_bool(g_context, "vpn", "enabled", FALSE);
        if (vpn_enabled) {
            g_info("VPN gateway enabled");

            g_context->vpn = g_new0(DeadlightVPNManager, 1);
            g_context->vpn->context            = g_context;
            g_context->vpn->tun_fd             = -1;
            g_context->vpn->total_connections  = 0;
            g_context->vpn->active_connections = 0;
            g_context->vpn->bytes_sent         = 0;
            g_context->vpn->bytes_received     = 0;

            if (!deadlight_vpn_gateway_init(g_context, &error)) {
                g_warning("VPN init failed: %s — continuing without VPN", error->message);
                g_clear_error(&error);
                g_free(g_context->vpn);
                g_context->vpn = NULL;
            } else {
                g_info("VPN initialized successfully");
            }
        } else {
            g_debug("VPN gateway disabled (vpn.enabled=true to enable)");
        }
    }

#ifdef ENABLE_UI
    g_info("Starting UI server...");
    start_ui_server(g_context);
#endif

    // ── Signal handlers ────────────────────────────────────────
    g_unix_signal_add(SIGINT,  signal_handler, g_context);
    g_unix_signal_add(SIGTERM, signal_handler, g_context);
    g_unix_signal_add(SIGHUP,  signal_handler, g_context);   // back-ported from proxy.deadlight

    // ── Start listening ────────────────────────────────────────
    gint port = deadlight_config_get_int(g_context, "core", "port", 8080);
    g_info("Starting proxy on port %d", port);

    if (!deadlight_network_start_listener(g_context, port, &error)) {
        g_critical("Failed to start listener: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_listener;
    }

    // ── Startup output (interactive only) ─────────────────────
    if (!opt_daemon) {
        g_print("\ndeadmesh %s is ready!\n", VERSION);
        g_print("Build:  %s\n", BUILD_DATE);
        g_print("Port:   %d\n", port);
        g_print("Config: %s\n", opt_config_file ? opt_config_file : "default");
        g_print("Plugins loaded: %d\n", deadlight_plugins_count(g_context));

        if (opt_verbose) {
            print_test_commands(port, g_context->vpn != NULL);
        }

        g_print("\nPress Ctrl+C to stop\n\n");
    }

    // ── Main loop ──────────────────────────────────────────────
    g_context->main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(g_context->main_loop);

    // ── Ordered teardown ───────────────────────────────────────

cleanup_listener:
    g_info("Stopping network listener...");
    deadlight_network_stop(g_context);

cleanup_plugins:
    g_info("Cleaning up plugins...");
    deadlight_plugins_cleanup(g_context);

cleanup_ssl:
    g_info("Cleaning up SSL...");
    deadlight_ssl_cleanup(g_context);

cleanup_network:
    g_info("Cleaning up network...");
    deadlight_network_cleanup(g_context);

    if (g_context && g_context->vpn) {
        g_info("Cleaning up VPN...");
        deadlight_vpn_gateway_cleanup(g_context);
    }

#ifdef ENABLE_UI
    g_info("Stopping UI server...");
    stop_ui_server();
#endif

cleanup:
    if (g_context && g_context->main_loop) {
        g_main_loop_unref(g_context->main_loop);
        g_context->main_loop = NULL;
    }

    g_info("deadmesh stopped");
    return ret;
}

/* ─────────────────────────────────────────────────────────────
 * Output helpers
 * ───────────────────────────────────────────────────────────── */

static void print_test_commands(gint port, gboolean vpn_enabled) {
    g_print("\nTest commands:\n");

    g_print("  # HTTP\n");
    g_print("  curl -x http://localhost:%d http://example.com\n", port);

    g_print("\n  # HTTPS (install ~/.deadlight/ca.crt on clients first)\n");
    g_print("  curl --cacert ~/.deadlight/ca.crt -x http://localhost:%d https://example.com\n", port);

    g_print("\n  # SOCKS4\n");
    g_print("  curl --socks4 localhost:%d http://example.com\n", port);

    g_print("\n  # SOCKS5\n");
    g_print("  curl --socks5 localhost:%d http://example.com\n", port);

    g_print("\n  # SMTP\n");
    g_print("  printf \"HELO test.com\\r\\n\" | nc localhost %d\n", port);

    g_print("\n  # IMAP (NOOP)\n");
    g_print("  printf \"A001 NOOP\\r\\n\" | nc localhost %d\n", port);

    g_print("\n  # IMAP STARTTLS\n");
    g_print("  openssl s_client -connect localhost:%d -starttls imap -crlf\n", port);

    g_print("\n  # WebSocket\n");
    g_print("  curl -v --proxy http://localhost:%d -H \"Upgrade: websocket\" http://ws.ifelse.io/\n", port);

    g_print("\n  # FTP\n");
    g_print("  printf \"USER anonymous\\r\\n\" | nc localhost %d\n\n", port);

    if (vpn_enabled) {
        g_print("  # VPN gateway (requires root / CAP_NET_ADMIN)\n");
        g_print("  sudo ip route add default via 10.8.0.1 dev tun0\n");
        g_print("  curl http://example.com  # routes through proxy\n\n");
    }
}

static void print_banner(void) {
    g_print("\n");
    g_print("═══════════════════════════════════════════════════════════\n");
    g_print("                         deadmesh                          \n");
    g_print("           Internet-over-LoRa mesh gateway v%s          \n", VERSION);
    g_print("                  https://deadmesh.boo                     \n");
    g_print("═══════════════════════════════════════════════════════════\n");
    g_print("\n");
}

static void print_usage(void) {
    g_print("deadmesh %s\n", VERSION);
    g_print("Internet-over-LoRa mesh gateway — part of the Deadlight ecosystem\n\n");
    g_print("Usage: deadmesh [OPTIONS]\n\n");
    g_print("Options:\n");
    g_print("  -d, --daemon           Run as daemon\n");
    g_print("  -v, --verbose          Verbose output (also shows test commands on start)\n");
    g_print("  -c, --config FILE      Configuration file\n");
    g_print("  -p, --port PORT        Listen port (overrides config)\n");
    g_print("      --pid-file FILE    PID file for daemon mode\n");
    g_print("  -t, --test MODULE      Test specific module\n");
    g_print("      --test-mode        Enable test mode\n");
    g_print("  -h, --help             Show this help\n\n");
    g_print("Test modules:\n");
    g_print("  all, config, logging, network, protocols, ssl, plugins, meshtastic\n\n");
    g_print("Examples:\n");
    g_print("  deadmesh -p 8080\n");
    g_print("  deadmesh -c deadmesh.conf -v\n");
    g_print("  deadmesh -d --pid-file /var/run/deadmesh.pid\n");
    g_print("  deadmesh -t all\n");
    g_print("\n");
}

/* ─────────────────────────────────────────────────────────────
 * Entry point
 * ───────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");

    GError *error = NULL;
    GOptionContext *context;

    g_log_set_default_handler(deadlight_log_handler, NULL);

    context = g_option_context_new("- LoRa mesh Internet gateway");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_description(context,
        "deadmesh v" DEADMESH_VERSION " — part of the Deadlight ecosystem\n"
        "https://deadmesh.boo  |  https://deadlight.boo");

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("Option parsing failed: %s\n", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }
    g_option_context_free(context);

    if (argc > 1 && (g_strcmp0(argv[1], "-h") == 0 ||
                     g_strcmp0(argv[1], "--help") == 0)) {
        print_usage();
        return 0;
    }

    if (opt_test_module) {
        int result = run_tests(opt_test_module);
        cleanup_and_exit(result);
    }

    if (opt_daemon) {
        return run_daemon_mode();
    }

    int ret = run_interactive_mode();
    cleanup_and_exit(ret);
}