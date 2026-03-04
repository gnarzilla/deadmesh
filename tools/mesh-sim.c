/**
 * deadmesh - Meshtastic Radio Simulator
 *
 * Opens a PTY pair. The slave end acts as a virtual /dev/ttyACM0 that
 * deadmesh can connect to. The master end speaks the Meshtastic serial
 * framing protocol, injecting synthetic mesh sessions and printing
 * everything it receives back from deadmesh.
 *
 * Build (standalone, no GLib needed):
 *   gcc -o mesh-sim tools/mesh-sim.c src/mesh/mesh_framing.c \
 *       -I src/mesh -I src -Wall -Wextra -o tools/mesh-sim
 *
 * Usage:
 *   ./tools/mesh-sim [--loss N] [--delay MS]
 *
 * Interactive commands (stdin):
 *   session <node_id_hex>          Start new session from node (hex node ID)
 *   send <node_id_hex> <hex_data>  Send raw hex payload from node
 *   http <node_id_hex> <url>       Send a minimal HTTP GET request
 *   loss <0-100>                   Set packet loss % for injected packets
 *   delay <ms>                     Add artificial delay to injected packets
 *   hops <n>                       Set hop count on injected packets (1-7)
 *   status                         Print active sessions and stats
 *   help                           Print this list
 *   quit / exit / q                Exit
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pty.h>           /* openpty() — link with -lutil              */
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>

#include "mesh_framing.h"

/* ─────────────────────────────────────────────────────────────
 * Minimal protobuf helpers
 *
 * We avoid a full nanopb dependency in the sim by hand-encoding
 * the fields we actually need. The real plugin uses nanopb.
 *
 * Meshtastic MeshPacket (from mesh.proto):
 *   field 1  (from)       : uint32  varint
 *   field 4  (decoded)    : message (Data)   <-- oneof payload_variant, tag 4
 *   field 6  (hop_limit)  : uint32  varint
 *   field 8  (id)         : uint32  varint
 *
 * Meshtastic Data (from mesh.proto):
 *   field 1  (portnum)    : uint32  varint
 *   field 2  (payload)    : bytes            <-- field 2, not 3
 *
 * FromRadio wrapper:
 *   field 2  (packet)     : message (MeshPacket)
 * ───────────────────────────────────────────────────────────── */

static size_t pb_encode_varint(uint8_t *buf, uint64_t val) {
    size_t i = 0;
    do {
        buf[i] = (uint8_t)(val & 0x7F);
        val >>= 7;
        if (val) buf[i] |= 0x80;
        i++;
    } while (val);
    return i;
}

static size_t pb_encode_tag_varint(uint8_t *buf, uint32_t field, uint64_t val) {
    size_t n = pb_encode_varint(buf, (uint64_t)field << 3 | 0); /* wire type 0 */
    n += pb_encode_varint(buf + n, val);
    return n;
}

static size_t pb_encode_tag_bytes(uint8_t *buf, uint32_t field,
                                   const uint8_t *data, size_t len) {
    size_t n = pb_encode_varint(buf, (uint64_t)field << 3 | 2); /* wire type 2 */
    n += pb_encode_varint(buf + n, len);
    memcpy(buf + n, data, len);
    n += len;
    return n;
}

static size_t pb_encode_tag_message(uint8_t *buf, uint32_t field,
                                     const uint8_t *msg, size_t msg_len) {
    return pb_encode_tag_bytes(buf, field, msg, msg_len);
}

/**
 * Encode a Data message (portnum + payload bytes).
 * Returns bytes written into @buf.
 *
 * Data proto fields: portnum=1, payload=2
 */
static size_t encode_data_msg(uint8_t *buf, size_t buf_len,
                               uint32_t portnum,
                               const uint8_t *payload, size_t payload_len) {
    (void)buf_len;
    size_t n = 0;
    n += pb_encode_tag_varint(buf + n, 1, portnum);             /* field 1: portnum */
    n += pb_encode_tag_bytes(buf + n, 2, payload, payload_len); /* field 2: payload */
    return n;
}

/**
 * Encode a MeshPacket and wrap it in a FromRadio.
 * Writes the complete framed serial bytes into @out_frame.
 * Returns total bytes written (including framing), 0 on error.
 *
 * MeshPacket.decoded is oneof payload_variant, tag 4.
 */
static size_t build_from_radio_frame(uint8_t *out_frame, size_t out_len,
                                      uint32_t from_node, uint32_t session_id,
                                      uint32_t portnum, uint32_t hop_limit,
                                      const uint8_t *payload, size_t payload_len) {
    uint8_t data_buf[600];
    uint8_t packet_buf[700];
    uint8_t from_radio_buf[800];

    /* Encode Data sub-message */
    size_t data_len = encode_data_msg(data_buf, sizeof(data_buf),
                                       portnum, payload, payload_len);

    /* Encode MeshPacket */
    size_t pkt_len = 0;
    pkt_len += pb_encode_tag_varint(packet_buf + pkt_len, 1, from_node);   /* from      */
    pkt_len += pb_encode_tag_varint(packet_buf + pkt_len, 8, session_id);  /* id        */
    pkt_len += pb_encode_tag_varint(packet_buf + pkt_len, 6, hop_limit);   /* hop_limit */
    pkt_len += pb_encode_tag_message(packet_buf + pkt_len, 4,              /* decoded — tag 4 */
                                      data_buf, data_len);

    /* Wrap in FromRadio (field 2 = packet) */
    size_t fr_len = pb_encode_tag_message(from_radio_buf, 2,
                                           packet_buf, pkt_len);

    /* Apply serial framing */
    return mesh_frame_encode(from_radio_buf, (uint16_t)fr_len,
                              out_frame, out_len);
}

/* ─────────────────────────────────────────────────────────────
 * Simulator state
 * ───────────────────────────────────────────────────────────── */

#define MAX_SESSIONS 64
#define SIM_PORTNUM  100    /* matches DEFAULT_CUSTOM_PORT in plugin */

typedef struct {
    uint32_t node_id;
    uint32_t session_id;
    bool     active;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
} SimSession;

static struct {
    int      master_fd;
    int      slave_fd;
    char     slave_name[64];

    SimSession sessions[MAX_SESSIONS];
    int        session_count;
    uint32_t   next_session_id;

    int      loss_pct;      /* 0-100 */
    int      delay_ms;
    int      hop_limit;     /* 1-7   */

    volatile bool running;

    MeshFrameReader reader;

    /* Stats */
    uint64_t frames_sent;
    uint64_t frames_recv;
    uint64_t frames_dropped;
} sim;

static pthread_mutex_t sim_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ─────────────────────────────────────────────────────────────
 * PTY setup
 * ───────────────────────────────────────────────────────────── */

static bool sim_open_pty(void) {
    struct winsize ws = { .ws_row = 24, .ws_col = 80 };

    if (openpty(&sim.master_fd, &sim.slave_fd, sim.slave_name,
                NULL, &ws) < 0) {
        perror("openpty");
        return false;
    }

    /* Set master non-blocking for the reader thread */
    int flags = fcntl(sim.master_fd, F_GETFL, 0);
    fcntl(sim.master_fd, F_SETFL, flags | O_NONBLOCK);

    /* Raw mode on slave so deadmesh gets clean binary data */
    struct termios tios;
    if (tcgetattr(sim.slave_fd, &tios) == 0) {
        cfmakeraw(&tios);
        tcsetattr(sim.slave_fd, TCSANOW, &tios);
    }

    return true;
}

/* ─────────────────────────────────────────────────────────────
 * Frame I/O
 * ───────────────────────────────────────────────────────────── */

static bool sim_should_drop(void) {
    if (sim.loss_pct == 0) return false;
    return (rand() % 100) < sim.loss_pct;
}

static void sim_apply_delay(void) {
    if (sim.delay_ms > 0) {
        struct timespec ts = {
            .tv_sec  = sim.delay_ms / 1000,
            .tv_nsec = (sim.delay_ms % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
    }
}

static bool sim_send_frame(const uint8_t *payload, size_t payload_len,
                            uint32_t from_node, uint32_t session_id) {
    if (sim_should_drop()) {
        sim.frames_dropped++;
        fprintf(stderr, "[sim] DROP  packet from node %08x (loss=%d%%)\n",
                from_node, sim.loss_pct);
        return true; /* not an error — intentional drop */
    }

    sim_apply_delay();

    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL + 64];
    size_t frame_len = build_from_radio_frame(
        frame_buf, sizeof(frame_buf),
        from_node, session_id,
        SIM_PORTNUM, (uint32_t)sim.hop_limit,
        payload, payload_len);

    if (frame_len == 0) {
        fprintf(stderr, "[sim] ERROR encoding frame\n");
        return false;
    }

    ssize_t written = write(sim.master_fd, frame_buf, frame_len);
    if (written < 0) {
        perror("[sim] write to PTY master");
        return false;
    }

    sim.frames_sent++;
    fprintf(stderr, "[sim] SEND  %zu bytes from node %08x session %08x\n",
            payload_len, from_node, session_id);
    return true;
}

/* ─────────────────────────────────────────────────────────────
 * Reader thread — receives frames from deadmesh
 * ───────────────────────────────────────────────────────────── */

static void *reader_thread(void *arg) {
    (void)arg;
    uint8_t buf[512];
    MeshFrameReader reader;
    mesh_frame_reader_init(&reader);

    fprintf(stderr, "[sim] Reader thread started\n");

    while (sim.running) {
        struct pollfd pfd = { .fd = sim.master_fd, .events = POLLIN };
        int rc = poll(&pfd, 1, 200); /* 200ms timeout so we check sim.running */

        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[sim] poll");
            break;
        }

        if (rc == 0) continue; /* timeout — loop and check running */

        ssize_t n = read(sim.master_fd, buf, sizeof(buf));
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            break;
        }

        size_t pos = 0;
        while (pos < (size_t)n) {
            size_t consumed = mesh_frame_reader_push(&reader,
                                                      buf + pos,
                                                      (size_t)n - pos);
            pos += consumed;

            if (reader.state == MESH_FRAME_STATE_READY) {
                MeshFrame frame;
                mesh_frame_get(&reader, &frame);
                sim.frames_recv++;

                /* Print hex dump of received frame */
                fprintf(stderr, "[sim] RECV  %u bytes: ", frame.len);
                for (uint16_t i = 0; i < frame.len && i < 32; i++) {
                    fprintf(stderr, "%02x ", frame.payload[i]);
                }
                if (frame.len > 32) fprintf(stderr, "...");
                fprintf(stderr, "\n");

                mesh_frame_reader_reset(&reader);
            }
        }
    }

    fprintf(stderr, "[sim] Reader thread exiting\n");
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Session management
 * ───────────────────────────────────────────────────────────── */

static SimSession *sim_find_session(uint32_t node_id) {
    for (int i = 0; i < sim.session_count; i++) {
        if (sim.sessions[i].active && sim.sessions[i].node_id == node_id) {
            return &sim.sessions[i];
        }
    }
    return NULL;
}

static SimSession *sim_new_session(uint32_t node_id) {
    if (sim.session_count >= MAX_SESSIONS) {
        fprintf(stderr, "[sim] ERROR max sessions reached\n");
        return NULL;
    }

    SimSession *s = &sim.sessions[sim.session_count++];
    s->node_id    = node_id;
    s->session_id = sim.next_session_id++;
    s->active     = true;
    s->packets_sent = s->packets_recv = 0;
    s->bytes_sent = s->bytes_recv = 0;

    fprintf(stderr, "[sim] NEW SESSION  node=%08x session=%08x\n",
            s->node_id, s->session_id);
    return s;
}

/* ─────────────────────────────────────────────────────────────
 * Command handlers
 * ───────────────────────────────────────────────────────────── */

static void cmd_session(const char *args) {
    uint32_t node_id = 0;
    if (sscanf(args, "%x", &node_id) != 1) {
        fprintf(stderr, "[sim] usage: session <node_id_hex>\n");
        return;
    }

    pthread_mutex_lock(&sim_mutex);
    SimSession *s = sim_new_session(node_id);
    if (s) {
        /* Send an empty "hello" packet to announce the session */
        uint8_t hello[] = { 0x00 }; /* session open marker */
        sim_send_frame(hello, 1, s->node_id, s->session_id);
        s->packets_sent++;
    }
    pthread_mutex_unlock(&sim_mutex);
}

static void cmd_send(const char *args) {
    uint32_t node_id = 0;
    char hex_data[1024] = {0};

    if (sscanf(args, "%x %1023s", &node_id, hex_data) != 2) {
        fprintf(stderr, "[sim] usage: send <node_id_hex> <hex_data>\n");
        return;
    }

    /* Decode hex string */
    size_t hex_len = strlen(hex_data);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "[sim] hex_data must have even length\n");
        return;
    }
    size_t data_len = hex_len / 2;
    uint8_t *data = malloc(data_len);
    for (size_t i = 0; i < data_len; i++) {
        unsigned byte;
        sscanf(hex_data + i * 2, "%02x", &byte);
        data[i] = (uint8_t)byte;
    }

    pthread_mutex_lock(&sim_mutex);
    SimSession *s = sim_find_session(node_id);
    if (!s) s = sim_new_session(node_id);
    if (s) {
        sim_send_frame(data, data_len, s->node_id, s->session_id);
        s->packets_sent++;
        s->bytes_sent += data_len;
    }
    pthread_mutex_unlock(&sim_mutex);
    free(data);
}

static void cmd_http(const char *args) {
    uint32_t node_id = 0;
    char url[512] = {0};

    if (sscanf(args, "%x %511s", &node_id, url) != 2) {
        fprintf(stderr, "[sim] usage: http <node_hex> <url>\n");
        return;
    }

    /* Build a minimal HTTP GET request */
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n"
        "User-Agent: deadmesh-sim/1.0\r\n"
        "\r\n", url);

    fprintf(stderr, "[sim] Sending HTTP GET for %s (%d bytes)\n", url, req_len);

    /* Fragment into 220-byte chunks with deadmesh chunk header */
    int total_chunks = (req_len + 219) / 220;

    pthread_mutex_lock(&sim_mutex);
    SimSession *s = sim_find_session(node_id);
    if (!s) s = sim_new_session(node_id);
    if (s) {
        for (int i = 0; i < total_chunks; i++) {
            int offset    = i * 220;
            int chunk_len = (req_len - offset < 220) ? req_len - offset : 220;

            /* deadmesh chunk header: seq(4 LE) + total(4 LE) + data */
            uint8_t chunk_buf[220 + 8];
            uint32_t seq   = (uint32_t)i;
            uint32_t total = (uint32_t)total_chunks;
            memcpy(chunk_buf + 0, &seq,   4);
            memcpy(chunk_buf + 4, &total, 4);
            memcpy(chunk_buf + 8, request + offset, chunk_len);

            sim_send_frame(chunk_buf, chunk_len + 8,
                           s->node_id, s->session_id);
            s->packets_sent++;
            s->bytes_sent += chunk_len;

            /* Small gap between chunks to simulate LoRa airtime */
            usleep(50000); /* 50ms between chunks */
        }
    }
    pthread_mutex_unlock(&sim_mutex);
}

static void cmd_loss(const char *args) {
    int pct = 0;
    if (sscanf(args, "%d", &pct) != 1 || pct < 0 || pct > 100) {
        fprintf(stderr, "[sim] usage: loss <0-100>\n");
        return;
    }
    sim.loss_pct = pct;
    fprintf(stderr, "[sim] Packet loss set to %d%%\n", pct);
}

static void cmd_delay(const char *args) {
    int ms = 0;
    if (sscanf(args, "%d", &ms) != 1 || ms < 0) {
        fprintf(stderr, "[sim] usage: delay <ms>\n");
        return;
    }
    sim.delay_ms = ms;
    fprintf(stderr, "[sim] Injection delay set to %dms\n", ms);
}

static void cmd_hops(const char *args) {
    int hops = 0;
    if (sscanf(args, "%d", &hops) != 1 || hops < 1 || hops > 7) {
        fprintf(stderr, "[sim] usage: hops <1-7>\n");
        return;
    }
    sim.hop_limit = hops;
    fprintf(stderr, "[sim] Hop limit set to %d\n", hops);
}

static void cmd_status(void) {
    fprintf(stderr, "\n[sim] ── Status ────────────────────────────────\n");
    fprintf(stderr, "[sim]   PTY slave : %s\n",   sim.slave_name);
    fprintf(stderr, "[sim]   Loss      : %d%%\n", sim.loss_pct);
    fprintf(stderr, "[sim]   Delay     : %dms\n", sim.delay_ms);
    fprintf(stderr, "[sim]   Hop limit : %d\n",   sim.hop_limit);
    fprintf(stderr, "[sim]   Frames sent/recv/dropped: %lu / %lu / %lu\n",
            sim.frames_sent, sim.frames_recv, sim.frames_dropped);
    fprintf(stderr, "[sim]   Sessions  : %d\n", sim.session_count);

    pthread_mutex_lock(&sim_mutex);
    for (int i = 0; i < sim.session_count; i++) {
        SimSession *s = &sim.sessions[i];
        if (!s->active) continue;
        fprintf(stderr, "[sim]     [%d] node=%08x session=%08x  "
                "pkt\u2191%lu \u2193%lu  bytes\u2191%lu \u2193%lu\n",
                i, s->node_id, s->session_id,
                s->packets_sent, s->packets_recv,
                s->bytes_sent, s->bytes_recv);
    }
    pthread_mutex_unlock(&sim_mutex);
    fprintf(stderr, "[sim] ────────────────────────────────────────────\n\n");
}

static void cmd_help(void) {
    printf("\ndeadmesh simulator commands:\n"
           "  session <node_hex>            Start new session from node\n"
           "  send <node_hex> <hex_data>    Send raw hex payload\n"
           "  http <node_hex> <url>         Send HTTP GET request\n"
           "  loss <0-100>                  Set packet loss %%\n"
           "  delay <ms>                    Set injection delay\n"
           "  hops <1-7>                    Set hop limit on packets\n"
           "  status                        Print stats and sessions\n"
           "  help                          Print this\n"
           "  quit / exit / q               Exit\n\n");
}

/* ─────────────────────────────────────────────────────────────
 * Main loop
 * ───────────────────────────────────────────────────────────── */

static void handle_sigint(int sig) {
    (void)sig;
    sim.running = false;
}

int main(int argc, char *argv[]) {
    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--loss") == 0 && i + 1 < argc) {
            sim.loss_pct = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--delay") == 0 && i + 1 < argc) {
            sim.delay_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--hops") == 0 && i + 1 < argc) {
            sim.hop_limit = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            fprintf(stderr, "Usage: mesh-sim [--loss N] [--delay MS] [--hops N]\n");
            return 1;
        }
    }

    /* Defaults */
    if (sim.hop_limit == 0) sim.hop_limit = 3;
    sim.running         = true;
    sim.next_session_id = 1;
    srand((unsigned)time(NULL));
    mesh_frame_reader_init(&sim.reader);

    /* Open PTY */
    if (!sim_open_pty()) return 1;

    signal(SIGINT,  handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("\n");
    printf("  deadmesh simulator\n");
    printf("  ══════════════════\n");
    printf("  PTY slave: %s\n", sim.slave_name);
    printf("  Configure deadmesh: serial_port = %s\n\n", sim.slave_name);
    printf("  Type 'help' for commands, 'status' for stats\n\n");
    fflush(stdout);

    /* Start reader thread */
    pthread_t reader_tid;
    pthread_create(&reader_tid, NULL, reader_thread, NULL);

    /* Command loop */
    char line[1024];
    while (sim.running) {
        printf("sim> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        /* Strip trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;

        /* Parse command */
        char cmd[64] = {0};
        char args[960] = {0};
        sscanf(line, "%63s %959[^\n]", cmd, args);

        if      (strcmp(cmd, "session") == 0) cmd_session(args);
        else if (strcmp(cmd, "send")    == 0) cmd_send(args);
        else if (strcmp(cmd, "http")    == 0) cmd_http(args);
        else if (strcmp(cmd, "loss")    == 0) cmd_loss(args);
        else if (strcmp(cmd, "delay")   == 0) cmd_delay(args);
        else if (strcmp(cmd, "hops")    == 0) cmd_hops(args);
        else if (strcmp(cmd, "status")  == 0) cmd_status();
        else if (strcmp(cmd, "help")    == 0) cmd_help();
        else if (strcmp(cmd, "quit")    == 0 ||
                 strcmp(cmd, "exit")    == 0 ||
                 strcmp(cmd, "q")       == 0) {
            sim.running = false;
        } else {
            fprintf(stderr, "[sim] unknown command '%s' — try 'help'\n", cmd);
        }
    }

    /* Shutdown */
    sim.running = false;
    pthread_join(reader_tid, NULL);
    close(sim.master_fd);
    close(sim.slave_fd);

    printf("\n[sim] Exiting. Frames: sent=%lu recv=%lu dropped=%lu\n",
           sim.frames_sent, sim.frames_recv, sim.frames_dropped);
    return 0;
}