/**
 * client_transport.c — Meshtastic radio transport for deadmesh-client
 *
 * Implements the send/receive path connecting the proxy core to a
 * Meshtastic radio. Mirrors the gateway's meshtastic.c transport but
 * runs in the opposite direction: browser → mesh → gateway → internet.
 *
 * Radio connection modes (compile-time, default TCP):
 *
 *   TCP  (default):
 *     Connects to Meshtastic app API at localhost:4403.
 *     Same ToRadio/FromRadio protobuf framing as serial.
 *     Works on Android (Termux) without root.
 *
 *   Serial (-DCLIENT_TRANSPORT_SERIAL):
 *     Opens /dev/rfcomm0 (BT) or /dev/ttyACM0 (USB) directly.
 *
 * Wire protocol (same as gateway):
 *   Out: logical_session_id(4LE) + seq(4LE) + total(4LE) + payload
 *        → Data → MeshPacket (unique packet.id per chunk)
 *        → ToRadio → 0x94 0xC3 framing → radio fd
 *   In:  0x94 0xC3 framing → FromRadio → portnum==custom_port
 *        → strip 12-byte header → push to MeshSession pipe
 */

#include "client_transport.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

/* nanopb + Meshtastic protobufs */
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "mesh.pb.h"
#include "portnums.pb.h"

#include "mesh_framing.h"
#include "mesh_session.h"

/* ─────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────── */

#define CLIENT_MESHTASTIC_TCP_PORT  4403
#define CLIENT_MESHTASTIC_TCP_HOST  "127.0.0.1"
#define CLIENT_FRAGMENT_SIZE        220
#define CLIENT_SESSION_TIMEOUT_MS   60000

/* ─────────────────────────────────────────────────────────────
 * nanopb encode / decode callback helpers
 *
 * Data.payload is a pb_callback_t (plugin-mode codegen).
 * We use the same pattern as meshtastic.c.
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *buf;
    size_t         len;
} PbEncodeCtx;

typedef struct {
    uint8_t *buf;
    size_t   len;       /* filled in by callback */
    size_t   max;
} PbDecodeCtx;

static bool payload_encode_cb(pb_ostream_t *stream,
                               const pb_field_iter_t *field,
                               void * const *arg) {
    const PbEncodeCtx *ctx = (const PbEncodeCtx *)*arg;
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, ctx->buf, ctx->len);
}

static bool payload_decode_cb(pb_istream_t *stream,
                               const pb_field_iter_t *field,
                               void **arg) {
    (void)field;
    PbDecodeCtx *ctx = (PbDecodeCtx *)*arg;
    ctx->len = stream->bytes_left;
    if (ctx->len > ctx->max) {
        g_warning("client: payload too large (%zu > %zu), truncating",
                  ctx->len, ctx->max);
        ctx->len = ctx->max;
    }
    return pb_read(stream, ctx->buf, ctx->len);
}

/* ─────────────────────────────────────────────────────────────
 * Forward declarations
 * ───────────────────────────────────────────────────────────── */

static gpointer client_reader_thread(gpointer user_data);
static void     handle_incoming_frame(ClientTransport *ct,
                                       const MeshFrame *frame);

/* ─────────────────────────────────────────────────────────────
 * Radio connection — TCP
 * ───────────────────────────────────────────────────────────── */

static int connect_tcp(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        g_warning("client: socket() failed: %s", g_strerror(errno));
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        g_warning("client: invalid host: %s", host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        g_warning("client: connect %s:%u failed: %s",
                  host, port, g_strerror(errno));
        close(fd);
        return -1;
    }

    g_info("client: connected to %s:%u", host, port);
    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * Radio connection — Serial
 * ───────────────────────────────────────────────────────────── */

#ifdef CLIENT_TRANSPORT_SERIAL
static int connect_serial(const char *device, int baud) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        g_warning("client: open %s failed: %s", device, g_strerror(errno));
        return -1;
    }

    /* Set blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    struct termios tty = {0};
    if (tcgetattr(fd, &tty) != 0) {
        g_warning("client: tcgetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    speed_t speed = (baud == 115200) ? B115200 : B9600;
    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);
    cfmakeraw(&tty);
    tty.c_cc[VMIN]  = 1;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        g_warning("client: tcsetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    g_info("client: opened serial %s at %d baud", device, baud);
    return fd;
}
#endif /* CLIENT_TRANSPORT_SERIAL */

/* ─────────────────────────────────────────────────────────────
 * want_config handshake
 *
 * Sends ToRadio{want_config_id=1} to kick off the startup dump.
 * Without this the radio stays silent.
 * ───────────────────────────────────────────────────────────── */

static gboolean send_want_config(ClientTransport *ct) {
    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
    to_radio.payload_variant.want_config_id = 1;

    uint8_t pb_buf[64];
    pb_ostream_t stream = pb_ostream_from_buffer(pb_buf, sizeof(pb_buf));
    if (!pb_encode(&stream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("client: want_config encode failed: %s",
                  PB_GET_ERROR(&stream));
        return FALSE;
    }

    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL];
    size_t frame_len = mesh_frame_encode(pb_buf,
                                          (uint16_t)stream.bytes_written,
                                          frame_buf, sizeof(frame_buf));
    if (frame_len == 0) {
        g_warning("client: want_config frame encoding failed");
        return FALSE;
    }

    g_mutex_lock(&ct->write_mutex);
    ssize_t written = write(ct->radio_fd, frame_buf, frame_len);
    g_mutex_unlock(&ct->write_mutex);

    if (written < 0 || (size_t)written != frame_len) {
        g_warning("client: want_config write failed: %s", g_strerror(errno));
        return FALSE;
    }

    g_info("client: sent want_config handshake (%zu bytes)", frame_len);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * MeshSendFn — called by MeshOutputStream for each chunk
 *
 * Mirrors send_chunk() in meshtastic.c:
 *   - writes to radio_fd (TCP or serial)
 *   - uses gateway_node_id as packet.to
 *   - uses unique packet.id per chunk to defeat firmware dedup
 *     (session identity is in the 12-byte logical header, not packet.id)
 * ───────────────────────────────────────────────────────────── */

int client_send_fn(const uint8_t *payload, size_t len,
                   uint32_t seq, uint32_t total,
                   gpointer user_data) {
    ClientSendCtx *ctx = (ClientSendCtx *)user_data;

    if (ctx->radio_fd < 0) {
        g_warning("client: send_fn — radio not connected");
        return 0;
    }

    /* Build chunk: logical_session_id(4LE) + seq(4LE) + total(4LE) + payload */
    uint8_t chunk_buf[12 + CLIENT_FRAGMENT_SIZE];
    if (len > CLIENT_FRAGMENT_SIZE) {
        g_warning("client: chunk too large (%zu)", len);
        return 0;
    }
    uint32_t logical_session_id = ctx->session_id;
    memcpy(chunk_buf,      &logical_session_id, 4);
    memcpy(chunk_buf + 4,  &seq,                4);
    memcpy(chunk_buf + 8,  &total,              4);
    memcpy(chunk_buf + 12, payload,             len);
    size_t chunk_total = 12 + len;

    /* Data sub-message — payload is a pb_callback_t, use encode callback */
    meshtastic_Data pb_data = meshtastic_Data_init_default;
    pb_data.portnum = (meshtastic_PortNum)ctx->custom_port;

    g_message("Client sending on portnum=%d session=%08x chunk %u/%u (%zu bytes payload)",
          ctx->custom_port, ctx->session_id, seq, total, len);

    PbEncodeCtx payload_ctx = { chunk_buf, chunk_total };
    pb_data.payload.funcs.encode = payload_encode_cb;
    pb_data.payload.arg          = &payload_ctx;

    /* MeshPacket — addressed TO the gateway */
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
    packet.which_payload_variant            = meshtastic_MeshPacket_decoded_tag;
    packet.payload_variant.decoded          = pb_data;
    packet.from                             = ctx->local_node_id;
    packet.to                               = ctx->gateway_node_id;
    packet.id                               = (uint32_t)(g_get_monotonic_time()
                                                ^ ((uint64_t)ctx->session_id << 16)
                                                ^ seq);
    packet.hop_limit                        = 3;

    uint8_t packet_buf[600];
    pb_ostream_t pstream = pb_ostream_from_buffer(packet_buf, sizeof(packet_buf));
    if (!pb_encode(&pstream, meshtastic_MeshPacket_fields, &packet)) {
        g_warning("client: MeshPacket encode failed: %s", PB_GET_ERROR(&pstream));
        return 0;
    }

    /* ToRadio wrapper */
    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant        = meshtastic_ToRadio_packet_tag;
    to_radio.payload_variant.packet       = packet;

    uint8_t to_buf[700];
    pb_ostream_t tostream = pb_ostream_from_buffer(to_buf, sizeof(to_buf));
    if (!pb_encode(&tostream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("client: ToRadio encode failed: %s", PB_GET_ERROR(&tostream));
        return 0;
    }

    /* Serial framing */
    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL];
    size_t frame_len = mesh_frame_encode(to_buf,
                                          (uint16_t)tostream.bytes_written,
                                          frame_buf, sizeof(frame_buf));
    if (frame_len == 0) {
        g_warning("client: frame encoding failed");
        return 0;
    }

    /* Write — mutex protects concurrent proxy worker threads */
    g_mutex_lock(ctx->write_mutex);
    ssize_t written = write(ctx->radio_fd, frame_buf, frame_len);
    g_mutex_unlock(ctx->write_mutex);

    if (written < 0 || (size_t)written != frame_len) {
        g_warning("client: radio write failed: %s", g_strerror(errno));
        return 0;
    }

    g_debug("client: sent chunk %u/%u session=%08x (%zu bytes)",
            seq + 1, total, ctx->session_id, len);
    return 1;
}

/* ─────────────────────────────────────────────────────────────
 * Incoming frame handler
 *
 * Called by the reader thread for each decoded FromRadio frame.
 * We act on portnum==custom_port packets from the gateway.
 * Sessions are keyed by (gateway_node_id, logical_session_id) — the
 * logical_session_id is carried in the first 4 bytes of the chunk payload,
 * separate from packet.id which is unique per chunk to defeat firmware dedup.
 * ───────────────────────────────────────────────────────────── */

static void handle_incoming_frame(ClientTransport *ct,
                                   const MeshFrame *frame) {

    /* Pass 1: decode FromRadio with NO payload callback pre-wired.
     * nanopb zeroes the oneof union when it writes packet_tag, so any
     * callback set on packet.payload_variant.decoded.payload is destroyed
     * before it fires.  We get from/to/portnum here; payload comes in
     * pass 2 via a direct meshtastic_Data decode on the raw wire bytes. */
    meshtastic_FromRadio from_radio = meshtastic_FromRadio_init_default;

    pb_istream_t istream = pb_istream_from_buffer(frame->payload, frame->len);
    if (!pb_decode(&istream, meshtastic_FromRadio_fields, &from_radio)) {
        g_warning("client: FromRadio decode failed: %s", PB_GET_ERROR(&istream));
        return;
    }

    switch (from_radio.which_payload_variant) {

        case meshtastic_FromRadio_my_info_tag:
            if (ct->local_node_id == 0) {
                ct->local_node_id =
                    from_radio.payload_variant.my_info.my_node_num;
                g_info("client: local node ID detected: %08x",
                       ct->local_node_id);
            }
            return;

        case meshtastic_FromRadio_config_complete_id_tag:
            g_info("client: mesh state sync complete (id=%u)",
                   from_radio.payload_variant.config_complete_id);
            return;

        case meshtastic_FromRadio_packet_tag:
            break;  /* handled below */

        /* suppress startup noise */
        case meshtastic_FromRadio_config_tag:
        case meshtastic_FromRadio_moduleConfig_tag:
        case meshtastic_FromRadio_channel_tag:
        case meshtastic_FromRadio_node_info_tag:
        case meshtastic_FromRadio_rebooted_tag:
        case meshtastic_FromRadio_queueStatus_tag:
        case meshtastic_FromRadio_metadata_tag:
        case meshtastic_FromRadio_fileInfo_tag:
        case meshtastic_FromRadio_deviceuiConfig_tag:
        case meshtastic_FromRadio_log_record_tag:
            return;

        default:
            g_debug("client: unhandled FromRadio variant %d",
                    from_radio.which_payload_variant);
            return;
    }

    /* ── packet_tag path ──────────────────────────────────────── */
    meshtastic_MeshPacket *pkt = &from_radio.payload_variant.packet;

    if (pkt->which_payload_variant != meshtastic_MeshPacket_decoded_tag) {
        g_debug("client: encrypted packet from %08x — skipping", pkt->from);
        return;
    }

    int portnum = (int)pkt->payload_variant.decoded.portnum;

    g_debug("client: packet from=%08x to=%08x port=%d",
            pkt->from, pkt->to, portnum);

    if (portnum != (int)ct->custom_port)
        return;

    if (pkt->from != ct->gateway_node_id) {
        g_debug("client: portnum=%d from unknown node %08x (expected %08x)",
                portnum, pkt->from, ct->gateway_node_id);
        return;
    }

    /* Pass 2: manual wire scan to extract the Data submessage bytes,
     * then decode meshtastic_Data directly with callbacks pre-wired.
     *
     * We cannot pre-wire payload_decode_cb before pb_decode() on
     * FromRadio/MeshPacket because nanopb zeroes each oneof union
     * before writing the selected variant, destroying the callback.
     *
     * Strategy: walk the raw protobuf bytes to find:
     *   FromRadio field 2 (packet, LEN)  →  MeshPacket field 4 (decoded, LEN)
     * then pb_decode meshtastic_Data directly — it has no oneof, so
     * the callback pointer survives.
     *
     * Wire format: (field_number << 3) | wire_type
     *   wire_type 0 = varint   wire_type 2 = LEN   wire_type 5 = 32-bit
     *   wire_type 1 = 64-bit
     */

    uint8_t     payload_buf[512];
    PbDecodeCtx decode_ctx  = { payload_buf, 0, sizeof(payload_buf) };
    gboolean    payload_ok  = FALSE;

    #define READ_VARINT(ptr, endp, out, ok) do {                        \
        uint64_t _v = 0; int _s = 0; (ok) = false;                     \
        while ((ptr) < (endp)) {                                        \
            uint8_t _b = *(ptr)++;                                      \
            _v |= (uint64_t)(_b & 0x7F) << _s; _s += 7;               \
            if (!(_b & 0x80)) { (out) = _v; (ok) = true; break; }     \
        }                                                               \
    } while (0)

    {
        const uint8_t *p   = frame->payload;
        const uint8_t *end = frame->payload + frame->len;

        while (p < end) {
            uint64_t tag_val; bool tok;
            READ_VARINT(p, end, tag_val, tok);
            if (!tok) break;

            uint32_t fn = (uint32_t)(tag_val >> 3);
            uint32_t wt = (uint32_t)(tag_val & 0x7);

            if (wt == 2) {                      /* LEN field */
                uint64_t flen; bool lok;
                READ_VARINT(p, end, flen, lok);
                if (!lok || p + flen > end) break;

                if (fn == (uint32_t)meshtastic_FromRadio_packet_tag) {
                    /* Found MeshPacket — scan it for field 4 (decoded) */
                    const uint8_t *pp   = p;
                    const uint8_t *pend = p + flen;

                    while (pp < pend) {
                        uint64_t t2; bool t2ok;
                        READ_VARINT(pp, pend, t2, t2ok);
                        if (!t2ok) break;

                        uint32_t fn2 = (uint32_t)(t2 >> 3);
                        uint32_t wt2 = (uint32_t)(t2 & 0x7);

                        if (wt2 == 2) {
                            uint64_t fl2; bool l2ok;
                            READ_VARINT(pp, pend, fl2, l2ok);
                            if (!l2ok || pp + fl2 > pend) break;

                            if (fn2 == (uint32_t)meshtastic_MeshPacket_decoded_tag) {
                                /* Found Data submessage — decode directly */
                                meshtastic_Data data_msg =
                                    meshtastic_Data_init_default;
                                data_msg.payload.funcs.decode = payload_decode_cb;
                                data_msg.payload.arg          = &decode_ctx;

                                pb_istream_t ds =
                                    pb_istream_from_buffer(pp, (size_t)fl2);
                                if (pb_decode(&ds, meshtastic_Data_fields,
                                              &data_msg)) {
                                    payload_ok = TRUE;
                                }
                                pp = pend;  /* done scanning MeshPacket */
                            } else {
                                pp += (size_t)fl2;
                            }
                        } else if (wt2 == 0) {
                            uint64_t dummy; bool dok;
                            READ_VARINT(pp, pend, dummy, dok);
                            (void)dummy;
                            if (!dok) break;
                        } else if (wt2 == 5) { pp += 4; }
                        else if (wt2 == 1)   { pp += 8; }
                        else break;
                    }

                    p += flen;
                    break;  /* done scanning FromRadio */
                } else {
                    p += flen;
                }
            } else if (wt == 0) {
                uint64_t dummy; bool dok;
                READ_VARINT(p, end, dummy, dok);
                (void)dummy;
                if (!dok) break;
            } else if (wt == 5) { p += 4; }
            else if (wt == 1)   { p += 8; }
            else break;
        }
    }

    #undef READ_VARINT

    if (!payload_ok || decode_ctx.len == 0) {
        g_warning("client: failed to extract payload from response "
                  "(payload_ok=%d len=%zu)", payload_ok, decode_ctx.len);
        return;
    }

    const uint8_t *raw     = payload_buf;
    size_t         raw_len = decode_ctx.len;

    if (raw_len < 12) {
        g_warning("client: response chunk too short (%zu bytes)", raw_len);
        return;
    }

    uint32_t logical_session_id = 0;
    uint32_t seq_num            = 0;
    uint32_t total_chunks       = 0;
    memcpy(&logical_session_id, raw,     4);
    memcpy(&seq_num,            raw + 4, 4);
    memcpy(&total_chunks,       raw + 8, 4);

    const uint8_t *chunk_data = raw + 12;
    size_t         chunk_len  = raw_len - 12;

    g_debug("client: response chunk %u/%u session=%08x len=%zu",
            seq_num + 1, total_chunks, logical_session_id, chunk_len);

    /* Key on logical_session_id from payload, not pkt->id */
    MeshSession *session = mesh_session_get_or_create(
        ct->sessions, ct->gateway_node_id, logical_session_id);

    if (seq_num == 0 || session->expected_chunks == 0)
        mesh_session_init_reassembly(session, total_chunks);

    bool complete = mesh_session_record_chunk(
        session, seq_num, chunk_data, chunk_len);

    ct->frames_recv++;

    if (!complete)
        return;

    /* All chunks in — push assembled response to the MeshStream pipe */
    if (session->user_data) {
        MeshStream *ms = (MeshStream *)session->user_data;
        mesh_stream_push_data(ms,
                              session->assembly_buf->data,
                              session->assembly_buf->len);
        g_info("client: response complete — pushed %u bytes session=%08x",
               session->assembly_buf->len, logical_session_id);
    } else {
        g_warning("client: session %08x complete but no MeshStream assigned",
                  logical_session_id);
    }

    mesh_session_init_reassembly(session, 0);
}

/* ─────────────────────────────────────────────────────────────
 * Reader thread
 * ───────────────────────────────────────────────────────────── */

static gpointer client_reader_thread(gpointer user_data) {
    ClientTransport *ct = (ClientTransport *)user_data;
    MeshFrameReader  reader;
    mesh_frame_reader_init(&reader);

    g_info("client: reader thread started (fd=%d)", ct->radio_fd);

    uint8_t buf[512];
    while (ct->running) {
        ssize_t n = read(ct->radio_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            g_warning("client: radio read error: %s", g_strerror(errno));
            break;
        }
        if (n == 0) {
            g_info("client: radio connection closed");
            break;
        }

        /* Feed bytes one at a time — mesh_frame_reader_push expects
         * (reader, const uint8_t *data, size_t len, MeshFrame *out) */
        for (ssize_t i = 0; i < n; i++) {
            if (mesh_frame_reader_push(&reader, buf + i, 1)) {
                MeshFrame frame;
                if (mesh_frame_get(&reader, &frame)) {
                    handle_incoming_frame(ct, &frame);
                }
            }
        }
    }

    g_info("client: reader thread exiting");
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────── */

ClientTransport *client_transport_new(uint32_t gateway_node_id,
                                       uint32_t custom_port) {
    ClientTransport *ct = g_new0(ClientTransport, 1);
    ct->radio_fd         = -1;
    ct->gateway_node_id  = gateway_node_id;
    ct->custom_port      = custom_port > 0 ? custom_port : 100;
    ct->next_session_id  = (uint32_t)(g_get_monotonic_time() & 0xFFFFFFFF);
    ct->sessions         = mesh_session_table_new(CLIENT_SESSION_TIMEOUT_MS);
    g_mutex_init(&ct->write_mutex);
    g_mutex_init(&ct->session_id_mutex);
    return ct;
}

gboolean client_transport_connect(ClientTransport *ct,
                                   const char *host_or_device) {
#ifdef CLIENT_TRANSPORT_SERIAL
    ct->radio_fd = connect_serial(host_or_device, 115200);
#else
    (void)host_or_device;
    ct->radio_fd = connect_tcp(CLIENT_MESHTASTIC_TCP_HOST,
                                CLIENT_MESHTASTIC_TCP_PORT);
#endif

    if (ct->radio_fd < 0)
        return FALSE;

    if (!send_want_config(ct)) {
        close(ct->radio_fd);
        ct->radio_fd = -1;
        return FALSE;
    }

    ct->running       = TRUE;
    ct->reader_thread = g_thread_new("client-reader",
                                      client_reader_thread, ct);

    g_info("client: transport ready — gateway=%08x port=%u",
           ct->gateway_node_id, ct->custom_port);
    return TRUE;
}

ClientSendCtx *client_transport_new_session(ClientTransport *ct,
                                             MeshSession    **out_session) {
    g_mutex_lock(&ct->session_id_mutex);
    uint32_t sid = ct->next_session_id++;
    g_mutex_unlock(&ct->session_id_mutex);

    /* Get/create the session — user_data will be set by caller after
     * the MeshStream is created (chicken-and-egg otherwise)          */
    MeshSession *session = mesh_session_get_or_create(
        ct->sessions, ct->gateway_node_id, sid);

    if (out_session)
        *out_session = session;

    ClientSendCtx *ctx   = g_new0(ClientSendCtx, 1);
    ctx->radio_fd         = ct->radio_fd;
    ctx->local_node_id    = ct->local_node_id;
    ctx->gateway_node_id  = ct->gateway_node_id;
    ctx->session_id       = sid;
    ctx->custom_port      = ct->custom_port;
    ctx->write_mutex      = &ct->write_mutex;

    g_debug("client: new session %08x → gateway %08x", sid, ct->gateway_node_id);
    return ctx;
}

void client_transport_free(ClientTransport *ct) {
    if (!ct) return;

    ct->running = FALSE;

    if (ct->radio_fd >= 0) {
        shutdown(ct->radio_fd, SHUT_RDWR);
        close(ct->radio_fd);
        ct->radio_fd = -1;
    }

    if (ct->reader_thread) {
        g_thread_join(ct->reader_thread);
        ct->reader_thread = NULL;
    }

    mesh_session_table_free(ct->sessions);
    g_mutex_clear(&ct->write_mutex);
    g_mutex_clear(&ct->session_id_mutex);
    g_free(ct);
}