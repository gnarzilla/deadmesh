/**
 * deadmesh - Meshtastic Transport Plugin (revised)
 *
 * Wires the Meshtastic serial radio into the deadlight proxy core.
 *
 * Architecture:
 *   serial fd
 *     └─> mesh_frame_read_blocking()   [framing layer]
 *           └─> mesh_session_get_or_create()  [session routing]
 *                 └─> DeadlightConnection     [proxy core, unmodified]
 *
 * What changed from the original:
 *   - Serial framing is now correct (0x94 0xC3 length-prefix state machine)
 *   - reader_thread uses blocking reads — no 100ms busy-poll
 *   - Session routing maps (src_node_id, session_id) -> connection
 *   - send_chunk uses nanopb, not a raw memcpy struct cast
 *   - Reassembly uses the bitmap tracker in mesh_session — handles out-of-order
 *   - on_connection_close frees session state cleanly
 *   - Serial open moved to a dedicated helper with proper baud rate config
 *   - Node table: upserts MeshNode into context->node_table on every packet
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "core/plugins.h"
#include "core/deadlight.h"
#include "mesh_framing.h"
#include "mesh_session.h"

/* nanopb */
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "mesh.pb.h"
#include "portnums.pb.h"

/* ─────────────────────────────────────────────────────────────
 * Plugin state
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    /* Context — needed by reader thread to create connections */
    DeadlightContext *context;

    /* Config */
    gchar    *serial_device;
    int       baud_rate;
    uint32_t  custom_port;
    uint32_t  local_node_id;
    gboolean  enabled;

    /* Serial fd — owned by this struct */
    int       serial_fd;

    /* Framing */
    MeshFrameReader frame_reader;

    /* Session routing */
    MeshSessionTable *sessions;

    /* Reader thread */
    GThread          *reader_thread;
    volatile gboolean running;

    /* Write mutex — reader thread reads, worker threads write */
    GMutex            write_mutex;

    /* Stats */
    guint64 frames_sent;
    guint64 frames_recv;
    guint64 frames_dropped;
    guint64 encode_errors;
} MeshtasticPlugin;

/* ─────────────────────────────────────────────────────────────
 * Forward declarations
 * ───────────────────────────────────────────────────────────── */

static gpointer reader_thread_func(gpointer user_data);
static gboolean send_chunk(MeshtasticPlugin *mp,
                            DeadlightConnection *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t seq, uint32_t total);
static int  open_serial(const char *device, int baud);
static int  baud_constant(int baud_rate);
static void handle_incoming_frame(MeshtasticPlugin *mp,
                                   DeadlightContext *context,
                                   const MeshFrame *frame);

/* ─────────────────────────────────────────────────────────────
 * Node table helpers
 * ───────────────────────────────────────────────────────────── */

/* Get-or-create a MeshNode in context->node_table.
 * Caller must hold context->node_table_mutex.               */
static MeshNode *node_upsert(DeadlightContext *context, uint32_t node_id)
{
    if (!context->node_table) return NULL;

    MeshNode *node = g_hash_table_lookup(context->node_table,
                                          GUINT_TO_POINTER(node_id));
    if (!node) {
        node = g_new0(MeshNode, 1);
        node->node_id   = node_id;
        node->hops_away = -1;
        node->snr       = 0.0f;
        g_hash_table_insert(context->node_table,
                             GUINT_TO_POINTER(node_id), node);
    }
    node->last_heard = g_get_real_time() / G_USEC_PER_SEC;
    return node;
}

/* Update per-packet header fields (hops, SNR) for a source node.
 * Safe to call from the reader thread — takes the mutex itself.  */
static void node_update_from_packet(DeadlightContext *context,
                                     uint32_t node_id,
                                     int32_t  hops_away,
                                     float    snr)
{
    if (!context->node_table || node_id == 0) return;

    g_mutex_lock(&context->node_table_mutex);
    MeshNode *node = node_upsert(context, node_id);
    if (node) {
        if (hops_away >= 0)  node->hops_away = hops_away;
        node->snr = snr;
    }
    g_mutex_unlock(&context->node_table_mutex);
}


/* Broadcast a single node's current state via SSE.
 * Caller must NOT hold node_table_mutex.              */
static void node_sse_push(DeadlightContext *context, uint32_t node_id)
{
    if (!context->node_table) return;

    g_mutex_lock(&context->node_table_mutex);
    MeshNode *node = g_hash_table_lookup(context->node_table,
                                          GUINT_TO_POINTER(node_id));
    if (!node) { g_mutex_unlock(&context->node_table_mutex); return; }

    gchar *short_esc = g_strescape(node->short_name, NULL);
    gchar *long_esc  = g_strescape(node->long_name,  NULL);
    gchar *json = g_strdup_printf(
        "{\"id\":\"%08x\",\"short\":\"%s\",\"long\":\"%s\","
        "\"hops\":%d,\"snr\":%.1f,\"last_heard\":%" G_GINT64_FORMAT ","
        "\"battery\":%u,\"has_position\":%s,"
        "\"lat\":%.6f,\"lon\":%.6f,\"alt\":%d,\"is_local\":%s}",
        node->node_id, short_esc, long_esc,
        node->hops_away, (double)node->snr, node->last_heard,
        (unsigned)node->battery_level,
        node->has_position ? "true" : "false",
        node->latitude, node->longitude, node->altitude,
        node->is_local ? "true" : "false");
    g_free(short_esc);
    g_free(long_esc);
    g_mutex_unlock(&context->node_table_mutex);

    deadlight_sse_broadcast(context, "node_update", json);
    g_free(json);
}

/* ─────────────────────────────────────────────────────────────
 * nanopb callback helpers for Data.payload (bytes field)
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *buf;
    size_t         len;
} PbEncodeCtx;

typedef struct {
    uint8_t buf[256];
    size_t  len;
} PbDecodeCtx;

static bool payload_encode_cb(pb_ostream_t *stream,
                               const pb_field_t *field,
                               void * const *arg)
{
    const PbEncodeCtx *ctx = *arg;
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, ctx->buf, ctx->len);
}

static bool payload_decode_cb(pb_istream_t *stream,
                               const pb_field_t *field G_GNUC_UNUSED,
                               void **arg)
{
    PbDecodeCtx *ctx = *arg;
    ctx->len = stream->bytes_left;
    if (ctx->len > sizeof(ctx->buf)) {
        ctx->len = sizeof(ctx->buf);
        if (!pb_read(stream, ctx->buf, ctx->len)) return false;
        uint8_t discard[64];
        while (stream->bytes_left > 0) {
            size_t n = stream->bytes_left < sizeof(discard)
                     ? stream->bytes_left : sizeof(discard);
            if (!pb_read(stream, discard, n)) return false;
        }
        return true;
    }
    return pb_read(stream, ctx->buf, ctx->len);
}

typedef struct {
    char   buf[384];
} PbStringCtx;

static bool string_decode_cb(pb_istream_t *stream,
                              const pb_field_t *field G_GNUC_UNUSED,
                              void **arg)
{
    PbStringCtx *ctx = *arg;
    size_t len = stream->bytes_left;
    if (len >= sizeof(ctx->buf)) len = sizeof(ctx->buf) - 1;
    if (!pb_read(stream, (pb_byte_t *)ctx->buf, len)) return false;
    ctx->buf[len] = '\0';
    uint8_t discard[64];
    while (stream->bytes_left > 0) {
        size_t n = stream->bytes_left < sizeof(discard)
                 ? stream->bytes_left : sizeof(discard);
        if (!pb_read(stream, discard, n)) return false;
    }
    return true;
}

/* ─────────────────────────────────────────────────────────────
 * Serial helpers
 * ───────────────────────────────────────────────────────────── */

static gboolean send_want_config(MeshtasticPlugin *mp) {
    if (mp->serial_fd < 0) return FALSE;

    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
    to_radio.payload_variant.want_config_id = 0xDEAD1234;

    uint8_t pb_buf[128];
    pb_ostream_t stream = pb_ostream_from_buffer(pb_buf, sizeof(pb_buf));
    if (!pb_encode(&stream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("Meshtastic: failed to encode want_config: %s",
                  PB_GET_ERROR(&stream));
        return FALSE;
    }

    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL];
    size_t frame_len = mesh_frame_encode(pb_buf,
                                          (uint16_t)stream.bytes_written,
                                          frame_buf, sizeof(frame_buf));
    if (frame_len == 0) {
        g_warning("Meshtastic: failed to frame want_config");
        return FALSE;
    }

    ssize_t written = write(mp->serial_fd, frame_buf, frame_len);
    if (written < 0 || (size_t)written != frame_len) {
        g_warning("Meshtastic: failed to write want_config: %s",
                  g_strerror(errno));
        return FALSE;
    }

    tcflush(mp->serial_fd, TCIFLUSH);
    g_info("Meshtastic: sent want_config handshake (%zu bytes)", frame_len);
    return TRUE;
}

static int baud_constant(int baud_rate) {
    switch (baud_rate) {
        case 9600:   return B9600;
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
        default:
            g_warning("Meshtastic: unknown baud rate %d, defaulting to 115200",
                      baud_rate);
            return B115200;
    }
}

static int open_serial(const char *device, int baud_rate) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        g_warning("Meshtastic: cannot open %s: %s", device, g_strerror(errno));
        return -1;
    }

    struct termios tios;
    if (tcgetattr(fd, &tios) < 0) {
        g_warning("Meshtastic: tcgetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    cfmakeraw(&tios);
    cfsetispeed(&tios, baud_constant(baud_rate));
    cfsetospeed(&tios, baud_constant(baud_rate));

    tios.c_cflag |= (CLOCAL | CREAD);
    tios.c_cflag &= ~CSTOPB;
    tios.c_cflag &= ~CRTSCTS;
    tios.c_cc[VMIN]  = 1;
    tios.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tios) < 0) {
        g_warning("Meshtastic: tcsetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    tcflush(fd, TCIOFLUSH);
    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin lifecycle
 * ───────────────────────────────────────────────────────────── */

static gboolean meshtastic_init(DeadlightContext *context) {
    g_info("Meshtastic: initialising transport plugin");

    MeshtasticPlugin *mp = g_new0(MeshtasticPlugin, 1);
    mp->context = context;

    mp->enabled       = deadlight_config_get_bool(context,
                            "meshtastic", "enabled", TRUE);
    mp->serial_device = deadlight_config_get_string(context,
                            "meshtastic", "serial_port", "/dev/ttyACM0");
    mp->baud_rate     = deadlight_config_get_int(context,
                            "meshtastic", "baud_rate", 115200);
    mp->custom_port   = (uint32_t)deadlight_config_get_int(context,
                            "meshtastic", "custom_port", 100);
    mp->local_node_id = (uint32_t)deadlight_config_get_int(context,
                            "meshtastic", "mesh_node_id", 0);

    if (!mp->enabled) {
        g_info("Meshtastic: disabled in config, skipping init");
        g_free(mp->serial_device);
        g_free(mp);
        return TRUE;
    }

    mp->sessions = mesh_session_table_new(5 * 60 * 1000);
    mesh_frame_reader_init(&mp->frame_reader);

    mp->serial_fd = open_serial(mp->serial_device, mp->baud_rate);
    if (mp->serial_fd < 0) {
        g_warning("Meshtastic: failed to open serial port %s — "
                  "is the radio connected?", mp->serial_device);
        mp->serial_fd = -1;
    } else {
        g_info("Meshtastic: opened %s at %d baud (fd=%d)",
               mp->serial_device, mp->baud_rate, mp->serial_fd);
    }

    g_mutex_init(&mp->write_mutex);
    mp->running = TRUE;

    if (mp->serial_fd >= 0) {
        if (!send_want_config(mp)) {
            g_warning("Meshtastic: want_config handshake failed — "
                      "device may not stream packets");
        }
    }

    if (mp->serial_fd >= 0) {
        mp->reader_thread = g_thread_new("mesh-reader",
                                          reader_thread_func, mp);
    }

    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, NULL);
    }
    g_hash_table_insert(context->plugins_data,
                        g_strdup("meshtastic"), mp);

    if (context->mesh) {
        context->mesh->radio_fd = mp->serial_fd;
    }

    g_info("Meshtastic: transport ready — device=%s port=%u",
           mp->serial_device, mp->custom_port);
    return TRUE;
}

static void meshtastic_cleanup(DeadlightContext *context) {
    if (!context->plugins_data) return;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp) return;

    g_info("Meshtastic: shutting down transport");

    mp->running = FALSE;

    if (mp->serial_fd >= 0) {
        close(mp->serial_fd);
        mp->serial_fd = -1;
    }

    if (mp->reader_thread) {
        g_thread_join(mp->reader_thread);
        mp->reader_thread = NULL;
    }

    mesh_session_table_free(mp->sessions);
    g_mutex_clear(&mp->write_mutex);
    g_free(mp->serial_device);
    g_free(mp);

    g_hash_table_remove(context->plugins_data, "meshtastic");
}

/* ─────────────────────────────────────────────────────────────
 * Reader thread
 * ───────────────────────────────────────────────────────────── */

static gpointer reader_thread_func(gpointer user_data) {
    MeshtasticPlugin *mp = (MeshtasticPlugin *)user_data;
    DeadlightContext *context = mp->context;

    g_info("Meshtastic reader thread started (fd=%d)", mp->serial_fd);

    MeshFrameReader reader;
    mesh_frame_reader_init(&reader);

    while (mp->running && mp->serial_fd >= 0) {
        MeshFrame frame;

        if (!mesh_frame_read_blocking(mp->serial_fd, &reader, &frame)) {
            if (mp->running) {
                g_warning("Meshtastic: serial read failed — fd=%d err=%s",
                           mp->serial_fd, g_strerror(errno));
            }
            break;
        }

        mp->frames_recv++;
        mesh_frame_reader_reset(&reader);

        if (context) {
            handle_incoming_frame(mp, context, &frame);
        }

        if (mp->frames_recv % 100 == 0) {
            guint expired = mesh_session_expire(mp->sessions);
            if (expired > 0) {
                g_info("Meshtastic: expired %u idle sessions", expired);
            }
        }
    }

    g_info("Meshtastic reader thread exiting "
           "(frames recv=%lu sync_errors=%lu)",
           mp->frames_recv, reader.sync_errors);
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Incoming frame handler
 * ───────────────────────────────────────────────────────────── */

static void handle_incoming_frame(MeshtasticPlugin *mp,
                                   DeadlightContext *context,
                                   const MeshFrame *frame) {
    meshtastic_FromRadio from_radio = meshtastic_FromRadio_init_default;

    /* NOTE: do NOT pre-wire decoded.payload here — nanopb zeros the
     * MeshPacket union when it writes packet_tag, destroying any callback
     * pointer we set before the decode. Instead we re-decode the packet
     * payload in a second pass once we know which portnum we have.
     * decoded_payload is populated by that second pass below.           */
    PbDecodeCtx decoded_payload = {0};

    PbStringCtx log_message = {0};
    from_radio.payload_variant.log_record
              .message.funcs.decode = string_decode_cb;
    from_radio.payload_variant.log_record
              .message.arg = &log_message;

    /* NodeInfo user string callbacks — MUST be wired on the primary decode
     * or nanopb hits an unhandled callback field and aborts early, leaving
     * which_payload_variant unset so the switch falls to default.
     * Throwaway buffers here; node_info_tag re-decodes to read the values. */
    PbStringCtx ni_short_discard = {0};
    PbStringCtx ni_long_discard  = {0};
    from_radio.payload_variant.node_info.user
              .short_name.funcs.decode = string_decode_cb;
    from_radio.payload_variant.node_info.user
              .short_name.arg = &ni_short_discard;
    from_radio.payload_variant.node_info.user
              .long_name.funcs.decode = string_decode_cb;
    from_radio.payload_variant.node_info.user
              .long_name.arg = &ni_long_discard;

    pb_istream_t istream = pb_istream_from_buffer(frame->payload, frame->len);

    if (!pb_decode(&istream, meshtastic_FromRadio_fields, &from_radio)) {
        g_warning("Meshtastic: protobuf decode failed: %s",
                  PB_GET_ERROR(&istream));
        return;
    }

    switch (from_radio.which_payload_variant) {

        /* ── MeshPacket ─────────────────────────────────────── */
        case meshtastic_FromRadio_packet_tag: {
            meshtastic_MeshPacket *pkt = &from_radio.payload_variant.packet;

            /* Update node table on every decoded packet — hops + SNR */
            if (pkt->which_payload_variant == meshtastic_MeshPacket_decoded_tag) {
                node_update_from_packet(context,
                                        pkt->from,
                                        (int32_t)pkt->hop_start - (int32_t)pkt->hop_limit,
                                        pkt->rx_snr);

                int portnum = pkt->payload_variant.decoded.portnum;

                /* Decode Data.payload by walking the wire directly.
                 *
                 * We cannot pre-wire payload_decode_cb before pb_decode()
                 * on a FromRadio or MeshPacket struct because nanopb zeroes
                 * each oneof union before writing the selected variant,
                 * destroying any callback pointer we set beforehand.
                 *
                 * Strategy: manually scan the raw protobuf bytes to locate
                 * the MeshPacket (FromRadio field 2) and then the Data
                 * submessage (MeshPacket field 4), then decode meshtastic_Data
                 * directly — it has no oneof, so the callback survives.
                 *
                 * Protobuf wire format: each field is (tag<<3)|wire_type
                 *   wire_type 0 = varint, 2 = length-delimited (LEN)
                 * We skip fields we don't care about by reading their length
                 * and jumping past them.                                    */
                {
                    const uint8_t *p   = frame->payload;
                    const uint8_t *end = frame->payload + frame->len;

                    /* Helper lambda (as inline block) to decode a varint */
                    #define READ_VARINT(ptr, endp, out, ok) do {                                   uint64_t _val = 0; int _shift = 0; (ok) = false;                          while ((ptr) < (endp)) {                                                       uint8_t _b = *(ptr)++;                                                     _val |= (uint64_t)(_b & 0x7F) << _shift;                                  _shift += 7;                                                               if (!(_b & 0x80)) { (out) = _val; (ok) = true; break; }                         }                                                                      } while(0)

                    /* Scan FromRadio for field 2 (packet, LEN) */
                    while (p < end) {
                        uint64_t tag_val; bool tok;
                        READ_VARINT(p, end, tag_val, tok);
                        if (!tok) break;
                        uint32_t field_num = (uint32_t)(tag_val >> 3);
                        uint32_t wire_type = (uint32_t)(tag_val & 0x7);

                        if (wire_type == 2) { /* LEN */
                            uint64_t flen; bool lok;
                            READ_VARINT(p, end, flen, lok);
                            if (!lok || p + flen > end) break;

                            if (field_num == meshtastic_FromRadio_packet_tag) {
                                /* Found MeshPacket — scan it for field 4 (decoded, LEN) */
                                const uint8_t *pp  = p;
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
                                        if (fn2 == meshtastic_MeshPacket_decoded_tag) {
                                            /* Found Data — decode it directly, no oneof */
                                            meshtastic_Data data_msg = meshtastic_Data_init_default;
                                            data_msg.payload.funcs.decode = payload_decode_cb;
                                            data_msg.payload.arg          = &decoded_payload;
                                            pb_istream_t ds = pb_istream_from_buffer(pp, (size_t)fl2);
                                            pb_decode(&ds, meshtastic_Data_fields, &data_msg);
                                            pp = pend; /* done */
                                        } else {
                                            pp += (size_t)fl2;
                                        }
                                    } else if (wt2 == 0) {
                                        uint64_t dummy; bool dok;
                                        READ_VARINT(pp, pend, dummy, dok);
                                        (void)dummy;
                                        if (!dok) break;
                                    } else if (wt2 == 5) { pp += 4; }
                                    else if (wt2 == 1) { pp += 8; }
                                    else break; /* unknown wire type */
                                }
                                p += flen;
                                break; /* done with FromRadio scan */
                            } else {
                                p += flen;
                            }
                        } else if (wire_type == 0) {
                            uint64_t dummy; bool dok;
                            READ_VARINT(p, end, dummy, dok);
                            (void)dummy;
                            if (!dok) break;
                        } else if (wire_type == 5) { p += 4; }
                        else if (wire_type == 1) { p += 8; }
                        else break;
                    }
                    #undef READ_VARINT
                    /* decoded_payload.len now reflects actual payload bytes */
                }

                g_info("Meshtastic: packet from %08x port=%d len=%zu %s",
                       pkt->from, portnum, decoded_payload.len,
                       (portnum == (int)mp->custom_port)
                           ? "[DEADMESH]" : "[passthrough]");

                /* Text messages */
                if (portnum == meshtastic_PortNum_TEXT_MESSAGE_APP) {
                    /* decoded_payload is populated by the second-pass above */
                    gchar *text = (decoded_payload.len > 0)
                        ? g_strndup((const gchar *)decoded_payload.buf, decoded_payload.len)
                        : g_strdup("");
                    g_info("Meshtastic: TEXT from %08x: [%s] (len=%zu)",
                           pkt->from, text, decoded_payload.len);

                    /* Append to context ring buffer */
                    if (context->message_ring_head >= 0) {
                        g_mutex_lock(&context->message_ring_mutex);

                        MeshMessage *slot =
                            &context->message_ring[context->message_ring_head];
                        slot->from_node = pkt->from;
                        slot->timestamp = g_get_real_time() / G_USEC_PER_SEC;
                        slot->hops      = (pkt->hop_start > pkt->hop_limit)
                                          ? (uint8_t)(pkt->hop_start - pkt->hop_limit)
                                          : 0;
                        slot->snr       = pkt->rx_snr;
                        g_strlcpy(slot->text, text, sizeof(slot->text));

                        context->message_ring_head =
                            (context->message_ring_head + 1) % MESH_MESSAGE_RING_SIZE;
                        if (context->message_ring_count < MESH_MESSAGE_RING_SIZE)
                            context->message_ring_count++;

                        g_mutex_unlock(&context->message_ring_mutex);

                        /* SSE push — notify dashboard clients immediately */
                        {
                            gchar *text_esc = g_strescape(text, NULL);
                            gchar *json = g_strdup_printf(
                                "{\"from\":\"%08x\",\"text\":\"%s\","
                                "\"ts\":%" G_GINT64_FORMAT ",\"hops\":%u,\"snr\":%.1f}",
                                pkt->from, text_esc,
                                (gint64)(g_get_real_time() / G_USEC_PER_SEC),
                                (pkt->hop_start > pkt->hop_limit)
                                    ? (unsigned)(pkt->hop_start - pkt->hop_limit) : 0u,
                                (double)pkt->rx_snr);
                            deadlight_sse_broadcast(context, "message", json);
                            g_free(json);
                            g_free(text_esc);
                        }
                    }

                    g_free(text);
                }

                /* Position — decode and store in node table */
                if (portnum == meshtastic_PortNum_POSITION_APP
                    && decoded_payload.len > 0)
                {
                    meshtastic_Position pos = meshtastic_Position_init_default;
                    pb_istream_t ps = pb_istream_from_buffer(
                        decoded_payload.buf, decoded_payload.len);

                    if (pb_decode(&ps, meshtastic_Position_fields, &pos)) {
                        g_mutex_lock(&context->node_table_mutex);
                        MeshNode *node = node_upsert(context, pkt->from);
                        if (node && (pos.latitude_i != 0 || pos.longitude_i != 0)) {
                            node->latitude    = pos.latitude_i  * 1e-7;
                            node->longitude   = pos.longitude_i * 1e-7;
                            node->altitude    = pos.altitude;
                            node->has_position = TRUE;
                        }
                        g_mutex_unlock(&context->node_table_mutex);
                        g_debug("Meshtastic: POSITION from %08x (%.5f, %.5f)",
                                pkt->from, pos.latitude_i * 1e-7,
                                pos.longitude_i * 1e-7);
                        node_sse_push(context, pkt->from);
                    }
                }

                /* Telemetry — decode battery level */
                if (portnum == meshtastic_PortNum_TELEMETRY_APP
                    && decoded_payload.len > 0)
                {
                    meshtastic_Telemetry tel = meshtastic_Telemetry_init_default;
                    pb_istream_t ts = pb_istream_from_buffer(
                        decoded_payload.buf, decoded_payload.len);

                    if (pb_decode(&ts, meshtastic_Telemetry_fields, &tel)
                        && tel.which_variant == meshtastic_Telemetry_device_metrics_tag)
                    {
                        g_mutex_lock(&context->node_table_mutex);
                        MeshNode *node = node_upsert(context, pkt->from);
                        if (node) {
                            node->battery_level  = (uint8_t)
                                tel.variant.device_metrics.battery_level;
                            node->has_telemetry  = TRUE;
                        }
                        g_mutex_unlock(&context->node_table_mutex);
                        g_debug("Meshtastic: TELEMETRY from %08x (battery=%u%%)",
                                pkt->from,
                                tel.variant.device_metrics.battery_level);
                        node_sse_push(context, pkt->from);
                    }
                }

                /* NodeInfo portnum — also decode name if present */
                if (portnum == meshtastic_PortNum_NODEINFO_APP
                    && decoded_payload.len > 0)
                {
                    g_debug("Meshtastic: NODEINFO from %08x (%zu bytes)",
                            pkt->from, decoded_payload.len);
                }

            } else {
                g_debug("Meshtastic: encrypted packet from %08x (can't decode)",
                        pkt->from);
            }
            break;
        }

        /* ── MyNodeInfo — our local node ID ─────────────────── */
        case meshtastic_FromRadio_my_info_tag: {
            uint32_t my_num = from_radio.payload_variant.my_info.my_node_num;
            g_info("Meshtastic: received MyNodeInfo (node_num=%u)", my_num);
            if (mp->local_node_id == 0) {
                mp->local_node_id = my_num;
                g_info("Meshtastic: auto-detected local node ID: %08x",
                       mp->local_node_id);
            }
            /* Mark our own node in the table */
            g_mutex_lock(&context->node_table_mutex);
            MeshNode *local = node_upsert(context, my_num);
            if (local) local->is_local = TRUE;
            g_mutex_unlock(&context->node_table_mutex);
            break;
        }

        /* ── NodeInfo — neighbour list on startup ────────────── */
        case meshtastic_FromRadio_node_info_tag: {
            /* node_info is a sub-message — we need to re-decode it with
             * string callbacks wired, because short_name / long_name on
             * meshtastic_User are pb_callback_t in the plugin-mode codegen
             * (same situation as Data.payload and LogRecord.message).
             *
             * Decode the raw frame payload a second time targeting only
             * the node_info variant so we can attach the callbacks first. */

            PbStringCtx short_ctx = {0};
            PbStringCtx long_ctx  = {0};

            meshtastic_FromRadio ni_radio = meshtastic_FromRadio_init_default;
            ni_radio.payload_variant.node_info.user
                .short_name.funcs.decode = string_decode_cb;
            ni_radio.payload_variant.node_info.user
                .short_name.arg = &short_ctx;
            ni_radio.payload_variant.node_info.user
                .long_name.funcs.decode = string_decode_cb;
            ni_radio.payload_variant.node_info.user
                .long_name.arg = &long_ctx;

            pb_istream_t ni_stream = pb_istream_from_buffer(
                frame->payload, frame->len);
            /* Ignore decode errors here — partial data is fine, we take
             * whatever fields decoded successfully.                      */
            pb_decode(&ni_stream, meshtastic_FromRadio_fields, &ni_radio);

            meshtastic_NodeInfo *ni = &ni_radio.payload_variant.node_info;
            g_debug("Meshtastic: NodeInfo update for %08x", ni->num);

            g_mutex_lock(&context->node_table_mutex);
            MeshNode *node = node_upsert(context, ni->num);
            if (node) {
                /* Names — from the re-decoded callbacks */
                if (short_ctx.buf[0] != '\0')
                    g_strlcpy(node->short_name, short_ctx.buf,
                              sizeof(node->short_name));
                if (long_ctx.buf[0] != '\0')
                    g_strlcpy(node->long_name, long_ctx.buf,
                              sizeof(node->long_name));

                /* Position embedded in NodeInfo */
                if (ni->position.latitude_i != 0
                    || ni->position.longitude_i != 0)
                {
                    node->latitude     = ni->position.latitude_i  * 1e-7;
                    node->longitude    = ni->position.longitude_i * 1e-7;
                    node->altitude     = ni->position.altitude;
                    node->has_position = TRUE;
                }

                /* SNR if present */
                if (ni->snr != 0.0f) node->snr = ni->snr;

                /* last_heard from NodeInfo timestamp */
                if (ni->last_heard != 0)
                    node->last_heard = (gint64)ni->last_heard;
            }
            g_mutex_unlock(&context->node_table_mutex);
            node_sse_push(context, ni->num);
            break;
        }

        case meshtastic_FromRadio_config_tag:
            g_debug("Meshtastic: device config received");
            break;

        case meshtastic_FromRadio_log_record_tag:
            g_debug("Meshtastic: device log: %s", log_message.buf);
            break;

        default:
            g_debug("Meshtastic: FromRadio variant %d",
                    from_radio.which_payload_variant);
            break;
    }

    /* === Gateway logic: only process custom port === */
    if (from_radio.which_payload_variant != meshtastic_FromRadio_packet_tag)
        return;

    meshtastic_MeshPacket *pkt = &from_radio.payload_variant.packet;

    if (pkt->which_payload_variant != meshtastic_MeshPacket_decoded_tag)
        return;

    if (pkt->payload_variant.decoded.portnum != (meshtastic_PortNum)mp->custom_port)
        return;

    uint32_t src_node  = pkt->from;
    uint32_t packet_id = pkt->id;

    if (src_node == 0) {
        g_warning("Meshtastic: received packet with zero src_node, discarding");
        return;
    }

    const pb_byte_t *raw     = decoded_payload.buf;
    size_t           raw_len = decoded_payload.len;

    if (raw_len < 8) {
        g_warning("Meshtastic: packet from %08x too short (%zu bytes)",
                   src_node, raw_len);
        return;
    }

    uint32_t seq_num      = 0;
    uint32_t total_chunks = 0;
    memcpy(&seq_num,      raw,     4);
    memcpy(&total_chunks, raw + 4, 4);

    const uint8_t *chunk_data = raw + 8;
    size_t         chunk_len  = raw_len - 8;

    uint32_t session_id = (seq_num == 0) ? packet_id : packet_id;

    MeshSession *session = mesh_session_get_or_create(
        mp->sessions, src_node, session_id);

    if (seq_num == 0 || session->expected_chunks == 0) {
        mesh_session_init_reassembly(session, total_chunks);
    }

    bool complete = mesh_session_record_chunk(
        session, seq_num, chunk_data, chunk_len);

    g_debug("Meshtastic: chunk %u/%u from node %08x session %08x",
            seq_num + 1, total_chunks, src_node, session_id);

    if (!complete) return;

    if (!session->conn) {
        g_info("Meshtastic: session %08x:%08x complete (%u bytes) "
               "— no connection assigned yet (mesh_stream pending)",
               src_node, session_id,
               session->assembly_buf->len);
        return;
    }

    g_byte_array_append(session->conn->client_buffer,
                        session->assembly_buf->data,
                        session->assembly_buf->len);

    g_info("Meshtastic: injected %u reassembled bytes into conn %lu",
            session->assembly_buf->len, session->conn->id);

    mesh_session_init_reassembly(session, 0);
    (void)context;
}

/* ─────────────────────────────────────────────────────────────
 * Outbound: chunk and send
 * ───────────────────────────────────────────────────────────── */

static gboolean send_chunk(MeshtasticPlugin *mp,
                            DeadlightConnection *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t seq, uint32_t total) {
    if (mp->serial_fd < 0) {
        g_warning("Meshtastic: cannot send — serial port not open");
        return FALSE;
    }

    uint8_t chunk_buf[8 + MESH_FRAME_MAX_PAYLOAD];
    if (len > MESH_FRAME_MAX_PAYLOAD - 8) {
        g_warning("Meshtastic: chunk too large (%zu)", len);
        return FALSE;
    }
    memcpy(chunk_buf,     &seq,   4);
    memcpy(chunk_buf + 4, &total, 4);
    memcpy(chunk_buf + 8, payload, len);
    size_t chunk_total = 8 + len;

    PbEncodeCtx payload_ctx = { chunk_buf, chunk_total };
    meshtastic_Data pb_data = meshtastic_Data_init_default;
    pb_data.portnum              = (meshtastic_PortNum)mp->custom_port;
    pb_data.payload.funcs.encode = payload_encode_cb;
    pb_data.payload.arg          = &payload_ctx;

    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
    packet.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    packet.payload_variant.decoded = pb_data;
    packet.from                  = mp->local_node_id;
    packet.id                    = (uint32_t)conn->mesh_session_id;
    packet.hop_limit             = 3;

    uint8_t packet_buf[600];
    pb_ostream_t pstream = pb_ostream_from_buffer(packet_buf,
                                                   sizeof(packet_buf));
    if (!pb_encode(&pstream, meshtastic_MeshPacket_fields, &packet)) {
        g_warning("Meshtastic: MeshPacket encode failed: %s",
                  PB_GET_ERROR(&pstream));
        mp->encode_errors++;
        return FALSE;
    }

    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant = meshtastic_ToRadio_packet_tag;
    to_radio.payload_variant.packet = packet;

    uint8_t to_buf[700];
    pb_ostream_t tostream = pb_ostream_from_buffer(to_buf, sizeof(to_buf));
    if (!pb_encode(&tostream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("Meshtastic: ToRadio encode failed: %s",
                  PB_GET_ERROR(&tostream));
        mp->encode_errors++;
        return FALSE;
    }

    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL];
    size_t frame_len = mesh_frame_encode(to_buf,
                                          (uint16_t)tostream.bytes_written,
                                          frame_buf, sizeof(frame_buf));
    if (frame_len == 0) {
        g_warning("Meshtastic: frame encoding failed (payload too large?)");
        return FALSE;
    }

    g_mutex_lock(&mp->write_mutex);
    ssize_t written = write(mp->serial_fd, frame_buf, frame_len);
    g_mutex_unlock(&mp->write_mutex);

    if (written < 0 || (size_t)written != frame_len) {
        g_warning("Meshtastic: serial write failed: %s", g_strerror(errno));
        return FALSE;
    }

    mp->frames_sent++;
    g_debug("Meshtastic: sent chunk %u/%u for conn %lu (%zu bytes)",
             seq + 1, total, conn->id, len);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin hooks
 * ───────────────────────────────────────────────────────────── */

static gboolean on_request_body(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context)
        return TRUE;

    DeadlightContext *context = request->connection->context;
    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp || !mp->enabled || mp->serial_fd < 0) return TRUE;

    GByteArray *body = request->body;
    if (!body || body->len == 0) return TRUE;

    uint32_t total_chunks = (body->len + 219) / 220;
    for (uint32_t i = 0; i < total_chunks; i++) {
        size_t offset    = i * 220;
        size_t chunk_len = MIN(220, body->len - offset);
        if (!send_chunk(mp, request->connection,
                        body->data + offset, chunk_len,
                        i, total_chunks)) {
            g_warning("Meshtastic: chunk %u/%u send failed for conn %lu",
                       i + 1, total_chunks, request->connection->id);
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean on_response_body(DeadlightResponse *response G_GNUC_UNUSED) {
    return TRUE;
}

static gboolean on_connection_close(DeadlightConnection *conn) {
    if (!conn->context || !conn->context->plugins_data) return TRUE;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        conn->context->plugins_data, "meshtastic");
    if (!mp) return TRUE;

    if (conn->mesh_session_id != 0) {
        MeshSession *session = mesh_session_lookup(
            mp->sessions,
            conn->mesh_source_node,
            conn->mesh_session_id);

        if (session) {
            mesh_session_close(mp->sessions, session);
            mesh_session_remove(mp->sessions,
                                 conn->mesh_source_node,
                                 conn->mesh_session_id);
            g_debug("Meshtastic: closed session %08x:%08x on conn close",
                    conn->mesh_source_node, conn->mesh_session_id);
        }
    }
    return TRUE;
}

static gboolean on_config_change(DeadlightContext *context,
                              const gchar *section,
                              const gchar *key G_GNUC_UNUSED) {
    if (g_strcmp0(section, "meshtastic") != 0) return TRUE;
    if (!context->plugins_data) return TRUE;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp) return TRUE;

    mp->custom_port = (uint32_t)deadlight_config_get_int(
        context, "meshtastic", "custom_port", 100);

    g_info("Meshtastic: config updated (custom_port=%u)", mp->custom_port);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin registration
 * ───────────────────────────────────────────────────────────── */

static DeadlightPlugin meshtastic_plugin = {
    .name               = "meshtastic",
    .version            = "1.1.0",
    .description        = "Meshtastic LoRa serial transport for deadmesh",
    .author             = "deadlight.boo",
    .init               = meshtastic_init,
    .cleanup            = meshtastic_cleanup,
    .on_request_headers = NULL,
    .on_request_body    = on_request_body,
    .on_response_headers= NULL,
    .on_response_body   = on_response_body,
    .on_connection_accept = NULL,
    .on_protocol_detect = NULL,
    .on_connection_close= on_connection_close,
    .on_config_change   = on_config_change,
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin) {
    *plugin = &meshtastic_plugin;
    return TRUE;
}