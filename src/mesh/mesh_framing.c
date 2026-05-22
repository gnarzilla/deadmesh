/**
 * deadmesh - Meshtastic Serial Framing Layer Implementation
 */

#include "mesh_framing.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>     // select(), fd_set, FD_ZERO, FD_SET
#include <inttypes.h>       // PRIu64
#include <glib.h>           // g_warning, g_debug
#include <termios.h>        // tcflush(), TCIFLUSH

/* Byte-level serial framing trace.
 * Enable with:
 *   DEADMESH_MESH_FRAME_TRACE=1 ./bin/deadmesh -c deadmesh -v
 */
static gboolean mesh_frame_trace_enabled(void) {
    static gint cached = -1;

    if (cached == -1) {
        const gchar *v = g_getenv("DEADMESH_MESH_FRAME_TRACE");
        cached = (v && *v && g_strcmp0(v, "0") != 0) ? 1 : 0;
    }

    return cached == 1;
}

/* ─────────────────────────────────────────────────────────────
 * Reader
 * ───────────────────────────────────────────────────────────── */

void mesh_frame_reader_init(MeshFrameReader *reader) {
    memset(reader, 0, sizeof(*reader));
    reader->state = MESH_FRAME_STATE_WAIT_MAGIC0;
}

size_t mesh_frame_reader_push(MeshFrameReader *reader,
                               const uint8_t *data, size_t len) {
    size_t consumed = 0;

    while (consumed < len) {
        /* Stop if a frame is ready — caller must drain it first */
        if (reader->state == MESH_FRAME_STATE_READY) {
            break;
        }

        uint8_t byte = data[consumed++];

        switch (reader->state) {

        case MESH_FRAME_STATE_WAIT_MAGIC0:
            if (byte == MESH_FRAME_MAGIC0) {
                reader->state = MESH_FRAME_STATE_WAIT_MAGIC1;
            }
            /* Any non-magic byte keeps us here; count as sync error
             * only when we were mid-frame (payload_pos > 0 implies
             * we were already synced once and lost it).             */
            else if (reader->payload_pos > 0) {
                reader->sync_errors++;
                reader->payload_pos = 0;
            }
            break;

        case MESH_FRAME_STATE_WAIT_MAGIC1:
            if (byte == MESH_FRAME_MAGIC1) {
                reader->state = MESH_FRAME_STATE_READ_LEN_HI;
            } else if (byte == MESH_FRAME_MAGIC0) {
                /* Second byte is also 0x94 — stay in MAGIC1 wait
                 * (handles back-to-back 0x94 0x94 0xC3 sequences) */
                reader->state = MESH_FRAME_STATE_WAIT_MAGIC1;
            } else {
                /* Not a valid second magic byte — resync */
                reader->sync_errors++;
                reader->state = MESH_FRAME_STATE_WAIT_MAGIC0;
            }
            break;

        case MESH_FRAME_STATE_READ_LEN_HI:
            reader->payload_len = (uint16_t)(byte << 8);
            reader->state = MESH_FRAME_STATE_READ_LEN_LO;
            break;

        case MESH_FRAME_STATE_READ_LEN_LO:
            reader->payload_len |= byte;
            reader->payload_pos  = 0;

            if (reader->payload_len == 0) {
                /* Zero-length frame — valid but unusual; treat as ready */
                reader->state = MESH_FRAME_STATE_READY;
            } else if (reader->payload_len > MESH_FRAME_MAX_PAYLOAD) {
                /* Frame claims to be larger than our buffer — resync */
                reader->sync_errors++;
                reader->state = MESH_FRAME_STATE_WAIT_MAGIC0;
            } else {
                reader->state = MESH_FRAME_STATE_READ_PAYLOAD;
            }
            break;

        case MESH_FRAME_STATE_READ_PAYLOAD:
            reader->payload[reader->payload_pos++] = byte;
            if (reader->payload_pos >= reader->payload_len) {
                reader->state = MESH_FRAME_STATE_READY;
                reader->frames_decoded++;
            }
            break;

        case MESH_FRAME_STATE_READY:
            /* Should have broken out above — defensive */
            break;
        }
    }

    return consumed;
}

bool mesh_frame_get(const MeshFrameReader *reader, MeshFrame *out) {
    if (reader->state != MESH_FRAME_STATE_READY) {
        return false;
    }
    out->len = reader->payload_len;
    memcpy(out->payload, reader->payload, reader->payload_len);
    return true;
}

void mesh_frame_reader_reset(MeshFrameReader *reader) {
    /* Preserve lifetime counters, reset everything else */
    uint64_t frames  = reader->frames_decoded;
    uint64_t errors  = reader->sync_errors;

    memset(reader, 0, sizeof(*reader));
    reader->state          = MESH_FRAME_STATE_WAIT_MAGIC0;
    reader->frames_decoded = frames;
    reader->sync_errors    = errors;
}

/* ─────────────────────────────────────────────────────────────
 * Encoder
 * ───────────────────────────────────────────────────────────── */

size_t mesh_frame_encode(const uint8_t *payload, uint16_t payload_len,
                          uint8_t *out_buf, size_t out_buf_len) {
    size_t total = MESH_FRAME_HEADER_LEN + payload_len;

    if (payload_len > MESH_FRAME_MAX_PAYLOAD) return 0;
    if (out_buf_len < total)                  return 0;

    out_buf[0] = MESH_FRAME_MAGIC0;
    out_buf[1] = MESH_FRAME_MAGIC1;
    out_buf[2] = (uint8_t)(payload_len >> 8);
    out_buf[3] = (uint8_t)(payload_len & 0xFF);

    if (payload_len > 0) {
        memcpy(out_buf + MESH_FRAME_HEADER_LEN, payload, payload_len);
    }

    return total;
}

/* ─────────────────────────────────────────────────────────────
 * Blocking fd reader
 * ───────────────────────────────────────────────────────────── */

bool mesh_frame_read_blocking(int fd, MeshFrameReader *reader, MeshFrame *out) {
    uint8_t buf[256];
    time_t start = time(NULL);

    while (reader->state != MESH_FRAME_STATE_READY) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };  // 5 second timeout

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r == 0) {
            g_warning("mesh_frame_read_blocking: timeout after %ld s - state=%d, sync_errors=%" PRIu64,
                      (long)(time(NULL) - start), reader->state, reader->sync_errors);
            // Optional: aggressive resync on timeout
            mesh_frame_reader_reset(reader);
            tcflush(fd, TCIFLUSH);
            continue;  // retry
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            g_warning("select failed: %s", strerror(errno));
            return false;
        }

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) {
            g_warning("EOF on serial fd");
            return false;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            g_warning("read failed: %s", strerror(errno));
            return false;
        }

        size_t pos = 0;
        while (pos < (size_t)n) {
            size_t consumed = mesh_frame_reader_push(reader, buf + pos, (size_t)n - pos);
            pos += consumed;

            if (mesh_frame_trace_enabled()) {
                g_debug("Pushed %zu bytes, new state=%d, pos=%u/%u",
                        consumed,
                        reader->state,
                        reader->payload_pos,
                        reader->payload_len);
            }

            if (reader->state == MESH_FRAME_STATE_READY) {
                break;
            }
        }
    }

    return mesh_frame_get(reader, out);
}