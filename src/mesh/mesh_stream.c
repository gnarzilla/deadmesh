/**
 * deadmesh - MeshStream Implementation
 *
 * GIOStream subclass that makes a Meshtastic mesh session look like
 * a regular socket to the proxy core.
 *
 * Read path:  pipe(2) read end → GInputStream.read() blocks here
 *             reader thread writes reassembled data to pipe write end
 *
 * Write path: GOutputStream.write() → chunk → MeshSendFn callback
 *             → serial write (in meshtastic.c)
 */

#include "mesh_stream.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* ─────────────────────────────────────────────────────────────
 * Private data
 * ───────────────────────────────────────────────────────────── */

struct _MeshStreamPrivate {
    MeshSession  *session;
    MeshSendFn    send_fn;
    gpointer      send_ctx;
    gsize         fragment_size;

    /* pipe(2): reader thread writes to pipe_write_fd,
     * GInputStream reads from pipe_read_fd.           */
    int           pipe_read_fd;
    int           pipe_write_fd;

    GInputStream  *input_stream;
    GOutputStream *output_stream;

    gboolean      closed;
    GMutex        close_mutex;
};

/* ─────────────────────────────────────────────────────────────
 * MeshInputStream
 * ───────────────────────────────────────────────────────────── */

#define MESH_TYPE_INPUT_STREAM       (mesh_input_stream_get_type())
#define MESH_INPUT_STREAM(obj)       (G_TYPE_CHECK_INSTANCE_CAST((obj), MESH_TYPE_INPUT_STREAM, MeshInputStream))

typedef struct _MeshInputStream      MeshInputStream;
typedef struct _MeshInputStreamClass MeshInputStreamClass;

struct _MeshInputStream {
    GInputStream  parent_instance;
    int           read_fd;          /* pipe read end */
    gboolean      closed;
};

struct _MeshInputStreamClass {
    GInputStreamClass parent_class;
};

G_DEFINE_TYPE(MeshInputStream, mesh_input_stream, G_TYPE_INPUT_STREAM)

static gssize mesh_input_stream_read(GInputStream *stream,
                                      void *buffer, gsize count,
                                      GCancellable *cancellable,
                                      GError **error) {
    MeshInputStream *self = MESH_INPUT_STREAM(stream);

    if (self->closed || self->read_fd < 0) {
        return 0; /* EOF */
    }

    /* If cancellable, check before blocking */
    if (g_cancellable_set_error_if_cancelled(cancellable, error)) {
        return -1;
    }

    gssize n;
    do {
        n = read(self->read_fd, buffer, count);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Non-blocking pipe with no data — return WOULD_BLOCK */
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                        "MeshInputStream: no data available");
            return -1;
        }
        g_set_error(error, G_IO_ERROR,
                    g_io_error_from_errno(errno),
                    "MeshInputStream read error: %s", g_strerror(errno));
        return -1;
    }

    return n; /* 0 = EOF (write end was closed) */
}

static gboolean mesh_input_stream_close(GInputStream *stream,
                                         GCancellable *cancellable G_GNUC_UNUSED,
                                         GError **error G_GNUC_UNUSED) {
    MeshInputStream *self = MESH_INPUT_STREAM(stream);
    if (!self->closed && self->read_fd >= 0) {
        close(self->read_fd);
        self->read_fd = -1;
        self->closed  = TRUE;
    }
    return TRUE;
}

static void mesh_input_stream_class_init(MeshInputStreamClass *klass) {
    GInputStreamClass *istream_class = G_INPUT_STREAM_CLASS(klass);
    istream_class->read_fn = mesh_input_stream_read;
    istream_class->close_fn = mesh_input_stream_close;
}

static void mesh_input_stream_init(MeshInputStream *self) {
    self->read_fd = -1;
    self->closed  = FALSE;
}

static GInputStream *mesh_input_stream_new(int read_fd) {
    MeshInputStream *s = g_object_new(MESH_TYPE_INPUT_STREAM, NULL);
    s->read_fd = read_fd;
    return G_INPUT_STREAM(s);
}

/* ─────────────────────────────────────────────────────────────
 * MeshOutputStream
 * ───────────────────────────────────────────────────────────── */

#define MESH_TYPE_OUTPUT_STREAM        (mesh_output_stream_get_type())
#define MESH_OUTPUT_STREAM(obj)        (G_TYPE_CHECK_INSTANCE_CAST((obj), MESH_TYPE_OUTPUT_STREAM, MeshOutputStream))

typedef struct _MeshOutputStream       MeshOutputStream;
typedef struct _MeshOutputStreamClass  MeshOutputStreamClass;

struct _MeshOutputStream {
    GOutputStream  parent_instance;
    MeshSendFn     send_fn;
    gpointer       send_ctx;
    gsize          fragment_size;
    guint32        session_seq;     /* monotonic per-stream write counter */
    gboolean       closed;
};

struct _MeshOutputStreamClass {
    GOutputStreamClass parent_class;
};

G_DEFINE_TYPE(MeshOutputStream, mesh_output_stream, G_TYPE_OUTPUT_STREAM)

static gssize mesh_output_stream_write(GOutputStream *stream,
                                        const void *buffer, gsize count,
                                        GCancellable *cancellable,
                                        GError **error) {
    MeshOutputStream *self = MESH_OUTPUT_STREAM(stream);

    if (self->closed) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                    "MeshOutputStream: stream is closed");
        return -1;
    }

    if (g_cancellable_set_error_if_cancelled(cancellable, error)) {
        return -1;
    }

    if (count == 0) return 0;

    const guint8 *data     = (const guint8 *)buffer;
    gsize         fs       = self->fragment_size > 0 ? self->fragment_size : 220;
    guint32       total    = (guint32)((count + fs - 1) / fs);
    gsize         sent     = 0;

    for (guint32 seq = 0; seq < total; seq++) {
        gsize offset    = seq * fs;
        gsize chunk_len = MIN(fs, count - offset);

        if (!self->send_fn(data + offset, chunk_len, seq, total,
                           self->send_ctx)) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                        "MeshOutputStream: send_fn failed on chunk %u/%u",
                        seq + 1, total);
            /* Return bytes sent so far so caller knows partial progress */
            return sent > 0 ? (gssize)sent : -1;
        }

        sent += chunk_len;
    }

    self->session_seq++;
    return (gssize)count;
}

static gboolean mesh_output_stream_close(GOutputStream *stream,
                                          GCancellable *cancellable G_GNUC_UNUSED,
                                          GError **error G_GNUC_UNUSED) {
    MeshOutputStream *self = MESH_OUTPUT_STREAM(stream);
    self->closed = TRUE;
    return TRUE;
}

static void mesh_output_stream_class_init(MeshOutputStreamClass *klass) {
    GOutputStreamClass *ostream_class = G_OUTPUT_STREAM_CLASS(klass);
    ostream_class->write_fn  = mesh_output_stream_write;
    ostream_class->close_fn  = mesh_output_stream_close;
}

static void mesh_output_stream_init(MeshOutputStream *self) {
    self->fragment_size = 220;
    self->session_seq   = 0;
    self->closed        = FALSE;
}

static GOutputStream *mesh_output_stream_new(MeshSendFn send_fn,
                                              gpointer   send_ctx,
                                              gsize      fragment_size) {
    MeshOutputStream *s = g_object_new(MESH_TYPE_OUTPUT_STREAM, NULL);
    s->send_fn       = send_fn;
    s->send_ctx      = send_ctx;
    s->fragment_size = fragment_size > 0 ? fragment_size : 220;
    return G_OUTPUT_STREAM(s);
}

/* ─────────────────────────────────────────────────────────────
 * MeshStream (GIOStream)
 * ───────────────────────────────────────────────────────────── */

G_DEFINE_TYPE_WITH_PRIVATE(MeshStream, mesh_stream, G_TYPE_IO_STREAM)

static GInputStream *mesh_stream_get_input_stream(GIOStream *stream) {
    MeshStream *self = MESH_STREAM(stream);
    return self->priv->input_stream;
}

static GOutputStream *mesh_stream_get_output_stream(GIOStream *stream) {
    MeshStream *self = MESH_STREAM(stream);
    return self->priv->output_stream;
}

static gboolean mesh_stream_close_impl(GIOStream *stream,
                                        GCancellable *cancellable,
                                        GError **error) {
    MeshStream *self = MESH_STREAM(stream);
    MeshStreamPrivate *priv = self->priv;

    g_mutex_lock(&priv->close_mutex);
    gboolean already_closed = priv->closed;
    if (!already_closed) {
        priv->closed = TRUE;
        if (priv->pipe_write_fd >= 0) {
            close(priv->pipe_write_fd);
            priv->pipe_write_fd = -1;
        }
    }
    g_mutex_unlock(&priv->close_mutex);  /* ← release before blocking */

    if (!already_closed) {
        g_input_stream_close(priv->input_stream,   cancellable, error);
        g_output_stream_close(priv->output_stream, cancellable, NULL);
    }

    return G_IO_STREAM_CLASS(mesh_stream_parent_class)
               ->close_fn(stream, cancellable, error);
}

static void mesh_stream_finalize(GObject *object) {
    MeshStream *self = MESH_STREAM(object);
    MeshStreamPrivate *priv = self->priv;

    if (priv->pipe_write_fd >= 0) {
        close(priv->pipe_write_fd);
        priv->pipe_write_fd = -1;
    }
    if (priv->pipe_read_fd >= 0) {   /* ← add */
        close(priv->pipe_read_fd);
        priv->pipe_read_fd = -1;
    }

    g_clear_object(&priv->input_stream);
    g_clear_object(&priv->output_stream);
    g_mutex_clear(&priv->close_mutex);

    G_OBJECT_CLASS(mesh_stream_parent_class)->finalize(object);
}

static void mesh_stream_class_init(MeshStreamClass *klass) {
    GObjectClass   *obj_class    = G_OBJECT_CLASS(klass);
    GIOStreamClass *stream_class = G_IO_STREAM_CLASS(klass);

    obj_class->finalize           = mesh_stream_finalize;
    stream_class->get_input_stream  = mesh_stream_get_input_stream;
    stream_class->get_output_stream = mesh_stream_get_output_stream;
    stream_class->close_fn          = mesh_stream_close_impl;
}

static void mesh_stream_init(MeshStream *self) {
    self->priv = mesh_stream_get_instance_private(self);
    g_mutex_init(&self->priv->close_mutex);
    self->priv->pipe_read_fd  = -1;
    self->priv->pipe_write_fd = -1;
    self->priv->closed        = FALSE;
}

/* ─────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────── */

GIOStream *mesh_stream_new(MeshSession *session,
                            MeshSendFn   send_fn,
                            gpointer     send_ctx,
                            gsize        fragment_size) {
    g_return_val_if_fail(session  != NULL, NULL);
    g_return_val_if_fail(send_fn  != NULL, NULL);

    MeshStream *self = g_object_new(MESH_TYPE_STREAM, NULL);
    MeshStreamPrivate *priv = self->priv;

    priv->session       = session;
    priv->send_fn       = send_fn;
    priv->send_ctx      = send_ctx;
    priv->fragment_size = fragment_size > 0 ? fragment_size : 220;

    /* Create the pipe that connects reader thread to GInputStream */
    int fds[2];
    if (pipe(fds) < 0) {
        g_critical("MeshStream: pipe() failed: %s", g_strerror(errno));
        g_object_unref(self);
        return NULL;
    }

    priv->pipe_read_fd  = fds[0];
    priv->pipe_write_fd = fds[1];

    /* Create sub-streams */
    priv->input_stream  = mesh_input_stream_new(priv->pipe_read_fd);
    priv->output_stream = mesh_output_stream_new(send_fn, send_ctx,
                                                  fragment_size);

    return G_IO_STREAM(self);
}

gboolean mesh_stream_push_data(MeshStream    *stream,
                                const guint8  *data,
                                gsize          len) {
    g_return_val_if_fail(MESH_IS_STREAM(stream), FALSE);
    g_return_val_if_fail(data != NULL, FALSE);

    MeshStreamPrivate *priv = stream->priv;

    g_mutex_lock(&priv->close_mutex);
    if (priv->closed || priv->pipe_write_fd < 0) {
        g_mutex_unlock(&priv->close_mutex);
        return FALSE;
    }

    /* Write all data into the pipe.
     * A single write() is atomic for PIPE_BUF (4KB on Linux) bytes.
     * For larger payloads, loop.                                      */
    gsize remaining = len;
    const guint8 *ptr = data;

    while (remaining > 0) {
        ssize_t written = write(priv->pipe_write_fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            g_warning("MeshStream: pipe write failed: %s", g_strerror(errno));
            g_mutex_unlock(&priv->close_mutex);
            return FALSE;
        }
        ptr       += written;
        remaining -= written;
    }

    g_mutex_unlock(&priv->close_mutex);
    return TRUE;
}

void mesh_stream_close_read(MeshStream *stream) {
    g_return_if_fail(MESH_IS_STREAM(stream));

    MeshStreamPrivate *priv = stream->priv;

    g_mutex_lock(&priv->close_mutex);
    if (priv->pipe_write_fd >= 0) {
        /* Closing the write end signals EOF to the read end */
        close(priv->pipe_write_fd);
        priv->pipe_write_fd = -1;
    }
    g_mutex_unlock(&priv->close_mutex);
}

MeshSession *mesh_stream_get_session(MeshStream *stream) {
    g_return_val_if_fail(MESH_IS_STREAM(stream), NULL);
    return stream->priv->session;
}
