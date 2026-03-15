# deadmesh Architecture

deadmesh allows ordinary Internet applications to operate across a Meshtastic LoRa mesh network without modification.

Instead of building mesh-aware applications, deadmesh makes the mesh appear as a normal network connection. Applications communicate with deadmesh through a standard SOCKS5 proxy, while deadmesh handles the translation between TCP streams and Meshtastic packets.

This document describes the internal architecture that makes this possible.

---

# Problem

Meshtastic networks are excellent for messaging and telemetry but are not designed for general Internet protocols.

Traditional applications expect a reliable byte stream (TCP). Meshtastic instead provides a packet-based mesh transport over LoRa radios with strict payload limits and variable latency.

Rewriting every application to speak a mesh protocol is unrealistic.

deadmesh solves this by acting as a bridge between these two worlds.

```
Application → SOCKS5 → deadmesh → Meshtastic → LoRa Mesh
```

Applications remain unchanged while deadmesh handles fragmentation, reassembly, and routing across the mesh.

---

# High-Level Architecture

deadmesh is organized as a set of layered components that progressively transform TCP streams into mesh packets and back again.

```
Applications
     │
  SOCKS5 Proxy
     │
  deadlight core
     │
  MeshStream (GIOStream)
     │
  MeshSession
     │
  MeshFraming
     │
 Meshtastic Serial API
     │
    LoRa
```

Each layer performs a specific task in the translation process.

---

# MeshFrame: Serial Protocol Handling

Meshtastic communicates with host systems over a serial interface using a framed packet format.

Each frame begins with a magic sequence followed by a payload length and protobuf payload:

```
0x94 0xC3 | length_hi | length_lo | payload
```

The framing layer (`mesh_framing.c`) performs:

* stream decoding from the serial device
* synchronization and error recovery
* frame boundary detection
* payload extraction

Because serial communication is a continuous byte stream, the decoder is implemented as a state machine that processes incoming bytes incrementally.

Once a complete frame is decoded, the protobuf payload is passed to higher layers.

---

# MeshSession: Session Management and Reassembly

Mesh traffic is packet-oriented, but applications expect continuous streams. The session layer bridges this mismatch.

Each logical connection is represented by a `MeshSession` identified by:

```
(src_node_id, session_id)
```

The session layer manages:

* connection lifecycle
* fragment tracking
* payload reassembly
* idle expiration

Fragments arriving from the mesh are tracked using a bitmap that records which pieces of the payload have been received.

```
chunk_bitmap[word] |= (1 << bit)
```

When all fragments for a message are present, the session reassembles the payload into a contiguous buffer and forwards it to the stream layer.

Sessions automatically expire if they remain inactive for a configured timeout.

---

# Fragmentation Strategy

LoRa radios impose strict limits on payload size. Large TCP messages must therefore be split into smaller fragments.

Outgoing data is divided into fixed-size chunks:

```
fragment_size ≈ 220 bytes
```

Each fragment carries metadata:

```
sequence_number
total_fragments
```

Fragments can arrive out of order, so the receiver uses the bitmap mechanism described above to determine when a message is complete.

---

# MeshStream: Stream Abstraction

The key architectural idea in deadmesh is the **MeshStream** abstraction.

Instead of implementing a custom networking interface, deadmesh exposes mesh sessions as a standard GLib `GIOStream`.

```
MeshSession → MeshStream → GIOStream
```

This allows the proxy core to treat mesh connections exactly like normal TCP sockets.

The stream implementation provides:

```
read()  → returns reassembled mesh payloads
write() → fragments outgoing data into mesh packets
```

Internally, a pipe is used to bridge between the mesh reader thread and the `GInputStream` interface:

```
mesh reader thread → pipe write
GInputStream.read() → pipe read
```

This design avoids complex asynchronous coordination while preserving blocking stream semantics expected by higher layers.

---

# SOCKS Proxy Integration

Applications interact with deadmesh through a standard SOCKS5 proxy.

Example:

```
curl --socks5 localhost:8080 http://example.com
```

The connection flow is:

```
Client
  │
SOCKS5 handshake
  │
deadlight proxy
  │
MeshStream (if mesh route selected)
  │
Meshtastic packets
```

After the SOCKS handshake completes, deadmesh enters tunnel mode:

```
client stream ↔ mesh stream
```

From the application's perspective, the connection behaves like a normal TCP tunnel.

---

# Result

By combining stream abstraction with packet fragmentation and session management, deadmesh allows existing software to operate across a LoRa mesh network without modification.

Any application that supports SOCKS5 can immediately use the mesh transport.

Examples include:

* curl
* SSH
* git
* email clients
* package managers
* CLI tools and APIs

No mesh-aware application logic is required.

---

# Design Philosophy

deadmesh follows a simple guiding principle:

> Make the mesh look like the Internet, not the other way around.

Instead of requiring applications to adapt to mesh networking constraints, deadmesh hides those constraints behind familiar abstractions.

Applications see a standard proxy and a byte stream.

deadmesh handles the complexity of transporting that stream across a constrained LoRa mesh network.

---

# Summary

deadmesh bridges two very different networking models:

```
TCP byte streams
        ↓
deadmesh transport abstraction
        ↓
Meshtastic packet mesh
```

By layering framing, session management, fragmentation, and stream abstraction, the system converts ordinary Internet traffic into mesh-compatible packets and back again.

The result is a transparent gateway that allows existing applications to operate over Meshtastic networks with no modification.
