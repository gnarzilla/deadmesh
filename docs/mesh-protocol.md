# Mesh Protocol (mesh://)

**Draft Version:** 0.1
**Status:** Experimental
**Intended Environment:** Extremely low-bandwidth, high-latency mesh radio networks

---

# 1. Overview

Mesh Protocol (mesh://) is a lightweight application-layer protocol designed for networks where bandwidth is scarce, latency is high, and connectivity may be intermittent.

The protocol prioritizes:

* extremely small request sizes
* structured content rather than presentation markup
* aggressive caching
* tolerance for fragmentation and delay

Unlike traditional web protocols, Mesh Protocol does not attempt to deliver full web pages. Instead it delivers structured information objects that clients can render locally.

Typical transport layers include radio mesh networks such as LoRa, packet radio, or other constrained links.

---

# 2. Design Principles

Mesh Protocol follows several core principles:

1. **Bandwidth is precious** – responses should be as small as possible.
2. **Latency is expected** – the protocol must tolerate slow multi-hop delivery.
3. **Content over presentation** – data is structured rather than HTML.
4. **Cache everything** – nodes should store useful content whenever possible.
5. **Human-readable where practical** – simple text formats are preferred.
6. **Graceful degradation** – partial responses should still be useful.

---

# 3. URI Scheme

Mesh resources are addressed using the `mesh://` URI scheme.

General format:

```
mesh://service/resource
```

Examples:

```
mesh://wiki/Alan_Turing
mesh://weather/seattle
mesh://library/agriculture/soil
mesh://node/status
```

The `service` component identifies the logical service providing the content.

---

# 4. Request Format

Requests must be extremely compact.

Minimal request:

```
REQ
PATH wiki/Alan_Turing
```

Optional parameters may be included:

```
REQ
PATH wiki/Alan_Turing
MODE summary
MAXSIZE 4096
```

### Common Request Fields

| Field   | Description           |
| ------- | --------------------- |
| PATH    | resource path         |
| MODE    | optional content mode |
| MAXSIZE | maximum response size |

Requests should ideally remain under 100 bytes.

---

# 5. Response Format

Responses return structured content blocks.

Example response:

```
RES
TYPE article
TITLE Alan Turing
SIZE 3820

SECTION Early Life
Alan Mathison Turing was born...

SECTION Enigma Work
During World War II...
```

Clients are responsible for rendering the response appropriately.

---

# 6. Content Types

Initial content types include:

| Type      | Description             |
| --------- | ----------------------- |
| text      | simple text content     |
| article   | structured article      |
| directory | list of resources       |
| message   | short communication     |
| status    | node status information |
| binary    | encoded binary data     |

Directory responses may look like:

```
DIR
wiki
weather
messages
library
```

---

# 7. Fragmentation

Mesh Protocol assumes the underlying transport may require fragmentation.

Responses may include fragment metadata:

```
FRAGMENTS 12
FRAG 1/12
```

The transport layer is responsible for reassembly.

---

# 8. Caching

Caching is strongly encouraged.

Responses may include caching directives:

```
CACHE 86400
```

This indicates the content may be cached for the specified number of seconds.

Alternatively:

```
CACHE FOREVER
```

Nodes should store cached content when storage permits.

---

# 9. Node Information

Nodes may expose basic metadata about themselves.

Example:

```
mesh://node/info
```

Example response:

```
RES
TYPE status
NODE deadmesh-gateway-3
SERVICES wiki weather library
CACHE_SIZE 800GB
```

---

# 10. Error Handling

Errors should be informative but compact.

Example:

```
ERR
NOT_FOUND
```

Or:

```
ERR
TOO_LARGE
EST_TIME 7200
```

Clients should display these messages to the user when appropriate.

---

# 11. Versioning

Protocol versions are identified in implementation metadata rather than individual messages.

Initial version: **MP-0.1**

---

# 12. Future Extensions

Future protocol revisions may include:

* authentication
* encryption
* compression negotiation
* service discovery
* distributed caching mechanisms

These features are intentionally excluded from the initial draft to maintain simplicity.

---

# 13. Reference Implementation

The first reference implementation of Mesh Protocol is expected to be included within the deadmesh project.

Initial responsibilities include:

* translating mesh:// requests into internet API calls
* transforming responses into structured mesh objects
* fragmenting responses for radio transport

---

# 14. Status

This document represents an experimental starting point for discussion and implementation.

The protocol is expected to evolve through experimentation within real mesh networks.
