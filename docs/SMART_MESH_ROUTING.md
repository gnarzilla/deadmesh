## Smart Mesh Routing

LoRa bandwidth is precious — roughly 3-4 kbps raw, shared across every node on the channel. Not all traffic is worth the airtime. A full Wikipedia page is 500KB of HTML, images, and JS. The actual article text is 8KB. Smart mesh routing closes that gap automatically.

### How It Works

Every request through deadmesh passes through a three-layer routing decision before it touches the wire:

```
Request
   │
   ▼
┌──────────────────┐
│  Scheme Handler  │  mesh:// prefix → force LoRa path
└────────┬─────────┘
         ▼
┌──────────────────┐
│   Mesh Router    │  whitelist / blacklist / API substitution
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Content Transform│  strip to text, drop images, size cap
└────────┬─────────┘
         ▼
    proxy core
```

### The `mesh://` Scheme

Prefix any URL with `mesh://` to explicitly force gateway-side optimization for LoRa delivery:

```bash
# Standard proxy request — goes through normally
curl -x http://gateway:8080 https://wikipedia.org/wiki/Meshtastic

# mesh:// — gateway strips to article text, drops all images and JS
curl -x http://gateway:8080 mesh://wikipedia.org/wiki/Meshtastic
```

Without smart routing:
  wikipedia.org/wiki/Meshtastic → 487KB HTML, ~20 min over mesh

With smart routing (mesh://):
  Same request → 11KB plaintext, ~45 seconds over mesh
  Cached repeat → 0 seconds, 0 airtime

The `mesh://` prefix is stripped by the gateway before the upstream request is made. The client receives clean, compressed, text-first content sized for the mesh. **No special client software required** — the scheme is handled entirely on the gateway.

### Routing Tiers

The router classifies every destination into one of three tiers:

| Tier | Behavior | Example destinations |
|---|---|---|
| **mesh_allow** | Full content transformation, LoRa-optimized | wikipedia.org, text.npr.org, news.ycombinator.com |
| **mesh_api** | Substitute lean API endpoint, skip frontend | spotify.com → api.spotify.com, weather.com → api.weather.gov |
| **mesh_deny** | Reject immediately with friendly error | youtube.com, *.twitch.tv, *.cdn.*, any binary media CDN |

Denied requests fail fast with a human-readable error rather than timing out after fragmenting gigabytes of video over LoRa.

### API Substitution

Many services have lean JSON APIs that return the same data as their heavyweight frontends. The router maintains a substitution table:

```ini
[mesh_router.api_map]
spotify.com         = api.spotify.com/v1
weather.com         = api.weather.gov
maps.google.com     = maps.googleapis.com/maps/api
openstreetmap.org   = overpass-api.de/api
```

A `mesh://spotify.com/track/xyz` request silently becomes `api.spotify.com/v1/tracks/xyz` — the client gets structured JSON in a fraction of the bytes.

### Content Transformation

For `mesh_allow` destinations, the gateway applies a transformation pipeline before fragmenting:

- **Readability strip**: extract article body, discard nav/ads/scripts (Mozilla Readability algorithm)
- **Image policy**: drop all images by default; `image_mode=none|placeholder|thumbnail`
- **Wikipedia fast path**: use `api.php?action=query&prop=extracts&explaintext=1` to get clean plaintext directly — no HTML parsing needed
- **Size cap**: hard ceiling on response size before it hits the mesh; configurable per-tier

A full Wikipedia article becomes 5-15KB of plain text. Readable, useful, and deliverable in under 2 minutes over LONG_FAST.

Typical transformed request times (LONG_FAST, 2 hops):
- Wikipedia article (text):     60-90 seconds
- HN front page (titles only):  20-30 seconds  
- Weather API response:         10-15 seconds
- DNS lookup (cached):          2-3 seconds

### Configuration

```ini
[mesh_router]
# Destinations where mesh optimization is always applied
whitelist           = wikipedia.org, *.wikipedia.org, text.npr.org, \
                      news.ycombinator.com, lobste.rs

# Destinations that will never route over mesh — fail fast
blacklist           = youtube.com, *.twitch.tv, *.cloudfront.net, \
                      *.cdn.*, *.akamaized.net, *.fastly.net

# API substitution table: domain = lean API endpoint
[mesh_router.api_map]
spotify.com         = api.spotify.com/v1
weather.com         = api.weather.gov
maps.google.com     = maps.googleapis.com/maps/api

# Content transformation settings
[mesh_router.transform]
# Apply readability strip to these domains (space = article text only)
text_only           = *.wikipedia.org, text.npr.org

# Image handling: none | placeholder | thumbnail
image_mode          = none

# Hard response size cap before error (KB)
max_response_kb     = 100

# Compress transformed responses before fragmenting
compress            = true
```

### Why Not Just Cache?

Caching (in `plugin.cache`) handles repeat requests. Smart routing handles the *first* request — ensuring that even a cold-cache request for wikipedia.org delivers a readable article in reasonable time rather than a multi-megabyte rendering pipeline that exhausts airtime and patience.

The two features compose: a transformed, compressed Wikipedia article gets cached on first fetch. Every subsequent mesh client gets it instantly from cache, zero airtime cost.


---

