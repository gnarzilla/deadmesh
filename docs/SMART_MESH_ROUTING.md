# Smart Mesh Routing

LoRa bandwidth is precious — roughly 3-4 kbps shared across every node on your channel. Not all traffic is worth the airtime. A full Wikipedia page is 500KB of HTML, images, and JavaScript. The actual article text is 8KB.

Smart mesh routing closes that gap automatically, and over time builds a distributed cache of mesh-optimized content that serves your entire community.

The Three-Layer Router

Every request passes through three decision layers before touching the mesh:

```
Request
   │
   ▼
┌─────────────────────────────────┐
│  Layer 1: Scheme Handler        │
│  mesh:// → force optimization   │
│  http:// → apply routing rules  │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│  Layer 2: Mesh Router           │
│  ┌─────────────┐                │
│  │ ALLOW list  │ → Transform    │
│  │ DENY list   │ → Fast fail    │
│  │ API map     │ → Substitution │
│  └─────────────┘                │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│  Layer 3: Content Transform     │
│  • Readability extraction       │
│  • Image policy (none/thumb)    │
│  • Size capping                 │
│  • Compression                  │
└───────────────┬─────────────────┘
                │
                ▼
    ┌─────────────────────┐
    │  PROXY CORE         │
    │  ┌───────────────┐  │
    │  │ LOCAL CACHE   │──┼──┐
    │  └───────────────┘  │  │
    └─────────────────────┘  │
                              ▼
                    ┌─────────────────────┐
                    │ PEER GATEWAYS       │
                    │ (distributed cache) │
                    └─────────────────────┘
```

The mesh:// Scheme

Prefix any URL with mesh:// to explicitly request LoRa-optimized delivery:

```bash
# Standard request — hits internet normally
curl -x http://gateway:8080 https://en.wikipedia.org/wiki/Meshtastic

# mesh:// — optimized for mesh delivery
curl -x http://gateway:8080 mesh://en.wikipedia.org/wiki/Meshtastic
```

Why a special scheme? It signals user intent. Someone typing mesh:// knows they're on limited bandwidth and accepts text-only, optimized content. The gateway doesn't have to guess.

URL What Happens
http://example.com Normal proxy (may be optimized based on rules)
mesh://example.com Force optimization: transform, strip, compress
mesh://api.spotify.com API passthrough (JSON already efficient)

Tiered Routing Rules

The router classifies every destination:

```ini
[mesh_router]
# Destinations that get full transformation
allow = wikipedia.org, *.wikipedia.org, text.npr.org, \
        news.ycombinator.com, lobste.rs, arstechnica.com

# Destinations rejected immediately (never waste airtime)
deny = youtube.com, *.twitch.tv, *.cloudfront.net, \
       *.cdn.*, tiktok.com, instagram.com

# API substitution: domain → lean endpoint
[mesh_router.api_map]
spotify.com         = api.spotify.com/v1
weather.com         = api.weather.gov
maps.google.com     = maps.googleapis.com/maps/api
openstreetmap.org   = overpass-api.de/api
github.com          = api.github.com/repos
```

Denied requests fail instantly with a helpful message:

```
❌ youtube.com is not available over mesh
   (Would take ~47 hours and use 300% of daily duty cycle)
   
✅ Try these mesh-friendly alternatives:
   • Invidious (text search): mesh://invidious.site/search?q=...
   • RSS feeds: mesh://youtube.com/feeds/videos.xml?user=...
```

Content Transformation Pipeline

For allow-list destinations, content is transformed before hitting the mesh:

```ini
[mesh_router.transform]
# Domains that should be stripped to plain text
text_only = *.wikipedia.org, text.npr.org, *.gov, *.edu

# Image handling: none | placeholder | thumbnail
image_mode = none
thumbnail_max_kb = 5

# Hard size cap before fragmentation (KB)
max_response_kb = 100

# Always compress transformed content
compress = true

# Wikipedia gets special fast-path (direct API call)
wikipedia_fastpath = true
```

Transformation results:

Content Original Transformed Time over mesh
Wikipedia article 487 KB HTML+CSS+JS 11 KB plain text 45 seconds
News article 2.3 MB (with images) 8 KB text 35 seconds
Weather forecast 850 KB (ads + JS) 3 KB JSON 15 seconds
GitHub README 1.1 MB (site wrapper) 28 KB markdown 2 minutes

The Mesh Cache Network

This is where deadmesh becomes infrastructure, not just a tool.

Every gateway maintains a persistent cache of transformed responses. But unlike a normal cache, gateways share with each other:

```
┌─────────────────────────────────────────────────┐
│         DISTRIBUTED MESH CACHE                   │
│                                                   │
│  Gateway A (city)    ◀───── LoRa sync ─────▶   Gateway B (rural)
│  • Wikipedia (full)          (nightly)          • Wikipedia (full)
│  • Project Gutenberg                            • Project Gutenberg
│  • Stack Overflow                               • Stack Overflow
│  • Local news                                   • Local news
│                                                   │
│        ▲                                         ▲
│        │                                         │
│   USB sync                                 USB sync
│   (monthly)                                 (monthly)
│        ▼                                         ▼
│  Gateway C (library)                       Gateway D (school)
└─────────────────────────────────────────────────┘
```

How Cache Sharing Works

```ini
[mesh_cache]
# Enable distributed caching
enabled = true
cache_dir = /var/cache/deadmesh
max_size_gb = 100

# Share with peer gateways
[mesh_cache.peers]
# Format: nickname = connection_string
north_gateway = radio://longfast/channel4?nodeid=!abcdef12
south_gateway = radio://longfast/channel4?nodeid=!12345678

# Sync schedule
sync_interval = 86400  # Once daily (seconds)
sync_window = "02:00-04:00"  # Overnight when mesh idle
max_sync_bytes = 10485760  # 10MB per sync

# Cache index exchange (tiny—just URLs and hashes)
share_index = true
index_broadcast_interval = 3600  # Hourly "what's new?"
```

Cache Hierarchy

Tier Contents Access Time Persistence
L1: Local RAM Hot items (last 24h) Instant Volatile
L2: Local Disk All transformed content <10ms Permanent
L3: Peer Cache Neighbor gateway's content Minutes (LoRa fetch) Until evicted
L4: Regional Offline archive (USB/sneakernet) Hours-days Physical media

Cache Warming Expeditions

The most exciting possibility: physical cache transport.

```bash
# On source gateway (city library)
$ ./tools/cache-export --output /mnt/usb3/wikipedia-cache \
  --domain wikipedia.org --size 80GB

# On target gateway (rural school)
$ ./tools/cache-import --input /mnt/usb3/wikipedia-cache \
  --verify --priority high
```

A volunteer with a USB drive becomes a mesh librarian, carrying terabytes of transformed knowledge to communities without internet. The mesh network gets faster over time as the cache grows.

Real-World Impact: Before and After

Scenario: Rural school with deadmesh gateway (no internet)

Day Student Experience
Day 1 Requests Wikipedia article → gateway fetches via satellite (slow, expensive), transforms, delivers in 90 seconds
Day 30 After daily peer sync with city gateway, local cache holds 10,000 transformed articles
Day 90 Monthly USB sync adds Project Gutenberg (60GB) and Khan Academy videos (compressed)
Day 365 School has 95% of curriculum content cached locally. Internet fetches only needed for new or rare queries.

The mesh becomes a knowledge appliance, not just a network.

Configuration: Putting It All Together

```ini
[core]
port = 8080
log_level = info

[meshtastic]
enabled = true
serial_port = /dev/ttyACM0
hop_limit = 3

[mesh_router]
# Routing rules
allow = wikipedia.org, *.wikipedia.org, text.npr.org, *.edu
deny = *.youtube.com, *.twitch.tv, *.tiktok.com
api_map = spotify.com=api.spotify.com/v1, weather.com=api.weather.gov

[mesh_router.transform]
text_only = *.wikipedia.org, *.npr.org, *.edu
image_mode = none
max_response_kb = 100
compress = true

[mesh_cache]
enabled = true
max_size_gb = 100
sync_interval = 86400

[mesh_cache.peers]
city_hall = radio://longfast/channel4?nodeid=!abcdef
mountain_top = radio://longfast/channel4?nodeid=!123456
library = usb://media/deadmesh-archive  # Mount point for sneakernet

[plugin.cache]  # Legacy cache (now integrated)
# Kept for backward compatibility
disk_cache_dir = /var/cache/deadmesh
```

Why This Changes Everything

Without Smart Routing With Smart Routing + Mesh Cache
Every request hits the internet Most requests hit local/peer cache
Users wait minutes for bloated pages Users get text in seconds
Bandwidth wasted on ads/JS Bandwidth used for actual content
Gateways are isolated Gateways form a distributed knowledge network
Network is always slow Network gets faster with use

The Vision

A network where:

· A student in a remote village accesses Wikipedia instantly because their local gateway cached it last month
· A journalist in a blackout zone emails their editor via any nearby gateway, even if neither has live internet
· Communities share knowledge peer-to-peer, bypassing the need for expensive satellite backhaul
· The cache grows to include curated collections: medical texts, agricultural guides, technical documentation, educational materials
· Anyone with a USB drive can be a librarian, physically transporting knowledge to disconnected communities

Deadmesh stops being just a bridge to the internet. It becomes an alternative internet—one that's resilient, community-owned, and optimized for human-scale communication.

---
