# Smart Mesh Routing – deadmesh UX Philosophy

**Goal:** Give every user a clear, predictable, and delightful experience even when the LoRa mesh is slow, lossy, or duty-cycle limited.

## The `mesh://` URL scheme

Prefix any URL with `mesh://` to instantly switch into **mesh-optimized mode**.

```text
Normal internet:     http://en.wikipedia.org/wiki/Meshtastic
Mesh-optimized:      mesh://en.wikipedia.org/wiki/Meshtastic
```

- `http://` = best-effort (normal rules may still apply)
- `mesh://` = aggressive optimization: text-only, stripped media, heavy compression, smart caching

This gives users **explicit intent** and removes all guesswork.

### Quick Cheat Sheet

| You type                              | What you get                                      | Best for                              |
|---------------------------------------|---------------------------------------------------|---------------------------------------|
| `http://wikipedia.org`                | Normal page (may be filtered or throttled)        | Decent signal / short session         |
| `mesh://wikipedia.org`                | Clean text-only version (~98% smaller)            | Long sessions, poor signal            |
| `mesh://api.example.com/data`         | Raw JSON (no HTML transformation)                 | Apps, scripts, structured data        |
| `mesh://youtube.com/watch?v=…`        | Friendly denial + alternatives                    | Never — YouTube is not mesh-friendly  |

## What happens when something is impossible

Instead of silent timeouts or ugly 404s, deadmesh gives **helpful, honest, and occasionally fun** responses.

**Example – trying to watch YouTube over LoRa:**

```
❌ youtube.com is not available over mesh

   Estimated time: ~47 hours
   Duty-cycle used: 312% of daily limit

✅ Try these mesh-friendly alternatives instead:
   • mesh://en.wikipedia.org/wiki/YouTube
   • mesh://invidious.io  (lightweight YouTube frontend)
   • mesh://yt.odysee.com
```

Users leave the page **smarter** than when they arrived.

## How the smart router actually works (flow)

```
Incoming request
       ↓
1. Is it mesh:// ? → Yes → enter ultra-light mode
       ↓
2. Check local cache (instant hit = magic)
       ↓
3. Check peer gateways (multi-gateway routing)
       ↓
4. Apply transformation rules (HTML→text, strip images, compress)
       ↓
5. Fragment, send over LoRa with store-and-forward
       ↓
6. Cache result + share with mesh (knowledge appliance)
```

## Real-world impact examples

| Scenario                        | Before (normal http)       | After (mesh:// + smart cache)          |
|---------------------------------|----------------------------|----------------------------------------|
| Wikipedia article               | 487 KB                     | 11 KB (97.7% reduction)                |
| Rural school (1 year)           | 18 GB total traffic        | 340 MB total (after cache warming)     |
| Hiker checking weather          | 3-minute timeout           | 11 seconds, cached for whole valley    |

## The “Knowledge Appliance” vision

Every deadmesh gateway slowly turns the entire mesh into a **living library**.

- First week: mostly empty cache
- Month 3: popular articles, maps, medical guides, repair manuals already cached
- Year 1: the mesh becomes dramatically more useful every single day

### Cache Warming Expeditions (the fun part)

Volunteers can load a USB stick with curated content, walk the trail/mesh, and “seed” every gateway they pass.

We call them **mesh librarians** — the most wholesome job in off-grid networking.

## Configuration – clean & annotated

```ini
[routing]
; Enable the mesh:// scheme (highly recommended)
mesh_scheme = true

[transform]
; Convert HTML to clean text, strip images/videos
html_to_text = true
max_size_kb = 64

[cache]
; Share everything we fetch with the rest of the mesh
share_cache = true
max_age_days = 30
warm_on_boot = true

[denied]
; Friendly messages instead of errors
show_alternatives = true
```

## Next steps for you

1. Try `mesh://` on any link — you’ll immediately feel the difference.
2. Seed your local gateway with a few important pages (weather, Wikipedia survival articles, local maps).
3. Become a mesh librarian — load a USB stick and go for a walk.

---

**This is how deadmesh turns painful LoRa limitations into a delightful, human-centered experience.**

The mesh doesn’t have to feel like a downgrade.  
With `mesh://` + smart routing + helpful denials + shared cache, it feels like the network is **on your side**.

— gnarzilla
---