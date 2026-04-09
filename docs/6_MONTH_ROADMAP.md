Project Title: Deadmesh: Content-Addressed Caching and Smart mesh:// Routing for Resilient LoRa Meshes
Duration: 6 months (April–September 2026, flexible)
Milestones & Deliverables (all MIT-licensed, public on GitHub):

Month 1–2: Core Caching Layer

Design and implement hash-based content store (with deduplication, gzip compression, TTL/expiration).
Integrate with existing proxy for automatic caching of HTTP responses and email content.
Add simple embedded dashboard for cache stats and manual management.
Deliverable: Working cache module + unit tests; blog post explaining the design.

Month 2–3: Smart mesh:// Routing

Implement mesh:// URI scheme handler (prefers local/cached content, falls back across hops based on airtime, battery, RSSI).
Add intelligent routing logic (no central coordinator; uses existing mesh metadata).
Handle fragmentation/reassembly enhancements for larger cached objects.
Deliverable: mesh:// support in gateway + proxy; demo showing zero-airtime repeat loads.

Month 3–4: Integration, Dashboard & Librarian Tools

Extend live dashboard with cache visualization and "mesh librarian" features (e.g., import/export popular content packs like Wikipedia excerpts).
Add basic eviction and consistency policies for delay-tolerant meshes.
Deliverable: Updated firmware for Raspberry Pi/compatible nodes; hardware build guide (solar-powered example).

Month 4–5: Real-World Testing & Optimization

Deploy 3–5 test nodes (mix of rural/off-grid setups).
Measure improvements: airtime savings, battery life, success rate for standard apps (browser/email).
Iterate based on logs and edge cases (intermittent links, power failures).
Deliverable: Test report with metrics + video demos on deadmesh.boo or YouTube.

Month 5–6: Documentation, Outreach & Polish

Full README updates, user/hardware guides, and API docs.
Engage communities (Meshtastic Discord, off-grid forums, potential EU contacts).
Release everything publicly; prepare for follow-on contributions.
Deliverable: Complete project documentation + outreach summary (blog posts, PRs if applicable).

Risks & Contingencies: Focus on software-first; hardware testing uses existing low-cost nodes. If caching proves trickier on constrained devices, prioritize core router and defer advanced eviction
