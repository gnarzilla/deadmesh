## Real-World Use Cases

> These scenarios illustrate what a complete deadmesh deployment enables. The gateway proxy pipeline supports all of them today; full end-to-end mesh delivery is in final testing

### Disaster Response Network

**Scenario**: Earthquake destroys cell infrastructure

**Setup**: Solar-powered deadmesh gateway at field hospital (satellite uplink). Rescue teams carry Meshtastic handhelds (10km range per hop). Coordinate via email, share maps, update databases.

**Result**: Teams stay connected across 50+ km² with zero functioning infrastructure.

### Rural Community Internet

**Scenario**: Village 30km from nearest fiber

**Setup**: One gateway at village center (WiMAX or satellite backhaul). Residents install Meshtastic radios on roofs. Multi-hop mesh covers entire valley.

**Result**: 100+ households share a single Internet connection. Hardware cost ~$50/household, no monthly fees.

### Carrier-Independent Daily Use

**Scenario**: You'd rather not pay for a cellular data plan for text-first use

**Setup**: $30 Heltec connected to a phone via USB OTG or Bluetooth. deadmesh-client running locally. Nearest gateway (yours, a friend's, or a community node) within LoRa range.

**Result**: Email, text-based browsing, weather, maps — all working without a carrier. Voice calls remain impossible at LoRa bitrates, but that's most of what a phone actually does for most people.

### Protest / Festival Network

**Scenario**: Large gathering needs coordination without government-controlled infrastructure

**Setup**: Organizers carry deadmesh gateways with LTE failover. Attendees use Meshtastic app on phones. Network disappears forensically when powered down.

**Result**: Thousands communicate freely. No persistent logs, no fixed infrastructure to seize.

### Journalist in Blackout Zone

**Scenario**: Government shuts down Internet during protests

**Setup**: Journalist has Meshtastic radio + deadmesh on laptop. Connects to gateway run by colleague 15km away (who has connectivity). Files stories via mesh SMTP relay.

**Result**: Censorship bypassed. Reports reach editors despite blackout.
