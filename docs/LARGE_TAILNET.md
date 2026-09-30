# Large Tailnet Considerations

MicroLink v2 has been tested with 1000+ peer tailnets. This document covers configuration and limits.

## Configuration

### ML_MAX_PEERS (Kconfig)

The slots of the peer table, each with its WireGuard tunnel. WireGuard's own peer count follows it.

```
idf.py menuconfig → MicroLink V2 → Slots in the peer table
```

A slot takes about 1.2 KB on a 32-bit target, in use or not: 264 bytes of the instance (`ml_peer_t`) and 904 bytes of the WireGuard device (`struct wireguard_peer`).

| Setting | Memory | Use case |
|---|---|---|
| 4 | ~4.7KB | A node that talks to a few peers, and keeps them (below) |
| 16 | ~18.7KB | Default |
| 64 | ~74.8KB | The most; PSRAM |

### A tailnet larger than the table

The table holds the first `ML_MAX_PEERS` peers it is given: the peers cached in NVS at start, then the peers of the control server's map in the order it lists them. Every peer after that is left out, with a warning (`Peer table full (16 slots), cannot add <name>`): the node has no tunnel to it, accepts none from it, and resolves no name to it (`microlink_resolve`). Which peers those are is the map's order, not a choice. A peer the table holds is updated in place by every later map, so the same peers hold the slots from one map to the next; a slot comes free when its peer leaves the tailnet. A cached peer the first map lacks gives its slot up only when that map ends: until then it can cost a peer of the map its slot.

The peers that must not be left out are **kept**: `microlink_keep_peers()` names up to 8 of them, by address or by name (`config.priority_peer_ip` and `ML_PRIORITY_PEER_IP` name one from the start). A kept peer that finds the table full takes the slot of a peer that is not kept — one the last full map has not listed (a cached peer, say) before one it has, and among those the one heard from or sent to the longest ago — whose tunnel closes (`Peer table full (16 slots): evicting <name> (<ip>) for kept peer <name>`). A kept peer never gives way. Naming a peer the table does not hold while the node runs makes it reconnect to the control server for the full map, where the peer takes its slot; the tunnels stay up meanwhile.

So a node on a tailnet of any size needs as many slots as the peers it keeps, and a few more if the rest matter. A tailnet policy that shows the node only the peers it talks to keeps the others out of its map altogether: they take no slot, and no room in the buffers below.

### ML_NVS_MAX_PEERS (Kconfig)

Controls NVS flash cache for peer metadata (persists across reboots).

```
idf.py menuconfig → MicroLink V2 → Maximum cached peers in NVS
```

| Setting | NVS Blob Size | Partition Requirement |
|---|---|---|
| 16 | ~1.5KB | Default NVS partition |
| 64 | ~5.9KB | Default NVS partition |
| 256 | ~23.6KB | Default NVS partition |
| 1024 | ~94.2KB | Custom NVS partition (≥128KB) |

For 1024 peers, you need a custom partition table with a larger NVS partition:
```csv
# Name,   Type, SubType, Offset,  Size,    Flags
nvs,      data, nvs,     ,        0x20000,
phy_init, data, phy,     ,        0x1000,
factory,  app,  factory, ,        0x300000,
```

### Coordination Buffer

Large peer lists require larger HTTP/2 response buffers:

```
idf.py menuconfig → MicroLink V2 → Coord buffer size (KB)
```

- 64KB: ~30 peers
- Default: 512KB, ~300 peers (PSRAM-backed)

The first map must fit both `ML_H2_BUFFER_SIZE_KB` and `ML_JSON_BUFFER_SIZE_KB` whole. One that does not is cut at the buffer's end and cannot be read: the node does not join, `microlink_get_map()` answers `ML_MAP_OVERSIZED`, the log says `MapResponse larger than its buffers`, and the node registers again a minute later, then two, up to fifteen.

Already configured in `microlink_internal.h`:
- H2 WINDOW_UPDATE: proactive updates for responses >64KB
- Recv timeout: 60s (control plane may be slow with large peer lists)

## DISCO Scaling

With 100+ peers, DISCO probe intervals are staggered to prevent network flooding:

- Peers are probed in batches of 10
- 3s delay between batches
- On cellular: all proactive DISCO is suppressed (only respond to incoming probes)

## Delta Updates

MicroLink v2 supports Tailscale's incremental peer updates:
- `PeersChanged`: Only changed peers sent
- `PeersRemoved`: Only removed peer IDs sent
- `PeersChangedPatch`: Minimal field-level patches

This means a 1000-peer tailnet doesn't re-download the full peer list on every long-poll response.

## Recommendations

1. **Keep the peers you need** — `ML_MAX_PEERS` need not be the tailnet's size: name the peers the node talks to with `microlink_keep_peers()`, and the table leaves others out, never those.
2. **Use PSRAM** — Required for large tailnets. All ESP32-S3 boards we support have 8MB PSRAM.
3. **Use reusable auth keys** — Large deployments should use pre-generated reusable keys.
4. **IMEI-based naming** — For cellular deployments, `microlink_imei_device_name()` generates unique names.
5. **NVS partition** — For 1024+ cached peers, use a custom partition table.
