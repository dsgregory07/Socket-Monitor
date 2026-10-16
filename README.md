# Socket Monitor

A small Python tool that watches active TCP/UDP socket connections on a Linux host and
logs each one as it appears and closes. It can filter by port and/or destination
(IP, CIDR, or hostname) and optionally raise desktop notifications via `notify-send`.

## How it works
`monitor.py` polls `ss` on an interval and diffs each snapshot against the previous one:
- TCP via `ss -tnpn state established`, UDP via `ss -unpn`.
- `parse_ss_output()` matches `IPv4:port` / `[IPv6]:port` pairs with a regex, so it is
  robust to `ss` dropping columns when a state filter is applied.
- New and closed (`CLOSED`) connections are written to the log.
- `connection_direction()` infers INBOUND / OUTBOUND from which side holds a watched
  port, falling back to the Linux ephemeral range (>= 32768 = OUTBOUND).
- New remote IPs are enriched with their MAC address from `/proc/net/arp`.
- Destinations are re-resolved every `resolve_interval` seconds.

The poll loop runs in a daemon thread; Ctrl+C shuts it down cleanly.

## Requirements
- Linux with `iproute2` (the tool shells out to `ss`).
- Python 3 (standard library only).
- Optional: `notify-send` (libnotify) for desktop notifications.

## Configuration (`config.json`)
| Key | Meaning |
|---|---|
| `destinations` | IPs / CIDRs / hostnames to watch (empty = all) |
| `ports` | TCP ports to watch |
| `udp_ports` | UDP ports to watch |
| `poll_interval` | seconds between `ss` snapshots |
| `resolve_interval` | seconds between re-resolving destinations |
| `log_file` | where to write the connection log |
| `notify` | enable `notify-send` notifications |
| `notify_timeout` | notification timeout (ms) |

## Usage
```
python3 monitor.py                              # use config.json
python3 monitor.py --config other.json
python3 monitor.py --ports 80,443 --udp-ports 53
python3 monitor.py --destinations 10.0.0.0/8,example.com
```
CLI flags override the matching `config.json` values. Connections are logged to the
configured `log_file` (default `connections.log`) and echoed to stdout.
