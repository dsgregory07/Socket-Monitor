#!/usr/bin/env python3
import ipaddress
import json
import logging
import argparse
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"


def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return json.load(f)


def setup_logging(log_file):
    log_path = BASE_DIR / log_file
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(),
        ],
    )


def notify(title, message, timeout_ms):
    try:
        subprocess.run(
            ["notify-send", "-t", str(timeout_ms), title, message],
            check=False,
            capture_output=True,
        )
    except FileNotFoundError:
        pass


def get_arp_table():
    arp = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3]
                    if mac != "00:00:00:00:00:00":
                        arp[ip] = mac
    except OSError:
        pass
    return arp


def resolve_destinations(destinations):
    """Resolve a list of hostnames, IPs, or CIDRs into a flat IP set and list of networks."""
    ip_set = set()
    networks = []
    for dest in destinations:
        try:
            net = ipaddress.ip_network(dest, strict=False)
            if net.num_addresses == 1:
                ip_set.add(str(net.network_address))
            else:
                networks.append(net)
            continue
        except ValueError:
            pass
        try:
            for info in socket.getaddrinfo(dest, None):
                ip_set.add(info[4][0])
        except socket.gaierror:
            logging.warning(f"Could not resolve destination: {dest}")
    return ip_set, networks


def ip_in_destinations(ip, ip_set, networks):
    if ip in ip_set:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


# Matches IPv4:port or [IPv6]:port — used to find address pairs regardless of ss column layout.
# ss omits the Netid/State columns when a state filter is applied, so column-based indexing breaks.
_ADDR_RE = re.compile(
    r'((?:\d{1,3}(?:\.\d{1,3}){3}|\[[\da-fA-F:]+\]):\d+)'
    r'[ \t]+'
    r'((?:\d{1,3}(?:\.\d{1,3}){3}|\[[\da-fA-F:]+\]):\d+)'
)


def _split_addr(addr):
    """Split 'ip:port' or '[ipv6]:port' into (ip, port_str)."""
    if addr.startswith('['):
        end = addr.index(']')
        return addr[1:end], addr[end + 2:]
    ip, _, port = addr.rpartition(':')
    return (ip, port) if ip else (addr, '0')


def parse_ss_output(output):
    """Parse ss output into (local_ip, local_port, remote_ip, remote_port) tuples."""
    connections = []
    for line in output.splitlines()[1:]:
        m = _ADDR_RE.search(line)
        if not m:
            continue
        local_ip, local_port = _split_addr(m.group(1))
        remote_ip, remote_port = _split_addr(m.group(2))
        connections.append((local_ip, local_port, remote_ip, remote_port))
    return connections


def connection_direction(local_port, remote_port, all_ports):
    """Infer INBOUND/OUTBOUND from port positions relative to watched ports."""
    try:
        lp, rp = int(local_port), int(remote_port)
    except ValueError:
        return "UNKNOWN"
    if all_ports:
        if lp in all_ports:
            return "INBOUND"
        if rp in all_ports:
            return "OUTBOUND"
    # Linux ephemeral range fallback
    return "OUTBOUND" if lp >= 32768 else "INBOUND"


def get_connections(tcp_ports, udp_ports, dest_ip_set, dest_networks):
    """Return set of (proto, local_ip, local_port, remote_ip, remote_port) matching active filters."""
    connections = set()
    filter_by_dest = bool(dest_ip_set or dest_networks)

    def matches(local_port, remote_ip, remote_port, port_set):
        if filter_by_dest:
            if not ip_in_destinations(remote_ip, dest_ip_set, dest_networks):
                return False
            if not port_set:
                return True
            # In destination mode, match on either side of the connection (inbound or outbound)
            lp = int(local_port) if local_port.isdigit() else -1
            rp = int(remote_port) if remote_port.isdigit() else -1
            return lp in port_set or rp in port_set
        # Port-only mode: match inbound (local port is the watched service port)
        return local_port.isdigit() and int(local_port) in port_set

    if tcp_ports or filter_by_dest:
        try:
            result = subprocess.run(
                ["ss", "-tnpn", "state", "established"],
                capture_output=True, text=True, check=True,
            )
            for entry in parse_ss_output(result.stdout):
                if matches(entry[1], entry[2], entry[3], tcp_ports):
                    connections.add(("TCP", *entry))
        except subprocess.CalledProcessError:
            pass

    if udp_ports or filter_by_dest:
        try:
            result = subprocess.run(
                ["ss", "-unpn"],
                capture_output=True, text=True, check=True,
            )
            for entry in parse_ss_output(result.stdout):
                if matches(entry[1], entry[2], entry[3], udp_ports):
                    connections.add(("UDP", *entry))
        except subprocess.CalledProcessError:
            pass

    return connections


def monitor_loop(config, stop_event):
    tcp_ports = set(config.get("ports", []))
    udp_ports = set(config.get("udp_ports", []))
    destinations = config.get("destinations", [])
    poll_interval = config.get("poll_interval", 1)
    notify_enabled = config.get("notify", False)
    notify_timeout = config.get("notify_timeout", 5000)
    resolve_interval = config.get("resolve_interval", 60)

    dest_ip_set, dest_networks = resolve_destinations(destinations)
    last_resolve = time.monotonic()

    if destinations:
        logging.info(f"Watching destinations: {destinations}  ({len(dest_ip_set)} resolved IPs, {len(dest_networks)} networks)")
    if tcp_ports:
        logging.info(f"Watching TCP ports: {sorted(tcp_ports)}")
    if udp_ports:
        logging.info(f"Watching UDP ports: {sorted(udp_ports)}")

    all_ports = tcp_ports | udp_ports
    known = get_connections(tcp_ports, udp_ports, dest_ip_set, dest_networks)

    while not stop_event.is_set():
        time.sleep(poll_interval)

        if destinations and (time.monotonic() - last_resolve) >= resolve_interval:
            dest_ip_set, dest_networks = resolve_destinations(destinations)
            last_resolve = time.monotonic()

        current = get_connections(tcp_ports, udp_ports, dest_ip_set, dest_networks)
        new_conns = current - known
        dropped = known - current

        arp = get_arp_table() if new_conns else {}

        for proto, local_ip, local_port, remote_ip, remote_port in new_conns:
            direction = connection_direction(local_port, remote_port, all_ports)
            mac = arp.get(remote_ip, "")
            mac_str = f" ({mac})" if mac else ""
            msg = f"[{proto}] [{direction}] {local_ip}:{local_port} <-> {remote_ip}:{remote_port}{mac_str}"
            logging.info(msg)
            if notify_enabled:
                notify(f"SocketMon: {proto} {direction}", msg, notify_timeout)

        for proto, local_ip, local_port, remote_ip, remote_port in dropped:
            direction = connection_direction(local_port, remote_port, all_ports)
            logging.info(f"[{proto}] [{direction}] CLOSED {local_ip}:{local_port} <-> {remote_ip}:{remote_port}")

        known = current


def main():
    parser = argparse.ArgumentParser(description="Monitor socket connections by destination and/or port")
    parser.add_argument("--config", default=CONFIG_PATH, help="Path to config.json")
    parser.add_argument("--ports", nargs="+", type=int, help="Override TCP ports to watch")
    parser.add_argument("--udp-ports", nargs="+", type=int, help="Override UDP ports to watch")
    parser.add_argument("--destinations", nargs="+", help="Override destinations to watch (IPs, CIDRs, or hostnames)")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.ports:
        config["ports"] = args.ports
    if args.udp_ports:
        config["udp_ports"] = args.udp_ports
    if args.destinations:
        config["destinations"] = args.destinations

    setup_logging(config["log_file"])

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_loop, args=(config, stop_event), daemon=True)
    monitor_thread.start()

    logging.info("SocketMon started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down.")
        stop_event.set()
        monitor_thread.join(timeout=2)


if __name__ == "__main__":
    main()
