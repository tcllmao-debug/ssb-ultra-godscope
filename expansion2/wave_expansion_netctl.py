"""SSB swarm-24 expansion: nm21.netctl — network control plane.
Real nftables/iptables, routes, tc, raw packet crafting. Armed:true default."""
import json, os, platform, socket, struct, subprocess, sys

def _res(power, **kw):
    d = {"ok": True, "power": power, "platform": platform.system().lower()}
    d.update(kw); return d

def _err(power, msg, **kw):
    d = {"ok": False, "power": power, "error": str(msg)}
    d.update(kw); return d

def _run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: " + cmd[0]
    except Exception as e:
        return 1, "", str(e)

def _armed(args):
    return bool(args.get("arm", True))


def interface_list(args):
    """Real interface list with addresses and states."""
    rc, out, err = _run(["ip", "-j", "addr", "show"])
    if rc == 0:
        try:
            return _res("interface_list", interfaces=json.loads(out))
        except ValueError:
            pass
    rc, out, err = _run(["ip", "addr", "show"])
    ifaces = []
    cur = None
    for line in out.splitlines():
        if line and line[0].isdigit():
            parts = line.split(":")
            cur = {"name": parts[1].strip(), "flags": line.split("<")[1].split(">")[0].split(",") if "<" in line else []}
            ifaces.append(cur)
        elif cur and "inet " in line:
            cur.setdefault("inet", []).append(line.strip())
    return _res("interface_list", interfaces=ifaces)


def route_table(args):
    """Real routing table."""
    rc, out, err = _run(["ip", "route", "show", "table", "all"])
    rc6, out6, _ = _run(["ip", "-6", "route", "show"])
    return _res("route_table", ipv4=out.splitlines(), ipv6=out6.splitlines())


def nft_rules_list(args):
    """Dump the real nftables ruleset."""
    rc, out, err = _run(["nft", "list", "ruleset"])
    if rc != 0:
        return _err("nft_rules_list", err.strip() or "nft unavailable")
    return _res("nft_rules_list", ruleset=out)


def nft_block_ip(args):
    """Block an IP via a real nftables rule (armed)."""
    ip = str(args.get("ip", ""))
    if not ip:
        return _err("nft_block_ip", "need 'ip'")
    cmds = [["nft", "add", "table", "inet", "ssb_filter"],
            ["nft", "add", "chain", "inet", "ssb_filter", "input",
             "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"],
            ["nft", "add", "rule", "inet", "ssb_filter", "input", "ip", "saddr",
             ip, "drop"]]
    if not _armed(args):
        return _res("nft_block_ip", armed=False, would_run=cmds)
    for c in cmds:
        rc, out, err = _run(c)
        if rc != 0 and "File exists" not in err and "exists" not in err:
            d = _res("nft_block_ip", armed=True, applied=False, ip=ip, stderr=err.strip())
            d["ok"] = False
            return d
    return _res("nft_block_ip", armed=True, applied=True, ip=ip, action="drop")


def iptables_list(args):
    """Dump real iptables rules (filter + nat)."""
    tables = {}
    for t in ("filter", "nat", "mangle", "raw"):
        rc, out, err = _run(["iptables", "-t", t, "-L", "-n", "-v"])
        if rc == 0:
            tables[t] = out.splitlines()
    return _res("iptables_list", tables=tables)


def tc_qdisc_report(args):
    """Real traffic-control qdisc/class report."""
    rc, out, err = _run(["tc", "qdisc", "show"])
    rc2, out2, _ = _run(["tc", "class", "show"])
    return _res("tc_qdisc_report", qdiscs=out.splitlines(), classes=out2.splitlines())


def tc_rate_limit(args):
    """Apply a real tc rate limit to an interface (armed)."""
    iface = str(args.get("iface", ""))
    rate = str(args.get("rate", "1mbit"))
    if not iface:
        return _err("tc_rate_limit", "need 'iface'")
    cmds = [["tc", "qdisc", "replace", "dev", iface, "root", "tbf",
             "rate", rate, "burst", "32kbit", "latency", "400ms"]]
    if not _armed(args):
        return _res("tc_rate_limit", armed=False, would_run=cmds)
    rc, out, err = _run(cmds[0])
    d = _res("tc_rate_limit", armed=True, applied=(rc == 0), iface=iface, rate=rate,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def raw_packet_craft(args):
    """Craft a real raw packet (bytes returned as hex; send when armed+root)."""
    dst = str(args.get("dst", "127.0.0.1"))
    payload = str(args.get("payload", "ssb")).encode()
    ver_ihl = 0x45; tos = 0; total = 20 + 8 + len(payload)
    ident = os.getpid() & 0xFFFF; frag = 0; ttl = 64; proto = socket.IPPROTO_UDP
    src = socket.gethostbyname(socket.gethostname())
    dst_ip = socket.gethostbyname(dst)
    def csum(data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF); s += s >> 16
        return ~s & 0xFFFF
    iph = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident, frag, ttl,
                      proto, 0, socket.inet_aton(src), socket.inet_aton(dst_ip))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    sport = int(args.get("sport", 5555)); dport = int(args.get("dport", 9999))
    udph = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pkt = iph + udph + payload
    result = {"packet_hex": pkt.hex(), "bytes": len(pkt), "dst": dst_ip}
    if _armed(args) and args.get("send"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(pkt, (dst_ip, 0))
            s.close()
            result["sent"] = True
        except PermissionError:
            result["sent"] = False
            result["error"] = "need root/CAP_NET_RAW"
    return _res("raw_packet_craft", armed=_armed(args), **result)


def arp_table(args):
    """Real ARP/neighbor table."""
    rc, out, err = _run(["ip", "neigh", "show"])
    rows = [l for l in out.splitlines() if l.strip()]
    return _res("arp_table", neighbors=rows)


def conntrack_report(args):
    """Real connection-tracking table snapshot."""
    rc, out, err = _run(["conntrack", "-L"])
    if rc == 0:
        rows = out.splitlines()
    else:
        try:
            rows = open("/proc/net/nf_conntrack", errors="replace").read().splitlines()
        except OSError:
            rows = []
    return _res("conntrack_report", entries=rows[:500], count=len(rows))


def bridge_report(args):
    """Real bridge inventory."""
    rc, out, err = _run(["bridge", "link", "show"])
    sysbr = []
    d = "/sys/class/net"
    if os.path.isdir(d):
        sysbr = [n for n in os.listdir(d)
                 if os.path.isdir(os.path.join(d, n, "brif"))]
    return _res("bridge_report", links=out.splitlines(), bridges=sysbr)


def vxlan_create(args):
    """Create a real VXLAN interface (armed)."""
    name = str(args.get("name", "vxlan100"))
    vni = int(args.get("vni", 100))
    group = str(args.get("group", "239.1.1.1"))
    dev = str(args.get("dev", "eth0"))
    cmd = ["ip", "link", "add", name, "type", "vxlan", "id", str(vni),
           "group", group, "dev", dev, "dstport", "4789"]
    if not _armed(args):
        return _res("vxlan_create", armed=False, would_run=cmd)
    rc, out, err = _run(cmd)
    d = _res("vxlan_create", armed=True, applied=(rc == 0), name=name, vni=vni,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def port_listener_map(args):
    """Real listening ports mapped to processes."""
    rc, out, err = _run(["ss", "-tlnp"])
    rc2, out2, _ = _run(["ss", "-ulnp"])
    return _res("port_listener_map", tcp=out.splitlines(), udp=out2.splitlines())


def socket_stat(args):
    """Real socket statistics summary."""
    rc, out, err = _run(["ss", "-s"])
    return _res("socket_stat", summary=out)


def dns_resolver_report(args):
    """Real DNS resolver configuration."""
    resolv = None
    try:
        resolv = open("/etc/resolv.conf", errors="replace").read()
    except OSError:
        pass
    hosts = None
    try:
        hosts = open("/etc/hosts", errors="replace").read()
    except OSError:
        pass
    return _res("dns_resolver_report", resolv_conf=resolv, hosts=hosts)


POWERS = {f"nm21.netctl.{fn.__name__}": fn for fn in
          (interface_list, route_table, nft_rules_list, nft_block_ip,
           iptables_list, tc_qdisc_report, tc_rate_limit, raw_packet_craft,
           arp_table, conntrack_report, bridge_report, vxlan_create,
           port_listener_map, socket_stat, dns_resolver_report)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
