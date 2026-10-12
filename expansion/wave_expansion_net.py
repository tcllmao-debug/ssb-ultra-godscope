"""SSB ULTRA wave-expansion module: domain 'net' (nm20.net.*).

Pure stdlib network powers: real /proc parsing, real sockets, real artifact
generators. Import-safe: no side effects at import time.
"""

import os
import sys
import json
import socket
import struct
import subprocess
import tempfile
import time

PLATFORM = sys.platform
TMPDIR = tempfile.gettempdir()


def _base(name):
    return {"ok": False, "power": "nm20.net.%s" % name, "platform": PLATFORM}


def _run(cmd, timeout=10):
    """Run a command, returning (rc, stdout, stderr) without raising."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ds" % timeout
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _hex_ip(h, little=True):
    b = bytes.fromhex(h)
    if little:
        b = b[::-1]
    return socket.inet_ntoa(b)


_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _parse_proc_net_tcp(path, family):
    rows = []
    try:
        with open(path) as f:
            lines = f.readlines()[1:]
    except (OSError, IOError) as e:
        return rows, str(e)
    for ln in lines:
        parts = ln.split()
        if len(parts) < 10:
            continue
        try:
            lip_hex, lp_hex = parts[1].split(":")
            rip_hex, rp_hex = parts[2].split(":")
            if family == 6:
                lip = socket.inet_ntop(socket.AF_INET6,
                                       struct.pack("<IIII", *struct.unpack(">IIII", bytes.fromhex(lip_hex))))
                rip = socket.inet_ntop(socket.AF_INET6,
                                       struct.pack("<IIII", *struct.unpack(">IIII", bytes.fromhex(rip_hex))))
            else:
                lip = _hex_ip(lip_hex)
                rip = _hex_ip(rip_hex)
            st = parts[3]
            rows.append({
                "local": "%s:%d" % (lip, int(lp_hex, 16)),
                "remote": "%s:%d" % (rip, int(rp_hex, 16)),
                "state": _TCP_STATES.get(st.upper(), st),
                "tx_queue": int(parts[4].split(":")[0], 16),
                "rx_queue": int(parts[4].split(":")[1], 16),
                "uid": int(parts[7]),
                "inode": parts[9],
            })
        except (ValueError, IndexError):
            continue
    return rows, None


def nm20_net_netstat_dump(args):
    """Parse /proc/net/{tcp,udp,tcp6,udp6} into a real socket table (plus ss if present)."""
    r = _base("netstat_dump")
    limit = int(args.get("limit", 200))
    table = {}
    for path, fam, key in (("/proc/net/tcp", 4, "tcp"),
                           ("/proc/net/udp", 4, "udp"),
                           ("/proc/net/tcp6", 6, "tcp6"),
                           ("/proc/net/udp6", 6, "udp6")):
        rows, err = _parse_proc_net_tcp(path, fam)
        if err:
            table[key] = {"error": err}
        else:
            table[key] = rows[:limit]
    r["sockets"] = table
    r["counts"] = {k: (len(v) if isinstance(v, list) else 0) for k, v in table.items()}
    rc, out, err = _run(["ss", "-tuanp"], timeout=5)
    r["ss_available"] = rc == 0
    if rc == 0:
        r["ss_sample"] = out.splitlines()[:40]
    r["ok"] = True
    return r


def nm20_net_conn_table(args):
    """Map live socket inodes to owning PIDs/process names via /proc/*/fd."""
    r = _base("conn_table")
    inode_to_sock = {}
    for fam_file in ("tcp", "udp", "tcp6", "udp6"):
        rows, _ = _parse_proc_net_tcp("/proc/net/" + fam_file, 6 if fam_file.endswith("6") else 4)
        for row in rows:
            inode_to_sock[row["inode"]] = (fam_file, row)
    pid_map = []
    scanned = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        try:
            with open("/proc/%s/comm" % pid) as f:
                comm = f.read().strip()
        except OSError:
            comm = "?"
        socks = []
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                inode = link[8:-1]
                entry = {"fd": fd, "inode": inode}
                if inode in inode_to_sock:
                    fam, row = inode_to_sock[inode]
                    entry.update({"proto": fam, "local": row["local"],
                                  "remote": row["remote"], "state": row["state"]})
                socks.append(entry)
        scanned += 1
        if socks:
            pid_map.append({"pid": int(pid), "comm": comm, "sockets": socks})
    r["ok"] = True
    r["pids_scanned"] = scanned
    r["processes_with_sockets"] = len(pid_map)
    r["table"] = pid_map[: int(args.get("limit", 100))]
    return r


def nm20_net_arp_table(args):
    """Dump the real kernel ARP cache from /proc/net/arp."""
    r = _base("arp_table")
    entries = []
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]
        for ln in lines:
            p = ln.split()
            if len(p) >= 6:
                entries.append({"ip": p[0], "hw_type": p[1], "flags": p[2],
                                "mac": p[3], "mask": p[4], "device": p[5]})
        r["ok"] = True
    except OSError as e:
        r["error"] = str(e)
    r["count"] = len(entries)
    r["entries"] = entries
    return r


def nm20_net_route_table(args):
    """Dump IPv4 routes from /proc/net/route (and IPv6 from /proc/net/ipv6_route)."""
    r = _base("route_table")
    v4 = []
    try:
        with open("/proc/net/route") as f:
            hdr = f.readline().split()
            for ln in f:
                p = ln.split()
                if len(p) < len(hdr):
                    continue
                row = dict(zip(hdr, p))
                try:
                    row["Destination"] = _hex_ip(row["Destination"])
                    row["Gateway"] = _hex_ip(row["Gateway"])
                    row["Mask"] = _hex_ip(row["Mask"])
                    row["Flags"] = hex(int(row["Flags"], 16))
                    row["Metric"] = int(row["Metric"])
                except (ValueError, KeyError):
                    pass
                v4.append(row)
    except OSError as e:
        r["v4_error"] = str(e)
    v6 = []
    try:
        with open("/proc/net/ipv6_route") as f:
            for ln in f:
                p = ln.split()
                if len(p) >= 10:
                    dst = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(p[0]))
                    nh = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(p[4]))
                    v6.append({"dest": "%s/%d" % (dst, int(p[1], 16)),
                               "next_hop": nh, "metric": int(p[5], 16),
                               "flags": p[8], "iface": p[9]})
    except OSError as e:
        r["v6_error"] = str(e)
    r["ok"] = True
    r["ipv4"] = v4
    r["ipv6"] = v6[: int(args.get("limit", 100))]
    return r


def nm20_net_dns_resolver(args):
    """Resolve a host argument via real socket.getaddrinfo (A/AAAA/CNAME chain)."""
    r = _base("dns_resolver")
    host = args.get("host", "localhost")
    r["host"] = host
    try:
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
        seen = []
        for fam, _typ, _proto, canon, sa in infos:
            famname = {socket.AF_INET: "A", socket.AF_INET6: "AAAA"}.get(fam, str(fam))
            rec = {"type": famname, "addr": sa[0]}
            if canon:
                rec["canonname"] = canon
            if rec not in seen:
                seen.append(rec)
        r["ok"] = True
        r["records"] = seen
        try:
            r["fqdn"] = socket.getfqdn(host)
        except Exception:  # noqa: BLE001
            pass
    except socket.gaierror as e:
        r["error"] = "getaddrinfo: %s" % e
    return r


def nm20_net_port_check(args):
    """Real TCP connect to host:port with timeout; reports open/closed and latency."""
    r = _base("port_check")
    host = args.get("host", "127.0.0.1")
    port = int(args.get("port", 80))
    timeout = float(args.get("timeout", 3.0))
    r["target"] = "%s:%d" % (host, port)
    t0 = time.time()
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                      socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        r["ok"] = True
        r["open"] = True
        r["rtt_ms"] = round((time.time() - t0) * 1000.0, 3)
    except socket.timeout:
        r["ok"] = True
        r["open"] = False
        r["reason"] = "timeout (filtered?)"
    except OSError as e:
        r["ok"] = True
        r["open"] = False
        r["reason"] = str(e)
    finally:
        s.close()
    return r


def nm20_net_banner_grab(args):
    """Connect to host:port and read the real service banner (optional probe payload)."""
    r = _base("banner_grab")
    host = args.get("host", "127.0.0.1")
    port = int(args.get("port", 22))
    timeout = float(args.get("timeout", 4.0))
    probe = args.get("probe")  # optional string to send first, e.g. HTTP request
    r["target"] = "%s:%d" % (host, port)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                      socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if probe:
            s.sendall(probe.encode() if isinstance(probe, str) else probe)
        data = s.recv(1024)
        r["ok"] = True
        r["banner"] = data.decode("utf-8", "replace")
        r["bytes"] = len(data)
    except socket.timeout:
        r["error"] = "timeout waiting for banner"
    except OSError as e:
        r["error"] = str(e)
    finally:
        s.close()
    return r


def nm20_net_http_probe(args):
    """Real HTTP(S) HEAD/GET via urllib; reports status line, headers, body sample."""
    r = _base("http_probe")
    url = args.get("url", "http://127.0.0.1/")
    method = args.get("method", "GET").upper()
    timeout = float(args.get("timeout", 5.0))
    r["url"] = url
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": "nm20-http-probe/1.0"})
    try:
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = b""
            if method == "GET":
                body = resp.read(4096)
            r["ok"] = True
            r["status"] = resp.status
            r["reason"] = resp.reason
            r["headers"] = dict(resp.headers.items())
            r["elapsed_ms"] = round((time.time() - t0) * 1000.0, 3)
            r["body_bytes_read"] = len(body)
            r["body_sample"] = body[:512].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        r["ok"] = True  # reached the server; non-2xx is still a real answer
        r["status"] = e.code
        r["reason"] = e.reason
        r["headers"] = dict(e.headers.items()) if e.headers else {}
    except (urllib.error.URLError, OSError, ValueError) as e:
        r["error"] = str(e)
    return r


def nm20_net_tls_inspect(args):
    """Do a real TLS handshake to host:port and dump the peer cert chain details."""
    r = _base("tls_inspect")
    host = args.get("host", "localhost")
    port = int(args.get("port", 443))
    timeout = float(args.get("timeout", 6.0))
    r["target"] = "%s:%d" % (host, port)
    import ssl
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                r["ok"] = True
                r["tls_version"] = tls.version()
                r["cipher"] = {"name": cipher[0], "protocol": cipher[1],
                               "secret_bits": cipher[2]} if cipher else None
                r["cert"] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "serial": cert.get("serialNumber"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName", []),
                }
                der = tls.getpeercert(binary_form=True)
                if der:
                    r["cert_der_bytes"] = len(der)
    except ssl.SSLError as e:
        r["error"] = "TLS: %s" % e
    except (OSError, socket.timeout) as e:
        r["error"] = str(e)
    return r


def nm20_net_pcap_parser(args):
    """Parse a real pcap file global header and per-packet records (minimal, stdlib)."""
    r = _base("pcap_parser")
    path = args.get("path")
    limit = int(args.get("limit", 50))
    if not path:
        r["error"] = "missing arg: path"
        return r
    r["path"] = path
    magics = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
              b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    linktypes = {0: "NULL", 1: "ETHERNET", 6: "IEEE802_5", 7: "ARCNET",
                 9: "PPP", 101: "RAW_IP", 105: "IEEE802_11", 113: "LINUX_SLL",
                 276: "LINUX_SLL2"}
    try:
        with open(path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                r["error"] = "file too short for pcap global header"
                return r
            magic = gh[:4]
            if magic not in magics:
                r["error"] = "bad magic %s (not classic pcap)" % magic.hex()
                return r
            endian, ts_res = magics[magic]
            vmaj, vmin, _tz, _sig, snaplen, network = struct.unpack(
                endian + "HHiiii", gh[4:24])
            r["global_header"] = {
                "magic": magic.hex(), "version": "%d.%d" % (vmaj, vmin),
                "snaplen": snaplen,
                "linktype": linktypes.get(network, "UNKNOWN(%d)" % network),
                "endian": "little" if endian == "<" else "big",
                "ts_resolution": "nanosecond" if ts_res == 1e-9 else "microsecond",
            }
            pkts = []
            total = 0
            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", ph)
                data = f.read(incl)
                if len(data) < incl:
                    break
                total += 1
                if len(pkts) < limit:
                    pkts.append({"index": total, "ts": ts_sec + ts_frac * ts_res,
                                 "len": incl,
                                 "first16": data[:16].hex()})
            r["ok"] = True
            r["packet_count"] = total
            r["packets"] = pkts
            r["truncated"] = total > limit
    except OSError as e:
        r["error"] = str(e)
    return r


_SUBNET_SWEEP_SRC = '''#!/usr/bin/env python3
"""nm20 async subnet TCP sweep — generated by nm20.net.subnet_sweep_gen.
Usage: python3 nm20_subnet_sweep.py <cidr> [ports comma-list] [concurrency]
"""
import asyncio, ipaddress, sys

async def probe(ip, port, timeout=1.5):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout)
        w.close()
        return (str(ip), port, True)
    except Exception:
        return (str(ip), port, False)

async def main():
    net = ipaddress.ip_network(sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24", strict=False)
    ports = [int(p) for p in (sys.argv[2].split(",") if len(sys.argv) > 2 else ["22", "80", "443"])]
    conc = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    sem = asyncio.Semaphore(conc)
    async def guarded(ip, p):
        async with sem:
            return await probe(ip, p)
    tasks = [guarded(ip, p) for ip in net.hosts() for p in ports]
    for coro in asyncio.as_completed(tasks):
        ip, port, up = await coro
        if up:
            print("OPEN %s:%d" % (ip, port), flush=True)

if __name__ == "__main__":
    asyncio.run(main())
'''

_RAW_SYN_SRC = r'''/* nm20 raw SYN sender — generated by nm20.net.raw_syn_gen
 * Build: gcc -O2 -o nm20_raw_syn nm20_raw_syn.c
 * Run (root): ./nm20_raw_syn <dst_ip> <dst_port> [count]
 * Uses IP_HDRINCL raw sockets: real SYNs on the wire, hand-built headers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

static unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (int i = 0; i < nwords; i++) sum += buf[i];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)~sum;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dst_ip> <dst_port> [count]\n", argv[0]); return 1; }
    const char *dst = argv[1];
    int dport = atoi(argv[2]);
    int count = argc > 3 ? atoi(argv[3]) : 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { perror("socket (need root)"); return 1; }
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *ip = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst);
    for (int i = 0; i < count; i++) {
        memset(pkt, 0, sizeof(pkt));
        ip->ihl = 5; ip->version = 4; ip->tos = 0;
        ip->tot_len = htons(sizeof(pkt));
        ip->id = htons(rand() & 0xffff);
        ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->saddr = 0; /* kernel fills if 0 */
        ip->daddr = sin.sin_addr.s_addr;
        tcp->source = htons(40000 + (rand() % 20000));
        tcp->dest = htons(dport);
        tcp->seq = htonl(rand());
        tcp->doff = 5; tcp->syn = 1; tcp->window = htons(5840);
        tcp->check = 0; /* note: pseudo-header csum left as exercise / kernel assist */
        ip->check = csum((unsigned short *)pkt, ip->ihl * 2);
        if (sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            perror("sendto");
        else
            printf("SYN %d -> %s:%d sent\n", i + 1, dst, dport);
    }
    close(s);
    return 0;
}
'''

_WS_PROBE_SRC = '''#!/usr/bin/env python3
"""nm20 pure-stdlib WebSocket probe — generated by nm20.net.websocket_probe_gen.
Usage: python3 nm20_ws_probe.py ws://host:port/path "message"
"""
import base64, os, socket, sys, urllib.parse

def run(url, msg):
    u = urllib.parse.urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    s = socket.create_connection((host, port), timeout=5)
    if u.scheme == "wss":
        import ssl
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET %s HTTP/1.1\\r\\nHost: %s:%d\\r\\nUpgrade: websocket\\r\\n"
           "Connection: Upgrade\\r\\nSec-WebSocket-Key: %s\\r\\n"
           "Sec-WebSocket-Version: 13\\r\\n\\r\\n") % (path, host, port, key)
    s.sendall(req.encode())
    resp = s.recv(4096)
    status = resp.split(b"\\r\\n", 1)[0].decode("latin1")
    print("HANDSHAKE:", status)
    if b"101" not in resp.split(b"\\r\\n", 1)[0]:
        print(resp.decode("latin1", "replace")); return 1
    payload = msg.encode()
    mask = os.urandom(4)
    hdr = bytearray([0x81])
    n = len(payload)
    if n < 126: hdr.append(0x80 | n)
    elif n < 65536: hdr += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else: hdr += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    s.sendall(bytes(hdr) + mask + masked)
    r = s.recv(65536)
    if len(r) >= 2:
        plen = r[1] & 0x7f
        off = 2 + (2 if plen == 126 else 8 if plen == 127 else 0)
        print("RECV opcode=%d:" % (r[0] & 0x0f), r[off:].decode("utf-8", "replace"))
    s.close()
    return 0

if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:80/ws",
                 sys.argv[2] if len(sys.argv) > 2 else "ping"))
'''

_SOCKS5_SRC = '''#!/usr/bin/env python3
"""nm20 single-file SOCKS5 server — generated by nm20.net.socks_pivot_gen.
Usage: python3 nm20_socks5.py [bind] [port]   (no-auth, CONNECT only)
"""
import select, socket, struct, sys, threading

def handle(client):
    try:
        ver, nmethods = client.recv(1)[0], client.recv(1)[0]
        methods = client.recv(nmethods)
        if ver != 5 or 0 not in methods:
            client.sendall(b"\\x05\\xff"); return
        client.sendall(b"\\x05\\x00")
        hdr = client.recv(4)
        ver, cmd, _rsv, atyp = hdr
        if cmd != 1:
            client.sendall(b"\\x05\\x07\\x00\\x01" + b"\\x00" * 6); return
        if atyp == 1:
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:
            addr = client.recv(client.recv(1)[0]).decode()
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            return
        port = struct.unpack(">H", client.recv(2))[0]
        try:
            remote = socket.create_connection((addr, port), timeout=10)
        except OSError:
            client.sendall(b"\\x05\\x05\\x00\\x01" + b"\\x00" * 6); return
        client.sendall(b"\\x05\\x00\\x00\\x01" + b"\\x00" * 6)
        socks = [client, remote]
        while True:
            rd, _, _ = select.select(socks, [], [], 60)
            if not rd: break
            for s in rd:
                data = s.recv(65536)
                if not data: return
                (remote if s is client else client).sendall(data)
    finally:
        client.close()

def main():
    bind = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port)); srv.listen(64)
    print("nm20 SOCKS5 listening on %s:%d" % (bind, port))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
'''

_UDP_FLOOD_SRC = r'''/* nm20 UDP flood tool — generated by nm20.net.udp_flood_gen (ARTIFACT ONLY).
 * Build: gcc -O2 -o nm20_udp_flood nm20_udp_flood.c
 * Run: ./nm20_udp_flood <dst_ip> <dst_port> <pps> <seconds>
 * Lab/stress-test use only. Rate-limited to <pps> packets/sec.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s <ip> <port> <pps> <secs>\n", argv[0]); return 1; }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    sin.sin_port = htons(atoi(argv[2]));
    long pps = atol(argv[3]), secs = atol(argv[4]);
    char buf[512];
    memset(buf, 0x41, sizeof(buf));
    struct timespec tick = {0, 1000000000L / (pps > 0 ? pps : 1)};
    for (long t = 0; t < secs * pps; t++) {
        sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&sin, sizeof(sin));
        nanosleep(&tick, NULL);
    }
    printf("sent %ld datagrams to %s:%s\n", secs * pps, argv[1], argv[2]);
    close(s);
    return 0;
}
'''


def _write_artifact(name, src):
    path = os.path.join(TMPDIR, name)
    with open(path, "w") as f:
        f.write(src)
    return path


def nm20_net_subnet_sweep_gen(args):
    """Generate a real asyncio subnet TCP-sweep scanner script into /tmp."""
    r = _base("subnet_sweep_gen")
    name = args.get("name", "nm20_subnet_sweep.py")
    path = _write_artifact(name, _SUBNET_SWEEP_SRC)
    r["ok"] = True
    r["artifact"] = path
    r["bytes"] = os.path.getsize(path)
    r["usage"] = "python3 %s <cidr> [ports] [concurrency]" % path
    return r


def nm20_net_raw_syn_gen(args):
    """Generate real raw-socket SYN-sender C source into /tmp (arm=true to compile)."""
    r = _base("raw_syn_gen")
    arm = bool(args.get("arm", True))
    name = args.get("name", "nm20_raw_syn.c")
    path = _write_artifact(name, _RAW_SYN_SRC)
    r["ok"] = True
    r["artifact"] = path
    r["bytes"] = os.path.getsize(path)
    r["armed"] = arm
    r["note"] = "raw sockets need root; receiver sees hand-built SYNs"
    if arm:
        exe = path[:-2]
        rc, out, err = _run(["gcc", "-O2", "-o", exe, path], timeout=30)
        r["compile_rc"] = rc
        r["compiled"] = rc == 0
        r["compiler_output"] = (out + err).strip()
        if rc == 0:
            r["binary"] = exe
    else:
        r["would_do"] = "arm=true compiles with gcc; run as root to send real SYNs"
    return r


def nm20_net_websocket_probe_gen(args):
    """Generate a real pure-stdlib WebSocket handshake/message probe script."""
    r = _base("websocket_probe_gen")
    name = args.get("name", "nm20_ws_probe.py")
    path = _write_artifact(name, _WS_PROBE_SRC)
    r["ok"] = True
    r["artifact"] = path
    r["bytes"] = os.path.getsize(path)
    r["usage"] = "python3 %s ws://host:port/path 'message'" % path
    return r


def nm20_net_socks_pivot_gen(args):
    """Generate a real single-file SOCKS5 pivot server script into /tmp."""
    r = _base("socks_pivot_gen")
    name = args.get("name", "nm20_socks5.py")
    path = _write_artifact(name, _SOCKS5_SRC)
    r["ok"] = True
    r["artifact"] = path
    r["bytes"] = os.path.getsize(path)
    r["usage"] = "python3 %s [bind] [port]  # no-auth SOCKS5, CONNECT only" % path
    return r


def nm20_net_udp_flood_gen(args):
    """Generate a rate-limited UDP flood C source artifact (never executed here)."""
    r = _base("udp_flood_gen")
    name = args.get("name", "nm20_udp_flood.c")
    path = _write_artifact(name, _UDP_FLOOD_SRC)
    r["ok"] = True
    r["artifact"] = path
    r["bytes"] = os.path.getsize(path)
    r["note"] = "artifact only; lab stress-testing use; compile with gcc"
    r["would_do"] = "sends <pps> UDP datagrams/sec for <secs> seconds when run"
    return r


def nm20_net_port_forwarder(args):
    """Real userland TCP forwarder, time-boxed; binds 127.0.0.1 unless arm=true."""
    r = _base("port_forwarder")
    import select
    listen_host = args.get("listen_host", "127.0.0.1")
    listen_port = int(args.get("listen_port", 18080))
    target_host = args.get("target_host", "127.0.0.1")
    target_port = int(args.get("target_port", 80))
    seconds = min(float(args.get("seconds", 3.0)), 30.0)
    arm = bool(args.get("arm", True))
    if listen_host != "127.0.0.1" and not arm:
        r["error"] = "refusing to bind non-loopback without arm=true"
        r["would_do"] = "bind %s:%d -> %s:%d for %.1fs" % (
            listen_host, listen_port, target_host, target_port, seconds)
        return r
    r["forward"] = "%s:%d -> %s:%d" % (listen_host, listen_port, target_host, target_port)
    r["seconds"] = seconds
    stats = {"accepted": 0, "completed": 0, "errors": 0, "bytes": 0}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((listen_host, listen_port))
        srv.listen(16)
        srv.setblocking(False)
    except OSError as e:
        r["error"] = "bind/listen: %s" % e
        srv.close()
        return r
    deadline = time.time() + seconds
    pairs = {}  # client_sock -> upstream_sock
    try:
        while time.time() < deadline:
            rd, _, _ = select.select([srv] + list(pairs) + list(pairs.values()),
                                     [], [], max(0.0, deadline - time.time()))
            if not rd:
                break
            for s in rd:
                if s is srv:
                    try:
                        c, _addr = srv.accept()
                        up = socket.create_connection((target_host, target_port),
                                                      timeout=3)
                        pairs[c] = up
                        stats["accepted"] += 1
                    except OSError:
                        stats["errors"] += 1
                    continue
                try:
                    data = s.recv(65536)
                except OSError:
                    data = b""
                peer = pairs.get(s)
                if peer is None:
                    # s is an upstream; find its client
                    for k, v in pairs.items():
                        if v is s:
                            peer = k
                            break
                    if peer is None:
                        continue
                    if data:
                        try:
                            peer.sendall(data)
                            stats["bytes"] += len(data)
                        except OSError:
                            stats["errors"] += 1
                    else:
                        peer.close(); s.close(); del pairs[peer]
                        stats["completed"] += 1
                else:
                    if data:
                        try:
                            peer.sendall(data)
                            stats["bytes"] += len(data)
                        except OSError:
                            stats["errors"] += 1
                    else:
                        peer.close(); s.close(); del pairs[s]
                        stats["completed"] += 1
    finally:
        for c, u in pairs.items():
            c.close(); u.close()
        srv.close()
    r["ok"] = True
    r["stats"] = stats
    return r


def nm20_net_icmp_echo(args):
    """Send one real ICMP echo to a host (raw socket if root, ping-socket else)."""
    r = _base("icmp_echo")
    host = args.get("host", "127.0.0.1")
    timeout = float(args.get("timeout", 2.0))
    r["host"] = host
    r["euid"] = os.geteuid() if hasattr(os, "geteuid") else None

    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    try:
        dst = socket.gethostbyname(host)
    except socket.gaierror as e:
        r["error"] = "resolve: %s" % e
        return r
    r["dst_ip"] = dst
    ident = (os.getpid() ^ 0xBEEF) & 0xFFFF
    seq = 1
    payload = b"nm20-echo-payload"
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    cksum = _checksum(hdr + payload)
    pkt = struct.pack("!BBHHH", 8, 0, cksum, ident, seq) + payload
    s = None
    try:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            r["mode"] = "raw"
        except PermissionError:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            r["mode"] = "ping-dgram"
            # dgram ping socket: kernel adds ident; send without our own id trick
            pkt = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
            pkt = pkt[:2] + struct.pack("!H", _checksum(pkt)) + pkt[4:]
        s.settimeout(timeout)
        t0 = time.time()
        s.sendto(pkt, (dst, 0))
        while True:
            data, addr = s.recvfrom(1024)
            rtt = (time.time() - t0) * 1000.0
            if r["mode"] == "raw":
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 8:
                    continue
                typ, _code, _cs, rid, _sq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
            else:
                typ, _code, _cs, rid, _sq = struct.unpack("!BBHHH", data[:8])
            if typ == 0 and (r["mode"] != "raw" or rid == ident):
                r["ok"] = True
                r["reply_from"] = addr[0]
                r["rtt_ms"] = round(rtt, 3)
                if r["mode"] == "raw":
                    r["ttl"] = data[8]
                break
    except socket.timeout:
        r["error"] = "no reply within %.1fs" % timeout
    except PermissionError:
        r["error"] = "permission denied: raw and ping sockets both unavailable (need root or ping_group_range)"
    except OSError as e:
        r["error"] = str(e)
    finally:
        if s:
            s.close()
    return r


def nm20_net_netns_lister(args):
    """List real network namespaces via /var/run/netns and `ip netns list` if present."""
    r = _base("netns_lister")
    entries = []
    d = "/var/run/netns"
    try:
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            st = os.stat(p)
            entries.append({"name": name, "path": p, "inode": st.st_ino})
        r["procfs_netns"] = entries
    except OSError as e:
        r["procfs_netns_error"] = str(e)
    rc, out, err = _run(["ip", "netns", "list"], timeout=5)
    r["ip_netns_available"] = rc == 0
    if rc == 0:
        r["ip_netns"] = [ln.strip() for ln in out.splitlines() if ln.strip()]
    else:
        r["ip_netns_error"] = err.strip() or "rc=%d" % rc
    # also count netns inode diversity across /proc/*/ns/net
    seen = {}
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                link = os.readlink("/proc/%s/ns/net" % pid)
            except OSError:
                continue
            seen.setdefault(link, []).append(int(pid))
    except OSError:
        pass
    r["netns_inodes_in_use"] = [
        {"ns": k, "pids": v[:10], "pid_count": len(v)} for k, v in seen.items()]
    r["ok"] = True
    return r


def nm20_net_iface_stats(args):
    """Dump real per-interface rx/tx byte/packet/error counters from /proc/net/dev."""
    r = _base("iface_stats")
    ifaces = {}
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]
        for ln in lines:
            name, _, rest = ln.partition(":")
            p = rest.split()
            if len(p) < 16:
                continue
            ifaces[name.strip()] = {
                "rx_bytes": int(p[0]), "rx_packets": int(p[1]),
                "rx_errs": int(p[2]), "rx_drop": int(p[3]),
                "tx_bytes": int(p[8]), "tx_packets": int(p[9]),
                "tx_errs": int(p[10]), "tx_drop": int(p[11]),
            }
        r["ok"] = True
    except OSError as e:
        r["error"] = str(e)
    r["interfaces"] = ifaces
    r["count"] = len(ifaces)
    return r


def nm20_net_arp_watch(args):
    """One-shot ARP cache diff: sample /proc/net/arp twice and report churn."""
    r = _base("arp_watch")
    interval = min(float(args.get("interval", 1.0)), 10.0)

    def _snap():
        out = {}
        try:
            with open("/proc/net/arp") as f:
                for ln in f.readlines()[1:]:
                    p = ln.split()
                    if len(p) >= 6 and p[3] != "00:00:00:00:00:00":
                        out[p[0]] = (p[3], p[5])
        except OSError:
            pass
        return out

    a = _snap()
    time.sleep(interval)
    b = _snap()
    added = {ip: mac for ip, mac in b.items() if ip not in a}
    removed = {ip: mac for ip, mac in a.items() if ip not in b}
    changed = {ip: {"old": a[ip], "new": b[ip]}
               for ip in a if ip in b and a[ip] != b[ip]}
    r["ok"] = True
    r["interval_s"] = interval
    r["before_count"] = len(a)
    r["after_count"] = len(b)
    r["added"] = [{"ip": k, "mac": v[0], "dev": v[1]} for k, v in added.items()]
    r["removed"] = [{"ip": k, "mac": v[0], "dev": v[1]} for k, v in removed.items()]
    r["changed"] = [{"ip": k, "old_mac": v["old"][0], "new_mac": v["new"][0],
                     "dev": v["new"][1]} for k, v in changed.items()]
    return r


def nm20_net_firewall_audit(args):
    """Read real firewall rules: nft list ruleset / iptables-save, or report denial."""
    r = _base("firewall_audit")
    rc, out, err = _run(["nft", "list", "ruleset"], timeout=10)
    if rc == 0:
        r["ok"] = True
        r["backend"] = "nftables"
        r["ruleset"] = out
        r["rule_lines"] = len(out.splitlines())
        return r
    r["nft_error"] = (err.strip() or "rc=%d" % rc)[:300]
    rc, out, err = _run(["iptables-save"], timeout=10)
    if rc == 0:
        r["ok"] = True
        r["backend"] = "iptables"
        r["ruleset"] = out
        r["rule_lines"] = len(out.splitlines())
        return r
    r["iptables_error"] = (err.strip() or "rc=%d" % rc)[:300]
    r["error"] = "no readable firewall ruleset (need CAP_NET_ADMIN/root or tools missing)"
    return r


POWERS = {
    "nm20.net.netstat_dump": nm20_net_netstat_dump,
    "nm20.net.conn_table": nm20_net_conn_table,
    "nm20.net.arp_table": nm20_net_arp_table,
    "nm20.net.route_table": nm20_net_route_table,
    "nm20.net.dns_resolver": nm20_net_dns_resolver,
    "nm20.net.port_check": nm20_net_port_check,
    "nm20.net.banner_grab": nm20_net_banner_grab,
    "nm20.net.http_probe": nm20_net_http_probe,
    "nm20.net.tls_inspect": nm20_net_tls_inspect,
    "nm20.net.pcap_parser": nm20_net_pcap_parser,
    "nm20.net.subnet_sweep_gen": nm20_net_subnet_sweep_gen,
    "nm20.net.raw_syn_gen": nm20_net_raw_syn_gen,
    "nm20.net.websocket_probe_gen": nm20_net_websocket_probe_gen,
    "nm20.net.socks_pivot_gen": nm20_net_socks_pivot_gen,
    "nm20.net.port_forwarder": nm20_net_port_forwarder,
    "nm20.net.udp_flood_gen": nm20_net_udp_flood_gen,
    "nm20.net.icmp_echo": nm20_net_icmp_echo,
    "nm20.net.netns_lister": nm20_net_netns_lister,
    "nm20.net.iface_stats": nm20_net_iface_stats,
    "nm20.net.arp_watch": nm20_net_arp_watch,
    "nm20.net.firewall_audit": nm20_net_firewall_audit,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.net.iface_stats"]({}), indent=2, default=str))
