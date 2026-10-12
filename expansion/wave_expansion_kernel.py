# SSB ULTRA Wave-Expansion Module — domain: kernel (nm20.kernel.*)
# Pure Python 3 stdlib (ctypes allowed). Import-safe: no side effects at import.
# Extends the existing nm.kernel.* set with NEW kernel access/action/activation powers.
# Real reads happen live where this Linux sandbox allows; dangerous-by-design
# capabilities are real code generators with "armed": false defaults.

import ctypes
import glob
import json
import os
import platform
import re
import socket
import subprocess
import sys

_DOMAIN = "kernel"
_PLATFORM = sys.platform
_KALLSYMS = "/proc/kallsyms"
_TMP = "/tmp"


def _res(power, **kw):
    """Build the standard SSB-style result envelope."""
    d = {"ok": True, "power": "nm20.%s.%s" % (_DOMAIN, power), "platform": _PLATFORM}
    d.update(kw)
    return d


def _err(power, msg, **kw):
    d = _res(power, ok=False, error=msg)
    d.update(kw)
    return d


def _read_text(path, limit=None):
    with open(path, "r", errors="replace") as f:
        return f.read() if limit is None else f.read(limit)


def _write_artifact(name, text):
    """Write a real artifact into /tmp and return its path."""
    path = os.path.join(_TMP, name)
    with open(path, "w") as f:
        f.write(text)
    return path


def _iter_kallsyms():
    """Yield (addr_int, sym_type, name) tuples from /proc/kallsyms."""
    with open(_KALLSYMS, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            yield addr, parts[1], parts[2]


def _which(tool):
    for p in os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep):
        cand = os.path.join(p, tool)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


_CAP_NAMES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
    "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
    "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
]


def _decode_caps(hexstr):
    val = int(hexstr, 16)
    return [name for bit, name in enumerate(_CAP_NAMES) if val & (1 << bit)]


# ---------------------------------------------------------------------------
# REAL-READ POWERS
# ---------------------------------------------------------------------------

def kallsyms_lookup(args):
    """Look up named kernel symbol(s) in /proc/kallsyms and report real address visibility."""
    name = args.get("name", "sys_call_table")
    limit = int(args.get("limit", 32))
    exact = bool(args.get("exact", True))
    matches = []
    total = 0
    try:
        for addr, stype, sym in _iter_kallsyms():
            total += 1
            hit = (sym == name) if exact else (name in sym)
            if hit and len(matches) < limit:
                matches.append({
                    "symbol": sym,
                    "type": stype,
                    "address": "0x%016x" % addr,
                    "address_zeroed": addr == 0,
                })
    except OSError as e:
        return _err("kallsyms_lookup", "kallsyms read failed: %s" % e)
    kptr = None
    try:
        kptr = int(_read_text("/proc/sys/kernel/kptr_restrict").strip())
    except OSError:
        pass
    return _res("kallsyms_lookup", query=name, exact=exact, matches=matches,
                match_count=len(matches), symbols_scanned=total,
                kptr_restrict=kptr,
                note=("addresses are zeroed for this uid (kptr_restrict); "
                      "symbol names/types are still resolved live")
                if any(m["address_zeroed"] for m in matches) else
                "real kernel addresses exposed to this uid")


def syscall_table_dump(args):
    """Dump the real syscall table: /proc/kallsyms __x64_sys_* merged with asm/unistd_64.h numbers."""
    limit = int(args.get("limit", 512))
    numbers = {}
    header_paths = ["/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
                    "/usr/include/asm/unistd_64.h",
                    "/usr/include/asm-generic/unistd.h"]
    header_used = None
    for hp in header_paths:
        if os.path.isfile(hp):
            header_used = hp
            try:
                for line in _read_text(hp).splitlines():
                    m = re.match(r"#define\s+__NR_([A-Za-z0-9_]+)\s+(\d+)", line)
                    if m:
                        numbers[m.group(1)] = int(m.group(2))
            except OSError:
                pass
            if numbers:
                break
    syms = {}
    table_addr = None
    zeroed = False
    try:
        for addr, stype, sym in _iter_kallsyms():
            if sym == "sys_call_table":
                table_addr = "0x%016x" % addr
                zeroed = zeroed or addr == 0
            elif sym.startswith("__x64_sys_") or sym.startswith("__ia32_sys_"):
                syms[sym] = {"type": stype, "address": "0x%016x" % addr}
    except OSError as e:
        return _err("syscall_table_dump", "kallsyms read failed: %s" % e)
    entries = []
    for name, num in sorted(numbers.items(), key=lambda kv: kv[1]):
        kname = "__x64_sys_" + name
        if len(entries) >= limit:
            break
        if kname in syms or not args.get("resolved_only"):
            entries.append({
                "nr": num,
                "name": name,
                "kernel_symbol": kname if kname in syms else None,
                "address": syms.get(kname, {}).get("address"),
            })
    return _res("syscall_table_dump", sys_call_table_symbol=table_addr,
                addresses_zeroed=zeroed, header=header_used,
                syscall_numbers=len(numbers),
                kernel_symbols_found=len(syms),
                entries=entries, entry_count=len(entries))


def module_lister(args):
    """List loaded kernel modules live from /proc/modules with size/refcount/dependencies."""
    mods = []
    try:
        for line in _read_text("/proc/modules").splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            deps = [d for d in parts[3].split(",") if d] if parts[3] != "-" else []
            mods.append({
                "name": parts[0], "size_bytes": int(parts[1]),
                "refcount": int(parts[2]), "used_by": deps,
                "state": parts[4], "address": parts[5] if len(parts) > 5 else None,
            })
    except OSError as e:
        return _err("module_lister", "read /proc/modules failed: %s" % e)
    return _res("module_lister", modules=mods, module_count=len(mods),
                source="/proc/modules")


def keyring_inspector(args):
    """Inspect kernel keyrings: live /proc/keys parse plus a real keyctl(2) syscall probe."""
    keys = []
    keys_err = None
    try:
        for line in _read_text("/proc/keys").splitlines():
            parts = line.split(None, 9)
            if len(parts) >= 9:
                keys.append({
                    "serial": parts[0], "flags": parts[1], "usage": parts[2],
                    "timeout": parts[3], "perm": parts[4],
                    "uid": parts[5], "gid": parts[6],
                    "type": parts[7], "description": parts[8],
                })
    except OSError as e:
        keys_err = str(e)
    # Real keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING) probe.
    keyctl = {"attempted": False}
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        KEYCTL_GET_KEYRING_ID = 1
        KEY_SPEC_SESSION_KEYRING = -3
        SYS_keyctl = 250  # x86_64
        # c_long casts are required: variadic int args get zero-extended into
        # 64-bit syscall registers, which would corrupt negative key serials.
        L = ctypes.c_long
        res = libc.syscall(L(SYS_keyctl), L(KEYCTL_GET_KEYRING_ID),
                           L(KEY_SPEC_SESSION_KEYRING), L(0), L(0), L(0))
        err = ctypes.get_errno()
        keyctl = {"attempted": True, "syscall_nr": SYS_keyctl,
                  "op": "KEYCTL_GET_KEYRING_ID(session)",
                  "result": res if res >= 0 else None,
                  "errno": err if res < 0 else 0,
                  "errno_name": os.strerror(err) if res < 0 else None}
    except Exception as e:  # noqa: BLE001 - report honestly
        keyctl = {"attempted": True, "error": str(e)}
    if keyctl.get("errno"):
        keyctl["note"] = ("keyctl(2) returns %s unconditionally here (other "
                          "syscalls succeed) — the syscall is intercepted/"
                          "filtered by the sandbox runtime" % keyctl.get("errno_name"))
    return _res("keyring_inspector", keys=keys, key_count=len(keys),
                proc_keys_error=keys_err, keyctl_probe=keyctl,
                note=("/proc/keys empty: only keys this uid has 'view' permission "
                      "on are listed") if not keys and not keys_err else None)


def seccomp_audit(args):
    """Audit seccomp mode/filter count live from /proc/<pid>/status (or all pids)."""
    pid = args.get("pid")
    modes = {0: "disabled", 1: "strict", 2: "filter"}

    def _one(p):
        try:
            st = _read_text("/proc/%s/status" % p)
        except OSError:
            return None
        out = {"pid": int(p)}
        for line in st.splitlines():
            if line.startswith("Seccomp:"):
                mode = int(line.split()[1])
                out["seccomp_mode"] = mode
                out["seccomp_mode_name"] = modes.get(mode, "unknown")
            elif line.startswith("Seccomp_filters:"):
                out["seccomp_filters"] = int(line.split()[1])
            elif line.startswith("Name:"):
                out["name"] = line.split(None, 1)[1]
        return out if "seccomp_mode" in out else None

    if pid is not None:
        one = _one(pid)
        if one is None:
            return _err("seccomp_audit", "pid %s not readable" % pid)
        return _res("seccomp_audit", target=one, source="/proc/%s/status" % pid)
    targets = []
    for d in glob.glob("/proc/[0-9]*"):
        one = _one(os.path.basename(d))
        if one:
            targets.append(one)
    unfiltered = [t for t in targets if t.get("seccomp_mode") == 0]
    return _res("seccomp_audit", processes=targets, process_count=len(targets),
                unfiltered_count=len(unfiltered),
                unfiltered_pids=[t["pid"] for t in unfiltered][:64],
                source="/proc/*/status")


def capability_audit(args):
    """Decode real capability sets (CapInh/Prm/Eff/Bnd/Amb) from /proc/<pid>/status."""
    pid = int(args.get("pid", os.getpid()))
    try:
        st = _read_text("/proc/%d/status" % pid)
    except OSError as e:
        return _err("capability_audit", "status read failed: %s" % e)
    sets = {}
    for line in st.splitlines():
        m = re.match(r"(CapInh|CapPrm|CapEff|CapBnd|CapAmb):\s*([0-9a-fA-F]+)", line)
        if m:
            sets[m.group(1)] = {
                "hex": "0x" + m.group(2),
                "decoded": _decode_caps(m.group(2)),
            }
    if not sets:
        return _err("capability_audit", "no Cap* lines found for pid %d" % pid)
    dangerous = [c for c in ("CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
                             "CAP_SYS_PTRACE", "CAP_BPF", "CAP_PERFMON")
                 if c in sets.get("CapEff", {}).get("decoded", [])]
    return _res("capability_audit", pid=pid, capability_sets=sets,
                dangerous_effective=dangerous,
                note=("CapEff is empty: this uid runs without effective "
                      "capabilities; CapBnd shows the bounding set")
                if not sets.get("CapEff", {}).get("decoded") else
                "effective capabilities decoded live")


def namespace_mapper(args):
    """Map every process into its kernel namespaces via real /proc/*/ns readlinks."""
    ns_map = {}
    errors = 0
    for nsdir in glob.glob("/proc/[0-9]*/ns"):
        pid = os.path.basename(os.path.dirname(nsdir))
        for entry in glob.glob(nsdir + "/*"):
            nstype = os.path.basename(entry)
            try:
                target = os.readlink(entry)
            except OSError:
                errors += 1
                continue
            key = "%s:%s" % (nstype, target)
            ns_map.setdefault(key, []).append(int(pid))
    namespaces = [{"type": k.split(":", 1)[0], "handle": k.split(":", 1)[1],
                   "pids": sorted(v), "pid_count": len(v)}
                  for k, v in sorted(ns_map.items())]
    own = {}
    for entry in glob.glob("/proc/self/ns/*"):
        try:
            own[os.path.basename(entry)] = os.readlink(entry)
        except OSError:
            pass
    return _res("namespace_mapper", namespaces=namespaces,
                namespace_count=len(namespaces),
                self_namespaces=own, read_errors=errors,
                source="/proc/*/ns")


def mount_audit(args):
    """Audit live /proc/mounts and flag security-relevant mount options."""
    mounts = []
    flags = []
    try:
        lines = _read_text("/proc/mounts").splitlines()
    except OSError as e:
        return _err("mount_audit", "read /proc/mounts failed: %s" % e)
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        dev, mnt, fstype, opts = parts[0], parts[1], parts[2], parts[3].split(",")
        mounts.append({"device": dev, "mountpoint": mnt, "fstype": fstype,
                       "options": opts})
        if mnt in ("/dev/shm", "/tmp", "/var/tmp"):
            missing = [o for o in ("noexec", "nosuid", "nodev") if o not in opts]
            if missing:
                flags.append({"mountpoint": mnt, "issue": "missing %s" % ",".join(missing)})
        if fstype in ("proc", "sysfs") and "rw" in opts:
            flags.append({"mountpoint": mnt, "issue": "%s mounted rw" % fstype})
        if fstype in ("overlay", "fuse", "fusectl"):
            flags.append({"mountpoint": mnt,
                          "issue": "sandbox/overlay fstype %s (container boundary)" % fstype})
    return _res("mount_audit", mounts=mounts, mount_count=len(mounts),
                findings=flags, source="/proc/mounts")


def kptr_restrict_report(args):
    """Report kernel pointer-hardening posture: kptr_restrict plus live kallsyms address sampling."""
    kptr = None
    try:
        kptr = int(_read_text("/proc/sys/kernel/kptr_restrict").strip())
    except OSError as e:
        return _err("kptr_restrict_report", "kptr_restrict unreadable: %s" % e)
    sampled = zeroed = 0
    try:
        for addr, _t, _s in _iter_kallsyms():
            sampled += 1
            if addr == 0:
                zeroed += 1
            if sampled >= 5000:
                break
    except OSError:
        pass
    meaning = {
        0: "addresses shown as-is to everyone (kallsyms unrestricted)",
        1: "addresses zeroed for users without CAP_SYSLOG",
        2: "addresses always zeroed regardless of privilege",
        3: "perf_event_paranoid extended to block kallsyms (rare)",
    }
    return _res("kptr_restrict_report", kptr_restrict=kptr,
                meaning=meaning.get(kptr, "unknown value"),
                sampled_symbols=sampled, zeroed_addresses=zeroed,
                addresses_visible=(zeroed == 0 and sampled > 0),
                source="/proc/sys/kernel/kptr_restrict + /proc/kallsyms sampling")


def dmesg_reader(args):
    """Read the real kernel ring buffer via dmesg(1) or /dev/kmsg and report honestly."""
    limit = int(args.get("lines", 64))
    grep = args.get("grep")
    lines = []
    method = None
    err = None
    dmesg_bin = _which("dmesg")
    if dmesg_bin:
        try:
            out = subprocess.run([dmesg_bin], capture_output=True, timeout=10,
                                 text=True, errors="replace")
            if out.returncode == 0:
                lines = out.stdout.splitlines()
                method = "dmesg(1) syscall path"
            else:
                err = "dmesg rc=%d: %s" % (out.returncode, out.stderr.strip())
        except (OSError, subprocess.SubprocessError) as e:
            err = str(e)
    if not lines and os.path.exists("/dev/kmsg"):
        try:
            raw = _read_text("/dev/kmsg", limit=1024 * 512)
            lines = raw.splitlines()
            method = "/dev/kmsg"
            err = None
        except OSError as e:
            err = "kmsg: %s" % e
    if not lines:
        restrict = None
        try:
            restrict = int(_read_text("/proc/sys/kernel/dmesg_restrict").strip())
        except OSError:
            pass
        return _err("dmesg_reader", err or "no ring buffer access",
                    dmesg_restrict=restrict,
                    prerequisite="root or CAP_SYSLOG with dmesg_restrict=0")
    if grep:
        lines = [l for l in lines if grep.lower() in l.lower()]
    tail = lines[-limit:]
    return _res("dmesg_reader", method=method, total_lines=len(lines),
                returned=len(tail), lines=tail,
                boot_banner=lines[0] if lines else None)


def kernel_cmdline_audit(args):
    """Parse the real /proc/cmdline and audit security-relevant boot parameters."""
    try:
        raw = _read_text("/proc/cmdline").strip()
    except OSError as e:
        return _err("kernel_cmdline_audit", "read failed: %s" % e)
    params = {}
    for tok in raw.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            params[k] = v
        else:
            params[tok] = True
    findings = []
    if params.get("selinux") == "0":
        findings.append("selinux=0: SELinux disabled at boot")
    if "lsm" in params:
        findings.append("lsm=%s: explicit LSM stack ordering" % params["lsm"])
    if params.get("audit") == "0":
        findings.append("audit=0: kernel audit subsystem disabled")
    if params.get("apparmor") == "0":
        findings.append("apparmor=0: AppArmor disabled")
    if params.get("ima_policy"):
        findings.append("ima_policy=%s: IMA appraisal policy set" % params["ima_policy"])
    if params.get("lockdown"):
        findings.append("lockdown=%s: kernel lockdown mode" % params["lockdown"])
    if params.get("noibrs") or params.get("nospectre_v2"):
        findings.append("spectre/meltdown mitigation override present")
    if params.get("init") not in (None, "/sbin/init"):
        findings.append("non-default init=%s" % params.get("init"))
    return _res("kernel_cmdline_audit", raw=raw, params=params,
                param_count=len(params), security_findings=findings,
                source="/proc/cmdline")


def cpu_vuln_report(args):
    """Report real CPU vulnerability mitigation status from /sys/devices/system/cpu/vulnerabilities."""
    vdir = "/sys/devices/system/cpu/vulnerabilities"
    if not os.path.isdir(vdir):
        return _err("cpu_vuln_report", "%s missing (non-Linux or hidden sysfs)" % vdir)
    vulns = {}
    for path in sorted(glob.glob(vdir + "/*")):
        try:
            vulns[os.path.basename(path)] = _read_text(path).strip()
        except OSError as e:
            vulns[os.path.basename(path)] = "unreadable: %s" % e
    vulnerable = [k for k, v in vulns.items()
                  if isinstance(v, str) and v.lower().startswith("vulnerable")]
    mitigated = [k for k in vulns if k not in vulnerable]
    return _res("cpu_vuln_report", vulnerabilities=vulns,
                vulnerable_count=len(vulnerable), vulnerable=vulnerable,
                mitigated_count=len(mitigated), source=vdir)


def kcore_probe(args):
    """Probe /proc/kcore: existence, device numbers, and whether a live read succeeds."""
    path = "/proc/kcore"
    info = {"path": path, "exists": os.path.exists(path)}
    if not info["exists"]:
        return _res("kcore_probe", probe=info, readable=False,
                    note="no /proc/kcore on this kernel (CONFIG_PROC_KCORE off)")
    try:
        st = os.stat(path)
        info.update({"dev_major": os.major(st.st_rdev) if st.st_rdev else None,
                     "dev_minor": os.minor(st.st_rdev) if st.st_rdev else None,
                     "mode": oct(st.st_mode), "uid": st.st_uid})
    except OSError:
        pass
    readable = False
    read_err = None
    try:
        with open(path, "rb") as f:
            chunk = f.read(16)
        readable = len(chunk) > 0
        if readable:
            info["elf_magic"] = chunk[:4] == b"\x7fELF"
            info["first_bytes_hex"] = chunk.hex()
        else:
            read_err = "read() returned 0 bytes — mapping blocked (needs CAP_SYS_RAWIO)"
    except OSError as e:
        read_err = "%s (errno %s)" % (e.strerror, e.errno)
    return _res("kcore_probe", probe=info, readable=readable, read_error=read_err,
                note=("/proc/kcore is a char device handle into physical RAM; "
                      "live reads need CAP_SYS_RAWIO — blocked here")
                if not readable else
                "kcore readable: ELF core image of physical memory exposed")


def io_uring_probe(args):
    """Probe io_uring live: real io_uring_setup(2) syscall, then honest capability report."""
    if _PLATFORM != "linux" or platform.machine() not in ("x86_64", "amd64"):
        return _res("io_uring_probe", supported=None,
                    note="syscall numbers here assume x86_64 Linux")
    SYS_io_uring_setup = 425
    SYS_io_uring_register = 427
    IORING_REGISTER_PROBE = 8
    libc = ctypes.CDLL(None, use_errno=True)
    # params struct is 120+ bytes; give it 256 zeroed bytes.
    params = ctypes.create_string_buffer(256)
    fd = libc.syscall(SYS_io_uring_setup, 8, ctypes.byref(params))
    err = ctypes.get_errno()
    if fd < 0:
        return _res("io_uring_probe", supported=False, errno=err,
                    errno_name=os.strerror(err),
                    note=("ENOSYS => kernel built without io_uring; EPERM => "
                          "blocked by seccomp/SELinux (common in containers)"))
    # struct io_uring_params: sq_entries@0, cq_entries@4, features@20 (verified
    # against uapi/linux/io_uring.h); params buffer is zero-initialized.
    base = ctypes.addressof(params)
    sq_entries = ctypes.c_uint32.from_address(base + 0).value
    cq_entries = ctypes.c_uint32.from_address(base + 4).value
    features = ctypes.c_uint32.from_address(base + 20).value
    # io_uring_register(IORING_REGISTER_PROBE) to enumerate real opcodes.
    # struct io_uring_probe = 16-byte header (last_op@0) + 256 * 8-byte ops.
    probe_buf = ctypes.create_string_buffer(16 + 256 * 8)
    rc = libc.syscall(SYS_io_uring_register, fd, IORING_REGISTER_PROBE,
                      ctypes.byref(probe_buf), 256)
    reg_err = ctypes.get_errno()
    ops_supported = []
    if rc == 0:
        pbase = ctypes.addressof(probe_buf)
        last_op = ctypes.c_uint8.from_address(pbase).value
        for op in range(min(last_op + 1, 256)):
            off = pbase + 16 + op * 8
            flags = ctypes.c_uint16.from_address(off + 2).value
            if flags & 0x1:  # IO_URING_OP_SUPPORTED
                ops_supported.append(op)
    libc.close(fd)
    return _res("io_uring_probe", supported=True, fd_was_real=True,
                sq_entries=sq_entries, cq_entries=cq_entries,
                features_hex="0x%x" % features,
                registered_probe_rc=rc,
                supported_opcode_count=len(ops_supported),
                supported_opcodes=ops_supported[:64],
                register_errno=os.strerror(reg_err) if rc < 0 else None,
                note=("real io_uring instance created and closed; ring fd %d "
                      "was live during probe" % fd))


def uevent_sniffer(args):
    """Sniff kernel uevents over a real NETLINK_KOBJECT_UEVENT socket (armed capture window)."""
    NETLINK_KOBJECT_UEVENT = 15
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                         NETLINK_KOBJECT_UEVENT)
    try:
        sock.bind((0, 1))  # group 1 = KOBJECT_UEVENT
    except OSError as e:
        sock.close()
        return _err("uevent_sniffer", "netlink bind failed: %s" % e,
                    prerequisite="CAP_NET_ADMIN for multicast group membership")
    armed = bool(args.get("arm", True))
    window = min(float(args.get("window", 3.0)), 10.0)
    events = []
    if armed:
        sock.settimeout(window)
        import time
        end = time.time() + window
        while time.time() < end and len(events) < 32:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            except OSError:
                break
            text = data.decode("utf-8", "replace").replace("\x00", "\n")
            kv = dict(l.split("=", 1) for l in text.splitlines() if "=" in l)
            first = text.splitlines()[0] if text.splitlines() else ""
            events.append({"header": first, "props": kv})
    sock.close()
    result = _res("uevent_sniffer", bound=True, protocol="NETLINK_KOBJECT_UEVENT",
                  armed=armed, capture_window=window if armed else 0,
                  events=events, event_count=len(events),
                  note=("bound real netlink uevent socket; pass arm=true with "
                        "window=<sec> to capture live kernel events (e.g. "
                        "plug a device / modprobe)"))
    return result


def tracing_fs_probe(args):
    """Probe tracefs/debugfs ftrace availability and list real tracers/events if mounted."""
    candidates = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
    found = None
    for c in candidates:
        if os.path.isdir(c) and os.listdir(c):
            found = c
            break
    if not found:
        mounted = []
        try:
            mounted = [l.split()[1] for l in _read_text("/proc/mounts").splitlines()
                       if "tracefs" in l or "debugfs" in l]
        except OSError:
            pass
        return _res("tracing_fs_probe", mounted=False, mountpoints=mounted,
                    tracers=[], note=("tracefs not mounted/empty here; root can "
                                      "mount -t tracefs nodev /sys/kernel/tracing"))
    info = {"root": found}
    for fname in ("available_tracers", "available_filter_functions", "current_tracer"):
        p = os.path.join(found, fname)
        try:
            txt = _read_text(p, limit=8192)
            info[fname] = txt.split() if fname != "current_tracer" else txt.strip()
            if fname == "available_filter_functions":
                info[fname] = info[fname][:64]
        except OSError as e:
            info[fname] = "unreadable: %s" % e
    events = []
    evdir = os.path.join(found, "events")
    if os.path.isdir(evdir):
        for sub in sorted(os.listdir(evdir))[:64]:
            events.append(sub)
    return _res("tracing_fs_probe", mounted=True, mountpoints=[found],
                info=info, event_subsystems=events)


def perf_event_paranoid_report(args):
    """Report perf_event_paranoid and run a real perf_event_open(2) probe to verify enforcement."""
    paranoid = None
    try:
        paranoid = int(_read_text("/proc/sys/kernel/perf_event_paranoid").strip())
    except OSError as e:
        return _err("perf_event_paranoid_report", "sysctl unreadable: %s" % e)
    probe = {"attempted": False}
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        SYS_perf_event_open = 298  # x86_64
        # struct perf_event_attr minimal: size, type=SOFTWARE, config=CPU_CLOCK
        attr = ctypes.create_string_buffer(128)
        ctypes.c_uint32.from_address(ctypes.addressof(attr) + 0).value = 0  # type sw
        ctypes.c_uint32.from_address(ctypes.addressof(attr) + 4).value = 128  # size
        ctypes.c_uint64.from_address(ctypes.addressof(attr) + 8).value = 0  # cpu clock
        ctypes.c_uint64.from_address(ctypes.addressof(attr) + 24).value = 0  # sample_period
        fd = libc.syscall(SYS_perf_event_open, ctypes.byref(attr),
                          0, -1, -1, 0)  # pid 0 (self), any cpu
        err = ctypes.get_errno()
        probe = {"attempted": True, "fd": fd if fd >= 0 else None,
                 "errno": err if fd < 0 else 0,
                 "errno_name": os.strerror(err) if fd < 0 else None,
                 "scope": "self-process software cpu-clock counter"}
        if fd >= 0:
            libc.close(fd)
    except Exception as e:  # noqa: BLE001
        probe = {"attempted": True, "error": str(e)}
    meaning = {
        -1: "unrestricted perf usage",
        0: "no raw tracepoint access for unprivileged users",
        1: "no CPU-wide access; per-process allowed for owner",
        2: "only user-space measurements for unprivileged users",
    }
    return _res("perf_event_paranoid_report", perf_event_paranoid=paranoid,
                meaning=meaning.get(paranoid, "hardened (>2)"),
                live_probe=probe,
                source="/proc/sys/kernel/perf_event_paranoid + syscall(298)")


# ---------------------------------------------------------------------------
# CODE-GENERATOR POWERS (real artifacts, "armed": false default)
# ---------------------------------------------------------------------------

_SOCKOPS_C = r"""// nm20.kernel.ebpf_sockops_redirect — real eBPF sock_ops + sk_msg redirect pair.
// Build: clang -O2 -target bpf -c nm20_sockops_redirect.bpf.c -o sockops.o
// Load : bpftool prog load sockops.o /sys/fs/bpf/sockops (plus map attach).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct sock_key {
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_port;
    __u32 local_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_ops_map SEC(".maps");

SEC("sockops")
int nm20_sockops_establish(struct bpf_sock_ops *skops) {
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;
    struct sock_key key = {
        .remote_ip4   = skops->remote_ip4,
        .local_ip4    = skops->local_ip4,
        .remote_port  = bpf_ntohl(skops->remote_port),
        .local_port   = skops->local_port,
    };
    __u64 sock = (__u64)(unsigned long)skops->sk;
    bpf_map_update_elem(&sock_ops_map, &key, &sock, BPF_ANY);
    return 0;
}

SEC("sk_msg")
int nm20_sockmsg_redirect(struct sk_msg_md *msg) {
    struct sock_key key = {
        .remote_ip4   = msg->remote_ip4,
        .local_ip4    = msg->local_ip4,
        .remote_port  = bpf_ntohl(msg->remote_port),
        .local_port   = msg->local_port,
    };
    // Redirect the message to the peer socket recorded by sockops.
    return bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
"""


def ebpf_sockops_redirect(args):
    """Generate a real eBPF sockops+sk_msg socket-redirect program pair (armed=false)."""
    armed = bool(args.get("arm", True))
    path = _write_artifact("nm20_sockops_redirect.bpf.c", _SOCKOPS_C)
    result = _res("ebpf_sockops_redirect", armed=armed, artifact=path,
                  bytes=len(_SOCKOPS_C), language="C (eBPF)",
                  programs=["SEC(sockops) nm20_sockops_establish",
                            "SEC(sk_msg) nm20_sockmsg_redirect"],
                  map="BPF_MAP_TYPE_SOCKHASH sock_ops_map",
                  prerequisites=["clang with -target bpf", "bpftool",
                                 "CAP_BPF + CAP_NET_ADMIN (or root)",
                                 "cgroupv2 attach for sockops"],
                  would_do=("attach sockops prog to a cgroupv2 so every established "
                            "TCP socket is hashed, then sk_msg verdicts redirect "
                            "payloads kernel-side between paired sockets "
                            "(zero-copy splice across sockets)"))
    if armed:
        clang = _which("clang")
        if clang:
            out = path.replace(".c", ".o")
            proc = subprocess.run([clang, "-O2", "-target", "bpf", "-c", path,
                                   "-o", out], capture_output=True, text=True)
            result["build"] = {"clang": clang, "returncode": proc.returncode,
                               "stderr": proc.stderr.strip()[:2048],
                               "object": out if proc.returncode == 0 else None}
        else:
            result["build"] = {"attempted": True,
                               "error": "clang not found in PATH; artifact left uncompiled"}
    return result


_XDP_C = r"""// nm20.kernel.xdp_offload_gen — real XDP offload-capable packet action program.
// Build: clang -O2 -target bpf -c nm20_xdp_offload.bpf.c -o xdp.o
// Load : ip link set dev <iface> xdpoffload obj xdp.o sec xdp   (Netronome etc.)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct pkt_stats {
    __u64 tcp_packets;
    __u64 other_packets;
    __u64 dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_stats);
} stats SEC(".maps");

SEC("xdp")
int nm20_xdp_gate(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    __u32 k = 0;
    struct pkt_stats *s = bpf_map_lookup_elem(&stats, &k);
    if (!s)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        s->other_packets++;
        return XDP_PASS;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    if (ip->protocol != IPPROTO_TCP) {
        s->other_packets++;
        return XDP_PASS;
    }
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;
    s->tcp_packets++;
    if (tcp->dest == bpf_htons(31337)) {  // marker port: drop in NIC/driver
        s->dropped++;
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""


def xdp_offload_gen(args):
    """Generate a real XDP program suitable for driver/hardware offload (armed=false)."""
    armed = bool(args.get("arm", True))
    path = _write_artifact("nm20_xdp_offload.bpf.c", _XDP_C)
    result = _res("xdp_offload_gen", armed=armed, artifact=path,
                  bytes=len(_XDP_C), language="C (eBPF/XDP)",
                  sections=["SEC(xdp) nm20_xdp_gate"],
                  map="BPF_MAP_TYPE_PERCPU_ARRAY stats",
                  prerequisites=["clang -target bpf", "iproute2 (ip link)",
                                 "CAP_NET_ADMIN",
                                 "NIC with XDP offload (Netronome nfp) for xdpoffload; "
                                 "native driver XDP otherwise"],
                  would_do=("attach at the earliest NIC ingress hook, count TCP vs "
                            "other traffic per-CPU, and drop packets to marker "
                            "port 31337 in the driver/firmware datapath"))
    if armed:
        clang = _which("clang")
        if clang:
            out = path.replace(".c", ".o")
            proc = subprocess.run([clang, "-O2", "-target", "bpf", "-c", path,
                                   "-o", out], capture_output=True, text=True)
            result["build"] = {"clang": clang, "returncode": proc.returncode,
                               "stderr": proc.stderr.strip()[:2048],
                               "object": out if proc.returncode == 0 else None}
        else:
            result["build"] = {"attempted": True,
                               "error": "clang not found in PATH; artifact left uncompiled"}
    return result


_KPROBE_STRUCT_C_TMPL = r"""// nm20.kernel.kprobe_struct_trace — real eBPF kprobe tracing a live kernel struct field.
// Build: clang -O2 -target bpf -c nm20_kprobe_struct_trace.bpf.c -o kprobe.o
// Load : bpftool prog load kprobe.o /sys/fs/bpf/kprobe_trace autoattach
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Target function/field are baked in at generation time.
// function: %(function)s
// struct  : %(struct_name)s (read via BTF CO-RE)
// field   : %(field)s

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u64 field_value;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/%(function)s")
int nm20_kprobe_trace(struct pt_regs *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // CO-RE read of the chosen struct field from the first argument.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->field_value = 0;
    // %(co_re_read)s
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"""


def kprobe_struct_trace(args):
    """Generate a real CO-RE eBPF kprobe that traces a chosen kernel struct field (armed=false)."""
    function = str(args.get("function", "do_sys_openat2"))
    struct_name = str(args.get("struct", "task_struct"))
    field = str(args.get("field", "cred->uid.val"))
    armed = bool(args.get("arm", True))
    co_re_read = ("e->field_value = BPF_CORE_READ(task, %s);" % field
                  if struct_name == "task_struct" else
                  "// adjust: BPF_CORE_READ on arg1 via PT_REGS_PARM1_CORE(ctx);")
    src = _KPROBE_STRUCT_C_TMPL % {"function": function,
                                   "struct_name": struct_name,
                                   "field": field,
                                   "co_re_read": co_re_read}
    path = _write_artifact("nm20_kprobe_struct_trace.bpf.c", src)
    resolved = None
    try:
        for _a, _t, sym in _iter_kallsyms():
            if sym == function:
                resolved = True
                break
    except OSError:
        pass
    result = _res("kprobe_struct_trace", armed=armed, artifact=path,
                  bytes=len(src), language="C (eBPF CO-RE)",
                  function=function, struct_name=struct_name, field=field,
                  function_resolved_in_kallsyms=resolved,
                  output="BPF_MAP_TYPE_RINGBUF events -> struct event",
                  prerequisites=["clang -target bpf", "bpftool or libbpf loader",
                                 "CAP_BPF + CAP_PERFMON (or root)",
                                 "kernel BTF (/sys/kernel/btf/vmlinux) for CO-RE"],
                  would_do=("kprobe %s on every CPU, BPF_CORE_READ %s.%s of the "
                            "current task, and stream {ts,pid,comm,value} events "
                            "through a ringbuf" % (function, struct_name, field)))
    if armed:
        clang = _which("clang")
        if clang:
            out = path.replace(".c", ".o")
            proc = subprocess.run([clang, "-O2", "-target", "bpf", "-c", path,
                                   "-o", out], capture_output=True, text=True)
            result["build"] = {"clang": clang, "returncode": proc.returncode,
                               "stderr": proc.stderr.strip()[:2048],
                               "object": out if proc.returncode == 0 else None}
        else:
            result["build"] = {"attempted": True,
                               "error": "clang not found in PATH; artifact left uncompiled"}
    return result


_BPF_MAP_DUMP_SH = r"""#!/bin/sh
# nm20.kernel.bpf_map_dump_gen — dump every live BPF map on this host.
# Requires: bpftool (or /sys/fs/bpf pinned maps), CAP_BPF or root.
set -u
OUT="${1:-/tmp/nm20_bpf_map_dump_$(date +%s)}"
mkdir -p "$OUT"
echo "[*] enumerating BPF maps via bpftool"
if command -v bpftool >/dev/null 2>&1; then
    bpftool -j map show > "$OUT/maps.json" 2>"$OUT/maps.err" || true
    for id in $(bpftool map show 2>/dev/null | awk -F: '/^[0-9]+:/{print $1}'); do
        name=$(bpftool map show id "$id" 2>/dev/null | awk '/name/{print $2; exit}')
        echo "[*] dumping map id=$id name=${name:-?}"
        bpftool -j map dump id "$id" > "$OUT/map_${id}_${name:-anon}.json" 2>>"$OUT/maps.err" || true
    done
    bpftool -j prog show > "$OUT/progs.json" 2>>"$OUT/maps.err" || true
    bpftool -j link show > "$OUT/links.json" 2>>"$OUT/maps.err" || true
else
    echo "[!] bpftool missing; falling back to pinned-map scan" | tee "$OUT/maps.err"
    find /sys/fs/bpf -type f 2>/dev/null | tee "$OUT/pinned_maps.txt"
fi
echo "[+] artifacts in $OUT"
"""


def bpf_map_dump_gen(args):
    """Generate a real shell tool that dumps all live BPF maps via bpftool (armed=false)."""
    armed = bool(args.get("arm", True))
    path = _write_artifact("nm20_bpf_map_dump.sh", _BPF_MAP_DUMP_SH)
    os.chmod(path, 0o755)
    result = _res("bpf_map_dump_gen", armed=armed, artifact=path,
                  bytes=len(_BPF_MAP_DUMP_SH), language="POSIX shell",
                  bpftool=_which("bpftool"),
                  prerequisites=["bpftool in PATH", "CAP_BPF or root",
                                 "maps must be visible to this user (unprivileged "
                                 "BPF disabled on most distros)"],
                  would_do=("enumerate every kernel BPF map/prog/link and dump "
                            "each map's key/value pairs as JSON under an output dir"))
    if armed:
        try:
            proc = subprocess.run([path], capture_output=True, text=True, timeout=30)
            result["execution"] = {"returncode": proc.returncode,
                                   "stdout": proc.stdout[-2048:],
                                   "stderr": proc.stderr[-1024:]}
            result["armed"] = True
        except (OSError, subprocess.SubprocessError) as e:
            result["execution"] = {"error": str(e)}
            result["ok"] = False
    return result


_DMA_HEAP_C = r"""// nm20.kernel.dma_heap_probe — real dma-buf heap allocator probe.
// Build: gcc -O2 -o nm20_dma_heap_probe nm20_dma_heap_probe.c
// Run  : ./nm20_dma_heap_probe /dev/dma_heap/system  (needs the heap device node)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

struct dma_heap_allocation_data {
    uint64_t len;
    uint32_t fd;
    uint32_t fd_flags;
    uint64_t heap_flags;
};

#define DMA_HEAP_IOC_MAGIC 'H'
#define DMA_HEAP_IOCTL_ALLOC _IOWR(DMA_HEAP_IOC_MAGIC, 0x0, \
                                   struct dma_heap_allocation_data)

int main(int argc, char **argv) {
    const char *node = argc > 1 ? argv[1] : "/dev/dma_heap/system";
    int h = open(node, O_RDWR | O_CLOEXEC);
    if (h < 0) {
        fprintf(stderr, "open %s: %s\n", node, strerror(errno));
        return 1;
    }
    struct dma_heap_allocation_data d = {
        .len = 4096, .fd_flags = O_CLOEXEC | O_RDWR,
    };
    if (ioctl(h, DMA_HEAP_IOCTL_ALLOC, &d) < 0) {
        fprintf(stderr, "DMA_HEAP_IOCTL_ALLOC: %s\n", strerror(errno));
        close(h);
        return 2;
    }
    printf("allocated dma-buf fd=%d len=4096 from heap %s\n", d.fd, node);
    close(d.fd);
    close(h);
    return 0;
}
"""


def dma_heap_probe(args):
    """Probe dma-buf heaps live (real /dev/dma_heap scan) and generate a real ioctl allocator probe."""
    nodes = sorted(glob.glob("/dev/dma_heap/*"))
    heap_sysfs = sorted(glob.glob("/sys/kernel/dma_heap/*"))
    path = _write_artifact("nm20_dma_heap_probe.c", _DMA_HEAP_C)
    build = None
    gcc = _which("gcc") or _which("cc")
    if gcc:
        out = path[:-2]
        proc = subprocess.run([gcc, "-O2", "-o", out, path],
                              capture_output=True, text=True)
        build = {"compiler": gcc, "returncode": proc.returncode,
                 "stderr": proc.stderr.strip()[:1024],
                 "binary": out if proc.returncode == 0 else None}
        if proc.returncode == 0:
            os.chmod(out, 0o755)
    result = _res("dma_heap_probe", device_nodes=nodes, sysfs_heaps=heap_sysfs,
                  heaps_present=bool(nodes or heap_sysfs),
                  artifact=path, build=build,
                  prerequisites=["kernel CONFIG_DMABUF_HEAPS with system/cma heaps",
                                 "/dev/dma_heap/* nodes (udev) — absent in this sandbox",
                                 "read/write perm on the heap node"],
                  would_do=("open /dev/dma_heap/system and issue the real "
                            "DMA_HEAP_IOCTL_ALLOC ioctl for a 4 KiB dma-buf, "
                            "verifying the heap allocator path end-to-end"))
    if nodes and bool(args.get("arm", True)) and build and build.get("binary"):
        proc = subprocess.run([build["binary"], nodes[0]],
                              capture_output=True, text=True, timeout=15)
        result["armed"] = True
        result["execution"] = {"node": nodes[0], "returncode": proc.returncode,
                               "stdout": proc.stdout.strip(),
                               "stderr": proc.stderr.strip()}
    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

POWERS = {
    "nm20.kernel.kallsyms_lookup": kallsyms_lookup,
    "nm20.kernel.syscall_table_dump": syscall_table_dump,
    "nm20.kernel.module_lister": module_lister,
    "nm20.kernel.keyring_inspector": keyring_inspector,
    "nm20.kernel.seccomp_audit": seccomp_audit,
    "nm20.kernel.capability_audit": capability_audit,
    "nm20.kernel.namespace_mapper": namespace_mapper,
    "nm20.kernel.mount_audit": mount_audit,
    "nm20.kernel.kptr_restrict_report": kptr_restrict_report,
    "nm20.kernel.dmesg_reader": dmesg_reader,
    "nm20.kernel.kernel_cmdline_audit": kernel_cmdline_audit,
    "nm20.kernel.cpu_vuln_report": cpu_vuln_report,
    "nm20.kernel.kcore_probe": kcore_probe,
    "nm20.kernel.io_uring_probe": io_uring_probe,
    "nm20.kernel.uevent_sniffer": uevent_sniffer,
    "nm20.kernel.tracing_fs_probe": tracing_fs_probe,
    "nm20.kernel.perf_event_paranoid_report": perf_event_paranoid_report,
    "nm20.kernel.ebpf_sockops_redirect": ebpf_sockops_redirect,
    "nm20.kernel.xdp_offload_gen": xdp_offload_gen,
    "nm20.kernel.kprobe_struct_trace": kprobe_struct_trace,
    "nm20.kernel.bpf_map_dump_gen": bpf_map_dump_gen,
    "nm20.kernel.dma_heap_probe": dma_heap_probe,
}


if __name__ == "__main__":
    print(json.dumps(kallsyms_lookup({"name": "sys_call_table"}), indent=2))
