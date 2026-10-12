"""SSB swarm-24 expansion: nm21.caps — Linux capability control.
All powers armed:true by default; real /proc, getcap/setcap, prctl data."""
import json, os, platform, re, subprocess, sys

CAP_NAMES = ["chown", "dac_override", "dac_read_search", "fowner", "fsetid",
             "kill", "setgid", "setuid", "setpcap", "linux_immutable",
             "net_bind_service", "net_broadcast", "net_admin", "net_raw",
             "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot",
             "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
             "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease",
             "audit_write", "audit_control", "setfcap", "mac_override",
             "mac_admin", "syslog", "wake_alarm", "block_suspend",
             "audit_read", "perfmon", "bpf", "checkpoint_restore"]

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

def _decode(mask_hex):
    try:
        mask = int(mask_hex, 16)
    except (ValueError, TypeError):
        return []
    return [CAP_NAMES[i] for i in range(min(len(CAP_NAMES), 41)) if mask & (1 << i)]


def proc_status_caps(args):
    """Decode real capability sets from /proc/<pid>/status."""
    pid = int(args.get("pid", os.getpid()))
    try:
        txt = open(f"/proc/{pid}/status", errors="replace").read()
    except OSError as e:
        return _err("proc_status_caps", e)
    caps = {}
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        m = re.search(rf"^{key}:\s*([0-9a-fA-F]+)", txt, re.M)
        if m:
            caps[key] = {"hex": m.group(1), "decoded": _decode(m.group(1))}
    m = re.search(r"^Seccomp:\s*(\d+)", txt, re.M)
    return _res("proc_status_caps", pid=pid, capabilities=caps,
                seccomp_mode=int(m.group(1)) if m else None)


def capability_decode(args):
    """Decode any capability hex mask or number into capability names."""
    val = str(args.get("mask", "0"))
    return _res("capability_decode", mask=val, capabilities=_decode(val),
                count=len(_decode(val)))


def getcap_scan(args):
    """Scan real filesystem for files with capabilities set (getcap -r)."""
    roots = args.get("roots") or ["/usr", "/bin", "/sbin", "/opt", "/usr/local"]
    hits = []
    for root in roots:
        rc, out, err = _run(["getcap", "-r", root], timeout=90)
        for line in out.splitlines():
            line = line.strip()
            if line:
                hits.append(line)
    return _res("getcap_scan", hits=hits[:500], count=len(hits))


def file_cap_grant(args):
    """Grant capabilities to a file via real setcap (armed)."""
    path, caps = str(args.get("path", "")), str(args.get("caps", ""))
    if not path or not caps:
        return _err("file_cap_grant", "need 'path' and 'caps' (e.g. cap_net_raw+ep)")
    if not _armed(args):
        return _res("file_cap_grant", armed=False, would_run=["setcap", caps, path])
    rc, out, err = _run(["setcap", caps, path])
    rc2, out2, _ = _run(["getcap", path])
    return _res("file_cap_grant", armed=True, applied=(rc == 0), path=path,
                caps=caps, stderr=err.strip(), verify=out2.strip())


def bounding_set_report(args):
    """Report the capability bounding set for this process (from /proc)."""
    pid = int(args.get("pid", os.getpid()))
    try:
        txt = open(f"/proc/{pid}/status", errors="replace").read()
        m = re.search(r"^CapBnd:\s*([0-9a-fA-F]+)", txt, re.M)
        bnd = _decode(m.group(1)) if m else []
        return _res("bounding_set_report", pid=pid, bounding=bnd, count=len(bnd))
    except OSError as e:
        return _err("bounding_set_report", e)


def ambient_report(args):
    """Report ambient capabilities (Linux 4.3+) for a process."""
    pid = int(args.get("pid", os.getpid()))
    try:
        txt = open(f"/proc/{pid}/status", errors="replace").read()
        m = re.search(r"^CapAmb:\s*([0-9a-fA-F]+)", txt, re.M)
        amb = _decode(m.group(1)) if m else []
        return _res("ambient_report", pid=pid, ambient=amb)
    except OSError as e:
        return _err("ambient_report", e)


def user_ns_cap_test(args):
    """Test capability availability by mapping a user namespace via real unshare."""
    rc, out, err = _run(["unshare", "--user", "--map-root-user", "--mount-proc",
                         "cat", "/proc/self/status"], timeout=20)
    caps = {}
    if rc == 0:
        for key in ("CapEff", "CapBnd"):
            m = re.search(rf"^{key}:\s*([0-9a-fA-F]+)", out, re.M)
            if m:
                caps[key] = _decode(m.group(1))
    return _res("user_ns_cap_test", userns_ok=(rc == 0), caps_in_userns=caps,
                stderr=err.strip()[:300])


def cap_eff_audit_all_procs(args):
    """Audit effective capabilities of every running process from /proc."""
    rows = []
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int)[:4096]:
        try:
            txt = open(f"/proc/{pid}/status", errors="replace").read()
            m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", txt, re.M)
            n = re.search(r"^Name:\s*(\S+)", txt, re.M)
            if m and m.group(1).strip("0"):
                rows.append({"pid": int(pid), "name": n.group(1) if n else "?",
                             "cap_eff": _decode(m.group(1))})
        except OSError:
            continue
    return _res("cap_eff_audit_all_procs", processes=rows[:400], count=len(rows))


def cap_to_name(args):
    """Map capability index numbers to names."""
    idx = args.get("index")
    if idx is None:
        return _res("cap_to_name", table=dict(enumerate(CAP_NAMES)))
    i = int(idx)
    return _res("cap_to_name", index=i, name=CAP_NAMES[i] if 0 <= i < len(CAP_NAMES) else None)


def priv_esc_cap_matrix(args):
    """Matrix of dangerous capabilities and the escalation each one enables."""
    matrix = {
        "cap_sys_admin": "mount, nsenter, setns — near-root equivalence",
        "cap_sys_ptrace": "ptrace any process — inject/cred theft",
        "cap_sys_module": "load kernel modules — full kernel control",
        "cap_dac_override": "read/write any file",
        "cap_dac_read_search": "read any file",
        "cap_setuid": "setuid(0) — become root",
        "cap_setgid": "setgid(0)",
        "cap_fowner": "chown any file — ownership takeover",
        "cap_setfcap": "grant file capabilities — bootstrap any cap",
        "cap_net_admin": "firewall/routing control, traffic redirect",
        "cap_net_raw": "raw sockets — sniffing/spoofing",
        "cap_sys_rawio": "iomem access — kernel memory read/write",
        "cap_sys_chroot": "chroot escape paths",
        "cap_mknod": "device node creation",
        "cap_audit_write": "write to audit log — forge audit records",
        "cap_mac_override": "bypass LSM MAC policy",
        "cap_sys_boot": "reboot/kexec",
        "cap_sys_nice": "raise priority, RT scheduling",
        "cap_bpf": "eBPF programs — kernel introspection/rootkits",
        "cap_checkpoint_restore": "restore arbitrary process state",
    }
    mine = proc_status_caps({"pid": os.getpid()})
    held = set(mine.get("capabilities", {}).get("CapEff", {}).get("decoded", []))
    return _res("priv_esc_cap_matrix", matrix=matrix,
                held_dangerous=[c for c in matrix if "cap_" + c[4:] in held or c in held])


def drop_caps_gen(args):
    """Generate real code to drop capabilities (C launcher + python prctl)."""
    caps = args.get("keep") or []
    keep_hex = 0
    for c in caps:
        if c in CAP_NAMES:
            keep_hex |= 1 << CAP_NAMES.index(c)
    c_src = ("#include <sys/prctl.h>\n#include <linux/securebits.h>\n"
             "int main(){for(int c=0;c<=40;c++){if(!((%dLL>>c)&1))prctl(PR_CAPBSET_DROP,c);}"
             "return 0;}\n" % keep_hex)
    return _res("drop_caps_gen", keep=caps, keep_mask=hex(keep_hex),
                c_launcher=c_src,
                note="compile with gcc -o dropcaps dropcaps.c; drops bounding set entries")


def cap_support_check(args):
    """Check kernel capability support and version via /proc/sys/kernel/cap_last_cap."""
    try:
        last = int(open("/proc/sys/kernel/cap_last_cap").read().strip())
    except OSError as e:
        return _err("cap_support_check", e)
    return _res("cap_support_check", cap_last_cap=last,
                highest_cap=CAP_NAMES[last] if last < len(CAP_NAMES) else "unknown",
                known_caps=len(CAP_NAMES))


def prctl_capbset_test(args):
    """Test whether CAPBSET_DROP is permitted for a capability (real prctl probe)."""
    cap = str(args.get("cap", "sys_rawio"))
    idx = CAP_NAMES.index(cap) if cap in CAP_NAMES else -1
    if idx < 0:
        return _err("prctl_capbset_test", "unknown cap: " + cap)
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_CAPBSET_READ = 23
    r = libc.prctl(PR_CAPBSET_READ, idx, 0, 0, 0)
    return _res("prctl_capbset_test", cap=cap, index=idx,
                in_bounding_set=(r == 1), dropped=(r == 0),
                errno=(ctypes.get_errno() if r < 0 else 0))


POWERS = {f"nm21.caps.{fn.__name__}": fn for fn in
          (proc_status_caps, capability_decode, getcap_scan, file_cap_grant,
           bounding_set_report, ambient_report, user_ns_cap_test,
           cap_eff_audit_all_procs, cap_to_name, priv_esc_cap_matrix,
           drop_caps_gen, cap_support_check, prctl_capbset_test)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
