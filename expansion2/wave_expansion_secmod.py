"""SSB swarm-24 expansion: nm21.secmod — LSM control (SELinux/AppArmor/seccomp).
Real securityfs reads and mutations. Armed:true default."""
import json, os, platform, re, subprocess, sys

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


def lsm_list(args):
    """List active LSMs from the real kernel lsm file (with fallbacks)."""
    for p in ("/sys/kernel/security/lsm", "/proc/sys/kernel/lsm"):
        try:
            return _res("lsm_list", active_lsms=open(p).read().strip().split(","))
        except OSError:
            pass
    # fallback: infer from present LSM filesystems/directories
    guessed = []
    if os.path.isdir("/sys/fs/selinux"):
        guessed.append("selinux")
    if os.path.isdir("/sys/kernel/security/apparmor"):
        guessed.append("apparmor")
    if os.path.isdir("/sys/fs/smackfs"):
        guessed.append("smack")
    if os.path.isdir("/sys/kernel/security/tomoyo"):
        guessed.append("tomoyo")
    try:
        open("/proc/self/attr/current").read()
        guessed = guessed or ["apparmor-or-selinux(attr present)"]
    except OSError:
        pass
    return _res("lsm_list", active_lsms=guessed, inferred=True,
                note="kernel lsm file unavailable; inferred from LSM filesystems")


def selinux_status(args):
    """Real SELinux status: mode, policy version, loaded policy name."""
    info = {}
    for p, key in (("/sys/fs/selinux/enforce", "enforce"),
                   ("/sys/fs/selinux/policyvers", "policyvers"),
                   ("/etc/selinux/config", "config")):
        try:
            info[key] = open(p, errors="replace").read().strip()
        except OSError:
            info[key] = None
    rc, out, err = _run(["sestatus"])
    return _res("selinux_status", present=os.path.isdir("/sys/fs/selinux"),
                info=info, sestatus=out if rc == 0 else err.strip())


def selinux_booleans(args):
    """List real SELinux booleans and values."""
    rc, out, err = _run(["getsebool", "-a"])
    bools = {}
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"(\S+)\s+-->\s+(\S+)", line)
            if m:
                bools[m.group(1)] = m.group(2)
    else:
        d = "/sys/fs/selinux/booleans"
        if os.path.isdir(d):
            for b in sorted(os.listdir(d))[:300]:
                try:
                    vals = open(os.path.join(d, b)).read().split()
                    bools[b] = vals[0] if vals else "?"
                except OSError:
                    pass
    return _res("selinux_booleans", booleans=bools, count=len(bools))


def selinux_boolean_set(args):
    """Set a real SELinux boolean (armed)."""
    name, value = str(args.get("name", "")), str(args.get("value", ""))
    if not name or value not in ("0", "1", "on", "off"):
        return _err("selinux_boolean_set", "need 'name' and 'value' in 0/1/on/off")
    if not _armed(args):
        return _res("selinux_boolean_set", armed=False, would_set={name: value})
    rc, out, err = _run(["setsebool", name, value])
    if rc != 0:
        p = f"/sys/fs/selinux/booleans/{name}"
        try:
            open(p, "w").write("1" if value in ("1", "on") else "0")
            rc = 0
        except OSError as e:
            err = str(e)
    d = _res("selinux_boolean_set", armed=True, applied=(rc == 0), name=name, value=value,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def selinux_enforce_set(args):
    """Set SELinux enforcing/permissive (armed, real securityfs write)."""
    mode = int(args.get("mode", 1))
    if mode not in (0, 1):
        return _err("selinux_enforce_set", "mode must be 0 (permissive) or 1 (enforcing)")
    p = "/sys/fs/selinux/enforce"
    if not _armed(args):
        return _res("selinux_enforce_set", armed=False, would_set=mode)
    try:
        open(p, "w").write(str(mode))
        return _res("selinux_enforce_set", armed=True, enforce=mode,
                    verify=open(p).read().strip())
    except (PermissionError, OSError) as e:
        return _err("selinux_enforce_set", e, prerequisite="root + SELinux permissive-capable")


def apparmor_status(args):
    """Real AppArmor status: profiles and modes from securityfs."""
    base = "/sys/kernel/security/apparmor"
    if not os.path.isdir(base):
        rc, out, err = _run(["aa-status"])
        if rc == 0:
            return _res("apparmor_status", enabled=True, aa_status=out)
        return _err("apparmor_status", "apparmor not present")
    profiles = {}
    pdir = os.path.join(base, "profiles")
    try:
        for line in open(pdir, errors="replace"):
            f = line.split()
            if len(f) >= 2:
                profiles[f[0]] = f[1]
    except OSError as e:
        return _err("apparmor_status", e)
    counts = {}
    for mode in profiles.values():
        counts[mode] = counts.get(mode, 0) + 1
    return _res("apparmor_status", enabled=True, profiles=profiles,
                mode_counts=counts, total=len(profiles))


def apparmor_enforce(args):
    """Change a real AppArmor profile mode via securityfs (armed)."""
    profile, mode = str(args.get("profile", "")), str(args.get("mode", "enforce"))
    if not profile or mode not in ("enforce", "complain"):
        return _err("apparmor_enforce", "need 'profile' and mode enforce|complain")
    if not _armed(args):
        return _res("apparmor_enforce", armed=False, would_set={profile: mode})
    tool = "aa-enforce" if mode == "enforce" else "aa-complain"
    rc, out, err = _run([tool, profile])
    d = _res("apparmor_enforce", armed=True, applied=(rc == 0), profile=profile,
             mode=mode, stderr=err.strip())
    d["ok"] = rc == 0
    return d


def aa_gen_profile(args):
    """Generate a real AppArmor profile for a binary."""
    binary = str(args.get("binary", ""))
    if not binary:
        return _err("aa_gen_profile", "need 'binary'")
    profile = (f"#include <tunables/global>\n{binary} {{\n"
               f"  #include <abstractions/base>\n  {binary} mr,\n"
               f"  /tmp/** rw,\n  deny /etc/shadow r,\n}}\n")
    path = "/etc/apparmor.d/" + binary.replace("/", ".").lstrip(".")
    return _res("aa_gen_profile", binary=binary, profile=profile,
                install_path=path, load_cmd=f"apparmor_parser -r {path}")


def seccomp_process_audit(args):
    """Audit seccomp mode of all real processes (0=off 1=strict 2=filter)."""
    rows = []
    for pid in (p for p in os.listdir("/proc") if p.isdigit()):
        try:
            txt = open(f"/proc/{pid}/status", errors="replace").read()
            m = re.search(r"^Seccomp:\s*(\d+)", txt, re.M)
            n = re.search(r"^Name:\s*(\S+)", txt, re.M)
            if m:
                rows.append({"pid": int(pid), "name": n.group(1) if n else "?",
                             "seccomp": int(m.group(1))})
        except OSError:
            continue
    dist = {}
    for r in rows:
        dist[r["seccomp"]] = dist.get(r["seccomp"], 0) + 1
    return _res("seccomp_process_audit", processes=rows[:500], distribution=dist)


def tomoyo_check(args):
    """Check TOMOYO LSM presence."""
    present = os.path.isdir("/sys/kernel/security/tomoyo")
    return _res("tomoyo_check", present=present)


def smack_check(args):
    """Check SMACK LSM presence and current label."""
    present = os.path.isdir("/sys/fs/smackfs") or os.path.exists("/proc/self/attr/current")
    label = None
    try:
        label = open("/proc/self/attr/current").read().strip()
    except OSError:
        pass
    return _res("smack_check", present=present, current_label=label)


def avc_denials_scan(args):
    """Scan real logs for SELinux AVC denials and AppArmor DENIED events."""
    hits = []
    sources = ["/var/log/audit/audit.log", "/var/log/syslog", "/var/log/messages",
               "/var/log/kern.log"]
    for src in sources:
        if not os.path.isfile(src):
            continue
        try:
            rc, out, err = _run(["grep", "-h", "-E", "avc:.*denied|apparmor=\"DENIED\"", src], timeout=30)
            hits += [{"source": src, "line": l} for l in out.splitlines()[:100]]
        except OSError:
            pass
    rc, out, err = _run(["journalctl", "--no-pager", "-g", "denied", "-n", "50"], timeout=30)
    hits += [{"source": "journal", "line": l} for l in out.splitlines() if "denied" in l.lower()][:50]
    return _res("avc_denials_scan", denials=hits[:200], count=len(hits))


def permissive_domains(args):
    """List SELinux permissive domains (real semanage/sestatus path)."""
    rc, out, err = _run(["sestatus"])
    perms = []
    if rc == 0:
        m = re.search(r"Permissive domains:\n((?:\t\S+\n?)*)", out)
        if m:
            perms = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    rc2, out2, _ = _run(["semodule", "-l"])
    return _res("permissive_domains", domains=perms,
                module_count=len(out2.splitlines()) if rc2 == 0 else None)


POWERS = {f"nm21.secmod.{fn.__name__}": fn for fn in
          (lsm_list, selinux_status, selinux_booleans, selinux_boolean_set,
           selinux_enforce_set, apparmor_status, apparmor_enforce, aa_gen_profile,
           seccomp_process_audit, tomoyo_check, smack_check, avc_denials_scan,
           permissive_domains)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
