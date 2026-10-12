"""SSB swarm-24 expansion: nm21.audit — auditd, logs, integrity verification.
Real auditctl rules, auth log analysis, package integrity checks. Armed:true default."""
import json, os, platform, re, subprocess, sys, time

def _res(power, **kw):
    d = {"ok": True, "power": power, "platform": platform.system().lower()}
    d.update(kw); return d

def _err(power, msg, **kw):
    d = {"ok": False, "power": power, "error": str(msg)}
    d.update(kw); return d

def _run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: " + cmd[0]
    except Exception as e:
        return 1, "", str(e)

def _armed(args):
    return bool(args.get("arm", True))


def auditd_status(args):
    """Real auditd status from auditctl -s."""
    rc, out, err = _run(["auditctl", "-s"])
    kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l) if rc == 0 else {}
    running = os.path.exists("/var/run/auditd.pid") or rc == 0
    return _res("auditd_status", running=running, status=kv, raw=out[:1500])


def audit_rules_list(args):
    """List real loaded audit rules."""
    rc, out, err = _run(["auditctl", "-l"])
    rules = out.splitlines() if rc == 0 else []
    files_rules = []
    d = "/etc/audit/rules.d"
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            try:
                files_rules.append({"file": os.path.join(d, f),
                                    "content": open(os.path.join(d, f), errors="replace").read()})
            except OSError:
                pass
    return _res("audit_rules_list", loaded=rules, rule_files=files_rules)


def audit_rule_add(args):
    """Add a real audit rule, e.g. watch a file or trace a syscall (armed)."""
    rule = args.get("rule")
    if isinstance(rule, str):
        rule = rule.split()
    if not rule:
        return _err("audit_rule_add", "need 'rule' list (auditctl args)")
    if not _armed(args):
        return _res("audit_rule_add", armed=False, would_add=rule)
    rc, out, err = _run(["auditctl"] + rule)
    d = _res("audit_rule_add", armed=True, applied=(rc == 0), rule=rule, stderr=err.strip())
    d["ok"] = rc == 0
    return d


def audit_rule_delete(args):
    """Delete a real audit rule (armed)."""
    rule = args.get("rule")
    if isinstance(rule, str):
        rule = rule.split()
    if not rule:
        return _err("audit_rule_delete", "need 'rule'")
    if not _armed(args):
        return _res("audit_rule_delete", armed=False, would_delete=rule)
    mapped = [("-W" if r == "-w" else r) for r in rule]
    rc, out, err = _run(["auditctl"] + mapped)
    d = _res("audit_rule_delete", armed=True, applied=(rc == 0), stderr=err.strip())
    d["ok"] = rc == 0
    return d


def auth_log_scan(args):
    """Scan real auth logs for logins, sudo use, and failures."""
    files = ["/var/log/auth.log", "/var/log/secure"]
    found = [f for f in files if os.path.isfile(f)]
    events = {"accepted": [], "failed": [], "sudo": []}
    for f in found:
        try:
            txt = open(f, errors="replace").read()[-2_000_000:]
        except OSError:
            continue
        for line in txt.splitlines():
            l = line.lower()
            if "accepted password" in l or "accepted publickey" in l:
                events["accepted"].append(line)
            elif "failed password" in l or "authentication failure" in l:
                events["failed"].append(line)
            elif "sudo:" in l and "command" in l:
                events["sudo"].append(line)
    for k in events:
        events[k] = events[k][-100:]
    return _res("auth_log_scan", files=found, events=events,
                counts={k: len(v) for k, v in events.items()})


def failed_login_report(args):
    """Aggregate failed logins by user and source IP from real logs."""
    scan = auth_log_scan(args)
    by_user, by_ip = {}, {}
    for line in scan.get("events", {}).get("failed", []):
        m = re.search(r"for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)", line)
        if m:
            by_user[m.group(1)] = by_user.get(m.group(1), 0) + 1
            by_ip[m.group(2)] = by_ip.get(m.group(2), 0) + 1
    top = lambda d: sorted(d.items(), key=lambda x: -x[1])[:20]
    return _res("failed_login_report", top_users=top(by_user), top_ips=top(by_ip))


def audit_watch_file(args):
    """Watch a sensitive file with auditd (armed, real rule)."""
    path = str(args.get("path", "/etc/shadow"))
    perms = str(args.get("perms", "wa"))
    key = str(args.get("key", "ssb-watch"))
    if not _armed(args):
        return _res("audit_watch_file", armed=False, would_watch=path)
    rc, out, err = _run(["auditctl", "-w", path, "-p", perms, "-k", key])
    d = _res("audit_watch_file", armed=True, applied=(rc == 0), path=path, key=key,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def log_files_inventory(args):
    """Inventory real log files with sizes and mtimes."""
    roots = ["/var/log"]
    files = []
    for root in roots:
        for r, dirs, fs in os.walk(root):
            for f in fs:
                p = os.path.join(r, f)
                try:
                    st = os.stat(p)
                    files.append({"path": p, "bytes": st.st_size,
                                  "mtime": int(st.st_mtime)})
                except OSError:
                    pass
    files.sort(key=lambda x: -x["bytes"])
    return _res("log_files_inventory", files=files[:300], count=len(files))


def wtmp_last_report(args):
    """Real last-login report from wtmp via `last`."""
    rc, out, err = _run(["last", "-n", "50", "-F"])
    rows = [l for l in out.splitlines() if l.strip() and not l.startswith(("wtmp", "btmp"))]
    return _res("wtmp_last_report", logins=rows[:50])


def journal_auth_failures(args):
    """Pull auth failures from the real systemd journal."""
    rc, out, err = _run(["journalctl", "--no-pager", "-n", "100",
                         "_SYSTEMD_UNIT=sshd.service"], timeout=30)
    fails = [l for l in out.splitlines() if "fail" in l.lower() or "invalid" in l.lower()]
    return _res("journal_auth_failures", failures=fails[:100], count=len(fails))


def audit_backlog_report(args):
    """Report audit backlog health (lost events, backlog limit)."""
    rc, out, err = _run(["auditctl", "-s"])
    kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l) if rc == 0 else {}
    keys = ("lost", "backlog", "backlog_limit", "backlog_wait_time", "enabled", "failure")
    return _res("audit_backlog_report", metrics={k: kv.get(k) for k in keys if k in kv})


def integrity_rpm_verify(args):
    """Real package integrity verification (rpm -Va or debsums/dpkg --verify)."""
    rc, out, err = _run(["rpm", "-Va"], timeout=300)
    if rc == 127:
        rc, out, err = _run(["dpkg", "--verify"], timeout=300)
        tool = "dpkg"
    else:
        tool = "rpm"
    lines = [l for l in out.splitlines() if l.strip()]
    return _res("integrity_rpm_verify", tool=tool, changed_files=lines[:300],
                count=len(lines), note="files modified since package install")


def logrotate_audit(args):
    """Audit logrotate configuration for coverage gaps."""
    files = ["/etc/logrotate.conf"]
    d = "/etc/logrotate.d"
    if os.path.isdir(d):
        files += [os.path.join(d, f) for f in sorted(os.listdir(d))]
    cfgs = {}
    for f in files:
        try:
            cfgs[f] = open(f, errors="replace").read()
        except OSError:
            pass
    rotated = set(re.findall(r"^(/[^\s{]+)", "\n".join(cfgs.values()), re.M))
    return _res("logrotate_audit", configs=list(cfgs), rotated_paths=sorted(rotated))


def audit_enable(args):
    """Enable/disable the audit subsystem (armed, real auditctl -e)."""
    val = int(args.get("enable", 1))
    if val not in (0, 1, 2):
        return _err("audit_enable", "enable must be 0, 1, or 2 (lock)")
    if not _armed(args):
        return _res("audit_enable", armed=False, would_set=val)
    rc, out, err = _run(["auditctl", "-e", str(val)])
    d = _res("audit_enable", armed=True, applied=(rc == 0), enabled=val, stderr=err.strip())
    d["ok"] = rc == 0
    return d


POWERS = {f"nm21.audit.{fn.__name__}": fn for fn in
          (auditd_status, audit_rules_list, audit_rule_add, audit_rule_delete,
           auth_log_scan, failed_login_report, audit_watch_file,
           log_files_inventory, wtmp_last_report, journal_auth_failures,
           audit_backlog_report, integrity_rpm_verify, logrotate_audit,
           audit_enable)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
