"""SSB swarm-24 expansion: nm21.vault — secrets & key material control.
Real keyctl, gpg/ssh-agent inventories, secret scans, JWT decode. Armed:true default."""
import base64, hashlib, json, os, platform, pwd, re, subprocess, sys

def _res(power, **kw):
    d = {"ok": True, "power": power, "platform": platform.system().lower()}
    d.update(kw); return d

def _err(power, msg, **kw):
    d = {"ok": False, "power": power, "error": str(msg)}
    d.update(kw); return d

def _run(cmd, timeout=15, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: " + cmd[0]
    except Exception as e:
        return 1, "", str(e)

def _armed(args):
    return bool(args.get("arm", True))

SECRET_PATTERNS = {
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret_key": r"(?i)aws.{0,20}['\"]([0-9a-zA-Z/+=]{40})['\"]",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "generic_api_key": r"(?i)(api[_-]?key|apikey|secret|token|password)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}


def keyctl_session_report(args):
    """Real keyctl session keyring report."""
    rc, out, err = _run(["keyctl", "show"])
    rc2, out2, _ = _run(["keyctl", "list", "@s"])
    return _res("keyctl_session_report", session=out if rc == 0 else err.strip(),
                keys=out2.splitlines() if rc2 == 0 else [])


def keyctl_list(args):
    """List real keys in the user/session keyring."""
    ring = str(args.get("ring", "@u"))
    rc, out, err = _run(["keyctl", "list", ring])
    keys = []
    if rc == 0:
        for line in out.splitlines():
            keys.append(line.strip())
    return _res("keyctl_list", ring=ring, keys=keys)


def keyctl_add(args):
    """Add a real key to the session keyring (armed)."""
    name = str(args.get("name", ""))
    value = str(args.get("value", ""))
    ring = str(args.get("ring", "@s"))
    if not name or not value:
        return _err("keyctl_add", "need 'name' and 'value'")
    if not _armed(args):
        return _res("keyctl_add", armed=False, would_add=name)
    rc, out, err = _run(["keyctl", "add", "user", name, value, ring])
    d = _res("keyctl_add", armed=True, applied=(rc == 0), name=name,
             serial=out.strip(), stderr=err.strip())
    d["ok"] = rc == 0
    return d


def gpg_key_list(args):
    """List real GPG public and secret keys."""
    rc, out, err = _run(["gpg", "--list-keys", "--with-colons"])
    rc2, out2, _ = _run(["gpg", "--list-secret-keys", "--with-colons"])
    pubs, secs = [], []
    for line in out.splitlines():
        if line.startswith("pub:"):
            f = line.split(":")
            pubs.append({"keyid": f[4], "uid_hint": f[9] if len(f) > 9 else ""})
    for line in out2.splitlines():
        if line.startswith("sec:"):
            f = line.split(":")
            secs.append({"keyid": f[4]})
    return _res("gpg_key_list", public_keys=pubs, secret_keys=secs)


def ssh_agent_keys(args):
    """List real keys held by the ssh-agent."""
    rc, out, err = _run(["ssh-add", "-l"])
    agent = bool(os.environ.get("SSH_AUTH_SOCK"))
    keys = out.splitlines() if rc == 0 else []
    return _res("ssh_agent_keys", agent_socket=agent, keys=keys,
                status=err.strip() if rc != 0 else "ok")


def env_secret_scan(args):
    """Scan real process environments for secret-looking variables."""
    hits = []
    pids = [os.getpid()] + [int(p) for p in os.listdir("/proc") if p.isdigit()][:200]
    for pid in pids:
        try:
            raw = open(f"/proc/{pid}/environ", "rb").read().decode("utf-8", "replace")
        except OSError:
            continue
        for var in raw.split("\x00"):
            if "=" not in var:
                continue
            k, v = var.split("=", 1)
            if re.search(r"(?i)(key|secret|token|passw|cred)", k) and v:
                hits.append({"pid": pid, "var": k, "value_len": len(v),
                             "value_preview": v[:4] + "..."})
    return _res("env_secret_scan", hits=hits[:200], count=len(hits))


def history_secret_scan(args):
    """Scan real shell histories for typed secrets."""
    files = []
    for p in pwd.getpwall():
        for name in (".bash_history", ".zsh_history", ".sh_history"):
            f = os.path.join(p.pw_dir, name)
            if os.path.isfile(f):
                files.append(f)
    hits = []
    for f in files:
        try:
            for line in open(f, errors="replace"):
                for pat_name, pat in SECRET_PATTERNS.items():
                    if re.search(pat, line):
                        hits.append({"file": f, "pattern": pat_name,
                                     "line": line.strip()[:160]})
        except OSError:
            pass
    return _res("history_secret_scan", files_scanned=files, hits=hits[:200],
                count=len(hits))


def config_secret_scan(args):
    """Scan common config locations for embedded credentials (real files)."""
    roots = args.get("roots") or [os.path.expanduser("~/.config"), os.path.expanduser("~/.ssh"),
                                  "/etc"]
    hits = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for r, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ("cache", "Cache", "__pycache__")]
            for fn in files:
                p = os.path.join(r, fn)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    txt = open(p, errors="replace").read()
                except OSError:
                    continue
                for pat_name, pat in SECRET_PATTERNS.items():
                    if re.search(pat, txt):
                        hits.append({"file": p, "pattern": pat_name})
            if len(hits) > 400:
                break
    return _res("config_secret_scan", hits=hits[:400], count=len(hits))


def token_pattern_scan(args):
    """Scan a given file or text for token patterns (AWS/GitHub/JWT/keys)."""
    text = args.get("text")
    path = args.get("path")
    if path:
        try:
            text = open(str(path), errors="replace").read()
        except OSError as e:
            return _err("token_pattern_scan", e)
    if not text:
        return _err("token_pattern_scan", "need 'text' or 'path'")
    found = {}
    for name, pat in SECRET_PATTERNS.items():
        m = re.findall(pat, text)
        if m:
            found[name] = [x if isinstance(x, str) else x[0] for x in m][:10]
    return _res("token_pattern_scan", found=found, count=sum(len(v) for v in found.values()))


def cred_file_permissions_audit(args):
    """Audit permissions on real credential files (should be 600/400)."""
    targets = []
    for p in pwd.getpwall():
        for name in (".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials",
                     ".netrc", ".pgpass", ".kube/config", ".docker/config.json",
                     ".gnupg/secring.gpg"):
            f = os.path.join(p.pw_dir, name)
            if os.path.isfile(f):
                targets.append(f)
    rows = []
    for f in targets:
        try:
            st = os.stat(f)
            mode = oct(st.st_mode & 0o777)
            rows.append({"file": f, "mode": mode,
                         "too_open": bool(st.st_mode & 0o077)})
        except OSError:
            pass
    return _res("cred_file_permissions_audit", files=rows,
                exposed=[r["file"] for r in rows if r["too_open"]])


def hash_identify(args):
    """Identify a hash by length/charset (real analysis)."""
    h = str(args.get("hash", "")).strip()
    kinds = {32: "MD5/NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
             96: "SHA-384", 128: "SHA-512"}
    result = {"hash": h[:64], "length": len(h)}
    if h.startswith("$2"):
        result["type"] = "bcrypt"
    elif h.startswith("$6$"):
        result["type"] = "sha512crypt"
    elif h.startswith("$5$"):
        result["type"] = "sha256crypt"
    elif h.startswith("$1$"):
        result["type"] = "md5crypt"
    elif h.startswith("$y$"):
        result["type"] = "yescrypt"
    elif re.fullmatch(r"[0-9a-fA-F]+", h):
        result["type"] = kinds.get(len(h), "unknown-hex")
    else:
        result["type"] = "unknown"
    return _res("hash_identify", **result)


def jwt_decode(args):
    """Decode a real JWT (header + payload) without verifying signature."""
    tok = str(args.get("token", ""))
    parts = tok.split(".")
    if len(parts) < 2:
        return _err("jwt_decode", "need 'token'")
    def b64(s):
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s.encode()))
    try:
        header = b64(parts[0]); payload = b64(parts[1])
    except Exception as e:
        return _err("jwt_decode", e)
    return _res("jwt_decode", header=header, payload=payload,
                signature_present=len(parts) == 3 and bool(parts[2]))


def cert_inventory(args):
    """Inventory real TLS certificates on the system."""
    dirs = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/usr/local/share/ca-certificates"]
    certs = []
    for d in dirs:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d))[:400]:
                if f.endswith((".crt", ".pem", ".cer")):
                    certs.append(os.path.join(d, f))
    return _res("cert_inventory", certs=certs[:400], count=len(certs))


def ssh_hostkey_report(args):
    """Report real SSH host keys and fingerprints."""
    d = "/etc/ssh"
    keys = []
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.startswith("ssh_host_") and f.endswith(".pub"):
                p = os.path.join(d, f)
                try:
                    content = open(p).read().strip()
                    rc, out, err = _run(["ssh-keygen", "-lf", p])
                    keys.append({"file": p, "fingerprint": out.strip(),
                                 "type": content.split()[0]})
                except OSError:
                    pass
    return _res("ssh_hostkey_report", host_keys=keys)


POWERS = {f"nm21.vault.{fn.__name__}": fn for fn in
          (keyctl_session_report, keyctl_list, keyctl_add, gpg_key_list,
           ssh_agent_keys, env_secret_scan, history_secret_scan,
           config_secret_scan, token_pattern_scan, cred_file_permissions_audit,
           hash_identify, jwt_decode, cert_inventory, ssh_hostkey_report)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
