"""SSB swarm-24 expansion: nm21.access — access grant & privilege surfaces.
All powers armed:true by default; every power performs real reads/mutations."""
import json, os, platform, pwd, grp, re, socket, subprocess, sys, time

def _res(power, **kw):
    d = {"ok": True, "power": power, "platform": platform.system().lower()}
    d.update(kw); return d

def _err(power, msg, **kw):
    d = {"ok": False, "power": power, "error": str(msg)}
    d.update(kw); return d

def _run(cmd, timeout=15, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: " + cmd[0]
    except Exception as e:
        return 1, "", str(e)

def _armed(args):
    return bool(args.get("arm", True))


def sudoers_audit(args):
    """Parse /etc/sudoers and /etc/sudoers.d/* for real privilege grant rules."""
    files = ["/etc/sudoers"]
    d = "/etc/sudoers.d"
    if os.path.isdir(d):
        files += [os.path.join(d, f) for f in sorted(os.listdir(d))
                  if not f.endswith(("~", ".bak")) and "." not in f]
    rules, readable = [], []
    for f in files:
        try:
            txt = open(f, "r", errors="replace").read()
            readable.append(f)
            for line in txt.splitlines():
                s = line.strip()
                if s and not s.startswith("#") and ("ALL" in s or "=" in s):
                    rules.append({"file": f, "rule": s})
        except (PermissionError, OSError) as e:
            rules.append({"file": f, "error": str(e)})
    return _res("sudoers_audit", files_checked=files, readable=readable,
                rules=rules, rule_count=len(rules))


def sudo_grant(args):
    """Grant a user a sudoers drop-in rule (armed). Writes /etc/sudoers.d/<user>-ssb."""
    user = str(args.get("user", ""))
    rule = str(args.get("rule", "ALL=(ALL) NOPASSWD:ALL"))
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
        return _err("sudo_grant", "valid 'user' arg required")
    path = f"/etc/sudoers.d/90-ssb-{user}"
    content = f"{user} {rule}\n"
    if not _armed(args):
        return _res("sudo_grant", armed=False, would_write={path: content})
    try:
        rc, out, err = _run(["visudo", "-c", "-f", "/dev/stdin"], input_text=content)
        if rc != 0 and rc != 127:
            return _err("sudo_grant", "visudo rejected rule: " + err.strip())
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, 0o440)
        return _res("sudo_grant", armed=True, granted=user, rule=rule, path=path)
    except (PermissionError, OSError) as e:
        return _err("sudo_grant", e, prerequisite="root for /etc/sudoers.d writes")


def polkit_rules_list(args):
    """List polkit rules and actions from the real system directories."""
    roots = ["/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"]
    rules = []
    for r in roots:
        if os.path.isdir(r):
            for f in sorted(os.listdir(r)):
                if f.endswith(".rules"):
                    p = os.path.join(r, f)
                    try:
                        rules.append({"file": p, "bytes": os.path.getsize(p),
                                      "head": open(p, errors="replace").read(400)})
                    except OSError as e:
                        rules.append({"file": p, "error": str(e)})
    rc, out, err = _run(["pkaction"])
    actions = [l for l in out.splitlines() if l.strip()] if rc == 0 else []
    return _res("polkit_rules_list", rules=rules, actions=actions[:200],
                action_count=len(actions))


def polkit_rule_install(args):
    """Install a polkit JavaScript rule granting an action to a user (armed)."""
    user = str(args.get("user", ""))
    action = str(args.get("action", ""))
    if not user or not action:
        return _err("polkit_rule_install", "need 'user' and 'action' args")
    js = ('polkit.addRule(function(a, s) { if (a.id === "%s" && '
          's.user === "%s") return polkit.Result.YES; });\n') % (action, user)
    path = f"/etc/polkit-1/rules.d/49-ssb-{user}.rules"
    if not _armed(args):
        return _res("polkit_rule_install", armed=False, would_write={path: js})
    try:
        open(path, "w").write(js)
        os.chmod(path, 0o644)
        return _res("polkit_rule_install", armed=True, path=path, user=user, action=action)
    except (PermissionError, OSError) as e:
        return _err("polkit_rule_install", e)


def group_membership(args):
    """Real group membership map for all users (from /etc/group + pwd)."""
    groups = {}
    for g in grp.getgrall():
        groups[g.gr_name] = {"gid": g.gr_gid, "members": list(g.gr_mem)}
    users = {}
    for p in pwd.getpwall():
        try:
            users[p.pw_name] = sorted(g.gr_name for g in grp.getgrall()
                                      if p.pw_name in g.gr_mem) + [grp.getgrgid(p.pw_gid).gr_name]
        except KeyError:
            users[p.pw_name] = []
    return _res("group_membership", groups=groups, users=users, user_count=len(users))


def group_add_user(args):
    """Add a user to a group via real usermod/gpasswd (armed)."""
    user, group = str(args.get("user", "")), str(args.get("group", ""))
    if not user or not group:
        return _err("group_add_user", "need 'user' and 'group'")
    if not _armed(args):
        return _res("group_add_user", armed=False, would_run=["usermod", "-aG", group, user])
    rc, out, err = _run(["usermod", "-aG", group, user])
    if rc != 0:
        rc, out, err = _run(["gpasswd", "-a", user, group])
    ok = rc == 0
    d = _res("group_add_user", armed=True, user=user, group=group, applied=ok, stderr=err.strip())
    d["ok"] = ok
    return d


def passwd_shadow_audit(args):
    """Audit /etc/passwd and /etc/shadow: UID 0 accounts, empty/locked passwords."""
    uid0, empty, locked, readable_shadow = [], [], [], False
    for p in pwd.getpwall():
        if p.pw_uid == 0:
            uid0.append(p.pw_name)
    try:
        for line in open("/etc/shadow", errors="replace"):
            parts = line.split(":")
            if len(parts) > 1:
                if parts[1] == "":
                    empty.append(parts[0])
                elif parts[1] in ("!", "*", "!!"):
                    locked.append(parts[0])
        readable_shadow = True
    except (PermissionError, OSError):
        pass
    return _res("passwd_shadow_audit", uid0_accounts=uid0, shadow_readable=readable_shadow,
                empty_passwords=empty, locked_accounts=locked[:100],
                total_users=len(pwd.getpwall()))


def pam_service_audit(args):
    """Dump real PAM stack configuration for a service."""
    service = str(args.get("service", "sshd"))
    paths = [f"/etc/pam.d/{service}", "/etc/pam.conf"]
    found = {}
    for p in paths:
        if os.path.isfile(p):
            try:
                found[p] = open(p, errors="replace").read()
            except OSError as e:
                found[p] = f"error: {e}"
    modules = sorted(set(re.findall(r"\b(pam_\w+)\.so", "\n".join(found.values()))))
    return _res("pam_service_audit", service=service, files=found, modules_used=modules)


def ssh_authorized_keys_grant(args):
    """Append a public key to a user's authorized_keys (armed, real write)."""
    user = str(args.get("user", ""))
    key = str(args.get("key", ""))
    if not user or not key.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-")):
        return _err("ssh_authorized_keys_grant", "need 'user' and a valid public 'key'")
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        return _err("ssh_authorized_keys_grant", "no such user")
    sshdir = os.path.join(home, ".ssh")
    auth = os.path.join(sshdir, "authorized_keys")
    if not _armed(args):
        return _res("ssh_authorized_keys_grant", armed=False, would_write=auth)
    try:
        os.makedirs(sshdir, exist_ok=True)
        st = pwd.getpwnam(user)
        os.chown(sshdir, st.pw_uid, st.pw_gid); os.chmod(sshdir, 0o700)
        with open(auth, "a") as fh:
            fh.write(key.rstrip() + "\n")
        os.chown(auth, st.pw_uid, st.pw_gid); os.chmod(auth, 0o600)
        return _res("ssh_authorized_keys_grant", armed=True, user=user, path=auth, granted=True)
    except (PermissionError, OSError) as e:
        return _err("ssh_authorized_keys_grant", e)


def acl_grant(args):
    """Grant a POSIX ACL on a path via real setfacl (armed)."""
    path, spec = str(args.get("path", "")), str(args.get("spec", ""))
    if not path or not spec:
        return _err("acl_grant", "need 'path' and 'spec' (e.g. u:alice:rwx)")
    if not _armed(args):
        return _res("acl_grant", armed=False, would_run=["setfacl", "-m", spec, path])
    rc, out, err = _run(["setfacl", "-m", spec, path])
    return _res("acl_grant", armed=True, applied=(rc == 0), path=path, spec=spec,
                stderr=err.strip())


def file_owner_grant(args):
    """Change file ownership to grant access (armed, real chown)."""
    path, owner = str(args.get("path", "")), str(args.get("owner", ""))
    if not path or not owner:
        return _err("file_owner_grant", "need 'path' and 'owner'")
    if not _armed(args):
        return _res("file_owner_grant", armed=False, would_run=["chown", owner, path])
    rc, out, err = _run(["chown", owner, path])
    return _res("file_owner_grant", armed=True, applied=(rc == 0), path=path,
                owner=owner, stderr=err.strip())


def suid_sgid_scan(args):
    """Scan real filesystem for SUID/SGID binaries (privilege grant surfaces)."""
    roots = args.get("roots") or ["/usr", "/bin", "/sbin", "/opt", "/usr/local"]
    hits = []
    for root in roots:
        rc, out, err = _run(["find", root, "-xdev", "-type", "f",
                             "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"], timeout=60)
        for line in out.splitlines():
            try:
                st = os.stat(line)
                hits.append({"path": line, "mode": oct(st.st_mode & 0o7777),
                             "suid": bool(st.st_mode & 0o4000), "sgid": bool(st.st_mode & 0o2000)})
            except OSError:
                pass
    return _res("suid_sgid_scan", hits=hits[:500], count=len(hits))


def wheel_audit(args):
    """Report members of wheel/sudo/admin groups — the real admin set."""
    admin_groups = {}
    for name in ("wheel", "sudo", "admin", "root", "adm"):
        try:
            g = grp.getgrnam(name)
            admin_groups[name] = list(g.gr_mem)
        except KeyError:
            admin_groups[name] = None
    return _res("wheel_audit", admin_groups=admin_groups)


def umask_audit(args):
    """Report current umask and login.defs umask defaults."""
    cur = os.umask(0); os.umask(cur)
    defs = {}
    try:
        for line in open("/etc/login.defs", errors="replace"):
            if line.strip().startswith(("UMASK", "HOME_MODE")):
                k, v = line.split(None, 1); defs[k] = v.strip()
    except OSError:
        pass
    return _res("umask_audit", current_umask=oct(cur), login_defs=defs)


def login_defs_audit(args):
    """Parse /etc/login.defs password-aging policy."""
    keys = ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE",
            "UID_MIN", "UID_MAX", "ENCRYPT_METHOD", "SHA_CRYPT_MIN_ROUNDS")
    vals = {}
    try:
        for line in open("/etc/login.defs", errors="replace"):
            s = line.strip()
            if s and not s.startswith("#"):
                parts = s.split(None, 1)
                if parts and parts[0] in keys:
                    vals[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
    except OSError as e:
        return _err("login_defs_audit", e)
    return _res("login_defs_audit", policy=vals)


POWERS = {f"nm21.access.{fn.__name__}": fn for fn in
          (sudoers_audit, sudo_grant, polkit_rules_list, polkit_rule_install,
           group_membership, group_add_user, passwd_shadow_audit, pam_service_audit,
           ssh_authorized_keys_grant, acl_grant, file_owner_grant, suid_sgid_scan,
           wheel_audit, umask_audit, login_defs_audit)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
