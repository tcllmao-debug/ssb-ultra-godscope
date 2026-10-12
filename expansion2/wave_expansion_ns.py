"""SSB swarm-24 expansion: nm21.ns — namespaces & cgroups control.
Real /proc ns inventory, cgroup v2 reads/writes, nsenter/unshare. Armed:true default."""
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

NS_TYPES = ("mnt", "pid", "net", "ipc", "uts", "user", "cgroup", "time")


def namespace_inventory(args):
    """Real namespace inventory of this process from /proc/self/ns."""
    pid = int(args.get("pid", os.getpid()))
    out = {}
    for ns in NS_TYPES:
        p = f"/proc/{pid}/ns/{ns}"
        try:
            out[ns] = os.readlink(p)
        except OSError:
            pass
    return _res("namespace_inventory", pid=pid, namespaces=out)


def ns_process_map(args):
    """Group all running processes by their namespaces (real /proc walk)."""
    table = {}
    for pid in (p for p in os.listdir("/proc") if p.isdigit()):
        try:
            links = {}
            for ns in ("pid", "net", "mnt", "user"):
                links[ns] = os.readlink(f"/proc/{pid}/ns/{ns}")
            key = tuple(links.values())
            table.setdefault(key, []).append(int(pid))
        except OSError:
            continue
    groups = [{"namespaces": dict(zip(("pid", "net", "mnt", "user"), k)),
               "pids": v[:60], "count": len(v)} for k, v in table.items()]
    return _res("ns_process_map", groups=groups, group_count=len(groups))


def setns_join(args):
    """Join a target process's namespaces and run a command (armed, real setns)."""
    pid = int(args.get("pid", 0))
    command = args.get("command")
    if isinstance(command, str):
        command = command.split()
    if not pid or not command:
        return _err("setns_join", "need 'pid' and 'command'")
    if not _armed(args):
        return _res("setns_join", armed=False, would_run=["nsenter", "-t", str(pid), "-a"] + command)
    rc, out, err = _run(["nsenter", "-t", str(pid), "-a"] + command, timeout=30)
    d = _res("setns_join", armed=True, applied=(rc == 0), pid=pid,
             stdout=out[:4000], stderr=err.strip()[:1000])
    d["ok"] = rc == 0
    return d


def unshare_gen(args):
    """Generate and optionally execute a real unshare command for ns isolation."""
    kinds = args.get("kinds") or ["mount", "uts", "ipc", "pid", "net"]
    command = args.get("command") or ["/bin/sh"]
    if isinstance(command, str):
        command = command.split()
    flags = []
    for k in kinds:
        flags += {"mount": ["--mount"], "uts": ["--uts"], "ipc": ["--ipc"],
                  "pid": ["--pid", "--fork", "--mount-proc"], "net": ["--net"],
                  "user": ["--user", "--map-root-user"], "cgroup": ["--cgroup"]}.get(k, [])
    cmd = ["unshare"] + flags + command
    if not _armed(args):
        return _res("unshare_gen", armed=False, command=cmd)
    rc, out, err = _run(cmd, timeout=30)
    return _res("unshare_gen", armed=True, command=cmd, rc=rc,
                stdout=out[:3000], stderr=err.strip()[:1000])


def _cg_root():
    return "/sys/fs/cgroup" if os.path.isdir("/sys/fs/cgroup") else None


def cgroup_v2_tree(args):
    """Walk the real cgroup v2 tree."""
    root = _cg_root()
    if not root:
        return _err("cgroup_v2_tree", "cgroupfs not mounted")
    depth = int(args.get("depth", 3))
    tree = []
    base_depth = root.count("/")
    for r, dirs, files in os.walk(root):
        if r.count("/") - base_depth > depth:
            dirs[:] = []
            continue
        tree.append(r)
        if len(tree) > 500:
            break
    return _res("cgroup_v2_tree", root=root, entries=tree, count=len(tree))


def cgroup_read(args):
    """Read real cgroup files (cpu.max, memory.current, pids.current...)."""
    path = str(args.get("path", "/sys/fs/cgroup"))
    keys = args.get("keys") or ["cpu.max", "cpu.stat", "memory.current", "memory.max",
                                "pids.current", "pids.max", "cgroup.controllers",
                                "cgroup.subtree_control"]
    vals = {}
    for k in keys:
        p = os.path.join(path, k)
        try:
            vals[k] = open(p, errors="replace").read().strip()
        except OSError:
            pass
    return _res("cgroup_read", path=path, values=vals)


def cgroup_write(args):
    """Write a real cgroup control value (armed — applies resource limits)."""
    path, key = str(args.get("path", "")), str(args.get("key", ""))
    value = str(args.get("value", ""))
    if not path or not key or value == "":
        return _err("cgroup_write", "need 'path', 'key', 'value'")
    p = os.path.join(path, key)
    if not _armed(args):
        return _res("cgroup_write", armed=False, would_write={p: value})
    try:
        open(p, "w").write(value)
        return _res("cgroup_write", armed=True, wrote={p: value},
                    verify=open(p).read().strip())
    except (PermissionError, OSError) as e:
        return _err("cgroup_write", e, path=p)


def cgroup_procs(args):
    """List real PIDs in a cgroup."""
    path = str(args.get("path", "/sys/fs/cgroup"))
    try:
        procs = [int(x) for x in open(os.path.join(path, "cgroup.procs")).read().split()]
        return _res("cgroup_procs", path=path, pids=procs, count=len(procs))
    except OSError as e:
        return _err("cgroup_procs", e, path=path)


def userns_map_gen(args):
    """Generate real uid_map/gid_map payloads for a user namespace."""
    inner = int(args.get("inner", 0)); outer = int(args.get("outer", os.getuid()))
    count = int(args.get("count", 1))
    uid_map = f"{inner} {outer} {count}\n"
    return _res("userns_map_gen", uid_map=uid_map, gid_map=uid_map,
                setgroups="deny\n",
                usage="write uid_map/gid_map to /proc/<pid>/ after unshare(CLONE_NEWUSER)")


def netns_list(args):
    """List real named network namespaces (ip netns)."""
    rc, out, err = _run(["ip", "netns", "list"])
    named = [l.split()[0] for l in out.splitlines() if l.strip()]
    varrun = []
    d = "/var/run/netns"
    if os.path.isdir(d):
        varrun = sorted(os.listdir(d))
    return _res("netns_list", ip_netns=named, var_run_netns=varrun)


def netns_create(args):
    """Create a named network namespace (armed, real ip netns add)."""
    name = str(args.get("name", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
        return _err("netns_create", "need valid 'name'")
    if not _armed(args):
        return _res("netns_create", armed=False, would_create=name)
    rc, out, err = _run(["ip", "netns", "add", name])
    d = _res("netns_create", armed=True, applied=(rc == 0), name=name, stderr=err.strip())
    d["ok"] = rc == 0
    return d


def netns_exec(args):
    """Execute a command inside a named netns (armed, real ip netns exec)."""
    name = str(args.get("name", ""))
    command = args.get("command")
    if isinstance(command, str):
        command = command.split()
    if not name or not command:
        return _err("netns_exec", "need 'name' and 'command'")
    if not _armed(args):
        return _res("netns_exec", armed=False, would_run=["ip", "netns", "exec", name] + command)
    rc, out, err = _run(["ip", "netns", "exec", name] + command, timeout=30)
    d = _res("netns_exec", armed=True, applied=(rc == 0), stdout=out[:3000], stderr=err.strip()[:500])
    d["ok"] = rc == 0
    return d


def mntns_propagation(args):
    """Report real mount propagation flags from /proc/self/mountinfo."""
    rows = []
    try:
        for line in open("/proc/self/mountinfo", errors="replace"):
            f = line.split()
            if len(f) >= 7:
                optional = f[6:f.index("-") if "-" in f else len(f)]
                rows.append({"mount": f[4], "propagation": [o for o in optional if ":" in o]})
    except OSError as e:
        return _err("mntns_propagation", e)
    return _res("mntns_propagation", mounts=rows[:200], count=len(rows))


def pidns_report(args):
    """Report PID namespace depth via NSpid of a process."""
    pid = int(args.get("pid", os.getpid()))
    try:
        txt = open(f"/proc/{pid}/status", errors="replace").read()
        m = re.search(r"^NSpid:\s*(.+)", txt, re.M)
        nspid = m.group(1).split() if m else []
        return _res("pidns_report", pid=pid, nspid_chain=nspid, depth=len(nspid))
    except OSError as e:
        return _err("pidns_report", e)


def cgroup_limits_set(args):
    """Set real CPU/memory/pids limits on a cgroup (armed)."""
    path = str(args.get("path", ""))
    limits = args.get("limits") or {}
    if not path or not limits:
        return _err("cgroup_limits_set", "need 'path' and 'limits' dict")
    results = {}
    if not _armed(args):
        return _res("cgroup_limits_set", armed=False, would_set=limits, path=path)
    for k, v in limits.items():
        p = os.path.join(path, k)
        try:
            open(p, "w").write(str(v))
            results[k] = {"applied": True, "verify": open(p).read().strip()}
        except (PermissionError, OSError) as e:
            results[k] = {"applied": False, "error": str(e)}
    return _res("cgroup_limits_set", armed=True, path=path, results=results)


POWERS = {f"nm21.ns.{fn.__name__}": fn for fn in
          (namespace_inventory, ns_process_map, setns_join, unshare_gen,
           cgroup_v2_tree, cgroup_read, cgroup_write, cgroup_procs,
           userns_map_gen, netns_list, netns_create, netns_exec,
           mntns_propagation, pidns_report, cgroup_limits_set)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
