"""SSB swarm-24 expansion: nm21.kernctl — kernel control plane.
Sysctl reads/writes, module load/unload, tracefs kprobes. All armed:true default."""
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

def _sysctl_path(key):
    return "/proc/sys/" + key.replace(".", "/")


def sysctl_read(args):
    """Read a real sysctl value from /proc/sys."""
    key = str(args.get("key", ""))
    if not key:
        return _err("sysctl_read", "need 'key' (e.g. kernel.kptr_restrict)")
    p = _sysctl_path(key)
    try:
        return _res("sysctl_read", key=key, value=open(p).read().strip())
    except OSError as e:
        return _err("sysctl_read", e, key=key)


def sysctl_write(args):
    """Write a sysctl value directly to /proc/sys (armed, real kernel mutation)."""
    key, value = str(args.get("key", "")), str(args.get("value", ""))
    if not key or value == "":
        return _err("sysctl_write", "need 'key' and 'value'")
    p = _sysctl_path(key)
    if not os.path.exists(p):
        return _err("sysctl_write", "unknown sysctl", key=key)
    if not _armed(args):
        return _res("sysctl_write", armed=False, key=key, would_set=value)
    try:
        old = open(p).read().strip()
        open(p, "w").write(value)
        return _res("sysctl_write", armed=True, key=key, old=old, new=open(p).read().strip())
    except (PermissionError, OSError) as e:
        return _err("sysctl_write", e, key=key, prerequisite="root")


def sysctl_dump(args):
    """Dump real sysctl values for a subtree."""
    prefix = str(args.get("prefix", "kernel"))
    base = _sysctl_path(prefix)
    out = {}
    for root, dirs, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            key = os.path.relpath(p, "/proc/sys").replace("/", ".")
            try:
                out[key] = open(p, errors="replace").read().strip()[:256]
            except OSError:
                pass
        if len(out) > int(args.get("limit", 300)):
            break
    return _res("sysctl_dump", prefix=prefix, values=out, count=len(out))


def module_list(args):
    """List loaded kernel modules from /proc/modules with sizes and users."""
    mods = []
    try:
        for line in open("/proc/modules", errors="replace"):
            f = line.split()
            if len(f) >= 3:
                mods.append({"name": f[0], "size": int(f[1]),
                             "refcount": int(f[2]), "used_by": f[3].split(",") if len(f) > 3 else []})
    except OSError as e:
        return _err("module_list", e)
    return _res("module_list", modules=mods, count=len(mods))


def module_load(args):
    """Load a kernel module via real finit_module/init_module syscall (armed)."""
    name = str(args.get("name", ""))
    params = str(args.get("params", ""))
    if not name:
        return _err("module_load", "need 'name'")
    if not _armed(args):
        return _res("module_load", armed=False, would_load=name, params=params)
    ko = name if name.endswith(".ko") else None
    if ko and os.path.exists(ko):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        fd = os.open(ko, os.O_RDONLY)
        r = libc.finit_module(fd, params.encode(), 0)
        err = ctypes.get_errno()
        os.close(fd)
        if r == 0:
            return _res("module_load", armed=True, loaded=name, method="finit_module")
        return _err("module_load", f"finit_module errno {err}: {os.strerror(err)}")
    rc, out, err2 = _run(["modprobe", name])
    d = _res("module_load", armed=True, applied=(rc == 0), name=name, stderr=err2.strip())
    d["ok"] = rc == 0
    return d


def module_unload(args):
    """Unload a kernel module via real delete_module syscall (armed)."""
    name = str(args.get("name", ""))
    if not name:
        return _err("module_unload", "need 'name'")
    if not _armed(args):
        return _res("module_unload", armed=False, would_unload=name)
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    r = libc.delete_module(name.encode(), os.O_NONBLOCK)
    err = ctypes.get_errno()
    if r == 0:
        return _res("module_unload", armed=True, unloaded=name, method="delete_module")
    return _err("module_unload", f"delete_module errno {err}: {os.strerror(err)}",
                prerequisite="root + refcount 0")


def module_params(args):
    """Read real parameters of a loaded module from /sys/module."""
    name = str(args.get("name", ""))
    if not name:
        return _err("module_params", "need 'name'")
    base = f"/sys/module/{name}"
    if not os.path.isdir(base):
        return _err("module_params", "module not loaded", name=name)
    params = {}
    pdir = os.path.join(base, "parameters")
    if os.path.isdir(pdir):
        for f in sorted(os.listdir(pdir)):
            try:
                params[f] = open(os.path.join(pdir, f), errors="replace").read().strip()
            except OSError:
                pass
    info = {}
    for f in ("refcnt", "coresize", "initstate", "taint"):
        try:
            info[f] = open(os.path.join(base, f)).read().strip()
        except OSError:
            pass
    return _res("module_params", name=name, parameters=params, info=info)


def _tracefs():
    for c in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        if os.path.isdir(c):
            return c
    return None


def kprobe_list(args):
    """List real kprobes/uprobes registered in tracefs."""
    t = _tracefs()
    if not t:
        return _err("kprobe_list", "tracefs not mounted")
    out = {}
    for f in ("kprobe_events", "uprobe_events"):
        try:
            out[f] = open(os.path.join(t, f), errors="replace").read().splitlines()
        except OSError as e:
            out[f] = f"error: {e}"
    return _res("kprobe_list", tracefs=t, events=out)


def kprobe_enable(args):
    """Register a real kprobe in tracefs kprobe_events (armed kernel hook)."""
    spec = str(args.get("spec", ""))
    if not spec:
        return _err("kprobe_enable", "need 'spec' (e.g. 'p:ssb_probe do_sys_open')")
    t = _tracefs()
    if not t:
        return _err("kprobe_enable", "tracefs not mounted")
    if not _armed(args):
        return _res("kprobe_enable", armed=False, would_write=spec, to=t + "/kprobe_events")
    try:
        with open(os.path.join(t, "kprobe_events"), "a") as fh:
            fh.write(spec + "\n")
        return _res("kprobe_enable", armed=True, registered=spec,
                    events=open(os.path.join(t, "kprobe_events")).read().splitlines())
    except (PermissionError, OSError) as e:
        return _err("kprobe_enable", e, prerequisite="root + tracefs")


def kernel_taint_report(args):
    """Decode the real kernel taint flags."""
    flags = {"P": "proprietary module", "F": "force-loaded module", "S": "SMP on non-SMP hw",
             "R": "force-unloaded module", "M": "machine check", "B": "bad page",
             "U": "user-defined", "D": "kernel died", "A": "ACPI override",
             "W": "warning issued", "C": "staging driver", "I": "firmware workaround",
             "O": "out-of-tree module", "E": "unsigned module", "L": "soft lockup",
             "K": "live patch", "X": "aux taint", "T": "struct randomization", "N": "in-kernel test"}
    try:
        taint = open("/proc/sys/kernel/tainted").read().strip()
    except OSError as e:
        return _err("kernel_taint_report", e)
    return _res("kernel_taint_report", tainted_value=taint, flags=flags)


def kptr_restrict_set(args):
    """Read/write kernel.kptr_restrict — controls /proc symbol exposure (armed)."""
    return sysctl_write({"key": "kernel.kptr_restrict",
                         "value": str(args.get("value", "")),
                         "arm": args.get("arm", True)}) if "value" in args \
        else sysctl_read({"key": "kernel.kptr_restrict"})


def dmesg_clear(args):
    """Clear the kernel ring buffer via real klogctl (armed)."""
    if not _armed(args):
        return _res("dmesg_clear", armed=False)
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    SYSLOG_ACTION_CLEAR = 5
    r = libc.klogctl(SYSLOG_ACTION_CLEAR, None, 0) if hasattr(libc, "klogctl") else libc.syscall(103, SYSLOG_ACTION_CLEAR, None, 0)
    err = ctypes.get_errno()
    if r == 0:
        return _res("dmesg_clear", armed=True, cleared=True)
    return _err("dmesg_clear", f"errno {err}: {os.strerror(err)}", prerequisite="root or CAP_SYSLOG")


def cmdline_report(args):
    """Report the real boot kernel command line."""
    try:
        cmd = open("/proc/cmdline").read().strip()
    except OSError as e:
        return _err("cmdline_report", e)
    kv = {}
    for tok in cmd.split():
        if "=" in tok:
            k, v = tok.split("=", 1); kv[k] = v
    return _res("cmdline_report", cmdline=cmd, parsed=kv)


def perf_paranoid_set(args):
    """Read/write kernel.perf_event_paranoid (armed)."""
    if "value" in args:
        return sysctl_write({"key": "kernel.perf_event_paranoid",
                             "value": str(args["value"]), "arm": args.get("arm", True)})
    return sysctl_read({"key": "kernel.perf_event_paranoid"})


def yama_scope_set(args):
    """Read/write kernel.yama.ptrace_scope — ptrace hardening control (armed)."""
    if "value" in args:
        return sysctl_write({"key": "kernel.yama.ptrace_scope",
                             "value": str(args["value"]), "arm": args.get("arm", True)})
    return sysctl_read({"key": "kernel.yama.ptrace_scope"})


POWERS = {f"nm21.kernctl.{fn.__name__}": fn for fn in
          (sysctl_read, sysctl_write, sysctl_dump, module_list, module_load,
           module_unload, module_params, kprobe_list, kprobe_enable,
           kernel_taint_report, kptr_restrict_set, dmesg_clear, cmdline_report,
           perf_paranoid_set, yama_scope_set)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
