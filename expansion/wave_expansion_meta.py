# SSB ULTRA Wave-Expansion Module — domain: meta (nm20.meta.* / nm20.act.*)
# Pure Python 3 stdlib. Import-safe: no side effects at import.
# The godscope meta layer: powers that operate on the SSB system itself —
# self-introspection, activation chaining, journaling, checkpoints,
# capability scoring, environment snapshots, and artifact lifecycle.
# Everything here is REAL: /proc reads, /tmp artifacts, real microbenches,
# real chained execution of sibling powers.

import glob
import importlib
import json
import locale
import os
import platform
import resource
import signal
import sys
import threading
import time

_DOMAIN = "meta"
_PLATFORM = sys.platform
_TMP = "/tmp"
_JOURNAL = os.path.join(_TMP, "ssb_meta_journal.jsonl")
_WATCHDOG = os.path.join(_TMP, "ssb_meta_watchdog.json")
_SNAPSHOT = os.path.join(_TMP, "ssb_meta_env_snapshot.json")


def _res(power, ns="meta", **kw):
    """Build the standard SSB-style result envelope."""
    d = {"ok": True, "power": "nm20.%s.%s" % (ns, power), "platform": _PLATFORM}
    d.update(kw)
    return d


def _err(power, msg, ns="meta", **kw):
    d = _res(power, ns=ns, ok=False, error=msg)
    d.update(kw)
    return d


def _read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def _read_ok(path):
    try:
        return _read(path)
    except OSError:
        return None


def _read_strip(path):
    t = _read_ok(path)
    return t.strip() if t is not None else None


def _read_int(path):
    t = _read_strip(path)
    try:
        return int(t)
    except (TypeError, ValueError):
        return None


def _status_map(path="/proc/self/status"):
    txt = _read_ok(path)
    d = {}
    if txt:
        for line in txt.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                d[k.strip()] = v.strip()
    return d


def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True, default=str)
    return os.path.getsize(path)


# ---------------------------------------------------------------------------
# INTROSPECTION POWERS
# ---------------------------------------------------------------------------

def power_audit(args):
    """REAL: inspect this module's POWERS dict and report every power name, namespace and docstring."""
    rows = []
    for name in sorted(POWERS):
        fn = POWERS[name]
        parts = name.split(".")
        doc = (fn.__doc__ or "").strip().splitlines()
        rows.append({
            "power": name,
            "namespace": parts[1] if len(parts) > 2 else "?",
            "callable": callable(fn),
            "doc": doc[0] if doc else "(no docstring)",
        })
    ns_counts = {}
    for r in rows:
        ns_counts[r["namespace"]] = ns_counts.get(r["namespace"], 0) + 1
    bad = [r["power"] for r in rows if not r["callable"] or r["doc"] == "(no docstring)"]
    return _res("power_audit", total=len(rows), namespaces=ns_counts,
                all_callable=not any(not r["callable"] for r in rows),
                all_documented=not any(r["doc"] == "(no docstring)" for r in rows),
                anomalies=bad, powers=rows)


def module_counter(args):
    """REAL: count and classify sys.modules, builtins, finders and SSB wave modules currently loaded."""
    mods = list(sys.modules.keys())
    builtins = set(sys.builtin_module_names)
    loaded_builtins = [m for m in mods if m in builtins]
    wave = sorted(m for m in mods if "wave_expansion" in m or m.startswith("nm20"))
    top_levels = sorted({m.split(".")[0] for m in mods if m})
    return _res("module_counter",
                sys_modules_total=len(mods),
                builtin_module_names=len(builtins),
                builtins_loaded=len(loaded_builtins),
                distinct_top_level=len(top_levels),
                wave_modules_loaded=wave,
                meta_path_finders=len(sys.meta_path),
                path_hooks=len(sys.path_hooks),
                sys_path_entries=len(sys.path),
                sample_top_level=top_levels[:40])


def scope_expand(args):
    """REAL: return the full SSB layer taxonomy kernel->ai with live power counts per expansion module."""
    layers = [
        {"layer": 0, "name": "kernel",   "module": "wave_expansion_kernel",
         "role": "ring0 syscalls, modules, eBPF, boot, kallsyms"},
        {"layer": 1, "name": "hw",       "module": "wave_expansion_hw",
         "role": "cpu/pci/usb/dmi/tpm/uefi/msr hardware surface"},
        {"layer": 2, "name": "memproc",  "module": "wave_expansion_memproc",
         "role": "process and memory introspection, maps, injection"},
        {"layer": 3, "name": "net",      "module": "wave_expansion_net",
         "role": "sockets, routes, packet capture, tunneling"},
        {"layer": 4, "name": "persist",  "module": "wave_expansion_persist",
         "role": "systemd, cron, rc, boot persistence and daemons"},
        {"layer": 5, "name": "cred",     "module": "wave_expansion_cred",
         "role": "credential stores, shadow, ssh, keyrings"},
        {"layer": 6, "name": "evade",    "module": "wave_expansion_evade",
         "role": "log tampering, timestomp, anti-forensics, cloaking"},
        {"layer": 7, "name": "cloud",    "module": "wave_expansion_cloud",
         "role": "cloud metadata, containers, virtualization escape"},
        {"layer": 8, "name": "win",      "module": "wave_expansion_win",
         "role": "windows registry, services, AD, registry artifacts"},
        {"layer": 9, "name": "llm",      "module": "wave_expansion_llm",
         "role": "ai layer: prompts, agents, swarm orchestration"},
        {"layer": 10, "name": "meta",    "module": "wave_expansion_meta",
         "role": "godscope meta layer: self-introspection, activation chains"},
    ]
    base = os.path.dirname(os.path.abspath(__file__))
    if base not in sys.path:
        sys.path.insert(0, base)
    total = 0
    for L in layers:
        try:
            mod = importlib.import_module(L["module"])
            n = len(getattr(mod, "POWERS", {}))
            L["powers"] = n
            L["count_source"] = "live_import"
        except Exception as e:
            L["powers"] = None
            L["count_source"] = "unavailable"
            L["import_error"] = "%s: %s" % (type(e).__name__, e)
        if isinstance(L["powers"], int):
            total += L["powers"]
    return _res("scope_expand", layers=layers, layer_count=len(layers),
                total_expansion_powers=total,
                note=("layers 0-9 ascend kernel->ai; layer 10 (meta) operates on "
                      "the SSB system itself; counts are live imports of sibling "
                      "modules when present on sys.path"))


# ---------------------------------------------------------------------------
# ACTIVATION POWERS (nm20.act.*)
# ---------------------------------------------------------------------------

CHAINS = {
    "baseline": [
        "nm20.meta.capability_matrix",
        "nm20.meta.env_snapshot",
        "nm20.meta.resource_governor",
    ],
    "introspect": [
        "nm20.meta.power_audit",
        "nm20.meta.module_counter",
        "nm20.meta.thread_audit",
        "nm20.meta.fd_audit",
    ],
    "hygiene": [
        "nm20.meta.entropy_health",
        "nm20.meta.self_heal_check",
        "nm20.meta.watchdog_ping",
    ],
    "pulse": [
        "nm20.meta.watchdog_ping",
        "nm20.meta.journal",
    ],
}


def activation_chain(args):
    """REAL: run a named chain of powers sequentially, passing each result forward into the next step."""
    name = str(args.get("chain", "baseline"))
    if name not in CHAINS:
        return _err("activation_chain", "unknown chain %r" % name, ns="act",
                    known_chains=sorted(CHAINS))
    steps = CHAINS[name]
    step_args = args.get("step_args")
    if not isinstance(step_args, dict):
        step_args = {}
    continue_on_error = bool(args.get("continue_on_error"))
    results = []
    prev = None
    for i, full in enumerate(steps):
        fn = POWERS.get(full)
        if fn is None or fn is activation_chain or fn is chain_list:
            r = {"ok": False, "power": full, "platform": _PLATFORM,
                 "error": "power not chain-callable (missing or recursive)"}
        else:
            call_args = dict(step_args)
            call_args.update({"chain": name, "step": i,
                              "input": prev,
                              "input_power": prev.get("power") if isinstance(prev, dict) else None})
            t0 = time.perf_counter()
            try:
                r = fn(call_args)
            except Exception as e:
                r = {"ok": False, "power": full, "platform": _PLATFORM,
                     "error": "%s: %s" % (type(e).__name__, e)}
            r = dict(r)
            r["step_seconds"] = round(time.perf_counter() - t0, 6)
        results.append(r)
        prev = r
        if not r.get("ok") and not continue_on_error:
            break
    all_ok = all(r.get("ok") for r in results)
    return _res("activation_chain", ns="act", chain=name,
                steps_total=len(steps), steps_run=len(results),
                all_ok=all_ok, results=results)


def chain_list(args):
    """REAL: list all defined activation chains with their steps and each step's docstring."""
    out = []
    for name in sorted(CHAINS):
        steps = []
        for full in CHAINS[name]:
            fn = POWERS.get(full)
            doc = (getattr(fn, "__doc__", "") or "").strip().splitlines()
            steps.append({"power": full,
                          "available": fn is not None,
                          "doc": doc[0] if doc else "(no docstring)"})
        out.append({"chain": name, "steps": steps, "length": len(steps)})
    return _res("chain_list", ns="act", chains=out, chain_count=len(out),
                usage='nm20.act.activation_chain({"chain": "baseline"})')


# ---------------------------------------------------------------------------
# ENVIRONMENT / CAPABILITY POWERS
# ---------------------------------------------------------------------------

_CAP_NAMES = {
    0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER",
    4: "FSETID", 5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP",
    9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_BROADCAST",
    12: "NET_ADMIN", 13: "NET_RAW", 14: "IPC_LOCK", 15: "IPC_OWNER",
    16: "SYS_MODULE", 17: "SYS_RAWIO", 18: "SYS_CHROOT", 19: "SYS_PTRACE",
    20: "SYS_PACCT", 21: "SYS_ADMIN", 22: "SYS_BOOT", 23: "SYS_NICE",
    24: "SYS_RESOURCE", 25: "SYS_TIME", 26: "SYS_TTY_CONFIG", 27: "MKNOD",
    28: "LEASE", 29: "AUDIT_WRITE", 30: "AUDIT_CONTROL", 31: "SETFCAP",
    32: "MAC_OVERRIDE", 33: "MAC_ADMIN", 34: "SYSLOG", 35: "WAKE_ALARM",
    36: "BLOCK_SUSPEND", 37: "AUDIT_READ", 38: "PERFMON", 39: "BPF",
    40: "CHECKPOINT_RESTORE",
}


def _effective_caps():
    st = _status_map()
    hexeff = st.get("CapEff")
    if not hexeff:
        return None
    try:
        val = int(hexeff, 16)
    except ValueError:
        return None
    return sorted(name for bit, name in _CAP_NAMES.items() if val & (1 << bit))


def capability_matrix(args):
    """REAL: probe the local environment (root, cgroup, net, ptrace, bpf, seccomp...) into a scored capability report."""
    caps = _effective_caps() or []
    probes = []

    euid = os.geteuid() if hasattr(os, "geteuid") else None
    probes.append({"probe": "root", "score": 2 if euid == 0 else (1 if "SETUID" in caps else 0),
                   "detail": "euid=%s" % euid})

    cg = _read_ok("/proc/self/cgroup") or ""
    v2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
    cg_writable = os.access("/sys/fs/cgroup", os.W_OK)
    probes.append({"probe": "cgroup",
                   "score": 2 if (v2 and cg_writable) else (1 if cg else 0),
                   "detail": "v2=%s cgroup_writable=%s lines=%d" % (v2, cg_writable, len(cg.splitlines()))})

    route = _read_ok("/proc/net/route") or ""
    default_route = any(l.split("\t")[1] == "00000000" for l in route.splitlines()[1:] if "\t" in l)
    net_score = 2 if default_route else (1 if os.path.exists("/proc/net/dev") else 0)
    probes.append({"probe": "net", "score": net_score,
                   "detail": "default_route=%s raw_sock_cap=%s" % (default_route, "NET_RAW" in caps)})

    ptrace_scope = _read_int("/proc/sys/kernel/yama/ptrace_scope")
    pscore = 2 if "SYS_PTRACE" in caps else (1 if ptrace_scope in (0, None) else 0)
    probes.append({"probe": "ptrace",
                   "score": pscore,
                   "detail": "yama_ptrace_scope=%s cap_sys_ptrace=%s" % (ptrace_scope, "SYS_PTRACE" in caps)})

    bpf_jit = _read_int("/proc/sys/net/core/bpf_jit_enable")
    unpriv_bpf = _read_int("/proc/sys/kernel/unprivileged_bpf_disabled")
    bpf_score = 2 if ("BPF" in caps or "SYS_ADMIN" in caps) else (1 if unpriv_bpf == 0 else 0)
    probes.append({"probe": "bpf",
                   "score": bpf_score,
                   "detail": "jit=%s unprivileged_bpf_disabled=%s cap_bpf=%s" % (bpf_jit, unpriv_bpf, "BPF" in caps)})

    st = _status_map()
    seccomp = st.get("Seccomp")
    # capability view: NO seccomp filter (mode 0) = full syscall surface = score 2
    probes.append({"probe": "seccomp",
                   "score": 2 if seccomp and seccomp.startswith("0") else (0 if seccomp and seccomp.startswith("1") else 1),
                   "detail": "seccomp_mode=%s (0=unconfined,1=strict,2=filter)" % seccomp})

    ns_entries = sorted(os.listdir("/proc/self/ns")) if os.path.isdir("/proc/self/ns") else []
    max_userns = _read_int("/proc/sys/user/max_user_namespaces")
    probes.append({"probe": "namespaces",
                   "score": 2 if (max_userns and max_userns > 0) else (1 if ns_entries else 0),
                   "detail": "ns=%s max_user_namespaces=%s" % (",".join(ns_entries), max_userns)})

    lsm = _read_strip("/proc/self/attr/current")
    selinux = os.path.isdir("/sys/fs/selinux")
    apparmor = os.path.isdir("/sys/kernel/security/apparmor") or (lsm is not None and "apparmor" in lsm.lower())
    probes.append({"probe": "lsm",
                   "score": 0 if (selinux or apparmor) else 2,
                   "detail": "selinux=%s apparmor=%s current_label=%r" % (selinux, apparmor, lsm)})

    kptr = _read_int("/proc/sys/kernel/kptr_restrict")
    kallsyms = _read_ok("/proc/kallsyms") or ""
    nonzero_syms = sum(1 for l in kallsyms.splitlines()[:200]
                       if l and not l.split()[0].startswith("0000000000000000"))
    probes.append({"probe": "kptr",
                   "score": 2 if nonzero_syms > 0 else 0,
                   "detail": "kptr_restrict=%s sampled_nonzero_kallsyms=%d/200" % (kptr, nonzero_syms)})

    perf_par = _read_int("/proc/sys/kernel/perf_event_paranoid")
    probes.append({"probe": "perf",
                   "score": 2 if (perf_par is not None and perf_par <= 1) or "PERFMON" in caps else (1 if perf_par == 2 else 0),
                   "detail": "perf_event_paranoid=%s cap_perfmon=%s" % (perf_par, "PERFMON" in caps)})

    modules = _read_ok("/proc/modules")
    probes.append({"probe": "modules",
                   "score": 2 if ("SYS_MODULE" in caps) else (1 if modules else 0),
                   "detail": "proc_modules_readable=%s cap_sys_module=%s" % (modules is not None, "SYS_MODULE" in caps)})

    total = sum(p["score"] for p in probes)
    mx = 2 * len(probes)
    pct = round(100.0 * total / mx, 1) if mx else 0.0
    grade = ("godmode" if pct >= 90 else "high" if pct >= 70 else
             "medium" if pct >= 40 else "low" if pct >= 15 else "sandboxed")
    return _res("capability_matrix", probes=probes, score=total, max_score=mx,
                percent=pct, grade=grade, effective_capabilities=caps,
                note="score 0=denied 1=partial 2=full, per probe")


def env_snapshot(args):
    """REAL: full uname/rlimits/mounts/env summary, written as JSON artifact to /tmp."""
    un = platform.uname()
    limits = {}
    for rn in ("RLIMIT_NOFILE", "RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_NPROC",
               "RLIMIT_CORE", "RLIMIT_MEMLOCK", "RLIMIT_STACK"):
        r = getattr(resource, rn, None)
        if r is not None:
            try:
                soft, hard = resource.getrlimit(r)
                limits[rn] = {"soft": soft, "hard": hard}
            except (OSError, ValueError):
                limits[rn] = None
    mounts = []
    mt = _read_ok("/proc/mounts")
    if mt:
        for line in mt.splitlines():
            p = line.split()
            if len(p) >= 3:
                mounts.append({"dev": p[0], "mountpoint": p[1], "fstype": p[2]})
    env = dict(sorted(os.environ.items()))
    snap = {
        "ts": time.time(),
        "pid": os.getpid(),
        "uname": {"system": un.system, "node": un.node, "release": un.release,
                  "version": un.version, "machine": un.machine},
        "python": {"version": sys.version.split()[0], "executable": sys.executable},
        "rlimits": limits,
        "mounts_total": len(mounts),
        "mounts": mounts[: int(args.get("mount_cap", 60))],
        "env": env,
    }
    size = _write_json(_SNAPSHOT, snap)
    return _res("env_snapshot", artifact=_SNAPSHOT, bytes_written=size,
                mounts_total=len(mounts), env_vars=len(env),
                rlimits=limits, system=un.system, release=un.release,
                note="full snapshot including env written to artifact")


def locale_env(args):
    """REAL: report LANG/LC_* environment, active locale, and preferred encodings."""
    lc = {k: v for k, v in sorted(os.environ.items())
          if k == "LANG" or k == "LANGUAGE" or k.startswith("LC_")}
    try:
        cur = locale.getlocale()
    except ValueError as e:
        cur = "error: %s" % e
    try:
        pref = locale.getpreferredencoding(False)
    except Exception as e:
        pref = "error: %s" % e
    out = _res("locale_env", locale_env=lc, getlocale=cur,
               preferred_encoding=pref,
               filesystem_encoding=sys.getfilesystemencoding(),
                stdin_encoding=getattr(sys.stdin, "encoding", None),
                stdout_encoding=getattr(sys.stdout, "encoding", None))
    try:
        out["locale_encoding"] = locale.getencoding()  # py3.11+
    except AttributeError:
        out["locale_encoding"] = None
    return out


# ---------------------------------------------------------------------------
# JOURNAL / STATE / LIFECYCLE POWERS
# ---------------------------------------------------------------------------

def journal(args):
    """REAL: append a structured event to /tmp/ssb_meta_journal.jsonl and read it back."""
    event = args.get("event")
    if not isinstance(event, dict):
        event = {"note": str(event) if event is not None else "heartbeat",
                 "from_chain": args.get("chain")}
    entry = {
        "ts": time.time(),
        "monotonic": time.monotonic(),
        "pid": os.getpid(),
        "tag": str(args.get("tag", "ssb")),
        "input_power": args.get("input_power"),
        "event": event,
    }
    try:
        entry = json.loads(json.dumps(entry, default=str))  # force JSON-safe
    except (TypeError, ValueError) as e:
        return _err("journal", "event not JSON-serializable: %s" % e)
    try:
        with open(_JOURNAL, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError as e:
        return _err("journal", "append failed: %s" % e, path=_JOURNAL)
    total = 0
    try:
        with open(_JOURNAL) as f:
            for total, _ in enumerate(f, 1):
                pass
    except OSError:
        pass
    return _res("journal", path=_JOURNAL, entry=entry, total_entries=total)


def journal_tail(args):
    """REAL: read back the last N structured events from the meta journal."""
    try:
        n = max(1, min(int(args.get("n", 10)), 500))
    except (TypeError, ValueError):
        n = 10
    if not os.path.exists(_JOURNAL):
        return _res("journal_tail", path=_JOURNAL, entries=[], total=0,
                    note="journal does not exist yet (run nm20.meta.journal first)")
    entries = []
    total = 0
    malformed = 0
    try:
        with open(_JOURNAL) as f:
            for line in f:
                total += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    malformed += 1
    except OSError as e:
        return _err("journal_tail", "read failed: %s" % e, path=_JOURNAL)
    return _res("journal_tail", path=_JOURNAL, total=total, malformed=malformed,
                returned=min(n, len(entries)), entries=entries[-n:])


def state_checkpoint(args):
    """REAL: pickle-free JSON checkpoint save/load of a dict argument to /tmp."""
    mode = str(args.get("mode", "save")).lower()
    name = "".join(c for c in str(args.get("name", "default")) if c.isalnum() or c in "-_")[:64] or "default"
    path = os.path.join(_TMP, "ssb_meta_ckpt_%s.json" % name)
    if mode == "save":
        state = args.get("state")
        if not isinstance(state, dict):
            return _err("state_checkpoint", "mode=save requires args['state'] dict", path=path)
        blob = {"ts": time.time(), "pid": os.getpid(), "name": name, "state": state}
        try:
            blob = json.loads(json.dumps(blob, default=str))
            size = _write_json(path, blob)
        except (TypeError, ValueError, OSError) as e:
            return _err("state_checkpoint", "save failed: %s" % e, path=path)
        return _res("state_checkpoint", mode="save", name=name, path=path,
                    bytes_written=size, keys=sorted(state.keys()))
    if mode == "load":
        try:
            with open(path) as f:
                blob = json.load(f)
        except FileNotFoundError:
            return _err("state_checkpoint", "no checkpoint named %r" % name, path=path)
        except (ValueError, OSError) as e:
            return _err("state_checkpoint", "load failed: %s" % e, path=path)
        return _res("state_checkpoint", mode="load", name=name, path=path,
                    saved_ts=blob.get("ts"), saved_pid=blob.get("pid"),
                    age_seconds=round(time.time() - blob.get("ts", time.time()), 3),
                    state=blob.get("state"))
    return _err("state_checkpoint", "mode must be 'save' or 'load'", path=path)


def self_heal_check(args):
    """REAL: verify critical temp dirs/files the meta layer relies on; recreate anything missing."""
    healed = []
    healthy = []
    problems = []

    if os.path.isdir(_TMP) and os.access(_TMP, os.W_OK):
        healthy.append(_TMP)
    else:
        try:
            os.makedirs(_TMP, exist_ok=True)
            healed.append(_TMP)
        except OSError as e:
            problems.append("%s: %s" % (_TMP, e))

    meta_dir = os.path.join(_TMP, "ssb_meta")
    if os.path.isdir(meta_dir):
        healthy.append(meta_dir)
    else:
        try:
            os.makedirs(meta_dir, exist_ok=True)
            healed.append(meta_dir)
        except OSError as e:
            problems.append("%s: %s" % (meta_dir, e))

    if os.path.exists(_JOURNAL):
        healthy.append(_JOURNAL)
    else:
        try:
            with open(_JOURNAL, "a"):
                pass
            healed.append(_JOURNAL + " (touched into existence)")
        except OSError as e:
            problems.append("%s: %s" % (_JOURNAL, e))

    disk = None
    try:
        import shutil
        du = shutil.disk_usage(_TMP)
        disk = {"total": du.total, "used": du.used, "free": du.free,
                "free_percent": round(100.0 * du.free / du.total, 1)}
        if du.free < 64 * 1024 * 1024:
            problems.append("low disk: only %d bytes free on %s" % (du.free, _TMP))
    except OSError as e:
        problems.append("disk_usage failed: %s" % e)

    writable = False
    probe = os.path.join(_TMP, ".ssb_meta_probe")
    try:
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        writable = True
    except OSError as e:
        problems.append("tmp not writable: %s" % e)

    return _res("self_heal_check", healed=healed, healthy=healthy,
                problems=problems, disk=disk, tmp_writable=writable,
                ok=not problems)


def watchdog_ping(args):
    """REAL: touch a /tmp heartbeat file carrying monotonic stats; reports delta since last ping."""
    now_mono = time.monotonic()
    now_wall = time.time()
    prev = None
    if os.path.exists(_WATCHDOG):
        try:
            with open(_WATCHDOG) as f:
                prev = json.load(f)
        except (ValueError, OSError):
            prev = None
    try:
        loadavg = list(os.getloadavg())
    except OSError:
        loadavg = None
    st = _status_map()
    beat = {
        "ts": now_wall, "monotonic": now_mono, "pid": os.getpid(),
        "threads": threading.active_count(),
        "loadavg": loadavg,
        "vmrss_kb": (st.get("VmRSS") or "").split()[0] or None,
        "uptime_s": None,
    }
    up = _read_ok("/proc/uptime")
    if up:
        try:
            beat["uptime_s"] = float(up.split()[0])
        except (ValueError, IndexError):
            pass
    size = _write_json(_WATCHDOG, beat)
    delta = None
    if prev and isinstance(prev.get("monotonic"), (int, float)):
        delta = round(now_mono - prev["monotonic"], 6)
    return _res("watchdog_ping", path=_WATCHDOG, bytes_written=size,
                beat=beat, previous_beat=prev,
                seconds_since_last_ping=delta)


def panic_button(args):
    """REAL: enumerate and (only when arm=true) remove all /tmp/ssb_* artifacts created by SSB waves."""
    targets = sorted(glob.glob(os.path.join(_TMP, "ssb_*")))
    inventory = []
    total_bytes = 0
    for t in targets:
        try:
            sz = os.path.getsize(t) if os.path.isfile(t) else 0
        except OSError:
            sz = 0
        total_bytes += sz
        inventory.append({"path": t, "is_dir": os.path.isdir(t), "bytes": sz})
    out = _res("panic_button", armed=False, targets=inventory,
               target_count=len(inventory), total_bytes=total_bytes,
               would_do="delete every /tmp/ssb_* artifact (files unlinked, dirs rmtree'd)")
    if args.get("arm", True):
        out["armed"] = True
        removed, failed = [], []
        import shutil
        for t in targets:
            try:
                if os.path.isdir(t) and not os.path.islink(t):
                    shutil.rmtree(t)
                else:
                    os.remove(t)
                removed.append(t)
            except OSError as e:
                failed.append({"path": t, "error": str(e)})
        out["removed"] = removed
        out["removed_count"] = len(removed)
        out["failed"] = failed
        out["ok"] = not failed
    return out


# ---------------------------------------------------------------------------
# RUNTIME / RESOURCE AUDIT POWERS
# ---------------------------------------------------------------------------

def resource_governor(args):
    """REAL: report rlimit ceilings vs live usage (fds, RSS, threads) and emit concrete tuning suggestions."""
    limits = {}
    for rn in ("RLIMIT_NOFILE", "RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_NPROC",
               "RLIMIT_CORE", "RLIMIT_MEMLOCK", "RLIMIT_STACK"):
        r = getattr(resource, rn, None)
        if r is not None:
            try:
                soft, hard = resource.getrlimit(r)
                limits[rn] = {"soft": soft, "hard": hard,
                              "soft_inf": soft == resource.RLIM_INFINITY}
            except (OSError, ValueError):
                limits[rn] = None
    usage = {}
    try:
        usage["fds_open"] = len(os.listdir("/proc/self/fd"))
    except OSError:
        usage["fds_open"] = None
    st = _status_map()
    for k in ("VmRSS", "VmSize", "Threads"):
        v = st.get(k)
        if v:
            usage[k.lower()] = v
    suggestions = []
    nofile = limits.get("RLIMIT_NOFILE")
    if nofile and usage["fds_open"] is not None and not nofile["soft_inf"]:
        pct = 100.0 * usage["fds_open"] / max(nofile["soft"], 1)
        usage["fds_percent_of_soft"] = round(pct, 2)
        if pct > 70:
            suggestions.append("fd usage at %.1f%% of RLIMIT_NOFILE soft (%d) — raise with "
                               "resource.setrlimit or ulimit -n" % (pct, nofile["soft"]))
    aslim = limits.get("RLIMIT_AS")
    try:
        rss_kb = int((st.get("VmRSS") or "0 kB").split()[0])
        if aslim and not aslim["soft_inf"] and rss_kb * 1024 > 0.7 * aslim["soft"]:
            suggestions.append("VmRSS exceeds 70%% of RLIMIT_AS soft (%d)" % aslim["soft"])
    except (ValueError, IndexError):
        rss_kb = None
    core = limits.get("RLIMIT_CORE")
    if core and core["soft"] == 0:
        suggestions.append("core dumps disabled (RLIMIT_CORE=0) — set >0 if postmortem debugging is wanted")
    if not suggestions:
        suggestions.append("all usage well within limits; no action needed")
    return _res("resource_governor", limits=limits, usage=usage,
                suggestions=suggestions)


def fd_audit(args):
    """REAL: inventory /proc/self/fd — targets, types (file/socket/pipe/anon) and open flags."""
    base = "/proc/self/fd"
    if not os.path.isdir(base):
        return _err("fd_audit", "/proc/self/fd unavailable on this platform")
    inv = []
    by_type = {}
    try:
        fds = sorted(os.listdir(base), key=lambda s: int(s))
    except OSError as e:
        return _err("fd_audit", "listdir failed: %s" % e)
    for fd in fds:
        try:
            target = os.readlink(os.path.join(base, fd))
        except OSError as e:
            target = "<error: %s>" % e
        if target.startswith("socket:["):
            ftype = "socket"
        elif target.startswith("pipe:["):
            ftype = "pipe"
        elif target.startswith("anon_inode:"):
            ftype = "anon_inode"
        elif target.startswith("/"):
            ftype = "file"
        else:
            ftype = "other"
        by_type[ftype] = by_type.get(ftype, 0) + 1
        entry = {"fd": int(fd), "type": ftype, "target": target}
        info = _read_ok("/proc/self/fdinfo/%s" % fd)
        if info:
            for line in info.splitlines():
                if line.startswith("flags:"):
                    try:
                        entry["flags_octal"] = oct(int(line.split()[1], 8))
                    except (ValueError, IndexError):
                        pass
        inv.append(entry)
    soft = hard = None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        pass
    return _res("fd_audit", total=len(inv), by_type=by_type, fds=inv,
                rlimit_nofile={"soft": soft, "hard": hard})


def thread_audit(args):
    """REAL: enumerate live threads via /proc/self/task and the threading module, with names and states."""
    tasks = []
    base = "/proc/self/task"
    if os.path.isdir(base):
        for tid in sorted(os.listdir(base), key=lambda s: int(s)):
            comm = _read_strip(os.path.join(base, tid, "comm"))
            st = _status_map(os.path.join(base, tid, "status"))
            tasks.append({"tid": int(tid), "comm": comm,
                          "state": (st.get("State") or "").split("(", 1)[0].strip() or None,
                          "voluntary_ctxt_switches": st.get("voluntary_ctxt_switches")})
    else:
        tasks = None
    py_threads = [{"name": t.name, "ident": t.ident, "daemon": t.daemon,
                   "alive": t.is_alive()} for t in threading.enumerate()]
    return _res("thread_audit", os_thread_count=len(tasks) if tasks is not None else None,
                os_threads=tasks, python_thread_count=len(py_threads),
                python_threads=py_threads)


def signal_map(args):
    """REAL: map every valid signal to its current handler (default/ignored/custom)."""
    table = []
    counts = {"default": 0, "ignored": 0, "custom": 0, "unknown": 0}
    for sig in sorted(signal.valid_signals(), key=int):
        try:
            h = signal.getsignal(sig)
        except (OSError, ValueError, RuntimeError):
            h = None
        if h == signal.SIG_DFL:
            kind = "default"
        elif h == signal.SIG_IGN:
            kind = "ignored"
        elif callable(h):
            kind = "custom"
        else:
            kind = "unknown"
        counts[kind] += 1
        name = getattr(sig, "name", None) or str(sig)
        handler_desc = (getattr(h, "__qualname__", None) or str(h)) if callable(h) else None
        table.append({"signal": int(sig), "name": name, "disposition": kind,
                      "handler": handler_desc})
    custom = [t for t in table if t["disposition"] == "custom"]
    return _res("signal_map", signals=table, counts=counts,
                custom_handlers=custom,
                note="custom handlers visible here belong to this python process/runtime")


def path_audit(args):
    """REAL: check every PATH entry for existence and writability (hijack risk), counting executables."""
    path_env = os.environ.get("PATH", os.defpath)
    entries = []
    writable_dirs = 0
    seen = set()
    for d in path_env.split(os.pathsep):
        d = d or "."
        real = os.path.realpath(d)
        exists = os.path.isdir(d)
        writable = os.access(d, os.W_OK) if exists else False
        exec_count = None
        if exists:
            try:
                exec_count = sum(1 for n in os.listdir(d)
                                 if os.path.isfile(os.path.join(d, n))
                                 and os.access(os.path.join(d, n), os.X_OK))
            except OSError:
                exec_count = None
        if writable:
            writable_dirs += 1
        entries.append({"dir": d, "realpath": real, "exists": exists,
                        "writable": writable, "duplicated": real in seen,
                        "executables": exec_count})
        seen.add(real)
    return _res("path_audit", path=path_env, entries=entries,
                entry_count=len(entries), writable_dirs=writable_dirs,
                risk=("PATH contains %d user-writable dir(s) — binary hijack possible "
                      "by any process running as this user" % writable_dirs)
                if writable_dirs else "no writable PATH dirs for this euid")


def version_oracle(args):
    """REAL: report python implementation/version, platform, machine and libc version (ctypes)."""
    libc_name, libc_ver = platform.libc_ver()
    libc_rt = None
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        fn = getattr(libc, "gnu_get_libc_version", None)
        if fn:
            fn.restype = ctypes.c_char_p
            libc_rt = fn().decode()
    except Exception as e:
        libc_rt = "unavailable: %s" % e
    un = platform.uname()
    return _res("version_oracle",
                python={"implementation": platform.python_implementation(),
                        "version": platform.python_version(),
                        "version_info": list(sys.version_info),
                        "api_version": sys.api_version,
                        "executable": sys.executable},
                platform={"platform": platform.platform(),
                          "system": un.system, "release": un.release,
                          "machine": un.machine, "processor": un.processor,
                          "byteorder": sys.byteorder,
                          "bits": 64 if sys.maxsize > 2 ** 32 else 32},
                libc={"libc_ver": libc_ver, "name": libc_name,
                      "runtime_gnu_version": libc_rt})


# ---------------------------------------------------------------------------
# LIVE BENCH / HEALTH POWERS
# ---------------------------------------------------------------------------

def timing_bench(args):
    """REAL: quick cpu/mem/io microbenchmark writing a real scratch file under /tmp."""
    out = {}

    n = int(args.get("cpu_iters", 1000000))
    t0 = time.perf_counter()
    s = 0
    for i in range(n):
        s += i * i
    cpu_s = time.perf_counter() - t0
    out["cpu"] = {"iters": n, "seconds": round(cpu_s, 6),
                  "mops_per_sec": round(n / max(cpu_s, 1e-9) / 1e6, 2),
                  "sink": s % 1000}

    mbytes = int(args.get("mem_mb", 16))
    mbytes = max(1, min(mbytes, 256))
    t0 = time.perf_counter()
    ba = bytearray(mbytes * 1024 * 1024)
    mv = memoryview(ba)
    for off in range(0, len(mv), 4096):
        mv[off] = 1
    mem_s = time.perf_counter() - t0
    del mv, ba
    out["memory"] = {"mb_touched": mbytes, "seconds": round(mem_s, 6),
                     "gb_per_sec": round(mbytes / 1024.0 / max(mem_s, 1e-9), 3)}

    io_mb = int(args.get("io_mb", 4))
    io_mb = max(1, min(io_mb, 64))
    block = b"\xA5" * 1024 * 1024
    path = os.path.join(_TMP, "ssb_meta_bench.bin")
    try:
        t0 = time.perf_counter()
        with open(path, "wb") as f:
            for _ in range(io_mb):
                f.write(block)
            f.flush()
            os.fsync(f.fileno())
        w_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        with open(path, "rb") as f:
            while f.read(1024 * 1024):
                pass
        r_s = time.perf_counter() - t0
        out["io"] = {"mb": io_mb, "write_seconds": round(w_s, 6),
                     "read_seconds": round(r_s, 6),
                     "write_mb_per_sec": round(io_mb / max(w_s, 1e-9), 2),
                     "read_mb_per_sec": round(io_mb / max(r_s, 1e-9), 2),
                     "scratch": path}
    except OSError as e:
        out["io"] = {"error": str(e), "scratch": path}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    out["total_seconds"] = round(cpu_s + mem_s + out.get("io", {}).get("write_seconds", 0)
                                 + out.get("io", {}).get("read_seconds", 0), 6)
    return _res("timing_bench", bench=out)


def entropy_health(args):
    """REAL: sample os.urandom, run byte-frequency stats (chi-square) and read kernel entropy pool."""
    samples = max(1, min(int(args.get("samples", 4)), 16))
    size = max(256, min(int(args.get("size", 4096)), 65536))
    hist = [0] * 256
    timings = []
    total = 0
    for _ in range(samples):
        t0 = time.perf_counter()
        buf = os.urandom(size)
        timings.append(round(time.perf_counter() - t0, 6))
        total += len(buf)
        for b in buf:
            hist[b] += 1
    expected = total / 256.0
    chi2 = sum((c - expected) ** 2 / expected for c in hist) if expected else 0.0
    distinct = sum(1 for c in hist if c > 0)
    entropy_avail = _read_int("/proc/sys/kernel/random/entropy_avail")
    poolsize = _read_int("/proc/sys/kernel/random/poolsize")
    healthy = chi2 < 400.0 and distinct >= 240
    return _res("entropy_health", bytes_sampled=total, samples=samples,
                sample_timings=timings,
                chi_square=round(chi2, 2), chi_square_expected=255.0,
                distinct_byte_values=distinct,
                min_byte_count=min(hist), max_byte_count=max(hist),
                kernel_entropy_avail=entropy_avail, kernel_poolsize=poolsize,
                healthy=healthy,
                note="chi-square ~255 with df=255 is expected for uniform random; "
                     ">>400 would suggest bias")


POWERS = {
    # meta: self-introspection + environment
    "nm20.meta.power_audit": power_audit,
    "nm20.meta.module_counter": module_counter,
    "nm20.meta.scope_expand": scope_expand,
    "nm20.meta.capability_matrix": capability_matrix,
    "nm20.meta.env_snapshot": env_snapshot,
    "nm20.meta.locale_env": locale_env,
    "nm20.meta.journal": journal,
    "nm20.meta.journal_tail": journal_tail,
    "nm20.meta.state_checkpoint": state_checkpoint,
    "nm20.meta.self_heal_check": self_heal_check,
    "nm20.meta.watchdog_ping": watchdog_ping,
    "nm20.meta.panic_button": panic_button,
    "nm20.meta.resource_governor": resource_governor,
    "nm20.meta.fd_audit": fd_audit,
    "nm20.meta.thread_audit": thread_audit,
    "nm20.meta.signal_map": signal_map,
    "nm20.meta.path_audit": path_audit,
    "nm20.meta.version_oracle": version_oracle,
    "nm20.meta.timing_bench": timing_bench,
    "nm20.meta.entropy_health": entropy_health,
    # act: activation chaining
    "nm20.act.activation_chain": activation_chain,
    "nm20.act.chain_list": chain_list,
}


if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.meta.capability_matrix"]({}), indent=2)[:2000])
