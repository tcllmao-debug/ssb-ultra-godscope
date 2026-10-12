"""SSB swarm-24 expansion: nm21.sched — scheduling & resource control.
Real sched_setaffinity, chrt, ionice, rlimits, OOM scores. Armed:true default."""
import ctypes, json, os, platform, re, subprocess, sys

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

LIBC = ctypes.CDLL(None, use_errno=True)


def affinity_get(args):
    """Real CPU affinity of a pid via sched_getaffinity."""
    pid = int(args.get("pid", os.getpid()))
    n = os.cpu_count() or 1
    mask = ctypes.c_ulonglong(0)
    r = LIBC.sched_getaffinity(pid, ctypes.sizeof(mask), ctypes.byref(mask))
    if r != 0:
        return _err("affinity_get", "errno %d" % ctypes.get_errno())
    cpus = [i for i in range(64) if mask.value & (1 << i)]
    return _res("affinity_get", pid=pid, cpus=cpus, mask=hex(mask.value))


def affinity_set(args):
    """Pin a pid to specific CPUs via real sched_setaffinity (armed)."""
    pid = int(args.get("pid", os.getpid()))
    cpus = args.get("cpus") or [0]
    if not _armed(args):
        return _res("affinity_set", armed=False, pid=pid, would_pin=cpus)
    mask = ctypes.c_ulonglong(0)
    for c in cpus:
        mask.value |= 1 << int(c)
    r = LIBC.sched_setaffinity(pid, ctypes.sizeof(mask), ctypes.byref(mask))
    if r != 0:
        return _err("affinity_set", "errno %d: %s" % (ctypes.get_errno(),
                    os.strerror(ctypes.get_errno())))
    return _res("affinity_set", armed=True, pid=pid, cpus=cpus,
                verify=affinity_get({"pid": pid}).get("cpus"))


def chrt_report(args):
    """Real scheduling policy of a pid via sched_getscheduler."""
    pid = int(args.get("pid", os.getpid()))
    r = LIBC.sched_getscheduler(pid)
    policies = {0: "SCHED_OTHER", 1: "SCHED_FIFO", 2: "SCHED_RR", 3: "SCHED_BATCH",
                5: "SCHED_IDLE", 6: "SCHED_DEADLINE"}
    if r < 0:
        return _err("chrt_report", "errno %d" % ctypes.get_errno())
    return _res("chrt_report", pid=pid, policy=policies.get(r, r))


def chrt_set(args):
    """Set real-time scheduling policy via sched_setscheduler (armed)."""
    pid = int(args.get("pid", os.getpid()))
    policy_name = str(args.get("policy", "SCHED_RR")).upper()
    prio = int(args.get("priority", 10))
    policies = {"SCHED_OTHER": 0, "SCHED_FIFO": 1, "SCHED_RR": 2, "SCHED_BATCH": 3,
                "SCHED_IDLE": 5, "SCHED_DEADLINE": 6}
    if policy_name not in policies:
        return _err("chrt_set", "unknown policy: " + policy_name)
    if not _armed(args):
        return _res("chrt_set", armed=False, would_set={policy_name: prio})
    class SchedParam(ctypes.Structure):
        _fields_ = [("sched_priority", ctypes.c_int)]
    param = SchedParam(prio)
    r = LIBC.sched_setscheduler(pid, policies[policy_name], ctypes.byref(param))
    if r != 0:
        return _err("chrt_set", "errno %d: %s" % (ctypes.get_errno(),
                    os.strerror(ctypes.get_errno())),
                    prerequisite="CAP_SYS_NICE for RT policies")
    return _res("chrt_set", armed=True, pid=pid, policy=policy_name, priority=prio)


def ionice_set(args):
    """Set real IO scheduling class/priority via ioprio_set syscall (armed)."""
    pid = int(args.get("pid", os.getpid()))
    cls = int(args.get("cls", 2))  # 1=RT 2=BE 3=IDLE
    data = int(args.get("data", 4))
    IOPRIO_WHO_PROCESS = 1
    ioprio = (cls << 13) | data
    if not _armed(args):
        return _res("ionice_set", armed=False, pid=pid, cls=cls, data=data)
    SYS_ioprio_set = 251 if platform.machine() == "x86_64" else 30
    r = LIBC.syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid, ioprio)
    if r != 0:
        return _err("ionice_set", "errno %d: %s" % (ctypes.get_errno(),
                    os.strerror(ctypes.get_errno())))
    return _res("ionice_set", armed=True, pid=pid, cls=cls, data=data)


def nice_set(args):
    """Set real nice level via setpriority (armed)."""
    pid = int(args.get("pid", os.getpid()))
    nice = int(args.get("nice", 10))
    if not (-20 <= nice <= 19):
        return _err("nice_set", "nice must be -20..19")
    if not _armed(args):
        return _res("nice_set", armed=False, pid=pid, would_set=nice)
    r = LIBC.setpriority(0, pid, nice)
    if r != 0:
        return _err("nice_set", "errno %d: %s" % (ctypes.get_errno(),
                    os.strerror(ctypes.get_errno())))
    return _res("nice_set", armed=True, pid=pid, nice=os.getpriority(0, pid) if hasattr(os, 'getpriority') else nice)


def cpuset_report(args):
    """Report real cpuset cgroup configuration."""
    vals = {}
    for p in ("/sys/fs/cgroup/cpuset.cpus", "/sys/fs/cgroup/cpuset.cpus.effective",
              "/sys/fs/cgroup/cpuset.mems", "/sys/fs/cgroup/cpuset/cpuset.cpus"):
        try:
            vals[p] = open(p).read().strip()
        except OSError:
            pass
    return _res("cpuset_report", cpusets=vals)


def cpu_online_report(args):
    """Real CPU online/offline map."""
    cpus = {}
    d = "/sys/devices/system/cpu"
    for c in sorted((x for x in os.listdir(d) if re.fullmatch(r"cpu\d+", x)),
                    key=lambda x: int(x[3:])):
        online = os.path.join(d, c, "online")
        if os.path.exists(online):
            try:
                cpus[c] = int(open(online).read().strip())
            except OSError:
                pass
        else:
            cpus[c] = 1
    try:
        present = open(os.path.join(d, "present")).read().strip()
    except OSError:
        present = None
    return _res("cpu_online_report", cpus=cpus, present=present,
                online_count=sum(cpus.values()))


def cpu_online_set(args):
    """Bring a CPU online/offline via real sysfs write (armed)."""
    cpu = str(args.get("cpu", ""))
    state = int(args.get("state", 1))
    p = f"/sys/devices/system/cpu/{cpu}/online"
    if not os.path.exists(p):
        return _err("cpu_online_set", "cpu not hotpluggable: " + cpu)
    if not _armed(args):
        return _res("cpu_online_set", armed=False, would_write={p: state})
    try:
        open(p, "w").write(str(state))
        return _res("cpu_online_set", armed=True, cpu=cpu, state=state,
                    verify=open(p).read().strip())
    except (PermissionError, OSError) as e:
        return _err("cpu_online_set", e)


def numa_report(args):
    """Real NUMA topology from /sys/devices/system/node."""
    d = "/sys/devices/system/node"
    nodes = {}
    if os.path.isdir(d):
        for n in sorted(x for x in os.listdir(d) if re.fullmatch(r"node\d+", x)):
            info = {}
            for f in ("cpulist", "meminfo"):
                try:
                    info[f] = open(os.path.join(d, n, f), errors="replace").read().strip()
                except OSError:
                    pass
            nodes[n] = info
    return _res("numa_report", nodes=nodes)


def irq_affinity_report(args):
    """Real IRQ affinity (smp_affinity) for IRQ lines."""
    d = "/proc/irq"
    rows = []
    if os.path.isdir(d):
        for irq in sorted((x for x in os.listdir(d) if x.isdigit()), key=int)[:64]:
            try:
                aff = open(os.path.join(d, irq, "smp_affinity")).read().strip()
                rows.append({"irq": int(irq), "smp_affinity": aff})
            except OSError:
                pass
    return _res("irq_affinity_report", irqs=rows)


def rlimit_report(args):
    """Real resource limits of a process from /proc/<pid>/limits."""
    import resource
    pid = int(args.get("pid", os.getpid()))
    try:
        txt = open(f"/proc/{pid}/limits", errors="replace").read()
    except OSError as e:
        return _err("rlimit_report", e)
    limits = []
    for line in txt.splitlines()[1:]:
        m = re.match(r"(\S.*?)\s{2,}(\S+)\s+(\S+)\s+(\S*)", line)
        if m:
            limits.append({"name": m.group(1).strip(), "soft": m.group(2),
                           "hard": m.group(3), "units": m.group(4)})
    return _res("rlimit_report", pid=pid, limits=limits)


def rlimit_set(args):
    """Set a real rlimit via setrlimit (armed)."""
    import resource
    name = str(args.get("name", "NOFILE")).upper()
    soft = int(args.get("soft", 65536))
    hard = int(args.get("hard", soft))
    res = getattr(resource, "RLIMIT_" + name, None)
    if res is None:
        return _err("rlimit_set", "unknown rlimit: " + name)
    if not _armed(args):
        return _res("rlimit_set", armed=False, would_set={name: (soft, hard)})
    try:
        resource.setrlimit(res, (soft, hard))
        return _res("rlimit_set", armed=True, name=name,
                    current=resource.getrlimit(res))
    except (ValueError, OSError) as e:
        return _err("rlimit_set", e)


def oom_score_set(args):
    """Set real OOM score adjustment for a pid (armed)."""
    pid = int(args.get("pid", os.getpid()))
    score = int(args.get("score", 0))
    if not (-1000 <= score <= 1000):
        return _err("oom_score_set", "score must be -1000..1000")
    p = f"/proc/{pid}/oom_score_adj"
    if not _armed(args):
        return _res("oom_score_set", armed=False, would_write={p: score})
    try:
        open(p, "w").write(str(score))
        return _res("oom_score_set", armed=True, pid=pid, score=score,
                    verify=open(p).read().strip())
    except (PermissionError, OSError) as e:
        return _err("oom_score_set", e)


def scheduler_policy_report(args):
    """Report real scheduler tunables (sched_latency, CFS/RT bandwidth)."""
    keys = ["kernel.sched_latency_ns", "kernel.sched_rt_runtime_us",
            "kernel.sched_rt_period_us", "kernel.sched_cfs_bandwidth_slice_us"]
    vals = {}
    for k in keys:
        p = "/proc/sys/" + k.replace(".", "/")
        try:
            vals[k] = open(p).read().strip()
        except OSError:
            pass
    return _res("scheduler_policy_report", tunables=vals)


def thp_report(args):
    """Report real transparent-hugepage state."""
    vals = {}
    for f in ("enabled", "defrag", "khugepaged/scan_sleep_millisecs"):
        p = "/sys/kernel/mm/transparent_hugepage/" + f
        try:
            vals[f] = open(p).read().strip()
        except OSError:
            pass
    return _res("thp_report", thp=vals)


POWERS = {f"nm21.sched.{fn.__name__}": fn for fn in
          (affinity_get, affinity_set, chrt_report, chrt_set, ionice_set,
           nice_set, cpuset_report, cpu_online_report, cpu_online_set,
           numa_report, irq_affinity_report, rlimit_report, rlimit_set,
           oom_score_set, scheduler_policy_report, thp_report)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
