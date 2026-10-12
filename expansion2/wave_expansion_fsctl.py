"""SSB swarm-24 expansion: nm21.fsctl — filesystem control plane.
Mounts, overlays, immutable attrs, ACLs, quotas. Armed:true default."""
import json, os, platform, re, subprocess, sys

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


def mount_table(args):
    """Real mount table with filesystem types and options."""
    mounts = []
    try:
        for line in open("/proc/mounts", errors="replace"):
            f = line.split()
            if len(f) >= 4:
                mounts.append({"device": f[0], "mountpoint": f[1], "fstype": f[2],
                               "options": f[3]})
    except OSError as e:
        return _err("mount_table", e)
    return _res("mount_table", mounts=mounts, count=len(mounts))


def mount_bind(args):
    """Create a real bind mount (armed)."""
    src, dst = str(args.get("src", "")), str(args.get("dst", ""))
    if not src or not dst:
        return _err("mount_bind", "need 'src' and 'dst'")
    if not _armed(args):
        return _res("mount_bind", armed=False, would_bind={src: dst})
    os.makedirs(dst, exist_ok=True)
    rc, out, err = _run(["mount", "--bind", src, dst])
    d = _res("mount_bind", armed=True, applied=(rc == 0), src=src, dst=dst,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def mount_overlay(args):
    """Create a real overlayfs mount (armed) — classic mutation layer."""
    lower = str(args.get("lower", "")); upper = str(args.get("upper", ""))
    work = str(args.get("work", "")); target = str(args.get("target", ""))
    if not all((lower, upper, work, target)):
        return _err("mount_overlay", "need lower/upper/work/target")
    if not _armed(args):
        return _res("mount_overlay", armed=False,
                    opts=f"lowerdir={lower},upperdir={upper},workdir={work}")
    for d in (upper, work, target):
        os.makedirs(d, exist_ok=True)
    rc, out, err = _run(["mount", "-t", "overlay", "overlay", "-o",
                         f"lowerdir={lower},upperdir={upper},workdir={work}", target])
    d = _res("mount_overlay", armed=True, applied=(rc == 0), target=target,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def umount_call(args):
    """Unmount a real mountpoint (armed)."""
    target = str(args.get("target", ""))
    if not target:
        return _err("umount_call", "need 'target'")
    if not _armed(args):
        return _res("umount_call", armed=False, would_umount=target)
    rc, out, err = _run(["umount", target])
    d = _res("umount_call", armed=True, applied=(rc == 0), target=target, stderr=err.strip())
    d["ok"] = rc == 0
    return d


def chattr_immutable_set(args):
    """Set/unset the real immutable attribute on a file (armed)."""
    path = str(args.get("path", ""))
    on = bool(args.get("on", True))
    if not path:
        return _err("chattr_immutable_set", "need 'path'")
    if not _armed(args):
        return _res("chattr_immutable_set", armed=False, would_set=("+i" if on else "-i"))
    rc, out, err = _run(["chattr", "+i" if on else "-i", path])
    d = _res("chattr_immutable_set", armed=True, applied=(rc == 0), path=path,
             immutable=on, stderr=err.strip())
    d["ok"] = rc == 0
    return d


def chattr_list(args):
    """List real file attributes (lsattr) for a path."""
    path = str(args.get("path", "/etc/passwd"))
    rc, out, err = _run(["lsattr", "-d", path])
    return _res("chattr_list", path=path, attributes=out.strip(), rc=rc)


def acl_get(args):
    """Read real POSIX ACLs on a path."""
    path = str(args.get("path", ""))
    if not path:
        return _err("acl_get", "need 'path'")
    rc, out, err = _run(["getfacl", "-p", path])
    if rc == 127:
        return _err("acl_get", "getfacl not installed")
    return _res("acl_get", path=path, acl=out)


def acl_set(args):
    """Set a real POSIX ACL entry (armed)."""
    path, spec = str(args.get("path", "")), str(args.get("spec", ""))
    if not path or not spec:
        return _err("acl_set", "need 'path' and 'spec'")
    if not _armed(args):
        return _res("acl_set", armed=False, would_set={path: spec})
    rc, out, err = _run(["setfacl", "-m", spec, path])
    d = _res("acl_set", armed=True, applied=(rc == 0), path=path, spec=spec,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def quota_report(args):
    """Real filesystem usage + quota report."""
    path = str(args.get("path", "/"))
    st = os.statvfs(path)
    usage = {"path": path, "total_mb": st.f_blocks * st.f_frsize // 1048576,
             "free_mb": st.f_bfree * st.f_frsize // 1048576,
             "avail_mb": st.f_bavail * st.f_frsize // 1048576,
             "files_total": st.f_files, "files_free": st.f_ffree}
    rc, out, err = _run(["quota", "-v"])
    return _res("quota_report", usage=usage, quota_cmd=out[:2000] if rc == 0 else None)


def tmpfs_mount(args):
    """Mount a real tmpfs (armed) — RAM-backed mutation workspace."""
    target = str(args.get("target", ""))
    size = str(args.get("size", "64m"))
    if not target:
        return _err("tmpfs_mount", "need 'target'")
    if not _armed(args):
        return _res("tmpfs_mount", armed=False, would_mount={"target": target, "size": size})
    os.makedirs(target, exist_ok=True)
    rc, out, err = _run(["mount", "-t", "tmpfs", "-o", f"size={size}", "tmpfs", target])
    d = _res("tmpfs_mount", armed=True, applied=(rc == 0), target=target, size=size,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def loop_device_list(args):
    """List real loop devices."""
    rc, out, err = _run(["losetup", "-a"])
    loops = [l for l in out.splitlines() if l.strip()]
    sysloops = sorted(os.listdir("/sys/block")) if os.path.isdir("/sys/block") else []
    return _res("loop_device_list", losetup=loops,
                loop_blocks=[b for b in sysloops if b.startswith("loop")])


def swap_report(args):
    """Real swap usage from /proc/swaps."""
    swaps = []
    try:
        for line in open("/proc/swaps").read().splitlines()[1:]:
            f = line.split()
            swaps.append({"device": f[0], "type": f[1], "size_kb": int(f[2]),
                          "used_kb": int(f[3]), "priority": f[4] if len(f) > 4 else ""})
    except OSError as e:
        return _err("swap_report", e)
    return _res("swap_report", swaps=swaps)


def inode_usage(args):
    """Real inode usage for a path (df -i equivalent via statvfs)."""
    path = str(args.get("path", "/"))
    st = os.statvfs(path)
    used = st.f_files - st.f_ffree
    return _res("inode_usage", path=path, total=st.f_files, free=st.f_ffree,
                used=used, pct=round(100 * used / st.f_files, 2) if st.f_files else None)


def open_files_lsof(args):
    """Real open-files listing for a pid via /proc/<pid>/fd."""
    pid = int(args.get("pid", os.getpid()))
    fds = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in sorted(os.listdir(fd_dir), key=lambda x: int(x)):
            try:
                fds.append({"fd": int(fd), "target": os.readlink(os.path.join(fd_dir, fd))})
            except OSError:
                pass
    except OSError as e:
        return _err("open_files_lsof", e)
    return _res("open_files_lsof", pid=pid, fds=fds, count=len(fds))


def deleted_open_files(args):
    """Find real deleted-but-open files (classic hiding spot)."""
    hits = []
    for pid in (p for p in os.listdir("/proc") if p.isdigit()):
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    t = os.readlink(os.path.join(fd_dir, fd))
                    if t.endswith(" (deleted)"):
                        hits.append({"pid": int(pid), "fd": int(fd), "target": t})
                except OSError:
                    pass
        except OSError:
            continue
    return _res("deleted_open_files", hits=hits[:300], count=len(hits))


POWERS = {f"nm21.fsctl.{fn.__name__}": fn for fn in
          (mount_table, mount_bind, mount_overlay, umount_call,
           chattr_immutable_set, chattr_list, acl_get, acl_set, quota_report,
           tmpfs_mount, loop_device_list, swap_report, inode_usage,
           open_files_lsof, deleted_open_files)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
