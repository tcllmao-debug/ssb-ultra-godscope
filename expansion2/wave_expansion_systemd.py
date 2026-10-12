"""SSB swarm-24 expansion: nm21.systemd — init system control.
Unit/timer/journal/drop-in control via real systemctl + filesystem. Armed:true default."""
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

def _systemctl(args_l, timeout=25):
    return _run(["systemctl"] + args_l, timeout=timeout)


def unit_list(args):
    """List real systemd units with states."""
    rc, out, err = _systemctl(["list-units", "--all", "--no-pager", "--plain", "--no-legend"])
    units = []
    for line in out.splitlines():
        f = line.split(None, 4)
        if len(f) >= 4:
            units.append({"unit": f[0], "load": f[1], "active": f[2], "sub": f[3],
                          "desc": f[4] if len(f) > 4 else ""})
    return _res("unit_list", units=units, count=len(units), rc=rc)


def unit_status(args):
    """Real systemctl status for one unit."""
    unit = str(args.get("unit", ""))
    if not unit:
        return _err("unit_status", "need 'unit'")
    rc, out, err = _systemctl(["status", unit, "--no-pager"])
    rc2, props, _ = _systemctl(["show", unit, "--no-pager"])
    parsed = dict(l.split("=", 1) for l in props.splitlines() if "=" in l) if rc2 == 0 else {}
    return _res("unit_status", unit=unit, status=out, properties=parsed)


def unit_enable(args):
    """Enable a unit for boot (armed, real systemctl enable)."""
    unit = str(args.get("unit", ""))
    if not unit:
        return _err("unit_enable", "need 'unit'")
    if not _armed(args):
        return _res("unit_enable", armed=False, would_enable=unit)
    rc, out, err = _systemctl(["enable", unit])
    d = _res("unit_enable", armed=True, unit=unit, applied=(rc == 0), output=(out + err).strip())
    d["ok"] = rc == 0
    return d


def unit_disable(args):
    """Disable a unit (armed)."""
    unit = str(args.get("unit", ""))
    if not unit:
        return _err("unit_disable", "need 'unit'")
    if not _armed(args):
        return _res("unit_disable", armed=False, would_disable=unit)
    rc, out, err = _systemctl(["disable", unit])
    d = _res("unit_disable", armed=True, unit=unit, applied=(rc == 0), output=(out + err).strip())
    d["ok"] = rc == 0
    return d


def unit_mask(args):
    """Mask a unit so it can never start (armed)."""
    unit = str(args.get("unit", ""))
    if not unit:
        return _err("unit_mask", "need 'unit'")
    if not _armed(args):
        return _res("unit_mask", armed=False, would_mask=unit)
    rc, out, err = _systemctl(["mask", unit])
    d = _res("unit_mask", armed=True, unit=unit, applied=(rc == 0), output=(out + err).strip())
    d["ok"] = rc == 0
    return d


def timer_list(args):
    """List real systemd timers and next fire times."""
    rc, out, err = _systemctl(["list-timers", "--all", "--no-pager", "--no-legend"])
    timers = [l.split() for l in out.splitlines() if l.strip()]
    return _res("timer_list", timers=timers, count=len(timers))


def journal_read(args):
    """Read real journal entries for a unit or priority."""
    unit = str(args.get("unit", ""))
    prio = str(args.get("priority", ""))
    lines = int(args.get("lines", 50))
    cmd = ["journalctl", "--no-pager", "-n", str(lines), "-o", "short-iso"]
    if unit:
        cmd += ["-u", unit]
    if prio:
        cmd += ["-p", prio]
    rc, out, err = _run(cmd, timeout=30)
    return _res("journal_read", entries=out.splitlines(), count=len(out.splitlines()))


def journal_vacuum(args):
    """Vacuum journal logs to a size limit (armed, real log mutation)."""
    size = str(args.get("size", "100M"))
    if not _armed(args):
        return _res("journal_vacuum", armed=False, would_vacuum_to=size)
    rc, out, err = _run(["journalctl", "--vacuum-size=" + size])
    return _res("journal_vacuum", armed=True, applied=(rc == 0), output=(out + err).strip())


def transient_service_run(args):
    """Run a command as a transient systemd service (armed, real systemd-run)."""
    command = args.get("command")
    if isinstance(command, str):
        command = command.split()
    if not command:
        return _err("transient_service_run", "need 'command'")
    name = str(args.get("name", "ssb-transient"))
    if not _armed(args):
        return _res("transient_service_run", armed=False, would_run=command)
    rc, out, err = _run(["systemd-run", "--unit", name, "--collect"] + command)
    d = _res("transient_service_run", armed=True, applied=(rc == 0), unit=name,
             command=command, output=(out + err).strip())
    d["ok"] = rc == 0
    return d


def service_dropin_install(args):
    """Install a systemd drop-in override for a service (armed, real write)."""
    unit = str(args.get("unit", ""))
    section = str(args.get("section", "Service"))
    entries = args.get("entries") or {}
    if not unit or not entries:
        return _err("service_dropin_install", "need 'unit' and 'entries' dict")
    body = "[%s]\n" % section + "".join(f"{k}={v}\n" for k, v in entries.items())
    d = f"/etc/systemd/system/{unit}.d"
    path = os.path.join(d, "90-ssb.conf")
    if not _armed(args):
        return _res("service_dropin_install", armed=False, would_write={path: body})
    try:
        os.makedirs(d, exist_ok=True)
        open(path, "w").write(body)
        _systemctl(["daemon-reload"])
        return _res("service_dropin_install", armed=True, path=path, content=body)
    except (PermissionError, OSError) as e:
        return _err("service_dropin_install", e)


def target_get(args):
    """Report the real default boot target."""
    rc, out, err = _systemctl(["get-default"])
    return _res("target_get", default_target=out.strip(), rc=rc)


def target_set_default(args):
    """Set the default boot target (armed)."""
    target = str(args.get("target", ""))
    if not target:
        return _err("target_set_default", "need 'target'")
    if not _armed(args):
        return _res("target_set_default", armed=False, would_set=target)
    rc, out, err = _systemctl(["set-default", target])
    d = _res("target_set_default", armed=True, applied=(rc == 0), target=target)
    d["ok"] = rc == 0
    return d


def boot_analysis(args):
    """Real systemd-analyze boot timing breakdown."""
    rc, out, err = _run(["systemd-analyze"])
    rc2, blame, _ = _run(["systemd-analyze", "blame", "--no-pager"], timeout=30)
    return _res("boot_analysis", summary=out.strip(),
                blame=[l for l in blame.splitlines()[:40]])


def failed_units(args):
    """List real failed units."""
    rc, out, err = _systemctl(["--failed", "--no-pager", "--no-legend", "--plain"])
    failed = [l.split(None, 4) for l in out.splitlines() if l.strip()]
    return _res("failed_units", failed=failed, count=len(failed))


def unit_cat(args):
    """Dump the real unit file content systemd has loaded."""
    unit = str(args.get("unit", ""))
    if not unit:
        return _err("unit_cat", "need 'unit'")
    rc, out, err = _systemctl(["cat", unit])
    return _res("unit_cat", unit=unit, content=out)


def daemon_reload(args):
    """systemctl daemon-reload (armed, real)."""
    if not _armed(args):
        return _res("daemon_reload", armed=False)
    rc, out, err = _systemctl(["daemon-reload"])
    d = _res("daemon_reload", armed=True, applied=(rc == 0))
    d["ok"] = rc == 0
    return d


POWERS = {f"nm21.systemd.{fn.__name__}": fn for fn in
          (unit_list, unit_status, unit_enable, unit_disable, unit_mask,
           timer_list, journal_read, journal_vacuum, transient_service_run,
           service_dropin_install, target_get, target_set_default,
           boot_analysis, failed_units, unit_cat, daemon_reload)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
