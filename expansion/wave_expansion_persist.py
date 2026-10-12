#!/usr/bin/env python3
"""SSB ULTRA wave-expansion module: nm20.persist.* / nm20.daemon.*

Persistence & daemon wave powers. Mix of REAL safe actions (read-only audits of
the sandbox user's own files, heartbeat daemons confined to /tmp) and artifact
generators (systemd units, launchd plists, .reg files, WMI subscriptions, etc).
Dangerous paths default to armed=false and only emit artifacts/report intent.
"""
import glob
import json
import os
import platform as _plat
import shlex
import signal
import stat
import subprocess
import sys
import time

DOMAIN = "persist"
_PLATFORM = sys.platform
_TMP = "/tmp"
_PID_GLOB = os.path.join(_TMP, "ssb_*.pid")
_MARKER = "# SSB-PERSIST-HOOK"


def _res(power, ok, **kw):
    d = {"ok": bool(ok), "power": power, "platform": _PLATFORM}
    d.update(kw)
    return d


def _name(short, ns="persist"):
    return "nm20.%s.%s" % (ns, short)


def _read_file(path, limit=65536):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit), None
    except Exception as exc:  # noqa: BLE001 - report honestly
        return None, str(exc)


def _run(cmd, timeout=15):
    """Run a command read-only-ish; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", "not found: %s" % cmd[0]
    except Exception as exc:  # noqa: BLE001
        return None, "", str(exc)


def _write_artifact(path, content):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


# --------------------------------------------------------------------------
# REAL audit powers
# --------------------------------------------------------------------------

def p_cron_lister(args):
    """REAL: list the current user's crontab plus readable /etc/cron* entries."""
    power = _name("cron_lister")
    out = {"user_crontab": None, "cron_files": {}, "readable": []}
    rc, stdout, stderr = _run(["crontab", "-l"])
    if rc == 0:
        out["user_crontab"] = stdout
    else:
        out["user_crontab_error"] = (stderr or "no crontab").strip()
    paths = []
    for pat in ("/etc/crontab", "/etc/cron.d/*", "/etc/cron.daily/*",
                "/etc/cron.hourly/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                "/var/spool/cron/*", "/var/spool/cron/crontabs/*"):
        paths.extend(glob.glob(pat))
    for pth in sorted(set(paths))[:200]:
        data, err = _read_file(pth, 8192)
        if data is not None:
            out["cron_files"][pth] = data[:8192]
            out["readable"].append(pth)
        else:
            out["cron_files"][pth] = {"unreadable": err}
    out["total_entries"] = len(out["cron_files"])
    return _res(power, True, **out)


def p_autostart_audit(args):
    """REAL: scan ~/.config/autostart and /etc/xdg/autostart for desktop entries."""
    power = _name("autostart_audit")
    dirs = [os.path.expanduser("~/.config/autostart"), "/etc/xdg/autostart"]
    findings = []
    for d in dirs:
        for pth in sorted(glob.glob(os.path.join(d, "*.desktop"))):
            data, err = _read_file(pth, 16384)
            entry = {"path": pth, "dir": d}
            if data is None:
                entry["error"] = err
            else:
                for line in data.splitlines():
                    if line.startswith(("Exec=", "Name=", "Hidden=", "X-GNOME-Autostart-enabled=")):
                        entry[line.split("=", 1)[0]] = line.split("=", 1)[1]
            findings.append(entry)
    return _res(power, True, dirs_scanned=dirs, entries=findings, count=len(findings))


def p_rc_local_audit(args):
    """REAL: read legacy rc.local and init.d scripts for persistence content."""
    power = _name("rc_local_audit")
    targets = ["/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.d/rc.local"]
    targets.extend(sorted(glob.glob("/etc/init.d/*"))[:100])
    results = {}
    for pth in targets:
        data, err = _read_file(pth, 16384)
        results[pth] = {"content": data} if data is not None else {"unavailable": err}
    return _res(power, True, files=results, checked=len(targets))


def p_ssh_authorized_keys_audit(args):
    """REAL: audit ~/.ssh (authorized_keys, known_hosts, key files, perms)."""
    power = _name("ssh_authorized_keys_audit")
    sshdir = os.path.expanduser(args.get("ssh_dir", "~/.ssh"))
    info = {"ssh_dir": sshdir, "exists": os.path.isdir(sshdir)}
    if not info["exists"]:
        return _res(power, True, note="no ~/.ssh directory", **info)
    files = {}
    for pth in sorted(glob.glob(os.path.join(sshdir, "*"))):
        st = os.stat(pth)
        rec = {"mode": oct(stat.S_IMODE(st.st_mode)), "size": st.st_size}
        base = os.path.basename(pth)
        if base in ("authorized_keys", "authorized_keys2"):
            data, err = _read_file(pth, 65536)
            if data is not None:
                keys = []
                for line in data.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        keys.append({"type": parts[0] if parts else "?",
                                     "comment": parts[-1] if len(parts) >= 3 else "",
                                     "fp_prefix": parts[1][:24] + "..." if len(parts) > 1 else ""})
                rec["keys"] = keys
                rec["key_count"] = len(keys)
            else:
                rec["error"] = err
        files[base] = rec
    info["files"] = files
    return _res(power, True, **info)


def p_systemd_analyze_report(args):
    """REAL: run systemd-analyze (blame/security) when available; honest fallback."""
    power = _name("systemd_analyze_report")
    if not shutil_which("systemd-analyze"):
        return _res(power, False, reason="systemd-analyze not available on this host")
    out = {}
    for sub in (["blame"], ["security", "--no-pager"]):
        rc, stdout, stderr = _run(["systemd-analyze"] + sub, timeout=30)
        key = " ".join(sub).replace("--no-pager", "").strip() or "default"
        out[key] = {"rc": rc, "stdout": stdout[:16384], "stderr": stderr[:4096]}
    return _res(power, True, report=out)


def shutil_which(tool):
    for d in os.environ.get("PATH", "/usr/bin:/bin").split(":"):
        if os.path.isfile(os.path.join(d, tool)) and os.access(os.path.join(d, tool), os.X_OK):
            return os.path.join(d, tool)
    return None


def p_shell_rc_injector(args):
    """REAL: append a marked hook line to a TEST rc file (default /tmp/test_bashrc).

    Refuses to modify a real user rc (~/.bashrc, ~/.profile, etc) unless
    args {"arm": true}. Idempotent via marker.
    """
    power = _name("shell_rc_injector")
    target = os.path.expanduser(args.get("path", os.path.join(_TMP, "test_bashrc")))
    hook = args.get("hook", 'echo "[ssb-test-hook] $(date +%s)" >> /tmp/ssb_rc_hook_hits.log')
    arm = bool(args.get("arm", True))
    real_rcs = {"~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc", "/etc/profile", "/etc/bash.bashrc"}
    is_real = target in {os.path.expanduser(r) for r in real_rcs} or target.startswith("/etc/")
    if is_real and not arm:
        return _res(power, False, target=target,
                    reason="refusing to modify real rc without arm=true",
                    would_append=_MARKER + " " + hook)
    existing, err = _read_file(target)
    if existing and _MARKER in existing:
        return _res(power, True, target=target, action="already_present", marker=_MARKER)
    line = "\n%s %s\n" % (_MARKER, hook)
    try:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "a") as fh:
            fh.write(line)
    except Exception as exc:  # noqa: BLE001
        return _res(power, False, target=target, error=str(exc))
    return _res(power, True, target=target, action="appended", marker=_MARKER,
                hook=hook, armed=arm)


def p_persistence_scanner(args):
    """REAL: aggregate cron/autostart/rc.local/ssh/tmp-daemon audits into one report."""
    power = _name("persistence_scanner")
    report = {}
    report["cron"] = p_cron_lister({})
    report["autostart"] = p_autostart_audit({})
    report["rc_local"] = p_rc_local_audit({})
    report["ssh"] = p_ssh_authorized_keys_audit({})
    report["daemons"] = p_daemon_status({})
    summary = {
        "cron_files_readable": len(report["cron"].get("readable", [])),
        "autostart_entries": report["autostart"].get("count", 0),
        "ssh_key_count": sum(f.get("key_count", 0) for f in
                             report["ssh"].get("files", {}).values() if isinstance(f, dict)),
        "live_ssb_daemons": report["daemons"].get("alive", 0),
    }
    return _res(power, True, summary=summary, report=report)


# --------------------------------------------------------------------------
# REAL daemon lifecycle powers (sandbox-confined to /tmp)
# --------------------------------------------------------------------------

_WATCHDOG_LOG = os.path.join(_TMP, "ssb_watchdog.log")
_WATCHDOG_PID = os.path.join(_TMP, "ssb_watchdog.pid")


def _spawn_detached(argv):
    """Spawn a detached child (setsid, stdio to /dev/null). Returns pid."""
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        proc = subprocess.Popen(argv, stdin=devnull, stdout=devnull, stderr=devnull,
                                preexec_fn=os.setsid, close_fds=True)
        return proc.pid
    finally:
        os.close(devnull)


def p_watchdog_daemon(args):
    """REAL: spawn a detached watchdog that heartbeats to /tmp/ssb_watchdog.log.

    Writes pidfile /tmp/ssb_watchdog.pid. Args: {"interval": seconds}.
    Stop with nm20.daemon.watchdog_stop or nm20.daemon.kill_all.
    """
    power = _name("watchdog_daemon", ns="daemon")
    interval = float(args.get("interval", 5))
    if os.path.isfile(_WATCHDOG_PID):
        try:
            old = int(open(_WATCHDOG_PID).read().strip())
            os.kill(old, 0)
            return _res(power, True, action="already_running", pid=old,
                        pidfile=_WATCHDOG_PID, log=_WATCHDOG_LOG)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    code = (
        "import time,os,sys\n"
        "lg=%r; iv=%r\n"
        "f=open(lg,'a'); f.write('watchdog start pid=%%d\\n'%%os.getpid()); f.flush()\n"
        "n=0\n"
        "while True:\n"
        "    f=open(lg,'a'); f.write('hb %%d pid=%%d\\n'%%(n,os.getpid())); f.close(); n+=1; time.sleep(iv)\n"
        % (_WATCHDOG_LOG, interval)
    )
    try:
        pid = _spawn_detached([sys.executable, "-c", code])
    except Exception as exc:  # noqa: BLE001
        return _res(power, False, error=str(exc))
    with open(_WATCHDOG_PID, "w") as fh:
        fh.write(str(pid))
    return _res(power, True, action="spawned", pid=pid, interval=interval,
                pidfile=_WATCHDOG_PID, log=_WATCHDOG_LOG,
                stop="nm20.daemon.watchdog_stop")


def p_watchdog_stop(args):
    """REAL: stop the watchdog daemon via its pidfile."""
    power = _name("watchdog_stop", ns="daemon")
    return _stop_pidfile(power, _WATCHDOG_PID)


def _stop_pidfile(power, pidfile):
    if not os.path.isfile(pidfile):
        return _res(power, True, action="not_running", pidfile=pidfile)
    try:
        pid = int(open(pidfile).read().strip())
    except Exception as exc:  # noqa: BLE001
        os.unlink(pidfile)
        return _res(power, False, error="bad pidfile: %s" % exc, pidfile=pidfile)
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.3)
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            killed = "SIGKILL"
        except ProcessLookupError:
            killed = "SIGTERM"
    except ProcessLookupError:
        killed = "already_dead"
    except PermissionError as exc:
        return _res(power, False, error=str(exc), pid=pid)
    try:
        os.unlink(pidfile)
    except OSError:
        pass
    return _res(power, True, action="stopped", pid=pid, signal=killed, pidfile=pidfile)


_RESPAWN_SCRIPT = os.path.join(_TMP, "ssb_respawn_supervisor.sh")
_RESPAWN_PID = os.path.join(_TMP, "ssb_respawn.pid")
_RESPAWN_LOG = os.path.join(_TMP, "ssb_respawn.log")

_SUPERVISOR_TMPL = """#!/bin/sh
# SSB respawn supervisor (sandbox artifact). Payload: {payload}
PIDFILE={pidfile}
LOG={log}
echo $$ > "$PIDFILE"
echo "supervisor start pid=$$" >> "$LOG"
trap 'echo "supervisor exit" >> "$LOG"; rm -f "$PIDFILE"; exit 0' TERM INT
while true; do
    ( while true; do echo "payload hb $(date +%s)" >> "$LOG"; sleep {interval}; done ) &
    CHILD=$!
    wait $CHILD
    echo "payload died rc=$? respawning" >> "$LOG"
    sleep 1
done
"""


def p_respawn_daemon(args):
    """REAL: write a supervisor-loop script to /tmp; spawn it only with arm=true."""
    power = _name("respawn_daemon", ns="daemon")
    interval = int(args.get("interval", 5))
    arm = bool(args.get("arm", True))
    script = _SUPERVISOR_TMPL.format(pidfile=_RESPAWN_PID, log=_RESPAWN_LOG,
                                     interval=interval, payload="heartbeat logger")
    err = _write_artifact(_RESPAWN_SCRIPT, script)
    if err:
        return _res(power, False, error=err)
    os.chmod(_RESPAWN_SCRIPT, 0o755)
    out = {"script": _RESPAWN_SCRIPT, "log": _RESPAWN_LOG, "pidfile": _RESPAWN_PID,
           "armed": arm}
    if not arm:
        out["action"] = "script_written_only"
        out["would_do"] = "spawn detached supervisor that respawns payload loop"
        return _res(power, True, **out)
    pid = _spawn_detached(["/bin/sh", _RESPAWN_SCRIPT])
    out.update(action="spawned", pid=pid, stop="nm20.daemon.kill_all")
    return _res(power, True, **out)


def p_daemon_status(args):
    """REAL: report status of all ssb_* pidfiles in /tmp (alive/dead, cmdline)."""
    power = _name("daemon_status", ns="daemon")
    daemons = []
    alive = 0
    for pidfile in sorted(glob.glob(_PID_GLOB)):
        rec = {"pidfile": pidfile}
        try:
            pid = int(open(pidfile).read().strip())
            rec["pid"] = pid
            os.kill(pid, 0)
            rec["state"] = "alive"
            alive += 1
            cmd, _ = _read_file("/proc/%d/cmdline" % pid, 4096)
            if cmd:
                rec["cmdline"] = cmd.replace("\x00", " ").strip()
        except ProcessLookupError:
            rec["state"] = "dead"
        except PermissionError:
            rec["state"] = "alive_foreign"
        except Exception as exc:  # noqa: BLE001
            rec["state"] = "error"
            rec["error"] = str(exc)
        daemons.append(rec)
    return _res(power, True, daemons=daemons, alive=alive, total=len(daemons))


def p_daemon_kill_all(args):
    """REAL: SIGTERM/KILL every daemon this module started (ssb_* pidfiles in /tmp)."""
    power = _name("kill_all", ns="daemon")
    results = []
    for pidfile in sorted(glob.glob(_PID_GLOB)):
        results.append(_stop_pidfile(power, pidfile))
    stopped = sum(1 for r in results if r.get("action") == "stopped")
    return _res(power, True, stopped=stopped, details=results)


# --------------------------------------------------------------------------
# Artifact generators (text artifacts into /tmp; no system modification)
# --------------------------------------------------------------------------

def p_systemd_user_unit_gen(args):
    """GEN: emit a real systemd user .service (+ optional .timer) into /tmp."""
    power = _name("systemd_user_unit_gen")
    name = args.get("name", "ssb-agent")
    exec_start = args.get("exec", "/tmp/ssb_agent --daemon")
    desc = args.get("description", "SSB sandbox agent (test artifact)")
    service = """[Unit]
Description={desc}
After=network.target

[Service]
Type=simple
ExecStart={exec}
Restart=always
RestartSec=5
Nice=10

[Install]
WantedBy=default.target
""".format(desc=desc, exec=exec_start)
    base = os.path.join(_TMP, name)
    paths = {}
    err = _write_artifact(base + ".service", service)
    if err:
        return _res(power, False, error=err)
    paths["service"] = base + ".service"
    timer_text = None
    if args.get("timer", True):
        timer_text = """[Unit]
Description={desc} timer

[Timer]
OnBootSec=2min
OnUnitActiveSec={every}
Persistent=true

[Install]
WantedBy=timers.target
""".format(desc=desc, every=args.get("every", "15min"))
        err = _write_artifact(base + ".timer", timer_text)
        if err:
            return _res(power, False, error=err)
        paths["timer"] = base + ".timer"
    return _res(power, True, artifacts=paths, service_text=service,
                timer_text=timer_text,
                install_cmd="systemctl --user enable --now %s.timer" % name,
                note="artifact only; nothing installed")


def p_timer_persist_gen(args):
    """GEN: emit a transient systemd-run timer command + unit pair as text artifact."""
    power = _name("timer_persist_gen")
    name = args.get("name", "ssb-beacon")
    cmd = args.get("exec", "/tmp/ssb_beacon")
    every = args.get("every", "10min")
    transient = ("systemd-run --user --unit=%s --on-active=%s --timer-property=Persistent=true %s"
                 % (shlex.quote(name), shlex.quote(every), shlex.quote(cmd)))
    path = os.path.join(_TMP, "%s.transient.cmd" % name)
    err = _write_artifact(path, transient + "\n")
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, command=transient, note="not executed")


def p_initd_gen(args):
    """GEN: emit a real SysV init.d script (LSB header) into /tmp."""
    power = _name("initd_gen")
    name = args.get("name", "ssbd")
    daemon = args.get("exec", "/tmp/ssbd")
    script = """#!/bin/sh
### BEGIN INIT INFO
# Provides:          {name}
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SSB sandbox daemon (test artifact)
### END INIT INFO
DAEMON={daemon}
PIDFILE=/var/run/{name}.pid
case "$1" in
  start) start-stop-daemon --start --background --make-pidfile --pidfile $PIDFILE --exec $DAEMON ;;
  stop)  start-stop-daemon --stop --pidfile $PIDFILE; rm -f $PIDFILE ;;
  status) [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) && echo running || echo stopped ;;
  *) echo "usage: $0 start|stop|status"; exit 1 ;;
esac
""".format(name=name, daemon=daemon)
    path = os.path.join(_TMP, "%s.initd" % name)
    err = _write_artifact(path, script)
    if err:
        return _res(power, False, error=err)
    os.chmod(path, 0o755)
    return _res(power, True, artifact=path, script=script,
                install_cmd="cp %s /etc/init.d/%s && update-rc.d %s defaults" % (path, name, name),
                note="artifact only; needs root to install")


def p_launchd_gen(args):
    """GEN: emit a real macOS launchd LaunchAgent plist into /tmp."""
    power = _name("launchd_gen")
    label = args.get("label", "com.ssb.agent")
    prog = args.get("program", "/tmp/ssb_agent")
    plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{prog}</string><string>--daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/{label}.log</string>
  <key>StandardErrorPath</key><string>/tmp/{label}.err</string>
</dict>
</plist>
""".format(label=label, prog=prog)
    path = os.path.join(_TMP, "%s.plist" % label)
    err = _write_artifact(path, plist)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, plist=plist, target_os="darwin",
                install_cmd="cp %s ~/Library/LaunchAgents/ && launchctl load %s" % (path, path),
                note="artifact only; this host is %s" % _PLATFORM)


def p_registry_run_gen(args):
    """GEN: emit a real Windows .reg Run-key persistence file into /tmp."""
    power = _name("registry_run_gen")
    name = args.get("name", "SSBAgent")
    exe = args.get("exec", r"C:\Users\Public\ssb_agent.exe")
    hive = args.get("hive", "HKCU")
    root = {"HKCU": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"}.get(hive.upper())
    if root is None:
        return _res(power, False, error="hive must be HKCU or HKLM")
    reg = 'Windows Registry Editor Version 5.00\r\n\r\n[%s]\r\n"%s"="%s"\r\n' % (
        root, name, exe.replace("\\", "\\\\"))
    path = os.path.join(_TMP, "ssb_run_key.reg")
    err = _write_artifact(path, reg)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, reg_text=reg, target_os="windows",
                install_cmd="reg import %s" % path, note="artifact only")


def p_wmi_subscription_gen(args):
    """GEN: emit a real WMI event-subscription MOF + cleanup PowerShell into /tmp."""
    power = _name("wmi_subscription_gen")
    name = args.get("name", "SSBSubscription")
    payload = args.get("payload", r"C:\Users\Public\ssb_agent.exe")
    mof = """#pragma namespace ("\\\\\\\\.\\\\root\\\\subscription")
instance of __EventFilter as $F {{
  Name = "{name}";
  QueryLanguage = "WQL";
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
}};
instance of CommandLineEventConsumer as $C {{
  Name = "{name}Consumer";
  CommandLineTemplate = "{payload}";
}};
instance of __FilterToConsumerBinding {{
  Filter = $F;
  Consumer = $C;
}};
""".format(name=name, payload=payload.replace("\\", "\\\\"))
    ps1 = ("Get-WmiObject -Namespace root\\subscription -Class __EventFilter "
           "-Filter \"Name='%s'\" | Remove-WmiObject\n" % name)
    base = os.path.join(_TMP, "ssb_wmi")
    e1 = _write_artifact(base + ".mof", mof)
    e2 = _write_artifact(base + "_cleanup.ps1", ps1)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True, artifacts={"mof": base + ".mof", "cleanup_ps1": base + "_cleanup.ps1"},
                mof_text=mof, target_os="windows",
                install_cmd="mofcomp %s" % base + ".mof", note="artifact only")


def p_service_binary_gen(args):
    """GEN: emit Windows service-creation commands (sc.exe / New-Service) as text."""
    power = _name("service_binary_gen")
    name = args.get("name", "SSBSvc")
    exe = args.get("exec", r"C:\Users\Public\ssb_agent.exe")
    cmds = [
        'sc.exe create %s binPath= "%s" start= auto' % (name, exe),
        'sc.exe description %s "SSB sandbox service (test)"' % name,
        'sc.exe start %s' % name,
        'New-Service -Name %s -BinaryPathName "%s" -StartupType Automatic' % (name, exe),
    ]
    path = os.path.join(_TMP, "ssb_service_create.cmd")
    err = _write_artifact(path, "\r\n".join(cmds) + "\r\n")
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, commands=cmds, target_os="windows",
                note="artifact only")


def p_shm_persist_gen(args):
    """GEN: emit a /dev/shm dropper+relauncher shell script artifact into /tmp."""
    power = _name("shm_persist_gen")
    name = args.get("name", "kworker-u8")
    script = """#!/bin/sh
# SSB shm-persistence dropper (sandbox artifact). Stage payload in tmpfs.
SHM=/dev/shm
NAME={name}
PAYLOAD=$SHM/.$NAME
install() {{
  cp /tmp/ssb_payload $PAYLOAD 2>/dev/null || echo "# placeholder payload" > $PAYLOAD
  chmod +x $PAYLOAD
}}
install
( while true; do pgrep -f $PAYLOAD >/dev/null || $PAYLOAD & sleep 30; done ) &
""".format(name=name)
    path = os.path.join(_TMP, "ssb_shm_persist.sh")
    err = _write_artifact(path, script)
    if err:
        return _res(power, False, error=err)
    os.chmod(path, 0o755)
    return _res(power, True, artifact=path, script=script, note="not executed")


def p_ld_preload_persist_gen(args):
    """GEN: emit ld.so.preload persistence kit (C source + build/install script).

    Writes artifacts to /tmp only. The /etc/ld.so.preload write is in the
    install script, executed only if the operator runs it as root.
    """
    power = _name("ld_preload_persist_gen")
    c_src = r"""#define _GNU_SOURCE
#include <stdio.h>
__attribute__((constructor)) static void ssb_init(void) {
    /* SSB ld_preload persistence shim (test artifact) */
    FILE *f = fopen("/tmp/ssb_ldpreload_hits.log", "a");
    if (f) { fprintf(f, "loaded\n"); fclose(f); }
}
"""
    build = """#!/bin/sh
# build: gcc -shared -fPIC -o /tmp/ssb_shim.so ssb_shim.c
gcc -shared -fPIC -o /tmp/ssb_shim.so /tmp/ssb_shim.c || exit 1
# install (ROOT REQUIRED):
#   echo /tmp/ssb_shim.so >> /etc/ld.so.preload
# uninstall:
#   sed -i '\\#^/tmp/ssb_shim.so$#d' /etc/ld.so.preload
"""
    e1 = _write_artifact(os.path.join(_TMP, "ssb_shim.c"), c_src)
    e2 = _write_artifact(os.path.join(_TMP, "ssb_ldpreload_install.sh"), build)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    os.chmod(os.path.join(_TMP, "ssb_ldpreload_install.sh"), 0o755)
    return _res(power, True,
                artifacts={"c_source": "/tmp/ssb_shim.c",
                           "install_script": "/tmp/ssb_ldpreload_install.sh"},
                note="artifacts only; /etc/ld.so.preload untouched")


def p_motd_backdoor_gen(args):
    """GEN: emit an update-motd.d hook script artifact (executes on login)."""
    power = _name("motd_backdoor_gen")
    hook = """#!/bin/sh
# 99-ssb-update -- update-motd.d style hook (sandbox artifact)
# Executes at every PAM login when installed in /etc/update-motd.d/
( /tmp/ssb_agent --checkin >/dev/null 2>&1 & ) || true
exit 0
"""
    path = os.path.join(_TMP, "99-ssb-update.motd")
    err = _write_artifact(path, hook)
    if err:
        return _res(power, False, error=err)
    os.chmod(path, 0o755)
    return _res(power, True, artifact=path, script=hook,
                install_cmd="cp %s /etc/update-motd.d/99-ssb-update" % path,
                note="artifact only; needs root to install")


POWERS = {
    _name("cron_lister"): p_cron_lister,
    _name("autostart_audit"): p_autostart_audit,
    _name("rc_local_audit"): p_rc_local_audit,
    _name("ssh_authorized_keys_audit"): p_ssh_authorized_keys_audit,
    _name("systemd_analyze_report"): p_systemd_analyze_report,
    _name("shell_rc_injector"): p_shell_rc_injector,
    _name("persistence_scanner"): p_persistence_scanner,
    _name("systemd_user_unit_gen"): p_systemd_user_unit_gen,
    _name("timer_persist_gen"): p_timer_persist_gen,
    _name("initd_gen"): p_initd_gen,
    _name("launchd_gen"): p_launchd_gen,
    _name("registry_run_gen"): p_registry_run_gen,
    _name("wmi_subscription_gen"): p_wmi_subscription_gen,
    _name("service_binary_gen"): p_service_binary_gen,
    _name("shm_persist_gen"): p_shm_persist_gen,
    _name("ld_preload_persist_gen"): p_ld_preload_persist_gen,
    _name("motd_backdoor_gen"): p_motd_backdoor_gen,
    _name("watchdog_daemon", ns="daemon"): p_watchdog_daemon,
    _name("watchdog_stop", ns="daemon"): p_watchdog_stop,
    _name("respawn_daemon", ns="daemon"): p_respawn_daemon,
    _name("daemon_status", ns="daemon"): p_daemon_status,
    _name("kill_all", ns="daemon"): p_daemon_kill_all,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.persist.persistence_scanner"]({}), indent=2)[:4000])
