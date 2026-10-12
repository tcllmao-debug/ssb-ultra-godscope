"""SSB swarm-24 expansion: nm21.boot — boot chain control.
Bootloader entries, initramfs, EFI/secure-boot state, kexec. Armed:true default."""
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


def bootloader_entries(args):
    """List real bootloader entries (bootctl or grub cfg parse)."""
    rc, out, err = _run(["bootctl", "list"])
    if rc == 0:
        return _res("bootloader_entries", source="bootctl", entries=out)
    entries = []
    for cfg in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/loader/entries"):
        if os.path.isdir(cfg):
            for f in sorted(os.listdir(cfg)):
                try:
                    entries.append({"file": os.path.join(cfg, f),
                                    "content": open(os.path.join(cfg, f), errors="replace").read()})
                except OSError:
                    pass
        elif os.path.isfile(cfg):
            try:
                txt = open(cfg, errors="replace").read()
                for m in re.finditer(r"menuentry\s+'([^']+)'", txt):
                    entries.append({"menuentry": m.group(1), "source": cfg})
            except OSError:
                pass
    return _res("bootloader_entries", source="grub/loader", entries=entries[:50])


def kernel_images(args):
    """Inventory real kernel images and their versions in /boot."""
    imgs = []
    if os.path.isdir("/boot"):
        for f in sorted(os.listdir("/boot")):
            if f.startswith(("vmlinuz", "bzImage", "kernel")):
                p = os.path.join("/boot", f)
                try:
                    imgs.append({"file": p, "bytes": os.path.getsize(p)})
                except OSError:
                    pass
    running = platform.release()
    return _res("kernel_images", images=imgs, running_kernel=running)


def initramfs_list(args):
    """Inventory real initramfs images."""
    imgs = []
    if os.path.isdir("/boot"):
        for f in sorted(os.listdir("/boot")):
            if f.startswith(("initramfs", "initrd")):
                p = os.path.join("/boot", f)
                try:
                    imgs.append({"file": p, "bytes": os.path.getsize(p)})
                except OSError:
                    pass
    return _res("initramfs_list", images=imgs)


def initramfs_unpack_list(args):
    """List the contents of a real initramfs (lsinitramfs)."""
    image = str(args.get("image", ""))
    if not image:
        return _err("initramfs_unpack_list", "need 'image'")
    rc, out, err = _run(["lsinitramfs", image], timeout=120)
    if rc != 0:
        return _err("initramfs_unpack_list", err.strip() or "lsinitramfs failed")
    files = out.splitlines()
    interesting = [f for f in files if any(k in f for k in
                   ("scripts/", "hooks/", "crypttab", "ssh", "network"))]
    return _res("initramfs_unpack_list", image=image, total_files=len(files),
                interesting=interesting[:200])


def default_kernel_report(args):
    """Report the default boot kernel and fallback."""
    rc, out, err = _run(["grubby", "--default-kernel"])
    rc2, out2, _ = _run(["grubby", "--info", "DEFAULT"])
    return _res("default_kernel_report", default=out.strip() if rc == 0 else None,
                info=out2 if rc2 == 0 else None)


def grub_env_report(args):
    """Read real grubenv saved-entry state."""
    for p in ("/boot/grub/grubenv", "/boot/grub2/grubenv", "/boot/efi/EFI/grubenv"):
        if os.path.isfile(p):
            try:
                return _res("grub_env_report", path=p,
                            env=dict(l.split("=", 1) for l in
                                     open(p, errors="replace").read().splitlines() if "=" in l))
            except OSError as e:
                return _err("grub_env_report", e)
    return _err("grub_env_report", "grubenv not found")


def bootctl_status(args):
    """Real bootctl status (systemd-boot systems)."""
    rc, out, err = _run(["bootctl", "status"])
    return _res("bootctl_status", available=(rc == 0), output=(out or err)[:3000])


def runlevel_report(args):
    """Real current runlevel/target."""
    rc, out, err = _run(["runlevel"])
    rc2, out2, _ = _run(["systemctl", "get-default"])
    rc3, out3, _ = _run(["who", "-r"])
    return _res("runlevel_report", runlevel=out.strip(), default_target=out2.strip(),
                who=out3.strip())


def rc_local_audit(args):
    """Audit rc.local and legacy init scripts (persistence surfaces)."""
    paths = ["/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.d"]
    found = {}
    for p in paths:
        if os.path.isfile(p):
            try:
                found[p] = open(p, errors="replace").read()
            except OSError:
                pass
        elif os.path.isdir(p):
            found[p] = sorted(os.listdir(p))
    return _res("rc_local_audit", found=found)


def cron_boot_audit(args):
    """Audit all real @reboot cron entries (boot persistence)."""
    files = ["/etc/crontab"]
    for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
        if os.path.isdir(d):
            files += [os.path.join(d, f) for f in sorted(os.listdir(d))]
    hits = []
    for f in files:
        try:
            for line in open(f, errors="replace"):
                if line.strip().startswith("@reboot"):
                    hits.append({"file": f, "entry": line.strip()})
        except OSError:
            pass
    return _res("cron_boot_audit", reboot_entries=hits)


def motd_audit(args):
    """Audit MOTD/pam.d message scripts (execution-on-login surface)."""
    paths = ["/etc/motd", "/etc/update-motd.d", "/etc/profile.d"]
    found = {}
    for p in paths:
        if os.path.isfile(p):
            try:
                found[p] = open(p, errors="replace").read()[:2000]
            except OSError:
                pass
        elif os.path.isdir(p):
            found[p] = sorted(os.listdir(p))
    return _res("motd_audit", found=found)


def efi_vars_report(args):
    """Real EFI variable inventory (boot order etc.)."""
    d = "/sys/firmware/efi/efivars"
    if not os.path.isdir(d):
        return _res("efi_vars_report", efi=False, note="system booted in BIOS/legacy mode")
    names = sorted(os.listdir(d))[:200]
    boot_order = None
    for n in names:
        if n.startswith("BootOrder"):
            try:
                data = open(os.path.join(d, n), "rb").read()
                import struct
                boot_order = [struct.unpack("<H", data[4 + 2*i:6 + 2*i])[0]
                              for i in range((len(data) - 4) // 2)]
            except OSError:
                pass
    return _res("efi_vars_report", efi=True, variable_count=len(names),
                variables=[n.split("-")[0] for n in names][:80], boot_order=boot_order)


def secure_boot_report(args):
    """Real SecureBoot state from EFI vars."""
    d = "/sys/firmware/efi/efivars"
    for n in os.listdir(d) if os.path.isdir(d) else []:
        if n.startswith("SecureBoot-"):
            try:
                data = open(os.path.join(d, n), "rb").read()
                return _res("secure_boot_report", supported=True,
                            enabled=bool(data[-1]))
            except OSError:
                pass
    return _res("secure_boot_report", supported=os.path.isdir(d), enabled=None)


def kexec_load(args):
    """Load a kernel for kexec (armed, real kexec -l)."""
    kernel = str(args.get("kernel", ""))
    initrd = str(args.get("initrd", ""))
    cmdline = str(args.get("cmdline", "reuse"))
    if not kernel:
        return _err("kexec_load", "need 'kernel'")
    if not _armed(args):
        return _res("kexec_load", armed=False, would_load=kernel)
    cmd = ["kexec", "-l", kernel, "--append=" + (open("/proc/cmdline").read().strip()
           if cmdline == "reuse" else cmdline)]
    if initrd:
        cmd += ["--initrd=" + initrd]
    rc, out, err = _run(cmd)
    d = _res("kexec_load", armed=True, applied=(rc == 0), kernel=kernel,
             stderr=err.strip())
    d["ok"] = rc == 0
    return d


def boot_services_wanted(args):
    """List real services wired into boot targets (wants symlinks)."""
    wants = {}
    for target in ("multi-user.target", "graphical.target", "sysinit.target",
                   "network-online.target", "timers.target"):
        d = f"/etc/systemd/system/{target}.wants"
        if os.path.isdir(d):
            wants[target] = sorted(os.listdir(d))
    return _res("boot_services_wanted", wants=wants)


POWERS = {f"nm21.boot.{fn.__name__}": fn for fn in
          (bootloader_entries, kernel_images, initramfs_list, initramfs_unpack_list,
           default_kernel_report, grub_env_report, bootctl_status, runlevel_report,
           rc_local_audit, cron_boot_audit, motd_audit, efi_vars_report,
           secure_boot_report, kexec_load, boot_services_wanted)}

if __name__ == "__main__":
    print(json.dumps({"powers": sorted(POWERS)}, indent=2))
