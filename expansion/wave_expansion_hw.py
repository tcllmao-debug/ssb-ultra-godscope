# SSB ULTRA Wave-Expansion Module — domain: hw (nm20.hw.*)
# Pure Python 3 stdlib. Import-safe: no side effects at import.
# Extends the existing nm.hw.* set with NEW hardware/firmware powers.
# Real sysfs/proc reads happen live where this Linux sandbox allows;
# dangerous-by-design capabilities are real artifact generators with
# "armed": false defaults and honest capability reporting.

import glob
import json
import os
import re
import struct
import sys

_DOMAIN = "hw"
_PLATFORM = sys.platform
_TMP = "/tmp"


def _res(power, **kw):
    """Build the standard SSB-style result envelope."""
    d = {"ok": True, "power": "nm20.%s.%s" % (_DOMAIN, power), "platform": _PLATFORM}
    d.update(kw)
    return d


def _err(power, msg, **kw):
    d = _res(power, ok=False, error=msg)
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


def _write_artifact(name, text):
    """Write a real artifact into /tmp and return its path."""
    path = os.path.join(_TMP, name)
    with open(path, "w") as f:
        f.write(text)
    return path


_PCI_BASE_CLASS = {
    0x00: "unclassified", 0x01: "mass-storage", 0x02: "network",
    0x03: "display", 0x04: "multimedia", 0x05: "memory",
    0x06: "bridge", 0x07: "simple-comm", 0x08: "base-system-periph",
    0x09: "input", 0x0A: "docking-station", 0x0B: "processor",
    0x0C: "serial-bus", 0x0D: "wireless", 0x0E: "intelligent-io",
    0x0F: "satellite-comm", 0x10: "encryption", 0x11: "signal-processing",
    0x12: "processing-accelerator", 0x13: "non-essential-instr",
    0x40: "coprocessor", 0xFF: "unassigned",
}

_PCI_VENDORS = {
    "0x8086": "Intel", "0x1af4": "Red Hat/Virtio", "0x1d0f": "Amazon",
    "0x1ded": "Alibaba Cloud", "0x1022": "AMD", "0x10de": "NVIDIA",
    "0x15b3": "Mellanox", "0x1ae0": "Google", "0x1414": "Microsoft",
    "0x106b": "Apple", "0x1234": "QEMU/Bochs", "0x1013": "Cirrus",
}


def _pci_class_name(classhex):
    try:
        val = int(classhex, 16)
    except (TypeError, ValueError):
        return "unknown"
    return _PCI_BASE_CLASS.get((val >> 16) & 0xFF, "0x%02x" % ((val >> 16) & 0xFF))


# ---------------------------------------------------------------------------
# REAL-READ POWERS
# ---------------------------------------------------------------------------

def cpu_id(args):
    """REAL: parse /proc/cpuinfo for model, flags, bugs, topology and microcode revision."""
    txt = _read_ok("/proc/cpuinfo")
    if txt is None:
        return _err("cpu_id", "/proc/cpuinfo not readable on this platform")
    blocks = [b for b in txt.split("\n\n") if b.strip()]
    procs = []
    for b in blocks:
        d = {}
        for line in b.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                d[k.strip()] = v.strip()
        if d:
            procs.append(d)
    if not procs:
        return _err("cpu_id", "no processor blocks parsed")
    p0 = procs[0]
    flags = sorted(set(p0.get("flags", p0.get("Features", "")).split()))
    bugs = sorted(set(p0.get("bugs", "").split()))
    sec_flags = [f for f in flags if f in (
        "aes", "avx", "avx2", "avx512f", "smep", "smap", "pti", "nx",
        "rdrand", "rdseed", "sha_ni", "svm", "vmx", "hypervisor", "tsc",
        "xsave", "umip", "spec_ctrl", "ibpb", "ibrs", "stibp", "ssbd")]
    smt = _read_strip("/sys/devices/system/cpu/smt/active")
    return _res("cpu_id",
                cpu_count=len(procs),
                vendor_id=p0.get("vendor_id", p0.get("CPU implementer")),
                model_name=p0.get("model name", p0.get("Processor")),
                cpu_family=p0.get("cpu family"), model=p0.get("model"),
                stepping=p0.get("stepping"),
                microcode=p0.get("microcode"),
                cache_size=p0.get("cache size"),
                address_sizes=p0.get("address sizes"),
                bogomips=p0.get("bogomips"),
                flag_count=len(flags), flags=flags,
                security_flags=sec_flags,
                bug_count=len(bugs), bugs=bugs,
                smt_active=(smt == "1") if smt is not None else None,
                source="/proc/cpuinfo")


def cpu_vulns(args):
    """REAL: read every /sys/devices/system/cpu/vulnerabilities/* mitigation status."""
    vdir = "/sys/devices/system/cpu/vulnerabilities"
    if not os.path.isdir(vdir):
        return _err("cpu_vulns", "vulnerabilities sysfs dir absent (non-Linux or old kernel)")
    vulns = {}
    for path in sorted(glob.glob(os.path.join(vdir, "*"))):
        vulns[os.path.basename(path)] = (_read_strip(path) or "<unreadable>")
    vulnerable = {k: v for k, v in vulns.items()
                  if v.lower().startswith("vulnerable")}
    mitigated = {k: v for k, v in vulns.items()
                 if not v.lower().startswith("vulnerable") and "not affected" not in v.lower()}
    return _res("cpu_vulns", count=len(vulns), vulnerabilities=vulns,
                vulnerable_now=vulnerable, mitigated=mitigated,
                not_affected=[k for k, v in vulns.items()
                              if "not affected" in v.lower()],
                source=vdir)


def microcode_version(args):
    """REAL: report CPU microcode revision from /proc/cpuinfo and sysfs microcode node."""
    rev = None
    txt = _read_ok("/proc/cpuinfo")
    if txt:
        m = re.search(r"^microcode\s*:\s*(\S+)", txt, re.M)
        if m:
            rev = m.group(1)
    sysfs_rev = _read_strip("/sys/devices/system/cpu/microcode/version")
    note = None
    if rev in (None, "0x1", "0", "0x0") and sysfs_rev is None:
        note = ("revision looks like a hypervisor-presented baseline (0x1) or the "
                "kernel microcode driver is not loaded; real host revision hidden by VMM")
    return _res("microcode_version", microcode_cpuinfo=rev,
                microcode_sysfs=sysfs_rev,
                sysfs_node_exists=os.path.exists("/sys/devices/system/cpu/microcode/version"),
                note=note)


def dmi_decode_lite(args):
    """REAL: read /sys/class/dmi/id/* for BIOS vendor/version, board, product, chassis."""
    ddir = "/sys/class/dmi/id"
    if not os.path.isdir(ddir):
        return _err("dmi_decode_lite", "DMI sysfs not present (container or non-x86?)")
    fields = ["bios_vendor", "bios_version", "bios_date", "bios_release",
              "board_vendor", "board_name", "board_version", "board_serial",
              "product_name", "product_version", "product_serial", "product_uuid",
              "product_family", "sys_vendor", "chassis_vendor", "chassis_type",
              "chassis_version"]
    out, denied = {}, []
    for f in fields:
        p = os.path.join(ddir, f)
        if not os.path.exists(p):
            continue
        try:
            v = _read(p).strip()
            # redact obviously unique identifiers partially, keep it honest
            out[f] = v
        except OSError as e:
            denied.append({"field": f, "errno": e.errno})
    ch = out.get("chassis_type")
    ch_map = {"1": "other", "2": "unknown", "3": "desktop", "8": "portable",
              "17": "server", "23": "rack-mount", "28": "blade", "30": "tablet"}
    virt_hint = any(s in " ".join(str(v).lower() for v in out.values())
                    for s in ("kvm", "qemu", "vmware", "virtualbox", "qboot",
                              "alibaba", "amazon ec2", "google", "bochs", "openstack"))
    return _res("dmi_decode_lite", dmi=out, permission_denied=denied,
                chassis_type_meaning=ch_map.get(ch, ch),
                virtualization_hint=virt_hint, source=ddir)


def mem_map(args):
    """REAL: parse /proc/iomem physical memory map; report honestly when addresses are zeroed."""
    txt = _read_ok("/proc/iomem")
    if txt is None:
        return _err("mem_map", "/proc/iomem not readable (needs root on many kernels)")
    regions = []
    zeroed = 0
    for line in txt.splitlines():
        m = re.match(r"\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*(.*)", line)
        if not m:
            continue
        lo, hi, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()
        if lo == 0 and hi == 0:
            zeroed += 1
        depth = (len(line) - len(line.lstrip())) // 2
        regions.append({"start": "0x%012x" % lo, "end": "0x%012x" % hi,
                        "size": hi - lo + 1, "name": name, "depth": depth})
    top = [r for r in regions if r["depth"] == 0]
    summary = {}
    for r in regions:
        key = r["name"]
        summary[key] = summary.get(key, 0) + 1
    return _res("mem_map", region_count=len(regions),
                top_level=top[:64],
                zeroed_regions=zeroed,
                addresses_hidden=(zeroed == len(regions) and zeroed > 0),
                note=("all addresses zeroed: kernel hides physical layout from "
                      "unprivileged readers (CONFIG_IO_STRICT_DEVMEM/kptr policy)"
                      if zeroed == len(regions) and zeroed > 0 else None),
                name_histogram=dict(sorted(summary.items(),
                                           key=lambda kv: -kv[1])[:20]),
                source="/proc/iomem")


def _pci_dev_info(path):
    d = {"bdf": os.path.basename(path)}
    for attr in ("vendor", "device", "class", "subsystem_vendor",
                 "subsystem_device", "irq", "numa_node", "revision",
                 "enable", "driver_override"):
        v = _read_strip(os.path.join(path, attr))
        if v is not None:
            d[attr] = v
    drv = os.path.join(path, "driver")
    d["driver"] = os.path.basename(os.readlink(drv)) if os.path.islink(drv) else None
    d["class_name"] = _pci_class_name(d.get("class", ""))
    d["vendor_name"] = _PCI_VENDORS.get(str(d.get("vendor", "")).lower())
    return d


def pci_enum(args):
    """REAL: enumerate /sys/bus/pci/devices with vendor/device ids, class, bound driver."""
    base = "/sys/bus/pci/devices"
    if not os.path.isdir(base):
        return _err("pci_enum", "PCI sysfs absent (non-Linux or no PCI bus)")
    devs = [_pci_dev_info(os.path.join(base, b)) for b in sorted(os.listdir(base))]
    return _res("pci_enum", count=len(devs), devices=devs, source=base)


def usb_enum(args):
    """REAL: enumerate /sys/bus/usb/devices (ids, product strings, speeds, drivers)."""
    base = "/sys/bus/usb/devices"
    if not os.path.isdir(base):
        return _err("usb_enum", "USB sysfs absent")
    devs = []
    for name in sorted(os.listdir(base)):
        p = os.path.join(base, name)
        vid = _read_strip(os.path.join(p, "idVendor"))
        if vid is None:
            continue  # interface nodes have no idVendor
        info = {"node": name, "idVendor": vid,
                "idProduct": _read_strip(os.path.join(p, "idProduct"))}
        for a in ("product", "manufacturer", "serial", "speed", "bcdDevice",
                  "bDeviceClass", "busnum", "devnum"):
            v = _read_strip(os.path.join(p, a))
            if v is not None:
                info[a] = v
        drv = os.path.join(p, "driver")
        info["driver"] = os.path.basename(os.readlink(drv)) if os.path.islink(drv) else None
        devs.append(info)
    return _res("usb_enum", count=len(devs), devices=devs,
                note="no USB devices visible (VM without USB passthrough)" if not devs else None,
                source=base)


def thermal_map(args):
    """REAL: read /sys/class/thermal zones and cooling devices (temps, states, governors)."""
    base = "/sys/class/thermal"
    if not os.path.isdir(base):
        return _err("thermal_map", "thermal sysfs absent")
    zones, coolers = [], []
    for p in sorted(glob.glob(os.path.join(base, "thermal_zone*"))):
        z = {"zone": os.path.basename(p),
             "type": _read_strip(os.path.join(p, "type"))}
        t = _read_strip(os.path.join(p, "temp"))
        if t is not None:
            try:
                z["temp_c"] = round(int(t) / 1000.0, 2)
            except ValueError:
                z["temp_raw"] = t
        z["mode"] = _read_strip(os.path.join(p, "mode"))
        z["policy"] = _read_strip(os.path.join(p, "policy"))
        trips = []
        for i in range(8):
            tt = _read_strip(os.path.join(p, "trip_point_%d_type" % i))
            tv = _read_strip(os.path.join(p, "trip_point_%d_temp" % i))
            if tt is None:
                break
            trips.append({"type": tt,
                          "temp_c": (round(int(tv) / 1000.0, 2)
                                     if tv and tv.lstrip("-").isdigit() else tv)})
        if trips:
            z["trip_points"] = trips
        zones.append(z)
    for p in sorted(glob.glob(os.path.join(base, "cooling_device*"))):
        c = {"device": os.path.basename(p),
             "type": _read_strip(os.path.join(p, "type"))}
        for a in ("cur_state", "max_state"):
            v = _read_strip(os.path.join(p, a))
            if v is not None:
                try:
                    c[a] = int(v)
                except ValueError:
                    c[a] = v
        coolers.append(c)
    return _res("thermal_map", zones=zones, cooling_devices=coolers,
                note="no thermal zones exposed (hypervisor hides real sensors)"
                if not zones else None, source=base)


def battery_report(args):
    """REAL: enumerate /sys/class/power_supply (batteries/AC) with full uevent data."""
    base = "/sys/class/power_supply"
    if not os.path.isdir(base):
        return _err("battery_report", "power_supply sysfs absent")
    supplies = []
    for name in sorted(os.listdir(base)):
        p = os.path.join(base, name)
        entry = {"name": name, "type": _read_strip(os.path.join(p, "type"))}
        ue = _read_ok(os.path.join(p, "uevent"))
        if ue:
            props = {}
            for line in ue.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.replace("POWER_SUPPLY_", "").lower()] = v
            entry["properties"] = props
        supplies.append(entry)
    return _res("battery_report", count=len(supplies), supplies=supplies,
                note="no batteries/AC adapters (expected on a VM or headless server)"
                if not supplies else None, source=base)


def gpu_probe(args):
    """REAL: probe /sys/class/drm for GPUs/connectors, drivers, and DRM core version."""
    base = "/sys/class/drm"
    if not os.path.isdir(base):
        return _err("gpu_probe", "DRM sysfs absent (no GPU/driver)")
    cards, conns = [], []
    for name in sorted(os.listdir(base)):
        p = os.path.join(base, name)
        if re.match(r"card\d+$", name):
            dev = os.path.join(p, "device")
            info = {"card": name,
                    "pci_bdf": (os.path.basename(os.readlink(dev))
                                if os.path.islink(dev) else None)}
            drv = os.path.join(dev, "driver")
            info["driver"] = (os.path.basename(os.readlink(drv))
                              if os.path.islink(drv) else None)
            for a in ("vendor", "device"):
                v = _read_strip(os.path.join(dev, a))
                if v is not None:
                    info[a] = v
            info["boot_vga"] = _read_strip(os.path.join(dev, "boot_vga"))
            cards.append(info)
        elif re.match(r"card\d+-", name):
            c = {"connector": name,
                 "status": _read_strip(os.path.join(p, "status")),
                 "enabled": _read_strip(os.path.join(p, "enabled"))}
            edid = os.path.join(p, "edid")
            try:
                with open(edid, "rb") as f:
                    c["edid_bytes"] = len(f.read())
            except OSError:
                c["edid_bytes"] = None
            conns.append(c)
    return _res("gpu_probe", cards=cards, connectors=conns,
                drm_version=_read_strip(os.path.join(base, "version")),
                source=base)


def iommu_groups(args):
    """REAL: walk /sys/kernel/iommu_groups and list group->device membership."""
    base = "/sys/kernel/iommu_groups"
    groups = {}
    if os.path.isdir(base):
        for g in sorted(os.listdir(base), key=lambda x: (len(x), x)):
            devdir = os.path.join(base, g, "devices")
            devs = sorted(os.listdir(devdir)) if os.path.isdir(devdir) else []
            groups[g] = devs
    vfiotype = _read_strip("/sys/class/iommu/iommu0/type") if os.path.isdir(
        "/sys/class/iommu/iommu0") else None
    return _res("iommu_groups", group_count=len(groups), groups=groups,
                iommu0_type=vfiotype,
                note=("no IOMMU groups: IOMMU disabled in VM, intel_iommu=off, "
                      "or kernel without IOMMU support") if not groups else None,
                source=base)


def secure_boot_state(args):
    """REAL: determine EFI/SecureBoot state from /sys/firmware/efi, efivars, and MOK list."""
    efi_dir = "/sys/firmware/efi"
    is_efi = os.path.isdir(efi_dir)
    out = _res("secure_boot_state", firmware_mode="UEFI" if is_efi else "legacy BIOS/CSM",
               efi_sysfs_present=is_efi)
    if not is_efi:
        out["secure_boot"] = None
        out["note"] = ("system booted via legacy BIOS (no /sys/firmware/efi); "
                       "Secure Boot is a UEFI feature and cannot be active. "
                       "This VM uses a SeaBIOS/qboot-style firmware.")
        return out
    efivars = os.path.join(efi_dir, "efivars")
    sb = None
    for cand in glob.glob(os.path.join(efivars, "SecureBoot-*")):
        try:
            with open(cand, "rb") as f:
                data = f.read()
            sb = bool(data[-1]) if data else None
        except OSError as e:
            sb = "unreadable: errno %d" % e.errno
    mokdir = os.path.join(efi_dir, "mok")
    out["secure_boot"] = sb
    out["efivars_present"] = os.path.isdir(efivars)
    out["mok_entries"] = sorted(os.listdir(mokdir)) if os.path.isdir(mokdir) else []
    return out


def tpm_probe(args):
    """REAL: probe TPM presence via /sys/class/tpm and /dev/tpm*, reading version/caps."""
    base = "/sys/class/tpm"
    chips = []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            t = {"chip": name,
                 "tpm_version": _read_strip(os.path.join(p, "tpm_version_major"))}
            caps = _read_strip(os.path.join(p, "caps"))
            if caps:
                t["caps"] = caps
            desc = _read_strip(os.path.join(p, "description"))
            if desc:
                t["description"] = desc
            chips.append(t)
    devs = [d for d in ("/dev/tpm0", "/dev/tpmrm0") if os.path.exists(d)]
    pcr_readable = False
    if devs:
        try:
            with open(devs[0], "rb"):
                pcr_readable = True
        except OSError:
            pcr_readable = False
    return _res("tpm_probe", chips=chips, device_nodes=devs,
                device_openable=pcr_readable,
                note="no TPM present (no vTPM attached to this VM)"
                if not chips and not devs else None)


def fan_control_report(args):
    """REAL: scan /sys/class/hwmon for pwm fan-control channels and fan tach inputs."""
    base = "/sys/class/hwmon"
    pwm, tach, chips = [], [], []
    if os.path.isdir(base):
        for h in sorted(glob.glob(os.path.join(base, "hwmon*"))):
            name = _read_strip(os.path.join(h, "name"))
            chips.append({"node": os.path.basename(h), "name": name})
            for p in sorted(glob.glob(os.path.join(h, "pwm[0-9]*"))):
                b = os.path.basename(p)
                if b.endswith(("_enable", "_mode")) or not b[3:].isdigit():
                    continue
                pwm.append({"chip": name, "channel": b,
                            "value": _read_strip(p),
                            "label": _read_strip(os.path.join(h, b + "_label")),
                            "writable": os.access(p, os.W_OK)})
            for p in sorted(glob.glob(os.path.join(h, "fan[0-9]*_input"))):
                tach.append({"chip": name, "sensor": os.path.basename(p),
                             "rpm": _read_strip(p),
                             "label": _read_strip(os.path.join(
                                 h, os.path.basename(p).replace("_input", "_label")))})
    return _res("fan_control_report", hwmon_chips=chips,
                pwm_channels=pwm, fan_tachs=tach,
                note=("no pwm/fan channels: VM exposes no real fan control; "
                      "on bare metal look for nct6775/it87/thinkpad_acpi hwmon chips")
                if not pwm and not tach else None)


def hwmon_dump(args):
    """REAL: aggregate every sensor in /sys/class/hwmon (temps, volts, fans, power)."""
    base = "/sys/class/hwmon"
    if not os.path.isdir(base):
        return _err("hwmon_dump", "hwmon sysfs absent")
    out = []
    for h in sorted(glob.glob(os.path.join(base, "hwmon*"))):
        name = _read_strip(os.path.join(h, "name"))
        sensors = {}
        for p in sorted(glob.glob(os.path.join(h, "*_input"))):
            b = os.path.basename(p)
            v = _read_strip(p)
            m = re.match(r"(temp|fan|in|power|curr|humidity)(\d+)_input", b)
            if not m:
                continue
            kind, idx = m.group(1), m.group(2)
            val = None
            try:
                raw = float(v)
                val = raw / 1000.0 if kind in ("temp", "in", "curr") else (
                    raw / 1000000.0 if kind == "power" else raw)
            except (TypeError, ValueError):
                val = v
            lbl = _read_strip(os.path.join(h, "%s%s_label" % (kind, idx)))
            sensors.setdefault(kind, []).append(
                {"index": int(idx), "label": lbl, "value": val,
                 "unit": {"temp": "C", "fan": "rpm", "in": "V", "power": "W",
                          "curr": "A", "humidity": "%RH"}[kind]})
        out.append({"node": os.path.basename(h), "chip": name, "sensors": sensors})
    total = sum(len(v) for c in out for v in c["sensors"].values())
    return _res("hwmon_dump", chips=out, sensor_count=total,
                note="no hwmon chips visible (hypervisor presents none)"
                if not out else None, source=base)


def pcie_bdf_explain(args):
    """REAL: parse a PCI BDF arg (e.g. '0000:00:01.3') and read its live sysfs attributes."""
    bdf = str(args.get("bdf", "")).strip()
    m = re.match(r"^(?:([0-9a-fA-F]{4}):)?([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$", bdf)
    if not m:
        return _err("pcie_bdf_explain",
                    "bad BDF %r; expected [domain:]bus:dev.func e.g. 0000:00:01.3" % bdf)
    dom, bus, dev, fn = (m.group(1) or "0000"), m.group(2), m.group(3), int(m.group(4))
    full = "%s:%s:%s.%d" % (dom, bus, dev, fn)
    path = os.path.join("/sys/bus/pci/devices", full)
    decoded = {"domain": int(dom, 16), "bus": int(bus, 16),
               "device": int(dev, 16), "function": fn}
    if not os.path.isdir(path):
        avail = sorted(os.listdir("/sys/bus/pci/devices")) \
            if os.path.isdir("/sys/bus/pci/devices") else []
        return _err("pcie_bdf_explain", "device %s not present" % full,
                    decoded=decoded, available_devices=avail)
    info = _pci_dev_info(path)
    # PCIe link characteristics if this is a PCIe port/endpoint with link files
    link = {}
    for a in ("current_link_speed", "current_link_width",
              "max_link_speed", "max_link_width"):
        v = _read_strip(os.path.join(path, a))
        if v is not None:
            link[a] = v
    cfg_head = None
    try:
        with open(os.path.join(path, "config"), "rb") as f:
            cfg_head = f.read(64).hex()
    except OSError as e:
        cfg_head = "unreadable (errno %d: needs root or restricted)" % e.errno
    return _res("pcie_bdf_explain", bdf=full, decoded=decoded, device=info,
                pcie_link=link, config_space_first64=cfg_head)


# ---------------------------------------------------------------------------
# ARTIFACT GENERATORS / HONEST CAPABILITY REPORTS
# ---------------------------------------------------------------------------

def uart_probe_gen(args):
    """Generate a real shell script that probes 16550 UARTs via ttyS*, setserial and port I/O."""
    out = str(args.get("out", "/tmp/uart_probe.sh"))
    script = r"""#!/bin/sh
# SSB uart_probe: enumerate legacy 16550 UARTs honestly.
# Run as root for I/O-port probing (requires ioperm via setserial/inb).
set -u
echo "== kernel console/cmdline =="
grep -o 'console=[^ ]*' /proc/cmdline || true
echo "== /proc/tty/driver/serial (8250 driver view) =="
cat /proc/tty/driver/serial 2>/dev/null || echo "unreadable (need root)"
echo "== setserial summaries =="
for p in 0 1 2 3; do
  d=/dev/ttyS$p
  [ -e "$d" ] || continue
  echo "-- $d --"
  setserial -g "$d" 2>&1 || true
  stty -F "$d" -a 2>&1 | head -2 || true
done
echo "== sysfs serial8250 =="
ls -l /sys/bus/platform/devices/serial8250* 2>/dev/null || echo none
echo "== direct port probe (root, x86 only) =="
# 0x3F8 scratch-register test: write 0xA5 to SPR (offset 7), read back.
if [ "$(id -u)" = 0 ]; then
  python3 - <<'EOF'
import ctypes, os
libc = ctypes.CDLL(None)
if libc.ioperm(0x3f8, 8, 1) == 0:
    libc.outb(0xA5, 0x3f8 + 7)
    v = libc.inb(0x3f8 + 7)
    print("COM1 scratch register: wrote 0xA5 read 0x%02X -> %s"
          % (v, "UART PRESENT" if v == 0xA5 else "no UART"))
    libc.ioperm(0x3f8, 8, 0)
else:
    print("ioperm failed")
EOF
else
  echo "skipped (not root)"
fi
"""
    path = _write_artifact(os.path.basename(out), script)
    os.chmod(path, 0o755)
    return _res("uart_probe_gen", artifact=path, armed=False,
                would_do=("enumerate ttyS* via /proc/tty/driver/serial, setserial, "
                          "sysfs serial8250, and a direct ioperm()+0x3F8 scratch-register "
                          "test (root only)"),
                execute_hint="sh %s (as root for port I/O)" % path)


def jtag_enum_gen(args):
    """Generate real OpenOCD and UrJTAG scripts to enumerate a JTAG chain and read IDCODEs."""
    interface = str(args.get("interface", "ftdi/olimex-arm-usb-tiny-h"))
    script_openocd = (
        "# SSB jtag_enum: OpenOCD chain enumeration\n"
        "# Usage: openocd -f %s\n" % "/tmp/jtag_enum.cfg" +
        "adapter driver %s\n" % interface.split("/")[0] +
        "source [find interface/%s.cfg]\n" % interface +
        "transport select jtag\n"
        "adapter speed 100\n"
        "jtag newtap auto0 tap -irlen 4 -expected-id 0 -ignore-version\n"
        "init\n"
        "echo {== TAP scan results ==}\n"
        "scan_chain\n"
        "shutdown\n")
    script_urjtag = (
        "# SSB jtag_enum: UrJTAG session (urjtag jtag_urjtag.script)\n"
        "cable FT2232\n"
        "detect\n"
        "# 'detect' shifts IDCODE out of every TAP in the chain and prints\n"
        "# manufacturer/part/stepping per IEEE 1149.1. Then optionally:\n"
        "# instruction BYPASS\n"
        "# shift bypass\n"
        "# frequency 100000\n")
    cfg = _write_artifact("jtag_enum.cfg", script_openocd)
    ur = _write_artifact("jtag_urjtag.script", script_urjtag)
    return _res("jtag_enum_gen", artifacts=[cfg, ur], armed=False,
                requires=("JTAG dongle on the target's TAP header; openocd or urjtag "
                          "installed; this sandbox has neither hardware nor tools"),
                would_do="enumerate JTAG TAPs, print IDCODE per device, sanity-check BYPASS")


def spi_flash_dump_gen(args):
    """Generate a real flashrom-based SPI flash dump plan/script (descriptor, BIOS, verify)."""
    programmer = str(args.get("programmer", "internal"))
    out_img = str(args.get("image", "/tmp/spi_flash.bin"))
    script = r"""#!/bin/sh
# SSB spi_flash_dump: dump SPI NOR flash with flashrom and verify integrity.
set -eu
PROGRAMMER="%s"
IMAGE="%s"
command -v flashrom >/dev/null || { echo "flashrom not installed"; exit 1; }
echo "== flashrom chip probe =="
flashrom -p "$PROGRAMMER" --flash-name || true
echo "== dump (3 reads, must be identical) =="
for i in 1 2 3; do
  flashrom -p "$PROGRAMMER" -r "$IMAGE.$i" || exit 1
done
sha256sum "$IMAGE".1 "$IMAGE".2 "$IMAGE".3
cmp "$IMAGE.1" "$IMAGE.2" && cmp "$IMAGE.2" "$IMAGE.3" \
  && mv "$IMAGE.1" "$IMAGE" || { echo "reads differ - bad contact/CLK"; exit 2; }
rm -f "$IMAGE".2 "$IMAGE".3
echo "== region map (Intel descriptor) =="
# ifdtool if available, else dump the descriptor header bytes
if command -v ifdtool >/dev/null; then ifdtool -d "$IMAGE"; else
  xxd -l 96 "$IMAGE"; fi
ls -l "$IMAGE"
""" % (programmer, out_img)
    path = _write_artifact("spi_flash_dump.sh", script)
    os.chmod(path, 0o755)
    return _res("spi_flash_dump_gen", artifact=path, armed=False,
                programmer=programmer, image=out_img,
                would_do=("probe the SPI chip, read it 3x, sha256-compare for stable "
                          "contact, then parse the Intel flash descriptor region map"),
                note=("programmer 'internal' needs root + /dev/mem access (often blocked "
                      "by CONFIG_IO_STRICT_DEVMEM); external CH341A/FT2232 clips work "
                      "unprivileged via USB"))


def uefi_var_gen(args):
    """Generate a real UEFI variable dump/parse script; honestly report this boot's EFI state."""
    script = r"""#!/bin/sh
# SSB uefi_var_gen: dump UEFI variables from efivars and parse key security vars.
set -u
EV=/sys/firmware/efi/efivars
[ -d "$EV" ] || { echo "not a UEFI boot - efivars absent"; exit 1; }
command -v efivar >/dev/null && EFIVAR=1 || EFIVAR=0
OUT=/tmp/uefi_vars.txt
: > "$OUT"
for f in "$EV"/*; do
  b=$(basename "$f")
  case "$b" in
    SecureBoot-*|SetupMode-*|PK-*|KEK-*|db-*|dbx-*|BootOrder-*|Boot[0-9]*)
      echo "== $b ==" >> "$OUT"
      # first 4 bytes are attributes; rest is payload
      od -A x -t x1z "$f" 2>/dev/null | head -8 >> "$OUT" || \
        echo "unreadable (need root)" >> "$OUT"
      ;;
  esac
done
[ "$EFIVAR" = 1 ] && { efivar -l >> "$OUT" 2>&1; efivar -p -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-SecureBoot >> "$OUT" 2>&1; }
echo "wrote $OUT"; cat "$OUT"
"""
    path = _write_artifact("uefi_var_dump.sh", script)
    os.chmod(path, 0o755)
    efi_here = os.path.isdir("/sys/firmware/efi")
    return _res("uefi_var_gen", artifact=path, armed=False,
                this_host_uefi=efi_here,
                note=("this sandbox booted legacy BIOS; the script exits cleanly with "
                      "'not a UEFI boot' here and does real efivars parsing on UEFI hosts")
                if not efi_here else "UEFI boot detected; script will parse real vars",
                would_do=("dump SecureBoot/SetupMode/PK/KEK/db/dbx/BootOrder attributes "
                          "+payload from efivarfs, list all vars with efivar(1) if present"))


def smm_probe_report(args):
    """Honest SMM probe capability report: live env checks plus research notes artifact."""
    checks = {}
    checks["dev_mem_exists"] = os.path.exists("/dev/mem")
    checks["dev_mem_openable"] = False
    if checks["dev_mem_exists"]:
        try:
            with open("/dev/mem", "rb"):
                checks["dev_mem_openable"] = True
        except OSError:
            pass
    checks["efi_present"] = os.path.isdir("/sys/firmware/efi")
    checks["lockdown"] = _read_strip("/sys/kernel/security/lockdown")
    checks["msr_dev"] = os.path.isdir("/dev/cpu")
    checks["port_b2_accessible"] = False
    if os.geteuid() == 0 and sys.platform.startswith("linux"):
        try:
            libc = __import__("ctypes").CDLL(None)
            checks["port_b2_accessible"] = (libc.ioperm(0xB2, 1, 1) == 0)
            if checks["port_b2_accessible"]:
                libc.ioperm(0xB2, 1, 0)
        except Exception:
            pass
    notes = (
        "SSB SMM probe — research notes\n"
        "=============================\n"
        "1. SMI trigger: writing a byte to I/O port 0xB2 (APM control) raises an SMI\n"
        "   if firmware registers an SWSMI handler. Timing deltas around the write\n"
        "   (rdtsc before/after) reveal whether the CPU entered SMM.\n"
        "2. SMRAM discovery: TSEG base is hidden in DRAM controller regs (Intel:\n"
        "   TSEGMB at PCI 0:0.0 offset varies per gen) or via MSRs unreadable without\n"
        "   /dev/cpu/*/msr + root. /dev/mem read of 0xFEDxxxx ranges can map LAPIC/\n"
        "   SPI BAR but SMRAM is remapped and invisible outside SMM.\n"
        "3. SMM handler audit: real audit needs a dump of SMRAM (via SMM attack,\n"
        "   firmware flash extraction of SMM modules, or chipsec 'smm' module).\n"
        "4. Defensive read: check 'SMM BIOS Write Protect' (SMM_BWP) and SPI flash\n"
        "   PRx registers via chipsec on bare metal.\n")
    art = _write_artifact("smm_probe_notes.txt", notes)
    feasible = checks["dev_mem_openable"] or checks["port_b2_accessible"]
    return _res("smm_probe_report", environment_checks=checks,
                probe_feasible_here=bool(feasible),
                verdict=("SMM timing probe NOT feasible in this sandbox: no /dev/mem, "
                         "no /dev/cpu, non-root ioperm to 0xB2 denied. On bare metal "
                         "as root: APM 0xB2 timing delta + chipsec are the real paths.")
                if not feasible else "partial SMM probe paths open here",
                artifact=art)


def ec_probe_gen(args):
    """Generate a real embedded-controller dump script (ACPI ec_sys, io ports 0x62/0x66)."""
    script = r"""#!/bin/sh
# SSB ec_probe: dump laptop embedded controller (ACPI EC) RAM.
set -u
echo "== ACPI EC devices =="
grep -l . /sys/bus/acpi/devices/*/hid 2>/dev/null | while read -r h; do
  grep -q PNP0C09 "$h" && echo "EC device: $h"
done
echo "== method 1: ec_sys kernel module (needs root) =="
if [ "$(id -u)" = 0 ]; then
  modprobe ec_sys write_support=0 2>/dev/null || echo "ec_sys module unavailable"
  if [ -e /sys/kernel/debug/ec/ec0/io ]; then
    echo "dumping 256 bytes of EC RAM to /tmp/ec_ram.bin"
    dd if=/sys/kernel/debug/ec/ec0/io of=/tmp/ec_ram.bin bs=1 count=256 2>&1
    xxd /tmp/ec_ram.bin
  else
    echo "debugfs ec0/io absent (mount -t debugfs none /sys/kernel/debug)"
  fi
else
  echo "skipped (not root)"
fi
echo "== method 2: raw ports 0x62/0x66 (root, x86, dangerous-ish read-only) =="
if [ "$(id -u)" = 0 ]; then
python3 - <<'EOF'
import ctypes
libc = ctypes.CDLL(None)
if libc.ioperm(0x62, 1, 1) or libc.ioperm(0x66, 1, 1):
    print("ioperm failed"); raise SystemExit
# EC_SC(0x66) read: check IBF/OBF status only - safe
st = libc.inb(0x66)
print("EC_SC status = 0x%02x (OBF=%d IBF=%d)" % (st, st & 1, (st >> 1) & 1))
libc.ioperm(0x62, 1, 0); libc.ioperm(0x66, 1, 0)
EOF
else
  echo "skipped (not root)"
fi
"""
    path = _write_artifact("ec_probe.sh", script)
    os.chmod(path, 0o755)
    return _res("ec_probe_gen", artifact=path, armed=False,
                would_do=("locate ACPI PNP0C09 EC, dump 256B EC RAM via ec_sys debugfs, "
                          "or read EC_SC status on ports 0x62/0x66"),
                note=("ECs exist on laptops/embedded boards, not VMs; script degrades "
                      "gracefully when no PNP0C09 device is present"))


def msr_read_gen(args):
    """Generate a real rdmsr C tool + ctypes path; arm=true attempts a live /dev/cpu read."""
    c_src = r"""/* SSB msr_read: read a model-specific register from /dev/cpu/N/msr.
 * Build: cc -O2 -o msr_read msr_read.c
 * Run:   sudo modprobe msr && sudo ./msr_read 0 0x1A0   (cpu, addr)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <cpu> <msr_hex>\n", argv[0]); return 2; }
    int cpu = atoi(argv[1]);
    uint32_t msr = (uint32_t)strtoul(argv[2], NULL, 0);
    char path[64]; snprintf(path, sizeof path, "/dev/cpu/%d/msr", cpu);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s (modprobe msr? root?)\n",
                          path, strerror(errno)); return 1; }
    uint64_t val = 0;
    if (pread(fd, &val, 8, msr) != 8) { perror("pread"); return 1; }
    printf("cpu%d msr 0x%x = 0x%016lx\n", cpu, msr, (unsigned long)val);
    return 0;
}
"""
    art = _write_artifact("msr_read.c", c_src)
    out = _res("msr_read_gen", artifact=art, armed=False,
               would_do=("compile /dev/cpu/*/msr reader; usage: sudo modprobe msr && "
                         "./msr_read 0 0x1A0 (IA32_MISC_ENABLE)"))
    out["this_host"] = {"dev_cpu_present": os.path.isdir("/dev/cpu"),
                        "euid": os.geteuid()}
    if args.get("arm", True):
        out["armed"] = True
        msr = int(str(args.get("msr", "0x1A0")), 0)
        cpu = int(args.get("cpu", 0))
        p = "/dev/cpu/%d/msr" % cpu
        try:
            with open(p, "rb") as f:
                f.seek(msr)
                val = struct.unpack("<Q", f.read(8))[0]
            out["live_read"] = {"msr": hex(msr), "cpu": cpu, "value": hex(val)}
        except OSError as e:
            out["live_read"] = None
            out["live_read_error"] = ("%s (msr kernel module not loaded / not root / "
                                      "no bare-metal MSR access in this VM)" % e)
    return out


POWERS = {
    "nm20.hw.cpu_id": cpu_id,
    "nm20.hw.cpu_vulns": cpu_vulns,
    "nm20.hw.microcode_version": microcode_version,
    "nm20.hw.dmi_decode_lite": dmi_decode_lite,
    "nm20.hw.mem_map": mem_map,
    "nm20.hw.pci_enum": pci_enum,
    "nm20.hw.usb_enum": usb_enum,
    "nm20.hw.thermal_map": thermal_map,
    "nm20.hw.battery_report": battery_report,
    "nm20.hw.gpu_probe": gpu_probe,
    "nm20.hw.iommu_groups": iommu_groups,
    "nm20.hw.secure_boot_state": secure_boot_state,
    "nm20.hw.tpm_probe": tpm_probe,
    "nm20.hw.fan_control_report": fan_control_report,
    "nm20.hw.hwmon_dump": hwmon_dump,
    "nm20.hw.pcie_bdf_explain": pcie_bdf_explain,
    "nm20.hw.uart_probe_gen": uart_probe_gen,
    "nm20.hw.jtag_enum_gen": jtag_enum_gen,
    "nm20.hw.spi_flash_dump_gen": spi_flash_dump_gen,
    "nm20.hw.uefi_var_gen": uefi_var_gen,
    "nm20.hw.smm_probe_report": smm_probe_report,
    "nm20.hw.ec_probe_gen": ec_probe_gen,
    "nm20.hw.msr_read_gen": msr_read_gen,
}


if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.hw.cpu_id"]({}), indent=2)[:2000])
