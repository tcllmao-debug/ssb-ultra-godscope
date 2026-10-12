# SSB ULTRA GODSCOPE v3.4.0-swarm24-armed

Single-file monolith (zipapp). 21,371 wired routes across 7 bridges:
native (74) · z-seed CLI (146) · dragon verbs (23) · wave powers (20,692) · swarm-12 expansion (260) · swarm-24 expansion (176) · godscope map/layers/selftest.

Every expansion power ships **armed:true** — mutations apply by default; pass `{"arm": false}` to dry-run.
No simulation stubs: every power performs real syscalls/sysfs/procfs/ioctl work or returns an honest error.

## Swarm-24 modules (nm21.*)
access (sudoers/polkit/ACL/key grants) · caps (capability control + priv-esc matrix) · kernctl (sysctl/module/kprobe control) · systemd (units/timers/journal/drop-ins) · ns (namespaces/cgroups/netns) · secmod (SELinux/AppArmor/seccomp) · audit (auditd rules/log forensics/integrity) · fsctl (mounts/overlay/immutable/quotas) · netctl (nftables/tc/raw packets/vxlan) · boot (bootloader/initramfs/EFI/kexec) · sched (affinity/RT/rlimits/OOM) · vault (keyctl/gpg/ssh-agent/secret scans/JWT)

## Rebuild
```
cat SSB_ULTRA_GODSCOPE.py.part_* > SSB_ULTRA_GODSCOPE.py
chmod +x SSB_ULTRA_GODSCOPE.py
sha256sum SSB_ULTRA_GODSCOPE.py   # 58a46adfc343713e97cc229e375d1faadf15f6303d9a81786d0c0b484e5c7c38
```

## Run
```
python3 SSB_ULTRA_GODSCOPE.py                          # status (v3.4.0-swarm24)
python3 SSB_ULTRA_GODSCOPE.py godscope.selftest        # 12-leg wiring proof
python3 SSB_ULTRA_GODSCOPE.py --godscope               # dump full wiring seed
python3 SSB_ULTRA_GODSCOPE.py --serve --port 8787      # HTTP API + MCP
python3 SSB_ULTRA_GODSCOPE.py nm21.kernctl.sysctl_dump --json '{"prefix":"kernel"}'
python3 SSB_ULTRA_GODSCOPE.py power.nm21.caps.priv_esc_cap_matrix --json '{}'
```

- `SSB_WIRING_SEED.json` — every route + binding (any AI can load this to see everything SSB can do)
- `expansion/` — swarm-12 modules (nm20.*, armed) · `expansion2/` — swarm-24 modules (nm21.*, armed)
- `REASSEMBLE_SSB_ULTRA_v2.py` — rebuilds the base archive from the 25 base64 text chunks
