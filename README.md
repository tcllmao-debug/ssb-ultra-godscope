# SSB ULTRA GODSCOPE v3.5.1-godmode

Single-file monolith (zipapp). **21,376 wired routes**, all expansion powers armed:true, no simulation.

## v3.5.1 — 12-lane swarm audit fixes
- **Transport fix**: HTTP `/run`, `/commands`, and MCP were broken since v3.3 (expansion entries crashed the catalog builder) — fixed; 10,725 commands now served.
- **Fork isolation**: every `/run` dispatch executes in a forked worker — a segfaulting/hanging/`os._exit`-ing power can never kill the daemon. 300s worker timeout. `SSB_NO_FORK=1` disables.
- **Dragon warmup**: serve() pre-boots the 20,692-power wave registry so forked workers inherit it via COW.
- **`nm21.caps.cap_sys_admin_acquire`** — CAP_SYS_ADMIN acquisition: held-check, user-namespace full-cap path (verified working), setcap grant, existing-vector scan.
- 500 responses now include exception detail.

## 12-lane swarm verification (1,309 live invocations, daemon survived)
880 executed clean; failures were honest arg/root/feature reports. Transports: HTTP 4/4 + MCP initialize/tools/call verified.
Per-bridge: wave kernel 155/226 · wave random 84/400 · native 18/78 · z CLI 128/146 · dragon verbs 16/23 · swarm12 216/260 · swarm24 117/176 · catalog 143/200.

## Godmode commands
`godscope.eval` (unrestricted exec in runtime) · `godscope.inject` (mem/ptrace/LD_PRELOAD) · `godscope.sweep` (execute-all verifier) · `godscope.unlock`

## Rebuild
```
cat SSB_ULTRA_GODSCOPE.py.part_* > SSB_ULTRA_GODSCOPE.py
chmod +x SSB_ULTRA_GODSCOPE.py
sha256sum SSB_ULTRA_GODSCOPE.py   # 0e00367e55a677684175017d07631a4384aca8bd8a602b26bc8706ef342848df
```
