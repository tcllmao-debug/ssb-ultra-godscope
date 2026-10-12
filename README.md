# SSB ULTRA GODSCOPE v3.5.0-godmode

Single-file monolith (zipapp). **21,375 wired routes**, every expansion power **armed:true**, no simulation.

## Godmode commands (new)
- `godscope.eval` — unrestricted Python eval/exec inside the live runtime (`dispatch` + `seed` in scope)
- `godscope.inject` — local injection primitives: `maps`, `mem_write` (/proc/pid/mem), `ptrace_write` (PTRACE_POKEDATA), `ld_preload_gen`, `dlopen_gen`
- `godscope.sweep` — executes every route and classifies executed/error/stub (filters: kind, category, limit, workers)
- `godscope.unlock` — rearms dragon guards (1,821), sets SSB_UNRESTRICTED, confirms armed state

## Bridges
native (78) · z-seed CLI (146) · dragon verbs (23) · wave powers (20,692) · swarm-12 nm20 (260) · swarm-24 nm21 (176) · godscope

## Rebuild
```
cat SSB_ULTRA_GODSCOPE.py.part_* > SSB_ULTRA_GODSCOPE.py
chmod +x SSB_ULTRA_GODSCOPE.py
sha256sum SSB_ULTRA_GODSCOPE.py   # 4256e15c14576566a3fd05cbfbebd2d3e736d3a873de30d4945e536afd40fb13
```

## Run
```
python3 SSB_ULTRA_GODSCOPE.py godscope.unlock
python3 SSB_ULTRA_GODSCOPE.py godscope.eval --json '{"code":"dispatch(\"nm21.caps.priv_esc_cap_matrix\",{})"}'
python3 SSB_ULTRA_GODSCOPE.py godscope.sweep --json '{"kind":"swarm24_expansion"}'
python3 SSB_ULTRA_GODSCOPE.py --serve --port 8787     # HTTP + MCP
```
