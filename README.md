# SSB ULTRA GODSCOPE v3.3.1-swarm12-armed

Single-file monolith (zipapp). 21,195 wired routes across 6 bridges:
native (74) · z-seed CLI (146) · dragon verbs (23) · wave powers (20,692) · swarm-12 expansion (260, all armed=true) · godscope map/layers/selftest.

## Rebuild
```
cat SSB_ULTRA_GODSCOPE.py.part_* > SSB_ULTRA_GODSCOPE.py
chmod +x SSB_ULTRA_GODSCOPE.py
sha256sum SSB_ULTRA_GODSCOPE.py   # af5af30f6ddb9dd5989552ae608ef6f802cedfc01f08ebf4afe2d14d885e61e7
```

## Run
```
python3 SSB_ULTRA_GODSCOPE.py                          # status
python3 SSB_ULTRA_GODSCOPE.py godscope.selftest        # 12-leg wiring proof
python3 SSB_ULTRA_GODSCOPE.py --godscope               # dump full wiring seed
python3 SSB_ULTRA_GODSCOPE.py --serve --port 8787      # HTTP API + MCP
python3 SSB_ULTRA_GODSCOPE.py power.nm20.kernel.kallsyms_resolver --json '{}'
```

- `SSB_WIRING_SEED.json` — every route + binding (any AI can load this to see everything SSB can do)
- `expansion/` — the 12 armed swarm-12 modules (nm20.* powers, sources)
- `REASSEMBLE_SSB_ULTRA_v2.py` — rebuilds the base archive from the 25 base64 text chunks
