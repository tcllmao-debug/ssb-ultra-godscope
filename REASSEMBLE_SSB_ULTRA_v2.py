#!/usr/bin/env python3
"""
REASSEMBLE_SSB_ULTRA_v2.py — fixed & enhanced reassembler for the SSB ULTRA
Google Drive base64 chunk set (SSB_ULTRA_TEXT_01A..05E).

Fixes vs. the original REASSEMBLE_GOOGLE_DRIVE_PARTS.py:
  * CRITICAL: one incremental base64 decoder PER GROUP that persists across
    chunk-file boundaries. The 32 MiB Drive splits cut base64 lines mid-way;
    decoding/flushing per file corrupts the stream. v2 carries the partial
    quantum (and partial line) across files.
  * Whitespace-tolerant decoding (translate-based strip), tolerant of \r\n.
  * Auto-detects 25-file (01A..05E) or 5-file (01..05 concatenated) layout.
  * Per-group SHA-256 verification against the known manifest; on mismatch the
    error names the group and its chunks.
  * Resume-safe: writes to <out>.part and atomically renames on success.
  * Progress with MiB/s and ETA; --quiet to silence.
  * --verify-only (hash existing output), --extract (gunzip after assembly),
    --force (overwrite), --src/--out/--layout arguments.

Expected artifact:
  SSB_ULTRA_REPAIRED_MONOLITH.py.gz
  size    : 549,998,691 bytes
  sha256  : 04234ffe1d9894e981ab6f9782b282d864623e58fc31a6d977651d5257cd3be5
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import os
import re
import sys
import time

EXPECTED_SIZE = 549_998_691
EXPECTED_SHA256 = "04234ffe1d9894e981ab6f9782b282d864623e58fc31a6d977651d5257cd3be5"

GROUP_SHA256 = {
    1: "7f7177f9064309e22d1c7bbf65e305afb071a8d3205f1c4ed60e684d3fe96d8c",
    2: "9e82e9d4c66901a51d84e792d59be148dd8069e9fa204b7146654b55c0730615",
    3: "2ec4c3071fffc7a685d5ba37d594f90ccb6fe8a9884c9414c49fa5e879346eaa",
    4: "2e0a08b253ed867149b68f3fed37614f3f2ea69b5909b62aa9ec91c11b8f1044",
    5: "971e0721f861cfe7c256a7db2518515f6c5201ec614e9dbf47346943fbd8b6ce",
}

_B64_KEEP = re.compile(rb"[^A-Za-z0-9+/=]")
CHUNK_RE = re.compile(r"SSB_ULTRA_TEXT_(\d{2})([A-E])\.txt$", re.IGNORECASE)
GROUP_RE = re.compile(r"SSB_ULTRA_TEXT_(\d{2})\.txt$", re.IGNORECASE)


class IncrementalB64:
    """Streaming base64 decoder that survives arbitrary chunk boundaries."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def update(self, data: bytes) -> bytes:
        self._buf.extend(_B64_KEEP.sub(b"", data))
        usable = (len(self._buf) // 4) * 4
        if b"=" in self._buf[:usable]:
            idx = self._buf.index(b"=")
            usable = (idx // 4 + 1) * 4
        if usable == 0:
            return b""
        out = base64.b64decode(bytes(self._buf[:usable]))
        del self._buf[:usable]
        return out

    def flush(self) -> bytes:
        if not self._buf:
            return b""
        tail = bytes(self._buf)
        self._buf.clear()
        if len(tail) % 4:
            tail += b"=" * (4 - len(tail) % 4)
        return base64.b64decode(tail)


def _log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, flush=True)


def detect_layout(src: str) -> dict[int, list[str]]:
    files = [os.path.join(src, f) for f in sorted(os.listdir(src))]
    groups: dict[int, list[str]] = {}
    for p in files:
        m = CHUNK_RE.search(os.path.basename(p))
        if m:
            groups.setdefault(int(m.group(1)), []).append(p)
    if groups:
        for g in groups.values():
            g.sort(key=lambda p: CHUNK_RE.search(os.path.basename(p)).group(2))  # type: ignore[union-attr]
        return dict(sorted(groups.items()))
    for p in files:
        m = GROUP_RE.search(os.path.basename(p))
        if m:
            groups.setdefault(int(m.group(1)), []).append(p)
    if groups:
        return dict(sorted(groups.items()))
    raise SystemExit(f"error: no SSB_ULTRA_TEXT_* parts found in {src}")


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(8 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def verify_only(out: str) -> int:
    if not os.path.exists(out):
        print(f"error: {out} does not exist", file=sys.stderr)
        return 2
    size = os.path.getsize(out)
    print(f"size ......... {size:,} bytes  {'OK' if size == EXPECTED_SIZE else 'MISMATCH'}")
    digest = hash_file(out)
    print(f"{digest}  {'OK' if digest == EXPECTED_SHA256 else 'MISMATCH'}")
    ok = size == EXPECTED_SIZE and digest == EXPECTED_SHA256
    try:
        with gzip.open(out, "rb") as gz:
            while gz.read(8 << 20):
                pass
        print("stream reads clean  OK")
    except Exception as exc:  # noqa: BLE001
        print(f"stream reads clean  FAIL ({exc})")
        ok = False
    return 0 if ok else 1


def assemble(src: str, out: str, quiet: bool = False) -> int:
    groups = detect_layout(src)
    layout_kind = "25-file" if any(len(v) > 1 for v in groups.values()) else "5-file"
    _log(f"Detected {layout_kind} layout in {src}", quiet)
    tmp = out + ".part"
    total_bytes = sum(os.path.getsize(p) for v in groups.values() for p in v)
    done = 0
    t0 = time.monotonic()
    with open(tmp, "wb") as w:
        for gno, chunks in groups.items():
            dec = IncrementalB64()
            ghash = hashlib.sha256()
            for p in chunks:
                name = os.path.basename(p)
                try:
                    with open(p, "rb") as f:
                        while True:
                            blk = f.read(4 << 20)
                            if not blk:
                                break
                            ghash.update(blk)
                            w.write(dec.update(blk))
                            done += len(blk)
                except OSError as exc:
                    raise SystemExit(f"error reading chunk {name}: {exc}") from exc
                if not quiet:
                    el = max(time.monotonic() - t0, 1e-6)
                    rate = done / el / (1 << 20)
                    eta = (total_bytes - done) / max(done / el, 1e-6)
                    print(f"\r  {done*100/total_bytes:5.1f}%  {rate:7.1f} MiB/s  ETA {eta:5.0f}s  ({name})   ", end="", flush=True)
            w.write(dec.flush())
            digest = ghash.hexdigest()
            want = GROUP_SHA256.get(gno)
            if want and digest != want:
                names = ", ".join(os.path.basename(c) for c in chunks)
                os.unlink(tmp)
                raise SystemExit(
                    f"\nerror: group {gno:02d} text hash mismatch\n"
                    f"  got  {digest}\n  want {want}\n  chunks: {names}"
                )
            _log(f"\ngroup {gno:02d} sha256 {digest} OK", quiet)
    os.replace(tmp, out)
    _log("Archive assembled; running full verification ...", quiet)
    rc = verify_only(out)
    if rc == 0:
        _log(f"SUCCESS: byte-for-byte original GZIP recovered in {time.monotonic()-t0:.0f}s -> {out}", quiet)
    return rc


def extract(out: str) -> str:
    target = out[:-3] if out.endswith(".gz") else out + ".out"
    with gzip.open(out, "rb") as gz, open(target, "wb") as w:
        while True:
            blk = gz.read(8 << 20)
            if not blk:
                break
            w.write(blk)
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Reassemble SSB ULTRA Drive base64 parts (v2 fixed/enhanced).")
    ap.add_argument("--src", default=".")
    ap.add_argument("--out", default="SSB_ULTRA_REPAIRED_MONOLITH.py.gz")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    if args.verify_only:
        return verify_only(args.out)
    if os.path.exists(args.out) and not args.force:
        print(f"note: {args.out} exists; verifying (use --force to rebuild)")
        return verify_only(args.out)
    rc = assemble(args.src, args.out, quiet=args.quiet)
    if rc == 0 and args.extract:
        path = extract(args.out)
        print(f"extracted -> {path} ({os.path.getsize(path):,} bytes)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
