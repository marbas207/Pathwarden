#!/usr/bin/env python3
"""Verify a Pathwarden evidence pack without Pathwarden.

    python3 verify_evidence.py PACK --fingerprint SHA256:...
    python3 verify_evidence.py PACK --key evidence.pub

PACK is the .zip or the folder. The script checks, independently of the
Pathwarden code:

1. manifest.json.minisig is an Ed25519 signature (minisign's legacy "Ed"
   format) of manifest.json, including its trusted comment, made by the
   expected key; and the signature file is exactly as Pathwarden writes it;
2. every file listed in manifest.json has that SHA-256 and size;
3. the pack holds no file the manifest doesn't list.

The format is described in docs/evidence.md. Only the standard library is
needed; if the `cryptography` package is installed, it checks the Ed25519
signatures, otherwise the RFC 8032 reference algorithm below does.

Exit status: 0 verified, 1 not verified, 2 usage error, 3 intact and validly
signed but the signer was not checked (no --key or --fingerprint given).
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import zipfile

MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.minisig"
SCHEMA = "pathwarden.evidence.v1"
UNTRUSTED = "untrusted comment: "
TRUSTED = "trusted comment: "


# --- Ed25519 verification (RFC 8032, section 6) -----------------------------

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def _verify_reference(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def ed25519_verify(public, message, signature):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _verify_reference(public, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --- Keys ---------------------------------------------------------------------


def key_line(text):
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith(UNTRUSTED):
            return line
    return None


def parse_public_key(text):
    """(key_id, public key) from a minisign public key (file text or line)."""
    line = key_line(text)
    raw = base64.b64decode(line or "", validate=True)
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise ValueError("not an Ed25519 public key in minisign format")
    return raw[2:10], raw[10:]


def fingerprint(public):
    digest = hashlib.sha256(public).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def normalize_fingerprint(s):
    s = s.strip()
    for prefix in ("SHA256:", "sha256:"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return "SHA256:" + s.rstrip("=")


# --- Reading the pack ---------------------------------------------------------


def check_name(name):
    parts = name.split("/")
    return (
        name
        and not name.startswith("/")
        and "\\" not in name
        and ":" not in name
        and "\0" not in name
        and all(p not in ("", ".", "..") for p in parts)
    )


def check_local_headers(raw, z):
    """Each file's own (local) header must say what the zip's directory says
    (name, flags, method, checksum, sizes), and the files must sit end to end
    from the start of the zip to its directory, with nothing between them.
    zipfile reads the directory and compares only the name, so otherwise
    another zip tool could show other files than the ones checked here
    ("zip cloaking")."""
    at = 0
    for info in sorted(z.infolist(), key=lambda i: i.header_offset):
        if info.header_offset != at:
            raise ValueError("the zip holds data its directory doesn't list")
        raw.seek(at)
        head = raw.read(30)
        if len(head) != 30 or head[:4] != b"PK\x03\x04":
            raise ValueError("%s has no file header where the directory says" % info.filename)
        flags, method = struct.unpack("<HH", head[6:10])
        crc, csize, usize, nlen, elen = struct.unpack("<LLLHH", head[14:30])
        name = raw.read(nlen)
        encoding = "utf-8" if info.flag_bits & 0x800 else "cp437"
        local = (name, flags, method)
        central = (info.orig_filename.encode(encoding), info.flag_bits, info.compress_type)
        sizes = (crc, csize, usize)
        listed = (info.CRC, info.compress_size, info.file_size)
        # A data descriptor after the data may give the sizes instead.
        described = flags & 0x8 and sizes == (0, 0, 0)
        if local != central or (sizes != listed and not described):
            raise ValueError(
                "the file header of %s doesn't match the zip's directory" % info.filename
            )
        at += 30 + nlen + elen + info.compress_size
        if flags & 0x8:
            raw.seek(at)
            at += 16 if raw.read(4) == b"PK\x07\x08" else 12
    if at != z.start_dir:
        raise ValueError("the zip holds data its directory doesn't list")


def read_pack(path):
    """{name: (sha256 hex, size, bytes for the manifest and signature)}."""
    found = {}
    keep = (MANIFEST, SIGNATURE)

    def add(name, stream):
        if not check_name(name):
            raise ValueError("%r is not an allowed file name in a pack" % name)
        if name in found:
            raise ValueError("the pack contains two files named %s" % name)
        h = hashlib.sha256()
        size = 0
        content = bytearray() if name in keep else None
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if content is not None:
                content.extend(chunk)
                if size > 4 << 20:
                    raise ValueError("%s is larger than any manifest" % name)
        found[name] = (h.hexdigest(), size, bytes(content) if content is not None else None)

    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    raise ValueError("%s is a link; a pack folder holds plain files only" % d)
            for f in files:
                full = os.path.join(root, f)
                if os.path.islink(full):
                    raise ValueError("%s is a link; a pack folder holds plain files only" % f)
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                with open(full, "rb") as stream:
                    add(rel, stream)
    else:
        with open(path, "rb") as raw, zipfile.ZipFile(raw) as z:
            check_local_headers(raw, z)
            for info in z.infolist():
                if info.is_dir():
                    continue
                with z.open(info) as stream:
                    add(info.filename, stream)
    return found


# --- Verification -------------------------------------------------------------


def parse_signature(text):
    lines = text.split("\n")
    if len(lines) < 4 or not lines[0].startswith(UNTRUSTED) or not lines[2].startswith(TRUSTED):
        raise ValueError("not a minisign signature file")
    raw = base64.b64decode(lines[1], validate=True)
    if len(raw) != 74 or raw[:2] != b"Ed":
        raise ValueError("unsupported signature (Pathwarden writes Ed25519 \"Ed\" signatures)")
    glob = base64.b64decode(lines[3], validate=True)
    if len(glob) != 64:
        raise ValueError("the comment signature has the wrong length")
    return raw[2:10], raw[10:], lines[2][len(TRUSTED):], glob


def canonical_signature(key_id, sig, comment, glob, public):
    return "%ssignature from Pathwarden evidence key %s\n%s\n%s%s\n%s\n" % (
        UNTRUSTED,
        fingerprint(public),
        base64.b64encode(b"Ed" + key_id + sig).decode(),
        TRUSTED,
        comment,
        base64.b64encode(glob).decode(),
    )


def verify(pack, key_text=None, want_fingerprint=None):
    """Returns (outcome, problems, signer fingerprint, manifest)."""
    problems = []
    try:
        found = read_pack(pack)
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        return "failed", ["the pack can't be read: %s" % e], None, None
    manifest_entry = found.pop(MANIFEST, None)
    sig_entry = found.pop(SIGNATURE, None)
    if manifest_entry is None:
        return "failed", ["%s is missing, so nothing can be checked" % MANIFEST], None, None
    manifest_bytes = manifest_entry[2]
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as e:
        return "failed", ["%s is not valid JSON (%s)" % (MANIFEST, e)], None, None
    if manifest.get("schema") != SCHEMA:
        problems.append("%s is not a %s manifest" % (MANIFEST, SCHEMA))

    # The key: the one given, else the manifest's own (integrity only).
    try:
        if key_text is not None:
            key_id, public = parse_public_key(key_text)
        else:
            key_id, public = parse_public_key(manifest.get("signer", {}).get("public_key", ""))
    except ValueError as e:
        return "failed", problems + ["the public key is unusable: %s" % e], None, manifest

    signed_by = None
    if sig_entry is None:
        problems.append("%s is missing: the pack is not signed" % SIGNATURE)
    else:
        try:
            text = sig_entry[2].decode("utf-8")
            s_id, sig, comment, glob = parse_signature(text)
            if s_id != key_id:
                problems.append("the pack was not signed by the expected key")
            elif not ed25519_verify(public, manifest_bytes, sig):
                problems.append("the signature does not match the manifest")
            elif not ed25519_verify(public, sig + comment.encode("utf-8"), glob):
                problems.append("the signature's trusted comment was changed")
            elif canonical_signature(s_id, sig, comment, glob, public) != text:
                problems.append("the signature file was edited (its comment or layout changed)")
            else:
                signed_by = fingerprint(public)
        except (UnicodeDecodeError, ValueError) as e:
            problems.append("the signature is not valid: %s" % e)

    checked = key_text is not None
    if signed_by:
        signer = manifest.get("signer", {})
        own = signer.get("public_key", "")
        if own != base64.b64encode(b"Ed" + key_id + public).decode():
            problems.append("the manifest names a different signer than the key that signed it")
        if want_fingerprint:
            want = normalize_fingerprint(want_fingerprint)
            if want != signed_by:
                problems.append("the pack was signed by key %s, not by the expected %s" % (signed_by, want))
            checked = True

    listed = set()
    for entry in manifest.get("files", []):
        path = entry.get("path")
        if path in listed:
            problems.append("the manifest lists %s twice" % path)
            continue
        listed.add(path)
        got = found.get(path)
        if got is None:
            problems.append("%s is missing from the pack" % path)
        elif got[0] != str(entry.get("sha256", "")).lower() or got[1] != entry.get("bytes"):
            problems.append("%s was changed after signing (its SHA-256 does not match the manifest)" % path)
    for name in sorted(found):
        if name not in listed:
            problems.append("%s is in the pack but not in the manifest (added after signing)" % name)

    if problems or not signed_by:
        return "failed", problems, signed_by, manifest
    return ("verified" if checked else "signer_not_checked"), [], signed_by, manifest


def main():
    ap = argparse.ArgumentParser(description="Verify a Pathwarden evidence pack.")
    ap.add_argument("pack", help="the pack: a .zip or a folder")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--key", help="the organisation's public key file (evidence.pub)")
    group.add_argument("--fingerprint", help="the organisation's published key fingerprint (SHA256:...)")
    args = ap.parse_args()
    if not os.path.exists(args.pack):
        print("error: %s does not exist" % args.pack, file=sys.stderr)
        return 2
    key_text = None
    if args.key:
        with open(args.key, encoding="utf-8") as f:
            key_text = f.read()
    outcome, problems, signed_by, manifest = verify(args.pack, key_text, args.fingerprint)
    if outcome == "verified":
        print("VERIFIED: every file is exactly as signed, by key %s." % signed_by)
        return 0
    if outcome == "signer_not_checked":
        print("INTACT, SIGNER NOT CHECKED: every file is exactly as signed by key %s," % signed_by)
        print("but nothing says whose key that is. Give --fingerprint or --key.")
        return 3
    print("NOT VERIFIED: do not rely on this pack.")
    for p in problems:
        print("  - %s" % p)
    return 1


if __name__ == "__main__":
    sys.exit(main())
