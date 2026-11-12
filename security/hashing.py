"""
Hash function helpers for the Hashing Laboratory (Module H).

Everything here uses only the Python standard library (hashlib, hmac, zlib),
so no extra dependency is needed. bcrypt and Argon2 are described in the
documentation but are not part of the standard library.
"""
import hashlib
import hmac
import secrets
import time
import zlib

# name, label, family, kind, status, note
ALGORITHMS = [
    ("crc32", "CRC-32", "Checksum", "Non-cryptographic", "not-crypto",
     "Detects accidental corruption only; trivial to forge."),
    ("md5", "MD5", "MD family", "Cryptographic (broken)", "broken",
     "Practical collisions since 2004. Never use for security."),
    ("sha1", "SHA-1", "SHA-1", "Cryptographic (broken)", "broken",
     "Practical collision (SHAttered) in 2017. Legacy only."),
    ("sha224", "SHA-224", "SHA-2", "Cryptographic", "secure", "Truncated SHA-256 variant."),
    ("sha256", "SHA-256", "SHA-2", "Cryptographic", "secure",
     "Most widely used secure hash today (TLS, Git, Bitcoin)."),
    ("sha384", "SHA-384", "SHA-2", "Cryptographic", "secure", "Truncated SHA-512 variant."),
    ("sha512", "SHA-512", "SHA-2", "Cryptographic", "secure", "64-bit word variant of SHA-2."),
    ("sha3_256", "SHA3-256", "SHA-3 (Keccak)", "Cryptographic", "secure",
     "Sponge construction; immune to length-extension."),
    ("sha3_512", "SHA3-512", "SHA-3 (Keccak)", "Cryptographic", "secure", "512-bit SHA-3."),
    ("blake2b", "BLAKE2b", "BLAKE2", "Cryptographic", "secure",
     "Fast on 64-bit CPUs; up to 512-bit output."),
    ("blake2s", "BLAKE2s", "BLAKE2", "Cryptographic", "secure",
     "Optimised for 32-bit and small devices; up to 256-bit output."),
]

STATUS_LABEL = {
    "broken": "Broken – do not use",
    "secure": "Secure",
    "not-crypto": "Not cryptographic",
}


def digest(name: str, data: bytes) -> str:
    if name == "crc32":
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    return hashlib.new(name, data).hexdigest()


def hash_all(text: str):
    """Return one row per algorithm for the hash generator table."""
    data = text.encode("utf-8")
    rows = []
    for name, label, family, kind, status, note in ALGORITHMS:
        hexd = digest(name, data)
        rows.append({
            "name": name, "label": label, "family": family, "kind": kind,
            "status": status, "status_label": STATUS_LABEL[status], "note": note,
            "bits": len(hexd) * 4, "hex": hexd,
        })
    return rows


def bit_difference(hex_a: str, hex_b: str):
    """Number of differing bits between two equal-length hex digests."""
    a, b = int(hex_a, 16), int(hex_b, 16)
    bits = len(hex_a) * 4
    diff = bin(a ^ b).count("1")
    return diff, bits, round(100 * diff / bits, 1)


def avalanche(text_a: str, text_b: str, algorithm: str = "sha256"):
    ha = digest(algorithm, text_a.encode("utf-8"))
    hb = digest(algorithm, text_b.encode("utf-8"))
    diff, bits, pct = bit_difference(ha, hb)
    # per-hex-character comparison for the visual
    chars = [{"a": x, "b": y, "same": x == y} for x, y in zip(ha, hb)]
    return {"hash_a": ha, "hash_b": hb, "diff": diff, "bits": bits, "pct": pct, "chars": chars}


def salting_demo(password: str):
    """
    Same input hashed twice without salt and twice with a random salt.
    Shows why identical passwords must not produce identical stored hashes.
    """
    data = password.encode("utf-8")
    unsalted = [hashlib.sha256(data).hexdigest() for _ in range(2)]
    salted = []
    for _ in range(2):
        salt = secrets.token_hex(8)
        salted.append({"salt": salt, "hash": hashlib.sha256((salt + password).encode("utf-8")).hexdigest()})
    return {"unsalted": unsalted, "salted": salted,
            "unsalted_equal": unsalted[0] == unsalted[1],
            "salted_equal": salted[0]["hash"] == salted[1]["hash"]}


# Cost comparison: how long ONE hash takes. Slow, salted password-hashing
# functions are deliberately expensive; general-purpose hashes are fast.
COST_METHODS = [
    ("SHA-256 (single pass, averaged over 100,000 runs)", "fast"),
    ("PBKDF2-HMAC-SHA256, 600,000 iterations", "slow"),
    ("scrypt N=2^17, r=8, p=1 (128 MiB)", "slow"),
]


def cost_comparison(password: str):
    pw = password.encode("utf-8")
    salt = secrets.token_bytes(16)
    results = []

    # One SHA-256 is far below timer resolution, so average over many runs.
    runs = 100_000
    t = time.perf_counter()
    for _ in range(runs):
        hashlib.sha256(salt + pw).digest()
    results.append((time.perf_counter() - t) / runs)

    t = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000)
    results.append(time.perf_counter() - t)

    t = time.perf_counter()
    hashlib.scrypt(pw, salt=salt, n=2**17, r=8, p=1, maxmem=132 * 2**17 * 8)
    results.append(time.perf_counter() - t)

    rows = []
    for (label, speed), seconds in zip(COST_METHODS, results):
        rows.append({
            "label": label, "speed": speed,
            "ms": round(seconds * 1000, 4) if seconds < 0.001 else round(seconds * 1000, 1),
            "per_second": int(1 / seconds) if seconds > 0 else 0,
        })
    return rows


def hmac_demo(message: str, tampered: str, key: str):
    """HMAC-SHA256 tag on a message, then verification of a (possibly) changed copy."""
    k = key.encode("utf-8")
    tag = hmac.new(k, message.encode("utf-8"), hashlib.sha256).hexdigest()
    check = hmac.new(k, tampered.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"tag": tag, "check": check, "valid": hmac.compare_digest(tag, check)}


def describe_stored_hash(stored: str):
    """
    Split a Werkzeug hash string into its parts for display.
    The digest itself is masked - only its length is shown.
    """
    try:
        method, salt, hexd = stored.split("$", 2)
    except ValueError:
        return None
    parts = method.split(":")
    return {
        "method": method,
        "algorithm": parts[0],
        "params": parts[1:],
        "salt_len": len(salt),
        "digest_bits": len(hexd) * 4,
        "masked": f"{method}${'•' * 8}${hexd[:6]}…",
    }
