#!/usr/bin/env python3
"""Pre-download the images' pinned dependencies, fast and verified.

Why this exists: `pip install` and `npm ci` download each file over a single
connection. On links where a CDN is rate-limited per connection that turns a
few dozen megabytes into an hour. This script fetches the same files from the
same official sources (PyPI, the npm registry), but over many parallel
connections in ranged chunks with retries, and verifies every file against the
published checksum (PyPI's SHA-256; the SHA-512 integrity value in
package-lock.json). The image builds then install offline from what it fetched.

Standard library only, so it runs on the host without installing anything.

    python3 tools/fetch_deps.py wheels     # backend/requirements.lock -> backend/wheelhouse/
    python3 tools/fetch_deps.py npm        # frontend/package-lock.json -> frontend/.npm-offline/
    python3 tools/fetch_deps.py all
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import platform
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_MINOR = 12  # must match the FROM line of backend/Dockerfile
CHUNK = 256 * 1024
WORKERS = 48
UA = "kivuli-deps-fetch/1.0"


def request(url: str, headers: dict | None = None, method: str = "GET", attempts: int = 8):
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})}, method=method)
            with urllib.request.urlopen(req, timeout=90) as resp:
                return resp.read(), resp.headers
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as exc:
            # HTTPException covers IncompleteRead: a connection dropped mid-chunk is retried like any other.
            last = exc
            time.sleep(min(20, 1.5 * (attempt + 1)))
    raise RuntimeError(f"giving up on {url}: {last!r}")


def digest(path: str, algorithm: str) -> bytes:
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while block := fh.read(1 << 20):
            h.update(block)
    return h.digest()


def verified(path: str, item: dict) -> bool:
    return os.path.exists(path) and digest(path, item["algorithm"]) == item["digest"]


def download(items: list[dict]) -> bool:
    """Fetch items ({url, path, size, algorithm, digest}) in parallel ranged chunks and verify each."""
    todo = [i for i in items if not verified(i["path"], i)]
    if not todo:
        return True
    total = sum(i["size"] for i in todo)
    print(f"downloading {len(todo)} files, {total / 1e6:.1f} MB, over {WORKERS} connections...", flush=True)

    jobs = []
    for item in todo:
        os.makedirs(os.path.dirname(item["path"]), exist_ok=True)
        with open(item["path"] + ".part", "wb") as fh:  # pre-size, then fill chunk by chunk
            fh.truncate(item["size"])
        for start in range(0, item["size"], CHUNK):
            jobs.append((item, start, min(start + CHUNK, item["size"]) - 1))

    def fetch(job) -> int:
        item, start, end = job
        data, _ = request(item["url"], {"Range": f"bytes={start}-{end}"})
        if len(data) != end - start + 1:
            raise RuntimeError(f"short read for {item['url']}")
        fd = os.open(item["path"] + ".part", os.O_WRONLY)
        try:
            os.pwrite(fd, data, start)
        finally:
            os.close(fd)
        return len(data)

    done, started, last = 0, time.time(), 0.0
    with ThreadPoolExecutor(WORKERS) as pool:
        for future in as_completed([pool.submit(fetch, job) for job in jobs]):
            done += future.result()
            if time.time() - last > 5:
                last = time.time()
                print(f"  {done / 1e6:6.1f} / {total / 1e6:.1f} MB  {done / max(1e-6, time.time() - started) / 1024:.0f} KB/s", flush=True)

    for item in todo:
        part = item["path"] + ".part"
        if digest(part, item["algorithm"]) != item["digest"]:
            os.remove(part)
            print(f"CHECKSUM MISMATCH: {item['url']} does not match its published checksum", file=sys.stderr)
            return False
        os.replace(part, item["path"])
    print(f"verified {len(items)} files in {time.time() - started:.0f}s")
    return True


def up_to_date(manifest_path: str, key: str) -> bool:
    try:
        manifest = json.load(open(manifest_path))
    except (OSError, ValueError):
        return False
    return manifest.get("key") == key and all(
        os.path.exists(f["path"]) and os.path.getsize(f["path"]) == f["size"] for f in manifest.get("files", [])
    )


def write_manifest(manifest_path: str, key: str, items: list[dict]) -> None:
    json.dump({"key": key, "files": [{"path": i["path"], "size": i["size"]} for i in items]}, open(manifest_path, "w"), indent=1)


def prune(directory: str, keep: set[str], suffix: str) -> None:
    for base, _dirs, names in os.walk(directory):
        for name in names:
            path = os.path.join(base, name)
            if name.endswith((suffix, ".part")) and path not in keep:
                os.remove(path)


# ── Python wheels ───────────────────────────────────────────────────────────

def wheel_rank(filename: str, arch: str) -> int:
    """Rank a wheel for CPython 3.PYTHON_MINOR on glibc Linux. 0 means unusable."""
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return 0
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    if plat != "any" and not any(re.fullmatch(rf"manylinux\w*_{arch}", p) for p in plat.split(".")):
        return 0
    pys = py.split(".")
    if f"cp3{PYTHON_MINOR}" in pys and abi in (f"cp3{PYTHON_MINOR}", "none"):
        return 3
    if abi == "abi3" and any(re.fullmatch(r"cp3(\d+)", p) and int(p[3:]) <= PYTHON_MINOR for p in pys):
        return 2
    if abi == "none" and any(p in ("py3", f"py3{PYTHON_MINOR}") for p in pys):
        return 1
    return 0


def fetch_wheels(arch: str) -> bool:
    lock = os.path.join(ROOT, "backend", "requirements.lock")
    out = os.path.join(ROOT, "backend", "wheelhouse")
    manifest = os.path.join(out, ".manifest.json")
    pins = {}
    for line in open(lock):
        line = line.split("#")[0].strip()
        if "==" in line:
            name, version = line.split("==", 1)
            pins[name.strip().lower()] = version.strip()
    key = hashlib.sha256((json.dumps(pins, sort_keys=True) + arch).encode()).hexdigest()
    os.makedirs(out, exist_ok=True)
    if up_to_date(manifest, key):
        print(f"wheelhouse is up to date ({len(pins)} wheels)")
        return True

    print(f"resolving {len(pins)} pinned Python packages on PyPI...", flush=True)

    def resolve(name: str, version: str) -> dict:
        data = json.loads(request(f"https://pypi.org/pypi/{name}/{version}/json")[0])
        ranked = sorted(((wheel_rank(f["filename"], arch), f) for f in data["urls"] if f["filename"].endswith(".whl")), key=lambda r: r[0], reverse=True)
        if not ranked or ranked[0][0] == 0:
            raise RuntimeError(f"no wheel for {name}=={version} on cp3{PYTHON_MINOR} linux {arch}")
        best = ranked[0][1]
        return {"url": best["url"], "path": os.path.join(out, best["filename"]), "size": best["size"],
                "algorithm": "sha256", "digest": bytes.fromhex(best["digests"]["sha256"])}

    with ThreadPoolExecutor(WORKERS) as pool:
        items = [f.result() for f in as_completed([pool.submit(resolve, n, v) for n, v in pins.items()])]
    if not download(items):
        return False
    prune(out, {i["path"] for i in items}, ".whl")
    write_manifest(manifest, key, items)
    return True


# ── npm tarballs ────────────────────────────────────────────────────────────

def fetch_npm(arch: str) -> bool:
    lock_path = os.path.join(ROOT, "frontend", "package-lock.json")
    out = os.path.join(ROOT, "frontend", ".npm-offline")
    manifest = os.path.join(out, ".manifest.json")
    cpu = {"x86_64": "x64", "aarch64": "arm64"}.get(arch, arch)
    lock_text = open(lock_path).read()
    key = hashlib.sha256((lock_text + cpu).encode()).hexdigest()
    os.makedirs(out, exist_ok=True)
    if up_to_date(manifest, key):
        print("npm package cache is up to date")
        return True

    # Everything the web image (node:alpine => linux, musl) will install.
    wanted = []
    for meta in json.loads(lock_text)["packages"].values():
        url, integrity = meta.get("resolved"), meta.get("integrity")
        if not url or not integrity or not url.startswith("https://registry.npmjs.org/"):
            continue
        if ("os" in meta and "linux" not in meta["os"]) or ("cpu" in meta and cpu not in meta["cpu"]) or ("libc" in meta and "musl" not in meta["libc"]):
            continue
        algorithm, _, encoded = integrity.split(" ")[0].partition("-")
        wanted.append({"url": url, "path": os.path.join(out, *urllib.parse.urlsplit(url).path.strip("/").split("/")),
                       "algorithm": algorithm, "digest": base64.b64decode(encoded)})
    unique = list({i["path"]: i for i in wanted}.values())

    print(f"sizing {len(unique)} npm packages...", flush=True)

    def size(item: dict) -> dict:
        if os.path.exists(item["path"]):
            item["size"] = os.path.getsize(item["path"])
            return item
        # The lock file does not record sizes. HEAD usually has one; otherwise a
        # one-byte ranged GET reports the total in Content-Range.
        length = request(item["url"], method="HEAD")[1].get("Content-Length")
        if length is None:
            content_range = request(item["url"], {"Range": "bytes=0-0"})[1].get("Content-Range", "")
            length = content_range.rpartition("/")[2] if "/" in content_range else None
        if length is None or not str(length).isdigit():
            raise RuntimeError(f"could not determine the size of {item['url']}")
        item["size"] = int(length)
        return item

    with ThreadPoolExecutor(WORKERS) as pool:
        items = [f.result() for f in as_completed([pool.submit(size, i) for i in unique])]
    if not download(items):
        return False
    prune(out, {i["path"] for i in items}, ".tgz")
    write_manifest(manifest, key, items)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Pre-download pinned dependencies in parallel, with checksum verification.")
    parser.add_argument("what", choices=("wheels", "npm", "all"))
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine())
    parser.add_argument("--arch", default=machine, help="target architecture (default: this machine)")
    args = parser.parse_args()
    ok = True
    if args.what in ("wheels", "all"):
        ok = fetch_wheels(args.arch) and ok
    if args.what in ("npm", "all"):
        ok = fetch_npm(args.arch) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # one line, not a traceback: the image build downloads the same pins itself
        print(f"prefetch stopped: {exc}", file=sys.stderr)
        sys.exit(1)
