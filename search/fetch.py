"""Download the OpenSearch minimal distribution with resume and checksum verification.

Build-time only. The stock opensearchproject/opensearch image is ~1 GB because it
bundles every plugin; the minimal distribution is the same engine at a quarter of
the size, which is all this stack uses.
"""
import hashlib
import sys
import time
import urllib.request

version = sys.argv[1]
dest = sys.argv[2]
url = f"https://artifacts.opensearch.org/releases/core/opensearch/{version}/opensearch-min-{version}-linux-x64.tar.gz"

expected = urllib.request.urlopen(url + ".sha512", timeout=60).read().decode().split()[0]

have = 0
open(dest, "wb").close()
for attempt in range(1, 41):
    try:
        req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "ab") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
                have += len(chunk)
        break
    except Exception as exc:  # resume from where the connection dropped
        print(f"attempt {attempt}: {exc!r} at {have} bytes, resuming", flush=True)
        time.sleep(min(30, 2 * attempt))
else:
    sys.exit("download failed")

digest = hashlib.sha512()
with open(dest, "rb") as fh:
    while chunk := fh.read(1 << 20):
        digest.update(chunk)
if digest.hexdigest() != expected:
    sys.exit("checksum mismatch for the OpenSearch tarball")
print(f"downloaded and verified {have} bytes")
