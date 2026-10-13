"""Onion services that are never fetched.

Ahmia, the Tor search engine, publishes the MD5 hashes of onion domains it has
banned for hosting child sexual abuse material. The platform keeps a copy of
that list and refuses to file, crawl or probe any address on it. Hashes only:
the addresses themselves are never stored.
"""
import hashlib

BLOCKLIST_KEY = "kivuli:blocklist:onion_md5"
BLOCKLIST_META = "kivuli:blocklist:onion_md5:meta"


def host_hashes(host: str) -> list[str]:
    host = host.lower().strip(".")
    names = {host, host.removesuffix(".onion")}
    # A subdomain of a banned service is the same service.
    if host.endswith(".onion") and host.count(".") > 1:
        base = ".".join(host.split(".")[-2:])
        names |= {base, base.removesuffix(".onion")}
    return [hashlib.md5(n.encode(), usedforsecurity=False).hexdigest() for n in names if n]


def is_blocked(redis_client, host: str) -> bool:
    """True when the host is on the abuse blocklist. A Redis failure blocks nothing but is not swallowed silently by callers that log."""
    if not host.endswith(".onion"):
        return False
    pipe = redis_client.pipeline(transaction=False)
    for digest in host_hashes(host):
        pipe.sismember(BLOCKLIST_KEY, digest)
    return any(pipe.execute())
