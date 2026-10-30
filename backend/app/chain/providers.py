"""Public blockchain explorers, read through the egress proxy.

One normalised shape for every chain, so the tracer and the graph do not care
which explorer answered:

    {chain, address, token, balance, total_in, total_out, tx_count,
     first_seen, last_seen, examined, truncated,
     counterparties: [{address, direction, value, tx_count, first_seen, last_seen, txid}],
     co_spent: [address, ...]}         # addresses co-spent with this one (Bitcoin clustering)

Values are in whole coin units (BTC, ETH, TRX/USDT), as floats. The explorers
used need no API key. Everything is read-only: balances and transactions that
are already public on the chain.
"""
from collections import defaultdict
from datetime import datetime, timezone

from app.enrich.http import EnrichError, api_request

# How many recent transactions to read per address. Explorers page; one page is
# plenty to draw the immediate neighbourhood, which is what an analyst expands by hand.
PAGE = 50


def _ts(value) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat() if value else None
    except (ValueError, OSError, OverflowError):
        return None


def _edge(bucket: dict, address: str, direction: str, value: float, when: str | None, txid: str) -> None:
    key = (address, direction)
    e = bucket.get(key)
    if e is None:
        bucket[key] = {"address": address, "direction": direction, "value": value, "tx_count": 1,
                       "first_seen": when, "last_seen": when, "txid": txid}
        return
    e["value"] += value
    e["tx_count"] += 1
    if when and (e["first_seen"] is None or when < e["first_seen"]):
        e["first_seen"] = when
    if when and (e["last_seen"] is None or when > e["last_seen"]):
        e["last_seen"] = when


def _result(chain: str, address: str, token: str, **rest) -> dict:
    base = {"chain": chain, "address": address, "token": token, "balance": 0.0, "total_in": 0.0, "total_out": 0.0,
            "tx_count": 0, "first_seen": None, "last_seen": None, "examined": 0, "truncated": False,
            "counterparties": [], "co_spent": []}
    base.update(rest)
    return base


# ── Bitcoin (Blockstream) ────────────────────────────────────────────────────

def parse_btc(address: str, summary: dict, txs: list) -> dict:
    chain_stats = summary.get("chain_stats") or {}
    sats = 100_000_000
    total_in = (chain_stats.get("funded_txo_sum", 0)) / sats
    total_out = (chain_stats.get("spent_txo_sum", 0)) / sats
    tx_count = chain_stats.get("tx_count", 0)
    edges: dict = {}
    co_spent: set[str] = set()
    first = last = None
    for tx in txs:
        when = _ts((tx.get("status") or {}).get("block_time"))
        if when:
            first = when if first is None or when < first else first
            last = when if last is None or when > last else last
        ins = [v.get("prevout") or {} for v in tx.get("vin") or []]
        in_addrs = {i.get("scriptpubkey_address") for i in ins if i.get("scriptpubkey_address")}
        outs = tx.get("vout") or []
        spends = address in in_addrs
        if spends:
            co_spent |= in_addrs - {address}  # common-input heuristic: these were spent together
            for o in outs:
                dst = o.get("scriptpubkey_address")
                if dst and dst != address:
                    _edge(edges, dst, "out", (o.get("value") or 0) / sats, when, tx["txid"])
        else:
            received = sum(o.get("value") or 0 for o in outs if o.get("scriptpubkey_address") == address) / sats
            for i in ins:
                src = i.get("scriptpubkey_address")
                if src and src != address:
                    share = received / max(1, len(in_addrs))
                    _edge(edges, src, "in", share, when, tx["txid"])
    return _result("btc", address, "BTC", balance=round(total_in - total_out, 8), total_in=round(total_in, 8),
                   total_out=round(total_out, 8), tx_count=tx_count, first_seen=first, last_seen=last,
                   examined=len(txs), truncated=tx_count > len(txs),
                   counterparties=_rank(edges), co_spent=sorted(co_spent)[:100])


def fetch_btc(address: str) -> dict:
    status, summary = api_request(f"https://blockstream.info/api/address/{address}")
    if status == 404 or not isinstance(summary, dict):
        return _result("btc", address, "BTC")
    if status != 200:
        raise EnrichError(f"Blockstream returned HTTP {status}")
    status, txs = api_request(f"https://blockstream.info/api/address/{address}/txs")
    return parse_btc(address, summary, txs if status == 200 and isinstance(txs, list) else [])


# ── Ethereum (BlockCypher) ───────────────────────────────────────────────────

def parse_eth(address: str, full: dict) -> dict:
    wei = 1e18
    edges: dict = {}
    first = last = None
    for tx in full.get("txs") or []:
        when = tx.get("confirmed") or tx.get("received")
        if when:
            first = when if first is None or when < first else first
            last = when if last is None or when > last else last
        in_addrs = {a.lower() for i in tx.get("inputs") or [] for a in (i.get("addresses") or [])}
        spends = address in in_addrs
        for o in tx.get("outputs") or []:
            for dst in o.get("addresses") or []:
                dst = dst.lower()
                val = (o.get("value") or 0) / wei
                if spends and dst != address:
                    _edge(edges, dst, "out", val, when, tx.get("hash", ""))
                elif not spends and dst == address:
                    for src in in_addrs - {address}:
                        _edge(edges, src, "in", val / max(1, len(in_addrs - {address})), when, tx.get("hash", ""))
    return _result("eth", address, "ETH", balance=(full.get("balance") or 0) / wei,
                   total_in=(full.get("total_received") or 0) / wei, total_out=(full.get("total_sent") or 0) / wei,
                   tx_count=full.get("n_tx", 0), first_seen=first, last_seen=last,
                   examined=len(full.get("txs") or []), truncated=bool(full.get("hasMore")),
                   counterparties=_rank(edges))


def fetch_eth(address: str) -> dict:
    status, full = api_request(f"https://api.blockcypher.com/v1/eth/main/addrs/{address[2:]}/full",
                               params={"limit": str(PAGE), "txlimit": "40"})
    if status == 404 or not isinstance(full, dict):
        return _result("eth", address, "ETH")
    if status == 429:
        raise EnrichError("BlockCypher rate limit reached; try again shortly")
    if status != 200:
        raise EnrichError(f"BlockCypher returned HTTP {status}")
    return parse_eth(address, full)


# ── TRON / USDT (TronGrid) ───────────────────────────────────────────────────

def parse_tron(address: str, account: dict, transfers: list) -> dict:
    sun = 1e6
    trx_balance = (account.get("balance") or 0) / sun if account else 0.0
    edges: dict = {}
    first = last = None
    total_in = total_out = 0.0
    for t in transfers:
        info = t.get("token_info") or {}
        decimals = info.get("decimals", 6)
        symbol = info.get("symbol", "?")
        try:
            val = int(t.get("value", 0)) / (10 ** decimals)
        except (TypeError, ValueError):
            continue
        when = _ts((t.get("block_timestamp") or 0) / 1000)
        if when:
            first = when if first is None or when < first else first
            last = when if last is None or when > last else last
        if t.get("from") == address and t.get("to") and t["to"] != address:
            total_out += val
            _edge(edges, t["to"], "out", val, when, t.get("transaction_id", ""))
        elif t.get("to") == address and t.get("from") and t["from"] != address:
            total_in += val
            _edge(edges, t["from"], "in", val, when, t.get("transaction_id", ""))
    token = (transfers[0].get("token_info") or {}).get("symbol", "USDT") if transfers else "USDT"
    return _result("tron", address, f"{token} (TRC20)", balance=round(trx_balance, 6),
                   total_in=round(total_in, 6), total_out=round(total_out, 6), tx_count=len(transfers),
                   first_seen=first, last_seen=last, examined=len(transfers), truncated=len(transfers) >= PAGE,
                   counterparties=_rank(edges), co_spent=[])


def fetch_tron(address: str) -> dict:
    status, account = api_request(f"https://api.trongrid.io/v1/accounts/{address}")
    acc = (account.get("data") or [{}])[0] if isinstance(account, dict) else {}
    status2, transfers = api_request(f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20",
                                     params={"limit": str(PAGE), "only_confirmed": "true"})
    rows = transfers.get("data") if status2 == 200 and isinstance(transfers, dict) else []
    if status not in (200, 404) and not rows:
        raise EnrichError(f"TronGrid returned HTTP {status}")
    return parse_tron(address, acc, rows or [])


# ── shared ───────────────────────────────────────────────────────────────────

def _rank(edges: dict) -> list[dict]:
    """Counterparties, largest flow first, rounded, capped so the graph stays legible."""
    out = sorted(edges.values(), key=lambda e: e["value"], reverse=True)[:60]
    for e in out:
        e["value"] = round(e["value"], 8)
    return out


_FETCH = {"btc": fetch_btc, "eth": fetch_eth, "tron": fetch_tron}
HOSTS = {"btc": ("blockstream.info",), "eth": ("api.blockcypher.com",), "tron": ("api.trongrid.io",)}


def lookup(chain: str, address: str) -> dict:
    fetch = _FETCH.get(chain)
    if fetch is None:
        raise EnrichError(f"on-chain lookup is not available for {chain}")
    return fetch(address)
