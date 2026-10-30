"""Labels for wallet addresses: what kind of thing an address is.

Two sources. A small built-in list of publicly documented addresses (sanctioned
mixer contracts, published exchange hot wallets). And a heuristic read of an
address's own on-chain shape, so an unlabelled address is still described as
"looks like an exchange / a distributor / a personal wallet".

The built-in list is deliberately small and verifiable, and every entry is a
normalised address (lower case for Ethereum, as detection returns it). Getting a
label wrong on a real investigation is worse than having none, so the list errs
towards leaving an address unlabelled. The strongest signal in practice — that
an address already appears in collected dark-web intelligence — is added by the
tracer from the platform's own findings, not here.
"""

# Normalised address -> (category, name). Ethereum addresses only, lower case.
# Sources: OFAC SDN list (sanctioned mixer/actor addresses) and exchanges' own
# published hot-wallet disclosures.
_KNOWN: dict[str, tuple[str, str]] = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": ("sanctioned", "Tornado Cash: donations (OFAC SDN)"),
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": ("sanctioned", "Tornado Cash: router (OFAC SDN)"),
    "0xd96f2b1c14db8458374d9aca76e26c3d18364307": ("sanctioned", "Tornado Cash: 1 ETH pool (OFAC SDN)"),
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": ("sanctioned", "OFAC SDN: Lazarus Group"),
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": ("sanctioned", "OFAC SDN: Lazarus Group"),
    "0x28c6c06298d514db089934071355e5743bf21d60": ("exchange", "Binance: hot wallet 14"),
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": ("exchange", "Binance: hot wallet 15"),
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": ("exchange", "Binance"),
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": ("exchange", "Binance"),
    "0x564286362092d8e7936f0549571a803b203aaced": ("exchange", "Binance"),
}


def known_label(address: str) -> tuple[str, str] | None:
    """Return (category, name) for a documented address, or None. Pass the normalised address."""
    return _KNOWN.get(address or "")


def heuristic_category(*, tx_count: int, counterparties: int, co_spent: int, total_in: float, total_out: float) -> str:
    """A cautious read of an address's shape when nothing else is known.

    service     very high throughput, as an exchange or market hot wallet would have
    distributor receives little, pays out to many (a payout or tumbler-like pattern)
    collector   receives from many, pays out to few
    personal    everything else
    """
    if tx_count >= 5000 or counterparties >= 200:
        return "service"
    if counterparties >= 40 and total_out >= total_in * 0.8:
        return "distributor"
    if counterparties >= 40:
        return "collector"
    if co_spent >= 20:
        return "wallet-cluster"
    return "personal"


CATEGORY_LABELS = {
    "sanctioned": "Sanctioned (OFAC)", "exchange": "Exchange", "mixer": "Mixer / tumbler",
    "service": "High-throughput service", "distributor": "Distributor", "collector": "Collector",
    "wallet-cluster": "Clustered wallet", "personal": "Personal wallet", "unknown": "Unknown",
    "intel": "Seen in collected intelligence",
}
# Categories that stand out in the graph as noteworthy, like severity does for findings.
RISK_CATEGORIES = {"sanctioned", "mixer", "service", "distributor", "intel"}


def classify(result: dict, in_intel: bool) -> tuple[str, str]:
    """Decide an address's category and display name from a lookup result and whether it is in our intelligence.

    Order of precedence: a documented address, then that it appears in collected
    intelligence, then its on-chain shape.
    """
    known = known_label(result["address"])
    if known:
        return known
    if in_intel:
        return "intel", ""
    cat = heuristic_category(tx_count=result.get("tx_count", 0), counterparties=len(result.get("counterparties", [])),
                             co_spent=len(result.get("co_spent", [])), total_in=result.get("total_in", 0.0),
                             total_out=result.get("total_out", 0.0))
    return cat, ""
