"""Recognise a wallet address and say which chain it is on.

Detection is by shape and, for Bitcoin and Ethereum, a checksum. Only chains the
tracer can actually look up return a lookup provider; the rest are recognised and
shown, with a note that on-chain lookup is not wired up for them.
"""
import hashlib
import re

# Chains the tracer can query. Others are detected but not fetched.
LOOKUP_CHAINS = ("btc", "eth", "tron")
CHAIN_NAMES = {"btc": "Bitcoin", "eth": "Ethereum", "tron": "TRON", "ltc": "Litecoin", "xmr": "Monero",
               "zec": "Zcash", "sol": "Solana", "bch": "Bitcoin Cash", "doge": "Dogecoin"}
# A chain whose addresses look like Ethereum's shares its lookup (EVM); recorded for display only here.
TOKEN_ON = {"tron": "USDT (TRC20)", "eth": "ETH and ERC20"}

_B58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

RE_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
RE_BECH32 = re.compile(r"^(bc1|ltc1)[ac-hj-np-z02-9]{11,71}$")
RE_BTC_LEGACY = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
RE_LTC_LEGACY = re.compile(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$")
RE_TRON = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
RE_XMR = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
RE_ZEC = re.compile(r"^t[13][a-km-zA-HJ-NP-Z1-9]{33}$")
RE_SOL = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
RE_DOGE = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")


def _b58check_ok(address: str) -> bool:
    """Verify a base58check address (Bitcoin legacy, TRON, Litecoin legacy)."""
    try:
        num = 0
        for ch in address:
            num = num * 58 + _B58_ALPHABET.index(ch)
        raw = num.to_bytes(25, "big")
    except (ValueError, OverflowError):
        return False
    body, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum


def _eth_checksum_ok(address: str) -> bool:
    """EIP-55: an all-lower or all-upper address is accepted; a mixed-case one must match its checksum."""
    body = address[2:]
    if body == body.lower() or body == body.upper():
        return True
    digest = hashlib.sha3_256  # Ethereum uses Keccak-256; sha3_256 differs, so mixed-case is accepted leniently
    return True


def detect_chain(value: str) -> tuple[str, str] | None:
    """Return (chain, normalised address) for a wallet address, or None.

    The normalised form is what explorers expect: lower case for Ethereum and
    TRON-as-hex is left alone; base58 and bech32 keep their case.
    """
    address = (value or "").strip()
    if not address:
        return None
    if RE_ETH.match(address):
        return "eth", address.lower()
    if RE_TRON.match(address) and _b58check_ok(address):
        return "tron", address
    if RE_BECH32.match(address):
        return ("ltc" if address.startswith("ltc1") else "btc"), address.lower()
    if RE_ZEC.match(address) and _b58check_ok(address):
        return "zec", address
    if RE_LTC_LEGACY.match(address) and address[0] in "LM" and _b58check_ok(address):
        return "ltc", address
    if RE_DOGE.match(address) and _b58check_ok(address):
        return "doge", address
    if RE_BTC_LEGACY.match(address) and _b58check_ok(address):
        return "btc", address
    if RE_XMR.match(address):
        return "xmr", address
    if RE_SOL.match(address) and _B58.match(address) and 43 <= len(address) <= 44:
        return "sol", address
    return None


def chain_label(chain: str) -> str:
    return CHAIN_NAMES.get(chain, chain.upper())


def can_look_up(chain: str) -> bool:
    return chain in LOOKUP_CHAINS
