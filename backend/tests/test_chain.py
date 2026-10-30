"""Blockchain tracer: address detection, the three chain parsers, and labelling."""
import json
from pathlib import Path

from app.chain import addresses as a
from app.chain import labels, providers

FIX = Path(__file__).parent / "fixtures"


def test_detects_the_chain_and_normalises():
    assert a.detect_chain("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") == ("eth", "0x742d35cc6634c0532925a3b844bc454e4438f44e")
    assert a.detect_chain("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") == ("tron", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
    assert a.detect_chain("bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97")[0] == "btc"
    assert a.detect_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert a.detect_chain("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A") == ("xmr", "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
    assert a.detect_chain("not-a-wallet") is None and a.detect_chain("") is None
    # A legacy address with a broken checksum is rejected, not mis-chained.
    assert a.detect_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf00") is None
    assert a.can_look_up("btc") and a.can_look_up("eth") and a.can_look_up("tron") and not a.can_look_up("xmr")


def test_btc_parser_balances_edges_and_clustering():
    summary = {"chain_stats": {"funded_txo_sum": 530775984312979, "spent_txo_sum": 517774975978040, "tx_count": 348}}
    addr = "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97"
    txs = [{"txid": "t1", "status": {"block_time": 1792985551, "confirmed": True},
            "vin": [{"prevout": {"scriptpubkey_address": addr, "value": 100000}}, {"prevout": {"scriptpubkey_address": "cosigner", "value": 50000}}],
            "vout": [{"scriptpubkey_address": "dest1", "value": 120000}, {"scriptpubkey_address": addr, "value": 25000}]}]
    r = providers.parse_btc(addr, summary, txs)
    assert r["chain"] == "btc" and r["token"] == "BTC"
    assert round(r["balance"], 4) == round((530775984312979 - 517774975978040) / 1e8, 4)
    assert r["tx_count"] == 348 and r["examined"] == 1 and r["truncated"] is True
    assert "cosigner" in r["co_spent"]  # co-spent input -> same wallet cluster
    out = [c for c in r["counterparties"] if c["address"] == "dest1"]
    assert out and out[0]["direction"] == "out" and out[0]["value"] == 0.0012


def test_eth_parser():
    full = {"balance": int(1.5e18), "total_received": int(5e18), "total_sent": int(3.5e18), "n_tx": 10, "hasMore": True,
            "txs": [{"hash": "0xabc", "confirmed": "2026-10-30T00:30:11Z", "inputs": [{"addresses": ["0xSENDER"]}], "outputs": [{"addresses": ["0xME"], "value": int(2e18)}]}]}
    r = providers.parse_eth("0xme", full)
    assert r["balance"] == 1.5 and r["total_in"] == 5.0 and r["total_out"] == 3.5 and r["truncated"] is True
    # our address received, so the sender is an "in" counterparty
    assert any(c["address"] == "0xsender" and c["direction"] == "in" for c in r["counterparties"])


def test_tron_parser_scales_usdt_and_trx():
    account = {"balance": 1094470867104}  # sun
    transfers = [
        {"from": "TATTACKER", "to": "TME", "value": "1000000000", "block_timestamp": 1700000000000, "transaction_id": "x1",
         "token_info": {"symbol": "USDT", "decimals": 6}},
        {"from": "TME", "to": "TEXCHANGE", "value": "500000000", "block_timestamp": 1700000500000, "transaction_id": "x2",
         "token_info": {"symbol": "USDT", "decimals": 6}},
    ]
    r = providers.parse_tron("TME", account, transfers)
    assert round(r["balance"], 2) == 1094470.87 and r["token"].startswith("USDT")
    assert r["total_in"] == 1000.0 and r["total_out"] == 500.0
    dirs = {c["address"]: c["direction"] for c in r["counterparties"]}
    assert dirs["TATTACKER"] == "in" and dirs["TEXCHANGE"] == "out"


def test_labels_known_shape_and_intel_precedence():
    assert labels.known_label("0x722122df12d4e14e13ac3b6895a86e84145b6967") == ("sanctioned", "Tornado Cash: router (OFAC SDN)")
    assert labels.known_label("0x0000000000000000000000000000000000000000") is None
    assert labels.heuristic_category(tx_count=9000, counterparties=5, co_spent=0, total_in=1, total_out=1) == "service"
    assert labels.heuristic_category(tx_count=10, counterparties=60, co_spent=0, total_in=1, total_out=5) == "distributor"
    assert labels.heuristic_category(tx_count=10, counterparties=60, co_spent=0, total_in=5, total_out=0) == "collector"
    assert labels.heuristic_category(tx_count=3, counterparties=2, co_spent=25, total_in=1, total_out=1) == "wallet-cluster"
    assert labels.heuristic_category(tx_count=3, counterparties=2, co_spent=0, total_in=1, total_out=1) == "personal"
    # a documented address beats everything; intel beats shape
    known = {"address": "0x722122df12d4e14e13ac3b6895a86e84145b6967", "tx_count": 1, "counterparties": [], "co_spent": [], "total_in": 0, "total_out": 0}
    assert labels.classify(known, True)[0] == "sanctioned"
    plain = {"address": "0xdeadbeef", "tx_count": 1, "counterparties": [], "co_spent": [], "total_in": 0, "total_out": 0}
    assert labels.classify(plain, True) == ("intel", "")
    assert labels.classify(plain, False) == ("personal", "")
