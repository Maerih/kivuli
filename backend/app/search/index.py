"""OpenSearch index definition and write path.

The index is derived data: it can be dropped and rebuilt from PostgreSQL at any
time with ``python -m app.manage reindex``.
"""
import logging
from functools import lru_cache
from typing import Iterable

from opensearchpy import OpenSearch, helpers

from app.config import get_settings
from app.extract.iocs import registered_domain

log = logging.getLogger(__name__)

HL_OPEN, HL_CLOSE = "@@HL@@", "@@/HL@@"
MAX_INDEXED_CHARS = 400_000

# Query-time synonyms. Applied when searching, so the list can grow without a reindex.
SYNONYMS = [
    "ransomware, extortion, ransom",
    "breach, leak, leaked, dump, exfiltration",
    "hacked, compromised, breached, pwned",
    "credentials, passwords, logins, combolist, combo",
    "ddos, denial of service",
    "defaced, defacement",
    "database, db",
    "vulnerability, vuln, flaw",
    "exploit, 0day, zeroday, zero day",
    "stealer, infostealer",
    "govt, government",
    "telco, telecom, telecommunications",
    "uni, university",
    "bank, banking",
    "hospital, healthcare, clinic",
    "cyberattack, cyber attack",
    "darkweb, dark web, darknet",
    "sim swap, simswap",
    "mpesa, m pesa",
]

_NAME_FIELD = {
    "type": "keyword",
    "fields": {
        "lc": {"type": "keyword", "normalizer": "lower"},
        "text": {"type": "text", "analyzer": "exact"},
        "ac": {"type": "text", "analyzer": "autocomplete_index", "search_analyzer": "exact"},
    },
}
_LC = {"type": "keyword", "normalizer": "lower"}

INDEX_BODY = {
    "settings": {
        "index": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "2s",
            "max_ngram_diff": 20,
            "highlight.max_analyzed_offset": MAX_INDEXED_CHARS + 1000,
        },
        "analysis": {
            "char_filter": {
                # Index defanged indicators (example[.]com, hxxp://) as the real value.
                "refang_dot": {"type": "pattern_replace", "pattern": r"\[\.\]|\(\.\)|\[dot\]", "replacement": "."},
                "refang_http": {"type": "pattern_replace", "pattern": r"hxxp", "replacement": "http"},
            },
            "filter": {
                "en_stop": {"type": "stop", "stopwords": "_english_"},
                "en_stem": {"type": "stemmer", "language": "light_english"},
                "ti_synonyms": {"type": "synonym_graph", "synonyms": SYNONYMS, "lenient": True},
                "edge": {"type": "edge_ngram", "min_gram": 2, "max_gram": 20},
            },
            "analyzer": {
                "text_index": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "char_filter": ["refang_dot", "refang_http"],
                    "filter": ["lowercase", "asciifolding", "en_stop", "en_stem"],
                },
                "text_search": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "char_filter": ["refang_dot", "refang_http"],
                    "filter": ["lowercase", "asciifolding", "ti_synonyms", "en_stop", "en_stem"],
                },
                # No stemming, stop words or synonyms: what quoted phrases search.
                "exact": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "char_filter": ["refang_dot", "refang_http"],
                    "filter": ["lowercase", "asciifolding"],
                },
                "autocomplete_index": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "asciifolding", "edge"],
                },
            },
            "normalizer": {"lower": {"type": "custom", "filter": ["lowercase", "asciifolding"]}},
        },
    },
    "mappings": {
        "dynamic": False,
        "properties": {
            "title": {
                "type": "text",
                "analyzer": "text_index",
                "search_analyzer": "text_search",
                "fields": {
                    "exact": {"type": "text", "analyzer": "exact"},
                    "ac": {"type": "text", "analyzer": "autocomplete_index", "search_analyzer": "exact"},
                },
            },
            "content": {
                "type": "text",
                "analyzer": "text_index",
                "search_analyzer": "text_search",
                "fields": {"exact": {"type": "text", "analyzer": "exact"}},
            },
            "summary": {"type": "keyword", "index": False, "doc_values": False},
            "url": _LC,
            "host": _LC,
            "source_id": {"type": "integer"},
            "source_name": {"type": "keyword", "fields": {"lc": _LC}},
            "source_category": {"type": "keyword"},
            "network": {"type": "keyword"},
            "threat_type": {"type": "keyword"},
            "threat_types": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "risk_score": {"type": "integer"},
            "confidence": {"type": "integer"},
            "countries": {"type": "keyword"},
            "sectors": {"type": "keyword", "fields": {"lc": _LC, "text": {"type": "text", "analyzer": "exact"}}},
            "lang": {"type": "keyword"},
            "actors": _NAME_FIELD,
            "organizations": _NAME_FIELD,
            "malware": _NAME_FIELD,
            "campaigns": _NAME_FIELD,
            "ioc_domain": _LC,
            "ioc_onion": _LC,
            "ioc_url": _LC,
            "ioc_email": _LC,
            "ioc_ip": {"type": "ip", "ignore_malformed": True},
            "ioc_hash": _LC,
            "ioc_cve": _LC,
            "ioc_crypto": {"type": "keyword"},
            "ioc_username": _LC,
            # Every indicator value, for "paste anything" lookups and wildcards.
            "ioc_all": _LC,
            # mail.example.co.ke is indexed as itself, example.co.ke - so a search for
            # the organisation's domain finds every subdomain and mailbox under it.
            "domain_suffixes": _LC,
            "email_domains": _LC,
            "ioc_count": {"type": "integer"},
            "tags": {"type": "keyword"},
            "status": {"type": "keyword"},
            "techniques": {"type": "keyword"},
            "tactics": {"type": "keyword"},
            "verification": {"type": "keyword"},
            "corroboration": {"type": "integer"},
            "admiralty": {"type": "keyword"},
            "source_trust": {"type": "integer"},
            "seen_at": {"type": "integer"},  # sources carrying the same content: 1 plus its duplicates
            "has_credentials": {"type": "boolean"},
            "credential_count": {"type": "integer"},
            "is_duplicate": {"type": "boolean"},
            "version_count": {"type": "integer"},
            "date": {"type": "date"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "last_changed": {"type": "date"},
            "published_at": {"type": "date"},
        },
    },
}


@lru_cache
def client() -> OpenSearch:
    settings = get_settings()
    auth = (settings.opensearch_user, settings.opensearch_password) if settings.opensearch_user else None
    return OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )


def index_name() -> str:
    return get_settings().opensearch_index


def ensure_index(recreate: bool = False) -> bool:
    """Create the index if missing. Returns True when a new index was created."""
    os_client, name = client(), index_name()
    exists = os_client.indices.exists(index=name)
    if exists and recreate:
        os_client.indices.delete(index=name)
        exists = False
    if not exists:
        os_client.indices.create(index=name, body=INDEX_BODY)
        log.info("created search index %s", name)
        return True
    # Adding fields to a live index is safe and idempotent; existing documents are
    # filled in by the release backfill (manage upgrade-intel) or a reindex.
    os_client.indices.put_mapping(index=name, body={"properties": {
        key: INDEX_BODY["mappings"]["properties"][key] for key in ("techniques", "tactics", "verification", "corroboration", "admiralty")}})
    return False


def parent_domains(host: str) -> list[str]:
    """mail.example.co.ke -> [mail.example.co.ke, example.co.ke]."""
    host = host.lower().strip(".")
    base = registered_domain(host)
    if not base or not host.endswith(base):
        return [host]
    labels = host[: -len(base)].strip(".").split(".") if host != base else []
    out = [base]
    for label in reversed([l for l in labels if l]):
        out.append(f"{label}.{out[-1]}")
    return out[::-1]


def build_index_doc(doc, iocs: Iterable[tuple[str, str]], entities: Iterable[tuple[str, str]], tags: Iterable[str], duplicate_count: int = 0) -> dict:
    """Flatten a Document row plus its indicators and entities into an index document."""
    from app.intel import attack, quality  # local import: the index module is also loaded by roles without the catalogue

    known = attack.techniques()
    tactics = sorted({t for technique in doc.techniques or [] for t in known.get(technique, {}).get("tactics", [])})
    by_type: dict[str, list[str]] = {}
    for kind, value in iocs:
        by_type.setdefault(kind, []).append(value)
    names: dict[str, list[str]] = {}
    for kind, name in entities:
        names.setdefault(kind, []).append(name)

    suffixes: set[str] = set()
    for host in by_type.get("domain", []):
        suffixes.update(parent_domains(host))
    email_domains: set[str] = set()
    for email in by_type.get("email", []):
        email_domains.update(parent_domains(email.rsplit("@", 1)[-1]))

    event_date = doc.published_at if doc.published_at and doc.published_at <= doc.first_seen_at else doc.first_seen_at
    return {
        "title": doc.title,
        "content": doc.content[:MAX_INDEXED_CHARS],
        "summary": doc.summary,
        "url": doc.url,
        "host": doc.host,
        "source_id": doc.source_id,
        "source_name": doc.source.name if doc.source else "",
        "source_category": doc.source.category if doc.source else "",
        "network": doc.network,
        "threat_type": doc.threat_type,
        "threat_types": doc.threat_types,
        "severity": doc.severity,
        "risk_score": doc.risk_score,
        "confidence": doc.confidence,
        "countries": doc.countries,
        "sectors": doc.sectors,
        "lang": doc.lang,
        "actors": names.get("actor", []),
        "organizations": names.get("organization", []),
        "malware": names.get("malware", []),
        "campaigns": names.get("campaign", []),
        "ioc_domain": by_type.get("domain", []),
        "ioc_onion": by_type.get("onion", []),
        "ioc_url": by_type.get("url", []),
        "ioc_email": by_type.get("email", []),
        "ioc_ip": by_type.get("ip", []),
        "ioc_hash": by_type.get("hash", []),
        "ioc_cve": by_type.get("cve", []),
        "ioc_crypto": by_type.get("crypto", []),
        "ioc_username": by_type.get("username", []),
        "ioc_all": [v for values in by_type.values() for v in values],
        "domain_suffixes": sorted(suffixes),
        "email_domains": sorted(email_domains),
        "ioc_count": sum(len(v) for v in by_type.values()),
        "tags": list(tags),
        "status": doc.status,
        "techniques": list(doc.techniques or []),
        "tactics": tactics,
        "verification": doc.verification,
        "corroboration": doc.corroboration,
        "admiralty": quality.admiralty(doc.source, doc.verification) if doc.source else "",
        "source_trust": doc.source.trust if doc.source else 50,
        "seen_at": 1 + int(duplicate_count),
        "has_credentials": doc.has_credentials,
        "credential_count": (doc.exposure or {}).get("credential_pairs", 0),
        "is_duplicate": doc.duplicate_of is not None,
        "version_count": doc.version_count,
        "date": event_date.isoformat(),
        "first_seen": doc.first_seen_at.isoformat(),
        "last_seen": doc.last_seen_at.isoformat(),
        "last_changed": doc.last_changed_at.isoformat(),
        "published_at": doc.published_at.isoformat() if doc.published_at else None,
    }


def index_document(doc_id: str, body: dict, refresh: bool = False) -> None:
    """``refresh`` makes the change searchable immediately; use it for edits an analyst is waiting on."""
    client().index(index=index_name(), id=doc_id, body=body, refresh=refresh)


def bulk_index(actions: Iterable[tuple[str, dict]]) -> int:
    ok, _ = helpers.bulk(
        client(),
        ({"_op_type": "index", "_index": index_name(), "_id": doc_id, "_source": body} for doc_id, body in actions),
        chunk_size=200,
        request_timeout=120,
    )
    return ok


def delete_document(doc_id: str) -> None:
    client().delete(index=index_name(), id=doc_id, ignore=[404])


def update_fields(doc_id: str, fields: dict, refresh: bool = False) -> None:
    client().update(index=index_name(), id=doc_id, body={"doc": fields}, refresh=refresh, ignore=[404])
