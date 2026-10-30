"""Search execution: filters, ranking, facets, highlighting and suggestions."""
from dataclasses import dataclass, field
from datetime import datetime

from app.search import query as q
from app.search.index import HL_CLOSE, HL_OPEN, client, index_name

SORTS = {
    "relevance": ["_score", {"date": "desc"}],
    "newest": [{"date": "desc"}, "_score"],
    "oldest": [{"date": "asc"}],
    "risk": [{"risk_score": "desc"}, {"date": "desc"}],
    "changed": [{"last_changed": "desc"}],
}
FACETS = {
    "threat_types": ("threat_types", 15),
    "countries": ("countries", 25),
    "severity": ("severity", 5),
    "network": ("network", 3),
    "sources": ("source_name", 25),
    "actors": ("actors", 15),
    "organizations": ("organizations", 15),
    "malware": ("malware", 10),
    "sectors": ("sectors", 12),
    "tags": ("tags", 15),
    "status": ("status", 5),
    "techniques": ("techniques", 15),
    "verification": ("verification", 4),
    "languages": ("lang", 12),
    "source_types": ("source_category", 10),
    "hosts": ("host", 20),
}
_SOURCE_FIELDS = {
    "excludes": ["content", "ioc_all", "ioc_url", "ioc_domain", "ioc_onion", "ioc_email", "ioc_ip", "ioc_hash", "ioc_cve", "ioc_crypto", "ioc_username", "domain_suffixes", "email_domains"]
}


@dataclass
class SearchParams:
    q: str = ""
    strict: bool = False
    threat_types: list[str] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    date_from: datetime | None = None
    date_to: datetime | None = None
    min_risk: int | None = None
    min_confidence: int | None = None
    has_credentials: bool | None = None
    include_duplicates: bool = False
    sort: str = ""
    page: int = 1
    size: int = 20


def build_filters(p: SearchParams) -> list[dict]:
    filters: list[dict] = []
    for values, index_field in (
        (p.threat_types, "threat_types"), (p.countries, "countries"), (p.severities, "severity"), (p.networks, "network"),
        (p.sources, "source_name"), (p.actors, "actors"), (p.organizations, "organizations"), (p.malware, "malware"),
        (p.sectors, "sectors"), (p.tags, "tags"), (p.statuses, "status"), (p.techniques, "techniques"), (p.verification, "verification"),
        (p.languages, "lang"), (p.source_types, "source_category"), (p.hosts, "host"),
    ):
        if values:
            filters.append({"terms": {index_field: values}})
    if p.date_from or p.date_to:
        bounds = {}
        if p.date_from:
            bounds["gte"] = p.date_from.isoformat()
        if p.date_to:
            bounds["lte"] = p.date_to.isoformat()
        filters.append({"range": {"date": bounds}})
    if p.min_risk:
        filters.append({"range": {"risk_score": {"gte": p.min_risk}}})
    if p.min_confidence:
        filters.append({"range": {"confidence": {"gte": p.min_confidence}}})
    if p.has_credentials is not None:
        filters.append({"term": {"has_credentials": p.has_credentials}})
    if not p.include_duplicates:
        filters.append({"term": {"is_duplicate": False}})
    return filters


def _ranked(bool_query: dict) -> dict:
    """Blend how well the text matches with what makes a finding worth a researcher's time.

    Text relevance is multiplied by a sum of: risk, recency, how reliable the source is, how many
    independent sources report the same thing, how many sources carry the same content, and how
    often the page has been seen to change. Each part is small, so none can outvote a good match.
    """
    return {
        "function_score": {
            "query": bool_query,
            "functions": [
                {"weight": 1},
                {"field_value_factor": {"field": "risk_score", "factor": 0.006, "missing": 0}},
                {"gauss": {"date": {"origin": "now", "scale": "45d", "offset": "3d", "decay": 0.5}}, "weight": 0.6},
                {"field_value_factor": {"field": "source_trust", "factor": 0.003, "missing": 50}},
                {"field_value_factor": {"field": "corroboration", "factor": 0.08, "modifier": "log1p", "missing": 0}},
                {"field_value_factor": {"field": "seen_at", "factor": 0.06, "modifier": "log1p", "missing": 1}},
                {"field_value_factor": {"field": "version_count", "factor": 0.04, "modifier": "log1p", "missing": 1}},
            ],
            "score_mode": "sum",
            "boost_mode": "multiply",
        }
    }


def _why(hit: dict, src: dict, interpretation: list[dict]) -> list[dict]:
    """Why this result appeared: the parts of the query it matched, then what lifted it in the ranking."""
    reasons: list[dict] = []
    for name in hit.get("matched_queries") or []:
        if name[:1] == "q" and name[1:].isdigit() and int(name[1:]) < len(interpretation):
            entry = interpretation[int(name[1:])]
            reasons.append({"kind": entry["kind"], "label": entry["label"]})
    highlight = hit.get("highlight", {})
    if any(k.startswith("title") for k in highlight):
        reasons.append({"kind": "where", "label": "Match in the title"})
    if (src.get("corroboration") or 0) > 0:
        reasons.append({"kind": "rank", "label": f"Corroborated by {src['corroboration']} other source{'s' if src['corroboration'] != 1 else ''}"})
    if (src.get("seen_at") or 1) > 1:
        reasons.append({"kind": "rank", "label": f"Same content seen at {src['seen_at']} sources"})
    if (src.get("risk_score") or 0) >= 70:
        reasons.append({"kind": "rank", "label": f"High risk ({src['risk_score']})"})
    if (src.get("source_trust") or 0) >= 80:
        reasons.append({"kind": "rank", "label": "Reliable source"})
    return reasons[:8]


def _split_highlight(fragment: str) -> list[dict]:
    """Turn a sentinel-marked fragment into [{t: text, h: highlighted?}] parts.

    The UI renders these as text nodes, so crawled content is never injected as HTML.
    """
    parts: list[dict] = []
    for i, chunk in enumerate(fragment.split(HL_OPEN)):
        if i == 0:
            if chunk:
                parts.append({"t": chunk, "h": False})
            continue
        marked, _, rest = chunk.partition(HL_CLOSE)
        if marked:
            parts.append({"t": marked, "h": True})
        if rest:
            parts.append({"t": rest, "h": False})
    return parts


def _hit(hit: dict, interpretation: list[dict] | None = None, max_score: float | None = None) -> dict:
    src = hit["_source"]
    hl = hit.get("highlight", {})
    fragments = hl.get("content") or []
    exact = hl.get("content.exact") or []
    if exact and not any(HL_OPEN in f for f in fragments):
        fragments = exact
    title_hl = (hl.get("title") or hl.get("title.exact") or [src.get("title", "")])[0]
    return {
        "id": hit["_id"],
        "score": hit.get("_score"),
        # Relative to the best result of this search, so 100 always means "the strongest match here".
        "relevance": round(100 * hit["_score"] / max_score) if hit.get("_score") and max_score else None,
        "why": _why(hit, src, interpretation or []),
        "title": src.get("title") or "(untitled)",
        "title_parts": _split_highlight(title_hl) or [{"t": src.get("title") or "(untitled)", "h": False}],
        "snippets": [_split_highlight(f) for f in fragments[:3]] or [[{"t": src.get("summary", ""), "h": False}]],
        **{k: src.get(k) for k in (
            "url", "host", "source_id", "source_name", "source_category", "network", "threat_type", "threat_types", "severity",
            "risk_score", "confidence", "countries", "sectors", "actors", "organizations", "malware", "tags", "status",
            "has_credentials", "credential_count", "ioc_count", "is_duplicate", "version_count", "date", "first_seen",
            "last_seen", "last_changed", "published_at", "techniques", "verification", "corroboration", "admiralty", "lang", "seen_at",
            "source_trust",
        )},
    }


def search(p: SearchParams) -> dict:
    parsed = q.parse_query(p.q, strict=p.strict)
    bool_query = q.to_bool_query(parsed, build_filters(p))
    has_text = bool(parsed.must or parsed.should)
    sort = p.sort if p.sort in SORTS else ("relevance" if has_text else "newest")
    size = max(1, min(p.size, 100))
    start = (max(1, p.page) - 1) * size
    if start + size > 10_000:
        start = 10_000 - size

    body: dict = {
        "query": _ranked(bool_query) if sort == "relevance" else bool_query,
        "sort": SORTS[sort],
        "from": start,
        "size": size,
        "track_total_hits": True,
        "track_scores": True,  # so relevance can be shown whatever the sort order
        "_source": _SOURCE_FIELDS,
        "highlight": {
            "pre_tags": [HL_OPEN],
            "post_tags": [HL_CLOSE],
            "require_field_match": False,
            "fields": {
                "title": {"number_of_fragments": 0},
                "title.exact": {"number_of_fragments": 0},
                "content": {"fragment_size": 190, "number_of_fragments": 3, "no_match_size": 240},
                "content.exact": {"fragment_size": 190, "number_of_fragments": 3},
            },
        },
        "aggs": {
            **{name: {"terms": {"field": fld, "size": n}} for name, (fld, n) in FACETS.items()},
            "timeline": {"auto_date_histogram": {"field": "date", "buckets": 40}},
            "credentials": {"filter": {"term": {"has_credentials": True}}},
            "risk": {"stats": {"field": "risk_score"}},
            # Which sources carry the matches: the step from a query to the places worth opening.
            "by_source": {"terms": {"field": "source_id", "size": 12}, "aggs": {
                "latest": {"max": {"field": "date"}},
                "top": {"top_hits": {"size": 1, "_source": ["source_name", "source_category", "network", "host"]}}}},
        },
    }
    if parsed.similar_to:
        body["query"] = {"bool": {"must": [body["query"]], "must_not": [{"ids": {"values": [parsed.similar_to]}}]}}
    if parsed.text_terms:
        body["suggest"] = {
            "text": " ".join(parsed.text_terms),
            "dym": {"term": {"field": "content.exact", "suggest_mode": "missing", "min_word_length": 4, "prefix_length": 1, "size": 1}},
        }

    res = client().search(index=index_name(), body=body)
    aggs = res.get("aggregations", {})

    did_you_mean = None
    if parsed.text_terms and res["hits"]["total"]["value"] < 3:
        words = []
        for entry in res.get("suggest", {}).get("dym", []):
            words.append(entry["options"][0]["text"] if entry.get("options") else entry["text"])
        candidate = " ".join(words)
        if candidate and candidate.lower() != " ".join(parsed.text_terms).lower():
            did_you_mean = candidate

    return {
        "query": p.q,
        "total": res["hits"]["total"]["value"],
        "took_ms": res["took"],
        "page": start // size + 1,
        "size": size,
        "sort": sort,
        "hits": [_hit(h, parsed.interpretation, (res["hits"].get("max_score") or max((h.get("_score") or 0 for h in res["hits"]["hits"]), default=0)) if has_text else None)
                 for h in res["hits"]["hits"]],
        "sources": [{"id": b["key"], "count": b["doc_count"], "latest": b.get("latest", {}).get("value_as_string"),
                     **{k: (b["top"]["hits"]["hits"][0]["_source"].get(v) if b["top"]["hits"]["hits"] else "") for k, v in
                        (("name", "source_name"), ("category", "source_category"), ("network", "network"), ("host", "host"))}}
                    for b in aggs.get("by_source", {}).get("buckets", [])],
        "facets": {name: [{"value": b["key"], "count": b["doc_count"]} for b in aggs.get(name, {}).get("buckets", [])] for name in FACETS},
        "timeline": {
            "interval": aggs.get("timeline", {}).get("interval", ""),
            "buckets": [{"date": b["key_as_string"], "count": b["doc_count"]} for b in aggs.get("timeline", {}).get("buckets", [])],
        },
        "summary": {
            "with_credentials": aggs.get("credentials", {}).get("doc_count", 0),
            "avg_risk": round(aggs.get("risk", {}).get("avg") or 0),
            "max_risk": int(aggs.get("risk", {}).get("max") or 0),
        },
        "interpretation": parsed.interpretation,
        "did_you_mean": did_you_mean,
    }


def scan_ids(p: SearchParams, limit: int = 5000) -> list[str]:
    """Document ids matching a search, best first - used by exports."""
    parsed = q.parse_query(p.q, strict=p.strict)
    body = {
        "query": q.to_bool_query(parsed, build_filters(p)),
        "sort": SORTS[p.sort if p.sort in SORTS else "newest"],
        "size": min(limit, 10_000),
        "_source": False,
    }
    res = client().search(index=index_name(), body=body)
    return [h["_id"] for h in res["hits"]["hits"]]


def suggest_titles(prefix: str, size: int = 5) -> list[dict]:
    body = {
        "query": {"bool": {"must": [{"match": {"title.ac": {"query": prefix, "operator": "and"}}}], "filter": [{"term": {"is_duplicate": False}}]}},
        "sort": [{"risk_score": "desc"}, {"date": "desc"}],
        "size": size,
        "_source": ["title", "threat_type", "severity"],
    }
    res = client().search(index=index_name(), body=body)
    return [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]


def related(doc_id: str, size: int = 6, min_match: str = "55%") -> list[dict]:
    body = {
        "query": {
            "bool": {
                "must": [{"more_like_this": {"fields": ["title", "content"], "like": [{"_index": index_name(), "_id": doc_id}], "min_term_freq": 1, "min_doc_freq": 1, "max_query_terms": 30, "minimum_should_match": min_match}}],
                "filter": [{"term": {"is_duplicate": False}}],
                "must_not": [{"ids": {"values": [doc_id]}}],
            }
        },
        "size": size,
        "_source": ["title", "threat_type", "severity", "risk_score", "source_name", "date", "countries", "network"],
    }
    res = client().search(index=index_name(), body=body)
    return [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]


def watch_query(kind: str, value: str) -> dict:
    """Index query that finds candidates for a watchlist entry (used for retro-hunts)."""
    if kind in ("keyword", "brand", "executive", "technology"):
        return q._phrase_query(value)
    if kind == "vendor":
        kind = "organization"
    if kind in ("organization", "actor"):
        index_field = "organizations" if kind == "organization" else "actors"
        return {"bool": {"should": [q._name_query(index_field, value), q._phrase_query(value)], "minimum_should_match": 1}}
    if kind == "ip":
        return q.indicator_query("cidr" if "/" in value else "ip", value)
    return q.indicator_query(kind, value)


def retro_candidates(kind: str, value: str, limit: int = 300) -> list[str]:
    body = {"query": watch_query(kind, value), "sort": [{"date": "desc"}], "size": limit, "_source": False}
    res = client().search(index=index_name(), body=body)
    return [h["_id"] for h in res["hits"]["hits"]]


def overview(days: int = 30) -> dict:
    """Aggregates for the dashboard."""
    window = {"range": {"date": {"gte": f"now-{days}d/d"}}}
    base = [{"term": {"is_duplicate": False}}]
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": base}},
        "aggs": {
            "window": {
                "filter": window,
                "aggs": {
                    "severity": {"terms": {"field": "severity", "size": 5}},
                    "types": {"terms": {"field": "threat_type", "size": 12}},
                    "countries": {"terms": {"field": "countries", "size": 12}},
                    "country_map": {"terms": {"field": "countries", "size": 250}},  # every country, for the world map
                    "actors": {"terms": {"field": "actors", "size": 10}},
                    "organizations": {"terms": {"field": "organizations", "size": 10}},
                    "sectors": {"terms": {"field": "sectors", "size": 8}},
                    "network": {"terms": {"field": "network", "size": 3}},
                    "credentials": {"filter": {"term": {"has_credentials": True}}},
                    "timeline": {
                        "date_histogram": {"field": "date", "calendar_interval": "day", "min_doc_count": 0, "extended_bounds": {"min": f"now-{days}d/d", "max": "now/d"}},
                        "aggs": {"high": {"filter": {"terms": {"severity": ["high", "critical"]}}}},
                    },
                },
            },
            "last_24h": {"filter": {"range": {"first_seen": {"gte": "now-24h"}}}},
            "prev_window": {"filter": {"range": {"date": {"gte": f"now-{days * 2}d/d", "lt": f"now-{days}d/d"}}}},
        },
    }
    res = client().search(index=index_name(), body=body)
    aggs = res["aggregations"]
    win = aggs["window"]

    def buckets(name: str) -> list[dict]:
        return [{"value": b["key"], "count": b["doc_count"]} for b in win[name]["buckets"]]

    return {
        "days": days,
        "total": res["hits"]["total"]["value"],
        "in_window": win["doc_count"],
        "prev_window": aggs["prev_window"]["doc_count"],
        "last_24h": aggs["last_24h"]["doc_count"],
        "with_credentials": win["credentials"]["doc_count"],
        "country_map": buckets("country_map"),
        "severity": buckets("severity"),
        "types": buckets("types"),
        "countries": buckets("countries"),
        "actors": buckets("actors"),
        "organizations": buckets("organizations"),
        "sectors": buckets("sectors"),
        "network": buckets("network"),
        "timeline": [{"date": b["key_as_string"][:10], "count": b["doc_count"], "high": b["high"]["doc_count"]} for b in win["timeline"]["buckets"]],
    }


def entity_timeline(index_field: str, name: str, days: int = 180) -> list[dict]:
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {index_field: name}}, {"range": {"date": {"gte": f"now-{days}d/d"}}}]}},
        "aggs": {"timeline": {"date_histogram": {"field": "date", "calendar_interval": "week", "min_doc_count": 0,
                                                 "extended_bounds": {"min": f"now-{days}d/d", "max": "now/d"}}}},
    }
    res = client().search(index=index_name(), body=body)
    return [{"date": b["key_as_string"][:10], "count": b["doc_count"]} for b in res["aggregations"]["timeline"]["buckets"]]


def count() -> int:
    return client().count(index=index_name())["count"]


def rule_filter(query: str, since: datetime | None = None, until: datetime | None = None) -> dict:
    """The index query for a detection rule: the analyst's query, restricted to when findings were first collected."""
    bounds = {}
    if since:
        bounds["gt"] = since.isoformat()
    if until:
        bounds["lte"] = until.isoformat()
    extra = [{"term": {"is_duplicate": False}}] + ([{"range": {"first_seen": bounds}}] if bounds else [])
    return q.to_bool_query(q.parse_query(query), extra)


def count_matching(query: str, since: datetime | None = None, until: datetime | None = None) -> int:
    return client().count(index=index_name(), body={"query": rule_filter(query, since, until)})["count"]


def new_matches(query: str, since: datetime | None, limit: int = 200) -> list[str]:
    body = {"query": rule_filter(query, since), "sort": [{"first_seen": "asc"}], "size": limit, "_source": False}
    return [h["_id"] for h in client().search(index=index_name(), body=body)["hits"]["hits"]]


def retrieve_for_answer(query: str, size: int = 10) -> list[dict]:
    """Top findings for a question, with enough text for a grounded answer."""
    parsed = q.parse_query(query)
    body = {"query": _ranked(q.to_bool_query(parsed, [{"term": {"is_duplicate": False}}])), "size": size,
            "_source": ["title", "content", "summary", "source_name", "date", "threat_type", "verification", "countries", "actors", "severity"]}
    res = client().search(index=index_name(), body=body)
    return [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]


def technique_counts(days: int = 90) -> dict[str, int]:
    body = {"size": 0, "query": {"bool": {"filter": [{"term": {"is_duplicate": False}}, {"range": {"date": {"gte": f"now-{days}d/d"}}}]}},
            "aggs": {"techniques": {"terms": {"field": "techniques", "size": 800}}}}
    res = client().search(index=index_name(), body=body)
    return {b["key"]: b["doc_count"] for b in res["aggregations"]["techniques"]["buckets"]}


def movers(days: int = 30, field_name: str = "actors", size: int = 8) -> list[dict]:
    """What is rising: activity in the current window against the window before it."""
    body = {"size": 0, "query": {"bool": {"filter": [{"term": {"is_duplicate": False}}]}}, "aggs": {
        "now": {"filter": {"range": {"date": {"gte": f"now-{days}d/d"}}}, "aggs": {"t": {"terms": {"field": field_name, "size": 60}}}},
        "before": {"filter": {"range": {"date": {"gte": f"now-{days * 2}d/d", "lt": f"now-{days}d/d"}}}, "aggs": {"t": {"terms": {"field": field_name, "size": 200}}}},
    }}
    aggs = client().search(index=index_name(), body=body)["aggregations"]
    before = {b["key"]: b["doc_count"] for b in aggs["before"]["t"]["buckets"]}
    rows = [{"value": b["key"], "count": b["doc_count"], "previous": before.get(b["key"], 0)} for b in aggs["now"]["t"]["buckets"]]
    for row in rows:
        row["change"] = row["count"] - row["previous"]
    return sorted(rows, key=lambda r: (r["change"], r["count"]), reverse=True)[:size]
