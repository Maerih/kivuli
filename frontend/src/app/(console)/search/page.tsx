"use client";

import { Bookmark, ChevronDown, Crosshair, Download, HelpCircle, History, Search, Siren, SlidersHorizontal, Sparkles, Trash2, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { AddToCase, AiLabel, AiSources, CitedText, Countries, CrawlButton, CredentialBadge, Highlight, NetworkBadge, RiskMeter, SeverityBadge, StateBadge, useAiJob, VerificationBadge } from "@/components/bits";
import { MiniColumns } from "@/components/charts";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Pagination, Spinner, useAction } from "@/components/ui";
import { api, useApi, type Bucket, type Hit, type SearchResult, type SourceBrief } from "@/lib/api";
import { ago, cn, day, defang, num, SEVERITY_ORDER, shortHost, SOURCE_KIND_LABELS, stamp, titleCase } from "@/lib/format";

// facet key in the API response -> URL parameter
const FACETS: { key: string; param: string; label: string; open?: boolean }[] = [
  { key: "threat_types", param: "type", label: "Threat type", open: true },
  { key: "severity", param: "severity", label: "Severity", open: true },
  { key: "countries", param: "country", label: "Country", open: true },
  { key: "network", param: "network", label: "Network", open: true },
  { key: "source_types", param: "kind", label: "Source type", open: true },
  { key: "languages", param: "lang", label: "Language" },
  { key: "hosts", param: "site", label: "Site or onion service" },
  { key: "actors", param: "actor", label: "Threat actor" },
  { key: "organizations", param: "org", label: "Organisation" },
  { key: "sectors", param: "sector", label: "Sector" },
  { key: "malware", param: "malware", label: "Malware" },
  { key: "sources", param: "source", label: "Source" },
  { key: "techniques", param: "technique", label: "ATT&CK technique" },
  { key: "verification", param: "verified", label: "Verification" },
  { key: "tags", param: "tag", label: "Tag" },
  { key: "status", param: "status", label: "Triage status" },
];
const SORTS = [["relevance", "Most relevant"], ["newest", "Newest"], ["risk", "Highest risk"], ["changed", "Recently changed"], ["oldest", "Oldest"]];
const EXAMPLES = ["cyber attack Kenya", "ransomware country:KE after:90d", "domain:example.co.ke has:creds", "actor:lockbit OR actor:akira", '"initial access" bank'];

interface Suggestions {
  operators: { op: string; help: string; example: string }[];
  entities: { id: number; type: string; name: string; count: number }[];
  iocs: { id: number; type: string; value: string; count: number }[];
  countries: { code: string; name: string }[];
  titles: { id: string; title: string; threat_type: string; severity: string }[];
}
type Option = { key: string; group: string; label: string; hint?: string; apply: () => void };

/** "3M" -> " (per 3 months)", "1d" -> " (per day)". */
function intervalLabel(interval: string) {
  const m = /^(\d+)([smhdwMqy])$/.exec(interval ?? "");
  if (!m) return "";
  const unit = { s: "second", m: "minute", h: "hour", d: "day", w: "week", M: "month", q: "quarter", y: "year" }[m[2]]!;
  return m[1] === "1" ? ` (per ${unit})` : ` (per ${m[1]} ${unit}s)`;
}

function networkLabel(value: string) {
  return value === "onion" ? "Tor hidden services" : value === "surface" ? "Surface web" : value;
}

function SearchBox({ initial, onSearch }: { initial: string; onSearch: (q: string) => void }) {
  const router = useRouter();
  const [text, setText] = useState(initial);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [debounced, setDebounced] = useState("");
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => setText(initial), [initial]);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(text), 180);
    return () => clearTimeout(timer);
  }, [text]);
  const { data } = useApi<Suggestions>(open && debounced.trim().length >= 2 ? `/search/suggest?q=${encodeURIComponent(debounced)}` : null, { keepPreviousData: true });

  // Replace the token being typed, keeping everything before it.
  const replaceLast = useCallback((replacement: string, submit: boolean) => {
    const head = text.replace(/\S*$/, "");
    const next = head + replacement;
    setText(next);
    if (submit) { setOpen(false); onSearch(next.trim()); } else input.current?.focus();
  }, [text, onSearch]);

  const options: Option[] = useMemo(() => {
    if (!data) return [];
    const quote = (v: string) => (/\s/.test(v) ? `"${v}"` : v);
    const prefix: Record<string, string> = { actor: "actor", organization: "org", malware: "malware", campaign: "campaign" };
    return [
      ...data.operators.map((o) => ({ key: `op-${o.op}`, group: "Operators", label: o.op, hint: `${o.help} · e.g. ${o.example}`, apply: () => replaceLast(o.op, false) })),
      ...data.countries.map((c) => ({ key: `c-${c.code}`, group: "Countries", label: c.name, hint: `country:${c.code}`, apply: () => replaceLast(`country:${c.code} `, true) })),
      ...data.entities.map((e) => ({ key: `e-${e.id}`, group: "Entities", label: e.name, hint: `${titleCase(e.type)} · ${e.count} findings`, apply: () => replaceLast(`${prefix[e.type] ?? "actor"}:${quote(e.name)} `, true) })),
      ...data.iocs.map((i) => ({ key: `i-${i.id}`, group: "Indicators", label: i.value, hint: `${i.type} · ${i.count} findings`, apply: () => replaceLast(`${i.value} `, true) })),
      ...data.titles.map((t) => ({ key: `t-${t.id}`, group: "Findings", label: t.title, hint: titleCase(t.threat_type), apply: () => router.push(`/findings/${t.id}`) })),
    ];
  }, [data, replaceLast, router]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (open && active >= 0 && options[active]) return options[active].apply();
    setOpen(false);
    onSearch(text.trim());
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, options.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, -1)); }
    else if (e.key === "Escape") setOpen(false);
  };
  const showList = open && options.length > 0 && text.trim().length >= 2;

  return (
    <form onSubmit={submit} className="relative" role="search">
      <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
      <input
        ref={input}
        value={text}
        onChange={(e) => { setText(e.target.value); setOpen(true); setActive(-1); }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={onKey}
        autoFocus
        spellCheck={false}
        autoComplete="off"
        role="combobox"
        aria-expanded={showList}
        aria-controls="search-suggestions"
        aria-label="Search findings"
        placeholder='Search dark-web intelligence: cyber attack Kenya · company.com · "leaked credentials" · ransomware AND Kenya NOT advertisement'
        className="h-11 w-full rounded-lg border border-line-strong bg-raised pl-10 pr-24 text-[15px] placeholder:text-muted"
      />
      {text && <button type="button" aria-label="Clear" onClick={() => { setText(""); onSearch(""); input.current?.focus(); }} className="absolute right-[5.25rem] top-1/2 -translate-y-1/2 rounded p-1 text-muted hover:text-ink"><X className="h-4 w-4" /></button>}
      <Button variant="primary" type="submit" className="absolute right-1 top-1/2 -translate-y-1/2">Search</Button>
      {showList && (
        <ul id="search-suggestions" role="listbox" className="scroll-thin absolute left-0 right-0 top-12 z-30 max-h-96 overflow-y-auto rounded-lg bg-raised py-1 shadow-pop">
          {options.map((o, i) => (
            <li key={o.key} role="option" aria-selected={i === active}>
              {(i === 0 || options[i - 1].group !== o.group) && <div className="label px-3 pb-1 pt-2">{o.group}</div>}
              <button type="button" onMouseDown={(e) => { e.preventDefault(); o.apply(); }} onMouseEnter={() => setActive(i)}
                className={cn("flex w-full items-baseline justify-between gap-4 px-3 py-1.5 text-left text-sm", i === active && "bg-accent-soft")}>
                <span className="truncate">{o.label}</span>
                {o.hint && <span className="shrink-0 truncate text-xs text-muted">{o.hint}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </form>
  );
}

function FacetGroup({ label, buckets, selected, onToggle, format, defaultOpen }: { label: string; buckets: Bucket[]; selected: string[]; onToggle: (v: string) => void; format: (b: Bucket) => string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(Boolean(defaultOpen) || selected.length > 0);
  const [all, setAll] = useState(false);
  // Keep selected values visible even when the current result set has no bucket for them.
  const merged = [...buckets, ...selected.filter((s) => !buckets.some((b) => b.value === s)).map((s) => ({ value: s, count: 0 }))];
  if (!merged.length) return null;
  const visible = all ? merged : merged.slice(0, 6);
  return (
    <div className="border-b border-line py-2.5 last:border-b-0">
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center justify-between text-left text-xs font-semibold text-ink-2 hover:text-ink">
        <span>{label}{selected.length > 0 && <span className="ml-1.5 rounded bg-accent-soft px-1 text-2xs text-accent-ink">{selected.length}</span>}</span>
        <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <ul className="mt-1.5 space-y-0.5">
          {visible.map((b) => (
            <li key={b.value}>
              <label className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-sunken">
                <input type="checkbox" checked={selected.includes(b.value)} onChange={() => onToggle(b.value)} className="h-3.5 w-3.5 accent-[var(--accent)]" />
                <span className="min-w-0 flex-1 truncate text-ink-2">{format(b)}</span>
                <span className="text-xs tabular-nums text-muted">{num(b.count)}</span>
              </label>
            </li>
          ))}
          {merged.length > 6 && <li><button onClick={() => setAll(!all)} className="link px-1 text-xs">{all ? "Show fewer" : `Show ${merged.length - 6} more`}</button></li>}
        </ul>
      )}
    </div>
  );
}

function ResultCard({ hit, onFilter }: { hit: Hit; onFilter: (param: string, value: string) => void }) {
  const chips: [string, string, string[]][] = [["actor", "Actor", hit.actors ?? []], ["org", "Org", hit.organizations ?? []], ["malware", "Malware", hit.malware ?? []], ["technique", "Technique", hit.techniques ?? []]];
  return (
    <article className="border-b border-line px-4 py-3.5 last:border-b-0">
      <div className="flex items-start justify-between gap-4">
        <h3 className="min-w-0 text-[15px] font-semibold leading-snug">
          <Link href={`/findings/${hit.id}`} className="hover:text-accent-ink hover:underline"><Highlight parts={hit.title_parts} /></Link>
        </h3>
        <div className="flex shrink-0 flex-col items-end gap-0.5">
          <RiskMeter score={hit.risk_score} />
          {typeof hit.relevance === "number" && <span className="text-2xs tabular-nums text-muted" title="How strongly this matches, relative to the best result of this search">Relevance {hit.relevance}</span>}
        </div>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={hit.severity} />
        <Badge tone="accent">{titleCase(hit.threat_type)}</Badge>
        <NetworkBadge network={hit.network} />
        {hit.has_credentials && <CredentialBadge count={hit.credential_count} />}
        {hit.version_count > 1 && <Badge title="The source changed this page after it was first captured"><History className="h-3 w-3" />{hit.version_count} versions</Badge>}
        {hit.verification && hit.verification !== "reported" && <VerificationBadge state={hit.verification} admiralty={hit.admiralty} corroboration={hit.corroboration} />}
        {(hit.seen_at ?? 1) > 1 && <Badge title="The same content was collected from this many sources; it is shown once">Seen at {hit.seen_at} sources</Badge>}
        {hit.is_duplicate && <Badge>Duplicate</Badge>}
        {hit.status !== "new" && <Badge>{titleCase(hit.status)}</Badge>}
        {(hit.tags ?? []).map((t) => <Badge key={t}>#{t}</Badge>)}
      </div>
      <div className="mt-2 space-y-1 text-sm leading-relaxed text-ink-2">
        {hit.snippets.slice(0, 2).map((parts, i) => <p key={i} className="line-clamp-2 break-words"><Highlight parts={parts} /></p>)}
      </div>
      {chips.some(([, , values]) => values.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {chips.flatMap(([param, label, values]) => values.slice(0, 4).map((v) => (
            <button key={param + v} onClick={() => onFilter(param, v)} title={`Filter by this ${label.toLowerCase()}`} className="rounded border border-line px-1.5 py-0.5 text-xs text-ink-2 hover:border-accent hover:text-accent-ink">
              <span className="text-muted">{label}</span> {v}
            </button>
          )))}
        </div>
      )}
      {(hit.why ?? []).length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1 text-2xs">
          <span className="text-muted">Why matched</span>
          {hit.why!.map((w, i) => <span key={i} className={cn("rounded px-1.5 py-0.5", w.kind === "rank" || w.kind === "where" ? "bg-sunken text-ink-2" : "bg-accent-soft text-accent-ink")}>{w.label}</span>)}
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
        {hit.source_id ? <Link href={`/sources/${hit.source_id}`} className="hover:text-ink hover:underline" title="Open the source profile">{hit.source_name}</Link> : <span>{hit.source_name}</span>}
        <Countries codes={hit.countries ?? []} />
        <span title={`First seen ${stamp(hit.first_seen)} · last seen ${stamp(hit.last_seen)}`}>First seen {day(hit.first_seen)} · last seen {ago(hit.last_seen)}</span>
        <span>Confidence {hit.confidence}%</span>
        {hit.ioc_count > 0 && <Link href={`/findings/${hit.id}?tab=iocs`} className="hover:text-ink hover:underline">{hit.ioc_count} indicators</Link>}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Link href={`/findings/${hit.id}`}><Button size="sm" variant="primary">Open</Button></Link>
        {hit.network === "onion" && <CrawlButton url={hit.url} />}
        {hit.source_id && <Link href={`/sources/${hit.source_id}`}><Button size="sm" title="The source's profile: monitor it, see its history and related sources">Source</Button></Link>}
        <Link href={`/search?q=${encodeURIComponent(`similar:${hit.id}`)}`}><Button size="sm" title="Findings with similar wording">Similar</Button></Link>
        <Link href={`/findings/${hit.id}?tab=history`}><Button size="sm" title="When it was seen and how it changed">History</Button></Link>
        <Link href={`/graph?node=finding:${hit.id}`}><Button size="sm" title="What it connects to">Connections</Button></Link>
        <AddToCase objectType="finding" objectId={hit.id} size="sm" label="Add to investigation" />
      </div>
    </article>
  );
}

function SearchPage() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const { meta, canWrite } = useSession();
  const queryString = params.toString();
  const { data, error, isLoading } = useApi<SearchResult>(`/search${queryString ? `?${queryString}` : ""}`, { keepPreviousData: true });
  // Sites that are known but not collected yet and look relevant to the query: the places this search has not reached.
  const { data: uncollected } = useApi<SourceBrief[]>((params.get("q") ?? "").trim().length >= 3 ? `/sources/suggest?q=${encodeURIComponent(params.get("q")!)}` : null);
  const { data: saved, mutate: reloadSaved } = useApi<{ id: number; name: string; query: string; params: Record<string, string> }[]>("/saved-searches");
  const [help, setHelp] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [asking, setAsking] = useState(false);
  const [question, setQuestion] = useState("");
  const ask = useAiJob();
  const { busy, run } = useAction();
  const submitQuestion = (e: FormEvent) => { e.preventDefault(); if (question.trim().length >= 3) ask.start("/ai/ask", { question: question.trim() }); };

  const update = useCallback((mutate: (sp: URLSearchParams) => void) => {
    const sp = new URLSearchParams(params.toString());
    mutate(sp);
    sp.delete("page");
    router.replace(`${pathname}${sp.toString() ? `?${sp}` : ""}`, { scroll: false });
  }, [params, pathname, router]);

  const toggle = useCallback((param: string, value: string) => update((sp) => {
    const current = sp.getAll(param);
    sp.delete(param);
    (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]).forEach((v) => sp.append(param, v));
  }), [update]);
  const setParam = (key: string, value: string) => update((sp) => (value ? sp.set(key, value) : sp.delete(key)));

  const q = params.get("q") ?? "";
  const label = (param: string, b: Bucket) => b.label ?? (param === "country" ? meta.countries[b.value] ?? b.value : param === "type" ? meta.threat_types[b.value] ?? b.value : param === "network" ? networkLabel(b.value) : param === "severity" || param === "status" ? titleCase(b.value)
    : param === "technique" ? `${b.value} ${meta.techniques?.[b.value] ?? ""}`.trim() : param === "verified" ? titleCase(b.value)
    : param === "lang" ? meta.languages?.[b.value] ?? (b.value || "Undetermined") : param === "kind" ? SOURCE_KIND_LABELS[b.value] ?? titleCase(b.value) : param === "site" ? defang(shortHost(b.value)) : b.value);
  const activeFilters = FACETS.flatMap((f) => params.getAll(f.param).map((v) => ({ param: f.param, value: v, text: `${f.label}: ${label(f.param, { value: v, count: 0 })}` })));
  const extraFilters = ([["from", "Since"], ["to", "Until"], ["min_risk", "Risk ≥"], ["creds", "With credentials"], ["dupes", "Including duplicates"], ["strict", "All terms required"]] as const)
    .filter(([key]) => params.get(key)).map(([key, text]) => ({ key, text: ["creds", "dupes", "strict"].includes(key) ? text : `${text} ${params.get(key)}` }));
  const hasFilters = activeFilters.length + extraFilters.length > 0;
  const page = Number(params.get("page") ?? 1);

  const saveSearch = async () => {
    const stored: Record<string, string> = {};
    params.forEach((v, k) => { if (k !== "q" && k !== "page") stored[k] = stored[k] ? `${stored[k]},${v}` : v; });
    if (await run(() => api("/saved-searches", { method: "POST", body: { name: saveName, query: q, params: { qs: queryString } } }), "Search saved")) { setSaving(false); setSaveName(""); reloadSaved(); }
  };

  const facetPanel = data && (
    <div>
      <div className="border-b border-line pb-3">
        <div className="mb-2 text-xs font-semibold text-ink-2">Date reported</div>
        <div className="grid grid-cols-2 gap-2">
          <input type="date" aria-label="From date" className="field h-8 px-2 text-xs" value={params.get("from") ?? ""} onChange={(e) => setParam("from", e.target.value)} />
          <input type="date" aria-label="To date" className="field h-8 px-2 text-xs" value={params.get("to") ?? ""} onChange={(e) => setParam("to", e.target.value)} />
        </div>
        <div className="mt-2 flex flex-wrap gap-1">
          {[["24h", 1], ["7d", 7], ["30d", 30], ["90d", 90]].map(([text, days]) => (
            <button key={text} onClick={() => update((sp) => { sp.set("from", new Date(Date.now() - Number(days) * 864e5).toISOString().slice(0, 10)); sp.delete("to"); })} className="rounded border border-line px-1.5 py-0.5 text-xs text-ink-2 hover:border-accent hover:text-accent-ink">Last {text}</button>
          ))}
        </div>
      </div>
      <div className="space-y-1.5 border-b border-line py-3">
        <label className="flex items-center justify-between gap-2 text-sm text-ink-2">Minimum risk
          <select className="field h-8 w-24 px-2 text-xs" value={params.get("min_risk") ?? ""} onChange={(e) => setParam("min_risk", e.target.value)}>
            <option value="">Any</option><option value="40">40+</option><option value="60">60+</option><option value="80">80+</option>
          </select>
        </label>
        {([["creds", "Credentials exposed"], ["dupes", "Include duplicates"], ["strict", "Require every term"]] as const).map(([key, text]) => (
          <label key={key} className="flex cursor-pointer items-center gap-2 text-sm text-ink-2">
            <input type="checkbox" className="h-3.5 w-3.5 accent-[var(--accent)]" checked={params.get(key) === "true"} onChange={(e) => setParam(key, e.target.checked ? "true" : "")} />{text}
          </label>
        ))}
      </div>
      {FACETS.map((f) => (
        <FacetGroup key={f.key} label={f.label} buckets={f.key === "severity" ? [...(data.facets[f.key] ?? [])].sort((a, b) => SEVERITY_ORDER.indexOf(a.value) - SEVERITY_ORDER.indexOf(b.value)) : data.facets[f.key] ?? []} selected={params.getAll(f.param)} onToggle={(v) => toggle(f.param, v)} format={(b) => label(f.param, b)} defaultOpen={f.open} />
      ))}
    </div>
  );

  return (
    <>
      <div className="mb-4">
        <SearchBox initial={q} onSearch={(next) => setParam("q", next)} />
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
          <button onClick={() => setHelp(!help)} className="inline-flex items-center gap-1 text-ink-2 hover:text-ink" aria-expanded={help}><HelpCircle className="h-3.5 w-3.5" /> Search syntax</button>
          <button onClick={() => { setAsking(!asking); if (!question) setQuestion(q); }} className="inline-flex items-center gap-1 text-ink-2 hover:text-ink" aria-expanded={asking}><Sparkles className="h-3.5 w-3.5" /> Ask a question</button>
          <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-2"><input type="checkbox" className="accent-[var(--accent)]" checked={params.getAll("network").includes("onion") && params.getAll("network").length === 1} onChange={(e) => update((sp) => { sp.delete("network"); if (e.target.checked) sp.append("network", "onion"); })} /> Tor sources only</label>
          {saved && saved.length > 0 && (
            <span className="flex flex-wrap items-center gap-1.5">
              <Bookmark className="h-3.5 w-3.5 text-muted" />
              {saved.slice(0, 6).map((s) => (
                <span key={s.id} className="group inline-flex items-center rounded border border-line">
                  <Link href={`/search?${s.params?.qs ?? `q=${encodeURIComponent(s.query)}`}`} className="px-1.5 py-0.5 text-ink-2 hover:text-accent-ink">{s.name}</Link>
                  <button aria-label={`Delete saved search ${s.name}`} onClick={() => run(() => api(`/saved-searches/${s.id}`, { method: "DELETE" })).then(() => reloadSaved())} className="border-l border-line px-1 text-muted hover:text-critical"><Trash2 className="h-3 w-3" /></button>
                </span>
              ))}
            </span>
          )}
        </div>
        {asking && (
          <Card className="mt-2 p-4">
            <form onSubmit={submitQuestion} className="flex gap-2">
              <input className="field" value={question} onChange={(e) => setQuestion(e.target.value)} aria-label="Question" placeholder="Which ransomware groups hit East African banks this quarter, and how did they get in?" />
              <Button variant="primary" type="submit" busy={ask.busy} disabled={question.trim().length < 3}>Ask</Button>
            </form>
            {ask.job.status === "idle" && <p className="mt-2 text-xs text-muted">The question is turned into a search, the best-matching findings are retrieved, and the answer is written from those findings only, with a citation for each claim. It cannot browse or look anything up outside what has been collected.</p>}
            {ask.busy && <p className="mt-3 flex items-center gap-2 text-sm text-muted" role="status"><span className="h-2 w-2 animate-pulse rounded-full bg-accent" />{ask.step}{ask.job.query ? <> · searching <code className="font-mono text-xs text-ink-2">{ask.job.query}</code></> : null}</p>}
            {ask.job.status === "error" && <p className="mt-3 rounded-md bg-critical-soft px-3 py-2 text-sm text-critical" role="alert">{ask.job.error}</p>}
            {ask.job.status === "disabled" && (
              <div className="mt-3 text-sm">
                <p className="text-ink-2">{ask.job.message}</p>
                <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs"><span className="text-muted">Understood as</span>{(ask.job.interpretation ?? []).map((i, n) => <Badge key={n} tone={i.kind === "broad" ? "neutral" : "accent"} title={i.detail || undefined}>{i.label}</Badge>)}</div>
                <Button size="sm" className="mt-2" onClick={() => { setParam("q", ask.job.query ?? question); setAsking(false); }}>Show the matching findings</Button>
              </div>
            )}
            {ask.job.status === "done" && (
              <div className="mt-3">
                <CitedText text={ask.job.answer ?? ""} sources={ask.job.sources} />
                {ask.job.gaps && <p className="mt-2 text-xs text-muted"><span className="font-semibold text-ink-2">Not covered by the findings:</span> {ask.job.gaps}</p>}
                <AiSources sources={ask.job.sources} cited={ask.job.citations} />
                <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line pt-2">
                  <AiLabel />
                  {ask.job.confidence && <Badge tone={ask.job.confidence === "high" ? "good" : ask.job.confidence === "medium" ? "neutral" : "warning"}>{titleCase(ask.job.confidence)} confidence</Badge>}
                  {ask.job.query && <button className="link text-xs" title={ask.job.explanation} onClick={() => setParam("q", ask.job.query!)}>Searched for <code className="font-mono">{ask.job.query}</code>: show all matches</button>}
                </div>
              </div>
            )}
          </Card>
        )}
        {help && (
          <Card className="mt-2 p-4">
            <p className="mb-3 text-sm text-ink-2">Type naturally, paste any indicator (defanged is fine), or combine operators. Country names and broad words like “cyber attack” are understood rather than matched literally. Quote a phrase for an exact match, prefix with <code className="font-mono">-</code> to exclude, and use <code className="font-mono">OR</code> between alternatives.</p>
            <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
              {meta.operators.map((o) => (
                <button key={o.op} onClick={() => { setParam("q", `${q} ${o.example}`.trim()); setHelp(false); }} className="flex items-baseline gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-sunken">
                  <code className="shrink-0 font-mono text-accent-ink">{o.example}</code><span className="truncate text-muted">{o.help}</span>
                </button>
              ))}
            </div>
          </Card>
        )}
      </div>

      {data && data.interpretation.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-muted">Understood as</span>
          {data.interpretation.map((i, n) => (
            <Badge key={n} tone={i.kind === "warning" ? "warning" : i.kind === "exclude" ? "critical" : i.kind === "broad" ? "neutral" : "accent"} title={i.detail || undefined}>
              {i.kind === "broad" ? `${i.label} (optional)` : i.label}
            </Badge>
          ))}
        </div>
      )}
      {data?.did_you_mean && (
        <p className="mb-3 text-sm">Did you mean <button className="link font-medium" onClick={() => setParam("q", data.did_you_mean!)}>{data.did_you_mean}</button>?</p>
      )}
      {hasFilters && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          {activeFilters.map((f) => (
            <button key={f.param + f.value} onClick={() => toggle(f.param, f.value)} className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-raised px-2 py-0.5 text-xs hover:border-critical">{f.text}<X className="h-3 w-3" /></button>
          ))}
          {extraFilters.map((f) => (
            <button key={f.key} onClick={() => setParam(f.key, "")} className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-raised px-2 py-0.5 text-xs hover:border-critical">{f.text}<X className="h-3 w-3" /></button>
          ))}
          <button className="link text-xs" onClick={() => router.replace(q ? `${pathname}?q=${encodeURIComponent(q)}` : pathname)}>Clear filters</button>
        </div>
      )}

      <ErrorNote error={error} />
      {!data && isLoading && <Spinner label="Searching" />}
      {data && (
        <div className="grid gap-4 lg:grid-cols-[15.5rem_minmax(0,1fr)]">
          <aside className="hidden lg:block"><Card className="sticky top-[4.5rem] max-h-[calc(100vh-5.5rem)] overflow-y-auto px-3.5 py-3 scroll-thin">{facetPanel}</Card></aside>
          <div className="min-w-0">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <p className="mr-auto text-sm text-ink-2" aria-live="polite">
                <span className="font-semibold text-ink">{num(data.total)}</span> finding{data.total === 1 ? "" : "s"}
                {data.summary.with_credentials > 0 && <> · {num(data.summary.with_credentials)} with credentials</>}
                <span className="text-muted"> · {data.took_ms} ms</span>
              </p>
              <Button size="sm" className="lg:hidden" onClick={() => setFiltersOpen(true)}><SlidersHorizontal className="h-3.5 w-3.5" /> Filters</Button>
              <select aria-label="Sort" className="field h-7 w-auto px-2 text-xs" value={data.sort} onChange={(e) => setParam("sort", e.target.value)}>
                {SORTS.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
              <Button size="sm" onClick={() => { setSaveName(q || "All findings"); setSaving(true); }}><Bookmark className="h-3.5 w-3.5" /> Save</Button>
              {canWrite && q && <Link href={`/watchlists?value=${encodeURIComponent(q)}`}><Button size="sm"><Crosshair className="h-3.5 w-3.5" /> Watch</Button></Link>}
              {canWrite && q && <Link href={`/rules?query=${encodeURIComponent(q)}`}><Button size="sm" title="Create a detection rule from this search"><Siren className="h-3.5 w-3.5" /> Alert</Button></Link>}
              {canWrite && q && <AddToCase objectType="query" objectId={q.slice(0, 64)} note={q} size="sm" label="Save hunt to case" />}
              <a href={`/api/search/export?format=csv${queryString ? `&${queryString}` : ""}`}><Button size="sm" disabled={!data.total}><Download className="h-3.5 w-3.5" /> CSV</Button></a>
              <a href={`/api/search/export?format=json${queryString ? `&${queryString}` : ""}`}><Button size="sm" disabled={!data.total}>JSON</Button></a>
            </div>

            {data.total > 0 && data.timeline.buckets.length > 2 && (
              <Card className="mb-3 px-4 pb-2 pt-3">
                <div className="mb-1 flex items-center justify-between text-xs text-muted">
                  <span>Matches over time{intervalLabel(data.timeline.interval)}</span>
                  <span>{day(data.timeline.buckets[0].date)} – {day(data.timeline.buckets[data.timeline.buckets.length - 1].date)}</span>
                </div>
                <MiniColumns values={data.timeline.buckets.map((b) => b.count)} labels={data.timeline.buckets.map((b) => day(b.date))} caption="Matching findings over time" />
              </Card>
            )}

            {(data.sources ?? []).length > 1 && (
              <Card className="mb-3 px-4 py-2.5">
                <div className="mb-1.5 text-xs text-muted">Sources carrying these results</div>
                <div className="flex flex-wrap gap-1.5">
                  {data.sources!.map((src) => (
                    <span key={src.id} className="inline-flex items-center rounded border border-line text-xs">
                      <button onClick={() => toggle("source", src.name)} title="Show only results from this source" className="px-1.5 py-0.5 text-ink-2 hover:text-accent-ink">{src.name} <span className="tabular-nums text-muted">{src.count}</span></button>
                      <Link href={`/sources/${src.id}`} title="Open the source profile" className="border-l border-line px-1.5 py-0.5 text-muted hover:text-ink">profile</Link>
                    </span>
                  ))}
                </div>
              </Card>
            )}
            {(uncollected ?? []).length > 0 && (
              <Card className="mb-3 px-4 py-2.5">
                <div className="mb-1.5 text-xs text-muted">Known sites that may cover this but are not being collected</div>
                <ul className="space-y-1">
                  {uncollected!.map((src) => (
                    <li key={src.id} className="flex flex-wrap items-center gap-2 text-sm">
                      <Link href={`/sources/${src.id}`} className="min-w-0 truncate font-medium hover:underline">{src.title || src.name}</Link>
                      <span className="font-mono text-2xs text-muted">{defang(shortHost(src.host))}</span><StateBadge state={src.state} />
                      {src.network === "onion" && src.status !== "blocked" && <span className="ml-auto"><CrawlButton url={`http://${src.host}/`} label="Crawl it" /></span>}
                    </li>
                  ))}
                </ul>
              </Card>
            )}

            <Card className={cn(isLoading && "opacity-60")}>
              {data.total === 0 ? (
                <Empty
                  title="No findings match"
                  hint={<>
                    {hasFilters ? "Try removing a filter. " : ""}{params.get("strict") ? "Turn off “Require every term”. " : ""}
                    Nothing collected so far matches this search. Add it to a watchlist to be emailed the moment it appears.
                  </>}
                  action={<div className="flex flex-wrap justify-center gap-2">{EXAMPLES.map((ex) => <button key={ex} onClick={() => router.replace(`${pathname}?q=${encodeURIComponent(ex)}`)} className="rounded border border-line px-2 py-1 font-mono text-xs text-ink-2 hover:border-accent">{ex}</button>)}</div>}
                />
              ) : data.hits.map((hit) => <ResultCard key={hit.id} hit={hit} onFilter={toggle} />)}
            </Card>
            <Pagination page={page} size={data.size} total={data.total} onPage={(p) => { const sp = new URLSearchParams(params.toString()); sp.set("page", String(p)); router.push(`${pathname}?${sp}`); }} />
          </div>
        </div>
      )}

      <Modal open={filtersOpen} onClose={() => setFiltersOpen(false)} title="Filters" footer={<Button variant="primary" onClick={() => setFiltersOpen(false)}>Show results</Button>}>{facetPanel}</Modal>
      <Modal open={saving} onClose={() => setSaving(false)} title="Save this search" footer={<><Button onClick={() => setSaving(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!saveName.trim()} onClick={saveSearch}>Save</Button></>}>
        <Field label="Name" hint="Saved searches keep the query and every filter, and appear under the search box."><input className="field" value={saveName} onChange={(e) => setSaveName(e.target.value)} /></Field>
      </Modal>
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><SearchPage /></Suspense>;
}
