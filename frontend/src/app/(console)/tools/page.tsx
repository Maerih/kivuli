"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { Defanged, FindingRow } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, Spinner, Tabs, useAction } from "@/components/ui";
import { api, type FindingSummary } from "@/lib/api";
import { ago, day, IOC_LABELS } from "@/lib/format";

type Tool = "verdict" | "headers" | "decode";
type Tone = "neutral" | "accent" | "critical" | "serious" | "warning" | "good";

interface Known { id: number; findings: number; feeds: string[]; benign: boolean; last_seen: string | null }
interface FoundIoc { type: string; value: string; defanged: string; known: Known | null }

const VERDICT: Record<string, { tone: Tone; label: string }> = {
  malicious: { tone: "critical", label: "Malicious" }, suspicious: { tone: "warning", label: "Suspicious" },
  seen: { tone: "accent", label: "Seen in intelligence" }, clean: { tone: "good", label: "No sign of harm" }, benign: { tone: "good", label: "Benign" }, unknown: { tone: "neutral", label: "Unknown" },
};
const LEVEL: Record<string, Tone> = { high: "critical", medium: "warning", low: "neutral" };

function Indicators({ items }: { items: FoundIoc[] }) {
  if (!items.length) return <p className="px-4 py-3 text-sm text-muted">No indicators found.</p>;
  return (
    <div className="divide-y divide-line">
      {items.map((i) => (
        <div key={`${i.type}:${i.value}`} className="flex flex-wrap items-center gap-2 px-4 py-2">
          <Badge>{IOC_LABELS[i.type] ?? i.type}</Badge>
          <Defanged value={i.value} className="min-w-0 flex-1" pivot />
          {i.known ? (
            <Link href={`/indicators/${i.known.id}`} className="text-xs text-accent-ink hover:underline">
              {i.known.feeds.length ? <Badge tone="critical">On {i.known.feeds.length} feed{i.known.feeds.length > 1 ? "s" : ""}</Badge> : null}{" "}
              In {i.known.findings} finding{i.known.findings === 1 ? "" : "s"}
            </Link>
          ) : <span className="text-xs text-muted">Not in collected intelligence</span>}
        </div>
      ))}
    </div>
  );
}

// ── Quick verdict ──────────────────────────────────────────────────────────
interface ProviderResult { provider: string; label: string; fetched_at: string; ok: boolean; verdict: string; score: number | null; summary: Record<string, unknown>; error: string }
interface Verdict {
  value: string; type: string; defanged: string; verdict: string; reasons: string[]; enrichable: boolean; providers_for_type: string[]; key_rejected: { provider: string; label: string; message: string }[];
  indicator: { id: number; findings: number; first_seen: string | null; last_seen: string | null; feeds: string[]; tags: string[]; benign: boolean } | null;
  findings: FindingSummary[]; watchlists: { id: number; name: string }[]; results: ProviderResult[];
  wallet: { category: string; category_label: string; label: string; balance: number | null; token: string; total_in: number | null; total_out: number | null; tx_count: number | null;
            counterparties: number | null; first_tx: string | null; last_tx: string | null; looked_up: boolean; error: string; truncated: boolean } | null;
  chain_supported: boolean;
}

function summaryText(s: Record<string, unknown>) {
  return Object.entries(s).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length) && typeof v !== "object")
    .slice(0, 6).map(([k, v]) => `${k.replace(/_/g, " ")}: ${String(v)}`).join(" · ");
}

function VerdictTool() {
  const params = useSearchParams();
  const router = useRouter();
  const { canWrite } = useSession();
  const { busy, run } = useAction();
  const [value, setValue] = useState(params.get("value") ?? "");
  const [data, setData] = useState<Verdict | null>(null);
  const [error, setError] = useState("");
  const [polling, setPolling] = useState(0);

  const load = useCallback(async (v: string) => {
    try { setData(await api<Verdict>(`/tools/verdict?value=${encodeURIComponent(v)}`)); setError(""); }
    catch (e) { setData(null); setError(e instanceof Error ? e.message : "Lookup failed"); }
  }, []);

  const check = async (v = value) => {
    v = v.trim();
    if (!v) return;
    router.replace(`/tools?tool=verdict&value=${encodeURIComponent(v)}`);
    if (canWrite) {
      const ok = await run(async () => {
        const r = await api<{ queued: boolean }>("/tools/verdict", { method: "POST", body: { value: v } });
        if (r.queued) setPolling(8);
      });
      if (!ok) return;
    }
    await load(v);
  };

  // Provider answers arrive over the next few seconds; refresh a few times.
  useEffect(() => {
    if (!polling || !data) return;
    const t = setTimeout(() => { load(data.value); setPolling((p) => p - 1); }, 2500);
    return () => clearTimeout(t);
  }, [polling, data, load]);

  useEffect(() => { const v = params.get("value"); if (v) load(v); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const v = data ? VERDICT[data.verdict] ?? VERDICT.unknown : null;
  return (
    <div className="space-y-4">
      <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); check(); }}>
        <input className="field min-w-0 flex-1 font-mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder="IP, domain, URL, hash, email, wallet, CVE or handle (defanged is fine)" aria-label="Indicator" />
        <Button variant="primary" busy={busy} type="submit">Check</Button>
      </form>
      {error && <p className="text-sm text-critical">{error}</p>}
      {!data && !error && <Empty title="One indicator, everything known about it" hint="What your collected intelligence says, whether a watchlist covers it, and what the enrichment providers report. The indicator itself is never contacted." />}
      {data && v && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="min-w-0 space-y-4">
            <Card>
              <div className="flex flex-wrap items-center gap-3 px-4 py-4">
                <Badge tone={v.tone}>{v.label}</Badge>
                <Badge>{IOC_LABELS[data.type] ?? data.type}</Badge>
                <Defanged value={data.value} className="min-w-0 flex-1" pivot />
                {polling > 0 && <span className="flex items-center gap-1 text-xs text-muted"><Spinner label="Waiting for providers" /> Waiting for providers</span>}
              </div>
              <ul className="list-disc space-y-1 border-t border-line px-8 py-3 text-sm text-ink-2">{data.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
            </Card>
            {data.type !== "crypto" && <Card>
              <CardHeader title="Providers" hint={data.enrichable ? (data.providers_for_type.length ? `Switched on for this type: ${data.providers_for_type.join(", ")}` : "No provider is switched on for this type") : "No provider covers this type; collected intelligence only"} />
{(data.key_rejected ?? []).length > 0 && <p className="border-t border-line px-4 py-2 text-xs text-warning">{(data.key_rejected ?? []).map((k) => k.label).join(", ")} skipped: {(data.key_rejected ?? []).length === 1 ? "its key was" : "their keys were"} rejected. <Link href="/integrations" className="underline">Replace under Integrations</Link>; the free providers still answer.</p>}
              {data.results.length === 0 ? <p className="px-4 py-3 text-sm text-muted">{data.enrichable ? (canWrite ? "No answers yet." : "No answers yet. An analyst can run the check.") : "Not applicable."}</p> : (
                <div className="divide-y divide-line">
                  {data.results.map((r) => (
                    <div key={r.provider} className="px-4 py-2 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{r.label}</span>
                        {r.ok ? <Badge tone={(VERDICT[r.verdict] ?? VERDICT.unknown).tone}>{(VERDICT[r.verdict] ?? VERDICT.unknown).label}</Badge> : <Badge tone="neutral">No answer</Badge>}
                        {r.score !== null && <span className="text-xs tabular-nums text-muted">score {r.score}</span>}
                        <span className="ml-auto text-xs text-muted">{ago(r.fetched_at)}</span>
                      </div>
                      <p className="mt-0.5 break-words text-xs text-muted">{r.ok ? summaryText(r.summary) : r.error}</p>
                    </div>
                  ))}
                </div>
              )}
            </Card>}
            <Card>
              <CardHeader title="Where it appears" hint="Most recent findings that mention it" />
              {data.findings.length ? <div className="divide-y divide-line">{data.findings.map((f) => <FindingRow key={f.id} f={f} />)}</div> : <p className="px-4 py-3 text-sm text-muted">Not seen in collected intelligence.</p>}
            </Card>
          </div>
          <aside className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="In your intelligence" />
              <dl className="space-y-2 px-4 py-3 text-sm">
                {data.indicator ? <>
                  <div><dt className="label">Findings</dt><dd><Link className="text-accent-ink hover:underline" href={`/indicators/${data.indicator.id}`}>{data.indicator.findings}, open the indicator</Link></dd></div>
                  <div><dt className="label">Seen</dt><dd>{data.indicator.first_seen ? ago(data.indicator.first_seen) : "—"} to {data.indicator.last_seen ? ago(data.indicator.last_seen) : "—"}</dd></div>
                  {data.indicator.feeds.length > 0 && <div><dt className="label">Threat feeds</dt><dd>{data.indicator.feeds.join(", ")}</dd></div>}
                  {data.indicator.tags.length > 0 && <div><dt className="label">Tags</dt><dd>{data.indicator.tags.join(", ")}</dd></div>}
                </> : <p className="text-muted">Never collected.</p>}
                <div><dt className="label">Watchlists</dt><dd>{data.watchlists.length ? data.watchlists.map((w) => w.name).join(", ") : "None cover it"}</dd></div>
              </dl>
            </Card>
            {data.type === "crypto" && (
              <Card>
                <CardHeader title="On the blockchain" hint={data.chain_supported ? "Public explorer data; nothing is signed or sent" : "This chain cannot be read on-chain"} action={<Link className="text-xs text-accent-ink hover:underline" href={`/crypto?address=${encodeURIComponent(data.value)}`}>Trace the flow</Link>} />
                <dl className="space-y-2 px-4 py-3 text-sm">
                  {!data.wallet?.looked_up ? <p className="text-muted">{data.chain_supported ? (polling > 0 ? "Reading the blockchain…" : canWrite ? "Press Check to read it on-chain." : "Not read yet.") : "Only where it appears in collected intelligence."}</p> : data.wallet.error ? <p className="text-muted">{data.wallet.error}</p> : <>
                    <div><dt className="label">Type</dt><dd>{data.wallet.category_label}{data.wallet.label ? `: ${data.wallet.label}` : ""}</dd></div>
                    <div><dt className="label">Balance</dt><dd className="tabular-nums">{data.wallet.balance ?? "—"} {data.wallet.token}</dd></div>
                    <div><dt className="label">Received / sent</dt><dd className="tabular-nums">{data.wallet.total_in ?? "—"} / {data.wallet.total_out ?? "—"}</dd></div>
                    <div><dt className="label">Transactions</dt><dd className="tabular-nums">{data.wallet.tx_count ?? "—"} with {data.wallet.counterparties ?? 0} counterparties</dd></div>
                    <div><dt className="label">{data.wallet.truncated ? "Active (latest transactions read)" : "Active"}</dt><dd>{data.wallet.first_tx ? day(data.wallet.first_tx) : "—"} to {data.wallet.last_tx ? day(data.wallet.last_tx) : "—"}</dd></div>
                  </>}
                </dl>
              </Card>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

// ── Email headers ──────────────────────────────────────────────────────────
interface HeaderResult {
  ok: boolean; error?: string;
  summary: { from: string; from_name: string; return_path: string; reply_to: string[]; sender: string; to: string[]; subject: string; date: string; message_id: string; mailer: string; hops: number };
  origin: { ip: string; host: string; detail: string } | null;
  auth: Record<string, { result: string; domain: string }>;
  dkim_domains: string[];
  hops: { from: string; from_detail: string; by: string; with: string; ip: string; time: string | null; delay_seconds: number | null; raw: string }[];
  warnings: { level: string; title: string; detail: string }[];
  indicators: FoundIoc[];
}

function HeadersTool() {
  const { busy, run } = useAction();
  const [text, setText] = useState("");
  const [data, setData] = useState<HeaderResult | null>(null);
  const go = () => run(async () => setData(await api<HeaderResult>("/tools/headers", { method: "POST", body: { text } })));
  const fact = (label: string, value: React.ReactNode) => value ? <div><dt className="label">{label}</dt><dd className="mt-0.5 break-words text-sm">{value}</dd></div> : null;
  return (
    <div className="space-y-4">
      <textarea className="field h-48 w-full font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the full headers (Gmail: Show original · Outlook: View message source). A whole message is fine; the body is ignored." aria-label="Email headers" />
      <div className="flex items-center gap-3"><Button variant="primary" busy={busy} disabled={!text.trim()} onClick={go}>Analyse</Button><span className="text-xs text-muted">Offline: nothing in the message is looked up or contacted, and the text is not stored.</span></div>
      {data && !data.ok && <p className="text-sm text-critical">{data.error}</p>}
      {data?.ok && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="Warnings" hint={data.warnings.length ? `${data.warnings.length} found` : "Nothing out of place"} />
              {data.warnings.length === 0 ? <p className="px-4 py-3 text-sm text-muted">Sender, authentication and routing are consistent.</p> : (
                <div className="divide-y divide-line">{data.warnings.map((w) => (
                  <div key={w.title} className="px-4 py-2"><div className="flex items-center gap-2"><Badge tone={LEVEL[w.level] ?? "neutral"}>{w.level}</Badge><span className="text-sm font-medium">{w.title}</span></div><p className="mt-0.5 text-xs text-muted">{w.detail}</p></div>
                ))}</div>
              )}
            </Card>
            <Card>
              <CardHeader title="Delivery path" hint="Oldest hop first" />
              <ol className="divide-y divide-line">{data.hops.map((h, i) => (
                <li key={i} className="px-4 py-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2"><span className="tabular-nums text-muted">{i + 1}</span><span className="font-mono text-xs">{h.from || "?"}</span><span className="text-muted">→</span><span className="font-mono text-xs">{h.by || "?"}</span>
                    {h.ip && <Defanged value={h.ip} pivot />}{h.with && <Badge>{h.with}</Badge>}
                    {h.delay_seconds !== null && <span className={h.delay_seconds < 0 ? "ml-auto text-xs text-warning" : "ml-auto text-xs tabular-nums text-muted"}>{h.delay_seconds < 0 ? `${h.delay_seconds}s (clock out of order)` : `+${h.delay_seconds}s`}</span>}</div>
                  <p className="mt-0.5 truncate font-mono text-2xs text-muted" title={h.raw}>{h.raw}</p>
                </li>
              ))}</ol>
            </Card>
            <Card><CardHeader title="Indicators in the headers" /><Indicators items={data.indicators} /></Card>
          </div>
          <aside className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="Origin" />
              <dl className="space-y-2 px-4 py-3">{data.origin ? <>{fact("First public IP", <span className="flex items-center gap-2"><Defanged value={data.origin.ip} /><Link className="text-xs text-accent-ink hover:underline" href={`/tools?tool=verdict&value=${encodeURIComponent(data.origin.ip)}`}>Check</Link></span>)}{fact("Announced as", data.origin.host)}</> : <p className="text-sm text-muted">No public IP in the path.</p>}</dl>
            </Card>
            <Card>
              <CardHeader title="Authentication" hint="As the receiving server recorded it" />
              <dl className="space-y-2 px-4 py-3">{["spf", "dkim", "dmarc"].map((k) => fact(k.toUpperCase(), data.auth[k] ? <span className="flex items-center gap-2"><Badge tone={data.auth[k].result === "pass" ? "good" : "critical"}>{data.auth[k].result}</Badge><span className="text-xs text-muted">{data.auth[k].domain}</span></span> : <span className="text-muted">not recorded</span>))}{fact("DKIM signed by", data.dkim_domains.join(", "))}</dl>
            </Card>
            <Card>
              <CardHeader title="Message" />
              <dl className="space-y-2 px-4 py-3">{fact("From", `${data.summary.from_name ? `${data.summary.from_name} ` : ""}<${data.summary.from}>`)}{fact("Return-Path", data.summary.return_path)}{fact("Reply-To", data.summary.reply_to.join(", "))}{fact("Sender", data.summary.sender)}{fact("Subject", data.summary.subject)}{fact("Date", data.summary.date)}{fact("Message-ID", data.summary.message_id)}{fact("Mailer", data.summary.mailer)}</dl>
            </Card>
          </aside>
        </div>
      )}
    </div>
  );
}

// ── Payload decoder ────────────────────────────────────────────────────────
interface DecodeResult { ok: boolean; error?: string; decoded: boolean; layers: { step: string; text: string; length: number }[]; final: string; behaviours: { key: string; label: string; evidence: string[] }[]; indicators: FoundIoc[] }

function DecodeTool() {
  const { busy, run } = useAction();
  const [text, setText] = useState("");
  const [data, setData] = useState<DecodeResult | null>(null);
  const go = () => run(async () => setData(await api<DecodeResult>("/tools/decode", { method: "POST", body: { text } })));
  return (
    <div className="space-y-4">
      <textarea className="field h-48 w-full font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste a script, command line or encoded blob: powershell -enc …, base64, hex, %-encoding, fromCharCode(…), gzip-in-base64…" aria-label="Payload" spellCheck={false} />
      <div className="flex items-center gap-3"><Button variant="primary" busy={busy} disabled={!text.trim()} onClick={go}>Decode</Button><span className="text-xs text-muted">Nothing is run: each layer is a text transformation. The text is not stored.</span></div>
      {data && !data.ok && <p className="text-sm text-critical">{data.error}</p>}
      {data?.ok && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="Decoded" hint={data.decoded ? `${data.layers.length - 1} layer${data.layers.length === 2 ? "" : "s"} removed` : "No known encoding found"} />
              <pre className="scroll-thin max-h-[28rem] overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs">{data.final}</pre>
            </Card>
            {data.layers.length > 2 && (
              <Card>
                <CardHeader title="Layers" hint="Each step, in order" />
                <ol className="divide-y divide-line">{data.layers.slice(1).map((l, i) => (
                  <li key={i} className="px-4 py-2"><div className="flex items-center gap-2 text-sm"><span className="tabular-nums text-muted">{i + 1}</span><span className="font-medium">{l.step}</span><span className="ml-auto text-xs tabular-nums text-muted">{l.length.toLocaleString()} chars</span></div>
                    <p className="mt-0.5 truncate font-mono text-2xs text-muted">{l.text.slice(0, 300)}</p></li>
                ))}</ol>
              </Card>
            )}
            <Card><CardHeader title="Indicators" hint="From every layer" /><Indicators items={data.indicators} /></Card>
          </div>
          <aside className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="What it does" hint="Behaviours named in the decoded text" />
              {data.behaviours.length === 0 ? <p className="px-4 py-3 text-sm text-muted">No known behaviour patterns.</p> : (
                <div className="divide-y divide-line">{data.behaviours.map((b) => (
                  <div key={b.key} className="px-4 py-2"><div className="text-sm font-medium">{b.label}</div><p className="mt-0.5 break-words font-mono text-2xs text-muted">{b.evidence.join(" · ")}</p></div>
                ))}</div>
              )}
            </Card>
          </aside>
        </div>
      )}
    </div>
  );
}

function ToolsPage() {
  const params = useSearchParams();
  const router = useRouter();
  const tool = (["verdict", "headers", "decode"].includes(params.get("tool") ?? "") ? params.get("tool") : "verdict") as Tool;
  return (
    <>
      <PageHeader title="Tools" subtitle="Check an indicator, read an email's headers, or decode an obfuscated payload" />
      <Tabs<Tool> tabs={[{ id: "verdict", label: "Quick verdict" }, { id: "headers", label: "Email headers" }, { id: "decode", label: "Payload decoder" }]} value={tool} onChange={(t) => router.replace(`/tools?tool=${t}`)} />
      <div className="mt-4">{tool === "verdict" ? <VerdictTool /> : tool === "headers" ? <HeadersTool /> : <DecodeTool />}</div>
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><ToolsPage /></Suspense>;
}
