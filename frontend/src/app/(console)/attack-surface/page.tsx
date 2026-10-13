"use client";

import { ChevronDown, RefreshCw, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Fragment, useState } from "react";
import { FactorList, RiskMeter } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Pagination, Spinner, useAction } from "@/components/ui";
import { api, qs, useApi, type Factor } from "@/lib/api";
import { ago, cn, defang, num } from "@/lib/format";

interface Asset {
  id: number; host: string; ips: string[]; ports: number[]; risky_ports: { port: number; service: string }[]; cpes: string[]; tags: string[]; vulns: string[];
  kev_vulns: string[]; asn: string; discovered_via: string; risk: number; risk_factors: Factor[]; first_seen: string; last_seen: string; last_scanned: string | null;
  error: string; watchlist: { id: number; name: string; value: string; criticality: number };
}
interface Surface {
  total: number; items: Asset[];
  summary: { hosts: number; resolving: number; at_risk: number; with_kev: number; ports: { port: number; count: number; service: string }[] };
  owned: { id: number; name: string; kind: string; value: string; criticality: number; hosts: number; last_scanned: string | null }[];
}
const VIA: Record<string, string> = { certspotter: "Certificate transparency", "crt.sh": "Certificate transparency", "declared domain": "Declared asset", "declared range": "Declared asset" };

export default function AttackSurfacePage() {
  const { canWrite } = useSession();
  const [watch, setWatch] = useState<number | "">("");
  const [exposed, setExposed] = useState(false);
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<number | null>(null);
  const { data, error, mutate, isLoading } = useApi<Surface>(`/attack-surface${qs({ watchlist_id: watch || undefined, exposed, q, page, size: 50 })}`, { keepPreviousData: true, refreshInterval: 30000 });
  const { busy, run } = useAction();
  const scan = (id: number) => run(() => api("/attack-surface/scan", { method: "POST", body: { watchlist_id: id } }), "Discovery started. Results arrive over the next few minutes.").then(() => setTimeout(() => mutate(), 8000));
  const reset = (fn: () => void) => { fn(); setPage(1); };

  return (
    <>
      <PageHeader
        title="Attack surface"
        subtitle="What an outsider can already see of the assets you own: hosts named in public certificate logs and DNS, with the open ports and known vulnerabilities that internet-wide scan data reports for them. This is passive. The platform asks public datasets about your assets; it never connects to, scans or probes them."
        actions={<Link href="/watchlists"><Button>Manage owned assets</Button></Link>}
      />
      <ErrorNote error={error} />
      {!data ? <Spinner /> : data.owned.length === 0 ? (
        <Card><Empty title="No owned assets declared yet" hint="Add your domain or IP range to a watchlist and tick “This is an asset we own”. Discovery then runs automatically and on a schedule. Only assets you declare are ever looked up." action={<Link href="/watchlists"><Button variant="primary">Declare an asset</Button></Link>} /></Card>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <div className="card px-4 py-3"><div className="text-xs text-muted">Hosts discovered</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{num(data.summary.hosts)}</div><div className="text-xs text-muted">{num(data.summary.resolving)} resolve publicly</div></div>
            <button onClick={() => reset(() => setExposed(!exposed))} className={cn("card px-4 py-3 text-left", exposed && "border-accent")}><div className="text-xs text-muted">At risk (score 40+)</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{num(data.summary.at_risk)}</div><div className="text-xs text-muted">Click to show only hosts with findings</div></button>
            <div className="card px-4 py-3"><div className="text-xs text-muted">With an actively exploited CVE</div><div className={cn("mt-0.5 text-2xl font-semibold tabular-nums", data.summary.with_kev > 0 && "text-critical")}>{num(data.summary.with_kev ?? 0)}</div><div className="text-xs text-muted">Listed in CISA KEV</div></div>
            <div className="card px-4 py-3"><div className="text-xs text-muted">Most common open ports</div><div className="mt-1 flex flex-wrap gap-1">{data.summary.ports.length === 0 ? <span className="text-sm text-muted">None reported</span> : data.summary.ports.slice(0, 8).map((p) => <Badge key={p.port} tone={p.service ? "serious" : "neutral"} title={p.service ? `${p.service}: should rarely face the internet` : undefined}>{p.port}<span className="font-normal opacity-70">×{p.count}</span></Badge>)}</div></div>
          </div>

          <Card className="mb-4">
            <CardHeader title="Owned assets" hint="Discovery runs when an asset is added and then on a schedule" />
            <ul className="divide-y divide-line">
              {data.owned.map((w) => (
                <li key={w.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-sm">
                  <button onClick={() => reset(() => setWatch(watch === w.id ? "" : w.id))} className={cn("font-mono text-xs hover:underline", watch === w.id && "font-semibold text-accent-ink")}>{defang(w.value)}</button>
                  <span className="text-xs text-muted">{w.name !== w.value ? w.name : ""}</span>
                  <Badge title="Business criticality, 1 (low) to 5 (crown jewels). Raises the priority of anything found here.">Criticality {w.criticality}/5</Badge>
                  <span className="text-xs text-ink-2">{num(w.hosts)} host{w.hosts === 1 ? "" : "s"}</span>
                  <span className="ml-auto text-xs text-muted">{w.last_scanned ? `Checked ${ago(w.last_scanned)}` : "Not checked yet"}</span>
                  {canWrite && <Button size="sm" busy={busy} onClick={() => scan(w.id)}><RefreshCw className="h-3.5 w-3.5" /> Check now</Button>}
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
              <h2 className="text-sm font-semibold">Hosts <span className="font-normal text-muted">· {num(data.total)}{watch || exposed || q ? " matching" : ""}</span></h2>
              <form onSubmit={(e) => { e.preventDefault(); reset(() => setQ(text)); }}><input className="field h-8 w-56 text-xs" placeholder="Filter by host, IP or CVE…" aria-label="Filter hosts" value={text} onChange={(e) => setText(e.target.value)} /></form>
            </div>
            {data.items.length === 0 ? <Empty title="No hosts match" hint={data.summary.hosts === 0 ? "Discovery has not returned anything yet. It can take a few minutes after an asset is added." : "Try clearing the filter."} /> : (
              <div className={cn("overflow-x-auto", isLoading && "opacity-60")}>
                <table className="w-full min-w-[820px]">
                  <thead><tr className="border-b border-line"><th className="th w-8" /><th className="th">Host</th><th className="th">Resolves to</th><th className="th">Open ports</th><th className="th">Known vulnerabilities</th><th className="th">Risk</th><th className="th">Checked</th></tr></thead>
                  <tbody className="divide-y divide-line">
                    {data.items.map((a) => (
                      <Fragment key={a.id}>
                        <tr className="cursor-pointer hover:bg-sunken" onClick={() => setOpen(open === a.id ? null : a.id)}>
                          <td className="td"><ChevronDown className={cn("h-3.5 w-3.5 text-muted transition-transform", open === a.id && "rotate-180")} aria-label={open === a.id ? "Collapse" : "Expand"} /></td>
                          <td className="td max-w-[16rem]"><span className="block truncate font-mono text-xs" title={defang(a.host)}>{defang(a.host)}</span><span className="text-2xs text-muted">{VIA[a.discovered_via] ?? a.discovered_via}</span></td>
                          <td className="td font-mono text-xs text-ink-2">{a.ips.length ? <>{a.ips.slice(0, 2).join(", ")}{a.ips.length > 2 && ` +${a.ips.length - 2}`}</> : <span className="font-sans text-muted">Does not resolve</span>}</td>
                          <td className="td"><div className="flex max-w-[14rem] flex-wrap gap-1">{a.ports.length === 0 ? <span className="text-xs text-muted">None reported</span> : a.ports.slice(0, 8).map((p) => { const risky = a.risky_ports.find((r) => r.port === p); return <Badge key={p} tone={risky ? "serious" : "neutral"} title={risky?.service}>{p}</Badge>; })}{a.ports.length > 8 && <span className="text-xs text-muted">+{a.ports.length - 8}</span>}</div></td>
                          <td className="td text-xs">{a.vulns.length === 0 ? <span className="text-muted">None reported</span> : <span className="inline-flex flex-wrap items-center gap-1">{a.kev_vulns.length > 0 && <Badge tone="critical" title="In CISA's Known Exploited Vulnerabilities catalogue"><ShieldAlert className="h-3 w-3" />{a.kev_vulns.length} exploited</Badge>}<span className="text-ink-2">{a.vulns.length} CVE{a.vulns.length === 1 ? "" : "s"}</span></span>}</td>
                          <td className="td"><RiskMeter score={a.risk} /></td>
                          <td className="td whitespace-nowrap text-xs text-muted">{a.error ? <span className="text-warning" title={a.error}>Lookup failed</span> : ago(a.last_scanned)}</td>
                        </tr>
                        {open === a.id && (
                          <tr><td colSpan={7} className="bg-sunken px-4 py-3">
                            <div className="grid gap-4 lg:grid-cols-2">
                              <div className="card"><div className="border-b border-line px-4 py-2 text-xs font-semibold text-ink-2">Why this score</div><FactorList factors={a.risk_factors} total={a.risk} /></div>
                              <dl className="space-y-2 text-sm">
                                {a.vulns.length > 0 && <div><dt className="label">Vulnerabilities reported for this host</dt><dd className="mt-1 flex flex-wrap gap-1">{a.vulns.slice(0, 40).map((c) => <Link key={c} href={`/vulnerabilities/${c}`}><Badge tone={a.kev_vulns.includes(c) ? "critical" : "neutral"}>{c}</Badge></Link>)}{a.vulns.length > 40 && <span className="text-xs text-muted">+{a.vulns.length - 40} more</span>}</dd></div>}
                                {a.risky_ports.length > 0 && <div><dt className="label">Services that should rarely face the internet</dt><dd className="mt-0.5 text-ink-2">{a.risky_ports.map((r) => `${r.service} (${r.port})`).join(", ")}</dd></div>}
                                {a.cpes.length > 0 && <div><dt className="label">Software identified</dt><dd className="mt-0.5 break-all font-mono text-xs text-ink-2">{a.cpes.slice(0, 12).join("  ")}</dd></div>}
                                {a.tags.length > 0 && <div><dt className="label">Tags from scan data</dt><dd className="mt-1 flex flex-wrap gap-1">{a.tags.map((t) => <Badge key={t}>{t}</Badge>)}</dd></div>}
                                <div className="text-xs text-muted">Part of {a.watchlist.name} · first seen {ago(a.first_seen)}{a.asn ? ` · ${a.asn}` : ""}. Vulnerabilities come from banner matching in public scan data and are unverified: confirm before acting.</div>
                              </dl>
                            </div>
                          </td></tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          <Pagination page={page} size={50} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
