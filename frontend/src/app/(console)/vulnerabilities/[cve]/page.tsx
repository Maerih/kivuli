"use client";

import { ArrowLeft, Flame, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AddToCase, FactorList, FindingRow, RiskMeter } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner } from "@/components/ui";
import { useApi, type Factor, type FindingSummary } from "@/lib/api";
import { ago, day, defang, ENTITY_LABELS, pct } from "@/lib/format";

interface Detail {
  cve: string; title: string; vendor: string; product: string; description: string; cvss: number | null; cvss_vector: string; epss: number | null;
  epss_percentile: number | null; kev: boolean; kev_added: string | null; kev_due: string | null; ransomware_use: boolean; mention_count: number;
  exposed_assets: number; priority: number; priority_factors: Factor[]; enriched_at: string | null; ioc_id: number | null; findings: FindingSummary[];
  related: { id: number; type: string; name: string; shared: number }[];
  assets: { id: number; host: string; ips: string[]; risk: number; watchlist: { name: string; criticality: number } }[];
}

export default function VulnerabilityPage() {
  const { cve } = useParams<{ cve: string }>();
  const { data: v, error } = useApi<Detail>(`/vulnerabilities/${cve}`);
  if (error) return <><Link href="/vulnerabilities" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Vulnerabilities</Link><ErrorNote error={error} /></>;
  if (!v) return <Spinner />;
  const stat = (label: string, value: React.ReactNode, hint?: string) => <div><dt className="label">{label}</dt><dd className="mt-0.5 text-sm">{value}{hint && <span className="block text-xs text-muted">{hint}</span>}</dd></div>;

  return (
    <>
      <Link href="/vulnerabilities" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Vulnerabilities</Link>
      <PageHeader
        title={<span className="font-mono">{v.cve}</span>}
        subtitle={<span className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-sm text-ink-2">{v.title || [v.vendor, v.product].filter(Boolean).join(" ")}</span>
          {v.exposed_assets > 0 && <Badge tone="critical"><ShieldAlert className="h-3 w-3" />On {v.exposed_assets} of your hosts</Badge>}
          {v.kev && <Badge tone="serious"><Flame className="h-3 w-3" />Actively exploited</Badge>}
          {v.ransomware_use && <Badge tone="serious">Used by ransomware</Badge>}
        </span>}
        actions={<>
          <Link href={`/search?q=${encodeURIComponent(v.cve)}`}><Button>Search findings</Button></Link>
          {v.ioc_id && <AddToCase objectType="ioc" objectId={String(v.ioc_id)} />}
        </>}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Summary" />
            <p className="px-4 py-3 text-sm leading-relaxed text-ink-2">{v.description || "No description has been retrieved for this CVE yet."}</p>
            <dl className="grid gap-4 border-t border-line px-4 py-3 sm:grid-cols-2 lg:grid-cols-4">
              {stat("Exploit likelihood (EPSS)", pct(v.epss), v.epss_percentile !== null ? `Higher than ${pct(Math.min(v.epss_percentile, 0.999))} of CVEs` : "Not scored yet")}
              {stat("Severity (CVSS)", v.cvss ?? "n/a", v.cvss_vector || undefined)}
              {stat("CISA KEV", v.kev ? `Listed ${day(v.kev_added)}` : "Not listed", v.kev && v.kev_due ? `US federal patch deadline ${day(v.kev_due)}` : undefined)}
              {stat("Mentions collected", v.mention_count, v.enriched_at ? `Scores refreshed ${ago(v.enriched_at)}` : undefined)}
            </dl>
          </Card>

          {v.assets.length > 0 && (
            <Card>
              <CardHeader title={`Your hosts reported with this vulnerability (${v.assets.length})`} hint="From banner matching in public scan data: unverified, so confirm the version before acting" />
              <ul className="divide-y divide-line">
                {v.assets.map((a) => (
                  <li key={a.id} className="flex items-center gap-3 px-4 py-2 text-sm">
                    <span className="min-w-0 flex-1 truncate font-mono text-xs">{defang(a.host)}</span>
                    <span className="hidden font-mono text-xs text-muted sm:inline">{a.ips.slice(0, 2).join(", ")}</span>
                    <span className="text-xs text-muted">{a.watchlist.name} · criticality {a.watchlist.criticality}/5</span>
                    <RiskMeter score={a.risk} />
                  </li>
                ))}
              </ul>
              <p className="border-t border-line px-4 py-2 text-xs"><Link className="link" href={`/attack-surface`}>Open the attack surface</Link></p>
            </Card>
          )}

          <Card>
            <CardHeader title={`Findings that mention it (${v.findings.length})`} />
            {v.findings.length === 0 ? <Empty title="Not mentioned in collected intelligence yet" hint="Watch this CVE to be alerted when it is." action={<Link href={`/watchlists?value=${v.cve}`}><Button>Watch {v.cve}</Button></Link>} /> : v.findings.map((f) => <FindingRow key={f.id} f={f} />)}
          </Card>
        </div>

        <aside className="min-w-0 space-y-4">
          <Card><CardHeader title="Priority" hint="Why this ranks where it does" action={<RiskMeter score={v.priority} />} /><FactorList factors={v.priority_factors} total={v.priority} totalLabel="Priority" /></Card>
          {v.related.length > 0 && (
            <Card>
              <CardHeader title="Seen alongside" hint="Actors, malware and techniques in the same findings" />
              <ul className="divide-y divide-line">
                {v.related.map((e) => (
                  <li key={e.id} className="flex items-center justify-between gap-2 px-4 py-2 text-sm">
                    <Link href={`/entities/${e.id}`} className="min-w-0 truncate hover:underline">{e.name}</Link>
                    <span className="shrink-0 text-xs text-muted">{ENTITY_LABELS[e.type] ?? e.type} · {e.shared}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}
