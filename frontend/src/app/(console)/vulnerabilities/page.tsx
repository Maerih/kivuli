"use client";

import { Flame, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { RiskMeter } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { Badge, Card, Empty, ErrorNote, Pagination, Spinner } from "@/components/ui";
import { qs, useApi, type Factor } from "@/lib/api";
import { cn, day, num, pct } from "@/lib/format";

interface Vuln {
  cve: string; title: string; vendor: string; product: string; description: string; cvss: number | null; cvss_vector: string; epss: number | null;
  epss_percentile: number | null; kev: boolean; kev_added: string | null; kev_due: string | null; ransomware_use: boolean; mention_count: number;
  last_mentioned: string | null; exposed_assets: number; priority: number; priority_factors: Factor[]; enriched_at: string | null;
}
interface VulnList { total: number; items: Vuln[]; summary: { tracked: number; kev: number; exposed: number; mentioned: number; high_epss: number } }
const SORTS = [["priority", "Priority"], ["recent", "Recently exploited"], ["epss", "Exploit likelihood"], ["cvss", "Severity (CVSS)"], ["mentions", "Most mentioned"]];

export default function VulnerabilitiesPage() {
  const [flag, setFlag] = useState<"" | "kev" | "exposed" | "mentioned">("");
  const [sort, setSort] = useState("priority");
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const { data, error, isLoading } = useApi<VulnList>(`/vulnerabilities${qs({ q, sort, page, size: 50, [flag || "_"]: flag ? true : undefined })}`, { keepPreviousData: true });
  const reset = (fn: () => void) => { fn(); setPage(1); };
  const tile = (id: typeof flag, label: string, value: number, hint: string, alarm = false) => (
    <button onClick={() => reset(() => setFlag(flag === id ? "" : id))} className={cn("card px-4 py-3 text-left", flag === id && "border-accent")}>
      <div className="text-xs text-muted">{label}</div><div className={cn("mt-0.5 text-2xl font-semibold tabular-nums", alarm && value > 0 && "text-critical")}>{num(value)}</div><div className="text-xs text-muted">{hint}</div>
    </button>
  );

  return (
    <>
      <PageHeader title="Vulnerabilities" subtitle="Ranked by what attackers are doing and what you actually run, not by CVSS alone: confirmed exploitation (CISA KEV), likelihood of exploitation (EPSS), mentions in collected intelligence, and whether the flaw is present on your attack surface." />
      {data && (
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          {tile("exposed", "On your attack surface", data.summary.exposed, "Reported for a host you own", true)}
          {tile("kev", "Actively exploited", data.summary.kev, "In the CISA KEV catalogue")}
          {tile("mentioned", "Seen in intelligence", data.summary.mentioned, "Named in a collected finding")}
          <div className="card px-4 py-3"><div className="text-xs text-muted">Likely to be exploited</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{num(data.summary.high_epss)}</div><div className="text-xs text-muted">EPSS 50% or higher · {num(data.summary.tracked)} tracked</div></div>
        </div>
      )}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
          <form onSubmit={(e) => { e.preventDefault(); reset(() => setQ(text)); }}><input className="field h-8 w-64 text-xs" placeholder="CVE, vendor or product…" aria-label="Filter vulnerabilities" value={text} onChange={(e) => setText(e.target.value)} /></form>
          <label className="flex items-center gap-2 text-xs text-ink-2">Sort by
            <select className="field h-8 w-auto px-2 text-xs" value={sort} onChange={(e) => reset(() => setSort(e.target.value))}>{SORTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
          </label>
        </div>
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.items.length === 0 ? (
          <Empty title="No vulnerabilities match" hint={data.summary.tracked === 0 ? "The catalogue fills from the CISA KEV feed and from CVEs named in collected findings. It is empty until the first sync completes." : "Try clearing the filter."} />
        ) : (
          <div className={cn("overflow-x-auto", isLoading && "opacity-60")}>
            <table className="w-full min-w-[860px]">
              <thead><tr className="border-b border-line"><th className="th">Vulnerability</th><th className="th">Why it matters</th><th className="th text-right" title="Exploit Prediction Scoring System: probability of exploitation in the next 30 days">EPSS</th><th className="th text-right">CVSS</th><th className="th text-right">Mentions</th><th className="th">Priority</th></tr></thead>
              <tbody className="divide-y divide-line">
                {data.items.map((v) => (
                  <tr key={v.cve}>
                    <td className="td max-w-[22rem]">
                      <Link href={`/vulnerabilities/${v.cve}`} className="font-mono text-xs font-semibold hover:text-accent-ink hover:underline">{v.cve}</Link>
                      <div className="truncate text-sm" title={v.title}>{v.title || [v.vendor, v.product].filter(Boolean).join(" ") || "No description yet"}</div>
                      {(v.vendor || v.product) && v.title && <div className="truncate text-xs text-muted">{[v.vendor, v.product].filter(Boolean).join(" · ")}</div>}
                    </td>
                    <td className="td"><div className="flex max-w-[18rem] flex-wrap gap-1">
                      {v.exposed_assets > 0 && <Badge tone="critical" title="Public scan data reports this CVE for a host you own"><ShieldAlert className="h-3 w-3" />On {v.exposed_assets} of your hosts</Badge>}
                      {v.kev && <Badge tone="serious" title={v.kev_added ? `Added to CISA KEV on ${day(v.kev_added)}` : undefined}><Flame className="h-3 w-3" />Exploited{v.kev_added ? ` · ${day(v.kev_added)}` : ""}</Badge>}
                      {v.ransomware_use && <Badge tone="serious">Used by ransomware</Badge>}
                      {!v.exposed_assets && !v.kev && !v.ransomware_use && <span className="text-xs text-muted">{v.priority_factors[0]?.factor ?? "No exploitation reported"}</span>}
                    </div></td>
                    <td className="td whitespace-nowrap text-right text-xs tabular-nums" title={v.epss_percentile !== null ? `Higher than ${pct(Math.min(v.epss_percentile, 0.999))} of all CVEs` : undefined}>{pct(v.epss)}</td>
                    <td className="td text-right text-xs tabular-nums">{v.cvss ?? <span className="text-muted">n/a</span>}</td>
                    <td className="td text-right text-xs tabular-nums">{v.mention_count || <span className="text-muted">0</span>}</td>
                    <td className="td"><RiskMeter score={v.priority} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {data && <Pagination page={page} size={50} total={data.total} onPage={setPage} />}
    </>
  );
}
