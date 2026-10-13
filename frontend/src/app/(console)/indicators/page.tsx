"use client";

import Link from "next/link";
import { useState } from "react";
import { Defanged } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { Card, Empty, ErrorNote, Pagination, Spinner, Tabs } from "@/components/ui";
import { qs, useApi } from "@/lib/api";
import { ago, day, IOC_LABELS } from "@/lib/format";

interface Row { id: number; type: string; value: string; doc_count: number; first_seen: string; last_seen: string }
interface List { total: number; counts: Record<string, number>; items: Row[] }
const TYPES = ["", "domain", "email", "ip", "url", "onion", "hash", "cve", "crypto", "username"];

export default function IndicatorsPage() {
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("recent");
  const [page, setPage] = useState(1);
  const { data, error } = useApi<List>(`/iocs${qs({ type, q, sort, page, size: 50 })}`, { keepPreviousData: true });
  const all = data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : 0;

  return (
    <>
      <PageHeader title="Indicators" subtitle="Every domain, address, hash, CVE and wallet extracted from collected intelligence. Values are shown defanged and are never contacted by the platform." />
      <Card>
        <div className="flex flex-wrap items-center gap-3 px-3 pt-1">
          <div className="min-w-0 flex-1">
            <Tabs value={type} onChange={(v) => { setType(v); setPage(1); }} tabs={TYPES.map((t) => ({ id: t, label: t ? IOC_LABELS[t] : "All", count: t ? data?.counts[t] ?? 0 : all }))} />
          </div>
          <input className="field mb-1 h-8 w-56 font-mono text-xs" placeholder="Contains… (defanged is fine)" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Filter indicators" />
          <select className="field mb-1 h-8 w-36 px-2 text-xs" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort"><option value="recent">Recently seen</option><option value="frequent">Most findings</option></select>
        </div>
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.items.length === 0 ? <Empty title="No indicators match" /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px]">
              <thead><tr className="border-b border-line"><th className="th">Type</th><th className="th">Value</th><th className="th text-right">Findings</th><th className="th">First seen</th><th className="th">Last seen</th></tr></thead>
              <tbody className="divide-y divide-line">
                {data.items.map((i) => (
                  <tr key={i.id}>
                    <td className="td whitespace-nowrap text-xs text-muted">{IOC_LABELS[i.type] ?? i.type}</td>
                    <td className="td max-w-xl"><Defanged value={i.value} /></td>
                    <td className="td text-right"><Link className="link tabular-nums" href={`/indicators/${i.id}`}>{i.doc_count}</Link></td>
                    <td className="td whitespace-nowrap text-xs text-muted">{day(i.first_seen)}</td>
                    <td className="td whitespace-nowrap text-xs text-muted">{ago(i.last_seen)}</td>
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
