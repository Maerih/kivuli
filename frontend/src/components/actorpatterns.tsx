"use client";

import Link from "next/link";
import { BarList, MiniColumns } from "@/components/charts";
import { Card, CardHeader, Spinner } from "@/components/ui";
import { useApi } from "@/lib/api";
import { ago, day, num } from "@/lib/format";

interface Country { code: string; name: string }
interface Site { id: number; name: string; category: string; network: string; findings: number; last_seen: string | null }
interface Patterns {
  claims: number; dated: number; claim_days: number; first: string | null; last: string | null; last_30_days: number; previous_30_days: number;
  median_gap_days: number | null; longest_quiet_days: number | null; uncollected_days: number | null; weekdays: { day: string; count: number }[];
  monthly: { month: string; claims: number; top_sectors: string[]; top_countries: Country[]; new_sectors: string[]; new_countries: Country[] }[];
  sites: Site[]; reporters: Site[]; collecting_since: string | null; comparable: boolean; note: string;
}

const monthName = (key: string) => new Date(`${key}-01T00:00:00Z`).toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" });
const gap = (d: number | null) => (d === null ? "—" : d < 1 ? "Same day" : `${num(Math.round(d * 10) / 10)} day${d === 1 ? "" : "s"}`);

function Tile({ label, value, sub }: { label: string; value: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-md bg-sunken px-3 py-2">
      <div className="label">{label}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums text-ink">{value}</div>
      {sub && <div className="truncate text-2xs text-muted">{sub}</div>}
    </div>
  );
}

/** How a threat actor operates, from its own claims: tempo, weekdays, where it posts, how its targeting shifts. */
export function ActorPatterns({ entityId, name }: { entityId: number; name: string }) {
  const { data } = useApi<Patterns>(`/entities/${entityId}/patterns`);
  if (!data) return <Card><CardHeader title="Activity patterns" /><div className="p-4"><Spinner /></div></Card>;
  if (data.claims === 0) return null;
  const change = data.comparable ? data.last_30_days - data.previous_30_days : null;
  return (
    <Card>
      <CardHeader title="Activity patterns" hint={`From ${name}'s own claims: tracker posts naming it as the actor, and pages of its leak site. Mentions in news and research are listed separately.`} />
      <div className="grid grid-cols-2 gap-2 px-4 pt-3 sm:grid-cols-4">
        <Tile label="Claims" value={num(data.claims)} sub={data.first ? `Since ${day(data.first)}` : undefined} />
        <Tile label="Last 30 days" value={num(data.last_30_days)}
              sub={change === null ? `Collecting since ${data.collecting_since ? day(data.collecting_since) : "recently"}; too early to compare` : `${change >= 0 ? "+" : ""}${num(change)} on the 30 days before`} />
        <Tile label="Typical gap" value={gap(data.median_gap_days)} sub="Median between days with claims, while collected" />
        <Tile label="Longest quiet" value={data.longest_quiet_days === null ? "—" : `${num(data.longest_quiet_days)} days`} sub={data.uncollected_days ? `Collected days only; ${num(data.uncollected_days)} uncollected left out` : data.last ? `Last claim ${ago(data.last)}` : "In the last 180 days"} />
      </div>

      <div className="grid gap-4 px-4 py-4 lg:grid-cols-2">
        <div>
          <div className="label mb-1">Day of the week <span className="normal-case text-muted">· from {num(data.claim_days)} day{data.claim_days === 1 ? "" : "s"} with claims{data.claim_days < 8 ? ", too few to call a habit" : ""}</span></div>
          <MiniColumns height={64} values={data.weekdays.map((w) => w.count)} labels={data.weekdays.map((w) => `${w.day}: ${w.count} claims`)} caption={`${name} claims by day of the week`} />
          <div className="mt-1 flex justify-between px-0.5 text-2xs text-muted">{data.weekdays.map((w) => <span key={w.day}>{w.day}</span>)}</div>
          <p className="mt-1 text-2xs text-muted">{data.note} Hours of the day are not shown for that reason.</p>
        </div>
        <div className="min-w-0 space-y-3">
          {data.sites.length > 0 && <div><div className="label mb-1">Where its claims appear</div><BarList items={data.sites.map((s) => ({ key: String(s.id), label: s.name, value: s.findings, href: `/sources/${s.id}`, hint: s.network === "onion" ? "Tor" : undefined }))} /></div>}
          {data.reporters.length > 0 && <div><div className="label mb-1">Written about by</div><BarList color="var(--series-3)" items={data.reporters.map((s) => ({ key: String(s.id), label: s.name, value: s.findings, href: `/sources/${s.id}` }))} /></div>}
        </div>
      </div>

      {data.monthly.length > 0 && (
        <div className="scroll-thin overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-line"><th className="th">Month</th><th className="th text-right">Claims</th><th className="th">Main sectors</th><th className="th">Main countries</th><th className="th">New this month</th></tr></thead>
            <tbody className="divide-y divide-line">
              {[...data.monthly].reverse().map((m) => (
                <tr key={m.month}>
                  <td className="td whitespace-nowrap">{monthName(m.month)}</td>
                  <td className="td text-right tabular-nums">{num(m.claims)}</td>
                  <td className="td text-xs">{m.top_sectors.join(", ") || "—"}</td>
                  <td className="td text-xs">{m.top_countries.length ? m.top_countries.map((c, i) => <span key={c.code}>{i > 0 && ", "}<Link className="hover:underline" href={`/search?country=${c.code}`}>{c.name}</Link></span>) : "—"}</td>
                  <td className="td text-xs text-ink-2">{[...m.new_sectors, ...m.new_countries.map((c) => c.name)].join(", ") || <span className="text-muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
