"use client";

import { Download, KeyRound, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { NetworkBadge, VerificationBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CopyButton, Empty, ErrorNote, Pagination, Spinner, Tabs, useAction } from "@/components/ui";
import { api, qs, useApi } from "@/lib/api";
import { ago, cn, defang, EXPOSURE_LABELS, num, secretLabel, stamp, titleCase } from "@/lib/format";

interface Exposure {
  id: number; kind: string; identity: string; domain: string; service: string; secret_type: string; fingerprint: string; password_exposed: boolean;
  status: string; first_seen: string; last_seen: string;
  finding: { id: string; title: string; source_name: string; network: string; threat_type: string; risk_score: number; verification: string };
}
interface ExposureList {
  total: number; kinds: string[]; statuses: string[]; owned_domains: string[]; by_kind: Record<string, number>; by_status: Record<string, number>;
  open_mine: number; top_domains: { value: string; count: number }[]; items: Exposure[];
}
const STATUS_HINT: Record<string, string> = { open: "Needs action", remediated: "Password reset or secret rotated", ignored: "Risk accepted, no action planned", false_positive: "Not ours or not real" };

export default function ExposuresPage() {
  const { canWrite } = useSession();
  const [status, setStatus] = useState("open");
  const [kind, setKind] = useState("");
  const [domain, setDomain] = useState("");
  const [mine, setMine] = useState(false);
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const filters = { status: status === "all" ? undefined : status, kind, domain, mine, q };
  const { data, error, mutate, isLoading } = useApi<ExposureList>(`/exposures${qs({ ...filters, page, size: 50 })}`, { keepPreviousData: true });
  const { busy, run } = useAction();

  const reset = (fn: () => void) => { fn(); setPage(1); setSelected(new Set()); };
  const mark = async (next: string) => {
    if (await run(() => api("/exposures/status", { method: "POST", body: { ids: [...selected], status: next } }), `${selected.size} marked ${titleCase(next).toLowerCase()}`)) { setSelected(new Set()); mutate(); }
  };
  const pick = (id: number) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allOnPage = data?.items.length ? data.items.every((e) => selected.has(e.id)) : false;
  const counts = data?.by_status ?? {};

  return (
    <>
      <PageHeader
        title="Identity exposure"
        subtitle="Accounts, sessions and secrets found in leaks and infostealer logs. The platform records who is exposed and where, never the password or the secret itself: only a short fingerprint, so the same secret can be recognised again."
        actions={<a href={`/api/exposures/export${qs(filters)}`}><Button disabled={!data?.total}><Download className="h-3.5 w-3.5" /> Export CSV</Button></a>}
      />

      {data && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <button onClick={() => reset(() => { setMine(!mine); setStatus("open"); })} className={cn("card px-4 py-3 text-left", mine && "border-critical")}>
            <div className="text-xs text-muted">Open on your domains</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{num(data.open_mine)}</div>
          </button>
          {data.kinds.slice(0, 5).map((k) => (
            <button key={k} onClick={() => reset(() => { setKind(kind === k ? "" : k); setStatus("open"); })} className={cn("card px-4 py-3 text-left", kind === k && "border-accent")}>
              <div className="truncate text-xs text-muted">{EXPOSURE_LABELS[k] ?? titleCase(k)}</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{num(data.by_kind[k] ?? 0)}</div>
            </button>
          ))}
        </div>
      )}
      {data && data.owned_domains.length === 0 && (
        <p className="mb-4 flex items-start gap-2 rounded-md border border-line bg-accent-soft px-3 py-2 text-sm">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-accent-ink" />
          <span>You are not watching a domain yet, so nothing can be marked as yours. <Link className="link" href="/watchlists">Add your domain to a watchlist</Link> to separate your organisation&apos;s exposure from everyone else&apos;s.</span>
        </p>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_17rem]">
        <Card className="min-w-0">
          <div className="flex flex-wrap items-center gap-3 px-3 pt-1">
            <div className="min-w-0 flex-1">
              <Tabs value={status} onChange={(v) => reset(() => setStatus(v))} tabs={[
                ...(data?.statuses ?? ["open", "remediated", "ignored", "false_positive"]).map((s) => ({ id: s, label: titleCase(s), count: counts[s] ?? 0 })), { id: "all", label: "All" },
              ]} />
            </div>
            <form onSubmit={(e) => { e.preventDefault(); reset(() => setQ(text)); }} className="pb-1">
              <input className="field h-8 w-52 text-xs" placeholder="Filter by account, domain, service…" aria-label="Filter exposures" value={text} onChange={(e) => setText(e.target.value)} />
            </form>
          </div>
          {(domain || kind || q) && (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-4 py-2 text-xs">
              {domain && <button onClick={() => reset(() => setDomain(""))} className="rounded-full border border-line-strong px-2 py-0.5 hover:border-critical">Domain: {domain} ×</button>}
              {kind && <button onClick={() => reset(() => setKind(""))} className="rounded-full border border-line-strong px-2 py-0.5 hover:border-critical">{EXPOSURE_LABELS[kind] ?? kind} ×</button>}
              {q && <button onClick={() => reset(() => { setQ(""); setText(""); })} className="rounded-full border border-line-strong px-2 py-0.5 hover:border-critical">“{q}” ×</button>}
            </div>
          )}
          {canWrite && selected.size > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-b border-line bg-accent-soft px-4 py-2 text-sm">
              <span className="font-medium">{selected.size} selected</span>
              {(data?.statuses ?? []).filter((s) => s !== status).map((s) => <Button key={s} size="sm" busy={busy} title={STATUS_HINT[s]} onClick={() => mark(s)}>{titleCase(s)}</Button>)}
              <button className="link ml-auto text-xs" onClick={() => setSelected(new Set())}>Clear</button>
            </div>
          )}
          <ErrorNote error={error} />
          {!data ? <Spinner /> : data.items.length === 0 ? (
            <Empty title={status === "open" ? "No open exposures" : "Nothing here"} hint="Exposures are recorded when a collected leak, combo list or stealer log contains an account, a session or a secret. Secrets are fingerprinted and then discarded." />
          ) : (
            <div className={cn("overflow-x-auto", isLoading && "opacity-60")}>
              <table className="w-full min-w-[820px]">
                <thead><tr className="border-b border-line">
                  {canWrite && <th className="th w-8"><input type="checkbox" aria-label="Select all on this page" className="accent-[var(--accent)]" checked={allOnPage} onChange={() => setSelected(allOnPage ? new Set() : new Set(data.items.map((e) => e.id)))} /></th>}
                  <th className="th">Account or secret</th><th className="th">Kind</th><th className="th">Where it works</th><th className="th">Found in</th><th className="th">Last seen</th>
                </tr></thead>
                <tbody className="divide-y divide-line">
                  {data.items.map((e) => (
                    <tr key={e.id}>
                      {canWrite && <td className="td"><input type="checkbox" aria-label={`Select exposure ${e.id}`} className="accent-[var(--accent)]" checked={selected.has(e.id)} onChange={() => pick(e.id)} /></td>}
                      <td className="td max-w-[17rem]">
                        <div className="flex items-center gap-1"><span className="truncate font-mono text-xs" title={defang(e.identity)}>{e.identity ? defang(e.identity) : <span className="text-muted">{secretLabel(e.secret_type)}</span>}</span>{e.identity && <CopyButton value={e.identity} />}</div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1">
                          {e.password_exposed && <Badge tone="critical" title="A password was present next to this account. It was redacted and not stored."><KeyRound className="h-3 w-3" />Password exposed</Badge>}
                          {e.fingerprint && <span className="font-mono text-2xs text-muted" title="First 16 hex characters of the secret's SHA-256. Enough to recognise the same secret elsewhere, useless for recovering it.">fp {e.fingerprint}</span>}
                          {status === "all" && e.status !== "open" && <Badge tone={e.status === "remediated" ? "good" : "neutral"}>{titleCase(e.status)}</Badge>}
                        </div>
                      </td>
                      <td className="td whitespace-nowrap text-xs text-ink-2">{EXPOSURE_LABELS[e.kind] ?? titleCase(e.kind)}{e.secret_type && <div className="text-muted">{secretLabel(e.secret_type)}</div>}</td>
                      <td className="td max-w-[12rem] text-xs">
                        {e.service ? <span className="block truncate font-mono" title={defang(e.service)}>{defang(e.service)}</span> : e.domain ? <button className="link font-mono" onClick={() => reset(() => setDomain(e.domain))}>{defang(e.domain)}</button> : <span className="text-muted">Unknown</span>}
                      </td>
                      <td className="td max-w-[18rem]">
                        <Link href={`/findings/${e.finding.id}`} className="block truncate text-sm hover:underline">{e.finding.title}</Link>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted"><NetworkBadge network={e.finding.network} /><span className="truncate">{e.finding.source_name}</span><VerificationBadge state={e.finding.verification} /></div>
                      </td>
                      <td className="td whitespace-nowrap text-xs text-muted" title={`First seen ${stamp(e.first_seen)}`}>{ago(e.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <aside className="min-w-0 space-y-4">
          <Card>
            <div className="border-b border-line px-4 py-3"><h2 className="text-sm font-semibold">Most exposed domains</h2><p className="mt-0.5 text-xs text-muted">Open exposures by mailbox domain</p></div>
            {!data?.top_domains.length ? <p className="px-4 py-3 text-sm text-muted">None yet.</p> : (
              <ul className="divide-y divide-line text-sm">
                {data.top_domains.map((d) => (
                  <li key={d.value}>
                    <button onClick={() => reset(() => setDomain(domain === d.value ? "" : d.value))} className={cn("flex w-full items-center justify-between gap-2 px-4 py-1.5 text-left hover:bg-sunken", domain === d.value && "bg-accent-soft")}>
                      <span className="min-w-0 truncate font-mono text-xs">{defang(d.value)}{data.owned_domains.some((o) => d.value === o || d.value.endsWith(`.${o}`)) && <Badge tone="accent" className="ml-1.5">Yours</Badge>}</span>
                      <span className="shrink-0 tabular-nums text-ink-2">{num(d.count)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card className="px-4 py-3 text-xs leading-relaxed text-muted">
            <p className="mb-1 font-semibold text-ink-2">What to do with an exposure</p>
            Reset the password and revoke sessions for the account, rotate the token or key, then mark it <em>Remediated</em>. An infostealer log means the device itself was infected: treat every credential saved in that browser as compromised.
          </Card>
        </aside>
      </div>
      {data && <Pagination page={page} size={50} total={data.total} onPage={setPage} />}
    </>
  );
}
