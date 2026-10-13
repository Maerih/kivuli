"use client";

import { Plus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Pagination, Spinner, Tabs, useAction } from "@/components/ui";
import { api, qs, useApi } from "@/lib/api";
import { ago, day, ENTITY_LABELS } from "@/lib/format";

interface Row { id: number; type: string; name: string; aliases: string[]; doc_count: number; curated: boolean; first_seen: string | null; last_seen: string | null; description: string; countries: string[] }
interface List { total: number; counts: Record<string, number>; items: Row[] }
const TYPES = ["actor", "organization", "incident", "malware", "campaign", "technique"] as const;
const PLURAL: Record<string, string> = { actor: "Threat actors", organization: "Organisations", incident: "Incidents", malware: "Malware", campaign: "Campaigns", technique: "Techniques" };

export default function EntitiesPage() {
  const { canWrite } = useSession();
  const [type, setType] = useState<(typeof TYPES)[number]>("actor");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("recent");
  const [page, setPage] = useState(1);
  const { data, error, mutate } = useApi<List>(`/entities${qs({ type, q, sort, page, size: 50 })}`, { keepPreviousData: true });
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ type: "campaign", name: "", description: "", aliases: "" });
  const { busy, run } = useAction();
  const create = async () => {
    const body = { ...form, aliases: form.aliases.split(",").map((a) => a.trim()).filter(Boolean) };
    if (await run(() => api("/entities", { method: "POST", body }), "Created")) { setCreating(false); setForm({ type: "campaign", name: "", description: "", aliases: "" }); mutate(); }
  };

  return (
    <>
      <PageHeader
        title="Actors and entities"
        subtitle="Who is attacking, who is being attacked, and with what. Entities are recognised automatically in every finding; campaigns are yours to define."
        actions={canWrite && <Button variant="primary" onClick={() => setCreating(true)}><Plus className="h-4 w-4" /> New entity</Button>}
      />
      <Card>
        <div className="flex flex-wrap items-center gap-3 px-3 pt-1">
          <div className="min-w-0 flex-1"><Tabs value={type} onChange={(v) => { setType(v); setPage(1); }} tabs={TYPES.map((t) => ({ id: t, label: PLURAL[t], count: data?.counts[t] ?? 0 }))} /></div>
          <input className="field mb-1 h-8 w-48 text-xs" placeholder="Filter by name or alias" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Filter entities" />
          <select className="field mb-1 h-8 w-36 px-2 text-xs" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
            <option value="recent">Recently active</option><option value="frequent">Most findings</option><option value="first">Newest</option><option value="name">Name</option>
          </select>
        </div>
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.items.length === 0 ? (
          <Empty title={`No ${PLURAL[type].toLowerCase()} yet`} hint={type === "campaign" ? "Create a campaign to group related findings you are tracking." : "They appear as intelligence is collected."} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px]">
              <thead><tr className="border-b border-line"><th className="th">Name</th><th className="th text-right">Findings</th><th className="th">First seen</th><th className="th">Last active</th></tr></thead>
              <tbody className="divide-y divide-line">
                {data.items.map((e) => (
                  <tr key={e.id}>
                    <td className="td max-w-xl">
                      <Link href={`/entities/${e.id}`} className="font-medium hover:text-accent-ink hover:underline">{e.name}</Link>
                      {e.curated && e.type !== "campaign" && <Badge className="ml-2" title="From the built-in reference list">Tracked</Badge>}
                      {e.aliases.length > 0 && <div className="truncate text-xs text-muted">Also: {e.aliases.join(", ")}</div>}
                      {e.description && <div className="line-clamp-1 text-xs text-muted">{e.description}</div>}
                    </td>
                    <td className="td text-right tabular-nums">{e.doc_count}</td>
                    <td className="td whitespace-nowrap text-xs text-muted">{day(e.first_seen)}</td>
                    <td className="td whitespace-nowrap text-xs text-muted">{ago(e.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {data && <Pagination page={page} size={50} total={data.total} onPage={setPage} />}

      <Modal open={creating} onClose={() => setCreating(false)} title="New entity" footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.name.trim().length < 2} onClick={create}>Create</Button></>}>
        <div className="space-y-4">
          <Field label="Type"><select className="field" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>{["campaign", "actor", "organization", "malware"].map((t) => <option key={t} value={t}>{ENTITY_LABELS[t]}</option>)}</select></Field>
          <Field label="Name"><input className="field" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Aliases" hint="Comma separated. Findings mentioning an alias are linked automatically from now on."><input className="field" value={form.aliases} onChange={(e) => setForm({ ...form, aliases: e.target.value })} /></Field>
          <Field label="Description"><textarea className="field h-24 py-2" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      </Modal>
    </>
  );
}
