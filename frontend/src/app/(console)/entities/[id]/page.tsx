"use client";

import { ArrowLeft, Crosshair, GitMerge, Pencil, Plus, Share2, Sparkles, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { AddToCase, AiLabel, AiSources, CitedText, Defanged, FindingRow, Notes, useAiJob } from "@/components/bits";
import { ActorPatterns } from "@/components/actorpatterns";
import { BarList, MiniColumns } from "@/components/charts";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Field, Modal, Spinner, useAction } from "@/components/ui";
import { api, qs, useApi, type Bucket, type FindingSummary } from "@/lib/api";
import { ago, day, ENTITY_LABELS, IOC_LABELS } from "@/lib/format";

interface Detail {
  id: number; type: string; name: string; aliases: string[]; description: string; curated: boolean; doc_count: number; first_seen: string | null;
  last_seen: string | null; meta: Record<string, unknown>; timeline: { date: string; count: number }[]; findings: FindingSummary[];
  related: { id: number; type: string; name: string; shared: number }[]; iocs: { id: number; type: string; value: string; shared: number }[];
  countries: Bucket[]; sectors: Bucket[];
}
interface Rel { id: number; direction: "out" | "in"; kind: string; confidence: number; source: string; first_seen: string | null; last_seen: string | null; entity: { id: number; type: string; name: string } }
interface Found { items: { id: number; type: string; name: string; doc_count: number }[] }
const SEARCH_OP: Record<string, string> = { actor: "actor", organization: "org", malware: "malware", campaign: "campaign" };
// How a relationship reads from each side.
const REL_OUT: Record<string, string> = { uses: "Uses", targets: "Targets", attributed_to: "Attributed to", exploits: "Exploits", delivers: "Delivers", related_to: "Related to" };
const REL_IN: Record<string, string> = { uses: "Used by", targets: "Targeted by", attributed_to: "Attributed to it", exploits: "Exploited by", delivers: "Delivered by", related_to: "Related to" };

export default function EntityPage() {
  const { id } = useParams<{ id: string }>();
  const { meta, canWrite } = useSession();
  const { data: e, error, mutate } = useApi<Detail>(`/entities/${id}`);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", aliases: "" });
  const { busy, run } = useAction();
  const router = useRouter();
  const { data: rels, mutate: reloadRels } = useApi<Rel[]>(`/entities/${id}/relationships`);
  const { data: duplicates } = useApi<{ id: number; name: string; doc_count: number }[]>(canWrite ? `/entities/${id}/duplicates` : null);
  const { data: ai } = useApi<{ enabled: boolean }>("/ai/status");
  const profile = useAiJob();
  const [linking, setLinking] = useState(false);
  const [link, setLink] = useState({ kind: "uses", q: "", target: null as Found["items"][number] | null, confidence: 70 });
  const { data: candidates } = useApi<Found>(linking && link.q.trim().length >= 2 && !link.target ? `/entities${qs({ q: link.q.trim(), sort: "frequent", size: 8 })}` : null);

  if (error) return <ErrorNote error={error} />;
  if (!e) return <Spinner />;

  const save = async () => {
    const body = { name: form.name, description: form.description, aliases: form.aliases.split(",").map((a) => a.trim()).filter(Boolean) };
    if (await run(() => api(`/entities/${id}`, { method: "PATCH", body }), "Saved")) { setEditing(false); mutate(); }
  };
  const merge = (into: { id: number; name: string }) => confirm(`Merge "${e.name}" into "${into.name}"? Its findings and relationships move across and "${e.name}" becomes an alias. This cannot be undone.`)
    && run(() => api(`/entities/${e.id}/merge`, { method: "POST", body: { into_id: into.id } }), "Merged").then((ok) => ok && router.push(`/entities/${into.id}`));
  const addLink = async () => {
    if (!link.target) return;
    if (await run(() => api("/relationships", { method: "POST", body: { src_id: e.id, dst_id: link.target!.id, kind: link.kind, confidence: link.confidence } }), "Relationship recorded")) { setLinking(false); setLink({ kind: "uses", q: "", target: null, confidence: 70 }); reloadRels(); }
  };
  const relGroups = Object.entries((rels ?? []).reduce<Record<string, Rel[]>>((acc, r) => { const key = (r.direction === "out" ? REL_OUT : REL_IN)[r.kind] ?? r.kind; (acc[key] ??= []).push(r); return acc; }, {}));
  const attackId = typeof e.meta.attack_id === "string" ? e.meta.attack_id : "";
  const byType = (type: string) => e.related.filter((r) => r.type === type);
  const groups: [string, string][] = e.type === "actor" ? [["organization", "Victims and organisations"], ["malware", "Malware"], ["actor", "Related actors"]]
    : e.type === "organization" ? [["actor", "Threat actors"], ["malware", "Malware"], ["organization", "Mentioned alongside"]]
    : [["actor", "Threat actors"], ["organization", "Organisations"], ["malware", "Malware"]];
  const op = SEARCH_OP[e.type];
  const quoted = /\s/.test(e.name) ? `"${e.name}"` : e.name;
  const searchQuery = attackId ? `technique:${attackId}` : op ? `${op}:${quoted}` : "";

  return (
    <>
      <Link href="/entities" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> All entities</Link>
      <PageHeader
        title={e.name}
        subtitle={<span className="flex flex-wrap items-center gap-2 pt-1"><Badge tone="accent">{ENTITY_LABELS[e.type]}</Badge>{e.aliases.length > 0 && <span>Also known as {e.aliases.join(", ")}</span>}<span>{e.doc_count} findings · first seen {day(e.first_seen) || "n/a"} · last active {ago(e.last_seen)}</span></span>}
        actions={<>
          {searchQuery && <Link href={`/search?q=${encodeURIComponent(searchQuery)}`}><Button>Search findings</Button></Link>}
          {attackId && <Link href={`/attack/${attackId}`}><Button>ATT&amp;CK reference</Button></Link>}
          {canWrite && (e.type === "actor" || e.type === "organization") && <Link href={`/watchlists?value=${encodeURIComponent(e.name)}`}><Button><Crosshair className="h-3.5 w-3.5" /> Watch</Button></Link>}
          <Link href={`/graph?node=entity:${e.id}`}><Button><Share2 className="h-3.5 w-3.5" /> Relationships</Button></Link>
          <AddToCase objectType="entity" objectId={String(e.id)} />
          {canWrite && e.type !== "incident" && e.type !== "technique" && <Button onClick={() => { setForm({ name: e.name, description: e.description, aliases: e.aliases.join(", ") }); setEditing(true); }}><Pencil className="h-3.5 w-3.5" /> Edit</Button>}
        </>}
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          {e.description && <Card className="px-4 py-3"><p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-2">{e.description}</p>{typeof e.meta.profile_source === "string" && <p className="mt-2 text-xs text-muted">Profile from {e.meta.profile_source}</p>}</Card>}
          {canWrite && duplicates && duplicates.length > 0 && e.type !== "technique" && e.type !== "incident" && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-warning-soft px-3 py-2 text-sm">
              <GitMerge className="h-4 w-4 shrink-0 text-warning" /><span>Possibly the same {ENTITY_LABELS[e.type]?.toLowerCase() ?? "entity"} under another name:</span>
              {duplicates.map((d) => <span key={d.id} className="inline-flex items-center gap-1"><Link className="link font-medium" href={`/entities/${d.id}`}>{d.name}</Link><span className="text-xs text-muted">({d.doc_count})</span><Button size="sm" busy={busy} onClick={() => merge(d)}>Merge into it</Button></span>)}
            </div>
          )}
          {ai?.enabled && e.type !== "technique" && e.findings.length > 0 && (
            <Card>
              <CardHeader title={<span className="inline-flex items-center gap-1.5"><Sparkles className="h-3.5 w-3.5 text-accent-ink" />Profile from collected findings</span>} action={<Button size="sm" busy={profile.busy} onClick={() => profile.start("/ai/brief", { entity_id: e.id })}>{profile.busy ? "Drafting" : profile.job.status === "done" ? "Draft again" : "Draft profile"}</Button>} />
              {profile.job.status === "error" && <p className="px-4 py-3 text-sm text-critical">{profile.job.error}</p>}
              {profile.job.status === "done" && profile.job.text ? (
                <div className="px-4 py-3"><CitedText text={profile.job.text} sources={profile.job.sources} /><AiSources sources={profile.job.sources} cited={profile.job.citations} /><p className="mt-3 border-t border-line pt-2"><AiLabel /></p></div>
              ) : profile.job.status !== "error" && <p className="px-4 py-3 text-sm text-muted">{profile.busy ? profile.step || "Working" : "Drafts who this is, who they target and how they operate, from the latest findings that mention them, with a citation for each claim."}</p>}
            </Card>
          )}
          {e.timeline.some((t) => t.count > 0) && (
            <Card>
              <CardHeader title="Activity" hint="Findings per week, last six months" />
              <div className="px-4 pb-3 pt-8"><MiniColumns height={72} values={e.timeline.map((t) => t.count)} labels={e.timeline.map((t) => `Week of ${day(t.date)}`)} caption={`Weekly findings mentioning ${e.name}`} /></div>
            </Card>
          )}
          {e.type === "actor" && <ActorPatterns entityId={e.id} name={e.name} />}
          <Card>
            <CardHeader title="Findings" hint={e.doc_count > e.findings.length ? `Latest ${e.findings.length} of ${e.doc_count}` : undefined} />
            {e.findings.length === 0 ? <Empty title="No findings linked yet" /> : e.findings.map((f) => <FindingRow key={f.id} f={f} />)}
          </Card>
          <Card><CardHeader title="Analyst notes" /><div className="px-4 py-3"><Notes objectType="entity" objectId={String(e.id)} /></div></Card>
        </div>

        <aside className="min-w-0 space-y-4">
          {(relGroups.length > 0 || (canWrite && e.type !== "incident")) && (
            <Card>
              <CardHeader title="Stated relationships" hint="Each with a confidence and where it came from" action={canWrite && e.type !== "incident" && <Button size="sm" onClick={() => setLinking(true)}><Plus className="h-3.5 w-3.5" /> Add</Button>} />
              {relGroups.length === 0 ? <p className="px-4 py-3 text-sm text-muted">None recorded yet.</p> : (
                <div className="scroll-thin max-h-[26rem] overflow-y-auto">
                  {relGroups.map(([title, rows]) => (
                    <div key={title}>
                      <div className="label border-b border-line bg-sunken px-4 py-1">{title} · {rows.length}</div>
                      <ul className="divide-y divide-line">
                        {rows.slice(0, 40).map((r) => (
                          <li key={r.id} className="flex items-center gap-2 px-4 py-1.5 text-sm" title={`${r.source}${r.first_seen ? ` · first recorded ${day(r.first_seen)}` : ""}`}>
                            <Link href={`/entities/${r.entity.id}`} className="min-w-0 flex-1 truncate hover:underline">{r.entity.name}</Link>
                            <span className="shrink-0 text-2xs text-muted">{r.confidence}% · {r.source.startsWith("MITRE") ? "ATT&CK" : r.source.startsWith("analyst") ? "Analyst" : r.source.startsWith("STIX") ? "STIX import" : "Reporting"}</span>
                            {canWrite && <button aria-label="Remove relationship" className="shrink-0 text-muted hover:text-critical" onClick={() => confirm("Remove this relationship?") && run(() => api(`/relationships/${r.id}`, { method: "DELETE" }), "Removed").then(() => reloadRels())}><Trash2 className="h-3 w-3" /></button>}
                          </li>
                        ))}
                        {rows.length > 40 && <li className="px-4 py-1.5 text-xs text-muted">and {rows.length - 40} more: see the relationship graph</li>}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}
          {groups.map(([type, title]) => byType(type).length > 0 && (
            <Card key={type}>
              <CardHeader title={title} hint="By findings in common" />
              <div className="p-3"><BarList items={byType(type).slice(0, 10).map((r) => ({ key: String(r.id), label: r.name, value: r.shared, href: `/entities/${r.id}` }))} /></div>
            </Card>
          ))}
          {e.countries.length > 0 && <Card><CardHeader title="Countries" /><div className="p-3"><BarList items={e.countries.map((c) => ({ key: c.value, label: meta.countries[c.value] ?? c.value, value: c.count, href: `/search?country=${c.value}` }))} /></div></Card>}
          {e.sectors.length > 0 && <Card><CardHeader title="Sectors" /><div className="p-3"><BarList items={e.sectors.map((c) => ({ key: c.value, label: c.value, value: c.count }))} /></div></Card>}
          {e.iocs.length > 0 && (
            <Card>
              <CardHeader title="Indicators" hint="Seen in this entity's findings" />
              <ul className="divide-y divide-line">
                {e.iocs.slice(0, 15).map((i) => (
                  <li key={i.id} className="flex items-center justify-between gap-2 px-4 py-2">
                    <div className="min-w-0"><div className="text-2xs text-muted">{IOC_LABELS[i.type] ?? i.type}</div><Defanged value={i.value} /></div>
                    <Link href={`/indicators/${i.id}`} className="link shrink-0 text-xs">{i.shared}×</Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </aside>
      </div>

      <Modal open={linking} onClose={() => setLinking(false)} title={`Add a relationship from ${e.name}`} footer={<><Button onClick={() => setLinking(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!link.target} onClick={addLink}>Record</Button></>}>
        <div className="space-y-4">
          <Field label={e.name}><select className="field" value={link.kind} onChange={(ev) => setLink({ ...link, kind: ev.target.value })}>{Object.entries(REL_OUT).map(([k, v]) => <option key={k} value={k}>{v.toLowerCase()}</option>)}</select></Field>
          <Field label="Which entity" hint="Search actors, malware, organisations, campaigns and techniques by name.">
            {link.target ? <div className="flex items-center justify-between rounded-md border border-line px-3 py-2 text-sm"><span>{link.target.name} <span className="text-xs text-muted">{ENTITY_LABELS[link.target.type]}</span></span><button className="link text-xs" onClick={() => setLink({ ...link, target: null })}>Change</button></div>
              : <input className="field" value={link.q} placeholder="Start typing a name" onChange={(ev) => setLink({ ...link, q: ev.target.value })} />}
            {!link.target && candidates && (candidates.items.filter((c) => c.id !== e.id).length === 0 ? <span className="mt-1 block text-xs text-muted">No matching entity.</span> : (
              <ul className="mt-1 max-h-48 divide-y divide-line overflow-y-auto rounded-md border border-line">
                {candidates.items.filter((c) => c.id !== e.id).map((c) => <li key={c.id}><button type="button" className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-sm hover:bg-sunken" onClick={() => setLink({ ...link, target: c })}><span className="truncate">{c.name}</span><span className="shrink-0 text-xs text-muted">{ENTITY_LABELS[c.type]}</span></button></li>)}
              </ul>
            ))}
          </Field>
          <Field label={`Confidence: ${link.confidence}%`} hint="Your own assessment. It is recorded with your name as the source."><input type="range" min={10} max={100} step={5} className="w-full accent-[var(--accent)]" value={link.confidence} onChange={(ev) => setLink({ ...link, confidence: Number(ev.target.value) })} /></Field>
        </div>
      </Modal>

      <Modal open={editing} onClose={() => setEditing(false)} title="Edit entity" footer={<><Button onClick={() => setEditing(false)}>Cancel</Button><Button variant="primary" busy={busy} onClick={save}>Save</Button></>}>
        <div className="space-y-4">
          <Field label="Name"><input className="field" value={form.name} onChange={(ev) => setForm({ ...form, name: ev.target.value })} /></Field>
          <Field label="Aliases" hint="Comma separated"><input className="field" value={form.aliases} onChange={(ev) => setForm({ ...form, aliases: ev.target.value })} /></Field>
          <Field label="Description"><textarea className="field h-40 py-2" value={form.description} onChange={(ev) => setForm({ ...form, description: ev.target.value })} /></Field>
        </div>
      </Modal>
    </>
  );
}
