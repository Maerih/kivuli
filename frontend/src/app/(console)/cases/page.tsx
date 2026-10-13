"use client";

import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { PRIORITY_TONE, TlpBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Spinner, Tabs, useAction } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { ago, titleCase } from "@/lib/format";

interface CaseRow { id: number; title: string; description: string; status: string; priority: string; tlp: string; owner: string; owner_id: number | null; item_count: number; created_at: string; updated_at: string }

export default function CasesPage() {
  const { canWrite } = useSession();
  const router = useRouter();
  const [status, setStatus] = useState("active");
  const { data, error } = useApi<CaseRow[]>("/cases");
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: "", description: "", priority: "medium", tlp: "amber" });
  const { busy, run } = useAction();
  const create = () => run(async () => { const c = await api<{ id: number }>("/cases", { method: "POST", body: form }); router.push(`/cases/${c.id}`); });
  const rows = data?.filter((c) => (status === "active" ? c.status !== "closed" : c.status === "closed")) ?? [];

  return (
    <>
      <PageHeader title="Investigations" subtitle="Group findings, indicators and entities into an investigation, record your analysis, and export a report." actions={canWrite && <Button variant="primary" onClick={() => setCreating(true)}><Plus className="h-4 w-4" /> New case</Button>} />
      <Card>
        <div className="px-3 pt-1"><Tabs value={status} onChange={setStatus} tabs={[{ id: "active", label: "Active", count: data?.filter((c) => c.status !== "closed").length ?? 0 }, { id: "closed", label: "Closed", count: data?.filter((c) => c.status === "closed").length ?? 0 }]} /></div>
        <ErrorNote error={error} />
        {!data ? <Spinner /> : rows.length === 0 ? (
          <Empty title={status === "active" ? "No active cases" : "No closed cases"} hint="Open a case from here, or use “Add to case” on any finding, indicator or entity." />
        ) : (
          <ul className="divide-y divide-line">
            {rows.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <Link href={`/cases/${c.id}`} className="font-medium hover:text-accent-ink hover:underline">{c.title}</Link>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
                    <Badge tone={PRIORITY_TONE[c.priority]}>{titleCase(c.priority)} priority</Badge><TlpBadge tlp={c.tlp} /><Badge>{titleCase(c.status)}</Badge>
                    <span>{c.item_count} item{c.item_count === 1 ? "" : "s"}</span>{c.owner && <span>Owner: {c.owner}</span>}<span>Updated {ago(c.updated_at)}</span>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Modal open={creating} onClose={() => setCreating(false)} title="New case" footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.title.trim().length < 3} onClick={create}>Create case</Button></>}>
        <div className="space-y-4">
          <Field label="Title"><input className="field" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="e.g. Credential exposure: example.co.ke" /></Field>
          <Field label="Summary"><textarea className="field h-24 py-2" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Priority"><select className="field" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>{["low", "medium", "high", "critical"].map((p) => <option key={p} value={p}>{titleCase(p)}</option>)}</select></Field>
            <Field label="Sharing (TLP)"><select className="field" value={form.tlp} onChange={(e) => setForm({ ...form, tlp: e.target.value })}>{["clear", "green", "amber", "red"].map((p) => <option key={p} value={p}>TLP:{p.toUpperCase()}</option>)}</select></Field>
          </div>
        </div>
      </Modal>
    </>
  );
}
