"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AddToCase, FindingRow } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Spinner } from "@/components/ui";
import { useApi, type FindingSummary } from "@/lib/api";
import { ENTITY_LABELS } from "@/lib/format";

interface Technique {
  id: string; name: string; tactics: string[]; description: string; entity_id: number | null; url: string;
  sub_techniques: { id: string; name: string }[]; findings: FindingSummary[];
  used_by: { id: number; type: string; name: string; confidence: number; source: string; doc_count: number }[];
}

export default function TechniquePage() {
  const { id } = useParams<{ id: string }>();
  const { meta } = useSession();
  const { data: t, error } = useApi<Technique>(`/attack/techniques/${id}`);
  const back = <Link href="/attack" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> ATT&amp;CK coverage</Link>;
  if (error) return <>{back}<ErrorNote error={error} /></>;
  if (!t) return <Spinner />;
  const tactic = (short: string) => meta.tactics?.find((x) => x.shortname === short)?.name ?? short;
  const parent = t.id.includes(".") ? t.id.split(".")[0] : null;

  return (
    <>
      {back}
      <PageHeader
        title={<><span className="font-mono text-muted">{t.id}</span> {t.name}</>}
        subtitle={<span className="flex flex-wrap items-center gap-1.5 pt-1">
          {t.tactics.map((x) => <Link key={x} href={`/search?q=${encodeURIComponent(`tactic:${x}`)}`}><Badge tone="accent">{tactic(x)}</Badge></Link>)}
          {parent && <Link href={`/attack/${parent}`} className="link text-xs">Sub-technique of {parent} {meta.techniques?.[parent] ?? ""}</Link>}
        </span>}
        actions={<>
          <Link href={`/search?q=${encodeURIComponent(`technique:${t.id}`)}`}><Button>Search findings</Button></Link>
          {t.entity_id && <Link href={`/graph?node=entity:${t.entity_id}`}><Button>Relationships</Button></Link>}
          {t.entity_id && <AddToCase objectType="entity" objectId={String(t.entity_id)} />}
        </>}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="What it is" />
            <p className="px-4 py-3 text-sm leading-relaxed text-ink-2">{t.description || "No description in the catalogue."}</p>
            <p className="flex items-center gap-1.5 border-t border-line px-4 py-2 text-xs text-muted">Full reference, detections and mitigations at MITRE: <code className="font-mono text-ink-2">{t.url}</code><CopyButton value={t.url} label="Copy the MITRE reference address" /></p>
          </Card>
          <Card>
            <CardHeader title={`Findings tagged with this technique (${t.findings.length}${t.findings.length === 30 ? "+" : ""})`} />
            {t.findings.length === 0 ? <Empty title="Not observed in collected intelligence yet" hint="The technique is tagged when a finding names its ID or describes the behaviour." /> : t.findings.map((f) => <FindingRow key={f.id} f={f} />)}
          </Card>
        </div>
        <aside className="min-w-0 space-y-4">
          <Card>
            <CardHeader title={`Known to be used by (${t.used_by.length})`} hint="From the ATT&CK catalogue and from collected reporting" />
            {t.used_by.length === 0 ? <p className="px-4 py-3 text-sm text-muted">No tracked group or malware is linked to this technique.</p> : (
              <ul className="scroll-thin max-h-[30rem] divide-y divide-line overflow-y-auto">
                {t.used_by.map((u) => (
                  <li key={u.id} className="flex items-center justify-between gap-2 px-4 py-2 text-sm">
                    <Link href={`/entities/${u.id}`} className="min-w-0 truncate hover:underline">{u.name}</Link>
                    <span className="shrink-0 text-xs text-muted" title={`Source: ${u.source} · confidence ${u.confidence}%`}>{ENTITY_LABELS[u.type] ?? u.type}{u.doc_count > 0 ? ` · ${u.doc_count} findings` : ""}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          {t.sub_techniques.length > 0 && (
            <Card>
              <CardHeader title={`Sub-techniques (${t.sub_techniques.length})`} />
              <ul className="divide-y divide-line">
                {t.sub_techniques.map((s) => <li key={s.id} className="px-4 py-1.5 text-sm"><Link href={`/attack/${s.id}`} className="hover:underline"><span className="font-mono text-xs text-muted">{s.id}</span> {s.name}</Link></li>)}
              </ul>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}
