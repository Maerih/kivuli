"use client";

import { CheckCircle2, CircleOff, KeyRound, Loader2, Plus, Send, Sparkles, Trash2, Upload, XCircle } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Field, Modal, Spinner, Tabs, useAction, useToast } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { ago, cn, IOC_LABELS, stamp, titleCase } from "@/lib/format";

interface Integration {
  id: number; name: string; kind: string; kind_label: string; url: string; config: Record<string, string>; has_secret: boolean; min_severity: string;
  categories: string[]; is_active: boolean; last_delivery_at: string | null; last_error: string; failures: number; created_at: string;
}
interface IntegrationList { kinds: Record<string, string>; config_keys: Record<string, string[]>; allow_private: boolean; items: Integration[] }
interface Delivery { id: number; ts: string; ok: boolean; status_code: number | null; error: string; alert_id: number | null }
interface TestResult { at?: string; ok: boolean; message: string; detail?: Record<string, unknown>; latency_ms?: number }
interface KeyState { key_source: "console" | "env" | "none" | "not_needed"; hint: string; key_updated_at: string | null; blocked_hosts: string[]; last_test: TestResult | null; key_rejected?: string }
interface Provider extends KeyState {
  name: string; label: string; kinds: string[]; tier: "free" | "commercial" | "planned"; enabled: boolean; about: string; env: string; hosts: string[];
  takes_key: boolean; optional_key: boolean; signup: string; testable: boolean;
}
interface Ai extends KeyState { enabled: boolean; model: string; models: { id: string; label: string }[] }
interface Providers { reported: boolean; providers: Provider[]; ai: Ai; egress_allow_hosts: string[]; can_manage: boolean }
type Running = Record<string, "running" | TestResult>;
interface ApiKey { id: number; name: string; prefix: string; scopes: string[]; created_at: string; last_used_at: string | null; expires_at: string | null; revoked: boolean; key?: string }

const KIND_HELP: Record<string, { url: string; secret?: string; note: string }> = {
  webhook: { url: "https://soar.example.com/hooks/kivuli", secret: "Signing secret (optional)", note: "Posts each alert as JSON. With a secret, every request carries an X-Kivuli-Signature header (HMAC-SHA-256 of the body) so the receiver can verify it. Use this for SOAR platforms, Sentinel Logic Apps, Cortex XSOAR or anything that accepts a webhook." },
  slack: { url: "https://hooks.slack.com/services/…", note: "An incoming-webhook URL from your Slack app. The URL is the credential, so it is stored encrypted and never shown again." },
  teams: { url: "https://….webhook.office.com/…", note: "A Teams workflow webhook URL. Stored encrypted and never shown again." },
  splunk_hec: { url: "https://splunk.example.com:8088", secret: "HEC token", note: "Sends each alert as an event to the HTTP Event Collector." },
  jira: { url: "https://yourcompany.atlassian.net", secret: "API token", note: "Opens an issue per alert. Needs the project key and the account email the token belongs to." },
  servicenow: { url: "https://yourcompany.service-now.com", secret: "Password", note: "Opens an incident per alert through the Table API using basic authentication." },
};
const CONFIG_LABEL: Record<string, string> = { index: "Index", sourcetype: "Source type", project: "Project key", issue_type: "Issue type", user: "Account (user or email)", table: "Table (default: incident)", category: "Category" };
const TIER: Record<Provider["tier"], { label: string; tone: "good" | "accent" | "neutral" }> = { free: { label: "Free", tone: "neutral" }, commercial: { label: "Needs an API key", tone: "accent" }, planned: { label: "Planned", tone: "neutral" } };
const BLANK = { name: "", kind: "webhook", url: "", secret: "", min_severity: "high", config: {} as Record<string, string> };

function Destinations() {
  const { isAdmin } = useSession();
  const { data, error, mutate } = useApi<IntegrationList>("/integrations", { refreshInterval: 30000 });
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [log, setLog] = useState<Integration | null>(null);
  const { data: deliveries } = useApi<Delivery[]>(log ? `/integrations/${log.id}/deliveries` : null);
  const { busy, run } = useAction();
  const [tests, setTests] = useState<Running>({});
  const set = (patch: Partial<typeof BLANK>) => setForm((f) => ({ ...f, ...patch }));
  /** Send a test alert and wait for the delivery record, so the outcome is shown rather than assumed. */
  const sendTest = async (i: Integration) => {
    const key = String(i.id);
    setTests((t) => ({ ...t, [key]: "running" }));
    const finish = (result: TestResult) => { setTests((t) => ({ ...t, [key]: result })); mutate(); };
    try {
      const before = Math.max(0, ...(await api<Delivery[]>(`/integrations/${i.id}/deliveries`)).map((d) => d.id));
      await api(`/integrations/${i.id}/test`, { method: "POST" });
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const fresh = (await api<Delivery[]>(`/integrations/${i.id}/deliveries`)).find((d) => d.id > before && d.alert_id === null);
        if (fresh) return finish({ ok: fresh.ok, message: fresh.ok ? `The destination accepted a test alert (HTTP ${fresh.status_code ?? 200}).` : fresh.error.replace(/^test: /, "").replace(/^./, (c) => c.toUpperCase()) });
      }
      finish({ ok: false, message: "No delivery result after 30 seconds. Check that the notify container is running (./ctl.sh status)." });
    } catch (err) {
      finish({ ok: false, message: err instanceof Error ? err.message : "The test could not be started" });
    }
  };
  // A new destination is tested straight away: adding one that silently does not work helps nobody.
  const create = () => run(async () => { const created = await api<Integration>("/integrations", { method: "POST", body: form }); setOpen(false); setForm(BLANK); await mutate(); sendTest(created); }, "Destination added. Sending a test alert to it now.");
  const help = KIND_HELP[form.kind];

  if (error) return <ErrorNote error={error} />;
  if (!data) return <Spinner />;
  return (
    <>
      <Card>
        <CardHeader title="Alert destinations" hint="Every new alert at or above a destination's severity is delivered to it, in addition to email" action={isAdmin && <Button variant="primary" size="sm" onClick={() => { setForm(BLANK); setOpen(true); }}><Plus className="h-3.5 w-3.5" /> Add destination</Button>} />
        {data.items.length === 0 ? <Empty title="No destinations yet" hint="Send alerts to a SIEM, a SOAR playbook, a chat channel or a ticket queue. Delivery leaves through the mail/notification container only, to public HTTPS addresses." /> : (
          <ul className="divide-y divide-line">
            {data.items.map((i) => (
              <li key={i.id} className={cn("flex flex-wrap items-center gap-x-4 gap-y-1.5 px-4 py-3", !i.is_active && "opacity-60")}>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5 text-sm font-medium">{i.name}<Badge>{i.kind_label}</Badge>{!i.is_active && <Badge tone="warning" title={i.failures >= 10 ? "Paused automatically after repeated failures" : undefined}>Paused</Badge>}</div>
                  <div className="mt-0.5 truncate font-mono text-xs text-muted">{i.url}</div>
                  <div className="mt-0.5 text-xs text-muted">{titleCase(i.min_severity)} and above · {i.last_delivery_at ? `last delivered ${ago(i.last_delivery_at)}` : "nothing delivered yet"}{i.last_error && !tests[String(i.id)] && <span className="text-critical"> · last error: {i.last_error}</span>}</div>
                  {tests[String(i.id)] && <TestLine state={tests[String(i.id)]} last={null} />}
                </div>
                <div className="flex gap-1">
                  <Button size="sm" onClick={() => setLog(i)}>Deliveries</Button>
                  {isAdmin && <>
                    <Button size="sm" title="Send a test alert and report whether the destination accepted it" disabled={tests[String(i.id)] === "running"} onClick={() => sendTest(i)}><Send className="h-3.5 w-3.5" /> Test</Button>
                    <Button size="sm" onClick={() => run(() => api(`/integrations/${i.id}`, { method: "PATCH", body: { is_active: !i.is_active } }), i.is_active ? "Paused" : "Resumed").then(() => mutate())}>{i.is_active ? "Pause" : "Resume"}</Button>
                    <Button size="sm" variant="ghost" title="Delete" onClick={() => confirm(`Delete the destination "${i.name}"?`) && run(() => api(`/integrations/${i.id}`, { method: "DELETE" }), "Deleted").then(() => mutate())}><Trash2 className="h-3.5 w-3.5" /></Button>
                  </>}
                </div>
              </li>
            ))}
          </ul>
        )}
        {!isAdmin && <p className="border-t border-line px-4 py-2 text-xs text-muted">Only administrators can add or change destinations.</p>}
      </Card>

      <Modal open={open} onClose={() => setOpen(false)} title="Add an alert destination" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.name.trim().length < 2 || form.url.trim().length < 8} onClick={create}>Add</Button></>}>
        <div className="space-y-4">
          <Field label="Type" hint={help?.note}>
            <select className="field" value={form.kind} onChange={(e) => set({ kind: e.target.value, config: {}, secret: "" })}>{Object.entries(data.kinds).map(([k, label]) => <option key={k} value={k}>{label}</option>)}</select>
          </Field>
          <Field label="Name"><input className="field" value={form.name} placeholder="SOC channel" onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field label="Address" hint={data.allow_private ? "Private addresses are allowed on this deployment." : "Must be HTTPS and publicly resolvable: internal addresses are refused."}><input className="field font-mono" value={form.url} placeholder={help?.url} autoComplete="off" onChange={(e) => set({ url: e.target.value })} /></Field>
          {help?.secret && <Field label={help.secret} hint="Stored encrypted. It cannot be read back, only replaced."><input className="field font-mono" type="password" autoComplete="new-password" value={form.secret} onChange={(e) => set({ secret: e.target.value })} /></Field>}
          {(data.config_keys[form.kind] ?? []).length > 0 && (
            <div className="grid gap-4 sm:grid-cols-2">
              {data.config_keys[form.kind].map((k) => <Field key={k} label={CONFIG_LABEL[k] ?? titleCase(k)}><input className="field" value={form.config[k] ?? ""} onChange={(e) => set({ config: { ...form.config, [k]: e.target.value } })} /></Field>)}
            </div>
          )}
          <Field label="Send alerts that are"><select className="field" value={form.min_severity} onChange={(e) => set({ min_severity: e.target.value })}><option value="info">Any severity</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option></select></Field>
        </div>
      </Modal>

      <Modal open={Boolean(log)} onClose={() => setLog(null)} title={`Deliveries: ${log?.name ?? ""}`} wide>
        {!deliveries ? <Spinner /> : deliveries.length === 0 ? <p className="text-sm text-muted">Nothing has been sent to this destination yet.</p> : (
          <table className="w-full"><thead><tr className="border-b border-line"><th className="th">When</th><th className="th">Result</th><th className="th">Alert</th><th className="th">Detail</th></tr></thead>
            <tbody className="divide-y divide-line">{deliveries.map((d) => (
              <tr key={d.id}><td className="td whitespace-nowrap text-xs">{stamp(d.ts)}</td><td className="td"><Badge tone={d.ok ? "good" : "critical"}>{d.ok ? "Delivered" : "Failed"}{d.status_code ? ` · ${d.status_code}` : ""}</Badge></td><td className="td text-xs">{d.alert_id ? `#${d.alert_id}` : "Test"}</td><td className="td break-words text-xs text-muted">{d.error}</td></tr>
            ))}</tbody></table>
        )}
      </Modal>
    </>
  );
}

/** Run a provider's connection test and wait for its answer. The request is made by the isolated enrichment worker, so the result arrives a moment later. */
function useProviderTests(onSettled: () => void) {
  const [running, setRunning] = useState<Running>({});
  const timers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  useEffect(() => { const held = timers.current; return () => Object.values(held).forEach(clearTimeout); }, []);

  const watch = useCallback((name: string, jobId: string) => {
    clearTimeout(timers.current[name]);
    setRunning((r) => ({ ...r, [name]: "running" }));
    const started = Date.now();
    const finish = (result: TestResult) => { setRunning((r) => ({ ...r, [name]: result })); onSettled(); };
    const poll = async () => {
      try {
        const job = await api<TestResult & { status: string }>(`/providers/tests/${jobId}`);
        if (job.status === "done") return finish(job);
      } catch (err) {
        return finish({ ok: false, message: err instanceof Error ? err.message : "The test result could not be read" });
      }
      if (Date.now() - started > 170000) return finish({ ok: false, message: "No answer from the enrichment worker after three minutes. Check that the enricher container is running (./ctl.sh status)." });
      timers.current[name] = setTimeout(poll, 1000);
    };
    timers.current[name] = setTimeout(poll, 700);
  }, [onSettled]);

  const test = useCallback(async (name: string) => {
    setRunning((r) => ({ ...r, [name]: "running" }));
    try {
      const { job_id } = await api<{ job_id: string }>(`/providers/${name}/test`, { method: "POST" });
      watch(name, job_id);
    } catch (err) {
      setRunning((r) => ({ ...r, [name]: { ok: false, message: err instanceof Error ? err.message : "The test could not be started" } }));
    }
  }, [watch]);
  return { running, test, watch };
}

/** The verdict of a connection test: working, or what is wrong. Icon and words, never colour alone. */
function TestLine({ state, last }: { state?: "running" | TestResult; last: TestResult | null }) {
  if (state === "running") return <p className="mt-1 flex items-center gap-1.5 text-xs text-ink-2" role="status"><Loader2 className="h-3.5 w-3.5 animate-spin" />Testing: making a real request to the provider…</p>;
  const result = state ?? last;
  if (!result) return <p className="mt-1 text-xs text-muted">Not tested yet.</p>;
  return (
    <p className={cn("mt-1 flex items-start gap-1.5 text-xs", result.ok ? "text-good" : "text-critical")} role="status">
      {result.ok ? <CheckCircle2 className="mt-px h-3.5 w-3.5 shrink-0" /> : <XCircle className="mt-px h-3.5 w-3.5 shrink-0" />}
      <span><span className="font-semibold">{result.ok ? "Working." : "Not working."}</span> <span className="text-ink-2">{result.message}</span>
        <span className="text-muted">{result.at ? ` · tested ${ago(result.at)}` : " · tested just now"}{result.latency_ms ? ` · ${(result.latency_ms / 1000).toFixed(1)} s` : ""}</span></span>
    </p>
  );
}

function KeyLine({ item, envName }: { item: KeyState; envName: string }) {
  if (item.key_source === "not_needed") return null;
  return (
    <p className="mt-0.5 text-xs text-muted">
      {item.key_source === "console" ? <>Key set here{item.hint ? <>, ending <span className="font-mono text-ink-2">…{item.hint}</span></> : null}{item.key_updated_at ? ` · saved ${ago(item.key_updated_at)}` : ""}</>
        : item.key_source === "env" ? <>Key from <code className="font-mono">{envName}</code> in <code className="font-mono">.env</code>. A key entered here would take precedence.</>
        : "No key set."}
    </p>
  );
}

interface KeyTarget { name: string; label: string; signup: string; replacing: boolean }

function KeyDialog({ target, onClose, state, onSaved }: { target: KeyTarget | null; onClose: () => void; state?: "running" | TestResult; onSaved: (name: string, jobId: string) => void }) {
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  const { busy, run } = useAction();
  useEffect(() => { setKey(""); setSaved(false); }, [target?.name]);
  if (!target) return null;
  const save = () => run(async () => {
    const out = await api<{ job_id: string }>(`/providers/${target.name}/key`, { method: "PUT", body: { key: key.trim() } });
    setSaved(true);
    setKey("");
    onSaved(target.name, out.job_id);
  });
  const result = saved && state && state !== "running" ? state : null;
  return (
    <Modal open onClose={onClose} title={`${target.replacing ? "Replace the" : "Add an"} API key: ${target.label}`}
      footer={saved
        ? <>{result && !result.ok && <Button onClick={() => setSaved(false)}>Try another key</Button>}<Button variant="primary" onClick={onClose}>{result ? "Done" : "Close"}</Button></>
        : <><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} disabled={key.trim().length < 8} onClick={save}>Save and test</Button></>}>
      {saved ? (
        <div className="space-y-2 text-sm">
          <p className="text-ink-2">The key is saved, encrypted. It is now being used for a real request to {target.label}:</p>
          <div className="rounded-md border border-line bg-sunken px-3 py-2"><TestLine state={state ?? "running"} last={null} /></div>
          {result && !result.ok && <p className="text-xs text-muted">The key stays saved until you replace or remove it, but it will not be used successfully while the test fails.</p>}
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="API key" hint="Stored encrypted and never shown again; only its last four characters are kept visible so you can recognise it.">
            <input className="field font-mono" type="password" autoComplete="new-password" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} onKeyDown={(e) => e.key === "Enter" && key.trim().length >= 8 && save()} />
          </Field>
          <p className="text-xs text-muted">Saving makes one real request to {target.label} with this key and reports here whether it was accepted.{target.signup && <> Keys are issued at <a className="link" href={target.signup} target="_blank" rel="noopener noreferrer">{target.signup.replace(/^https:\/\//, "")}</a>.</>}</p>
        </div>
      )}
    </Modal>
  );
}

function ProviderList() {
  const { canWrite } = useSession();
  const { data, error, mutate } = useApi<Providers>("/providers", { refreshInterval: 60000 });
  const reload = useCallback(() => { mutate(); }, [mutate]);
  const { running, test, watch } = useProviderTests(reload);
  const [target, setTarget] = useState<KeyTarget | null>(null);
  const [customModel, setCustomModel] = useState("");
  const { busy, run } = useAction();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Spinner />;
  const admin = data.can_manage;
  const removeKey = (name: string, label: string) => confirm(`Remove the ${label} key entered here?`) && run(() => api(`/providers/${name}/key`, { method: "DELETE" }), "Key removed").then(() => setTimeout(reload, 1200));
  const setModel = (model: string) => run(async () => { const out = await api<{ job_id: string }>("/providers/anthropic/config", { method: "PUT", body: { model } }); watch("anthropic", out.job_id); }, "Model changed. Testing it now.").then(reload);
  const hasKey = (item: KeyState) => item.key_source === "console" || item.key_source === "env";
  const blocked = (hosts: string[]) => hosts.length > 0 && <p className="mt-1 text-xs text-warning">Blocked by the egress allow-list: add {hosts.join(", ")} to EGRESS_ALLOW_HOSTS in <code className="font-mono">.env</code> and restart.</p>;
  const keyButtons = (item: KeyState & { name: string; label: string; signup?: string }) => admin && (
    <>
      <Button size="sm" onClick={() => setTarget({ name: item.name, label: item.label, signup: item.signup ?? "", replacing: item.key_source === "console" })}><KeyRound className="h-3.5 w-3.5" /> {item.key_source === "console" ? "Replace key" : "Set key"}</Button>
      {item.key_source === "console" && <Button size="sm" variant="ghost" title="Remove the key entered here" busy={busy} onClick={() => removeKey(item.name, item.label)}><Trash2 className="h-3.5 w-3.5" /></Button>}
    </>
  );
  const ai = data.ai;
  const knownModel = ai.models.some((m) => m.id === ai.model);

  return (
    <>
      <Card className="mb-4">
        <CardHeader title="AI analyst" hint="Natural-language questions answered from collected findings, finding summaries and report drafts" action={ai.enabled ? <Badge tone="good"><CheckCircle2 className="h-3 w-3" />On</Badge> : <Badge><CircleOff className="h-3 w-3" />Off</Badge>} />
        <div className="space-y-3 px-4 py-3 text-sm text-ink-2">
          <p className="flex items-start gap-2"><Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-accent-ink" /><span>Optional. When it is on, the text of the findings relevant to a question is sent to the Anthropic API so the model can answer from them. Secrets are already redacted from that text. Answers cite the findings they rest on; the model has no tools and cannot browse, search or change anything. With no key, nothing leaves the platform.</span></p>
          <div className="flex flex-wrap items-start gap-x-4 gap-y-2 rounded-md border border-line px-3 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-ink">Anthropic API key</div>
              <KeyLine item={ai} envName="ANTHROPIC_API_KEY" />
              {blocked(ai.blocked_hosts)}
              <TestLine state={running.anthropic} last={ai.last_test} />
            </div>
            <div className="flex flex-wrap gap-1">
              {canWrite && hasKey(ai) && <Button size="sm" disabled={running.anthropic === "running"} title="Looks up the model, then sends one tiny request of the kind the analyst makes" onClick={() => test("anthropic")}><Send className="h-3.5 w-3.5" /> Test</Button>}
              {keyButtons({ ...ai, name: "anthropic", label: "Anthropic", signup: "https://console.anthropic.com/settings/keys" })}
            </div>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Model">
              <select className="field w-72" disabled={!admin || busy} value={knownModel ? ai.model : "custom"} onChange={(e) => (e.target.value === "custom" ? setCustomModel(ai.model) : setModel(e.target.value))}>
                {ai.models.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
                <option value="custom">{knownModel ? "Another model ID…" : `Custom: ${ai.model}`}</option>
              </select>
            </Field>
            {admin && customModel !== "" && (
              <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); setModel(customModel.trim()); setCustomModel(""); }}>
                <Field label="Model ID"><input className="field w-64 font-mono" value={customModel} placeholder="claude-…" onChange={(e) => setCustomModel(e.target.value)} /></Field>
                <Button type="submit" disabled={!/^claude-[a-z0-9.-]{3,60}$/.test(customModel.trim())}>Use and test</Button>
              </form>
            )}
          </div>
          {!admin && <p className="text-xs text-muted">Only administrators can change the key or the model.</p>}
        </div>
      </Card>

      <Card>
        <CardHeader title="Enrichment providers" hint="The platform asks these services about an indicator or an owned asset. It never contacts the indicator itself." />
        {!data.reported && <p className="border-b border-line bg-warning-soft px-4 py-2 text-xs">The enrichment worker has not reported in yet, so keys set in <code className="font-mono">.env</code> are not shown. It reports within a minute of starting.</p>}
        <ul className="divide-y divide-line">
          {data.providers.map((p) => (
            <li key={p.name} className={cn("flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3", p.tier === "planned" && "opacity-70")}>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5 text-sm font-medium">{p.label}
                  <Badge tone={TIER[p.tier].tone}>{p.optional_key ? "Free · key optional" : TIER[p.tier].label}</Badge>
                  {p.tier !== "planned" && (p.enabled ? <Badge tone="good"><CheckCircle2 className="h-3 w-3" />On</Badge> : <Badge><CircleOff className="h-3 w-3" />Off: no key</Badge>)}
                  <span className="text-xs font-normal text-muted">{p.kinds.map((k) => IOC_LABELS[k] ?? k).join(" · ")}</span>
                </div>
                <p className="mt-0.5 text-xs text-muted">{p.about}</p>
                {p.takes_key && <KeyLine item={p} envName={p.env} />}
                {blocked(p.blocked_hosts)}
                {p.key_rejected && <p className="mt-2 rounded-md bg-sunken px-3 py-2 text-xs text-warning">Not in use: {p.key_rejected} It is skipped on lookups until a different key is saved or a test passes.</p>}
                {p.testable && (p.enabled || running[p.name] || p.last_test) && <TestLine state={running[p.name]} last={p.last_test} />}
              </div>
              {p.tier !== "planned" && (
                <div className="flex flex-wrap gap-1">
                  {canWrite && p.testable && p.enabled && <Button size="sm" disabled={running[p.name] === "running"} title="Make one real request and report whether it works" onClick={() => test(p.name)}><Send className="h-3.5 w-3.5" /> Test</Button>}
                  {p.takes_key && keyButtons(p)}
                </div>
              )}
            </li>
          ))}
        </ul>
        <p className="border-t border-line px-4 py-2 text-xs text-muted">Keys are encrypted at rest and used only by the enrichment worker, which has no database access and can reach nothing but the allow-listing egress proxy. They are never shown again after saving. Which hosts may be contacted at all stays in <code className="font-mono">.env</code> (EGRESS_ALLOW_HOSTS) on purpose: the application cannot widen its own network access.</p>
      </Card>

      <KeyDialog target={target} onClose={() => { setTarget(null); reload(); }} state={target ? running[target.name] : undefined} onSaved={watch} />
    </>
  );
}

function ApiAccess() {
  const { canWrite, me } = useSession();
  const toast = useToast();
  const { data, error, mutate } = useApi<ApiKey[]>("/api-keys");
  const { data: taxii } = useApi<{ collections: { id: string; title: string; description: string }[] }>("/taxii2/root/collections/");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", write: false, expires_days: 365 });
  const [created, setCreated] = useState<ApiKey | null>(null);
  const [importing, setImporting] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const { busy, run } = useAction();
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  const create = async () => {
    await run(async () => { const key = await api<ApiKey>("/api-keys", { method: "POST", body: { ...form, expires_days: form.expires_days || null } }); setCreated(key); setOpen(false); mutate(); });
  };
  const importBundle = async (f: File | undefined) => {
    if (!f) return;
    setImporting(true);
    try {
      const bundle = JSON.parse(await f.text());
      const out = await api<{ finding_id: string | null; entities: number; indicators: number; relationships: number; vulnerabilities: number }>("/stix/import", { method: "POST", body: bundle });
      toast(`Imported ${out.entities} entities, ${out.indicators} indicators, ${out.vulnerabilities} CVEs and ${out.relationships} relationships`);
    } catch (err) {
      toast(err instanceof SyntaxError ? "That file is not valid JSON" : err instanceof Error ? err.message : "Import failed", "critical");
    } finally { setImporting(false); if (file.current) file.current.value = ""; }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader title="Your API keys" hint={`Keys act as you (${me.role}). Send one as “Authorization: Bearer <key>”.`} action={<Button variant="primary" size="sm" onClick={() => { setForm({ name: "", write: false, expires_days: 365 }); setOpen(true); }}><Plus className="h-3.5 w-3.5" /> New key</Button>} />
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.length === 0 ? <Empty title="No API keys" hint="Create a read-only key to pull intelligence into a SIEM, a TIP or a script." /> : (
          <ul className="divide-y divide-line">
            {data.map((k) => (
              <li key={k.id} className={cn("flex items-center gap-3 px-4 py-2.5", k.revoked && "opacity-50")}>
                <KeyRound className="h-4 w-4 shrink-0 text-muted" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5 text-sm font-medium">{k.name}<Badge tone={k.scopes.includes("write") ? "warning" : "neutral"}>{k.scopes.includes("write") ? "Read and write" : "Read only"}</Badge>{k.revoked && <Badge tone="critical">Revoked</Badge>}</div>
                  <div className="text-xs text-muted"><span className="font-mono">{k.prefix}…</span> · created {ago(k.created_at)} · {k.last_used_at ? `last used ${ago(k.last_used_at)}` : "never used"}{k.expires_at ? ` · expires ${stamp(k.expires_at)}` : ""}</div>
                </div>
                {!k.revoked && <Button size="sm" variant="danger" onClick={() => confirm(`Revoke "${k.name}"? Anything using it stops working immediately.`) && run(() => api(`/api-keys/${k.id}`, { method: "DELETE" }), "Key revoked").then(() => mutate())}>Revoke</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <div className="space-y-4">
        <Card>
          <CardHeader title="TAXII 2.1 feed" hint="Read-only STIX 2.1 for SIEMs, TIPs and MISP. Authenticate with an API key." />
          <dl className="space-y-2 px-4 py-3 text-sm">
            <div><dt className="label">Discovery URL</dt><dd className="mt-0.5 flex items-center gap-1 font-mono text-xs">{origin}/api/taxii2/<CopyButton value={`${origin}/api/taxii2/`} /></dd></div>
            <div><dt className="label">API root</dt><dd className="mt-0.5 flex items-center gap-1 font-mono text-xs">{origin}/api/taxii2/root/<CopyButton value={`${origin}/api/taxii2/root/`} /></dd></div>
            <div><dt className="label">Credentials</dt><dd className="mt-0.5 text-xs text-ink-2">Bearer token, or HTTP Basic with any username and the API key as the password.</dd></div>
          </dl>
          <ul className="divide-y divide-line border-t border-line">
            {(taxii?.collections ?? []).map((c) => <li key={c.id} className="px-4 py-2"><div className="text-sm font-medium">{c.title}</div><div className="text-xs text-muted">{c.description}</div><div className="mt-0.5 flex items-center gap-1 font-mono text-2xs text-muted">{c.id}<CopyButton value={c.id} label="Copy collection ID" /></div></li>)}
          </ul>
        </Card>
        <Card>
          <CardHeader title="REST API and STIX" />
          <div className="space-y-2 px-4 py-3 text-sm text-ink-2">
            <p>Everything the console does goes through the same REST API under <code className="font-mono text-xs">{origin}/api</code>: search, findings, indicators, alerts, exposures, vulnerabilities and cases.</p>
            <pre className="scroll-thin overflow-x-auto rounded-md bg-sunken px-3 py-2 font-mono text-xs">{`curl -H "Authorization: Bearer $KIVULI_KEY" \\\n  "${origin}/api/search?q=type:ransomware+country:KE&size=20"`}</pre>
            <p className="text-xs text-muted">Cases export as STIX 2.1 bundles from the case page. Prometheus metrics are at <code className="font-mono">/api/metrics</code> (analyst or administrator key).</p>
            {canWrite && (
              <div className="border-t border-line pt-3">
                <input ref={file} type="file" accept=".json,application/json" className="hidden" aria-label="STIX bundle file" onChange={(e) => importBundle(e.target.files?.[0])} />
                <Button busy={importing} onClick={() => file.current?.click()}><Upload className="h-3.5 w-3.5" /> Import a STIX 2.1 bundle</Button>
                <p className="mt-1.5 text-xs text-muted">Actors, malware, techniques, indicators and their relationships are merged into what is already known, and the bundle is kept as a finding so its origin stays traceable. Up to 10 MB.</p>
              </div>
            )}
          </div>
        </Card>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title="New API key" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.name.trim().length < 2} onClick={create}>Create key</Button></>}>
        <div className="space-y-4">
          <Field label="Name" hint="What will use it, so you can recognise it later."><input className="field" value={form.name} placeholder="Splunk TAXII input" onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Expires"><select className="field" value={form.expires_days} onChange={(e) => setForm({ ...form, expires_days: Number(e.target.value) })}><option value={30}>In 30 days</option><option value={90}>In 90 days</option><option value={365}>In one year</option><option value={0}>Never</option></select></Field>
          {me.role !== "viewer" && <label className="flex items-start gap-2 text-sm text-ink-2"><input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.write} onChange={(e) => setForm({ ...form, write: e.target.checked })} /><span>Allow changes. <span className="text-muted">Off by default: a read-only key can search and export but cannot triage, edit or import.</span></span></label>}
        </div>
      </Modal>
      <Modal open={Boolean(created)} onClose={() => setCreated(null)} title="Copy your key now" footer={<Button variant="primary" onClick={() => setCreated(null)}>I have saved it</Button>}>
        <p className="mb-3 text-sm text-ink-2">This is the only time the key is shown. Only a hash of it is stored, so it cannot be recovered: if you lose it, revoke it and create another.</p>
        <div className="flex items-center gap-2 rounded-md border border-line bg-sunken px-3 py-2"><code className="min-w-0 flex-1 break-all font-mono text-xs">{created?.key}</code>{created?.key && <CopyButton value={created.key} label="Copy key" />}</div>
      </Modal>
    </div>
  );
}

export default function IntegrationsPage() {
  const { canWrite } = useSession();
  const [tab, setTab] = useState<"destinations" | "providers" | "api">(canWrite ? "destinations" : "providers");
  return (
    <>
      <PageHeader title="Integrations" subtitle={<>Send alerts out, bring context in, and let other tools read what the platform knows. For which alerts are raised in the first place, see <Link className="link" href="/watchlists">watchlists</Link> and <Link className="link" href="/rules">detection rules</Link>.</>} />
      <div className="mb-4"><Tabs value={tab} onChange={setTab} tabs={[...(canWrite ? [{ id: "destinations" as const, label: "Alert destinations" }] : []), { id: "providers", label: "Enrichment and AI" }, { id: "api", label: "API, TAXII and STIX" }]} /></div>
      {tab === "destinations" && canWrite && <Destinations />}
      {tab === "providers" && <ProviderList />}
      {tab === "api" && <ApiAccess />}
    </>
  );
}
