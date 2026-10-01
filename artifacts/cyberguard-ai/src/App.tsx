import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { ClerkProvider, Show, SignIn, SignUp, useClerk, useUser } from '@clerk/react';
import { publishableKeyFromHost } from '@clerk/react/internal';
import { shadcn } from '@clerk/themes';
import {
  Activity, AlertTriangle, BarChart3, Bot, ChevronRight, CircleHelp, Clock3,
  CloudUpload, Database, Filter, Fingerprint, HardDrive, HeartPulse, Laptop,
  Menu, Search, Send, ShieldAlert, ShieldCheck, Sparkles, Terminal, X
} from 'lucide-react';
import {
  getGetCyberguardAnalyticsQueryKey, getGetCyberguardDevicesQueryKey,
  getGetCyberguardEventsQueryKey, getGetCyberguardOverviewQueryKey,
  getGetCyberguardScanQueryKey,
  getGetCyberguardScansQueryKey, getGetCyberguardThreatsQueryKey,
  useAskCyberguardAssistant, useGetCyberguardAnalytics, useGetCyberguardDevices,
  useGetCyberguardEvents, useGetCyberguardOverview, useGetCyberguardScan,
  useGetCyberguardScans, useGetCyberguardThreats, useHealthCheck,
  useResetCyberguardDemo, useStartCyberguardScan, useUpdateCyberguardThreat,
  useUploadCyberguardEvents
} from '@workspace/api-client-react';
import { Link, Redirect, Route, Router as WouterRouter, Switch, useLocation } from 'wouter';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';

const queryClient = new QueryClient();
const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);
const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;
const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');
function stripBase(path: string) {
  return basePath && path.startsWith(basePath) ? path.slice(basePath.length) || '/' : path;
}
if (!clerkPubKey) throw new Error('Missing VITE_CLERK_PUBLISHABLE_KEY in .env file');

const clerkAppearance = {
  theme: shadcn,
  cssLayerName: 'clerk',
  options: {
    logoPlacement: 'inside' as const,
    logoLinkUrl: basePath || '/',
    logoImageUrl: `${window.location.origin}${basePath}/logo.svg`,
  },
  variables: {
    colorPrimary: '#56d7b7',
    colorForeground: '#dce6e8',
    colorMutedForeground: '#96a6ac',
    colorDanger: '#f27672',
    colorBackground: '#171f29',
    colorInput: '#101720',
    colorInputForeground: '#e4edef',
    colorNeutral: '#354450',
    fontFamily: 'Manrope, sans-serif',
    borderRadius: '0.7rem',
  },
  elements: {
    rootBox: 'w-full flex justify-center',
    cardBox: 'bg-[#171f29] rounded-2xl w-[440px] max-w-full overflow-hidden border border-[#354450]',
    card: '!shadow-none !border-0 !bg-transparent !rounded-none',
    footer: '!shadow-none !border-0 !bg-transparent !rounded-none',
    headerTitle: 'text-[#e4edef] font-extrabold tracking-tight',
    headerSubtitle: 'text-[#96a6ac]',
    socialButtonsBlockButtonText: 'text-[#dce6e8] font-semibold',
    formFieldLabel: 'text-[#dce6e8] font-semibold',
    footerActionLink: 'text-[#56d7b7] font-bold',
    footerActionText: 'text-[#96a6ac]',
    dividerText: 'text-[#96a6ac]',
    identityPreviewEditButton: 'text-[#56d7b7]',
    formFieldSuccessText: 'text-[#56d7b7]',
    alertText: 'text-[#f5b6ae]',
    logoBox: 'mb-2',
    logoImage: 'h-10 w-auto',
    socialButtonsBlockButton: 'border-[#354450] bg-[#101720] hover:bg-[#202c38]',
    formButtonPrimary: 'bg-[#56d7b7] text-[#101720] hover:bg-[#72e2c5] font-extrabold',
    formFieldInput: 'border-[#354450] bg-[#101720] text-[#e4edef]',
    footerAction: 'border-t border-[#354450]',
    dividerLine: 'bg-[#354450]',
    alert: 'border-[#f27672]/30 bg-[#f27672]/10',
    otpCodeFieldInput: 'border-[#354450] bg-[#101720] text-[#e4edef]',
    formFieldRow: 'gap-2',
    main: 'gap-5',
  },
};
const nav = [
  { href: '/dashboard', label: 'Overview', icon: Activity },
  { href: '/scans', label: 'Scans', icon: ShieldCheck },
  { href: '/logs', label: 'Event review', icon: Terminal },
  { href: '/threats', label: 'Findings', icon: ShieldAlert },
  { href: '/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/assistant', label: 'Assistant', icon: Bot },
  { href: '/devices', label: 'Devices', icon: Laptop },
];
const severityClass: Record<string, string> = {
  Critical: 'text-rose-300 bg-rose-400/10 border-rose-300/20',
  High: 'text-orange-200 bg-orange-400/10 border-orange-300/20',
  Medium: 'text-amber-200 bg-amber-400/10 border-amber-300/20',
  Low: 'text-teal-200 bg-teal-400/10 border-teal-300/20',
  Informational: 'text-slate-300 bg-slate-400/10 border-slate-300/20',
};
const fmt = (value?: string | null) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Not available';

function LogoutButton() {
  const { signOut } = useClerk();
  return <button type="button" onClick={() => signOut({ redirectUrl: basePath || '/' })} data-testid="button-sign-out" className="rounded-lg border border-border px-3 py-2 text-[11px] font-bold text-muted-foreground transition hover:border-rose-300/30 hover:text-rose-200">Sign out</button>;
}

function AppShell({ children }: { children: ReactNode }) {
  const [path] = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const { user, isLoaded } = useUser();
  const displayName = user?.fullName || user?.primaryEmailAddress?.emailAddress || 'Signed-in operator';
  const displayEmail = user?.primaryEmailAddress?.emailAddress || 'Authenticated session';
  const health = useHealthCheck();
  const reset = useResetCyberguardDemo();
  const qc = useQueryClient();
  const resetDemo = () => reset.mutate(undefined, { onSuccess: () => {
    [getGetCyberguardOverviewQueryKey(), getGetCyberguardEventsQueryKey(), getGetCyberguardThreatsQueryKey(), getGetCyberguardScansQueryKey(), getGetCyberguardDevicesQueryKey(), getGetCyberguardAnalyticsQueryKey()].forEach(queryKey => qc.invalidateQueries({ queryKey }));
  } });
  return <div className="min-h-[100dvh] bg-background text-foreground">
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-[244px] flex-col border-r border-border bg-[hsl(var(--sidebar))] px-4 py-5 transition-transform lg:translate-x-0 ${menuOpen ? 'translate-x-0' : '-translate-x-full'}`}>
      <Link href="/" className="mb-8 flex items-center gap-3 px-2" data-testid="link-brand">
        <span className="grid h-9 w-9 place-items-center overflow-hidden rounded-xl border border-primary/30 bg-primary/10"><img src={`${window.location.origin}${basePath}/logo.svg`} alt="CyberGuard AI mark" className="h-8 w-8" /></span>
        <span><span className="block text-[15px] font-extrabold tracking-tight text-foreground">CYBERGUARD<span className="text-primary"> AI</span></span><span className="eyebrow !text-[9px]">SOC workbench / M.Tech</span></span>
      </Link>
      <div className="mb-3 px-3 eyebrow">Workspace</div>
      <nav className="space-y-1" aria-label="Main navigation">{nav.map(({ href, label, icon: Icon }) => <Link key={href} href={href} onClick={() => setMenuOpen(false)} data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] font-semibold transition-colors ${path === href ? 'bg-primary/10 text-primary ring-1 ring-inset ring-primary/15' : 'text-muted-foreground hover:bg-white/[.04] hover:text-foreground'}`}><Icon size={16}/>{label}{path === href && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary"/>}</Link>)}</nav>
      <div className="mt-auto space-y-4">
        <div className="rounded-xl border border-border bg-white/[.025] p-3.5">
          <div className="flex items-center gap-2 text-xs font-bold"><span className={`h-1.5 w-1.5 rounded-full ${health.isError ? 'bg-rose-400' : 'bg-primary'}`}/>API {health.isLoading ? 'checking' : health.isError ? 'unavailable' : 'reachable'}</div>
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">Model state: <span className="text-foreground">not trained / not evaluated yet</span></p>
        </div>
        <button onClick={resetDemo} disabled={reset.isPending} data-testid="button-reset-demo" className="flex w-full items-center justify-center gap-2 rounded-lg border border-border px-3 py-2.5 text-xs font-semibold text-muted-foreground transition hover:border-primary/40 hover:text-foreground disabled:opacity-50"><Activity size={14}/>{reset.isPending ? 'Resetting sample…' : 'Reset simulated data'}</button>
        <div className="rounded-xl border border-border bg-white/[.025] p-3" data-testid="profile-sidebar">
          <div className="flex items-center gap-2.5">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full border border-primary/25 bg-primary/10 text-[10px] font-extrabold text-primary">{isLoaded ? displayName.slice(0, 1).toUpperCase() : '·'}</span>
            <span className="min-w-0"><span className="block truncate text-[11px] font-bold text-foreground">{isLoaded ? displayName : 'Loading profile'}</span><span className="block truncate text-[9px] text-muted-foreground">{isLoaded ? displayEmail : 'Checking session'}</span></span>
          </div>
        </div>
        <LogoutButton/>
        <div className="flex items-center justify-between px-2 text-[10px] text-muted-foreground"><span>CYBERGUARD / 0.1</span><span className="mono">LOCAL LAB</span></div>
      </div>
    </aside>
    {menuOpen && <button aria-label="Close menu" onClick={() => setMenuOpen(false)} className="fixed inset-0 z-30 bg-black/50 lg:hidden" data-testid="button-close-menu"/>}
    <main className="min-h-[100dvh] lg:pl-[244px]">
      <header className="sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-border bg-[hsl(var(--background)/.92)] px-4 backdrop-blur-xl sm:px-7">
        <div className="flex items-center gap-3"><button onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle navigation" data-testid="button-toggle-nav" className="rounded-lg p-2 text-muted-foreground hover:bg-white/5 lg:hidden"><Menu size={18}/></button><div><div className="text-sm font-bold">{nav.find(n => n.href === path)?.label ?? 'SOC workspace'}</div><div className="hidden text-[10px] text-muted-foreground sm:block">Stored telemetry review · no live monitoring</div></div></div>
        <div className="flex items-center gap-3"><span className="hidden rounded-full border border-amber-300/20 bg-amber-300/[.07] px-2.5 py-1 text-[10px] font-bold tracking-wide text-amber-200 sm:inline-flex">STORED TELEMETRY</span><div className="hidden items-center gap-2 rounded-lg border border-border px-2.5 py-1.5 sm:flex"><span className={`h-1.5 w-1.5 rounded-full ${health.isError ? 'bg-rose-400' : 'bg-primary'}`}/><span className="text-[10px] font-semibold text-muted-foreground">{health.isError ? 'API offline' : health.isLoading ? 'Checking API' : 'API available'}</span></div><div className="hidden max-w-36 truncate text-right text-[10px] font-semibold text-muted-foreground md:block" data-testid="profile-header-name">{displayName}</div></div>
      </header>
      <div className="mx-auto max-w-[1440px] p-4 sm:p-7 xl:px-9"><div className="mb-6 flex items-center gap-2 rounded-lg border border-amber-300/15 bg-amber-300/[.045] px-3.5 py-2.5 text-[11px] leading-relaxed text-amber-100/80" data-testid="notice-simulated-data"><Fingerprint size={14} className="shrink-0 text-amber-200"/>STORED TELEMETRY <span className="text-amber-100/45">/</span> Individual records are labeled when simulated. No live endpoint is connected; no model performance claims are available.</div>{children}</div>
    </main>
    <Toaster/>
  </div>;
}

function PageTitle({ kicker, title, desc, action }: { kicker: string; title: string; desc: string; action?: ReactNode }) {
  return <div className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end fade-up"><div><div className="eyebrow mb-2">{kicker}</div><h1 className="text-[26px] font-extrabold tracking-[-.045em] sm:text-[32px]">{title}</h1><p className="mt-1.5 max-w-2xl text-[13px] text-muted-foreground">{desc}</p></div>{action}</div>;
}
function Panel({ children, className = '' }: { children: ReactNode; className?: string }) { return <section className={`panel rounded-xl ${className}`}>{children}</section>; }
function PanelHead({ title, trailing }: { title: string; trailing?: ReactNode }) { return <div className="flex items-center justify-between border-b border-border px-4 py-3.5 sm:px-5"><h2 className="text-[13px] font-bold">{title}</h2>{trailing}</div>; }
function LoadingPanel({ label = 'Loading stored records' }: { label?: string }) { return <Panel className="p-5"><div className="mb-4 h-3 w-36 animate-pulse rounded bg-white/10"/><div className="space-y-3">{[1,2,3].map(n=><div key={n} className="h-10 animate-pulse rounded-lg bg-white/[.04]"/>)}<p className="pt-1 text-xs text-muted-foreground">{label}…</p></div></Panel>; }
function QueryError({ retry, label = 'Stored records could not be loaded.' }: { retry: () => void; label?: string }) { return <div className="rounded-xl border border-rose-300/20 bg-rose-400/[.06] p-5" data-testid="state-query-error"><div className="flex items-center gap-2 text-sm font-bold text-rose-200"><AlertTriangle size={16}/>{label}</div><p className="mt-1 text-xs text-muted-foreground">No substitute values are shown. Check the API connection and retry.</p><button onClick={retry} className="mt-3 rounded-md border border-rose-300/20 px-3 py-1.5 text-xs text-rose-100 hover:bg-rose-300/10" data-testid="button-retry">Retry request</button></div>; }
function Empty({ title, text }: { title: string; text: string }) { return <div className="flex min-h-44 flex-col items-center justify-center px-5 py-10 text-center" data-testid="state-empty"><span className="mb-3 grid h-10 w-10 place-items-center rounded-xl border border-border bg-white/[.025] text-muted-foreground"><Database size={17}/></span><p className="text-sm font-semibold">{title}</p><p className="mt-1 max-w-sm text-xs text-muted-foreground">{text}</p></div>; }
function Pill({ value }: { value: string }) { return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-[10px] font-bold ${severityClass[value] ?? 'border-border bg-white/[.04] text-muted-foreground'}`}>{value}</span>; }
function Metric({ label, value, icon: Icon, detail, accent = false }: { label: string; value: ReactNode; icon: typeof Activity; detail: string; accent?: boolean }) { return <Panel className="relative overflow-hidden p-4 sm:p-5"><div className={`absolute right-4 top-4 grid h-8 w-8 place-items-center rounded-lg ${accent ? 'bg-primary/10 text-primary' : 'bg-white/[.04] text-muted-foreground'}`}><Icon size={16}/></div><div className="eyebrow">{label}</div><div className="mt-3 text-[26px] font-extrabold tracking-tight">{value}</div><div className="mt-1 text-[11px] text-muted-foreground">{detail}</div></Panel>; }
function EventTable({ events }: { events: any[] }) {
  if (!events.length) return <Empty title="No events in this view" text="Try another query or ingest a CSV/JSON event batch." />;
  return <div className="overflow-x-auto"><table className="w-full min-w-[800px] text-left"><thead><tr className="border-b border-border text-[10px] uppercase tracking-[.12em] text-muted-foreground"><th className="px-5 py-3 font-medium">Event / time</th><th className="px-4 py-3 font-medium">Type</th><th className="px-4 py-3 font-medium">Actor / source</th><th className="px-4 py-3 font-medium">Severity</th><th className="px-4 py-3 font-medium">Evidence</th><th className="px-4 py-3 font-medium">Record</th></tr></thead><tbody>{events.map(e=><tr key={e.id} className="border-b border-border/70 last:border-0 hover:bg-white/[.018]" data-testid={`row-event-${e.id}`}><td className="px-5 py-3.5"><div className="mono text-[11px] text-primary">{e.eventId || e.id}</div><div className="mt-1 text-[10px] text-muted-foreground">{fmt(e.timestamp)}</div></td><td className="px-4 py-3.5 text-xs">{e.eventType}</td><td className="px-4 py-3.5"><div className="text-xs">{e.user || '—'}</div><div className="mono mt-1 text-[10px] text-muted-foreground">{e.sourceIp || '—'}</div></td><td className="px-4 py-3.5"><Pill value={e.severity || 'Informational'}/></td><td className="max-w-[230px] truncate px-4 py-3.5 text-xs text-muted-foreground" title={e.description}>{e.description}</td><td className="px-4 py-3.5"><span className="rounded border border-amber-300/15 px-1.5 py-1 text-[9px] text-amber-200">{e.simulated ? 'SIMULATED' : 'STORED'}</span></td></tr>)}</tbody></table></div>;
}

function OverviewPage() {
  const q = useGetCyberguardOverview();
  const overview = q.data;
  if (q.isLoading) return <><PageTitle kicker="Command / overview" title="Security posture" desc="A grounded view of ingested events and findings."/><LoadingPanel/></>;
  if (q.isError || !overview) return <><PageTitle kicker="Command / overview" title="Security posture" desc="A grounded view of ingested events and findings."/><QueryError retry={() => q.refetch()}/></>;
  const stats = [
    ['Events stored', overview.totalEvents, Database, 'All ingested records'],
    ['Active findings', overview.activeThreats, ShieldAlert, 'Open investigation states'],
    ['Anomalies today', overview.anomaliesToday, Activity, 'As recorded by API'],
    ['Failed logins', overview.failedLogins, Fingerprint, 'Stored event count'],
  ] as const;
  return <div className="fade-up"><PageTitle kicker="Command / overview" title="Security posture" desc="A grounded view of ingested events and findings." action={<Link href="/logs" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-extrabold text-primary-foreground hover:brightness-105" data-testid="link-review-events"><Search size={14}/>Review event evidence</Link>}/>
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{stats.map(([label, value, icon], i)=><Metric key={label} label={label} value={value} icon={icon} accent={i===1} detail={label === 'Events stored' ? 'Stored dataset' : 'Reported aggregate'}/>)}</div>
    <div className="mt-4 grid gap-4 xl:grid-cols-[1.4fr_.85fr]">
      <Panel><PanelHead title="Recent stored events" trailing={<Link href="/logs" className="text-[11px] font-bold text-primary" data-testid="link-all-events">View all →</Link>}/>{overview.recentEvents?.length ? <EventTable events={overview.recentEvents.slice(0,5)}/> : <Empty title="No recent event evidence" text="Ingest a simulated CSV or JSON event batch to begin review."/>}</Panel>
      <Panel><PanelHead title="Investigation queue" trailing={<Link href="/threats" className="text-[11px] font-bold text-primary" data-testid="link-all-findings">All findings →</Link>}/>{overview.recentThreats?.length ? <div className="divide-y divide-border">{overview.recentThreats.slice(0,5).map((t:any)=><Link key={t.id} href="/threats" className="block px-4 py-3.5 transition hover:bg-white/[.025]" data-testid={`row-overview-finding-${t.id}`}><div className="flex items-center justify-between gap-3"><span className="truncate text-xs font-bold">{t.title}</span><Pill value={t.severity}/></div><div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground"><span>{t.category} · {t.status}</span><span className="mono">{t.eventIds?.length ?? 0} evidence IDs</span></div></Link>)}</div> : <Empty title="No findings returned" text="Findings appear here only when present in stored API data."/>}</Panel>
    </div>
    <div className="mt-4 grid gap-4 md:grid-cols-3"><Panel className="p-4"><div className="eyebrow">Critical event count</div><div className="mt-2 text-xl font-bold">{overview.criticalEvents}</div><div className="mt-1 text-[11px] text-muted-foreground">Stored severity aggregate</div></Panel><Panel className="p-4"><div className="eyebrow">Endpoint readiness</div><div className="mt-2 flex items-center gap-2 text-sm font-bold"><span className="h-2 w-2 rounded-full bg-rose-300"/>No live device connected</div><p className="mt-1 text-[11px] text-muted-foreground">Reported state: {overview.deviceStatus || 'not available'} · demo only</p></Panel><Panel className="p-4"><div className="eyebrow">Model state</div><div className="mt-2 text-sm font-bold">{overview.modelStatus || 'Not trained / not evaluated yet'}</div><p className="mt-1 text-[11px] text-muted-foreground">No accuracy or efficacy claim is made.</p></Panel></div>
     <div className="mt-4 flex items-center gap-2 text-[10px] text-muted-foreground"><Clock3 size={13}/>Last scan: {fmt(overview.lastScan)} <span className="ml-2 text-amber-200">{overview.simulated ? 'All current records are simulated.' : 'Records include uploaded or mixed-source telemetry.'}</span></div>
  </div>;
}

function ScansPage() {
  const q = useGetCyberguardScans();
  const start = useStartCyberguardScan();
  const [scanId, setScanId] = useState('');
  const active = useGetCyberguardScan(scanId, { query: { enabled: !!scanId, queryKey: getGetCyberguardScanQueryKey(scanId), refetchInterval: scanId ? 1800 : false } });
  const launch = (type: 'quick' | 'deep') => start.mutate({ data: { type } }, { onSuccess: async scan => { setScanId(scan.id); await queryClient.invalidateQueries({ queryKey: getGetCyberguardScansQueryKey() }); } });
  const scan = active.data;
  return <div className="fade-up"><PageTitle kicker="Operations / scans" title="Scan history" desc="Launch a scan against available stored telemetry. Scans do not connect to live endpoints."/>
    <Panel className="mb-4"><PanelHead title="Launch analysis" trailing={<span className="eyebrow">SIMULATED DATA</span>}/><div className="grid gap-4 p-4 sm:grid-cols-[1fr_auto] sm:items-center sm:p-5"><div><div className="text-sm font-bold">Select scope for stored-event analysis</div><p className="mt-1 text-xs text-muted-foreground">Quick and Deep requests are recorded through the CyberGuard API; they are not endpoint actions.</p>{start.isError && <p className="mt-2 text-xs text-rose-200">Scan could not be started. No progress has been fabricated.</p>}</div><div className="flex gap-2"><button onClick={()=>launch('quick')} disabled={start.isPending} data-testid="button-start-quick-scan" className="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-xs font-bold hover:border-primary/50 disabled:opacity-50"><Activity size={14}/>Quick scan</button><button onClick={()=>launch('deep')} disabled={start.isPending} data-testid="button-start-deep-scan" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-extrabold text-primary-foreground disabled:opacity-50"><Sparkles size={14}/>Deep scan</button></div></div></Panel>
    {scanId && <Panel className="mb-4"><PanelHead title="Current scan progress" trailing={<span className="mono text-[10px] text-primary">{scan?.status ?? (active.isLoading ? 'connecting' : 'unavailable')}</span>}/>{active.isLoading ? <div className="p-5"><div className="h-2 animate-pulse rounded-full bg-white/10"/><div className="mt-3 text-xs text-muted-foreground">Awaiting stored scan status…</div></div> : scan ? <div className="p-5" data-testid="scan-progress"><div className="flex justify-between text-xs"><span>{scan.currentStage || scan.status}</span><span className="mono">{scan.progress}%</span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-white/[.07]"><div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{width:`${Math.max(0,Math.min(100,scan.progress))}%`}}/></div><div className="mt-3 flex flex-wrap gap-4 text-[11px] text-muted-foreground"><span>Type: {scan.type}</span><span>Threats: {scan.threats}</span><span>Anomalies: {scan.anomalies}</span><span>Model: {scan.modelStatus || 'not trained / not evaluated yet'}</span></div><span className="mt-3 inline-block text-[10px] text-amber-200">{scan.simulated ? 'SIMULATED DATA' : 'Stored scan record'}</span></div> : <div className="p-5 text-xs text-rose-200">Progress unavailable. Please retry by launching a scan.</div>}</Panel>}
    <Panel><PanelHead title="Recent scan records" trailing={q.data && <span className="eyebrow">{q.data.length} records</span>}/>{q.isLoading ? <LoadingPanel label="Loading scan records"/> : q.isError ? <QueryError retry={()=>q.refetch()}/> : !q.data?.length ? <Empty title="No scans recorded" text="Start a Quick or Deep scan to request analysis of stored telemetry."/> : <div className="overflow-x-auto"><table className="w-full min-w-[650px] text-left"><thead><tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground"><th className="px-5 py-3">Scan</th><th className="px-4 py-3">Started</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Progress</th><th className="px-4 py-3">Findings</th><th className="px-4 py-3">Data</th></tr></thead><tbody>{q.data.map((s:any)=><tr key={s.id} className="border-b border-border/60 text-xs last:border-0" data-testid={`row-scan-${s.id}`}><td className="px-5 py-3.5 font-bold uppercase">{s.type} <span className="mono ml-2 text-[10px] text-muted-foreground">{s.id}</span></td><td className="px-4 py-3.5 text-muted-foreground">{fmt(s.startedAt)}</td><td className="px-4 py-3.5">{s.status}</td><td className="px-4 py-3.5 mono">{s.progress}%</td><td className="px-4 py-3.5">{s.threats} threats · {s.anomalies} anomalies</td><td className="px-4 py-3.5 text-[10px] text-amber-200">{s.simulated ? 'SIMULATED' : 'stored'}</td></tr>)}</tbody></table></div>}</Panel>
  </div>;
}

function parseCsv(text: string) {
  const lines = text.trim().split(/\r?\n/);
  const headers = lines.shift()?.split(',').map(x=>x.trim().replace(/^"|"$/g,'')) ?? [];
  return lines.filter(Boolean).map(line => {
    const cells = line.match(/("(?:[^"]|"")*"|[^,]*)(,|$)/g)?.map(c=>c.replace(/,$/,'').replace(/^"|"$/g,'').replace(/""/g,'"')) ?? line.split(',');
    return Object.fromEntries(headers.map((h,i)=>[h,cells[i] ?? '']));
  });
}
function LogsPage() {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [feedback, setFeedback] = useState('');
  const [markUploadSimulated, setMarkUploadSimulated] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const params = useMemo(()=>({ search: search || undefined, severity: severity ? severity as any : undefined, limit: 200 }), [search,severity]);
  const q = useGetCyberguardEvents(params);
  const upload = useUploadCyberguardEvents();
  const ingestFile = async (file?: File) => {
    if (!file) return;
    try {
      const raw = await file.text();
      const parsed: unknown = file.name.toLowerCase().endsWith('.json') ? JSON.parse(raw) : parseCsv(raw);
      const parsedObject = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
      const rows: unknown[] = Array.isArray(parsed) ? parsed : Array.isArray(parsedObject?.events) ? parsedObject.events : [];
      if (!Array.isArray(rows) || !rows.length) throw new Error('The file must contain at least one event.');
      const events = rows.map((rawRow, index) => {
        const row = rawRow && typeof rawRow === 'object' && !Array.isArray(rawRow) ? rawRow as Record<string, unknown> : {};
        const value = (...keys: string[]) => {
          for (const key of keys) {
            if (row[key] != null && String(row[key]).trim()) return String(row[key]).trim();
          }
          return '';
        };
        const timestamp = value('timestamp', 'time', 'created_at');
        const eventId = value('eventId', 'event_id', 'id');
        const eventType = value('eventType', 'event_type', 'type');
        const user = value('user', 'username', 'actor');
        const sourceIp = value('sourceIp', 'source_ip', 'src_ip');
        const severity = value('severity');
        const status = value('status', 'result');
        const description = value('description', 'message');
        const missing = [
          ['timestamp', timestamp], ['eventId', eventId], ['eventType', eventType],
          ['user', user], ['sourceIp', sourceIp], ['severity', severity],
          ['status', status], ['description', description],
        ].filter(([, field]) => !field).map(([field]) => field);
        if (missing.length) throw new Error(`Row ${index + 1} is missing required fields: ${missing.join(', ')}.`);
        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) throw new Error(`Row ${index + 1} has an invalid timestamp.`);
        if (!['Critical', 'High', 'Medium', 'Low', 'Informational'].includes(severity)) throw new Error(`Row ${index + 1} has an unsupported severity.`);
        return {
          timestamp: date.toISOString(),
          eventId,
          eventType,
          user,
          sourceIp,
          destinationIp: value('destinationIp', 'destination_ip', 'dst_ip') || undefined,
          severity: severity as 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational',
          status,
          description,
          simulated: markUploadSimulated,
        };
      });
      upload.mutate({ data: { events } }, { onSuccess: async result => { setFeedback(`${result.accepted} accepted · ${result.rejected} duplicates skipped. ${result.simulated ? 'Upload labeled as simulated data.' : 'Stored as user-provided telemetry; source is not independently verified.'}`); await Promise.all([queryClient.invalidateQueries({queryKey:getGetCyberguardEventsQueryKey()}), queryClient.invalidateQueries({queryKey:getGetCyberguardOverviewQueryKey()}), queryClient.invalidateQueries({queryKey:getGetCyberguardAnalyticsQueryKey()}), queryClient.invalidateQueries({queryKey:getGetCyberguardThreatsQueryKey()})]); }, onError: () => setFeedback('Upload failed. No records were added.') });
    } catch (err) { setFeedback(err instanceof Error ? err.message : 'Could not parse the selected file.'); }
  };
   return <div className="fade-up"><PageTitle kicker="Evidence / event review" title="Stored event log" desc="Search imported telemetry and inspect evidence. Uploaded sources are not independently verified." action={<><input ref={inputRef} type="file" accept=".csv,.json,application/json,text/csv" className="hidden" onChange={e=>{ void ingestFile(e.target.files?.[0]); e.currentTarget.value=''; }} data-testid="input-event-upload"/><button onClick={()=>inputRef.current?.click()} disabled={upload.isPending} data-testid="button-upload-events" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-extrabold text-primary-foreground disabled:opacity-50"><CloudUpload size={15}/>{upload.isPending?'Uploading…':'Upload CSV / JSON'}</button></>}/>
   <label className="mb-4 flex cursor-pointer items-start gap-2.5 rounded-lg border border-border bg-white/[.025] px-3.5 py-3 text-[11px] leading-relaxed text-muted-foreground"><input type="checkbox" checked={markUploadSimulated} onChange={e=>setMarkUploadSimulated(e.target.checked)} className="mt-0.5 accent-[hsl(var(--primary))]" data-testid="checkbox-upload-simulated"/><span><strong className="text-foreground">These file records are simulated</strong><br/>Unchecked uploads are stored as user-provided telemetry. CyberGuard does not verify imported source data.</span></label>
    {feedback && <div className="mb-4 flex items-center justify-between rounded-lg border border-border bg-white/[.025] px-4 py-3 text-xs" data-testid="status-upload-result"><span>{feedback}</span><button onClick={()=>setFeedback('')} aria-label="Dismiss upload result"><X size={14}/></button></div>}
    <Panel className="mb-4"><div className="flex flex-col gap-3 p-3.5 sm:flex-row sm:items-center"><label className="relative flex-1"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search event IDs, actors, IPs…" data-testid="input-search-events" className="h-10 w-full rounded-lg border border-border bg-black/10 pl-9 pr-3 text-xs outline-none placeholder:text-muted-foreground/70 focus:border-primary/50"/></label><label className="flex items-center gap-2 rounded-lg border border-border px-3 text-muted-foreground"><Filter size={14}/><select value={severity} onChange={e=>setSeverity(e.target.value)} data-testid="select-filter-severity" className="h-10 bg-transparent text-xs text-foreground outline-none"><option value="">All severities</option>{['Critical','High','Medium','Low','Informational'].map(s=><option key={s}>{s}</option>)}</select></label><span className="eyebrow">{q.data?.length ?? '—'} matching</span></div></Panel>
    <Panel><PanelHead title="Event evidence" trailing={<span className="eyebrow">Up to 200 / query</span>}/>{q.isLoading ? <LoadingPanel label="Searching event records"/> : q.isError ? <QueryError retry={()=>q.refetch()}/> : <EventTable events={q.data ?? []}/>}</Panel>
  </div>;
}

function ThreatsPage() {
  const q = useGetCyberguardThreats();
  const update = useUpdateCyberguardThreat();
  const [selected, setSelected] = useState<any>(null);
  const changeStatus = (id:string,status:string) => update.mutate({threatId:id,data:{status:status as any}}, {onSuccess: async () => { await Promise.all([queryClient.invalidateQueries({queryKey:getGetCyberguardThreatsQueryKey()}),queryClient.invalidateQueries({queryKey:getGetCyberguardOverviewQueryKey()})]); }});
  return <div className="fade-up"><PageTitle kicker="Investigations / findings" title="Threat findings" desc="Each finding links to stored event IDs. Confidence is reported only when supplied by the API."/>
    <Panel><PanelHead title="Investigation queue" trailing={q.data && <span className="eyebrow">{q.data.length} findings</span>}/>{q.isLoading ? <LoadingPanel/> : q.isError ? <QueryError retry={()=>q.refetch()}/> : !q.data?.length ? <Empty title="No findings to investigate" text="The API has not returned threat findings. No detections are generated in the interface."/> : <div className="divide-y divide-border">{q.data.map((t:any)=><article key={t.id} className="grid gap-4 p-4 sm:grid-cols-[1fr_auto] sm:p-5" data-testid={`finding-${t.id}`}><div><div className="flex flex-wrap items-center gap-2"><Pill value={t.severity}/><span className="text-[10px] text-muted-foreground">{t.category} · {t.status}</span><span className="text-[9px] text-amber-200">{t.simulated?'SIMULATED DATA':'STORED RECORD'}</span></div><h3 className="mt-2 text-sm font-bold">{t.title}</h3><p className="mt-1 max-w-3xl text-xs leading-relaxed text-muted-foreground">{t.evidence}</p><div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground"><span>Source: {t.source}</span><span>·</span><span>{fmt(t.timestamp)}</span>{t.confidence != null && <><span>·</span><span>API confidence: {t.confidence}</span></>}</div><div className="mt-3 flex flex-wrap gap-1.5">{(t.eventIds ?? []).map((id:string)=><button key={id} onClick={()=>setSelected(t)} className="mono rounded border border-primary/20 bg-primary/[.06] px-2 py-1 text-[10px] text-primary hover:bg-primary/10" data-testid={`button-evidence-${t.id}-${id}`}>Evidence {id}</button>)}</div></div><div className="flex flex-row items-start gap-2 sm:flex-col sm:items-end"><select value={t.status} onChange={e=>changeStatus(t.id,e.target.value)} disabled={update.isPending} data-testid={`select-status-${t.id}`} className="rounded-lg border border-border bg-card px-2 py-2 text-xs outline-none focus:border-primary/50">{['New','Investigating','Resolved','Dismissed'].map(s=><option key={s}>{s}</option>)}</select><Link href="/logs" className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-2 text-[10px] font-bold text-muted-foreground hover:text-foreground" data-testid={`link-events-${t.id}`}>Open event log <ChevronRight size={12}/></Link></div></article>)}</div>}</Panel>
    {update.isError && <p className="mt-3 text-xs text-rose-200">Status update failed. The displayed status remains the last stored value.</p>}
    {selected && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 p-4" role="dialog" aria-modal="true"><Panel className="w-full max-w-md p-5"><div className="flex justify-between"><h2 className="font-bold">Evidence IDs</h2><button onClick={()=>setSelected(null)} aria-label="Close evidence"><X size={16}/></button></div><p className="mt-2 text-xs text-muted-foreground">Finding: {selected.title}</p><div className="mt-4 space-y-2">{selected.eventIds?.map((id:string)=><div key={id} className="mono rounded-lg border border-border px-3 py-2 text-xs">{id}</div>)}</div><Link href="/logs" onClick={()=>setSelected(null)} className="mt-4 inline-block text-xs font-bold text-primary">Review stored events →</Link></Panel></div>}
  </div>;
}

function AnalyticsPage() {
  const q = useGetCyberguardAnalytics();
  const data=q.data;
  if(q.isLoading) return <><PageTitle kicker="Observability / aggregates" title="Event analytics" desc="Descriptive aggregates computed from stored event records only."/><LoadingPanel/></>;
  if(q.isError || !data) return <><PageTitle kicker="Observability / aggregates" title="Event analytics" desc="Descriptive aggregates computed from stored event records only."/><QueryError retry={()=>q.refetch()}/></>;
  const maxHour=Math.max(1,...(data.eventsByHour ?? []).map(x=>x.count));
  const maxSev=Math.max(1,...(data.severityCounts ?? []).map(x=>x.count));
  const maxType=Math.max(1,...(data.eventTypeCounts ?? []).map(x=>x.count));
  return <div className="fade-up"><PageTitle kicker="Observability / aggregates" title="Event analytics" desc="Descriptive aggregates computed from stored event records only." action={<span className="rounded-full border border-amber-300/20 bg-amber-300/[.06] px-3 py-1.5 text-[10px] font-bold text-amber-200">{data.simulated ? 'SIMULATED DATA' : 'STORED TELEMETRY'}</span>}/>
    <div className="mb-4 grid gap-4 xl:grid-cols-[1.3fr_.7fr]"><Panel><PanelHead title="Events by hour" trailing={<span className="eyebrow">API aggregate · count</span>}/>{data.eventsByHour?.length ? <div className="flex h-56 items-end gap-2 overflow-x-auto px-5 pb-5 pt-6">{data.eventsByHour.map((item:any,i:number)=><div key={`${item.hour}-${i}`} className="flex h-full min-w-[28px] flex-1 flex-col items-center justify-end gap-2" data-testid={`bar-hour-${i}`}><span className="mono text-[9px] text-muted-foreground">{item.count}</span><div className="relative w-full max-w-12 rounded-t bg-primary/75" style={{height:`${Math.max(4,item.count/maxHour*74)}%`}}><div className="absolute bottom-0 w-full rounded-t bg-sky-200/80" style={{height:`${item.count ? item.anomalies/item.count*100 : 0}%`}}/></div><span className="mono text-[9px] text-muted-foreground">{item.hour}</span></div>)}</div> : <Empty title="No hourly aggregate" text="No hourly values were returned by the API."/>}</Panel>
      <Panel><PanelHead title="Severity distribution"/>{data.severityCounts?.length ? <div className="space-y-4 p-5">{data.severityCounts.map((it:any)=><div key={it.severity} data-testid={`metric-severity-${it.severity}`}><div className="mb-1.5 flex justify-between text-xs"><span>{it.severity}</span><span className="mono text-muted-foreground">{it.count}</span></div><div className="h-1.5 rounded-full bg-white/[.06]"><div className="h-full rounded-full bg-primary/80" style={{width:`${Math.max(3,it.count/maxSev*100)}%`}}/></div></div>)}</div> : <Empty title="No severity aggregate" text="The API did not return severity counts."/>}</Panel></div>
    <Panel><PanelHead title="Event types" trailing={<span className="eyebrow">Stored records</span>}/>{data.eventTypeCounts?.length ? <div className="grid gap-x-10 gap-y-4 p-5 sm:grid-cols-2">{data.eventTypeCounts.map((it:any)=><div key={it.eventType} data-testid={`metric-type-${it.eventType}`}><div className="mb-1.5 flex justify-between gap-4 text-xs"><span className="truncate">{it.eventType}</span><span className="mono text-muted-foreground">{it.count}</span></div><div className="h-1.5 rounded-full bg-white/[.06]"><div className="h-full rounded-full bg-sky-300/75" style={{width:`${Math.max(3,it.count/maxType*100)}%`}}/></div></div>)}</div> : <Empty title="No event type aggregate" text="No event types were returned by the API."/>}</Panel>
    <p className="mt-4 text-[11px] text-muted-foreground">These charts summarize stored events. They are not model evaluation metrics, detection rates, or security guarantees.</p>
  </div>;
}

function AssistantPage() {
  const [question,setQuestion]=useState('');
  const ask=useAskCyberguardAssistant();
  const send=(e:FormEvent)=>{e.preventDefault();if(!question.trim())return;ask.mutate({data:{question:question.trim()}},{onSuccess:()=>setQuestion('')});};
  return <div className="fade-up"><PageTitle kicker="Analysis / assistant" title="Evidence-grounded assistant" desc="Ask about the stored records. Answers should be treated as demo analysis and checked against their cited evidence."/>
    <div className="grid gap-4 xl:grid-cols-[1fr_300px]"><Panel className="flex min-h-[480px] flex-col"><PanelHead title="Conversation" trailing={<span className="inline-flex items-center gap-1.5 text-[10px] text-primary"><span className="h-1.5 w-1.5 rounded-full bg-primary"/>Evidence mode</span>}/><div className="flex-1 p-5">{!ask.data && !ask.isPending && <div className="flex h-full min-h-64 flex-col items-center justify-center text-center"><div className="mb-4 grid h-12 w-12 place-items-center rounded-2xl border border-primary/20 bg-primary/[.07] text-primary"><Bot size={22}/></div><h3 className="font-bold">Ask about recorded telemetry</h3><p className="mt-2 max-w-md text-xs leading-relaxed text-muted-foreground">Answers are grounded in available stored findings. If evidence is unavailable, the response should say so. No external or live data is queried.</p></div>}
      {ask.isPending && <div className="rounded-xl border border-border bg-white/[.025] p-4"><div className="mb-3 flex items-center gap-2 text-xs font-bold"><span className="h-2 w-2 animate-pulse rounded-full bg-primary"/>Reviewing stored evidence</div><div className="h-2 w-3/4 animate-pulse rounded bg-white/10"/><div className="mt-2 h-2 w-1/2 animate-pulse rounded bg-white/[.06]"/></div>}
      {ask.isError && <div className="rounded-lg border border-rose-300/20 bg-rose-400/[.05] p-4 text-xs text-rose-100" data-testid="assistant-error">Assistant request failed. No answer was generated. Please retry.</div>}
      {ask.data && <div className="space-y-4" data-testid="assistant-answer"><div className="rounded-xl border border-primary/20 bg-primary/[.045] p-4"><div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-primary"><Sparkles size={13}/>Grounded response {ask.data.simulated && '· simulated'}</div><p className="whitespace-pre-wrap text-sm leading-relaxed">{ask.data.answer}</p></div><div className="rounded-xl border border-border p-4"><div className="eyebrow mb-3">Evidence trail</div>{ask.data.evidenceAvailable && ask.data.evidenceIds?.length ? <div className="flex flex-wrap gap-2">{ask.data.evidenceIds.map((id:string)=><Link key={id} href="/logs" className="mono rounded-md border border-primary/20 bg-primary/[.05] px-2.5 py-1.5 text-[10px] text-primary" data-testid={`link-assistant-evidence-${id}`}>{id}</Link>)}</div> : <p className="text-xs text-muted-foreground">No evidence IDs were made available for this answer. Treat it as unverified; no supporting records are shown.</p>}</div></div>}
    </div><form onSubmit={send} className="border-t border-border p-4"><label className="sr-only" htmlFor="assistant-question">Question</label><div className="flex gap-2"><input id="assistant-question" maxLength={1000} value={question} onChange={e=>setQuestion(e.target.value)} placeholder="Ask about an event, finding, or evidence ID…" data-testid="input-assistant-question" className="h-11 min-w-0 flex-1 rounded-lg border border-border bg-black/10 px-3 text-xs outline-none placeholder:text-muted-foreground/70 focus:border-primary/50"/><button type="submit" disabled={!question.trim()||ask.isPending} data-testid="button-ask-assistant" className="grid h-11 w-11 place-items-center rounded-lg bg-primary text-primary-foreground disabled:opacity-40"><Send size={16}/></button></div></form></Panel>
    <div className="space-y-4"><Panel className="p-4"><div className="mb-3 flex items-center gap-2 text-xs font-bold"><CircleHelp size={15} className="text-primary"/>Good questions</div>{['Which stored events support the latest finding?','What evidence is available for failed logins?','Summarize events linked to an event ID.'].map((text,i)=><button key={text} onClick={()=>setQuestion(text)} className="mb-2 block w-full rounded-lg border border-border px-3 py-2.5 text-left text-[11px] leading-relaxed text-muted-foreground hover:border-primary/30 hover:text-foreground" data-testid={`button-suggest-question-${i}`}>{text}</button>)}</Panel><Panel className="p-4"><div className="eyebrow">Boundaries</div><ul className="mt-3 space-y-2 text-[11px] leading-relaxed text-muted-foreground"><li>• Stored context only</li><li>• Citations are event IDs, not proof of causality</li><li>• Model is not trained or evaluated</li><li>• No live endpoint actions</li></ul></Panel></div></div>
  </div>;
}

function DevicesPage() {
  const q=useGetCyberguardDevices();
  return <div className="fade-up"><PageTitle kicker="Environment / devices" title="Endpoint readiness" desc="Inventory records describe the demo dataset only. This workbench has no live endpoint connection."/>
    <div className="mb-4 flex gap-3 rounded-xl border border-rose-300/20 bg-rose-400/[.055] p-4" data-testid="status-live-device"><span className="mt-0.5 text-rose-200"><HardDrive size={17}/></span><div><div className="text-sm font-bold text-rose-100">No live device is connected</div><p className="mt-1 text-xs text-rose-100/65">Endpoint status below is API-reported sample metadata; it does not indicate a reachable or protected machine.</p></div></div>
    <Panel><PanelHead title="Device records" trailing={<span className="eyebrow">No live enrollment controls</span>}/>{q.isLoading?<LoadingPanel label="Loading device metadata"/>:q.isError?<QueryError retry={()=>q.refetch()}/>:!q.data?.length?<Empty title="No device records" text="The API returned no endpoint metadata. No device status has been inferred."/>:<div className="divide-y divide-border">{q.data.map((d:any)=><div key={d.id} className="grid gap-3 p-4 sm:grid-cols-[1fr_1fr_auto] sm:items-center sm:px-5" data-testid={`device-${d.id}`}><div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg border border-border text-muted-foreground"><Laptop size={16}/></div><div><div className="text-sm font-bold">{d.name}</div><div className="mt-1 text-[10px] text-muted-foreground">{d.operatingSystem}</div></div></div><div className="text-xs text-muted-foreground">Agent {d.agentVersion || 'not reported'}<div className="mt-1 text-[10px]">Last seen: {fmt(d.lastSeen)}</div></div><div className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-muted-foreground"/><span className="text-xs">{d.connectionStatus}</span><span className="rounded border border-amber-300/15 px-1.5 py-1 text-[9px] text-amber-200">{d.simulated?'SIMULATED':'METADATA'}</span></div></div>)}</div>}</Panel>
    <Panel className="mt-4 p-5"><div className="flex items-start gap-3"><HeartPulse className="mt-0.5 text-primary" size={17}/><div><div className="text-sm font-bold">Readiness, not protection</div><p className="mt-1 text-xs leading-relaxed text-muted-foreground">Device inventory and connection labels are descriptive fields from stored API data. No live telemetry, enforcement, agent heartbeat, or production security guarantee is represented.</p></div></div></Panel>
  </div>;
}

function AuthLoading() {
  return <div className="grid min-h-[100dvh] place-items-center bg-background px-4"><div className="w-full max-w-sm rounded-2xl border border-border bg-card p-6 text-center"><img src={`${window.location.origin}${basePath}/logo.svg`} alt="" className="mx-auto mb-4 h-10 w-10"/><div className="eyebrow">CyberGuard / session</div><p className="mt-2 text-sm font-bold">Checking operator access</p><div className="mx-auto mt-4 h-1 w-28 animate-pulse rounded-full bg-primary/50"/></div></div>;
}
function PublicLanding() {
  return <main className="relative min-h-[100dvh] overflow-hidden bg-background text-foreground">
    <div className="pointer-events-none absolute -right-44 -top-48 h-[620px] w-[620px] rounded-full border border-primary/[.08]"/>
    <div className="pointer-events-none absolute -right-20 -top-24 h-[380px] w-[380px] rounded-full border border-primary/[.1]"/>
    <header className="relative z-10 mx-auto flex max-w-7xl items-center justify-between px-5 py-5 sm:px-9">
      <Link href="/" className="flex items-center gap-3" data-testid="link-public-brand"><img src={`${window.location.origin}${basePath}/logo.svg`} alt="" className="h-10 w-10"/><span><span className="block text-sm font-extrabold tracking-tight">CYBERGUARD<span className="text-primary"> AI</span></span><span className="eyebrow !text-[9px]">M.Tech SOC workbench</span></span></Link>
      <div className="flex items-center gap-2"><Link href="/sign-in" className="rounded-lg px-3.5 py-2 text-xs font-bold text-muted-foreground hover:text-foreground" data-testid="link-sign-in">Sign in</Link><Link href="/sign-up" className="rounded-lg bg-primary px-4 py-2.5 text-xs font-extrabold text-primary-foreground hover:brightness-105" data-testid="link-sign-up">Create access</Link></div>
    </header>
    <section className="relative z-10 mx-auto grid max-w-7xl items-center gap-14 px-5 pb-20 pt-12 sm:px-9 lg:grid-cols-[1fr_.8fr] lg:pb-28 lg:pt-20">
      <div className="fade-up"><div className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/[.06] px-3 py-1.5 text-[10px] font-bold tracking-[.12em] text-primary"><span className="h-1.5 w-1.5 rounded-full bg-primary"/>SIMULATED TELEMETRY ENVIRONMENT</div><h1 className="max-w-3xl text-[44px] font-extrabold leading-[1.03] tracking-[-.055em] sm:text-6xl xl:text-[72px]">Investigate the signal.<br/><span className="text-primary">Keep the evidence.</span></h1><p className="mt-6 max-w-xl text-sm leading-7 text-muted-foreground sm:text-base">A focused security operations workbench for reviewing simulated endpoint events, tracing findings to records, and learning the investigative workflow.</p><div className="mt-8 flex flex-wrap gap-3"><Link href="/sign-up" className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-3 text-xs font-extrabold text-primary-foreground" data-testid="button-landing-create-account">Enter the workbench <ChevronRight size={15}/></Link><Link href="/sign-in" className="inline-flex items-center rounded-lg border border-border px-5 py-3 text-xs font-bold text-foreground hover:border-primary/40" data-testid="button-landing-sign-in">I already have access</Link></div><div className="mt-8 flex flex-wrap gap-x-5 gap-y-2 text-[10px] text-muted-foreground"><span className="inline-flex items-center gap-1.5"><ShieldCheck size={13} className="text-primary"/>Stored evidence first</span><span className="inline-flex items-center gap-1.5"><Database size={13} className="text-primary"/>Sample data labeled</span><span className="inline-flex items-center gap-1.5"><Fingerprint size={13} className="text-primary"/>No live endpoint</span></div></div>
      <div className="relative fade-up [animation-delay:100ms]"><div className="absolute -inset-8 rounded-[34px] bg-primary/[.035] blur-2xl"/><div className="panel relative overflow-hidden rounded-2xl p-4 sm:p-5"><div className="flex items-center justify-between border-b border-border pb-4"><div><div className="eyebrow">Telemetry / review stream</div><div className="mt-1 text-xs font-bold">Session replay · sample</div></div><span className="rounded-md border border-amber-300/20 bg-amber-300/[.06] px-2 py-1 text-[9px] font-bold text-amber-200">SIMULATED</span></div><div className="space-y-3 py-4">{[['14:23:08.441','AUTH_FAILURE','svc-backup','High'],['14:22:51.092','PROCESS_START','workstation-07','Informational'],['14:20:32.710','PRIVILEGE_CHANGE','ops-admin','Medium'],['14:18:09.226','AUTH_FAILURE','svc-backup','High']].map(([time,type,actor,level],i)=><div key={time} className="grid grid-cols-[84px_1fr_auto] items-center gap-3 rounded-lg border border-border/70 bg-black/[.1] px-3 py-3" data-testid={`landing-event-${i}`}><span className="mono text-[9px] text-muted-foreground">{time}</span><div className="min-w-0"><div className="mono truncate text-[10px] text-primary">{type}</div><div className="mt-1 truncate text-[10px] text-muted-foreground">{actor}</div></div><Pill value={level}/></div>)}</div><div className="grid grid-cols-2 gap-3 border-t border-border pt-4"><div className="rounded-lg bg-white/[.025] p-3"><div className="eyebrow !text-[9px]">Evidence links</div><div className="mono mt-1.5 text-sm text-primary">EVT-04A7</div></div><div className="rounded-lg bg-white/[.025] p-3"><div className="eyebrow !text-[9px]">Model lifecycle</div><div className="mt-1.5 text-xs font-bold">Not evaluated yet</div></div></div></div><div className="relative mt-4 flex items-center gap-3 px-2 text-[10px] leading-relaxed text-muted-foreground"><span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-border text-primary"><Activity size={13}/></span>Every sample record is clearly marked. The preview above is illustrative, not a live feed.</div></div>
    </section>
    <section className="border-y border-border bg-white/[.015]"><div className="mx-auto grid max-w-7xl gap-7 px-5 py-10 sm:px-9 md:grid-cols-3">{[['01 / Inspect','Search across stored event records.'],['02 / Investigate','Review findings against cited event IDs.'],['03 / Learn','Explore aggregates without overstating model capability.']].map(([title,copy])=><div key={title}><div className="eyebrow text-primary">{title}</div><p className="mt-2 text-sm font-semibold">{copy}</p></div>)}</div></section>
    <footer className="mx-auto flex max-w-7xl flex-col gap-2 px-5 py-7 text-[10px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-9"><span>CyberGuard AI · educational M.Tech SOC workbench</span><span>Simulated data only · model not trained or evaluated · no live device connected</span></footer>
  </main>;
}
function HomeRoute() {
  const { isLoaded } = useUser();
  if (!isLoaded) return <AuthLoading/>;
  return <><Show when="signed-in"><Redirect to="/dashboard"/></Show><Show when="signed-out"><PublicLanding/></Show></>;
}
function SignInRoute() {
  const { isLoaded } = useUser();
  if (!isLoaded) return <AuthLoading/>;
  return <><Show when="signed-in"><Redirect to="/dashboard"/></Show><Show when="signed-out"><main className="relative grid min-h-[100dvh] place-items-center overflow-hidden bg-background px-4 py-10"><div className="absolute left-[-180px] top-[-180px] h-[450px] w-[450px] rounded-full border border-primary/[.08]"/><div className="relative z-10 w-full"><div className="mb-6 text-center"><div className="eyebrow">SECURE WORKSPACE ACCESS</div><p className="mt-2 text-xs text-muted-foreground">Sign in to review stored CyberGuard telemetry.</p></div><SignIn routing="path" path={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`}/><p className="mx-auto mt-5 max-w-[440px] text-center text-[10px] leading-relaxed text-muted-foreground">Access is for the CyberGuard AI educational workbench. Telemetry in this environment is simulated.</p></div></main></Show></>;
}
function SignUpRoute() {
  const { isLoaded } = useUser();
  if (!isLoaded) return <AuthLoading/>;
  return <><Show when="signed-in"><Redirect to="/dashboard"/></Show><Show when="signed-out"><main className="relative grid min-h-[100dvh] place-items-center overflow-hidden bg-background px-4 py-10"><div className="absolute bottom-[-220px] right-[-150px] h-[520px] w-[520px] rounded-full border border-primary/[.08]"/><div className="relative z-10 w-full"><div className="mb-6 text-center"><div className="eyebrow">CREATE OPERATOR ACCESS</div><p className="mt-2 text-xs text-muted-foreground">Set up an account for your SOC learning workspace.</p></div><SignUp routing="path" path={`${basePath}/sign-up`} signInUrl={`${basePath}/sign-in`}/><p className="mx-auto mt-5 max-w-[440px] text-center text-[10px] leading-relaxed text-muted-foreground">Demo telemetry only. No endpoint is enrolled or protected by creating an account.</p></div></main></Show></>;
}
function NotFoundPage() {
  return <div className="fade-up"><PageTitle kicker="Workspace / route" title="Page not found" desc="This route is not part of the CyberGuard workbench."/><Empty title="No page at this address" text="Use the navigation to return to a stored telemetry view."/></div>;
}
function PrivateRoutes() {
  const [location] = useLocation();
  return <><Show when="signed-in"><ErrorBoundary resetKey={location}><AppShell><Switch>
    <Route path="/dashboard" component={OverviewPage}/><Route path="/scans" component={ScansPage}/><Route path="/logs" component={LogsPage}/><Route path="/threats" component={ThreatsPage}/><Route path="/analytics" component={AnalyticsPage}/><Route path="/assistant" component={AssistantPage}/><Route path="/devices" component={DevicesPage}/><Route component={NotFoundPage}/>
  </Switch></AppShell></ErrorBoundary></Show><Show when="signed-out"><Redirect to="/"/></Show></>;
}
function ClerkQueryCacheInvalidator() {
  const { addListener } = useClerk();
  const qc = useQueryClient();
  const previousUserId = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    const unsubscribe = addListener(({ user }) => {
      const currentUserId = user?.id ?? null;
      if (previousUserId.current !== undefined && previousUserId.current !== currentUserId) qc.clear();
      previousUserId.current = currentUserId;
    });
    return unsubscribe;
  }, [addListener, qc]);
  return null;
}
function ClerkAppRoutes() {
  const [, setLocation] = useLocation();
  return <ClerkProvider
    publishableKey={clerkPubKey}
    proxyUrl={clerkProxyUrl}
    appearance={clerkAppearance}
    signInUrl={`${basePath}/sign-in`}
    signUpUrl={`${basePath}/sign-up`}
    localization={{
      signIn: { start: { title: 'Welcome back', subtitle: 'Sign in to review your CyberGuard workspace.' } },
      signUp: { start: { title: 'Create operator access', subtitle: 'Set up your CyberGuard learning workspace.' } },
    }}
    routerPush={(to) => setLocation(stripBase(to))}
    routerReplace={(to) => setLocation(stripBase(to), { replace: true })}
  >
    <ClerkQueryCacheInvalidator/>
    <Switch><Route path="/" component={HomeRoute}/><Route path="/sign-in/*?" component={SignInRoute}/><Route path="/sign-up/*?" component={SignUpRoute}/><Route component={PrivateRoutes}/></Switch>
  </ClerkProvider>;
}
function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={basePath}><ClerkAppRoutes/></WouterRouter></TooltipProvider></QueryClientProvider>;
}
export default App;