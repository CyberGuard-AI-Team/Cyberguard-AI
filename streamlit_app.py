from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from sklearn.ensemble import IsolationForest


st.set_page_config(page_title="CyberGuard AI | SOC Workbench", page_icon="🛡️", layout="wide")

NAV = ["Overview", "Scans", "Event review", "Findings", "Investigations", "Analytics", "ML Lab", "Assistant", "Devices"]
PAGE_LABELS = {"Overview": "Home", "About CyberGuard": "About CyberGuard", "Scans": "Check my activity", "Event review": "Activity history", "Findings": "What needs attention", "Investigations": "My follow-ups", "Analytics": "Activity summary", "ML Lab": "Smart analysis", "Assistant": "Ask CyberGuard", "Devices": "Connect my PC"}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
COLORS = {"Critical": "#fb7185", "High": "#fb923c", "Medium": "#fbbf24", "Low": "#56d7b7", "Informational": "#94a3b8"}
INDIA_TZ = ZoneInfo("Asia/Kolkata")


def local_time(value: datetime, fmt: str = "%d %b %Y, %I:%M %p IST") -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(INDIA_TZ).strftime(fmt)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --cg-bg:#101720; --cg-panel:#171f29; --cg-border:#2b3946; --cg-teal:#56d7b7; --cg-muted:#96a6ac; }
html, body, [class*="css"] { font-family:Manrope, sans-serif; }
.stApp { background:radial-gradient(ellipse at 78% -12%,#18352f 0,transparent 35%),var(--cg-bg); color:#dce6e8; }
section[data-testid="stSidebar"] { background:#121a23; border-right:1px solid var(--cg-border); }
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#dce6e8; }
h1,h2,h3 { letter-spacing:-.04em; }
.cg-brand { font-size:16px;font-weight:800;letter-spacing:-.04em; }
.cg-brand span { color:var(--cg-teal); }
.cg-eyebrow { color:var(--cg-muted);font-size:10px;font-weight:800;letter-spacing:.13em;text-transform:uppercase; }
.cg-notice { border:1px solid #fbbf2430;background:#fbbf240b;color:#f5d98e;border-radius:10px;padding:12px 15px;font-size:12px;margin:4px 0 22px; }
.cg-card { background:linear-gradient(145deg,#19232d,#151e27);border:1px solid var(--cg-border);border-radius:14px;padding:18px 20px;margin-bottom:12px; }
.cg-metric { background:linear-gradient(145deg,#19232d,#151e27);border:1px solid var(--cg-border);border-radius:14px;padding:18px 20px;min-height:125px; }
.cg-metric-label { color:var(--cg-muted);font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase; }
.cg-metric-value { font-size:30px;font-weight:800;letter-spacing:-.05em;margin-top:12px; }
.cg-metric-detail { color:var(--cg-muted);font-size:11px;margin-top:2px; }
.cg-pill { display:inline-block;border-radius:6px;padding:4px 8px;font-size:10px;font-weight:800;border:1px solid currentColor; }
.cg-mono { font-family:'DM Mono',monospace; }
.cg-scan-visual { display:flex;align-items:center;gap:16px;border:1px solid #56d7b733;background:linear-gradient(120deg,#56d7b70c,#171f29);border-radius:13px;padding:16px 18px;margin:10px 0 14px; }
.cg-radar { position:relative;width:46px;height:46px;flex:none;border:1px solid #56d7b766;border-radius:50%;overflow:hidden;background:radial-gradient(circle,#56d7b722 0 2px,transparent 3px),linear-gradient(90deg,transparent 49%,#56d7b733 50%,transparent 51%),linear-gradient(0deg,transparent 49%,#56d7b733 50%,transparent 51%); }
.cg-radar:before { content:'';position:absolute;inset:2px;border-radius:50%;background:conic-gradient(from 0deg,transparent 0 72%,#56d7b799 100%);animation:cg-sweep 1.5s linear infinite; }
.cg-radar:after { content:'';position:absolute;left:50%;top:50%;width:6px;height:6px;transform:translate(-50%,-50%);border-radius:50%;background:#56d7b7;box-shadow:0 0 12px #56d7b7;animation:cg-pulse 1s ease-in-out infinite alternate; }
@keyframes cg-sweep { to { transform:rotate(360deg); } }
@keyframes cg-pulse { to { opacity:.35;box-shadow:0 0 3px #56d7b7; } }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#19232d,#151e27);border:1px solid var(--cg-border);border-radius:14px;padding:14px 17px; }
div[data-testid="stMetricLabel"] p { color:var(--cg-muted);font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.1em; }
div[data-testid="stMetricValue"] { font-weight:800; }
.stButton button[kind="primary"] { background:#56d7b7;border:0;color:#101720;font-weight:800; }
.stButton button { border-radius:9px;transition:transform .16s ease,box-shadow .16s ease,border-color .16s ease; }
.stButton button:hover { transform:translateY(-1px);box-shadow:0 8px 24px #0004;border-color:#56d7b766; }
[data-testid="stTabs"] button[aria-selected="true"] { color:var(--cg-teal); }
[data-testid="stDataFrame"] { border:1px solid var(--cg-border);border-radius:10px;overflow:hidden; }
footer { visibility:hidden; }
</style>
""", unsafe_allow_html=True)


def make_demo_events() -> list[dict]:
    now = datetime.now(timezone.utc)
    templates = [
        ("4624", "Successful Login", "j.wells", "Low", "Success", "Interactive sign-in completed from a known private network.", "10.20.1.15"),
        ("4688", "Process Start", "SYSTEM", "Informational", "Observed", "A signed operating-system service process started.", "127.0.0.1"),
        ("5156", "Network Connection", "SYSTEM", "Informational", "Allowed", "An outbound connection was permitted by the local firewall.", "10.20.1.15"),
        ("4624", "Successful Login", "svc-backup", "Low", "Success", "A scheduled service account sign-in completed.", "10.20.1.26"),
        ("5158", "Port Activity", "SYSTEM", "Low", "Observed", "A local process bound to an ephemeral port.", "10.20.1.15"),
    ]
    events = []
    for i in range(38):
        eid, typ, user, severity, status, desc, ip = templates[i % len(templates)]
        events.append({"id": f"evt-{uuid.uuid4().hex[:10]}", "timestamp": now - timedelta(minutes=28 + i * 34), "eventId": eid, "eventType": typ, "user": user, "sourceIp": ip, "destinationIp": "192.0.2.40" if typ == "Network Connection" else "", "severity": severity, "status": status, "description": desc, "simulated": True})
    ip = "198.51.100.23"
    for i in range(9):
        events.append({"id": f"evt-{uuid.uuid4().hex[:10]}", "timestamp": now - timedelta(minutes=36 - i * 2), "eventId": "4625", "eventType": "Failed Login", "user": "j.wells", "sourceIp": ip, "destinationIp": "", "severity": "Medium", "status": "Failed", "description": "A Windows Security log records a failed sign-in attempt. This event is simulated.", "simulated": True})
    for eid, typ, severity, status, desc, ago in [
        ("4624", "Successful Login", "High", "Success", "A successful sign-in followed the simulated failed-login burst from the same address.", 16),
        ("4672", "Privilege Change", "High", "Observed", "A privileged sign-in token was assigned shortly after the simulated authentication sequence.", 14),
    ]:
        events.append({"id": f"evt-{uuid.uuid4().hex[:10]}", "timestamp": now - timedelta(minutes=ago), "eventId": eid, "eventType": typ, "user": "j.wells", "sourceIp": ip, "destinationIp": "", "severity": severity, "status": status, "description": desc, "simulated": True})
    return sorted(events, key=lambda row: row["timestamp"], reverse=True)


def findings_from_events(events: list[dict]) -> list[dict]:
    failed = [e for e in events if e["eventType"].lower() == "failed login"]
    groups: dict[str, list[dict]] = {}
    for e in failed:
        groups.setdefault(e.get("sourceIp") or e.get("user", "unknown"), []).append(e)
    findings = []
    for ip, rows in groups.items():
        rows.sort(key=lambda e: e["timestamp"])
        burst = next((window for i, first in enumerate(rows) if (window := [e for e in rows[i:] if e["timestamp"] <= first["timestamp"] + timedelta(minutes=15)]) and len(window) >= 5), [])
        if not burst:
            continue
        last = burst[-1]["timestamp"]
        follow = [e for e in events if e.get("sourceIp") == ip and last <= e["timestamp"] <= last + timedelta(hours=1) and e["eventType"] in ("Successful Login", "Privilege Change")]
        success = any(e["eventType"] == "Successful Login" for e in follow)
        privileged = any(e["eventType"] == "Privilege Change" for e in follow)
        finding_title = "Several sign-in attempts failed, then one succeeded" if success else "Several sign-in attempts failed in a short time"
        plain_summary = f"We found {len(burst)} failed sign-in attempts from {ip} within 15 minutes" + (", followed by a successful sign-in" if success else "") + (" and an account-permission change" if privileged else "") + "."
        next_steps = ("If this was not you, change the account password, sign out other sessions, and ask your IT support team to review the sign-in." if success else "If these attempts were not yours, change the account password and enable multi-factor authentication.")
        findings.append({"id": f"finding-{ip}", "timestamp": last, "title": finding_title, "plain_summary": plain_summary, "next_steps": next_steps, "category": "Sign-in activity", "severity": "High" if success and privileged else "Medium", "source": "SIMULATED DATA · Endpoint simulator" if all(e["simulated"] for e in burst + follow) else "Collected telemetry", "evidence": plain_summary + " This is an automated rule match, not proof that someone accessed the device.", "status": "New", "eventIds": [e["id"] for e in burst + follow], "simulated": all(e["simulated"] for e in burst + follow)})
    return findings


def set_page(page: str) -> None:
    st.session_state.workspace_page = page


FEATURE_GUIDES = {
    "Overview": ("Your starting point", "See the most important thing to do next, recent activity, and quick links to the right page."),
    "Scans": ("Check my activity", "Runs a guided review of the activity already in this workspace and turns it into easy-to-read results."),
    "Event review": ("Activity history", "Search or upload activity records, then open an item to understand what happened."),
    "Findings": ("What needs attention", "Shows possible security concerns in plain language, along with the safest next action."),
    "Investigations": ("My follow-ups", "Keep a simple record of what you checked, who is handling it, and what should happen next."),
    "Analytics": ("Activity summary", "Shows patterns in your activity over time so you can spot changes without reading every record."),
    "ML Lab": ("Smart analysis", "Uses an AI model to find activity that differs from the usual pattern and explains why it stood out."),
    "Assistant": ("Ask CyberGuard", "Ask everyday questions about the activity shown in this workspace and get a simple answer."),
    "Devices": ("Connect my PC", "When run locally on Windows, this can bring selected Windows Event Log activity into the workspace."),
}


def show_feature_guide(feature: str) -> None:
    title, description = FEATURE_GUIDES[feature]
    with st.expander(f"About {title}", expanded=False):
        st.markdown(f"**What it does:** {description}\n\n**How to use it:** Start with the information on this page, then use the buttons or filters to focus on what matters to you.\n\n**What to do with the result:** If you see something you do not recognise, open it, read the recommended next step, and contact your IT support team if needed.")


def in_window(event: dict, window: str) -> bool:
    if window == "All records":
        return True
    hours = 24 if window == "Past 24 hours" else 24 * 7
    stamp = event["timestamp"]
    if not isinstance(stamp, datetime):
        stamp = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    return stamp >= datetime.now(timezone.utc) - timedelta(hours=hours)


def anomaly_scores(events: list[dict], contamination: float) -> pd.DataFrame:
    """Score stored telemetry with an unsupervised Isolation Forest model."""
    frame = pd.DataFrame(events).copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame["hour"] = frame["timestamp"].dt.hour
    frame["severity_weight"] = frame["severity"].map({"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}).fillna(0)
    frame["type_frequency"] = frame.groupby("eventType")["eventType"].transform("size")
    frame["actor_frequency"] = frame.groupby("user")["user"].transform("size")
    frame["source_frequency"] = frame.groupby("sourceIp")["sourceIp"].transform("size")
    encoded = pd.get_dummies(frame[["eventType", "user", "sourceIp", "status"]].fillna("unknown"), dtype=float)
    numeric = frame[["hour", "severity_weight", "type_frequency", "actor_frequency", "source_frequency"]].astype(float)
    features = pd.concat([numeric, encoded], axis=1)
    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=200)
    prediction = model.fit_predict(features)
    raw_score = -model.decision_function(features)
    scale = raw_score.max() - raw_score.min()
    frame["anomaly_score"] = 50.0 if scale == 0 else ((raw_score - raw_score.min()) / scale * 100)
    frame["model_label"] = ["Anomalous" if value == -1 else "Baseline" for value in prediction]

    def explain(row: pd.Series) -> str:
        reasons = []
        if row["source_frequency"] <= 1 and row["sourceIp"]:
            reasons.append("rare source address")
        if row["actor_frequency"] <= 1 and row["user"]:
            reasons.append("rare account activity")
        if row["type_frequency"] <= 1:
            reasons.append("rare event type")
        if row["hour"] < 6 or row["hour"] > 22:
            reasons.append("unusual time of day")
        return ", ".join(reasons) if reasons else "combination of event attributes differs from the baseline"

    frame["explanation"] = frame.apply(explain, axis=1)
    result = frame[["id", "timestamp", "eventType", "user", "sourceIp", "severity", "anomaly_score", "model_label", "explanation"]].copy()
    result["timestamp"] = result["timestamp"].apply(local_time)
    return result.sort_values("anomaly_score", ascending=False)


def local_db() -> sqlite3.Connection:
    conn = sqlite3.connect("cyberguard-local.db")
    conn.execute("CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, finding_id TEXT, title TEXT, status TEXT, owner TEXT, notes TEXT, updated_at TEXT)")
    conn.commit()
    return conn


def browser_case_workspace(findings: list[dict]) -> None:
    """Host a browser-local investigation workspace without transmitting case notes."""
    cases = [{"id": f"case-{finding['id']}", "title": finding["title"], "summary": finding.get("plain_summary", finding["evidence"])} for finding in findings]
    payload = json.dumps(cases).replace("</", "<\\/")
    markup = f'''<!doctype html><html><head><style>
      * {{ box-sizing:border-box }} body {{ margin:0;background:#101720;color:#dce6e8;font-family:system-ui,sans-serif }}
      .toolbar,.case {{ border:1px solid #2b3946;background:#171f29;border-radius:12px;padding:15px;margin-bottom:12px }}
      h3 {{ margin:0 0 6px;font-size:16px }} p,label {{ color:#aebdc2;font-size:13px }}
      .grid {{ display:grid;grid-template-columns:150px 1fr;gap:10px;margin-top:12px }}
      input,select,textarea {{ width:100%;background:#101720;color:#dce6e8;border:1px solid #41515e;border-radius:7px;padding:8px;font:inherit }}
      textarea {{ min-height:80px;resize:vertical }} button {{ background:#56d7b7;color:#101720;border:0;border-radius:8px;padding:9px 12px;font-weight:700;cursor:pointer }}
      .muted {{ color:#96a6ac;font-size:12px }} @media(max-width:560px) {{ .grid {{ grid-template-columns:1fr }} }}
    </style></head><body><div class="toolbar"><b>Investigation workspace</b><p>Cases are saved in this browser. Export the report when you are done.</p><button id="export">Download case report (CSV)</button></div><div id="cases"></div>
    <script>
      const seed = {payload}; const key = 'cyberguard-investigations-v1';
      const saved = JSON.parse(localStorage.getItem(key) || '{{}}');
      seed.forEach(item => {{ if (!saved[item.id]) saved[item.id] = {{...item, status:'New', owner:'Unassigned', notes:'', updated:''}}; }});
      const persist = () => localStorage.setItem(key, JSON.stringify(saved));
      const esc = value => String(value || '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
      function render() {{
        document.querySelector('#cases').innerHTML = Object.values(saved).map(item => `<section class="case"><h3>${{esc(item.title)}}</h3><p>${{esc(item.summary)}}</p><div class="grid"><label>Case status<select data-id="${{item.id}}" data-field="status">${{['New','Investigating','Resolved','Dismissed'].map(x=>`<option ${{x===item.status?'selected':''}}>${{x}}</option>`).join('')}}</select></label><label>Assigned to<input data-id="${{item.id}}" data-field="owner" value="${{esc(item.owner)}}"></label></div><label>Investigation notes<textarea data-id="${{item.id}}" data-field="notes" placeholder="What did you check? What happens next?">${{esc(item.notes)}}</textarea></label><p class="muted">Last saved: ${{item.updated || 'Not yet saved'}}</p></section>`).join('');
        document.querySelectorAll('[data-field]').forEach(el => el.addEventListener('input', event => {{ const item=saved[event.target.dataset.id]; item[event.target.dataset.field]=event.target.value; item.updated=new Date().toLocaleString('en-IN'); persist(); render(); }}));
      }}
      document.querySelector('#export').addEventListener('click', () => {{ const rows=[['Case ID','Finding','Status','Assigned to','Notes','Updated'],...Object.values(saved).map(x=>[x.id,x.title,x.status,x.owner,x.notes,x.updated])]; const csv=rows.map(row=>row.map(x=>'"'+String(x).replaceAll('"','""')+'"').join(',')).join('\n'); const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{{type:'text/csv'}})); a.download='cyberguard-investigations.csv'; a.click(); }});
      render();
    </script></body></html>'''
    components.html(markup, height=max(280, 235 * len(cases) + 110), scrolling=True)


if "events" not in st.session_state:
    st.session_state.events = make_demo_events()
if "findings" not in st.session_state:
    st.session_state.findings = findings_from_events(st.session_state.events)
if "scans" not in st.session_state:
    st.session_state.scans = []
if "chat" not in st.session_state:
    st.session_state.chat = []
if "local_collection_meta" not in st.session_state:
    st.session_state.local_collection_meta = None

events: list[dict] = st.session_state.events
findings: list[dict] = st.session_state.findings
active_findings = sum(f["status"] in ("New", "Investigating") for f in findings)

if "workspace_page" not in st.session_state:
    st.session_state.workspace_page = "Overview"
if "sidebar_page" not in st.session_state:
    st.session_state.sidebar_page = st.session_state.workspace_page if st.session_state.workspace_page in NAV else "Overview"


def select_workspace_page() -> None:
    st.session_state.workspace_page = st.session_state.sidebar_page

with st.sidebar:
    st.markdown('<div class="cg-brand">CYBERGUARD<span> AI</span></div><div class="cg-eyebrow">SOC workbench / M.Tech</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    st.radio("MENU", NAV, format_func=lambda item: PAGE_LABELS[item], label_visibility="visible", key="sidebar_page", on_change=select_workspace_page)
    st.markdown("---")
    st.markdown("<div class='cg-eyebrow'>MODEL / ANALYTICS</div><p style='font-size:12px;color:#56d7b7'>● Telemetry workspace ready</p><p style='font-size:11px;color:#96a6ac'>Isolation Forest · unsupervised anomaly scoring</p>", unsafe_allow_html=True)
    if st.button("↻  Reset simulated data", use_container_width=True):
        st.session_state.events = make_demo_events()
        st.session_state.findings = findings_from_events(st.session_state.events)
        st.session_state.scans = []
        st.rerun()
    st.markdown("<br><div class='cg-eyebrow'>CYBERGUARD / 0.1<br>LOCAL LAB</div>", unsafe_allow_html=True)

page = st.session_state.workspace_page
header_left, header_right = st.columns([6, 1])
with header_left:
    st.markdown(f"<div class='cg-eyebrow'>CYBERGUARD / YOUR SECURITY</div><h1 style='margin:.15rem 0 .2rem'>{PAGE_LABELS[page] if page != 'Overview' else 'Your security at a glance'}</h1><div style='color:#96a6ac;font-size:13px'>Simple explanations and clear next steps</div>", unsafe_allow_html=True)
with header_right:
    if page == "About CyberGuard":
        if st.button("← Back", use_container_width=True):
            set_page(st.session_state.sidebar_page)
            st.rerun()
    elif st.button("ⓘ About CyberGuard", use_container_width=True):
        set_page("About CyberGuard")
        st.rerun()
if page in FEATURE_GUIDES:
    show_feature_guide(page)


def event_table(rows: list[dict], key: str) -> None:
    if not rows:
        st.info("No events in this view. Try another query or import a CSV / JSON event batch.")
        return
    frame = pd.DataFrame(rows).copy()
    frame["timestamp"] = frame["timestamp"].map(lambda x: local_time(x) if isinstance(x, datetime) else str(x))
    frame = frame.rename(columns={"timestamp": "When", "eventType": "What happened", "user": "Account", "severity": "How important", "description": "Plain explanation"})
    st.dataframe(frame[["When", "What happened", "Account", "How important", "Plain explanation"]], use_container_width=True, hide_index=True, key=key)


if page == "About CyberGuard":
    st.markdown("<div class='cg-card'><h2 style='margin-top:0'>CyberGuard AI</h2><p style='color:#aebdc2;font-size:15px'>A simple cybersecurity workspace that turns activity records into understandable advice. It is designed for people who want to know what happened, whether it matters, and what to do next.</p></div>", unsafe_allow_html=True)
    journey, features, data = st.tabs(["How it works", "What each feature does", "Your data and results"])
    with journey:
        st.markdown("### A simple four-step journey")
        steps = st.columns(4)
        for col, title, body in zip(steps, ["1. Add activity", "2. Check it", "3. Understand it", "4. Follow up"], ["Review the workspace activity, upload a file, or collect selected Windows logs locally.", "Run a quick activity check or use Smart analysis to identify unusual patterns.", "Open What needs attention for a plain explanation and recommended next step.", "Save notes in My follow-ups and download a report when you need one."]):
            col.markdown(f"<div class='cg-card'><b>{title}</b><div style='color:#aebdc2;font-size:12px;margin-top:8px'>{body}</div></div>", unsafe_allow_html=True)
        a1, a2, a3 = st.columns(3)
        if a1.button("Add or review activity", use_container_width=True, key="about-history"):
            set_page("Event review")
            st.rerun()
        if a2.button("Run an activity check", type="primary", use_container_width=True, key="about-check"):
            set_page("Scans")
            st.rerun()
        if a3.button("See next steps", use_container_width=True, key="about-findings"):
            set_page("Findings")
            st.rerun()
    with features:
        st.markdown("### Project functionality")
        for feature in FEATURE_GUIDES:
            title, description = FEATURE_GUIDES[feature]
            st.markdown(f"<div class='cg-card'><b>{title}</b><div style='color:#aebdc2;font-size:13px;margin-top:7px'>{description}</div></div>", unsafe_allow_html=True)
    with data:
        st.markdown("### What happens when you use CyberGuard")
        st.markdown("**Activity history** works with the records in the current workspace. **Check my activity** uses clear security rules to look for sign-in patterns. **Smart analysis** uses an Isolation Forest model to rank records that differ from the current activity pattern. **What needs attention** turns those results into plain language.\n\nWhen you use the hosted app, follow-up notes are saved in your browser and can be downloaded as a CSV file. Windows Event Log collection is available only when the project runs locally on a Windows computer.")
        st.info("CyberGuard helps you decide what to review first. For an unfamiliar sign-in or a possible account issue, change the password and contact your IT support team.")

elif page == "Overview":
    filter_col, _ = st.columns([1, 3])
    with filter_col:
        window = st.radio("Time range", ["Past 24 hours", "Past 7 days", "All records"], horizontal=True, label_visibility="collapsed", key="overview_window")
    visible_events = [e for e in events if in_window(e, window)]
    st.markdown("<div class='cg-eyebrow' style='margin:18px 0 8px'>START HERE</div>", unsafe_allow_html=True)
    if active_findings:
        st.markdown("<div class='cg-card'><b>There is activity worth checking.</b><div style='color:#96a6ac;font-size:13px;margin-top:8px'>Open “What needs attention” to see a plain-language explanation and the safest next step.</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='cg-card'><b>No urgent activity needs your attention right now.</b><div style='color:#96a6ac;font-size:13px;margin-top:8px'>You can still review recent activity or run a check whenever you want.</div></div>", unsafe_allow_html=True)
    actions = st.columns(3)
    actions[0].button("See recent activity", use_container_width=True, on_click=set_page, args=("Event review",))
    actions[1].button("Check my activity", type="primary", use_container_width=True, on_click=set_page, args=("Scans",))
    actions[2].button("See what needs attention", use_container_width=True, on_click=set_page, args=("Findings",))
    a, b = st.columns([1.45, 1])
    with a:
        st.subheader("Recent activity")
        event_table(visible_events[:5], "overview-events")
    with b:
        st.subheader("Your next steps")
        if findings:
            for f in findings[:5]:
                st.markdown(f"<div class='cg-card'><b>{f['title']}</b><div style='color:#96a6ac;font-size:12px;margin-top:8px'>{f.get('next_steps', 'Open this item to see what to do next.')}</div></div>", unsafe_allow_html=True)
        else:
            st.info("Nothing needs action right now.")
    st.caption("Last scan: " + (st.session_state.scans[0]["started"] if st.session_state.scans else "Not available") + " · Time zone: IST (UTC+05:30).")

elif page == "Event review":
    st.caption("Search stored telemetry, narrow the view, and select a row to inspect its full evidence record.")
    upcol, flagcol = st.columns([1, 2])
    with upcol:
        upload = st.file_uploader("Upload CSV / JSON", type=["csv", "json"])
    with flagcol:
        mark_sim = st.checkbox("These file records are simulated", value=False, help="Unchecked uploads are stored as user-provided telemetry. The source is not independently verified.")
    if upload is not None and st.button("Import records", type="primary"):
        try:
            raw = upload.getvalue().decode("utf-8-sig")
            if upload.name.lower().endswith(".json"):
                parsed = json.loads(raw)
                rows = parsed.get("events", []) if isinstance(parsed, dict) else parsed
            else:
                rows = list(csv.DictReader(io.StringIO(raw)))
            if not isinstance(rows, list) or not rows:
                raise ValueError("File must contain at least one event row.")
            normalized = []
            for i, row in enumerate(rows, start=1):
                aliases = {"timestamp": ("timestamp", "time", "created_at"), "eventId": ("eventId", "event_id", "id"), "eventType": ("eventType", "event_type", "type"), "user": ("user", "username", "actor"), "sourceIp": ("sourceIp", "source_ip", "src_ip"), "severity": ("severity",), "status": ("status", "result"), "description": ("description", "message"), "destinationIp": ("destinationIp", "destination_ip", "dst_ip")}
                item = {target: next((str(row.get(k, "")).strip() for k in keys if row.get(k) is not None and str(row.get(k)).strip()), "") for target, keys in aliases.items()}
                for required in ("timestamp", "eventId", "eventType", "user", "sourceIp", "severity", "status", "description"):
                    if not item[required]:
                        raise ValueError(f"Row {i} is missing required field: {required}.")
                stamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
                if item["severity"] not in SEVERITIES:
                    raise ValueError(f"Row {i} has unsupported severity.")
                item.update({"id": f"upload-{uuid.uuid4().hex[:10]}", "timestamp": stamp.astimezone(timezone.utc), "simulated": mark_sim})
                normalized.append(item)
            st.session_state.events = sorted(normalized + events, key=lambda e: e["timestamp"], reverse=True)
            st.session_state.findings = findings_from_events(st.session_state.events)
            st.success(f"{len(normalized)} events imported. Source data has not been independently verified.")
            st.rerun()
        except Exception as exc:
            st.error(f"Upload not imported: {exc}")
    controls = st.columns([3, 1, 1, 1.5])
    query = controls[0].text_input("Search event IDs, actors, IPs, or evidence", placeholder="e.g. 198.51.100.23")
    sev = controls[1].selectbox("Severity", ["All severities"] + SEVERITIES)
    source = controls[2].selectbox("Record source", ["All records", "Simulated", "Non-simulated"])
    event_types = sorted({e["eventType"] for e in events})
    selected_types = controls[3].multiselect("Event types", event_types, placeholder="All event types")
    subset = [e for e in events if (sev == "All severities" or e["severity"] == sev) and (source == "All records" or e["simulated"] == (source == "Simulated")) and (not selected_types or e["eventType"] in selected_types) and (not query or query.lower() in " ".join(str(e.get(k, "")) for k in ("eventId", "eventType", "user", "sourceIp", "description")).lower())]
    st.caption(f"{len(subset)} matching records · up to 200 displayed")
    if subset:
        frame = pd.DataFrame(subset[:200]).copy()
        frame["timestamp"] = frame["timestamp"].map(lambda x: local_time(x) if isinstance(x, datetime) else str(x))
        frame = frame.rename(columns={"eventId": "Event ID", "timestamp": "Time", "eventType": "Type", "user": "Actor", "sourceIp": "Source IP", "severity": "Severity", "status": "Status", "description": "Evidence", "simulated": "Simulated"})
        selection = st.dataframe(frame[["Event ID", "Time", "Type", "Actor", "Source IP", "Severity", "Status", "Evidence", "Simulated"]], use_container_width=True, hide_index=True, key="event-review-table", on_select="rerun", selection_mode="single-row", height=430)
        selected_rows = selection.selection.rows
        if selected_rows:
            chosen = subset[selected_rows[0]]
            st.markdown(f"#### Selected event · `{chosen['eventId']}`")
            st.caption(f"{chosen['eventType']} · {chosen['severity']} · {'Simulated' if chosen['simulated'] else 'User-provided / collected'}")
            st.write(chosen["description"])
            with st.expander("Full event details"):
                st.json({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in chosen.items()})
    else:
        st.info("No events match these filters. Clear a filter or change the search.")
    st.download_button("Download current events as CSV", pd.DataFrame(subset).to_csv(index=False), "cyberguard-events.csv", "text/csv")

elif page == "Scans":
    st.caption("Run a quick check to find sign-in activity that may need your attention.")

    def run_stored_scan(scan_type: str) -> None:
        deep = scan_type == "deep"
        stages = [
            "Loading stored security event records",
            "Reviewing authentication event sequences",
            "Checking the 5-failures-in-15-minutes rule",
            "Correlating any successful sign-in or privilege change",
            "Summarizing severity and building evidence links",
            "Finalizing stored-event scan report",
        ] if deep else [
            "Loading stored security event records",
            "Reviewing authentication event sequences",
            "Checking the 5-failures-in-15-minutes rule",
            "Finalizing stored-event scan report",
        ]
        total = len(events)
        detected: list[dict] = []
        high_critical = 0
        failed_logins = 0
        evidence_links = 0
        completed: list[tuple[str, bool]] = []
        with st.status(f"{scan_type.title()} scan running · stored records only", expanded=True) as status:
            st.markdown("<div class='cg-scan-visual'><div class='cg-radar'></div><div><div class='cg-eyebrow' style='color:#56d7b7'>ANALYZING STORED EVENTS</div><div style='font-size:12px;color:#dce6e8;margin-top:4px'>This animation represents staged checks over the app's event records, not a scan of your device.</div></div></div>", unsafe_allow_html=True)
            progress = st.progress(0, text="Preparing stored-event checks…")
            stage_log = st.empty()
            for index, stage in enumerate(stages):
                progress.progress(int(index / len(stages) * 100), text=stage)
                if stage == "Loading stored security event records":
                    total = len(events)
                    check_label, check_ok = f"Activity records loaded and ready to check", True
                elif stage == "Reviewing authentication event sequences":
                    failed_logins = sum(e["eventType"] == "Failed Login" for e in events)
                    check_label = "No failed sign-ins were found" if failed_logins == 0 else "Failed sign-ins were found and reviewed"
                    check_ok = failed_logins == 0
                elif stage == "Checking the 5-failures-in-15-minutes rule":
                    detected = findings_from_events(events)
                    high_critical = sum(e["severity"] in ("High", "Critical") for e in events)
                    evidence_links = sum(len(f.get("eventIds", [])) for f in detected)
                    check_label = "No repeated sign-in pattern found" if not detected else "Repeated sign-in attempts need attention"
                    check_ok = not detected
                elif stage == "Correlating any successful sign-in or privilege change":
                    risky_followup = any("then one succeeded" in item["title"].lower() for item in detected)
                    check_label = "No risky follow-up sign-in found" if not risky_followup else "A successful sign-in followed repeated failed attempts"
                    check_ok = not risky_followup
                elif stage == "Summarizing severity and building evidence links":
                    evidence_links = sum(len(f.get("eventIds", [])) for f in detected)
                    check_label = "No high-priority activity found" if high_critical == 0 else "High-priority activity needs review"
                    check_ok = high_critical == 0
                else:
                    check_label, check_ok = "Your activity check report is ready", True
                time.sleep(1.0 if deep else 0.9)
                completed.append((check_label, check_ok))
                lines = "".join(
                    f"<div style='display:flex;align-items:center;gap:10px;padding:8px 10px;margin:6px 0;border-radius:8px;background:{'#12362d' if passed else '#3a1b22'};color:#dce6e8'><span style='font-size:18px;font-weight:800;color:{'#56d7b7' if passed else '#fb7185'}'>{'✓' if passed else '✕'}</span><span>{label}</span></div>"
                    for label, passed in completed
                )
                stage_log.markdown(lines, unsafe_allow_html=True)
            progress.progress(100, text="Scan complete · rule-based checks only")
            status.update(label=f"{scan_type.title()} scan complete · {total} stored records reviewed", state="complete", expanded=True)

        if not detected:
            detected = findings_from_events(events)
        st.session_state.findings = detected
        st.session_state.scans.insert(0, {
            "id": f"scan-{uuid.uuid4().hex[:8]}",
            "type": scan_type,
            "started": local_time(datetime.now(timezone.utc)),
            "status": "Completed",
            "progress": 100,
            "records reviewed": total,
            "failed logins reviewed": failed_logins,
            "high / critical events": high_critical,
            "rule-based findings": len(detected),
            "evidence links": evidence_links or sum(len(f.get("eventIds", [])) for f in detected),
            "simulated": all(e["simulated"] for e in events),
        })
        st.success("Your activity check is complete. Open “What needs attention” to see clear next steps.")

    with st.container(border=True):
        st.subheader("Check your activity")
        c1, c2, c3 = st.columns([3, 1, 1])
        c1.write("CyberGuard checks the activity currently shown in this workspace and turns it into simple advice.")
        if c2.button("Quick check", use_container_width=True):
            run_stored_scan("quick")
        if c3.button("Detailed check", type="primary", use_container_width=True):
            run_stored_scan("deep")
    st.subheader("Past checks")
    if st.session_state.scans:
        st.dataframe(pd.DataFrame(st.session_state.scans), use_container_width=True, hide_index=True)
    else:
        st.info("No activity checks have been run yet.")

elif page == "Findings":
    st.caption("These are the things worth looking at first. Each card explains what happened and what you can do.")
    if not findings:
        st.info("No findings to investigate. A scan can evaluate the stored records.")
    for finding in findings:
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"<span class='cg-pill' style='color:{COLORS.get(finding['severity'], '#94a3b8')}'>{finding['severity']} priority</span>", unsafe_allow_html=True)
            c1.markdown(f"### {finding['title']}\n**What happened:** {finding.get('plain_summary', finding['evidence'])}\n\n**What to do now:** {finding.get('next_steps', 'Open the activity details and review this item.')}")
            c1.caption(f"Noticed {local_time(finding['timestamp'])}")
            with c2:
                state = st.selectbox("My progress", ["New", "Investigating", "Resolved", "Dismissed"], format_func=lambda item: {"New": "Needs attention", "Investigating": "I am checking", "Resolved": "Done", "Dismissed": "Ignore"}[item], index=["New", "Investigating", "Resolved", "Dismissed"].index(finding["status"]), key=f"status-{finding['id']}")
                finding["status"] = state
            with st.expander("Technical details for IT support"):
                st.code("\n".join(finding["eventIds"]), language=None)

elif page == "Investigations":
    st.caption("Track findings, assign ownership, record investigation notes, and export case reports.")
    if os.name != "nt":
        browser_case_workspace(findings)
    else:
        conn = local_db()
        for finding in findings:
            case_id = f"case-{finding['id']}"
            existing = conn.execute("SELECT status, owner, notes FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not existing:
                conn.execute("INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?)", (case_id, finding["id"], finding["title"], "New", "Unassigned", "", local_time(datetime.now(timezone.utc))))
        conn.commit()
        if not findings:
            st.info("No findings to turn into an investigation yet. Run a scan after collecting or importing events.")
        for finding in findings:
            case_id = f"case-{finding['id']}"
            status, owner, notes = conn.execute("SELECT status, owner, notes FROM cases WHERE case_id=?", (case_id,)).fetchone()
            with st.container(border=True):
                st.markdown(f"### {finding['title']}")
                st.write(finding.get("plain_summary", finding["evidence"]))
                c1, c2, c3 = st.columns([1, 1, 2])
                new_status = c1.selectbox("Case status", ["New", "Investigating", "Resolved", "Dismissed"], index=["New", "Investigating", "Resolved", "Dismissed"].index(status), key=f"case-status-{case_id}")
                new_owner = c2.text_input("Assigned to", value=owner, key=f"case-owner-{case_id}")
                new_notes = st.text_area("Investigation notes", value=notes, key=f"case-notes-{case_id}", placeholder="What did you check? What should happen next?")
                if st.button("Save case", key=f"case-save-{case_id}"):
                    conn.execute("UPDATE cases SET status=?, owner=?, notes=?, updated_at=? WHERE case_id=?", (new_status, new_owner, new_notes, local_time(datetime.now(timezone.utc)), case_id))
                    conn.commit()
                    st.success("Case saved on this PC.")
        rows = conn.execute("SELECT case_id, title, status, owner, notes, updated_at FROM cases ORDER BY updated_at DESC").fetchall()
        if rows:
            report = pd.DataFrame(rows, columns=["Case ID", "Finding", "Status", "Assigned to", "Notes", "Updated (IST)"])
            st.download_button("Download investigation report (CSV)", report.to_csv(index=False), "cyberguard-investigations.csv", "text/csv")
        conn.close()

elif page == "Analytics":
    st.caption("See simple patterns in your activity. Use the filters to focus on a time period or level of importance.")
    f1, f2 = st.columns([1, 2])
    window = f1.radio("Time range", ["Past 24 hours", "Past 7 days", "All records"], horizontal=True, label_visibility="collapsed", key="analytics_window")
    selected_severities = f2.multiselect("Severities", SEVERITIES, default=SEVERITIES, placeholder="Choose severities")
    filtered_events = [e for e in events if in_window(e, window) and e["severity"] in selected_severities]
    if not filtered_events:
        st.info("No records match this time range and severity selection.")
    else:
        df = pd.DataFrame(filtered_events)
        cols = st.columns(4)
        for col, label, val in zip(cols, ["Activity records", "Needs attention", "Accounts involved", "Places activity came from"], [len(filtered_events), int(df["severity"].isin(["High", "Critical"]).sum()), df["user"].nunique(), df["sourceIp"].replace("", pd.NA).nunique()]):
            col.metric(label, val)
        severity_tab, type_tab, activity_tab = st.tabs(["What needs attention", "What happened", "When it happened"])
        with severity_tab:
            counts = df["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
            st.bar_chart(counts, color="#56d7b7")
            st.caption("Select a time range and severity above to update this chart.")
        with type_tab:
            type_counts = df["eventType"].value_counts().head(10)
            st.bar_chart(type_counts, color="#56d7b7")
            st.dataframe(type_counts.rename("Records").to_frame(), use_container_width=True)
        with activity_tab:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
            hourly = df.set_index("timestamp").resample("1h").size().rename("Events").to_frame()
            st.line_chart(hourly, color="#56d7b7")
            st.caption("Times are shown in Indian Standard Time (IST, UTC+05:30). Hover over the plot to inspect values.")

elif page == "ML Lab":
    st.caption("CyberGuard looks for activity that is different from the usual pattern, then explains why it deserves a closer look.")
    if len(events) < 8:
        st.info("Add at least 8 event records to create an anomaly baseline.")
    else:
        c1, c2 = st.columns([2, 1])
        sensitivity = c1.select_slider("How much should CyberGuard flag?", options=["Only unusual", "Balanced", "Show more"], value="Balanced")
        contamination = {"Only unusual": 0.05, "Balanced": 0.10, "Show more": 0.20}[sensitivity]
        c2.metric("Activity reviewed", len(events))
        if st.button("Find unusual activity", type="primary", use_container_width=True):
            st.session_state.ml_results = anomaly_scores(events, contamination)
            st.session_state.ml_sensitivity = sensitivity
        results = st.session_state.get("ml_results")
        if results is None:
            st.info("Choose “Find unusual activity” to get a simple list of items worth checking first.")
        else:
            anomalies = results[results["model_label"] == "Anomalous"]
            if anomalies.empty:
                st.success("Nothing looked unusual in this activity set.")
            else:
                st.warning("Some activity looks different from the usual pattern. Review the items below first.")
            st.markdown("### Things to review first")
            display = results.copy()
            display["Priority"] = display["model_label"].map({"Anomalous": "Review first", "Baseline": "Normal pattern"})
            display = display.rename(columns={"timestamp": "When", "eventType": "What happened", "user": "Account", "sourceIp": "Source IP", "severity": "Importance", "explanation": "Why it stands out"})[["Priority", "When", "What happened", "Account", "Importance", "Why it stands out"]]
            st.dataframe(display, use_container_width=True, hide_index=True)
            st.download_button("Download this review list (CSV)", display.to_csv(index=False), "cyberguard-review-list.csv", "text/csv")
            with st.expander("Technical details for your M.Tech project"):
                st.markdown("**Algorithm:** Isolation Forest with 200 trees and a fixed random seed for repeatable classroom demonstrations.\n\n**Features:** hour of event, severity weight, frequency of the event type, account, and source address, plus one-hot encoded event type, account, source address, and status.\n\n**Interpretation:** the anomaly score is a relative rank within the records currently loaded into the app. It is not a probability of compromise, and results should be reviewed with the linked evidence.")

elif page == "Assistant":
    st.caption("Ask a question in everyday language. CyberGuard will explain the activity shown in this workspace.")
    for item in st.session_state.chat:
        with st.chat_message(item["role"]):
            st.markdown(item["content"])
            if item.get("evidence"):
                st.caption("Evidence IDs: " + ", ".join(item["evidence"]))
    for suggestion in ["What should I look at first?", "Explain the failed sign-ins simply", "What happened recently?"]:
        if st.button(suggestion, key=f"suggest-{suggestion}"):
            st.session_state.pending_question = suggestion
    question = st.chat_input("For example: What should I do next?")
    if question is None and st.session_state.get("pending_question"):
        question = st.session_state.pop("pending_question")
    if question:
        st.session_state.chat.append({"role": "user", "content": question})
        q = question.lower()
        matches = []
        for e in events:
            if (any(ch.isdigit() for ch in question) and question.strip() in (e["eventId"], e["id"])) or ("login" in q or "sign-in" in q or "failed" in q) and "login" in e["eventType"].lower() or ("today" in q or "recent" in q or "summary" in q) and e["timestamp"] >= datetime.now(timezone.utc) - timedelta(days=1):
                matches.append(e)
        related = next((f for f in findings if f["status"] in ("New", "Investigating") and set(f["eventIds"]) & {e["id"] for e in matches}), None)
        if related is None and ("first" in q or "next" in q or "help" in q):
            related = next((f for f in findings if f["status"] in ("New", "Investigating")), None)
        if related:
            answer = related["title"] + ". " + related.get("plain_summary", related["evidence"]) + " What you can do: " + related.get("next_steps", "Review the linked records. This rule match is not proof of compromise.")
        elif matches:
            failed_count = sum(e["eventType"] == "Failed Login" for e in matches)
            answer = f"{len(matches)} matching event records found" + (" in simulated telemetry" if all(e["simulated"] for e in matches) else " in stored telemetry") + (f"; {failed_count} are failed sign-in events." if failed_count else ".")
        else:
            answer = "I don't have enough matching evidence in the stored telemetry to determine that."
        evidence = [e["id"] for e in matches[:8]]
        st.session_state.chat.append({"role": "assistant", "content": answer, "evidence": evidence})
        st.rerun()
    st.info("Answers are based on the activity in this workspace. If something feels unfamiliar, change your password and contact your IT support team.")

elif page == "Devices":
    st.caption("One-time local Windows Event Log collection. No log data is sent to CyberGuard cloud services.")
    if os.name == "nt":
        st.success("Local Windows mode · PowerShell reads this PC's event logs and keeps results in this local app session.")
        st.warning("Security event access may require running the local app as Administrator. Collection is limited to selected event types and a recent time window.")
        days_back = st.select_slider("Look back", options=[1, 2, 3, 7], value=1, format_func=lambda d: f"{d} day" if d == 1 else f"{d} days")
        if st.button("Collect Windows logs on this PC", type="primary"):
            ps = r'''
$ErrorActionPreference = 'SilentlyContinue'
$since = [DateTime]::UtcNow.AddDays(-__DAYS__)
$output = [System.Collections.Generic.List[object]]::new()
$labels = @{4624='Successful Login';4625='Failed Login';4672='Privilege Change';4688='Process Start';4697='Service Install'}
foreach ($channel in @('Security','System','Application')) {
  if ($channel -eq 'Security') {
    $filter = @{LogName=$channel; StartTime=$since; Id=@(4624,4625,4672,4688,4697)}
  } else {
    $filter = @{LogName=$channel; StartTime=$since; Level=@(1,2)}
  }
  $items = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction SilentlyContinue)
  foreach ($event in $items) {
    $message = [string]$event.Message
    if ($message.Length -gt 1800) { $message = $message.Substring(0,1800) }
    $ip = [regex]::Match($message, '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])').Value
    $severity = if ($event.Id -eq 4625 -or $event.Id -eq 4697) {'Medium'} elseif ($event.Id -eq 4672) {'High'} elseif ($event.Id -eq 4688) {'Informational'} elseif ($event.Level -eq 1) {'Critical'} elseif ($event.Level -eq 2) {'High'} else {'Low'}
    $type = if ($labels.ContainsKey([int]$event.Id)) {$labels[[int]$event.Id]} elseif ($channel -eq 'System') {'System Event'} else {'Application Event'}
    $user = if ($event.UserId) {$event.UserId.Value} else {'unknown'}
    $status = if ($event.Id -eq 4625) {'Failed'} elseif ($event.Id -eq 4624) {'Success'} else {'Observed'}
    $output.Add([pscustomobject]@{timestamp=$event.TimeCreated.ToUniversalTime().ToString('o'); eventId=[string]$event.Id; eventType=$type; user=$user; sourceIp=$ip; destinationIp=''; severity=$severity; status=$status; description=$message; source=$channel; simulated=$false; provider=[string]$event.ProviderName; computer=[string]$event.MachineName})
  }
}
ConvertTo-Json -InputObject @($output) -Depth 4 -Compress
'''.replace("__DAYS__", str(int(days_back)))
            try:
                result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=90, check=False)
                if result.returncode != 0 or not result.stdout.strip():
                    raise RuntimeError("PowerShell could not read the selected event logs. Try running this local app as Administrator.")
                raw_events = json.loads(result.stdout)
                if isinstance(raw_events, dict):
                    raw_events = [raw_events]
                collected = []
                for raw in raw_events:
                    stamp = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
                    collected.append({**raw, "id": f"local-{uuid.uuid4().hex[:10]}", "timestamp": stamp.astimezone(timezone.utc), "simulated": False})
                st.session_state.local_collection_meta = {"count": len(collected), "days": days_back, "channels": sorted({e.get("source", "") for e in collected if e.get("source")})}
                if collected:
                    st.session_state.events = sorted(collected, key=lambda e: e["timestamp"], reverse=True)
                    st.session_state.findings = findings_from_events(st.session_state.events)
                    st.success(f"Collected {len(collected)} local event records from {', '.join(st.session_state.local_collection_meta['channels'])}. Records remain in this local app session.")
                else:
                    st.info("No matching events were found in that time window, or Windows denied access. No records were added.")
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, RuntimeError) as exc:
                st.error(str(exc) if isinstance(exc, RuntimeError) else "Local collection failed. Confirm PowerShell is available and try running the app as Administrator.")
        if st.session_state.local_collection_meta:
            meta = st.session_state.local_collection_meta
            st.caption(f"Last local collection: {meta['count']} event records · past {meta['days']} day(s) · {', '.join(meta['channels']) or 'no accessible channels'} · held in local session only")
        st.markdown("### Data handling")
        st.write("The collector uses Windows PowerShell's Get-WinEvent on this computer. It does not upload, persist, or transmit the records. Closing the local app session clears them.")
    else:
        st.warning("This page is running on Streamlit Community Cloud, a remote Linux server. It cannot read your Windows Event Logs. For local-only collection, run a copy of this repository on your Windows PC.")
        st.markdown("1. [Download the project ZIP](https://github.com/vaibhavrxj/Cyberguard-AI/archive/refs/heads/main.zip) and extract it.\n2. Install Python 3.10 or newer if needed.\n3. Open PowerShell in the extracted folder and run:\n   `py -m pip install -r requirements.txt`\n   `py -m streamlit run streamlit_app.py --server.address 127.0.0.1`\n4. Open `http://127.0.0.1:8501`, then choose **Devices** → **Collect Windows logs on this PC**. The local app does not send log data to the hosted site.")
        st.caption("Selected records: Windows Security sign-in / privilege / process / service events (IDs 4624, 4625, 4672, 4688, 4697), plus System and Application warnings/errors. Maximum 500 records per channel.")
    st.markdown("### Live monitoring")
    st.write("This is a one-time collection. It does not run in the background, stream events continuously, or take response actions.")

st.markdown("<hr style='border-color:#2b3946;margin-top:30px'><div class='cg-eyebrow'>CYBERGUARD AI · M.TECH CYBERSECURITY ANALYTICS WORKBENCH</div>", unsafe_allow_html=True)
