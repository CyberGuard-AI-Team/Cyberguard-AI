from __future__ import annotations

import csv
import hashlib
import html
import hmac
import io
import json
import os
import re
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor



st.set_page_config(page_title="CyberGuard AI | SOC Workbench", page_icon="🛡️", layout="wide")

NAV = ["Overview", "Profile", "Scans", "Event review", "Findings", "Investigations", "Analytics", "ML Lab", "Assistant", "Devices"]
PAGE_LABELS = {"Overview": "Home", "Profile": "My profile", "About CyberGuard": "About CyberGuard", "Scans": "Check my activity", "Event review": "Activity history", "Findings": "What needs attention", "Investigations": "My follow-ups", "Analytics": "Activity summary", "ML Lab": "Smart analysis", "Assistant": "Ask CyberGuard", "Devices": "Connect my PC"}
NAV_ICONS = {"Overview": "⌂", "Profile": "◉", "Scans": "⌁", "Event review": "▤", "Findings": "◇", "Investigations": "☷", "Analytics": "⌗", "ML Lab": "✦", "Assistant": "◎", "Devices": "▣"}
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
.cg-auth-hero { max-width:560px;margin:8vh auto 0;text-align:center; }
.cg-auth-badge { width:58px;height:58px;display:grid;place-items:center;margin:0 auto 16px;border-radius:18px;background:#56d7b71a;border:1px solid #56d7b755;color:#56d7b7;font-size:28px; }
.cg-team-list { display:grid;gap:7px;margin:10px 0 4px; }
.cg-team-link { display:flex;align-items:center;justify-content:space-between;padding:9px 11px;border:1px solid var(--cg-border);border-radius:9px;background:#171f29;color:#dce6e8!important;text-decoration:none!important;font-size:12px;font-weight:700;transition:border-color .16s ease,transform .16s ease; }
.cg-team-link:hover { border-color:#56d7b777;transform:translateX(2px); }
.cg-team-link span { color:#56d7b7;font-family:'DM Mono',monospace;font-size:10px; }
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
.cg-scan-complete { display:flex;align-items:center;gap:16px;border:1px solid #56d7b766;background:linear-gradient(120deg,#56d7b71a,#171f29);border-radius:13px;padding:16px 18px;margin:10px 0 14px;animation:cg-complete-in .45s ease-out both; }
.cg-scan-complete.alert { border-color:#fb718566;background:linear-gradient(120deg,#fb71851a,#171f29); }
.cg-complete-mark { width:48px;height:48px;flex:none;display:grid;place-items:center;border-radius:50%;font-size:28px;font-weight:800;color:#101720;background:#56d7b7;box-shadow:0 0 0 0 #56d7b755;animation:cg-complete-pulse 1.6s ease-out infinite; }
.cg-scan-complete.alert .cg-complete-mark { background:#fb7185;box-shadow:0 0 0 0 #fb718555; }
@keyframes cg-complete-in { from { opacity:0;transform:translateY(8px) scale(.97); } to { opacity:1;transform:translateY(0) scale(1); } }
@keyframes cg-complete-pulse { 60% { box-shadow:0 0 0 13px transparent; } 100% { box-shadow:0 0 0 0 transparent; } }
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

# CyberGuard's visual system. This second layer intentionally overrides the
# legacy styles above while keeping older page components compatible.
st.markdown("""
<style>
:root {
  --cg-bg:#060b16; --cg-bg-2:#091223; --cg-panel:#0e1729; --cg-panel-2:#121e33;
  --cg-border:#233452; --cg-border-soft:#1a2942; --cg-cyan:#35d8ff;
  --cg-blue:#4d7cff; --cg-violet:#8b5cf6; --cg-green:#48e39b; --cg-red:#ff667a;
  --cg-amber:#ffbe55; --cg-text:#f3f7ff; --cg-muted:#91a0ba;
  --cg-shadow:0 22px 60px rgba(0,0,0,.28);
}
html, body, [class*="css"] { font-family:Manrope, sans-serif; }
.stApp {
  color:var(--cg-text);
  background:
    radial-gradient(circle at 78% 2%,rgba(41,112,164,.17),transparent 31%),
    radial-gradient(circle at 23% 72%,rgba(75,70,190,.1),transparent 32%),
    linear-gradient(145deg,var(--cg-bg),var(--cg-bg-2) 58%,#07101e);
}
.stApp:before {
  content:"";position:fixed;inset:0;pointer-events:none;opacity:.16;z-index:0;
  background-image:linear-gradient(rgba(80,131,193,.1) 1px,transparent 1px),linear-gradient(90deg,rgba(80,131,193,.1) 1px,transparent 1px);
  background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 72%);
}
.block-container { max-width:1580px;padding-top:1.45rem;padding-bottom:4rem; }
header[data-testid="stHeader"] { background:rgba(6,11,22,.72);backdrop-filter:blur(18px);border-bottom:1px solid rgba(60,85,124,.28); }
section[data-testid="stSidebar"] { width:304px!important;background:linear-gradient(180deg,rgba(10,18,33,.98),rgba(7,13,24,.99));border-right:1px solid var(--cg-border-soft); }
section[data-testid="stSidebar"] > div { width:304px!important; }
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#d8e3f6; }
section[data-testid="stSidebar"] hr { border-color:var(--cg-border-soft);margin:1.2rem 0; }
.cg-brand { font-size:22px;font-weight:800;letter-spacing:-.045em;display:flex;align-items:center;gap:10px;margin-top:.35rem; }
.cg-brand:before { content:"◆";display:grid;place-items:center;width:34px;height:34px;border-radius:11px;color:#07101e;background:linear-gradient(135deg,var(--cg-cyan),var(--cg-violet));box-shadow:0 0 25px rgba(53,216,255,.22);font-size:15px; }
.cg-brand span { color:var(--cg-cyan); }
.cg-eyebrow { color:#8495b2;font-size:10px;font-weight:800;letter-spacing:.17em;text-transform:uppercase; }
section[data-testid="stSidebar"] div[role="radiogroup"] { gap:5px; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label { padding:10px 12px;border:1px solid transparent;border-radius:11px;transition:.18s ease;background:transparent; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover { background:#15233a;border-color:#263a5d;transform:translateX(2px); }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) { background:linear-gradient(100deg,rgba(50,101,194,.28),rgba(31,185,220,.12));border-color:#2e80b5;box-shadow:inset 3px 0 0 var(--cg-cyan),0 9px 30px rgba(0,0,0,.16); }
section[data-testid="stSidebar"] div[role="radiogroup"] label p { font-size:13px;font-weight:650;color:#aebbd0; }
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p { color:#f5f9ff; }
section[data-testid="stSidebar"] div[role="radiogroup"] [data-testid="stRadio"] { display:none; }
h1,h2,h3 { color:var(--cg-text);letter-spacing:-.045em; }
h1 { font-size:clamp(2.2rem,4vw,4.3rem)!important;line-height:1.02!important; }
p,li,label { color:#b3c0d4; }
a { color:var(--cg-cyan); }
.cg-page-head { display:flex;align-items:center;gap:12px;min-height:32px;margin:2px 0 8px; }
.cg-page-kicker { color:#8fa0ba;font-size:10px;font-weight:800;letter-spacing:.18em;text-transform:uppercase; }
.cg-live-dot { display:inline-block;width:7px;height:7px;border-radius:99px;background:var(--cg-green);box-shadow:0 0 12px var(--cg-green);margin-right:7px; }
.cg-head-chip { display:inline-flex;align-items:center;padding:6px 10px;border:1px solid #28415c;border-radius:999px;background:#0e1b2c;color:#a9bad1;font-size:10px;font-weight:750; }
.cg-hero { position:relative;overflow:hidden;border:1px solid #233b60;border-radius:24px;padding:clamp(24px,4vw,48px);margin:10px 0 20px;background:linear-gradient(125deg,rgba(17,31,54,.97),rgba(8,18,34,.95));box-shadow:var(--cg-shadow); }
.cg-hero:before { content:"";position:absolute;width:520px;height:520px;border-radius:50%;right:-160px;top:-280px;background:radial-gradient(circle,rgba(53,216,255,.21),rgba(79,86,245,.08) 45%,transparent 70%); }
.cg-hero-grid { position:relative;z-index:1;display:grid;grid-template-columns:minmax(0,1.45fr) minmax(240px,.55fr);gap:36px;align-items:center; }
.cg-hero h1 { max-width:760px;margin:.5rem 0 1rem;font-size:clamp(2.25rem,4.4vw,4.8rem)!important; }
.cg-hero-copy { max-width:740px;color:#aebdd2;font-size:15px;line-height:1.75; }
.cg-status-badge { display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid #2c4664;border-radius:999px;background:#0c192b;color:#b9c8dc;font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase; }
.cg-status-badge.safe { border-color:rgba(72,227,155,.35);color:#70efae;background:rgba(23,91,66,.18); }
.cg-status-badge.warning { border-color:rgba(255,190,85,.38);color:#ffd17c;background:rgba(111,69,10,.2); }
.cg-status-badge.urgent { border-color:rgba(255,102,122,.4);color:#ff8f9e;background:rgba(113,27,42,.2); }
.cg-orb-wrap { min-height:238px;display:grid;place-items:center;position:relative; }
.cg-orb { width:188px;height:188px;border-radius:50%;position:relative;background:radial-gradient(circle at 34% 30%,#4ce7ff 0 2%,#1b7ed1 10%,#172e75 33%,#0a1534 62%,#050a15 73%);box-shadow:0 0 55px rgba(53,216,255,.26),inset -20px -24px 50px rgba(0,0,0,.5);animation:cg-float 5s ease-in-out infinite; }
.cg-orb:before,.cg-orb:after { content:"";position:absolute;border-radius:50%;inset:-17px;border:1px solid rgba(53,216,255,.45);transform:rotate(-18deg) scaleY(.48);box-shadow:0 0 18px rgba(53,216,255,.12); }
.cg-orb:after { inset:-38px;border-color:rgba(139,92,246,.4);transform:rotate(24deg) scaleY(.55); }
.cg-orb-grid { position:absolute;inset:17%;border-radius:50%;opacity:.65;background-image:linear-gradient(rgba(115,230,255,.22) 1px,transparent 1px),linear-gradient(90deg,rgba(115,230,255,.22) 1px,transparent 1px);background-size:14px 14px;mask-image:radial-gradient(circle,black,transparent 72%); }
.cg-orb-node { position:absolute;width:9px;height:9px;border-radius:50%;background:var(--cg-red);box-shadow:0 0 0 6px rgba(255,102,122,.12),0 0 17px var(--cg-red); }
.cg-orb-node.one { left:20%;top:35%; }.cg-orb-node.two { right:15%;top:48%;background:var(--cg-amber);box-shadow:0 0 0 6px rgba(255,190,85,.12),0 0 17px var(--cg-amber); }.cg-orb-node.three { left:48%;bottom:12%;background:var(--cg-green);box-shadow:0 0 0 6px rgba(72,227,155,.12),0 0 17px var(--cg-green); }
@keyframes cg-float { 50% { transform:translateY(-8px) rotate(2deg); } }
.cg-kpis { display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 22px; }
.cg-kpi { position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(18,31,53,.96),rgba(10,19,34,.96));border:1px solid var(--cg-border);border-radius:17px;padding:18px 19px;min-height:126px;box-shadow:0 13px 35px rgba(0,0,0,.16);transition:.2s ease; }
.cg-kpi:hover,.cg-step:hover { transform:translateY(-3px);border-color:#32659a;box-shadow:0 18px 42px rgba(0,0,0,.25); }
.cg-kpi:after { content:"";position:absolute;width:85px;height:85px;border-radius:50%;right:-35px;top:-35px;background:radial-gradient(circle,rgba(53,216,255,.22),transparent 70%); }
.cg-kpi-label { color:#8293ae;font-size:9px;font-weight:800;letter-spacing:.14em;text-transform:uppercase; }
.cg-kpi-value { color:#f5f8ff;font-size:29px;font-weight:800;letter-spacing:-.055em;margin:11px 0 4px; }
.cg-kpi-detail { color:#8697b1;font-size:10px;line-height:1.5; }
.cg-section-title { display:flex;align-items:end;justify-content:space-between;gap:12px;margin:30px 0 12px; }
.cg-section-title h2 { margin:0;font-size:1.45rem; }.cg-section-title p { margin:0;color:#8293ae;font-size:11px; }
.cg-step-grid { display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin-bottom:14px; }
.cg-step { min-height:188px;padding:20px;border:1px solid var(--cg-border);border-radius:18px;background:linear-gradient(145deg,rgba(17,29,50,.96),rgba(9,18,32,.96));transition:.2s ease; }
.cg-step-num { display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:linear-gradient(135deg,var(--cg-cyan),var(--cg-violet));color:#06101d;font-size:11px;font-weight:900;box-shadow:0 8px 22px rgba(65,146,238,.2); }
.cg-step h3 { margin:18px 0 8px;font-size:1rem;letter-spacing:-.02em; }.cg-step p { color:#91a0b7;font-size:11px;line-height:1.65;margin:0; }
.cg-card,.cg-metric,div[data-testid="stMetric"],div[data-testid="stVerticalBlockBorderWrapper"] { background:linear-gradient(145deg,rgba(17,29,49,.97),rgba(9,18,31,.97));border-color:var(--cg-border);box-shadow:0 13px 38px rgba(0,0,0,.14); }
.cg-card,.cg-metric { border-radius:17px; }.cg-metric { min-height:125px; }
.cg-metric-label,div[data-testid="stMetricLabel"] p { color:#8293ae; }.cg-metric-detail { color:#8697b1; }
.cg-notice { border-color:rgba(255,190,85,.28);background:rgba(255,190,85,.07);color:#e8c985; }
.cg-team-link { background:#0c1728;border-color:#21334f; }.cg-team-link:hover { border-color:#35d8ff88; }
.cg-auth-hero { max-width:650px;margin:6vh auto 0;text-align:center; }
.cg-auth-hero h1 { margin:.7rem 0!important;background:linear-gradient(100deg,#f5f8ff 25%,#80e8ff 63%,#a48aff);-webkit-background-clip:text;background-clip:text;color:transparent; }
.cg-auth-badge { width:68px;height:68px;border-radius:21px;border:1px solid rgba(79,176,255,.45);background:linear-gradient(145deg,rgba(53,216,255,.2),rgba(139,92,246,.18));color:#8eeaff;box-shadow:0 18px 55px rgba(43,130,219,.18),inset 0 0 24px rgba(53,216,255,.08); }
.cg-auth-features { display:flex;justify-content:center;flex-wrap:wrap;gap:8px;margin:18px 0 22px; }
.cg-auth-features span { padding:7px 10px;border:1px solid #243a59;border-radius:999px;background:rgba(12,25,43,.72);color:#93a7c4;font-size:9px;font-weight:800;letter-spacing:.05em;text-transform:uppercase; }
.stButton button { min-height:42px;border-radius:11px;border-color:#2b3e5d;background:#111d31;color:#dce7f8;font-weight:750; }
.stButton button[kind="primary"] { background:linear-gradient(110deg,var(--cg-cyan),#5887ff 55%,var(--cg-violet));color:#06101c;border:0;box-shadow:0 9px 28px rgba(53,216,255,.18); }
.stButton button:hover { border-color:#3f8ac2;color:#fff;box-shadow:0 12px 32px rgba(0,0,0,.28); }
[data-testid="stForm"],div[data-testid="stExpander"],div[data-testid="stFileUploader"] { border-color:var(--cg-border)!important;border-radius:15px!important;background:rgba(10,19,34,.58); }
div[data-baseweb="input"] > div,div[data-baseweb="select"] > div,textarea { background:#0b1526!important;border-color:#283b59!important;color:#e8f0ff!important;border-radius:10px!important; }
input,textarea { color:#e9f1ff!important;caret-color:var(--cg-cyan); }
input:focus,textarea:focus { outline:2px solid rgba(53,216,255,.35)!important;outline-offset:1px; }
[data-testid="stTabs"] [role="tablist"] { gap:7px;border-bottom-color:#20304b; }
[data-testid="stTabs"] button { border-radius:10px 10px 0 0;padding-left:18px;padding-right:18px;color:#8fa0ba; }
[data-testid="stTabs"] button[aria-selected="true"] { color:var(--cg-cyan);background:rgba(53,216,255,.06); }
[data-testid="stDataFrame"] { border-color:var(--cg-border);border-radius:13px;box-shadow:0 12px 34px rgba(0,0,0,.14); }
[data-testid="stAlert"] { border-radius:13px;border-color:#2a415f;background:#0d192b; }
.cg-queue { border:1px solid var(--cg-border);border-radius:18px;overflow:hidden;background:#0a1424;box-shadow:var(--cg-shadow); }
.cg-queue-head,.cg-queue-row { display:grid;grid-template-columns:110px minmax(220px,1.6fr) minmax(170px,.9fr) 120px;gap:14px;align-items:center;padding:14px 18px; }
.cg-queue-head { background:#13213a;color:#8293ae;font-size:9px;font-weight:850;text-transform:uppercase;letter-spacing:.13em; }.cg-queue-row { border-top:1px solid #1d2c46;color:#dce6f6;font-size:11px; }.cg-queue-row:hover { background:#101d31; }
.cg-severity { display:inline-flex;width:max-content;padding:5px 9px;border-radius:999px;font-weight:800;font-size:9px; }.cg-severity.high,.cg-severity.critical { color:#ff9baa;background:rgba(182,35,62,.28); }.cg-severity.medium { color:#ffd77e;background:rgba(154,103,15,.24); }.cg-severity.low,.cg-severity.informational { color:#70efae;background:rgba(20,121,81,.22); }
.cg-queue-main { font-weight:700; }.cg-queue-sub { color:#7f90ab;font-size:9px;margin-top:3px; }.cg-state { color:#8ae7bc;font-size:9px;font-weight:800; }
footer { visibility:hidden; }
@media (max-width:1000px) { .cg-hero-grid{grid-template-columns:1fr}.cg-orb-wrap{display:none}.cg-kpis{grid-template-columns:repeat(2,1fr)}.cg-step-grid{grid-template-columns:1fr}.cg-queue-head,.cg-queue-row{grid-template-columns:90px 1fr 100px}.cg-queue-head>*:nth-child(3),.cg-queue-row>*:nth-child(3){display:none} }
@media (max-width:640px) { .block-container{padding-left:1rem;padding-right:1rem}.cg-kpis{grid-template-columns:1fr}.cg-hero{padding:24px 20px;border-radius:18px}.cg-queue-head,.cg-queue-row{grid-template-columns:78px 1fr}.cg-queue-head>*:last-child,.cg-queue-row>*:last-child{display:none} }
@media (prefers-reduced-motion:reduce) { *,*:before,*:after { animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important; } }
</style>
""", unsafe_allow_html=True)


def auth_db() -> sqlite3.Connection:
    """Open the small local account store used by this Streamlit application."""
    # Anchor the database to this file instead of the process working directory.
    # Streamlit can launch an app from different working directories locally and
    # in the cloud; using a stable path prevents valid accounts from appearing to
    # vanish merely because the launch directory changed.
    db_path = Path(__file__).resolve().with_name("cyberguard-users.db")
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        about TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    return conn


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"{salt.hex()}${digest.hex()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, stored_digest = stored.split("$", 1)
        candidate = password_hash(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
        return hmac.compare_digest(candidate, stored_digest)
    except (TypeError, ValueError):
        return False


def password_policy_error(password: str) -> str | None:
    """Return a friendly validation message shared by sign-up and password change."""
    if len(password) < 8:
        return "Use at least 8 characters."
    if "@" not in password:
        return "Include the @ symbol in your password."
    if not any(character.isdigit() for character in password):
        return "Include at least one number in your password."
    return None


def create_account(display_name: str, username: str, password: str) -> tuple[bool, str]:
    display_name, username = display_name.strip(), username.strip().lower()
    if len(display_name) < 2:
        return False, "Enter the name you want to show on your profile."
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", username):
        return False, "Username must be 3–32 characters: letters, numbers, dot, underscore, or hyphen."
    if policy_error := password_policy_error(password):
        return False, policy_error
    conn = auth_db()
    try:
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, display_name, password_hash(password), local_time(datetime.now(timezone.utc))),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return False, "That username is already in use. Try signing in instead."
    finally:
        conn.close()
    return True, username


def authenticate(username: str, password: str) -> tuple[bool, str, str, str]:
    conn = auth_db()
    row = conn.execute("SELECT username, display_name, password_hash FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
    conn.close()
    if not row:
        return False, "", "", "account_not_found"
    if not password_matches(password, row[2]):
        return False, "", "", "password_mismatch"
    return True, row[0], row[1], "ok"


def current_user() -> tuple[str, str, str] | None:
    username = st.session_state.get("auth_username")
    if not username:
        return None
    conn = auth_db()
    row = conn.execute("SELECT username, display_name, about FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row


def update_profile(username: str, display_name: str, about: str) -> tuple[bool, str]:
    display_name = display_name.strip()
    if len(display_name) < 2:
        return False, "Enter a name with at least 2 characters."
    conn = auth_db()
    conn.execute("UPDATE users SET display_name=?, about=? WHERE username=?", (display_name, about.strip()[:300], username))
    conn.commit()
    conn.close()
    st.session_state.auth_display_name = display_name
    return True, "Profile saved."


def change_password(username: str, current_password: str, new_password: str) -> tuple[bool, str]:
    if policy_error := password_policy_error(new_password):
        return False, policy_error
    conn = auth_db()
    row = conn.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
    if not row or not password_matches(current_password, row[0]):
        conn.close()
        return False, "Your current password is incorrect."
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash(new_password), username))
    conn.commit()
    conn.close()
    return True, "Password updated."


def sign_out() -> None:
    st.session_state.authenticated = False
    st.session_state.auth_username = ""
    st.session_state.auth_display_name = ""
    st.session_state.workspace_page = "Overview"
    st.session_state.sidebar_page = "Overview"
    st.session_state.page_history = []


def show_auth_page() -> None:
    _, panel, _ = st.columns([1, 1.2, 1])
    with panel:
        st.markdown("<div class='cg-auth-hero'><div class='cg-auth-badge'>⬡</div><div class='cg-eyebrow'>CYBERGUARD AI / SECURE WORKSPACE</div><h1>Welcome</h1><p style='color:#aebdd2'>Sign in to turn real Windows activity into clear, understandable security findings.</p><div class='cg-auth-features'><span>Real log analysis</span><span>Explainable findings</span><span>Indian Standard Time</span></div></div>", unsafe_allow_html=True)
        mode = st.radio("Account option", ["Sign in", "Create account"], horizontal=True, label_visibility="collapsed", key="auth_mode")
        if mode == "Sign in":
            with st.form("sign-in-form"):
                username = st.text_input("Username", placeholder="Your username")
                password = st.text_input("Password", type="password", placeholder="Your password")
                submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if submitted:
                valid, verified_username, display_name, reason = authenticate(username, password)
                if valid:
                    st.session_state.authenticated = True
                    st.session_state.auth_username = verified_username
                    st.session_state.auth_display_name = display_name
                    st.rerun()
                if reason == "account_not_found":
                    st.error("No saved account was found for that username.")
                    st.info("If you created this account before the latest Streamlit deployment, its local demo record may have been cleared. Select **Create account** once to save it again.")
                else:
                    st.error("The password does not match this account. Check Caps Lock and enter the exact password you created.")
            st.caption("New here? Select **Create account** above.")
        else:
            with st.form("create-account-form"):
                display_name = st.text_input("Your name", placeholder="How should CyberGuard address you?")
                username = st.text_input("Choose a username", placeholder="e.g. rahul.sharma")
                password = st.text_input("Create password", type="password", placeholder="8+ characters with @ and a number")
                confirm_password = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)
            if submitted:
                if password != confirm_password:
                    st.error("The passwords do not match.")
                else:
                    created, result = create_account(display_name, username, password)
                    if created:
                        st.session_state.authenticated = True
                        st.session_state.auth_username = result
                        st.session_state.auth_display_name = display_name.strip()
                        st.rerun()
                    st.error(result)
            st.caption("Already have an account? Select **Sign in** above.")
        st.caption("Password rule: 8+ characters, the @ symbol, and at least one number. Use a unique practice password; do not reuse a work or banking password.")


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
        findings.append({"id": f"finding-{ip}", "timestamp": last, "title": finding_title, "plain_summary": plain_summary, "next_steps": next_steps, "category": "Sign-in activity", "severity": "High" if success and privileged else "Medium", "source": "Collected or uploaded logs", "evidence": plain_summary + " This is an automated rule match, not proof that someone accessed the device.", "status": "New", "eventIds": [e["id"] for e in burst + follow], "simulated": False})
    return findings


def set_page(page: str) -> None:
    current = st.session_state.get("workspace_page", "Overview")
    if page != current:
        st.session_state.page_history.append(current)
        st.session_state.workspace_page = page
    if page in NAV:
        st.session_state.sidebar_page = page


def go_back() -> None:
    if st.session_state.page_history:
        previous = st.session_state.page_history.pop()
        st.session_state.workspace_page = previous
        if previous in NAV:
            st.session_state.sidebar_page = previous


FEATURE_GUIDES = {
    "Overview": ("Your starting point", "See the most important thing to do next, recent activity, and quick links to the right page."),
    "Profile": ("My profile", "View and update the name and short description used in your CyberGuard workspace."),
    "Scans": ("Check my activity", "Runs a guided review of the activity already in this workspace and turns it into easy-to-read results."),
    "Event review": ("Activity history", "Search or upload activity records, then open an item to understand what happened."),
    "Findings": ("What needs attention", "Shows possible security concerns in plain language, along with the safest next action."),
    "Investigations": ("My follow-ups", "Keep a simple record of what you checked, who is handling it, and what should happen next."),
    "Analytics": ("Activity summary", "Shows patterns in your activity over time so you can spot changes without reading every record."),
    "ML Lab": ("Smart analysis", "Combines Isolation Forest, Local Outlier Factor, and an Autoencoder to rank unusual activity and explain why it stood out."),
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


def structured_log_features(events: list[dict]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Convert stored log records into the shared numeric anomaly feature matrix."""
    frame = pd.DataFrame(events).copy()
    frame["id"] = frame["id"].astype(str)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame["hour"] = frame["timestamp"].dt.hour
    frame["severity_weight"] = frame["severity"].map({"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}).fillna(0)
    frame["type_frequency"] = frame.groupby("eventType")["eventType"].transform("size")
    frame["actor_frequency"] = frame.groupby("user")["user"].transform("size")
    frame["source_frequency"] = frame.groupby("sourceIp")["sourceIp"].transform("size")
    encoded = pd.get_dummies(frame[["eventType", "user", "sourceIp", "status"]].fillna("unknown"), dtype=float)
    numeric = frame[["hour", "severity_weight", "type_frequency", "actor_frequency", "source_frequency"]].astype(float)
    features = pd.concat([numeric, encoded], axis=1)
    return frame, features


def anomaly_scores(events: list[dict], contamination: float) -> pd.DataFrame:
    """Score stored telemetry with an unsupervised Isolation Forest model."""
    frame, features = structured_log_features(events)
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


def local_outlier_factor_scores(events: list[dict], contamination: float) -> pd.DataFrame:
    """Score records by comparing each event with its nearest neighbours."""
    frame, features = structured_log_features(events)
    neighbour_count = max(2, min(20, len(frame) - 1))
    model = LocalOutlierFactor(n_neighbors=neighbour_count, contamination=contamination)
    model.fit_predict(features)
    raw_score = -model.negative_outlier_factor_
    scale = raw_score.max() - raw_score.min()
    frame["lof_score"] = 50.0 if scale == 0 else ((raw_score - raw_score.min()) / scale * 100)
    return frame[["id", "lof_score"]]


def hybrid_anomaly_scores(events: list[dict], contamination: float, progress=None) -> tuple[pd.DataFrame, list[dict]]:
    """Combine Isolation Forest, Local Outlier Factor, and one Autoencoder."""
    baseline = anomaly_scores(events, contamination).rename(columns={"anomaly_score": "isolation_forest_score"})
    diagnostics = [{
        "model": "Isolation Forest",
        "family": "Classical unsupervised ML",
        "status": "Completed",
        "final_loss": None,
        "records": len(events),
        "note": "200 trees; retained as the explainable machine-learning baseline.",
    }]
    if progress:
        progress("Local Outlier Factor", 0.12)
    try:
        lof_scores = local_outlier_factor_scores(events, contamination)
        combined = baseline.merge(lof_scores, on="id", how="left")
        diagnostics.append({
            "model": "Local Outlier Factor",
            "family": "Neighbour-based unsupervised ML",
            "status": "Completed",
            "final_loss": None,
            "records": len(events),
            "note": f"Compared each event with its {max(2, min(20, len(events) - 1))} nearest neighbours.",
        })
    except ValueError as exc:
        combined = baseline.copy()
        diagnostics.append({
            "model": "Local Outlier Factor",
            "family": "Neighbour-based unsupervised ML",
            "status": "Unavailable",
            "final_loss": None,
            "records": len(events),
            "note": str(exc),
        })
    try:
        from cyberguard_dl import DeepLearningUnavailable, deep_learning_scores

        deep_scores, deep_diagnostics = deep_learning_scores(events, progress=progress)
        diagnostics.extend(deep_diagnostics)
        combined = combined.merge(deep_scores, on="id", how="left")
    except (ImportError, DeepLearningUnavailable, ValueError) as exc:
        diagnostics.append({
            "model": "Autoencoder",
            "family": "Reconstruction neural network",
            "status": "Unavailable",
            "final_loss": None,
            "records": len(events),
            "note": str(exc),
        })

    score_weights = {
        "isolation_forest_score": 0.34,
        "lof_score": 0.33,
        "autoencoder_score": 0.33,
    }
    available_scores = [column for column in score_weights if column in combined and combined[column].notna().any()]
    weighted_total = pd.Series(0.0, index=combined.index)
    available_weight = pd.Series(0.0, index=combined.index)
    for column in available_scores:
        valid = combined[column].notna()
        weighted_total.loc[valid] += combined.loc[valid, column] * score_weights[column]
        available_weight.loc[valid] += score_weights[column]
    combined["anomaly_score"] = (weighted_total / available_weight.replace(0, 1)).clip(0, 100)

    model_names = {
        "isolation_forest_score": "Isolation Forest",
        "lof_score": "Local Outlier Factor",
        "autoencoder_score": "Autoencoder",
    }
    thresholds = {
        column: combined[column].quantile(max(0.0, 1.0 - contamination))
        for column in available_scores
    }

    def agreement(row: pd.Series) -> tuple[int, str]:
        raised = [
            model_names[column]
            for column in available_scores
            if pd.notna(row[column]) and row[column] >= thresholds[column] and row[column] > 0
        ]
        return len(raised), ", ".join(raised) if raised else "No individual model placed it in its highest-risk group"

    agreements = combined.apply(agreement, axis=1)
    combined["model_agreement"] = agreements.map(lambda value: value[0])
    combined["models_raising"] = agreements.map(lambda value: value[1])
    review_count = max(1, int(round(len(combined) * contamination)))
    review_ids = set(combined.nlargest(review_count, "anomaly_score")["id"])
    combined["model_label"] = combined["id"].map(lambda value: "Anomalous" if value in review_ids else "Baseline")
    combined["explanation"] = combined.apply(
        lambda row: f"{row['explanation']}; model agreement: {row['models_raising']}", axis=1
    )
    return combined.sort_values("anomaly_score", ascending=False), diagnostics


def local_db() -> sqlite3.Connection:
    conn = sqlite3.connect("cyberguard-local.db")
    conn.execute("CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, finding_id TEXT, title TEXT, status TEXT, owner TEXT, notes TEXT, updated_at TEXT)")
    conn.commit()
    return conn


def downloadable_collector_script() -> str:
    """Return the local-only PowerShell collector embedded in the CMD download."""
    return r'''# CyberGuard AI Windows Log Collector
param([int]$Days = 7)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$warnings = [System.Collections.Generic.List[string]]::new()

function Find-OutputFolder {
  $candidates = [System.Collections.Generic.List[string]]::new()
  try {
    $value = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name Desktop -ErrorAction Stop).Desktop
    if ($value) { $candidates.Add([Environment]::ExpandEnvironmentVariables($value)) }
  } catch {}
  $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
  if ($desktop) { $candidates.Add($desktop) }
  if ($env:OneDrive) { $candidates.Add((Join-Path $env:OneDrive 'Desktop')) }
  if ($env:OneDriveCommercial) { $candidates.Add((Join-Path $env:OneDriveCommercial 'Desktop')) }
  if ($env:USERPROFILE) {
    $candidates.Add((Join-Path $env:USERPROFILE 'Desktop'))
    $candidates.Add((Join-Path $env:USERPROFILE 'Downloads'))
    $candidates.Add((Join-Path $env:USERPROFILE 'Documents'))
  }
  $candidates.Add($env:TEMP)
  foreach ($candidate in @($candidates | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($candidate) -or -not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
    try {
      $probe = Join-Path $candidate ('.cyberguard-write-test-' + [Guid]::NewGuid().ToString('N') + '.tmp')
      [IO.File]::WriteAllText($probe, 'ok')
      Remove-Item -LiteralPath $probe -Force
      return (Resolve-Path -LiteralPath $candidate).Path
    } catch {}
  }
  throw 'CyberGuard could not find a writable Desktop, Downloads, or Documents folder.'
}

try {
  $outputFolder = Find-OutputFolder
  $csvPath = Join-Path $outputFolder 'cyberguard-real-logs.csv'
  $statusPath = Join-Path $outputFolder 'cyberguard-collector-status.txt'
  $since = (Get-Date).AddDays(-$Days)
  $labels = @{4624='Successful Login';4625='Failed Login';4672='Privilege Change';4688='Process Start';4697='Service Installation'}
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($channel in @('Security','System','Application')) {
    if ($channel -eq 'Security') {
      $filter = @{LogName='Security'; Id=@(4624,4625,4672,4688,4697); StartTime=$since}
    } else {
      $filter = @{LogName=$channel; Level=@(1,2,3); StartTime=$since}
    }
    try { $channelEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 750 -ErrorAction Stop) }
    catch {
      $warnings.Add("$channel log: $($_.Exception.Message)")
      continue
    }
    foreach ($event in $channelEvents) {
      try {
        $eventId = [int]$event.Id
        $eventType = if ($labels.ContainsKey($eventId)) {$labels[$eventId]} elseif ($channel -eq 'System') {'System Event'} else {'Application Event'}
        $severity = if ($eventId -eq 4625 -or $eventId -eq 4697) {'Medium'} elseif ($eventId -eq 4672 -or $event.Level -eq 2) {'High'} elseif ($event.Level -eq 1) {'Critical'} elseif ($event.Level -eq 3) {'Medium'} else {'Low'}
        $status = if ($eventId -eq 4625) {'Failed'} elseif ($eventId -eq 4624) {'Success'} else {'Observed'}
        $user = 'unknown'
        if ($null -ne $event.UserId) { try {$user = $event.UserId.Translate([System.Security.Principal.NTAccount]).Value} catch {} }
        try { $message = [string]$event.FormatDescription() } catch { $message = '' }
        $message = ($message -replace "[`r`n]+", ' ').Trim()
        if ([string]::IsNullOrWhiteSpace($message)) { $message = "Windows $channel event $eventId from $($event.ProviderName)." }
        $ip = if ($message -match '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)') {$Matches[0]} else {'unknown'}
        $eventTime = if ($null -ne $event.TimeCreated) {$event.TimeCreated.ToUniversalTime()} else {(Get-Date).ToUniversalTime()}
        $rows.Add([PSCustomObject]@{timestamp=$eventTime.ToString('o');eventId=[string]$eventId;eventType=$eventType;user=$user;sourceIp=$ip;destinationIp='unknown';severity=$severity;status=$status;description=$message})
      } catch {
        $warnings.Add("Skipped one $channel event: $($_.Exception.Message)")
      }
    }
  }

  if ($rows.Count -gt 0) {
    $rows | Sort-Object timestamp -Descending | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
  } else {
    'timestamp,eventId,eventType,user,sourceIp,destinationIp,severity,status,description' | Set-Content -LiteralPath $csvPath -Encoding UTF8
  }

  $summary = @(
    'CyberGuard AI Windows Log Collector',
    "Completed: $(Get-Date -Format 'dd MMM yyyy, hh:mm:ss tt')",
    "Records collected: $($rows.Count)",
    "CSV file: $csvPath"
  )
  if ($warnings.Count -gt 0) { $summary += ''; $summary += 'Non-fatal notes:'; $summary += $warnings }
  $summary | Set-Content -LiteralPath $statusPath -Encoding UTF8

  Write-Host ''
  Write-Host "SUCCESS: $($rows.Count) real Windows event records collected." -ForegroundColor Green
  Write-Host 'Your CSV file is here:' -ForegroundColor White
  Write-Host $csvPath -ForegroundColor Cyan
  if ($outputFolder -like '*\Downloads') { Write-Host 'Desktop was not writable, so the file was saved in Downloads.' -ForegroundColor Yellow }
  if ($rows.Count -eq 0) { Write-Host 'The CSV has headers only. Read the status file to see which Windows logs were unavailable.' -ForegroundColor Yellow }
  Write-Host "Status details: $statusPath" -ForegroundColor DarkGray
  try { Start-Process explorer.exe -ArgumentList "/select,`"$csvPath`"" } catch {}
  exit 0
} catch {
  $fallbackStatus = Join-Path $env:TEMP 'cyberguard-collector-error.txt'
  $errorText = @(
    'CyberGuard AI collector could not finish.',
    "Time: $(Get-Date -Format 'dd MMM yyyy, hh:mm:ss tt')",
    "Error: $($_.Exception.Message)",
    'Run the downloaded CMD file again and accept the Administrator prompt.'
  )
  try { $errorText | Set-Content -LiteralPath $fallbackStatus -Encoding UTF8 } catch {}
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'This window will stay open. Take a screenshot of this error if you need help.' -ForegroundColor Yellow
  Write-Host "Diagnostic file: $fallbackStatus" -ForegroundColor Cyan
  exit 1
}
'''


def downloadable_collector_launcher() -> str:
    """Return a hybrid CMD/PowerShell launcher without command-length limits."""
    launcher = r'''@echo off
setlocal EnableExtensions DisableDelayedExpansion
title CyberGuard AI Windows Log Collector
color 0B

if /I "%~1"=="elevated" goto collect
powershell.exe -NoProfile -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto collect

echo CyberGuard needs Administrator permission to read Windows Event Logs.
echo Select YES in the Windows prompt.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -WorkingDirectory '%~dp0' -Verb RunAs -Wait"
if errorlevel 1 (
  echo.
  echo ERROR: Administrator permission was cancelled or the elevated collector could not start.
  echo Download the file again, then right-click it and select Run as administrator.
  echo.
  pause
  exit /b 1
)
exit /b 0

:collect
cls
echo ================================================================
echo              CYBERGUARD AI WINDOWS LOG COLLECTOR
echo ================================================================
echo.
echo Reading selected Security, System, and Application events...
echo This can take 1 to 3 minutes. Do not close this window.
echo.

set "collector=%TEMP%\cyberguard-log-collector.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$content=Get-Content -LiteralPath '%~f0'; $marker=[Array]::IndexOf($content,'REM_CYBERGUARD_POWERSHELL_PAYLOAD'); if($marker -lt 0){throw 'Collector payload was not found.'}; [IO.File]::WriteAllLines($env:TEMP+'\cyberguard-log-collector.ps1',$content[($marker+1)..($content.Length-1)],(New-Object Text.UTF8Encoding($true)))"
if errorlevel 1 (
  echo ERROR: The collector script could not be prepared.
  echo Delete this file, download a fresh copy from CyberGuard, and try again.
  echo.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%collector%"
set "collectorExit=%errorlevel%"
echo.
if "%collectorExit%"=="0" (
  echo File Explorer should now be showing cyberguard-real-logs.csv.
) else (
  echo Collection did not finish. Read the ERROR message above.
)
echo.
echo Press any key to close this window.
pause >nul
exit /b %collectorExit%

REM_CYBERGUARD_POWERSHELL_PAYLOAD
__POWERSHELL_PAYLOAD__
'''
    return launcher.replace("__POWERSHELL_PAYLOAD__", downloadable_collector_script()).replace("\n", "\r\n")


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


def security_posture(events: list[dict], findings: list[dict]) -> tuple[str, str, str]:
    """Describe the current workspace without inventing a security score."""
    if not events:
        return "Ready for real logs", "safe", "No activity file is loaded yet"
    open_findings = [item for item in findings if item.get("status") in ("New", "Investigating")]
    urgent_events = [item for item in events if item.get("severity") in ("Critical", "High")]
    if any(item.get("severity") in ("Critical", "High") for item in open_findings):
        return "Review recommended", "urgent", "A high-priority pattern needs your attention"
    if open_findings or urgent_events:
        return "Check these records", "warning", "CyberGuard found activity worth reviewing"
    return "No urgent pattern found", "safe", "The loaded records have no active rule-based finding"


def overview_hero(events: list[dict], findings: list[dict], scans: list[dict], display_name: str) -> None:
    title, tone, detail = security_posture(events, findings)
    open_findings = sum(item.get("status") in ("New", "Investigating") for item in findings)
    urgent_events = sum(item.get("severity") in ("Critical", "High") for item in events)
    latest_check = scans[0].get("started", "Available") if scans else "Not run"
    latest_check = html.escape(str(latest_check))
    safe_name = html.escape(display_name or "there")
    st.markdown(f"""
    <section class="cg-hero">
      <div class="cg-hero-grid">
        <div>
          <span class="cg-status-badge {tone}"><span class="cg-live-dot"></span>{html.escape(title)}</span>
          <h1>Clear security answers,<br>from your real activity.</h1>
          <p class="cg-hero-copy">Welcome back, {safe_name}. CyberGuard reads the Windows activity you choose to add, highlights unusual patterns, and explains what they mean in everyday language—without pretending to scan your device from the cloud.</p>
          <p class="cg-hero-copy" style="font-size:11px;margin-top:12px;color:#7f91ac">{html.escape(detail)}</p>
        </div>
        <div class="cg-orb-wrap" aria-label="Decorative security analysis visual">
          <div class="cg-orb"><div class="cg-orb-grid"></div><i class="cg-orb-node one"></i><i class="cg-orb-node two"></i><i class="cg-orb-node three"></i></div>
        </div>
      </div>
    </section>
    <section class="cg-kpis">
      <article class="cg-kpi"><div class="cg-kpi-label">Activity records</div><div class="cg-kpi-value">{len(events):,}</div><div class="cg-kpi-detail">Real rows currently loaded</div></article>
      <article class="cg-kpi"><div class="cg-kpi-label">Needs review</div><div class="cg-kpi-value">{open_findings:,}</div><div class="cg-kpi-detail">Open rule-based findings</div></article>
      <article class="cg-kpi"><div class="cg-kpi-label">High priority</div><div class="cg-kpi-value">{urgent_events:,}</div><div class="cg-kpi-detail">High or critical event labels</div></article>
      <article class="cg-kpi"><div class="cg-kpi-label">Latest activity check</div><div class="cg-kpi-value" style="font-size:18px;margin-top:17px">{latest_check}</div><div class="cg-kpi-detail">Displayed in Indian Standard Time</div></article>
    </section>
    """, unsafe_allow_html=True)


def incident_queue(findings: list[dict], events: list[dict]) -> None:
    """Render a compact, readable queue using only real workspace records."""
    rows: list[dict] = []
    for finding in findings[:6]:
        rows.append({
            "severity": finding.get("severity", "Medium"),
            "title": finding.get("title", "Activity needs review"),
            "detail": finding.get("category", "Rule-based finding"),
            "source": finding.get("source", "Loaded logs"),
            "state": finding.get("status", "New"),
        })
    if not rows:
        for event in sorted(events, key=lambda item: item.get("timestamp", datetime.min.replace(tzinfo=timezone.utc)), reverse=True)[:6]:
            rows.append({
                "severity": event.get("severity", "Informational"),
                "title": event.get("eventType", "Windows activity"),
                "detail": event.get("description", "Recorded Windows activity"),
                "source": event.get("sourceIp") or event.get("user") or "Local record",
                "state": "Reviewed" if event.get("severity") not in ("Critical", "High") else "Check",
            })
    if not rows:
        return
    body = []
    for row in rows:
        severity = str(row["severity"])
        tone = severity.lower() if severity.lower() in {"critical", "high", "medium", "low", "informational"} else "informational"
        body.append(
            f'<div class="cg-queue-row"><div><span class="cg-severity {tone}">{html.escape(severity)}</span></div>'
            f'<div><div class="cg-queue-main">{html.escape(str(row["title"]))}</div><div class="cg-queue-sub">{html.escape(str(row["detail"]))}</div></div>'
            f'<div>{html.escape(str(row["source"]))}</div><div class="cg-state">{html.escape(str(row["state"]))}</div></div>'
        )
    st.markdown('<div class="cg-queue"><div class="cg-queue-head"><div>Priority</div><div>Activity</div><div>Source</div><div>Status</div></div>' + "".join(body) + "</div>", unsafe_allow_html=True)


if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "auth_username" not in st.session_state:
    st.session_state.auth_username = ""
if "auth_display_name" not in st.session_state:
    st.session_state.auth_display_name = ""

if not st.session_state.authenticated:
    show_auth_page()
    st.stop()


if "events" not in st.session_state:
    st.session_state.events = []
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
if "page_history" not in st.session_state:
    st.session_state.page_history = []


def select_workspace_page() -> None:
    set_page(st.session_state.sidebar_page)

with st.sidebar:
    st.markdown('<div class="cg-brand">CYBERGUARD<span> AI</span></div><div class="cg-eyebrow">SOC workbench / M.Tech</div>', unsafe_allow_html=True)
    st.markdown("---")
    st.radio("WORKSPACE", NAV, format_func=lambda item: f"{NAV_ICONS[item]}   {PAGE_LABELS[item]}", label_visibility="visible", key="sidebar_page", on_change=select_workspace_page)
    st.markdown("---")
    with st.expander(f"👤  {st.session_state.auth_display_name}", expanded=False):
        st.markdown("<div class='cg-eyebrow'>SIGNED IN ACCOUNT</div>", unsafe_allow_html=True)
        st.caption(f"@{st.session_state.auth_username}")
        st.button("Open my profile", use_container_width=True, on_click=set_page, args=("Profile",))
        st.button("Sign out", use_container_width=True, on_click=sign_out)
    st.markdown("---")
    st.markdown("""
    <div class='cg-eyebrow'>PROJECT TEAM / GITHUB</div>
    <div class='cg-team-list'>
      <a class='cg-team-link' href='https://github.com/vaibhavrxj' target='_blank'>Vaibhav Raj <span>@vaibhavrxj ↗</span></a>
      <a class='cg-team-link' href='https://github.com/AnieeD' target='_blank'>Aniket <span>@AnieeD ↗</span></a>
      <a class='cg-team-link' href='https://github.com/akhilpanwar873' target='_blank'>Akhil Panwar <span>@akhilpanwar873 ↗</span></a>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    model_copy = "Ready for uploaded activity" if not events else f"{len(events):,} records available"
    st.markdown(f"<div class='cg-eyebrow'>MODEL / ANALYTICS</div><p style='font-size:12px;color:#48e39b'><span class='cg-live-dot'></span>{model_copy}</p><p style='font-size:11px;color:#8293ae'>Isolation Forest+Local Outlier Factor+ DL models</p>", unsafe_allow_html=True)
    if st.button("↻  Clear loaded logs", use_container_width=True):
        st.session_state.events = []
        st.session_state.findings = []
        st.session_state.scans = []
        st.session_state.pop("ml_results", None)
        st.session_state.pop("ml_diagnostics", None)
        st.session_state.pop("ml_event_signature", None)
        st.rerun()
    st.markdown("<br><div class='cg-eyebrow'>CYBERGUARD / 0.1<br>LOCAL LAB</div>", unsafe_allow_html=True)

page = st.session_state.workspace_page
header_left, header_back, header_about = st.columns([5, 1, 1])
with header_left:
    page_title = PAGE_LABELS[page] if page != "Overview" else "Security workspace"
    st.markdown(f"<div class='cg-page-head'><span class='cg-page-kicker'>CYBERGUARD / YOUR SECURITY</span><span class='cg-head-chip'><span class='cg-live-dot'></span>Workspace ready</span></div><h1 style='margin:.15rem 0 .35rem'>{html.escape(page_title)}</h1><div style='color:#91a0ba;font-size:13px'>Real activity, clear explanations, safer next steps</div>", unsafe_allow_html=True)
with header_back:
    if page != "Overview":
        st.button("← Back", use_container_width=True, on_click=go_back, disabled=not st.session_state.page_history)
with header_about:
    if page != "About CyberGuard":
        st.button("ⓘ About", use_container_width=True, on_click=set_page, args=("About CyberGuard",))
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


if page == "Profile":
    profile = current_user()
    if profile is None:
        sign_out()
        st.rerun()
    username, display_name, about = profile
    st.markdown(f"<div class='cg-card'><div class='cg-eyebrow'>YOUR CYBERGUARD ACCOUNT</div><h2 style='margin:.35rem 0'>{display_name}</h2><div style='color:#96a6ac;font-size:13px'>@{username}</div></div>", unsafe_allow_html=True)
    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Profile details")
        with st.form("profile-form"):
            new_name = st.text_input("Name", value=display_name)
            new_about = st.text_area("About you", value=about, max_chars=300, placeholder="For example: M.Tech student interested in cybersecurity.")
            save_profile = st.form_submit_button("Save profile", type="primary")
        if save_profile:
            saved, message = update_profile(username, new_name, new_about)
            (st.success if saved else st.error)(message)
            if saved:
                st.rerun()
    with right:
        st.subheader("Account security")
        with st.form("password-form"):
            current_password = st.text_input("Current password", type="password")
            new_password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            save_password = st.form_submit_button("Update password")
        if save_password:
            if new_password != confirm_password:
                st.error("The new passwords do not match.")
            else:
                changed, message = change_password(username, current_password, new_password)
                (st.success if changed else st.error)(message)
        st.caption("Your password is stored as a salted cryptographic hash, not as plain text.")

    st.markdown("---")
    st.subheader("Recent activity")
    st.caption("This is the latest security activity and activity-check history currently loaded in your CyberGuard workspace.")
    recent_events_col, recent_checks_col = st.columns([1.65, 1])
    with recent_events_col:
        st.markdown("#### Latest security records")
        if events:
            recent_events = sorted(events, key=lambda item: item["timestamp"], reverse=True)[:5]
            event_table(recent_events, "profile-recent-events")
        else:
            st.info("No security records have been added yet. Upload logs or connect your PC to begin building your activity history.")
    with recent_checks_col:
        st.markdown("#### Recent checks")
        if st.session_state.scans:
            scan_history = pd.DataFrame(st.session_state.scans[:5]).rename(columns={"started": "When", "type": "Check", "status": "Result", "records reviewed": "Records reviewed"})
            st.dataframe(scan_history[["When", "Check", "Result", "Records reviewed"]], use_container_width=True, hide_index=True, height=245)
        else:
            st.info("No activity checks have been run yet.")

elif page == "About CyberGuard":
    st.markdown("<div class='cg-card'><h2 style='margin-top:0'>CyberGuard AI</h2><p style='color:#aebdc2;font-size:15px'>A simple cybersecurity workspace that turns activity records into understandable advice. It is designed for people who want to know what happened, whether it matters, and what to do next.</p></div>", unsafe_allow_html=True)
    journey, features, data = st.tabs(["How it works", "What each feature does", "Your data and results"])
    with journey:
        st.markdown("### A simple four-step journey")
        steps = st.columns(4)
        for col, title, body in zip(steps, ["1. Add activity", "2. Check it", "3. Understand it", "4. Follow up"], ["Upload a real log file or collect selected Windows logs locally.", "Run a quick activity check or use Smart analysis to identify unusual patterns.", "Open What needs attention for a plain explanation and recommended next step.", "Save notes in My follow-ups and download a report when you need one."]):
            col.markdown(f"<div class='cg-card'><b>{title}</b><div style='color:#aebdc2;font-size:12px;margin-top:8px'>{body}</div></div>", unsafe_allow_html=True)
        a1, a2, a3 = st.columns(3)
        a1.button("Add or review activity", use_container_width=True, key="about-history", on_click=set_page, args=("Event review",))
        a2.button("Run an activity check", type="primary", use_container_width=True, key="about-check", on_click=set_page, args=("Scans",))
        a3.button("See next steps", use_container_width=True, key="about-findings", on_click=set_page, args=("Findings",))
    with features:
        st.markdown("### Project functionality")
        for feature in FEATURE_GUIDES:
            title, description = FEATURE_GUIDES[feature]
            st.markdown(f"<div class='cg-card'><b>{title}</b><div style='color:#aebdc2;font-size:13px;margin-top:7px'>{description}</div></div>", unsafe_allow_html=True)
    with data:
        st.markdown("### What happens when you use CyberGuard")
        st.markdown("**Activity history** works with the records in the current workspace. **Check my activity** uses clear security rules to look for sign-in patterns. **Smart analysis** combines Isolation Forest, Local Outlier Factor, and an Autoencoder to rank records that differ from the current activity pattern. **What needs attention** turns those results into plain language.\n\nWhen you use the hosted app, follow-up notes are saved in your browser and can be downloaded as a CSV file. Windows Event Log collection is available only when the project runs locally on a Windows computer.")
        st.info("CyberGuard helps you decide what to review first. For an unfamiliar sign-in or a possible account issue, change the password and contact your IT support team.")

elif page == "Overview":
    overview_hero(events, findings, st.session_state.scans, st.session_state.auth_display_name)
    if not events:
        st.markdown("<div class='cg-section-title'><div><div class='cg-eyebrow'>START HERE</div><h2>From Windows logs to a clear answer</h2></div><p>Three guided steps · no cybersecurity background needed</p></div>", unsafe_allow_html=True)
        st.markdown("""
        <section class="cg-step-grid">
          <article class="cg-step"><div class="cg-step-num">01</div><h3>Collect real activity</h3><p>Download the Windows collector, run it on the computer you want to check, and let it create a CSV file on that computer.</p></article>
          <article class="cg-step"><div class="cg-step-num">02</div><h3>Add the CSV securely</h3><p>Open Activity history and upload the file. CyberGuard reads only the activity included in that file.</p></article>
          <article class="cg-step"><div class="cg-step-num">03</div><h3>Understand the result</h3><p>Run an activity check, then open What needs attention for a plain-language explanation and next step.</p></article>
        </section>
        """, unsafe_allow_html=True)
        b1, b2, b3 = st.columns(3)
        b1.button("01  Get Windows logs", type="primary", use_container_width=True, on_click=set_page, args=("Devices",))
        b2.button("02  Upload a log file", use_container_width=True, on_click=set_page, args=("Event review",))
        b3.button("Learn how it works", use_container_width=True, on_click=set_page, args=("About CyberGuard",))
        st.info("Your dashboard is intentionally empty until you add real activity. CyberGuard does not fill it with demo incidents.")
    else:
        filter_col, action_col = st.columns([1.2, 2.8])
        with filter_col:
            window = st.radio("Show activity from", ["Past 24 hours", "Past 7 days", "All records"], horizontal=True, label_visibility="collapsed", key="overview_window")
        with action_col:
            quick_one, quick_two = st.columns(2)
            quick_one.button("Run another activity check", type="primary", use_container_width=True, on_click=set_page, args=("Scans",))
            quick_two.button("Open smart analysis", use_container_width=True, on_click=set_page, args=("ML Lab",))
        visible_events = [e for e in events if in_window(e, window)]
        st.markdown("<div class='cg-section-title'><div><div class='cg-eyebrow'>PRIORITY QUEUE</div><h2>Activity to understand first</h2></div><p>Built only from the records currently loaded</p></div>", unsafe_allow_html=True)
        incident_queue(findings, visible_events)
        actions = st.columns([1, 1, 1])
        actions[0].button("Review all activity", use_container_width=True, on_click=set_page, args=("Event review",))
        actions[1].button("Explain the findings", use_container_width=True, on_click=set_page, args=("Findings",))
        actions[2].button("Ask CyberGuard", use_container_width=True, on_click=set_page, args=("Assistant",))
        st.markdown("<div class='cg-section-title'><div><div class='cg-eyebrow'>NEXT ACTIONS</div><h2>What CyberGuard recommends</h2></div><p>Suggestions—not automatic changes to your PC</p></div>", unsafe_allow_html=True)
        if findings:
            recommendation_columns = st.columns(min(3, len(findings)))
            for index, finding in enumerate(findings[:3]):
                safe_title = html.escape(str(finding.get("title", "Review this activity")))
                safe_step = html.escape(str(finding.get("next_steps", "Open the finding to see the recommended next step.")))
                recommendation_columns[index].markdown(f"<div class='cg-card' style='min-height:160px'><span class='cg-severity {str(finding.get('severity', 'Medium')).lower()}'>{html.escape(str(finding.get('severity', 'Medium')))}</span><h3 style='font-size:15px;margin:15px 0 8px'>{safe_title}</h3><div style='color:#91a0ba;font-size:11px;line-height:1.6'>{safe_step}</div></div>", unsafe_allow_html=True)
        else:
            st.success("No active rule-based finding needs action right now. You can still review the records or run Smart analysis.")
        st.caption("Last check: " + (st.session_state.scans[0]["started"] if st.session_state.scans else "Not run yet") + " · Time zone: IST (UTC+05:30).")

elif page == "Event review":
    st.caption("Upload a real CSV/JSON log file, then search and inspect the records.")
    upload = st.file_uploader("Upload CSV / JSON logs", type=["csv", "json"])
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
                item.update({"id": f"upload-{uuid.uuid4().hex[:10]}", "timestamp": stamp.astimezone(timezone.utc), "simulated": False})
                normalized.append(item)
            st.session_state.events = sorted(normalized + events, key=lambda e: e["timestamp"], reverse=True)
            st.session_state.findings = findings_from_events(st.session_state.events)
            st.success(f"{len(normalized)} events imported. Source data has not been independently verified.")
            st.rerun()
        except Exception as exc:
            st.error(f"Upload not imported: {exc}")
    controls = st.columns([3, 1, 1.5])
    query = controls[0].text_input("Search event IDs, actors, IPs, or evidence", placeholder="e.g. 198.51.100.23")
    sev = controls[1].selectbox("Severity", ["All severities"] + SEVERITIES)
    event_types = sorted({e["eventType"] for e in events})
    selected_types = controls[2].multiselect("Event types", event_types, placeholder="All event types")
    subset = [e for e in events if (sev == "All severities" or e["severity"] == sev) and (not selected_types or e["eventType"] in selected_types) and (not query or query.lower() in " ".join(str(e.get(k, "")) for k in ("eventId", "eventType", "user", "sourceIp", "description")).lower())]
    st.caption(f"{len(subset)} matching records · up to 200 displayed")
    if subset:
        frame = pd.DataFrame(subset[:200]).copy()
        frame["timestamp"] = frame["timestamp"].map(lambda x: local_time(x) if isinstance(x, datetime) else str(x))
        frame = frame.rename(columns={"eventId": "Event ID", "timestamp": "Time", "eventType": "Type", "user": "Actor", "sourceIp": "Source IP", "severity": "Severity", "status": "Status", "description": "Evidence"})
        selection = st.dataframe(frame[["Event ID", "Time", "Type", "Actor", "Source IP", "Severity", "Status", "Evidence"]], use_container_width=True, hide_index=True, key="event-review-table", on_select="rerun", selection_mode="single-row", height=430)
        selected_rows = selection.selection.rows
        if selected_rows:
            chosen = subset[selected_rows[0]]
            st.markdown(f"#### Selected event · `{chosen['eventId']}`")
            st.caption(f"{chosen['eventType']} · {chosen['severity']} · Real uploaded or locally collected log")
            st.write(chosen["description"])
            with st.expander("Full event details"):
                st.json({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in chosen.items()})
    else:
        st.info("No events match these filters. Clear a filter or change the search.")
    st.download_button("Download current events as CSV", pd.DataFrame(subset).to_csv(index=False), "cyberguard-events.csv", "text/csv")

elif page == "Scans":
    st.caption("Run a quick check to find sign-in activity that may need your attention.")

    def run_stored_scan(scan_type: str) -> None:
        if not events:
            st.warning("No real logs are loaded yet. Use Connect my PC on a local Windows run, or upload a CSV/JSON log file in Activity history.")
            return
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
            scan_visual = st.empty()
            scan_visual.markdown("<div class='cg-scan-visual'><div class='cg-radar'></div><div><div class='cg-eyebrow' style='color:#56d7b7'>ANALYZING ACTIVITY</div><div style='font-size:12px;color:#dce6e8;margin-top:4px'>CyberGuard is checking the activity in this workspace.</div></div></div>", unsafe_allow_html=True)
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
            has_attention_item = any(not passed for _, passed in completed)
            completion_icon = "!" if has_attention_item else "✓"
            completion_title = "CHECK COMPLETE · ATTENTION NEEDED" if has_attention_item else "CHECK COMPLETE · ALL CLEAR"
            completion_text = "Some activity needs your attention. See the checklist below and open What needs attention for clear next steps." if has_attention_item else "The activity review is complete. No concerning pattern was found in these checks."
            scan_visual.markdown(f"<div class='cg-scan-complete {'alert' if has_attention_item else ''}'><div class='cg-complete-mark'>{completion_icon}</div><div><div class='cg-eyebrow' style='color:{'#fb7185' if has_attention_item else '#56d7b7'}'>{completion_title}</div><div style='font-size:12px;color:#dce6e8;margin-top:4px'>{completion_text}</div></div></div>", unsafe_allow_html=True)
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
    st.caption("CyberGuard combines two machine-learning models with one Autoencoder, then explains which activity deserves a closer look.")
    if len(events) < 8:
        st.info("Add at least 8 event records to create the ML and deep-learning baselines. Thirty or more records produce a more useful classroom experiment.")
    else:
        current_event_signature = tuple(str(event.get("id", "")) for event in events)
        if st.session_state.get("ml_event_signature") != current_event_signature:
            st.session_state.pop("ml_results", None)
            st.session_state.pop("ml_diagnostics", None)
        c1, c2 = st.columns([2, 1])
        sensitivity = c1.select_slider("How much should CyberGuard flag?", options=["Only unusual", "Balanced", "Show more"], value="Balanced")
        contamination = {"Only unusual": 0.05, "Balanced": 0.10, "Show more": 0.20}[sensitivity]
        c2.metric("Activity reviewed", len(events))
        st.markdown("<div class='cg-card'><div class='cg-eyebrow'>HYBRID INTELLIGENCE</div><div style='font-size:13px;margin-top:8px;color:#b8c5d8'><b>Machine Learning:</b> Isolation Forest and Local Outlier Factor &nbsp;·&nbsp; <b>Deep Learning:</b> Autoencoder</div></div>", unsafe_allow_html=True)
        if st.button("Run ML + deep-learning analysis", type="primary", use_container_width=True):
            progress_bar = st.progress(0, text="Preparing the hybrid analysis…")

            def update_model_progress(model_name: str, fraction: float) -> None:
                progress_bar.progress(min(100, int(fraction * 100)), text=f"Training {model_name} on the current logs…")

            with st.spinner("The Autoencoder is training inside this app session. This can take a short time."):
                st.session_state.ml_results, st.session_state.ml_diagnostics = hybrid_anomaly_scores(
                    events, contamination, progress=update_model_progress
                )
                st.session_state.ml_sensitivity = sensitivity
                st.session_state.ml_event_signature = current_event_signature
            progress_bar.progress(100, text="Hybrid analysis complete")
        results = st.session_state.get("ml_results")
        if results is None:
            st.info("Choose “Run ML + deep-learning analysis” to run the three-model hybrid and get a simple review list.")
        else:
            anomalies = results[results["model_label"] == "Anomalous"]
            if anomalies.empty:
                st.success("Nothing looked unusual in this activity set.")
            else:
                st.warning("The hybrid model found activity that differs from the current baseline. Review these records; this is not proof of an attack.")
            st.markdown("### Things to review first")
            display = results.copy()
            display["Priority"] = display["model_label"].map({"Anomalous": "Review first", "Baseline": "Normal pattern"})
            display = display.rename(columns={"timestamp": "When", "eventType": "What happened", "user": "Account", "sourceIp": "Source IP", "severity": "Importance", "explanation": "Why it stands out", "model_agreement": "Models agreeing"})[["Priority", "When", "What happened", "Account", "Importance", "Models agreeing", "Why it stands out"]]
            st.dataframe(display, use_container_width=True, hide_index=True)
            st.download_button("Download this review list (CSV)", display.to_csv(index=False), "cyberguard-review-list.csv", "text/csv")
            diagnostics = st.session_state.get("ml_diagnostics", [])
            if diagnostics:
                completed = sum(item.get("status") == "Completed" for item in diagnostics)
                metric_columns = st.columns(3)
                metric_columns[0].metric("Models completed", f"{completed} / 3")
                metric_columns[1].metric("Review-first records", int((results["model_label"] == "Anomalous").sum()))
                metric_columns[2].metric("Highest ensemble score", f"{results['anomaly_score'].max():.1f} / 100")
            with st.expander("Compare each model's score"):
                score_columns = [column for column in ["isolation_forest_score", "lof_score", "autoencoder_score", "anomaly_score"] if column in results]
                score_labels = {"id": "Record ID", "eventType": "Activity", "isolation_forest_score": "Isolation Forest", "lof_score": "Local Outlier Factor", "autoencoder_score": "Autoencoder", "anomaly_score": "Combined score"}
                score_table = results[["id", "eventType", *score_columns]].rename(columns=score_labels).copy()
                numeric_score_columns = [label for label in score_labels.values() if label in score_table and label not in ("Record ID", "Activity")]
                score_table[numeric_score_columns] = score_table[numeric_score_columns].round(2)
                st.dataframe(score_table, use_container_width=True, hide_index=True)
            with st.expander("Technical details for your M.Tech project"):
                st.markdown("**Isolation Forest:** Uses 200 random trees to identify rare combinations of structured log fields.\n\n**Local Outlier Factor:** Compares each event with nearby records. An event receives a higher score when its local pattern differs from its neighbours.\n\n**Autoencoder:** Learns to reconstruct the current log-feature pattern. A high reconstruction error raises the review score because the event does not fit that pattern well.\n\n**Hybrid weights:** Isolation Forest 34%, Local Outlier Factor 33%, and Autoencoder 33%. Available model weights are rebalanced automatically if a model cannot run.\n\n**Interpretation:** every score is a relative priority within the records currently loaded. It is not a probability of compromise and it is not proof of an attack.")
                diagnostics = st.session_state.get("ml_diagnostics", [])
                if diagnostics:
                    diagnostic_frame = pd.DataFrame(diagnostics).rename(columns={"model": "Model", "family": "Method", "status": "Status", "final_loss": "Final training loss", "records": "Records", "note": "Notes"})
                    diagnostic_frame["Final training loss"] = pd.to_numeric(diagnostic_frame["Final training loss"], errors="coerce").round(5)
                    st.dataframe(diagnostic_frame, use_container_width=True, hide_index=True)

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
            answer = f"{len(matches)} matching log records found" + (f"; {failed_count} are failed sign-in events." if failed_count else ".")
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
        st.markdown("### Get real Windows logs")
        st.write("Download the fixed launcher, run it once on your Windows PC, then upload the created CSV in **Activity history**.")
        st.download_button("Download fixed Windows Log Collector", downloadable_collector_launcher(), "cyberguard-log-collector-fixed.cmd", "application/octet-stream", type="primary", use_container_width=True)
        with st.container(border=True):
            st.markdown("### How to use this file")
            st.markdown("1. Delete any older CyberGuard collector from **Downloads** so you do not run the wrong copy.\n2. Download `cyberguard-log-collector-fixed.cmd` above.\n3. Open **Downloads**, right-click the new file, and choose **Run as administrator**.\n4. Select **Yes** in the Windows permission prompt.\n5. Wait for the green **SUCCESS** message. Collection can take 1–3 minutes.\n6. File Explorer opens automatically and selects `cyberguard-real-logs.csv`.\n7. The preferred save location is your real Desktop, including a OneDrive Desktop. If Desktop is not writable, the collector uses **Downloads**, then **Documents**.\n8. Return here, open **Activity history**, upload the CSV, then use **Check my activity**.")
        st.info("The CSV is a normal spreadsheet file and opens in Excel. A second file named `cyberguard-collector-status.txt` records the exact save path and any Windows logs that could not be read.")
        with st.expander("If the CSV still does not appear"):
            st.markdown("- Keep the black collector window open and read the final green or red message.\n- Search File Explorer for `cyberguard-real-logs.csv`.\n- Check **Desktop**, **OneDrive → Desktop**, **Downloads**, and **Documents**.\n- If you see a red error, take a screenshot. A diagnostic copy is also saved as `%TEMP%\\cyberguard-collector-error.txt`.\n- Do not rename the file to `.xlsx`; upload the generated `.csv` file directly.")
        st.caption("This fixed launcher skips individual unreadable event messages instead of cancelling the whole export, detects redirected OneDrive desktops, and keeps the result window open.")
    st.markdown("### Live monitoring")
    st.write("This is a one-time collection. It does not run in the background, stream events continuously, or take response actions.")

st.markdown("<hr style='border-color:#2b3946;margin-top:30px'><div class='cg-eyebrow'>CYBERGUARD AI · M.TECH CYBERSECURITY ANALYTICS WORKBENCH</div>", unsafe_allow_html=True)
