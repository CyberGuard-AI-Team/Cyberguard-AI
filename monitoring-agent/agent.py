#!/usr/bin/env python3
"""Independent CyberGuard OS event collector (Windows first, Linux supported)."""
import json, os, platform, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
import requests

VERSION = "1.0.0"
API = os.environ.get("CYBERGUARD_API", "").rstrip("/")
TOKEN = os.environ.get("CYBERGUARD_TOKEN", "")
STATE = Path(__file__).with_name("agent-state.json")
WINDOWS_IDS = {4624, 4625, 4672, 4688, 4697}

def utc_now(): return datetime.now(timezone.utc).isoformat()
def read_state():
    try: return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError): return {"records": {}, "journal_cursor": ""}
def save_state(state): STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
def severity(event_id, level=""):
    if event_id in (4625, 4697): return "Medium"
    if event_id == 4672: return "High"
    if event_id == 4688: return "Informational"
    return {"0":"Critical", "1":"High", "2":"Medium", "3":"Low", "4":"Informational"}.get(str(level), "Low")

def windows_events(state):
    try: import win32evtlog
    except ImportError:
        print("pywin32 is required for Windows Event Log collection", file=sys.stderr); return []
    result=[]
    labels={4624:"Successful Login",4625:"Failed Login",4672:"Privilege Change",4688:"Process Start",4697:"Service Install"}
    for channel in ("Security", "System", "Application"):
        try:
            handle=win32evtlog.OpenEventLog(None, channel)
            flags=win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
            collected=[]
            for _ in range(20):
                batch=win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch: break
                for e in batch:
                    rid=int(e.RecordNumber); key=f"{channel}:{rid}"
                    if rid <= int(state["records"].get(channel, 0)): continue
                    eid=int(e.EventID) & 0xffff
                    if channel == "Security" and eid not in WINDOWS_IDS: continue
                    if channel != "Security" and e.EventType not in (1,2): continue
                    when=e.TimeGenerated.replace(tzinfo=timezone.utc).isoformat()
                    msg=" ".join(str(x) for x in (e.StringInserts or []) if x)[:1800]
                    ip_match=re.search(r"(?:from |Source Network Address:\s*)(\d{1,3}(?:\.\d{1,3}){3})",msg,re.I)
                    computer=getattr(e,"ComputerName",getattr(e,"Computer","unknown"))
                    user=(f"{computer}\\{e.Sid}") if e.Sid else "unknown"
                    typ=labels.get(eid, "System Event" if channel=="System" else "Application Event")
                    collected.append({"timestamp":when,"eventId":str(eid),"eventType":typ,"user":user,"sourceIp":ip_match.group(1) if ip_match else "","severity":severity(eid,str(e.EventType)),"status":"Failed" if eid==4625 else "Observed","description":msg or f"Windows {channel} event {eid}","source":channel,"metadata":{"computer":computer,"recordId":rid,"channel":channel,"provider":str(e.SourceName)}})
                    state["records"][channel]=max(int(state["records"].get(channel,0)),rid)
            win32evtlog.CloseEventLog(handle)
            result.extend(reversed(collected))
        except Exception as exc: print(f"Cannot read {channel} log (permission/auditing may be disabled): {exc}", file=sys.stderr)
    return result

def linux_events(state):
    result=[]
    try:
        cmd=["journalctl","-o","json","--no-pager","-n","500"]
        if state.get("journal_cursor"): cmd += ["--after-cursor",state["journal_cursor"]]
        raw=subprocess.run(cmd,capture_output=True,text=True,timeout=20,check=False)
        if raw.returncode==0:
            for line in raw.stdout.splitlines():
                try: item=json.loads(line)
                except ValueError: continue
                msg=str(item.get("MESSAGE","")); ident=str(item.get("SYSLOG_IDENTIFIER", "journal")); cursor=item.get("__CURSOR")
                if cursor: state["journal_cursor"]=cursor
                low=msg.lower(); auth=any(x in (low+ident.lower()) for x in ("sshd","sudo","authentication","session opened","session closed","failed password","accepted password"))
                if not auth: continue
                failed=any(x in low for x in ("failed", "failure", "invalid user")); elevated="sudo" in low
                result.append({"timestamp":datetime.fromtimestamp(int(item.get("__REALTIME_TIMESTAMP", "0"))/1e6,tz=timezone.utc).isoformat(),"eventId":str(item.get("_SYSTEMD_UNIT",ident)),"eventType":"Failed Login" if failed else "Privilege Change" if elevated else "Successful Login","user":str(item.get("_UID","unknown")),"sourceIp":( __import__("re").search(r"from\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})",msg,re.I).group(1) if __import__("re").search(r"from\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})",msg,re.I) else ""),"severity":"Medium" if failed else "High" if elevated else "Low","status":"Failed" if failed else "Observed","description":msg[:1800],"source":"journal","metadata":{"identifier":ident,"cursor":cursor,"host":item.get("_HOSTNAME")}})
            return result
    except (FileNotFoundError, subprocess.TimeoutExpired): pass
    for filename in ("/var/log/auth.log","/var/log/syslog"):
        path=Path(filename)
        try:
            offset=int(state["records"].get(filename,0))
            with path.open(errors="replace") as f:
                f.seek(offset)
                for line in f:
                    low=line.lower()
                    if not any(x in low for x in ("sshd", "sudo", "authentication")): continue
                    failed="failed" in low or "invalid user" in low
                    ip_match=re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})",line,re.I)
                    result.append({"timestamp":utc_now(),"eventId":filename.rsplit("/",1)[-1],"eventType":"Failed Login" if failed else "Privilege Change" if "sudo" in low else "Successful Login","user":"unknown","sourceIp":ip_match.group(1) if ip_match else "","severity":"Medium" if failed else "Low","status":"Failed" if failed else "Observed","description":line.strip()[:1800],"source":filename,"metadata":{"file":filename}})
                state["records"][filename]=f.tell()
        except (OSError, ValueError) as exc: print(f"Cannot read {filename}: {exc}",file=sys.stderr)
    return result

def main():
    if not API or not TOKEN: raise SystemExit("Set CYBERGUARD_API and CYBERGUARD_TOKEN first.")
    session=requests.Session(); session.headers.update({"Authorization":f"Bearer {TOKEN}","User-Agent":f"CyberGuard-Agent/{VERSION}"})
    state=read_state(); system=platform.system()
    if system not in ("Windows","Linux"): raise SystemExit(f"Unsupported operating system: {system}")
    print(f"CyberGuard collector starting on {system}; API {API}")
    try:
        while True:
            try:
                heartbeat=session.post(API+"/agent/heartbeat",timeout=15); heartbeat.raise_for_status()
                cfg=heartbeat.json().get("config",{}); interval=max(5,min(3600,int(cfg.get("intervalSeconds",15))))
                if cfg.get("enabled",True):
                    events=windows_events(state) if system=="Windows" else linux_events(state)
                    for start in range(0,len(events),200):
                        response=session.post(API+"/agent/events",json={"events":events[start:start+200]},timeout=30); response.raise_for_status()
                        print(f"Sent {response.json().get('accepted',0)} events; duplicates skipped: {response.json().get('duplicates',0)}")
                    save_state(state)
                time.sleep(interval)
            except requests.RequestException as exc:
                print(f"Backend unavailable: {exc}",file=sys.stderr); time.sleep(15)
    except KeyboardInterrupt:
        try: session.post(API+"/agent/disconnect",timeout=5)
        except requests.RequestException: pass
        save_state(state); print("Agent stopped.")

if __name__=="__main__": main()
