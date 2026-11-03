# CyberGuard monitoring agent

The agent runs as a separate process and reads Windows Event Logs (Security, System and Application) or Linux journal/auth/syslog. It sends normalized events to the existing API using its enrollment token. TLS verification is enabled by default. Do not expose the API over plain HTTP outside localhost or a trusted tunnel.

Before first use, apply the additive database migration to the existing PostgreSQL database (for example, from PowerShell with `psql $env:DATABASE_URL -f lib/db/migrations/0001_monitoring_agents.sql`). For deployments behind a proxy, configure `CYBERGUARD_PUBLIC_API_URL` on the API server to the externally reachable HTTPS API base, such as `https://host.example/api`; this is the URL returned during enrollment.

## Windows setup

1. In the signed-in CyberGuard dashboard, call `POST /api/agents/enroll` with a device name and `operatingSystem: "Windows"`. Save the returned token securely; it is shown only once.
2. Install Python 3.10+ and install dependencies: `py -m pip install -r requirements.txt`.
3. Run in an elevated PowerShell window for Security log access:

```powershell
$env:CYBERGUARD_API="https://your-host/api"
$env:CYBERGUARD_TOKEN="<enrollment token>"
py .\agent.py
```

The agent collects available event IDs 4624, 4625, 4672, 4688 and 4697, plus system/application warnings and errors. Process creation collection requires Windows audit policy configuration; missing permission or disabled auditing is reported in the log and does not fabricate records.

## Linux setup

Install Python 3.10+ and `requests`. The user must have permission to read the system journal and auth logs (typically `systemd-journal` membership or root). Set `CYBERGUARD_API` and `CYBERGUARD_TOKEN`, then run `python3 agent.py`. It reads journal entries with a saved cursor and falls back to `/var/log/auth.log` and `/var/log/syslog` when journalctl is unavailable.

The agent stores cursors in `agent-state.json` beside the script. Protect this file and the token. Stop with Ctrl+C; the agent reports disconnection. Dashboard controls can revoke a credential immediately. Tokens are stored as SHA-256 hashes on the server. Events are deduplicated server-side by agent, source, event ID and timestamp.

## Host anomaly model

`ml/host_anomaly.py` provides an explicit Isolation Forest training and inference utility for host events. Install `ml/requirements.txt`, prepare JSON Lines records from your own representative host telemetry (at least 50 records), and run:

```sh
python ml/host_anomaly.py train host-events.jsonl host-model.joblib
python ml/host_anomaly.py predict one-event.json host-model.joblib
```

The repository contains no pretrained artifact. A model becomes available only after this training command succeeds. The current service ingestion path reports rule-based findings and does not yet invoke this model automatically; treat the CLI as an independent evaluation pipeline until an operator wires and evaluates inference for their deployment.
