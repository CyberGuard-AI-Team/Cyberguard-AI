# CyberGuard AI on Streamlit

This folder-level app is an educational Streamlit port of the CyberGuard AI SOC dashboard. It includes overview, scans, event review, plain-language findings, local investigations, analytics, an Isolation Forest ML lab, an evidence lookup assistant, and Windows event collection.

## How CyberGuard works

1. Upload a CSV/JSON event file, or collect selected Windows Event Logs in a local Windows run.
2. Use **Check my activity** for the guided rule checks, or **Smart analysis** for the Isolation Forest anomaly ranking.
3. Read **What needs attention** for a plain-language explanation and suggested next action.
4. Use **My follow-ups** to record what you checked and download a case report.

The app includes a full **About CyberGuard** section opened from the top-right corner. It explains the four-step workflow, every feature, the model's role, and how the app handles activity and follow-up notes. Every feature screen also has an **About this page** panel for first-time users.

## Run locally

From the repository root:

```bash
python -m pip install -r requirements.txt
python -m streamlit run streamlit_app.py --server.address 127.0.0.1
```

On the hosted site, **Connect my PC** provides a downloadable Windows PowerShell collector. Run it once on the Windows PC to create `cyberguard-real-logs.csv` on the Desktop, then upload that file in **Activity history**. Windows requires a person to approve the downloaded script before it can run.

On Windows, open **Devices** and choose **Collect Windows logs on this PC**. The local app reads a selected recent window from Security sign-in / privilege / process / service events (IDs 4624, 4625, 4672, 4688, 4697) and System/Application warnings and errors. It analyzes the collected records in local session memory only. Security-log access may require starting the local app from an Administrator PowerShell.

The **ML Lab** runs an Isolation Forest model with 200 trees over the currently stored telemetry. It uses event hour, severity, event type frequency, account frequency, source-address frequency, and one-hot encoded categories to rank anomalous records. **Investigations** stores case status, assignee, and notes in `cyberguard-local.db` on a local Windows run. On the hosted site, investigation notes are saved in the visitor's browser and can be exported as a CSV report.

## Deploy with Streamlit Community Cloud

Connect this GitHub repository, choose the `main` branch, and set the app file to `streamlit_app.py`. Community Cloud installs packages from `requirements.txt`.

## Current port boundaries

- The app starts without logs. Imported CSV/JSON data and locally collected Windows Event Logs are held for the current session and are not written to the original API database.
- The original React app's Clerk authentication, PostgreSQL-backed Node API, monitoring-agent enrollment, and cross-user persistence are not connected here.
- The Streamlit Community Cloud instance cannot read a visitor's computer. Local Windows event collection is available only when this app is running on that Windows computer; it is a one-time collection, not continuous background monitoring.
- On the hosted site, the ML Lab runs on the currently stored browser-session telemetry. Direct Windows event collection requires running the app locally on Windows. Hosted investigation notes remain in browser-local storage.
- The anomaly score is a relative rank for the telemetry currently loaded into the app. It is not a probability of compromise and needs analyst review with the linked event evidence.
- Scans run transparent rule-based checks against the session's stored events; there is no trained or evaluated ML model, live endpoint collection, or remediation.
