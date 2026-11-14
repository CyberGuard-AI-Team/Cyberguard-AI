# CyberGuard AI on Streamlit

This folder-level app is an educational Streamlit port of the CyberGuard AI SOC dashboard. It includes overview, scans, event review, findings, analytics, an evidence lookup assistant, and device status views.

## Run locally

From the repository root:

```bash
python -m pip install -r requirements.txt
python -m streamlit run streamlit_app.py --server.address 127.0.0.1
```

On Windows, open **Devices** and choose **Collect Windows logs on this PC**. The local app reads a selected recent window from Security sign-in / privilege / process / service events (IDs 4624, 4625, 4672, 4688, 4697) and System/Application warnings and errors. It analyzes the collected records in local session memory only. Security-log access may require starting the local app from an Administrator PowerShell.

## Deploy with Streamlit Community Cloud

Connect this GitHub repository, choose the `main` branch, and set the app file to `streamlit_app.py`. Community Cloud installs packages from `requirements.txt`.

## Current port boundaries

- The port uses sample data in Streamlit session state. Imported CSV/JSON data is held for that browser session and is not written to the original API database.
- Sample records are marked simulated. Uploaded data is user-provided and its source is not independently verified.
- The original React app's Clerk authentication, PostgreSQL-backed Node API, monitoring-agent enrollment, and cross-user persistence are not connected here.
- The Streamlit Community Cloud instance cannot read a visitor's computer. Local Windows event collection is available only when this app is running on that Windows computer; it is a one-time collection, not continuous background monitoring.
- Scans run transparent rule-based checks against the session's stored events; there is no trained or evaluated ML model, live endpoint collection, or remediation.
