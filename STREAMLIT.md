# CyberGuard AI on Streamlit

This folder-level app is an educational Streamlit port of the CyberGuard AI SOC dashboard. It includes overview, scans, event review, findings, analytics, an evidence lookup assistant, and device status views.

## Run locally

From the repository root:

```bash
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Deploy with Streamlit Community Cloud

Connect this GitHub repository, choose the `main` branch, and set the app file to `streamlit_app.py`. Community Cloud installs packages from `requirements.txt`.

## Current port boundaries

- The port uses sample data in Streamlit session state. Imported CSV/JSON data is held for that browser session and is not written to the original API database.
- Sample records are marked simulated. Uploaded data is user-provided and its source is not independently verified.
- The original React app's Clerk authentication, PostgreSQL-backed Node API, monitoring-agent enrollment, and cross-user persistence are not connected here.
- Scans run transparent rule-based checks against the session's stored events; there is no trained or evaluated ML model, live endpoint collection, or remediation.
