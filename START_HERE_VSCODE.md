# Open CyberGuard AI in VS Code

## 1. Extract and open

1. Extract the ZIP file to a normal folder.
2. Open Visual Studio Code.
3. Choose **File → Open Folder** and select the extracted `CyberGuard-AI` folder.

## 2. Create a Python environment

Open the VS Code terminal in the project folder and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run this once in the same terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again.

## 3. Start the website

```powershell
python -m streamlit run streamlit_app.py
```

Open the local address displayed in the terminal, normally `http://localhost:8501`.

## Current anomaly models

- **Isolation Forest:** classical unsupervised machine learning with 200 trees.
- **Local Outlier Factor:** neighbour-based unsupervised machine learning.
- **Autoencoder:** compact PyTorch neural network that scores reconstruction error.
- **Combined score:** 34% Isolation Forest, 33% Local Outlier Factor, and 33% Autoencoder.

The score is a review priority within the currently loaded records. It is not proof of an attack.

## Important files

- `streamlit_app.py` — website, workflow, authentication and hybrid scoring.
- `cyberguard_dl.py` — Autoencoder model and feature preparation.
- `requirements.txt` — Python dependencies.
- `README.md` — complete project documentation.
- `STREAMLIT.md` — Streamlit-specific usage and deployment notes.

Local account databases, Python caches, Git history and installed dependency folders are intentionally not included in the shared ZIP.
