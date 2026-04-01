╔══════════════════════════════════════════════════════╗
║         CyberShield AI — Setup Guide                 ║
╚══════════════════════════════════════════════════════╝

STEP 1 — Copy your model .pkl files
────────────────────────────────────
From your Jupyter project folder, copy these files:
  models/traditional/network_rf_model.pkl
  models/traditional/network_scaler.pkl
  models/traditional/apk_model.pkl
  models/traditional/apk_scaler.pkl
  models/traditional/url_model.pkl
  models/traditional/pdf_rf_model.pkl
  models/traditional/pdf_scaler.pkl

Paste them into:
  cybershield/backend/models/traditional/

(If no models found, the system runs in demo/mock mode)

STEP 2 — Start Backend
────────────────────────────────────
Open Terminal 1, navigate to backend folder:

  cd cybershield/backend
  pip install -r requirements.txt
  python main.py

Backend runs on: http://localhost:8000

STEP 3 — Start Frontend
────────────────────────────────────
Open Terminal 2, navigate to frontend folder:

  cd cybershield/frontend
  npm install
  npm start

Frontend runs on: http://localhost:3000

STEP 4 — Login
────────────────────────────────────
Open browser: http://localhost:3000
Username: admin
Password: admin123

PAGES
────────────────────────────────────
/dashboard    — Overview with live stats + charts
/scanner      — Upload APK/PDF for real model prediction
/url          — Scan any URL with 16-feature analysis
/network      — Network traffic monitoring (78 features)
/ai-insights  — Explainable AI analysis log
/reports      — Session summary + executive report
