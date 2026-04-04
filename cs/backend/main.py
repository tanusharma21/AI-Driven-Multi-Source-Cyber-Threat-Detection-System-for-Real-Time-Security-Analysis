from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from utils import (predict_apk, predict_pdf, predict_url,
                   predict_network, predict_image, predict_zip,
                   get_dashboard_stats, get_ai_insight)
import uvicorn
import secrets
import os
from datetime import datetime

# ── Optional MongoDB ───────────────────────────────────────────────────────────
db = None
scans_col  = None
tokens_col = None

try:
    from pymongo import MongoClient
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    client.server_info()
    db = client["aegis"]
    scans_col  = db["scans"]
    tokens_col = db["tokens"]
    print("[OK] MongoDB connected!")
except Exception as e:
    print(f"[WARN] MongoDB not available: {e} — running without DB")

# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(title="⟬⟭ AEGIS ⟭⟬", version="1.0.0")

# ── CORS ───────────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://ai-driven-multi-source-cyber-threat.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth Config ────────────────────────────────────────────────────────────────
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "ame")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "wabisabi.11.11")
VALID_TOKENS: set = set()

# ── Pydantic Models ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class URLRequest(BaseModel):
    url: str

class NetworkRequest(BaseModel):
    features: list

# ── Auth Dependency ────────────────────────────────────────────────────────────
def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if not token or token not in VALID_TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized — please log in")
    return token

# ── Auth Routes ────────────────────────────────────────────────────────────────
@app.post("/api/login")
def login(req: LoginRequest):
    if req.username == ADMIN_USERNAME and req.password == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        VALID_TOKENS.add(token)
        if tokens_col is not None:
            tokens_col.insert_one({"token": token, "created_at": datetime.now()})
        return {"token": token, "message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/logout")
def logout(token: str = Depends(get_current_user)):
    VALID_TOKENS.discard(token)
    if tokens_col is not None:
        tokens_col.delete_one({"token": token})
    return {"message": "Logged out successfully"}

@app.get("/api/verify")
def verify(token: str = Depends(get_current_user)):
    return {"valid": True}

# ── Public Routes ──────────────────────────────────────────────────────────────
@app.get("/api/stats")
def stats():
    base = get_dashboard_stats()
    if scans_col is not None:
        try:
            base["total_scans"]      = scans_col.count_documents({})
            base["malicious_files"]  = scans_col.count_documents({"label": "Malicious"})
            base["suspicious_urls"]  = scans_col.count_documents({"label": "Suspicious", "type": "URL"})
            base["intrusion_alerts"] = scans_col.count_documents({"label": "Malicious", "type": "Network"})
        except Exception:
            pass
    return base

@app.get("/api/scans")
def get_scans(token: str = Depends(get_current_user)):
    if scans_col is None:
        return []
    try:
        scans = list(scans_col.find({}, {"_id": 0}).sort("time", -1).limit(50))
        return scans
    except Exception:
        return []

@app.get("/api/health")
def health():
    from utils import net_model, apk_model, url_model, pdf_model
    return {
        "status": "ok",
        "mongodb": db is not None,
        "models": {
            "network": net_model is not None,
            "apk":     apk_model is not None,
            "url":     url_model is not None,
            "pdf":     pdf_model is not None,
        }
    }

# ── Helper: persist scan ───────────────────────────────────────────────────────
def save_scan(data: dict):
    if scans_col is not None:
        try:
            doc = {**data, "time": datetime.now().strftime("%H:%M:%S")}
            doc.pop("_id", None)
            scans_col.insert_one(doc)
        except Exception:
            pass

# ── Protected Scan Routes ──────────────────────────────────────────────────────
@app.post("/api/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    token: str = Depends(get_current_user)
):
    contents = await file.read()
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""

    if ext == "apk":
        result = predict_apk(contents, file.filename)
    elif ext == "pdf":
        result = predict_pdf(contents, file.filename)
    elif ext in {"jpg", "jpeg", "png", "gif", "bmp", "webp"}:
        result = predict_image(contents, file.filename)
    elif ext == "zip":
        result = predict_zip(contents, file.filename)
    else:
        raise HTTPException(
            400,
            f"Unsupported file type: .{ext} — use .apk, .pdf, image (.jpg/.png/…) or .zip"
        )

    result["insight"] = get_ai_insight(result["type"], result["label"], result["confidence"])
    save_scan({**result, "file": file.filename})
    return result

@app.post("/api/scan/url")
def scan_url(req: URLRequest, token: str = Depends(get_current_user)):
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL is empty")
    result = predict_url(url)
    result["insight"] = get_ai_insight("URL", result["label"], result["confidence"])
    save_scan({**result, "type": "URL"})
    return result

@app.post("/api/scan/network")
def scan_network(req: NetworkRequest, token: str = Depends(get_current_user)):
    if not req.features:
        raise HTTPException(400, "Features list is empty")
    result = predict_network(req.features)
    result["insight"] = get_ai_insight("Network", result["label"], result["confidence"])
    save_scan({**result, "type": "Network"})
    return result

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=False)