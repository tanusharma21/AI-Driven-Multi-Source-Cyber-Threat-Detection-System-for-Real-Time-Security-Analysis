from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from utils import (predict_apk, predict_pdf, predict_url,
                   predict_network, predict_image, predict_zip,
                   get_dashboard_stats, get_ai_insight)
import uvicorn
import secrets
from pymongo import MongoClient
from datetime import datetime

app = FastAPI(title="⟬⟭ AEGIS ⟭⟬", version="1.0.0")

app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── MongoDB Connection ─────────────────────────────────────────────────────────
try:
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
    client.server_info()
    db = client["aegis"]
    scans_col  = db["scans"]
    tokens_col = db["tokens"]
    print("[OK] MongoDB connected!")
except Exception as e:
    print(f"[WARN] MongoDB not available: {e} — running without DB")
    db = None
    scans_col  = None
    tokens_col = None

# ── Auth Config ────────────────────────────────────────────────────────────────
ADMIN_USERNAME = "ame"
ADMIN_PASSWORD = "wabisabi.11.11"
VALID_TOKENS: set = set()

# ── Auth Models ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

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
            base["total_scans"]     = scans_col.count_documents({})
            base["malicious_files"] = scans_col.count_documents({"label": "Malicious"})
            base["suspicious_urls"] = scans_col.count_documents({"label": "Suspicious", "type": "URL"})
            base["intrusion_alerts"]= scans_col.count_documents({"label": "Malicious", "type": "Network"})
        except: pass
    return base

@app.get("/api/scans")
def get_scans(token: str = Depends(get_current_user)):
    if scans_col is None:
        return []
    try:
        scans = list(scans_col.find({}, {"_id": 0}).sort("time", -1).limit(50))
        return scans
    except:
        return []

@app.get("/api/health")
def health():
    return {"status": "ok", "mongodb": db is not None}

# ── Protected Routes ───────────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

class NetworkRequest(BaseModel):
    features: list

def save_scan(data: dict):
    if scans_col is not None:
        try:
            scans_col.insert_one({**data, "time": datetime.now().strftime("%H:%M:%S"), "_id_str": str(datetime.now().timestamp())})
        except: pass

@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...), token: str = Depends(get_current_user)):
    contents = await file.read()
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext == "apk":
        result = predict_apk(contents, file.filename)
    elif ext == "pdf":
        result = predict_pdf(contents, file.filename)
    elif ext in {"jpg", "jpeg", "png", "gif", "bmp", "webp"}:
        result = predict_image(contents, file.filename)
    elif ext == "zip":
        result = predict_zip(contents, file.filename)
    else:
        raise HTTPException(400, f"Unsupported: .{ext} — use .apk, .pdf, .jpg, .png or .zip")
    result["insight"] = get_ai_insight(result["type"], result["label"], result["confidence"])
    save_scan({**result, "file": file.filename})
    return result

@app.post("/api/scan/url")
def scan_url(req: URLRequest, token: str = Depends(get_current_user)):
    if not req.url.strip(): raise HTTPException(400, "URL is empty")
    result = predict_url(req.url.strip())
    result["insight"] = get_ai_insight("URL", result["label"], result["confidence"])
    save_scan({**result, "type": "URL"})
    return result

@app.post("/api/scan/network")
def scan_network(req: NetworkRequest, token: str = Depends(get_current_user)):
    result = predict_network(req.features)
    result["insight"] = get_ai_insight("Network", result["label"], result["confidence"])
    save_scan({**result, "type": "Network"})
    return result

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)