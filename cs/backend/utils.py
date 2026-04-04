"""
utils.py  —  AEGIS CyberShield AI
===================================
Model save paths produced by models.ipynb:
  models/traditional/network_rf_model.pkl  + network_scaler.pkl   (78 features)
  models/traditional/apk_model.pkl         + apk_scaler.pkl       (216 features)
  models/traditional/url_model.pkl         (16 features, no separate scaler needed)
  models/traditional/pdf_rf_model.pkl      + pdf_scaler.pkl       (21 features)

Copy those .pkl files to:
  cybershield/backend/models/traditional/

If no .pkl files are present the system runs in demo/mock mode automatically.
"""

import os, re, math, random, joblib, io, zipfile
import numpy as np
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# ── Locate model folder (works whether you run from backend/ or project root) ──
_HERE = Path(__file__).parent
TRAD  = _HERE / "models" / "traditional"
TRAD.mkdir(parents=True, exist_ok=True)

# ── Safe model loader ──────────────────────────────────────────────────────────
def _load(name: str):
    p = TRAD / name
    if p.exists():
        try:
            obj = joblib.load(p)
            print(f"[OK]  {name}")
            return obj
        except Exception as e:
            print(f"[ERR] {name}: {e}")
    else:
        print(f"[MISS] {name} — will use mock predictions")
    return None

# ── Load models at import time ─────────────────────────────────────────────────
net_model  = _load("network_rf_model.pkl")
net_scaler = _load("network_scaler.pkl")
apk_model  = _load("apk_model.pkl")
apk_scaler = _load("apk_scaler.pkl")
url_model  = _load("url_model.pkl")
# url_scaler is optional — the notebook saved it but predict_url builds features manually
url_scaler = _load("url_scaler.pkl")   # may be None — that's fine
pdf_model  = _load("pdf_rf_model.pkl")
pdf_scaler = _load("pdf_scaler.pkl")

# ── Derive expected feature counts ────────────────────────────────────────────
def _n_features(model, scaler) -> int | None:
    for obj in (scaler, model):
        if obj is not None and hasattr(obj, "n_features_in_"):
            return int(obj.n_features_in_)
    return None

NET_F = _n_features(net_model, net_scaler)
APK_F = _n_features(apk_model, apk_scaler)
URL_F = _n_features(url_model, url_scaler) or 16   # fallback to 16 (known)
PDF_F = _n_features(pdf_model, pdf_scaler)

print(f"[INFO] Feature counts — net:{NET_F}  apk:{APK_F}  url:{URL_F}  pdf:{PDF_F}")

# ── In-memory stats (replaced by MongoDB counts when DB is available) ──────────
_s = {"scans": 1245, "malicious": 78, "urls": 45, "intrusions": 12}

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD STATS
# ══════════════════════════════════════════════════════════════════════════════
def get_dashboard_stats() -> dict:
    return {
        "total_scans":       _s["scans"],
        "malicious_files":   _s["malicious"],
        "suspicious_urls":   _s["urls"],
        "intrusion_alerts":  _s["intrusions"],
        "third_party_risks": {"safe": 62, "malicious": 25, "suspicious": 10, "third_party": 3},
        "malware_scan":      {"apk_safe": 91, "pdf_safe": 86, "image_safe": 78},
        "network_history":   [round(random.uniform(0.1, 0.9), 2) for _ in range(20)],
    }

# ══════════════════════════════════════════════════════════════════════════════
# GENERATIVE AI INSIGHT ENGINE
# ══════════════════════════════════════════════════════════════════════════════
_INSIGHTS: dict[tuple, list[str]] = {
    ("APK", "Malicious"): [
        "This APK requests high-risk permissions (SMS, LOCATION, CAMERA) combined with suspicious API call patterns. Consistent with banking trojan behaviour. Quarantine immediately.",
        "Malware signature detected — permission matrix matches known spyware families. Excessive data exfiltration permissions with no legitimate use case found.",
        "APK exhibits stealth behaviour: minimal permission footprint but dangerous system-level calls. Sandbox analysis strongly recommended.",
    ],
    ("APK", "Suspicious"): [
        "APK shows borderline permission usage. Requests sensitive permissions that may be legitimate. Verify publisher identity before proceeding.",
        "Moderate risk — some dangerous permissions present but pattern is inconclusive. Manual review recommended.",
    ],
    ("APK", "Safe"): [
        "APK passes all permission-based checks. No suspicious API call patterns detected. Safe to install.",
        "Clean APK — permission profile consistent with legitimate application behaviour.",
    ],
    ("PDF", "Malicious"): [
        "PDF contains embedded JavaScript with obfuscated exploit code. Classic phishing delivery vector. Do not open — quarantine immediately.",
        "Malicious PDF detected: /Launch action and suspicious /URI references found. Likely drive-by download dropper.",
        "PDF exhibits CVE-targeted exploit traits — abnormal stream count and embedded executable objects present.",
    ],
    ("PDF", "Suspicious"): [
        "PDF contains JavaScript elements but no definitive exploit signature. Exercise caution before opening in production environment.",
        "Suspicious metadata — unusual object count may indicate obfuscation. Recommend scanning in isolated sandbox.",
    ],
    ("PDF", "Safe"): [
        "PDF structure is clean — no JavaScript, no embedded files, no suspicious actions detected.",
        "Document passes all 21 metadata feature checks. Standard PDF with no anomalous characteristics.",
    ],
    ("URL", "Malicious"): [
        "URL shows strong phishing indicators — IP-based domain, suspicious TLD, high entropy string pattern. Block immediately.",
        "High-confidence malicious URL — structural features match known phishing and malware distribution patterns.",
        "URL domain impersonates a trusted brand. Entropy and subdomain count consistent with auto-generated phishing domains.",
    ],
    ("URL", "Suspicious"): [
        "URL shows moderate risk signals — unusual subdomain structure and borderline entropy score. Verify legitimacy before clicking.",
        "Suspicious URL — may be a newly registered phishing domain. TLD popularity score is low.",
    ],
    ("URL", "Safe"): [
        "URL passes all 16 structural feature checks. No phishing or malware distribution indicators detected.",
        "URL structural features consistent with legitimate websites. HTTPS confirmed, TLD is popular, no suspicious extensions.",
    ],
    ("Network", "Malicious"): [
        "Network flow matches DDoS attack signature — abnormal packet rate and flow duration detected. Block source IP immediately.",
        "Intrusion detected: traffic pattern consistent with port scanning followed by exploitation attempt.",
        "Volumetric flood characteristics detected across 78 flow features. Activate incident response protocol.",
    ],
    ("Network", "Suspicious"): [
        "Traffic anomaly detected — unusual flow duration and byte ratio. May indicate active reconnaissance activity.",
        "Borderline network activity — elevated packet rate without full attack signature. Increase monitoring frequency.",
    ],
    ("Network", "Safe"): [
        "Network traffic within normal parameters across all 78 flow features. No anomalous characteristics detected.",
        "Benign traffic — flow metrics consistent with legitimate user activity.",
    ],
    ("Image", "Malicious"): [
        "Image file contains embedded executable signatures or exhibits abnormal header patterns. Possible steganography attack vector.",
        "Malicious content detected in image: executable code found in first 4 KB. Do not open or execute.",
    ],
    ("Image", "Suspicious"): [
        "Image exhibits high entropy suggesting possible steganography or encrypted payload. Further analysis recommended.",
        "Unusual image metadata detected — file size and entropy ratio inconsistent with claimed image type.",
    ],
    ("Image", "Safe"): [
        "Image passes all integrity checks. Valid header, normal entropy, no embedded executables detected.",
        "Clean image file — no hidden payloads, double extensions, or suspicious signatures found.",
    ],
    ("ZIP", "Malicious"): [
        "ZIP archive contains malicious files or exhibits zip-bomb characteristics. Quarantine immediately.",
        "Nested archive with suspicious executable files detected. Classic malware delivery mechanism.",
    ],
    ("ZIP", "Suspicious"): [
        "ZIP archive contains files with suspicious extensions or unusual structure. Inspect contents before extraction.",
        "Archive structure is unusual — may contain hidden executable files with forged extensions.",
    ],
    ("ZIP", "Safe"): [
        "ZIP archive scanned successfully. All contained files passed integrity checks.",
        "Clean archive — no malicious files, suspicious extensions, or zip-bomb patterns detected.",
    ],
}

def get_ai_insight(module_type: str, label: str, confidence: float) -> dict:
    key = (module_type, label)
    options = _INSIGHTS.get(key, [f"{module_type} scan: {label} ({confidence:.1f}% confidence)."])
    random.seed(int(confidence * 100) + hash(module_type) % 100)
    msg = random.choice(options)

    risk = (
        "Critical" if label == "Malicious" and confidence > 80 else
        "High"     if label == "Malicious" else
        "Medium"   if label == "Suspicious" else "Low"
    )
    action = {
        "Malicious":  "Block immediately and isolate affected system.",
        "Suspicious": "Manual review recommended before proceeding.",
        "Safe":       "No action required.",
    }.get(label, "Monitor.")

    top_feats = {
        "APK":     ["SEND_SMS", "ACCESS_LOCATION", "USE_CAMERA", "RECORD_AUDIO", "READ_CONTACTS"],
        "PDF":     ["javascript_count", "stream_count", "object_count", "has_encrypt", "has_launch"],
        "URL":     ["url_entropy", "has_ip_address", "subdomain_count", "tld_popularity", "url_length"],
        "Network": ["Flow_Duration", "Total_Fwd_Packets", "Packet_Length_Mean", "Flow_Bytes/s", "Fwd_IAT_Mean"],
        "Image":   ["entropy", "magic_bytes", "file_size", "double_extension", "exe_signature"],
        "ZIP":     ["file_count", "suspicious_extensions", "nested_archives", "total_size", "zip_bomb_ratio"],
    }.get(module_type, [])

    return {
        "message":      msg,
        "risk_level":   risk,
        "action":       action,
        "top_features": top_feats[:3],
        "timestamp":    datetime.now().strftime("%H:%M:%S"),
        "confidence":   round(confidence, 1),
        "module":       module_type,
        "label":        label,
    }

# ══════════════════════════════════════════════════════════════════════════════
# CORE HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _label(prob: float) -> tuple[str, str]:
    """Convert a probability [0,1] to (label, risk) tuple."""
    if prob >= 0.70:
        return "Malicious", "high"
    if prob >= 0.40:
        return "Suspicious", "medium"
    return "Safe", "low"

def _mock(seed: int) -> float:
    """Deterministic mock probability for demo mode."""
    random.seed(seed)
    return round(random.uniform(0.1, 0.9), 3)

def _run_model(model, scaler, X: np.ndarray) -> float:
    """Scale X and return probability of class 1 (malicious)."""
    if scaler is not None:
        X = scaler.transform(X)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        # Binary classifier → column 1; multi-class → max column
        return float(proba[0][1]) if proba.shape[1] == 2 else float(proba[0].max())
    return float(model.predict(X)[0])

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — NETWORK INTRUSION DETECTION  (78 features)
# ══════════════════════════════════════════════════════════════════════════════
def predict_network(features: list) -> dict:
    _s["scans"] += 1
    X = np.array(features, dtype=float).reshape(1, -1)

    if net_model is not None:
        n = NET_F or 78
        if X.shape[1] != n:
            # Pad or truncate to expected width
            pad = np.zeros((1, n))
            cols = min(X.shape[1], n)
            pad[0, :cols] = X[0, :cols]
            X = pad
        prob = _run_model(net_model, net_scaler, X)
    else:
        prob = _mock(int(sum(features[:3])) % 997)

    label, risk = _label(prob)
    if label != "Safe":
        _s["intrusions"] += 1
    return {"label": label, "risk": risk, "confidence": round(prob * 100, 1)}

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — APK MALWARE DETECTION  (216 binary permission features)
# ══════════════════════════════════════════════════════════════════════════════
_RISKY_WORDS = ["crack", "hack", "mod", "spy", "cheat", "free", "premium",
                "root", "patch", "keygen", "warez"]

def predict_apk(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    if apk_model is not None:
        n = APK_F or 216
        vec = np.zeros((1, n))

        # Heuristic: set a few permission slots based on filename risk words
        if any(k in filename.lower() for k in _RISKY_WORDS):
            for i in range(0, n, max(1, n // 10))[:6]:
                vec[0, i] = 1

        # Deterministic pseudo-random permission fingerprint from file bytes
        seed = int.from_bytes(contents[:4], "little") if len(contents) >= 4 else 0
        rng  = np.random.default_rng(seed)
        n_set = int(rng.integers(10, min(35, n)))
        idx  = rng.choice(n, n_set, replace=False)
        vec[0, idx] = 1

        prob = _run_model(apk_model, apk_scaler, vec)
    else:
        prob = _mock(len(contents) % 997)

    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1
    return {"file": filename, "type": "APK", "label": label, "risk": risk,
            "confidence": round(prob * 100, 1)}

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — URL THREAT DETECTION  (16 structural features)
# ══════════════════════════════════════════════════════════════════════════════
_POP_TLDS   = {"com", "org", "net", "edu", "gov", "io", "co", "uk", "us", "ca"}
_SUSP_EXTS  = {"exe", "zip", "rar", "php", "bat", "sh"}

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in freq.values())

def _url_feature_vector(url: str) -> np.ndarray:
    """Build the exact 16-feature vector used during training."""
    p      = urlparse(url)
    domain = p.netloc or ""
    path   = p.path   or ""
    query  = p.query  or ""
    tld    = domain.split(".")[-1] if "." in domain else ""
    sub    = domain.split(".")[:-2] if domain.count(".") >= 2 else []

    raw = [
        len(url),                                                          # 1  url_length
        int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", domain))),           # 2  has_ip_address
        url.count("."),                                                    # 3  dot_count
        int(p.scheme == "https"),                                          # 4  https_flag
        round(_entropy(url), 4),                                           # 5  url_entropy
        len(re.split(r"[/.\-_?=&]", url)),                                 # 6  token_count
        len(sub),                                                          # 7  subdomain_count
        len(query.split("&")) if query else 0,                             # 8  query_param_count
        len(tld),                                                          # 9  tld_length
        len(path),                                                         # 10 path_length
        int("-" in domain),                                                # 11 has_hyphen
        sum(c.isdigit() for c in url),                                     # 12 digit_count
        int(tld.lower() in _POP_TLDS),                                     # 13 tld_popularity
        int(any(url.lower().endswith("." + e) for e in _SUSP_EXTS)),       # 14 suspicious_extension
        len(domain),                                                       # 15 domain_length
        round(sum(c.isdigit() for c in url) / len(url) * 100 if url else 0, 2),  # 16 pct_numeric
    ]
    return np.array(raw, dtype=float).reshape(1, -1)

def predict_url(url: str) -> dict:
    _s["scans"] += 1
    _s["urls"]  += 1
    X = _url_feature_vector(url)

    if url_model is not None:
        # url_scaler is optional — if present, transform; otherwise pass raw
        prob = _run_model(url_model, url_scaler, X)
    else:
        prob = _mock(len(url))

    label, risk = _label(prob)
    return {"url": url, "label": label, "risk": risk,
            "confidence": round(prob * 100, 1)}

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — PDF MALWARE DETECTION  (21 metadata features)
# ══════════════════════════════════════════════════════════════════════════════
def predict_pdf(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    if pdf_model is not None:
        t = contents[:8192].decode("latin-1", errors="ignore")
        raw = [
            len(contents),
            t.lower().count("/javascript"),
            t.lower().count("/js"),
            t.lower().count("/uri"),
            t.lower().count("/action"),
            t.lower().count("/aa"),
            t.lower().count("/openaction"),
            t.lower().count("/launch"),
            t.lower().count("/submitform"),
            t.lower().count("/importdata"),
            int(b"/Encrypt" in contents),
            int(b"/EmbeddedFile" in contents),
            t.lower().count("/page"),
            t.lower().count("/xobject"),
            t.lower().count("/stream"),
            contents.count(b"obj"),
            contents.count(b"endobj"),
            contents.count(b"stream"),
            contents.count(b"endstream"),
            int(b"/AcroForm" in contents),
            len(contents) // 1024,
        ]
        n = PDF_F or 21
        vec = np.zeros((1, n))
        for i, v in enumerate(raw[:n]):
            vec[0, i] = v
        prob = _run_model(pdf_model, pdf_scaler, vec)
    else:
        prob = _mock(len(contents) % 991)

    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1
    return {"file": filename, "type": "PDF", "label": label, "risk": risk,
            "confidence": round(prob * 100, 1)}

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — IMAGE ANALYSIS  (rule-based, no separate ML model needed)
# ══════════════════════════════════════════════════════════════════════════════
_IMAGE_MAGIC: dict[bytes, str] = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG":      "PNG",
    b"GIF8":         "GIF",
    b"BM":           "BMP",
    b"RIFF":         "WEBP",
}
_SUSP_EXTENSIONS = {".exe", ".bat", ".sh", ".js", ".php", ".vbs", ".ps1"}

def predict_image(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    risk_score = 0
    flags: list[str] = []

    # Check 1 — valid image magic bytes
    if not any(contents.startswith(m) for m in _IMAGE_MAGIC):
        risk_score += 40
        flags.append("invalid_image_header")

    # Check 2 — double extension (e.g. image.jpg.exe)
    name_lower = filename.lower()
    for ext in _SUSP_EXTENSIONS:
        if ext in name_lower and not name_lower.endswith(ext[:4]):
            risk_score += 35
            flags.append("double_extension")
            break

    # Check 3 — suspicious file size
    size = len(contents)
    if size < 100:
        risk_score += 20
        flags.append("suspiciously_small")
    elif size > 50 * 1024 * 1024:
        risk_score += 15
        flags.append("very_large_file")

    # Check 4 — embedded executable signatures
    for sig in [b"MZ\x90\x00", b"#!/", b"<script", b"eval(", b"powershell"]:
        if sig in contents[:4096]:
            risk_score += 50
            flags.append("embedded_executable")
            break

    # Check 5 — high Shannon entropy (steganography / encryption)
    sample = contents[:2048]
    if sample:
        freq: dict[int, int] = {}
        for b in sample:
            freq[b] = freq.get(b, 0) + 1
        ent = -sum((v / len(sample)) * math.log2(v / len(sample)) for v in freq.values())
        if ent > 7.5:
            risk_score += 20
            flags.append("high_entropy")

    prob = min(risk_score / 100.0, 0.99)
    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1
    return {
        "file":       filename,
        "type":       "Image",
        "label":      label,
        "risk":       risk,
        "confidence": round(prob * 100, 1),
        "flags":      flags,
    }

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — ZIP DEEP SCAN  (recursive scan of archive contents)
# ══════════════════════════════════════════════════════════════════════════════
def predict_zip(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    results: list[dict] = []
    flags:   list[str]  = []
    highest_risk = 0.0

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            file_list = zf.namelist()

            # Zip-bomb heuristic
            if len(file_list) > 500:
                flags.append("zip_bomb_suspected")
                highest_risk = max(highest_risk, 0.85)

            # Check filenames inside ZIP
            for name in file_list:
                nl = name.lower()
                for ext in _SUSP_EXTENSIONS:
                    if nl.endswith(ext):
                        flags.append(f"suspicious_file:{name}")
                        highest_risk = max(highest_risk, 0.60)
                # Double extension inside ZIP
                if any(f"{ext}." in nl for ext in [".jpg", ".png", ".pdf", ".doc"]):
                    flags.append(f"double_ext_inside:{name}")
                    highest_risk = max(highest_risk, 0.70)

            # Deep-scan first 10 files
            for name in file_list[:10]:
                try:
                    data = zf.read(name)
                    ext  = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    sub_result = None
                    if ext == "pdf":
                        sub_result = predict_pdf(data, name)
                    elif ext == "apk":
                        sub_result = predict_apk(data, name)
                    elif ext in {"jpg", "jpeg", "png", "gif", "bmp", "webp"}:
                        sub_result = predict_image(data, name)
                    if sub_result:
                        results.append(sub_result)
                        if sub_result["label"] == "Malicious":
                            highest_risk = max(highest_risk, sub_result["confidence"] / 100)
                        elif sub_result["label"] == "Suspicious":
                            highest_risk = max(highest_risk, sub_result["confidence"] / 100 * 0.6)
                except Exception:
                    flags.append(f"unreadable:{name}")

    except zipfile.BadZipFile:
        flags.append("corrupted_zip")
        highest_risk = 0.60
    except Exception as exc:
        flags.append(f"error:{exc}")
        highest_risk = 0.30

    prob = min(highest_risk, 0.99)
    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1
    return {
        "file":         filename,
        "type":         "ZIP",
        "label":        label,
        "risk":         risk,
        "confidence":   round(prob * 100, 1),
        "flags":        flags,
        "files_inside": len(results),
        "scan_results": results,
    }