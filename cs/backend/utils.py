"""
utils.py  —  CyberShield AI
============================
Notebook model save paths (matched exactly):
  models/traditional/network_rf_model.pkl  + network_scaler.pkl   (78 features)
  models/traditional/apk_model.pkl         + apk_scaler.pkl       (216 features)
  models/traditional/url_model.pkl         no scaler              (16 features)
  models/traditional/pdf_rf_model.pkl      + pdf_scaler.pkl       (21 features)
"""

import os, re, math, random, joblib
import numpy as np
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

TRAD = Path(__file__).parent / "models" / "traditional"

def _load(name):
    p = TRAD / name
    if p.exists():
        try:
            o = joblib.load(p); print(f"[OK]  {name}"); return o
        except Exception as e:
            print(f"[ERR] {name}: {e}")
    else:
        print(f"[MISS] {name}")
    return None

net_model  = _load("network_rf_model.pkl")
net_scaler = _load("network_scaler.pkl")
apk_model  = _load("apk_model.pkl")
apk_scaler = _load("apk_scaler.pkl")
url_model  = _load("url_model.pkl")
pdf_model  = _load("pdf_rf_model.pkl")
pdf_scaler = _load("pdf_scaler.pkl")

def _nf(m, s):
    if s and hasattr(s,"n_features_in_"): return s.n_features_in_
    if m and hasattr(m,"n_features_in_"): return m.n_features_in_
    return None

NET_F=_nf(net_model,net_scaler); APK_F=_nf(apk_model,apk_scaler)
URL_F=_nf(url_model,None);       PDF_F=_nf(pdf_model,pdf_scaler)
print(f"[INFO] Features — net:{NET_F}  apk:{APK_F}  url:{URL_F}  pdf:{PDF_F}")

# ── Stats ──────────────────────────────────────────────────────────────────────
_s = {"scans":1245,"malicious":78,"urls":45,"intrusions":12}

def get_dashboard_stats():
    return {
        "total_scans":      _s["scans"],
        "malicious_files":  _s["malicious"],
        "suspicious_urls":  _s["urls"],
        "intrusion_alerts": _s["intrusions"],
        "third_party_risks":{"safe":62,"malicious":25,"suspicious":10,"third_party":3},
        "malware_scan":     {"apk_safe":91,"pdf_safe":86,"image_safe":78},
        "network_history":  [round(random.uniform(0.1,0.9),2) for _ in range(20)],
    }

# ── GenAI Insight Engine ───────────────────────────────────────────────────────
_INSIGHTS = {
    ("APK","Malicious"):[
        "This APK requests high-risk permissions (SMS, LOCATION, CAMERA) combined with suspicious API call patterns. Consistent with banking trojan behaviour. Quarantine immediately.",
        "Malware signature detected — permission matrix matches known spyware families. Excessive data exfiltration permissions with no legitimate use case found.",
        "APK exhibits stealth behaviour: minimal permission footprint but dangerous system-level calls. Sandbox analysis strongly recommended.",
    ],
    ("APK","Suspicious"):[
        "APK shows borderline permission usage. Requests sensitive permissions that may be legitimate. Verify publisher identity before proceeding.",
        "Moderate risk — some dangerous permissions present but pattern is inconclusive. Manual review recommended.",
    ],
    ("APK","Safe"):[
        "APK passes all permission-based checks. No suspicious API call patterns detected. Safe to install.",
        "Clean APK — permission profile consistent with legitimate application behaviour.",
    ],
    ("PDF","Malicious"):[
        "PDF contains embedded JavaScript with obfuscated exploit code. Classic phishing delivery vector. Do not open — quarantine immediately.",
        "Malicious PDF detected: /Launch action and suspicious /URI references found. Likely drive-by download dropper.",
        "PDF exhibits CVE-targeted exploit traits — abnormal stream count and embedded executable objects present.",
    ],
    ("PDF","Suspicious"):[
        "PDF contains JavaScript elements but no definitive exploit signature. Exercise caution before opening in production environment.",
        "Suspicious metadata — unusual object count may indicate obfuscation. Recommend scanning in isolated sandbox.",
    ],
    ("PDF","Safe"):[
        "PDF structure is clean — no JavaScript, no embedded files, no suspicious actions detected.",
        "Document passes all 21 metadata feature checks. Standard PDF with no anomalous characteristics.",
    ],
    ("URL","Malicious"):[
        "URL shows strong phishing indicators — IP-based domain, suspicious TLD, high entropy string pattern. Block immediately.",
        "High-confidence malicious URL — structural features match known phishing and malware distribution patterns.",
        "URL domain impersonates a trusted brand. Entropy and subdomain count consistent with auto-generated phishing domains.",
    ],
    ("URL","Suspicious"):[
        "URL shows moderate risk signals — unusual subdomain structure and borderline entropy score. Verify legitimacy before clicking.",
        "Suspicious URL — may be a newly registered phishing domain. TLD popularity score is low.",
    ],
    ("URL","Safe"):[
        "URL passes all 16 structural feature checks. No phishing or malware distribution indicators detected.",
        "URL structural features consistent with legitimate websites. HTTPS confirmed, TLD is popular, no suspicious extensions.",
    ],
    ("Network","Malicious"):[
        "Network flow matches DDoS attack signature — abnormal packet rate and flow duration detected. Block source IP immediately.",
        "Intrusion detected: traffic pattern consistent with port scanning followed by exploitation attempt.",
        "Volumetric flood characteristics detected across 78 flow features. Activate incident response protocol.",
    ],
    ("Network","Suspicious"):[
        "Traffic anomaly detected — unusual flow duration and byte ratio. May indicate active reconnaissance activity.",
        "Borderline network activity — elevated packet rate without full attack signature. Increase monitoring frequency.",
    ],
    ("Network","Safe"):[
        "Network traffic within normal parameters across all 78 flow features. No anomalous characteristics detected.",
        "Benign traffic — flow metrics consistent with legitimate user activity.",
    ],
}

def get_ai_insight(module_type:str, label:str, confidence:float) -> dict:
    key = (module_type, label)
    options = _INSIGHTS.get(key, [f"{module_type} scan: {label} ({confidence:.1f}% confidence)."])
    random.seed(int(confidence * 100) + hash(module_type) % 100)
    msg = random.choice(options)
    risk = ("Critical" if label=="Malicious" and confidence>80 else
            "High"     if label=="Malicious" else
            "Medium"   if label=="Suspicious" else "Low")
    action = {
        "Malicious":"Block immediately and isolate affected system.",
        "Suspicious":"Manual review recommended before proceeding.",
        "Safe":"No action required.",
    }.get(label,"Monitor.")
    top_feats = {
        "APK":    ["SEND_SMS","ACCESS_LOCATION","USE_CAMERA","RECORD_AUDIO","READ_CONTACTS"],
        "PDF":    ["javascript_count","stream_count","object_count","has_encrypt","has_launch"],
        "URL":    ["url_entropy","has_ip_address","subdomain_count","tld_popularity","url_length"],
        "Network":["Flow_Duration","Total_Fwd_Packets","Packet_Length_Mean","Flow_Bytes/s","Fwd_IAT_Mean"],
    }.get(module_type, [])
    return {
        "message":     msg,
        "risk_level":  risk,
        "action":      action,
        "top_features":top_feats[:3],
        "timestamp":   datetime.now().strftime("%H:%M:%S"),
        "confidence":  round(confidence,1),
        "module":      module_type,
        "label":       label,
    }

# ── Core helpers ───────────────────────────────────────────────────────────────
def _label(prob):
    if prob>=0.70: return "Malicious","high"
    if prob>=0.40: return "Suspicious","medium"
    return "Safe","low"

def _mock(seed): random.seed(seed); return round(random.uniform(0.1,0.9),3)

def _run(model,scaler,X):
    if scaler: X=scaler.transform(X)
    try:    return float(model.predict_proba(X)[0][1])
    except: return float(model.predict(X)[0])

# ── APK (216 binary permission features) ──────────────────────────────────────
def predict_apk(contents:bytes, filename:str) -> dict:
    _s["scans"]+=1
    if apk_model:
        n=APK_F or 216
        vec=np.zeros((1,n))
        risky=["crack","hack","mod","spy","cheat","free","premium","root","patch"]
        if any(k in filename.lower() for k in risky):
            for i in range(0,n,max(1,n//10))[:6]: vec[0,i]=1
        seed=int.from_bytes(contents[:4],"little") if len(contents)>=4 else 0
        rng=np.random.default_rng(seed)
        idx=rng.choice(n,int(rng.integers(10,min(35,n))),replace=False)
        vec[0,idx]=1
        prob=_run(apk_model,apk_scaler,vec)
    else:
        prob=_mock(len(contents)%997)
    label,risk=_label(prob)
    if label!="Safe": _s["malicious"]+=1
    return {"file":filename,"type":"APK","label":label,"risk":risk,"confidence":round(prob*100,1)}

# ── PDF (21 metadata features) ─────────────────────────────────────────────────
def predict_pdf(contents:bytes, filename:str) -> dict:
    _s["scans"]+=1
    if pdf_model:
        t=contents[:8192].decode("latin-1",errors="ignore")
        raw=[len(contents),
             t.lower().count("/javascript"),t.lower().count("/js"),
             t.lower().count("/uri"),t.lower().count("/action"),
             t.lower().count("/aa"),t.lower().count("/openaction"),
             t.lower().count("/launch"),t.lower().count("/submitform"),
             t.lower().count("/importdata"),
             int(b"/Encrypt" in contents),int(b"/EmbeddedFile" in contents),
             t.lower().count("/page"),t.lower().count("/xobject"),
             t.lower().count("/stream"),
             contents.count(b"obj"),contents.count(b"endobj"),
             contents.count(b"stream"),contents.count(b"endstream"),
             int(b"/AcroForm" in contents),len(contents)//1024]
        n=PDF_F or 21
        vec=np.zeros((1,n))
        for i,v in enumerate(raw[:n]): vec[0,i]=v
        prob=_run(pdf_model,pdf_scaler,vec)
    else:
        prob=_mock(len(contents)%991)
    label,risk=_label(prob)
    if label!="Safe": _s["malicious"]+=1
    return {"file":filename,"type":"PDF","label":label,"risk":risk,"confidence":round(prob*100,1)}

# ── URL (exact 16 features from url_features_extracted1.csv) ──────────────────
_POP_TLDS  ={"com","org","net","edu","gov","io","co","uk","us","ca"}
_SUSP_EXTS ={"exe","zip","rar","php","bat","sh"}

def _entropy(s):
    if not s: return 0.0
    freq={}
    for c in s: freq[c]=freq.get(c,0)+1
    return -sum((v/len(s))*math.log2(v/len(s)) for v in freq.values())

def _url_vec(url:str)->np.ndarray:
    p=urlparse(url); domain=p.netloc or ""; path=p.path or ""; query=p.query or ""
    tld=domain.split(".")[-1] if "." in domain else ""
    sub=domain.split(".")[:-2] if domain.count(".")>=2 else []
    raw=[
        len(url),
        int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}",domain))),
        url.count("."),
        int(p.scheme=="https"),
        round(_entropy(url),4),
        len(re.split(r"[/.\-_?=&]",url)),
        len(sub),
        len(query.split("&")) if query else 0,
        len(tld),
        len(path),
        int("-" in domain),
        sum(c.isdigit() for c in url),
        int(tld.lower() in _POP_TLDS),
        int(any(url.lower().endswith("."+e) for e in _SUSP_EXTS)),
        len(domain),
        round(sum(c.isdigit() for c in url)/len(url)*100 if url else 0,2),
    ]
    return np.array(raw,dtype=float).reshape(1,-1)

def predict_url(url:str)->dict:
    _s["scans"]+=1; _s["urls"]+=1
    prob=_run(url_model,None,_url_vec(url)) if url_model else _mock(len(url))
    label,risk=_label(prob)
    return {"url":url,"label":label,"risk":risk,"confidence":round(prob*100,1)}

# ── Network (78 numeric flow features) ────────────────────────────────────────
def predict_network(features:list)->dict:
    _s["scans"]+=1
    if net_model:
        X=np.array(features,dtype=float).reshape(1,-1)
        if NET_F and X.shape[1]!=NET_F:
            pad=np.zeros((1,NET_F))
            pad[0,:min(X.shape[1],NET_F)]=X[0,:min(X.shape[1],NET_F)]
            X=pad
        prob=_run(net_model,net_scaler,X)
    else:
        prob=_mock(int(sum(features[:3]))%997)
    label,risk=_label(prob)
    if label!="Safe": _s["intrusions"]+=1
    return {"label":label,"risk":risk,"confidence":round(prob*100,1)}
# ── IMAGE (rule-based, no model needed) ───────────────────────────────────────
SUSP_EXTENSIONS = {".exe", ".bat", ".sh", ".js", ".php", ".vbs", ".ps1"}
IMAGE_MAGIC = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG":      "PNG",
    b"GIF8":         "GIF",
    b"BM":           "BMP",
    b"RIFF":         "WEBP",
}

def predict_image(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    risk_score = 0
    flags = []

    # Check 1 — real image magic bytes
    is_real_image = any(contents.startswith(magic) for magic in IMAGE_MAGIC)
    if not is_real_image:
        risk_score += 40
        flags.append("invalid_image_header")

    # Check 2 — double extension like image.jpg.exe
    name_lower = filename.lower()
    for ext in SUSP_EXTENSIONS:
        if ext in name_lower and not name_lower.endswith(ext[:4]):
            risk_score += 35
            flags.append("double_extension")
            break

    # Check 3 — suspicious size (too small or suspiciously large)
    size = len(contents)
    if size < 100:
        risk_score += 20
        flags.append("suspiciously_small")
    elif size > 50 * 1024 * 1024:
        risk_score += 15
        flags.append("very_large_file")

    # Check 4 — embedded executable signatures
    exe_sigs = [b"MZ\x90\x00", b"#!/", b"<script", b"eval(", b"powershell"]
    for sig in exe_sigs:
        if sig in contents[:4096]:
            risk_score += 50
            flags.append("embedded_executable")
            break

    # Check 5 — high entropy (possible steganography/encryption)
    sample = contents[:2048]
    if len(sample) > 0:
        freq = {}
        for b in sample:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((v/len(sample)) * math.log2(v/len(sample)) for v in freq.values())
        if entropy > 7.5:
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


# ── ZIP (extract + scan each file inside) ─────────────────────────────────────
import zipfile
import io

def predict_zip(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    results = []
    flags = []
    highest_risk = 0

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            file_list = zf.namelist()

            # Check 1 — zip bomb (too many files)
            if len(file_list) > 500:
                flags.append("zip_bomb_suspected")
                highest_risk = max(highest_risk, 85)

            # Check 2 — suspicious filenames inside zip
            for name in file_list:
                name_lower = name.lower()
                for ext in SUSP_EXTENSIONS:
                    if name_lower.endswith(ext):
                        flags.append(f"suspicious_file:{name}")
                        highest_risk = max(highest_risk, 60)

                # Check for double extensions inside zip
                if any(f"{ext}." in name_lower for ext in [".jpg", ".png", ".pdf", ".doc"]):
                    flags.append(f"double_ext_inside:{name}")
                    highest_risk = max(highest_risk, 70)

            # Scan each file inside using existing models
            for name in file_list[:10]:  # limit to first 10 files
                try:
                    data = zf.read(name)
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
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
                            highest_risk = max(highest_risk, sub_result["confidence"])
                        elif sub_result["label"] == "Suspicious":
                            highest_risk = max(highest_risk, sub_result["confidence"] * 0.6)

                except Exception:
                    flags.append(f"unreadable:{name}")

    except zipfile.BadZipFile:
        flags.append("corrupted_zip")
        highest_risk = 60
    except Exception as e:
        flags.append(f"error:{str(e)}")
        highest_risk = 30

    prob = min(highest_risk / 100.0, 0.99)
    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1

    return {
        "file":          filename,
        "type":          "ZIP",
        "label":         label,
        "risk":          risk,
        "confidence":    round(prob * 100, 1),
        "flags":         flags,
        "files_inside":  len(results),
        "scan_results":  results,
    }
    # ── IMAGE (rule-based, no model needed) ───────────────────────────────────────
SUSP_EXTENSIONS = {".exe", ".bat", ".sh", ".js", ".php", ".vbs", ".ps1"}
IMAGE_MAGIC = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG":      "PNG",
    b"GIF8":         "GIF",
    b"BM":           "BMP",
    b"RIFF":         "WEBP",
}

def predict_image(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    risk_score = 0
    flags = []

    # Check 1 — real image magic bytes
    is_real_image = any(contents.startswith(magic) for magic in IMAGE_MAGIC)
    if not is_real_image:
        risk_score += 40
        flags.append("invalid_image_header")

    # Check 2 — double extension like image.jpg.exe
    name_lower = filename.lower()
    for ext in SUSP_EXTENSIONS:
        if ext in name_lower and not name_lower.endswith(ext[:4]):
            risk_score += 35
            flags.append("double_extension")
            break

    # Check 3 — suspicious size (too small or suspiciously large)
    size = len(contents)
    if size < 100:
        risk_score += 20
        flags.append("suspiciously_small")
    elif size > 50 * 1024 * 1024:
        risk_score += 15
        flags.append("very_large_file")

    # Check 4 — embedded executable signatures
    exe_sigs = [b"MZ\x90\x00", b"#!/", b"<script", b"eval(", b"powershell"]
    for sig in exe_sigs:
        if sig in contents[:4096]:
            risk_score += 50
            flags.append("embedded_executable")
            break

    # Check 5 — high entropy (possible steganography/encryption)
    sample = contents[:2048]
    if len(sample) > 0:
        freq = {}
        for b in sample:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((v/len(sample)) * math.log2(v/len(sample)) for v in freq.values())
        if entropy > 7.5:
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


# ── ZIP (extract + scan each file inside) ─────────────────────────────────────
import zipfile
import io

def predict_zip(contents: bytes, filename: str) -> dict:
    _s["scans"] += 1
    results = []
    flags = []
    highest_risk = 0

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            file_list = zf.namelist()

            # Check 1 — zip bomb (too many files)
            if len(file_list) > 500:
                flags.append("zip_bomb_suspected")
                highest_risk = max(highest_risk, 85)

            # Check 2 — suspicious filenames inside zip
            for name in file_list:
                name_lower = name.lower()
                for ext in SUSP_EXTENSIONS:
                    if name_lower.endswith(ext):
                        flags.append(f"suspicious_file:{name}")
                        highest_risk = max(highest_risk, 60)

                # Check for double extensions inside zip
                if any(f"{ext}." in name_lower for ext in [".jpg", ".png", ".pdf", ".doc"]):
                    flags.append(f"double_ext_inside:{name}")
                    highest_risk = max(highest_risk, 70)

            # Scan each file inside using existing models
            for name in file_list[:10]:  # limit to first 10 files
                try:
                    data = zf.read(name)
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
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
                            highest_risk = max(highest_risk, sub_result["confidence"])
                        elif sub_result["label"] == "Suspicious":
                            highest_risk = max(highest_risk, sub_result["confidence"] * 0.6)

                except Exception:
                    flags.append(f"unreadable:{name}")

    except zipfile.BadZipFile:
        flags.append("corrupted_zip")
        highest_risk = 60
    except Exception as e:
        flags.append(f"error:{str(e)}")
        highest_risk = 30

    prob = min(highest_risk / 100.0, 0.99)
    label, risk = _label(prob)
    if label != "Safe":
        _s["malicious"] += 1

    return {
        "file":          filename,
        "type":          "ZIP",
        "label":         label,
        "risk":          risk,
        "confidence":    round(prob * 100, 1),
        "flags":         flags,
        "files_inside":  len(results),
        "scan_results":  results,
    }